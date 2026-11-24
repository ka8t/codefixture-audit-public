//! Persistent PHP call graph — multi-hop interprocedural resolution.
//! Direct template of `js_call_graph.rs` for the shape
//! (nodes/edges/Tarjan SCC/fixpoint), **resolution algorithm entirely
//! specific to PHP** (`php_module_registry.rs` — two distinct
//! mechanisms: star-merge of `require`/`include`, global class-name
//! index for static-scope calls): no equivalent Python source exists
//! for this module (same observation as for JS, see
//! `js_call_graph.rs` doc) — new development, not a port.
//!
//! **Cycles/recursion**: decomposition into strongly connected
//! components (Tarjan) + bounded fixpoint
//! (`call_graph::MAX_SCC_FIXPOINT_ITER`), duplicated from
//! `call_graph.rs`/`js_call_graph.rs` — same deliberate choice as for
//! JS (no extraction into a shared helper for this effort).
//!
//! **Call resolution** (`outgoing_edges`, see `call_local_name` below
//! and the `php_module_registry.rs` doc for the details of the two
//! mechanisms):
//!   - Bare call `foo()` — same file, otherwise via a function made
//!     available by a literal `require`/`include` (star-merge).
//!   - `Klass::method()` (literal static scope) — resolved via the
//!     global class-name index, **with no notion of scope/
//!     namespace** (unlike Java, which limits itself to classes in
//!     the same package + explicit imports): sufficient to cover
//!     modern PHP code (Composer/PSR-4), which often has no explicit
//!     `require` between application classes.
//!   - `self::method()`/`static::method()` — resolved by bare name in
//!     the current file (same spirit as `this.method()` in JS).
//!   - `$obj->method()` — resolved **only** if `$obj` is literally
//!     `$this` (same file); no variable type tracking (no Java-style
//!     `type_map`), same limitation as JS for `obj.method()` on a
//!     non-imported receiver.
//!   - `parent::method()` — **not resolved in v1**: would require
//!     knowing which class encloses the calling method in order to
//!     find its superclass (Java does this via a qualified
//!     `JavaFunctionInfo` `Class.method` + a superclass map;
//!     `PhpFunctionInfo` does not keep this class-method association)
//!     — out of scope for this effort, documented rather than guessed.
//!
//! **Read from the tree file by file, linked without it (ticket #281)**:
//! [`PhpFile::extract`] reads from one file's tree everything the graph
//! needs (its prepared module and functions, its `require`s and classes,
//! and the local names of the calls of each function in the order its
//! body lists them), so that the scan can drop the tree right after;
//! [`PhpCallGraph::build_from`] links the files from these facts alone,
//! with the same edges as the former reading of the trees.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use rayon::prelude::*;

use tree_sitter::Node;

pub use super::call_graph::{FileInput, MAX_SCC_FIXPOINT_ITER, NodeKey, SummariesByFile};
use super::line_facts::{LinesByFile, RuleLinesByFile, rule_lines_by_file};
use super::php_module_registry::{
    build_class_name_index, collect_php_class_names, collect_php_requires, resolve_required_file,
};
use super::php_summary::{
    PhpFunctionInfo, collect_php_functions, compute_php_summary_with, prepare_php_functions,
};
use super::prepared::{PreparedFile, PreparedFiles};
use super::transfer::{FunctionSummary, RuleSpecs};
use super::visibility::{ImportVisibility, Visibility, graph_fingerprint};

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

/// Local call name of a PHP call node — three distinct node shapes
/// in PHP (unlike the unified `call_expression` in JS, see
/// `php_lowering.rs` doc):
///   - `function_call_expression` (`foo(...)`) → `foo`, only if the
///     callee is a literal `name` (not `$fn(...)`, a dynamic call).
///   - `member_call_expression` (`$obj->method(...)`) → `this.method`
///     only if `$obj` is literally `$this`; otherwise unresolved (no
///     variable type tracking).
///   - `scoped_call_expression` (`Klass::method(...)`/`self::.../
///     static::.../parent::...`) → `Klass.method` (scope = literal
///     class name) or `self.method`/`static.method` (relative scope
///     resolved by bare name in the current file); `None` for
///     `parent::...` (out of scope for v1, see module doc).
fn call_local_name(call_node: Node, source: &[u8]) -> Option<String> {
    match call_node.kind() {
        "function_call_expression" => {
            let func = call_node.child_by_field_name("function")?;
            if func.kind() != "name" {
                return None;
            }
            Some(text(func, source))
        }
        "member_call_expression" => {
            let obj = call_node.child_by_field_name("object")?;
            let name = call_node.child_by_field_name("name")?;
            if obj.kind() == "variable_name" && text(obj, source) == "$this" {
                Some(format!("this.{}", text(name, source)))
            } else {
                None
            }
        }
        "scoped_call_expression" => {
            let scope = call_node.child_by_field_name("scope")?;
            let name = call_node.child_by_field_name("name")?;
            match scope.kind() {
                "name" => Some(format!("{}.{}", text(scope, source), text(name, source))),
                "relative_scope" => match text(scope, source).as_str() {
                    "self" | "static" => {
                        Some(format!("{}.{}", text(scope, source), text(name, source)))
                    }
                    _ => None, // "parent" — not resolved in v1, see module doc.
                },
                _ => None,
            }
        }
        _ => None,
    }
}

const CALL_NODE_KINDS: [&str; 3] = [
    "function_call_expression",
    "member_call_expression",
    "scoped_call_expression",
];

fn walk_calls<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    if CALL_NODE_KINDS.contains(&node.kind()) {
        out.push(node);
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        walk_calls(child, out);
    }
}

/// The local names ([`call_local_name`]) of the calls under `body`, in
/// the order [`walk_calls`] lists them, the order in which the first
/// resolution of a name wins (ticket #281). A call without a local name
/// is not kept: no edge was ever drawn from it.
fn call_names(body: Node, source: &[u8]) -> Vec<String> {
    let mut calls = Vec::new();
    walk_calls(body, &mut calls);
    calls
        .into_iter()
        .filter_map(|call| call_local_name(call, source))
        .collect()
}

/// What the call graph needs from one PHP file, read from its tree once
/// ([`PhpFile::extract`], ticket #281): no node of the tree is kept.
pub struct PhpFile {
    /// The module top level and the functions, prepared for every rule.
    prepared: PreparedFile<PhpFunctionInfo>,
    /// The local names of the calls of each function of `prepared`, at
    /// the same index ([`call_names`]).
    calls: Vec<Vec<String>>,
    /// The literal `require`/`include` specifiers, in source order.
    requires: Vec<String>,
    /// The classes the file declares.
    class_names: Vec<String>,
}

impl PhpFile {
    /// Reads the file whose tree is `root`, parsed from `source`.
    pub fn extract(root: Node<'_>, source: &[u8]) -> Self {
        let functions = collect_php_functions(root, source);
        let calls = functions
            .iter()
            .map(|function| call_names(function.body, source))
            .collect();
        PhpFile {
            requires: collect_php_requires(root, source),
            class_names: collect_php_class_names(root, source),
            calls,
            prepared: prepare_php_functions(root, functions, source),
        }
    }
}

/// Returns the outgoing edges of a PHP function from the local names of
/// its calls ([`call_names`]). Resolves: a bare
/// call to a function in the same file, or one made available by a
/// literal `require`/`include`/static-scope
/// (`import_bindings`, see module doc for how the latter is built —
/// star-merge of `require` + global class index);
/// `self.`/`static.`/`this.` are resolved directly as same-file here
/// (never via `import_bindings`, which does not contain them).
fn outgoing_edges(
    calls: &[String],
    filepath: &str,
    local_names: &BTreeSet<String>,
    visibility: &dyn Visibility,
) -> BTreeMap<String, NodeKey> {
    let mut edges = BTreeMap::new();
    for local_name in calls {
        let local_name = local_name.clone();
        if edges.contains_key(&local_name) {
            continue;
        }
        let same_file_target = ["this.", "self.", "static."]
            .iter()
            .find_map(|prefix| local_name.strip_prefix(prefix));
        if let Some(method) = same_file_target {
            if local_names.contains(method) {
                edges.insert(
                    local_name.clone(),
                    (filepath.to_string(), method.to_string()),
                );
            }
            continue;
        }
        if local_names.contains(&local_name) {
            edges.insert(local_name.clone(), (filepath.to_string(), local_name));
        } else if let Some(target) = visibility.binding(filepath, &local_name) {
            edges.insert(local_name.clone(), target);
        }
    }
    edges
}

/// Bindings brought in by a file's `require`/`include` (literal
/// string) — star-merge (mirrors `call_graph.rs::
/// resolve_import_bindings`, Python star-import branch): each
/// function of the required file becomes callable **without a
/// prefix**. On collision (two required files each defining a
/// function with the same name) → neither is kept (anti-FP).
///
/// Test only since ticket #239: the graph no longer builds this map for
/// every file (see [`resolve_require_targets`]); kept as the oracle its
/// lookups are checked against.
#[cfg(test)]
fn resolve_require_bindings(
    filepath: &str,
    required_specifiers: &[String],
    known_files: &HashSet<String>,
    file_function_names: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, NodeKey> {
    let mut seen: BTreeMap<String, NodeKey> = BTreeMap::new();
    let mut collided: BTreeSet<String> = BTreeSet::new();
    let empty_set: BTreeSet<String> = BTreeSet::new();
    for spec in required_specifiers {
        let Some(target) = resolve_required_file(filepath, spec, known_files) else {
            continue;
        };
        if target == filepath {
            continue;
        }
        for fname in file_function_names.get(&target).unwrap_or(&empty_set) {
            let key = (target.clone(), fname.clone());
            match seen.get(fname) {
                Some(existing) if *existing != key => {
                    collided.insert(fname.clone());
                }
                None => {
                    seen.insert(fname.clone(), key);
                }
                _ => {}
            }
        }
    }
    seen.into_iter()
        .filter(|(name, _)| !collided.contains(name))
        .collect()
}

/// The files a file's literal `require`/`include` designate, in source
/// order, the file itself excepted (ticket #239): kept as star imports of
/// an [`ImportVisibility`] instead of the former expansion into one binding
/// per function of each required file ([`resolve_require_bindings`], now
/// the test oracle). A function name defined by two of them is not bound
/// (anti-FP, as before).
fn resolve_require_targets(
    filepath: &str,
    required_specifiers: &[String],
    known_files: &HashSet<String>,
) -> Vec<String> {
    required_specifiers
        .iter()
        .filter_map(|spec| resolve_required_file(filepath, spec, known_files))
        .filter(|target| target != filepath)
        .collect()
}

// ============================================================================
// PhpCallGraph
// ============================================================================

/// Call graph of a set of PHP files analyzed together — same
/// contract as `call_graph::CallGraph`/`js_call_graph::JsCallGraph`
/// (see their doc for field details, identical here).
#[derive(Default)]
pub struct PhpCallGraph {
    pub nodes: BTreeMap<NodeKey, PhpFunctionInfo>,
    pub edges: BTreeMap<NodeKey, BTreeMap<String, NodeKey>>,
    /// The `require` targets of each file and the class index of the
    /// project, looked up on demand (ticket #239), instead of the former
    /// per-file map, which held every method of every class of the project
    /// for every file.
    visibility: Arc<ImportVisibility>,
    /// Every file of the graph prepared once for all the rules of the
    /// scan (ticket #192): read for the summaries and handed to the
    /// taint analysis of each file ([`Self::prepared_file`]).
    prepared: PreparedFiles<PhpFunctionInfo>,
}

impl PhpCallGraph {
    /// The prepared form of `filepath`, one of the graph's files, for
    /// the taint analysis of each rule (ticket #192).
    pub fn prepared_file(&self, filepath: &str) -> Option<&PreparedFile<PhpFunctionInfo>> {
        self.prepared.file(filepath)
    }

    /// Builds the complete graph from a set of already-parsed PHP
    /// files.
    ///
    /// Static-scope bindings (`Klass.method`, via the global
    /// class-name index) are the same for every file (no scope/namespace
    /// notion is tracked, see module doc): the [`ImportVisibility`] keeps
    /// the index once and looks a key up in it before the `require`
    /// bindings of the file, as the former per-file map, which merged the
    /// class bindings of the whole project into every file after them
    /// (ticket #239). Each file is read ([`PhpFile::extract`], in
    /// parallel), then linked ([`Self::build_from`]).
    pub fn build(files: &[FileInput<'_>]) -> Self {
        Self::build_from(
            files
                .par_iter()
                .map(|f| (f.filepath.clone(), PhpFile::extract(f.root, f.source)))
                .collect(),
        )
    }

    /// Builds the complete graph from the files already read, by path,
    /// without any tree (ticket #281).
    pub fn build_from(files: Vec<(String, PhpFile)>) -> Self {
        let mut graph = PhpCallGraph::default();
        let mut file_function_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut requires_by_file: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut class_names_by_file: BTreeMap<String, Vec<String>> = BTreeMap::new();
        // The calls of each node. Homonyms: the last one, as in `nodes`
        // and `PreparedFiles::index_node`.
        let mut calls_by_node: BTreeMap<NodeKey, Vec<String>> = BTreeMap::new();

        // Each file was prepared once for every rule of the scan (ticket
        // #192). Its collected functions are the graph nodes.
        for (filepath, file) in files {
            let PhpFile {
                prepared,
                calls,
                requires,
                class_names,
            } = file;
            file_function_names.insert(
                filepath.clone(),
                prepared
                    .functions
                    .iter()
                    .map(|function| function.info.name.clone())
                    .collect(),
            );
            for (index, (function, calls)) in prepared.functions.iter().zip(calls).enumerate() {
                let key = (filepath.clone(), function.info.name.clone());
                graph.prepared.index_node(key.clone(), index);
                graph.nodes.insert(key.clone(), function.info.clone());
                calls_by_node.insert(key, calls);
            }
            graph.prepared.insert_file(filepath.clone(), prepared);
            requires_by_file.insert(filepath.clone(), requires);
            class_names_by_file.insert(filepath, class_names);
        }

        let known_files: Vec<String> = file_function_names.keys().cloned().collect();
        // Built once (ticket #239): the resolution used to build it again
        // for every `require`.
        let known_set: HashSet<String> = known_files.iter().cloned().collect();
        let star_targets = known_files
            .iter()
            .map(|filepath| {
                let requires = requires_by_file.get(filepath).cloned().unwrap_or_default();
                (
                    filepath.clone(),
                    resolve_require_targets(filepath, &requires, &known_set),
                )
            })
            .collect();
        graph.visibility = Arc::new(ImportVisibility::new(
            BTreeMap::new(),
            star_targets,
            build_class_name_index(&class_names_by_file),
            file_function_names.clone(),
            false,
            true,
        ));

        for filepath in &known_files {
            let local_names = file_function_names
                .get(filepath)
                .cloned()
                .unwrap_or_default();
            // This file's functions: a range of the sorted keys, not a scan
            // of every function of the project (as `call_graph.rs`).
            let fn_keys: Vec<NodeKey> = graph
                .nodes
                .range((filepath.clone(), String::new())..)
                .take_while(|((fp, _), _)| fp == filepath)
                .map(|(k, _)| k.clone())
                .collect();
            for key in fn_keys {
                let edges = outgoing_edges(
                    &calls_by_node[&key],
                    filepath,
                    &local_names,
                    graph.visibility.as_ref(),
                );
                graph.edges.insert(key, edges);
            }
        }
        graph
    }

    /// Decomposition into strongly connected components (Tarjan) —
    /// identical to `call_graph::CallGraph`/`js_call_graph::JsCallGraph`.
    fn strongly_connected_components(&self) -> Vec<Vec<NodeKey>> {
        let mut state = TarjanState::default();
        let node_keys: Vec<NodeKey> = self.nodes.keys().cloned().collect();
        for node in &node_keys {
            if !state.indices.contains_key(node) {
                self.tarjan_visit(node, &mut state);
            }
        }
        state.sccs
    }

    fn tarjan_visit(&self, node: &NodeKey, state: &mut TarjanState) {
        state.indices.insert(node.clone(), state.counter);
        state.lowlinks.insert(node.clone(), state.counter);
        state.counter += 1;
        state.stack.push(node.clone());
        state.on_stack.insert(node.clone());

        if let Some(node_edges) = self.edges.get(node) {
            for target in node_edges.values() {
                if !self.nodes.contains_key(target) {
                    continue;
                }
                if !state.indices.contains_key(target) {
                    self.tarjan_visit(target, state);
                    let target_low = state.lowlinks[target];
                    if target_low < state.lowlinks[node] {
                        state.lowlinks.insert(node.clone(), target_low);
                    }
                } else if state.on_stack.contains(target) {
                    let target_idx = state.indices[target];
                    if target_idx < state.lowlinks[node] {
                        state.lowlinks.insert(node.clone(), target_idx);
                    }
                }
            }
        }

        if state.lowlinks[node] == state.indices[node] {
            let mut component = Vec::new();
            loop {
                let w = state
                    .stack
                    .pop()
                    .expect("pile Tarjan non vide (racine SCC atteinte)");
                state.on_stack.remove(&w);
                let is_root = w == *node;
                component.push(w);
                if is_root {
                    break;
                }
            }
            state.sccs.push(component);
        }
    }

    fn build_seed(
        &self,
        node: &NodeKey,
        resolved: &BTreeMap<NodeKey, Arc<FunctionSummary>>,
        scc_current: &BTreeMap<NodeKey, Arc<FunctionSummary>>,
    ) -> BTreeMap<String, Arc<FunctionSummary>> {
        let mut seed = BTreeMap::new();
        if let Some(node_edges) = self.edges.get(node) {
            for (local_name, target) in node_edges {
                if let Some(s) = resolved.get(target) {
                    seed.insert(local_name.clone(), s.clone());
                } else if let Some(s) = scc_current.get(target) {
                    seed.insert(local_name.clone(), s.clone());
                }
            }
        }
        seed
    }

    fn compute_one(
        &self,
        node: &NodeKey,
        seed: BTreeMap<String, Arc<FunctionSummary>>,
        base_specs: &RuleSpecs,
        lines_for_rule: &RuleLinesByFile,
    ) -> Option<Arc<FunctionSummary>> {
        let (filepath, _name) = node;
        let function = self.prepared.function(node)?;
        let specs = if seed.is_empty() {
            base_specs.clone()
        } else {
            RuleSpecs {
                summaries: seed,
                ..base_specs.clone()
            }
        };
        let lines = lines_for_rule.get(filepath.as_str());
        Some(Arc::new(compute_php_summary_with(
            &function.info,
            function.body.as_ref()?,
            &specs,
            lines,
        )))
    }

    /// Computes the summaries of all functions in the graph — same
    /// algorithm and same `(own, extra)` return contract as the
    /// other call graphs (see their doc).
    pub fn resolve_summaries(
        &self,
        base_specs: &RuleSpecs,
        source_lines_by_file: Option<&LinesByFile>,
    ) -> (SummariesByFile, SummariesByFile) {
        let resolved = self.resolve_summaries_incremental(base_specs, source_lines_by_file, None);
        (resolved.own, resolved.extra)
    }

    /// `resolve_summaries`, reusing the summaries of a previous scan where
    /// they cannot have changed: see
    /// `call_graph::CallGraph::resolve_summaries_incremental` (same
    /// algorithm, shared through `call_graph::resolve_incremental`).
    pub fn resolve_summaries_incremental(
        &self,
        base_specs: &RuleSpecs,
        source_lines_by_file: Option<&LinesByFile>,
        reuse: Option<&super::call_graph::SummaryReuse>,
    ) -> super::call_graph::ResolvedSummaries {
        let empty_lines = BTreeMap::new();
        let source_lines_by_file = source_lines_by_file.unwrap_or(&empty_lines);
        // One per-line cache of the hybrid layer per file, shared by every
        // summary of this rule (ticket #190).
        let lines_for_rule = rule_lines_by_file(source_lines_by_file, base_specs);
        let sccs = self.strongly_connected_components();
        super::call_graph::resolve_incremental(
            sccs,
            &self.edges,
            reuse,
            |node, resolved, current| {
                let seed = self.build_seed(node, resolved, current);
                self.compute_one(node, seed, base_specs, &lines_for_rule)
            },
        )
    }

    /// What each file of the graph sees of the others, shared with the
    /// taint analysis of each file (ticket #239).
    pub fn visibility(&self) -> &Arc<ImportVisibility> {
        &self.visibility
    }

    /// The files that read a summary that changed in this scan: those
    /// defining a changed function, those requiring one, and every file
    /// when a changed method is bound through the class index (as the
    /// former per-file maps, which all held it). Computed once per rule
    /// (ticket #239), see `call_graph::CallGraph::readers`.
    pub fn readers(&self, changed: &BTreeSet<NodeKey>) -> BTreeSet<String> {
        let mut readers = self.visibility.readers_of(changed);
        readers.extend(changed.iter().map(|node| node.0.clone()));
        readers
    }

    /// What, besides its own text, decides the analysis of `file`.
    pub fn dependency_fingerprint(&self, file: &str) -> String {
        graph_fingerprint(&self.edges, &self.nodes, self.visibility.as_ref(), file)
    }
}

#[derive(Default)]
struct TarjanState {
    counter: usize,
    indices: BTreeMap<NodeKey, usize>,
    lowlinks: BTreeMap<NodeKey, usize>,
    on_stack: BTreeSet<NodeKey>,
    stack: Vec<NodeKey>,
    sccs: Vec<Vec<NodeKey>>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::transfer::SinkSpec;
    use tree_sitter::Parser;

    /// The edges of a function as the graph drew them from its tree
    /// before ticket #281, when `outgoing_edges` walked the call nodes
    /// under `node` itself: the reference the edges drawn from the local
    /// names read once ([`call_names`]) must equal. Kept as it was, but for
    /// the node passed instead of the metadata that held it.
    fn edges_from_tree(
        node: Node,
        source: &[u8],
        filepath: &str,
        local_names: &BTreeSet<String>,
        visibility: &dyn Visibility,
    ) -> BTreeMap<String, NodeKey> {
        let mut edges = BTreeMap::new();
        let mut calls = Vec::new();
        walk_calls(node, &mut calls);
        for call_node in calls {
            let Some(local_name) = call_local_name(call_node, source) else {
                continue;
            };
            if edges.contains_key(&local_name) {
                continue;
            }
            let same_file_target = ["this.", "self.", "static."]
                .iter()
                .find_map(|prefix| local_name.strip_prefix(prefix));
            if let Some(method) = same_file_target {
                if local_names.contains(method) {
                    edges.insert(
                        local_name.clone(),
                        (filepath.to_string(), method.to_string()),
                    );
                }
                continue;
            }
            if local_names.contains(&local_name) {
                edges.insert(local_name.clone(), (filepath.to_string(), local_name));
            } else if let Some(target) = visibility.binding(filepath, &local_name) {
                edges.insert(local_name.clone(), target);
            }
        }
        edges
    }

    /// Builds the graph of `files` and asserts that every node has the
    /// edges its tree gave before ticket #281 ([`edges_from_tree`]).
    fn build_checked(files: &[FileInput]) -> PhpCallGraph {
        let graph = PhpCallGraph::build(files);
        assert_edges_match_trees(&graph, files);
        graph
    }

    /// See [`build_checked`]; returns the number of edges compared.
    fn assert_edges_match_trees(graph: &PhpCallGraph, files: &[FileInput]) -> usize {
        let mut compared = 0;
        for f in files {
            let functions = collect_php_functions(f.root, f.source);
            let local_names: BTreeSet<String> = functions
                .iter()
                .map(|function| function.info.name.clone())
                .collect();
            // The node of each graph node: the last homonym, as the graph
            // keeps.
            let nodes: BTreeMap<String, Node> = functions
                .iter()
                .map(|function| (function.info.name.clone(), function.body))
                .collect();
            for (name, node) in &nodes {
                let key = (f.filepath.clone(), name.clone());
                let reference = edges_from_tree(
                    *node,
                    f.source,
                    &f.filepath,
                    &local_names,
                    graph.visibility.as_ref(),
                );
                assert_eq!(graph.edges[&key], reference, "{key:?}");
                compared += reference.len();
            }
        }
        compared
    }

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_php::LANGUAGE_PHP.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn specs_with(sinks: Vec<SinkSpec>) -> RuleSpecs {
        RuleSpecs {
            rule_id: "test-rule".to_string(),
            severity: "HIGH".to_string(),
            cwe: None,
            message: "test finding".to_string(),
            sources: vec![],
            sinks,
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
            summary_fallback: None,
            exprs: None,
        }
    }

    #[test]
    fn test_build_intra_file_edge_same_file_call() {
        let src = b"<?php\nfunction helper($x) {}\nfunction main() { helper(1); }\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.php".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = build_checked(&files);
        let edges = &graph.edges[&("m.php".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("helper"),
            Some(&("m.php".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_build_cross_file_edge_via_require() {
        let src_a = b"<?php\nrequire './utils.php';\nfunction main() { helper(1); }\n".to_vec();
        let src_u = b"<?php\nfunction helper($x) {}\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.php".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.php".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = build_checked(&files);
        let edges = &graph.edges[&("a.php".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("helper"),
            Some(&("utils.php".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_static_call_resolved_via_global_class_index() {
        let src_a = b"<?php\nfunction main() { Utils::helper(1); }\n".to_vec();
        let src_u = b"<?php\nclass Utils {\n  function helper($x) {}\n}\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.php".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.php".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = build_checked(&files);
        let edges = &graph.edges[&("a.php".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("Utils.helper"),
            Some(&("utils.php".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_ambiguous_class_name_not_resolved() {
        let src_a = b"<?php\nfunction main() { Utils::helper(1); }\n".to_vec();
        let src_u1 = b"<?php\nclass Utils {\n  function helper($x) {}\n}\n".to_vec();
        let src_u2 = b"<?php\nclass Utils {\n  function helper($x) {}\n}\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u1 = parse(std::str::from_utf8(&src_u1).unwrap());
        let tree_u2 = parse(std::str::from_utf8(&src_u2).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.php".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils1.php".to_string(),
                root: tree_u1.root_node(),
                source: &src_u1,
            },
            FileInput {
                filepath: "utils2.php".to_string(),
                root: tree_u2.root_node(),
                source: &src_u2,
            },
        ];
        let graph = build_checked(&files);
        let edges = &graph.edges[&("a.php".to_string(), "main".to_string())];
        assert!(edges.get("Utils.helper").is_none());
    }

    #[test]
    fn test_self_and_static_resolved_same_file() {
        let src = b"<?php\nclass C {\n  function helper($x) {}\n  function main() { self::helper(1); static::helper(2); }\n}\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.php".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = build_checked(&files);
        let edges = &graph.edges[&("m.php".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("self.helper"),
            Some(&("m.php".to_string(), "helper".to_string()))
        );
        assert_eq!(
            edges.get("static.helper"),
            Some(&("m.php".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_parent_call_not_resolved() {
        let src = b"<?php\nclass C extends Base {\n  function main() { parent::helper(1); }\n}\n"
            .to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.php".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = build_checked(&files);
        let edges = &graph.edges[&("m.php".to_string(), "main".to_string())];
        assert!(
            edges.is_empty(),
            "parent:: non resolu en v1, cf. doc de module"
        );
    }

    #[test]
    fn test_this_method_call_resolved_same_file() {
        let src = b"<?php\nclass C {\n  function helper($x) {}\n  function main() { $this->helper(1); }\n}\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.php".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = build_checked(&files);
        let edges = &graph.edges[&("m.php".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("this.helper"),
            Some(&("m.php".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_instance_call_on_other_variable_not_resolved() {
        let src = b"<?php\nfunction main($obj) { $obj->helper(1); }\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.php".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = build_checked(&files);
        let edges = &graph.edges[&("m.php".to_string(), "main".to_string())];
        assert!(edges.is_empty());
    }

    #[test]
    fn test_resolve_summaries_multi_hop_sink_propagation() {
        let src_a =
            b"<?php\nrequire './utils.php';\nfunction main($userInput) { helper($userInput); }\n"
                .to_vec();
        let src_u = b"<?php\nfunction helper($cmd) { $db->query($cmd); }\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.php".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.php".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = build_checked(&files);
        let specs = specs_with(vec![SinkSpec::new("*.query")]);
        let (own, _extra) = graph.resolve_summaries(&specs, None);

        let helper_summary = &own["utils.php"]["helper"];
        assert!(
            helper_summary.sink_param_findings.contains_key(&0),
            "helper: param 0 atteint db->query"
        );
        let main_summary = &own["a.php"]["main"];
        assert!(
            main_summary.sink_param_findings.contains_key(&0),
            "main: param 0 (userInput) atteint le sink via helper (multi-hop)"
        );
    }

    #[test]
    fn test_resolve_summaries_mutual_recursion_does_not_hang() {
        let src =
            b"<?php\nfunction f($x) { return g($x); }\nfunction g($y) { return f($y); }\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.php".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = build_checked(&files);
        let specs = specs_with(vec![]);
        let (own, _extra) = graph.resolve_summaries(&specs, None);
        assert!(own["m.php"].contains_key("f"));
        assert!(own["m.php"].contains_key("g"));
    }

    /// Ticket #239: the `require` targets and the class index looked up on
    /// demand answer every name as the former per-file map did (the
    /// `require` bindings, then the class bindings of the whole project
    /// over them; the oracle below rebuilds it as `build` did), and the
    /// files to redo for a changed function are exactly those whose former
    /// map held it.
    #[test]
    fn test_lookups_match_the_materialized_import_maps() {
        let sources: &[(&str, &str)] = &[
            (
                "lib/a.php",
                "<?php\nfunction fa() {}\nclass A { function m() {} }\nclass Solo { function run() {} }\n",
            ),
            (
                "lib/b.php",
                "<?php\nfunction shared() {}\nclass B { function m() {} }\n",
            ),
            (
                "lib/c.php",
                "<?php\nfunction shared() {}\nclass A { function n() {} }\n",
            ),
            (
                "main.php",
                "<?php\nrequire 'lib/a.php';\nrequire_once './lib/b.php';\ninclude 'lib/c.php';\nrequire 'main.php';\nfunction own() {}\n",
            ),
            ("other.php", "<?php\nrequire 'lib/b.php';\n"),
        ];
        let trees: Vec<_> = sources.iter().map(|(_, src)| parse(src)).collect();
        let files: Vec<FileInput> = sources
            .iter()
            .zip(&trees)
            .map(|((path, src), tree)| FileInput {
                filepath: path.to_string(),
                root: tree.root_node(),
                source: src.as_bytes(),
            })
            .collect();
        let graph = build_checked(&files);
        let mut names: BTreeMap<String, BTreeSet<String>> = sources
            .iter()
            .map(|(path, _)| (path.to_string(), BTreeSet::new()))
            .collect();
        for (file, name) in graph.nodes.keys() {
            names.entry(file.clone()).or_default().insert(name.clone());
        }
        let known: HashSet<String> = names.keys().cloned().collect();
        let class_names_by_file: BTreeMap<String, Vec<String>> = sources
            .iter()
            .zip(&trees)
            .map(|((path, src), tree)| {
                (
                    path.to_string(),
                    collect_php_class_names(tree.root_node(), src.as_bytes()),
                )
            })
            .collect();
        let mut global: BTreeMap<String, NodeKey> = BTreeMap::new();
        for (cname, target) in &build_class_name_index(&class_names_by_file) {
            let Some(target) = target else { continue };
            for method in &names[target] {
                global.insert(
                    format!("{cname}.{method}"),
                    (target.clone(), method.clone()),
                );
            }
        }
        let all_names: BTreeSet<String> = names.values().flatten().cloned().collect();
        let mut probes = all_names.clone();
        for class in ["A", "B", "Solo", "Nope"] {
            for name in &all_names {
                probes.insert(format!("{class}.{name}"));
            }
        }
        let visibility = graph.visibility();
        let mut maps = BTreeMap::new();
        for ((path, src), tree) in sources.iter().zip(&trees) {
            let requires = collect_php_requires(tree.root_node(), src.as_bytes());
            let mut former = resolve_require_bindings(path, &requires, &known, &names);
            former.extend(global.clone());
            for key in &probes {
                assert_eq!(
                    visibility.binding(path, key).as_ref(),
                    former.get(key),
                    "{key} from {path}"
                );
            }
            maps.insert(path.to_string(), former);
        }
        for node in graph.nodes.keys() {
            let expected: BTreeSet<String> = maps
                .iter()
                .filter(|(_, map)| map.values().any(|target| target == node))
                .map(|(file, _)| file.clone())
                .collect();
            assert_eq!(
                visibility.readers_of(&BTreeSet::from([node.clone()])),
                expected,
                "readers of {node:?}"
            );
        }
        // The fixture does exercise each precedence rule.
        let at = |file: &str, name: &str| Some((file.to_string(), name.to_string()));
        assert_eq!(visibility.binding("main.php", "fa"), at("lib/a.php", "fa"));
        assert_eq!(visibility.binding("main.php", "shared"), None);
        assert_eq!(visibility.binding("main.php", "own"), None);
        assert_eq!(visibility.binding("other.php", "B.m"), at("lib/b.php", "m"));
        assert_eq!(visibility.binding("other.php", "A.m"), None);
        assert_eq!(
            visibility.binding("other.php", "Solo.run"),
            at("lib/a.php", "run")
        );
    }
}
