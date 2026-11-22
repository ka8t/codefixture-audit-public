//! Persistent JavaScript/TypeScript call graph — multi-hop
//! interprocedural resolution. Direct template of `call_graph.rs`
//! (Python) for the shape (nodes/edges/SCC/fixed point), **entirely
//! original import-resolution algorithm** (`js_module_registry.rs`
//! — relative path, no Python-style suffix nor Java-style FQCN): no
//! equivalent Python source exists for this module (the reference
//! Python engine has no JS interprocedural analysis) — new development,
//! not a port.
//!
//! **Cycles/recursion**: decomposition into strongly connected
//! components (Tarjan) + bounded fixed point (`call_graph::
//! MAX_SCC_FIXPOINT_ITER`), duplicated from `call_graph.rs` rather than
//! extracted into a shared helper — a deliberate choice for this
//! effort (avoid touching `call_graph.rs`, tested and in production,
//! for a need that doesn't require it; extraction into a common helper
//! left as a future improvement if the Python/JS/PHP triplication
//! becomes bothersome). Not the naive DFS of `java_call_graph.rs`: Java
//! kept that only for fidelity to actual existing Python source code
//! (`java_call_graph.py`) — a constraint that doesn't apply here,
//! nothing to faithfully imitate.
//!
//! **Call resolution** (`outgoing_edges`): a bare call (`foo(...)`), a
//! non-computed member call on an identifier (`obj.method(...)`, `obj`
//! = resolved imported binding) or on `this` (`this.method(...)` →
//! resolved by name in the current file if a function/method of that
//! name is defined there, same spirit as the "bare name" fallback of
//! `java_call_graph.rs::add_bare_name_aliases`, simpler here: JS has no
//! class FQCN to disambiguate). A member call on a computed expression
//! (`obj[expr]()`) or a non-identifier receiver → never resolved
//! (anti-FP, same principle as everywhere else in the engine: better
//! to miss a flow than to invent one).
//!
//! **Over-approximation inherited from the Python template**
//! (`walk_calls` walks the entire subtree of a function, including the
//! bodies of **nested** functions): a call made from a nested JS
//! callback (`array.map(x => sink(x))`) therefore also appears in the
//! outgoing edges of the enclosing function, in addition to those of
//! the callback itself (which has its own node via
//! `collect_js_functions`). As on the Python side, this is not fixed
//! here — and it is actually welcome for JS: the `js_summary.rs` doc
//! already notes that most vulnerable JS code lives in callbacks passed
//! as arguments, a pattern even more dominant than in Python.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use rayon::prelude::*;

use tree_sitter::Node;

pub use super::call_graph::{FileInput, MAX_SCC_FIXPOINT_ITER, NodeKey, SummariesByFile};
use super::js_module_registry::{JsImportInfo, collect_js_imports, resolve_target_file};
use super::js_summary::{JsFunctionInfo, compute_js_summary_with, prepare_js_file};
use super::line_facts::{LinesByFile, RuleLinesByFile, rule_lines_by_file};
use super::prepared::{PreparedFile, PreparedFiles};
use super::transfer::{FunctionSummary, RuleSpecs};
use super::visibility::{ImportEntry, ImportVisibility, Visibility, graph_fingerprint};

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

/// Returns the bindings brought in by a file's imports, indexed by the
/// **local** call name as it appears in that file's code — mirror of
/// `call_graph.rs::resolve_import_bindings`, but simpler: resolution by
/// exact path ([`resolve_target_file`]) leaves no ambiguity to handle
/// (no suffix, no star to merge). An empty `orig_name` or `"*"`
/// (binding for the whole module — default import, plain
/// `require(mod)`, namespace import) produces one `"{local}.{fname}"`
/// edge per function of the target file, like Python's
/// `import mod as m`. A precise `orig_name` (named import /
/// `require` destructuring) produces a direct
/// `local -> (target, orig_name)` edge, only if `orig_name` actually
/// designates a known function of the target file (anti-FP guard
/// identical to Python: never invent a link to an export that doesn't
/// exist).
///
/// Test only since ticket #239: the graph no longer builds this map for
/// every file (see [`resolve_import_entries`]); kept as the oracle its
/// lookups are checked against.
#[cfg(test)]
fn resolve_import_bindings(
    filepath: &str,
    imports: &[JsImportInfo],
    known_files: &HashSet<String>,
    file_function_names: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, NodeKey> {
    let mut out = BTreeMap::new();
    let empty_set: BTreeSet<String> = BTreeSet::new();
    for imp in imports {
        let Some(target) = resolve_target_file(filepath, &imp.specifier, known_files) else {
            continue;
        };
        if imp.orig_name.is_empty() || imp.orig_name == "*" {
            for fname in file_function_names.get(&target).unwrap_or(&empty_set) {
                out.insert(
                    format!("{}.{}", imp.local_name, fname),
                    (target.clone(), fname.clone()),
                );
            }
        } else if file_function_names
            .get(&target)
            .is_some_and(|names| names.contains(&imp.orig_name))
        {
            out.insert(
                imp.local_name.clone(),
                (target.clone(), imp.orig_name.clone()),
            );
        }
    }
    out
}

/// The imports of a file, resolved to analyzed files and kept as written,
/// in source order (ticket #239), instead of the former expansion into one
/// binding per function of each imported module ([`resolve_import_bindings`],
/// now the test oracle). A whole-module import (default import, plain
/// `require(mod)`, namespace import: empty `orig_name` or `"*"`) is a
/// [`ImportEntry::Module`]; a named import or a `require` destructuring is
/// a [`ImportEntry::Function`], only when the target defines that function
/// (anti-FP, as before). The [`ImportVisibility`] built from them answers
/// each name with JavaScript's precedence: the last import binding a name
/// wins, and `local.name` designates any function of the module, a dotted
/// one (`Klass.method`) too.
fn resolve_import_entries(
    filepath: &str,
    imports: &[JsImportInfo],
    known_files: &HashSet<String>,
    file_function_names: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<ImportEntry> {
    let mut entries = Vec::new();
    for imp in imports {
        let Some(target) = resolve_target_file(filepath, &imp.specifier, known_files) else {
            continue;
        };
        if imp.orig_name.is_empty() || imp.orig_name == "*" {
            entries.push(ImportEntry::Module {
                local: imp.local_name.clone(),
                target,
            });
        } else if file_function_names
            .get(&target)
            .is_some_and(|names| names.contains(&imp.orig_name))
        {
            entries.push(ImportEntry::Function {
                local: imp.local_name.clone(),
                target,
                name: imp.orig_name.clone(),
            });
        }
    }
    entries
}

/// Local call name of a `call_expression` node: `foo` for
/// `foo(...)`, `obj.method` for `obj.method(...)` (identifier
/// receiver), `this.method` for `this.method(...)` (resolved later by
/// [`outgoing_edges`] within the current file, not here — this is not
/// an import binding). `None` for forms not statically resolvable
/// (computed receiver/complex expression, method chaining) — stays
/// over-approximated as today (no edge, not an error).
fn call_local_name(call_node: Node, source: &[u8]) -> Option<String> {
    let func = call_node.child_by_field_name("function")?;
    match func.kind() {
        "identifier" => Some(text(func, source)),
        "member_expression" => {
            let obj = func.child_by_field_name("object")?;
            let prop = func.child_by_field_name("property")?;
            if prop.kind() != "property_identifier" {
                return None;
            }
            match obj.kind() {
                "identifier" => Some(format!("{}.{}", text(obj, source), text(prop, source))),
                "this" => Some(format!("this.{}", text(prop, source))),
                _ => None,
            }
        }
        _ => None,
    }
}

fn walk_calls<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    if node.kind() == "call_expression" {
        out.push(node);
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        walk_calls(child, out);
    }
}

/// Returns the outgoing edges of a JS function: local call name →
/// target node. Resolves three cases: a call to a function in the
/// **same file** (`local_names`), a call to an **imported** function
/// (`import_bindings`), a `this.method()` call resolved in the current
/// file (see module doc). Other forms remain unresolved.
fn outgoing_edges(
    fn_info: &JsFunctionInfo,
    source: &[u8],
    filepath: &str,
    local_names: &BTreeSet<String>,
    visibility: &dyn Visibility,
) -> BTreeMap<String, NodeKey> {
    let mut edges = BTreeMap::new();
    let mut calls = Vec::new();
    walk_calls(fn_info.body_node, &mut calls);
    for call_node in calls {
        let Some(local_name) = call_local_name(call_node, source) else {
            continue;
        };
        if edges.contains_key(&local_name) {
            continue;
        }
        if let Some(method) = local_name.strip_prefix("this.") {
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

// ============================================================================
// JsCallGraph
// ============================================================================

/// Call graph of a set of JS/TS files analyzed together — same
/// contract as `call_graph::CallGraph` (see its doc for the detail of
/// the fields, identical here).
#[derive(Default)]
pub struct JsCallGraph<'tree> {
    pub nodes: BTreeMap<NodeKey, JsFunctionInfo<'tree>>,
    pub edges: BTreeMap<NodeKey, BTreeMap<String, NodeKey>>,
    /// The resolved imports of each file, looked up on demand (ticket
    /// #239), instead of the former per-file map of every imported name.
    visibility: Arc<ImportVisibility>,
    source_by_file: BTreeMap<String, &'tree [u8]>,
    /// Every file of the graph prepared once for all the rules of the
    /// scan (ticket #192): read for the summaries and handed to the
    /// taint analysis of each file ([`Self::prepared_file`]).
    prepared: PreparedFiles<'tree, JsFunctionInfo<'tree>>,
}

impl<'tree> JsCallGraph<'tree> {
    /// The prepared form of `filepath`, one of the graph's files, for
    /// the taint analysis of each rule (ticket #192).
    pub fn prepared_file(
        &self,
        filepath: &str,
    ) -> Option<&PreparedFile<'tree, JsFunctionInfo<'tree>>> {
        self.prepared.file(filepath)
    }

    /// Builds the complete graph (nodes + edges + import bindings) from
    /// a set of already-parsed JS/TS files.
    pub fn build(files: &[FileInput<'tree>]) -> Self {
        let mut graph = JsCallGraph::default();
        let mut file_function_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut imports_by_file: BTreeMap<String, Vec<JsImportInfo>> = BTreeMap::new();

        // Each file is prepared once for every rule of the scan (ticket
        // #192), in parallel: a file only reads its own tree. Its
        // collected functions are the graph nodes.
        let per_file: Vec<_> = files
            .par_iter()
            .map(|f| {
                (
                    prepare_js_file(f.root, f.source),
                    collect_js_imports(f.root, f.source),
                )
            })
            .collect();
        for (f, (prepared, imports)) in files.iter().zip(per_file) {
            file_function_names.insert(
                f.filepath.clone(),
                prepared
                    .functions
                    .iter()
                    .map(|function| function.info.name.clone())
                    .collect(),
            );
            for (index, function) in prepared.functions.iter().enumerate() {
                let key = (f.filepath.clone(), function.info.name.clone());
                graph.prepared.index_node(key.clone(), index);
                graph.nodes.insert(key, function.info.clone());
            }
            graph.prepared.insert_file(f.filepath.clone(), prepared);
            imports_by_file.insert(f.filepath.clone(), imports);
            graph.source_by_file.insert(f.filepath.clone(), f.source);
        }

        let known_files: Vec<String> = file_function_names.keys().cloned().collect();
        // Built once (ticket #239): the resolution used to build it again
        // for every import.
        let known_set: HashSet<String> = known_files.iter().cloned().collect();
        let entries = known_files
            .iter()
            .map(|filepath| {
                let imports = imports_by_file.get(filepath).cloned().unwrap_or_default();
                (
                    filepath.clone(),
                    resolve_import_entries(filepath, &imports, &known_set, &file_function_names),
                )
            })
            .collect();
        graph.visibility = Arc::new(ImportVisibility::new(
            entries,
            BTreeMap::new(),
            BTreeMap::new(),
            file_function_names.clone(),
            true,
            false,
        ));
        for filepath in &known_files {
            let local_names = file_function_names
                .get(filepath)
                .cloned()
                .unwrap_or_default();
            let source = graph.source_by_file[filepath];
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
                    &graph.nodes[&key],
                    source,
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
    /// identical to `call_graph::CallGraph::strongly_connected_components`.
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
        Some(Arc::new(compute_js_summary_with(
            &function.info,
            function.body.as_ref()?,
            &specs,
            lines,
        )))
    }

    /// Computes the summaries of every function in the graph — same
    /// algorithm and same `(own, extra)` return contract as
    /// `call_graph::CallGraph::resolve_summaries` (see its doc).
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
    /// defining a changed function and those importing one. Computed once
    /// per rule (ticket #239), see `call_graph::CallGraph::readers`.
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

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
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
        let src = b"function helper(x) {}\nfunction main() { helper(1); }\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.js".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = JsCallGraph::build(&files);
        let edges = &graph.edges[&("m.js".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("helper"),
            Some(&("m.js".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_build_keeps_two_anonymous_callbacks_of_one_line_as_two_nodes() {
        // Ticket #193: with a line-only synthetic name, the second
        // callback replaced the first one in the nodes keyed by
        // (file, name).
        let src = b"p.then(function (a) { f(a); }).catch(function (e) { g(e); });\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.js".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = JsCallGraph::build(&files);
        assert_eq!(graph.nodes.len(), 2);
    }

    #[test]
    fn test_build_cross_file_import_edge_named() {
        let src_a = b"import { helper } from './utils';\nfunction main() { helper(1); }\n".to_vec();
        let src_u = b"export function helper(x) {}\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.js".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.js".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = JsCallGraph::build(&files);
        let edges = &graph.edges[&("a.js".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("helper"),
            Some(&("utils.js".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_build_cross_file_require_whole_module_member_call() {
        let src_a =
            b"const utils = require('./utils');\nfunction main() { utils.helper(1); }\n".to_vec();
        let src_u = b"function helper(x) {}\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.js".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.js".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = JsCallGraph::build(&files);
        let edges = &graph.edges[&("a.js".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("utils.helper"),
            Some(&("utils.js".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_this_method_call_resolved_same_file() {
        let src = b"class C {\n  helper(x) {}\n  main() { this.helper(1); }\n}\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.js".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = JsCallGraph::build(&files);
        let edges = &graph.edges[&("m.js".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("this.helper"),
            Some(&("m.js".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_bare_import_yields_no_edge() {
        let src_a = b"import x from 'lodash';\nfunction main() { x.helper(1); }\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let files = vec![FileInput {
            filepath: "a.js".to_string(),
            root: tree_a.root_node(),
            source: &src_a,
        }];
        let graph = JsCallGraph::build(&files);
        let edges = &graph.edges[&("a.js".to_string(), "main".to_string())];
        assert!(edges.get("x.helper").is_none());
    }

    #[test]
    fn test_resolve_summaries_multi_hop_sink_propagation() {
        // a.js: main(userInput) -> helper() (utils.js) -> db.query(cmd):
        // the sink must be resolved at the level of main() via helper's
        // summary (multi-hop cross-file resolution).
        let src_a = b"const { helper } = require('./utils');\nfunction main(userInput) { helper(userInput); }\n".to_vec();
        let src_u = b"function helper(cmd) { db.query(cmd); }\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.js".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.js".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = JsCallGraph::build(&files);
        let specs = specs_with(vec![SinkSpec::new("db.query")]);
        let (own, _extra) = graph.resolve_summaries(&specs, None);

        let helper_summary = &own["utils.js"]["helper"];
        assert!(
            helper_summary.sink_param_findings.contains_key(&0),
            "helper: param 0 atteint db.query"
        );
        let main_summary = &own["a.js"]["main"];
        assert!(
            main_summary.sink_param_findings.contains_key(&0),
            "main: param 0 (userInput) atteint le sink via helper (multi-hop)"
        );
    }

    #[test]
    fn test_resolve_summaries_mutual_recursion_does_not_hang() {
        let src = b"function f(x) { return g(x); }\nfunction g(y) { return f(y); }\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.js".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = JsCallGraph::build(&files);
        let specs = specs_with(vec![]);
        let (own, _extra) = graph.resolve_summaries(&specs, None);
        assert!(own["m.js"].contains_key("f"));
        assert!(own["m.js"].contains_key("g"));
    }

    #[test]
    fn test_imported_summaries_found_by_local_import_name() {
        let src_a = b"const utils = require('./utils');\n".to_vec();
        let src_u = b"function helper() {}\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.js".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.js".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = JsCallGraph::build(&files);
        let specs = specs_with(vec![]);
        // An imported module function, even not called, is found by the
        // name `a.js` calls it with; since ticket #239 through the graph's
        // visibility (`RuleSpecs::summary_fallback`), no longer copied
        // into `extra`.
        let resolved = graph.resolve_summaries_incremental(&specs, None, None);
        assert!(resolved.extra.is_empty(), "nothing copied into extra");
        let visibility: Arc<dyn crate::scan::dataflow::visibility::Visibility> =
            graph.visibility().clone();
        let lookup = crate::scan::dataflow::visibility::FileSummaries::new(
            visibility,
            "a.js",
            resolved.all.clone(),
        );
        use crate::scan::dataflow::transfer::SummaryLookup;
        assert!(
            lookup.get("utils.helper").is_some(),
            "an imported module function, even not called, is found from a.js"
        );
        assert!(lookup.get("utils.missing").is_none());
    }

    /// Ticket #239: the imports kept as written and looked up on demand
    /// answer every name as the former per-file map did
    /// (`resolve_import_bindings`, the oracle), and the files to redo for a
    /// changed function are exactly those whose former map held it.
    #[test]
    fn test_lookups_match_the_materialized_import_maps() {
        let sources: &[(&str, &str)] = &[
            (
                "lib/utils.js",
                "function helper() {}\nfunction other() {}\nclass K { m() {} }\nmodule.exports = { helper, other, K };\n",
            ),
            (
                "lib/extra.js",
                "function helper() {}\nfunction unique() {}\nmodule.exports = { helper, unique };\n",
            ),
            ("lib/index.js", "function fromIndex() {}\n"),
            (
                "a.js",
                "var u = require('./lib/utils');\nconst { helper } = require('./lib/utils');\nconst { helper: h2, unique } = require('./lib/extra');\nimport * as ns from './lib/extra';\nimport dflt from './lib/utils';\nimport { other } from './lib/utils';\nvar u = require('./lib/extra');\nconst idx = require('./lib');\nconst { missing } = require('./lib/extra');\n",
            ),
            (
                "b.js",
                "const { other } = require('./lib/utils');\nconst lib = require('lodash');\n",
            ),
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
        let graph = JsCallGraph::build(&files);
        let mut names: BTreeMap<String, BTreeSet<String>> = sources
            .iter()
            .map(|(path, _)| (path.to_string(), BTreeSet::new()))
            .collect();
        for (file, name) in graph.nodes.keys() {
            names.entry(file.clone()).or_default().insert(name.clone());
        }
        let known: HashSet<String> = names.keys().cloned().collect();
        let all_names: BTreeSet<String> = names.values().flatten().cloned().collect();
        let mut probes = all_names.clone();
        for local in [
            "u", "helper", "h2", "unique", "ns", "dflt", "other", "idx", "missing", "lib",
            "nothing",
        ] {
            probes.insert(local.to_string());
            for name in &all_names {
                probes.insert(format!("{local}.{name}"));
            }
        }
        let visibility = graph.visibility();
        let mut maps = BTreeMap::new();
        for ((path, src), tree) in sources.iter().zip(&trees) {
            let imports = collect_js_imports(tree.root_node(), src.as_bytes());
            let former = resolve_import_bindings(path, &imports, &known, &names);
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
        assert_eq!(
            visibility.binding("a.js", "u.helper"),
            at("lib/extra.js", "helper")
        );
        assert_eq!(
            visibility.binding("a.js", "u.other"),
            at("lib/utils.js", "other")
        );
        assert_eq!(
            visibility.binding("a.js", "h2"),
            at("lib/extra.js", "helper")
        );
        assert_eq!(visibility.binding("a.js", "missing"), None);
    }
}
