//! Persistent call graph (Java) — multi-hop interprocedural
//! resolution. Faithful port of `Audit/sca/dataflow/java_call_graph.py`.
//!
//! Mirrors `call_graph.rs` (Python), same role: replace a
//! 1-hop resolution (import → already-computed summary, itself blind to
//! its own calls) with a real graph (nodes = methods/
//! constructors, edges = resolved calls, including intra-file) and
//! a summary computation in topological order (callees before callers).
//!
//! **Not a port of `_outgoing_edges`**: Java's call semantics
//! (enclosing class, `this`/`super`, package visibility, binding
//! via declared type) has nothing in common with Python's import
//! resolution — see `java_module_registry.rs` for the same distinction on the
//! import-resolution side.
//!
//! **`topological_order`/`resolve_summaries`, on the other hand, are duplicated
//! as-is in their structure** (post-order DFS, anti-FP cycles) —
//! NOT the SCC/Tarjan fixed point of `call_graph.rs` (Decision #3, a
//! deliberate correction on the Python side only): on the Java side, the
//! actual Python source (`java_call_graph.py`) never received this
//! correction — a choice already settled in the real code, not a
//! simplification introduced here. A node in a cycle is computed
//! last, with the summaries of the cycle's not-yet-resolved links
//! (better to miss a flow than invent a false one, the same
//! philosophy as `call_graph.rs`).
//!
//! Since ticket #284 that order and the summary resolution live in
//! `class_call_graph.rs`, shared with the C# graph (`csharp_call_graph.rs`),
//! moved there unchanged; this file keeps what is Java: the edges and the
//! visibility (packages, imports).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rayon::prelude::*;

use tree_sitter::Node;

pub use super::call_graph::{FileInput, NodeKey, SummariesByFile};
use super::class_call_graph::{
    ClassGraphView, ClassLanguageHooks, GraphCaches, resolve_in_topological_order,
    topological_order,
};
use super::java_module_registry::{
    JavaImportInfo, build_fqcn_index, collect_java_class_names, collect_java_imports,
    collect_java_superclass, collect_package,
};
use super::java_summary::{
    JavaFunctionInfo, add_bare_name_aliases, collect_java_field_types, collect_java_local_types,
    compute_java_summary_with, prepare_java_file,
};
use super::java_visibility::JavaVisibility;
use super::line_facts::{LinesByFile, RuleLines};
use super::prepared::{PreparedCfg, PreparedFile, PreparedFiles};
use super::transfer::RuleSpecs;
use super::visibility::{Visibility, graph_fingerprint};

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

fn simple_type_text(type_node: Node, source: &[u8]) -> String {
    let t = text(type_node, source);
    let before_generic = t.split('<').next().unwrap_or(&t).to_string();
    before_generic
        .rsplit('.')
        .next()
        .unwrap_or(&before_generic)
        .to_string()
}

/// Generic DFS over a tree-sitter subtree, returning all
/// `method_invocation` nodes encountered.
fn iter_method_invocations<'tree>(body: Node<'tree>) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        if n.kind() == "method_invocation" {
            out.push(n);
        }
        let mut w = n.walk();
        stack.extend(n.children(&mut w));
    }
    out
}

/// Structural metadata for a Java file, computed once
/// (independent of the rule specs — like `call_graph.rs`).
struct FileInfo {
    package: String,
    class_names: Vec<String>,
    imports: Vec<JavaImportInfo>,
    superclass: BTreeMap<String, Option<String>>,
    /// Fields + locals merged (locals take priority).
    type_map: BTreeMap<String, String>,
}

/// Call graph for a set of Java files analyzed together.
///
/// `nodes`: every known method/constructor, indexed by
/// `(file, "ClassName.methodName")`.
/// `edges`: for each node, its resolved outgoing calls (local call
/// key — EXACTLY the form that `transfer.rs::eval_call`
/// computes via `canon_callee`/its fallback logic — → target node).
/// `visibility`: what each file sees of the others (classes of its
/// package and of its imports, static imports), looked up on demand —
/// the multi-hop equivalent of the 1-hop resolution. It replaces the
/// former per-file `import_bindings` map (ticket #239, see
/// `java_visibility.rs`).
#[derive(Default)]
pub struct JavaCallGraph<'tree> {
    pub nodes: BTreeMap<NodeKey, JavaFunctionInfo<'tree>>,
    pub edges: BTreeMap<NodeKey, BTreeMap<String, NodeKey>>,
    visibility: Arc<JavaVisibility>,
    source_by_file: BTreeMap<String, &'tree [u8]>,
    /// Every file of the graph prepared once for all the rules of the
    /// scan (ticket #192): read for the summaries and handed to the
    /// taint analysis of each file ([`Self::prepared_file`]).
    prepared: PreparedFiles<'tree, JavaFunctionInfo<'tree>>,
    /// Lazy caches derived from the graph structure only, identical for
    /// every rule (see `class_call_graph::GraphCaches`).
    caches: GraphCaches,
}

impl<'tree> JavaCallGraph<'tree> {
    /// The prepared form of `filepath`, one of the graph's files, for
    /// the taint analysis of each rule (ticket #192).
    pub fn prepared_file(
        &self,
        filepath: &str,
    ) -> Option<&PreparedFile<'tree, JavaFunctionInfo<'tree>>> {
        self.prepared.file(filepath)
    }

    /// What each file of the graph sees of the others, shared with the
    /// taint analysis of each file (ticket #239).
    pub fn visibility(&self) -> &Arc<JavaVisibility> {
        &self.visibility
    }

    /// The nodes of `filepath`, in name order. A range of `nodes`, not a
    /// scan of every node: looked up once per file, a full scan cost a time
    /// growing with the square of the number of files (ticket #239).
    fn file_node_keys<'a>(&'a self, filepath: &'a str) -> impl Iterator<Item = &'a NodeKey> + 'a {
        self.nodes
            .range((filepath.to_string(), String::new())..)
            .map(|(key, _)| key)
            .take_while(move |key| key.0 == filepath)
    }

    /// Builds the complete graph (nodes + edges + what each file sees)
    /// from a set of already-parsed Java files.
    pub fn build(files: &[FileInput<'tree>]) -> Self {
        let mut graph = JavaCallGraph::default();

        let mut file_info: BTreeMap<String, FileInfo> = BTreeMap::new();
        let mut class_names_by_file: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
        let mut file_function_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        // Each file is prepared once for every rule of the scan (ticket
        // #192), in parallel: a file only reads its own tree. Its
        // collected methods are the graph nodes.
        let per_file: Vec<_> = files
            .par_iter()
            .map(|f| prepare_java_file(f.root, f.source))
            .collect();
        for (f, prepared) in files.iter().zip(per_file) {
            let mut names = BTreeSet::new();
            for (index, function) in prepared.functions.iter().enumerate() {
                names.insert(function.info.name.clone());
                let key = (f.filepath.clone(), function.info.name.clone());
                graph.prepared.index_node(key.clone(), index);
                graph.nodes.insert(key, function.info.clone());
            }
            graph.prepared.insert_file(f.filepath.clone(), prepared);
            file_function_names.insert(f.filepath.clone(), names);
            graph.source_by_file.insert(f.filepath.clone(), f.source);

            let package = collect_package(f.root, f.source);
            let class_names = collect_java_class_names(f.root, f.source);
            class_names_by_file.insert(f.filepath.clone(), (package.clone(), class_names.clone()));

            // Locals take priority over fields (more precise scope) —
            // MUST stay in sync with the same merge done on the
            // scan executor side (same logical dict), see the doc of
            // `java_summary.rs::collect_java_field_types`.
            let mut type_map = collect_java_field_types(f.root, f.source);
            type_map.extend(collect_java_local_types(f.root, f.source));

            file_info.insert(
                f.filepath.clone(),
                FileInfo {
                    package,
                    class_names,
                    imports: collect_java_imports(f.root, f.source),
                    superclass: collect_java_superclass(f.root, f.source),
                    type_map,
                },
            );
        }

        let fqcn_index = build_fqcn_index(&class_names_by_file);
        let imports_by_file: BTreeMap<String, Vec<JavaImportInfo>> = file_info
            .iter()
            .map(|(file, info)| (file.clone(), info.imports.clone()))
            .collect();
        graph.visibility = Arc::new(JavaVisibility::new(
            &class_names_by_file,
            &imports_by_file,
            &fqcn_index,
            file_function_names,
        ));

        for f in files {
            let info = &file_info[&f.filepath];
            let local_class_names: BTreeSet<String> = info.class_names.iter().cloned().collect();
            let statics = graph.visibility.statics(&f.filepath);
            let fn_keys: Vec<NodeKey> = graph.file_node_keys(&f.filepath).cloned().collect();
            let mut file_edges = Vec::with_capacity(fn_keys.len());
            for key in fn_keys {
                let enclosing_class = key.1.rsplit_once('.').map(|(c, _)| c).unwrap_or("");
                let edges = outgoing_edges(
                    &graph.nodes[&key],
                    &f.filepath,
                    enclosing_class,
                    &local_class_names,
                    info,
                    &graph.visibility,
                    statics,
                    &graph.nodes,
                    f.source,
                );
                file_edges.push((key, edges));
            }
            graph.edges.extend(file_edges);
        }

        graph
    }

    /// Returns a callees-before-callers order (post-order DFS). A
    /// cycle leaves the revisited link unreordered: it will be computed
    /// without that particular callee being resolved yet (no
    /// invented flow). Shared with C# (`class_call_graph::topological_order`).
    pub fn topological_order(&self) -> Vec<NodeKey> {
        topological_order(&self.nodes, &self.edges)
    }

    /// Computes summaries for all methods in the graph, in topological
    /// order, seeding `specs.summaries` with already-resolved
    /// summaries (same file or cross-file) — multi-hop resolution.
    /// Returns `(own, extra)`, the same shapes as `CallGraph::
    /// resolve_summaries` (Python).
    pub fn resolve_summaries(
        &self,
        base_specs: &RuleSpecs,
        source_lines_by_file: Option<&LinesByFile>,
    ) -> (SummariesByFile, SummariesByFile) {
        let resolved = self.resolve_summaries_incremental(base_specs, source_lines_by_file, None);
        (resolved.own, resolved.extra)
    }

    /// `resolve_summaries`, reusing the summaries of a previous scan where
    /// they cannot have changed (scan cache, issue #183). The algorithm
    /// (plain topological order, bare-name and call-site aliases) lives in
    /// `class_call_graph::resolve_in_topological_order`, shared with C#
    /// since ticket #284; it was written here first and moved unchanged.
    pub fn resolve_summaries_incremental(
        &self,
        base_specs: &RuleSpecs,
        source_lines_by_file: Option<&LinesByFile>,
        reuse: Option<&super::call_graph::SummaryReuse>,
    ) -> super::call_graph::ResolvedSummaries {
        resolve_in_topological_order(
            ClassGraphView {
                order: self.caches.topo_order(&self.nodes, &self.edges),
                edges: &self.edges,
                key_targets: self.caches.key_targets(&self.edges),
                prepared: &self.prepared,
                visibility: self.visibility.as_ref(),
                last_positions: self.caches.last_positions(&self.nodes, &self.edges),
            },
            ClassLanguageHooks {
                compute: |info: &JavaFunctionInfo<'tree>,
                          body: &PreparedCfg<'tree>,
                          specs: &RuleSpecs,
                          lines: Option<&RuleLines>| {
                    compute_java_summary_with(info, body, specs, lines)
                },
                add_bare_name_aliases,
            },
            base_specs,
            source_lines_by_file,
            reuse,
        )
    }

    /// The files whose cached findings no longer hold because they read a
    /// summary in `changed`: the files defining a changed method, and those
    /// that may call one ([`JavaVisibility`]'s `readers_of`, a superset).
    /// Computed once per rule (ticket #239): asking it file by file scanned
    /// every changed summary for every file.
    pub fn readers(&self, changed: &BTreeSet<NodeKey>) -> BTreeSet<String> {
        let mut readers = self.visibility.readers_of(changed);
        readers.extend(changed.iter().map(|node| node.0.clone()));
        readers
    }

    /// What, besides its own text, decides the analysis of `file`: the
    /// edges of its methods, their names, and what it sees of the other
    /// files ([`JavaVisibility`]): one digest per package and import instead
    /// of the former one line per method of every visible class (ticket
    /// #239).
    pub fn dependency_fingerprint(&self, file: &str) -> String {
        graph_fingerprint(&self.edges, &self.nodes, self.visibility.as_ref(), file)
    }
}

/// Returns the file defining `class_name` as seen from `filepath` —
/// the file itself first, otherwise via visible classes (same
/// package or import). `None` if unknown (anti-FP, no invention).
fn resolve_class_target(
    class_name: &str,
    filepath: &str,
    local_class_names: &BTreeSet<String>,
    visibility: &JavaVisibility,
) -> Option<String> {
    if local_class_names.contains(class_name) {
        return Some(filepath.to_string());
    }
    visibility
        .visible_class(filepath, class_name)
        .map(str::to_string)
}

/// Returns the outgoing edges of a method/constructor — one call
/// site per local key (the first resolution encountered wins,
/// as on the Python side).
#[allow(clippy::too_many_arguments)]
fn outgoing_edges<'tree>(
    fn_info: &JavaFunctionInfo<'tree>,
    filepath: &str,
    enclosing_class: &str,
    local_class_names: &BTreeSet<String>,
    info: &FileInfo,
    visibility: &JavaVisibility,
    static_bindings: &BTreeMap<String, NodeKey>,
    all_nodes: &BTreeMap<NodeKey, JavaFunctionInfo<'tree>>,
    source: &[u8],
) -> BTreeMap<String, NodeKey> {
    let mut edges: BTreeMap<String, NodeKey> = BTreeMap::new();

    let try_same_class = |name: &str| -> Option<NodeKey> {
        let key = (filepath.to_string(), format!("{enclosing_class}.{name}"));
        if all_nodes.contains_key(&key) {
            Some(key)
        } else {
            None
        }
    };

    for call in iter_method_invocations(fn_info.body_node) {
        let Some(name_node) = call.child_by_field_name("name") else {
            continue;
        };
        let name = text(name_node, source);
        let obj = call.child_by_field_name("object");

        let Some(obj) = obj else {
            // Bare call: same class first, then static import.
            if edges.contains_key(&name) {
                continue;
            }
            let target = try_same_class(&name).or_else(|| static_bindings.get(&name).cloned());
            if let Some(t) = target {
                edges.insert(name, t);
            }
            continue;
        };

        match obj.kind() {
            "this" => {
                let local_key = format!("this.{name}");
                if edges.contains_key(&local_key) {
                    continue;
                }
                if let Some(t) = try_same_class(&name) {
                    edges.insert(local_key, t);
                }
            }
            "super" => {
                let local_key = format!("super.{name}");
                if edges.contains_key(&local_key) {
                    continue;
                }
                if let Some(Some(super_name)) = info.superclass.get(enclosing_class)
                    && let Some(target_file) =
                        resolve_class_target(super_name, filepath, local_class_names, visibility)
                {
                    let target = (target_file, format!("{super_name}.{name}"));
                    if all_nodes.contains_key(&target) {
                        edges.insert(local_key, target);
                    }
                }
            }
            "object_creation_expression" => {
                let ctor_type_text = obj
                    .child_by_field_name("type")
                    .map(|t| simple_type_text(t, source));
                let Some(ctor_type_text) = ctor_type_text.filter(|s| !s.is_empty()) else {
                    continue;
                };
                let local_key = format!("{ctor_type_text}.{name}");
                if edges.contains_key(&local_key) {
                    continue;
                }
                if let Some(target_file) =
                    resolve_class_target(&ctor_type_text, filepath, local_class_names, visibility)
                {
                    let target = (target_file, local_key.clone());
                    if all_nodes.contains_key(&target) {
                        edges.insert(local_key, target);
                    }
                }
            }
            "identifier" => {
                let recv = text(obj, source);
                let local_key = format!("{recv}.{name}");
                if edges.contains_key(&local_key) {
                    continue;
                }
                // 1. `recv` is itself the name of a visible class
                //    (qualified static call, e.g. `Helper.doThing()`).
                let mut target_file =
                    resolve_class_target(&recv, filepath, local_class_names, visibility);
                let mut resolved_class = recv.clone();
                if target_file.is_none() {
                    // 2. `recv` is a variable/field with a known declared type.
                    if let Some(declared_type) = info.type_map.get(&recv) {
                        target_file = resolve_class_target(
                            declared_type,
                            filepath,
                            local_class_names,
                            visibility,
                        );
                        resolved_class = declared_type.clone();
                    }
                }
                if let Some(tf) = target_file {
                    let target = (tf, format!("{resolved_class}.{name}"));
                    if all_nodes.contains_key(&target) {
                        edges.insert(local_key, target);
                    }
                }
            }
            _ => {
                // Multi-level chain (`a.b.method()`) or a form not
                // handled in v1 — left unresolved (anti-FP), see the
                // module's non-goals.
            }
        }
    }

    edges
}

// ============================================================================
// Tests — mirror of `Audit/tests/dataflow/test_java_call_graph.py`.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::line_facts::SourceLines;
    use crate::scan::dataflow::transfer::{SinkSpec, SourceSpec};
    use tree_sitter::Parser;

    fn parse_java(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_java::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    /// Parses a set of Java `(path, source)` files and exposes
    /// the `JavaCallGraph` built on top of them to `f` — avoids letting
    /// a borrowed graph escape the scope of the trees it
    /// depends on.
    fn with_graph<R>(files: &[(&str, &str)], f: impl FnOnce(&JavaCallGraph) -> R) -> R {
        let trees: Vec<(String, String, tree_sitter::Tree)> = files
            .iter()
            .map(|(path, src)| {
                let tree = parse_java(src);
                assert!(
                    !tree.root_node().has_error(),
                    "syntaxe Java invalide dans {path} : {src:?}"
                );
                (path.to_string(), src.to_string(), tree)
            })
            .collect();
        let file_inputs: Vec<FileInput> = trees
            .iter()
            .map(|(path, src, tree)| FileInput {
                filepath: path.clone(),
                root: tree.root_node(),
                source: src.as_bytes(),
            })
            .collect();
        let graph = JavaCallGraph::build(&file_inputs);
        f(&graph)
    }

    fn sqli_specs() -> RuleSpecs {
        RuleSpecs {
            rule_id: "test-sqli".to_string(),
            severity: "HIGH".to_string(),
            cwe: None,
            message: "test finding".to_string(),
            sources: vec![SourceSpec::new("*.getParameter", "http")],
            sinks: vec![SinkSpec::new("*.execute")],
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
            summary_fallback: None,
            exprs: None,
        }
    }

    fn key(fp: &str, name: &str) -> NodeKey {
        (fp.to_string(), name.to_string())
    }

    // -------------------------------------------------------- build: edges

    #[test]
    fn test_bare_call_same_class() {
        with_graph(
            &[("A.java", "class A { void foo() { bar(); } void bar() {} }")],
            |graph| {
                assert_eq!(
                    graph.edges[&key("A.java", "A.foo")],
                    BTreeMap::from([("bar".to_string(), key("A.java", "A.bar"))])
                );
            },
        );
    }

    #[test]
    fn test_this_call_same_class() {
        with_graph(
            &[(
                "A.java",
                "class A { void foo() { this.bar(); } void bar() {} }",
            )],
            |graph| {
                assert_eq!(
                    graph.edges[&key("A.java", "A.foo")],
                    BTreeMap::from([("this.bar".to_string(), key("A.java", "A.bar"))])
                );
            },
        );
    }

    #[test]
    fn test_super_call_same_file() {
        with_graph(
            &[(
                "A.java",
                "class Base { void bar() {} } class Impl extends Base { void foo() { super.bar(); } }",
            )],
            |graph| {
                assert_eq!(
                    graph.edges[&key("A.java", "Impl.foo")],
                    BTreeMap::from([("super.bar".to_string(), key("A.java", "Base.bar"))])
                );
            },
        );
    }

    #[test]
    fn test_super_call_cross_file() {
        with_graph(
            &[
                ("Base.java", "package p; class Base { void bar() {} }"),
                (
                    "Impl.java",
                    "package p; class Impl extends Base { void foo() { super.bar(); } }",
                ),
            ],
            |graph| {
                assert_eq!(
                    graph.edges[&key("Impl.java", "Impl.foo")],
                    BTreeMap::from([("super.bar".to_string(), key("Base.java", "Base.bar"))])
                );
            },
        );
    }

    #[test]
    fn test_cross_file_edge_via_explicit_import() {
        with_graph(
            &[
                (
                    "Helper.java",
                    "package com.acme.util; class Helper { void run() {} }",
                ),
                (
                    "Api.java",
                    "package com.acme.service;\nimport com.acme.util.Helper;\nclass Api { void foo() { Helper h = new Helper(); h.run(); } }",
                ),
            ],
            |graph| {
                assert_eq!(
                    graph.edges[&key("Api.java", "Api.foo")],
                    BTreeMap::from([("h.run".to_string(), key("Helper.java", "Helper.run"))])
                );
            },
        );
    }

    #[test]
    fn test_cross_file_edge_same_package_no_import() {
        with_graph(
            &[
                ("Helper.java", "package p; class Helper { void run() {} }"),
                (
                    "Api.java",
                    "package p; class Api { void foo() { Helper.run(); } }",
                ),
            ],
            |graph| {
                assert_eq!(
                    graph.edges[&key("Api.java", "Api.foo")],
                    BTreeMap::from([("Helper.run".to_string(), key("Helper.java", "Helper.run"))])
                );
            },
        );
    }

    #[test]
    fn test_field_typed_receiver_edge() {
        with_graph(
            &[(
                "A.java",
                "class A { private final Helper helper; void foo() { helper.run(); } } class Helper { void run() {} }",
            )],
            |graph| {
                assert_eq!(
                    graph.edges[&key("A.java", "A.foo")],
                    BTreeMap::from([("helper.run".to_string(), key("A.java", "Helper.run"))])
                );
            },
        );
    }

    #[test]
    fn test_local_var_typed_receiver_edge() {
        with_graph(
            &[(
                "A.java",
                "class A { void foo() { Helper h = new Helper(); h.run(); } } class Helper { void run() {} }",
            )],
            |graph| {
                assert_eq!(
                    graph.edges[&key("A.java", "A.foo")],
                    BTreeMap::from([("h.run".to_string(), key("A.java", "Helper.run"))])
                );
            },
        );
    }

    #[test]
    fn test_chained_constructor_call_edge() {
        with_graph(
            &[(
                "A.java",
                "class A { void foo() { new Helper().run(); } } class Helper { void run() {} }",
            )],
            |graph| {
                assert_eq!(
                    graph.edges[&key("A.java", "A.foo")],
                    BTreeMap::from([("Helper.run".to_string(), key("A.java", "Helper.run"))])
                );
            },
        );
    }

    #[test]
    fn test_static_import_bare_call_edge() {
        with_graph(
            &[
                (
                    "Const.java",
                    "package p; class Const { static void log() {} }",
                ),
                (
                    "Api.java",
                    "package q;\nimport static p.Const.log;\nclass Api { void foo() { log(); } }",
                ),
            ],
            |graph| {
                assert_eq!(
                    graph.edges[&key("Api.java", "Api.foo")],
                    BTreeMap::from([("log".to_string(), key("Const.java", "Const.log"))])
                );
            },
        );
    }

    #[test]
    fn test_unresolvable_receiver_has_no_edge() {
        with_graph(
            &[("A.java", "class A { void foo(Object o) { o.toString(); } }")],
            |graph| {
                assert_eq!(graph.edges[&key("A.java", "A.foo")], BTreeMap::new());
            },
        );
    }

    #[test]
    fn test_multi_level_chain_not_resolved() {
        with_graph(
            &[(
                "A.java",
                "class A { void foo() { this.helper.run(); } Helper helper; } class Helper { void run() {} }",
            )],
            |graph| {
                assert_eq!(graph.edges[&key("A.java", "A.foo")], BTreeMap::new());
            },
        );
    }

    #[test]
    fn test_unknown_class_import_no_edge() {
        with_graph(
            &[(
                "Api.java",
                "package q; class Api { void foo() { Missing.run(); } }",
            )],
            |graph| {
                assert_eq!(graph.edges[&key("Api.java", "Api.foo")], BTreeMap::new());
            },
        );
    }

    // ---------------------------------------------------- topological_order

    #[test]
    fn test_callee_before_caller() {
        with_graph(
            &[("A.java", "class A { void foo() { bar(); } void bar() {} }")],
            |graph| {
                let order = graph.topological_order();
                let bar_idx = order.iter().position(|k| k == &key("A.java", "A.bar"));
                let foo_idx = order.iter().position(|k| k == &key("A.java", "A.foo"));
                assert!(bar_idx < foo_idx);
            },
        );
    }

    #[test]
    fn test_self_recursive_cycle_terminates() {
        with_graph(
            &[("A.java", "class A { void fact() { fact(); } }")],
            |graph| {
                let order = graph.topological_order();
                assert_eq!(order, vec![key("A.java", "A.fact")]);
            },
        );
    }

    // ------------------------------------------------- resolve_summaries

    #[test]
    fn test_transitive_source_reaches_caller_two_hops() {
        let c_src =
            "package p; class C { String getTainted(String v) { return v.getParameter(\"x\"); } }";
        let b_src = "package p; class B { C c = new C(); String wrapper(String v) { return c.getTainted(v); } }";
        let a_src = "package p; class A { B b = new B(); void entry(String v) { String x = b.wrapper(v); stmt.execute(x); } }";
        with_graph(
            &[("C.java", c_src), ("B.java", b_src), ("A.java", a_src)],
            |graph| {
                let lines = BTreeMap::from([
                    (
                        "C.java".to_string(),
                        c_src
                            .lines()
                            .map(str::to_string)
                            .collect::<SourceLines>()
                            .into(),
                    ),
                    (
                        "B.java".to_string(),
                        b_src
                            .lines()
                            .map(str::to_string)
                            .collect::<SourceLines>()
                            .into(),
                    ),
                    (
                        "A.java".to_string(),
                        a_src
                            .lines()
                            .map(str::to_string)
                            .collect::<SourceLines>()
                            .into(),
                    ),
                ]);
                let (own, _extra) = graph.resolve_summaries(&sqli_specs(), Some(&lines));
                assert!(own["C.java"]["C.getTainted"].return_tainted_uncond);
                assert!(
                    own["B.java"]["B.wrapper"].return_tainted_uncond,
                    "le taint inconditionnel de C.getTainted doit se propager à B.wrapper via le graphe multi-sauts"
                );
            },
        );
    }

    #[test]
    fn test_intra_file_sibling_resolution() {
        let src = "class A { String bar(String v) { return v.getParameter(\"x\"); } String foo(String v) { return bar(v); } }";
        with_graph(&[("A.java", src)], |graph| {
            let lines = BTreeMap::from([(
                "A.java".to_string(),
                src.lines()
                    .map(str::to_string)
                    .collect::<SourceLines>()
                    .into(),
            )]);
            let (own, _extra) = graph.resolve_summaries(&sqli_specs(), Some(&lines));
            assert!(own["A.java"]["A.bar"].return_tainted_uncond);
            assert!(own["A.java"]["A.foo"].return_tainted_uncond);
        });
    }

    #[test]
    fn test_cycle_resolves_without_crashing() {
        let src = "class A { void foo(int n) { bar(n); } void bar(int n) { foo(n); } }";
        with_graph(&[("A.java", src)], |graph| {
            let lines = BTreeMap::from([(
                "A.java".to_string(),
                src.lines()
                    .map(str::to_string)
                    .collect::<SourceLines>()
                    .into(),
            )]);
            let (own, _extra) = graph.resolve_summaries(&sqli_specs(), Some(&lines));
            let keys: std::collections::BTreeSet<&String> = own["A.java"].keys().collect();
            assert_eq!(
                keys,
                std::collections::BTreeSet::from([
                    &"A.foo".to_string(),
                    &"A.bar".to_string(),
                    &"foo".to_string(),
                    &"bar".to_string(),
                ])
            );
        });
    }

    // ------------------------------------------------------------------
    // Ticket #239: what a file sees is looked up on demand, with the same
    // answers as the former per-file maps.
    // ------------------------------------------------------------------

    /// The former per-file `import_bindings` construction, kept as the
    /// oracle of `test_lookups_match_the_materialized_maps`: visible
    /// classes (`resolve_visible_classes`), then one entry per method of
    /// each visible class, then the static imports.
    fn oracle_import_bindings(
        visible_classes: &BTreeMap<String, String>,
        static_bindings: &BTreeMap<String, NodeKey>,
        file_function_names: &BTreeMap<String, BTreeSet<String>>,
    ) -> BTreeMap<String, NodeKey> {
        let mut out = BTreeMap::new();
        for (cname, target_file) in visible_classes {
            let prefix = format!("{cname}.");
            if let Some(names) = file_function_names.get(target_file) {
                for dotted in names {
                    if dotted.starts_with(&prefix) {
                        out.insert(dotted.clone(), (target_file.clone(), dotted.clone()));
                    }
                }
            }
        }
        for (bare_name, target) in static_bindings {
            out.insert(bare_name.clone(), target.clone());
        }
        out
    }

    #[test]
    fn test_lookups_match_the_materialized_maps() {
        use crate::scan::dataflow::java_module_registry::{
            build_static_import_bindings, resolve_visible_classes,
        };
        // Each case of the precedence rules (java_visibility.rs): a class
        // defined in two files of one package, a wildcard import that
        // overrides the package, an explicit import that overrides both,
        // an ambiguous explicit import, an explicit import of the file
        // itself, static imports (one member, all members), nested
        // classes, and the default package.
        let files: &[(&str, &str)] = &[
            (
                "p/A.java",
                "package p; import q.*; import r.Util; import static s.Tools.*; import static r.Util.helper; class A { void run() { Helper.go(); Util.u(); helper(); a(); } }",
            ),
            (
                "p/Helper.java",
                "package p; class Helper { void go() {} void stop() {} }",
            ),
            (
                "p/other/Helper.java",
                "package p; class Helper { void go() {} void more() {} }",
            ),
            (
                "p/B.java",
                "package p; import p.B; class B { void m() { Helper.stop(); } static class Inner { void n() {} } }",
            ),
            (
                "p/C.java",
                "package p; import t.Amb; import q.Helper; class C { void c() { Helper.q(); Amb.z(); B.m(); } }",
            ),
            (
                "q/Helper.java",
                "package q; class Helper { void go() {} void q() {} }",
            ),
            ("q/Q.java", "package q; class Q { void x() {} }"),
            (
                "r/Util.java",
                "package r; class Util { static void helper() {} void u() {} }",
            ),
            (
                "s/Tools.java",
                "package s; class Tools { static void a() {} static void b() {} }",
            ),
            ("t/Amb.java", "package t; class Amb { void z() {} }"),
            ("t2/Amb.java", "package t; class Amb { void z() {} }"),
            ("D1.java", "class D1 { void d() {} }"),
            ("D2.java", "class D2 { void e() { D1.d(); } }"),
        ];
        with_graph(files, |graph| {
            let trees: BTreeMap<String, tree_sitter::Tree> = files
                .iter()
                .map(|(path, src)| (path.to_string(), parse_java(src)))
                .collect();
            let sources: BTreeMap<&str, &str> = files.iter().copied().collect();
            let mut class_names_by_file = BTreeMap::new();
            let mut imports_by_file = BTreeMap::new();
            for (path, tree) in &trees {
                let source = sources[path.as_str()].as_bytes();
                class_names_by_file.insert(
                    path.clone(),
                    (
                        collect_package(tree.root_node(), source),
                        collect_java_class_names(tree.root_node(), source),
                    ),
                );
                imports_by_file
                    .insert(path.clone(), collect_java_imports(tree.root_node(), source));
            }
            let mut file_function_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            for (file, name) in graph.nodes.keys() {
                file_function_names
                    .entry(file.clone())
                    .or_default()
                    .insert(name.clone());
            }
            let fqcn_index = build_fqcn_index(&class_names_by_file);

            // Every key a call could look up: each method name, dotted and
            // bare, each class name, and names nothing defines.
            let mut probes: BTreeSet<String> = BTreeSet::new();
            for (_, name) in graph.nodes.keys() {
                probes.insert(name.clone());
                if let Some((_, bare)) = name.rsplit_once('.') {
                    probes.insert(bare.to_string());
                }
            }
            probes.extend([
                "Nothing.go".to_string(),
                "unknown".to_string(),
                "Helper.none".to_string(),
            ]);
            let mut class_probes: BTreeSet<String> = class_names_by_file
                .values()
                .flat_map(|(_, names)| names.iter().cloned())
                .collect();
            class_probes.insert("Nowhere".to_string());

            let visibility = graph.visibility();
            let mut checked = 0;
            for (file, (package, _)) in &class_names_by_file {
                let imports = &imports_by_file[file];
                let visible = resolve_visible_classes(
                    file,
                    package,
                    imports,
                    &class_names_by_file,
                    &fqcn_index,
                );
                let statics =
                    build_static_import_bindings(file, imports, &fqcn_index, &file_function_names);
                let bindings = oracle_import_bindings(&visible, &statics, &file_function_names);
                for cname in &class_probes {
                    assert_eq!(
                        visibility.visible_class(file, cname),
                        visible.get(cname).map(String::as_str),
                        "visible class {cname} from {file}"
                    );
                }
                for key in &probes {
                    assert_eq!(
                        visibility.binding(file, key).as_ref(),
                        bindings.get(key),
                        "binding {key} from {file}"
                    );
                    checked += 1;
                }
                let targets: BTreeSet<&NodeKey> = bindings.values().collect();
                for node in graph.nodes.keys() {
                    assert_eq!(
                        visibility.is_binding_target(file, node),
                        targets.contains(node),
                        "target {node:?} from {file}"
                    );
                }
            }
            assert!(checked > 100, "too few lookups checked: {checked}");
            // The fixture does exercise each rule: without these, the test
            // would compare empty maps.
            assert_eq!(
                visibility.visible_class("p/A.java", "Helper"),
                Some("q/Helper.java")
            );
            assert_eq!(
                visibility.visible_class("p/B.java", "Helper"),
                Some("p/other/Helper.java")
            );
            assert_eq!(visibility.visible_class("p/C.java", "Amb"), None);
            assert_eq!(
                visibility.binding("p/A.java", "helper"),
                Some(("r/Util.java".to_string(), "Util.helper".to_string()))
            );
            assert_eq!(
                visibility.binding("D2.java", "D1.d"),
                Some(("D1.java".to_string(), "D1.d".to_string()))
            );
        });
    }

    #[test]
    fn test_visible_methods_reach_the_analysis_without_extra() {
        // `Api` calls `Helper.run` of its package: the summary is not
        // copied into `extra` any more (ticket #239), the analysis finds
        // it through `JavaFileSummaries`.
        let helper_src =
            "package p; class Helper { String run(String v) { return v.getParameter(\"x\"); } }";
        let api_src = "package p; class Api { void foo() {} }";
        with_graph(
            &[("Helper.java", helper_src), ("Api.java", api_src)],
            |graph| {
                let lines = BTreeMap::from([
                    (
                        "Helper.java".to_string(),
                        helper_src
                            .lines()
                            .map(str::to_string)
                            .collect::<SourceLines>()
                            .into(),
                    ),
                    (
                        "Api.java".to_string(),
                        api_src
                            .lines()
                            .map(str::to_string)
                            .collect::<SourceLines>()
                            .into(),
                    ),
                ]);
                let resolved =
                    graph.resolve_summaries_incremental(&sqli_specs(), Some(&lines), None);
                assert!(
                    resolved
                        .extra
                        .get("Api.java")
                        .is_none_or(|m| !m.contains_key("Helper.run"))
                );
                let visibility: Arc<dyn Visibility> = graph.visibility().clone();
                let lookup = crate::scan::dataflow::visibility::FileSummaries::new(
                    visibility,
                    "Api.java",
                    resolved.all.clone(),
                );
                use crate::scan::dataflow::transfer::SummaryLookup;
                assert!(lookup.get("Helper.run").is_some());
                assert!(lookup.get("Helper.missing").is_none());
            },
        );
    }
}
