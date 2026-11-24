//! Call graph of the C# files of a scan (ticket #284): nodes are the
//! methods and constructors that `csharp_summary.rs` collects
//! (`(file, "Class.Method")`), edges the calls resolved from their bodies,
//! across files through namespaces and `using` directives
//! (`csharp_visibility.rs`). The summaries are computed in topological
//! order, callees before callers, by the resolution shared with Java
//! (`class_call_graph.rs`).
//!
//! **Deliberate addition, no Python source**: the Audit has no C# call
//! graph (its C# pass was disabled); until this ticket the Rust port
//! resolved a C# call only to a method of the same file, each summary
//! computed alone, so a flow from a controller to a repository in another
//! file was missed (ADR-0060). Modelled on `java_call_graph.rs`.
//!
//! Calls resolved (the local key is the callee as
//! `transfer.rs::canon_callee` names it after `csharp_lowering.rs`):
//!   - `M(x)` / `M<T>(x)`: a method of the enclosing class (in the file, or
//!     in another file of a `partial` class), else a `using static` import;
//!   - `this.M(x)`: a method of the enclosing class;
//!   - `base.M(x)`: a method of a class of the base list;
//!   - `C.M(x)`: a static call, `C` a class visible from the file;
//!   - `obj.M(x)` and `this.obj.M(x)`: `obj` a field or local variable of
//!     declared class `C` (`collect_csharp_field_types`,
//!     `collect_csharp_local_types`);
//!   - `A.B.C.M(x)`: `A.B.C` a qualified class name, or `X.C` with `X` a
//!     `using` alias;
//!   - `new C(...).M(x)`: `C` a simple class name (the lowering keeps the
//!     constructor as the receiver, as in Java);
//!   - `x.M()` with `var x = new C(...)`: `x` is typed `C`.
//!
//! A call through an interface or an abstract method (no body, so no node)
//! resolves to the single implementation of the scan: the one subtype,
//! direct or indirect, that defines the method
//! (`CSharpVisibility::dispatch_method`). Two implementations or more:
//! no edge.
//!
//! Not resolved (anti-FP, a missed flow rather than an invented one):
//! virtual dispatch to an override (the body of the declared type is
//! followed), `new A.B.C().M()` (qualified), `var x = Make()`, extension
//! methods and delegates and lambdas, calls on the result of another call
//! (`a.B().C()`), null-conditional calls (`x?.M()`).
//!
//! **Read from the tree file by file, linked without it (ticket #281)**:
//! [`CSharpFile::extract`] reads from one file's tree everything the graph
//! needs (its prepared methods, scope, declared types, and the calls of
//! each method in the order its body lists them), so that the scan can
//! drop the tree right after; [`CSharpCallGraph::build_from`] links the
//! files from these facts alone, with the same edges as the former reading
//! of the trees.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rayon::prelude::*;
use tree_sitter::Node;

pub use super::call_graph::{FileInput, NodeKey, SummariesByFile};
use super::call_graph::{ResolvedSummaries, SummaryReuse};
use super::class_call_graph::{
    ClassGraphView, ClassLanguageHooks, Edges, GraphCaches, resolve_in_topological_order,
    topological_order,
};
use super::csharp_namespaces::{
    CSharpFileScope, base_types_by_class, collect_csharp_scope, normalize_name,
};
use super::csharp_summary::{
    CSharpFunctionInfo, add_bare_name_aliases, collect_csharp_field_types,
    collect_csharp_functions, compute_csharp_summary_with, local_types_of,
    prepare_csharp_functions,
};
use super::csharp_visibility::CSharpVisibility;
use super::line_facts::{LinesByFile, RuleLines};
use super::prepared::{PreparedCfg, PreparedFile, PreparedFiles};
use super::transfer::RuleSpecs;
use super::visibility::graph_fingerprint;

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

/// Every `invocation_expression` under `body` (DFS).
fn iter_invocations<'tree>(body: Node<'tree>) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        if n.kind() == "invocation_expression" {
            out.push(n);
        }
        let mut w = n.walk();
        stack.extend(n.children(&mut w));
    }
    out
}

/// `A.B.C` (or `this.a`) for a chain of `member_access_expression` over
/// identifiers, exactly as `canon_callee` writes it; `None` for any other
/// receiver.
fn dotted_identifiers(node: Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "this" => Some(text(node, source)),
        "member_access_expression" => {
            let base = dotted_identifiers(node.child_by_field_name("expression")?, source)?;
            let name = node.child_by_field_name("name")?;
            (name.kind() == "identifier").then(|| format!("{base}.{}", text(name, source)))
        }
        _ => None,
    }
}

/// One call of a method body, as the edges read it: what
/// [`outgoing_edges`] used to read from the `invocation_expression` node
/// (ticket #281). A call of another shape (a call on the result of
/// another call, a null-conditional call, a qualified `new A.B.C()`) is
/// not kept: no edge was ever drawn from it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CSharpCall {
    /// `M(x)` or `M<T>(x)`: the bare identifier.
    Bare(String),
    /// `new C(...).M(x)`: `C` a simple class name, never empty, and the
    /// method name as written (`M<T>`).
    New { class: String, attr: String },
    /// `receiver.M(x)`: `this`, `base` or a dotted chain of identifiers
    /// ([`dotted_identifiers`]), and the method name as written.
    Member { receiver: String, attr: String },
}

/// The calls of `body` in the order [`iter_invocations`] lists them, the
/// order in which the first resolution of a local key wins.
fn csharp_calls(body: Node, source: &[u8]) -> Vec<CSharpCall> {
    let mut calls = Vec::new();
    for call in iter_invocations(body) {
        let Some(function) = call.child_by_field_name("function") else {
            continue;
        };
        match function.kind() {
            "identifier" => calls.push(CSharpCall::Bare(text(function, source))),
            "generic_name" => {
                // `M<T>(x)` is lowered to its bare identifier.
                let mut w = function.walk();
                if let Some(id) = function
                    .named_children(&mut w)
                    .find(|n| n.kind() == "identifier")
                {
                    calls.push(CSharpCall::Bare(text(id, source)));
                }
            }
            "member_access_expression" => {
                let (Some(receiver), Some(name_node)) = (
                    function.child_by_field_name("expression"),
                    function.child_by_field_name("name"),
                ) else {
                    continue;
                };
                // The key keeps the name as written (`M<T>`), as the
                // lowering does.
                let attr = text(name_node, source);
                match receiver.kind() {
                    "this" => calls.push(CSharpCall::Member {
                        receiver: "this".to_string(),
                        attr,
                    }),
                    "base" => calls.push(CSharpCall::Member {
                        receiver: "base".to_string(),
                        attr,
                    }),
                    "object_creation_expression" => {
                        // `new C(...).M()`: the lowering keeps the class
                        // (`csharp_lowering.rs::lower_constructor_chain`)
                        // and `transfer.rs::eval_call` looks `C.M` up. A
                        // qualified `new A.B.C()` is left out: the
                        // analysis reads only a simple class name back.
                        if let Some(class) = receiver
                            .child_by_field_name("type")
                            .map(|t| normalize_name(&text(t, source)))
                            .filter(|c| !c.is_empty() && !c.contains('.'))
                        {
                            calls.push(CSharpCall::New { class, attr });
                        }
                    }
                    _ => {
                        if let Some(dotted) = dotted_identifiers(receiver, source) {
                            calls.push(CSharpCall::Member {
                                receiver: dotted,
                                attr,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    calls
}

/// What the call graph needs from one C# file, read from its tree once
/// ([`CSharpFile::extract`], ticket #281): no node of the tree is kept.
pub struct CSharpFile {
    /// The file's methods, prepared for every rule.
    prepared: PreparedFile<CSharpFunctionInfo>,
    /// The calls of each method of `prepared`, at the same index.
    calls: Vec<Vec<CSharpCall>>,
    /// Namespaces, `using` directives, classes and their bases.
    scope: CSharpFileScope,
    /// Field or local variable name → declared class (locals win).
    type_map: BTreeMap<String, String>,
}

impl CSharpFile {
    /// Reads the file whose tree is `root`, parsed from `source`.
    pub fn extract(root: Node<'_>, source: &[u8]) -> Self {
        let functions = collect_csharp_functions(root, source);
        let calls = functions
            .iter()
            .map(|function| csharp_calls(function.body, source))
            .collect();
        // Locals take priority over fields, as in the analysis
        // (`csharp_summary::collect_csharp_field_types`).
        let mut type_map = collect_csharp_field_types(root, source);
        type_map.extend(local_types_of(&functions, source));
        CSharpFile {
            scope: collect_csharp_scope(root, source),
            type_map,
            calls,
            prepared: prepare_csharp_functions(functions, source),
        }
    }
}

/// What the edges of one file are resolved from, read once per file.
struct FileContext<'a> {
    filepath: &'a str,
    /// Simple class name → its base types (`base.M()`).
    bases: BTreeMap<String, Vec<String>>,
    /// Field or local variable name → declared class (locals win).
    type_map: &'a BTreeMap<String, String>,
}

/// The C# call graph of the files of a scan (see the module doc).
#[derive(Default)]
pub struct CSharpCallGraph {
    /// Every method/constructor, by `(file, "Class.Method")`.
    pub nodes: BTreeMap<NodeKey, ()>,
    /// For each node, its resolved calls: local call key → target node.
    pub edges: Edges,
    visibility: Arc<CSharpVisibility>,
    /// Field or local variable name → declared class, per file: the table
    /// of the edges, handed as `RuleSpecs::type_map` to the analysis of the
    /// file, so that both resolve `obj.M()` alike.
    type_maps: BTreeMap<String, BTreeMap<String, String>>,
    /// Every file prepared once for all the rules of the scan (ticket
    /// #192).
    prepared: PreparedFiles<CSharpFunctionInfo>,
    caches: GraphCaches,
}

impl CSharpCallGraph {
    /// Builds the graph of `files`, already parsed: each file is read
    /// ([`CSharpFile::extract`], in parallel), then linked
    /// ([`Self::build_from`]).
    pub fn build(files: &[FileInput<'_>]) -> Self {
        Self::build_from(
            files
                .par_iter()
                .map(|f| (f.filepath.clone(), CSharpFile::extract(f.root, f.source)))
                .collect(),
        )
    }

    /// Builds the graph from the files already read, by path, without any
    /// tree (ticket #281): the classes are indexed, then the edges
    /// resolved, in parallel.
    pub fn build_from(files: Vec<(String, CSharpFile)>) -> Self {
        let mut graph = CSharpCallGraph::default();
        let mut scopes: BTreeMap<String, CSharpFileScope> = BTreeMap::new();
        let mut function_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut calls_by_file: Vec<(String, Vec<Vec<CSharpCall>>)> =
            Vec::with_capacity(files.len());
        for (filepath, file) in files {
            let CSharpFile {
                prepared,
                calls,
                scope,
                type_map,
            } = file;
            let mut names = BTreeSet::new();
            for (index, function) in prepared.functions.iter().enumerate() {
                names.insert(function.info.name.clone());
                let key = (filepath.clone(), function.info.name.clone());
                graph.prepared.index_node(key.clone(), index);
                graph.nodes.insert(key, ());
            }
            graph.prepared.insert_file(filepath.clone(), prepared);
            function_names.insert(filepath.clone(), names);
            scopes.insert(filepath.clone(), scope);
            graph.type_maps.insert(filepath.clone(), type_map);
            calls_by_file.push((filepath, calls));
        }
        graph.visibility = Arc::new(CSharpVisibility::new(&scopes, function_names));

        let edges: Vec<(NodeKey, BTreeMap<String, NodeKey>)> = calls_by_file
            .par_iter()
            .flat_map_iter(|(filepath, calls)| {
                let scope = &scopes[filepath];
                let context = FileContext {
                    filepath,
                    bases: base_types_by_class(scope),
                    type_map: &graph.type_maps[filepath],
                };
                let functions = &graph
                    .prepared
                    .file(filepath)
                    .expect("every file was prepared above")
                    .functions;
                let mut out = Vec::new();
                let mut seen = BTreeSet::new();
                // Homonyms (overloads): the node is the last one, as in
                // `nodes` and `PreparedFiles::index_node`.
                for (function, calls) in functions.iter().zip(calls).rev() {
                    if !seen.insert(function.info.name.clone()) {
                        continue;
                    }
                    let key = (filepath.clone(), function.info.name.clone());
                    let edges = outgoing_edges(&function.info, calls, &context, &graph);
                    out.push((key, edges));
                }
                out
            })
            .collect();
        graph.edges.extend(edges);
        graph
    }

    /// The prepared form of `filepath`, for the taint analysis of each
    /// rule (ticket #192).
    pub fn prepared_file(&self, filepath: &str) -> Option<&PreparedFile<CSharpFunctionInfo>> {
        self.prepared.file(filepath)
    }

    /// What each file sees of the others, shared with the taint analysis
    /// of each file.
    pub fn visibility(&self) -> &Arc<CSharpVisibility> {
        &self.visibility
    }

    /// The declared types of the fields and local variables of `filepath`.
    pub fn type_map(&self, filepath: &str) -> Option<&BTreeMap<String, String>> {
        self.type_maps.get(filepath)
    }

    /// A callees-before-callers order of the nodes
    /// (`class_call_graph::topological_order`).
    pub fn topological_order(&self) -> Vec<NodeKey> {
        topological_order(&self.nodes, &self.edges)
    }

    /// The summaries of every method for one rule, reusing those of a
    /// previous scan that cannot have changed
    /// (`class_call_graph::resolve_in_topological_order`).
    pub fn resolve_summaries_incremental(
        &self,
        base_specs: &RuleSpecs,
        source_lines_by_file: Option<&LinesByFile>,
        reuse: Option<&SummaryReuse>,
    ) -> ResolvedSummaries {
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
                compute: |info: &CSharpFunctionInfo,
                          body: &PreparedCfg,
                          specs: &RuleSpecs,
                          lines: Option<&RuleLines>| {
                    compute_csharp_summary_with(info, body, specs, lines)
                },
                add_bare_name_aliases,
            },
            base_specs,
            source_lines_by_file,
            reuse,
        )
    }

    /// The files whose cached findings no longer hold because they read a
    /// summary in `changed`: the files defining a changed method, those
    /// with an edge to one, and those that may see one through their
    /// visibility (`CSharpVisibility::readers_of`, a superset).
    pub fn readers(&self, changed: &BTreeSet<NodeKey>) -> BTreeSet<String> {
        use super::visibility::Visibility;
        let mut readers = self.visibility.readers_of(changed);
        let callers = self.caches.callers(&self.edges);
        for node in changed {
            readers.insert(node.0.clone());
            if let Some(files) = callers.get(node) {
                readers.extend(files.iter().cloned());
            }
        }
        readers
    }

    /// What, besides its own text, decides the analysis of `file`: the
    /// edges of its methods, their names, and what it sees of the other
    /// files (`CSharpVisibility`).
    pub fn dependency_fingerprint(&self, file: &str) -> String {
        graph_fingerprint(&self.edges, &self.nodes, self.visibility.as_ref(), file)
    }
}

/// The outgoing edges of one method from its `calls` ([`csharp_calls`]):
/// one target per local key, the first resolution met winning (as in
/// Java).
fn outgoing_edges(
    fn_info: &CSharpFunctionInfo,
    calls: &[CSharpCall],
    context: &FileContext,
    graph: &CSharpCallGraph,
) -> BTreeMap<String, NodeKey> {
    let filepath = context.filepath;
    let visibility = graph.visibility.as_ref();
    let enclosing = fn_info.name.rsplit_once('.').map(|(c, _)| c).unwrap_or("");
    // A method of the enclosing class: in this file first, else in
    // another file of the same (partial) class, else, for an abstract
    // method of an abstract class, its single implementation.
    let same_class = |method: &str| -> Option<NodeKey> {
        let key = (filepath.to_string(), format!("{enclosing}.{method}"));
        if graph.nodes.contains_key(&key) {
            return Some(key);
        }
        let class = visibility.simple_class(filepath, enclosing)?;
        visibility.dispatch_method(&class, method, filepath)
    };
    // A method of the class that `name` designates from this file.
    let class_method = |name: &str, method: &str| -> Option<NodeKey> {
        let class = visibility.class(filepath, name)?;
        visibility.method_node(&class, method, filepath)
    };
    // The method an instance of declared type `name` runs: its own body,
    // else the single implementation of an interface or abstract method
    // (`CSharpVisibility::dispatch_method`).
    let instance_method = |name: &str, method: &str| -> Option<NodeKey> {
        let class = visibility.class(filepath, name)?;
        visibility.dispatch_method(&class, method, filepath)
    };

    let mut edges: BTreeMap<String, NodeKey> = BTreeMap::new();
    for call in calls {
        let (local_key, target) = match call {
            CSharpCall::Bare(name) => {
                if edges.contains_key(name) {
                    continue;
                }
                let target = same_class(name).or_else(|| visibility.static_method(filepath, name));
                (name.clone(), target)
            }
            CSharpCall::New {
                class: created,
                attr,
            } => {
                // `new C(...).M()`: the key is `C.M`, resolved as a static
                // call (see [`csharp_calls`]); the method is its bare name.
                let method = normalize_name(attr);
                let local_key = format!("{created}.{attr}");
                if edges.contains_key(&local_key) {
                    continue;
                }
                (local_key, class_method(created, &method))
            }
            CSharpCall::Member {
                receiver: receiver_key,
                attr,
            } => {
                // The key keeps the name as written (`M<T>`), as the
                // lowering does; the method is its bare name.
                let method = normalize_name(attr);
                let local_key = format!("{receiver_key}.{attr}");
                if edges.contains_key(&local_key) {
                    continue;
                }
                let target = resolve_member_call(
                    receiver_key,
                    &method,
                    enclosing,
                    context,
                    &same_class,
                    &class_method,
                    &instance_method,
                );
                (local_key, target)
            }
        };
        if let Some(target) = target {
            edges.insert(local_key, target);
        }
    }
    edges
}

/// The target of `receiver.method(...)`, `receiver` being `this`, `base`
/// or a dotted chain of identifiers.
fn resolve_member_call(
    receiver: &str,
    method: &str,
    enclosing: &str,
    context: &FileContext,
    same_class: &dyn Fn(&str) -> Option<NodeKey>,
    class_method: &dyn Fn(&str, &str) -> Option<NodeKey>,
    instance_method: &dyn Fn(&str, &str) -> Option<NodeKey>,
) -> Option<NodeKey> {
    match receiver {
        "this" => same_class(method),
        "base" => context
            .bases
            .get(enclosing)?
            .iter()
            .find_map(|base| class_method(base, method)),
        _ => {
            if let Some(field) = receiver.strip_prefix("this.")
                && !field.contains('.')
            {
                let declared = context.type_map.get(field)?;
                return instance_method(declared, method);
            }
            if !receiver.contains('.') {
                // 1. `receiver` names a class (static call), declared in
                //    this file or visible from it (the class is looked up
                //    first, as in Java).
                if let Some(target) = class_method(receiver, method) {
                    return Some(target);
                }
                // 2. `receiver` is a field or local variable of known
                //    class, or of an interface or abstract class with a
                //    single implementation in the scan.
                let declared = context.type_map.get(receiver)?;
                return instance_method(declared, method);
            }
            // 3. A qualified class name (or alias-qualified).
            class_method(receiver, method)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::line_facts::SourceLines;
    use crate::scan::dataflow::transfer::{SinkSpec, SourceSpec};
    use crate::scan::dataflow::visibility::{FileSummaries, Visibility};

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        assert!(!tree.root_node().has_error(), "invalid C#: {src:?}");
        tree
    }

    /// Builds the graph of `files` (`(path, source)`) and hands it to `f`.
    fn with_graph<R>(files: &[(&str, &str)], f: impl FnOnce(&CSharpCallGraph) -> R) -> R {
        let trees: Vec<(String, String, tree_sitter::Tree)> = files
            .iter()
            .map(|(path, src)| (path.to_string(), src.to_string(), parse(src)))
            .collect();
        let inputs: Vec<FileInput> = trees
            .iter()
            .map(|(path, src, tree)| FileInput {
                filepath: path.clone(),
                root: tree.root_node(),
                source: src.as_bytes(),
            })
            .collect();
        let graph = CSharpCallGraph::build(&inputs);
        assert_edges_match_trees(&graph, &inputs);
        f(&graph)
    }

    /// The edges of a method as the graph drew them from its tree before
    /// ticket #281, when `outgoing_edges` walked the `invocation_expression`
    /// nodes of the body itself: the reference the edges drawn from the
    /// calls read once ([`csharp_calls`]) must equal. Kept as it was, but
    /// for the body passed beside the metadata that held it.
    fn edges_from_tree(
        fn_info: &CSharpFunctionInfo,
        body: Node,
        context: &FileContext,
        graph: &CSharpCallGraph,
        source: &[u8],
    ) -> BTreeMap<String, NodeKey> {
        let filepath = context.filepath;
        let visibility = graph.visibility.as_ref();
        let enclosing = fn_info.name.rsplit_once('.').map(|(c, _)| c).unwrap_or("");
        // A method of the enclosing class: in this file first, else in
        // another file of the same (partial) class, else, for an abstract
        // method of an abstract class, its single implementation.
        let same_class = |method: &str| -> Option<NodeKey> {
            let key = (filepath.to_string(), format!("{enclosing}.{method}"));
            if graph.nodes.contains_key(&key) {
                return Some(key);
            }
            let class = visibility.simple_class(filepath, enclosing)?;
            visibility.dispatch_method(&class, method, filepath)
        };
        // A method of the class that `name` designates from this file.
        let class_method = |name: &str, method: &str| -> Option<NodeKey> {
            let class = visibility.class(filepath, name)?;
            visibility.method_node(&class, method, filepath)
        };
        // The method an instance of declared type `name` runs: its own body,
        // else the single implementation of an interface or abstract method
        // (`CSharpVisibility::dispatch_method`).
        let instance_method = |name: &str, method: &str| -> Option<NodeKey> {
            let class = visibility.class(filepath, name)?;
            visibility.dispatch_method(&class, method, filepath)
        };

        let mut edges: BTreeMap<String, NodeKey> = BTreeMap::new();
        for call in iter_invocations(body) {
            let Some(function) = call.child_by_field_name("function") else {
                continue;
            };
            let (local_key, target) = match function.kind() {
                "identifier" | "generic_name" => {
                    // `M<T>(x)` is lowered to its bare identifier.
                    let name = if function.kind() == "identifier" {
                        text(function, source)
                    } else {
                        let mut w = function.walk();
                        let Some(id) = function
                            .named_children(&mut w)
                            .find(|n| n.kind() == "identifier")
                        else {
                            continue;
                        };
                        text(id, source)
                    };
                    if edges.contains_key(&name) {
                        continue;
                    }
                    let target =
                        same_class(&name).or_else(|| visibility.static_method(filepath, &name));
                    (name, target)
                }
                "member_access_expression" => {
                    let (Some(receiver), Some(name_node)) = (
                        function.child_by_field_name("expression"),
                        function.child_by_field_name("name"),
                    ) else {
                        continue;
                    };
                    // The key keeps the name as written (`M<T>`), as the
                    // lowering does; the method is its bare name.
                    let attr = text(name_node, source);
                    let method = normalize_name(&attr);
                    let receiver_key = match receiver.kind() {
                        "this" => "this".to_string(),
                        "base" => "base".to_string(),
                        "object_creation_expression" => {
                            // `new C(...).M()`: the lowering keeps the class
                            // (`csharp_lowering.rs::lower_constructor_chain`)
                            // and `transfer.rs::eval_call` looks `C.M` up, so
                            // the key is `C.M`, resolved as a static call. A
                            // qualified `new A.B.C()` is left out: the analysis
                            // reads only a simple class name back.
                            let Some(created) = receiver
                                .child_by_field_name("type")
                                .map(|t| normalize_name(&text(t, source)))
                                .filter(|c| !c.is_empty() && !c.contains('.'))
                            else {
                                continue;
                            };
                            let local_key = format!("{created}.{attr}");
                            if edges.contains_key(&local_key) {
                                continue;
                            }
                            if let Some(target) = class_method(&created, &method) {
                                edges.insert(local_key, target);
                            }
                            continue;
                        }
                        _ => match dotted_identifiers(receiver, source) {
                            Some(dotted) => dotted,
                            None => continue,
                        },
                    };
                    let local_key = format!("{receiver_key}.{attr}");
                    if edges.contains_key(&local_key) {
                        continue;
                    }
                    let target = resolve_member_call(
                        &receiver_key,
                        &method,
                        enclosing,
                        context,
                        &same_class,
                        &class_method,
                        &instance_method,
                    );
                    (local_key, target)
                }
                _ => continue,
            };
            if let Some(target) = target {
                edges.insert(local_key, target);
            }
        }
        edges
    }

    /// Asserts that every node of `graph`, built from `files`, has the
    /// edges its tree gave before ticket #281 ([`edges_from_tree`]), and
    /// the declared types read from the trees. Returns the number of
    /// edges compared.
    fn assert_edges_match_trees(graph: &CSharpCallGraph, files: &[FileInput]) -> usize {
        let mut compared = 0;
        for f in files {
            let mut type_map = collect_csharp_field_types(f.root, f.source);
            type_map.extend(super::super::csharp_summary::collect_csharp_local_types(
                f.root, f.source,
            ));
            assert_eq!(
                graph.type_map(&f.filepath),
                Some(&type_map),
                "{}",
                f.filepath
            );
            let scope = collect_csharp_scope(f.root, f.source);
            let context = FileContext {
                filepath: &f.filepath,
                bases: base_types_by_class(&scope),
                type_map: &type_map,
            };
            let functions = collect_csharp_functions(f.root, f.source);
            let mut seen = BTreeSet::new();
            // Homonyms (overloads): the node is the last one.
            for function in functions.iter().rev() {
                if !seen.insert(function.info.name.clone()) {
                    continue;
                }
                let key = (f.filepath.clone(), function.info.name.clone());
                let reference =
                    edges_from_tree(&function.info, function.body, &context, graph, f.source);
                assert_eq!(graph.edges[&key], reference, "{key:?}");
                compared += reference.len();
            }
            assert_eq!(
                seen.len(),
                graph
                    .nodes
                    .range((f.filepath.clone(), String::new())..)
                    .take_while(|((file, _), _)| *file == f.filepath)
                    .count()
            );
        }
        compared
    }

    fn key(file: &str, name: &str) -> NodeKey {
        (file.to_string(), name.to_string())
    }

    fn edges_of(graph: &CSharpCallGraph, file: &str, name: &str) -> BTreeMap<String, NodeKey> {
        graph.edges[&key(file, name)].clone()
    }

    fn sqli_specs() -> RuleSpecs {
        RuleSpecs {
            rule_id: "test-sqli".to_string(),
            severity: "HIGH".to_string(),
            cwe: None,
            message: "test finding".to_string(),
            sources: vec![SourceSpec::new("Request.GetParameter", "http")],
            sinks: vec![SinkSpec::new("*.Execute")],
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
            summary_fallback: None,
            exprs: None,
        }
    }

    const REPO: &str = "namespace App.Data { public class Repo { \
        public void Find(object db, string id) { db.Execute(id); } \
        public static void Run(object db, string id) { db.Execute(id); } } }";

    #[test]
    fn test_bare_and_this_calls_same_class() {
        with_graph(
            &[(
                "A.cs",
                "class A { void Foo() { Bar(); this.Baz(); } void Bar() {} void Baz() {} }",
            )],
            |graph| {
                assert_eq!(
                    edges_of(graph, "A.cs", "A.Foo"),
                    BTreeMap::from([
                        ("Bar".to_string(), key("A.cs", "A.Bar")),
                        ("this.Baz".to_string(), key("A.cs", "A.Baz")),
                    ])
                );
            },
        );
    }

    #[test]
    fn test_field_local_static_and_qualified_calls_cross_file() {
        with_graph(
            &[
                ("Repo.cs", REPO),
                (
                    "Api.cs",
                    "using App.Data;\nnamespace App.Web { class Api { \
                     private Repo _repo = new Repo(); \
                     void Field(object db, string id) { _repo.Find(db, id); this._repo.Find(db, id); } \
                     void Local(object db, string id) { Repo r = new Repo(); r.Find(db, id); } \
                     void Static(object db, string id) { Repo.Run(db, id); App.Data.Repo.Run(db, id); } } }",
                ),
            ],
            |graph| {
                let find = key("Repo.cs", "Repo.Find");
                let run = key("Repo.cs", "Repo.Run");
                assert_eq!(
                    edges_of(graph, "Api.cs", "Api.Field"),
                    BTreeMap::from([
                        ("_repo.Find".to_string(), find.clone()),
                        ("this._repo.Find".to_string(), find.clone()),
                    ])
                );
                assert_eq!(
                    edges_of(graph, "Api.cs", "Api.Local"),
                    BTreeMap::from([("r.Find".to_string(), find)])
                );
                assert_eq!(
                    edges_of(graph, "Api.cs", "Api.Static"),
                    BTreeMap::from([
                        ("Repo.Run".to_string(), run.clone()),
                        ("App.Data.Repo.Run".to_string(), run),
                    ])
                );
            },
        );
    }

    #[test]
    fn test_no_edge_without_using_or_for_an_interface() {
        with_graph(
            &[
                ("Repo.cs", REPO),
                (
                    "I.cs",
                    "namespace App.Data { interface IRepo { void Find(object db, string id); } }",
                ),
                (
                    "Api.cs",
                    "namespace Other { class Api { IRepo _i; \
                     void Foo(object db, string id) { Repo.Run(db, id); _i.Find(db, id); } } }",
                ),
            ],
            |graph| {
                assert_eq!(edges_of(graph, "Api.cs", "Api.Foo"), BTreeMap::new());
            },
        );
    }

    /// `var r = new Repo()` types `r`, and `new Repo().Find()` keeps the
    /// class of the created object; a qualified `new App.Data.Repo()` and a
    /// `var` not initialized by a constructor resolve nothing.
    #[test]
    fn test_var_from_new_and_constructor_chain() {
        with_graph(
            &[
                ("Repo.cs", REPO),
                (
                    "Api.cs",
                    "using App.Data;\nnamespace App.Web { class Api { \
                     void Var(object db, string id) { var r = new Repo(); r.Find(db, id); } \
                     void Chain(object db, string id) { new Repo().Find(db, id); new App.Data.Repo().Find(db, id); } \
                     void Unknown(object db, string id) { var u = Make(); u.Find(db, id); } \
                     object Make() { return null; } } }",
                ),
            ],
            |graph| {
                let find = key("Repo.cs", "Repo.Find");
                assert_eq!(
                    edges_of(graph, "Api.cs", "Api.Var"),
                    BTreeMap::from([("r.Find".to_string(), find.clone())])
                );
                assert_eq!(
                    edges_of(graph, "Api.cs", "Api.Chain"),
                    BTreeMap::from([("Repo.Find".to_string(), find)])
                );
                assert_eq!(
                    edges_of(graph, "Api.cs", "Api.Unknown"),
                    BTreeMap::from([("Make".to_string(), key("Api.cs", "Api.Make"))])
                );
            },
        );
    }

    const USER_REPOSITORY_INTERFACE: &str = "namespace App.Data { public interface IUserRepository { \
        void Find(object db, string id); } }";

    /// A field of interface type reaches the single implementation of the
    /// scan, also through an abstract class between them; a second
    /// implementation removes the edge.
    #[test]
    fn test_interface_with_a_single_implementation() {
        let api = "using App.Data;\nnamespace App.Web { class Api { \
                   private readonly IUserRepository _repo; \
                   public Api(IUserRepository repo) { _repo = repo; } \
                   void Go(object db, string id) { _repo.Find(db, id); } } }";
        let sql = "namespace App.Data { public abstract class BaseRepository : IUserRepository { \
                   public abstract void Find(object db, string id); } \
                   public class SqlUserRepository : BaseRepository { \
                   public override void Find(object db, string id) { db.Execute(id); } } }";
        with_graph(
            &[
                ("I.cs", USER_REPOSITORY_INTERFACE),
                ("Sql.cs", sql),
                ("Api.cs", api),
            ],
            |graph| {
                assert_eq!(
                    edges_of(graph, "Api.cs", "Api.Go"),
                    BTreeMap::from([(
                        "_repo.Find".to_string(),
                        key("Sql.cs", "SqlUserRepository.Find")
                    )])
                );
            },
        );
        let memory = "namespace App.Data { public class MemoryUserRepository : IUserRepository { \
                      public void Find(object db, string id) {} } }";
        with_graph(
            &[
                ("I.cs", USER_REPOSITORY_INTERFACE),
                ("Sql.cs", sql),
                ("Memory.cs", memory),
                ("Api.cs", api),
            ],
            |graph| {
                assert_eq!(edges_of(graph, "Api.cs", "Api.Go"), BTreeMap::new());
            },
        );
    }

    /// An abstract method called from its own abstract class (template
    /// method) reaches its single override.
    #[test]
    fn test_abstract_method_called_from_its_class() {
        with_graph(
            &[
                (
                    "Base.cs",
                    "abstract class Job { public void Run(object db, string id) { Step(db, id); } \
                     protected abstract void Step(object db, string id); }",
                ),
                (
                    "Sql.cs",
                    "class SqlJob : Job { protected override void Step(object db, string id) { db.Execute(id); } }",
                ),
            ],
            |graph| {
                assert_eq!(
                    edges_of(graph, "Base.cs", "Job.Run"),
                    BTreeMap::from([("Step".to_string(), key("Sql.cs", "SqlJob.Step"))])
                );
            },
        );
    }

    #[test]
    fn test_base_and_partial_and_static_using() {
        with_graph(
            &[
                (
                    "Base.cs",
                    "namespace App { class Base { protected void Save(object db, string id) { db.Execute(id); } } }",
                ),
                (
                    "P1.cs",
                    "namespace App { partial class P : Base { void One(object db, string id) { base.Save(db, id); Two(db, id); } } }",
                ),
                (
                    "P2.cs",
                    "namespace App { partial class P { void Two(object db, string id) {} } }",
                ),
                (
                    "S.cs",
                    "using static App.Data.Repo;\nclass S { void Go(object db, string id) { Run(db, id); } }",
                ),
                ("Repo.cs", REPO),
            ],
            |graph| {
                assert_eq!(
                    edges_of(graph, "P1.cs", "P.One"),
                    BTreeMap::from([
                        ("Two".to_string(), key("P2.cs", "P.Two")),
                        ("base.Save".to_string(), key("Base.cs", "Base.Save")),
                    ])
                );
                assert_eq!(
                    edges_of(graph, "S.cs", "S.Go"),
                    BTreeMap::from([("Run".to_string(), key("Repo.cs", "Repo.Run"))])
                );
            },
        );
    }

    #[test]
    fn test_callee_before_caller_and_cycle_terminates() {
        with_graph(
            &[(
                "A.cs",
                "class A { void Foo() { Bar(); } void Bar() {} void Baz() { Baz(); } \
                 void Ping() { Pong(); } void Pong() { Ping(); } }",
            )],
            |graph| {
                let order = graph.topological_order();
                assert_eq!(order.len(), 5);
                let pos = |n: &str| order.iter().position(|k| k.1 == n).unwrap();
                assert!(pos("A.Bar") < pos("A.Foo"));
            },
        );
    }

    /// A flow two hops away in another file reaches the summary of the
    /// caller, and the call-site alias `_repo.Find` reaches its analysis.
    #[test]
    fn test_summaries_cross_files_and_hops() {
        let api = "using App.Data;\nnamespace App.Web { class Api { private Repo _repo; \
                   void Handle(object db) { string id = Request.GetParameter(\"id\"); Relay(db, id); } \
                   void Relay(object db, string id) { _repo.Find(db, id); } } }";
        with_graph(&[("Repo.cs", REPO), ("Api.cs", api)], |graph| {
            let lines_of = |src: &str| -> Arc<SourceLines> {
                src.lines()
                    .map(str::to_string)
                    .collect::<SourceLines>()
                    .into()
            };
            let lines: LinesByFile = BTreeMap::from([
                ("Repo.cs".to_string(), lines_of(REPO)),
                ("Api.cs".to_string(), lines_of(api)),
            ]);
            let resolved = graph.resolve_summaries_incremental(&sqli_specs(), Some(&lines), None);
            let relay = &resolved.own["Api.cs"]["Api.Relay"];
            assert!(
                relay.sink_param_findings.contains_key(&1),
                "Relay must reach the sink through Repo.Find: {relay:?}"
            );
            assert!(resolved.extra["Api.cs"].contains_key("_repo.Find"));
            // The static key goes through the visibility instead of `extra`.
            let visibility: Arc<dyn Visibility> = graph.visibility().clone();
            let lookup = FileSummaries::new(visibility, "Api.cs", resolved.all.clone());
            use crate::scan::dataflow::transfer::SummaryLookup;
            assert!(lookup.get("Repo.Find").is_some());
            assert_eq!(
                graph.readers(&BTreeSet::from([key("Repo.cs", "Repo.Find")])),
                BTreeSet::from(["Api.cs".to_string(), "Repo.cs".to_string()])
            );
        });
    }

    #[test]
    fn test_fingerprint_holds_the_cross_file_edges() {
        let api = "namespace App.Data { class Api { void Go(object db, string id) { Repo.Run(db, id); } } }";
        with_graph(&[("Repo.cs", REPO), ("Api.cs", api)], |graph| {
            assert!(
                graph
                    .dependency_fingerprint("Api.cs")
                    .contains("Repo.Run=Repo.cs#Repo.Run")
            );
        });
    }
}
