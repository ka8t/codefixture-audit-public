//! Persistent (Python) call graph — multi-hop interprocedural
//! resolution. Port of `Audit/sca/dataflow/call_graph.py`.
//!
//! Replaces `ModuleRegistry`'s 1-hop resolution (import → already
//! computed summary, itself blind to its own calls) with a real graph
//! (nodes = functions, edges = resolved calls, including intra-file)
//! and a summary computation done in **topological order** (callees
//! before callers): when B (imported by A) itself calls a function of
//! C, that link is now resolved.
//!
//! Reuses the suffix-matching logic of `module_registry.py`
//! (`resolve_target_file`) — ported here as free functions, **without
//! the `ModuleRegistry` class**: `dataflow_adapter.py` (the prod entry
//! point) only uses `CallGraph`, never `ModuleRegistry` (confirmed via
//! grep on the Audit repo) — that class is dead code in production,
//! not ported.
//!
//! **Deviation vs Python (Decision #3, already settled in the plan)**:
//! `topological_order()` on the Python side is a naive DFS post-order
//! — a recursion cycle (A↔B) leaves the revisited link unresolved
//! (just an infinite-loop guard, not a real fixpoint). Here: breakdown
//! into strongly connected components (Tarjan), processed in the
//! topological order of the condensation (callees-before-callers,
//! guaranteed by construction); a non-trivial SCC (real cycle) is
//! resolved by a bounded fixpoint between its members
//! (`MAX_SCC_FIXPOINT_ITER` passes, same spirit as CFG loop widening)
//! instead of being given up on.
//!
//! **Read from the tree file by file, linked without it (ticket #281)**:
//! [`PythonFile::extract`] reads from one file's tree everything the
//! graph needs (its prepared module and functions, its imports, and the
//! local names of the calls of each function in the order its definition
//! lists them), so that the scan can drop the tree right after;
//! [`CallGraph::build_from`] links the files from these facts alone, with
//! the same edges as the former reading of the trees.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rayon::prelude::*;

use tree_sitter::Node;

use super::lattice::SharedText;
use super::line_facts::{LinesByFile, RuleLinesByFile, SourceLines, rule_lines_by_file};
use super::prepared::{PreparedFile, PreparedFiles};
use super::summary::{
    FunctionInfo, ImportInfo, collect_functions, collect_imports, compute_summary_with,
    prepare_python_functions,
};
use super::transfer::{FunctionSummary, RuleSpecs};
use super::visibility::{ImportEntry, ImportVisibility, Visibility, graph_fingerprint};

/// (file path, function name).
pub type NodeKey = (String, String);

/// `{file: {name: FunctionSummary}}` — shape shared by `own` and
/// `extra` in the `resolve_summaries` result.
///
/// `Arc<FunctionSummary>`, not `FunctionSummary` directly — found by
/// profiling (`sample`) a large Java corpus (2000+ files, OWASP
/// BenchmarkJava, 2026-08-26): `FunctionSummary` embeds
/// `sink_param_findings: BTreeMap<usize, Finding>`, and `Finding` is a
/// heavy struct (several `String` + `Vec<FlowStep>`). The summary of a
/// "hub" function (called by hundreds of near-identical files, typical
/// of this corpus) was being deep-cloned on EVERY incoming edge — the
/// real dominant cost, not `resolve_summaries` itself (two previous
/// fixes on
/// `topological_order`/`per_file_key_targets`/`base_specs.clone()`
/// had only given a marginal gain). `Arc` makes `.clone()` O(1)
/// (reference-count bump) regardless of content — no read logic
/// changes (transparent auto-dereferencing).
pub type SummariesByFile = BTreeMap<String, BTreeMap<String, Arc<FunctionSummary>>>;

/// Fixpoint threshold on a non-trivial SCC (recursion cycle) — same
/// spirit as `worklist::MAX_LOOP_ITER`: a few passes are enough in
/// practice, bounded to avoid pathological cases.
pub const MAX_SCC_FIXPOINT_ITER: u32 = 3;

/// Writes the file and the code line on every step of a summary's
/// template findings that has none yet: a step already stamped comes
/// from a deeper callee and keeps its own file. Once a summary is used
/// in another file, its steps still say where they are, so the report
/// can show the real line of a query written two calls away.
fn stamp_steps(summary: &mut FunctionSummary, filepath: &str, lines: Option<&SourceLines>) {
    for template in summary.sink_param_findings.values_mut() {
        for step in &mut template.flow {
            if step.file.is_some() {
                continue;
            }
            step.file = Some(filepath.to_string());
            step.code = lines
                .and_then(|l| l.get(step.line.wrapping_sub(1)))
                .map(|l| SharedText::from(l.trim()));
        }
    }
}

fn path_parts(path: &str) -> Vec<String> {
    path.replace('\\', "/")
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .map(|s| s.to_string())
        .collect()
}

fn common_prefix_len(a: &[String], b: &[String]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

/// The analysed files, indexed by file name with their path already split:
/// a suffix always ends with a file name, so only the files of that name
/// can match. Matching every import against every file, splitting each
/// path again, made the graph build grow with the square of the project
/// (1.1 s of a 2.8 s cached re-scan on 460 files, 2026-11-14).
pub(crate) struct KnownFiles {
    by_name: std::collections::HashMap<String, Vec<(String, Vec<String>)>>,
}

impl KnownFiles {
    /// Index of `files` (paths relative to the scanned root).
    pub(crate) fn new(files: &[String]) -> Self {
        let mut by_name: std::collections::HashMap<String, Vec<(String, Vec<String>)>> =
            std::collections::HashMap::new();
        for fp in files {
            let parts = path_parts(fp);
            if let Some(name) = parts.last() {
                by_name
                    .entry(name.clone())
                    .or_default()
                    .push((fp.clone(), parts));
            }
        }
        KnownFiles { by_name }
    }
}

/// Returns the file from `known_files` whose path ends with `suffix`.
/// `anchored` (relative import) requires an exact end match; when not
/// anchored (absolute import), a directory prefix is tolerated but
/// only one candidate is accepted (otherwise ambiguous → None).
fn match_unique_suffix(
    suffix: &str,
    anchored: bool,
    importer: &str,
    known_files: &KnownFiles,
) -> Option<String> {
    let suffix_parts = path_parts(suffix);
    let same_name = suffix_parts
        .last()
        .and_then(|name| known_files.by_name.get(name))
        .map(Vec::as_slice)
        .unwrap_or_default();
    let candidates: Vec<&String> = same_name
        .iter()
        .filter(|(fp, _)| fp.as_str() != importer)
        .filter(|(_, fp_parts)| {
            fp_parts.len() >= suffix_parts.len()
                && fp_parts[fp_parts.len() - suffix_parts.len()..] == suffix_parts[..]
        })
        .map(|(fp, _)| fp)
        .collect();
    if candidates.len() == 1 {
        return Some(candidates[0].clone());
    }
    if anchored && !candidates.is_empty() {
        let imp_parts = path_parts(importer);
        let mut sorted = candidates;
        sorted.sort_by_key(|c| std::cmp::Reverse(common_prefix_len(&path_parts(c), &imp_parts)));
        return Some(sorted[0].clone());
    }
    None
}

/// Returns the path of the analyzed file targeted by an import, or
/// None. Relative (`level >= 1`): anchored to the importer's
/// directory (goes up `level - 1` levels), then follows the module
/// path. Absolute (`level == 0`): `mod/parts.py` suffix, resolved only
/// if it matches **exactly one** file in the set (ambiguity →
/// give up, anti-FP).
fn resolve_target_file(
    importer: &str,
    imp: &ImportInfo,
    known_files: &KnownFiles,
) -> Option<String> {
    let mod_parts: Vec<String> = if imp.module.is_empty() {
        vec![]
    } else {
        imp.module.split('.').map(|s| s.to_string()).collect()
    };

    if imp.level >= 1 {
        let importer_parts = path_parts(importer);
        let dir_parts: Vec<String> = if importer_parts.is_empty() {
            vec![]
        } else {
            importer_parts[..importer_parts.len() - 1].to_vec()
        };
        let ascend = imp.level - 1;
        if ascend > dir_parts.len() {
            return None;
        }
        let base: Vec<String> = if ascend > 0 {
            dir_parts[..dir_parts.len() - ascend].to_vec()
        } else {
            dir_parts
        };
        let mut target_parts = base;
        target_parts.extend(mod_parts);
        if target_parts.is_empty() {
            return None;
        }
        let target_suffix = format!("{}.py", target_parts.join("/"));
        return match_unique_suffix(&target_suffix, true, importer, known_files);
    }

    if mod_parts.is_empty() {
        return None;
    }
    let target_suffix = format!("{}.py", mod_parts.join("/"));
    match_unique_suffix(&target_suffix, false, importer, known_files)
}

/// The imports of a file, resolved to analyzed files and kept as written
/// (ticket #239): the explicit ones in source order, and the targets of
/// its `from mod import *`. Mirrors `_resolve_one_import` /
/// `_apply_star_imports` (module_registry.py) like the former
/// [`resolve_import_bindings`], which expanded them into one binding per
/// function of each imported module, for every file; the
/// [`ImportVisibility`] built from these entries answers each name on
/// demand, with the same precedence (Python's: explicit imports first, the
/// last one binding a name winning; then the star imports, a name defined
/// by two of them dropped; a dotted function name, `Klass.method`, is
/// never bound through a module).
fn resolve_import_entries(
    filepath: &str,
    imports: &[ImportInfo],
    known_files: &KnownFiles,
    file_function_names: &BTreeMap<String, BTreeSet<String>>,
) -> (Vec<ImportEntry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut star_targets = Vec::new();
    for imp in imports {
        if imp.orig_name == "*" {
            if let Some(target) = resolve_target_file(filepath, imp, known_files) {
                star_targets.push(target);
            }
            continue;
        }
        if imp.orig_name.is_empty() {
            // `import mod [as m]` -> calls of the form `m.func(...)`.
            if let Some(target) = resolve_target_file(filepath, imp, known_files) {
                entries.push(ImportEntry::Module {
                    local: imp.local_name.clone(),
                    target,
                });
            }
            continue;
        }
        // `from mod import X`: X is either a function or a submodule.
        if let Some(target) = resolve_target_file(filepath, imp, known_files)
            && file_function_names
                .get(&target)
                .is_some_and(|names| names.contains(&imp.orig_name))
        {
            entries.push(ImportEntry::Function {
                local: imp.local_name.clone(),
                target,
                name: imp.orig_name.clone(),
            });
            continue;
        }
        let submod_module = if imp.module.is_empty() {
            imp.orig_name.clone()
        } else {
            format!("{}.{}", imp.module, imp.orig_name)
        };
        let submod_import = ImportInfo {
            local_name: imp.local_name.clone(),
            module: submod_module,
            orig_name: String::new(),
            level: imp.level,
        };
        if let Some(submod) = resolve_target_file(filepath, &submod_import, known_files) {
            entries.push(ImportEntry::Module {
                local: imp.local_name.clone(),
                target: submod,
            });
        }
    }
    (entries, star_targets)
}

/// Returns the bindings brought in by a file's imports, indexed by
/// the **local** call name as it appears in that file's code. Mirrors
/// `_resolve_one_import`/`_apply_star_imports` (module_registry.py),
/// but returns `NodeKey` rather than `FunctionSummary` — summary
/// resolution does not happen yet at this stage (structural pre-pass
/// of the graph, independent of the specs).
///
/// Test only since ticket #239: the graph no longer builds this map for
/// every file (see [`resolve_import_entries`]); kept as the oracle its
/// lookups are checked against.
#[cfg(test)]
fn resolve_import_bindings(
    filepath: &str,
    imports: &[ImportInfo],
    known_files: &KnownFiles,
    file_function_names: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, NodeKey> {
    let mut out: BTreeMap<String, NodeKey> = BTreeMap::new();
    let mut star_imports: Vec<&ImportInfo> = Vec::new();
    let empty_set: BTreeSet<String> = BTreeSet::new();

    for imp in imports {
        if imp.orig_name == "*" {
            star_imports.push(imp);
            continue;
        }
        if imp.orig_name.is_empty() {
            // `import mod [as m]` -> calls of the form `m.func(...)`.
            if let Some(target) = resolve_target_file(filepath, imp, known_files) {
                for fname in file_function_names.get(&target).unwrap_or(&empty_set) {
                    if !fname.contains('.') {
                        out.insert(
                            format!("{}.{}", imp.local_name, fname),
                            (target.clone(), fname.clone()),
                        );
                    }
                }
            }
            continue;
        }
        // `from mod import X`: X is either a function or a submodule.
        let target = resolve_target_file(filepath, imp, known_files);
        if let Some(t) = &target
            && file_function_names
                .get(t)
                .map(|s| s.contains(&imp.orig_name))
                .unwrap_or(false)
        {
            out.insert(imp.local_name.clone(), (t.clone(), imp.orig_name.clone()));
            continue;
        }
        let submod_module = if imp.module.is_empty() {
            imp.orig_name.clone()
        } else {
            format!("{}.{}", imp.module, imp.orig_name)
        };
        let submod_import = ImportInfo {
            local_name: imp.local_name.clone(),
            module: submod_module,
            orig_name: String::new(),
            level: imp.level,
        };
        if let Some(submod) = resolve_target_file(filepath, &submod_import, known_files) {
            for fname in file_function_names.get(&submod).unwrap_or(&empty_set) {
                if !fname.contains('.') {
                    out.insert(
                        format!("{}.{}", imp.local_name, fname),
                        (submod.clone(), fname.clone()),
                    );
                }
            }
        }
    }

    if !star_imports.is_empty() {
        let mut seen: BTreeMap<String, NodeKey> = BTreeMap::new();
        let mut collided: BTreeSet<String> = BTreeSet::new();
        for imp in &star_imports {
            let Some(target) = resolve_target_file(filepath, imp, known_files) else {
                continue;
            };
            for fname in file_function_names.get(&target).unwrap_or(&empty_set) {
                if fname.contains('.') {
                    continue;
                }
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
        for (name, key) in seen {
            if !collided.contains(&name) && !out.contains_key(&name) {
                out.insert(name, key);
            }
        }
    }
    out
}

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

/// Local call name of a `call` node: `foo` for `foo(...)`, `m.func`
/// for `m.func(...)`. `None` for forms not statically resolvable
/// (call on an expression, instance method with no type info — out of
/// scope, stays over-approximated as it does today).
fn call_local_name(call_node: Node, source: &[u8]) -> Option<String> {
    let func = call_node.child_by_field_name("function")?;
    match func.kind() {
        "identifier" => Some(text(func, source)),
        "attribute" => {
            let obj = func.child_by_field_name("object")?;
            if obj.kind() != "identifier" {
                return None;
            }
            let attr = func.child_by_field_name("attribute")?;
            Some(format!("{}.{}", text(obj, source), text(attr, source)))
        }
        _ => None,
    }
}

fn walk_calls<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) {
    if node.kind() == "call" {
        out.push(node);
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        walk_calls(child, out);
    }
}

/// The local names ([`call_local_name`]) of the calls under `def_node`
/// (a `function_definition`, nested functions and decorators included),
/// in the order [`walk_calls`] lists them, the order in which the first
/// resolution of a name wins (ticket #281). A call without a local name
/// is not kept: no edge was ever drawn from it.
fn call_names(def_node: Node, source: &[u8]) -> Vec<String> {
    let mut calls = Vec::new();
    walk_calls(def_node, &mut calls);
    calls
        .into_iter()
        .filter_map(|call| call_local_name(call, source))
        .collect()
}

/// What the call graph needs from one Python file, read from its tree
/// once ([`PythonFile::extract`], ticket #281): no node of the tree is
/// kept.
pub struct PythonFile {
    /// The module top level and the functions, prepared for every rule.
    prepared: PreparedFile<FunctionInfo>,
    /// The local names of the calls of each function of `prepared`, at
    /// the same index ([`call_names`]).
    calls: Vec<Vec<String>>,
    /// The imports, in source order, those inside functions included.
    imports: Vec<ImportInfo>,
}

impl PythonFile {
    /// Reads the file whose tree is `root`, parsed from `source`.
    pub fn extract(root: Node<'_>, source: &[u8]) -> Self {
        let functions = collect_functions(root, source);
        let calls = functions
            .iter()
            .map(|function| call_names(function.def_node, source))
            .collect();
        PythonFile {
            imports: collect_imports(root, source),
            calls,
            prepared: prepare_python_functions(root, functions, source),
        }
    }
}

/// Returns a function's outgoing edges from the local names of its calls
/// ([`call_names`]): local call name → target
/// node. Resolves two cases: a call to a function in the **same
/// file** (direct name in `local_names`), and a call to an
/// **imported** function (via `import_bindings`). Other call forms
/// remain unresolved — unchanged current behavior (SCA-9
/// over-approximation in `eval_call`).
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
        if local_names.contains(&local_name) {
            edges.insert(local_name.clone(), (filepath.to_string(), local_name));
        } else if let Some(target) = visibility.binding(filepath, &local_name) {
            edges.insert(local_name.clone(), target);
        }
    }
    edges
}

// ============================================================================
// CallGraph
// ============================================================================

/// An already-parsed Python file, ready to be integrated into the
/// graph.
pub struct FileInput<'tree> {
    pub filepath: String,
    pub root: Node<'tree>,
    pub source: &'tree [u8],
}

/// The summaries of a previous run and the files whose text changed since:
/// what `resolve_summaries_incremental` may reuse.
pub struct SummaryReuse<'a> {
    /// Every summary of the previous run, by function (`None` absent:
    /// the function had none).
    pub previous: &'a BTreeMap<NodeKey, Arc<FunctionSummary>>,
    /// Files new, modified, or whose `dependency_fingerprint` changed.
    pub dirty_files: &'a BTreeSet<String>,
}

/// Result of `resolve_summaries_incremental`.
#[derive(Default)]
pub struct ResolvedSummaries {
    /// Summaries of each file's own functions.
    pub own: SummariesByFile,
    /// Summaries each file imports, by local name.
    pub extra: SummariesByFile,
    /// Every summary, by function: what the cache stores for the next run.
    /// Shared (`Arc`): Java's taint analysis of each file looks up the
    /// summaries its package and imports expose in it (ticket #239).
    pub all: Arc<BTreeMap<NodeKey, Arc<FunctionSummary>>>,
    /// Functions whose summary differs from the previous run.
    pub changed: BTreeSet<NodeKey>,
    /// Functions whose summary was computed rather than reused.
    pub recomputed: usize,
}

/// Call graph of a set of Python files analyzed together.
///
/// `nodes`: every known function/method, indexed by (file, name).
/// `edges`: for each node, its resolved outgoing calls (local call
/// name → target node) — a subset of the real calls (a call that
/// cannot be statically resolved is simply absent, not an error).
#[derive(Default)]
pub struct CallGraph {
    pub nodes: BTreeMap<NodeKey, FunctionInfo>,
    pub edges: BTreeMap<NodeKey, BTreeMap<String, NodeKey>>,
    /// The resolved imports of each file, whether they are called inside a
    /// function or at module level, looked up on demand (ticket #239):
    /// the former per-file map of every imported name (`import_bindings`)
    /// held one entry per function of every module a file imports.
    visibility: Arc<ImportVisibility>,
    /// Every file of the graph prepared once for all the rules of the
    /// scan (ticket #192): read for the summaries and handed to the
    /// taint analysis of each file ([`Self::prepared_file`]).
    prepared: PreparedFiles<FunctionInfo>,
}

impl CallGraph {
    /// What each file of the graph sees of the others, shared with the
    /// taint analysis of each file (ticket #239).
    pub fn visibility(&self) -> &Arc<ImportVisibility> {
        &self.visibility
    }

    /// The prepared form of `filepath`, one of the graph's files, for
    /// the taint analysis of each rule (ticket #192).
    pub fn prepared_file(&self, filepath: &str) -> Option<&PreparedFile<FunctionInfo>> {
        self.prepared.file(filepath)
    }

    /// Builds the complete graph (nodes + edges + import bindings)
    /// from a set of already-parsed Python modules: each file is read
    /// ([`PythonFile::extract`], in parallel), then linked
    /// ([`Self::build_from`]).
    pub fn build(files: &[FileInput<'_>]) -> Self {
        Self::build_from(
            files
                .par_iter()
                .map(|f| (f.filepath.clone(), PythonFile::extract(f.root, f.source)))
                .collect(),
        )
    }

    /// Builds the complete graph from the files already read, by path,
    /// without any tree (ticket #281).
    pub fn build_from(files: Vec<(String, PythonFile)>) -> Self {
        let mut graph = CallGraph::default();
        let mut file_function_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut imports_by_file: BTreeMap<String, Vec<ImportInfo>> = BTreeMap::new();
        // The calls of each node. Homonyms: the last one, as in `nodes`
        // and `PreparedFiles::index_node`.
        let mut calls_by_node: BTreeMap<NodeKey, Vec<String>> = BTreeMap::new();

        // Each file was prepared once for every rule of the scan (ticket
        // #192). Its collected functions are the graph nodes.
        for (filepath, file) in files {
            let PythonFile {
                prepared,
                calls,
                imports,
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
            imports_by_file.insert(filepath, imports);
        }

        let known_files: Vec<String> = file_function_names.keys().cloned().collect();
        let known_index = KnownFiles::new(&known_files);
        let mut entries = BTreeMap::new();
        let mut star_targets = BTreeMap::new();
        for filepath in &known_files {
            let imports = imports_by_file.get(filepath).cloned().unwrap_or_default();
            let (file_entries, file_stars) =
                resolve_import_entries(filepath, &imports, &known_index, &file_function_names);
            entries.insert(filepath.clone(), file_entries);
            star_targets.insert(filepath.clone(), file_stars);
        }
        graph.visibility = Arc::new(ImportVisibility::new(
            entries,
            star_targets,
            BTreeMap::new(),
            file_function_names.clone(),
            false,
            false,
        ));
        for filepath in &known_files {
            let local_names = file_function_names
                .get(filepath)
                .cloned()
                .unwrap_or_default();
            // This file's functions: a range of the sorted keys, not a scan
            // of every function of the project.
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

    /// Breakdown into strongly connected components (Tarjan), returned
    /// in callees-before-callers order (guaranteed by construction: an
    /// SCC is only closed after those of all its successors).
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
                    continue; // target outside the graph (unresolved import)
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

    /// Builds a node's `specs.summaries` seed: already resolved
    /// summaries (outside the current SCC, or members of the SCC
    /// already stabilized) for its outgoing calls.
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
        let mut summary =
            compute_summary_with(&function.info, function.body.as_ref()?, &specs, lines);
        stamp_steps(&mut summary, filepath, lines.map(|l| l.lines()));
        Some(Arc::new(summary))
    }

    /// Computes the summaries of every function in the graph, in the
    /// topological order of the SCCs, seeding `specs.summaries` with
    /// the already-resolved summaries of the callees (same file or
    /// cross-file) — multi-hop resolution. A non-trivial SCC
    /// (recursion cycle) is resolved by a real bounded fixpoint between
    /// its members (Decision #3), not left unresolved.
    ///
    /// Returns `(own, extra)`:
    ///   - `own`: `{file: {function_name: FunctionSummary}}` —
    ///     functions defined in each file.
    ///   - `extra`: `{file: {local_import_name: FunctionSummary}}` —
    ///     all resolved imports of each file.
    pub fn resolve_summaries(
        &self,
        base_specs: &RuleSpecs,
        source_lines_by_file: Option<&LinesByFile>,
    ) -> (SummariesByFile, SummariesByFile) {
        let resolved = self.resolve_summaries_incremental(base_specs, source_lines_by_file, None);
        (resolved.own, resolved.extra)
    }

    /// `resolve_summaries`, reusing the summaries of a previous run where
    /// they cannot have changed (scan cache, 2026-11-14).
    ///
    /// A function keeps its previous summary when its file is not in
    /// `reuse.dirty_files` and no function it calls got a different
    /// summary in this run: its summary only depends on its own code and
    /// on its callees' summaries (`build_seed`). A cycle keeps its members'
    /// summaries on the same condition for all of them and their outside
    /// callees. Every function whose summary differs from the previous one
    /// (or that had none) is listed in `changed`, so the caller re-runs
    /// exactly the files that consume one of them. Without `reuse`, every
    /// summary is computed and listed as changed: the behavior of a full
    /// scan.
    pub fn resolve_summaries_incremental(
        &self,
        base_specs: &RuleSpecs,
        source_lines_by_file: Option<&LinesByFile>,
        reuse: Option<&SummaryReuse>,
    ) -> ResolvedSummaries {
        let empty_lines = BTreeMap::new();
        let source_lines_by_file = source_lines_by_file.unwrap_or(&empty_lines);
        // One per-line cache of the hybrid layer per file, shared by every
        // summary of this rule (ticket #190).
        let lines_for_rule = rule_lines_by_file(source_lines_by_file, base_specs);

        let sccs = self.strongly_connected_components();
        resolve_incremental(sccs, &self.edges, reuse, |node, resolved, current| {
            let seed = self.build_seed(node, resolved, current);
            self.compute_one(node, seed, base_specs, &lines_for_rule)
        })
    }

    /// The files that read a summary that changed in this run: those
    /// defining a changed function (module code and functions call each
    /// other) and those importing one. Such a file must be analysed again
    /// even if its text did not change. Computed once per rule (ticket
    /// #239): asking it file by file scanned every changed summary for
    /// every file.
    pub fn readers(&self, changed: &BTreeSet<NodeKey>) -> BTreeSet<String> {
        let mut readers = self.visibility.readers_of(changed);
        readers.extend(changed.iter().map(|node| node.0.clone()));
        readers
    }

    /// What, besides its own text, decides the analysis of `file`: its
    /// functions, the calls they resolve and the imports it resolves. It
    /// changes when another file is added, removed or renamed in a way
    /// that changes a resolution, so that a cached result is never reused
    /// against a different graph.
    pub fn dependency_fingerprint(&self, file: &str) -> String {
        graph_fingerprint(&self.edges, &self.nodes, self.visibility.as_ref(), file)
    }
}

/// The incremental summary resolution shared by every language's call
/// graph (scan cache, 2026-11-14): `sccs` in topological order (callees
/// first), the graph's `edges`, and `compute`, which computes one
/// function's summary from the summaries resolved so far and those of the
/// current cycle. See `CallGraph::resolve_summaries_incremental` for what
/// is reused and what is listed as changed.
///
/// `extra` stays empty: the summaries a file imports are no longer copied
/// into it for every file and every rule (ticket #239), the taint analysis
/// of each file looks them up through its graph's [`Visibility`]
/// (`RuleSpecs::summary_fallback`).
pub(crate) fn resolve_incremental(
    sccs: Vec<Vec<NodeKey>>,
    edges: &BTreeMap<NodeKey, BTreeMap<String, NodeKey>>,
    reuse: Option<&SummaryReuse>,
    compute: impl Fn(
        &NodeKey,
        &BTreeMap<NodeKey, Arc<FunctionSummary>>,
        &BTreeMap<NodeKey, Arc<FunctionSummary>>,
    ) -> Option<Arc<FunctionSummary>>,
) -> ResolvedSummaries {
    let mut resolved: BTreeMap<NodeKey, Arc<FunctionSummary>> = BTreeMap::new();
    let mut own: SummariesByFile = BTreeMap::new();
    let mut changed: BTreeSet<NodeKey> = BTreeSet::new();
    let mut recomputed = 0usize;

    // The previous summary of `node` (`None`: it had none), when the
    // node may reuse it; `Err(())` when it must be computed.
    let reusable = |node: &NodeKey, changed: &BTreeSet<NodeKey>, members: &[NodeKey]| {
        let reuse = reuse.ok_or(())?;
        if reuse.dirty_files.contains(&node.0) {
            return Err(());
        }
        let callees_unchanged = edges
            .get(node)
            .map(|e| {
                e.values()
                    .all(|t| members.contains(t) || !changed.contains(t))
            })
            .unwrap_or(true);
        if !callees_unchanged {
            return Err(());
        }
        Ok(reuse.previous.get(node).cloned())
    };
    let record = |node: &NodeKey,
                  summary: Option<Arc<FunctionSummary>>,
                  resolved: &mut BTreeMap<NodeKey, Arc<FunctionSummary>>,
                  own: &mut SummariesByFile,
                  changed: &mut BTreeSet<NodeKey>,
                  was_recomputed: bool| {
        if was_recomputed {
            let before = reuse.and_then(|r| r.previous.get(node));
            if reuse.is_none() || before != summary.as_ref() {
                changed.insert(node.clone());
            }
        }
        if let Some(summary) = summary {
            resolved.insert(node.clone(), summary.clone());
            own.entry(node.0.clone())
                .or_default()
                .insert(node.1.clone(), summary);
        }
    };

    for scc in sccs {
        let is_self_loop = scc.len() == 1
            && edges
                .get(&scc[0])
                .map(|e| e.values().any(|t| t == &scc[0]))
                .unwrap_or(false);

        if scc.len() == 1 && !is_self_loop {
            let node = &scc[0];
            match reusable(node, &changed, &[]) {
                Ok(previous) => {
                    record(node, previous, &mut resolved, &mut own, &mut changed, false)
                }
                Err(()) => {
                    let summary = compute(node, &resolved, &BTreeMap::new());
                    recomputed += 1;
                    record(node, summary, &mut resolved, &mut own, &mut changed, true);
                }
            }
            continue;
        }

        // A cycle keeps its previous summaries only as a whole.
        let previous: Option<Vec<Option<Arc<FunctionSummary>>>> = scc
            .iter()
            .map(|node| reusable(node, &changed, &scc).ok())
            .collect();
        if let Some(previous) = previous {
            for (node, summary) in scc.iter().zip(previous) {
                record(node, summary, &mut resolved, &mut own, &mut changed, false);
            }
            continue;
        }

        // Real cycle (multi-node SCC, or direct self-recursion):
        // bounded fixpoint between the members.
        let mut current: BTreeMap<NodeKey, Arc<FunctionSummary>> = BTreeMap::new();
        for _ in 0..MAX_SCC_FIXPOINT_ITER {
            let mut next: BTreeMap<NodeKey, Arc<FunctionSummary>> = BTreeMap::new();
            for node in &scc {
                if let Some(summary) = compute(node, &resolved, &current) {
                    next.insert(node.clone(), summary);
                }
            }
            let converged = next == current;
            current = next;
            if converged {
                break;
            }
        }
        for node in &scc {
            recomputed += 1;
            let summary = current.remove(node);
            record(node, summary, &mut resolved, &mut own, &mut changed, true);
        }
    }

    ResolvedSummaries {
        own,
        extra: BTreeMap::new(),
        all: Arc::new(resolved),
        changed,
        recomputed,
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
    fn build_checked(files: &[FileInput]) -> CallGraph {
        let graph = CallGraph::build(files);
        assert_edges_match_trees(&graph, files);
        graph
    }

    /// See [`build_checked`]; returns the number of edges compared.
    fn assert_edges_match_trees(graph: &CallGraph, files: &[FileInput]) -> usize {
        let mut compared = 0;
        for f in files {
            let functions = collect_functions(f.root, f.source);
            let local_names: BTreeSet<String> = functions
                .iter()
                .map(|function| function.info.name.clone())
                .collect();
            // The node of each graph node: the last homonym, as the graph
            // keeps.
            let nodes: BTreeMap<String, Node> = functions
                .iter()
                .map(|function| (function.info.name.clone(), function.def_node))
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
        let lang: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
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
    fn test_resolve_target_file_relative_single_dot() {
        let known = vec!["pkg/a.py".to_string(), "pkg/utils.py".to_string()];
        let imp = ImportInfo {
            local_name: "utils".to_string(),
            module: "utils".to_string(),
            orig_name: "utils".to_string(),
            level: 1,
        };
        assert_eq!(
            resolve_target_file("pkg/a.py", &imp, &KnownFiles::new(&known)),
            Some("pkg/utils.py".to_string())
        );
    }

    #[test]
    fn test_resolve_target_file_absolute_ambiguous_gives_up() {
        let known = vec!["a/utils.py".to_string(), "b/utils.py".to_string()];
        let imp = ImportInfo {
            local_name: "utils".to_string(),
            module: "utils".to_string(),
            orig_name: "".to_string(),
            level: 0,
        };
        assert_eq!(
            resolve_target_file("main.py", &imp, &KnownFiles::new(&known)),
            None,
            "ambiguïté -> anti-FP, abandon"
        );
    }

    #[test]
    fn test_build_intra_file_edge_same_file_call() {
        let (tree, src) = (
            parse("def helper(x):\n    pass\n\ndef main():\n    helper(1)\n"),
            b"def helper(x):\n    pass\n\ndef main():\n    helper(1)\n".to_vec(),
        );
        let files = vec![FileInput {
            filepath: "m.py".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = build_checked(&files);
        let edges = &graph.edges[&("m.py".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("helper"),
            Some(&("m.py".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_build_cross_file_import_edge() {
        let src_a = b"from utils import helper\n\ndef main():\n    helper(1)\n".to_vec();
        let src_u = b"def helper(x):\n    pass\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.py".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.py".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = build_checked(&files);
        let edges = &graph.edges[&("a.py".to_string(), "main".to_string())];
        assert_eq!(
            edges.get("helper"),
            Some(&("utils.py".to_string(), "helper".to_string()))
        );
    }

    #[test]
    fn test_resolve_summaries_multi_hop_sink_propagation() {
        // a.py: main() -> helper() (utils.py) -> os.system(x): the sink
        // must be resolved at main()'s level via helper's summary.
        let src_a =
            b"from utils import helper\n\ndef main(user_input):\n    helper(user_input)\n".to_vec();
        let src_u = b"import os\n\ndef helper(cmd):\n    os.system(cmd)\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.py".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.py".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = build_checked(&files);
        let specs = specs_with(vec![SinkSpec::new("os.system")]);
        let (own, _extra) = graph.resolve_summaries(&specs, None);

        let helper_summary = &own["utils.py"]["helper"];
        assert!(
            helper_summary.sink_param_findings.contains_key(&0),
            "helper: param 0 atteint os.system"
        );

        // main() does NOT call os.system directly: without multi-hop
        // resolution, no sink would be seen here. With the graph,
        // helper's summary is seeded into specs.summaries when
        // computing main's summary -> the sink must appear.
        let main_summary = &own["a.py"]["main"];
        assert!(
            main_summary.sink_param_findings.contains_key(&0),
            "main: param 0 (user_input) atteint le sink via helper (multi-hop)"
        );

        // The path keeps the real sink, in its own file, and the call
        // to helper in a.py: the report shows both lines.
        let flow = &main_summary.sink_param_findings[&0].flow;
        let sink = flow.iter().rev().find(|s| s.kind == "sink").unwrap();
        assert_eq!(
            (sink.file.as_deref(), sink.line),
            (Some("utils.py"), 4),
            "{flow:?}"
        );
        assert!(
            flow.iter().any(|s| s.kind == "propagation"
                && s.file.as_deref() == Some("a.py")
                && s.line == 4),
            "{flow:?}"
        );
    }

    #[test]
    fn test_resolve_summaries_mutual_recursion_does_not_hang_and_resolves() {
        // Direct cycle: f calls g, g calls f. An SCC fixpoint must
        // converge (no infinite loop) and resolve at least partially
        // the flow through the cycle.
        let src = b"def f(x):\n    return g(x)\n\ndef g(y):\n    return f(y)\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.py".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = build_checked(&files);
        let specs = specs_with(vec![]);
        let (own, _extra) = graph.resolve_summaries(&specs, None);
        assert!(own["m.py"].contains_key("f"));
        assert!(own["m.py"].contains_key("g"));
    }

    #[test]
    fn test_resolve_summaries_direct_self_recursion_terminates() {
        let src =
            b"def fact(n):\n    if n <= 1:\n        return 1\n    return fact(n - 1)\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.py".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = build_checked(&files);
        let specs = specs_with(vec![]);
        let (own, _extra) = graph.resolve_summaries(&specs, None);
        assert!(own["m.py"].contains_key("fact"));
    }

    #[test]
    fn test_imported_summaries_found_by_local_import_name() {
        let src_a = b"import utils\n".to_vec();
        let src_u = b"def helper():\n    pass\n".to_vec();
        let tree_a = parse(std::str::from_utf8(&src_a).unwrap());
        let tree_u = parse(std::str::from_utf8(&src_u).unwrap());
        let files = vec![
            FileInput {
                filepath: "a.py".to_string(),
                root: tree_a.root_node(),
                source: &src_a,
            },
            FileInput {
                filepath: "utils.py".to_string(),
                root: tree_u.root_node(),
                source: &src_u,
            },
        ];
        let graph = build_checked(&files);
        let specs = specs_with(vec![]);
        // An imported module function, even not called, is found by the
        // name `a.py` calls it with; since ticket #239 through the graph's
        // visibility (`RuleSpecs::summary_fallback`), no longer copied
        // into `extra`.
        let resolved = graph.resolve_summaries_incremental(&specs, None, None);
        assert!(resolved.extra.is_empty(), "nothing copied into extra");
        let visibility: Arc<dyn crate::scan::dataflow::visibility::Visibility> =
            graph.visibility().clone();
        let lookup = crate::scan::dataflow::visibility::FileSummaries::new(
            visibility,
            "a.py",
            resolved.all.clone(),
        );
        use crate::scan::dataflow::transfer::SummaryLookup;
        assert!(
            lookup.get("utils.helper").is_some(),
            "an imported module function, even not called, is found from a.py"
        );
        assert!(lookup.get("utils.missing").is_none());
    }

    #[test]
    fn test_topological_order_via_scc_is_callees_before_callers() {
        let src =
            b"def leaf():\n    pass\n\ndef mid():\n    leaf()\n\ndef top():\n    mid()\n".to_vec();
        let tree = parse(std::str::from_utf8(&src).unwrap());
        let files = vec![FileInput {
            filepath: "m.py".to_string(),
            root: tree.root_node(),
            source: &src,
        }];
        let graph = build_checked(&files);
        let sccs = graph.strongly_connected_components();
        let flat: Vec<&NodeKey> = sccs.iter().flatten().collect();
        let pos = |name: &str| flat.iter().position(|(_, n)| n == name).unwrap();
        assert!(
            pos("leaf") < pos("mid"),
            "leaf (callee) doit précéder mid (caller)"
        );
        assert!(
            pos("mid") < pos("top"),
            "mid (callee) doit précéder top (caller)"
        );
    }

    /// Ticket #239: the imports kept as written and looked up on demand
    /// answer every name as the former per-file map did
    /// (`resolve_import_bindings`, the oracle), and the files to redo for a
    /// changed function are exactly those whose former map held it.
    #[test]
    fn test_lookups_match_the_materialized_import_maps() {
        let sources: &[(&str, &str)] = &[
            (
                "pkg/utils.py",
                "def helper():\n    pass\n\ndef other():\n    pass\n\nclass Klass:\n    def method(self):\n        pass\n",
            ),
            (
                "pkg/extra.py",
                "def helper():\n    pass\n\ndef unique():\n    pass\n",
            ),
            (
                "pkg/star1.py",
                "def shared():\n    pass\n\ndef s1():\n    pass\n",
            ),
            (
                "pkg/star2.py",
                "def shared():\n    pass\n\ndef s2():\n    pass\n",
            ),
            (
                "app.py",
                "import pkg.utils as u\nfrom pkg.utils import helper\nfrom pkg.extra import helper\nfrom pkg.star1 import *\nfrom pkg.star2 import *\nfrom pkg.extra import unique as uq\nfrom pkg.extra import unique as s1\nfrom pkg import utils\nimport pkg.extra as u\nfrom .pkg import star1\n",
            ),
            (
                "other/app2.py",
                "from ..pkg.utils import other\nimport pkg.star1\nfrom pkg.star1 import *\n",
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
        let graph = build_checked(&files);
        let mut names: BTreeMap<String, BTreeSet<String>> = sources
            .iter()
            .map(|(path, _)| (path.to_string(), BTreeSet::new()))
            .collect();
        for (file, name) in graph.nodes.keys() {
            names.entry(file.clone()).or_default().insert(name.clone());
        }
        let known: Vec<String> = names.keys().cloned().collect();
        let known_index = KnownFiles::new(&known);
        let all_names: BTreeSet<String> = names.values().flatten().cloned().collect();
        let mut probes = all_names.clone();
        for local in [
            "u",
            "utils",
            "uq",
            "s1",
            "pkg",
            "pkg.utils",
            "pkg.star1",
            "star1",
            "helper",
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
            let imports = collect_imports(tree.root_node(), src.as_bytes());
            let former = resolve_import_bindings(path, &imports, &known_index, &names);
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
            visibility.binding("app.py", "helper"),
            at("pkg/extra.py", "helper")
        );
        assert_eq!(visibility.binding("app.py", "shared"), None);
        assert_eq!(
            visibility.binding("app.py", "u.other"),
            at("pkg/utils.py", "other")
        );
        assert_eq!(
            visibility.binding("app.py", "u.helper"),
            at("pkg/extra.py", "helper")
        );
        assert_eq!(
            visibility.binding("app.py", "s1"),
            at("pkg/extra.py", "unique")
        );
        assert_eq!(visibility.binding("app.py", "u.Klass.method"), None);
    }
}
