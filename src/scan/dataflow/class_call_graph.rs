//! Summary resolution shared by the call graphs of the class-based
//! languages, Java (`java_call_graph.rs`) and C# (`csharp_call_graph.rs`,
//! ticket #284).
//!
//! Both graphs have the same shape: nodes are methods and constructors
//! (`(file, "Class.method")`), edges are the calls resolved from a method
//! body (local call key, exactly as `transfer.rs::canon_callee` names the
//! callee, → target node), and the summaries are computed in a plain
//! topological order (callees before callers, post-order DFS). What differs
//! is how a call is resolved (packages and imports in Java, namespaces and
//! `using` directives in C#): each language builds its own edges and its
//! own [`Visibility`], then hands them to the functions of this module.
//!
//! The algorithm is the one `java_call_graph.rs` has always had (moved here
//! unchanged when C# got its graph, so that the two languages cannot drift
//! apart): NOT the SCC fixed point of `call_graph.rs` (Python). A node in a
//! cycle is computed last, with the summaries of the cycle's links not yet
//! resolved (better to miss a flow than invent one).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use super::call_graph::{NodeKey, ResolvedSummaries, SummariesByFile, SummaryReuse};
use super::line_facts::{LinesByFile, RuleLines};
use super::prepared::{PreparedCfg, PreparedFiles};
use super::transfer::{FunctionSummary, RuleSpecs};
use super::visibility::Visibility;

/// Outgoing edges of every node: local call key → target node.
pub type Edges = BTreeMap<NodeKey, BTreeMap<String, NodeKey>>;

/// `{caller file: {local key: {targets}}}`, derived from [`Edges`].
pub type KeyTargets = BTreeMap<String, BTreeMap<String, BTreeSet<NodeKey>>>;

/// Lazy caches derived only from the structure of a graph (`nodes` and
/// `edges`), so identical for every rule. The summaries are resolved once
/// per rule, rules running in parallel: without these caches the
/// topological order and the per-file key targets were recomputed on every
/// call (about 20 identical recomputations on a Java corpus), which, on
/// 2,000+ files (OWASP BenchmarkJava), amplified allocator contention to
/// the point of dominating the wall-clock time (profiled with `sample`,
/// 2026-08-26). `OnceLock`: thread-safe, one winner on a race.
#[derive(Default)]
pub struct GraphCaches {
    topo_order: OnceLock<Vec<NodeKey>>,
    key_targets: OnceLock<KeyTargets>,
    /// Target node → files having an edge to it (C# readers, ticket #284).
    callers: OnceLock<BTreeMap<NodeKey, BTreeSet<String>>>,
    /// File → position of its last node in `topo_order`.
    last_positions: OnceLock<BTreeMap<String, usize>>,
}

impl GraphCaches {
    /// The memoized [`topological_order`] of the graph.
    pub fn topo_order<T>(&self, nodes: &BTreeMap<NodeKey, T>, edges: &Edges) -> &[NodeKey] {
        self.topo_order
            .get_or_init(|| topological_order(nodes, edges))
    }

    /// The position, in [`Self::topo_order`], of the last node of each
    /// file: where the summary resolution drops the per-line cache of the
    /// file.
    pub fn last_positions<T>(
        &self,
        nodes: &BTreeMap<NodeKey, T>,
        edges: &Edges,
    ) -> &BTreeMap<String, usize> {
        self.last_positions.get_or_init(|| {
            self.topo_order(nodes, edges)
                .iter()
                .enumerate()
                .map(|(position, node)| (node.0.clone(), position))
                .collect()
        })
    }

    /// The memoized [`key_targets`] of the graph.
    pub fn key_targets(&self, edges: &Edges) -> &KeyTargets {
        self.key_targets.get_or_init(|| key_targets(edges))
    }

    /// The memoized index target node → files whose methods have an edge
    /// to it.
    pub fn callers(&self, edges: &Edges) -> &BTreeMap<NodeKey, BTreeSet<String>> {
        self.callers.get_or_init(|| {
            let mut callers: BTreeMap<NodeKey, BTreeSet<String>> = BTreeMap::new();
            for ((caller_file, _), targets) in edges {
                for target in targets.values() {
                    callers
                        .entry(target.clone())
                        .or_default()
                        .insert(caller_file.clone());
                }
            }
            callers
        })
    }
}

/// A callees-before-callers order of `nodes` (post-order DFS over
/// `edges`, nodes visited in key order). A cycle leaves the revisited link
/// unreordered: it is computed without that callee resolved yet (no
/// invented flow).
pub fn topological_order<T>(nodes: &BTreeMap<NodeKey, T>, edges: &Edges) -> Vec<NodeKey> {
    let mut order = Vec::new();
    let mut visited: BTreeSet<NodeKey> = BTreeSet::new();
    let mut in_progress: BTreeSet<NodeKey> = BTreeSet::new();
    for node in nodes.keys() {
        visit_topo(
            node,
            nodes,
            edges,
            &mut visited,
            &mut in_progress,
            &mut order,
        );
    }
    order
}

fn visit_topo<T>(
    node: &NodeKey,
    nodes: &BTreeMap<NodeKey, T>,
    edges: &Edges,
    visited: &mut BTreeSet<NodeKey>,
    in_progress: &mut BTreeSet<NodeKey>,
    order: &mut Vec<NodeKey>,
) {
    if visited.contains(node) || !nodes.contains_key(node) || in_progress.contains(node) {
        return;
    }
    in_progress.insert(node.clone());
    if let Some(targets) = edges.get(node) {
        for target in targets.values() {
            visit_topo(target, nodes, edges, visited, in_progress, order);
        }
    }
    in_progress.remove(node);
    visited.insert(node.clone());
    order.push(node.clone());
}

/// `{caller file: {local key: {targets}}}`: every target each local call
/// key of a file designates, over all the methods of that file.
pub fn key_targets(edges: &Edges) -> KeyTargets {
    let mut out: KeyTargets = BTreeMap::new();
    for ((caller_file, _caller_name), targets) in edges {
        for (local_key, target) in targets {
            out.entry(caller_file.clone())
                .or_default()
                .entry(local_key.clone())
                .or_default()
                .insert(target.clone());
        }
    }
    out
}

/// What [`resolve_in_topological_order`] reads from a graph.
pub struct ClassGraphView<'g, F> {
    /// Callees-before-callers order of the nodes ([`GraphCaches::topo_order`]).
    pub order: &'g [NodeKey],
    /// Outgoing edges of every node.
    pub edges: &'g Edges,
    /// [`key_targets`] of `edges` ([`GraphCaches::key_targets`]).
    pub key_targets: &'g KeyTargets,
    /// The prepared bodies of the nodes.
    pub prepared: &'g PreparedFiles<F>,
    /// What each file sees of the others.
    pub visibility: &'g dyn Visibility,
    /// Position in `order` of the last node of each file
    /// ([`GraphCaches::last_positions`]).
    pub last_positions: &'g BTreeMap<String, usize>,
}

/// What [`resolve_in_topological_order`] needs from the language.
pub struct ClassLanguageHooks<C, A> {
    /// Summary of one method from its metadata and prepared body
    /// (`compute_java_summary_with`, `compute_csharp_summary_with`).
    pub compute: C,
    /// Adds the bare-name aliases of a file's summaries
    /// (`java_summary::add_bare_name_aliases`, its C# twin).
    pub add_bare_name_aliases: A,
}

/// Computes the summaries of every method of the graph for one rule, in
/// topological order, each method seeded with the summaries of its already
/// resolved callees (multi-hop resolution), reusing the summaries of a
/// previous scan where they cannot have changed (`reuse`, scan cache,
/// issue #183).
///
/// A method keeps its previous summary when its file is clean and none of
/// its callees changed in this scan, which gives exactly the seed a full
/// scan would give it.
///
/// After the loop:
/// - `own[file]` gets the bare-name aliases of the language (an
///   unqualified call `runQuery(x)` targets the same class): without them a
///   bare call resolved as an edge seeds the caller's summary but stays
///   invisible to the final analysis of the caller, which looks the literal
///   bare key up (calibration on OWASP BenchmarkJava, F1 99.9 % → 88.8 %
///   before this fix, Audit/docs/ROADMAP.md § v2.0.0);
/// - every local call key of the edges (`this.foo`, `super.foo`,
///   `Class.method`, `recv.method` through the declared type) whose targets
///   in the file are a single node is exposed under that key, in `own`
///   when the target is in the same file, in `extra` otherwise unless the
///   visibility already binds the key to a resolved summary (a WebGoat case,
///   `super.execute(...)` cross-file, was missed without this). Two methods
///   of a file using the same key for different targets: nothing is
///   exposed for that key (a missed flow rather than an invented one).
///
/// What a file sees through its visibility is not copied into `extra`
/// (ticket #239): its analysis looks it up on demand
/// ([`super::visibility::FileSummaries`]).
pub fn resolve_in_topological_order<F, C, A>(
    graph: ClassGraphView<'_, F>,
    hooks: ClassLanguageHooks<C, A>,
    base_specs: &RuleSpecs,
    source_lines_by_file: Option<&LinesByFile>,
    reuse: Option<&SummaryReuse>,
) -> ResolvedSummaries
where
    C: Fn(&F, &PreparedCfg, &RuleSpecs, Option<&RuleLines>) -> FunctionSummary,
    A: Fn(&mut BTreeMap<String, Arc<FunctionSummary>>),
{
    let mut changed: BTreeSet<NodeKey> = BTreeSet::new();
    let mut recomputed = 0usize;
    let empty_lines = BTreeMap::new();
    let source_lines_by_file = source_lines_by_file.unwrap_or(&empty_lines);
    // One per-line cache of the hybrid layer per file, shared by every
    // summary of this rule (ticket #190), held only from the first node of
    // the file in `order` to its last one (ticket #284): the cache of a file
    // grows with the lines its summaries read, and holding the caches of
    // every file of the project until the end of the rule, as
    // `rule_lines_by_file` did, kept them all alive at once for every rule
    // running. The facts of a line do not depend on when they are
    // computed: dropping a cache only recomputes them, the summaries are
    // the same.
    let mut open_lines: BTreeMap<&str, RuleLines> = BTreeMap::new();

    let mut resolved: BTreeMap<NodeKey, Arc<FunctionSummary>> = BTreeMap::new();
    let mut own: SummariesByFile = BTreeMap::new();

    // Cloned once before the loop (sources, sinks, sanitizers,
    // passthroughs, each with their compiled regexes) rather than per
    // node: only `.summaries` varies per node. `base_specs.summaries` is
    // always empty on entry (built by `rule_json_to_specs`), so replacing
    // it with the seed of each node, even an empty one, is exact.
    let mut node_specs = base_specs.clone();
    for (position, node) in graph.order.iter().enumerate() {
        'node: {
            let (filepath, name) = node.clone();
            let Some(function) = graph.prepared.function(node) else {
                break 'node;
            };
            let Some(body) = function.body.as_ref() else {
                break 'node;
            };
            if let Some(reuse) = reuse
                && !reuse.dirty_files.contains(&filepath)
                && graph
                    .edges
                    .get(node)
                    .is_none_or(|e| e.values().all(|t| !changed.contains(t)))
                && let Some(previous) = reuse.previous.get(node)
            {
                resolved.insert(node.clone(), previous.clone());
                own.entry(filepath)
                    .or_default()
                    .insert(name, previous.clone());
                break 'node;
            }
            let mut seed: BTreeMap<String, Arc<FunctionSummary>> = BTreeMap::new();
            if let Some(edges) = graph.edges.get(node) {
                for (local_name, target) in edges {
                    if let Some(s) = resolved.get(target) {
                        seed.insert(local_name.clone(), s.clone());
                    }
                }
            }
            node_specs.summaries = seed;
            let lines = source_lines_by_file.get(&filepath).map(|file_lines| {
                &*open_lines
                    .entry(node.0.as_str())
                    .or_insert_with(|| RuleLines::shared(file_lines, base_specs))
            });
            // `Arc::new` once per node: every later `.clone()` (here and in
            // the callers' seeds) is a reference-count bump, not a deep copy
            // of `FunctionSummary` (whose `sink_param_findings` can hold
            // costly `Finding` values). This dominated the cost on high
            // fan-in "hub" nodes of a large corpus (OWASP BenchmarkJava).
            let summary = Arc::new((hooks.compute)(&function.info, body, &node_specs, lines));
            recomputed += 1;
            if reuse.is_none_or(|r| r.previous.get(node) != Some(&summary)) {
                changed.insert(node.clone());
            }
            resolved.insert(node.clone(), summary.clone());
            own.entry(filepath).or_default().insert(name, summary);
        }
        if graph.last_positions.get(&node.0) == Some(&position) {
            open_lines.remove(node.0.as_str());
        }
    }

    for summaries in own.values_mut() {
        (hooks.add_bare_name_aliases)(summaries);
    }

    let mut extra: SummariesByFile = BTreeMap::new();
    for (caller_file, key_targets) in graph.key_targets {
        for (local_key, targets) in key_targets {
            if targets.len() != 1 {
                continue;
            }
            let target = targets.iter().next().expect("one target");
            let Some(s) = resolved.get(target) else {
                continue;
            };
            let bucket = if &target.0 == caller_file {
                &mut own
            } else {
                // A key that the file's visibility already resolves to a
                // summary keeps that one: the former `extra` held those
                // first and these aliases did not replace them.
                if graph
                    .visibility
                    .binding(caller_file, local_key)
                    .is_some_and(|bound| resolved.contains_key(&bound))
                {
                    continue;
                }
                &mut extra
            };
            bucket
                .entry(caller_file.clone())
                .or_default()
                .entry(local_key.clone())
                .or_insert_with(|| s.clone());
        }
    }

    ResolvedSummaries {
        own,
        extra,
        all: Arc::new(resolved),
        changed,
        recomputed,
    }
}
