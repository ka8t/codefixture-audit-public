//! Java taint pass: what sets Java apart from the other languages.
//!
//! Calls are resolved across files by `dataflow::java_call_graph::
//! JavaCallGraph` (imports resolved by fully qualified class name), built
//! once per scan. Java also knows the declared type of each field and
//! local variable, so that `obj.method()` resolves through the class of
//! `obj` (Round 5); mirrors `dataflow_taint_java.py`, except that the
//! summaries are computed once by the call graph, as for Python.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    TaintFindings, TaintLanguage, call_graph_inputs, file_summaries, source_lines_by_file,
};
use crate::scan::dataflow::call_graph::{NodeKey, ResolvedSummaries, SummaryReuse};
use crate::scan::dataflow::java_call_graph::JavaCallGraph;
use crate::scan::dataflow::java_summary::{collect_java_field_types, collect_java_local_types};
use crate::scan::dataflow::java_taint_scan::run_taint_rule_java;
use crate::scan::dataflow::transfer::RuleSpecs;
use crate::scan::orchestrator::{ParsedFile, SourceLanguage};

/// Java files of the scan, linked by their call graph, with the declared
/// types of each file.
pub(in crate::scan::orchestrator) struct JavaTaint<'a> {
    call_graph: JavaCallGraph<'a>,
    source_lines: BTreeMap<String, Vec<String>>,
    /// Variable or field name → declared class, per file. Recomputed here,
    /// independently of the call graph: it is the same table as the one
    /// `JavaCallGraph::build` merges and MUST stay in sync with it (see
    /// `collect_java_field_types`; same choice as `dataflow_taint_java.py`).
    type_maps: BTreeMap<String, BTreeMap<String, String>>,
}

impl<'a> TaintLanguage<'a> for JavaTaint<'a> {
    const NAME: &'static str = "java";
    const FILE_LANGUAGES: &'static [SourceLanguage] = &[SourceLanguage::Java];
    const RULE_LANGUAGE: SourceLanguage = SourceLanguage::Java;
    const PHASE_LABEL: (&'static str, &'static str) =
        ("scan_phase_c_java", "phase C - Java (taint)");

    fn build(files: &[&'a ParsedFile]) -> Self {
        let type_maps = files
            .iter()
            .map(|pf| {
                let root = pf.tree.root_node();
                let mut type_map = collect_java_field_types(root, &pf.source_bytes);
                type_map.extend(collect_java_local_types(root, &pf.source_bytes));
                (pf.rel_path.clone(), type_map)
            })
            .collect();
        JavaTaint {
            call_graph: JavaCallGraph::build(&call_graph_inputs(files)),
            source_lines: source_lines_by_file(files),
            type_maps,
        }
    }

    fn dependency_fingerprint(&self, file: &str) -> String {
        self.call_graph.dependency_fingerprint(file)
    }

    fn resolve(&self, specs: &RuleSpecs, reuse: Option<&SummaryReuse>) -> ResolvedSummaries {
        self.call_graph
            .resolve_summaries_incremental(specs, Some(&self.source_lines), reuse)
    }

    fn consumes_changed(&self, file: &str, changed: &BTreeSet<NodeKey>) -> bool {
        self.call_graph.consumes_changed(file, changed)
    }

    fn analyse_file(
        &self,
        file: &ParsedFile,
        specs: &mut RuleSpecs,
        resolved: &ResolvedSummaries,
    ) -> TaintFindings {
        specs.summaries = file_summaries(resolved, &file.rel_path);
        specs.type_map = self.type_maps.get(&file.rel_path).cloned().unwrap_or_default();
        run_taint_rule_java(
            file.tree.root_node(),
            &file.source_bytes,
            specs,
            Some(&file.source_lines_plain),
        )
    }
}
