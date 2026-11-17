//! Python taint pass: what sets Python apart from the other languages.
//!
//! Calls are resolved across files by `dataflow::call_graph::CallGraph`
//! (imports resolved by module path), built once per scan; mirrors
//! `dataflow_adapter.py` on the Python source side.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    TaintFindings, TaintLanguage, call_graph_inputs, file_summaries, source_lines_by_file,
};
use crate::scan::dataflow::call_graph::{CallGraph, NodeKey, ResolvedSummaries, SummaryReuse};
use crate::scan::dataflow::taint_scan::{run_taint_rule, run_taint_rule_prepared};
use crate::scan::dataflow::transfer::RuleSpecs;
use crate::scan::orchestrator::{ParsedFile, SourceLanguage};

/// Python files of the scan, linked by their call graph.
pub(in crate::scan::orchestrator) struct PythonTaint<'a> {
    call_graph: CallGraph<'a>,
    source_lines: BTreeMap<String, Vec<String>>,
}

impl<'a> TaintLanguage<'a> for PythonTaint<'a> {
    const NAME: &'static str = "python";
    const FILE_LANGUAGES: &'static [SourceLanguage] = &[SourceLanguage::Python];
    const RULE_LANGUAGE: SourceLanguage = SourceLanguage::Python;
    const PHASE_LABEL: (&'static str, &'static str) =
        ("scan_phase_c_python", "phase C - Python (taint)");

    fn build(files: &[&'a ParsedFile]) -> Self {
        PythonTaint {
            call_graph: CallGraph::build(&call_graph_inputs(files)),
            source_lines: source_lines_by_file(files),
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
        // The graph prepared every file of the pass once for all its
        // rules (ticket #192). A file it does not know cannot happen (the
        // pass is built from the files it analyzes); it would still be
        // analyzed, only prepared again for this rule.
        match self.call_graph.prepared_file(&file.rel_path) {
            Some(prepared) => run_taint_rule_prepared(
                prepared,
                &file.source_bytes,
                specs,
                Some(&file.source_lines_plain),
            ),
            None => run_taint_rule(
                &file.tree,
                &file.source_bytes,
                specs,
                Some(&file.source_lines_plain),
            ),
        }
    }
}
