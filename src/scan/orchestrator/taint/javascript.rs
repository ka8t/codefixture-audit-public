//! JavaScript and TypeScript taint pass: what sets them apart from the
//! other languages.
//!
//! One pass for both: `run_taint_rule_js` works on a JS or a TS tree alike
//! (see `js_lowering.rs`) and both read the `javascript` rules. Calls are
//! resolved across files by `dataflow::js_call_graph::JsCallGraph`
//! (imports resolved by relative path), wired on 2026-08-30. **New
//! development, not a port**: the reference Python engine has no JS call
//! graph (intra-file lexical fallback only, see `js_call_graph.rs`); the
//! pass is designed by analogy with Python and Java.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    TaintFindings, TaintLanguage, call_graph_inputs, file_summaries, source_lines_by_file,
};
use crate::scan::dataflow::call_graph::{NodeKey, ResolvedSummaries, SummaryReuse};
use crate::scan::dataflow::js_call_graph::JsCallGraph;
use crate::scan::dataflow::js_taint_scan::run_taint_rule_js;
use crate::scan::dataflow::transfer::RuleSpecs;
use crate::scan::orchestrator::{ParsedFile, SourceLanguage};

/// JavaScript and TypeScript files of the scan, linked by their call graph.
pub(in crate::scan::orchestrator) struct JsTaint<'a> {
    call_graph: JsCallGraph<'a>,
    source_lines: BTreeMap<String, Vec<String>>,
}

impl<'a> TaintLanguage<'a> for JsTaint<'a> {
    const NAME: &'static str = "javascript";
    const FILE_LANGUAGES: &'static [SourceLanguage] =
        &[SourceLanguage::JavaScript, SourceLanguage::TypeScript];
    const RULE_LANGUAGE: SourceLanguage = SourceLanguage::JavaScript;
    const PHASE_LABEL: (&'static str, &'static str) =
        ("scan_phase_c_js", "phase C - JS/TS (taint)");

    fn build(files: &[&'a ParsedFile]) -> Self {
        JsTaint {
            call_graph: JsCallGraph::build(&call_graph_inputs(files)),
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
        run_taint_rule_js(
            file.tree.root_node(),
            &file.source_bytes,
            specs,
            Some(&file.source_lines_plain),
        )
    }
}
