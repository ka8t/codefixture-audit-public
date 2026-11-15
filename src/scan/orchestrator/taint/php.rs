//! PHP taint pass: what sets PHP apart from the other languages.
//!
//! Calls are resolved across files by `dataflow::php_call_graph::
//! PhpCallGraph`, wired on 2026-08-30, with two mechanisms of its own: the
//! functions of a `require`/`include`d file all become callable, and
//! static calls resolve through a project-wide index of class names (no
//! namespace tracked). **New development, not a port**, as for JS (see
//! `php_call_graph.rs`). PHP has its own rule catalog (`language php`).

use std::collections::{BTreeMap, BTreeSet};

use super::{
    TaintFindings, TaintLanguage, call_graph_inputs, file_summaries, source_lines_by_file,
};
use crate::scan::dataflow::call_graph::{NodeKey, ResolvedSummaries, SummaryReuse};
use crate::scan::dataflow::php_call_graph::PhpCallGraph;
use crate::scan::dataflow::php_taint_scan::run_taint_rule_php;
use crate::scan::dataflow::transfer::RuleSpecs;
use crate::scan::orchestrator::{ParsedFile, SourceLanguage};

/// PHP files of the scan, linked by their call graph.
pub(in crate::scan::orchestrator) struct PhpTaint<'a> {
    call_graph: PhpCallGraph<'a>,
    source_lines: BTreeMap<String, Vec<String>>,
}

impl<'a> TaintLanguage<'a> for PhpTaint<'a> {
    const NAME: &'static str = "php";
    const FILE_LANGUAGES: &'static [SourceLanguage] = &[SourceLanguage::Php];
    const RULE_LANGUAGE: SourceLanguage = SourceLanguage::Php;
    const PHASE_LABEL: (&'static str, &'static str) =
        ("scan_phase_c_php", "phase C - PHP (taint)");

    fn build(files: &[&'a ParsedFile]) -> Self {
        PhpTaint {
            call_graph: PhpCallGraph::build(&call_graph_inputs(files)),
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
        run_taint_rule_php(
            file.tree.root_node(),
            &file.source_bytes,
            specs,
            Some(&file.source_lines_plain),
        )
    }
}
