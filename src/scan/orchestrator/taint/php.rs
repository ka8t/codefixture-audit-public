//! PHP taint pass: what sets PHP apart from the other languages.
//!
//! Calls are resolved across files by `dataflow::php_call_graph::
//! PhpCallGraph`, wired on 2026-08-30, with two mechanisms of its own: the
//! functions of a `require`/`include`d file all become callable, and
//! static calls resolve through a project-wide index of class names (no
//! namespace tracked). **New development, not a port**, as for JS (see
//! `php_call_graph.rs`). PHP has its own rule catalog (`language php`).

use std::collections::BTreeSet;
use std::sync::Arc;

use super::{
    TaintFindings, TaintLanguage, call_graph_inputs, file_summaries, source_lines_by_file,
};
use crate::scan::dataflow::call_graph::{NodeKey, ResolvedSummaries, SummaryReuse};
use crate::scan::dataflow::line_facts::{LinesByFile, RuleLines};
use crate::scan::dataflow::php_call_graph::PhpCallGraph;
use crate::scan::dataflow::php_taint_scan::{run_taint_rule_php, run_taint_rule_php_prepared};
use crate::scan::dataflow::transfer::RuleSpecs;
use crate::scan::dataflow::visibility::{FileSummaries, Visibility};
use crate::scan::orchestrator::{ParsedFile, SourceLanguage};

/// PHP files of the scan, linked by their call graph.
pub(in crate::scan::orchestrator) struct PhpTaint<'a> {
    call_graph: PhpCallGraph<'a>,
    source_lines: LinesByFile,
}

impl<'a> TaintLanguage<'a> for PhpTaint<'a> {
    const NAME: &'static str = "php";
    const FILE_LANGUAGES: &'static [SourceLanguage] = &[SourceLanguage::Php];
    const RULE_LANGUAGE: SourceLanguage = SourceLanguage::Php;
    const PHASE_LABEL: (&'static str, &'static str) = ("scan_phase_c_php", "phase C - PHP (taint)");

    fn build(files: &[&'a ParsedFile]) -> Self {
        PhpTaint {
            call_graph: PhpCallGraph::build(&call_graph_inputs(files)),
            source_lines: source_lines_by_file(files),
        }
    }

    fn graph_size(&self) -> Option<(usize, usize)> {
        Some(super::graph_size(
            &self.call_graph.nodes,
            &self.call_graph.edges,
        ))
    }

    fn dependency_fingerprint(&self, file: &str) -> String {
        self.call_graph.dependency_fingerprint(file)
    }

    fn resolve(&self, specs: &RuleSpecs, reuse: Option<&SummaryReuse>) -> ResolvedSummaries {
        self.call_graph
            .resolve_summaries_incremental(specs, Some(&self.source_lines), reuse)
    }

    fn readers(&self, changed: &BTreeSet<NodeKey>) -> BTreeSet<String> {
        self.call_graph.readers(changed)
    }

    fn analyse_file(
        &self,
        file: &ParsedFile,
        specs: &mut RuleSpecs,
        resolved: &ResolvedSummaries,
    ) -> TaintFindings {
        specs.summaries = file_summaries(resolved, &file.rel_path);
        // What the file imports, looked up only when `summaries` has no
        // entry (ticket #239).
        let visibility: Arc<dyn Visibility> = self.call_graph.visibility().clone();
        specs.summary_fallback = Some(Arc::new(FileSummaries::new(
            visibility,
            &file.rel_path,
            resolved.all.clone(),
        )));
        // The graph prepared every file of the pass once for all its
        // rules (ticket #192). A file it does not know cannot happen (the
        // pass is built from the files it analyzes); it would still be
        // analyzed, only prepared again for this rule.
        match self.call_graph.prepared_file(&file.rel_path) {
            Some(prepared) => run_taint_rule_php_prepared(
                prepared,
                file.bytes(),
                specs,
                Some(RuleLines::shared(&file.source, specs)),
            ),
            None => run_taint_rule_php(
                file.tree().root_node(),
                file.bytes(),
                specs,
                Some(&file.source),
            ),
        }
    }
}
