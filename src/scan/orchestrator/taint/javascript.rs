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

use std::collections::BTreeSet;
use std::sync::Arc;

use super::{TaintFile, TaintFindings, TaintLanguage, file_summaries, missing_prepared_file};
use crate::scan::dataflow::call_graph::{NodeKey, ResolvedSummaries, SummaryReuse};
use crate::scan::dataflow::js_call_graph::{JsCallGraph, JsFile};
use crate::scan::dataflow::js_taint_scan::run_taint_rule_js_prepared;
use crate::scan::dataflow::line_facts::{LinesByFile, RuleLines};
use crate::scan::dataflow::transfer::RuleSpecs;
use crate::scan::dataflow::visibility::{FileSummaries, Visibility};
use crate::scan::orchestrator::{ParsedFile, SourceLanguage};
use tree_sitter::Node;

/// JavaScript and TypeScript files of the scan, linked by their call graph.
pub(in crate::scan::orchestrator) struct JsTaint {
    call_graph: JsCallGraph,
    source_lines: LinesByFile,
}

impl TaintLanguage for JsTaint {
    type File = JsFile;
    const NAME: &'static str = "javascript";
    const FILE_LANGUAGES: &'static [SourceLanguage] =
        &[SourceLanguage::JavaScript, SourceLanguage::TypeScript];
    const RULE_LANGUAGE: SourceLanguage = SourceLanguage::JavaScript;
    const PHASE_LABEL: (&'static str, &'static str) =
        ("scan_phase_c_js", "phase C - JS/TS (taint)");

    fn extract(root: Node<'_>, source: &[u8]) -> JsFile {
        JsFile::extract(root, source)
    }

    fn take(file: TaintFile) -> Option<JsFile> {
        match file {
            TaintFile::JavaScript(file) => Some(file),
            _ => None,
        }
    }

    fn build(files: Vec<(String, JsFile)>, source_lines: LinesByFile) -> Self {
        JsTaint {
            call_graph: JsCallGraph::build_from(files),
            source_lines,
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
        // pass is built from the files it analyzes); one would stop the
        // scan naming the file rather than analyse it without its
        // preparation: its tree is gone (ticket #281).
        let prepared = self
            .call_graph
            .prepared_file(&file.rel_path)
            .unwrap_or_else(|| missing_prepared_file(Self::NAME, &file.rel_path));
        run_taint_rule_js_prepared(
            prepared,
            specs,
            Some(RuleLines::shared(&file.source, specs)),
        )
    }
}
