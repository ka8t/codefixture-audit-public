//! Java taint pass: what sets Java apart from the other languages.
//!
//! Calls are resolved across files by `dataflow::java_call_graph::
//! JavaCallGraph` (imports resolved by fully qualified class name), built
//! once per scan. Java also knows the declared type of each field and
//! local variable, so that `obj.method()` resolves through the class of
//! `obj` (Round 5); mirrors `dataflow_taint_java.py`, except that the
//! summaries are computed once by the call graph, as for Python, and the
//! declared types are the graph's own table (ticket #281).

use std::collections::BTreeSet;
use std::sync::Arc;

use super::{TaintFile, TaintFindings, TaintLanguage, file_summaries, missing_prepared_file};
use crate::scan::dataflow::call_graph::{NodeKey, ResolvedSummaries, SummaryReuse};
use crate::scan::dataflow::java_call_graph::{JavaCallGraph, JavaFile};
use crate::scan::dataflow::java_taint_scan::run_taint_rule_java_prepared;
use crate::scan::dataflow::line_facts::{LinesByFile, RuleLines};
use crate::scan::dataflow::transfer::RuleSpecs;
use crate::scan::dataflow::visibility::{FileSummaries, Visibility};
use crate::scan::orchestrator::{ParsedFile, SourceLanguage};
use tree_sitter::Node;

/// Java files of the scan, linked by their call graph, with the declared
/// types of each file.
pub(in crate::scan::orchestrator) struct JavaTaint {
    call_graph: JavaCallGraph,
    source_lines: LinesByFile,
}

impl TaintLanguage for JavaTaint {
    type File = JavaFile;
    const NAME: &'static str = "java";
    const FILE_LANGUAGES: &'static [SourceLanguage] = &[SourceLanguage::Java];
    const RULE_LANGUAGE: SourceLanguage = SourceLanguage::Java;
    const PHASE_LABEL: (&'static str, &'static str) =
        ("scan_phase_c_java", "phase C - Java (taint)");

    fn extract(root: Node<'_>, source: &[u8]) -> JavaFile {
        JavaFile::extract(root, source)
    }

    fn take(file: TaintFile) -> Option<JavaFile> {
        match file {
            TaintFile::Java(file) => Some(file),
            _ => None,
        }
    }

    fn build(files: Vec<(String, JavaFile)>, source_lines: LinesByFile) -> Self {
        // The declared types of each file are the graph's own table
        // (`JavaCallGraph::type_map`): the pass used to compute it a
        // second time from the trees (ticket #281).
        JavaTaint {
            call_graph: JavaCallGraph::build_from(files),
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
        // What the file sees through its package and imports, looked up
        // only when `summaries` has no entry (ticket #239).
        let visibility: Arc<dyn Visibility> = self.call_graph.visibility().clone();
        specs.summary_fallback = Some(Arc::new(FileSummaries::new(
            visibility,
            &file.rel_path,
            resolved.all.clone(),
        )));
        // Variable or field name → declared class: the table the graph
        // resolved the file's edges with (`JavaCallGraph::type_map`), so
        // that both resolve `obj.method()` alike. Deliberate deviation
        // from `dataflow_taint_java.py`, which computes the same table a
        // second time for the analysis; the pass did too until ticket
        // #281.
        specs.type_map = self
            .call_graph
            .type_map(&file.rel_path)
            .cloned()
            .unwrap_or_default();
        // The graph prepared every file of the pass once for all its
        // rules (ticket #192). A file it does not know cannot happen (the
        // pass is built from the files it analyzes); one would stop the
        // scan naming the file rather than analyse it without its
        // preparation: its tree is gone (ticket #281).
        let prepared = self
            .call_graph
            .prepared_file(&file.rel_path)
            .unwrap_or_else(|| missing_prepared_file(Self::NAME, &file.rel_path));
        run_taint_rule_java_prepared(
            prepared,
            specs,
            Some(RuleLines::shared(&file.source, specs)),
        )
    }
}
