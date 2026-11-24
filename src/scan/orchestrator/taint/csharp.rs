//! C# taint pass: what sets C# apart from the other languages.
//!
//! Calls are resolved across files by `dataflow::csharp_call_graph::
//! CSharpCallGraph` (classes found through namespaces and `using`
//! directives), built once per scan, and the summaries are computed once
//! per rule in topological order and shared between files, as for Java
//! (ticket #284, ADR-0060). Before that ticket a C# call resolved only to a
//! method of the same file, each file depending only on itself. Like Java,
//! C# knows the declared type of each field and local variable, so that
//! `obj.Method()` resolves through the class of `obj`; the table comes from
//! the call graph, which resolves its edges with the same one.

use std::collections::BTreeSet;
use std::sync::Arc;

use super::{TaintFile, TaintFindings, TaintLanguage, file_summaries, missing_prepared_file};
use crate::scan::dataflow::call_graph::{NodeKey, ResolvedSummaries, SummaryReuse};
use crate::scan::dataflow::csharp_call_graph::{CSharpCallGraph, CSharpFile};
use crate::scan::dataflow::csharp_taint_scan::run_taint_rule_csharp_prepared;
use crate::scan::dataflow::line_facts::{LinesByFile, RuleLines};
use crate::scan::dataflow::transfer::RuleSpecs;
use crate::scan::dataflow::visibility::{FileSummaries, Visibility};
use crate::scan::orchestrator::{ParsedFile, SourceLanguage};
use tree_sitter::Node;

/// C# files of the scan, linked by their call graph.
pub(in crate::scan::orchestrator) struct CSharpTaint {
    call_graph: CSharpCallGraph,
    source_lines: LinesByFile,
}

impl TaintLanguage for CSharpTaint {
    type File = CSharpFile;
    const NAME: &'static str = "csharp";
    const FILE_LANGUAGES: &'static [SourceLanguage] = &[SourceLanguage::CSharp];
    const RULE_LANGUAGE: SourceLanguage = SourceLanguage::CSharp;
    const PHASE_LABEL: (&'static str, &'static str) =
        ("scan_phase_c_csharp", "phase C - C# (taint)");

    fn extract(root: Node<'_>, source: &[u8]) -> CSharpFile {
        CSharpFile::extract(root, source)
    }

    fn take(file: TaintFile) -> Option<CSharpFile> {
        match file {
            TaintFile::CSharp(file) => Some(file),
            _ => None,
        }
    }

    fn build(files: Vec<(String, CSharpFile)>, source_lines: LinesByFile) -> Self {
        CSharpTaint {
            call_graph: CSharpCallGraph::build_from(files),
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
        // What the file sees through its namespaces and `using`
        // directives, looked up only when `summaries` has no entry (as
        // Java, ticket #239).
        let visibility: Arc<dyn Visibility> = self.call_graph.visibility().clone();
        specs.summary_fallback = Some(Arc::new(FileSummaries::new(
            visibility,
            &file.rel_path,
            resolved.all.clone(),
        )));
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
        run_taint_rule_csharp_prepared(
            prepared,
            specs,
            Some(RuleLines::shared(&file.source, specs)),
        )
    }
}
