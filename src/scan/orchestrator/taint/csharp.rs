//! C# taint pass: what sets C# apart from the other languages.
//!
//! **No link between files** (tickets #78-79, spec #77): there is no C#
//! call graph yet, so a call resolves only to a function of the same file.
//! The summaries of a file's functions are computed per rule on that file
//! alone, and nothing is shared between files: a file depends only on
//! itself, which is what the cache needs to know. Like Java, C# knows the
//! declared type of each field and local variable.

use std::collections::{BTreeMap, BTreeSet};

use rayon::prelude::*;

use super::{TaintFindings, TaintLanguage};
use crate::scan::dataflow::call_graph::{NodeKey, ResolvedSummaries, SummaryReuse};
use crate::scan::dataflow::csharp_summary::{
    CSharpFunctionInfo, collect_csharp_field_types, collect_csharp_local_types,
    compute_csharp_file_summaries_prepared, prepare_csharp_file,
};
use crate::scan::dataflow::csharp_taint_scan::run_taint_rule_csharp_prepared;
use crate::scan::dataflow::line_facts::RuleLines;
use crate::scan::dataflow::prepared::PreparedFile;
use crate::scan::dataflow::transfer::RuleSpecs;
use crate::scan::orchestrator::{ParsedFile, SourceLanguage};

/// C# files of the scan, each with its declared types.
pub(in crate::scan::orchestrator) struct CSharpTaint<'a> {
    /// Variable or field name → declared class, per file.
    type_maps: BTreeMap<String, BTreeMap<String, String>>,
    /// Every file prepared once for all the rules of the scan (ticket
    /// #192); C# has no call graph to hold them.
    prepared: BTreeMap<String, PreparedFile<'a, CSharpFunctionInfo<'a>>>,
}

impl<'a> TaintLanguage<'a> for CSharpTaint<'a> {
    const NAME: &'static str = "csharp";
    const FILE_LANGUAGES: &'static [SourceLanguage] = &[SourceLanguage::CSharp];
    const RULE_LANGUAGE: SourceLanguage = SourceLanguage::CSharp;
    const PHASE_LABEL: (&'static str, &'static str) =
        ("scan_phase_c_csharp", "phase C - C# (taint)");

    fn build(files: &[&'a ParsedFile]) -> Self {
        let type_maps = files
            .iter()
            .map(|pf| {
                let root = pf.tree().root_node();
                let mut type_map = collect_csharp_field_types(root, pf.bytes());
                type_map.extend(collect_csharp_local_types(root, pf.bytes()));
                (pf.rel_path.clone(), type_map)
            })
            .collect();
        // In parallel: a file only reads its own tree.
        let prepared = files
            .par_iter()
            .map(|pf| {
                (
                    pf.rel_path.clone(),
                    prepare_csharp_file(pf.tree().root_node(), pf.bytes()),
                )
            })
            .collect();
        CSharpTaint {
            type_maps,
            prepared,
        }
    }

    /// A file resolves nothing from the others.
    fn graph_size(&self) -> Option<(usize, usize)> {
        None // No call graph: each C# file is analysed alone.
    }

    fn dependency_fingerprint(&self, _file: &str) -> String {
        String::new()
    }

    /// No summary is shared between files: each file computes its own in
    /// [`Self::analyse_file`].
    fn resolve(&self, _specs: &RuleSpecs, _reuse: Option<&SummaryReuse>) -> ResolvedSummaries {
        ResolvedSummaries::default()
    }

    /// A file reads no summary of another file.
    fn readers(&self, _changed: &BTreeSet<NodeKey>) -> BTreeSet<String> {
        BTreeSet::new()
    }

    fn analyse_file(
        &self,
        file: &ParsedFile,
        specs: &mut RuleSpecs,
        _resolved: &ResolvedSummaries,
    ) -> TaintFindings {
        // Back to the rule's own specs (no summaries, no types) before
        // computing this file's summaries, as fresh specs would be: the
        // previous file left its own in `specs`.
        specs.summaries = Default::default();
        specs.type_map = Default::default();
        // The file was prepared once for all the rules, in `build`; a
        // file it does not know cannot happen, it would only be prepared
        // again here.
        let fresh;
        let prepared = match self.prepared.get(&file.rel_path) {
            Some(prepared) => prepared,
            None => {
                fresh = prepare_csharp_file(file.tree().root_node(), file.bytes());
                &fresh
            }
        };
        // The guard facts of the lines are shared by every rule (ticket
        // #240); the other facts are bound to this rule.
        let lines = &file.source;
        specs.summaries = compute_csharp_file_summaries_prepared(
            prepared,
            specs,
            Some(RuleLines::shared(lines, specs)),
        );
        specs.type_map = self
            .type_maps
            .get(&file.rel_path)
            .cloned()
            .unwrap_or_default();
        run_taint_rule_csharp_prepared(prepared, specs, Some(RuleLines::shared(lines, specs)))
    }
}
