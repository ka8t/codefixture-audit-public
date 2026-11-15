//! C# taint pass: what sets C# apart from the other languages.
//!
//! **No link between files** (tickets #78-79, spec #77): there is no C#
//! call graph yet, so a call resolves only to a function of the same file.
//! The summaries of a file's functions are computed per rule on that file
//! alone, and nothing is shared between files: a file depends only on
//! itself, which is what the cache needs to know. Like Java, C# knows the
//! declared type of each field and local variable.

use std::collections::{BTreeMap, BTreeSet};

use super::{TaintFindings, TaintLanguage};
use crate::scan::dataflow::call_graph::{NodeKey, ResolvedSummaries, SummaryReuse};
use crate::scan::dataflow::csharp_summary::{
    collect_csharp_field_types, collect_csharp_local_types, compute_csharp_file_summaries,
};
use crate::scan::dataflow::csharp_taint_scan::run_taint_rule_csharp;
use crate::scan::dataflow::transfer::RuleSpecs;
use crate::scan::orchestrator::{ParsedFile, SourceLanguage};

/// C# files of the scan, each with its declared types.
pub(in crate::scan::orchestrator) struct CSharpTaint {
    /// Variable or field name → declared class, per file.
    type_maps: BTreeMap<String, BTreeMap<String, String>>,
}

impl<'a> TaintLanguage<'a> for CSharpTaint {
    const NAME: &'static str = "csharp";
    const FILE_LANGUAGES: &'static [SourceLanguage] = &[SourceLanguage::CSharp];
    const RULE_LANGUAGE: SourceLanguage = SourceLanguage::CSharp;
    const PHASE_LABEL: (&'static str, &'static str) =
        ("scan_phase_c_csharp", "phase C - C# (taint)");

    fn build(files: &[&'a ParsedFile]) -> Self {
        let type_maps = files
            .iter()
            .map(|pf| {
                let root = pf.tree.root_node();
                let mut type_map = collect_csharp_field_types(root, &pf.source_bytes);
                type_map.extend(collect_csharp_local_types(root, &pf.source_bytes));
                (pf.rel_path.clone(), type_map)
            })
            .collect();
        CSharpTaint { type_maps }
    }

    /// A file resolves nothing from the others.
    fn dependency_fingerprint(&self, _file: &str) -> String {
        String::new()
    }

    /// No summary is shared between files: each file computes its own in
    /// [`Self::analyse_file`].
    fn resolve(&self, _specs: &RuleSpecs, _reuse: Option<&SummaryReuse>) -> ResolvedSummaries {
        ResolvedSummaries::default()
    }

    /// A file reads no summary of another file.
    fn consumes_changed(&self, _file: &str, _changed: &BTreeSet<NodeKey>) -> bool {
        false
    }

    fn analyse_file(
        &self,
        file: &ParsedFile,
        specs: &mut RuleSpecs,
        _resolved: &ResolvedSummaries,
    ) -> TaintFindings {
        let root = file.tree.root_node();
        // Back to the rule's own specs (no summaries, no types) before
        // computing this file's summaries, as fresh specs would be: the
        // previous file left its own in `specs`.
        specs.summaries = Default::default();
        specs.type_map = Default::default();
        let summaries = compute_csharp_file_summaries(
            root,
            specs,
            &file.source_bytes,
            Some(&file.source_lines_plain),
        );
        specs.summaries = summaries;
        specs.type_map = self.type_maps.get(&file.rel_path).cloned().unwrap_or_default();
        run_taint_rule_csharp(root, &file.source_bytes, specs, Some(&file.source_lines_plain))
    }
}
