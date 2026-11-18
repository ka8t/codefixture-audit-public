//! Phase C of the scan: the taint passes, one per language (Python,
//! Java, JavaScript/TypeScript, PHP, C#).
//!
//! A taint pass follows untrusted data (a source) to a dangerous call (a
//! sink) for every taint rule of its language. The five passes share all
//! of their work except two things, so the module is split along that
//! line:
//!
//! - what differs per language lives in one file per language, behind the
//!   [`TaintLanguage`] trait: how the files of a project are linked
//!   together (the call graph, for the languages that have one) and how one
//!   file is analysed;
//! - what is the same for every language is written once, here:
//!   selecting the files and rules of the language, reusing the taint
//!   cache of the previous scan (`scan_cache`, issue #183), and merging
//!   the findings into the report (deduplication, suppressions, inline
//!   ignores).
//!
//! Before 2026-11-14 the five passes were five near-identical blocks of
//! `run_scan`, each passing four closures to a shared function: a fix to
//! the merge had to be repeated by hand five times (the suppression of
//! indented taint findings was, on 2026-11-14), and what set a language
//! apart was hidden among the copies.

mod csharp;
mod java;
mod javascript;
mod php;
mod python;

pub(super) use csharp::CSharpTaint;
pub(super) use java::JavaTaint;
pub(super) use javascript::JsTaint;
pub(super) use php::PhpTaint;
pub(super) use python::PythonTaint;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use rayon::prelude::*;

use super::{
    ParsedFile, PassContext, SourceLanguage, integrate_taint_finding, line_text, phase_label,
    taint_finding_to_report,
};
use crate::project::suppress::is_inline_ignored;
use crate::scan::dataflow::call_graph::{FileInput, NodeKey, ResolvedSummaries, SummaryReuse};
use crate::scan::dataflow::rule_loader::rule_json_to_specs;
use crate::scan::dataflow::summary::FunctionSummary;
use crate::scan::dataflow::transfer::RuleSpecs;
use crate::scan::scan_cache::{CacheStat, FileState, RuleState, TaintCache, sha256_hex};

/// Findings of one taint rule on one file.
pub(super) type TaintFindings = Vec<crate::scan::dataflow::transfer::Finding>;

/// Taint findings already merged into the report, by (file, rule, line,
/// source line): shared by the five passes, so that a flow found twice
/// is reported once.
///
/// The file is part of the key: without it, two files with the same line
/// number for the same rule cancelled each other out. Found on 2026-08-25
/// while calibrating Java on OWASP BenchmarkJava (recall 34% instead of
/// the ~100% expected); the Python source has the same defect.
pub(super) type SeenTaint = HashSet<(String, String, usize, Option<usize>)>;

/// What one language brings to its taint pass; everything else is shared.
///
/// A value of the type is built once per scan from the language's files
/// (its call graph, its type tables), then queried by the shared pass for
/// every taint rule. Each method states what the language does, even when
/// it does nothing (C# links no files together): no default
/// implementation, so that what sets a language apart reads in its own
/// file.
pub(super) trait TaintLanguage<'a>: Sync + Sized {
    /// Name of the language in the cache file (`taint-<name>.json.gz`)
    /// and in the cache statistics. Changing it discards existing caches.
    const NAME: &'static str;

    /// Languages of the files this pass analyses (JavaScript and
    /// TypeScript share one pass).
    const FILE_LANGUAGES: &'static [SourceLanguage];

    /// Language whose rules this pass runs (`language` of the rule).
    const RULE_LANGUAGE: SourceLanguage;

    /// Translation key and French fallback of the phase label printed
    /// when the pass ends.
    const PHASE_LABEL: (&'static str, &'static str);

    /// Prepares the pass for `files`, all of [`Self::FILE_LANGUAGES`].
    fn build(files: &[&'a ParsedFile]) -> Self;

    /// What `file` resolves from the other files (imports, calls): when
    /// it changes, the file's cached findings no longer hold. Empty when
    /// the language links no files together.
    fn dependency_fingerprint(&self, file: &str) -> String;

    /// The function summaries of every file for one rule, reusing those
    /// of the previous scan that are still valid (`reuse`).
    fn resolve(&self, specs: &RuleSpecs, reuse: Option<&SummaryReuse>) -> ResolvedSummaries;

    /// Whether `file` reads one of the summaries in `changed`: if so, its
    /// cached findings are redone even though its text did not change.
    fn consumes_changed(&self, file: &str, changed: &BTreeSet<NodeKey>) -> bool;

    /// The findings of one rule on one file. `specs` is the rule's specs,
    /// reused from file to file: the method sets its per-file parts
    /// (summaries, type table) before analysing.
    fn analyse_file(
        &self,
        file: &ParsedFile,
        specs: &mut RuleSpecs,
        resolved: &ResolvedSummaries,
    ) -> TaintFindings;
}

/// The parsed files as a call graph takes them (path, tree, bytes).
pub(super) fn call_graph_inputs<'a>(files: &[&'a ParsedFile]) -> Vec<FileInput<'a>> {
    files
        .iter()
        .map(|pf| FileInput {
            filepath: pf.rel_path.clone(),
            root: pf.tree.root_node(),
            source: pf.source_bytes.as_slice(),
        })
        .collect()
}

/// The source lines of every file, by path: summary resolution reads the
/// lines to evaluate multi-line conditions (sanitizers, allowlists).
pub(super) fn source_lines_by_file(files: &[&ParsedFile]) -> BTreeMap<String, Vec<String>> {
    files
        .iter()
        .map(|pf| (pf.rel_path.clone(), pf.source_lines_plain.clone()))
        .collect()
}

/// Summaries one file can call: those it imports, overridden by its own
/// functions of the same name (local > import, as `merged.update(
/// summaries)` in `dataflow_taint.py`). Shared by the languages that
/// resolve calls across files.
pub(super) fn file_summaries(
    resolved: &ResolvedSummaries,
    file: &str,
) -> BTreeMap<String, Arc<FunctionSummary>> {
    let mut summaries = resolved.extra.get(file).cloned().unwrap_or_default();
    if let Some(own) = resolved.own.get(file) {
        summaries.extend(own.clone());
    }
    summaries
}

/// Runs the taint pass of language `L` over the parsed files and merges
/// its findings into `context.findings`, skipping the flows in `seen`
/// (and adding the new ones to it). Returns the phase label, already
/// translated, and the time the pass took, for the scan's phase timings.
pub(super) fn run_taint_pass<'a, L: TaintLanguage<'a>>(
    parsed_files: &'a [ParsedFile],
    rule_jsons: &[serde_json::Value],
    context: &mut PassContext<'_>,
    seen: &mut SeenTaint,
) -> (String, std::time::Duration) {
    let started = std::time::Instant::now();
    let files: Vec<&ParsedFile> = parsed_files
        .iter()
        .filter(|pf| L::FILE_LANGUAGES.contains(&pf.language))
        .collect();
    let rules: Vec<&serde_json::Value> = rule_jsons
        .iter()
        .filter(|r| r.get("language").and_then(|v| v.as_str()) == Some(L::RULE_LANGUAGE.rule_tag()))
        .collect();
    let language = L::build(&files);
    let per_rule = cached_rule_runs(&language, &files, &rules, context);
    merge_taint_findings(&files, &rules, per_rule, context, seen);
    let (key, french_fallback) = L::PHASE_LABEL;
    (
        phase_label(context.config, key, french_fallback),
        started.elapsed(),
    )
}

/// Runs every taint rule on the files of one language, reusing the taint
/// cache of the previous scan.
///
/// Parallel **per rule**, not per file: resolving the summaries over the
/// whole call graph, once per rule, dominates the cost (measured on
/// 2026-08-26 on `Audit/sca`, 34k lines: up to 6-7 s per rule against 8 s
/// for all the per-file analyses). Each rule is independent; the merge
/// that follows stays sequential, in rule then file order, so the report
/// is the one of a sequential run.
///
/// A file keeps its previous findings for a rule when neither its text,
/// nor what it resolves, nor any summary it reads changed. The result is
/// one entry per rule (`None` for a rule without source or sink), each
/// holding the findings of every file, in file order.
fn cached_rule_runs<'a, L: TaintLanguage<'a>>(
    language: &L,
    files: &[&ParsedFile],
    rule_jsons: &[&serde_json::Value],
    context: &mut PassContext<'_>,
) -> Vec<Option<Vec<TaintFindings>>> {
    let config = context.config;
    let cache_path = context.cache.map(|c| TaintCache::path(&c.dir, L::NAME));
    let previous = context
        .cache
        .zip(cache_path.as_ref())
        .and_then(|(c, p)| TaintCache::load(p, &c.key));
    let file_states: BTreeMap<String, FileState> = files
        .iter()
        .map(|pf| {
            (
                pf.rel_path.clone(),
                FileState {
                    hash: sha256_hex(&pf.source_bytes),
                    deps: sha256_hex(language.dependency_fingerprint(&pf.rel_path).as_bytes()),
                },
            )
        })
        .collect();
    let dirty: BTreeSet<String> = previous.as_ref().map_or_else(
        || file_states.keys().cloned().collect(),
        |cache| cache.dirty_files(&file_states),
    );

    // Per rule: its per-file findings, id, cache entry and analyses run.
    type RuleRun = (Vec<TaintFindings>, String, RuleState, usize);
    let runs: Vec<Option<RuleRun>> = rule_jsons
        .par_iter()
        .map(|rule_json| {
            // `Some` as soon as the rule has a source and a sink, whatever
            // its `patterns` (a `regex+taint` rule goes through both phases).
            let base_specs = rule_json_to_specs(rule_json, &config.lang)?;
            let rule_hash = sha256_hex(
                serde_json::to_string(rule_json)
                    .unwrap_or_default()
                    .as_bytes(),
            );
            let prior = previous
                .as_ref()
                .and_then(|c| c.rules.get(&base_specs.rule_id))
                .filter(|r| r.rule_hash == rule_hash);
            let prior_summaries = prior.map(RuleState::previous_summaries);
            let reuse = prior_summaries.as_ref().map(|previous| SummaryReuse {
                previous,
                dirty_files: &dirty,
            });
            let resolved = language.resolve(&base_specs, reuse.as_ref());
            // Cloned once per rule, not per file: only the per-file parts
            // (summaries, type map) change between files.
            let mut node_specs = base_specs.clone();
            let mut analysed = 0usize;
            let mut per_file = Vec::with_capacity(files.len());
            for pf in files {
                if let Some(prior) = prior
                    && !dirty.contains(&pf.rel_path)
                    && !language.consumes_changed(&pf.rel_path, &resolved.changed)
                    && let Some(findings) = prior.findings.get(&pf.rel_path)
                {
                    per_file.push(findings.clone());
                    continue;
                }
                analysed += 1;
                per_file.push(language.analyse_file(pf, &mut node_specs, &resolved));
            }
            let state = RuleState {
                rule_hash,
                summaries: resolved
                    .all
                    .iter()
                    .map(|((f, n), s)| (f.clone(), n.clone(), (**s).clone()))
                    .collect(),
                findings: files
                    .iter()
                    .zip(&per_file)
                    .map(|(pf, f)| (pf.rel_path.clone(), f.clone()))
                    .collect(),
            };
            Some((per_file, base_specs.rule_id.clone(), state, analysed))
        })
        .collect();

    if let Some((cache_context, path)) = context.cache.zip(cache_path.as_ref()) {
        let mut cache = TaintCache::new(cache_context.key.clone());
        cache.files = file_states;
        let mut analysed = 0;
        let mut total = 0;
        for (_, rule_id, state, n) in runs.iter().flatten() {
            cache.rules.insert(rule_id.clone(), state.clone());
            analysed += n;
            total += files.len();
        }
        // Nothing redone and no file changed: the cache on disk is already
        // this one, rewriting it would only cost time. A cache that cannot
        // be written only costs the next scan its speed: never an error of
        // this one.
        if previous.is_none() || !dirty.is_empty() || analysed > 0 {
            let _ = cache.save(path);
        }
        context.cache_stats.push(CacheStat {
            language: L::NAME.to_string(),
            files: files.len(),
            dirty: dirty.len(),
            analysed,
            total,
        });
    }
    runs.into_iter()
        .map(|run| run.map(|(per_file, _, _, _)| per_file))
        .collect()
}

/// Adds the findings of one taint pass to the report, in rule then file
/// order, skipping a flow already reported, a finding the user suppressed
/// (`.sca-suppress.json`) and a line carrying an inline ignore comment.
fn merge_taint_findings(
    files: &[&ParsedFile],
    rule_jsons: &[&serde_json::Value],
    per_rule: Vec<Option<Vec<TaintFindings>>>,
    context: &mut PassContext<'_>,
    seen: &mut SeenTaint,
) {
    for (rule_json, maybe_per_file) in rule_jsons.iter().zip(per_rule) {
        let Some(per_file) = maybe_per_file else {
            continue;
        };
        for (pf, findings) in files.iter().zip(per_file) {
            for f in findings {
                let key = (
                    pf.rel_path.clone(),
                    f.rule_id.clone(),
                    f.line,
                    f.source_line,
                );
                if !seen.insert(key) {
                    continue;
                }
                let code = line_text(&pf.all_lines, f.line);
                // Trimmed, as the report hashes it for its 🚫 button
                // (`ReportFinding.code`): an indented line never matched.
                if context
                    .suppressions
                    .is_suppressed(&f.rule_id, &pf.rel_path, code.trim())
                {
                    continue;
                }
                if is_inline_ignored(&code, &f.rule_id) {
                    continue;
                }
                integrate_taint_finding(
                    context.findings,
                    taint_finding_to_report(
                        &f,
                        rule_json,
                        &pf.rel_path,
                        &pf.source_lines_plain,
                        &context.config.lang,
                    ),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::scan::orchestrator::{ScanConfig, ScanReport, run_scan};
    use std::path::Path;

    /// One rule and one vulnerable file for each taint pass.
    struct Case {
        rule: &'static str,
        /// Language, source and sink lines of the rule.
        specs: &'static str,
        file: &'static str,
        /// The file, with `SUFFIX` at the end of its sink line. The sink
        /// line is indented (inside a function), as in real code: the
        /// suppression hash of an indented line once differed between the
        /// report and the taint passes.
        code: &'static str,
        /// An inline ignore in a comment of the language.
        ignore_comment: &'static str,
    }

    const CASES: [Case; 5] = [
        Case {
            rule: "taint_py",
            specs: "language  python\n  source  input\\s*\\(  kind=cli\n  sink    os\\.system\\s*\\(",
            file: "app.py",
            code: "import os\n\ndef handler():\n    cmd = input()\n    os.system(cmd)SUFFIX\n",
            ignore_comment: "  # sca-ignore",
        },
        Case {
            rule: "taint_java",
            specs: "language  java\n  source  request\\.getParameter\\s*\\(  kind=http\n  sink    stmt\\.executeQuery\\s*\\(",
            file: "Api.java",
            code: "package app;\nclass Api {\n  void handle(HttpServletRequest request) {\n    String cmd = request.getParameter(\"q\");\n    stmt.executeQuery(cmd);SUFFIX\n  }\n}\n",
            ignore_comment: " // # sca-ignore",
        },
        Case {
            rule: "taint_js",
            specs: "language  javascript\n  source  readInput\\s*\\(  kind=cli\n  sink    db\\.query\\s*\\(",
            file: "handler.js",
            code: "function handler() {\n  const cmd = readInput();\n  db.query(cmd);SUFFIX\n}\n",
            ignore_comment: " // # sca-ignore",
        },
        Case {
            rule: "taint_php",
            specs: "language  php\n  source  readInput\\s*\\(  kind=cli\n  sink    \\$db->query\\s*\\(",
            file: "handler.php",
            code: "<?php\nfunction handler() {\n  $cmd = readInput();\n  $db->query($cmd);SUFFIX\n}\n",
            ignore_comment: " # sca-ignore",
        },
        Case {
            rule: "taint_cs",
            specs: "language  csharp\n  source  Request\\.Query\\[  kind=http\n  sink    Process\\.Start\\s*\\(",
            file: "C.cs",
            code: "class C {\n  void M() {\n    var cmd = Request.Query[\"q\"];\n    Process.Start(cmd);SUFFIX\n  }\n}\n",
            ignore_comment: " // # sca-ignore",
        },
    ];

    /// Writes the five rules and the five files (with an inline ignore on
    /// their sink line when `ignored`); returns the scan configuration.
    fn project(root: &Path, ignored: bool) -> ScanConfig {
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        for case in &CASES {
            let rule_text = format!(
                "rule {}\n  {}\n  category  security\n  severity  HIGH\nend\n",
                case.rule, case.specs
            );
            std::fs::write(rules_dir.join(format!("{}.sca", case.rule)), rule_text).unwrap();
            let suffix = if ignored { case.ignore_comment } else { "" };
            std::fs::write(root.join(case.file), case.code.replace("SUFFIX", suffix)).unwrap();
        }
        ScanConfig {
            root: root.to_path_buf(),
            rules_path: rules_dir,
            exclude_patterns: vec!["rules/".to_string()],
            ..ScanConfig::default()
        }
    }

    /// For each case, the number of findings of its rule in its file.
    fn counts(report: &ScanReport) -> Vec<(&'static str, usize)> {
        CASES
            .iter()
            .map(|case| {
                let n = report
                    .findings
                    .iter()
                    .filter(|f| f.rule_key == case.rule && f.file == case.file)
                    .count();
                (case.rule, n)
            })
            .collect()
    }

    /// Every case with the same count `n`.
    fn each(n: usize) -> Vec<(&'static str, usize)> {
        CASES.iter().map(|case| (case.rule, n)).collect()
    }

    #[test]
    fn test_every_taint_pass_merges_its_findings_the_same_way() {
        let root = std::env::temp_dir().join(format!("taint_merge_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();

        // 1. Each flow is found, once.
        let config = project(&root, false);
        let first = run_scan(&config);
        assert_eq!(counts(&first), each(1), "{:?}", first.findings);

        // 2. Suppressed from the report: rule, file and hash of the line
        // as the report shows it (`ReportFinding.code`, trimmed).
        let entries: Vec<String> = first
            .findings
            .iter()
            .map(|f| {
                let hash = crate::project::suppress::line_hash(&f.code);
                format!(
                    r#"{{"rule_key": "{}", "file": "{}", "code_hash": {hash}}}"#,
                    f.rule_key, f.file
                )
            })
            .collect();
        let suppress_path = root.join(".sca-suppress.json");
        std::fs::write(
            &suppress_path,
            format!(
                r#"{{"version": "1.0", "suppressions": [{}]}}"#,
                entries.join(", ")
            ),
        )
        .unwrap();
        let suppressed = run_scan(&ScanConfig {
            suppress_file: Some(suppress_path),
            ..config
        });
        assert_eq!(counts(&suppressed), each(0), "{:?}", suppressed.findings);

        // 3. Ignored inline, by a comment on the sink line.
        let ignored = run_scan(&project(&root, true));
        assert_eq!(counts(&ignored), each(0), "{:?}", ignored.findings);

        std::fs::remove_dir_all(&root).ok();
    }
}
