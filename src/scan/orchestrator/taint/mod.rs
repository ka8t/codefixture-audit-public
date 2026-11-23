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
    FindingsByLine, ParsedFile, PassContext, SourceLanguage, integrate_taint_finding, line_text,
    phase_label, taint_finding_to_report,
};
use crate::project::suppress::is_inline_ignored;
use crate::scan::dataflow::call_graph::{FileInput, NodeKey, ResolvedSummaries, SummaryReuse};
use crate::scan::dataflow::expr_table::ExprTable;
use crate::scan::dataflow::line_facts::LinesByFile;
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

    /// The files that read a summary in `changed` (a superset is allowed):
    /// their cached findings are redone even though their text did not
    /// change. Asked once per rule (ticket #239): asking it file by file
    /// scanned every changed summary for every file.
    fn readers(&self, changed: &BTreeSet<NodeKey>) -> BTreeSet<String>;

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

/// Most rules a taint pass runs at the same time (ticket #247), fewer when
/// memory is short (`scan::memory::plan`, ticket #281): half
/// the threads of the pool, at least one. A rule keeps the summaries of
/// every function of the project until its files are analysed: with every
/// rule of a pass at once, the 22 Java rules on the 46,793 files of the
/// Juliet Java suite held about 4 GB more than one rule at a time (11.96
/// against 7.98 GB), but one rule at a time doubled the time (76 → 144 s),
/// a rule's summary resolution being sequential. The files of a rule are
/// still analysed by every thread of the pool.
pub(in crate::scan) fn rule_lanes() -> usize {
    (rayon::current_num_threads() / 2).max(1)
}

/// Runs `run` on every rule of `rule_jsons` with its specs, at most
/// `lanes` rules at a time, and returns the results in rule order. Each
/// lane takes the next rule as soon as its own is done: no group of
/// rules waits for its slowest member. The work inside a rule (its files'
/// `par_iter`) uses the whole pool.
fn run_in_lanes<T: Send>(
    rule_jsons: &[&serde_json::Value],
    all_specs: Vec<Option<RuleSpecs>>,
    lanes: usize,
    run: impl Fn(&serde_json::Value, Option<RuleSpecs>) -> T + Sync,
) -> Vec<T> {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let specs: Vec<Mutex<Option<Option<RuleSpecs>>>> =
        all_specs.into_iter().map(|s| Mutex::new(Some(s))).collect();
    let results: Vec<Mutex<Option<T>>> = rule_jsons.iter().map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    rayon::scope(|scope| {
        for _ in 0..lanes.min(rule_jsons.len()) {
            scope.spawn(|_| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(rule_json) = rule_jsons.get(index) else {
                        break;
                    };
                    let specs = specs[index]
                        .lock()
                        .expect("no lane panics while holding it")
                        .take()
                        .expect("each rule is taken once");
                    let result = run(rule_json, specs);
                    *results[index]
                        .lock()
                        .expect("no lane panics while holding it") = Some(result);
                }
            });
        }
    });
    results
        .into_iter()
        .map(|cell| {
            cell.into_inner()
                .expect("no lane panicked")
                .expect("every rule ran")
        })
        .collect()
}

/// Whether `rule_jsons` hold a taint rule of `rule_language`: one that
/// gives taint specs (`rule_loader::has_taint_specs`). The scan keeps the
/// parse trees of a pass's files only when it does, and the pass only
/// runs then (ticket #241): both ask this function, so a pass never
/// meets a released tree.
pub(super) fn language_has_taint_rule(
    rule_language: SourceLanguage,
    rule_jsons: &[serde_json::Value],
) -> bool {
    rule_jsons.iter().any(|r| {
        r.get("language").and_then(|v| v.as_str()) == Some(rule_language.rule_tag())
            && crate::scan::dataflow::rule_loader::has_taint_specs(r)
    })
}

/// The parsed files as a call graph takes them (path, tree, bytes).
pub(super) fn call_graph_inputs<'a>(files: &[&'a ParsedFile]) -> Vec<FileInput<'a>> {
    files
        .iter()
        .map(|pf| FileInput {
            filepath: pf.rel_path.clone(),
            root: pf.tree().root_node(),
            source: pf.bytes(),
        })
        .collect()
}

/// The source lines of every file, by path: summary resolution reads the
/// lines to evaluate multi-line conditions (sanitizers, allowlists).
/// The lines are shared with the files, not copied.
pub(super) fn source_lines_by_file(files: &[&ParsedFile]) -> LinesByFile {
    files
        .iter()
        .map(|pf| (pf.rel_path.clone(), Arc::clone(&pf.source)))
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
    // Ticket #241: without a taint rule there is nothing to analyse, and
    // the scan kept no tree for these files. The pass used to build its
    // call graph and prepare every file anyway (1.9 s on 2,944 Java files
    // scanned with one pattern rule).
    if !language_has_taint_rule(L::RULE_LANGUAGE, rule_jsons) {
        let (key, french_fallback) = L::PHASE_LABEL;
        return (
            phase_label(context.config, key, french_fallback),
            started.elapsed(),
        );
    }
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
    let loaded = context
        .cache
        .zip(cache_path.as_ref())
        .map(|(c, p)| TaintCache::load(p, &c.key));
    // Ticket #204: why the previous cache could not serve, for the line.
    let miss = loaded.as_ref().and_then(|r| r.as_ref().err().cloned());
    let previous = loaded.and_then(Result::ok);
    // Ticket #240: without a cache, no file is hashed and no rule state
    // is kept, since nothing would read them.
    let caching = context.cache.is_some();
    let file_states: BTreeMap<String, FileState> = files
        .iter()
        .filter(|_| caching)
        .map(|pf| {
            (
                pf.rel_path.clone(),
                FileState {
                    // The bytes the analysis reads, see `run_file` in
                    // `patterns.rs` (ticket #241).
                    hash: sha256_hex(pf.bytes()),
                    deps: sha256_hex(language.dependency_fingerprint(&pf.rel_path).as_bytes()),
                },
            )
        })
        .collect();
    let dirty: BTreeSet<String> = previous.as_ref().map_or_else(
        || file_states.keys().cloned().collect(),
        |cache| cache.dirty_files(&file_states),
    );

    // Per rule: its per-file findings, id, cache entry (only with a
    // cache) and analyses run.
    type RuleRun = (Vec<TaintFindings>, String, Option<RuleState>, usize);
    // `Some` as soon as the rule has a source and a sink, whatever its
    // `patterns` (a `regex+taint` rule goes through both phases). Loaded
    // before the runs so that the raw regexes of all the rules are
    // numbered in one table, whose answers each line computes once for
    // every rule (ticket #240).
    let mut all_specs: Vec<Option<RuleSpecs>> = rule_jsons
        .par_iter()
        .map(|rule_json| rule_json_to_specs(rule_json, &config.lang))
        .collect();
    ExprTable::attach(all_specs.iter_mut().flatten());
    // Computed ahead for the files every rule will analyse: all of them
    // without a previous run, else the changed ones. A clean file that a
    // rule analyses again (it reads a changed summary) computes its lines
    // when the rule reaches them. Computing every file ahead cost a
    // re-scan of `owasp_java` with one changed file 1 s more (1.9 s →
    // 2.9 s).
    if let Some(exprs) = all_specs
        .iter()
        .flatten()
        .find_map(|specs| specs.exprs.as_ref())
    {
        files
            .par_iter()
            .filter(|pf| previous.is_none() || dirty.contains(&pf.rel_path))
            .for_each(|pf| pf.source.fill_exprs(&exprs.table));
    }
    let run_rule =
        |rule_json: &serde_json::Value, base_specs: Option<RuleSpecs>| -> Option<RuleRun> {
            let base_specs = base_specs?;
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
            // The files to redo although clean: only asked when a previous
            // run's findings can be reused.
            let readers = prior.map(|_| language.readers(&resolved.changed));
            // The previous findings of a file that nothing changed.
            let reused = |pf: &ParsedFile| {
                prior
                    .filter(|_| {
                        !dirty.contains(&pf.rel_path)
                            && !readers.as_ref().is_some_and(|r| r.contains(&pf.rel_path))
                    })
                    .and_then(|prior| prior.findings.get(&pf.rel_path))
            };
            let analysed = files.iter().filter(|pf| reused(pf).is_none()).count();
            // The files of the rule are analysed in parallel too (ticket
            // #240): with one rule per thread only, the last rules of the
            // pass ran alone while the other cores waited (4.9 of 8 cores
            // used on the `Java` project). The specs are cloned once per
            // batch of files, not per file: `analyse_file` sets every
            // per-file part (summaries, summary fallback, type map) before
            // reading it, so a batch's files do not depend on each other
            // nor on their order. `collect` keeps the file order.
            let per_file: Vec<TaintFindings> = files
                .par_iter()
                .with_min_len(16)
                .map_init(
                    || base_specs.clone(),
                    |node_specs, pf| match reused(pf) {
                        Some(findings) => findings.clone(),
                        None => language.analyse_file(pf, node_specs, &resolved),
                    },
                )
                .collect();
            let state = caching.then(|| RuleState {
                rule_hash,
                summaries: resolved
                    .all
                    .iter()
                    .map(|((f, n), s)| (f.clone(), n.clone(), Arc::clone(s)))
                    .collect(),
                findings: files
                    .iter()
                    .zip(&per_file)
                    .map(|(pf, f)| (pf.rel_path.clone(), f.clone()))
                    .collect(),
            });
            Some((per_file, base_specs.rule_id.clone(), state, analysed))
        };
    let runs = run_in_lanes(rule_jsons, all_specs, context.rules_at_once, run_rule);

    let mut per_rule = Vec::with_capacity(runs.len());
    let mut states = Vec::new();
    let (mut analysed, mut total) = (0, 0);
    for run in runs {
        per_rule.push(run.map(|(per_file, rule_id, state, n)| {
            states.extend(state.map(|state| (rule_id, state)));
            analysed += n;
            total += files.len();
            per_file
        }));
    }
    if let Some((cache_context, path)) = context.cache.zip(cache_path.as_ref()) {
        let mut cache = TaintCache::new(cache_context.key.clone());
        cache.files = file_states;
        // Moved, not copied: the findings and summaries stay in memory once.
        cache.rules.extend(states);
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
            full: miss,
        });
    }
    per_rule
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
    // Indexed once per pass, then kept up to date by each integration.
    let mut by_line = FindingsByLine::new(context.findings);
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
                let code = line_text(&pf.source, f.line);
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
                let finding = taint_finding_to_report(
                    &f,
                    rule_json,
                    &pf.rel_path,
                    &pf.source,
                    &context.config.lang,
                );
                // The rule's own finding, before it may be merged into a
                // finding of another rule on the same line (ticket #242).
                if let Some(rule_findings) = context.rule_findings.as_deref_mut() {
                    rule_findings.push(finding.clone());
                }
                integrate_taint_finding(context.findings, &mut by_line, finding);
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

    /// Ticket #247: the rules run in lanes give their results in rule
    /// order, each rule runs once with its own specs, and no more rules run
    /// at the same time than there are lanes.
    #[test]
    fn test_rules_run_in_lanes() {
        use crate::scan::dataflow::transfer::RuleSpecs;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let jsons: Vec<serde_json::Value> =
            (0..23).map(|i| serde_json::json!({ "n": i })).collect();
        let refs: Vec<&serde_json::Value> = jsons.iter().collect();
        for lanes in [1, 3, 8, 40] {
            let specs: Vec<Option<RuleSpecs>> = (0..23)
                .map(|i| {
                    (i % 5 != 0).then(|| RuleSpecs {
                        rule_id: format!("r{i}"),
                        ..RuleSpecs::default()
                    })
                })
                .collect();
            let (running, most, calls) = (
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
            );
            let results = super::run_in_lanes(&refs, specs, lanes, |json, specs| {
                calls.fetch_add(1, Ordering::SeqCst);
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(2));
                running.fetch_sub(1, Ordering::SeqCst);
                (json["n"].as_u64().unwrap(), specs.map(|s| s.rule_id))
            });
            let expected: Vec<(u64, Option<String>)> = (0..23)
                .map(|i| (i, (i % 5 != 0).then(|| format!("r{i}"))))
                .collect();
            assert_eq!(results, expected, "{lanes} lanes");
            assert_eq!(calls.load(Ordering::SeqCst), 23);
            assert!(most.load(Ordering::SeqCst) <= lanes, "{lanes} lanes");
        }
    }
}
