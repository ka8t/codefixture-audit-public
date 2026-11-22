//! Phase B of the scan: the pattern pass.
//!
//! Runs every rule that reads one file at a time: regular expressions
//! (`match`), file conditions (`requires`: content present or absent,
//! folder, governance file nearby) and both combined. A rule only applies
//! to the files of its own language (`language` of the rule). The taint
//! rules are left to phase C (`taint`).
//!
//! Each file is independent of the others, so the pass runs in parallel
//! per file; the findings keep the file then rule order, so the report is
//! the one of a sequential run.
//!
//! The pass reuses the pattern cache of the previous scan (`scan_cache`,
//! issue #183): a file keeps its findings when its bytes, the governance
//! files around it and the loaded rules are those of the previous scan.
//! The user's suppressions are applied after the cache, on every scan, so
//! that suppressing a finding never needs the file to change.
//!
//! Before 2026-11-14 this pass was written inline in `run_scan`, where it
//! could only be tested through a whole scan; the cache it uses had no
//! test of its own.

use std::collections::BTreeSet;

use rayon::prelude::*;

use super::{ParsedFile, PassContext, engine_finding_to_report, phase_label};
use crate::project::suppress::{Suppressions, is_inline_ignored};
use crate::report::exports::sarif::ReportFinding;
use crate::scan::engine::Finding;
use crate::scan::engine::dispatch::{DispatchOutcome, dispatch_rule};
use crate::scan::engine::file_contains::governance_fingerprint;
use crate::scan::scan_cache::{CacheStat, PatternCache, PatternFileState, sha256_hex};

/// Name of the pattern pass in the cache statistics.
const CACHE_STAT_NAME: &str = "patterns";

/// Runs the pattern pass over the parsed files and adds its findings to
/// `context.findings`. Returns the phase label, already translated, and
/// the time the pass took, for the scan's phase timings.
pub(super) fn run_pattern_pass(
    parsed_files: &[ParsedFile],
    rule_jsons: &[serde_json::Value],
    context: &mut PassContext<'_>,
) -> (String, std::time::Duration) {
    let started = std::time::Instant::now();
    let rules_hash = sha256_hex(
        serde_json::to_string(rule_jsons)
            .unwrap_or_default()
            .as_bytes(),
    );
    let governance = governance_names(rule_jsons);
    let cache_path = context.cache.map(|c| PatternCache::path(&c.dir));
    let loaded = context
        .cache
        .zip(cache_path.as_ref())
        .map(|(c, p)| PatternCache::load(p, &c.key, &rules_hash));
    // Ticket #204: why the previous cache could not serve, for the line.
    let miss = loaded.as_ref().and_then(|r| r.as_ref().err().cloned());
    let previous = loaded.and_then(Result::ok);

    let runs: Vec<FileRun> = parsed_files
        .par_iter()
        .map(|pf| run_file(pf, rule_jsons, &governance, previous.as_ref()))
        .collect();
    let (config, suppressions) = (context.config, context.suppressions);
    let reportable: Vec<Vec<ReportFinding>> = parsed_files
        .par_iter()
        .zip(runs.par_iter())
        .map(|(pf, run)| {
            reportable_findings(pf, &run.state, rule_jsons, suppressions, &config.lang)
        })
        .collect();

    if let Some((cache_context, path)) = context.cache.zip(cache_path.as_ref()) {
        let mut next = PatternCache::new(cache_context.key.clone(), rules_hash);
        let mut redone = 0;
        for (pf, run) in parsed_files.iter().zip(runs) {
            redone += usize::from(run.redone);
            next.files.insert(pf.rel_path.clone(), run.state);
        }
        // Nothing redone: the cache on disk is already this one. A cache
        // that cannot be written only costs the next scan its speed.
        if previous.is_none() || redone > 0 {
            let _ = next.save(path);
        }
        context.cache_stats.push(CacheStat {
            language: CACHE_STAT_NAME.to_string(),
            files: parsed_files.len(),
            dirty: redone,
            analysed: redone,
            total: parsed_files.len(),
            full: miss,
        });
    }
    for findings in reportable {
        // A pattern finding is never merged with another rule's: it is the
        // rule's own finding too (ticket #242).
        if let Some(rule_findings) = context.rule_findings.as_deref_mut() {
            rule_findings.extend(findings.iter().cloned());
        }
        context.findings.extend(findings);
    }
    (
        phase_label(
            context.config,
            "scan_phase_b",
            "phase B (regex/file_contains)",
        ),
        started.elapsed(),
    )
}

/// The governance file names any loaded rule looks for
/// (`not_path_has_file`), sorted and without duplicates: whether they
/// exist around a file is part of the file's cache key.
pub(super) fn governance_names(rule_jsons: &[serde_json::Value]) -> Vec<String> {
    rule_jsons
        .iter()
        .filter_map(|r| r.get("file_contains")?.get("not_path_has_file")?.as_array())
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect()
}

/// The pass's result for one file: its cache entry, and whether the rules
/// ran on it (`redone`) or its entry came from the previous scan.
struct FileRun {
    state: PatternFileState,
    redone: bool,
}

/// One file's findings before suppressions: those of the previous scan
/// when its bytes and its governance files are unchanged, otherwise those
/// of running the rules again.
fn run_file(
    pf: &ParsedFile,
    rule_jsons: &[serde_json::Value],
    governance: &[String],
    previous: Option<&PatternCache>,
) -> FileRun {
    // The bytes of the text the rules read (ticket #241): for a file that
    // is not valid UTF-8, those of the text with its invalid bytes
    // replaced, not those on disk. Two versions of such a file that only
    // differ by invalid bytes give the same findings, and share a hash.
    let hash = sha256_hex(pf.bytes());
    let governance = governance_fingerprint(&pf.filepath, governance);
    if let Some(prior) = previous.and_then(|c| c.files.get(&pf.rel_path))
        && prior.hash == hash
        && prior.governance == governance
    {
        return FileRun {
            state: prior.clone(),
            redone: false,
        };
    }
    FileRun {
        state: PatternFileState {
            hash,
            governance,
            findings: rules_on_file(pf, rule_jsons),
        },
        redone: true,
    }
}

/// Runs the rules of the file's language on it, in rule order. Each
/// finding carries the index of its rule in `rule_jsons`.
///
/// A configuration file (`pom.xml`, `web.config`, `package.json`,
/// ADR-0047) is read only by the rules that name a path with
/// `path_contains`: a Java rule written for `.java` code has no business
/// on a `pom.xml`. Its comments are stripped with its own syntax (XML or
/// none), not with the rule language's.
fn rules_on_file(pf: &ParsedFile, rule_jsons: &[serde_json::Value]) -> Vec<(usize, Finding)> {
    let mut findings = Vec::new();
    let syntax = pf.language.comment_syntax();
    // The numbered lines the pattern rules read, built when the first
    // rule of the file's language reaches it and dropped with this
    // call: the scan keeps one copy of each text (ticket #241).
    let mut numbered_lines = None;
    for (index, rule_json) in rule_jsons.iter().enumerate() {
        if rule_json.get("language").and_then(|v| v.as_str()) != Some(pf.language.rule_tag()) {
            continue;
        }
        if pf.language.is_config_file() && !names_a_path(rule_json) {
            continue;
        }
        let DispatchOutcome::Findings(found) = dispatch_rule(
            rule_json,
            pf.location(),
            numbered_lines.get_or_insert_with(|| pf.source.numbered_lines()),
            pf.source.text(),
            syntax,
        ) else {
            continue; // Taint/Ast/Hook: handled elsewhere (phase C) or out of scope.
        };
        findings.extend(found.into_iter().map(|f| (index, f)));
    }
    findings
}

/// `true` when the rule restricts itself to some paths
/// (`requires` … `path_contains`): the only rules a configuration file
/// is given to (ADR-0047). Whether this file's path matches is left to
/// the rule's own `requires` check in `dispatch_rule`.
fn names_a_path(rule_json: &serde_json::Value) -> bool {
    rule_json
        .get("file_contains")
        .and_then(|fc| fc.get("path_contains"))
        .and_then(|v| v.as_array())
        .is_some_and(|paths| !paths.is_empty())
}

/// The findings of one file that go into the report: those the user did
/// not suppress (`.sca-suppress.json`) nor ignore inline (`# sca-ignore`
/// on the line), as report findings.
fn reportable_findings(
    pf: &ParsedFile,
    state: &PatternFileState,
    rule_jsons: &[serde_json::Value],
    suppressions: &Suppressions,
    lang: &str,
) -> Vec<ReportFinding> {
    state
        .findings
        .iter()
        .filter(|(_, f)| !suppressions.is_suppressed(&f.rule_id, &pf.rel_path, &f.code))
        .filter(|(_, f)| !is_inline_ignored(&f.code, &f.rule_id))
        .map(|(index, f)| {
            engine_finding_to_report(f, &rule_jsons[*index], &pf.rel_path, &pf.source, lang)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::orchestrator::{ScanConfig, parse_file};
    use crate::scan::scan_cache::CacheContext;
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A fresh project folder, with its cache folder inside.
    fn project() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("patterns_pass_{}_{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A line rule: `pattern` on every line of the files of `language`.
    fn line_rule(id: &str, language: &str, pattern: &str) -> serde_json::Value {
        json!({
            "id": id, "language": language, "category": "security", "severity": "HIGH",
            "patterns": [{"pattern": pattern, "match": "line"}],
        })
    }

    /// A file rule that fires on every file of a `third_party/` folder
    /// unless a `LICENSE` file sits next to it.
    fn third_party_rule() -> serde_json::Value {
        json!({
            "id": "unreviewed_third_party", "language": "python", "category": "maintenance",
            "severity": "LOW",
            "file_contains": {"path_contains": ["third_party/"], "not_path_has_file": ["LICENSE"]},
        })
    }

    /// What one pass run produced: the findings as `file:line:rule`, and
    /// how many files it redid (`None` without cache).
    struct PassRun {
        findings: Vec<String>,
        redone: Option<usize>,
    }

    /// Parses the files of `root` (as phase A does) and runs the pass.
    fn run(
        root: &Path,
        files: &[&str],
        rules: &[serde_json::Value],
        suppress: &str,
        cached: bool,
    ) -> PassRun {
        let parsed: Vec<_> = files
            .iter()
            .map(|f| {
                parse_file(root, &root.join(f), &[])
                    .into_parsed()
                    .expect("parsable fixture")
            })
            .collect();
        let config = ScanConfig {
            root: root.to_path_buf(),
            ..ScanConfig::default()
        };
        let suppressions = Suppressions::load_from_json(suppress);
        let cache = cached.then(|| CacheContext::prepare(&root.join("cache"), "en", root).unwrap());
        let mut findings = Vec::new();
        let mut cache_stats = Vec::new();
        let mut context = PassContext {
            config: &config,
            suppressions: &suppressions,
            cache: cache.as_ref(),
            findings: &mut findings,
            cache_stats: &mut cache_stats,
            rule_findings: None,
        };
        run_pattern_pass(&parsed, rules, &mut context);
        PassRun {
            findings: findings
                .iter()
                .map(|f| format!("{}:{}:{}", f.file, f.line, f.rule_key))
                .collect(),
            redone: cache_stats
                .iter()
                .find(|s| s.language == CACHE_STAT_NAME)
                .map(|s| s.analysed),
        }
    }

    const NO_SUPPRESSION: &str = r#"{"suppressions": []}"#;

    fn write(root: &Path, file: &str, content: &str) {
        let path = root.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn test_a_rule_only_applies_to_the_files_of_its_language() {
        let root = project();
        write(&root, "app.py", "eval(x)\n");
        write(&root, "App.java", "class App { void m() { eval(x); } }\n");
        let rules = [
            line_rule("py_eval", "python", r"eval\("),
            line_rule("java_eval", "java", r"eval\("),
        ];
        let run = run(
            &root,
            &["app.py", "App.java"],
            &rules,
            NO_SUPPRESSION,
            false,
        );
        assert_eq!(run.findings, ["app.py:1:py_eval", "App.java:1:java_eval"]);
        std::fs::remove_dir_all(&root).ok();
    }

    /// A line rule restricted to the paths holding `path` (`requires` …
    /// `path_contains`), with an optional `pattern-not`.
    fn path_rule(
        id: &str,
        language: &str,
        pattern: &str,
        not: Option<&str>,
        path: &str,
    ) -> serde_json::Value {
        let mut block = json!({"pattern": pattern, "match": "line"});
        if let Some(not) = not {
            block["pattern-not"] = json!(not);
        }
        json!({
            "id": id, "language": language, "category": "security", "severity": "HIGH",
            "patterns": [block],
            "file_contains": {"path_contains": [path]},
        })
    }

    #[test]
    fn test_a_config_file_is_read_only_by_the_rules_that_name_it() {
        // ADR-0047: a Java rule written for code never runs on a pom.xml;
        // the rule naming pom.xml does, and no longer runs on .java code.
        let root = project();
        write(&root, "pom.xml", "<url>http://repo.example.com/</url>\n");
        write(
            &root,
            "App.java",
            "String u = \"<url>http://repo.example.com/</url>\";\n",
        );
        let rules = [
            line_rule("java_any_http", "java", r"http://"),
            path_rule("maven_http", "java", r"<url>http://", None, "pom.xml"),
        ];
        let run = run(
            &root,
            &["pom.xml", "App.java"],
            &rules,
            NO_SUPPRESSION,
            false,
        );
        assert_eq!(
            run.findings,
            ["pom.xml:1:maven_http", "App.java:1:java_any_http"]
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_a_config_file_keeps_its_own_comment_syntax() {
        // `//` is not a comment in XML: the Java stripping would cut the
        // `pattern-not` text after `http://` and raise a wrong finding;
        // an XML comment, on the other hand, no longer counts.
        let root = project();
        write(
            &root,
            "Web.config",
            "<system.webServer> <add url=\"http://x\" name=\"X-Frame-Options\" />\n\
             <system.webServer> <!-- X-Frame-Options -->\n",
        );
        let rules = [path_rule(
            "xfo",
            "csharp",
            r"<system\.webServer>",
            Some("X-Frame-Options"),
            "web.config",
        )];
        let run = run(&root, &["Web.config"], &rules, NO_SUPPRESSION, false);
        assert_eq!(run.findings, ["Web.config:2:xfo"]);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_unchanged_files_are_reused_and_a_changed_file_is_redone() {
        let root = project();
        write(&root, "a.py", "eval(x)\n");
        write(&root, "b.py", "print(x)\n");
        let rules = [line_rule("py_eval", "python", r"eval\(")];
        let files = ["a.py", "b.py"];

        let first = run(&root, &files, &rules, NO_SUPPRESSION, true);
        assert_eq!(
            (first.findings.as_slice(), first.redone),
            (&["a.py:1:py_eval".to_string()][..], Some(2))
        );

        let again = run(&root, &files, &rules, NO_SUPPRESSION, true);
        assert_eq!(
            (again.findings, again.redone),
            (first.findings.clone(), Some(0)),
            "nothing changed: all reused"
        );

        write(&root, "b.py", "print(x)\neval(y)\n");
        let changed = run(&root, &files, &rules, NO_SUPPRESSION, true);
        assert_eq!(changed.redone, Some(1), "only b.py redone");
        assert_eq!(changed.findings, ["a.py:1:py_eval", "b.py:2:py_eval"]);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_a_governance_file_appearing_redoes_the_file_it_covers() {
        // The file itself does not change: only the LICENSE next to it.
        let root = project();
        write(
            &root,
            "third_party/lib/util.py",
            "def helper():\n    return 2\n",
        );
        let rules = [third_party_rule()];
        let files = ["third_party/lib/util.py"];

        let before = run(&root, &files, &rules, NO_SUPPRESSION, true);
        assert_eq!(
            before.findings,
            ["third_party/lib/util.py:1:unreviewed_third_party"]
        );

        write(&root, "third_party/lib/LICENSE", "MIT\n");
        let after = run(&root, &files, &rules, NO_SUPPRESSION, true);
        assert_eq!(
            (after.findings.len(), after.redone),
            (0, Some(1)),
            "the cached finding must not survive"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_changing_the_rules_redoes_every_file() {
        let root = project();
        write(&root, "a.py", "eval(x)\nexec(y)\n");
        write(&root, "b.py", "exec(z)\n");
        let files = ["a.py", "b.py"];
        run(
            &root,
            &files,
            &[line_rule("py_eval", "python", r"eval\(")],
            NO_SUPPRESSION,
            true,
        );

        let new_rules = [line_rule("py_exec", "python", r"exec\(")];
        let after = run(&root, &files, &new_rules, NO_SUPPRESSION, true);
        assert_eq!(after.redone, Some(2));
        assert_eq!(after.findings, ["a.py:2:py_exec", "b.py:1:py_exec"]);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_a_suppression_added_later_hides_a_finding_taken_from_the_cache() {
        let root = project();
        write(&root, "a.py", "eval(x)\n");
        let rules = [line_rule("py_eval", "python", r"eval\(")];
        run(&root, &["a.py"], &rules, NO_SUPPRESSION, true);

        let suppress =
            r#"{"suppressions": [{"rule_key": "py_eval", "file": "a.py", "code_hash": null}]}"#;
        let after = run(&root, &["a.py"], &rules, suppress, true);
        assert_eq!(
            (after.findings.len(), after.redone),
            (0, Some(0)),
            "reused from the cache, then suppressed"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_an_unreadable_cache_gives_the_full_result() {
        let root = project();
        write(&root, "a.py", "eval(x)\n");
        let rules = [line_rule("py_eval", "python", r"eval\(")];
        let first = run(&root, &["a.py"], &rules, NO_SUPPRESSION, true);

        let context = CacheContext::prepare(&root.join("cache"), "en", &root).unwrap();
        std::fs::write(PatternCache::path(&context.dir), b"not a cache").unwrap();
        let after = run(&root, &["a.py"], &rules, NO_SUPPRESSION, true);
        assert_eq!((after.findings, after.redone), (first.findings, Some(1)));
        std::fs::remove_dir_all(&root).ok();
    }
}
