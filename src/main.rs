//! CLI for `codefixture-audit` (Step 5.1/5.2, Decision #7 for exit codes).
//! Compatibility contract: `0` remains the only success code (any
//! script that tests `$? != 0` keeps working identically); `1`/`2`/`4`
//! refine the cause for scripts that want to distinguish it.
//!
//! ```text
//! 0 = analysis succeeded, no blocking finding
//! 1 = security findings detected (HIGH/CRITICAL)
//! 2 = usage / configuration error
//! 4 = internal error
//! ```

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use codefixture_audit::report::brand::{
    Brand, brand_style_block, effective_company_name, effective_prefix, effective_tool_name,
    effective_website_url, inject_brand_style, load_brand_file,
};
use codefixture_audit::report::compliance_html::HealthThresholds;
use codefixture_audit::report::exports::sarif::ReportFinding;
use codefixture_audit::report::exports::sarif::build_sarif_report;
use codefixture_audit::report::html::{ReportContext, generate_html};
use codefixture_audit::scan::orchestrator::{ScanConfig, ScanReport, run_scan};
use codefixture_audit::scan::unchanged::{LastScan, ScanInputs};

/// Exclusions applied to every scan — same list as
/// `DEFAULT_CONFIG["paths"]["exclude"]` (`Audit/sca/config.py`).
/// `paths.exclude` (`audit.config.json`) and `--exclude` ADD to this
/// list, never replace it: these are security exclusions (never scan
/// third-party/vendored code, nor the engine's own reports), not a
/// project choice to override.
///
/// **Deliberate deviation from Python (ticket #132, 2026-11-09)**:
/// `sca/config.py::_merge_config` replaces lists, so a project
/// declaring its own `paths.exclude` silently lost these defaults —
/// and scanned its previous HTML reports (279 phantom findings on a
/// 4-line project). The Rust port had copied that replacement while
/// this comment claimed a merge.
///
/// Earlier deviation found by the maintainer (2026-08-26): a scan of `Audit`
/// (repo root, with `.venv/` + `videos/node_modules/` +
/// `videos/.piper-venv/` present) without an explicit `--exclude`
/// scanned tens of thousands of third-party files (numpy/transformers/
/// pytest...) — nothing to do with engine slowness, just the total
/// absence of these defaults on the Rust side.
///
/// The list lives in the library (`project_config::DEFAULT_SCAN_EXCLUDES`)
/// so that every caller of `run_scan` skips the same folders.
const DEFAULT_EXCLUDES: &[&str] = codefixture_audit::project::project_config::DEFAULT_SCAN_EXCLUDES;

/// Default report directory, relative to the scanned folder (ticket
/// #133, 2026-11-09). **Deliberate deviation from Python**, which writes
/// into `<project>/docs/audit-reports`: that silently added files to the
/// audited project's own `docs/` folder. See
/// `docs/adr/0036-reports-written-to-project-root-audit-reports.md`.
const REPORTS_DIR: &str = "audit-reports";

/// Default JSON history directory (exports, SBOM), inside
/// [`REPORTS_DIR`] — same nesting as before ticket #133.
const DATAS_DIR: &str = "audit-reports/audit-datas";

/// History directory used before ticket #133. Read only, as a
/// fallback when [`DATAS_DIR`] holds no baseline yet, so the first scan
/// after the upgrade still compares against the previous one. Nothing
/// is ever written there any more.
const LEGACY_DATAS_DIR: &str = "docs/audit-reports/audit-datas";

/// Path of `target` relative to `root`, with `/` separators, when
/// `target` lies strictly inside `root` — `None` otherwise (outside the
/// project, or the project root itself). Both sides are canonicalized
/// (`target` through its parent when it does not exist yet, like a
/// report about to be written), so `.`, relative paths and symlinks
/// such as macOS `/tmp` → `/private/tmp` compare correctly.
fn path_inside_root(root: &Path, target: &Path) -> Option<String> {
    let root = root.canonicalize().ok()?;
    let target = match target.canonicalize() {
        Ok(t) => t,
        Err(_) => {
            let parent = target.parent().filter(|p| !p.as_os_str().is_empty());
            let parent = parent.unwrap_or(Path::new(".")).canonicalize().ok()?;
            parent.join(target.file_name()?)
        }
    };
    let rel = target.strip_prefix(&root).ok()?;
    let rel = rel.to_string_lossy().replace('\\', "/");
    (!rel.is_empty()).then_some(rel)
}

/// Exclusion patterns for the engine's own outputs located inside the
/// scanned folder (ticket #132): the history directory and the report
/// file, wherever `--data-dir`/`--output` put them. `DEFAULT_EXCLUDES`
/// already covers the default locations (`audit-reports/`,
/// `audit-datas/`); this covers moved ones, so a scan never reads its
/// previous reports back as source code (an HTML report is a scanned
/// language).
fn output_excludes(root: &Path, data_dir: Option<&Path>, output: Option<&Path>) -> Vec<String> {
    [data_dir, output]
        .into_iter()
        .flatten()
        .filter_map(|p| path_inside_root(root, p))
        .collect()
}

/// Resolves `paths.include`/`paths.exclude` for a scan.
///
/// 1. `audit.config.json` exists at the project root: read
///    (`project_config::read_paths_config`) — mirror of
///    `sca/config.py::load_config`. A file without a `paths` section is
///    still a present file (default paths, no prompt). A present but
///    invalid file is reported and the defaults are used, never the
///    prompt (ticket #137: the prompt overwrote it).
/// 2. Absent: the whole directory (`["."]`). In a terminal the file is
///    created first by `project::config_wizard`, called by
///    `run_scan_command`, which then stops without scanning
///    (2026-11-12); this branch is reached without a terminal, with
///    `--quiet` or with JSON logs.
///
/// In every case the returned exclusions start with `DEFAULT_EXCLUDES`
/// (see its doc comment); the project's own patterns follow. The third
/// value says where the paths came from, for the scope line printed at
/// scan start (ticket #140).
fn resolve_project_paths(
    root: &Path,
    script_locale: &serde_json::Value,
) -> (Vec<String>, Vec<String>, PathsOrigin) {
    // Prompt messages in the `--lang` language (ticket #124 — they were
    // hard-coded in French).
    let say = |key: &str| codefixture_audit::i18n::t(script_locale, key);

    match codefixture_audit::project::project_config::load_config_json(root) {
        Ok(Some(_)) => {
            let (include, exclude) =
                codefixture_audit::project::project_config::read_paths_config(root)
                    .unwrap_or_default();
            let include = if include.is_empty() {
                vec![".".to_string()]
            } else {
                include
            };
            return (
                include,
                with_default_excludes(exclude),
                PathsOrigin::ConfigFile,
            );
        }
        Err(error) => {
            emit_warning(&format!(
                "[codefixture-audit] {}",
                say("config_invalid")
                    .replace(
                        "{path}",
                        &root.join("audit.config.json").display().to_string()
                    )
                    .replace("{error}", &error)
            ));
            return (
                vec![".".to_string()],
                with_default_excludes(Vec::new()),
                PathsOrigin::InvalidConfig,
            );
        }
        Ok(None) => {}
    }

    // No file: the whole folder. In a terminal the scan never gets
    // here without a file: `run_scan_command` asks for one first
    // (`project::config_wizard`) and stops.
    (
        vec![".".to_string()],
        with_default_excludes(Vec::new()),
        PathsOrigin::NoConfig,
    )
}

/// Entries of an include or exclude list printed on the scope line before
/// the rest is counted. A list one entry longer is printed in full: "+1
/// more" would take the room of the entry itself.
const SCOPE_LIST_MAX: usize = 5;

/// Where the include/exclude paths of a scan come from (ticket #140).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathsOrigin {
    /// `audit.config.json` read at the project root (or just written by
    /// the interactive prompt).
    ConfigFile,
    /// `audit.config.json` present but unreadable or invalid JSON: the
    /// whole project is scanned (the error is reported separately).
    InvalidConfig,
    /// No `audit.config.json` and no accepted prompt: the whole project.
    NoConfig,
}

/// The scope line printed once at scan start (ticket #140): where the
/// paths come from, the include paths applied, and the exclusions the
/// user chose (project file and `--exclude`), the built-in ones only as a
/// count. A tester's scan widened to the whole project after a rewrite of
/// `audit.config.json`, and nothing in the output said so.
///
/// `include` of `["."]` reads as "the whole project". Shown like the
/// other progress lines: in normal mode and as a JSON log event, not with
/// `--quiet`, which only keeps results, warnings and errors (ticket #44);
/// the problems that widen the scope silently are warnings, so they still
/// show under `--quiet`.
fn scope_line(
    root: &Path,
    origin: PathsOrigin,
    include: &[String],
    excludes: &[String],
    say: impl Fn(&str) -> String,
) -> String {
    let source = match origin {
        PathsOrigin::ConfigFile => say("scan_scope_source_config"),
        PathsOrigin::InvalidConfig => say("scan_scope_source_invalid"),
        PathsOrigin::NoConfig => {
            say("scan_scope_source_none").replace("{path}", &root.display().to_string())
        }
    };
    // A tester's file listed 67 project folders: past `SCOPE_LIST_MAX`
    // entries, the list is cut and the rest counted.
    let shorten = |items: &[&str]| -> String {
        if items.len() <= SCOPE_LIST_MAX + 1 {
            return items.join(", ");
        }
        let more =
            say("scan_scope_more").replace("{count}", &(items.len() - SCOPE_LIST_MAX).to_string());
        format!("{}, {more}", items[..SCOPE_LIST_MAX].join(", "))
    };
    let include = if include.iter().all(|p| p == "." || p == "./") {
        say("scan_scope_whole_project")
    } else {
        shorten(&include.iter().map(String::as_str).collect::<Vec<_>>())
    };
    let chosen: Vec<&str> = excludes
        .iter()
        .map(String::as_str)
        .filter(|p| !DEFAULT_EXCLUDES.contains(p))
        .collect();
    let defaults =
        say("scan_scope_default_excludes").replace("{count}", &DEFAULT_EXCLUDES.len().to_string());
    let exclude = if chosen.is_empty() {
        defaults
    } else {
        format!("{} + {defaults}", shorten(&chosen))
    };
    say("scan_scope_line")
        .replace("{source}", &source)
        .replace("{include}", &include)
        .replace("{exclude}", &exclude)
}

/// Whether `--rules` and `rules list` accept a folder of plain `.sca`
/// files. The shared binary only reads rule packs: plain rules are the
/// private repository's sources (ADR-0041), never delivered.
const RULE_FOLDERS_ACCEPTED: bool = false;

/// Catalog for `scan` and `list-rules` (ADR-0040): the `--rules` value
/// (a pack file, or a folder holding at least one `.sca` file), else
/// `rules.cfpack` next to the executable. Anything else stops the
/// command with exit code 2 and names the path searched, rather than
/// running with no rule.
fn resolve_rules_path(
    rules: Option<PathBuf>,
    script_locale: &serde_json::Value,
) -> Result<PathBuf, ExitCode> {
    let fail = |key: &str, path: &Path| {
        emit_error(
            &codefixture_audit::i18n::t(script_locale, key)
                .replace("{path}", &path.display().to_string()),
        );
        Err(ExitCode::from(2))
    };
    match rules {
        Some(path) if path.is_dir() && RULE_FOLDERS_ACCEPTED => {
            if codefixture_audit::rules::catalog::has_rule_files(&path) {
                Ok(path)
            } else {
                fail("scan_no_rule_files", &path)
            }
        }
        Some(path) if path.is_dir() => fail("scan_rules_pack_only", &path),
        Some(path) if path.is_file() => Ok(path),
        Some(path) => fail("scan_invalid_rules_dir", &path),
        None => {
            let pack =
                codefixture_audit::rules::catalog::default_pack_path().unwrap_or_else(|| {
                    PathBuf::from(codefixture_audit::rules::pack_format::PACK_FILE_NAME)
                });
            if pack.is_file() {
                Ok(pack)
            } else {
                fail("scan_no_rule_pack", &pack)
            }
        }
    }
}

/// Every rule file of a pack or folder for the `rules` subcommands, or
/// exit code 2 with the path and the reason.
fn read_rules_or_exit(
    path: &Path,
    script_locale: &serde_json::Value,
) -> Result<Vec<codefixture_audit::rules::catalog::RuleSource>, ExitCode> {
    codefixture_audit::rules::catalog::read_all_rule_sources(path).map_err(|error| {
        emit_error(
            &codefixture_audit::i18n::t(script_locale, "rules_open_error")
                .replace("{path}", &path.display().to_string())
                .replace("{error}", &error.render(script_locale)),
        );
        ExitCode::from(2)
    })
}

/// Rule languages declared by the project (ADR-0038): the `languages` key
/// of `audit.config.json`, warning once about the values that name no
/// supported language. `None` when the key is absent or gives no
/// supported language: the scan then reads the rules of the languages of
/// the files it finds.
fn declared_rule_languages(root: &Path, say: impl Fn(&str) -> String) -> Option<Vec<String>> {
    let config = codefixture_audit::project::project_config::read_languages_config(root)?;
    if !config.unknown.is_empty() {
        emit_warning(&format!(
            "[codefixture-audit] {}",
            say("scan_languages_unknown").replace("{languages}", &config.unknown.join(", "))
        ));
    }
    (!config.languages.is_empty()).then_some(config.languages)
}

/// Console lines saying what the rule sources gave a scan (ADR-0040,
/// feedback of 2026-11-10: a tester could not tell which rules were
/// loaded). Per source: rule files kept over files available and the
/// pack or folder path; last, the number of rules kept and the languages
/// they cover.
fn rule_source_lines(report: &ScanReport, script_locale: &serde_json::Value) -> Vec<String> {
    use codefixture_audit::rules::catalog::RuleSourceKind;
    let say = |key: &str| codefixture_audit::i18n::t(script_locale, key);
    let mut lines: Vec<String> = report
        .rule_sources
        .iter()
        .map(|source| {
            let key = match source.kind {
                RuleSourceKind::Pack => "scan_rules_source_pack",
                RuleSourceKind::Folder => "scan_rules_source_folder",
            };
            say(key)
                .replace("{read}", &source.files_read.to_string())
                .replace("{available}", &source.files_available.to_string())
                .replace("{path}", &source.path.display().to_string())
        })
        .collect();
    lines.push(
        say("scan_rule_languages")
            .replace("{count}", &report.rules_loaded.to_string())
            .replace("{languages}", &report.rule_languages.join(", ")),
    );
    lines
}

/// The console line of one pass's cache (`scan_cache`). A re-scan that
/// reused the previous cache says how many files changed and how much was
/// redone. A pass that could not use it at all says that the analysis was
/// a full one, and why (ticket #204): saying "changed since the last
/// scan" there named a false reason, for example after a change of
/// `--lang`, where no file had changed.
fn cache_stat_line(
    stat: &codefixture_audit::scan::scan_cache::CacheStat,
    t: impl Fn(&str) -> String,
) -> String {
    use codefixture_audit::scan::scan_cache::CacheMiss;
    let patterns = stat.language == "patterns";
    let template = match (&stat.full, patterns) {
        (None, true) => t("scan_cache_patterns_line"),
        (None, false) => t("scan_cache_line"),
        (Some(_), true) => t("scan_cache_patterns_full_line"),
        (Some(_), false) => t("scan_cache_full_line"),
    };
    let reason = match &stat.full {
        None => String::new(),
        Some(CacheMiss::Missing) => t("scan_cache_reason_missing"),
        Some(CacheMiss::Unreadable) => t("scan_cache_reason_unreadable"),
        Some(CacheMiss::Format) => t("scan_cache_reason_format"),
        Some(CacheMiss::Engine) => t("scan_cache_reason_engine"),
        Some(CacheMiss::Language { previous, current }) => t("scan_cache_reason_language")
            .replace("{previous}", previous)
            .replace("{current}", current),
        Some(CacheMiss::Rules) => t("scan_cache_reason_rules"),
    };
    template
        .replace("{language}", &stat.language)
        .replace("{dirty}", &stat.dirty.to_string())
        .replace("{files}", &stat.files.to_string())
        .replace("{analysed}", &stat.analysed.to_string())
        .replace("{total}", &stat.total.to_string())
        .replace("{reason}", &reason)
}

/// Console line naming the folders the walk skipped as holding no project
/// code (tickets #148 and #152): their path relative to the project, with
/// a trailing `/`, and why — `docs/ (documentation)`. Past
/// `SCOPE_LIST_MAX` folders the rest is counted, like the scope line.
/// `None` when nothing was skipped. A documentation folder can hold code
/// that runs: this line is what keeps it from going unchecked without a
/// word.
fn skipped_dirs_line(
    root: &Path,
    skipped: &[codefixture_audit::scan::discovery::SkippedDir],
    say: impl Fn(&str) -> String,
) -> Option<String> {
    use codefixture_audit::scan::discovery::SkippedDirKind;
    if skipped.is_empty() {
        return None;
    }
    let items: Vec<String> = skipped
        .iter()
        .map(|(path, kind)| {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            let reason = match kind {
                SkippedDirKind::Documentation => say("scan_skipped_documentation"),
                SkippedDirKind::Virtualenv => say("scan_skipped_virtualenv"),
                SkippedDirKind::BuildOutput => say("scan_skipped_build_output"),
            };
            format!("{rel}/ ({reason})")
        })
        .collect();
    let dirs = if items.len() <= SCOPE_LIST_MAX + 1 {
        items.join(", ")
    } else {
        let more =
            say("scan_scope_more").replace("{count}", &(items.len() - SCOPE_LIST_MAX).to_string());
        format!("{}, {more}", items[..SCOPE_LIST_MAX].join(", "))
    };
    Some(say("scan_skipped_dirs").replace("{dirs}", &dirs))
}

/// The console line naming the files skipped for one reason, from the
/// locale message `key`: minified files (`scan_skipped_minified`,
/// ADR-0045, `Skipped, minified code: a.js, b.html`) or saved web pages
/// (`scan_skipped_saved_pages`, ADR-0046). Past `SCOPE_LIST_MAX` files the
/// rest is counted, like the scope line. `None` when nothing was skipped.
/// Never silent, for the reason of [`skipped_dirs_line`]: a file the scan
/// leaves out must be named.
fn skipped_files_line(key: &str, files: &[String], say: impl Fn(&str) -> String) -> Option<String> {
    if files.is_empty() {
        return None;
    }
    let list = if files.len() <= SCOPE_LIST_MAX + 1 {
        files.join(", ")
    } else {
        let more =
            say("scan_scope_more").replace("{count}", &(files.len() - SCOPE_LIST_MAX).to_string());
        format!("{}, {more}", files[..SCOPE_LIST_MAX].join(", "))
    };
    Some(
        say(key)
            .replace("{count}", &files.len().to_string())
            .replace("{files}", &list),
    )
}

/// Include paths of `audit.config.json` that do not exist under `root`,
/// in their configured order. The walk skips them (`find_files`), so the
/// CLI reports them once per scan instead of letting a typo scan nothing
/// without a word (ticket #138 — Python skips them silently too).
fn missing_include_paths(root: &Path, include_paths: &[String]) -> Vec<String> {
    include_paths
        .iter()
        .filter(|p| !root.join(p).exists())
        .cloned()
        .collect()
}

/// `DEFAULT_EXCLUDES` followed by `project_excludes`, without
/// duplicates (first occurrence kept) — the project's patterns can
/// only add exclusions, never remove a default one (ticket #132).
fn with_default_excludes(project_excludes: Vec<String>) -> Vec<String> {
    let mut merged: Vec<String> = DEFAULT_EXCLUDES.iter().map(|s| s.to_string()).collect();
    for pattern in project_excludes {
        if !merged.contains(&pattern) {
            merged.push(pattern);
        }
    }
    merged
}

/// The line naming the version rules the dependencies were checked
/// against (ADR-0042, ADR-0043), and whether it is a warning: the pack
/// read with the date of its data and its advisories per ecosystem, or
/// why the dependencies were not compared with published vulnerabilities.
fn version_rules_line(
    status: &codefixture_audit::scan::orchestrator::VersionRulesStatus,
    script_locale: &serde_json::Value,
) -> (bool, String) {
    use codefixture_audit::scan::orchestrator::VersionRulesStatus;
    let say = |key: &str| codefixture_audit::i18n::t(script_locale, key);
    match status {
        VersionRulesStatus::Read {
            pack,
            created,
            counts,
            ..
        } => {
            let total: usize = counts.iter().map(|(_, n)| n).sum();
            let counts: Vec<String> = counts
                .iter()
                .map(|(name, n)| format!("{name} {n}"))
                .collect();
            (
                false,
                say("scan_version_rules_read")
                    .replace("{total}", &total.to_string())
                    .replace("{path}", &pack.display().to_string())
                    .replace("{date}", created)
                    .replace("{counts}", &counts.join(", ")),
            )
        }
        VersionRulesStatus::Missing => (true, say("scan_version_rules_missing")),
        VersionRulesStatus::Unreadable { error } => (
            true,
            say("scan_version_rules_unreadable").replace("{error}", &error.render(script_locale)),
        ),
    }
}

/// `ScanConfig::on_phase_complete` callback — displays progress LIVE,
/// phase by phase, instead of a single dump after the scan fully
/// completes (reported by the maintainer, 2026-08-26: nothing was displayed
/// until the very end). `run_scan` remains free of direct I/O (see
/// the field doc in `orchestrator.rs`); this callback is what writes
/// to stderr, one line per phase, as soon as it finishes.
fn print_phase_progress(label: &str, elapsed: std::time::Duration) {
    if JSON_LOGS.load(std::sync::atomic::Ordering::Relaxed) {
        emit_json_line(
            LogLevel::Info,
            label,
            Some(serde_json::json!(elapsed.as_millis())),
        );
    } else {
        eprintln!("{}", phase_progress_line(label, elapsed));
    }
}

/// Text-mode progress line of one phase, as printed by
/// `print_phase_progress` (kept separate so its format is testable
/// without capturing stderr).
fn phase_progress_line(label: &str, elapsed: std::time::Duration) -> String {
    format!(
        "[codefixture-audit]   {label} : {}",
        format_duration(elapsed)
    )
}

/// Human-readable duration for the console (ticket #135): `850 ms`
/// under a second, `12.4 s` under a minute, `1 min 12 s` under an hour,
/// `1 h 02 min` beyond. Units are the same in the four console languages
/// (SI symbols), hence no locale lookup. JSON logs keep the raw
/// `duration_ms`. Truncates rather than rounds at each level, so a
/// displayed value is never larger than the real one (`59.99 s` shows
/// `59.9 s`, not `60.0 s`).
fn format_duration(d: std::time::Duration) -> String {
    let ms = d.as_millis();
    if ms < 1_000 {
        format!("{ms} ms")
    } else if ms < 60_000 {
        format!("{}.{} s", ms / 1_000, (ms % 1_000) / 100)
    } else if ms < 3_600_000 {
        let secs = ms / 1_000;
        format!("{} min {} s", secs / 60, secs % 60)
    } else {
        let mins = ms / 60_000;
        format!("{} h {:02} min", mins / 60, mins % 60)
    }
}

/// `scan --log-format json` (ticket #92): every console line becomes one
/// JSON object instead of `[codefixture-audit] …` text. Process-wide because
/// the console helpers below are free functions called from everywhere
/// (and from a plain `fn` callback, `print_phase_progress`); set before
/// the scan's resource limits are resolved (`dispatch`, ticket #281), and
/// again at the start of `run_scan_command`, before the first message.
static JSON_LOGS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Level of a console message, as written in JSON log lines.
#[derive(Clone, Copy)]
enum LogLevel {
    Info,
    Warn,
    Error,
}

/// Writes one single-line JSON log event to stderr: `timestamp` (UTC,
/// RFC 3339, milliseconds), `level`, `message` (without the
/// `[codefixture-audit]` text prefix), plus `duration_ms` for a finished
/// phase. Built with `serde_json`, so any message text is escaped.
fn emit_json_line(level: LogLevel, message: &str, duration_ms: Option<serde_json::Value>) {
    let level = match level {
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    };
    let message = message
        .trim()
        .strip_prefix("[codefixture-audit]")
        .unwrap_or(message.trim())
        .trim();
    let mut event = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "level": level,
        "message": message,
    });
    if let Some(duration_ms) = duration_ms {
        event["duration_ms"] = duration_ms;
    }
    eprintln!("{event}");
}

/// Single choke point of every console line (ticket #44's rationale,
/// kept for ticket #92): plain text by default, a JSON event with
/// `--log-format json`.
fn log_line(level: LogLevel, msg: &str) {
    // Ticket #282: every console line is in the debug log too, at its
    // place among the steps.
    codefixture_audit::debug_log!(
        "console",
        "{} {msg:?}",
        match level {
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    );
    if JSON_LOGS.load(std::sync::atomic::Ordering::Relaxed) {
        emit_json_line(level, msg, None);
    } else {
        eprintln!("{msg}");
    }
}

/// Intermediate progress message ("Analysis in
/// progress...", path of the written report) — suppressed by
/// `--quiet`. Distinct from `emit_result`: never used for the final
/// summary or an error, see ticket #44 (spec #29) where `--quiet` used
/// to suppress those two categories too, making a CI scan
/// undiagnosable.
fn emit_progress(quiet: bool, msg: &str) {
    if !quiet {
        log_line(LogLevel::Info, msg);
    } else {
        // Hidden from the console, not from the debug log (ticket #282).
        codefixture_audit::debug_log!("console", "info_hidden_by_quiet {msg:?}");
    }
}

/// Final result or error message — never suppressed by `--quiet`,
/// regardless of its caller. A silent CI scan must remain
/// diagnosable: an invalid path or the final
/// summary must never disappear silently.
fn emit_result(msg: &str) {
    log_line(LogLevel::Info, msg);
}

/// Like `emit_result`, for a warning: the scan goes on (ignored config
/// section, skipped rule).
fn emit_warning(msg: &str) {
    log_line(LogLevel::Warn, msg);
}

/// Like `emit_result`, for an error that ends the command.
fn emit_error(msg: &str) {
    log_line(LogLevel::Error, msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ticket #214: the `text` format writes `file:line:` for a line
    /// finding and `file:` for a whole-file finding, never `file:1:`.
    #[test]
    fn test_format_text_report_whole_file_finding_has_no_line() {
        let finding = |file_scope: serde_json::Value| -> ReportFinding {
            serde_json::from_value(serde_json::json!({
                "rule_key": "file_too_long", "rule_name": "file_too_long",
                "category": "ARCH", "severity": "LOW", "risk": "Too long.",
                "file": "app/big.py", "line": 1, "solution": null, "cwe": [],
                "owasp": null, "taint_flow": null, "code": "import os",
                "context_before": "", "context_after": "", "confidence": 80,
                "benefit": "", "committer": null, "rule_source": "json_builtin",
                "file_scope": file_scope,
            }))
            .expect("valid ReportFinding")
        };
        let whole = finding(serde_json::json!({"line_count": 812, "min_lines": 500}));
        let line = finding(serde_json::Value::Null);
        assert_eq!(
            format_text_report(&[whole]),
            "app/big.py: [LOW] file_too_long — Too long.\n"
        );
        assert_eq!(
            format_text_report(&[line]),
            "app/big.py:1: [LOW] file_too_long — Too long.\n"
        );
    }

    #[test]
    fn test_rerun_command_is_the_typed_command_ready_to_copy() {
        let args = [
            "./target/release/codefixture-audit",
            "scan",
            "/Users/me/My Project",
            "--lang",
            "fr",
        ]
        .iter()
        .map(|s| s.to_string());
        assert_eq!(
            rerun_command(args),
            "./target/release/codefixture-audit scan '/Users/me/My Project' --lang fr"
        );
    }

    #[test]
    fn test_format_duration_picks_unit_by_magnitude() {
        use std::time::Duration;
        let cases = [
            (Duration::from_millis(31), "31 ms"),
            (Duration::from_millis(999), "999 ms"),
            (Duration::from_millis(12_480), "12.4 s"),
            (Duration::from_millis(59_990), "59.9 s"),
            (Duration::from_secs(72), "1 min 12 s"),
            (Duration::from_secs(3_720), "1 h 02 min"),
        ];
        for (duration, expected) in cases {
            // Called outside the macro so the code graph sees the call.
            let formatted = format_duration(duration);
            assert_eq!(formatted, expected);
        }
    }

    /// Ticket #204: a pass that reused its cache says how many files
    /// changed; one that could not use it says the analysis was a full
    /// one and why, never that every file changed.
    #[test]
    fn test_cache_stat_line_names_why_the_analysis_was_full() {
        use codefixture_audit::scan::scan_cache::{CacheMiss, CacheStat};
        let fr = codefixture_audit::i18n::load_script_locale("fr");
        let say = |k: &str| codefixture_audit::i18n::t(&fr, k);
        let stat = |language: &str, dirty: usize, full: Option<CacheMiss>| CacheStat {
            language: language.into(),
            files: 460,
            dirty,
            analysed: 10,
            total: 20,
            full,
        };
        assert_eq!(
            cache_stat_line(&stat("python", 3, None), say),
            "Cache (python) : 3/460 fichier(s) modifié(s) depuis la dernière analyse, \
             10/20 analyses de flux refaites."
        );
        let language = CacheMiss::Language {
            previous: "en".into(),
            current: "fr".into(),
        };
        assert_eq!(
            cache_stat_line(&stat("python", 460, Some(language.clone())), say),
            "Cache (python) : analyse complète des 460 fichier(s), langue du rapport \
             changée (en → fr) ; 10/20 analyses de flux faites."
        );
        assert_eq!(
            cache_stat_line(&stat("patterns", 460, Some(language)), say),
            "Cache (règles de motif) : analyse complète des 460 fichier(s), langue du \
             rapport changée (en → fr)."
        );
        // Every reason has a text in every language.
        for lang in ["en", "fr", "de", "es"] {
            let locale = codefixture_audit::i18n::load_script_locale(lang);
            let say = |k: &str| codefixture_audit::i18n::t(&locale, k);
            for miss in [
                CacheMiss::Missing,
                CacheMiss::Unreadable,
                CacheMiss::Format,
                CacheMiss::Engine,
                CacheMiss::Rules,
            ] {
                for language in ["python", "patterns"] {
                    let line = cache_stat_line(&stat(language, 460, Some(miss.clone())), say);
                    assert!(
                        !line.contains('{') && !line.contains("scan_cache"),
                        "{lang}: {line}"
                    );
                }
            }
        }
    }

    /// ADR-0043: the version rules read are named with their pack, the
    /// date of their data and their counts; a pack without them, or
    /// unreadable ones, is a warning saying the dependencies were not
    /// checked.
    #[test]
    fn test_version_rules_line_names_the_pack_or_says_not_checked() {
        use codefixture_audit::scan::orchestrator::VersionRulesStatus;
        let en = codefixture_audit::i18n::load_script_locale("en");
        let (warning, line) = version_rules_line(
            &VersionRulesStatus::Read {
                pack: PathBuf::from("/x/rules.cfpack"),
                created: "2026-11-11T00:00:00Z".into(),
                counts: vec![("PyPI".into(), 12), ("npm".into(), 30)],
                sources: vec![],
            },
            &en,
        );
        assert!(!warning);
        assert!(
            line.contains("/x/rules.cfpack")
                && line.contains("2026-11-11")
                && line.contains("PyPI 12, npm 30")
                && line.contains("42"),
            "{line}"
        );
        let (warning, line) = version_rules_line(&VersionRulesStatus::Missing, &en);
        assert!(
            warning && line.contains("not checked") && !line.contains("cfdb"),
            "{line}"
        );
        let (warning, line) = version_rules_line(
            &VersionRulesStatus::Unreadable {
                error: codefixture_audit::rules::pack_format::PackError::new(
                    codefixture_audit::rules::pack_format::keys::CORRUPT,
                ),
            },
            &en,
        );
        assert!(
            warning && line.contains("rule pack is corrupt") && line.contains("not checked"),
            "{line}"
        );
    }

    /// Ticket #280: unreadable version rules are named on a French console
    /// in French, the reason included: one of the pack, one of its
    /// advisory container.
    #[test]
    fn test_unreadable_version_rules_are_named_in_the_console_language() {
        use codefixture_audit::scan::orchestrator::VersionRulesStatus;
        let fr = codefixture_audit::i18n::load_script_locale("fr");
        let corrupt = VersionRulesStatus::Unreadable {
            error: codefixture_audit::rules::pack_format::PackError::new(
                codefixture_audit::rules::pack_format::keys::CORRUPT,
            ),
        };
        let (warning, line) = version_rules_line(&corrupt, &fr);
        assert!(warning);
        assert_eq!(
            line,
            "Règles de version du pack inutilisables (pack de règles corrompu ou modifié) : les dépendances n'ont pas été comparées aux vulnérabilités publiées."
        );
        let not_a_database = VersionRulesStatus::Unreadable {
            error: codefixture_audit::project::advisory_file::decode(
                Path::new("rules.cfpack"),
                b"garbage".to_vec(),
            )
            .unwrap_err(),
        };
        let (_, line) = version_rules_line(&not_a_database, &fr);
        assert!(
            line.contains("rules.cfpack : ce fichier n'est pas une base de vulnérabilités (cfdb)"),
            "{line}"
        );
    }

    #[test]
    fn test_with_default_excludes_keeps_defaults_and_adds_project_patterns() {
        let merged = with_default_excludes(vec!["legacy/".into(), "vendor/".into()]);
        assert!(merged.iter().any(|p| p == "audit-reports/"));
        assert_eq!(merged.iter().filter(|p| *p == "vendor/").count(), 1);
        assert_eq!(merged.last().map(String::as_str), Some("legacy/"));
    }

    #[test]
    fn test_missing_include_paths_keeps_only_absent_ones() {
        let root = std::env::temp_dir().join(format!("sast_missing_inc_{}", std::process::id()));
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.py"), "x = 1\n").unwrap();
        let include = ["src/", "src/a.py", "srcc/", "."].map(String::from);
        // Called outside the macro so the code graph sees the call.
        let missing = missing_include_paths(&root, &include);
        assert_eq!(missing, vec!["srcc/".to_string()]);
        std::fs::remove_dir_all(&root).ok();
    }

    /// `rules/builtin` of the repository, the folder `build.rs` packs
    /// next to the binary (unit test binaries run from `deps/`, where
    /// there is no pack).
    fn builtin_rules_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/builtin")
    }

    /// Ticket #152: skipped folders are named relative to the project with
    /// their reason, cut past `SCOPE_LIST_MAX`; nothing skipped, no line.
    #[test]
    fn test_skipped_files_line_names_files_and_counts_the_rest() {
        let say = |key: &str| match key {
            "scan_skipped_minified" => "Skipped, minified code ({count}): {files}.".to_string(),
            "scan_scope_more" => "+{count} more".to_string(),
            other => other.to_string(),
        };
        assert!(skipped_files_line("scan_skipped_minified", &[], say).is_none());
        let two = vec!["a.js".to_string(), "b.html".to_string()];
        assert_eq!(
            skipped_files_line("scan_skipped_minified", &two, say).unwrap(),
            "Skipped, minified code (2): a.js, b.html."
        );
        let many: Vec<String> = (0..SCOPE_LIST_MAX + 5)
            .map(|i| format!("f{i}.js"))
            .collect();
        let line = skipped_files_line("scan_skipped_minified", &many, say).unwrap();
        assert!(line.ends_with("+5 more."), "{line}");
    }

    #[test]
    fn test_skipped_dirs_line_names_folders_and_reasons() {
        use codefixture_audit::scan::discovery::SkippedDirKind;
        let locale = codefixture_audit::i18n::load_script_locale("en");
        let say = |key: &str| codefixture_audit::i18n::t(&locale, key);
        let root = Path::new("/p");
        let skipped = vec![
            (root.join("docs"), SkippedDirKind::Documentation),
            (root.join("tools/.venv-clone"), SkippedDirKind::Virtualenv),
            (root.join("api/target"), SkippedDirKind::BuildOutput),
        ];
        let line = skipped_dirs_line(root, &skipped, say).expect("a line");
        assert_eq!(
            line,
            "Skipped, not project code: docs/ (documentation), tools/.venv-clone/ (Python virtualenv), api/target/ (build output). Name a folder in paths.include to scan it."
        );
        let many: Vec<_> = (0..8)
            .map(|i| {
                (
                    root.join(format!("m{i}/docs")),
                    SkippedDirKind::Documentation,
                )
            })
            .collect();
        let cut = skipped_dirs_line(root, &many, say).unwrap();
        assert!(
            cut.contains("m4/docs/") && !cut.contains("m5/docs/"),
            "{cut}"
        );
        assert!(skipped_dirs_line(root, &[], say).is_none());
    }

    /// ADR-0040: `--rules` takes a pack file, or a folder holding `.sca`
    /// files; a folder without any, or a path that does not exist, stops
    /// the command with exit code 2.
    #[test]
    fn test_resolve_rules_path_accepts_pack_or_rule_folder() {
        let parent =
            std::env::temp_dir().join(format!("sast_resolve_rules_{}", std::process::id()));
        let empty = parent.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let pack = parent.join("rules.cfpack");
        std::fs::write(&pack, b"any file: opened at scan time").unwrap();
        let locale = codefixture_audit::i18n::load_script_locale("en");

        let folder = resolve_rules_path(Some(builtin_rules_dir()), &locale);
        let file = resolve_rules_path(Some(pack.clone()), &locale);
        let no_rules = resolve_rules_path(Some(empty), &locale);
        let missing = resolve_rules_path(Some(parent.join("missing")), &locale);
        std::fs::remove_dir_all(&parent).ok();

        // A folder of plain rules: private build only (ADR-0041).
        assert_eq!(folder.is_ok(), RULE_FOLDERS_ACCEPTED);
        assert_eq!(file.ok(), Some(pack));
        assert_eq!(no_rules.err(), Some(ExitCode::from(2)));
        assert_eq!(missing.err(), Some(ExitCode::from(2)));
    }

    #[test]
    fn test_phase_progress_line_and_print() {
        let elapsed = std::time::Duration::from_millis(1_250);
        let line = phase_progress_line("[2/4] phase A", elapsed);
        assert_eq!(line, "[codefixture-audit]   [2/4] phase A : 1.2 s");
        // Writes the same line to stderr; must not panic.
        print_phase_progress("[2/4] phase A", elapsed);
    }

    #[test]
    fn test_path_inside_root_cases() {
        let root = std::env::temp_dir().join(format!("sast_inside_{}", std::process::id()));
        std::fs::create_dir_all(root.join("out")).unwrap();
        let existing = path_inside_root(&root, &root.join("out"));
        let not_yet_written = path_inside_root(&root, &root.join("out/report.html"));
        let root_itself = path_inside_root(&root, &root);
        let outside = path_inside_root(&root, &std::env::temp_dir());
        let missing_parent = path_inside_root(&root, &root.join("nope/report.html"));
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(existing.as_deref(), Some("out"));
        assert_eq!(not_yet_written.as_deref(), Some("out/report.html"));
        assert_eq!(root_itself, None);
        assert_eq!(outside, None);
        assert_eq!(missing_parent, None, "parent must exist to canonicalize");
    }

    /// The non-interactive branches of `resolve_project_paths` (`quiet`
    /// never prompts): valid file, file with an empty include, invalid
    /// file, no file.
    #[test]
    fn test_resolve_project_paths_branches() {
        let locale = codefixture_audit::i18n::load_script_locale("en");
        let root = std::env::temp_dir().join(format!("sast_resolve_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let config = root.join("audit.config.json");
        let defaults = with_default_excludes(Vec::new());

        let absent = resolve_project_paths(&root, &locale);

        std::fs::write(
            &config,
            r#"{"paths": {"include": ["src/"], "exclude": ["legacy/", "vendor/"]}}"#,
        )
        .unwrap();
        let valid = resolve_project_paths(&root, &locale);

        std::fs::write(&config, r#"{"paths": {"include": []}}"#).unwrap();
        let empty_include = resolve_project_paths(&root, &locale);

        let invalid_text = r#"{"paths": {"include": ["src/"],}}"#;
        std::fs::write(&config, invalid_text).unwrap();
        let invalid = resolve_project_paths(&root, &locale);
        let after_invalid = std::fs::read_to_string(&config).unwrap();
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(
            absent,
            (
                vec![".".to_string()],
                defaults.clone(),
                PathsOrigin::NoConfig
            )
        );
        assert_eq!(valid.0, vec!["src/".to_string()]);
        assert_eq!(valid.2, PathsOrigin::ConfigFile);
        assert_eq!(
            valid.1,
            with_default_excludes(vec!["legacy/".into(), "vendor/".into()])
        );
        assert_eq!(empty_include.0, vec![".".to_string()]);
        assert_eq!(empty_include.1, defaults);
        assert_eq!(empty_include.2, PathsOrigin::ConfigFile);
        assert_eq!(
            invalid,
            (vec![".".to_string()], defaults, PathsOrigin::InvalidConfig)
        );
        assert_eq!(
            after_invalid, invalid_text,
            "an invalid file is never rewritten"
        );
    }

    /// Ticket #140: the scope line names the source, reads `["."]` as
    /// the whole project, lists the user's exclusions and counts the
    /// built-in ones.
    #[test]
    fn test_scope_line_per_origin() {
        let locale = codefixture_audit::i18n::load_script_locale("en");
        let say = |key: &str| codefixture_audit::i18n::t(&locale, key);
        let root = Path::new("/work/app");
        let defaults = with_default_excludes(Vec::new());
        let count = DEFAULT_EXCLUDES.len();

        let none = scope_line(root, PathsOrigin::NoConfig, &[".".into()], &defaults, say);
        let mut chosen = with_default_excludes(vec!["legacy/".into()]);
        chosen.push("*.mustache".into());
        let config = scope_line(
            root,
            PathsOrigin::ConfigFile,
            &["src/".into(), "web/".into()],
            &chosen,
            say,
        );
        let invalid = scope_line(
            root,
            PathsOrigin::InvalidConfig,
            &[".".into()],
            &defaults,
            say,
        );

        assert_eq!(
            none,
            format!(
                "Scope (no audit.config.json in /work/app): include the whole project; exclude {count} default patterns"
            )
        );
        assert_eq!(
            config,
            format!(
                "Scope (audit.config.json): include src/, web/; exclude legacy/, *.mustache + {count} default patterns"
            )
        );
        assert!(
            invalid.starts_with("Scope (invalid audit.config.json): include the whole project")
        );

        let many: Vec<String> = (1..=67).map(|i| format!("app-{i}/")).collect();
        let long = scope_line(root, PathsOrigin::ConfigFile, &many, &defaults, say);
        assert!(
            long.contains("app-5/, +62 more;") && !long.contains("app-6/"),
            "{long}"
        );
    }

    /// `--sbom` is a `scan` option of the shared build too (ticket #196):
    /// the parse goes through the public `Scan` fields, so this test holds
    /// in the private build and in the exported one.
    #[test]
    fn test_scan_accepts_sbom_in_every_build() {
        let cli = Cli::try_parse_from(["codefixture-audit", "scan", "project", "--sbom"])
            .expect("scan --sbom parses");
        match cli.command {
            Command::Scan { sbom, .. } => assert!(sbom),
            _ => panic!("expected the scan command"),
        }
        let cli = Cli::try_parse_from(["codefixture-audit", "scan", "project"]).unwrap();
        match cli.command {
            Command::Scan { sbom, .. } => assert!(!sbom, "off by default"),
            _ => panic!("expected the scan command"),
        }
    }

    #[test]
    fn test_write_sbom_writes_named_cyclonedx_file() {
        let root = std::env::temp_dir().join(format!("sast_sbom_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("requirements.txt"), "requests==2.31.0\n").unwrap();
        let config = ScanConfig {
            root: root.clone(),
            datas_dir: Some(root.join("datas")),
            timestamp: "2026-11-09-08-00".to_string(),
            ..ScanConfig::default()
        };
        let written = write_sbom(&config, "demo", &Brand::default(), &chrono::Local::now());
        let path = written.expect("SBOM written");
        let json = std::fs::read_to_string(&path).unwrap_or_default();
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(path, root.join("datas/SCA-SBOM-2026-11-09-08-00.json"));
        assert!(json.contains("CycloneDX"), "{json}");
        assert!(json.contains("requests"), "{json}");
    }

    #[test]
    fn test_output_excludes_only_paths_inside_root() {
        let root = std::env::temp_dir().join(format!("sast_out_excl_{}", std::process::id()));
        std::fs::create_dir_all(root.join("out/hist")).unwrap();
        let outside = std::env::temp_dir();
        let excludes = output_excludes(
            &root,
            Some(&root.join("out/hist")),
            Some(&root.join("report.html")),
        );
        assert_eq!(
            excludes,
            vec!["out/hist".to_string(), "report.html".to_string()]
        );
        let outside_only = output_excludes(&root, Some(&outside), Some(&root));
        assert!(outside_only.is_empty());
        std::fs::remove_dir_all(&root).ok();
    }
}

#[derive(Parser)]
#[command(
    name = "codefixture-audit",
    version = codefixture_audit::BUILD_VERSION,
    about = "SAST engine — Rust port of CodeFixture Audit"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Formats of `scan --format`: the shared binary writes the HTML report or
/// SARIF (for an IDE or a code platform); the plain-text listing is a
/// private tool (2026-11-14).
const SCAN_FORMATS: &[&str] = &["html", "sarif"];

/// The command line the user typed, ready to copy and run again: each
/// argument as it was, quoted when it holds a space or a quote.
fn rerun_command(args: impl Iterator<Item = String>) -> String {
    args.map(|a| {
        if a.is_empty() || a.contains([' ', '\'', '"']) {
            format!("'{}'", a.replace('\'', "'\\''"))
        } else {
            a
        }
    })
    .collect::<Vec<_>>()
    .join(" ")
}

/// Options of `scan` kept for the private binary only (2026-11-14): the
/// shared binary offers a short list, checks the dependencies whenever
/// its rule pack carries version rules (ADR-0043) and reads the project's
/// `.sca-suppress.json` by itself; these options then take their default.
#[derive(clap::Args, Debug)]
struct ScanExtraArgs {
    /// Console log format: `text` (default, `[codefixture-audit] …` lines)
    /// or `json` (one JSON object per line: `timestamp`, `level`,
    /// `message`, `duration_ms` for phases — ticket #92).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    log_format: String,
    /// Output file. Absent by default with `--format html`: writes
    /// `<PREFIX>-REPORT-<timestamp>.html` (`PREFIX` from
    /// `brand.json`, `SCA` by default) into `audit-reports/` of
    /// the scanned folder (Audit uses `docs/audit-reports/`). Absent with
    /// `--format text`/`sarif`: stdout.
    #[arg(long)]
    output: Option<PathBuf>,
    /// `.sca-suppress.json` file.
    #[arg(long)]
    suppress_file: Option<PathBuf>,
    /// Only displays the report, not the summary on stderr.
    #[arg(long)]
    quiet: bool,
    /// Runs the audited project's test suite (opt-in, executes
    /// arbitrary project code).
    #[arg(long)]
    with_tests: bool,
    /// Explicit test command (otherwise auto-detected).
    #[arg(long)]
    test_command: Option<String>,
    /// Runs the dependencies phase even with a rule pack (or folder)
    /// without version rules: unpinned dependencies are reported, and the
    /// scan says the versions were not checked. A pack carrying version
    /// rules runs the phase without this option (ADR-0043).
    #[arg(long)]
    with_deps: bool,
    /// PostgreSQL host — enables the DB schema audit if present.
    #[arg(long)]
    db_host: Option<String>,
    #[arg(long)]
    db_port: Option<u16>,
    #[arg(long)]
    db_name: Option<String>,
    #[arg(long)]
    db_user: Option<String>,
    /// `.env` file containing the DB password (default: `.env`).
    #[arg(long)]
    db_password_env_file: Option<String>,
    /// Variable in the `.env` file carrying the password (default: `DB_PASSWORD`).
    #[arg(long)]
    db_password_env_var: Option<String>,
    /// History directory (JSON export after every scan, compared
    /// against the last baseline found).
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Rule identifier to disable (repeatable).
    #[arg(long = "disable-rule")]
    disable_rule: Vec<String>,
    /// Severities to keep, comma-separated (e.g.
    /// "HIGH,CRITICAL"). Accepted values: CRITICAL/HIGH/MEDIUM/LOW/INFO.
    #[arg(long)]
    severity: Option<String>,
    /// `brand.json` runtime customization file (ticket #87/spec
    /// #83) — default: `brand.json` next to the executable.
    /// Absent or invalid: strictly unchanged behavior ("CodeFixture"
    /// defaults).
    #[arg(long)]
    brand_file: Option<PathBuf>,
    /// Writes a JSON file of scan metrics (files/LOC scanned,
    /// findings by severity, per-phase durations, exit code) to this
    /// path — opt-in, local file only (ticket #90).
    #[arg(long)]
    metrics_output: Option<PathBuf>,
}

impl Default for ScanExtraArgs {
    fn default() -> Self {
        Self {
            log_format: "text".to_string(),
            output: None,
            suppress_file: None,
            quiet: false,
            with_tests: false,
            test_command: None,
            with_deps: false,
            db_host: None,
            db_port: None,
            db_name: None,
            db_user: None,
            db_password_env_file: None,
            db_password_env_var: None,
            data_dir: None,
            disable_rule: Vec::new(),
            severity: None,
            brand_file: None,
            metrics_output: None,
        }
    }
}

#[derive(Subcommand)]
// Expected, harmless size gap: this enum only exists during CLI
// argument parsing (never stored in a collection/hot loop) — boxing
// `Scan`'s fields would complicate the `derive(Parser)` macro for
// clap with no real benefit.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Scans a project (Python, Java, JavaScript/TypeScript, PHP, C#,
    /// HTML and its templates, Razor views `.cshtml` and `.razor` among them,
    /// YAML, Dockerfile), and its `pom.xml`, `web.config`
    /// and `package.json` for the rules written for them. Minified files (a `.min.` name,
    /// or JavaScript, TypeScript and HTML written on very long lines) are
    /// skipped and listed after the scan, and so are web pages saved from
    /// a browser (a `<!-- saved from url=` mark, and their `<name>_files/`
    /// folder).
    Scan {
        /// Path of the project to scan.
        path: PathBuf,
        /// Rules: a rule pack (`*.cfpack`), ADR-0040 — default:
        /// `rules.cfpack` next to the executable. Only the rules of the
        /// project's languages are kept.
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Output format: `html` (the report, default) or `sarif` (for an
        /// IDE or a code platform).
        #[arg(long, default_value = "html", value_parser = clap::builder::PossibleValuesParser::new(SCAN_FORMATS))]
        format: String,
        /// HTML report language (`en`/`fr`/`es`/`de`).
        #[arg(long, default_value = "en")]
        lang: String,
        /// Analyses everything again, without reading or writing the taint
        /// cache of `audit-reports/audit-datas/cache/` (by default, a
        /// re-scan only redoes the files a change can affect).
        #[arg(long)]
        no_cache: bool,
        /// Exclusion pattern (repeatable, glob/directory/extension).
        #[arg(long = "exclude")]
        exclude: Vec<String>,
        /// Quick mode: skips the dependency check, for a faster run (in
        /// the private build, also the project tests and the database audit).
        #[arg(long)]
        quick: bool,
        /// Scans only a single rule category (e.g. "security").
        #[arg(long)]
        only_category: Option<String>,
        // In the shared build since 2026-11-18 (ticket #196); a private
        // option before. The `///` text below is the `--help` line.
        /// Also writes a CycloneDX SBOM of the project's declared
        /// dependencies (`<PREFIX>-SBOM-<timestamp>.json` in
        /// `audit-reports/audit-datas/`). A dependency declared with a
        /// range has no version in it.
        #[arg(long)]
        sbom: bool,
        // Ticket: compare two versions of a project (2026-11-20). The `///`
        // text below is the `--help` line.
        /// Earlier scan to compare with, as its JSON export
        /// (`audit-reports/audit-datas/<PREFIX>-DATA-<timestamp>.json`),
        /// for instance the scan of the previous version of the project.
        /// Default: the latest scan of the history folder.
        #[arg(long)]
        baseline: Option<PathBuf>,
        // Shared since ADR-0057 (2026-11-23, ticket #274); private before
        // (ADR-0041). The `///` text below is the `--help` line.
        /// Folder of your own rules (`.sca` files), loaded IN ADDITION to
        /// the delivered rules and filtered on the same languages. Default:
        /// `~/.codefixture-audit/custom-rules`, which no build or update
        /// touches. Ignored with `--rules`.
        #[arg(long)]
        custom_rules_dir: Option<PathBuf>,
        // Ticket #281. The `///` text below is the `--help` line.
        /// Runs the analysis even when it is expected to take more memory
        /// than the machine has available (by default it stops before
        /// reading the files, so that the system does not swap and
        /// freeze).
        #[arg(long)]
        skip_memory_check: bool,
        /// The most memory the analysis may take, in GB (`8`, `7.5`) or as
        /// a share of the installed memory (`50%`): it first runs fewer
        /// data flow rules at a time, then stops before reading the files
        /// when it is still expected to take more (it also stops when the
        /// machine has less available). Default: the environment variable
        /// CODEFIXTURE_AUDIT_MAX_MEMORY, else 75% of the installed memory;
        /// `100%` lifts the default.
        // Ticket #281: a text, parsed by `scan::resources`, so that an
        // invalid value gets the translated error that names it.
        #[arg(long, value_name = "GB|N%")]
        max_memory: Option<String>,
        // Ticket #281. The `///` text below is the `--help` line.
        /// The most threads the analysis runs, as a count (`4`) or a share
        /// of the cores (`50%`); fewer threads also run fewer data flow
        /// rules at a time. Default: the environment variable
        /// CODEFIXTURE_AUDIT_CPU, else every core but one.
        #[arg(long, value_name = "N|N%")]
        cpu: Option<String>,
        // Ticket #282. The `///` text below is the `--help` line. `=` is
        // required for the file (`--debug-log=scan.log`): with an optional
        // value, `--debug-log <project>` would take the project for the
        // file.
        /// Writes a debug log of every step of the analysis (each folder,
        /// file and rule, with times and memory), line by line, so that it
        /// still tells where the analysis stood after a crash or a frozen
        /// machine. Alone: `audit-reports/audit-datas/logs/scan-<date>.log.gz`,
        /// a gzip file of several members, one per second (read it with
        /// `gzip -dc`, from Git Bash on Windows, or 7-Zip);
        /// `--debug-log=FILE` writes to FILE, compressed when its name ends
        /// in `.gz`, plain text otherwise.
        #[arg(
            long,
            value_name = "FILE",
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = ""
        )]
        debug_log: Option<String>,
    },
    /// Lists the builtin rules by category (mirrors `--list-rules`).
    ListRules {
        /// Display language (`en`/`fr`/`es`/`de`).
        #[arg(long, default_value = "en")]
        lang: String,
        /// Rules: a rule pack — default: `rules.cfpack` next to the
        /// executable (same as `scan --rules`). Every language is listed.
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Your own rules (ADR-0057), kept in `~/.codefixture-audit/custom-rules`
    /// and added to every scan.
    CustomRules {
        #[command(subcommand)]
        action: CustomRulesAction,
    },
    // `rules` (pack tools) is a private tool: the shared binary scans and
    // lists its rules with `list-rules` (the maintainer, 2026-11-14).
}

/// Subcommands of `codefixture-audit custom-rules` (ADR-0057).
#[derive(Subcommand)]
enum CustomRulesAction {
    /// Creates or edits one of your rules, question by question: a text to
    /// search, or data followed from where it enters to a dangerous call.
    /// The rule is checked before it is written, and compared with the
    /// delivered rules.
    Create {
        /// Language of the questions (`en`/`fr`/`es`/`de`).
        #[arg(long, default_value = "en")]
        lang: String,
        /// Folder of your rules — default: `~/.codefixture-audit/custom-rules`.
        #[arg(long)]
        custom_rules_dir: Option<PathBuf>,
        /// Delivered rules your rule is compared with — default:
        /// `rules.cfpack` next to the executable (same as `scan --rules`).
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Runs the test cases of your rules (`cases/registry.json` of your
    /// rules folder): each vulnerable case must raise its rule, each clean
    /// case must not. Exit code 0 if all pass, 1 if one fails, 2 if the
    /// registry is missing or invalid.
    Test {
        /// Rules to test, as `<language>/<rule>` (repeatable) — default:
        /// every case of the registry.
        rules: Vec<String>,
        /// Folder of your rules — default: `~/.codefixture-audit/custom-rules`.
        #[arg(long)]
        custom_rules_dir: Option<PathBuf>,
        /// Machine-readable result on stdout.
        #[arg(long)]
        json: bool,
        /// Prints the failed cases only.
        #[arg(long)]
        quiet: bool,
        /// Message language (`en`/`fr`/`es`/`de`).
        #[arg(long, default_value = "en")]
        lang: String,
    },
    /// Runs one of your rules on a project and prints every line it flags,
    /// to tune it: no report; a line a delivered rule also flags is named
    /// with that rule, whose finding the report keeps.
    Try {
        /// The rule, as `<language>/<rule>`, or its name alone when only one
        /// language has it.
        rule: String,
        /// The project to run it on (its `audit.config.json` paths apply).
        project: PathBuf,
        /// Folder of your rules — default: `~/.codefixture-audit/custom-rules`.
        #[arg(long)]
        custom_rules_dir: Option<PathBuf>,
        /// Delivered rules run beside it, to name the lines where your rule
        /// duplicates one of them — default: `rules.cfpack` next to the
        /// executable (same as `scan --rules`).
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Message language (`en`/`fr`/`es`/`de`).
        #[arg(long, default_value = "en")]
        lang: String,
    },
}

impl Command {
    /// Console language of the subcommand, for messages emitted outside
    /// it (the panic hook).
    fn lang(&self) -> &str {
        match self {
            Command::Scan { lang, .. }
            | Command::ListRules { lang, .. }
            | Command::CustomRules {
                action:
                    CustomRulesAction::Create { lang, .. }
                    | CustomRulesAction::Test { lang, .. }
                    | CustomRulesAction::Try { lang, .. },
            } => lang,
        }
    }
}

/// Installs the hook first, then runs the subcommand under
/// `catch_unwind` so any panic — on the main thread or resumed from a
/// rayon worker — ends with exit code 4 ("internal error", ADR-0015)
/// instead of Rust's default 101 (ticket #91).
fn main() -> ExitCode {
    let cli = Cli::parse();
    install_panic_hook(cli.command.lang());
    let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dispatch(cli.command)))
        .unwrap_or(ExitCode::from(4));
    // Ticket #282: the debug log ends here, after a panic too; nothing
    // when it is off.
    codefixture_audit::debug_log!("end", "command_end exit={code:?}");
    codefixture_audit::scan::debug_log::finish();
    code
}

/// Replaces Rust's default panic output (raw message + `RUST_BACKTRACE`
/// hint) with one translated line carrying an incident id and the path
/// of a local crash log (ticket #91). The log gets the full details —
/// version, thread, panic message and location, a backtrace captured
/// regardless of `RUST_BACKTRACE` — so a client can attach it to a
/// support request after the fact. Several threads can panic during one
/// scan (rayon workers): each one is appended to the same log, but the
/// console line is printed once. Written to the system temp directory,
/// not next to the report as the ticket suggested: the hook cannot know
/// which subcommand or output path was running, and the temp directory
/// is always writable. Local only, never sent anywhere (ticket #93).
fn install_panic_hook(lang: &str) {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    static REPORTED: AtomicBool = AtomicBool::new(false);

    let locale = codefixture_audit::i18n::load_script_locale(lang);
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let incident = format!("{started:x}-{:x}", std::process::id());
    let log_path = std::env::temp_dir().join(format!("codefixture-audit-crash-{incident}.log"));
    std::panic::set_hook(Box::new(move |info| {
        // Ticket #282: the panic in the debug log first, on the disk
        // before anything else can fail.
        codefixture_audit::scan::debug_log::record_panic(info);
        let thread = std::thread::current();
        let entry = format!(
            "codefixture-audit {}\nincident: {incident}\nthread: {}\n{info}\n\nbacktrace:\n{}\n\n",
            codefixture_audit::BUILD_VERSION,
            thread.name().unwrap_or("<unnamed>"),
            std::backtrace::Backtrace::force_capture()
        );
        let written = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .and_then(|mut f| f.write_all(entry.as_bytes()))
            .is_ok();
        if written {
            codefixture_audit::debug_log!("panic", "crash_log path={:?}", log_path);
            codefixture_audit::scan::debug_log::sync();
        }
        if REPORTED.swap(true, Ordering::SeqCst) {
            return;
        }
        let message = if written {
            codefixture_audit::i18n::t(&locale, "internal_panic")
                .replace("{log}", &log_path.display().to_string())
        } else {
            codefixture_audit::i18n::t(&locale, "internal_panic_no_log")
        };
        emit_error(&format!(
            "[codefixture-audit] {}",
            message.replace("{incident}", &incident)
        ));
    }));
}

/// Runs the parsed subcommand.
fn dispatch(command: Command) -> ExitCode {
    // Debug builds only: lets the CLI tests exercise the panic hook on
    // the real binary. Compiled out of release builds.
    #[cfg(debug_assertions)]
    if std::env::var_os("CODEFIXTURE_AUDIT_DEBUG_PANIC").is_some() {
        panic!("CODEFIXTURE_AUDIT_DEBUG_PANIC set");
    }
    match command {
        Command::Scan {
            path,
            rules,
            format,
            lang,
            no_cache,
            exclude,
            quick,
            only_category,
            sbom,
            baseline,
            custom_rules_dir,
            skip_memory_check,
            max_memory,
            cpu,
            debug_log,
        } => {
            // Ticket #281: the limits are resolved and the thread pool
            // sized here, in the binary's entry point, before anything
            // uses the pool (the debug log header reads its size). The
            // console format must be known for an error.
            let resources = match start_scan_resources(cpu.as_deref(), max_memory.as_deref(), &lang)
            {
                Ok(resources) => resources,
                Err(code) => return code,
            };
            run_scan_command(ScanArgs {
                path,
                rules,
                format,
                lang,
                no_cache,
                exclude,
                quick,
                only_category,
                sbom,
                baseline,
                custom_rules_dir,
                skip_memory_check,
                resources,
                debug_log,
            })
        }
        Command::ListRules { lang, rules } => run_list_rules_command(&lang, rules),
        Command::CustomRules {
            action:
                CustomRulesAction::Create {
                    lang,
                    custom_rules_dir,
                    rules,
                },
        } => run_custom_rules_create_command(&lang, custom_rules_dir, rules),
        Command::CustomRules {
            action:
                CustomRulesAction::Test {
                    rules,
                    custom_rules_dir,
                    json,
                    quiet,
                    lang,
                },
        } => run_custom_rules_test_command(&lang, &rules, custom_rules_dir, json, quiet),
        Command::CustomRules {
            action:
                CustomRulesAction::Try {
                    rule,
                    project,
                    custom_rules_dir,
                    rules,
                    lang,
                },
        } => run_custom_rules_try_command(&lang, &rule, &project, custom_rules_dir, rules),
    }
}

/// Resolves the threads and memory a scan may take (ticket #281,
/// `scan::resources`): `--cpu` and `--max-memory`, else the environment
/// variables `CODEFIXTURE_AUDIT_CPU` and `CODEFIXTURE_AUDIT_MAX_MEMORY`,
/// else the defaults (every core but one, 75 % of the installed memory),
/// then sizes rayon's global pool, the one every phase of the scan runs on
/// (discovery, phases A, B and C; the taint rules run at once are half of
/// it). A value that cannot be applied stops the command (exit 2) with an
/// error, in the console language, that names the option or variable and
/// the value.
///
/// Called once per process, before anything uses the pool: rayon sizes its
/// global pool on first use, and cannot resize it after.
/// `RAYON_NUM_THREADS`, which rayon reads only for a pool it sizes itself,
/// no longer has any effect; a warning says so when it is set.
fn start_scan_resources(
    cpu: Option<&str>,
    max_memory: Option<&str>,
    lang: &str,
) -> Result<codefixture_audit::scan::resources::ScanResources, ExitCode> {
    use codefixture_audit::scan::resources::{LimitErrorKind, Setting, resolve};
    let script_locale = codefixture_audit::i18n::load_script_locale(lang);
    let say = |key: &str| codefixture_audit::i18n::t(&script_locale, key);
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    let total = codefixture_audit::scan::memory::system_memory().map(|m| m.total);
    let resources = match resolve(cpu, max_memory, |name| std::env::var_os(name), cores, total) {
        Ok(resources) => resources,
        Err(error) => {
            let key = match (error.setting, &error.kind) {
                (_, LimitErrorKind::PercentOfUnknownMemory) => "scan_limit_percent_unknown_memory",
                (Setting::Cpu, LimitErrorKind::Invalid) => "scan_limit_invalid_cpu",
                (Setting::MaxMemory, LimitErrorKind::Invalid) => "scan_limit_invalid_max_memory",
            };
            emit_error(&format!(
                "[codefixture-audit] {}",
                say(key)
                    .replace("{name}", error.source_name())
                    .replace("{value}", &error.input.value)
            ));
            return Err(ExitCode::from(2));
        }
    };
    if std::env::var_os("RAYON_NUM_THREADS").is_some() {
        emit_warning(&format!(
            "[codefixture-audit] {}",
            say("scan_rayon_variable_ignored")
        ));
    }
    if let Err(error) = rayon::ThreadPoolBuilder::new()
        .num_threads(resources.threads.threads)
        .build_global()
    {
        emit_error(&format!(
            "[codefixture-audit] {}",
            say("scan_threads_pool_error")
                .replace("{threads}", &resources.threads.threads.to_string())
                .replace("{error}", &error.to_string())
        ));
        return Err(ExitCode::from(4));
    }
    Ok(resources)
}

/// Where a limit comes from, as the console says it: `set with --cpu 4`,
/// `set with the environment variable CODEFIXTURE_AUDIT_CPU=4`, or the
/// default and what it is (ticket #281).
fn limit_origin_text(
    setting: codefixture_audit::scan::resources::Setting,
    origin: codefixture_audit::scan::resources::LimitOrigin,
    input: Option<&codefixture_audit::scan::resources::LimitInput>,
    percent: Option<u32>,
    script_locale: &serde_json::Value,
) -> String {
    use codefixture_audit::scan::resources::{LimitOrigin, Setting};
    let say = |key: &str| codefixture_audit::i18n::t(script_locale, key);
    let given = |key: &str| {
        let input = input.expect("a limit set by the user has its value");
        say(key)
            .replace("{name}", &input.display(setting))
            .replace("{value}", &input.value)
    };
    match (origin, setting) {
        (LimitOrigin::Option, _) => given("scan_limit_origin_option"),
        (LimitOrigin::Environment, _) => given("scan_limit_origin_environment"),
        (LimitOrigin::Default, Setting::Cpu) => say("scan_limit_origin_default_cpu"),
        (LimitOrigin::Default, Setting::MaxMemory) => say("scan_limit_origin_default_memory")
            .replace("{percent}", &percent.unwrap_or_default().to_string()),
    }
}

/// The console lines about a scan's memory and threads (ticket #281): the
/// estimate, the threads used and where their limit comes from, and what
/// bounds the memory (the machine's available memory, the limit and where
/// it comes from), or, for a scan stopped before reading its files, which
/// bound it passed, what it would have read, and what to do. Sizes in GB
/// with the console language's decimal separator.
fn memory_lines(
    memory: &codefixture_audit::scan::memory::MemoryEstimate,
    resources: &codefixture_audit::scan::resources::ScanResources,
    stopped: bool,
    script_locale: &serde_json::Value,
) -> Vec<String> {
    use codefixture_audit::scan::resources::Setting;
    let say = |key: &str| codefixture_audit::i18n::t(script_locale, key);
    let separator = say("decimal_separator");
    let decimal = |value: f64, digits: usize| format!("{value:.digits$}").replace('.', &separator);
    let gb = |bytes: u64| decimal(bytes as f64 / 1_073_741_824.0, 1);
    let estimate = gb(memory.bytes);
    let machine = memory.system.map(|system| {
        say("scan_memory_machine")
            .replace("{available}", &gb(system.available))
            .replace("{total}", &gb(system.total))
    });
    let memory_origin = limit_origin_text(
        Setting::MaxMemory,
        resources.memory.origin,
        resources.memory.input.as_ref(),
        resources.memory.percent,
        script_locale,
    );
    let limit = memory.limit.map(|limit| {
        say("scan_memory_limit")
            .replace("{limit}", &gb(limit))
            .replace("{origin}", &memory_origin)
    });
    let threads = &resources.threads;
    let mut threads_lines = vec![
        say("scan_threads")
            .replace("{threads}", &threads.threads.to_string())
            .replace("{cores}", &threads.cores.to_string())
            .replace(
                "{origin}",
                &limit_origin_text(
                    Setting::Cpu,
                    threads.origin,
                    threads.input.as_ref(),
                    None,
                    script_locale,
                ),
            ),
    ];
    if threads.capped_at_cores {
        threads_lines.push(
            say("scan_threads_capped")
                .replace("{cores}", &threads.cores.to_string())
                .replace(
                    "{name}",
                    &threads
                        .input
                        .as_ref()
                        .map(|input| input.display(Setting::Cpu))
                        .unwrap_or_default(),
                ),
        );
    }
    // The limit stops the scan when it is the smaller bound.
    let by_limit = memory
        .limit
        .is_some_and(|limit| memory.system.is_none_or(|system| limit < system.available));
    let mut lines = Vec::new();
    if stopped {
        lines.push(if by_limit {
            say("scan_memory_stop_limit")
                .replace("{estimate}", &estimate)
                .replace("{limit}", &gb(memory.limit.unwrap_or_default()))
                .replace("{origin}", &memory_origin)
        } else {
            say("scan_memory_stop").replace("{estimate}", &estimate)
        });
        lines.extend(machine);
        let sources: Vec<String> = memory
            .sources
            .iter()
            .map(|source| {
                let key = if source.followed {
                    "scan_memory_source_followed"
                } else {
                    "scan_memory_source"
                };
                say(key)
                    .replace("{language}", &source.language)
                    .replace("{size}", &decimal(source.bytes as f64 / 1_048_576.0, 0))
            })
            .collect();
        lines.push(say("scan_memory_sources").replace("{sources}", &sources.join(", ")));
        lines.push(say("scan_memory_stop_hint"));
        if by_limit {
            lines.push(say("scan_memory_stop_limit_hint"));
        }
        return lines;
    }
    lines.push(say("scan_memory_estimate").replace("{estimate}", &estimate));
    match machine {
        Some(machine) => lines.push(machine),
        None if limit.is_none() => lines.push(say("scan_memory_unknown")),
        None => {}
    }
    lines.extend(limit);
    // The threads before the rules at a time, which are half of them.
    lines.extend(threads_lines);
    if memory.rules_at_once < memory.max_rules_at_once {
        lines.push(
            say("scan_memory_fewer_rules")
                .replace("{rules}", &memory.rules_at_once.to_string())
                .replace("{max}", &memory.max_rules_at_once.to_string()),
        );
    }
    lines
}

/// `codefixture-audit custom-rules create` (ADR-0057, ticket #275): the
/// shared rule wizard writing into the client's rules folder
/// (`rules::custom::create`). It needs a terminal, as `create-rule`: without
/// one it refuses at once (exit 2) rather than reading answers from a
/// pipe; input closed mid-way stops it (exit 2) with nothing written. A
/// rule declined or that does not compile is exit 1, nothing written.
fn run_custom_rules_create_command(
    lang: &str,
    custom_rules_dir: Option<PathBuf>,
    rules: Option<PathBuf>,
) -> ExitCode {
    use std::io::IsTerminal;

    let script_locale = codefixture_audit::i18n::load_script_locale(lang);
    let say = |key: &str| codefixture_audit::i18n::t(&script_locale, key);
    if !std::io::stdin().is_terminal() {
        emit_error(&say("wizard_needs_terminal"));
        return ExitCode::from(2);
    }
    let Some(rules_dir) =
        codefixture_audit::rules::custom::resolve_custom_rules_dir(false, custom_rules_dir)
    else {
        emit_error(&say("custom_rules_no_home"));
        return ExitCode::from(2);
    };
    let pack = match resolve_rules_path(rules, &script_locale) {
        Ok(path) => path,
        Err(code) => return code,
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    match codefixture_audit::rules::custom::create::run_client_wizard(
        &mut stdin.lock(),
        &mut stdout.lock(),
        &script_locale,
        &rules_dir,
        &pack,
    ) {
        Ok(Some(_)) => ExitCode::SUCCESS,
        // Declined, or the rule did not compile: the wizard has said why;
        // nothing was written.
        Ok(None) => ExitCode::from(1),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            emit_error(&say("wizard_input_closed"));
            ExitCode::from(2)
        }
        Err(e) => {
            emit_error(&format!("[codefixture-audit] {e}"));
            ExitCode::from(4)
        }
    }
}

/// One line per (client rule, delivered rule) pair of
/// `ScanReport::custom_rule_duplicates` (epic #278), in the console
/// language: the client rule flags lines the delivered rule flags, and the
/// delivered findings are the ones kept. Shared by `scan` and
/// `custom-rules try`.
fn custom_duplicate_lines(
    duplicates: &[codefixture_audit::scan::orchestrator::CustomRuleDuplicate],
    script_locale: &serde_json::Value,
) -> Vec<String> {
    codefixture_audit::scan::orchestrator::custom_duplicate_pairs(duplicates)
        .into_iter()
        .map(|(custom, shipped, lines)| {
            codefixture_audit::i18n::t(script_locale, "scan_custom_rule_duplicates")
                .replace("{rule}", &custom.to_string())
                .replace("{shipped}", &shipped.to_string())
                .replace("{lines}", &lines.to_string())
        })
        .collect()
}

/// Prints the outcome of test cases, for `rules test` (the catalog's
/// cases, private) and `custom-rules test` (the client's, ticket #276):
/// one line per failed case with its reason in the console language,
/// then the counts (not with `quiet` when every case passed); with
/// `json`, one JSON object instead (`format`, `cases`, `passed`,
/// `failed`, `rules`), with `extra` merged in. Returns the number of
/// failed cases.
fn print_case_outcomes(
    outcomes: &[codefixture_audit::rules::cases::CaseOutcome],
    json: bool,
    quiet: bool,
    script_locale: &serde_json::Value,
    extra: serde_json::Map<String, serde_json::Value>,
) -> usize {
    use codefixture_audit::rules::cases::{Expect, Failure};
    let say = |key: &str| codefixture_audit::i18n::t(script_locale, key);
    let failed = outcomes.iter().filter(|o| !o.passed).count();
    let rules: std::collections::BTreeSet<_> =
        outcomes.iter().map(|o| (&o.language, &o.rule)).collect();
    let mut out = std::io::stdout().lock();
    if json {
        let mut value = serde_json::json!({
            "format": 1,
            "cases": outcomes,
            "passed": outcomes.len() - failed,
            "failed": failed,
            "rules": rules.len(),
        });
        if let Some(object) = value.as_object_mut() {
            object.extend(extra);
        }
        let _ = writeln!(out, "{value}");
        return failed;
    }
    for outcome in outcomes.iter().filter(|o| !o.passed) {
        let lines = format!("{:?}", outcome.found_lines);
        let reason = match &outcome.failure {
            Some(Failure::NoFinding) => say("rules_test_no_finding"),
            Some(Failure::WrongLines { expected }) => say("rules_test_wrong_lines")
                .replace("{expected}", &format!("{expected:?}"))
                .replace("{lines}", &lines),
            Some(Failure::UnexpectedFinding) => {
                say("rules_test_unexpected_finding").replace("{lines}", &lines)
            }
            Some(Failure::CouldNotRun { error }) => say("rules_test_could_not_run").replace(
                "{error}",
                &outcome
                    .error
                    .as_ref()
                    .map_or_else(|| error.clone(), |e| e.render(script_locale)),
            ),
            None => String::new(),
        };
        let expect = match outcome.expect {
            Expect::Detected => "detected",
            Expect::Clean => "clean",
        };
        let _ = writeln!(
            out,
            "{}",
            say("rules_test_failed_case")
                .replace("{key}", &outcome.key)
                .replace("{rule}", &format!("{}/{}", outcome.language, outcome.rule))
                .replace("{expect}", expect)
                .replace("{reason}", &reason)
                .replace("{file}", &outcome.file)
        );
    }
    if !quiet || failed > 0 {
        let _ = writeln!(
            out,
            "{}",
            say("rules_test_summary")
                .replace("{cases}", &outcomes.len().to_string())
                .replace("{rules}", &rules.len().to_string())
                .replace("{passed}", &(outcomes.len() - failed).to_string())
                .replace("{failed}", &failed.to_string())
        );
    }
    failed
}

/// Reads a test case registry and checks it against the rules folder
/// `rules_dir`, then turns the `<language>/<rule>` filters into the set
/// `run_cases` takes: shared by `rules test` and `custom-rules test`. A
/// registry that cannot be read, a problem in it, or a filter naming no
/// case stops before any case runs (exit 2), every problem named in the
/// console language: a case that cannot run must never count as passed.
fn load_checked_registry(
    registry_path: &Path,
    rules_dir: &Path,
    filters: &[String],
    script_locale: &serde_json::Value,
) -> Result<
    (
        codefixture_audit::rules::cases::Registry,
        std::collections::BTreeSet<(String, String)>,
    ),
    ExitCode,
> {
    use codefixture_audit::rules::cases;
    let say = |key: &str| codefixture_audit::i18n::t(script_locale, key);
    let registry = cases::read_registry(registry_path).map_err(|error| {
        emit_error(
            &say("rules_test_registry_error").replace("{error}", &error.render(script_locale)),
        );
        ExitCode::from(2)
    })?;
    let problems = cases::registry_problems(&registry, rules_dir);
    if !problems.is_empty() {
        for problem in &problems {
            emit_error(
                &say("rules_test_registry_problem")
                    .replace("{problem}", &problem.render(script_locale)),
            );
        }
        return Err(ExitCode::from(2));
    }
    let mut only = std::collections::BTreeSet::new();
    for filter in filters {
        let Some((language, rule)) = filter.split_once('/') else {
            emit_error(&say("rules_test_bad_filter").replace("{value}", filter));
            return Err(ExitCode::from(2));
        };
        let pair = (language.to_string(), rule.to_string());
        if !registry
            .cases
            .iter()
            .any(|(_, c)| c.language == pair.0 && c.rule == pair.1)
        {
            emit_error(&say("rules_test_no_case").replace("{value}", filter));
            return Err(ExitCode::from(2));
        }
        only.insert(pair);
    }
    Ok((registry, only))
}

/// `codefixture-audit custom-rules test` (ADR-0057, ticket #276): runs the
/// client's test cases (`<rules folder>/cases/registry.json`, the catalog's
/// format) through the engine, with the exit code of `rules test`: 0 when
/// every case passes, 1 when one fails, 2 when the registry is missing or
/// invalid. Every rule may be tested, or the `<language>/<rule>` given.
/// A rule of the folder without a case it must flag, or one it must not,
/// is named afterwards (Audit's `--custom-rules-match` listed them the
/// same way); it does not change the exit code, since such a rule has no
/// case that fails.
fn run_custom_rules_test_command(
    lang: &str,
    filters: &[String],
    custom_rules_dir: Option<PathBuf>,
    json: bool,
    quiet: bool,
) -> ExitCode {
    use codefixture_audit::rules::cases;
    use codefixture_audit::rules::custom::skeleton::registry_path;
    let script_locale = codefixture_audit::i18n::load_script_locale(lang);
    let say = |key: &str| codefixture_audit::i18n::t(&script_locale, key);
    let Some(rules_dir) =
        codefixture_audit::rules::custom::resolve_custom_rules_dir(false, custom_rules_dir)
    else {
        emit_error(&say("custom_rules_no_home"));
        return ExitCode::from(2);
    };
    let registry_file = registry_path(&rules_dir);
    if !registry_file.is_file() {
        emit_error(
            &say("custom_rules_test_no_registry")
                .replace("{path}", &registry_file.display().to_string()),
        );
        return ExitCode::from(2);
    }
    let (registry, only) =
        match load_checked_registry(&registry_file, &rules_dir, filters, &script_locale) {
            Ok(loaded) => loaded,
            Err(code) => return code,
        };
    let outcomes = cases::run_cases(&registry, &rules_dir, &only);
    // The rules lacking a case, among those tested.
    let missing: Vec<(String, (bool, bool))> = cases::rules_without_cases(&registry, &rules_dir)
        .into_iter()
        .filter(|(rule, _)| only.is_empty() || only.contains(rule))
        .map(|((language, rule), have)| (format!("{language}/{rule}"), have))
        .collect();
    let mut extra = serde_json::Map::new();
    extra.insert(
        "rules_without_cases".to_string(),
        serde_json::Value::Array(
            missing
                .iter()
                .map(|(rule, (detected, clean))| {
                    serde_json::json!({"rule": rule, "detected": detected, "clean": clean})
                })
                .collect(),
        ),
    );
    let failed = print_case_outcomes(&outcomes, json, quiet, &script_locale, extra);
    if !json {
        for (rule, (detected, clean)) in &missing {
            let key = match (detected, clean) {
                (false, false) => "custom_rules_test_missing_both",
                (false, true) => "custom_rules_test_missing_detected",
                _ => "custom_rules_test_missing_clean",
            };
            emit_warning(
                &say(key)
                    .replace("{rule}", rule)
                    .replace("{registry}", &registry_file.display().to_string()),
            );
        }
    }
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// `codefixture-audit custom-rules try <rule> <project>` (ADR-0057,
/// ticket #276): runs one client rule on a project and prints every line
/// it flags, to tune it (`rules::custom::try_rule`). The delivered rules
/// of its language run beside it (epic #278): a line a delivered rule also
/// flags is printed with that rule's name, since the report keeps the
/// delivered finding there, then each such pair is counted as `scan` does.
/// No report, no history. The project's `audit.config.json` paths and the
/// machine limits of a scan apply. Exit 0 whether the rule finds something
/// or not, 2 when the rule, the pack or the project cannot be used.
fn run_custom_rules_try_command(
    lang: &str,
    spec: &str,
    project: &Path,
    custom_rules_dir: Option<PathBuf>,
    rules: Option<PathBuf>,
) -> ExitCode {
    use codefixture_audit::rules::custom::try_rule::{RuleLookupError, find_client_rule, try_rule};
    let script_locale = codefixture_audit::i18n::load_script_locale(lang);
    let say = |key: &str| codefixture_audit::i18n::t(&script_locale, key);
    let Some(rules_dir) =
        codefixture_audit::rules::custom::resolve_custom_rules_dir(false, custom_rules_dir)
    else {
        emit_error(&say("custom_rules_no_home"));
        return ExitCode::from(2);
    };
    if !project.is_dir() {
        emit_error(&say("scan_invalid_path").replace("{path}", &project.display().to_string()));
        return ExitCode::from(2);
    }
    let rule = match find_client_rule(&rules_dir, spec) {
        Ok(rule) => rule,
        Err(RuleLookupError::NotFound { available }) => {
            emit_error(
                &say("custom_rules_try_not_found")
                    .replace("{value}", spec)
                    .replace("{dir}", &rules_dir.display().to_string()),
            );
            emit_error(&if available.is_empty() {
                say("custom_rules_try_none_available")
            } else {
                say("custom_rules_try_available").replace("{list}", &available.join(", "))
            });
            return ExitCode::from(2);
        }
        Err(RuleLookupError::Ambiguous { languages }) => {
            emit_error(
                &say("custom_rules_try_ambiguous")
                    .replace("{name}", spec)
                    .replace("{languages}", &languages.join(", ")),
            );
            return ExitCode::from(2);
        }
    };
    let pack = match resolve_rules_path(rules, &script_locale) {
        Ok(path) => path,
        Err(code) => return code,
    };
    let resources = match start_scan_resources(None, None, lang) {
        Ok(resources) => resources,
        Err(code) => return code,
    };
    let (include_paths, exclude_patterns, _) = resolve_project_paths(project, &script_locale);
    let started = std::time::Instant::now();
    let base = ScanConfig {
        root: project.to_path_buf(),
        include_paths,
        exclude_patterns,
        memory_check: true,
        memory_limit: resources.memory.bytes,
        lang: lang.to_string(),
        script_locale: Some(script_locale.clone()),
        ..ScanConfig::default()
    };
    let report = match try_rule(&rule, Some(&pack), base) {
        Ok(report) => report,
        Err(error) => {
            emit_error(
                &say("scan_internal_error")
                    .replace("{error}", &format!("{}: {error}", rule.file.display())),
            );
            return ExitCode::from(4);
        }
    };
    if report.stopped_for_memory {
        if let Some(memory) = &report.memory {
            for line in memory_lines(memory, &resources, true, &script_locale) {
                emit_error(&line);
            }
        }
        return ExitCode::from(2);
    }
    // The rule's own error; one of a delivered rule is the scan's concern.
    let rule_file_name = format!("{}.sca", rule.name);
    if let Some((_, error)) = report
        .rule_errors
        .iter()
        .find(|(path, _)| path.ends_with(&rule_file_name))
    {
        emit_error(
            &say("custom_rules_try_rule_error").replace("{error}", &error.render(&script_locale)),
        );
        return ExitCode::from(2);
    }
    let id = codefixture_audit::rules::identity::RuleId::new(&rule.language, &rule.name);
    // The findings go to standard output, as `rules test` prints its
    // cases: they are the command's result, the errors go to stderr.
    let println_result = |line: &str| println!("{line}");
    let rule_name = format!("{}/{}", rule.language, rule.name);
    println_result(
        &say("custom_rules_try_header")
            .replace("{rule}", &rule_name)
            .replace("{file}", &rule.file.display().to_string())
            .replace("{project}", &project.display().to_string()),
    );
    // The rule's own findings, and the lines it shares with a delivered
    // rule, shown with the delivered finding the report keeps there.
    let duplicates: Vec<&codefixture_audit::scan::orchestrator::CustomRuleDuplicate> = report
        .custom_rule_duplicates
        .iter()
        .filter(|d| d.custom_rule == id)
        .collect();
    let mut findings: Vec<(&ReportFinding, Option<String>)> = report
        .findings
        .iter()
        .filter(|f| f.rule_source == "json_custom" && f.rule_id() == id)
        .map(|f| (f, None))
        .collect();
    for duplicate in &duplicates {
        if let Some(kept) = report.findings.iter().find(|f| {
            f.file == duplicate.file
                && f.line == duplicate.line
                && f.rule_id() == duplicate.shipped_rule
        }) {
            findings.push((kept, Some(duplicate.shipped_rule.to_string())));
        }
    }
    findings.sort_by(|a, b| (&a.0.file, a.0.line).cmp(&(&b.0.file, b.0.line)));
    for (finding, shipped) in &findings {
        let code: String = finding.code.trim().chars().take(120).collect();
        println_result(&format!("  {}:{} — {code}", finding.file, finding.line));
        if let Some(shipped) = shipped {
            println_result(&format!(
                "      {}",
                say("custom_rules_try_duplicate").replace("{shipped}", shipped)
            ));
            continue;
        }
        for flow in finding.taint_flow.iter() {
            println_result(&format!(
                "      {}",
                say("custom_rules_try_source")
                    .replace("{source}", flow.source_expr.trim())
                    .replace("{file}", &flow.source_file)
                    .replace("{line}", &flow.source_line.to_string())
            ));
        }
    }
    let files: std::collections::BTreeSet<&str> =
        findings.iter().map(|(f, _)| f.file.as_str()).collect();
    let elapsed = format_duration(started.elapsed());
    println_result(&if findings.is_empty() {
        say("custom_rules_try_no_finding")
            .replace("{read}", &report.files_scanned.to_string())
            .replace("{elapsed}", &elapsed)
    } else {
        say("custom_rules_try_summary")
            .replace("{count}", &findings.len().to_string())
            .replace("{files}", &files.len().to_string())
            .replace("{read}", &report.files_scanned.to_string())
            .replace("{elapsed}", &elapsed)
    });
    let owned: Vec<_> = duplicates.into_iter().cloned().collect();
    for line in custom_duplicate_lines(&owned, &script_locale) {
        println_result(&line);
    }
    ExitCode::SUCCESS
}

/// Display order, icon and default activation of the listed categories
/// — verbatim from `Audit/sca/cli.py::list_rules` (`categories`), with
/// the folder → display key mapping (`dir_to_display`: `arch` →
/// `architecture`, every other folder maps to itself).
const LIST_RULES_CATEGORIES: [(&str, &str, bool); 8] = [
    ("security", "🛡️", true),
    ("architecture", "🏗️", true),
    ("ui", "🎨", true),
    ("ux", "🧑‍💻", true),
    ("maintenance", "🔧", true),
    ("dependencies", "📦", false),
    ("database", "🗄️", false),
    ("cicd", "⚙️", false),
];

/// Display name of a rule in `list-rules`: the rule's own `name` block in
/// `lang` (fallback `en`), otherwise its `risk` text truncated to 60
/// characters, otherwise the id — the fallback chain of `list_rules` on
/// the Python side, except that the name now comes from the rule file
/// (the report locale's name-keyed copy was removed on 2026-11-14).
fn rule_display_name(rule: &codefixture_audit::rules::catalog::RuleListing, lang: &str) -> String {
    if let Some(name) = rule
        .name
        .get(lang)
        .or_else(|| rule.name.get("en"))
        .and_then(|n| n.as_str())
        .filter(|n| !n.is_empty())
    {
        return name.to_string();
    }
    let risk = rule
        .risk
        .get(lang)
        .or_else(|| rule.risk.get("en"))
        .and_then(|v| v.as_str())
        .or_else(|| rule.risk.as_str());
    match risk {
        Some(text) if text.chars().count() > 60 => {
            format!("{}…", text.chars().take(60).collect::<String>())
        }
        Some(text) => text.to_string(),
        None => rule.id.clone(),
    }
}

/// `codefixture-audit list-rules` — port of `Audit/sca/cli.py::list_rules`
/// on the whole catalog, every language: header with the total, then one block per
/// category (translated title, rule count, `[disabled by default]` for
/// the opt-in ones) listing `id` and display name. The "project
/// fixtures" footer of the Python version is not ported: it reads the
/// per-project registry `Audit/projects/<slug>/`, classified out of
/// scope (issue #23).
fn run_list_rules_command(lang: &str, rules: Option<PathBuf>) -> ExitCode {
    use codefixture_audit::rules::catalog;
    let script_locale = codefixture_audit::i18n::load_script_locale(lang);
    let report_locale = codefixture_audit::i18n::load_report_locale(lang);
    let rules_path = match resolve_rules_path(rules, &script_locale) {
        Ok(path) => path,
        Err(code) => return code,
    };
    let sources = match read_rules_or_exit(&rules_path, &script_locale) {
        Ok(files) => files,
        Err(code) => return code,
    };
    let listing = catalog::rule_listing(&sources);
    let rules_label = codefixture_audit::i18n::t(&script_locale, "rules_count");
    // `writeln!` with ignored errors rather than `println!`: the latter
    // panics on a closed pipe (`list-rules | head`).
    // The count is on the very first line, with no blank line before it
    // (deviation from Python's leading newline): the install guide reads
    // it with `list-rules | head -1` (`Select-Object -First 1`).
    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "📋 {} ({} {rules_label}):\n",
        codefixture_audit::i18n::t(&script_locale, "available_rules"),
        listing.len()
    );
    for (display_key, icon, enabled_by_default) in LIST_RULES_CATEGORIES {
        let rules: Vec<_> = listing
            .iter()
            .filter(|r| {
                let display = if r.category_dir == "arch" {
                    "architecture"
                } else {
                    r.category_dir.as_str()
                };
                display == display_key
            })
            .collect();
        let title = report_locale
            .get("category_titles")
            .and_then(|t| t.get(display_key))
            .and_then(|t| t.as_str())
            .map(String::from)
            .unwrap_or_else(|| {
                let mut c = display_key.chars();
                c.next()
                    .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                    .unwrap_or_default()
            });
        let suffix = if enabled_by_default {
            String::new()
        } else {
            format!(
                "  [{}]",
                codefixture_audit::i18n::t(&script_locale, "disabled_by_default")
            )
        };
        let _ = writeln!(
            out,
            "{icon}  {title} ({} {rules_label}){suffix}",
            rules.len()
        );
        for rule in rules {
            let _ = writeln!(out, "   {:<40} {}", rule.id, rule_display_name(rule, lang));
        }
        let _ = writeln!(out);
    }
    ExitCode::from(0)
}

/// Writes the CycloneDX SBOM of the project's statically parsed
/// dependencies to `<data dir>/<PREFIX>-SBOM-<timestamp>.json` — same
/// location and name pattern as Python (`comparison.py::_export_sbom`,
/// `{datas_dir}/{brand_prefix}-SBOM-{timestamp}.json`), same manifests as
/// the `--with-deps` phase (`dependencies::collect_dependencies`).
/// Returns the written path, or a description of the I/O/serialization
/// failure.
fn write_sbom(
    config: &ScanConfig,
    project_name: &str,
    brand: &Brand,
    now: &chrono::DateTime<chrono::Local>,
) -> Result<PathBuf, String> {
    let dir = config
        .datas_dir
        .clone()
        .unwrap_or_else(|| config.root.join(DATAS_DIR));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let deps = codefixture_audit::project::dependencies::collect_dependencies(
        &config.root,
        &config.include_paths,
        &config.exclude_patterns,
    );
    let sbom = codefixture_audit::report::exports::sbom::build_dependency_sbom(
        &deps,
        project_name,
        "",
        &effective_tool_name(brand),
        codefixture_audit::BUILD_VERSION,
        &now.to_rfc3339(),
    );
    let json = sbom
        .to_json_string()
        .map_err(|e| format!("SBOM serialization: {e}"))?;
    let path = dir.join(format!(
        "{}-SBOM-{}.json",
        config.brand_prefix, config.timestamp
    ));
    std::fs::write(&path, json).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// The first lines of a debug log (ticket #282): the build, the command
/// as typed, the system, its threads and memory, the thread and memory
/// limits applied and where each comes from (ticket #281), the project and its
/// `audit.config.json`, and the settings of the analysis threads. The
/// scan's own settings follow in `run_scan` (`scan_config` line).
fn log_scan_header(project: &Path, resources: &codefixture_audit::scan::resources::ScanResources) {
    use codefixture_audit::debug_log;
    use codefixture_audit::scan::debug_log::mebibytes;
    use codefixture_audit::scan::resources::{CPU_VARIABLE, MAX_MEMORY_VARIABLE};
    debug_log!(
        "header",
        "build version={:?} os={} arch={} family={}",
        codefixture_audit::BUILD_VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::env::consts::FAMILY
    );
    debug_log!(
        "header",
        "command args={:?} cwd={:?} pid={}",
        std::env::args().collect::<Vec<_>>(),
        std::env::current_dir().ok(),
        std::process::id()
    );
    let system = codefixture_audit::scan::memory::system_memory();
    debug_log!(
        "header",
        "machine cores={} rayon_threads={} RAYON_NUM_THREADS={:?} mem_total={} mem_available={}",
        std::thread::available_parallelism().map_or(0, |n| n.get()),
        rayon::current_num_threads(),
        std::env::var("RAYON_NUM_THREADS").ok(),
        mebibytes(system.map(|s| s.total)),
        mebibytes(system.map(|s| s.available))
    );
    // Ticket #281: the limits applied, where each comes from, and both
    // variables as the process sees them (one may be set and overridden
    // by its option).
    debug_log!(
        "header",
        "limits threads={} cores={} threads_origin={:?} threads_input={:?} threads_capped_at_cores={} \
         max_memory={} max_memory_origin={:?} max_memory_input={:?} max_memory_percent={:?} \
         {CPU_VARIABLE}={:?} {MAX_MEMORY_VARIABLE}={:?}",
        resources.threads.threads,
        resources.threads.cores,
        resources.threads.origin,
        resources.threads.input.as_ref().map(|i| &i.value),
        resources.threads.capped_at_cores,
        mebibytes(resources.memory.bytes),
        resources.memory.origin,
        resources.memory.input.as_ref().map(|i| &i.value),
        resources.memory.percent,
        std::env::var_os(CPU_VARIABLE),
        std::env::var_os(MAX_MEMORY_VARIABLE)
    );
    let config_path = project.join("audit.config.json");
    match std::fs::read_to_string(&config_path) {
        Ok(text) => debug_log!(
            "header",
            "project path={:?} audit_config={:?} content={:?}",
            project,
            config_path,
            text
        ),
        Err(error) => debug_log!(
            "header",
            "project path={:?} audit_config={:?} unreadable={:?}",
            project,
            config_path,
            error.to_string()
        ),
    }
}

/// Arguments of the `scan` subcommand, grouped so as not to blow up
/// the number of parameters of `run_scan_command`.
struct ScanArgs {
    path: PathBuf,
    rules: Option<PathBuf>,
    format: String,
    lang: String,
    no_cache: bool,
    exclude: Vec<String>,
    quick: bool,
    only_category: Option<String>,
    sbom: bool,
    baseline: Option<PathBuf>,
    custom_rules_dir: Option<PathBuf>,
    skip_memory_check: bool,
    /// The threads and memory the scan may take (`--cpu`, `--max-memory`,
    /// their environment variables or the defaults), resolved by
    /// [`start_scan_resources`], which also sized the thread pool.
    resources: codefixture_audit::scan::resources::ScanResources,
    /// `--debug-log`: `Some("")` for the default file, `None` when off.
    debug_log: Option<String>,
}

fn run_scan_command(args: ScanArgs) -> ExitCode {
    let ScanArgs {
        path,
        rules,
        format,
        lang,
        no_cache,
        exclude,
        quick,
        only_category,
        sbom,
        baseline,
        custom_rules_dir,
        skip_memory_check,
        resources,
        debug_log,
    } = args;
    // The shared binary has none of these options: their defaults.
    let extra = ScanExtraArgs::default();
    let ScanExtraArgs {
        log_format,
        output,
        suppress_file,
        quiet,
        with_tests,
        test_command,
        with_deps,
        db_host,
        db_port,
        db_name,
        db_user,
        db_password_env_file,
        db_password_env_var,
        data_dir,
        disable_rule,
        severity,
        brand_file,
        metrics_output,
    } = extra;
    let t_command_start = std::time::Instant::now();
    JSON_LOGS.store(log_format == "json", std::sync::atomic::Ordering::Relaxed);
    // Loaded right from the start, before the first possible error —
    // same mechanism as `run_create_rule_command` (ticket #47): before
    // this ticket, `scan`'s CLI messages (errors, progress) stayed in
    // French regardless of `--lang`, only the HTML report was
    // translated.
    let script_locale = codefixture_audit::i18n::load_script_locale(&lang);
    if !path.is_dir() {
        emit_error(
            &codefixture_audit::i18n::t(&script_locale, "scan_invalid_path")
                .replace("{path}", &path.display().to_string()),
        );
        return ExitCode::from(2);
    }
    // 2026-11-12 (request from the maintainer): in a terminal, a folder without
    // `audit.config.json` is not scanned. The engine asks what to scan,
    // writes the file and asks to run the command again
    // (`project::config_wizard`). Never with `--quiet` or JSON logs
    // (ticket #92: no question in a machine-readable stream), nor without
    // a terminal (a script would wait forever): the whole folder is
    // scanned then, as before. Before the history folder is created, so
    // that nothing else is written into the project.
    if matches!(
        codefixture_audit::project::project_config::load_config_json(&path),
        Ok(None)
    ) && !quiet
        && log_format != "json"
        && std::io::stdin().is_terminal()
    {
        use codefixture_audit::project::config_wizard::{ConfigWizardOutcome, run_config_wizard};
        let say = |key: &str| codefixture_audit::i18n::t(&script_locale, key);
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        let mut writer = std::io::stderr();
        return match run_config_wizard(&mut reader, &mut writer, &path, &say) {
            // The settings are written but nothing was analysed: say so
            // plainly and give the exact command to run again (the maintainer,
            // 2026-11-14: a tester expects a report after the first run).
            Ok(ConfigWizardOutcome::Written(_)) => {
                eprintln!();
                eprintln!("    {}", rerun_command(std::env::args()));
                eprintln!();
                ExitCode::SUCCESS
            }
            Ok(ConfigWizardOutcome::Declined) => ExitCode::from(1),
            Ok(ConfigWizardOutcome::InputClosed) => {
                eprintln!();
                emit_error(&format!(
                    "[codefixture-audit] {}",
                    say("config_prompt_input_closed")
                ));
                ExitCode::from(2)
            }
            Err(error) => {
                emit_error(&format!(
                    "[codefixture-audit] {}",
                    say("config_prompt_write_error").replace("{error}", &error.to_string())
                ));
                ExitCode::from(4)
            }
        };
    }
    // Ticket #282: the debug log starts right after the configuration
    // wizard (which writes nothing else into the project), before the
    // rules are read, so that it holds every step of the scan. A log asked
    // for that cannot be written stops the scan: the user asked for it to
    // find where a scan stops.
    if let Some(requested) = &debug_log {
        let log_path = if requested.is_empty() {
            codefixture_audit::scan::debug_log::default_path(
                &data_dir.clone().unwrap_or_else(|| path.join(DATAS_DIR)),
            )
        } else {
            PathBuf::from(requested)
        };
        if let Err(error) = codefixture_audit::scan::debug_log::start(&log_path) {
            emit_error(&format!(
                "[codefixture-audit] {}",
                codefixture_audit::i18n::t(&script_locale, "scan_debug_log_error")
                    .replace("{path}", &log_path.display().to_string())
                    .replace("{error}", &error.to_string())
            ));
            return ExitCode::from(2);
        }
        log_scan_header(&path, &resources);
        emit_result(&format!(
            "[codefixture-audit] {}",
            codefixture_audit::i18n::t(&script_locale, "scan_debug_log")
                .replace("{path}", &log_path.display().to_string())
        ));
    }

    // ADR-0040: `--rules <PATH>`, else `rules.cfpack` next to the
    // executable. A missing pack or a folder without any `.sca` file would
    // scan with no rule at all, so it stops here with the path searched.
    // `--rules` given: the custom rules folder is left out (ticket #84).
    let explicit_rules = rules.is_some();
    let rules_path = match resolve_rules_path(rules, &script_locale) {
        Ok(path) => path,
        Err(code) => return code,
    };
    if format != "text" && format != "sarif" && format != "html" {
        emit_error(
            &codefixture_audit::i18n::t(&script_locale, "scan_unknown_format")
                .replace("{format}", &format),
        );
        return ExitCode::from(2);
    }
    // `--baseline`: read before the scan, so that a missing or unreadable
    // file stops here with its path and the reason. It never falls back on
    // the latest scan, which would compare with another version than the
    // one asked for.
    if let Some(file) = &baseline
        && let Err(error) = codefixture_audit::report::export_json::load_export(file)
    {
        emit_error(
            &codefixture_audit::i18n::t(&script_locale, "scan_baseline_unreadable")
                .replace("{path}", &file.display().to_string())
                .replace("{error}", &error),
        );
        return ExitCode::from(2);
    }

    let project_name = codefixture_audit::project::project_config::project_name_of(&path);

    let database = if db_host.is_some() || db_name.is_some() || db_user.is_some() {
        Some(codefixture_audit::project::database::live::DbConfig {
            host: db_host,
            port: db_port,
            database: db_name,
            user: db_user,
            password_env_file: db_password_env_file,
            password_env_var: db_password_env_var,
        })
    } else {
        None
    };

    const VALID_SEVERITIES: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    let severity_levels = match severity {
        None => None,
        Some(raw) => {
            let levels: Vec<String> = raw
                .split(',')
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty())
                .collect();
            let invalid: Vec<&String> = levels
                .iter()
                .filter(|s| !VALID_SEVERITIES.contains(&s.as_str()))
                .collect();
            if !invalid.is_empty() {
                // The order of the two `.replace()` calls is safe here:
                // `invalid` has already been uppercased (`.to_uppercase()`
                // above), so a user who literally typed "{valid}" as a
                // severity level would produce "{VALID}", never
                // recognized by the second `.replace()`. This safety
                // relies on case, not structure — don't copy this
                // chaining as-is onto non-normalized user data.
                emit_error(
                    &codefixture_audit::i18n::t(&script_locale, "scan_invalid_severities")
                        .replace(
                            "{invalid}",
                            &invalid
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                        )
                        .replace("{valid}", &VALID_SEVERITIES.join("/")),
                );
                return ExitCode::from(2);
            }
            Some(levels)
        }
    };

    // Single scan timestamp (mirror of `self.timestamp` on the Audit
    // side, computed only once — shared by the HTML report and the
    // JSON export so they carry exactly the same name). The
    // `%Y-%m-%d-%H-%M` format was verified empirically against a real
    // Python run (`SCA-REPORT-2026-08-26-09-16.html`), not assumed.
    let now = chrono::Local::now();
    let timestamp = now.format("%Y-%m-%d-%H-%M").to_string();

    // By default (no --data-dir), the JSON export is written to
    // `audit-reports/audit-datas` (`DATAS_DIR`, ticket #133 — Audit uses
    // `docs/audit-reports/audit-datas`). With the default only, the
    // pre-#133 location stays readable for the baseline lookup.
    let legacy_datas_dir = data_dir.is_none().then(|| path.join(LEGACY_DATAS_DIR));
    let data_dir = data_dir.or_else(|| Some(path.join(DATAS_DIR)));
    if let Some(dir) = &data_dir
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        emit_error(
            &codefixture_audit::i18n::t(&script_locale, "scan_internal_error")
                .replace("{error}", &format!("{}: {e}", dir.display())),
        );
        return ExitCode::from(4);
    }

    // Ticket #149 — the exact build first, even with `--quiet`: one line,
    // and the first thing a bug report needs.
    emit_result(&format!(
        "[codefixture-audit] codefixture-audit {}",
        codefixture_audit::BUILD_VERSION
    ));

    let (include_paths, base_excludes, paths_origin) = resolve_project_paths(&path, &script_locale);
    let exclude_patterns: Vec<String> = base_excludes.into_iter().chain(exclude).collect();

    // Ticket #140 — the scope actually applied, once per scan.
    emit_progress(
        quiet,
        &format!(
            "[codefixture-audit] {}",
            scope_line(
                &path,
                paths_origin,
                &include_paths,
                &exclude_patterns,
                |key| codefixture_audit::i18n::t(&script_locale, key),
            )
        ),
    );

    // Ticket #140 — paths keys that are ignored, wholly or partly, so the
    // scope silently differs from what the file seems to say. One
    // grouped warning, never suppressed by `--quiet` (like #138 below).
    let malformed_paths = codefixture_audit::project::project_config::malformed_paths_keys(&path);
    if !malformed_paths.is_empty() {
        emit_warning(&format!(
            "[codefixture-audit] {}",
            codefixture_audit::i18n::t(&script_locale, "scan_paths_config_malformed")
                .replace("{keys}", &malformed_paths.join(", "))
        ));
    }

    // Ticket #138 — one grouped warning, never suppressed by `--quiet`
    // (same treatment as the unsupported sections below).
    let missing_includes = missing_include_paths(&path, &include_paths);
    if !missing_includes.is_empty() {
        emit_warning(&format!(
            "[codefixture-audit] {}",
            codefixture_audit::i18n::t(&script_locale, "scan_include_paths_missing")
                .replace("{paths}", &missing_includes.join(", "))
        ));
    }

    // ADR-0038 — the rule languages declared by the project, if any.
    let target_languages =
        declared_rule_languages(&path, |key| codefixture_audit::i18n::t(&script_locale, key));

    // Ticket #43/spec #27 — a single grouped warning (not one per
    // key), never suppressed by `--quiet`: it's actionable information
    // about the config, same treatment as the ignored rules below
    // (`report.rule_errors`), not a mere intermediate progress
    // message.
    let unsupported_sections =
        codefixture_audit::project::project_config::unsupported_config_sections(&path);
    if !unsupported_sections.is_empty() {
        emit_warning(&format!(
            "[codefixture-audit] {}",
            codefixture_audit::i18n::t(&script_locale, "scan_unsupported_config_sections")
                .replace("{keys}", &unsupported_sections.join(", "))
        ));
    }

    // Priority CLI > file > default (ticket #40/spec #27).
    // `--disable-rule` is repeatable, so there's no "explicitly empty"
    // value distinct from "not provided": a non-empty vector means
    // "provided on the CLI", exactly like the other multi-value flags
    // of this binary.
    let disabled_rules = if !disable_rule.is_empty() {
        disable_rule
    } else {
        codefixture_audit::project::project_config::read_disabled_rules_config(&path)
    };
    // Always read, even if `only_category` (CLI) is already provided:
    // the CLI > file priority (ticket #41/spec #27) is resolved in
    // `orchestrator.rs` (rule filtering), not here — unlike
    // `disabled_rules` above, `only_category` and `category_overrides`
    // remain two distinct `ScanConfig` fields, see the field doc in
    // `orchestrator.rs`.
    let category_overrides =
        codefixture_audit::project::project_config::read_category_overrides_config(&path);

    // The client's own rules, read by both builds since ADR-0057.
    let custom_rules_dir = codefixture_audit::rules::custom::resolve_custom_rules_dir(
        explicit_rules,
        custom_rules_dir,
    );

    // Default: next to the executable (ticket #87/spec #83).
    // `load_brand_file`
    // returns `None` on any anomaly (missing file, unreadable,
    // invalid JSON) — safe, silent fallback to `Brand::default()`
    // (all the "CodeFixture" defaults), never a blocking error.
    let brand_file = brand_file.or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("brand.json")))
    });
    let brand: Brand = brand_file
        .and_then(|p| load_brand_file(&p))
        .unwrap_or_default();

    // By default (no --output), the HTML report is written to
    // `audit-reports` (`REPORTS_DIR`) under the scanned directory — same
    // root as the JSON export above. Resolved before the scan so the
    // report path can be excluded from it (ticket #132). `text`/`sarif`
    // without --output stay on stdout (explicitly requested format,
    // Unix convention — accepted deviation vs Audit, which always writes its
    // HTML report regardless of the format additionally requested).
    let explicit_output = output.is_some();
    let output = output.or_else(|| {
        if format == "html" {
            let dir = path.join(REPORTS_DIR);
            if let Err(e) = std::fs::create_dir_all(&dir) {
                emit_error(
                    &codefixture_audit::i18n::t(&script_locale, "scan_internal_error")
                        .replace("{error}", &format!("{}: {e}", dir.display())),
                );
                return None;
            }
            // Brand prefix, like `runner.py:167`
            // (`{brand_prefix}-REPORT-{timestamp}.html`) — was hard-coded
            // to `SCA`, so a white-label delivery still produced
            // `SCA-REPORT-*` files (found by ticket #106).
            Some(dir.join(format!(
                "{}-REPORT-{timestamp}.html",
                effective_prefix(&brand)
            )))
        } else {
            None
        }
    });
    if format == "html" && output.is_none() {
        return ExitCode::from(4);
    }

    let exclude_patterns: Vec<String> = exclude_patterns
        .into_iter()
        .chain(output_excludes(
            &path,
            data_dir.as_deref(),
            output.as_deref(),
        ))
        .collect();

    // The suppressions saved with the report's 🚫 button are read from the
    // project's root by themselves (the maintainer, 2026-11-14), `--suppress-file`
    // naming another file in the private binary.
    let suppress_file = suppress_file.or_else(|| {
        let at_root = path.join(".sca-suppress.json");
        at_root.is_file().then_some(at_root)
    });

    // Taint cache next to the history (`scan_cache`), unless `--no-cache`.
    let cache_dir = data_dir
        .as_ref()
        .filter(|_| !no_cache)
        .map(|d| d.join("cache"));
    let config = ScanConfig {
        root: path,
        include_paths,
        rules_path,
        target_languages,
        suppress_file,
        cache_dir,
        exclude_patterns,
        with_tests,
        test_command,
        with_deps,
        database,
        datas_dir: data_dir,
        legacy_datas_dir,
        baseline_path: baseline.clone(),
        timestamp: timestamp.clone(),
        quick_mode: quick,
        only_category,
        category_overrides,
        disabled_rules,
        severity_levels,
        lang: lang.clone(),
        on_phase_complete: if quiet {
            None
        } else {
            Some(print_phase_progress)
        },
        custom_rules_dir,
        memory_check: !skip_memory_check,
        memory_limit: resources.memory.bytes,
        script_locale: Some(script_locale.clone()),
        brand_prefix: effective_prefix(&brand),
        // Every file is discovered, so undeclared languages are named.
        only_target_language_files: false,
        // The report findings are enough (`rules noise` sets it).
        keep_rule_findings: false,
    };

    // ADR-0050: before any rule is loaded, has anything the scan reads
    // changed since the last one? Never with `--no-cache`, nor when the
    // results can change without any file changing (`--with-tests`,
    // `--database`), nor when the run itself is measured
    // (`--metrics-output`) or an HTML report is expected at an explicit
    // path. `inputs` is also what the record of this scan will hold.
    // `--baseline` asks for a comparison the last report may not hold:
    // the scan runs in full.
    let shortcut_allowed = !no_cache
        && baseline.is_none()
        && !config.with_tests
        && config.database.is_none()
        && metrics_output.is_none()
        && !(format == "html" && explicit_output);
    let shortcut_step = codefixture_audit::scan::debug_log::span("unchanged", || {
        format!("unchanged_check allowed={shortcut_allowed}")
    });
    let inputs = shortcut_allowed.then(|| ScanInputs::read(&config));
    let last_unchanged = inputs
        .as_ref()
        .and_then(|inputs| LastScan::find_unchanged(&config, inputs, format == "html"));
    shortcut_step.end_with(|| format!("unchanged={}", last_unchanged.is_some()));
    if let Some(last) = last_unchanged {
        return report_unchanged_scan(UnchangedScan {
            last: &last,
            config: &config,
            format: &format,
            output: output.as_deref().filter(|_| format != "html"),
            brand: &brand,
            quiet,
            sbom: sbom.then_some((project_name.as_str(), &now)),
            script_locale: &script_locale,
            t_command_start,
        });
    }

    emit_progress(
        quiet,
        &format!(
            "[codefixture-audit] {}",
            codefixture_audit::i18n::t(&script_locale, "scan_analyzing")
        ),
    );
    let t_scan_start = std::time::Instant::now();
    let scan_step = codefixture_audit::scan::debug_log::span("scan", || "run_scan".to_string());
    // Debug builds only: lets the CLI tests check that a panic during the
    // scan reaches the debug log (ticket #282). Compiled out of release
    // builds, like `CODEFIXTURE_AUDIT_DEBUG_PANIC`.
    #[cfg(debug_assertions)]
    if std::env::var_os("CODEFIXTURE_AUDIT_DEBUG_PANIC_IN_SCAN").is_some() {
        panic!("CODEFIXTURE_AUDIT_DEBUG_PANIC_IN_SCAN set");
    }
    let report = run_scan(&config);
    scan_step.end_with(|| {
        format!(
            "files={} loc={} findings={} stopped_for_memory={}",
            report.files_scanned,
            report.total_loc,
            report.findings.len(),
            report.stopped_for_memory
        )
    });

    // Ticket #281: the memory the scan was expected to take, on every
    // scan; a scan that did not fit stopped before reading the files.
    if let Some(memory) = &report.memory {
        let lines = memory_lines(
            memory,
            &resources,
            report.stopped_for_memory,
            &script_locale,
        );
        if report.stopped_for_memory {
            for line in &lines {
                emit_error(line);
            }
            return ExitCode::from(2);
        }
        for line in &lines {
            emit_progress(quiet, &format!("[codefixture-audit] {line}"));
        }
    }

    for (rule_path, err) in &report.rule_errors {
        emit_warning(
            &codefixture_audit::i18n::t(&script_locale, "scan_rule_skipped")
                .replace("{path}", &rule_path.display().to_string())
                .replace("{error}", &err.render(&script_locale)),
        );
    }
    // Rules of one identity met twice (`RuleRegistry`): a client rule
    // replacing the catalog's is wanted, so it is information; a rule
    // defined twice in one source is a mistake, so it is a warning.
    for conflict in &report.rule_conflicts {
        use codefixture_audit::rules::catalog::RuleConflictKind;
        let key = match conflict.kind {
            RuleConflictKind::ClientReplacesCatalog => "scan_rule_replaced",
            RuleConflictKind::DuplicateInSource => "scan_rule_duplicate",
        };
        let message = codefixture_audit::i18n::t(&script_locale, key)
            .replace("{rule}", &conflict.id.to_string())
            .replace("{kept}", &conflict.kept)
            .replace("{dropped}", &conflict.dropped);
        match conflict.kind {
            RuleConflictKind::ClientReplacesCatalog => {
                emit_progress(quiet, &format!("[codefixture-audit] {message}"))
            }
            RuleConflictKind::DuplicateInSource => emit_warning(&message),
        }
    }
    // Epic #278: a client rule flagging lines a delivered rule flags; the
    // delivered findings are kept. A warning: the client's rule does less
    // than they think, and `--quiet` must not hide it.
    for line in custom_duplicate_lines(&report.custom_rule_duplicates, &script_locale) {
        emit_warning(&line);
    }
    // ADR-0040: where the rules came from and how many were kept, then the
    // languages found in the project but left out of `languages`, whose
    // files got no rule — a warning, never suppressed by `--quiet`.
    for line in rule_source_lines(&report, &script_locale) {
        emit_progress(quiet, &format!("[codefixture-audit] {line}"));
    }
    // Ticket #152: the folders skipped as holding no project code, named
    // once per scan (`--quiet` hides it, like the scope line).
    if let Some(line) = skipped_dirs_line(&config.root, &report.skipped_dirs, |key| {
        codefixture_audit::i18n::t(&script_locale, key)
    }) {
        emit_progress(quiet, &format!("[codefixture-audit] {line}"));
    }
    // ADR-0045 and ADR-0046: the files skipped as minified or as saved
    // web pages, named once per scan.
    for (key, files) in [
        ("scan_skipped_minified", &report.skipped_minified),
        ("scan_skipped_saved_pages", &report.skipped_saved_pages),
    ] {
        if let Some(line) = skipped_files_line(key, files, |key| {
            codefixture_audit::i18n::t(&script_locale, key)
        }) {
            emit_progress(quiet, &format!("[codefixture-audit] {line}"));
        }
    }
    // Tickets #209, #210: a lockfile that gave no version is named once, as a
    // warning, never hidden by `--quiet`: the versions checked for its
    // manifest are declared minimums, not the installed ones.
    for (file, reason) in &report.lockfiles_not_used {
        let line = match reason {
            Some(reason) => codefixture_audit::i18n::t(&script_locale, "scan_lockfile_unreadable")
                .replace("{reason}", reason)
                .replace("{file}", file),
            None => codefixture_audit::i18n::t(&script_locale, "scan_lockfile_binary")
                .replace("{file}", file),
        };
        emit_warning(&format!("[codefixture-audit] {line}"));
    }
    // Taint cache (`scan_cache`): what a re-scan redid, so that a slow one
    // shows why (many files changed) and a fast one that it reused work.
    for stat in &report.cache_stats {
        let line = cache_stat_line(stat, |key| codefixture_audit::i18n::t(&script_locale, key));
        emit_progress(quiet, &format!("[codefixture-audit] {line}"));
    }
    if !report.undeclared_languages.is_empty() {
        emit_warning(&format!(
            "[codefixture-audit] {}",
            codefixture_audit::i18n::t(&script_locale, "scan_languages_undeclared")
                .replace("{languages}", &report.undeclared_languages.join(", "))
        ));
    }
    // ADR-0042, ADR-0043: every scan whose dependencies phase ran names
    // the version rules it read, even with `--quiet`; without them it says
    // the dependencies were not checked, so that no vulnerable dependency
    // reads as "none".
    if let Some(status) = &report.version_rules {
        let (warning, line) = version_rules_line(status, &script_locale);
        if warning {
            emit_warning(&format!("[codefixture-audit] {line}"));
        } else {
            emit_result(&format!("[codefixture-audit] {line}"));
        }
    }

    let mut sbom_written = None;
    if sbom {
        let _sbom_step =
            codefixture_audit::scan::debug_log::span("report", || "write_sbom".to_string());
        match write_sbom(&config, &project_name, &brand, &now) {
            Ok(sbom_path) => {
                emit_progress(
                    quiet,
                    &format!("[codefixture-audit] SBOM : {}", sbom_path.display()),
                );
                sbom_written = Some(sbom_path);
            }
            Err(e) => {
                emit_error(&format!(
                    "[codefixture-audit] {}",
                    codefixture_audit::i18n::t(&script_locale, "scan_internal_error")
                        .replace("{error}", &e)
                ));
                return ExitCode::from(4);
            }
        }
    }

    let render_step =
        codefixture_audit::scan::debug_log::span("report", || format!("render format={format}"));
    let output_text = match format.as_str() {
        "sarif" => match sarif_text(&report.findings, &brand, &script_locale) {
            Ok(text) => text,
            Err(code) => return code,
        },
        "html" => {
            let ctx = ReportContext {
                project_name,
                project_version: String::new(),
                project_uuid: String::new(),
                project_description: String::new(),
                project_path: config.root.display().to_string(),
                tool_name: effective_tool_name(&brand),
                tool_version: codefixture_audit::BUILD_VERSION.to_string(),
                company_name: effective_company_name(&brand),
                report_lang: lang,
                date_str: now.format("%d/%m/%Y à %H:%M").to_string(),
                timestamp,
                audit_total_time_secs: t_scan_start.elapsed().as_secs(),
                total_lines_code: report.total_loc,
                total_files_scanned: report.files_scanned,
                health_thresholds: HealthThresholds::default(),
                rule_catalog: &report.rule_catalog,
                history: &report.history,
                custom_rule_duplicates: &report.custom_rule_duplicates,
            };
            let audit_params_info = codefixture_audit::report::audit_params::AuditParamsInfo {
                languages: report.languages.clone(),
                include_paths: config.include_paths.clone(),
                exclude_patterns: config.exclude_patterns.clone(),
                quick_mode: config.quick_mode,
                only_category: config.only_category.clone(),
                disabled_rules: config.disabled_rules.clone(),
                with_tests: config.with_tests,
                with_deps: config.with_deps,
                // What the dependencies phase did, whatever started it
                // (`--with-deps` or a pack with version rules, ADR-0043):
                // a scope row, never an option name (ticket #188).
                dependencies: {
                    use codefixture_audit::report::audit_params::DependencyCheck;
                    use codefixture_audit::scan::orchestrator::VersionRulesStatus;
                    match &report.version_rules {
                        None => DependencyCheck::NotRun,
                        Some(VersionRulesStatus::Read { .. }) => DependencyCheck::Checked,
                        Some(
                            VersionRulesStatus::Missing | VersionRulesStatus::Unreadable { .. },
                        ) => DependencyCheck::VersionsNotChecked,
                    }
                },
                database_configured: config.database.is_some(),
                // ADR-0051: the databases of the version rules, credited.
                vulnerability_sources: match &report.version_rules {
                    Some(codefixture_audit::scan::orchestrator::VersionRulesStatus::Read {
                        sources,
                        ..
                    }) => sources.clone(),
                    _ => Vec::new(),
                },
                severity_levels: config.severity_levels.clone(),
                report_lang: ctx.report_lang.clone(),
            };
            let html = generate_html(
                &report.findings,
                &ctx,
                report.comparison.as_ref(),
                Some(&audit_params_info),
                report.test_results.as_ref(),
            );
            // Ticket #87/spec #83: brand color override,
            // injected after the main stylesheet (just
            // before `</head>`) — the CSS cascade does the rest, without
            // touching the embedded static `.css` file. No-op if
            // `brand.json` has no color (or doesn't exist).
            inject_brand_style(html, brand_style_block(&brand).as_deref())
        }
        _ => format_text_report(&report.findings),
    };
    render_step.end_with(|| format!("bytes={}", output_text.len()));

    let write_step = codefixture_audit::scan::debug_log::span("report", || {
        format!("write_output path={:?}", output.as_deref())
    });
    if let Err(code) = write_scan_output(output.as_deref(), &output_text, quiet, &script_locale) {
        return code;
    }
    drop(write_step);

    // ADR-0050: the record that lets the next scan skip everything when
    // nothing changes, written once this scan's export and report exist,
    // with the inputs read before the scan. A record that cannot be
    // written only costs the next scan its shortcut, never a wrong result.
    if let Some(inputs) = &inputs
        && let Some(export_path) = &report.export_path
    {
        let mut record = LastScan::new(
            inputs,
            report.governance_names.clone(),
            export_path.clone(),
            output.clone().filter(|_| format == "html"),
            report.files_scanned,
            report.total_loc,
        );
        record.sbom_path = sbom_written;
        let saved = record.save(&config);
        codefixture_audit::debug_log!(
            "report",
            "last_scan_record saved={}",
            match &saved {
                Ok(_) => "yes".to_string(),
                Err(error) => format!("no error={error:?}"),
            }
        );
    }

    let exit_code = finish_scan(
        &report.findings,
        report.files_scanned,
        report.total_loc,
        &config.root,
        &script_locale,
        t_command_start,
    );

    // Ticket #90: written last, so it records the real exit code. A
    // write failure is an internal error (4), like the report itself.
    if let Some(metrics_path) = &metrics_output {
        let metrics = codefixture_audit::report::exports::metrics::build_scan_metrics(
            &report,
            "codefixture-audit",
            codefixture_audit::BUILD_VERSION,
            &now.to_rfc3339(),
            t_command_start.elapsed().as_millis(),
            exit_code,
        );
        let written = serde_json::to_string_pretty(&metrics)
            .map_err(|e| e.to_string())
            .and_then(|s| std::fs::write(metrics_path, s).map_err(|e| e.to_string()));
        if let Err(e) = written {
            emit_error(
                &codefixture_audit::i18n::t(&script_locale, "scan_internal_error")
                    .replace("{error}", &format!("{}: {e}", metrics_path.display())),
            );
            return ExitCode::from(4);
        }
    }
    ExitCode::from(exit_code)
}

/// The SARIF document of `findings`, as written by `--format sarif`. An
/// error is reported to the user, and the exit code is returned.
fn sarif_text(
    findings: &[ReportFinding],
    brand: &Brand,
    script_locale: &serde_json::Value,
) -> Result<String, ExitCode> {
    let sarif = build_sarif_report(
        findings,
        "codefixture-audit",
        codefixture_audit::BUILD_VERSION,
        &effective_website_url(brand),
    );
    serde_json::to_string_pretty(&sarif).map_err(|e| {
        emit_error(
            &codefixture_audit::i18n::t(script_locale, "scan_internal_error")
                .replace("{error}", &format!("SARIF serialization: {e}")),
        );
        ExitCode::from(4)
    })
}

/// Writes a scan's output to `output` and names the file, or prints it on
/// stdout without `output`. A write error is reported, and the exit code
/// is returned.
fn write_scan_output(
    output: Option<&Path>,
    text: &str,
    quiet: bool,
    script_locale: &serde_json::Value,
) -> Result<(), ExitCode> {
    let Some(out_path) = output else {
        println!("{text}");
        return Ok(());
    };
    if let Err(e) = std::fs::write(out_path, text) {
        emit_error(
            &codefixture_audit::i18n::t(script_locale, "scan_internal_error")
                .replace("{error}", &format!("{}: {e}", out_path.display())),
        );
        return Err(ExitCode::from(4));
    }
    emit_progress(
        quiet,
        &format!(
            "[codefixture-audit] {} : {}",
            codefixture_audit::i18n::t(script_locale, "report_generated"),
            out_path.display()
        ),
    );
    Ok(())
}

/// The last two lines of every scan, full or skipped as unchanged
/// (ADR-0050): the summary and the total duration. Returns the exit code
/// that `findings` give against the project's threshold.
fn finish_scan(
    findings: &[ReportFinding],
    files_scanned: usize,
    total_loc: usize,
    root: &Path,
    script_locale: &serde_json::Value,
    t_command_start: std::time::Instant,
) -> u8 {
    // Never suppressed by `--quiet` (see ticket #44): it's the only
    // message guaranteed by a silent CI scan — without it, a run that
    // "succeeds" with no finding is indistinguishable from a run that scanned
    // nothing at all.
    emit_result(&format!(
        "[codefixture-audit] {}",
        codefixture_audit::i18n::t(script_locale, "scan_summary")
            .replace("{files}", &files_scanned.to_string())
            .replace("{loc}", &total_loc.to_string())
            .replace("{findings}", &findings.len().to_string())
    ));
    // Whole command, from argument parsing to the written report
    // (ticket #135) — the per-phase lines don't add up to it (rule
    // loading aside, discovery and report rendering are not phases).
    // Same never-suppressed treatment as the summary line above.
    let total_elapsed = t_command_start.elapsed();
    if JSON_LOGS.load(std::sync::atomic::Ordering::Relaxed) {
        emit_json_line(
            LogLevel::Info,
            &codefixture_audit::i18n::t(script_locale, "scan_total_duration")
                .replace("{duration}", &format_duration(total_elapsed)),
            Some(serde_json::json!(total_elapsed.as_millis())),
        );
    } else {
        emit_result(&format!(
            "[codefixture-audit] {}",
            codefixture_audit::i18n::t(script_locale, "scan_total_duration")
                .replace("{duration}", &format_duration(total_elapsed))
        ));
    }

    let high_count = findings
        .iter()
        .filter(|f| f.severity == "HIGH" || f.severity == "CRITICAL")
        .count();
    // Configurable threshold (ticket #42/spec #27) — `0` by default
    // (missing file or no `thresholds` section) reproduces
    // exactly the previous hardcoded behavior: failure as soon as
    // at least one HIGH/CRITICAL exists. Accepted deviations vs Python
    // documented in `read_max_high_threshold_config`.
    let max_high_threshold =
        codefixture_audit::project::project_config::read_max_high_threshold_config(root);
    u8::from(high_count as i64 > max_high_threshold)
}

/// What [`report_unchanged_scan`] needs from `run_scan_command`.
struct UnchangedScan<'a> {
    /// The record of the last scan, whose inputs are those of this one.
    last: &'a LastScan,
    config: &'a ScanConfig,
    format: &'a str,
    /// Where `sarif` and `text` go; `None` for stdout, and for `html`.
    output: Option<&'a Path>,
    brand: &'a Brand,
    quiet: bool,
    /// Project name and scan date when `--sbom` is set.
    sbom: Option<(&'a str, &'a chrono::DateTime<chrono::Local>)>,
    script_locale: &'a serde_json::Value,
    t_command_start: std::time::Instant,
}

/// Ends a scan whose inputs are those of the last one (ADR-0050): nothing
/// is analysed. `html` writes nothing and names the last report; `sarif`
/// and `text` are rebuilt from the findings of the last export; `--sbom`
/// names the SBOM already written for these inputs, if any. The
/// summary and the exit code are those of that export.
fn report_unchanged_scan(scan: UnchangedScan<'_>) -> ExitCode {
    let say = |key: &str| codefixture_audit::i18n::t(scan.script_locale, key);
    let export = match codefixture_audit::report::export_json::load_export(&scan.last.export_path) {
        Ok(export) => export,
        Err(error) => {
            emit_error(&say("scan_internal_error").replace(
                "{error}",
                &format!("{}: {error}", scan.last.export_path.display()),
            ));
            return ExitCode::from(4);
        }
    };
    // The export's `YYYY-MM-DD-HH-MM` stamp, as the reader writes a date.
    let date = chrono::NaiveDateTime::parse_from_str(&export.timestamp, "%Y-%m-%d-%H-%M")
        .map_or_else(
            |_| export.timestamp.clone(),
            |d| d.format("%d/%m/%Y %H:%M").to_string(),
        );
    emit_result(&format!(
        "[codefixture-audit] {}",
        say("scan_unchanged").replace("{date}", &date)
    ));
    // The SBOM follows the report: the one written for these inputs is
    // named, not written again; written only when none was yet, and then
    // kept in the record for the next runs.
    let recorded_sbom = scan.last.sbom_path.as_deref().filter(|p| p.is_file());
    if let (Some(_), Some(sbom_path)) = (scan.sbom, recorded_sbom) {
        emit_result(&format!(
            "[codefixture-audit] {}",
            say("scan_unchanged_sbom").replace("{path}", &sbom_path.display().to_string())
        ));
    } else if let Some((project_name, now)) = scan.sbom {
        match write_sbom(scan.config, project_name, scan.brand, now) {
            Ok(sbom_path) => {
                emit_progress(
                    scan.quiet,
                    &format!("[codefixture-audit] SBOM : {}", sbom_path.display()),
                );
                // A record that cannot be written only costs the next run
                // a new SBOM.
                let mut record = scan.last.clone();
                record.sbom_path = Some(sbom_path);
                let _ = record.save(scan.config);
            }
            Err(e) => {
                emit_error(&format!(
                    "[codefixture-audit] {}",
                    say("scan_internal_error").replace("{error}", &e)
                ));
                return ExitCode::from(4);
            }
        }
    }
    let text = match scan.format {
        "sarif" => match sarif_text(&export.findings, scan.brand, scan.script_locale) {
            Ok(text) => Some(text),
            Err(code) => return code,
        },
        "text" => Some(format_text_report(&export.findings)),
        _ => None,
    };
    match text {
        Some(text) => {
            if let Err(code) = write_scan_output(scan.output, &text, scan.quiet, scan.script_locale)
            {
                return code;
            }
        }
        // `find_unchanged` only matched for `html` when the report exists.
        None => {
            if let Some(report) = &scan.last.report_path {
                emit_result(&format!(
                    "[codefixture-audit] {}",
                    say("scan_unchanged_report").replace("{path}", &report.display().to_string())
                ));
            }
        }
    }
    ExitCode::from(finish_scan(
        &export.findings,
        scan.last.files_scanned,
        scan.last.total_loc,
        &scan.config.root,
        scan.script_locale,
        scan.t_command_start,
    ))
}

/// The `text` format: one `file:line: [severity] rule — message` line per
/// finding, `file: [severity] …` for a finding about the whole file, which
/// has no line to point an editor at (ticket #214).
fn format_text_report(findings: &[ReportFinding]) -> String {
    let mut out = String::new();
    for f in findings {
        let message = if f.risk.is_empty() {
            &f.rule_name
        } else {
            &f.risk
        };
        let location = if f.file_scope.is_some() {
            f.file.clone()
        } else {
            format!("{}:{}", f.file, f.line)
        };
        out.push_str(&format!(
            "{location}: [{}] {} — {}\n",
            f.severity, f.rule_key, message
        ));
    }
    out
}
