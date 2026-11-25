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
use codefixture_audit::report::locale_format::LocaleFormat;
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
    let numbers = console_format_of(&say);
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
            say("scan_scope_more").replace("{count}", &numbers.count(items.len() - SCOPE_LIST_MAX));
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
    let defaults = say("scan_scope_default_excludes")
        .replace("{count}", &numbers.count(DEFAULT_EXCLUDES.len()));
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

/// The number formats of the console whose texts `say` gives (its
/// `locale_code`), for the helpers that receive the console's texts as a
/// closure rather than its locale.
fn console_format_of(say: &impl Fn(&str) -> String) -> &'static LocaleFormat {
    LocaleFormat::for_language(&say("locale_code"))
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

/// The client's rules folder of a `custom-rules` command:
/// `--custom-rules-dir`, else `CODEFIXTURE_AUDIT_CUSTOM_RULES`, else the
/// default folder of the home (ticket #292: the commands follow the same
/// variable as `scan`, so that `create` never writes where `scan` does not
/// read). It need not exist: `create` makes it. An empty variable or no
/// home folder stops the command (exit 2) with a message that says what
/// to give.
fn custom_rules_tool_dir(
    option: Option<PathBuf>,
    script_locale: &serde_json::Value,
) -> Result<PathBuf, ExitCode> {
    use codefixture_audit::rules::custom::{
        CustomRulesLocationError, locate_custom_rules_dir_here,
    };
    match locate_custom_rules_dir_here(option) {
        Ok(dir) => Ok(dir.path),
        Err(error) => {
            let key = match error {
                CustomRulesLocationError::EmptyVariable => "custom_rules_empty_variable",
                CustomRulesLocationError::NoHome => "custom_rules_no_home",
            };
            emit_error(&codefixture_audit::i18n::t(script_locale, key));
            Err(ExitCode::from(2))
        }
    }
}

/// How the console names where the client's rules folder was given.
fn custom_rules_origin_text(
    origin: codefixture_audit::rules::custom::CustomRulesOrigin,
    script_locale: &serde_json::Value,
) -> String {
    use codefixture_audit::rules::custom::CustomRulesOrigin;
    let key = match origin {
        CustomRulesOrigin::Option => "custom_rules_origin_option",
        CustomRulesOrigin::Environment => "custom_rules_origin_environment",
        CustomRulesOrigin::Default => "custom_rules_origin_default",
    };
    codefixture_audit::i18n::t(script_locale, key)
}

/// The scan's choice for the client's rules, or the error that stops it
/// (exit 2, ticket #292): an empty `CODEFIXTURE_AUDIT_CUSTOM_RULES`, a
/// folder given with `--custom-rules-dir` or the variable that does not
/// exist, or a path that is not a folder. Before 2026-11-25 such a folder
/// was skipped without a word, and the scan ran without the client's rules.
fn scan_custom_rules_or_exit(
    explicit_rules: bool,
    option: Option<PathBuf>,
    script_locale: &serde_json::Value,
) -> Result<codefixture_audit::rules::custom::ScanCustomRules, ExitCode> {
    use codefixture_audit::rules::custom::{
        ScanCustomRulesError, locate_custom_rules_dir_here, scan_custom_rules,
    };
    let say = |key: &str| codefixture_audit::i18n::t(script_locale, key);
    let error = match scan_custom_rules(explicit_rules, locate_custom_rules_dir_here(option)) {
        Ok(choice) => return Ok(choice),
        Err(error) => error,
    };
    let message = match error {
        ScanCustomRulesError::EmptyVariable => say("custom_rules_empty_variable"),
        ScanCustomRulesError::Missing(dir) => say("scan_custom_rules_missing")
            .replace("{path}", &dir.path.display().to_string())
            .replace(
                "{origin}",
                &custom_rules_origin_text(dir.origin, script_locale),
            ),
        ScanCustomRulesError::NotAFolder(dir) => say("scan_custom_rules_not_a_folder")
            .replace("{path}", &dir.path.display().to_string())
            .replace(
                "{origin}",
                &custom_rules_origin_text(dir.origin, script_locale),
            ),
    };
    emit_error(&message);
    Err(ExitCode::from(2))
}

/// The counts of the client's rules that a scan read: rule files kept for
/// the project's languages, then rule files the folder holds.
type ClientRuleCounts = (usize, usize);

/// The client's rules source of a finished scan, as counts: `None` when
/// the scan read no client folder.
fn client_rule_counts(report: &ScanReport) -> Option<ClientRuleCounts> {
    report
        .rule_sources
        .iter()
        .find(|source| source.origin == codefixture_audit::rules::catalog::RuleOrigin::Client)
        .map(|source| (source.files_read, source.files_available))
}

/// The console line naming what the scan did with the client's rules
/// (ticket #292), shown even with `--quiet`: read (counts, folder, where
/// it was named), default folder absent, not read because of `--rules`,
/// or no folder known. `counts` are those of the folder read, `(0, 0)` when
/// it holds no rule file.
fn custom_rules_line(
    choice: &codefixture_audit::rules::custom::ScanCustomRules,
    counts: ClientRuleCounts,
    script_locale: &serde_json::Value,
) -> String {
    use codefixture_audit::rules::custom::ScanCustomRules;
    let say = |key: &str| codefixture_audit::i18n::t(script_locale, key);
    let numbers = LocaleFormat::of_console(script_locale);
    match choice {
        ScanCustomRules::Read(dir) => say("scan_custom_rules_read")
            .replace("{read}", &numbers.count(counts.0))
            .replace("{available}", &numbers.count(counts.1))
            .replace("{path}", &dir.path.display().to_string())
            .replace(
                "{origin}",
                &custom_rules_origin_text(dir.origin, script_locale),
            ),
        ScanCustomRules::DefaultMissing(path) => {
            say("scan_custom_rules_default_missing").replace("{path}", &path.display().to_string())
        }
        ScanCustomRules::NotRead => say("scan_custom_rules_not_read"),
        ScanCustomRules::NoHome => say("scan_custom_rules_no_home"),
    }
}

/// Prints [`custom_rules_line`] as a result, shown even with `--quiet`;
/// with `--log-format json`, the event also carries the `custom_rules`
/// block of the metrics file, for a machine (ticket #292).
fn emit_custom_rules_line(
    choice: &codefixture_audit::rules::custom::ScanCustomRules,
    counts: ClientRuleCounts,
    script_locale: &serde_json::Value,
) {
    log_line_with(
        LogLevel::Info,
        &format!(
            "[codefixture-audit] {}",
            custom_rules_line(choice, counts, script_locale)
        ),
        &[(
            "custom_rules",
            custom_rules_metrics(choice, counts).to_json(),
        )],
    );
}

/// The `custom_rules` block of `--metrics-output` (ticket #292).
fn custom_rules_metrics(
    choice: &codefixture_audit::rules::custom::ScanCustomRules,
    counts: ClientRuleCounts,
) -> codefixture_audit::report::exports::metrics::CustomRulesMetrics {
    use codefixture_audit::report::exports::metrics::CustomRulesMetrics;
    use codefixture_audit::rules::custom::{CustomRulesOrigin, ScanCustomRules};
    let origin = |origin: CustomRulesOrigin| match origin {
        CustomRulesOrigin::Option => "option",
        CustomRulesOrigin::Environment => "environment",
        CustomRulesOrigin::Default => "default",
    };
    let (status, path, origin, counts) = match choice {
        ScanCustomRules::Read(dir) => (
            "read",
            Some(dir.path.display().to_string()),
            Some(origin(dir.origin)),
            counts,
        ),
        ScanCustomRules::DefaultMissing(path) => (
            "default_missing",
            Some(path.display().to_string()),
            Some("default"),
            (0, 0),
        ),
        ScanCustomRules::NotRead => ("not_read", None, None, (0, 0)),
        ScanCustomRules::NoHome => ("no_home", None, None, (0, 0)),
    };
    CustomRulesMetrics {
        status,
        path,
        origin,
        files_read: counts.0,
        files_available: counts.1,
    }
}

/// Console lines saying what the rule sources gave a scan (ADR-0040,
/// feedback of 2026-11-10: a tester could not tell which rules were
/// loaded). Per source: rule files kept over files available and the
/// pack or folder path; last, the number of rules kept and the languages
/// they cover.
fn rule_source_lines(report: &ScanReport, script_locale: &serde_json::Value) -> Vec<String> {
    use codefixture_audit::rules::catalog::RuleSourceKind;
    let say = |key: &str| codefixture_audit::i18n::t(script_locale, key);
    let numbers = LocaleFormat::of_console(script_locale);
    // The client's folder has a line of its own, shown even with `--quiet`
    // (`custom_rules_line`, ticket #292).
    let mut lines: Vec<String> = report
        .rule_sources
        .iter()
        .filter(|source| source.origin != codefixture_audit::rules::catalog::RuleOrigin::Client)
        .map(|source| {
            let key = match source.kind {
                RuleSourceKind::Pack => "scan_rules_source_pack",
                RuleSourceKind::Folder => "scan_rules_source_folder",
            };
            say(key)
                .replace("{read}", &numbers.count(source.files_read))
                .replace("{available}", &numbers.count(source.files_available))
                .replace("{path}", &source.path.display().to_string())
        })
        .collect();
    lines.push(
        say("scan_rule_languages")
            .replace("{count}", &numbers.count(report.rules_loaded))
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
    let numbers = console_format_of(&t);
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
        .replace("{dirty}", &numbers.count(stat.dirty))
        .replace("{files}", &numbers.count(stat.files))
        .replace("{analysed}", &numbers.count(stat.analysed))
        .replace("{total}", &numbers.count(stat.total))
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
    let numbers = console_format_of(&say);
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
            say("scan_scope_more").replace("{count}", &numbers.count(items.len() - SCOPE_LIST_MAX));
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
    let numbers = console_format_of(&say);
    let list = if files.len() <= SCOPE_LIST_MAX + 1 {
        files.join(", ")
    } else {
        let more =
            say("scan_scope_more").replace("{count}", &numbers.count(files.len() - SCOPE_LIST_MAX));
        format!("{}, {more}", files[..SCOPE_LIST_MAX].join(", "))
    };
    Some(
        say(key)
            .replace("{count}", &numbers.count(files.len()))
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
/// The text of `key` (`scan_version_rules_read`, `rules_list_version_rules`)
/// with its counts: the advisory records of the pack and, when the pack
/// says it, the distinct published vulnerabilities they describe and how
/// many have a CVE. Until 2026-11-24 the records were called published
/// vulnerabilities: the demo pack's 26 records describe 21 of them. A pack
/// whose version rules predate the count (`advisory_file::Header`) gets
/// the `<key>_records` text, which names the records only.
fn version_rules_counts(
    script_locale: &serde_json::Value,
    key: &str,
    records: usize,
    vulnerabilities: Option<(usize, usize)>,
) -> String {
    let say = |key: &str| codefixture_audit::i18n::t(script_locale, key);
    let numbers = LocaleFormat::of_console(script_locale);
    match vulnerabilities {
        Some((all, cves)) => say(key)
            .replace("{records}", &numbers.count(records))
            .replace("{vulnerabilities}", &numbers.count(all))
            .replace("{cves}", &numbers.count(cves)),
        None => say(&format!("{key}_records")).replace("{records}", &numbers.count(records)),
    }
}

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
            vulnerabilities,
            ..
        } => {
            let numbers = LocaleFormat::of_console(script_locale);
            let total: usize = counts.iter().map(|(_, n)| n).sum();
            let counts: Vec<String> = counts
                .iter()
                .map(|(name, n)| format!("{name} {}", numbers.count(*n)))
                .collect();
            (
                false,
                version_rules_counts(
                    script_locale,
                    "scan_version_rules_read",
                    total,
                    *vulnerabilities,
                )
                .replace("{path}", &pack.display().to_string())
                .replace("{date}", &numbers.instant_date(created))
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
            &[("duration_ms", serde_json::json!(elapsed.as_millis()))],
        );
    } else {
        eprintln!("{}", phase_progress_line(label, elapsed));
    }
}

/// Text-mode progress line of one phase, as printed by
/// `print_phase_progress` (kept separate so its format is testable
/// without capturing stderr).
fn phase_progress_line(label: &str, elapsed: std::time::Duration) -> String {
    let console = console_locale();
    format!(
        "[codefixture-audit]   {label}{}{}",
        console.colon,
        console.format.duration(elapsed)
    )
}

/// What the lines written by a plain `fn` callback that has no locale,
/// `print_phase_progress`, take from the console's language: the
/// separator between a label and its value (`label_colon` of the console
/// locale: `": "`, French `" : "`) and the number formats
/// (`report::locale_format`). Set by `run_scan_command` once the console
/// language is known. The phase lines used to write `label : 34 ms`, the
/// French way, in every language, then `1.2 s` with a dot in French
/// (2026-11-24).
struct ConsoleLocale {
    colon: String,
    format: &'static LocaleFormat,
}

/// The [`ConsoleLocale`] of this process; `None` until a scan sets it.
static CONSOLE_LOCALE: std::sync::RwLock<Option<ConsoleLocale>> = std::sync::RwLock::new(None);

/// Sets [`CONSOLE_LOCALE`] from the console locale `script_locale`.
fn set_console_locale(script_locale: &serde_json::Value) {
    if let Ok(mut current) = CONSOLE_LOCALE.write() {
        *current = Some(ConsoleLocale {
            colon: codefixture_audit::i18n::t(script_locale, "label_colon"),
            format: LocaleFormat::of_console(script_locale),
        });
    }
}

/// [`CONSOLE_LOCALE`], the English one until a scan sets it.
fn console_locale() -> ConsoleLocale {
    CONSOLE_LOCALE
        .read()
        .ok()
        .and_then(|current| {
            current.as_ref().map(|c| ConsoleLocale {
                colon: c.colon.clone(),
                format: c.format,
            })
        })
        .unwrap_or_else(|| ConsoleLocale {
            colon: ": ".to_string(),
            format: LocaleFormat::for_language("en"),
        })
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
/// `[codefixture-audit]` text prefix), plus the fields of `extra`:
/// `duration_ms` for a finished phase, `custom_rules` for the line of the
/// client's rules (ticket #292), so that a machine reads a value rather
/// than a sentence that follows `--lang`. Built with `serde_json`, so any
/// message text is escaped.
fn emit_json_line(level: LogLevel, message: &str, extra: &[(&str, serde_json::Value)]) {
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
    for (key, value) in extra {
        event[*key] = value.clone();
    }
    eprintln!("{event}");
}

/// Single choke point of every console line (ticket #44's rationale,
/// kept for ticket #92): plain text by default, a JSON event with
/// `--log-format json`.
fn log_line(level: LogLevel, msg: &str) {
    log_line_with(level, msg, &[]);
}

/// [`log_line`] with fields that a JSON log event carries beside its
/// message (`emit_json_line`); plain text shows the message alone.
fn log_line_with(level: LogLevel, msg: &str, extra: &[(&str, serde_json::Value)]) {
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
        emit_json_line(level, msg, extra);
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

    /// Held by every test that sets [`CONSOLE_LOCALE`], directly or through
    /// `run_scan_command`: the console language is one value for the whole
    /// test process, and tests run in parallel. Without it, a scan run by
    /// `test_run_scan_command_scans_file_include_only` set it back to
    /// English in the middle of the French checks of
    /// `test_phase_progress_line_and_print`, which then failed now and then
    /// (seen on 2026-11-25).
    static CONSOLE_LOCALE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Takes [`CONSOLE_LOCALE_LOCK`], even after a test that held it
    /// panicked: the lock only orders the tests, it guards no data that a
    /// panic could leave half-written.
    fn lock_console_locale() -> std::sync::MutexGuard<'static, ()> {
        CONSOLE_LOCALE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

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

    // The durations of the console are tested with their formatter,
    // `LocaleFormat::duration` (`report::locale_format`), in each language.

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
        let read = |vulnerabilities| VersionRulesStatus::Read {
            pack: PathBuf::from("/x/rules.cfpack"),
            created: "2026-11-11T00:00:00Z".into(),
            counts: vec![("PyPI".into(), 12), ("npm".into(), 30)],
            vulnerabilities,
            sources: vec![],
        };
        let (warning, line) = version_rules_line(&read(Some((40, 38))), &en);
        assert!(!warning);
        assert!(
            line.contains("/x/rules.cfpack")
                && line.contains("November 11, 2026")
                && line.contains("PyPI 12, npm 30"),
            "{line}"
        );
        // 2026-11-24: the 42 records are not 42 vulnerabilities; the line
        // says both numbers, in every language.
        assert!(
            line.contains("42 advisory records for 40 published vulnerabilities (38 with a CVE)"),
            "{line}"
        );
        for (lang, words) in [
            (
                "fr",
                "42 fiches d'avis pour 40 vulnérabilités publiées (dont 38 avec un CVE)",
            ),
            (
                "es",
                "42 fichas de aviso para 40 vulnerabilidades publicadas (38 con un CVE)",
            ),
            (
                "de",
                "42 Sicherheitshinweise zu 40 veröffentlichten Schwachstellen (38 mit CVE)",
            ),
        ] {
            let locale = codefixture_audit::i18n::load_script_locale(lang);
            let (_, line) = version_rules_line(&read(Some((40, 38))), &locale);
            assert!(line.contains(words), "{lang}: {line}");
        }
        // A pack whose version rules predate the count names its records
        // only, never as vulnerabilities.
        let (_, line) = version_rules_line(&read(None), &en);
        assert!(
            line.contains("42 advisory records from") && !line.contains("vulnerabilities"),
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

    /// Ticket #294: the console line of a GitHub limit, rejected or cut,
    /// with the rule it is about, in the console language.
    #[test]
    fn test_github_limit_line_names_the_limit() {
        use codefixture_audit::report::exports::sarif::{GithubLimit, GithubLimitSubject};
        let en = codefixture_audit::i18n::load_script_locale("en");
        let tags = GithubLimit {
            subject: GithubLimitSubject::RuleTags("python/xss".to_string()),
            actual: 21,
            limit: 20,
            rejected: true,
        };
        assert_eq!(
            github_limit_line(&tags, &en),
            "GitHub code scanning would reject this SARIF file: the number of tags of rule python/xss is 21, at most 20."
        );
        let results = GithubLimit {
            subject: GithubLimitSubject::Results,
            actual: 7_500,
            limit: 5_000,
            rejected: false,
        };
        let fr = codefixture_audit::i18n::load_script_locale("fr");
        assert_eq!(
            github_limit_line(&results, &fr),
            "GitHub code scanning ne garde qu'une partie de ce fichier SARIF : le nombre de résultats vaut 7\u{202f}500, il en garde 5\u{202f}000."
        );
        assert!(gzip_size(&"a".repeat(10_000)) < 1_000, "gzip compresses");
    }

    /// Ticket #292: the console line and the metrics block of each choice
    /// for the client's rules.
    #[test]
    fn test_custom_rules_line_and_metrics_name_every_choice() {
        use codefixture_audit::rules::custom::{
            CustomRulesDir, CustomRulesOrigin, ScanCustomRules,
        };
        let en = codefixture_audit::i18n::load_script_locale("en");
        let read = ScanCustomRules::Read(CustomRulesDir {
            path: PathBuf::from("/srv/rules"),
            origin: CustomRulesOrigin::Option,
        });
        assert_eq!(
            custom_rules_line(&read, (3, 5), &en),
            "Your rules: 3/5 rule file(s) kept for the project's languages, from the folder /srv/rules (--custom-rules-dir)"
        );
        let missing = ScanCustomRules::DefaultMissing(PathBuf::from(
            "/home/ci/.codefixture-audit/custom-rules",
        ));
        assert!(custom_rules_line(&missing, (0, 0), &en).starts_with(
            "Your rules: none, the folder /home/ci/.codefixture-audit/custom-rules does not exist"
        ),);
        assert_eq!(
            custom_rules_line(&ScanCustomRules::NotRead, (0, 0), &en),
            "Your rules: not read, --rules names the whole catalog"
        );
        assert!(
            custom_rules_line(&ScanCustomRules::NoHome, (0, 0), &en)
                .contains("CODEFIXTURE_AUDIT_CUSTOM_RULES")
        );
        let fr = codefixture_audit::i18n::load_script_locale("fr");
        assert!(custom_rules_line(&read, (3, 5), &fr).starts_with("Vos règles : 3/5"));

        let metrics = custom_rules_metrics(&read, (3, 5));
        assert_eq!(
            (
                metrics.status,
                metrics.path.as_deref(),
                metrics.origin,
                metrics.files_read,
                metrics.files_available
            ),
            ("read", Some("/srv/rules"), Some("option"), 3, 5)
        );
        let metrics = custom_rules_metrics(&missing, (7, 7));
        assert_eq!(
            (metrics.status, metrics.origin, metrics.files_read),
            ("default_missing", Some("default"), 0)
        );
        assert_eq!(
            custom_rules_metrics(&ScanCustomRules::NotRead, (0, 0)).status,
            "not_read"
        );
        assert_eq!(
            custom_rules_metrics(&ScanCustomRules::NoHome, (0, 0)).path,
            None
        );
    }

    #[test]
    fn test_phase_progress_line_and_print() {
        let _console = lock_console_locale();
        let elapsed = std::time::Duration::from_millis(1_250);
        // The console language's colon and decimal separator (2026-11-24):
        // none before `:` in English, a space in French; `1,2 s` in
        // French. The only test that sets them.
        let en = codefixture_audit::i18n::load_script_locale("en");
        set_console_locale(&en);
        let line = phase_progress_line("[2/4] phase A", elapsed);
        assert_eq!(line, "[codefixture-audit]   [2/4] phase A: 1.2 s");
        set_console_locale(&codefixture_audit::i18n::load_script_locale("fr"));
        let line = phase_progress_line("[2/4] phase A", elapsed);
        assert_eq!(line, "[codefixture-audit]   [2/4] phase A : 1,2 s");
        set_console_locale(&codefixture_audit::i18n::load_script_locale("de"));
        let line = phase_progress_line("[2/4] phase A", elapsed);
        assert_eq!(line, "[codefixture-audit]   [2/4] phase A: 1,2 s");
        set_console_locale(&en);
        // Writes the same line to stderr; must not panic.
        print_phase_progress("[2/4] phase A", elapsed);
    }

    /// Every console line that writes a number, rendered in the four
    /// languages with numbers large enough to need a group separator and
    /// sizes and durations with a decimal: French, Spanish and German must
    /// never write a decimal point (the French console wrote `Durée
    /// totale : 12.7 s` and `11126 ligne(s)` until 2026-11-24). A dot that
    /// is not a decimal point is allowed: in a path, in a version or an
    /// IP-like value (`3.0.0`), and the Spanish and German group separator
    /// (a dot followed by exactly three digits).
    #[test]
    fn test_console_numbers_follow_the_language() {
        use codefixture_audit::rules::catalog::{RuleSourceKind, RuleSourceSummary};
        use codefixture_audit::rules::identity::RuleId;
        use codefixture_audit::scan::memory::{LanguageSources, MemoryEstimate, SystemMemory};
        use codefixture_audit::scan::orchestrator::{CustomRuleDuplicate, VersionRulesStatus};
        use codefixture_audit::scan::resources::{
            LimitOrigin, MemoryLimit, ScanResources, ThreadLimit,
        };
        use codefixture_audit::scan::scan_cache::CacheStat;
        use std::time::Duration;

        const GB: u64 = 1_073_741_824;
        let memory = MemoryEstimate {
            bytes: GB * 54 / 10,
            sources: vec![LanguageSources {
                language: "java".into(),
                bytes: 1_234 * 1_048_576,
                followed: true,
            }],
            rules_at_once: 1_200,
            max_rules_at_once: 2_400,
            system: Some(SystemMemory {
                total: GB * 32,
                available: GB * 157 / 10,
            }),
            limit: Some(GB * 3 / 2),
        };
        let resources = ScanResources {
            threads: ThreadLimit {
                threads: 1_023,
                cores: 1_024,
                origin: LimitOrigin::Default,
                input: None,
                capped_at_cores: false,
            },
            memory: MemoryLimit {
                bytes: Some(GB * 3 / 2),
                origin: LimitOrigin::Default,
                input: None,
                percent: Some(75),
            },
        };
        let report = ScanReport {
            rule_sources: vec![RuleSourceSummary {
                path: PathBuf::from("/opt/cfa-3.0.0/rules.cfpack"),
                kind: RuleSourceKind::Pack,
                origin: codefixture_audit::rules::catalog::RuleOrigin::Builtin,
                files_available: 7_110,
                files_read: 4_510,
            }],
            rules_loaded: 4_510,
            rule_languages: vec!["java".into()],
            ..ScanReport::default()
        };
        let cache = CacheStat {
            language: "php".into(),
            files: 1_690,
            dirty: 1_001,
            analysed: 30_420,
            total: 30_420,
            full: None,
        };
        let version_rules = VersionRulesStatus::Read {
            pack: PathBuf::from("/opt/cfa-3.0.0/rules.cfpack"),
            created: "2026-11-11T00:00:00Z".into(),
            counts: vec![("Maven".into(), 12_345), ("npm".into(), 2_600)],
            vulnerabilities: Some((14_000, 13_500)),
            sources: vec![],
        };
        let duplicates: Vec<CustomRuleDuplicate> = (1..=1_234)
            .map(|line| CustomRuleDuplicate {
                custom_rule: RuleId::new("java", "my_rule"),
                shipped_rule: RuleId::new("java", "sql_injection"),
                file: "src/App.java".into(),
                line,
            })
            .collect();
        let minified: Vec<String> = (0..1_500).map(|i| format!("static/m{i}.min.js")).collect();

        let render = |lang: &str| -> Vec<String> {
            let locale = codefixture_audit::i18n::load_script_locale(lang);
            let say = |key: &str| codefixture_audit::i18n::t(&locale, key);
            let mut lines = memory_lines(&memory, &resources, false, &locale);
            lines.extend(memory_lines(&memory, &resources, true, &locale));
            lines.extend(rule_source_lines(&report, &locale));
            lines.push(custom_rules_line(
                &codefixture_audit::rules::custom::ScanCustomRules::Read(
                    codefixture_audit::rules::custom::CustomRulesDir {
                        path: PathBuf::from("/srv/rules"),
                        origin: codefixture_audit::rules::custom::CustomRulesOrigin::Environment,
                    },
                ),
                (1_250, 2_480),
                &locale,
            ));
            lines.push(cache_stat_line(&cache, say));
            lines.push(version_rules_line(&version_rules, &locale).1);
            lines.extend(custom_duplicate_lines(&duplicates, &locale));
            lines.extend(skipped_files_line("scan_skipped_minified", &minified, say));
            lines.extend(scan_summary_lines(
                1_870,
                11_126,
                4_160,
                Duration::from_millis(12_780),
                &locale,
            ));
            lines.push(scan_summary_lines(1, 1, 0, Duration::from_secs(4_000), &locale)[1].clone());
            lines.push(try_summary_line(
                1_234,
                1_001,
                3_460,
                Duration::from_millis(1_250),
                &locale,
            ));
            lines.push(try_summary_line(
                0,
                0,
                3_460,
                Duration::from_millis(59_990),
                &locale,
            ));
            lines
        };

        // A dot between digits that is not a decimal point: inside a path
        // or a dotted version (two dots or more), removed before the check.
        let path_or_version =
            regex::Regex::new(r"\S*[/\\]\S*|\d+(\.\d+){2,}").expect("valid regex");
        // A dot between digits: a decimal point, unless the language
        // groups digits with a dot and three digits follow.
        let dot_between_digits = regex::Regex::new(r"\d\.(\d+)").expect("valid regex");
        for lang in ["fr", "es", "de"] {
            let groups_with_dot = LocaleFormat::for_language(lang).int(10_000u32) == "10.000";
            for line in render(lang) {
                let checked = path_or_version.replace_all(&line, "");
                for found in dot_between_digits.captures_iter(&checked) {
                    let is_group = groups_with_dot && found[1].len() == 3;
                    assert!(is_group, "{lang}: decimal point in {line:?}");
                }
            }
        }

        // What each language writes, read from the lines themselves.
        let joined = |lang: &str| render(lang).join("\n");
        let en = joined("en");
        for expected in [
            "1,870 file(s) scanned, 11,126 line(s) of code, 4,160 finding(s)",
            "12.7 s",
            "1 h 06 min",
            "about 5.4 GB",
            "15.7 GB available of 32.0 GB",
            "1.5 GB",
            "java 1,234 MB",
            "75%",
            "1,023 of 1,024 cores",
            "4,510/7,110",
            "1,250/2,480",
            "1,001/1,690",
            "30,420/30,420",
            "Maven 12,345, npm 2,600",
            "November 11, 2026",
            "1,234 line(s)",
            "1,500 file(s)",
            "1.2 s",
            "59.9 s",
        ] {
            assert!(en.contains(expected), "en: {expected:?} missing in\n{en}");
        }
        let fr = joined("fr");
        for expected in [
            "1\u{202f}870 fichier(s)",
            "11\u{202f}126 ligne(s)",
            "12,7 s",
            "environ 5,4 Go",
            "15,7 Go",
            "32,0 Go",
            "1\u{202f}234 Mo",
            "75\u{202f}%",
            "4\u{202f}510/7\u{202f}110",
            "1\u{202f}250/2\u{202f}480",
            "Maven 12\u{202f}345, npm 2\u{202f}600",
            "11/11/2026",
            "59,9 s",
        ] {
            assert!(fr.contains(expected), "fr: {expected:?} missing in\n{fr}");
        }
        let es = joined("es");
        // Spanish leaves a four-digit number whole, and groups from five.
        for expected in [
            "1870",
            "11.126",
            "12,7 s",
            "5,4",
            "Maven 12.345, npm 2600",
            "11/11/2026",
        ] {
            assert!(es.contains(expected), "es: {expected:?} missing in\n{es}");
        }
        let de = joined("de");
        for expected in [
            "1.870",
            "11.126",
            "12,7 s",
            "5,4",
            "Maven 12.345, npm 2.600",
            "11.11.2026",
        ] {
            assert!(de.contains(expected), "de: {expected:?} missing in\n{de}");
        }
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
        let written = write_sbom(
            &config,
            "demo",
            &Brand::default(),
            &chrono::Local::now(),
            None,
        );
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

/// Formats of `scan --format`: the shared binary writes the HTML report,
/// SARIF (for an IDE or a code platform) or GitLab's SAST report (ticket
/// #295, ADR-0069); the plain-text listing is a private tool (2026-11-14).
const SCAN_FORMATS: &[&str] = &["html", "sarif", "gitlab-sast"];

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

/// Options of `scan` for a CI/CD pipeline, in both builds (ADR-0066,
/// ticket #300): they change how the scan talks to the machine running it,
/// never which rules run, so holding them back protects nothing (the
/// product is the rule catalog, ADR-0034). Private-only from 2026-11-14 to
/// 2026-11-25, when a client compiling the shared repository for a CI had
/// neither JSON logs, nor a quiet mode, nor a metrics file. Shown under
/// their own heading in `scan --help`, so that the help of a manual scan
/// stays short.
#[derive(clap::Args, Debug)]
#[command(next_help_heading = "CI/CD")]
struct ScanCiArgs {
    /// Console log format: `text` (default, `[codefixture-audit] …` lines)
    /// or `json` (one JSON object per line: `timestamp`, `level`,
    /// `message`, `duration_ms` for phases — ticket #92).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    log_format: String,
    /// Output file. Absent by default with `--format html`: writes
    /// `<PREFIX>-REPORT-<timestamp>.html` (`PREFIX` from
    /// `brand.json`, `SCA` by default) into `audit-reports/` of
    /// the scanned folder (Audit uses `docs/audit-reports/`). Absent with
    /// another format: stdout.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Hides the progress lines on stderr (scope, steps, phases, skipped
    /// files, cache use). The version, the paths of the files written
    /// (report, scan data, SBOM, metrics), the summary, the warnings and
    /// the errors stay.
    #[arg(long)]
    quiet: bool,
    /// Writes a JSON file of scan metrics (files/LOC scanned,
    /// findings by severity, per-phase durations, the client's rules
    /// read, exit code) to this path — opt-in, local file only (ticket #90).
    #[arg(long)]
    metrics_output: Option<PathBuf>,
    /// The exit code counts only the findings new against the scan given
    /// with `--baseline`, which it requires (in a CI job: the scan data of
    /// the main branch), so that a project that already has findings can
    /// block only what a change adds. A finding is the same when its file,
    /// its rule and its code are, wherever its line moved.
    #[arg(long)]
    fail_on_new: bool,
    /// The severity from which a finding blocks: `critical`, `high`
    /// (default: HIGH and CRITICAL block), `medium`, `low` or `info`.
    #[arg(
        long,
        value_name = "SEVERITY",
        ignore_case = true,
        value_parser = clap::builder::PossibleValuesParser::new(["critical", "high", "medium", "low", "info"])
    )]
    fail_on: Option<String>,
    /// How many blocking findings the scan tolerates before it fails (exit
    /// code 1): it overrides `thresholds.max_high` of `audit.config.json`
    /// (default: 0, the first blocking finding fails).
    #[arg(long, value_name = "N")]
    max_blocking: Option<u64>,
    /// Writes the CycloneDX SBOM to this file instead of
    /// `audit-reports/audit-datas/<PREFIX>-SBOM-<timestamp>.json`, for a CI
    /// job that keeps it under a fixed name; implies `--sbom`.
    #[arg(long, value_name = "FILE")]
    sbom_output: Option<PathBuf>,
}

/// Options of `scan` kept for the private binary only (2026-11-14): the
/// editor's tools, and what carries a risk (`--with-tests` runs the
/// project's code). The shared binary checks the dependencies whenever
/// its rule pack carries version rules (ADR-0043) and reads the project's
/// `.sca-suppress.json` by itself; these options then take their default.
/// The CI/CD options left this list for [`ScanCiArgs`] (ADR-0066). The
/// shared binary runs with [`Default`]: every option off or empty.
#[derive(clap::Args, Debug, Default)]
struct ScanExtraArgs {
    /// `.sca-suppress.json` file.
    #[arg(long)]
    suppress_file: Option<PathBuf>,
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
    /// The findings left out are not counted for the exit code either;
    /// `--fail-on` chooses which findings block (ticket #290).
    #[arg(long)]
    severity: Option<String>,
    /// `brand.json` runtime customization file (ticket #87/spec
    /// #83) — default: `brand.json` next to the executable.
    /// Absent or invalid: strictly unchanged behavior ("CodeFixture"
    /// defaults).
    #[arg(long)]
    brand_file: Option<PathBuf>,
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
        /// Output format: `html` (the report, default), `sarif` (for an
        /// IDE or a code platform) or `gitlab-sast` (GitLab's SAST report,
        /// for `artifacts:reports:sast`).
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
        /// the environment variable CODEFIXTURE_AUDIT_CUSTOM_RULES, else
        /// `~/.codefixture-audit/custom-rules`, which no build or update
        /// touches. A folder given here or by the variable must exist.
        /// Ignored with `--rules`. The scan always says what it read.
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
        // Last: `ScanCiArgs` sets the "CI/CD" heading for the options that
        // follow it in `scan --help`, so nothing may come after it.
        #[command(flatten)]
        ci: ScanCiArgs,
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
        /// Folder of your rules — default: the environment variable
        /// CODEFIXTURE_AUDIT_CUSTOM_RULES, else
        /// `~/.codefixture-audit/custom-rules`.
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
        /// Folder of your rules — default: the environment variable
        /// CODEFIXTURE_AUDIT_CUSTOM_RULES, else
        /// `~/.codefixture-audit/custom-rules`.
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
        /// Folder of your rules — default: the environment variable
        /// CODEFIXTURE_AUDIT_CUSTOM_RULES, else
        /// `~/.codefixture-audit/custom-rules`.
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
        // The build identifier, not the release version: a crash log is a
        // diagnostic and names the exact build (2026-11-24).
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
            ci,
        } => {
            // Ticket #281: the limits are resolved and the thread pool
            // sized here, in the binary's entry point, before anything
            // uses the pool (the debug log header reads its size). The
            // console format must be known for an error.
            JSON_LOGS.store(
                ci.log_format == "json",
                std::sync::atomic::Ordering::Relaxed,
            );
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
                ci,
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
                .replace(
                    "{threads}",
                    &console_format_of(&say).count(resources.threads.threads)
                )
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
            .replace(
                "{percent}",
                // The percent sign as the language writes it (`75 %` with
                // a narrow no-break space in French), no longer in the text.
                &LocaleFormat::of_console(script_locale).percent(percent.unwrap_or_default()),
            ),
    }
}

/// The console lines about a scan's memory and threads (ticket #281): the
/// estimate, the threads used and where their limit comes from, and what
/// bounds the memory (the machine's available memory, the limit and where
/// it comes from), or, for a scan stopped before reading its files, which
/// bound it passed, what it would have read, and what to do. Sizes in GB
/// and every count in the console language's number format
/// (`report::locale_format`).
fn memory_lines(
    memory: &codefixture_audit::scan::memory::MemoryEstimate,
    resources: &codefixture_audit::scan::resources::ScanResources,
    stopped: bool,
    script_locale: &serde_json::Value,
) -> Vec<String> {
    use codefixture_audit::scan::resources::Setting;
    let say = |key: &str| codefixture_audit::i18n::t(script_locale, key);
    let numbers = LocaleFormat::of_console(script_locale);
    let gb = |bytes: u64| numbers.fixed(bytes as f64 / 1_073_741_824.0, 1);
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
            .replace("{threads}", &numbers.count(threads.threads))
            .replace("{cores}", &numbers.count(threads.cores))
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
                .replace("{cores}", &numbers.count(threads.cores))
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
                say(key).replace("{language}", &source.language).replace(
                    "{size}",
                    &numbers.fixed(source.bytes as f64 / 1_048_576.0, 0),
                )
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
                .replace("{rules}", &numbers.count(memory.rules_at_once))
                .replace("{max}", &numbers.count(memory.max_rules_at_once)),
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
    let rules_dir = match custom_rules_tool_dir(custom_rules_dir, &script_locale) {
        Ok(dir) => dir,
        Err(code) => return code,
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
    let numbers = LocaleFormat::of_console(script_locale);
    codefixture_audit::scan::orchestrator::custom_duplicate_pairs(duplicates)
        .into_iter()
        .map(|(custom, shipped, lines)| {
            codefixture_audit::i18n::t(script_locale, "scan_custom_rule_duplicates")
                .replace("{rule}", &custom.to_string())
                .replace("{shipped}", &shipped.to_string())
                .replace("{lines}", &numbers.count(lines))
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
        let numbers = LocaleFormat::of_console(script_locale);
        let _ = writeln!(
            out,
            "{}",
            say("rules_test_summary")
                .replace("{cases}", &numbers.count(outcomes.len()))
                .replace("{rules}", &numbers.count(rules.len()))
                .replace("{passed}", &numbers.count(outcomes.len() - failed))
                .replace("{failed}", &numbers.count(failed))
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
    let rules_dir = match custom_rules_tool_dir(custom_rules_dir, &script_locale) {
        Ok(dir) => dir,
        Err(code) => return code,
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
    let rules_dir = match custom_rules_tool_dir(custom_rules_dir, &script_locale) {
        Ok(dir) => dir,
        Err(code) => return code,
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
    println_result(&try_summary_line(
        findings.len(),
        files.len(),
        report.files_scanned,
        started.elapsed(),
        &script_locale,
    ));
    let owned: Vec<_> = duplicates.into_iter().cloned().collect();
    for line in custom_duplicate_lines(&owned, &script_locale) {
        println_result(&line);
    }
    ExitCode::SUCCESS
}

/// The last line of `custom-rules try`: the findings of the rule and the
/// files they are in, the files read and the time taken, in the console
/// language's number format (`report::locale_format`).
fn try_summary_line(
    findings: usize,
    files: usize,
    read: usize,
    elapsed: std::time::Duration,
    script_locale: &serde_json::Value,
) -> String {
    let say = |key: &str| codefixture_audit::i18n::t(script_locale, key);
    let numbers = LocaleFormat::of_console(script_locale);
    let elapsed = numbers.duration(elapsed);
    if findings == 0 {
        say("custom_rules_try_no_finding")
            .replace("{read}", &numbers.count(read))
            .replace("{elapsed}", &elapsed)
    } else {
        say("custom_rules_try_summary")
            .replace("{count}", &numbers.count(findings))
            .replace("{files}", &numbers.count(files))
            .replace("{read}", &numbers.count(read))
            .replace("{elapsed}", &elapsed)
    }
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
    let numbers = LocaleFormat::of_console(&script_locale);
    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "📋 {} ({} {rules_label}):\n",
        codefixture_audit::i18n::t(&script_locale, "available_rules"),
        numbers.count(listing.len())
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
            numbers.count(rules.len())
        );
        for rule in rules {
            let _ = writeln!(out, "   {:<40} {}", rule.id, rule_display_name(rule, lang));
        }
        let _ = writeln!(out);
    }
    ExitCode::from(0)
}

/// Writes the CycloneDX SBOM of the project's statically parsed
/// dependencies to `target` (`--sbom-output`, ticket #296), else to
/// `<data dir>/<PREFIX>-SBOM-<timestamp>.json` — same location and name
/// pattern as Python (`comparison.py::_export_sbom`,
/// `{datas_dir}/{brand_prefix}-SBOM-{timestamp}.json`), same manifests as
/// the `--with-deps` phase (`dependencies::collect_dependencies`). Each
/// SBOM gets a new serial number. Returns the written path, or a
/// description of the I/O, random source or serialization failure.
fn write_sbom(
    config: &ScanConfig,
    project_name: &str,
    brand: &Brand,
    now: &chrono::DateTime<chrono::Local>,
    target: Option<&Path>,
) -> Result<PathBuf, String> {
    let dir = config
        .datas_dir
        .clone()
        .unwrap_or_else(|| config.root.join(DATAS_DIR));
    if target.is_none() {
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let serial_number = codefixture_audit::report::exports::sbom::random_serial_number()?;
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
        // A deliverable: the release version, never the build identifier.
        codefixture_audit::RELEASE_VERSION,
        &now.to_rfc3339(),
        &serial_number,
    );
    let json = sbom
        .to_json_string()
        .map_err(|e| format!("SBOM serialization: {e}"))?;
    let path = match target {
        Some(file) => file.to_path_buf(),
        None => dir.join(format!(
            "{}-SBOM-{}.json",
            config.brand_prefix, config.timestamp
        )),
    };
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
    // The build identifier: the debug log names the exact build, unlike
    // the deliverables, which show the release version (2026-11-24).
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
    /// The CI/CD options, in both builds (ADR-0066).
    ci: ScanCiArgs,
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
        ci,
    } = args;
    let ScanCiArgs {
        log_format,
        output,
        quiet,
        metrics_output,
        fail_on_new,
        fail_on,
        max_blocking,
        sbom_output,
    } = ci;
    // Ticket #296: a path for the SBOM asks for an SBOM.
    let sbom = sbom || sbom_output.is_some();
    // The shared binary has none of these options: their defaults.
    let extra = ScanExtraArgs::default();
    let ScanExtraArgs {
        suppress_file,
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
    } = extra;
    let t_command_start = std::time::Instant::now();
    JSON_LOGS.store(log_format == "json", std::sync::atomic::Ordering::Relaxed);
    // Loaded right from the start, before the first possible error —
    // same mechanism as `run_create_rule_command` (ticket #47): before
    // this ticket, `scan`'s CLI messages (errors, progress) stayed in
    // French regardless of `--lang`, only the HTML report was
    // translated.
    let script_locale = codefixture_audit::i18n::load_script_locale(&lang);
    set_console_locale(&script_locale);
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
    if !SCAN_FORMATS.contains(&format.as_str()) {
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

    // Ticket #290: which findings block and how many are tolerated, read
    // before the scan, so that an invalid `thresholds.max_high` stops here
    // rather than after a long analysis.
    let blocking_rule = match blocking_rule(fail_on.as_deref(), max_blocking, &path, &script_locale)
    {
        Ok(rule) => rule,
        Err(code) => return code,
    };

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

    // Ticket #149 — the version first, even with `--quiet`: one line, and
    // the first thing a bug report needs. The release version since
    // 2026-11-24, as in every deliverable: the build identifier is for
    // `--version` and the debug log, which name the exact build.
    emit_result(&format!(
        "[codefixture-audit] codefixture-audit {}",
        codefixture_audit::RELEASE_VERSION
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

    // The client's own rules, read by both builds since ADR-0057. The
    // choice is named on the console after the rule lines (ticket #292).
    let custom_rules =
        match scan_custom_rules_or_exit(explicit_rules, custom_rules_dir, &script_locale) {
            Ok(choice) => choice,
            Err(code) => return code,
        };
    let custom_rules_dir = match &custom_rules {
        codefixture_audit::rules::custom::ScanCustomRules::Read(dir) => Some(dir.path.clone()),
        _ => None,
    };

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

    // Ticket #289: `--fail-on-new` compares with the scan named by
    // `--baseline` (already read above), never with the latest scan of the
    // history folder: on a CI server whose workspace persists, that one is
    // the previous pipeline's, maybe of another branch, and a new finding
    // would pass from the second run on. Without `--baseline`, it stops
    // (exit 2) and says what to give.
    if fail_on_new && baseline.is_none() {
        emit_error(
            &codefixture_audit::i18n::t(&script_locale, "scan_fail_on_new_no_baseline")
                .replace("{prefix}", &effective_prefix(&brand)),
        );
        return ExitCode::from(2);
    }

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
        && !(format == "html" && explicit_output)
        // Ticket #296: an explicit SBOM path expects a file written there,
        // as an explicit HTML report path does.
        && sbom_output.is_none();
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
            custom_rules: &custom_rules,
            blocking_rule: &blocking_rule,
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
    let client_counts = client_rule_counts(&report).unwrap_or((0, 0));
    emit_custom_rules_line(&custom_rules, client_counts, &script_locale);
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
        match write_sbom(&config, &project_name, &brand, &now, sbom_output.as_deref()) {
            Ok(sbom_path) => {
                // Ticket #297: a file written is a result, not progress: a
                // CI job reads its path to keep it, `--quiet` or not.
                emit_result(&format!(
                    "[codefixture-audit] SBOM{}{}",
                    codefixture_audit::i18n::t(&script_locale, "label_colon"),
                    sbom_path.display()
                ));
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
        "gitlab-sast" => {
            match gitlab_text(&report.findings, &brand, now.to_utc(), &script_locale) {
                Ok(text) => text,
                Err(code) => return code,
            }
        }
        "html" => {
            let ctx = ReportContext {
                project_name,
                project_version: String::new(),
                project_uuid: String::new(),
                project_description: String::new(),
                // The full path of the folder scanned, not the one typed
                // (`.` for `scan .` before 2026-11-25): shown in the header
                // and the parameters section of the report.
                project_path: codefixture_audit::project::project_config::project_dir_text(
                    &codefixture_audit::project::project_config::project_dir_of(&config.root),
                ),
                tool_name: effective_tool_name(&brand),
                // Footer, title and generator of the report: the release
                // version, it showed "v0.1.0+506.ade3297" before 2026-11-24.
                tool_version: codefixture_audit::RELEASE_VERSION.to_string(),
                company_name: effective_company_name(&brand),
                report_lang: lang,
                // Written in the report's language by the report itself
                // (`report::locale_format`), no longer here the French way.
                generated_at: now.naive_local(),
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
    if let Err(code) = write_scan_output(output.as_deref(), &output_text, &script_locale) {
        return code;
    }
    drop(write_step);
    // Ticket #297: the scan data (`<PREFIX>-DATA-<date>.json`) is the file a
    // later scan compares with (`--baseline`): a CI job keeps it from one
    // pipeline to the next, so its path is a result. It was never printed
    // before 2026-11-25.
    if let Some(export_path) = &report.export_path {
        emit_result(&format!(
            "[codefixture-audit] {}",
            codefixture_audit::i18n::t(&script_locale, "scan_export_written")
                .replace("{path}", &export_path.display().to_string())
        ));
    }

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
        record.client_rules = client_rule_counts(&report);
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

    // Ticket #289: with `--fail-on-new`, only the findings new against the
    // `--baseline` scan count for the exit code. The
    // comparison is the report's own (`report::comparison`), so the exit
    // code and the report's "new findings" never disagree.
    let blocking: Vec<ReportFinding> = if fail_on_new {
        let Some(comparison) = &report.comparison else {
            // The baseline was read before the scan: only a file removed
            // or damaged during the scan leaves no comparison.
            emit_error(
                &codefixture_audit::i18n::t(&script_locale, "scan_baseline_unreadable")
                    .replace(
                        "{path}",
                        &baseline
                            .as_deref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                    )
                    .replace("{error}", "no comparison could be made"),
            );
            return ExitCode::from(2);
        };
        emit_result(&format!(
            "[codefixture-audit] {}",
            fail_on_new_summary(
                comparison,
                baseline.as_deref(),
                &blocking_rule,
                &script_locale
            )
        ));
        comparison.new_findings.clone()
    } else {
        report.findings.clone()
    };
    let exit_code = finish_scan(
        &report.findings,
        &blocking,
        &blocking_rule,
        report.files_scanned,
        report.total_loc,
        &script_locale,
        t_command_start,
    );

    // Ticket #90: written last, so it records the real exit code. A
    // write failure is an internal error (4), like the report itself.
    if let Some(metrics_path) = &metrics_output {
        let metrics = codefixture_audit::report::exports::metrics::build_scan_metrics(
            &report,
            "codefixture-audit",
            codefixture_audit::RELEASE_VERSION,
            &now.to_rfc3339(),
            t_command_start.elapsed().as_millis(),
            exit_code,
            &custom_rules_metrics(&custom_rules, client_counts),
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
        // Ticket #297: named like the other files written, even with
        // `--quiet`.
        emit_result(&format!(
            "[codefixture-audit] {}",
            codefixture_audit::i18n::t(&script_locale, "scan_metrics_written")
                .replace("{path}", &metrics_path.display().to_string())
        ));
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
        codefixture_audit::RELEASE_VERSION,
        &effective_website_url(brand),
    );
    let text = serde_json::to_string_pretty(&sarif).map_err(|e| {
        emit_error(
            &codefixture_audit::i18n::t(script_locale, "scan_internal_error")
                .replace("{error}", &format!("SARIF serialization: {e}")),
        );
        ExitCode::from(4)
    })?;
    // Ticket #294: what GitHub code scanning would reject or cut, named
    // before the file reaches it. The file is written all the same: other
    // tools read SARIF without these limits.
    for limit in codefixture_audit::report::exports::sarif::github_limits(&sarif, gzip_size(&text))
    {
        emit_warning(&format!(
            "[codefixture-audit] {}",
            github_limit_line(&limit, script_locale)
        ));
    }
    Ok(text)
}

/// The GitLab SAST report of `findings` (ticket #295), for a scan started
/// at `start`. A vulnerability with more identifiers than GitLab keeps is
/// named in a warning; an error is reported to the user, and the exit
/// code is returned.
fn gitlab_text(
    findings: &[ReportFinding],
    brand: &Brand,
    start: chrono::DateTime<chrono::Utc>,
    script_locale: &serde_json::Value,
) -> Result<String, ExitCode> {
    use codefixture_audit::report::exports::gitlab::{
        GITLAB_MAX_IDENTIFIERS, GitlabToolInfo, build_gitlab_sast_report, gitlab_identifier_limits,
    };
    let stamp = |t: chrono::DateTime<chrono::Utc>| t.format("%Y-%m-%dT%H:%M:%S").to_string();
    let tool_name = effective_tool_name(brand);
    let vendor = effective_company_name(brand);
    let report = build_gitlab_sast_report(
        findings,
        &GitlabToolInfo {
            tool_name: &tool_name,
            tool_version: codefixture_audit::RELEASE_VERSION,
            vendor: &vendor,
        },
        &stamp(start),
        &stamp(chrono::Utc::now()),
    );
    let numbers = LocaleFormat::of_console(script_locale);
    for (rule, count) in gitlab_identifier_limits(&report) {
        emit_warning(&format!(
            "[codefixture-audit] {}",
            codefixture_audit::i18n::t(script_locale, "gitlab_identifiers_cut")
                .replace("{rule}", &rule)
                .replace("{count}", &numbers.count(count))
                .replace("{limit}", &numbers.count(GITLAB_MAX_IDENTIFIERS))
        ));
    }
    serde_json::to_string_pretty(&report).map_err(|e| {
        emit_error(
            &codefixture_audit::i18n::t(script_locale, "scan_internal_error")
                .replace("{error}", &format!("GitLab report serialization: {e}")),
        );
        ExitCode::from(4)
    })
}

/// The size of `text` once gzip-compressed, as GitHub measures an upload.
fn gzip_size(text: &str) -> usize {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    // Writing to memory cannot fail.
    encoder.write_all(text.as_bytes()).expect("gzip to memory");
    encoder.finish().expect("gzip to memory").len()
}

/// The console line of a limit of GitHub code scanning that the SARIF
/// output goes beyond (ticket #294).
fn github_limit_line(
    limit: &codefixture_audit::report::exports::sarif::GithubLimit,
    script_locale: &serde_json::Value,
) -> String {
    use codefixture_audit::report::exports::sarif::GithubLimitSubject;
    let say = |key: &str| codefixture_audit::i18n::t(script_locale, key);
    let numbers = LocaleFormat::of_console(script_locale);
    let (key, rule) = match &limit.subject {
        GithubLimitSubject::CompressedSize => ("sarif_limit_compressed", None),
        GithubLimitSubject::Results => ("sarif_limit_results", None),
        GithubLimitSubject::Rules => ("sarif_limit_rules", None),
        GithubLimitSubject::RuleTags(rule) => ("sarif_limit_tags", Some(rule)),
        GithubLimitSubject::FlowSteps(rule) => ("sarif_limit_flow", Some(rule)),
        GithubLimitSubject::Description(rule) => ("sarif_limit_description", Some(rule)),
        GithubLimitSubject::Name(rule) => ("sarif_limit_name", Some(rule)),
    };
    let what = say(key).replace("{rule}", rule.map(String::as_str).unwrap_or_default());
    say(if limit.rejected {
        "sarif_github_rejected"
    } else {
        "sarif_github_cut"
    })
    .replace("{what}", &what)
    .replace("{actual}", &numbers.count(limit.actual))
    .replace("{limit}", &numbers.count(limit.limit))
}

/// Writes a scan's output to `output` and names the file, or prints it on
/// stdout without `output`. A write error is reported, and the exit code
/// is returned. The file is named even with `--quiet` (ticket #297): a CI
/// job needs its path, and before 2026-11-25 `--quiet` hid it.
fn write_scan_output(
    output: Option<&Path>,
    text: &str,
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
    emit_result(&format!(
        "[codefixture-audit] {}{}{}",
        codefixture_audit::i18n::t(script_locale, "report_generated"),
        codefixture_audit::i18n::t(script_locale, "label_colon"),
        out_path.display()
    ));
    Ok(())
}

/// Which findings fail a scan, and how many are tolerated (ticket #290).
#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockingRule {
    /// The lowest severity that blocks, as the findings write it
    /// (`HIGH`): it and every severity above it block.
    severity: &'static str,
    /// Blocking findings tolerated before the scan fails: `--max-blocking`,
    /// else `thresholds.max_high` of `audit.config.json`, else 0.
    tolerated: u64,
}

/// The severities, the worst first.
const SEVERITIES_WORST_FIRST: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

impl BlockingRule {
    /// Whether `finding` blocks: its severity is this rule's or worse. A
    /// severity the engine does not write never blocks; none exists today.
    fn blocks(&self, finding: &ReportFinding) -> bool {
        let rank = |severity: &str| SEVERITIES_WORST_FIRST.iter().position(|s| *s == severity);
        match (rank(&finding.severity), rank(self.severity)) {
            (Some(finding_rank), Some(rule_rank)) => finding_rank <= rule_rank,
            _ => false,
        }
    }
}

/// The blocking rule of a scan of `root`: `--fail-on` (default HIGH, the
/// gate of ticket #42), and `--max-blocking`, which overrides
/// `thresholds.max_high` of `audit.config.json`. A `thresholds.max_high`
/// that is not a whole number of 0 or more stops the scan (exit 2) with
/// the file and the value; it counted as 0 without a word before
/// 2026-11-25. `--fail-on` and `--max-blocking` are checked by clap.
fn blocking_rule(
    fail_on: Option<&str>,
    max_blocking: Option<u64>,
    root: &Path,
    script_locale: &serde_json::Value,
) -> Result<BlockingRule, ExitCode> {
    let severity = match fail_on.map(str::to_uppercase) {
        None => "HIGH",
        Some(given) => SEVERITIES_WORST_FIRST
            .into_iter()
            .find(|s| *s == given)
            .expect("clap accepts only these severities"),
    };
    let tolerated = match max_blocking {
        Some(n) => n,
        None => match codefixture_audit::project::project_config::read_max_high_threshold(root) {
            Ok(value) => value.unwrap_or(0),
            Err(value) => {
                emit_error(
                    &codefixture_audit::i18n::t(script_locale, "scan_threshold_invalid")
                        .replace(
                            "{file}",
                            &root.join("audit.config.json").display().to_string(),
                        )
                        .replace("{value}", &value),
                );
                return Err(ExitCode::from(2));
            }
        },
    };
    Ok(BlockingRule {
        severity,
        tolerated,
    })
}

/// The console line of `--fail-on-new` (ticket #289): the scan compared
/// with, its new findings, how many of them block, and how many were
/// already there. Shown even with `--quiet`: it explains the exit code.
fn fail_on_new_summary(
    comparison: &codefixture_audit::report::comparison::ComparisonResult,
    baseline: Option<&Path>,
    rule: &BlockingRule,
    script_locale: &serde_json::Value,
) -> String {
    let numbers = LocaleFormat::of_console(script_locale);
    let blocking = comparison
        .new_findings
        .iter()
        .filter(|f| rule.blocks(f))
        .count();
    codefixture_audit::i18n::t(script_locale, "scan_fail_on_new_summary")
        .replace("{date}", &numbers.scan_timestamp(&comparison.baseline_date))
        .replace(
            "{path}",
            &baseline
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        )
        .replace("{new}", &numbers.count(comparison.new_findings.len()))
        .replace("{blocking}", &numbers.count(blocking))
        .replace("{severity}", rule.severity)
        .replace(
            "{unchanged}",
            &numbers.count(comparison.unchanged_findings.len()),
        )
}

/// The last two lines of every scan, full or skipped as unchanged
/// (ADR-0050): the summary and the total duration. Returns the exit code
/// that `blocking` gives against the project's threshold: every finding,
/// or with `--fail-on-new` the findings new against the baseline (ticket
/// #289). The summary counts `findings`, all of them.
fn finish_scan(
    findings: &[ReportFinding],
    blocking: &[ReportFinding],
    rule: &BlockingRule,
    files_scanned: usize,
    total_loc: usize,
    script_locale: &serde_json::Value,
    t_command_start: std::time::Instant,
) -> u8 {
    // Never suppressed by `--quiet` (see ticket #44): it's the only
    // message guaranteed by a silent CI scan — without it, a run that
    // "succeeds" with no finding is indistinguishable from a run that scanned
    // nothing at all.
    // Whole command, from argument parsing to the written report
    // (ticket #135) — the per-phase lines don't add up to it (rule
    // loading aside, discovery and report rendering are not phases).
    // Same never-suppressed treatment as the summary line.
    let total_elapsed = t_command_start.elapsed();
    let [summary, duration] = scan_summary_lines(
        files_scanned,
        total_loc,
        findings.len(),
        total_elapsed,
        script_locale,
    );
    emit_result(&format!("[codefixture-audit] {summary}"));
    if JSON_LOGS.load(std::sync::atomic::Ordering::Relaxed) {
        // The message is the console's text; `duration_ms` is the
        // neutral value for the machine reading the log.
        emit_json_line(
            LogLevel::Info,
            &duration,
            &[("duration_ms", serde_json::json!(total_elapsed.as_millis()))],
        );
    } else {
        emit_result(&format!("[codefixture-audit] {duration}"));
    }

    let blocking_count = blocking.iter().filter(|f| rule.blocks(f)).count() as u64;
    // Configurable threshold (ticket #42/spec #27, options of ticket #290):
    // by default HIGH and CRITICAL block and none is tolerated, the
    // previous hardcoded behavior. Accepted deviations vs Python
    // documented in `read_max_high_threshold`.
    u8::from(blocking_count > rule.tolerated)
}

/// The last two lines of a scan, without their `[codefixture-audit]`
/// prefix: the summary (files, lines of code, findings) and the total
/// duration, in the console language's number format
/// (`report::locale_format`). Until 2026-11-24 they wrote `11126` and
/// `12.7 s` in every language.
fn scan_summary_lines(
    files_scanned: usize,
    total_loc: usize,
    findings: usize,
    elapsed: std::time::Duration,
    script_locale: &serde_json::Value,
) -> [String; 2] {
    let numbers = LocaleFormat::of_console(script_locale);
    [
        codefixture_audit::i18n::t(script_locale, "scan_summary")
            .replace("{files}", &numbers.count(files_scanned))
            .replace("{loc}", &numbers.count(total_loc))
            .replace("{findings}", &numbers.count(findings)),
        codefixture_audit::i18n::t(script_locale, "scan_total_duration")
            .replace("{duration}", &numbers.duration(elapsed)),
    ]
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
    /// What this scan does with the client's rules, named as in a full
    /// scan (ticket #292).
    custom_rules: &'a codefixture_audit::rules::custom::ScanCustomRules,
    /// Which findings block, and how many are tolerated (ticket #290): the
    /// exit code is computed again from the last export's findings with
    /// this scan's options.
    blocking_rule: &'a BlockingRule,
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
    // The export's `YYYY-MM-DD-HH-MM` stamp, as the console's language
    // writes a date and time (`November 24, 2026 at 9:47 AM`): the French
    // `24/11/2026 09:47` in every language before 2026-11-24.
    let date = LocaleFormat::of_console(scan.script_locale).scan_timestamp(&export.timestamp);
    emit_result(&format!(
        "[codefixture-audit] {}",
        say("scan_unchanged").replace("{date}", &date)
    ));
    // Ticket #292: the client's rules, as the last scan read them. Equal
    // fingerprints mean the same rule files (`ScanInputs`), so its counts
    // hold; a record without counts read no client folder, and an equal
    // fingerprint then means the folder holds no rule file.
    emit_custom_rules_line(
        scan.custom_rules,
        scan.last.client_rules.unwrap_or((0, 0)),
        scan.script_locale,
    );
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
        // `--sbom-output` never takes this shortcut: the default path only.
        match write_sbom(scan.config, project_name, scan.brand, now, None) {
            Ok(sbom_path) => {
                // Ticket #297: named even with `--quiet`, as in a full scan.
                emit_result(&format!(
                    "[codefixture-audit] SBOM{}{}",
                    codefixture_audit::i18n::t(scan.script_locale, "label_colon"),
                    sbom_path.display()
                ));
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
        "gitlab-sast" => {
            // The scan of this run starts now, nothing being analysed again.
            let start = chrono::Utc::now() - scan.t_command_start.elapsed();
            match gitlab_text(&export.findings, scan.brand, start, scan.script_locale) {
                Ok(text) => Some(text),
                Err(code) => return code,
            }
        }
        "text" => Some(format_text_report(&export.findings)),
        _ => None,
    };
    match text {
        Some(text) => {
            if let Err(code) = write_scan_output(scan.output, &text, scan.script_locale) {
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
    // `--fail-on-new` never takes this shortcut (it sets a baseline), so
    // every finding counts here.
    ExitCode::from(finish_scan(
        &export.findings,
        &export.findings,
        scan.blocking_rule,
        scan.last.files_scanned,
        scan.last.total_loc,
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
