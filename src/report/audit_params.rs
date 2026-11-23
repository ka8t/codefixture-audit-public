//! HTML "audit parameters" section — port of
//! `_generate_audit_params_summary` (`Audit/sca/report.py`).
//!
//! **Assumed simplifications vs Python** (codefixture-audit has no
//! JSON-file-based configuration system, only CLI flags —
//! see `orchestrator::ScanConfig`):
//!   - **Categories**: Python displays an enabled/weighted badge per
//!     category, driven by `enabled_categories`/`category_weights`
//!     (project config, no CLI equivalent on the Python side either).
//!     codefixture-audit has no such notion — the badge simply reflects
//!     `only_category` (a single "active" category if filtered,
//!     all 5 otherwise), weight always displayed as `×1`.
//!   - **Scanned extensions**: derived from the detected languages and
//!     the discovery lists themselves (`SourceLanguage::EXTENSIONS` and
//!     the exact file names, `orchestrator.rs`) — not from a configurable
//!     `self._py_exts`/`_js_exts` as on the Python side. Until ticket #285
//!     a static copy named Python, Java, JavaScript and PHP only: an HTML,
//!     C#, YAML or Dockerfile project showed no extension at all.
//!   - **CLI options**: only the options of the binary that wrote the
//!     report are listed (ticket #188). The shared binary has seven scan
//!     options since 4e976cd; the report shows its `--quick`,
//!     `--only-category` and `--lang`. The private binary adds
//!     `--disable-rule`/`--severity`/`--with-tests`/`--with-deps`/
//!     `--db-host`, rendered from a private block the export
//!     removes. Not `--fail-on-high`/`--sarif`/`--sbom`/`--debug`
//!     (Python), which have no Rust equivalent as of today
//!     (`--format sarif` exists, but as a value of `--format`).
//!   - **Dependencies**: what the dependencies phase did is a scope row
//!     ("checked", "versions not checked", "not checked"), never an
//!     option name: a pack with version rules runs the phase without any
//!     option (ADR-0043), and the shared binary has no `--with-deps`.

use serde_json::Value;

use crate::i18n::t;
use crate::report::html::ReportContext;
use crate::report::report_assets::load_template;
use crate::report::text::escape;

/// Entries not derivable from the findings, for the "audit
/// parameters" section — mirrors the `ScanConfig` fields/CLI options
/// actually used for this scan.
pub struct AuditParamsInfo {
    /// Languages actually detected among the scanned files
    /// (`rule_tag()`, e.g. "python"/"java"/"javascript"/"php"), sorted.
    pub languages: Vec<String>,
    /// Explicitly included paths — empty = the whole project.
    pub include_paths: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub quick_mode: bool,
    pub only_category: Option<String>,
    pub disabled_rules: Vec<String>,
    pub with_tests: bool,
    /// `--with-deps` typed on the command line (private binary). Not
    /// whether the phase ran: see `dependencies`.
    pub with_deps: bool,
    /// What the dependencies phase did in this scan.
    pub dependencies: DependencyCheck,
    pub database_configured: bool,
    /// The databases of the version rules the scan used, with their
    /// licenses (ADR-0051): credited in a row of their own. Empty when no
    /// version rules were read, or for a pack built before 2026-11-18.
    pub vulnerability_sources: Vec<crate::project::advisory_file::DataSource>,
    pub severity_levels: Option<Vec<String>>,
    pub report_lang: String,
}

/// What the dependencies phase did, for the "Dependencies" row of the
/// audit scope (ticket #188). Derived from `ScanReport::version_rules`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyCheck {
    /// The phase did not run (no manifest, `--quick`, or no version
    /// rules and no `--with-deps`).
    NotRun,
    /// Versions checked against the version rules of the rule pack.
    Checked,
    /// The phase ran (unpinned versions reported) but the rule pack
    /// carries no readable version rules: published vulnerabilities were
    /// not checked.
    VersionsNotChecked,
}

impl DependencyCheck {
    /// Locale key of the row's value (`audit_params.dependencies_*`).
    fn i18n_key(self) -> &'static str {
        match self {
            DependencyCheck::NotRun => "audit_params.dependencies_not_run",
            DependencyCheck::Checked => "audit_params.dependencies_checked",
            DependencyCheck::VersionsNotChecked => "audit_params.dependencies_versions_not_checked",
        }
    }
}

/// What the scan reads for the rule language `lang`: its extensions
/// (`.cs`, `.html`, `.cshtml`, `.razor`…), then the files it recognizes
/// by exact name (`Dockerfile`, `pom.xml`, `web.config`, `package.json`),
/// in the order of the discovery lists. Read from the lists the discovery
/// itself uses (`SourceLanguage::EXTENSIONS`, `DOCKERFILE_FILENAMES`,
/// `CONFIG_FILENAMES`): the static copy it replaces (ticket #285) had
/// drifted to four languages and missed `.tsx`, `.inc` and every HTML
/// template.
fn language_files(lang: &str) -> Vec<String> {
    use crate::scan::orchestrator::SourceLanguage;
    let mut files: Vec<String> = SourceLanguage::EXTENSIONS
        .iter()
        .filter(|(_, l)| l.rule_tag() == lang)
        .map(|(ext, _)| format!(".{ext}"))
        .collect();
    if SourceLanguage::Dockerfile.rule_tag() == lang {
        files.extend(
            SourceLanguage::DOCKERFILE_FILENAMES
                .iter()
                .map(|n| n.to_string()),
        );
    }
    files.extend(
        SourceLanguage::CONFIG_FILENAMES
            .iter()
            .filter(|(_, l)| l.rule_tag() == lang)
            .map(|(n, _)| n.to_string()),
    );
    files
}

const CATEGORY_ORDER: [(&str, &str, &str); 5] = [
    ("SECURITY", "security", "🔒"),
    ("ARCH", "architecture", "🏗️"),
    ("UI", "ui", "🎨"),
    ("UX", "ux", "🧭"),
    ("MAINTENANCE", "maintenance", "🔧"),
];

/// The "scanned extensions" row: for each detected language, the files
/// the scan reads for it ([`language_files`]); a language that reads none
/// is left out.
fn extensions_for(languages: &[String]) -> String {
    let mut parts = Vec::new();
    for lang in languages {
        let exts = language_files(lang);
        if !exts.is_empty() {
            let exts_html = exts
                .iter()
                .map(|e| format!("<code>{}</code>", escape(e)))
                .collect::<Vec<_>>()
                .join(", ");
            parts.push(format!("<code>{}</code>: {exts_html}", escape(lang)));
        }
    }
    parts.join("<br>")
}

fn category_badges(only_category: Option<&str>, report_locale: &Value) -> String {
    let badge_tpl = load_template("category-badge.html");
    let mut html = String::new();
    for (cat_key, i18n_key, _icon) in CATEGORY_ORDER {
        let enabled = match only_category {
            Some(only) => only.eq_ignore_ascii_case(cat_key),
            None => true,
        };
        let label = t(report_locale, &format!("category_titles.{i18n_key}"));
        let badge = badge_tpl
            .replace("{{class}}", if enabled { "enabled" } else { "disabled" })
            .replace("{{status}}", if enabled { "✓" } else { "✗" })
            .replace("{{label}}", &escape(&label))
            .replace("{{weight}}", "1");
        html.push_str(&badge);
        html.push(' ');
    }
    html
}

/// One line of the options checklist (`cli-option-item.html`).
fn render_option(active: bool, flag_display: &str, desc: &str) -> String {
    load_template("cli-option-item.html")
        .replace(
            "{{option_class}}",
            if active { "active" } else { "inactive" },
        )
        .replace("{{option_check}}", if active { "✅" } else { "⬜" })
        .replace("{{option_flag}}", &escape(flag_display))
        .replace("{{option_desc}}", &escape(desc))
}

/// Options checklist: the options both binaries have, then (private
/// binary only) its own options. The export removes the private block,
/// so the shared report never names an option its binary does not have
/// (ticket #188).
fn cli_options_html(info: &AuditParamsInfo, report_locale: &Value) -> String {
    #[allow(unused_mut)] // appended to by the private block only.
    let mut html = shared_cli_options_html(info, report_locale);
    html
}

/// Options of the shared binary's `scan` shown in the report: `--quick`,
/// `--only-category`, `--lang`. Its other options (`--no-cache`,
/// `--format`, `--rules`, `--exclude`) are shown elsewhere in the
/// section or change nothing in its content.
fn shared_cli_options_html(info: &AuditParamsInfo, report_locale: &Value) -> String {
    let mut html = String::new();
    html.push_str(&render_option(
        info.quick_mode,
        "--quick",
        &t(report_locale, "cli_options_desc.quick"),
    ));
    let only_cat_flag = match &info.only_category {
        Some(c) => format!("--only-category {c}"),
        None => "--only-category".to_string(),
    };
    html.push_str(&render_option(
        info.only_category.is_some(),
        &only_cat_flag,
        &t(report_locale, "cli_options_desc.only_category"),
    ));
    html.push_str(&render_option(
        true,
        &format!("--lang {}", info.report_lang),
        &t(report_locale, "cli_options_desc.report_lang"),
    ));
    html
}

/// Generates the complete "audit parameters" section. The project
/// identity comes from `ctx` (which already carries these fields for
/// the rest of the report) rather than being duplicated in the
/// parameters — avoids forcing a caller to unpack `ctx` field by field.
pub fn render_audit_params_html(
    info: &AuditParamsInfo,
    ctx: &ReportContext,
    report_locale: &Value,
) -> String {
    let project_name = ctx.project_name.as_str();
    let project_version = ctx.project_version.as_str();
    let project_description = ctx.project_description.as_str();
    let project_uuid = ctx.project_uuid.as_str();
    let project_path = ctx.project_path.as_str();
    let template = load_template("audit-params.html");

    let languages_html = if info.languages.is_empty() {
        format!("<em>{}</em>", t(report_locale, "none"))
    } else {
        info.languages
            .iter()
            .map(|l| format!("<code>{}</code>", escape(l)))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let extensions_html = {
        let ext = extensions_for(&info.languages);
        if ext.is_empty() {
            format!("<em>{}</em>", t(report_locale, "none"))
        } else {
            ext
        }
    };

    let include_html = if info.include_paths.is_empty() {
        format!("<em>{}</em>", t(report_locale, "all"))
    } else {
        info.include_paths
            .iter()
            .map(|p| format!("<code>{}</code>", escape(p)))
            .collect::<Vec<_>>()
            .join(" ")
    };

    let exclude_html = if info.exclude_patterns.is_empty() {
        format!("<em>{}</em>", t(report_locale, "none"))
    } else {
        info.exclude_patterns
            .iter()
            .map(|p| format!("<code>{}</code>", escape(p)))
            .collect::<Vec<_>>()
            .join(" ")
    };

    let mode_label = if info.quick_mode {
        t(report_locale, "mode_quick")
    } else {
        t(report_locale, "mode_full")
    };

    let only_cat_html = match &info.only_category {
        Some(c) => format!("<code>{}</code>", escape(c)),
        None => format!("<em>{}</em>", t(report_locale, "all")),
    };

    let disabled_html = if info.disabled_rules.is_empty() {
        format!("<em>{}</em>", t(report_locale, "none"))
    } else {
        let mut sorted = info.disabled_rules.clone();
        sorted.sort();
        sorted
            .iter()
            .map(|r| format!("<code>{}</code>", escape(r)))
            .collect::<Vec<_>>()
            .join(", ")
    };

    template
        .replace("{{i18n_parameters}}", &t(report_locale, "parameters"))
        .replace(
            "{{i18n_project_info}}",
            &t(report_locale, "audit_params.project_info"),
        )
        .replace(
            "{{i18n_project_name}}",
            &t(report_locale, "audit_params.project_name"),
        )
        .replace(
            "{{i18n_project_description}}",
            &t(report_locale, "audit_params.project_description"),
        )
        .replace(
            "{{i18n_project_id}}",
            &t(report_locale, "audit_params.project_id"),
        )
        .replace(
            "{{i18n_project_path}}",
            &t(report_locale, "audit_params.project_path"),
        )
        .replace("{{project_name}}", &escape(project_name))
        .replace(
            "{{project_version}}",
            &if project_version.is_empty() {
                String::new()
            } else {
                format!("<code>v{}</code>", escape(project_version))
            },
        )
        .replace(
            "{{project_description}}",
            &if project_description.is_empty() {
                format!("<em>{}</em>", t(report_locale, "none"))
            } else {
                escape(project_description)
            },
        )
        .replace(
            "{{project_id}}",
            &if project_uuid.is_empty() {
                format!("<em>{}</em>", t(report_locale, "none"))
            } else {
                escape(project_uuid)
            },
        )
        .replace("{{project_path}}", &escape(project_path))
        .replace("{{i18n_audit_scope}}", &t(report_locale, "audit_scope"))
        .replace(
            "{{i18n_languages}}",
            &t(report_locale, "audit_params.languages"),
        )
        .replace("{{languages}}", &languages_html)
        .replace(
            "{{i18n_scanned_extensions}}",
            &t(report_locale, "audit_params.scanned_extensions"),
        )
        .replace("{{scanned_extensions}}", &extensions_html)
        .replace(
            "{{i18n_analyzed_dirs}}",
            &t(report_locale, "audit_params.analyzed_dirs"),
        )
        .replace("{{include_paths}}", &include_html)
        .replace(
            "{{i18n_excluded_patterns}}",
            &t(report_locale, "audit_params.excluded_patterns"),
        )
        .replace("{{exclude_patterns}}", &exclude_html)
        .replace("{{i18n_mode}}", &t(report_locale, "audit_params.mode"))
        .replace("{{mode}}", &escape(&mode_label))
        .replace(
            "{{i18n_filtered_category}}",
            &t(report_locale, "audit_params.filtered_category"),
        )
        .replace("{{only_category}}", &only_cat_html)
        .replace(
            "{{i18n_disabled_rules}}",
            &t(report_locale, "audit_params.disabled_rules"),
        )
        .replace("{{disabled_rules}}", &disabled_html)
        .replace(
            "{{i18n_dependencies}}",
            &t(report_locale, "audit_params.dependencies"),
        )
        .replace(
            "{{dependencies}}",
            &escape(&t(report_locale, info.dependencies.i18n_key())),
        )
        .replace(
            "{{vulnerability_sources_row}}",
            &vulnerability_sources_row(&info.vulnerability_sources, report_locale),
        )
        .replace(
            "{{i18n_categories}}",
            &t(report_locale, "audit_params.categories"),
        )
        .replace(
            "{{categories}}",
            &category_badges(info.only_category.as_deref(), report_locale),
        )
        .replace(
            "{{i18n_cli_options}}",
            &t(report_locale, "audit_params.cli_options"),
        )
        .replace(
            "{{cli_options_html}}",
            &cli_options_html(info, report_locale),
        )
}

/// The row crediting the databases of the version rules (ADR-0051):
/// each name links to where the data is published, followed by its
/// license. Their licenses (CC-BY 4.0, Apache 2.0…) ask for this credit
/// wherever the data is redistributed, and a report shows the findings
/// made from it. Empty without sources.
fn vulnerability_sources_row(
    sources: &[crate::project::advisory_file::DataSource],
    report_locale: &Value,
) -> String {
    if sources.is_empty() {
        return String::new();
    }
    let items: Vec<String> = sources
        .iter()
        .map(|s| {
            format!(
                "<a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">{}</a> ({})",
                escape(&s.url),
                escape(&s.name),
                escape(&s.license)
            )
        })
        .collect();
    format!(
        "<div class=\"param-item param-full\">\n            <span class=\"param-label\">{}</span>\n            <span class=\"param-value\">{}</span>\n        </div>",
        escape(&t(report_locale, "audit_params.vulnerability_sources")),
        items.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;
    use crate::report::compliance_html::HealthThresholds;
    use std::collections::BTreeMap;

    fn base_info() -> AuditParamsInfo {
        AuditParamsInfo {
            languages: vec!["python".to_string()],
            include_paths: vec![],
            exclude_patterns: vec![],
            quick_mode: false,
            only_category: None,
            disabled_rules: vec![],
            with_tests: false,
            with_deps: false,
            dependencies: DependencyCheck::NotRun,
            database_configured: false,
            vulnerability_sources: vec![],
            severity_levels: None,
            report_lang: "en".to_string(),
        }
    }

    /// ADR-0051: the databases of the version rules are credited with a
    /// link and their license, escaped; no row without them.
    #[test]
    fn test_vulnerability_sources_are_credited_with_their_license() {
        let locale = load_report_locale("en");
        assert_eq!(vulnerability_sources_row(&[], &locale), "");
        let row = vulnerability_sources_row(
            &[crate::project::advisory_file::DataSource {
                name: "GitHub Advisory Database <GHSA>".to_string(),
                url: "https://github.com/advisories".to_string(),
                license: "CC-BY-4.0".to_string(),
                records: 3,
            }],
            &locale,
        );
        assert!(
            row.contains(&escape(&t(&locale, "audit_params.vulnerability_sources"))),
            "{row}"
        );
        assert!(
            row.contains(r#"href="https://github.com/advisories""#),
            "{row}"
        );
        assert!(
            row.contains("GitHub Advisory Database &lt;GHSA&gt;</a> (CC-BY-4.0)"),
            "{row}"
        );
    }

    /// Builds a minimal `ReportContext` for the tests — only the 5
    /// project identity fields vary from one test to another, the
    /// rest (out of scope for this section) is neutral.
    fn test_ctx<'a>(
        project_name: &str,
        project_version: &str,
        project_description: &str,
        project_uuid: &str,
        project_path: &str,
        rule_catalog: &'a crate::rules::identity::RuleCatalog,
    ) -> ReportContext<'a> {
        ReportContext {
            project_name: project_name.to_string(),
            project_version: project_version.to_string(),
            project_uuid: project_uuid.to_string(),
            project_description: project_description.to_string(),
            project_path: project_path.to_string(),
            tool_name: "CodeFixture".to_string(),
            tool_version: "2.0.0".to_string(),
            company_name: "CodeFixture SAS".to_string(),
            report_lang: "en".to_string(),
            date_str: String::new(),
            timestamp: String::new(),
            audit_total_time_secs: 0,
            total_lines_code: 0,
            total_files_scanned: 0,
            health_thresholds: HealthThresholds::default(),
            rule_catalog,
            history: &[],
        }
    }

    #[test]
    fn test_renders_project_identity() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx(
            "MyProject",
            "1.2.3",
            "A test project",
            "uuid-1234",
            "/home/user/myproject",
            &catalog,
        );
        let html = render_audit_params_html(&base_info(), &ctx, &en);
        assert!(html.contains("MyProject"));
        assert!(html.contains("v1.2.3"));
        assert!(html.contains("A test project"));
        assert!(html.contains("uuid-1234"));
        assert!(html.contains("/home/user/myproject"));
    }

    #[test]
    fn test_empty_include_paths_shows_all() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let html = render_audit_params_html(&base_info(), &ctx, &en);
        assert!(html.contains(&t(&en, "all")));
    }

    #[test]
    fn test_languages_rendered_as_code() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let mut info = base_info();
        info.languages = vec!["java".to_string(), "python".to_string()];
        let html = render_audit_params_html(&info, &ctx, &en);
        assert!(html.contains("<code>java</code>"));
        assert!(html.contains("<code>python</code>"));
    }

    #[test]
    fn test_no_languages_shows_none() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let mut info = base_info();
        info.languages = vec![];
        let html = render_audit_params_html(&info, &ctx, &en);
        assert!(html.contains(&t(&en, "none")));
    }

    #[test]
    fn test_quick_mode_label() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let mut info = base_info();
        info.quick_mode = true;
        let html = render_audit_params_html(&info, &ctx, &en);
        assert!(html.contains(&t(&en, "mode_quick")));
    }

    #[test]
    fn test_only_category_shown_and_others_disabled() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let mut info = base_info();
        info.only_category = Some("security".to_string());
        let html = render_audit_params_html(&info, &ctx, &en);
        assert!(html.contains("<code>security</code>"));
        // The SECURITY badge must be "enabled", the others "disabled".
        assert!(html.contains(r#"cat-badge enabled"#));
        assert!(html.contains(r#"cat-badge disabled"#));
    }

    #[test]
    fn test_disabled_rules_sorted_and_listed() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let mut info = base_info();
        info.disabled_rules = vec!["zeta_rule".to_string(), "alpha_rule".to_string()];
        let html = render_audit_params_html(&info, &ctx, &en);
        let alpha_pos = html.find("alpha_rule").unwrap();
        let zeta_pos = html.find("zeta_rule").unwrap();
        assert!(alpha_pos < zeta_pos, "triés alphabétiquement");
    }

    /// Shared binary (ticket #188): its part of the checklist names only
    /// options of its `scan --help`, whatever ran (here the dependencies
    /// phase, started by a pack with version rules). The private binary
    /// adds its own after it (`cli_options_html`).
    #[test]
    fn test_shared_cli_options_name_only_shared_binary_options() {
        let en = load_report_locale("en");
        let mut info = base_info();
        info.dependencies = DependencyCheck::Checked;
        info.with_tests = true;
        info.disabled_rules = vec!["some_rule".to_string()];
        info.severity_levels = Some(vec!["HIGH".to_string()]);
        let html = shared_cli_options_html(&info, &en);
        for absent in [
            "--with-deps",
            "--with-tests",
            "--severity",
            "--disable-rule",
            "--db-host",
        ] {
            assert!(!html.contains(absent), "{absent} is not a shared option");
        }
        for present in ["--quick", "--only-category", "--lang en"] {
            assert!(html.contains(present), "{present} is a shared option");
        }
    }

    /// The "Dependencies" row says what the phase did, in the report
    /// language, for each outcome (ticket #188).
    #[test]
    fn test_dependencies_row_says_what_ran() {
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        for lang in ["en", "fr", "es", "de"] {
            let locale = load_report_locale(lang);
            assert!(
                render_audit_params_html(&base_info(), &ctx, &locale)
                    .contains(&escape(&t(&locale, "audit_params.dependencies")))
            );
            for check in [
                DependencyCheck::NotRun,
                DependencyCheck::Checked,
                DependencyCheck::VersionsNotChecked,
            ] {
                let mut info = base_info();
                info.dependencies = check;
                let html = render_audit_params_html(&info, &ctx, &locale);
                let label = t(&locale, check.i18n_key());
                assert_ne!(label, check.i18n_key(), "{lang}: missing locale key");
                assert!(html.contains(&escape(&label)), "{lang} {check:?}");
            }
        }
        // The three outcomes read differently.
        let en = load_report_locale("en");
        let labels: std::collections::BTreeSet<_> = [
            DependencyCheck::NotRun,
            DependencyCheck::Checked,
            DependencyCheck::VersionsNotChecked,
        ]
        .iter()
        .map(|c| t(&en, c.i18n_key()))
        .collect();
        assert_eq!(labels.len(), 3);
    }

    #[test]
    fn test_extensions_reflect_detected_languages() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let ctx = test_ctx("P", "", "", "", "/root", &catalog);
        let mut info = base_info();
        info.languages = vec!["php".to_string()];
        let html = render_audit_params_html(&info, &ctx, &en);
        assert!(html.contains("<code>.php</code>"));
    }

    /// Ticket #285: every language lists the files the discovery reads
    /// for it — HTML templates (Razor views among them), C#, YAML, the
    /// Dockerfile names and the configuration files of their language.
    #[test]
    fn test_language_files_follow_the_discovery_lists() {
        let html = language_files("html");
        for ext in [".html", ".htm", ".vue", ".cshtml", ".razor"] {
            assert!(html.contains(&ext.to_string()), "{ext}: {html:?}");
        }
        assert_eq!(language_files("csharp"), [".cs", "web.config"]);
        assert_eq!(language_files("yaml"), [".yml", ".yaml"]);
        assert_eq!(
            language_files("dockerfile"),
            ["Dockerfile", "Dockerfile.dev", "Dockerfile.prod"]
        );
        assert!(language_files("javascript").contains(&".tsx".to_string()));
        assert!(language_files("unknown").is_empty());
        let row = extensions_for(&["csharp".to_string(), "html".to_string()]);
        assert!(
            row.contains("<code>csharp</code>: <code>.cs</code>"),
            "{row}"
        );
        assert!(row.contains("<code>.razor</code>"), "{row}");
    }
}
