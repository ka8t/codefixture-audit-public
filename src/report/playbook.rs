//! Inline remediation playbook (diagnostic/fix/verification steps +
//! CWE/CVE/OWASP/ISO27001/WCAG references) — port of
//! `_load_playbook`/`_render_playbook_inline` (`Audit/sca/report.py`).
//!
//! `resources/remediation-playbook.json` (560 rules) is static and
//! embedded at compile time — same choice as the other report
//! resources (`report_assets.rs`, `compliance.rs`).

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use crate::i18n::t;
use crate::report::exports::sarif::ReportFinding;
use crate::report::text::escape;

const PLAYBOOK_JSON: &str = include_str!("../../resources/remediation-playbook.json");

#[derive(Debug, Deserialize)]
struct PlaybookStep {
    action: String,
    /// Translations of a rule-specific step (`fr`, `es`, `de`); the two
    /// generic steps and the fix step are translated elsewhere (see
    /// `step_text`).
    #[serde(default)]
    action_i18n: BTreeMap<String, String>,
    #[serde(rename = "type")]
    step_type: String,
}

/// The references of a playbook entry, every one shown in the report.
///
/// No CWE: a rule's CWE is read from the rule itself (ticket #215, see
/// `render_playbook_inline`). No CVE: no entry ever held one (a
/// dependency's CVE comes from the advisory database and is written in
/// its finding's own texts), so the Python report's CVE links never
/// rendered and were removed (2026-11-19).
///
/// `deny_unknown_fields`: a reference key the report does not show makes
/// the embedded playbook fail to load, naming the key, instead of being
/// dropped without a word. `iso25010` was dropped that way, from ten
/// accessibility entries, until 2026-11-19.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct PlaybookRefs {
    owasp: Option<String>,
    iso27001: Option<Vec<String>>,
    /// ISO/IEC 25010 quality characteristic, as `Characteristic.Sub`
    /// (`Usability.Accessibility`).
    iso25010: Option<String>,
    wcag: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct PlaybookEntry {
    #[serde(default)]
    steps: Vec<PlaybookStep>,
    #[serde(default)]
    references: PlaybookRefs,
    #[serde(default)]
    benefit: String,
}

#[derive(Debug, Deserialize)]
struct PlaybookFile {
    rules: BTreeMap<String, PlaybookEntry>,
}

fn load_playbook() -> PlaybookFile {
    serde_json::from_str(PLAYBOOK_JSON).expect("invalid embedded remediation-playbook.json")
}

/// A JSON value that can be either a single string or a list of
/// strings on the Python side (`isinstance(x, str)`/`isinstance(x,
/// list)`).
fn as_string_list(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(|i| i.as_str().map(|s| s.to_string()))
            .collect(),
        _ => vec![],
    }
}

/// One CWE reference of the playbook block: a link to its MITRE page for
/// a well-formed id (`CWE-` and a number), the escaped text otherwise. A
/// client rule writes its own `metadata cwe`, so the value is not trusted
/// to be either.
fn cwe_reference(id: &str) -> String {
    let number = id
        .strip_prefix("CWE-")
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    match number {
        Some(n) => format!(
            r#"<a href="https://cwe.mitre.org/data/definitions/{n}.html" target="_blank" class="playbook-ref">{}</a> "#,
            escape(id)
        ),
        None => format!(r#"<span class="playbook-ref">{}</span> "#, escape(id)),
    }
}

/// The W3C "Understanding WCAG 2.1" page of each success criterion the
/// playbook cites, checked on w3.org on 2026-11-19. The pages are named
/// after the criterion's title, not its number, so the link cannot be
/// built from the number (ticket #217).
const WCAG_PAGES: [(&str, &str); 9] = [
    ("1.2.2", "captions-prerecorded"),
    ("1.3.1", "info-and-relationships"),
    ("1.3.5", "identify-input-purpose"),
    ("1.3.6", "identify-purpose"),
    ("1.4.4", "resize-text"),
    ("2.4.1", "bypass-blocks"),
    ("3.1.1", "language-of-page"),
    ("3.1.2", "language-of-parts"),
    ("4.1.2", "name-role-value"),
];

/// The criterion numbers of a playbook `wcag` value. The file writes a
/// string or a list, each item one or several criteria separated by
/// commas, each with or without a `WCAG ` prefix (`"WCAG 1.3.1, WCAG
/// 4.1.2"`).
///
/// Deliberate deviation from the Python report, which used each item
/// whole: it showed "WCAG WCAG 1.3.1, WCAG 4.1.2" with a link to a page
/// that does not exist (ticket #217).
fn wcag_criteria(value: &Value) -> Vec<String> {
    as_string_list(value)
        .iter()
        .flat_map(|item| item.split(','))
        .map(|c| c.trim().trim_start_matches("WCAG").trim().to_string())
        .filter(|c| !c.is_empty())
        .collect()
}

/// One WCAG reference: a link to its W3C page when [`WCAG_PAGES`] knows
/// the criterion, the plain number otherwise (a test keeps every
/// criterion of the playbook in the table).
fn wcag_reference(number: &str) -> String {
    match WCAG_PAGES.iter().find(|(n, _)| *n == number) {
        Some((_, page)) => format!(
            r#"<a href="https://www.w3.org/WAI/WCAG21/Understanding/{page}" target="_blank" class="playbook-ref">WCAG {}</a> "#,
            escape(number)
        ),
        None => format!(
            r#"<span class="playbook-ref">WCAG {}</span> "#,
            escape(number)
        ),
    }
}

fn step_icon(step_type: &str) -> &'static str {
    match step_type {
        "diagnostic" => "🔍",
        "code_change" => "🔧",
        "verification" => "✅",
        _ => "▸",
    }
}

/// What the findings of a rule point at: it decides the text of the
/// playbook's generic first step (ticket #216).
///
/// Deliberate deviation from the Python report, which shows "Locate the
/// vulnerable code pattern in the file" for every rule: a whole-file rule
/// (`file_too_long`, `workflow_not_in_codeowners`, `unreviewed_vendor_code`)
/// has no code pattern to locate, and the step sent readers looking for
/// one above cards that say "whole file" (#214).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingTarget {
    /// Findings on lines of the file: the generic step stands.
    Lines,
    /// Findings about the whole file, for its place or content.
    WholeFile,
    /// Findings about the whole file, for its length (`min_lines`).
    FileLength,
}

impl FindingTarget {
    /// The target of a rule's findings. A rule produces either line
    /// findings or whole-file findings, never both, so the first one
    /// decides; the group is read as lines unless every finding is about
    /// the whole file, so a mixed group would keep the generic step.
    pub fn of(findings: &[&ReportFinding]) -> Self {
        if findings.is_empty() || findings.iter().any(|f| f.file_scope.is_none()) {
            return Self::Lines;
        }
        if findings
            .iter()
            .all(|f| f.file_scope.is_some_and(|s| s.min_lines.is_some()))
        {
            Self::FileLength
        } else {
            Self::WholeFile
        }
    }
}

/// The playbook of a rule that has no entry: the three steps every entry
/// starts from (`create-rule` writes them for a new rule), no reference of
/// its own and no benefit, so the rule's solution, benefit and CWE fill it
/// in `render_playbook_inline` (ticket #217).
fn derived_entry() -> PlaybookEntry {
    let step = |action: &str, step_type: &str| PlaybookStep {
        action: action.to_string(),
        action_i18n: BTreeMap::new(),
        step_type: step_type.to_string(),
    };
    PlaybookEntry {
        steps: vec![
            step(LOCATE, "diagnostic"),
            // Replaced by the rule's solution (`step_text`); this English
            // text only shows when the rule has none.
            step(APPLY, "code_change"),
            step(RERUN, "verification"),
        ],
        references: PlaybookRefs::default(),
        benefit: String::new(),
    }
}

/// The generic first step of a playbook entry, as the file writes it.
const LOCATE: &str = "Locate the vulnerable code pattern in the file";
/// The fix step of a derived entry, shown only for a rule with no
/// solution (a client rule may have none).
const APPLY: &str = "Apply the solution above.";
/// The generic last step of a playbook entry, as the file writes it.
const RERUN: &str = "Run the audit again to verify the finding is resolved";

/// The text of a playbook step in the report's language.
///
/// The fix step is the rule's own `solution` in the report's language,
/// in English too: the playbook is keyed by rule id, and one entry serves
/// every language that has a rule of that id (a `multi` entry holds a
/// general step, an entry of another language that language's API), so
/// only the rule's own text names the right functions (issue #184,
/// 2026-11-17). The playbook file is written in English. In another
/// language: the two generic steps ("Locate…", "Run the audit again…")
/// come from the report locale and a rule-specific step uses its
/// `action_i18n`. English text stays only as a last resort. Fixed after a
/// French report showed an English playbook (2026-11-14); the Python
/// report has the same English-only playbook.
///
/// The generic "Locate…" step depends on `target`: for whole-file
/// findings it says what to look at in the file instead, in every
/// language, English included (ticket #216).
fn step_text(
    step: &PlaybookStep,
    lang: &str,
    report_locale: &Value,
    solution: Option<&str>,
    target: FindingTarget,
) -> String {
    if step.step_type == "code_change"
        && let Some(own) = solution.filter(|s| !s.is_empty())
    {
        return own.to_string();
    }
    if step.step_type == "diagnostic" && step.action == LOCATE {
        match target {
            FindingTarget::Lines => {}
            FindingTarget::WholeFile => return t(report_locale, "playbook_step_locate_file"),
            FindingTarget::FileLength => {
                return t(report_locale, "playbook_step_locate_long_file");
            }
        }
    }
    if lang == "en" {
        return step.action.clone();
    }
    match step.step_type.as_str() {
        "diagnostic" if step.action == LOCATE => t(report_locale, "playbook_step_locate"),
        "verification" if step.action == RERUN => t(report_locale, "playbook_step_rerun"),
        "code_change" if step.action == APPLY => t(report_locale, "playbook_step_apply_solution"),
        "code_change" => step.action.clone(),
        _ => step
            .action_i18n
            .get(lang)
            .cloned()
            .unwrap_or_else(|| step.action.clone()),
    }
}

/// Renders the playbook of `rule_key` in the report's language.
/// `solution` and `benefit` are the rule's own texts, already in that
/// language (`ReportFinding`): they replace the English copies the
/// playbook file holds. `target` is what the rule's findings point at
/// ([`FindingTarget::of`]). `cwe` is the CWE of the rule
/// (`ReportFinding::cwe`, its `metadata cwe`) — port of
/// `_render_playbook_inline`.
///
/// A rule without a playbook entry gets the playbook every entry is
/// derived from (`create-rule` writes the same one): locate, the rule's
/// solution, run the audit again, with the rule's benefit and CWE.
/// Deliberate deviation from the Python report, which shows nothing for
/// such a rule: 62 catalog rules with a CWE had no entry, so the HTML
/// report showed their CWE nowhere (ticket #217). Only for a rule of the
/// scan's catalog, builtin or client (`in_catalog`): another key without
/// an entry, which no rule describes, shows nothing.
///
/// Every ISO 27001 control and WCAG criterion of the entry is shown: the
/// Python report kept the first three, and five entries list four ISO
/// controls, the fourth dropped without a word (ticket #217).
///
/// Deliberate deviation from the Python report, which shows the CWE of
/// the playbook entry: the playbook held its own copy, which differed from
/// the rule's for 34 rules and was missing for 40 others (measured
/// 2026-11-19), and one entry serves the rules of the same id in every
/// language. The rule file is the only source of a rule's CWE, as it is of
/// its texts (ticket #215).
pub fn render_playbook_inline(
    rule_key: &str,
    report_locale: &Value,
    solution: Option<&str>,
    benefit: &str,
    target: FindingTarget,
    cwe: &[String],
    in_catalog: bool,
) -> String {
    let lang = t(report_locale, "locale_code");
    let playbook = load_playbook();
    let derived;
    let entry = match playbook.rules.get(rule_key) {
        Some(entry) => entry,
        None if in_catalog => {
            derived = derived_entry();
            &derived
        }
        None => return String::new(),
    };
    if entry.steps.is_empty() && cwe.is_empty() {
        return String::new();
    }

    let label = t(report_locale, "playbook_link");

    let steps_html: String = entry
        .steps
        .iter()
        .map(|s| {
            format!(
                "<li>{} {}</li>",
                step_icon(&s.step_type),
                escape(&step_text(s, &lang, report_locale, solution, target))
            )
        })
        .collect();

    let mut refs_html = String::new();
    if let Some(owasp) = &entry.references.owasp {
        refs_html.push_str(&format!(
            r#"<span class="playbook-ref">{}</span> "#,
            escape(owasp)
        ));
    }
    if let Some(iso) = &entry.references.iso27001 {
        refs_html.push_str(&format!(
            r#"<span class="playbook-ref">ISO {}</span> "#,
            escape(&iso.join(", "))
        ));
    }
    if let Some(quality) = &entry.references.iso25010 {
        // `Usability.Accessibility` reads as the characteristic and its
        // sub-characteristic.
        refs_html.push_str(&format!(
            r#"<span class="playbook-ref">ISO 25010 {}</span> "#,
            escape(&quality.replace('.', " › "))
        ));
    }
    if let Some(wcag) = &entry.references.wcag {
        for number in wcag_criteria(wcag) {
            refs_html.push_str(&wcag_reference(&number));
        }
    }

    // The rule's own benefit, in every language, for the reason of
    // `step_text`; the playbook's copy only when the rule has none.
    let benefit = if !benefit.is_empty() {
        benefit
    } else {
        entry.benefit.as_str()
    };
    let benefit_html = if !benefit.is_empty() {
        format!(r#"<p class="playbook-benefit">💡 {}</p>"#, escape(benefit))
    } else {
        String::new()
    };

    let cwe_html = cwe_list(cwe, report_locale);
    format!(
        r#"<details class="playbook-details"><summary>📋 {label}</summary><ol class="playbook-steps">{steps_html}</ol>{benefit_html}{cwe_html}<div class="playbook-refs">{refs_html}</div></details>"#
    )
}

/// The CWEs of a finding with their names and attack patterns, from the
/// catalog embedded in the engine (ADR-0070): one line per CWE, its id
/// linked to MITRE's page, its name as MITRE writes it (MITRE publishes in
/// English only), "deprecated by MITRE" for an entry MITRE removed, then
/// the CAPEC attack patterns it points to, each linked. A CWE the catalog
/// does not hold keeps its id alone, as before. Empty without CWE.
fn cwe_list(cwe: &[String], report_locale: &Value) -> String {
    if cwe.is_empty() {
        return String::new();
    }
    let items: String = cwe
        .iter()
        .map(|id| {
            let reference = cwe_reference(id);
            let Some(entry) = crate::report::cwe_catalog::weakness(id) else {
                return format!("<li>{reference}</li>");
            };
            let deprecated = if entry.is_deprecated() {
                format!(
                    r#" <em class="playbook-cwe-deprecated">({})</em>"#,
                    escape(&t(report_locale, "playbook_cwe_deprecated"))
                )
            } else {
                String::new()
            };
            let patterns: Vec<String> = crate::report::cwe_catalog::attack_patterns(id)
                .into_iter()
                .map(|(capec, pattern)| capec_reference(capec, pattern.map(|p| p.name.as_str())))
                .collect();
            let patterns_html = if patterns.is_empty() {
                String::new()
            } else {
                format!(
                    r#"<div class="playbook-capec">{} {}</div>"#,
                    escape(&t(report_locale, "playbook_attack_patterns")),
                    patterns.join(" · ")
                )
            };
            format!(
                "<li>{reference}{}{deprecated}{patterns_html}</li>",
                escape(&entry.name)
            )
        })
        .collect();
    format!(r#"<ul class="playbook-cwe">{items}</ul>"#)
}

/// One CAPEC attack pattern: its id linked to MITRE's page, then its name
/// when the CAPEC catalog holds it.
fn capec_reference(id: &str, name: Option<&str>) -> String {
    let number = id
        .strip_prefix("CAPEC-")
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    let link = match number {
        Some(n) => format!(
            r#"<a href="https://capec.mitre.org/data/definitions/{n}.html" target="_blank" rel="noopener noreferrer">{}</a>"#,
            escape(id)
        ),
        None => escape(id),
    };
    match name {
        Some(name) => format!("{link} {}", escape(name)),
        None => link,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;

    /// The embedded playbook parses and its `total_rules` header matches
    /// the entries it holds (it said 204 for 225 entries before #157,
    /// which filled one entry per security rule of the catalog).
    #[test]
    fn test_playbook_loads_and_total_rules_matches() {
        let p = load_playbook();
        let header: Value = serde_json::from_str(PLAYBOOK_JSON).unwrap();
        assert_eq!(
            header["total_rules"].as_u64(),
            Some(p.rules.len() as u64),
            "total_rules is stale"
        );
        assert!(p.rules.len() >= 560, "{}", p.rules.len());
    }

    #[test]
    fn test_render_playbook_in_french_has_no_english_step() {
        // A French report showed this playbook in English (2026-11-14).
        let fr = load_report_locale("fr");
        let html = render_playbook_inline(
            "html_th_scope_missing",
            &fr,
            Some("Ajoutez scope=\"col\" ou scope=\"row\"."),
            "Rend les tableaux lisibles au lecteur d'écran.",
            FindingTarget::Lines,
            &[],
            false,
        );
        assert!(
            html.contains("Repérez tous les éléments &lt;th&gt;"),
            "{html}"
        );
        assert!(html.contains("Ajoutez scope="), "{html}");
        assert!(html.contains("Rend les tableaux lisibles"), "{html}");
        // `escape` encodes `'` as `&#39;` since the 2026-11-15 security fix.
        assert!(
            html.contains("lecteur d&#39;écran")
                || html.contains("lecteur d&#x27;écran")
                || html.contains("lecteur d'écran"),
            "{html}"
        );
        for english in ["Find all", "Test with a screen reader", "Run the audit"] {
            assert!(!html.contains(english), "{english}: {html}");
        }
        let generic = render_playbook_inline(
            "xss_unsafe_html_construction",
            &fr,
            None,
            "",
            FindingTarget::Lines,
            &[],
            false,
        );
        assert!(generic.contains("Repérez le code vulnérable"), "{generic}");
        assert!(generic.contains("Relancez l"), "{generic}");
    }

    /// An entry serves every rule of its id: in English too, the fix step
    /// and the benefit are the rule's own texts, so a JavaScript finding
    /// never shows the Python API of an entry written for Python.
    #[test]
    fn test_render_playbook_in_english_uses_the_rules_own_texts() {
        let en = load_report_locale("en");
        let html = render_playbook_inline(
            "insecure_cookie",
            &en,
            Some("Pass httpOnly: true and secure: true to res.cookie()."),
            "Scripts can no longer read the cookie.",
            FindingTarget::Lines,
            &[],
            false,
        );
        assert!(html.contains("Pass httpOnly: true"), "{html}");
        assert!(
            html.contains("Scripts can no longer read the cookie."),
            "{html}"
        );
        assert!(!html.contains("set_cookie"), "{html}");
        assert!(
            html.contains("Locate the vulnerable code pattern"),
            "{html}"
        );
    }

    /// A whole-file finding of `file_too_long` (`min_lines` 500) or of a
    /// governance rule (no threshold).
    fn whole_file(min_lines: Option<usize>) -> ReportFinding {
        serde_json::from_value(serde_json::json!({
            "rule_key": "file_too_long", "rule_name": "file_too_long",
            "category": "ARCH", "severity": "LOW", "risk": "", "file": "a.py",
            "line": 1, "solution": null, "cwe": [], "owasp": null,
            "taint_flow": null, "code": "import os", "context_before": "",
            "context_after": "", "confidence": 80, "benefit": "",
            "committer": null, "rule_source": "json_builtin",
            "file_scope": {"line_count": 812, "min_lines": min_lines},
        }))
        .expect("valid ReportFinding")
    }

    /// Ticket #216: the target of a group is whole-file only when every
    /// finding is, and a length rule only when every finding has a
    /// threshold.
    #[test]
    fn test_finding_target_of_groups() {
        let long = whole_file(Some(500));
        let governance = whole_file(None);
        let mut line = whole_file(None);
        line.file_scope = None;
        assert_eq!(FindingTarget::of(&[]), FindingTarget::Lines);
        assert_eq!(FindingTarget::of(&[&line]), FindingTarget::Lines);
        assert_eq!(FindingTarget::of(&[&long, &line]), FindingTarget::Lines);
        assert_eq!(
            FindingTarget::of(&[&long, &long]),
            FindingTarget::FileLength
        );
        assert_eq!(FindingTarget::of(&[&governance]), FindingTarget::WholeFile);
        assert_eq!(
            FindingTarget::of(&[&long, &governance]),
            FindingTarget::WholeFile
        );
    }

    /// Ticket #216: for whole-file findings the first step no longer asks
    /// to locate a code pattern, in English as in another language.
    #[test]
    fn test_render_playbook_whole_file_first_step() {
        let en = load_report_locale("en");
        let fr = load_report_locale("fr");
        let long = render_playbook_inline(
            "file_too_long",
            &fr,
            None,
            "",
            FindingTarget::FileLength,
            &[],
            false,
        );
        assert!(
            long.contains("Ouvrez chaque fichier cité ci-dessous et notez les sujets"),
            "{long}"
        );
        assert!(!long.contains("Repérez le code vulnérable"), "{long}");
        let governance = render_playbook_inline(
            "workflow_not_in_codeowners",
            &en,
            None,
            "",
            FindingTarget::WholeFile,
            &[],
            false,
        );
        assert!(
            governance.contains("the rule is about the file as a whole"),
            "{governance}"
        );
        assert!(
            !governance.contains("Locate the vulnerable code pattern"),
            "{governance}"
        );
        // The other steps are unchanged.
        assert!(governance.contains("Run the audit again"), "{governance}");
    }

    #[test]
    fn test_render_playbook_known_rule() {
        let en = load_report_locale("en");
        let html = render_playbook_inline(
            "autoplay_media",
            &en,
            None,
            "",
            FindingTarget::Lines,
            &[],
            false,
        );
        assert!(html.contains("playbook-details"));
        assert!(html.contains("Locate the vulnerable code pattern"));
        assert!(html.contains("playbook-benefit"));
    }

    /// Ticket #215: the block shows the rule's CWE, each with its MITRE
    /// link, and nothing else: the playbook no longer holds one.
    #[test]
    fn test_render_playbook_cwe_reference_link() {
        let en = load_report_locale("en");
        let cwe = ["CWE-396".to_string(), "CWE-390".to_string()];
        let html = render_playbook_inline(
            "catch_all_exception",
            &en,
            None,
            "",
            FindingTarget::Lines,
            &cwe,
            false,
        );
        assert!(html.contains("https://cwe.mitre.org/data/definitions/396.html"));
        assert!(html.contains("https://cwe.mitre.org/data/definitions/390.html"));
        let none = render_playbook_inline(
            "catch_all_exception",
            &en,
            None,
            "",
            FindingTarget::Lines,
            &[],
            false,
        );
        assert!(!none.contains("CWE-"), "{none}");
    }

    /// ADR-0070: each CWE comes with MITRE's name and its CAPEC attack
    /// patterns, linked; a deprecated entry says so in the report's
    /// language; an id the catalog lacks keeps its id alone.
    #[test]
    fn test_cwe_list_names_weaknesses_and_attack_patterns() {
        let fr = load_report_locale("fr");
        let cwe = [
            "CWE-89".to_string(),
            "CWE-247".to_string(),
            "CWE-999999".to_string(),
        ];
        let html = cwe_list(&cwe, &fr);
        let sql = crate::report::cwe_catalog::weakness("CWE-89").unwrap();
        assert!(html.contains(&escape(&sql.name)), "{html}");
        let (capec, pattern) = crate::report::cwe_catalog::attack_patterns("CWE-89")[0];
        let number = capec.trim_start_matches("CAPEC-");
        assert!(
            html.contains(&format!("capec.mitre.org/data/definitions/{number}.html")),
            "{html}"
        );
        assert!(html.contains(&escape(&pattern.unwrap().name)), "{html}");
        assert!(
            html.contains(&escape(&t(&fr, "playbook_attack_patterns"))),
            "{html}"
        );
        assert!(html.contains("(retiré par MITRE)"), "{html}");
        assert!(
            html.contains("<li><a href=\"https://cwe.mitre.org/data/definitions/999999.html\""),
            "{html}"
        );
        assert_eq!(cwe_list(&[], &fr), "");
    }

    /// Ticket #215: a client rule's CWE is escaped, and linked only when
    /// it is `CWE-` and a number.
    #[test]
    fn test_cwe_reference_escapes_and_links_only_a_well_formed_id() {
        assert!(cwe_reference("CWE-79").contains("definitions/79.html"));
        let odd = cwe_reference("<b>CWE-x</b>");
        assert!(!odd.contains("href"), "{odd}");
        assert!(odd.contains("&lt;b&gt;"), "{odd}");
        assert!(!cwe_reference("CWE-").contains("href"));
    }

    /// Ticket #215: no playbook entry holds a CWE of its own any more, so
    /// it cannot differ from the rule's again.
    #[test]
    fn test_playbook_entries_hold_no_cwe() {
        let raw: Value = serde_json::from_str(PLAYBOOK_JSON).unwrap();
        let with_cwe: Vec<&String> = raw["rules"]
            .as_object()
            .unwrap()
            .iter()
            .filter(|(_, e)| {
                e.get("references")
                    .is_some_and(|r| r.get("cwe").is_some() || r.get("cwe_url").is_some())
            })
            .map(|(k, _)| k)
            .collect();
        assert!(with_cwe.is_empty(), "{with_cwe:?}");
    }

    /// The references a playbook entry holds besides the rule's CWE:
    /// OWASP and ISO 27001 (`PlaybookRefs`), from the embedded playbook.
    #[test]
    fn test_render_playbook_shows_owasp_and_iso_references() {
        let en = load_report_locale("en");
        let html = render_playbook_inline(
            "command_injection_csharp",
            &en,
            None,
            "",
            FindingTarget::Lines,
            &[],
            false,
        );
        assert!(
            html.contains(r#"<span class="playbook-ref">A03:2021</span>"#),
            "{html}"
        );
        assert!(
            html.contains(r#"<span class="playbook-ref">ISO A.8.28, A.8.26</span>"#),
            "{html}"
        );
    }

    /// Ticket #217: a catalog rule without a playbook entry gets the
    /// derived playbook, filled with its solution, benefit and CWE.
    #[test]
    fn test_rule_without_entry_gets_the_derived_playbook() {
        let fr = load_report_locale("fr");
        let cwe = ["CWE-396".to_string()];
        let html = render_playbook_inline(
            "rule_without_entry_xyz",
            &fr,
            Some("Attrapez seulement les erreurs attendues."),
            "Les vraies pannes restent visibles.",
            FindingTarget::Lines,
            &cwe,
            true,
        );
        for text in [
            "Repérez le code vulnérable",
            "Attrapez seulement les erreurs attendues.",
            "Relancez l",
            "Les vraies pannes restent visibles.",
            "definitions/396.html",
        ] {
            assert!(html.contains(text), "{text}: {html}");
        }
        // Without a solution, the fix step is still in the report's language.
        let bare = render_playbook_inline(
            "rule_without_entry_xyz",
            &fr,
            None,
            "",
            FindingTarget::Lines,
            &[],
            true,
        );
        assert!(bare.contains("Appliquez la solution ci-dessus."), "{bare}");
    }

    /// Ticket #217: every ISO 27001 control of an entry is shown, not the
    /// first three (`hardcoded_secret` lists four).
    #[test]
    fn test_render_playbook_shows_every_iso_control() {
        let en = load_report_locale("en");
        let raw: Value = serde_json::from_str(PLAYBOOK_JSON).unwrap();
        let iso: Vec<String> = raw["rules"]["hardcoded_secret"]["references"]["iso27001"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(iso.len(), 4);
        let html = render_playbook_inline(
            "hardcoded_secret",
            &en,
            None,
            "",
            FindingTarget::Lines,
            &[],
            true,
        );
        assert!(html.contains(&format!("ISO {}", iso.join(", "))), "{html}");
    }

    /// Ticket #217: each WCAG criterion gets its own link to its W3C page,
    /// and every criterion the playbook cites is in [`WCAG_PAGES`].
    #[test]
    fn test_wcag_references_link_each_criterion() {
        let en = load_report_locale("en");
        let html = render_playbook_inline(
            "html_aria_hidden_focusable",
            &en,
            None,
            "",
            FindingTarget::Lines,
            &[],
            true,
        );
        assert!(html.contains(r#"Understanding/info-and-relationships" target="_blank" class="playbook-ref">WCAG 1.3.1</a>"#), "{html}");
        assert!(html.contains(r#"Understanding/name-role-value" target="_blank" class="playbook-ref">WCAG 4.1.2</a>"#), "{html}");
        assert!(!html.contains("WCAG WCAG"), "{html}");
        assert_eq!(
            wcag_criteria(&serde_json::json!(["WCAG 1.3.6, WCAG 2.4.1", "3.1.1"])),
            ["1.3.6", "2.4.1", "3.1.1"]
        );
        assert!(
            wcag_reference("9.9.9").contains("<span"),
            "unknown criterion stays text"
        );
        let raw: Value = serde_json::from_str(PLAYBOOK_JSON).unwrap();
        for (rule, entry) in raw["rules"].as_object().unwrap() {
            if let Some(w) = entry.get("references").and_then(|r| r.get("wcag")) {
                for number in wcag_criteria(w) {
                    assert!(
                        WCAG_PAGES.iter().any(|(n, _)| *n == number),
                        "{rule}: WCAG {number} has no page in WCAG_PAGES"
                    );
                }
            }
        }
    }

    /// The ISO 25010 quality characteristic of an accessibility entry is
    /// shown, not dropped (2026-11-19).
    #[test]
    fn test_render_playbook_shows_iso25010() {
        let en = load_report_locale("en");
        let html = render_playbook_inline(
            "html_th_scope_missing",
            &en,
            None,
            "",
            FindingTarget::Lines,
            &[],
            true,
        );
        assert!(
            html.contains(
                r#"<span class="playbook-ref">ISO 25010 Usability › Accessibility</span>"#
            ),
            "{html}"
        );
    }

    /// A reference key the report does not show makes the playbook fail
    /// to load, naming it, instead of being dropped (`deny_unknown_fields`).
    #[test]
    fn test_unknown_reference_key_is_refused() {
        let err = serde_json::from_str::<PlaybookRefs>(r#"{"cve": ["CVE-2021-44228"]}"#)
            .expect_err("an unknown key is refused");
        assert!(err.to_string().contains("cve"), "{err}");
        // The embedded playbook only holds keys the report shows.
        load_playbook();
    }

    #[test]
    fn test_render_playbook_unknown_rule_is_empty() {
        let en = load_report_locale("en");
        assert_eq!(
            render_playbook_inline(
                "does_not_exist_xyz",
                &en,
                None,
                "",
                FindingTarget::Lines,
                &[],
                false
            ),
            ""
        );
    }
}
