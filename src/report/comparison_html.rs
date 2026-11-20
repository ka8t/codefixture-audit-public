//! HTML rendering of the baseline comparison section — port of the
//! `comparison_html` block of `_generate_html` (`Audit/sca/report.py`).

use serde_json::Value;

use crate::i18n::t;
use crate::report::comparison::ComparisonResult;
use crate::report::data::ReportData;
use crate::report::exports::sarif::ReportFinding;
use crate::report::report_assets::load_template;
use crate::report::text::escape;

fn format_delta(d: i64) -> String {
    let (class, value) = if d > 0 {
        ("negative", format!("+{d}"))
    } else if d < 0 {
        ("positive", d.to_string())
    } else {
        ("neutral", "±0".to_string())
    };
    load_template("delta.html")
        .replace("{{class}}", class)
        .replace("{{value}}", &value)
}

fn render_finding_mini(f: &ReportFinding, resolved: bool, report_locale: &Value) -> String {
    let (severity_class, badge_class, badge_text) = if resolved {
        (
            "resolved".to_string(),
            "success".to_string(),
            format!("✓ {}", f.severity),
        )
    } else {
        (
            f.severity.to_lowercase(),
            f.severity.to_lowercase(),
            f.severity.clone(),
        )
    };
    load_template("finding-mini.html")
        .replace("{{severity_class}}", &severity_class)
        .replace("{{badge_class}}", &badge_class)
        .replace("{{badge_text}}", &badge_text)
        .replace("{{rule}}", &escape(&f.rule_name))
        // `file:line`, or the file alone for a whole-file finding
        // (ticket #214).
        .replace(
            "{{location}}",
            &escape(&crate::report::text::finding_location(f, report_locale)),
        )
}

/// The severities from the most to the least severe.
const SEVERITY_ORDER: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/// Most severe first, then by file. Python sorted HIGH, then MEDIUM, then
/// the rest, which put CRITICAL findings after the MEDIUM ones
/// (deliberate deviation, 2026-11-20).
fn sort_key(f: &ReportFinding) -> (usize, String) {
    let rank = SEVERITY_ORDER
        .iter()
        .position(|s| *s == f.severity)
        .unwrap_or(SEVERITY_ORDER.len());
    (rank, f.file.clone())
}

/// Number of `findings` of `severity`.
fn count_of(findings: &[ReportFinding], severity: &str) -> usize {
    findings.iter().filter(|f| f.severity == severity).count()
}

/// Synthesis table of the comparison, per severity: findings of the
/// baseline, those fixed since (number and share), those still to fix,
/// the new ones, and the current total. Added 2026-11-20 for a tester who
/// compares two versions of a project (`--baseline`): the section gave
/// the totals and the lists of new and resolved findings, but not how
/// many of the earlier findings were fixed, per severity.
///
/// The counts come from the matching of `compare_with_baseline`: a
/// baseline finding is fixed when no current finding matches it,
/// remaining when one does; it is counted at its current severity.
pub fn render_synthesis_table(comparison: &ComparisonResult, report_locale: &Value) -> String {
    let pct = |fixed: usize, base: usize| {
        if base == 0 {
            "—".to_string()
        } else {
            format!("{} %", (fixed as f64 * 100.0 / base as f64).round() as i64)
        }
    };
    let row = |label: String, fixed: usize, remaining: usize, new: usize, strong: bool| {
        let base = fixed + remaining;
        let (open, close) = if strong {
            ("<strong>", "</strong>")
        } else {
            ("", "")
        };
        format!(
            r#"<tr><td>{open}{label}{close}</td><td class="num">{open}{base}{close}</td><td class="num fixed">{open}{fixed} ({p}){close}</td><td class="num">{open}{remaining}{close}</td><td class="num added">{open}{new}{close}</td><td class="num">{open}{current}{close}</td></tr>"#,
            p = pct(fixed, base),
            current = remaining + new,
        )
    };
    let mut rows = String::new();
    for severity in SEVERITY_ORDER {
        rows.push_str(&row(
            t(
                report_locale,
                &format!("severity.{}", severity.to_lowercase()),
            ),
            count_of(&comparison.resolved_findings, severity),
            count_of(&comparison.unchanged_findings, severity),
            count_of(&comparison.new_findings, severity),
            false,
        ));
    }
    rows.push_str(&row(
        t(report_locale, "health_table_total"),
        comparison.resolved_findings.len(),
        comparison.unchanged_findings.len(),
        comparison.new_findings.len(),
        true,
    ));
    format!(
        r#"<div class="cmp-synthesis"><h3>{title}</h3><table class="health-calc-table"><thead><tr><th>{h_sev}</th><th class="num">{h_base}</th><th class="num">{h_fixed}</th><th class="num">{h_remaining}</th><th class="num">{h_new}</th><th class="num">{h_current}</th></tr></thead><tbody>{rows}</tbody></table><p class="health-table-note">{note}</p></div>"#,
        title = t(report_locale, "comparison_synthesis_title")
            .replace("{date}", &escape(&comparison.baseline_date)),
        h_sev = t(report_locale, "health_table_severity"),
        h_base = t(report_locale, "comparison_synthesis_baseline"),
        h_fixed = t(report_locale, "comparison_synthesis_fixed"),
        h_remaining = t(report_locale, "comparison_synthesis_remaining"),
        h_new = t(report_locale, "comparison_synthesis_new"),
        h_current = t(report_locale, "comparison_synthesis_current"),
        note = t(report_locale, "comparison_synthesis_note"),
    )
}

/// Generates the HTML comparison section — port of the
/// `comparison_html` block of `_generate_html`. The totals come from
/// `data` (already computed once by `compute_report_data` for the rest
/// of the report) rather than being duplicated as parameters.
pub fn render_comparison_html(
    comparison: &ComparisonResult,
    data: &ReportData,
    report_locale: &Value,
) -> String {
    let total_critical = data.total_critical;
    let total_high = data.total_high;
    let total_medium = data.total_medium;
    let total_low = data.total_low;
    // Deliberate improvement vs Python (whose comparison grid only
    // tracks HIGH/MEDIUM/LOW, see the 3-column `.cmp-sev-grid` on the
    // Audit side) — explicitly requested by the maintainer.
    let total_info = data.total_info;
    let total_findings = data.total_findings;

    let mut new_sorted = comparison.new_findings.clone();
    new_sorted.sort_by_key(sort_key);
    let new_items: String = new_sorted
        .iter()
        .map(|f| render_finding_mini(f, false, report_locale))
        .collect();

    let mut resolved_sorted = comparison.resolved_findings.clone();
    resolved_sorted.sort_by_key(sort_key);
    let resolved_items: String = resolved_sorted
        .iter()
        .map(|f| render_finding_mini(f, true, report_locale))
        .collect();

    // CRITICAL card added 2026-11-20: the grid showed HIGH to INFO only,
    // and critical findings appeared nowhere in the comparison.
    let baseline_critical = *comparison.baseline_totals.get("CRITICAL").unwrap_or(&0);
    let delta_critical = total_critical as i64 - baseline_critical as i64;
    let baseline_high = *comparison.baseline_totals.get("HIGH").unwrap_or(&0);
    let baseline_medium = *comparison.baseline_totals.get("MEDIUM").unwrap_or(&0);
    let baseline_low = *comparison.baseline_totals.get("LOW").unwrap_or(&0);
    let baseline_info = *comparison.baseline_totals.get("INFO").unwrap_or(&0);
    let delta_high = total_high as i64 - baseline_high as i64;
    let delta_medium = total_medium as i64 - baseline_medium as i64;
    let delta_low = total_low as i64 - baseline_low as i64;
    let delta_info = total_info as i64 - baseline_info as i64;

    let baseline_total: usize = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        .iter()
        .map(|s| *comparison.baseline_totals.get(*s).unwrap_or(&0))
        .sum();
    let current_total = total_findings;
    let total_delta = current_total as i64 - baseline_total as i64;
    let new_count = comparison.new_findings.len();
    let resolved_count = comparison.resolved_findings.len();

    let (trend_class, trend_icon, trend_label) =
        if total_delta < 0 || (total_delta == 0 && resolved_count > new_count) {
            (
                "improved",
                "📈",
                t(report_locale, "comparison_trend_improved"),
            )
        } else if total_delta > 0 || (total_delta == 0 && new_count > resolved_count) {
            (
                "regressed",
                "📉",
                t(report_locale, "comparison_trend_regressed"),
            )
        } else {
            ("stable", "➖", t(report_locale, "comparison_trend_stable"))
        };

    let mut trend_detail_parts = Vec::new();
    if resolved_count > 0 {
        trend_detail_parts.push(format!(
            "{resolved_count} {}",
            t(report_locale, "comparison_resolved_short")
        ));
    }
    if new_count > 0 {
        trend_detail_parts.push(format!(
            "{new_count} {}",
            t(report_locale, "comparison_new_short")
        ));
    }
    let trend_detail = if trend_detail_parts.is_empty() {
        t(report_locale, "comparison_no_change")
    } else {
        trend_detail_parts.join(" · ")
    };

    let no_new = format!(
        r#"<p class="empty">{}</p>"#,
        t(report_locale, "no_new_issues")
    );
    let no_resolved = format!(
        r#"<p class="empty">{}</p>"#,
        t(report_locale, "no_resolved_issues")
    );

    load_template("comparison-full.html")
        .replace("{{i18n_comparison}}", &t(report_locale, "comparison"))
        .replace("{{i18n_toc}}", &t(report_locale, "toc"))
        .replace("{{i18n_new_issues}}", &t(report_locale, "new_issues"))
        .replace(
            "{{i18n_resolved_issues}}",
            &t(report_locale, "resolved_issues"),
        )
        .replace(
            "{{i18n_baseline}}",
            &t(report_locale, "comparison_baseline"),
        )
        .replace("{{i18n_current}}", &t(report_locale, "comparison_current"))
        .replace("{{trend_class}}", trend_class)
        .replace("{{trend_icon}}", trend_icon)
        .replace("{{trend_label}}", &trend_label)
        .replace("{{trend_detail}}", &trend_detail)
        .replace("{{baseline_date}}", &escape(&comparison.baseline_date))
        .replace("{{baseline_total}}", &baseline_total.to_string())
        .replace("{{current_total}}", &current_total.to_string())
        .replace(
            "{{synthesis_table}}",
            &render_synthesis_table(comparison, report_locale),
        )
        .replace("{{baseline_critical}}", &baseline_critical.to_string())
        .replace("{{total_critical}}", &total_critical.to_string())
        .replace("{{delta_critical}}", &format_delta(delta_critical))
        .replace("{{baseline_high}}", &baseline_high.to_string())
        .replace("{{baseline_medium}}", &baseline_medium.to_string())
        .replace("{{baseline_low}}", &baseline_low.to_string())
        .replace("{{baseline_info}}", &baseline_info.to_string())
        .replace("{{total_high}}", &total_high.to_string())
        .replace("{{total_medium}}", &total_medium.to_string())
        .replace("{{total_low}}", &total_low.to_string())
        .replace("{{total_info}}", &total_info.to_string())
        .replace("{{delta_high}}", &format_delta(delta_high))
        .replace("{{delta_medium}}", &format_delta(delta_medium))
        .replace("{{delta_low}}", &format_delta(delta_low))
        .replace("{{delta_info}}", &format_delta(delta_info))
        .replace("{{new_count}}", &new_count.to_string())
        .replace("{{resolved_count}}", &resolved_count.to_string())
        .replace(
            "{{new_items}}",
            if new_items.is_empty() {
                &no_new
            } else {
                &new_items
            },
        )
        .replace(
            "{{resolved_items}}",
            if resolved_items.is_empty() {
                &no_resolved
            } else {
                &resolved_items
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;
    use crate::report::data::compute_report_data;
    use std::collections::BTreeMap;

    fn finding(file: &str, severity: &str, rule_name: &str) -> ReportFinding {
        ReportFinding {
            rule_key: "r".to_string(),
            rule_language: "python".to_string(),
            rule_name: rule_name.to_string(),
            category: "SECURITY".to_string(),
            severity: severity.to_string(),
            risk: String::new(),
            file: file.to_string(),
            line: 1,
            solution: None,
            cwe: vec![],
            owasp: None,
            taint_flow: None,
            taint_flows: vec![],
            code: String::new(),
            context_before: String::new(),
            context_after: String::new(),
            confidence: 90,
            benefit: String::new(),
            committer: None,
            rule_source: "json_builtin".to_string(),
            file_scope: None,
        }
    }

    /// Ticket #214: a mini card shows `file:line` for a line finding and
    /// the file alone for a whole-file finding.
    #[test]
    fn test_render_finding_mini_location() {
        let en = load_report_locale("en");
        let line = finding("a.py", "HIGH", "R");
        assert!(render_finding_mini(&line, false, &en).contains("a.py:1"));
        let mut whole = finding("big.py", "LOW", "R");
        whole.file_scope = Some(crate::scan::engine::FileScope {
            line_count: 700,
            min_lines: Some(500),
        });
        let html = render_finding_mini(&whole, true, &en);
        assert!(html.contains("big.py (whole file)"), "{html}");
        assert!(!html.contains("big.py:1"), "{html}");
    }

    /// The synthesis table counts, per severity, the baseline findings
    /// fixed (with their share), those still to fix and the new ones; the
    /// total row adds them up (2026-11-20).
    #[test]
    fn test_synthesis_table_counts_fixed_remaining_and_new() {
        let fr = load_report_locale("fr");
        let comparison = ComparisonResult {
            new_findings: vec![finding("n.py", "CRITICAL", "N")],
            resolved_findings: vec![
                finding("a.py", "HIGH", "A"),
                finding("b.py", "HIGH", "B"),
                finding("c.py", "LOW", "C"),
            ],
            unchanged_findings: vec![finding("d.py", "HIGH", "D"), finding("e.py", "LOW", "E")],
            baseline_date: "2026-11-02-10-15".to_string(),
            baseline_totals: BTreeMap::new(),
        };
        let html = render_synthesis_table(&comparison, &fr);
        assert!(
            html.contains("Synthèse depuis la référence du 2026-11-02-10-15"),
            "{html}"
        );
        // HIGH: 3 in the baseline, 2 fixed (67 %), 1 remaining, 0 new, 1 now.
        assert!(
            html.contains(r#"<td>Importants (HIGH)</td><td class="num">3</td><td class="num fixed">2 (67 %)</td><td class="num">1</td><td class="num added">0</td><td class="num">1</td>"#),
            "{html}"
        );
        // CRITICAL: none in the baseline, 1 new.
        assert!(
            html.contains(r#"<td>Critiques (CRITICAL)</td><td class="num">0</td><td class="num fixed">0 (—)</td><td class="num">0</td><td class="num added">1</td><td class="num">1</td>"#),
            "{html}"
        );
        // Total: 5 in the baseline, 3 fixed (60 %), 2 remaining, 1 new, 3 now.
        assert!(html.contains("<strong>5</strong>"), "{html}");
        assert!(html.contains("<strong>3 (60 %)</strong>"), "{html}");
    }

    /// The comparison shows a CRITICAL card, and lists critical findings
    /// first (2026-11-20).
    #[test]
    fn test_comparison_has_critical_card_and_lists_critical_first() {
        let en = load_report_locale("en");
        let current = vec![
            finding("z.py", "CRITICAL", "Crit"),
            finding("a.py", "MEDIUM", "Med"),
        ];
        let data = compute_report_data(&current, 1000);
        let mut totals = BTreeMap::new();
        totals.insert("CRITICAL".to_string(), 0usize);
        let comparison = ComparisonResult {
            new_findings: vec![
                finding("a.py", "MEDIUM", "Med"),
                finding("z.py", "CRITICAL", "Crit"),
            ],
            resolved_findings: vec![],
            unchanged_findings: vec![],
            baseline_date: "2026-11-02".to_string(),
            baseline_totals: totals,
        };
        let html = render_comparison_html(&comparison, &data, &en);
        assert!(html.contains("cmp-sev-card-critical"), "{html}");
        assert!(
            html.find("Crit").unwrap() < html.find("Med").unwrap(),
            "{html}"
        );
    }

    #[test]
    fn test_format_delta_positive_negative_zero() {
        assert!(format_delta(3).contains("negative"));
        assert!(format_delta(3).contains("+3"));
        assert!(format_delta(-2).contains("positive"));
        assert!(format_delta(-2).contains("-2"));
        assert!(format_delta(0).contains("neutral"));
        assert!(format_delta(0).contains("±0"));
    }

    #[test]
    fn test_render_comparison_html_improved_trend() {
        let en = load_report_locale("en");
        let mut baseline_totals = BTreeMap::new();
        baseline_totals.insert("HIGH".to_string(), 5usize);
        let comparison = ComparisonResult {
            new_findings: vec![],
            resolved_findings: vec![finding("a.py", "HIGH", "SQL Injection")],
            unchanged_findings: vec![],
            baseline_date: "2026-08-01".to_string(),
            baseline_totals,
        };
        // Current scan: 4 HIGH findings (baseline had 5 → improvement).
        let current_findings = vec![
            finding("a.py", "HIGH", "F1"),
            finding("b.py", "HIGH", "F2"),
            finding("c.py", "HIGH", "F3"),
            finding("d.py", "HIGH", "F4"),
        ];
        let data = compute_report_data(&current_findings, 0);
        let html = render_comparison_html(&comparison, &data, &en);
        assert!(html.contains("cmp-trend-improved"));
        assert!(html.contains("SQL Injection"));
        assert!(!html.contains("{{"));
    }

    #[test]
    fn test_render_comparison_html_no_new_no_resolved_shows_empty_state() {
        let en = load_report_locale("en");
        let mut baseline_totals = BTreeMap::new();
        baseline_totals.insert("HIGH".to_string(), 1usize);
        let comparison = ComparisonResult {
            new_findings: vec![],
            resolved_findings: vec![],
            unchanged_findings: vec![finding("a.py", "HIGH", "SQL Injection")],
            baseline_date: "2026-08-01".to_string(),
            baseline_totals,
        };
        let current_findings = vec![finding("a.py", "HIGH", "SQL Injection")];
        let data = compute_report_data(&current_findings, 0);
        let html = render_comparison_html(&comparison, &data, &en);
        assert!(html.contains(&t(&en, "no_new_issues")));
        assert!(html.contains(&t(&en, "no_resolved_issues")));
        assert!(html.contains("cmp-trend-stable"));
    }

    #[test]
    fn test_render_comparison_html_regressed_trend_with_new_findings() {
        let en = load_report_locale("en");
        let comparison = ComparisonResult {
            new_findings: vec![finding("a.py", "HIGH", "New Issue")],
            resolved_findings: vec![],
            unchanged_findings: vec![],
            baseline_date: "2026-08-01".to_string(),
            baseline_totals: BTreeMap::new(),
        };
        let current_findings = vec![finding("a.py", "HIGH", "New Issue")];
        let data = compute_report_data(&current_findings, 0);
        let html = render_comparison_html(&comparison, &data, &en);
        assert!(html.contains("cmp-trend-regressed"));
        assert!(html.contains("New Issue"));
    }
}
