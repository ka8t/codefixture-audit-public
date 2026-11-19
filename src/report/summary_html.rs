//! Executive summary (trend, prioritized recommendations, threat
//! context) and heatmap of the most problematic files — port of
//! `_build_exec_trend`/`_compute_top_priority_rules`/
//! `_format_priority_rule_list`/`_build_exec_recommendations`/
//! `_build_threat_context` (`Audit/sca/report.py`).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::i18n::t;
use crate::report::exports::sarif::ReportFinding;
use crate::report::report_assets::load_template;
use crate::report::text::escape;

/// Audit trend for the executive summary — port of
/// `_build_exec_trend`. `comparison`: `None` on the first audit (no
/// baseline).
pub fn build_exec_trend(
    comparison: Option<&crate::report::comparison::ComparisonResult>,
    report_locale: &Value,
) -> String {
    let Some(comparison) = comparison else {
        let label = t(report_locale, "exec_first_audit");
        return format!(
            r#"<div class="exec-trend-item"><span class="exec-trend-icon">📋</span> {label}</div>"#
        );
    };
    let new = comparison.new_findings.len();
    let resolved = comparison.resolved_findings.len();
    let persistent = comparison.unchanged_findings.len();
    let new_icon = if new > 0 { "🔴" } else { "⚪" };
    let resolved_icon = if resolved > 0 { "🟢" } else { "⚪" };
    format!(
        r#"<div class="exec-trend-item"><span class="exec-trend-icon">{new_icon}</span><span class="exec-trend-value">{new}</span> {}</div><div class="exec-trend-item"><span class="exec-trend-icon">{resolved_icon}</span><span class="exec-trend-value">{resolved}</span> {}</div><div class="exec-trend-item"><span class="exec-trend-icon">⚪</span><span class="exec-trend-value">{persistent}</span> {}</div>"#,
        t(report_locale, "exec_new_issues"),
        t(report_locale, "exec_resolved"),
        t(report_locale, "exec_persistent"),
    )
}

struct RankedRule {
    rule_name: String,
    count: usize,
    taint_verified: bool,
    score: f64,
}

/// Ranks rules with CRITICAL/HIGH findings by priority score
/// (severity × average confidence × occurrences × verified-taint
/// bonus) — port of `_compute_top_priority_rules`.
fn compute_top_priority_rules(findings: &[ReportFinding], limit: usize) -> Vec<RankedRule> {
    struct Entry {
        rule_name: String,
        severity_weight: f64,
        count: usize,
        confidence_sum: i64,
        taint_verified: bool,
    }
    let mut by_rule: BTreeMap<&str, Entry> = BTreeMap::new();
    for f in findings {
        let severity_weight = match f.severity.as_str() {
            "CRITICAL" => 100.0,
            "HIGH" => 70.0,
            _ => continue,
        };
        if f.rule_key.is_empty() {
            continue;
        }
        let entry = by_rule.entry(f.rule_key.as_str()).or_insert_with(|| Entry {
            rule_name: f.rule_name.clone(),
            severity_weight,
            count: 0,
            confidence_sum: 0,
            taint_verified: false,
        });
        entry.count += 1;
        entry.confidence_sum += f.confidence;
        if f.taint_flow.is_some() {
            entry.taint_verified = true;
        }
    }

    let mut ranked: Vec<RankedRule> = by_rule
        .into_values()
        .map(|e| {
            let avg_confidence = e.confidence_sum as f64 / e.count as f64;
            let occurrence_factor = e.count.min(10) as f64;
            let taint_bonus = if e.taint_verified { 1.5 } else { 1.0 };
            let score = e.severity_weight
                * (avg_confidence / 100.0)
                * (1.0 + occurrence_factor / 10.0)
                * taint_bonus;
            RankedRule {
                rule_name: e.rule_name,
                count: e.count,
                taint_verified: e.taint_verified,
                score: (score * 10.0).round() / 10.0,
            }
        })
        .collect();
    ranked.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    ranked.truncate(limit);
    ranked
}

/// Formats the list of priority rules for a recommendation — port of
/// `_format_priority_rule_list`.
fn format_priority_rule_list(ranked: &[RankedRule], report_locale: &Value) -> String {
    let occ_label = t(report_locale, "priority_occurrences_label");
    let taint_label = t(report_locale, "priority_taint_verified_label");
    ranked
        .iter()
        .map(|r| {
            let mut part = format!("{} ({} {occ_label}", escape(&r.rule_name), r.count);
            if r.taint_verified {
                part.push_str(&format!(", {taint_label}"));
            }
            part.push(')');
            part
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// One line of the prioritized recommendations.
struct Recommendation {
    /// `Some("p0")`…`Some("p3")` for an action, `None` for the health
    /// note, which states a diagnosis rather than a task.
    priority: Option<&'static str>,
    text: String,
    /// Id of the severity section of the findings list this line is
    /// about, linked at the end of the line.
    section_id: Option<&'static str>,
}

/// Prioritized recommendations for the executive summary — port of
/// `_build_exec_recommendations`.
///
/// Deliberate deviations from Python, so that a reader sees at once what
/// to fix first (tester feedback on a 2 947-finding project, 2026-11-19,
/// follow-up of ticket #220):
/// - one priority level per severity, never shared: P0 critical, P1 high,
///   P2/P3 medium. Python predates the CRITICAL severity; the first port
///   (#220) gave critical findings their own line but still labeled it
///   P1, like the HIGH line, so two P1 lines competed.
/// - no line for verified taint flows. Python added a third P1, "verified
///   exploitation path, absolute priority", with no count and no rule,
///   whatever the severity of the flows: on the tester's project 166 of
///   the 167 flows were MEDIUM log injections, yet the line outranked
///   the HIGH findings. A verified flow already raises its rule's rank in
///   each line (`compute_top_priority_rules`) and is named there.
/// - the health score line carries no priority badge: it states a
///   diagnosis, which the severity lines already turn into tasks; with a
///   badge it was a second P1 next to the HIGH line.
/// - each severity line links to its section of the findings list, which
///   it opens: the tester read "17 critical findings" in the summary and
///   could not find them below, the critical section being the only one
///   left folded.
pub fn build_exec_recommendations(
    findings: &[ReportFinding],
    total_critical: usize,
    total_high: usize,
    total_medium: usize,
    health_score: i64,
    report_locale: &Value,
) -> String {
    let mut recs: Vec<Recommendation> = Vec::new();
    let of_severity = |severity: &str| -> Vec<ReportFinding> {
        findings
            .iter()
            .filter(|f| f.severity == severity)
            .cloned()
            .collect()
    };
    // Line for a severity: the ranked template naming its top rules, or
    // the plain one when no rule can be ranked (findings without a key).
    let severity_line = |severity: &str, count: usize, plain_key: &str, ranked_key: &str| {
        let top_rules = compute_top_priority_rules(&of_severity(severity), 3);
        if top_rules.is_empty() {
            t(report_locale, plain_key).replace("{count}", &count.to_string())
        } else {
            t(report_locale, ranked_key)
                .replace("{count}", &count.to_string())
                .replace(
                    "{rules}",
                    &format_priority_rule_list(&top_rules, report_locale),
                )
        }
    };

    if total_critical > 0 {
        recs.push(Recommendation {
            priority: Some("p0"),
            text: severity_line(
                "CRITICAL",
                total_critical,
                "exec_rec_critical",
                "exec_rec_critical_ranked",
            ),
            section_id: Some("section-CRITICAL"),
        });
    }

    if total_high > 0 {
        recs.push(Recommendation {
            priority: Some("p1"),
            text: severity_line("HIGH", total_high, "exec_rec_high", "exec_rec_high_ranked"),
            section_id: Some("section-HIGH"),
        });
    }

    if total_medium > 20 {
        recs.push(Recommendation {
            priority: Some("p2"),
            text: t(report_locale, "exec_rec_medium"),
            section_id: Some("section-MEDIUM"),
        });
    } else if total_medium > 0 {
        recs.push(Recommendation {
            priority: Some("p3"),
            text: t(report_locale, "exec_rec_medium_low"),
            section_id: Some("section-MEDIUM"),
        });
    }

    let health_key = if health_score < 50 {
        Some("exec_rec_health_critical")
    } else if health_score < 80 {
        Some("exec_rec_health_warning")
    } else {
        None
    };

    if recs.is_empty() && health_key.is_none() {
        recs.push(Recommendation {
            priority: Some("p3"),
            text: t(report_locale, "exec_rec_good"),
            section_id: None,
        });
    }

    // The actions are pushed in priority order (P0, P1, then P2 or P3),
    // so no sort is needed; the health note closes the list.
    if let Some(key) = health_key {
        recs.push(Recommendation {
            priority: None,
            text: t(report_locale, key),
            section_id: None,
        });
    }

    let see_list = t(report_locale, "exec_rec_see_findings");
    recs.into_iter()
        .map(|rec| {
            let badge = match rec.priority {
                Some(priority) => {
                    let digit = &priority[1..];
                    format!(r#"<span class="exec-rec-priority {priority}">P{digit}</span> "#)
                }
                None => String::new(),
            };
            let link = match rec.section_id {
                Some(id) => format!(
                    r##" <a class="exec-rec-link" href="#{id}" onclick="scrollToSection('{id}');return false;">{see_list}</a>"##
                ),
                None => String::new(),
            };
            let class = if rec.priority.is_some() {
                "exec-rec-item"
            } else {
                "exec-rec-item exec-rec-note"
            };
            format!(r#"<div class="{class}">{badge}{}{link}</div>"#, rec.text)
        })
        .collect()
}

/// Threat context block (ZeroDayClock) for the executive summary —
/// port of `_build_threat_context`.
///
/// Deliberate deviation from Python: critical findings count with the
/// high ones, and both are named with their count ("9 Critical
/// (CRITICAL), 484 High (HIGH)"). Python only read HIGH and MEDIUM, so a
/// report whose worst findings were critical showed a lower level or no
/// block at all (ticket #220).
pub fn build_threat_context(
    total_critical: usize,
    total_high: usize,
    total_medium: usize,
    report_locale: &Value,
) -> String {
    if total_critical == 0 && total_high == 0 && total_medium == 0 {
        return String::new();
    }

    let tte_label = t(report_locale, "threat_tte");
    let exposure_label = t(report_locale, "threat_exposure");
    let context_label = t(report_locale, "threat_context");
    let disclaimer = t(report_locale, "threat_disclaimer");
    let source = t(report_locale, "threat_source");

    let (risk_level, risk_color, risk_text) = if total_critical + total_high > 0 {
        let severities = [
            ("severity.critical", total_critical),
            ("severity.high", total_high),
        ]
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(label, count)| format!("{count} {}", t(report_locale, label)))
        .collect::<Vec<_>>()
        .join(", ");
        let tpl = t(report_locale, "threat_risk_high_text");
        let text = tpl
            .replace("{severities}", &severities)
            .replace("{tte_label}", &tte_label)
            .replace("{exposure_label}", &exposure_label);
        (t(report_locale, "threat_level_critical"), "#ef4444", text)
    } else {
        let tpl = t(report_locale, "threat_risk_medium_text");
        let text = tpl
            .replace("{count}", &total_medium.to_string())
            .replace("{severity_label}", &t(report_locale, "severity.medium"))
            .replace("{exposure_label}", &exposure_label);
        (t(report_locale, "threat_level_elevated"), "#f59e0b", text)
    };

    format!(
        r#"<div class="threat-context" style="border-left:4px solid {risk_color};background:{risk_color}10;padding:12px 16px;border-radius:0 8px 8px 0;margin:12px 0;"><strong>{context_label}</strong> <span style="font-size:12px;color:{risk_color}">({risk_level})</span><br><span style="font-size:13px;color:var(--gray-700)">{risk_text}</span><br><span style="font-size:11px;color:var(--gray-500)">{disclaimer} {source}</span></div>"#
    )
}

/// HTML heatmap of the most problematic files — port of the
/// `heatmap_html` block in `_generate_html` (loop over `top_files`).
pub fn render_heatmap(top_files: &[crate::report::data::TopFile], report_locale: &Value) -> String {
    if top_files.is_empty() {
        return String::new();
    }
    let max_count = top_files[0].score.max(1);
    let item_tpl = load_template("heatmap-item.html");
    let severity_score_label = t(report_locale, "severity_score");

    top_files
        .iter()
        .enumerate()
        .map(|(idx, tf)| {
            let rank = idx + 1;
            let heat_pct = if max_count > 0 {
                (tf.score as f64 / max_count as f64) * 100.0
            } else {
                0.0
            };
            let (fdir, fname) = match tf.file.rsplit_once('/') {
                Some((dir, name)) => {
                    let dir = if dir.len() > 40 {
                        format!("...{}", &dir[dir.len().saturating_sub(37)..])
                    } else {
                        dir.to_string()
                    };
                    (format!("{dir}/"), name.to_string())
                }
                None => (String::new(), tf.file.clone()),
            };
            let chips: String = [
                ("CRITICAL", "chip-critical"),
                ("HIGH", "chip-high"),
                ("MEDIUM", "chip-medium"),
                ("LOW", "chip-low"),
                ("INFO", "chip-info"),
            ]
            .iter()
            .filter_map(|(sev, cls)| {
                let n = *tf.severities.get(sev).unwrap_or(&0);
                if n > 0 {
                    let sev_cap = format!("{}{}", &sev[..1], sev[1..].to_lowercase());
                    Some(format!(
                        r#"<span class="hm-chip {cls}">{n} {sev_cap}</span>"#
                    ))
                } else {
                    None
                }
            })
            .collect();
            item_tpl
                .replace("{{heat_pct}}", &format!("{heat_pct:.0}"))
                .replace("{{rank}}", &rank.to_string())
                .replace("{{filepath}}", &escape(&tf.file))
                .replace("{{fname}}", &escape(&fname))
                .replace("{{fdir}}", &escape(&fdir))
                .replace("{{count}}", &tf.score.to_string())
                .replace("{{chips}}", &chips)
                .replace("{{i18n_severity_score}}", &severity_score_label)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;
    use crate::report::data::TopFile;

    fn finding(rule_key: &str, rule_name: &str, severity: &str, confidence: i64) -> ReportFinding {
        ReportFinding {
            rule_key: rule_key.to_string(),
            rule_language: "python".to_string(),
            rule_name: rule_name.to_string(),
            category: "SECURITY".to_string(),
            severity: severity.to_string(),
            risk: String::new(),
            file: "a.py".to_string(),
            line: 1,
            solution: None,
            cwe: vec![],
            owasp: None,
            taint_flow: None,
            taint_flows: vec![],
            code: String::new(),
            context_before: String::new(),
            context_after: String::new(),
            confidence,
            benefit: String::new(),
            committer: None,
            rule_source: "json_builtin".to_string(),
            file_scope: None,
        }
    }

    #[test]
    fn test_build_exec_trend_first_audit_message() {
        let en = load_report_locale("en");
        let html = build_exec_trend(None, &en);
        assert!(html.contains("exec-trend-item"));
        assert!(html.contains(&t(&en, "exec_first_audit")));
    }

    #[test]
    fn test_build_exec_trend_with_comparison() {
        let en = load_report_locale("en");
        let comparison = crate::report::comparison::ComparisonResult {
            new_findings: vec![],
            resolved_findings: vec![],
            unchanged_findings: vec![],
            baseline_date: "2026-08-01".to_string(),
            baseline_totals: std::collections::BTreeMap::new(),
        };
        let html = build_exec_trend(Some(&comparison), &en);
        assert!(!html.contains("exec_first_audit"));
        assert!(html.contains(&t(&en, "exec_new_issues")));
    }

    #[test]
    fn test_compute_top_priority_rules_ranks_by_score() {
        let findings = vec![
            finding("r1", "Rule Low Conf", "HIGH", 50),
            finding("r2", "Rule High Conf", "CRITICAL", 100),
        ];
        let ranked = compute_top_priority_rules(&findings, 3);
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].rule_name, "Rule High Conf");
    }

    #[test]
    fn test_compute_top_priority_rules_ignores_medium_and_below() {
        let findings = vec![finding("r1", "Rule", "MEDIUM", 90)];
        let ranked = compute_top_priority_rules(&findings, 3);
        assert!(ranked.is_empty());
    }

    #[test]
    fn test_build_exec_recommendations_high_findings_produces_p1() {
        let en = load_report_locale("en");
        let findings = vec![finding("r1", "SQL Injection", "HIGH", 90)];
        let html = build_exec_recommendations(&findings, 0, 1, 0, 100, &en);
        assert!(html.contains("exec-rec-priority p1"));
        assert!(html.contains("SQL Injection"));
    }

    /// Critical findings get the first P1 line, naming the critical rules;
    /// the HIGH line names HIGH rules only (ticket #220).
    #[test]
    fn test_build_exec_recommendations_critical_line_comes_first() {
        let en = load_report_locale("en");
        let findings = vec![
            finding("r1", "SQL Injection", "HIGH", 90),
            finding("r2", "Secret in CI", "CRITICAL", 90),
        ];
        let html = build_exec_recommendations(&findings, 1, 1, 0, 100, &en);
        let critical = html
            .find("Fix the 1 critical findings first, starting with: Secret in CI")
            .expect("critical line");
        let high = html.find("high-risk findings").expect("high line");
        assert!(critical < high, "{html}");
        let high_line = &html[high..];
        let high_line = &high_line[..high_line.find("</div>").unwrap()];
        assert!(high_line.contains("SQL Injection"), "{high_line}");
        assert!(!high_line.contains("Secret in CI"), "{high_line}");
    }

    /// A report whose only serious findings are critical still gets the
    /// critical threat context, naming them (ticket #220).
    #[test]
    fn test_build_threat_context_counts_critical_findings() {
        let en = load_report_locale("en");
        let html = build_threat_context(9, 0, 0, &en);
        assert!(html.contains(&t(&en, "threat_level_critical")), "{html}");
        assert!(
            html.contains(&format!("9 {}", t(&en, "severity.critical"))),
            "{html}"
        );
        let both = build_threat_context(9, 484, 0, &en);
        assert!(
            both.contains(&format!(
                "9 {}, 484 {}",
                t(&en, "severity.critical"),
                t(&en, "severity.high")
            )),
            "{both}"
        );
    }

    /// One priority level per severity: P0 critical, P1 high, P2 medium,
    /// each level used once, in that order (tester feedback, 2026-11-19).
    #[test]
    fn test_build_exec_recommendations_one_level_per_severity() {
        let en = load_report_locale("en");
        let findings = vec![
            finding("r1", "SQL Injection", "HIGH", 90),
            finding("r2", "Secret in CI", "CRITICAL", 90),
        ];
        let html = build_exec_recommendations(&findings, 1, 1, 25, 100, &en);
        let badges: Vec<&str> = html
            .match_indices("exec-rec-priority ")
            .map(|(i, _)| &html[i + 18..i + 20])
            .collect();
        assert_eq!(badges, ["p0", "p1", "p2"], "{html}");
    }

    /// A verified taint flow no longer adds a priority line of its own:
    /// the flows of the tester's project were mostly MEDIUM, yet the line
    /// claimed "absolute priority" next to the HIGH line.
    #[test]
    fn test_build_exec_recommendations_no_taint_line() {
        let en = load_report_locale("en");
        let mut medium = finding("r1", "Log Injection", "MEDIUM", 90);
        medium.taint_flow = Some(
            serde_json::from_value(serde_json::json!({
                "source_file": "a.py", "source_line": 1, "source_expr": "request.args",
                "chain": [], "sink_file": "a.py", "sink_line": 2, "sink_expr": "log.info(x)"
            }))
            .expect("taint flow"),
        );
        let html = build_exec_recommendations(&[medium], 0, 0, 1, 100, &en);
        assert!(!html.contains("absolute priority"), "{html}");
        assert_eq!(html.matches("exec-rec-item").count(), 1, "{html}");
    }

    /// Each severity line links to its section of the findings list, and
    /// the link opens it through `scrollToSection`.
    #[test]
    fn test_build_exec_recommendations_links_to_severity_sections() {
        let en = load_report_locale("en");
        let findings = vec![
            finding("r1", "SQL Injection", "HIGH", 90),
            finding("r2", "Secret in CI", "CRITICAL", 90),
        ];
        let html = build_exec_recommendations(&findings, 1, 1, 0, 100, &en);
        for id in ["section-CRITICAL", "section-HIGH"] {
            assert!(
                html.contains(&format!(
                    r##"href="#{id}" onclick="scrollToSection('{id}');return false;""##
                )),
                "{id}: {html}"
            );
        }
    }

    /// The health score line is a note without a priority badge, written
    /// after the actions.
    #[test]
    fn test_build_exec_recommendations_health_note_has_no_badge() {
        let en = load_report_locale("en");
        let findings = vec![finding("r1", "SQL Injection", "HIGH", 90)];
        let html = build_exec_recommendations(&findings, 0, 1, 0, 30, &en);
        let note = html.find("exec-rec-note").expect("health note");
        assert!(html.find("exec-rec-priority p1").unwrap() < note, "{html}");
        assert_eq!(html.matches("exec-rec-priority").count(), 1, "{html}");
    }

    #[test]
    fn test_build_exec_recommendations_no_issues_gives_good_message() {
        let en = load_report_locale("en");
        let html = build_exec_recommendations(&[], 0, 0, 0, 100, &en);
        assert!(html.contains(&t(&en, "exec_rec_good")));
    }

    #[test]
    fn test_build_exec_recommendations_critical_health_score() {
        let en = load_report_locale("en");
        let html = build_exec_recommendations(&[], 0, 0, 0, 30, &en);
        assert!(html.contains(&t(&en, "exec_rec_health_critical")));
    }

    #[test]
    fn test_build_threat_context_empty_when_no_high_medium() {
        let en = load_report_locale("en");
        assert_eq!(build_threat_context(0, 0, 0, &en), "");
    }

    #[test]
    fn test_build_threat_context_critical_when_high_present() {
        let en = load_report_locale("en");
        let html = build_threat_context(0, 3, 0, &en);
        assert!(html.contains("threat-context"));
        assert!(html.contains(&t(&en, "threat_level_critical")));
    }

    #[test]
    fn test_render_heatmap_empty_when_no_files() {
        let en = load_report_locale("en");
        assert_eq!(render_heatmap(&[], &en), "");
    }

    #[test]
    fn test_render_heatmap_contains_filename_and_chips() {
        let en = load_report_locale("en");
        let mut severities = BTreeMap::new();
        severities.insert("HIGH", 2usize);
        let top_files = vec![TopFile {
            file: "src/app/views.py".to_string(),
            score: 10,
            severities,
        }];
        let html = render_heatmap(&top_files, &en);
        assert!(html.contains("views.py"));
        assert!(html.contains("src/app/"));
        assert!(html.contains("2 High"));
    }

    /// Security regression (2026-11-15): the heatmap renders a file path
    /// inside a single-quoted JS string of an inline `onclick`. A path
    /// controlled by the scanned project must not break out of that string.
    /// `escape` now encodes `'` as `&#39;`, so no bare quote reaches the
    /// handler. Before the fix, `('b.py` appeared verbatim in the output.
    #[test]
    fn test_render_heatmap_escapes_single_quote_in_path() {
        let en = load_report_locale("en");
        let top_files = vec![TopFile {
            file: "src/a'); alert(1); ('b.py".to_string(),
            score: 3,
            severities: BTreeMap::new(),
        }];
        let html = render_heatmap(&top_files, &en);
        assert!(
            html.contains("navigateToFile("),
            "the inline handler is present"
        );
        assert!(
            !html.contains("('b.py"),
            "a bare single quote must not survive inside the JS string"
        );
        assert!(html.contains("&#39;"), "the quote is HTML-encoded");
    }
}
