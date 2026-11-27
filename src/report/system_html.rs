//! The "System" section of the HTML report (ADR-0072, amended on
//! 2026-11-26): the machine the scan ran on and the runtimes of the
//! scanned languages, each with every known vulnerability of its version.
//!
//! the maintainer, 2026-11-26: urgent means exploited, and that covers the system
//! the binary runs on, "detailed in the reports". The top of the report
//! (`priorities`) says what to do; this section shows what that rests on:
//! for each detection, the line the console prints, then its exploited
//! vulnerabilities, always visible, then every known one in a folded
//! table, exploited first, then by NVD severity, then by EPSS. A detection
//! that could not be checked is named with why, as in the console, and so
//! is a pack without system data: nothing seen is left out.

use crate::project::host::{Check, HostSurvey};
use crate::project::platform::PlatformVulnerability;
use crate::report::text::escape;

/// The section, in the language of `locale` (a report locale).
pub fn section(host: &HostSurvey, locale: &serde_json::Value) -> String {
    let say = |key: &str| crate::i18n::t(locale, &format!("system.{key}"));
    let title = say("title");
    let mut body = String::new();
    match &host.unavailable {
        Some(unavailable) => {
            body.push_str(&format!("<p>{}</p>", escape(&unavailable.text(locale))));
        }
        None => {
            body.push_str(&format!(
                r#"<p class="system-intro">{}</p>"#,
                escape(&say("intro").replace("{date}", &host.date))
            ));
            if let Some(days) = host.stale_days {
                body.push_str(&format!(
                    r#"<p class="system-warning">{}</p>"#,
                    escape(
                        &crate::i18n::t(locale, "host_stale")
                            .replace("{days}", &days.to_string())
                            .replace("{date}", &host.date)
                    )
                ));
            }
            for entry in &host.entries {
                body.push_str(&match &entry.result {
                    Ok(check) => checked_entry(check, entry.system, &host.date, locale),
                    Err(missing) => format!(
                        r#"<div class="system-entry"><h3>{}</h3><p>{}</p></div>"#,
                        escape(&say("not_detected_title")),
                        escape(&crate::project::host::not_detected_text(missing, locale))
                    ),
                });
            }
        }
    }
    format!(
        r##"<div class="section system-section" id="section-system" data-nav-section="{t}"><h2 class="section-title">🖥️ {t} <a href="#sommaire" class="back-to-toc">↑ {toc}</a></h2>{body}</div>"##,
        t = escape(&title),
        toc = escape(&crate::i18n::t(locale, "toc"))
    )
}

/// One checked detection: its console line, its exploited
/// vulnerabilities, then all of them folded.
fn checked_entry(check: &Check, system: bool, date: &str, locale: &serde_json::Value) -> String {
    let say = |key: &str| crate::i18n::t(locale, &format!("system.{key}"));
    let heading = format!(
        "{} {}",
        check.detected.product.label, check.detected.shown_version
    );
    let line = crate::project::host::check_line(check, system, date, locale);
    let mut html = format!(
        r#"<div class="system-entry"><h3>{}</h3><p>{}</p>"#,
        escape(&heading),
        escape(&line)
    );
    if check.vulnerabilities.is_empty() {
        html.push_str(&format!("<p>{}</p>", escape(&say("none_known"))));
    } else {
        let ordered = ordered(check);
        let exploited: Vec<&PlatformVulnerability> = ordered
            .iter()
            .copied()
            .filter(|v| check.kev.contains_key(&v.cve))
            .collect();
        if !exploited.is_empty() {
            html.push_str(&format!(
                "<h4>{}</h4>{}",
                escape(&say("exploited_title").replace("{count}", &exploited.len().to_string())),
                table(check, &exploited, locale)
            ));
        }
        html.push_str(&format!(
            r#"<details class="system-all"><summary>{}</summary>{}</details>"#,
            escape(&say("all_title").replace("{count}", &ordered.len().to_string())),
            table(check, &ordered, locale)
        ));
    }
    html.push_str("</div>");
    html
}

/// The vulnerabilities of `check`, exploited first, then by NVD severity,
/// then by EPSS (highest first), then by identifier.
fn ordered(check: &Check) -> Vec<&PlatformVulnerability> {
    let rank = |v: &PlatformVulnerability| match v.severity.as_deref() {
        Some("CRITICAL") => 4,
        Some("HIGH") => 3,
        Some("MEDIUM") => 2,
        Some(_) => 1,
        None => 0,
    };
    let epss = |v: &PlatformVulnerability| check.epss.get(&v.cve).copied().unwrap_or(-1.0);
    let mut list: Vec<&PlatformVulnerability> = check.vulnerabilities.iter().collect();
    list.sort_by(|a, b| {
        check
            .kev
            .contains_key(&b.cve)
            .cmp(&check.kev.contains_key(&a.cve))
            .then_with(|| rank(b).cmp(&rank(a)))
            .then_with(|| epss(b).total_cmp(&epss(a)))
            .then_with(|| a.cve.cmp(&b.cve))
    });
    list
}

/// A table of `rows`: the identifier linked to its NVD page, the NVD
/// severity, the EPSS probability, and since when CISA lists it as
/// exploited.
fn table(check: &Check, rows: &[&PlatformVulnerability], locale: &serde_json::Value) -> String {
    let say = |key: &str| crate::i18n::t(locale, &format!("system.{key}"));
    let decimal = crate::i18n::t(locale, "priorities.decimal_mark");
    let body: String = rows
        .iter()
        .map(|v| {
            let severity = v.severity.clone().unwrap_or_else(|| say("unscored"));
            let epss = check
                .epss
                .get(&v.cve)
                .map(|e| {
                    format!("{:.1} %", (e * 1000.0 + 1e-9).floor() / 10.0).replace('.', &decimal)
                })
                .unwrap_or_else(|| "—".to_string());
            let exploited = match check.kev.get(&v.cve) {
                Some(row) => {
                    let mut text = say("exploited_since").replace("{date}", &row.added);
                    if row.ransomware {
                        text.push_str(&say("ransomware"));
                    }
                    text
                }
                None => say("not_exploited"),
            };
            // The report's own severity badges (`.sev-tag`), as the
            // comparison section shows them; a CVE the NVD has not scored
            // (or scored NONE) takes the neutral one.
            let badge = match v.severity.as_deref() {
                Some("CRITICAL") => "sev-critical",
                Some("HIGH") => "sev-high",
                Some("MEDIUM") => "sev-medium",
                Some("LOW") => "sev-low",
                _ => "sev-info",
            };
            let class = if check.kev.contains_key(&v.cve) {
                r#" class="system-exploited""#
            } else {
                ""
            };
            format!(
                r#"<tr{class}><td><a href="https://nvd.nist.gov/vuln/detail/{id}" target="_blank" rel="noopener noreferrer">{id}</a></td><td><span class="sev-tag {badge}">{severity}</span></td><td>{epss}</td><td>{exploited}</td></tr>"#,
                id = escape(&v.cve),
                severity = escape(&severity),
                epss = escape(&epss),
                exploited = escape(&exploited)
            )
        })
        .collect();
    format!(
        r#"<table class="system-table"><thead><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>{body}</tbody></table>"#,
        escape(&say("col_cve")),
        escape(&say("col_severity")),
        escape(&say("col_epss")),
        escape(&say("col_exploited"))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::host::{Detected, HostEntry, HostUnavailable, NotDetected, Support};

    fn vulnerability(cve: &str, severity: Option<&str>) -> PlatformVulnerability {
        PlatformVulnerability {
            cve: cve.to_string(),
            version: None,
            start_including: None,
            start_excluding: None,
            end_including: None,
            end_excluding: Some("26.7.3".to_string()),
            severity: severity.map(str::to_string),
        }
    }

    /// macOS 26.5.2: one exploited HIGH, one CRITICAL with an EPSS, one
    /// MEDIUM, one not scored.
    fn macos() -> Check {
        Check {
            detected: Detected {
                product: crate::project::platform::product("macos").expect("followed"),
                version: "26.5.2".to_string(),
                cycle: None,
                cpes: vec!["o:apple:macos".to_string()],
                on_linux: false,
                cpe_version: None,
                shown_version: "26.5.2".to_string(),
            },
            cycle: Some("26".to_string()),
            support: Support::Behind {
                latest: "26.7.3".to_string(),
            },
            newer: Some(("27".to_string(), "27.2.1".to_string())),
            vulnerabilities: vec![
                vulnerability("CVE-2026-4", None),
                vulnerability("CVE-2026-3", Some("MEDIUM")),
                vulnerability("CVE-2026-2", Some("CRITICAL")),
                vulnerability("CVE-2026-1", Some("HIGH")),
            ],
            exploited: 1,
            exploited_cves: vec!["CVE-2026-1".to_string()],
            kev: [(
                "CVE-2026-1".to_string(),
                crate::project::advisories::Exploited {
                    added: "2026-11-01".to_string(),
                    ransomware: true,
                },
            )]
            .into(),
            epss: [("CVE-2026-2".to_string(), 0.083)].into(),
        }
    }

    fn survey() -> HostSurvey {
        HostSurvey {
            unavailable: None,
            date: "2026-11-26".to_string(),
            stale_days: None,
            entries: vec![
                HostEntry {
                    system: true,
                    result: Ok(macos()),
                },
                HostEntry {
                    system: false,
                    result: Err(NotDetected {
                        what: "Node.js".to_string(),
                        reason: String::new(),
                        not_found: Some("node".to_string()),
                        no_version: None,
                    }),
                },
            ],
        }
    }

    /// Each vulnerability is listed, exploited first, then by severity;
    /// the exploited one is also shown apart with its KEV date; the
    /// runtime not found is named with why.
    #[test]
    fn test_section_lists_every_vulnerability_exploited_first() {
        let locale = crate::i18n::load_report_locale("en");
        let html = section(&survey(), &locale);
        assert!(html.contains(r#"id="section-system""#), "{html}");
        assert!(
            html.contains(
                "System: macOS 26.5.2, behind, the latest version of its release is 26.7.3"
            ),
            "{html}"
        );
        assert!(html.contains("Exploited in attacks (1)"), "{html}");
        assert!(
            html.contains("All known vulnerabilities (4), the exploited first"),
            "{html}"
        );
        let all = &html[html.find("system-all").unwrap()..];
        let at = |cve: &str| all.find(&format!(">{cve}</a>")).unwrap();
        assert!(at("CVE-2026-1") < at("CVE-2026-2"), "{all}");
        assert!(at("CVE-2026-2") < at("CVE-2026-3"), "{all}");
        assert!(at("CVE-2026-3") < at("CVE-2026-4"), "{all}");
        assert!(
            html.contains("since 2026-11-01, used by ransomware"),
            "{html}"
        );
        assert!(html.contains("8.3 %"), "{html}");
        assert!(html.contains("not scored"), "{html}");
        assert!(
            html.contains(r#"<span class="sev-tag sev-critical">CRITICAL</span>"#)
                && html.contains(r#"<span class="sev-tag sev-info">not scored</span>"#),
            "{html}"
        );
        assert!(
            html.contains("https://nvd.nist.gov/vuln/detail/CVE-2026-2"),
            "{html}"
        );
        assert!(
            html.contains("Node.js not checked: node not found on PATH"),
            "{html}"
        );
    }

    /// In French, with the decimal comma; without system data the
    /// section says why instead of being empty.
    #[test]
    fn test_section_in_french_and_without_data() {
        let locale = crate::i18n::load_report_locale("fr");
        let html = section(&survey(), &locale);
        assert!(html.contains("🖥️ Système"), "{html}");
        assert!(html.contains("8,3 %"), "{html}");
        assert!(html.contains("depuis le 2026-11-01"), "{html}");
        let none = HostSurvey {
            unavailable: Some(HostUnavailable::NoData),
            ..HostSurvey::default()
        };
        let html = section(&none, &locale);
        assert!(
            html.contains("Système et environnements non vérifiés"),
            "{html}"
        );
    }
}
