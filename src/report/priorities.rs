//! What to treat first (ticket #308): the vulnerabilities to treat
//! urgently, then the next ones, for the console and the top of the report.
//!
//! Brian's point, 2026-11-26: "the stake is no longer to have CVEs, it is
//! to determine those to treat urgently". The maintainer's decision the same day:
//!
//! - **urgent** means exploited in real attacks, as CISA's Known Exploited
//!   Vulnerabilities catalog lists them: a fact, not a threshold. The
//!   system the engine runs on and its runtimes count (ADR-0071), and so
//!   do the dependencies (ADR-0051);
//! - **next** are the dependencies that follow in the engine's own order,
//!   severity then EPSS probability (ADR-0051), the first
//!   [`NEXT_LIMIT`] of them;
//! - each one says what to do: the version that fixes it, or that none is
//!   published.
//!
//! No EPSS threshold decides anything: ADR-0051 found none with a reason.

use crate::project::host::{Check, Support};

/// How many dependencies the "next" list names.
pub const NEXT_LIMIT: usize = 5;

/// One vulnerability of a dependency, as the priorities name it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PriorityCve {
    /// CVE id when there is one, else the advisory id.
    pub id: String,
    /// Engine severity (NVD's when the records give none, ADR-0070).
    pub severity: String,
    /// EPSS probability, 0 to 1, when scored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    /// Date CISA added it to the KEV catalog, when exploited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploited_since: Option<String>,
    /// CISA knows it to be used by ransomware.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ransomware: bool,
}

/// One vulnerable dependency, as the priorities rank it. Built by the
/// dependency phase from the same records as its finding.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DependencyPriority {
    /// Manifest or lockfile, relative to the project.
    pub file: String,
    pub line: usize,
    pub package: String,
    pub version: String,
    /// The finding's severity.
    pub severity: String,
    /// Its vulnerabilities, in the engine's order (exploited, severity,
    /// EPSS).
    pub cves: Vec<PriorityCve>,
    /// The lowest version that fixes every one of them, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_version: Option<String>,
}

impl DependencyPriority {
    /// Its exploited vulnerabilities.
    pub fn exploited(&self) -> impl Iterator<Item = &PriorityCve> {
        self.cves.iter().filter(|c| c.exploited_since.is_some())
    }

    fn severity_rank(&self) -> u8 {
        match self.severity.as_str() {
            "CRITICAL" => 4,
            "HIGH" => 3,
            "MEDIUM" => 2,
            _ => 1,
        }
    }

    fn best_epss(&self) -> f64 {
        self.cves.iter().filter_map(|c| c.epss).fold(-1.0, f64::max)
    }
}

/// What to treat first.
#[derive(Debug, Clone, Default)]
pub struct Priorities {
    /// The system or runtimes with an exploited vulnerability.
    pub urgent_platform: Vec<Check>,
    /// The dependencies with an exploited vulnerability.
    pub urgent_dependencies: Vec<DependencyPriority>,
    /// The next dependencies, severity then EPSS.
    pub next: Vec<DependencyPriority>,
}

impl Priorities {
    /// The priorities of `checks` (the system check) and `dependencies`
    /// (the dependency phase).
    pub fn new(checks: &[Check], dependencies: &[DependencyPriority]) -> Self {
        let urgent_platform: Vec<Check> =
            checks.iter().filter(|c| c.exploited > 0).cloned().collect();
        let (mut urgent, mut rest): (Vec<_>, Vec<_>) = dependencies
            .iter()
            .cloned()
            .partition(|d| d.exploited().next().is_some());
        let order = |a: &DependencyPriority, b: &DependencyPriority| {
            b.severity_rank()
                .cmp(&a.severity_rank())
                .then_with(|| b.best_epss().total_cmp(&a.best_epss()))
                .then_with(|| a.package.cmp(&b.package))
        };
        urgent.sort_by(order);
        rest.sort_by(order);
        rest.truncate(NEXT_LIMIT);
        Self {
            urgent_platform,
            urgent_dependencies: urgent,
            next: rest,
        }
    }

    /// How many things are urgent: each system or runtime, each
    /// dependency.
    pub fn urgent_count(&self) -> usize {
        self.urgent_platform.len() + self.urgent_dependencies.len()
    }

    /// The console lines, in the language of `locale` (the script
    /// locale). `previous` is the urgent count of the previous scan, when
    /// known.
    pub fn console_lines(
        &self,
        locale: &serde_json::Value,
        previous: Option<usize>,
    ) -> Vec<String> {
        let say = |key: &str| crate::i18n::t(locale, &format!("priorities.{key}"));
        let decimal = say("decimal_mark");
        let mut lines = Vec::new();
        let compared = previous
            .map(|n| say("previous").replace("{count}", &n.to_string()))
            .unwrap_or_default();
        if self.urgent_count() == 0 {
            lines.push(format!("🚨 {}{compared}", say("urgent_none")));
        } else {
            lines.push(format!(
                "🚨 {}{compared}",
                say("urgent").replace("{count}", &self.urgent_count().to_string())
            ));
        }
        for check in &self.urgent_platform {
            lines.push(format!("   {}", platform_text(check, &say)));
        }
        for dependency in &self.urgent_dependencies {
            lines.push(format!("   {}", urgent_dependency_text(dependency, &say)));
        }
        if !self.next.is_empty() {
            lines.push(format!("➡  {}", say("next")));
            for dependency in &self.next {
                lines.push(format!(
                    "   {}",
                    next_dependency_text(dependency, &say, &decimal)
                ));
            }
        }
        lines
    }

    /// The block of the HTML report, right above the security score, in
    /// the language of `report_locale` (ticket #308: "the most
    /// important", the maintainer, 2026-11-26):
    ///
    /// - the urgent count in large, red when above zero;
    /// - each urgent item with a chart: its known vulnerabilities stacked by
    ///   severity, and how many are exploited;
    /// - each next dependency with a bar as long as the EPSS of its worst
    ///   vulnerability relative to the highest of the list, coloured by
    ///   its severity, the absolute value beside it;
    /// - links: every CVE or advisory id to its public page, every
    ///   dependency to its finding further down the report.
    pub fn html(&self, report_locale: &serde_json::Value, previous: Option<usize>) -> String {
        let escape = crate::report::text::escape;
        let say = |key: &str| crate::i18n::t(report_locale, &format!("priorities.{key}"));
        let decimal = say("decimal_mark");
        let compared = previous
            .map(|n| say("previous").replace("{count}", &n.to_string()))
            .unwrap_or_default();
        let title = if self.urgent_count() == 0 {
            say("urgent_none")
        } else {
            say("urgent").replace("{count}", &self.urgent_count().to_string())
        };
        let see = say("see_finding");
        let details = |file: &str, line: usize| {
            let anchor =
                crate::report::findings_html::finding_anchor("vulnerable_dependency", file, line);
            format!(
                r##" <a class="priority-details" href="#{anchor}" onclick="scrollToSection('{anchor}'); return false;">{}</a>"##,
                escape(&see)
            )
        };
        let exploited_label = say("exploited_badge");

        let mut urgent_rows: Vec<String> = self
            .urgent_platform
            .iter()
            .map(|c| {
                let ids: Vec<&str> = c.exploited_cves.iter().map(String::as_str).collect();
                let severities: Vec<&str> = c
                    .vulnerabilities
                    .iter()
                    .map(|v| v.severity.as_deref().unwrap_or("UNKNOWN"))
                    .collect();
                urgent_row(
                    &linkify(&escape(&platform_text(c, &say)), &ids),
                    &severities,
                    c.exploited,
                    &exploited_label,
                )
            })
            .collect();
        urgent_rows.extend(self.urgent_dependencies.iter().map(|d| {
            let ids: Vec<&str> = d.cves.iter().map(|c| c.id.as_str()).collect();
            let severities: Vec<&str> = d.cves.iter().map(|c| c.severity.as_str()).collect();
            urgent_row(
                &format!(
                    "{}{}",
                    linkify(&escape(&urgent_dependency_text(d, &say)), &ids),
                    details(&d.file, d.line)
                ),
                &severities,
                d.exploited().count(),
                &exploited_label,
            )
        }));

        // Relative to the highest EPSS of the list: at the absolute scale,
        // 8 % and 0.5 % both read as nothing.
        let highest = self
            .next
            .iter()
            .filter_map(|d| d.cves.first().and_then(|c| c.epss))
            .fold(0.0_f64, f64::max);
        let next_rows: String = self
            .next
            .iter()
            .map(|d| {
                let epss = d.cves.first().and_then(|c| c.epss);
                let width = epss
                    .filter(|_| highest > 0.0)
                    .map_or(0.0, |e| (e / highest * 100.0).max(3.0));
                let value = epss
                    .map(|e| {
                        format!("{:.1} %", (e * 1000.0 + 1e-9).floor() / 10.0)
                            .replace('.', &decimal)
                    })
                    .unwrap_or_else(|| "—".to_string());
                let ids: Vec<&str> = d.cves.first().map(|c| c.id.as_str()).into_iter().collect();
                format!(
                    r#"<li class="priority"><div class="priority-text">{}{}</div><div class="priority-bar"><span class="bar-{}" style="width:{width:.1}%"></span></div><span class="priority-value">{}</span></li>"#,
                    linkify(&escape(&next_dependency_text(d, &say, &decimal)), &ids),
                    details(&d.file, d.line),
                    escape(&d.severity.to_ascii_lowercase()),
                    escape(&value)
                )
            })
            .collect();
        let urgent_html = if urgent_rows.is_empty() {
            String::new()
        } else {
            format!(
                r#"<ul class="priorities-list">{}</ul>"#,
                urgent_rows.concat()
            )
        };
        let next_html = if next_rows.is_empty() {
            String::new()
        } else {
            format!(
                r#"<h3>➡ {}</h3><p class="priorities-legend">{}</p><ul class="priorities-list">{next_rows}</ul>"#,
                escape(&say("next")),
                escape(&say("chart_legend"))
            )
        };
        let state = if self.urgent_count() == 0 {
            "clear"
        } else {
            "urgent"
        };
        format!(
            r#"<div class="priorities priorities-{state}" id="section-priorities"><div class="priorities-head"><div class="priorities-count">{}</div><h2>🚨 {}{}</h2></div>{urgent_html}{next_html}</div>"#,
            self.urgent_count(),
            escape(&title),
            escape(&compared)
        )
    }
}

/// One urgent row: its text, then a chart of its known vulnerabilities
/// stacked by severity, with the count of each and of the exploited ones.
fn urgent_row(
    text_html: &str,
    severities: &[&str],
    exploited: usize,
    exploited_label: &str,
) -> String {
    const ORDER: [&str; 4] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    let total = severities.len().max(1) as f64;
    let count = |s: &str| {
        severities
            .iter()
            .filter(|v| match s {
                // NONE and unknown scores count as LOW, as the engine does.
                "LOW" => !matches!(**v, "CRITICAL" | "HIGH" | "MEDIUM"),
                other => **v == other,
            })
            .count()
    };
    let segments: String = ORDER
        .iter()
        .filter(|s| count(s) > 0)
        .map(|s| {
            format!(
                r#"<span class="bar-{}" style="width:{:.1}%" title="{s} {}"></span>"#,
                s.to_ascii_lowercase(),
                count(s) as f64 / total * 100.0,
                count(s)
            )
        })
        .collect();
    let legend: Vec<String> = ORDER
        .iter()
        .filter(|s| count(s) > 0)
        .map(|s| {
            format!(
                r#"<span class="legend-{}">{s} {}</span>"#,
                s.to_ascii_lowercase(),
                count(s)
            )
        })
        .collect();
    format!(
        r#"<li class="priority priority-urgent-item"><div class="priority-text">{text_html}</div><div class="severity-stack">{segments}</div><span class="priority-value bar-exploited-text">{exploited} {}</span><div class="severity-legend">{}</div></li>"#,
        crate::report::text::escape(exploited_label),
        legend.join(" · ")
    )
}

/// `escaped` with the first occurrence of each of `ids` linked to its
/// public page: a CVE to the NVD, a GitHub advisory to GitHub, any other
/// advisory id to OSV.
fn linkify(escaped: &str, ids: &[&str]) -> String {
    let mut html = escaped.to_string();
    for id in ids {
        let escaped_id = crate::report::text::escape(id);
        let url = if id.starts_with("CVE-") {
            format!("https://nvd.nist.gov/vuln/detail/{id}")
        } else if id.starts_with("GHSA-") {
            format!("https://github.com/advisories/{id}")
        } else {
            format!("https://osv.dev/vulnerability/{id}")
        };
        if let Some(at) = html.find(&escaped_id) {
            let link = format!(
                r#"<a href="{}" target="_blank" rel="noopener noreferrer">{escaped_id}</a>"#,
                crate::report::text::escape(&url)
            );
            html.replace_range(at..at + escaped_id.len(), &link);
        }
    }
    html
}

/// A system or runtime with exploited vulnerabilities, and what to do.
fn platform_text(check: &Check, say: &dyn Fn(&str) -> String) -> String {
    let action = match (&check.support, &check.newer) {
        (Support::Behind { latest }, _) => say("upgrade_to").replace("{version}", latest),
        (_, Some((_, latest))) => say("upgrade_to").replace("{version}", latest),
        _ => say("no_fix"),
    };
    say("platform_item")
        .replace("{what}", check.detected.product.label)
        .replace("{version}", &check.detected.version)
        .replace("{count}", &check.exploited.to_string())
        .replace("{cves}", &check.exploited_cves.join(", "))
        .replace("{action}", &action)
}

/// A dependency with exploited vulnerabilities, and what to do.
fn urgent_dependency_text(d: &DependencyPriority, say: &dyn Fn(&str) -> String) -> String {
    let exploited: Vec<String> = d
        .exploited()
        .map(|c| {
            let mut text = say("exploited_cve")
                .replace("{cve}", &c.id)
                .replace("{date}", c.exploited_since.as_deref().unwrap_or_default());
            if c.ransomware {
                text.push_str(&say("ransomware"));
            }
            text
        })
        .collect();
    say("dependency_urgent_item")
        .replace("{package}", &d.package)
        .replace("{version}", &d.version)
        .replace("{file}", &d.file)
        .replace("{line}", &d.line.to_string())
        .replace("{exploited}", &exploited.join(", "))
        .replace("{action}", &fix_action(d, say))
}

/// A next dependency: its worst vulnerability, and what to do.
fn next_dependency_text(
    d: &DependencyPriority,
    say: &dyn Fn(&str) -> String,
    decimal: &str,
) -> String {
    let worst = d.cves.first();
    let epss = worst
        .and_then(|c| c.epss)
        .map(|e| {
            say("epss").replace(
                "{percent}",
                &format!("{:.1}", (e * 1000.0 + 1e-9).floor() / 10.0).replace('.', decimal),
            )
        })
        .unwrap_or_default();
    say("dependency_next_item")
        .replace("{package}", &d.package)
        .replace("{version}", &d.version)
        .replace("{file}", &d.file)
        .replace("{line}", &d.line.to_string())
        .replace("{count}", &d.cves.len().to_string())
        .replace("{cve}", worst.map(|c| c.id.as_str()).unwrap_or_default())
        .replace("{severity}", &d.severity)
        .replace("{epss}", &epss)
        .replace("{action}", &fix_action(d, say))
}

/// "upgrade to X", or that no version fixes them all.
fn fix_action(d: &DependencyPriority, say: &dyn Fn(&str) -> String) -> String {
    match &d.fixed_version {
        Some(v) => say("upgrade_to").replace("{version}", v),
        None => say("no_fix"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dependency(package: &str, severity: &str, epss: f64, exploited: bool) -> DependencyPriority {
        DependencyPriority {
            file: "package.json".to_string(),
            line: 3,
            package: package.to_string(),
            version: "1.0.0".to_string(),
            severity: severity.to_string(),
            cves: vec![PriorityCve {
                id: format!("CVE-{package}"),
                severity: severity.to_string(),
                epss: Some(epss),
                exploited_since: exploited.then(|| "2026-11-01".to_string()),
                ransomware: false,
            }],
            fixed_version: Some("2.0.0".to_string()),
        }
    }

    /// Exploited dependencies are urgent; the others follow by severity,
    /// then EPSS, at most five.
    #[test]
    fn test_urgent_then_next_in_order() {
        let deps = vec![
            dependency("a", "MEDIUM", 0.5, false),
            dependency("b", "CRITICAL", 0.01, false),
            dependency("c", "HIGH", 0.9, true),
            dependency("d", "CRITICAL", 0.08, false),
            dependency("e", "LOW", 0.1, false),
            dependency("f", "LOW", 0.2, false),
            dependency("g", "LOW", 0.3, false),
        ];
        let p = Priorities::new(&[], &deps);
        assert_eq!(p.urgent_count(), 1);
        assert_eq!(p.urgent_dependencies[0].package, "c");
        let next: Vec<&str> = p.next.iter().map(|d| d.package.as_str()).collect();
        assert_eq!(next, vec!["d", "b", "a", "g", "f"]);
    }

    /// The console lines in French: the count compared with the previous
    /// scan, each item with what to do.
    #[test]
    fn test_console_lines() {
        let locale = crate::i18n::load_script_locale("fr");
        let p = Priorities::new(
            &[],
            &[
                dependency("c", "HIGH", 0.9, true),
                dependency("d", "CRITICAL", 0.083, false),
            ],
        );
        let lines = p.console_lines(&locale, Some(3));
        assert!(lines[0].starts_with("🚨 À traiter en urgence"), "{lines:?}");
        assert!(lines[0].contains("3"), "{lines:?}");
        assert!(
            lines[1].contains("CVE-c") && lines[1].contains("2.0.0"),
            "{lines:?}"
        );
        assert!(lines[3].contains("EPSS 8,3"), "{lines:?}");
        let none = Priorities::new(&[], &[]).console_lines(&locale, None);
        assert_eq!(none.len(), 1);
    }

    /// The HTML block: escaped, marked urgent or clear, in the report's
    /// language.
    #[test]
    fn test_html_block() {
        let locale = crate::i18n::load_report_locale("en");
        let mut urgent = dependency("<x>", "HIGH", 0.9, true);
        urgent.cves[0].ransomware = true;
        let html = Priorities::new(&[], &[urgent]).html(&locale, None);
        assert!(html.contains("priorities-urgent"), "{html}");
        assert!(
            html.contains("&lt;x&gt;") && !html.contains("<x>"),
            "{html}"
        );
        assert!(html.contains("used by ransomware"), "{html}");
        // Links: the CVE to the NVD, the dependency to its finding; the
        // urgent row carries the chart of its vulnerabilities.
        assert!(
            html.contains("https://nvd.nist.gov/vuln/detail/CVE-&lt;x&gt;")
                || html.contains("nvd.nist.gov/vuln/detail/"),
            "{html}"
        );
        let anchor = crate::report::findings_html::finding_anchor(
            "vulnerable_dependency",
            "package.json",
            3,
        );
        assert!(html.contains(&format!("href=\"#{anchor}\"")), "{html}");
        assert!(
            html.contains("severity-stack") && html.contains("HIGH 1"),
            "{html}"
        );
        let clear = Priorities::new(&[], &[]).html(&locale, Some(2));
        assert!(
            clear.contains("priorities-clear") && clear.contains("previous scan: 2"),
            "{clear}"
        );
    }
}
