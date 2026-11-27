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

use crate::project::host::{Check, HostSurvey, Support};

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

/// What the dependency phase could say of the scanned folder: the
/// folder's side of the urgent list, the machine's being the system check
/// (ADR-0072, amended 2026-11-26). Before it, a folder without any
/// exploited dependency was not named at all, and read as not scanned
/// (a scan of my-ia, 2026-11-26). Recorded in the scan data, so a scan
/// skipped as unchanged names it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum FolderCheck {
    /// The dependencies were compared with the vulnerability database:
    /// `compared` of them; `unversioned` have no version to compare,
    /// `outside_database` belong to an ecosystem the database does not
    /// hold or could not load, and `unreadable_manifests` manifests could
    /// not be read, so their dependencies are not known (ADR-0070). A
    /// folder whose every manifest is unreadable is `Checked` with
    /// nothing compared, never `NoDependency`.
    Checked {
        compared: usize,
        unversioned: usize,
        outside_database: usize,
        #[serde(default)]
        unreadable_manifests: usize,
    },
    /// No manifest of the folder declares a dependency, and none is
    /// unreadable.
    NoDependency,
    /// `--quick` leaves the dependency phase out.
    Quick,
    /// The rules carry no vulnerability database.
    NoVersionRules,
    /// The vulnerability database could not be read; the console names why.
    VersionRulesUnreadable,
}

/// What to treat first.
#[derive(Debug, Clone, Default)]
pub struct Priorities {
    /// The system check of this run, whole: every detection is named,
    /// exploited or not, checked or not.
    pub host: HostSurvey,
    /// The system or runtimes with an exploited vulnerability.
    pub urgent_platform: Vec<Check>,
    /// The dependencies with an exploited vulnerability.
    pub urgent_dependencies: Vec<DependencyPriority>,
    /// The next dependencies, severity then EPSS.
    pub next: Vec<DependencyPriority>,
    /// What the dependency phase said of the folder; `None` when the scan
    /// data of a skipped scan predate it.
    pub folder: Option<FolderCheck>,
}

impl Priorities {
    /// The priorities of `host` (the system check), `dependencies` (the
    /// dependency phase) and `folder` (what that phase could compare).
    pub fn new(
        host: &HostSurvey,
        dependencies: &[DependencyPriority],
        folder: Option<FolderCheck>,
    ) -> Self {
        let urgent_platform: Vec<Check> =
            host.checks().filter(|c| c.exploited > 0).cloned().collect();
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
            host: host.clone(),
            urgent_platform,
            urgent_dependencies: urgent,
            next: rest,
            folder,
        }
    }

    /// How many things are urgent: each system or runtime, each
    /// dependency.
    pub fn urgent_count(&self) -> usize {
        self.urgent_platform.len() + self.urgent_dependencies.len()
    }

    /// The machine's side, one text per detection in the language of
    /// `locale`: what to do for an exploited one, "no exploited
    /// vulnerability" otherwise, why for one not checked; a single text
    /// when the pack has no usable system data. Each comes with the
    /// check when there is one, for the report's chart.
    fn machine_items<'a>(
        &'a self,
        locale: &serde_json::Value,
        say: &dyn Fn(&str) -> String,
    ) -> Vec<(String, Option<&'a Check>)> {
        if let Some(unavailable) = &self.host.unavailable {
            return vec![(unavailable.text(locale), None)];
        }
        self.host
            .entries
            .iter()
            .map(|entry| match &entry.result {
                Ok(check) if check.exploited > 0 => (platform_text(check, say), Some(check)),
                Ok(check) => (
                    say("platform_clear")
                        .replace("{what}", check.detected.product.label)
                        .replace("{version}", &check.detected.shown_version),
                    None,
                ),
                Err(missing) => (
                    crate::project::host::not_detected_text(missing, locale),
                    None,
                ),
            })
            .collect()
    }

    /// The folder's side, in the language of `say`'s locale.
    fn folder_text(&self, say: &dyn Fn(&str) -> String) -> String {
        let exploited = self.urgent_dependencies.len();
        match self.folder {
            None => say("folder_unrecorded"),
            Some(FolderCheck::Checked {
                compared,
                unversioned,
                outside_database,
                unreadable_manifests,
            }) => {
                // What was not compared goes in parentheses, before the
                // result, so the result is read as that of the compared
                // ones only.
                let mut left_out = Vec::new();
                if unversioned > 0 {
                    left_out.push(
                        say("folder_unversioned").replace("{count}", &unversioned.to_string()),
                    );
                }
                if outside_database > 0 {
                    left_out.push(
                        say("folder_outside_database")
                            .replace("{count}", &outside_database.to_string()),
                    );
                }
                if unreadable_manifests > 0 {
                    left_out.push(
                        say("folder_unreadable_manifests")
                            .replace("{count}", &unreadable_manifests.to_string()),
                    );
                }
                let not_compared = if left_out.is_empty() {
                    String::new()
                } else {
                    say("folder_not_compared").replace("{list}", &left_out.join(", "))
                };
                let result = if exploited == 0 {
                    say("folder_result_none")
                } else {
                    say("folder_result_some").replace("{exploited}", &exploited.to_string())
                };
                say("folder_checked")
                    .replace("{count}", &compared.to_string())
                    .replace("{not_compared}", &not_compared)
                    .replace("{result}", &result)
            }
            Some(FolderCheck::NoDependency) => say("folder_no_dependency"),
            Some(FolderCheck::Quick) => say("folder_quick"),
            Some(FolderCheck::NoVersionRules) => say("folder_no_version_rules"),
            Some(FolderCheck::VersionRulesUnreadable) => say("folder_unreadable"),
        }
    }

    /// The console lines, in the language of `locale` (the script
    /// locale). `previous` is the urgent count of the previous scan, when
    /// known. Both sides are named, even when nothing in them is
    /// exploited: the machine, each detection on its line, then the
    /// folder and its exploited dependencies.
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
        lines.push(format!("   {}", say("machine")));
        for (text, _) in self.machine_items(locale, &say) {
            lines.push(format!("     {text}"));
        }
        lines.push(format!("   {}", self.folder_text(&say)));
        for dependency in &self.urgent_dependencies {
            lines.push(format!("     {}", urgent_dependency_text(dependency, &say)));
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
    /// - the machine's side: each detection, an exploited one with a chart
    ///   of its known vulnerabilities stacked by severity and how many are
    ///   exploited, and a link to the report's "System" section;
    /// - the folder's side: what was compared, and each exploited
    ///   dependency with the same chart;
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

        let machine_rows: String = self
            .machine_items(report_locale, &say)
            .into_iter()
            .map(|(text, check)| match check {
                Some(c) => {
                    let ids: Vec<&str> = c.exploited_cves.iter().map(String::as_str).collect();
                    let severities: Vec<&str> = c
                        .vulnerabilities
                        .iter()
                        .map(|v| v.severity.as_deref().unwrap_or("UNKNOWN"))
                        .collect();
                    urgent_row(
                        &linkify(&escape(&text), &ids),
                        &severities,
                        c.exploited,
                        &exploited_label,
                    )
                }
                None => format!(
                    r#"<li class="priority priority-clear-item"><div class="priority-text">{}</div></li>"#,
                    escape(&text)
                ),
            })
            .collect();
        let machine_html = if self.host.unavailable.is_some() {
            format!(r#"<ul class="priorities-list">{machine_rows}</ul>"#)
        } else {
            format!(
                r##"<h3>{} <a class="priority-details" href="#section-system" onclick="scrollToSection('section-system'); return false;">{}</a></h3><ul class="priorities-list">{machine_rows}</ul>"##,
                escape(&say("machine")),
                escape(&say("see_system"))
            )
        };

        let dependency_rows: String = self
            .urgent_dependencies
            .iter()
            .map(|d| {
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
            })
            .collect();
        let folder_html = format!(
            r#"<h3>{}</h3>{}"#,
            escape(&self.folder_text(&say)),
            if dependency_rows.is_empty() {
                String::new()
            } else {
                format!(r#"<ul class="priorities-list">{dependency_rows}</ul>"#)
            }
        );

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
            r#"<div class="priorities priorities-{state}" id="section-priorities"><div class="priorities-head"><div class="priorities-count">{}</div><h2>🚨 {}{}</h2></div>{machine_html}{folder_html}{next_html}</div>"#,
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
        // On Linux the vulnerability is a package's: an up-to-date release
        // gets it from the distribution's own updates, not from a newer
        // release (Ubuntu 24.04.5 told to move to 26.10, 2026-11-26).
        (Support::UpToDate, _) if check.detected.on_linux => say("update_packages"),
        (_, Some((_, latest))) => say("upgrade_to").replace("{version}", latest),
        _ => say("no_fix"),
    };
    say("platform_item")
        .replace("{what}", check.detected.product.label)
        .replace("{version}", &check.detected.shown_version)
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

    /// A folder whose `compared` dependencies were all compared.
    fn checked(compared: usize) -> Option<FolderCheck> {
        Some(FolderCheck::Checked {
            compared,
            unversioned: 0,
            outside_database: 0,
            unreadable_manifests: 0,
        })
    }

    /// macOS 26.5.2 with `exploited` of its two vulnerabilities exploited.
    fn macos(exploited: usize) -> Check {
        use crate::project::platform::PlatformVulnerability;
        let vulnerability = |cve: &str, severity: &str| PlatformVulnerability {
            cve: cve.to_string(),
            version: None,
            start_including: None,
            start_excluding: None,
            end_including: None,
            end_excluding: Some("26.7.3".to_string()),
            severity: Some(severity.to_string()),
        };
        let exploited_cves: Vec<String> = ["CVE-2026-1", "CVE-2026-2"]
            .iter()
            .take(exploited)
            .map(|c| c.to_string())
            .collect();
        Check {
            detected: crate::project::host::Detected {
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
            newer: None,
            vulnerabilities: vec![
                vulnerability("CVE-2026-1", "CRITICAL"),
                vulnerability("CVE-2026-2", "HIGH"),
            ],
            exploited,
            kev: exploited_cves
                .iter()
                .map(|c| {
                    (
                        c.clone(),
                        crate::project::advisories::Exploited {
                            added: "2026-11-01".to_string(),
                            ransomware: false,
                        },
                    )
                })
                .collect(),
            exploited_cves,
            epss: Default::default(),
        }
    }

    /// The system check of a machine: macOS with `exploited` exploited
    /// vulnerabilities, and a Node.js not found.
    fn machine(exploited: usize) -> HostSurvey {
        use crate::project::host::{HostEntry, NotDetected};
        HostSurvey {
            unavailable: None,
            date: "2026-11-26".to_string(),
            stale_days: None,
            entries: vec![
                HostEntry {
                    system: true,
                    result: Ok(macos(exploited)),
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
        let p = Priorities::new(&HostSurvey::default(), &deps, checked(7));
        assert_eq!(p.urgent_count(), 1);
        assert_eq!(p.urgent_dependencies[0].package, "c");
        let next: Vec<&str> = p.next.iter().map(|d| d.package.as_str()).collect();
        assert_eq!(next, vec!["d", "b", "a", "g", "f"]);
    }

    /// The console lines in French: the count compared with the previous
    /// scan, the machine's side then the folder's, each urgent item with
    /// what to do.
    #[test]
    fn test_console_lines() {
        let locale = crate::i18n::load_script_locale("fr");
        let p = Priorities::new(
            &machine(1),
            &[
                dependency("c", "HIGH", 0.9, true),
                dependency("d", "CRITICAL", 0.083, false),
            ],
            checked(12),
        );
        let lines = p.console_lines(&locale, Some(3));
        assert!(lines[0].starts_with("🚨 À traiter en urgence"), "{lines:?}");
        assert!(lines[0].contains("2 (analyse précédente : 3)"), "{lines:?}");
        assert_eq!(lines[1], "   Cette machine :", "{lines:?}");
        assert!(
            lines[2].contains("macOS 26.5.2") && lines[2].contains("passer à 26.7.3"),
            "{lines:?}"
        );
        assert!(lines[3].contains("Node.js non vérifié"), "{lines:?}");
        assert!(
            lines[4].starts_with("   Dossier analysé : 12 dépendance(s) comparée(s)")
                && lines[4].contains("1 avec une faille exploitée"),
            "{lines:?}"
        );
        assert!(
            lines[5].contains("CVE-c") && lines[5].contains("2.0.0"),
            "{lines:?}"
        );
        assert!(lines[7].contains("EPSS 8,3"), "{lines:?}");
    }

    /// Nothing exploited on either side: both are still named, so a folder
    /// is never read as not scanned (my-ia, 2026-11-26).
    #[test]
    fn test_console_lines_name_both_sides_when_nothing_is_exploited() {
        let locale = crate::i18n::load_script_locale("en");
        let lines = Priorities::new(&machine(0), &[], checked(37)).console_lines(&locale, None);
        assert_eq!(
            lines,
            vec![
                "🚨 To treat urgently: no known exploited vulnerability (CISA KEV)".to_string(),
                "   This machine:".to_string(),
                "     macOS 26.5.2: no exploited vulnerability".to_string(),
                "     Node.js not checked: node not found on PATH outside the scanned folder."
                    .to_string(),
                "   Scanned folder: 37 dependency(ies) compared with the vulnerability database, none with an exploited vulnerability".to_string(),
            ]
        );
    }

    /// Every state of the folder has its own text: nothing compared is
    /// never written as nothing exploited.
    #[test]
    fn test_folder_states() {
        let locale = crate::i18n::load_script_locale("en");
        let folder = |state: Option<FolderCheck>| {
            Priorities::new(&machine(0), &[], state).console_lines(&locale, None)[4].clone()
        };
        let partly = folder(Some(FolderCheck::Checked {
            compared: 3,
            unversioned: 1,
            outside_database: 2,
            unreadable_manifests: 1,
        }));
        assert!(
            partly.contains("3 dependency(ies) compared")
                && partly.contains("1 without a version")
                && partly.contains("2 of an ecosystem the database does not hold")
                && partly.contains("1 unreadable manifest(s)"),
            "{partly}"
        );
        assert!(folder(Some(FolderCheck::NoDependency)).contains("no declared dependency"));
        assert!(folder(Some(FolderCheck::Quick)).contains("--quick"));
        assert!(folder(Some(FolderCheck::NoVersionRules)).contains("no vulnerability database"));
        assert!(folder(Some(FolderCheck::VersionRulesUnreadable)).contains("could not be read"));
        assert!(folder(None).contains("--no-cache"));
        // Without system data, the machine's side says why on one line.
        let survey = HostSurvey {
            unavailable: Some(crate::project::host::HostUnavailable::NoData),
            ..HostSurvey::default()
        };
        let lines = Priorities::new(&survey, &[], checked(1)).console_lines(&locale, None);
        assert!(lines[2].contains("not checked"), "{lines:?}");
        // Every state reads the same in the scan data and back.
        for state in [
            checked(2),
            Some(FolderCheck::NoDependency),
            Some(FolderCheck::Quick),
        ] {
            let json = serde_json::to_string(&state).unwrap();
            assert_eq!(
                serde_json::from_str::<Option<FolderCheck>>(&json).unwrap(),
                state
            );
        }
    }

    /// The HTML block: escaped, marked urgent or clear, in the report's
    /// language, with both sides and the link to the "System" section.
    #[test]
    fn test_html_block() {
        let locale = crate::i18n::load_report_locale("en");
        let mut urgent = dependency("<x>", "HIGH", 0.9, true);
        urgent.cves[0].ransomware = true;
        let html = Priorities::new(&machine(2), &[urgent], checked(4)).html(&locale, None);
        assert!(html.contains("priorities-urgent"), "{html}");
        assert!(
            html.contains("&lt;x&gt;") && !html.contains("<x>"),
            "{html}"
        );
        assert!(html.contains("used by ransomware"), "{html}");
        // Links: the CVE to the NVD, the dependency to its finding; the
        // urgent row carries the chart of its vulnerabilities.
        assert!(
            html.contains("nvd.nist.gov/vuln/detail/CVE-2026-1"),
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
        assert!(html.contains("href=\"#section-system\""), "{html}");
        assert!(html.contains("Node.js not checked"), "{html}");
        assert!(
            html.contains("Scanned folder: 4 dependency(ies) compared"),
            "{html}"
        );
        let clear = Priorities::new(&machine(0), &[], checked(4)).html(&locale, Some(2));
        assert!(
            clear.contains("priorities-clear") && clear.contains("previous scan: 2"),
            "{clear}"
        );
        assert!(
            clear.contains("macOS 26.5.2: no exploited vulnerability"),
            "{clear}"
        );
    }
}
