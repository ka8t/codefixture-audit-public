//! GitLab SAST report export (`scan --format gitlab-sast`, ticket #295).
//!
//! GitLab reads its own JSON report, declared with `artifacts:reports:sast`
//! in a job, not SARIF. This module writes that report, in version
//! [`GITLAB_SAST_SCHEMA_VERSION`] of GitLab's security report schemas
//! (`gitlab-org/security-products/security-report-schemas`, copied in
//! `resources/schemas/gitlab/sast-report-format.json`, which the tests validate
//! against). No counterpart in the Python engine Audit.
//!
//! Choices, from GitLab's documentation read on 2026-11-25 (ADR-0069):
//!
//! - **Every finding goes in this one report**, the vulnerable
//!   dependencies included, each located at its manifest line. GitLab's
//!   `dependency_scanning` report belongs to its Gemnasium analyzer,
//!   deprecated since GitLab 17.9, and to the Ultimate tier; the list of
//!   dependencies goes to GitLab as the CycloneDX SBOM (`--sbom-output`,
//!   `artifacts:reports:cyclonedx`).
//! - **The primary identifier is the rule**, then its CWE and OWASP
//!   entries: GitLab tracks a vulnerability by its primary identifier and
//!   its location (file, first and last line).
//! - **The finding's identity of ADR-0067** goes in `tracking` as a signature
//!   of algorithm `hash`, the one GitLab's code names for a signature that
//!   is not a physical location
//!   (`app/models/concerns/vulnerability_finding_signature_helpers.rb`).
//!   GitLab uses these signatures in its advanced tracking, an Ultimate
//!   feature: not checked on a GitLab instance.

use serde::Serialize;

use crate::report::exports::sarif::ReportFinding;

/// The version of GitLab's security report schemas this module writes:
/// the latest one published on 2026-11-25 (tag v15.2.5). GitLab validates a
/// report against the version it declares, and a PATCH version it does not
/// know against the latest PATCH version it has.
pub const GITLAB_SAST_SCHEMA_VERSION: &str = "15.2.5";

/// GitLab keeps the first 20 identifiers of a vulnerability ("If a
/// vulnerability has more than 20 identifiers, the system saves only the
/// first 20 of them"): beyond, [`gitlab_identifier_limits`] names the rule.
pub const GITLAB_MAX_IDENTIFIERS: usize = 20;

/// The report: `version`, `scan`, `vulnerabilities`, the three required
/// top-level fields of the schema.
#[derive(Debug, Serialize, PartialEq)]
pub struct GitlabReport {
    pub version: String,
    pub scan: GitlabScan,
    pub vulnerabilities: Vec<GitlabVulnerability>,
}

/// What ran the scan, and when.
#[derive(Debug, Serialize, PartialEq)]
pub struct GitlabScan {
    pub analyzer: GitlabTool,
    pub scanner: GitlabTool,
    /// Always `sast`.
    #[serde(rename = "type")]
    pub scan_type: String,
    /// UTC, `yyyy-mm-ddThh:mm:ss`, as the schema requires.
    pub start_time: String,
    pub end_time: String,
    /// `success`: a scan that found vulnerabilities succeeded; a scan that
    /// failed writes no report at all.
    pub status: String,
}

/// The analyzer or the scanner: here both are the engine.
#[derive(Debug, Serialize, PartialEq)]
pub struct GitlabTool {
    pub id: String,
    pub name: String,
    pub version: String,
    pub vendor: GitlabVendor,
}

/// The vendor of the engine.
#[derive(Debug, Serialize, PartialEq)]
pub struct GitlabVendor {
    pub name: String,
}

/// One finding, as a GitLab vulnerability.
#[derive(Debug, Serialize, PartialEq)]
pub struct GitlabVulnerability {
    /// A UUID made of the finding's identity: stable from one pipeline to
    /// the next for the same finding.
    pub id: String,
    /// The rule's name (at most 255 characters for the schema).
    pub name: String,
    /// The risk the finding raises.
    pub description: String,
    /// `Critical`, `High`, `Medium`, `Low` or `Info`.
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solution: Option<String>,
    /// The rule first (the primary identifier), then its CWE and OWASP.
    pub identifiers: Vec<GitlabIdentifier>,
    pub location: GitlabLocation,
    pub tracking: GitlabTracking,
}

/// An identifier of a vulnerability.
#[derive(Debug, Serialize, PartialEq)]
pub struct GitlabIdentifier {
    #[serde(rename = "type")]
    pub identifier_type: String,
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Where a vulnerability is: GitLab's location fingerprint of a SAST
/// vulnerability combines `file`, `start_line` and `end_line`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GitlabLocation {
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
}

/// `tracking` of type `source`: one item, the finding's location, with its
/// identity as a `hash` signature.
#[derive(Debug, Serialize, PartialEq)]
pub struct GitlabTracking {
    #[serde(rename = "type")]
    pub tracking_type: String,
    pub items: Vec<GitlabTrackingItem>,
}

/// One tracked item.
#[derive(Debug, Serialize, PartialEq)]
pub struct GitlabTrackingItem {
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub signatures: Vec<GitlabSignature>,
}

/// One tracking signature.
#[derive(Debug, Serialize, PartialEq)]
pub struct GitlabSignature {
    pub algorithm: String,
    pub value: String,
}

/// The engine as GitLab names it in the report: `tool_name` (from
/// `brand.json`), the release version and the vendor.
pub struct GitlabToolInfo<'a> {
    pub tool_name: &'a str,
    pub tool_version: &'a str,
    pub vendor: &'a str,
}

/// GitLab's severity of an engine severity. The engine writes no other
/// severity; one it would is `Unknown`, a value of the schema, never a
/// made-up level.
fn gitlab_severity(severity: &str) -> &'static str {
    match severity {
        "CRITICAL" => "Critical",
        "HIGH" => "High",
        "MEDIUM" => "Medium",
        "LOW" => "Low",
        "INFO" => "Info",
        _ => "Unknown",
    }
}

/// The primary identifier's value: the rule as `<language>/<name>`, or
/// `<category>/<name>` for a project check, which has no language. Unlike
/// the SARIF rule id (ADR-0068), the severity is not part of it: GitLab
/// shows each vulnerability's own severity, and a dependency whose worst
/// CVE changes severity stays the same vulnerability.
fn primary_identifier(f: &ReportFinding) -> String {
    if f.rule_language.is_empty() {
        format!("{}/{}", f.category.to_lowercase(), f.rule_key)
    } else {
        f.rule_id().to_string()
    }
}

/// A CWE identifier: `CWE-79` gives the value `79` and MITRE's page; a CWE
/// written otherwise keeps its text as value, without a link.
fn cwe_identifier(cwe: &str) -> GitlabIdentifier {
    let number = cwe
        .strip_prefix("CWE-")
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    GitlabIdentifier {
        identifier_type: "cwe".to_string(),
        name: cwe.to_string(),
        value: number.unwrap_or(cwe).to_string(),
        url: number.map(|n| format!("https://cwe.mitre.org/data/definitions/{n}.html")),
    }
}

/// The location of a finding. A finding about a whole file (ticket #214)
/// spans its lines, 1 to its length: the schema has no whole-file location,
/// and GitLab's fingerprint needs a first and a last line.
fn gitlab_location(f: &ReportFinding) -> GitlabLocation {
    let (start_line, end_line) = match &f.file_scope {
        Some(scope) => (1, scope.line_count.max(1)),
        None => (f.line.max(1), f.line.max(1)),
    };
    GitlabLocation {
        file: f.file.replace('\\', "/"),
        start_line,
        end_line,
    }
}

/// The UUID form (8-4-4-4-12) of the first 32 hexadecimal digits of a
/// SHA-256, with the version (5, a name-based UUID) and variant bits set.
fn uuid_of(sha256_hex: &str) -> String {
    let mut hex: Vec<char> = sha256_hex.chars().take(32).collect();
    hex[12] = '5';
    let variant = hex[16].to_digit(16).unwrap_or(0);
    hex[16] = std::char::from_digit((variant & 0x3) | 0x8, 16).unwrap_or('8');
    let hex: String = hex.into_iter().collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Builds the GitLab SAST report of `findings`, scanned from `start_time` to
/// `end_time` (UTC, `yyyy-mm-ddThh:mm:ss`).
pub fn build_gitlab_sast_report(
    findings: &[ReportFinding],
    tool: &GitlabToolInfo<'_>,
    start_time: &str,
    end_time: &str,
) -> GitlabReport {
    let engine = || GitlabTool {
        id: "codefixture-audit".to_string(),
        name: tool.tool_name.to_string(),
        version: tool.tool_version.to_string(),
        vendor: GitlabVendor {
            name: tool.vendor.to_string(),
        },
    };
    let identities = crate::report::comparison::finding_identities(findings);
    let vulnerabilities = findings
        .iter()
        .zip(&identities)
        .map(|(f, identity)| {
            let hash = crate::scan::scan_cache::sha256_hex(identity.as_bytes());
            let mut identifiers = vec![GitlabIdentifier {
                identifier_type: "codefixture_audit_rule".to_string(),
                name: f.rule_name.clone(),
                value: primary_identifier(f),
                url: None,
            }];
            identifiers.extend(f.cwe.iter().map(|cwe| cwe_identifier(cwe)));
            if let Some(owasp) = &f.owasp {
                identifiers.push(GitlabIdentifier {
                    identifier_type: "owasp".to_string(),
                    name: owasp.clone(),
                    value: owasp.clone(),
                    url: None,
                });
            }
            let location = gitlab_location(f);
            GitlabVulnerability {
                id: uuid_of(&hash),
                name: f.rule_name.chars().take(255).collect(),
                description: if f.risk.is_empty() {
                    f.rule_name.clone()
                } else {
                    f.risk.clone()
                },
                severity: gitlab_severity(&f.severity).to_string(),
                solution: f
                    .solution
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.chars().take(7_000).collect()),
                identifiers,
                tracking: GitlabTracking {
                    tracking_type: "source".to_string(),
                    items: vec![GitlabTrackingItem {
                        file: location.file.clone(),
                        start_line: location.start_line,
                        end_line: location.end_line,
                        signatures: vec![GitlabSignature {
                            algorithm: "hash".to_string(),
                            value: hash,
                        }],
                    }],
                },
                location,
            }
        })
        .collect();
    GitlabReport {
        version: GITLAB_SAST_SCHEMA_VERSION.to_string(),
        scan: GitlabScan {
            analyzer: engine(),
            scanner: engine(),
            scan_type: "sast".to_string(),
            start_time: start_time.to_string(),
            end_time: end_time.to_string(),
            status: "success".to_string(),
        },
        vulnerabilities,
    }
}

/// The rules whose vulnerabilities have more identifiers than GitLab keeps
/// ([`GITLAB_MAX_IDENTIFIERS`]), with the largest count of each, in rule
/// order: the console names them, since GitLab drops the identifiers
/// beyond the 20th without a word.
pub fn gitlab_identifier_limits(report: &GitlabReport) -> Vec<(String, usize)> {
    let mut worst: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for vulnerability in &report.vulnerabilities {
        let count = vulnerability.identifiers.len();
        if count > GITLAB_MAX_IDENTIFIERS {
            let rule = vulnerability.identifiers[0].value.clone();
            let entry = worst.entry(rule).or_default();
            *entry = (*entry).max(count);
        }
    }
    worst.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::exports::sarif::TaintFlow;

    fn finding(rule_key: &str, file: &str, line: usize) -> ReportFinding {
        ReportFinding {
            rule_key: rule_key.to_string(),
            rule_language: "python".to_string(),
            rule_name: "Command injection".to_string(),
            category: "SECURITY".to_string(),
            severity: "HIGH".to_string(),
            risk: "User input reaches a shell command.".to_string(),
            file: file.to_string(),
            line,
            solution: Some("Pass the arguments as a list.".to_string()),
            cwe: vec!["CWE-78".to_string()],
            owasp: Some("A03:2021".to_string()),
            taint_flow: None,
            taint_flows: vec![],
            code: "os.system(input())".to_string(),
            context_before: String::new(),
            context_after: String::new(),
            confidence: 90,
            benefit: String::new(),
            committer: None,
            rule_source: "json_builtin".to_string(),
            file_scope: None,
        }
    }

    const TOOL: GitlabToolInfo<'static> = GitlabToolInfo {
        tool_name: "codefixture-audit",
        tool_version: "3.1.0",
        vendor: "CodeFixture",
    };

    fn build(findings: &[ReportFinding]) -> GitlabReport {
        build_gitlab_sast_report(
            findings,
            &TOOL,
            "2026-11-25T10:00:00",
            "2026-11-25T10:00:05",
        )
    }

    /// Ticket #295: the rule is the primary identifier, then its CWE (with
    /// MITRE's page) and OWASP; the severity and the location are GitLab's.
    #[test]
    fn test_vulnerability_fields() {
        let report = build(&[finding("os_system_injection", "app.py", 12)]);
        assert_eq!(report.version, "15.2.5");
        let v = &report.vulnerabilities[0];
        assert_eq!(v.severity, "High");
        assert_eq!(v.identifiers[0].value, "python/os_system_injection");
        assert_eq!(v.identifiers[1].value, "78");
        assert_eq!(
            v.identifiers[1].url.as_deref(),
            Some("https://cwe.mitre.org/data/definitions/78.html")
        );
        assert_eq!(v.identifiers[2].identifier_type, "owasp");
        assert_eq!(
            v.location,
            GitlabLocation {
                file: "app.py".to_string(),
                start_line: 12,
                end_line: 12
            }
        );
        assert_eq!(v.tracking.items[0].signatures[0].algorithm, "hash");
        assert_eq!(v.solution.as_deref(), Some("Pass the arguments as a list."));
    }

    /// Ticket #295: the id and the tracking signature are the finding's
    /// identity: unchanged when the line moves, different for two identical
    /// lines of one file; the id is a UUID.
    #[test]
    fn test_identity_survives_a_line_shift() {
        let first = build(&[finding("x", "a.py", 3)]);
        let moved = build(&[finding("x", "a.py", 40)]);
        assert_eq!(first.vulnerabilities[0].id, moved.vulnerabilities[0].id);
        assert_eq!(
            first.vulnerabilities[0].tracking.items[0].signatures,
            moved.vulnerabilities[0].tracking.items[0].signatures
        );
        let twins = build(&[finding("x", "a.py", 3), finding("x", "a.py", 9)]);
        assert_ne!(twins.vulnerabilities[0].id, twins.vulnerabilities[1].id);
        let uuid = regex::Regex::new(
            "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        .unwrap();
        assert!(
            uuid.is_match(&first.vulnerabilities[0].id),
            "{}",
            first.vulnerabilities[0].id
        );
    }

    /// Ticket #295: a project check is identified by its category and name,
    /// without its severity; a whole-file finding spans the file's lines; a
    /// CWE written otherwise keeps its text.
    #[test]
    fn test_project_checks_and_whole_file_findings() {
        let mut dependency = finding("vulnerable_dependency", "requirements.txt", 2);
        dependency.rule_language = String::new();
        dependency.category = "DEPENDENCIES".to_string();
        dependency.cwe = vec!["NVD-CWE-noinfo".to_string()];
        let mut whole = finding("file_too_long", "big.py", 1);
        whole.file_scope = Some(crate::scan::engine::FileScope {
            line_count: 2_400,
            min_lines: Some(1_000),
        });
        let report = build(&[dependency, whole]);
        let identifiers = &report.vulnerabilities[0].identifiers;
        assert_eq!(identifiers[0].value, "dependencies/vulnerable_dependency");
        assert_eq!(
            (identifiers[1].value.as_str(), identifiers[1].url.as_deref()),
            ("NVD-CWE-noinfo", None)
        );
        assert_eq!(
            (
                report.vulnerabilities[1].location.start_line,
                report.vulnerabilities[1].location.end_line
            ),
            (1, 2_400)
        );
    }

    /// Ticket #295: more identifiers than GitLab keeps are named, by rule.
    #[test]
    fn test_identifier_limit_is_named() {
        let mut many = finding("x", "a.py", 1);
        many.cwe = (0..25).map(|i| format!("CWE-{i}")).collect();
        let report = build(&[many, finding("y", "b.py", 1)]);
        assert_eq!(
            gitlab_identifier_limits(&report),
            [("python/x".to_string(), 27)]
        );
    }

    /// Ticket #295: the report validates against GitLab's official SAST
    /// schema, version 15.2.5, offline, with every kind of finding the
    /// engine writes; the validator does refuse a report without `scan`.
    #[test]
    fn test_report_validates_against_the_gitlab_schema() {
        let schema: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("resources/schemas/gitlab/sast-report-format.json"),
            )
            .expect("GitLab SAST schema"),
        )
        .expect("schema is JSON");
        let validator = jsonschema::validator_for(&schema).expect("valid JSON Schema");
        let mut taint = finding("taint_sqli", "db.py", 12);
        taint.taint_flow = Some(TaintFlow {
            rule_key: "taint_sqli".to_string(),
            source_file: "db.py".to_string(),
            source_line: 3,
            source_expr: "request.args['q']".to_string(),
            chain: vec![],
            sink_file: "db.py".to_string(),
            sink_line: 12,
            sink_expr: "cursor.execute(q)".to_string(),
            source_kind: "http".to_string(),
            steps: vec![],
        });
        let mut no_solution = finding("y", "b.py", 1);
        no_solution.solution = None;
        no_solution.owasp = None;
        no_solution.cwe = vec![];
        no_solution.severity = "INFO".to_string();
        let mut dependency = finding("vulnerable_dependency", "package.json", 4);
        dependency.rule_language = String::new();
        dependency.category = "DEPENDENCIES".to_string();
        dependency.severity = "CRITICAL".to_string();
        let instance =
            serde_json::to_value(build(&[taint, no_solution, dependency])).expect("report to JSON");
        let errors: Vec<String> = validator
            .iter_errors(&instance)
            .map(|e| format!("{e} at {}", e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "GitLab schema errors: {errors:#?}");
        let mut without_scan = instance.clone();
        without_scan.as_object_mut().unwrap().remove("scan");
        assert!(!validator.is_valid(&without_scan));
    }
}
