//! SARIF 2.1.0 export.
//!
//! Port of `Audit/sca/comparison.py::_export_sarif`, with these deliberate
//! deviations for code platforms (ticket #291, ADR-0068): one rule per
//! severity for the project checks (`dependencies/vulnerable_dependency/high`),
//! rule tags gathered from all their findings, a `security-severity` for the
//! security and dependency rules, `partialFingerprints` per result under
//! our versioned name and under `primaryLocationLineHash`, the only one
//! GitHub reads (ADR-0067, ADR-0068), `automationDetails`, and the solution in the message
//! instead of a `fixes` entry the schema refuses. The output validates
//! against the official schema (`tests/data/sarif-schema-2.1.0.json`). Version
//! **2.1.0** unambiguously (stable/final version of the OASIS
//! standard, already the one produced by Python — `$schema`
//! explicitly references `sarif-schema-2.1.0.json`).
//!
//! **Input**: `ReportFinding`, a flat denormalized model (each finding
//! carries its `risk`/`cwe`/`owasp` directly, no separate lookup in a
//! rule catalog like `self._rule(rk)` on the Python side) — this
//! module remains a pure data→JSON transformer, independent of the
//! orchestrator (Step 5, not yet built) which will have to build these
//! `ReportFinding` from the outputs of the various executors
//! (`engine::Finding` for regex/file_contains/ast,
//! `dataflow::transfer::Finding` for taint).
//!
//! Accepted simplification: the `rk = f.rule_key or f.rule` (fallback)
//! on the Python side exists for legacy findings outside the DSL
//! engine (dependency scanning) — out of scope, a product decision
//! already made (`project_no_dependency_scanning`): every finding from
//! this engine always has a `rule_key`, no fallback needed.
//!
//! Temporary `#![allow(dead_code)]`: not yet wired to the CLI (Step 5,
//! sequenced afterward) — to be removed at that point.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Flat model of a finding, as consumed by the SARIF export (and,
/// eventually, the other report formats). Denormalized: rule data
/// (risk/cwe/owasp) is carried directly by the finding, not resolved
/// via a separate catalog.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportFinding {
    /// The rule's name, as users see and write it (suppressions, history).
    pub rule_key: String,
    /// The rule's language (`language` of the rule): with `rule_key`, the
    /// rule's identity (`rules::identity::RuleId`), which tells apart the
    /// rules sharing a name across languages. Empty for the findings of no
    /// catalog rule (dependencies), and in a history file written before
    /// 2026-11-14 (`#[serde(default)]`).
    #[serde(default)]
    pub rule_language: String,
    pub rule_name: String,
    pub category: String,
    /// CRITICAL | HIGH | MEDIUM | LOW | INFO.
    pub severity: String,
    pub risk: String,
    pub file: String,
    pub line: usize,
    pub solution: Option<String>,
    pub cwe: Vec<String>,
    pub owasp: Option<String>,
    /// First taint flow attached to this finding — compatibility alias
    /// pointing to `taint_flows[0]`, mirroring `Finding.taint_flow`
    /// (singular) on the Audit side. `None` for a regex/file_contains/
    /// ast finding that no taint flow has ever joined.
    pub taint_flow: Option<TaintFlow>,
    /// All taint flows attached to this finding — mirrors
    /// `Finding.taint_flows` (`rule_engine.py::_integrate_taint_flow`):
    /// when a flow reaches a sink already flagged by an existing
    /// finding on the same line, it is added here instead of
    /// duplicating a report line (cf. `orchestrator::
    /// integrate_taint_finding`). `#[serde(default)]` to stay
    /// compatible with a baseline JSON written before this field.
    #[serde(default)]
    pub taint_flows: Vec<TaintFlow>,
    /// Detected code line — needed by the HTML report
    /// (`finding-item.html`), absent from SARIF/SBOM exports.
    pub code: String,
    /// Context displayed around the detected line (2 lines before/after
    /// by default, joined with `\n`) — port of `sca/utils.py::get_context`.
    pub context_before: String,
    pub context_after: String,
    /// Confidence score 0-100 — fixed at 90 for taint findings
    /// (mirrors `sca/rule_engine.py:1131`), as declared by the rule
    /// for regex/file_contains/ast findings.
    pub confidence: i64,
    pub benefit: String,
    /// Author of the last commit that touched the line — `None` as
    /// long as git blame isn't wired up (separate effort, not yet
    /// implemented on the codefixture-audit side).
    pub committer: Option<String>,
    /// Where the rule comes from: "json_builtin" (the catalog,
    /// `rules.cfpack` next to the executable or `--rules <PATH>`), "json_custom"
    /// (the client's own rules, custom rules folder), "advisory_db"
    /// (vulnerable dependency).
    pub rule_source: String,
    /// `Some` when the finding is about the whole file, not one of its
    /// lines: `line` and `code` are then only conventions (line 1, first
    /// non-blank line), kept for the suppression and comparison identity,
    /// and every output shows the file instead (ticket #214). Absent from
    /// a history file written before this field (`serde(default)`) and not
    /// written for a line finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_scope: Option<crate::scan::engine::FileScope>,
}

impl ReportFinding {
    /// The identity of the rule that produced the finding: the key of its
    /// texts in the scan's `RuleCatalog`.
    pub fn rule_id(&self) -> crate::rules::identity::RuleId {
        crate::rules::identity::RuleId::new(&self.rule_language, &self.rule_key)
    }
}

/// Source → sink flow of a taint finding, for `codeFlows` (standard
/// SARIF 2.1.0).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaintFlow {
    /// DSL rule that originated this flow — mirrors `TaintFlow.rule_key`
    /// on the Audit side (`sca/models.py`). Used to deduplicate attaching
    /// the same flow twice to a finding (`orchestrator::
    /// integrate_taint_finding`) and, eventually, to display which rules
    /// contributed to a merged finding.
    #[serde(default)]
    pub rule_key: String,
    pub source_file: String,
    pub source_line: usize,
    pub source_expr: String,
    /// (line, variable name, code) — intermediate propagation steps.
    pub chain: Vec<(usize, String, String)>,
    pub sink_file: String,
    pub sink_line: usize,
    pub sink_expr: String,
    /// http | cli | env | stdin | file | network — mirrors
    /// `TaintFlow.source_kind` on the Audit side (`sca/models.py`), as
    /// declared by the `SourceSpec` of the DSL rule that matched.
    /// `#[serde(default)]` to stay compatible with a baseline JSON
    /// written before this field.
    #[serde(default)]
    pub source_kind: String,
    /// Every step of the path in order, source first and sink last, each
    /// with its own file and code line: the report draws the path from
    /// it, including the steps inside a function of another file.
    /// Empty in a baseline written before this field (`chain` and
    /// `sink_*` then describe the flow).
    #[serde(default)]
    pub steps: Vec<TaintStep>,
}

/// One step of a taint path, as shown in the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaintStep {
    /// "source" | "propagation" | "sink".
    pub kind: String,
    /// File relative to the scanned root.
    pub file: String,
    pub line: usize,
    /// The real code line, trimmed; the engine's description of the
    /// step when the line could not be read.
    pub code: String,
}

fn severity_to_sarif_level(severity: &str) -> String {
    match severity {
        "CRITICAL" | "HIGH" => "error",
        "MEDIUM" => "warning",
        "LOW" | "INFO" => "note",
        _ => "warning",
    }
    .to_string()
}

/// Normalizes a file path into a SARIF URI (`/` separators,
/// OS-independent).
fn normalize_uri(path: &str) -> String {
    path.replace('\\', "/")
}

// ============================================================================
// SARIF types (exact JSON structure)
// ============================================================================

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifRun {
    pub tool: SarifTool,
    /// `runAutomationDetails`: the category of the analysis, which GitHub
    /// code scanning uses to tell the uploads of several jobs apart
    /// (ticket #291).
    #[serde(rename = "automationDetails")]
    pub automation_details: SarifAutomationDetails,
    pub results: Vec<SarifResult>,
}

/// `runAutomationDetails` of SARIF 2.1.0: `id` is `<category>/`, the part
/// before the last `/` naming the kind of analysis.
#[derive(Debug, Serialize, PartialEq)]
pub struct SarifAutomationDetails {
    pub id: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifText,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifText,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifRuleConfig,
    pub properties: SarifRuleProperties,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifText {
    pub text: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifRuleConfig {
    pub level: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifRuleProperties {
    pub category: String,
    pub tags: Vec<String>,
    /// `security-severity`, a score from 0.1 to 10.0 written as text, which
    /// GitHub code scanning reads to rank a security alert (critical from
    /// 9.0, high from 7.0, medium from 4.0, low below). Only for the
    /// security and dependency rules, which carry the `security` tag; never
    /// for an INFO rule (ticket #291).
    #[serde(rename = "security-severity", skip_serializing_if = "Option::is_none")]
    pub security_severity: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "ruleIndex")]
    pub rule_index: usize,
    pub level: String,
    /// The risk, then the solution as a second paragraph. A SARIF `fix`
    /// needs `artifactChanges` (the replacement text), which a solution
    /// written in words does not give: until 2026-11-25 the solution went
    /// into a `fixes` entry without them, which the SARIF 2.1.0 schema
    /// refuses (ticket #291).
    pub message: SarifText,
    pub locations: Vec<SarifLocation>,
    /// `partialFingerprints`: the identity of the finding across scans, so
    /// that a code platform does not reopen a finding whose line moved.
    #[serde(rename = "partialFingerprints")]
    pub partial_fingerprints: std::collections::BTreeMap<String, String>,
    #[serde(rename = "codeFlows", skip_serializing_if = "Option::is_none")]
    pub code_flows: Option<Vec<SarifCodeFlow>>,
    /// The CWE of a project check's finding (a vulnerable dependency: the
    /// CWE of its CVEs), which its rule's tags do not carry; `None` for a
    /// catalog rule, whose rule tags hold its CWE.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifResultProperties>,
}

/// The property bag of a result (SARIF 2.1.0 `propertyBag`).
#[derive(Debug, Serialize, PartialEq)]
pub struct SarifResultProperties {
    pub cwe: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    /// `None` for a finding about the whole file: SARIF 2.1.0
    /// reads a physical location without a region as the whole artifact,
    /// where `startLine: 1` would point a SARIF viewer at line 1
    /// (ticket #214).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifCodeFlow {
    #[serde(rename = "threadFlows")]
    pub thread_flows: Vec<SarifThreadFlow>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifThreadFlow {
    pub locations: Vec<SarifThreadFlowLocation>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifThreadFlowLocation {
    pub location: SarifThreadFlowLocationInner,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SarifThreadFlowLocationInner {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
    pub message: SarifText,
}

// ============================================================================
// Building
// ============================================================================

fn physical_location(file: &str, line: usize) -> SarifPhysicalLocation {
    SarifPhysicalLocation {
        artifact_location: SarifArtifactLocation {
            uri: normalize_uri(file),
        },
        region: Some(SarifRegion {
            start_line: line.max(1),
        }),
    }
}

/// The location of a finding: its line, or the whole file for a
/// whole-file finding (ticket #214).
fn finding_location(f: &ReportFinding) -> SarifPhysicalLocation {
    if f.file_scope.is_some() {
        SarifPhysicalLocation {
            artifact_location: SarifArtifactLocation {
                uri: normalize_uri(&f.file),
            },
            region: None,
        }
    } else {
        physical_location(&f.file, f.line)
    }
}

fn build_code_flows(tf: &TaintFlow) -> Vec<SarifCodeFlow> {
    let mut locations = Vec::with_capacity(tf.chain.len() + 2);
    locations.push(SarifThreadFlowLocation {
        location: SarifThreadFlowLocationInner {
            physical_location: physical_location(&tf.source_file, tf.source_line),
            message: SarifText {
                text: format!("Source: {}", tf.source_expr),
            },
        },
    });
    for (line, var, code) in &tf.chain {
        let code_snippet: String = code.chars().take(80).collect();
        locations.push(SarifThreadFlowLocation {
            location: SarifThreadFlowLocationInner {
                physical_location: physical_location(&tf.source_file, *line),
                message: SarifText {
                    text: format!("{var}: {code_snippet}"),
                },
            },
        });
    }
    locations.push(SarifThreadFlowLocation {
        location: SarifThreadFlowLocationInner {
            physical_location: physical_location(&tf.sink_file, tf.sink_line),
            message: SarifText {
                text: format!("Impact: {}", tf.sink_expr),
            },
        },
    });
    vec![SarifCodeFlow {
        thread_flows: vec![SarifThreadFlow { locations }],
    }]
}

/// Name of the finding identity in `partialFingerprints` (ADR-0067). The
/// version is part of the name, the SARIF convention
/// (`primaryLocationLineHash/v1`): a later change of the identity ships as
/// `/v2`, so that a platform that kept the `/v1` values does not see every
/// finding as new.
pub const FINDING_FINGERPRINT: &str = "codefixtureFinding/v1";

/// The fingerprint GitHub code scanning reads, and the only one: "Code
/// scanning only uses the `primaryLocationLineHash`" (GitHub's SARIF
/// documentation, read on 2026-11-25). It carries the same identity as
/// [`FINDING_FINGERPRINT`]. Without it, GitHub matched a result to the
/// alert of another line of the same rule: on ka8t/ChannelAgent-Public, a
/// removed line closed the alert of the next line and kept its own
/// (ticket #294). GitHub's name has no version: a later change of the
/// identity makes GitHub see every finding as new once.
pub const GITHUB_FINGERPRINT: &str = "primaryLocationLineHash";

/// The official location of the SARIF 2.1.0 schema (OASIS, errata 01),
/// the one the tests validate against (`tests/data/sarif-schema-2.1.0.json`).
pub const SARIF_SCHEMA_URI: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

/// The SARIF rule a finding belongs to. A catalog rule is `<language>/<name>`
/// (`RuleId`'s notation): SARIF requires unique rule ids, and the Python and
/// JavaScript `base64_eval` are two rules. A project check has no language
/// and a severity that can change from one finding to the next
/// (`vulnerable_dependency` takes the severity of its worst CVE), while a
/// code platform reads the severity from the rule: it is one rule per
/// category, name and severity, `dependencies/vulnerable_dependency/high`
/// (ticket #291, the maintainer's choice of 2026-11-25). Before, every vulnerable
/// dependency shared one rule `vulnerable_dependency` with the level and
/// tags of the first one found.
fn sarif_rule_id(f: &ReportFinding) -> String {
    if f.rule_language.is_empty() {
        format!(
            "{}/{}/{}",
            f.category.to_lowercase(),
            f.rule_key,
            f.severity.to_lowercase()
        )
    } else {
        f.rule_id().to_string()
    }
}

/// Rank of a severity, the worst first: the rule of several findings
/// takes the worst one.
fn severity_rank(severity: &str) -> u8 {
    match severity {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    }
}

/// Whether a rule's findings are security alerts for a code platform: the
/// security rules, and the dependency checks, which count for the security
/// score too (ADR-0054). They carry the `security` tag and a
/// `security-severity`.
fn is_security_category(category: &str) -> bool {
    matches!(
        category.to_uppercase().as_str(),
        "SECURITY" | "DEPENDENCIES"
    )
}

/// `security-severity` of a severity, on GitHub's scale (critical from 9.0,
/// high from 7.0, medium from 4.0, low from 0.1): a value inside each band.
/// INFO has none: it is not an alert.
fn security_severity(severity: &str) -> Option<String> {
    match severity {
        "CRITICAL" => Some("9.5"),
        "HIGH" => Some("8.0"),
        "MEDIUM" => Some("5.5"),
        "LOW" => Some("3.0"),
        _ => None,
    }
    .map(str::to_string)
}

/// A limit of GitHub code scanning that a SARIF report goes beyond
/// (ticket #294), from GitHub's SARIF documentation ("SARIF support for
/// code scanning", read on 2026-11-25). The file is still written, for
/// the other tools that read SARIF; the console names each limit, so that
/// an upload rejected or cut by GitHub is never a surprise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubLimit {
    /// What goes beyond the limit.
    pub subject: GithubLimitSubject,
    /// Its size.
    pub actual: usize,
    /// GitHub's limit.
    pub limit: usize,
    /// `true`: GitHub rejects the file; `false`: GitHub keeps only `limit`
    /// of it.
    pub rejected: bool,
}

/// The part of a SARIF report a [`GithubLimit`] is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubLimitSubject {
    /// The gzip-compressed file, in bytes.
    CompressedSize,
    /// The results of the run.
    Results,
    /// The rules of the run.
    Rules,
    /// The tags of a rule.
    RuleTags(String),
    /// The steps of the data flow of a result of a rule.
    FlowSteps(String),
    /// The characters of a rule's short or full description.
    Description(String),
    /// The characters of a rule's name.
    Name(String),
}

/// GitHub's limits, as documented: the maximum, beyond which the file is
/// rejected, and what it keeps, when it keeps less than the maximum.
const GITHUB_MAX_COMPRESSED_BYTES: usize = 10 * 1024 * 1024;
const GITHUB_MAX_RESULTS: usize = 25_000;
const GITHUB_KEPT_RESULTS: usize = 5_000;
const GITHUB_MAX_RULES: usize = 25_000;
const GITHUB_MAX_TAGS: usize = 20;
const GITHUB_MAX_FLOW_STEPS: usize = 10_000;
const GITHUB_KEPT_FLOW_STEPS: usize = 1_000;
const GITHUB_MAX_DESCRIPTION_CHARS: usize = 1_024;
const GITHUB_MAX_NAME_CHARS: usize = 255;

/// The limits of GitHub code scanning that `report` goes beyond, given
/// the size of its gzip-compressed file (`compressed_bytes`), in a stable
/// order: file, results, rules, then per rule. A rule's tags beyond 10
/// are reported only when they also go beyond 20: GitHub then rejects the
/// file, while between 10 and 20 it only shows the first 10 for filtering.
pub fn github_limits(report: &SarifReport, compressed_bytes: usize) -> Vec<GithubLimit> {
    let mut limits = Vec::new();
    let mut push = |subject, actual: usize, maximum: usize, kept: Option<usize>| {
        if actual > maximum {
            limits.push(GithubLimit {
                subject,
                actual,
                limit: maximum,
                rejected: true,
            });
        } else if let Some(kept) = kept.filter(|kept| actual > *kept) {
            limits.push(GithubLimit {
                subject,
                actual,
                limit: kept,
                rejected: false,
            });
        }
    };
    push(
        GithubLimitSubject::CompressedSize,
        compressed_bytes,
        GITHUB_MAX_COMPRESSED_BYTES,
        None,
    );
    for run in &report.runs {
        push(
            GithubLimitSubject::Results,
            run.results.len(),
            GITHUB_MAX_RESULTS,
            Some(GITHUB_KEPT_RESULTS),
        );
        push(
            GithubLimitSubject::Rules,
            run.tool.driver.rules.len(),
            GITHUB_MAX_RULES,
            None,
        );
        for rule in &run.tool.driver.rules {
            push(
                GithubLimitSubject::RuleTags(rule.id.clone()),
                rule.properties.tags.len(),
                GITHUB_MAX_TAGS,
                None,
            );
            let description = rule
                .short_description
                .text
                .chars()
                .count()
                .max(rule.full_description.text.chars().count());
            push(
                GithubLimitSubject::Description(rule.id.clone()),
                description,
                GITHUB_MAX_DESCRIPTION_CHARS,
                None,
            );
            push(
                GithubLimitSubject::Name(rule.id.clone()),
                rule.name.chars().count(),
                GITHUB_MAX_NAME_CHARS,
                None,
            );
        }
        let mut worst_flow: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();
        for result in &run.results {
            let steps: usize = result
                .code_flows
                .iter()
                .flatten()
                .flat_map(|flow| &flow.thread_flows)
                .map(|thread| thread.locations.len())
                .sum();
            let worst = worst_flow.entry(result.rule_id.as_str()).or_default();
            *worst = (*worst).max(steps);
        }
        for (rule_id, steps) in worst_flow {
            push(
                GithubLimitSubject::FlowSteps(rule_id.to_string()),
                steps,
                GITHUB_MAX_FLOW_STEPS,
                Some(GITHUB_KEPT_FLOW_STEPS),
            );
        }
    }
    limits
}

/// Builds the SARIF 2.1.0 report of `findings`.
///
/// One SARIF rule per [`sarif_rule_id`]: its tags gather those of all its
/// findings (category, CWE, OWASP), its default level and
/// `security-severity` are those of its worst finding. Each result keeps
/// its own level, the risk then the solution as its message, and the
/// finding's identity (`report::comparison::finding_identities`, hashed)
/// under [`FINDING_FINGERPRINT`] and [`GITHUB_FINGERPRINT`].
pub fn build_sarif_report(
    findings: &[ReportFinding],
    tool_name: &str,
    tool_version: &str,
    information_uri: &str,
) -> SarifReport {
    // Findings by SARIF rule, in the order the rules first appear.
    let mut rules_index: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut rule_findings: Vec<Vec<&ReportFinding>> = Vec::new();
    for f in findings {
        let id = sarif_rule_id(f);
        let index = *rules_index.entry(id).or_insert_with(|| {
            rule_findings.push(Vec::new());
            rule_findings.len() - 1
        });
        rule_findings[index].push(f);
    }
    let mut ids: Vec<(&String, &usize)> = rules_index.iter().collect();
    ids.sort_by_key(|(_, index)| **index);
    let rules_list: Vec<SarifRule> = ids
        .into_iter()
        .map(|(id, &index)| {
            let members = &rule_findings[index];
            let worst = members
                .iter()
                .min_by_key(|f| severity_rank(&f.severity))
                .expect("a rule has at least one finding");
            let security = is_security_category(&worst.category);
            let mut tags: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            if security {
                tags.insert("security".to_string());
            }
            // A catalog rule's findings share its CWE: the rule's tags carry
            // it. A project check's CWE are those of each finding's CVEs, a
            // set that grows with the project (14 tags for one vulnerable
            // dependency of ka8t/ChannelAgent-Public), while GitHub code
            // scanning rejects a file whose rule has more than 20 tags: they
            // go to each result's properties instead (ticket #294).
            let project_check = worst.rule_language.is_empty();
            for f in members {
                tags.insert(f.category.to_lowercase());
                if !project_check {
                    tags.extend(f.cwe.iter().cloned());
                }
                if let Some(owasp) = &f.owasp {
                    tags.insert(owasp.clone());
                }
            }
            SarifRule {
                id: id.clone(),
                // SARIF `name` is an identifier; the readable name goes in
                // `shortDescription` (ticket #227: `rule_name` is now the
                // translated name).
                name: worst.rule_key.clone(),
                short_description: SarifText {
                    text: worst.rule_name.clone(),
                },
                full_description: SarifText {
                    text: worst.risk.clone(),
                },
                default_configuration: SarifRuleConfig {
                    level: severity_to_sarif_level(&worst.severity),
                },
                properties: SarifRuleProperties {
                    category: worst.category.clone(),
                    tags: tags.into_iter().collect(),
                    security_severity: if security {
                        security_severity(&worst.severity)
                    } else {
                        None
                    },
                },
            }
        })
        .collect();

    let identities = crate::report::comparison::finding_identities(findings);
    let results: Vec<SarifResult> = findings
        .iter()
        .zip(&identities)
        .map(|(f, identity)| {
            let rule_id = sarif_rule_id(f);
            let rule_index = rules_index[&rule_id];
            let risk = if f.risk.is_empty() {
                f.rule_name.clone()
            } else {
                f.risk.clone()
            };
            let message_text = match f.solution.as_deref().filter(|s| !s.is_empty()) {
                Some(solution) => format!("{risk}\n\n{solution}"),
                None => risk,
            };
            SarifResult {
                rule_id,
                rule_index,
                level: severity_to_sarif_level(&f.severity),
                message: SarifText { text: message_text },
                locations: vec![SarifLocation {
                    physical_location: finding_location(f),
                }],
                partial_fingerprints: {
                    let hash = crate::scan::scan_cache::sha256_hex(identity.as_bytes());
                    std::collections::BTreeMap::from([
                        (FINDING_FINGERPRINT.to_string(), hash.clone()),
                        (GITHUB_FINGERPRINT.to_string(), hash),
                    ])
                },
                code_flows: f.taint_flow.as_ref().map(build_code_flows),
                properties: (f.rule_language.is_empty() && !f.cwe.is_empty())
                    .then(|| SarifResultProperties { cwe: f.cwe.clone() }),
            }
        })
        .collect();

    SarifReport {
        schema: SARIF_SCHEMA_URI.to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: tool_name.to_string(),
                    version: tool_version.to_string(),
                    information_uri: information_uri.to_string(),
                    rules: rules_list,
                },
            },
            automation_details: SarifAutomationDetails {
                id: format!("{tool_name}/"),
            },
            results,
        }],
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule_key: &str, file: &str, line: usize) -> ReportFinding {
        ReportFinding {
            rule_key: rule_key.to_string(),
            rule_language: "python".to_string(),
            rule_name: "Test Rule".to_string(),
            category: "Injection".to_string(),
            severity: "HIGH".to_string(),
            risk: "Risque de test".to_string(),
            file: file.to_string(),
            line,
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

    #[test]
    fn test_schema_and_version() {
        let report = build_sarif_report(&[], "codefixture-audit", "1.0", "https://codefixture.com");
        assert_eq!(report.schema, SARIF_SCHEMA_URI);
        assert_eq!(report.version, "2.1.0");
    }

    #[test]
    fn test_empty_findings_produces_empty_results_and_rules() {
        let report = build_sarif_report(&[], "codefixture-audit", "1.0", "https://codefixture.com");
        assert!(report.runs[0].results.is_empty());
        assert!(report.runs[0].tool.driver.rules.is_empty());
    }

    #[test]
    fn test_single_finding_produces_one_rule_and_one_result() {
        let f = finding("sql_injection", "app.py", 12);
        let report =
            build_sarif_report(&[f], "codefixture-audit", "1.0", "https://codefixture.com");
        assert_eq!(report.runs[0].tool.driver.rules.len(), 1);
        assert_eq!(report.runs[0].results.len(), 1);
        assert_eq!(report.runs[0].results[0].rule_id, "python/sql_injection");
        assert_eq!(report.runs[0].results[0].rule_index, 0);
    }

    #[test]
    fn test_one_name_in_two_languages_gives_two_sarif_rules() {
        let python = finding("base64_eval", "app.py", 2);
        let mut javascript = finding("base64_eval", "app.js", 1);
        javascript.rule_language = "javascript".to_string();
        javascript.risk = "JavaScript risk".to_string();
        let report = build_sarif_report(
            &[python, javascript],
            "codefixture-audit",
            "1.0",
            "https://codefixture.com",
        );
        let rules = &report.runs[0].tool.driver.rules;
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["python/base64_eval", "javascript/base64_eval"]);
        let js_result = &report.runs[0].results[1];
        assert_eq!(js_result.rule_id, "javascript/base64_eval");
        assert_eq!(
            rules[js_result.rule_index].full_description.text,
            "JavaScript risk"
        );
    }

    #[test]
    fn test_dedup_rules_by_rule_key() {
        let findings = vec![
            finding("sql_injection", "a.py", 1),
            finding("sql_injection", "b.py", 2),
        ];
        let report = build_sarif_report(
            &findings,
            "codefixture-audit",
            "1.0",
            "https://codefixture.com",
        );
        assert_eq!(
            report.runs[0].tool.driver.rules.len(),
            1,
            "un seul rule_key -> une seule entrée rules"
        );
        assert_eq!(
            report.runs[0].results.len(),
            2,
            "mais deux results distincts"
        );
        assert_eq!(report.runs[0].results[0].rule_index, 0);
        assert_eq!(report.runs[0].results[1].rule_index, 0);
    }

    #[test]
    fn test_severity_to_sarif_level_mapping() {
        assert_eq!(severity_to_sarif_level("CRITICAL"), "error");
        assert_eq!(severity_to_sarif_level("HIGH"), "error");
        assert_eq!(severity_to_sarif_level("MEDIUM"), "warning");
        assert_eq!(severity_to_sarif_level("LOW"), "note");
        assert_eq!(severity_to_sarif_level("INFO"), "note");
        assert_eq!(severity_to_sarif_level("UNKNOWN"), "warning");
    }

    #[test]
    fn test_tags_include_category_cwe_owasp() {
        let mut f = finding("xss", "app.py", 1);
        f.cwe = vec!["CWE-79".to_string()];
        f.owasp = Some("A03:2021".to_string());
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        let tags = &report.runs[0].tool.driver.rules[0].properties.tags;
        assert!(
            tags.contains(&"injection".to_string()),
            "catégorie en minuscules"
        );
        assert!(tags.contains(&"CWE-79".to_string()));
        assert!(tags.contains(&"A03:2021".to_string()));
    }

    /// Ticket #291: the solution follows the risk in the message, since a
    /// SARIF `fix` without `artifactChanges` is refused by the schema.
    #[test]
    fn test_solution_follows_the_risk_in_the_message() {
        let mut f = finding("xss", "app.py", 1);
        f.solution = Some("Échapper la sortie HTML".to_string());
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        assert_eq!(
            report.runs[0].results[0].message.text,
            "Risque de test\n\nÉchapper la sortie HTML"
        );
        let without = build_sarif_report(&[finding("xss", "app.py", 1)], "t", "1.0", "https://x");
        assert_eq!(without.runs[0].results[0].message.text, "Risque de test");
    }

    /// A vulnerable dependency, as the dependency phase writes it: no
    /// language, the severity of its worst CVE.
    fn dependency(severity: &str, cwe: &str, file: &str, code: &str) -> ReportFinding {
        ReportFinding {
            rule_key: "vulnerable_dependency".to_string(),
            rule_language: String::new(),
            category: "DEPENDENCIES".to_string(),
            severity: severity.to_string(),
            cwe: vec![cwe.to_string()],
            code: code.to_string(),
            ..finding("vulnerable_dependency", file, 1)
        }
    }

    /// Ticket #291: one SARIF rule per severity for the project checks,
    /// whose severity changes per finding; each rule's tags and severity
    /// are those of its own findings.
    #[test]
    fn test_project_checks_get_one_rule_per_severity() {
        let findings = vec![
            dependency("HIGH", "CWE-200", "requirements.txt", "requests==2.19.0"),
            dependency(
                "MEDIUM",
                "CWE-400",
                "package.json",
                "\"express\": \"^4.0.0\"",
            ),
            dependency(
                "HIGH",
                "CWE-1321",
                "package.json",
                "\"lodash\": \"4.17.15\"",
            ),
        ];
        let report = build_sarif_report(&findings, "t", "1.0", "https://x");
        let rules = &report.runs[0].tool.driver.rules;
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "dependencies/vulnerable_dependency/high",
                "dependencies/vulnerable_dependency/medium"
            ]
        );
        assert_eq!(
            rules[0].properties.tags,
            ["dependencies", "security"],
            "fixed tags: a project check's CWE grow with the project (ticket #294)"
        );
        assert_eq!(
            rules[0].properties.security_severity.as_deref(),
            Some("8.0")
        );
        assert_eq!(
            rules[1].properties.security_severity.as_deref(),
            Some("5.5")
        );
        assert_eq!(rules[1].default_configuration.level, "warning");
        let results = &report.runs[0].results;
        assert_eq!(
            (results[1].rule_index, results[2].rule_index),
            (1, 0),
            "each result points at its own rule"
        );
        assert_eq!(
            results[2].properties,
            Some(SarifResultProperties {
                cwe: vec!["CWE-1321".to_string()]
            }),
            "each result keeps the CWE of its CVEs"
        );
    }

    /// Ticket #294: a catalog rule keeps its CWE in its tags, and its
    /// results carry no property bag.
    #[test]
    fn test_catalog_rule_keeps_its_cwe_in_its_tags() {
        let mut f = finding("xss", "app.py", 1);
        f.cwe = vec!["CWE-79".to_string()];
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        assert!(
            report.runs[0].tool.driver.rules[0]
                .properties
                .tags
                .contains(&"CWE-79".to_string())
        );
        assert_eq!(report.runs[0].results[0].properties, None);
    }

    /// Ticket #294: each documented limit of GitHub code scanning is named
    /// when the report goes beyond it: rejected beyond its maximum, cut
    /// beyond what GitHub keeps.
    #[test]
    fn test_github_limits_name_what_github_rejects_or_cuts() {
        let many = |count: usize| -> Vec<ReportFinding> {
            (0..count)
                .map(|i| finding("xss", &format!("f{i}.py"), 1))
                .collect()
        };
        let small = build_sarif_report(&many(3), "t", "1.0", "https://x");
        assert!(github_limits(&small, 1_000).is_empty());
        assert_eq!(
            github_limits(&small, 11 * 1024 * 1024),
            [GithubLimit {
                subject: GithubLimitSubject::CompressedSize,
                actual: 11 * 1024 * 1024,
                limit: 10 * 1024 * 1024,
                rejected: true
            }]
        );
        let cut = build_sarif_report(&many(5_001), "t", "1.0", "https://x");
        assert_eq!(
            github_limits(&cut, 1_000),
            [GithubLimit {
                subject: GithubLimitSubject::Results,
                actual: 5_001,
                limit: 5_000,
                rejected: false
            }]
        );
        let rejected = build_sarif_report(&many(25_001), "t", "1.0", "https://x");
        assert_eq!(
            github_limits(&rejected, 1_000),
            [GithubLimit {
                subject: GithubLimitSubject::Results,
                actual: 25_001,
                limit: 25_000,
                rejected: true
            }]
        );
        let mut tagged = finding("xss", "a.py", 1);
        tagged.cwe = (0..21).map(|i| format!("CWE-{i}")).collect();
        tagged.risk = "x".repeat(1_025);
        let report = build_sarif_report(&[tagged], "t", "1.0", "https://x");
        let subjects: Vec<GithubLimitSubject> = github_limits(&report, 1_000)
            .into_iter()
            .map(|l| l.subject)
            .collect();
        assert_eq!(
            subjects,
            [
                GithubLimitSubject::RuleTags("python/xss".to_string()),
                GithubLimitSubject::Description("python/xss".to_string())
            ]
        );
    }

    /// Ticket #291: `security-severity` and the `security` tag for the
    /// security rules only, on GitHub's bands; none for INFO.
    #[test]
    fn test_security_severity_only_for_security_rules() {
        let mut critical = finding("sqli", "a.py", 1);
        critical.category = "SECURITY".to_string();
        critical.severity = "CRITICAL".to_string();
        let mut info = finding("note", "a.py", 2);
        info.category = "SECURITY".to_string();
        info.severity = "INFO".to_string();
        let mut quality = finding("long_function", "a.py", 3);
        quality.category = "MAINTENANCE".to_string();
        let report = build_sarif_report(&[critical, info, quality], "t", "1.0", "https://x");
        let rules = &report.runs[0].tool.driver.rules;
        assert_eq!(
            rules[0].properties.security_severity.as_deref(),
            Some("9.5")
        );
        assert!(rules[0].properties.tags.contains(&"security".to_string()));
        assert_eq!(
            rules[1].properties.security_severity, None,
            "INFO is no alert"
        );
        assert_eq!(rules[2].properties.security_severity, None);
        assert!(!rules[2].properties.tags.contains(&"security".to_string()));
    }

    /// Ticket #291: the fingerprint is the finding's identity of ADR-0067:
    /// it does not change when the line moves, and two identical lines of
    /// one file get two fingerprints.
    #[test]
    fn test_fingerprint_survives_a_line_shift_and_tells_twins_apart() {
        let mut first = finding("xss", "app.py", 3);
        first.code = "print(request.args['q'])".to_string();
        let fingerprint = |findings: &[ReportFinding]| -> Vec<String> {
            build_sarif_report(findings, "t", "1.0", "https://x").runs[0]
                .results
                .iter()
                .map(|r| r.partial_fingerprints[FINDING_FINGERPRINT].clone())
                .collect()
        };
        let before = fingerprint(std::slice::from_ref(&first));
        let mut moved = first.clone();
        moved.line = 40;
        assert_eq!(fingerprint(&[moved]), before);
        let mut twin = first.clone();
        twin.line = 9;
        let both = fingerprint(&[first.clone(), twin]);
        assert_eq!(both[0], before[0]);
        assert_ne!(both[0], both[1]);
        assert_eq!(before[0].len(), 64, "a SHA-256 in hexadecimal");
        // The key GitHub reads carries the same identity (ticket #294).
        let report = build_sarif_report(std::slice::from_ref(&first), "t", "1.0", "https://x");
        let fingerprints = &report.runs[0].results[0].partial_fingerprints;
        assert_eq!(
            fingerprints[GITHUB_FINGERPRINT],
            fingerprints[FINDING_FINGERPRINT]
        );
    }

    /// Ticket #291: the run names its category, for GitHub to tell uploads
    /// apart.
    #[test]
    fn test_run_has_automation_details() {
        let report = build_sarif_report(&[], "codefixture-audit", "1.0", "https://x");
        assert_eq!(report.runs[0].automation_details.id, "codefixture-audit/");
    }

    /// Ticket #291: the output validates against the official SARIF 2.1.0
    /// schema (OASIS, errata 01, `tests/data/sarif-schema-2.1.0.json`),
    /// offline, with every kind of finding the engine writes: a line
    /// finding with a solution, a taint flow, a whole-file finding and
    /// project checks of several severities.
    #[test]
    fn test_output_validates_against_the_sarif_schema() {
        let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/sarif-schema-2.1.0.json");
        let schema: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(schema_path).expect("SARIF schema"))
                .expect("SARIF schema is JSON");
        let validator = jsonschema::validator_for(&schema).expect("valid JSON Schema");

        let mut solved = finding("xss", "app.py", 4);
        solved.solution = Some("Escape the output".to_string());
        solved.cwe = vec!["CWE-79".to_string()];
        solved.owasp = Some("A03:2021".to_string());
        let mut taint = finding("sqli", "db.py", 12);
        taint.taint_flow = Some(TaintFlow {
            rule_key: "taint_sqli".to_string(),
            source_file: "db.py".to_string(),
            source_line: 3,
            source_expr: "request.args['q']".to_string(),
            chain: vec![(7, "q".to_string(), "q = request.args['q']".to_string())],
            sink_file: "db.py".to_string(),
            sink_line: 12,
            sink_expr: "cursor.execute(q)".to_string(),
            source_kind: "http".to_string(),
            steps: vec![],
        });
        let mut whole_file = finding("file_too_long", "big.py", 1);
        whole_file.file_scope = Some(crate::scan::engine::FileScope {
            line_count: 2_400,
            min_lines: Some(1_000),
        });
        let findings = vec![
            solved,
            taint,
            whole_file,
            dependency("CRITICAL", "CWE-94", "pom.xml", "log4j-core 2.14.1"),
            dependency("LOW", "CWE-400", "package.json", "minimist 1.2.5"),
        ];
        let report = build_sarif_report(
            &findings,
            "codefixture-audit",
            "3.1.0",
            "https://codefixture.com",
        );
        let instance = serde_json::to_value(&report).expect("SARIF to JSON");
        let errors: Vec<String> = validator
            .iter_errors(&instance)
            .map(|e| format!("{} at {}", e, e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "SARIF schema errors: {errors:#?}");

        // The validator does refuse what the schema forbids: the `fixes`
        // entry written before 2026-11-25, without `artifactChanges`.
        let mut old_output = instance.clone();
        old_output["runs"][0]["results"][0]["fixes"] =
            serde_json::json!([{"description": {"text": "Escape the output"}}]);
        assert!(
            !validator.is_valid(&old_output),
            "a fix without artifactChanges must fail the schema"
        );
    }

    #[test]
    fn test_code_flows_present_for_taint_flow() {
        let mut f = finding("sql_injection", "app.py", 10);
        f.taint_flow = Some(TaintFlow {
            rule_key: "taint_sqli".to_string(),
            source_file: "app.py".to_string(),
            source_line: 1,
            source_expr: "request.GET['q']".to_string(),
            chain: vec![(5, "q".to_string(), "q = request.GET['q']".to_string())],
            sink_file: "app.py".to_string(),
            sink_line: 10,
            sink_expr: "cursor.execute(q)".to_string(),
            source_kind: "http".to_string(),
            steps: vec![],
        });
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        let flows = report.runs[0].results[0].code_flows.as_ref().unwrap();
        let locations = &flows[0].thread_flows[0].locations;
        assert_eq!(locations.len(), 3, "source + 1 étape de chaîne + sink");
        assert!(locations[0].location.message.text.starts_with("Source:"));
        assert!(locations[2].location.message.text.starts_with("Impact:"));
    }

    #[test]
    fn test_code_flows_absent_without_taint_flow() {
        let f = finding("xss", "app.py", 1);
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        assert!(report.runs[0].results[0].code_flows.is_none());
    }

    #[test]
    fn test_windows_path_normalized_to_forward_slash() {
        let f = finding("xss", "src\\app.py", 1);
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        assert_eq!(
            report.runs[0].results[0].locations[0]
                .physical_location
                .artifact_location
                .uri,
            "src/app.py"
        );
    }

    #[test]
    fn test_line_zero_clamped_to_one() {
        let f = finding("xss", "app.py", 0);
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        assert_eq!(
            report.runs[0].results[0].locations[0]
                .physical_location
                .region
                .as_ref()
                .expect("a line finding has a region")
                .start_line,
            1
        );
    }

    /// Ticket #214: a whole-file finding is located on the file, with no
    /// region, so a SARIF viewer does not point at line 1.
    #[test]
    fn test_whole_file_finding_has_no_region() {
        let mut f = finding("file_too_long", "app/big.py", 1);
        f.file_scope = Some(crate::scan::engine::FileScope {
            line_count: 1363,
            min_lines: Some(500),
        });
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        let location = &report.runs[0].results[0].locations[0].physical_location;
        assert_eq!(location.artifact_location.uri, "app/big.py");
        assert!(location.region.is_none());
        let json = serde_json::to_value(&report).unwrap();
        assert!(
            json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
                .get("region")
                .is_none()
        );
    }

    #[test]
    fn test_unicode_path_preserved() {
        let f = finding("xss", "src/éàü_fichier.py", 3);
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        assert_eq!(
            report.runs[0].results[0].locations[0]
                .physical_location
                .artifact_location
                .uri,
            "src/éàü_fichier.py"
        );
    }

    #[test]
    fn test_json_serializable() {
        let f = finding("xss", "app.py", 1);
        let report =
            build_sarif_report(&[f], "codefixture-audit", "1.0", "https://codefixture.com");
        let json = serde_json::to_string(&report)
            .expect("le rapport SARIF doit être sérialisable en JSON");
        assert!(json.contains("\"ruleId\":\"python/xss\""));
        assert!(json.contains("\"$schema\""));
    }

    #[test]
    fn test_message_falls_back_to_rule_name_when_risk_empty() {
        let mut f = finding("xss", "app.py", 1);
        f.risk = String::new();
        let report = build_sarif_report(&[f], "t", "1.0", "https://x");
        assert_eq!(report.runs[0].results[0].message.text, "Test Rule");
    }
}
