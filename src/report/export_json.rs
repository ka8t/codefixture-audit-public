//! JSON export of a scan's results (serves as a future baseline) and
//! history directory — port of `_export_json`/
//! `_find_latest_baseline`/`_load_history` (`Audit/sca/comparison.py`
//! and `Audit/sca/database.py`).
//!
//! **Deliberately different shape from Python**: the format exported
//! here does not need to be byte-for-byte compatible with the Python
//! export (`sca/comparison.py::_export_json`, which serializes the
//! full `Finding` dataclass with fields absent on the Rust side) —
//! this is a loop internal to codefixture-audit (a Rust scan reads back a
//! baseline written by a previous Rust scan), not an interoperability
//! bridge with Python. Fields kept to the strict minimum needed by
//! `comparison::compare_with_baseline` and the DB schema history:
//! `findings`, `totals`, `timestamp`. The `{prefix}-DATA-{timestamp}.json`
//! naming convention is kept (same spirit as Python), with the same
//! timestamp format as the HTML report (`%Y%m%d_%H%M%S`) rather than
//! Python's dash-based format — a single timestamp format across the
//! whole tool.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::project::database::schema::DatabaseSchema;
use crate::report::exports::sarif::ReportFinding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportData {
    /// Format of this file (`1.0`), not the engine version.
    pub version: String,
    /// Release version of the engine that wrote it
    /// ([`crate::RELEASE_VERSION`], `3.1.0`); the build identifier until
    /// 2026-11-24 (ticket #149). Empty when reading a baseline written
    /// before that field existed. Nothing reads it back.
    #[serde(default)]
    pub tool_version: String,
    pub timestamp: String,
    pub date: String,
    pub totals: BTreeMap<String, usize>,
    pub findings: Vec<ReportFinding>,
    /// DB schema of this scan, if `database.py` was active — serves
    /// as the baseline for the next scan
    /// (`_load_schema_from_history`).
    pub database_schema: Option<DatabaseSchema>,
    /// The name of every CWE the findings cite, by id, from the catalog
    /// embedded in the engine (ADR-0070); a CWE it lacks is not listed.
    /// Empty in a file written before it. Nothing reads it back.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cwe_names: BTreeMap<String, String>,
    /// MITRE's copyright designation and license, which the CWE terms of
    /// use ask every copy of CWE names to reproduce; empty without names.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cwe_notice: String,
    /// How many things the scan found to treat urgently (ticket #308):
    /// systems, runtimes and dependencies with an exploited vulnerability.
    /// The next scan compares its own count with it. `None` in a file
    /// written before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urgent: Option<usize>,
    /// The vulnerable dependencies, structured as the priorities rank
    /// them (ticket #308): a scan skipped because nothing changed shows
    /// them again. Empty in a file written before it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependency_priorities: Vec<crate::report::priorities::DependencyPriority>,
    /// What the dependency phase could compare in the folder (ADR-0072,
    /// amended 2026-11-26): a scan skipped as unchanged names it again.
    /// `None` in a file written before it, which that scan then says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_check: Option<crate::report::priorities::FolderCheck>,
}

fn compute_totals(findings: &[ReportFinding]) -> BTreeMap<String, usize> {
    let mut totals: BTreeMap<String, usize> = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        .iter()
        .map(|s| (s.to_string(), 0))
        .collect();
    for f in findings {
        if let Some(c) = totals.get_mut(f.severity.as_str()) {
            *c += 1;
        }
    }
    totals
}

/// Builds the data to export — port of `_export_json` (findings/totals
/// part, see module doc for scope).
pub fn build_export_data(
    findings: &[ReportFinding],
    timestamp: &str,
    date: &str,
    database_schema: Option<DatabaseSchema>,
) -> ExportData {
    let cwe_names = crate::report::cwe_catalog::names_of(findings.iter().flat_map(|f| &f.cwe));
    ExportData {
        version: "1.0".to_string(),
        tool_version: crate::RELEASE_VERSION.to_string(),
        timestamp: timestamp.to_string(),
        date: date.to_string(),
        totals: compute_totals(findings),
        findings: findings.to_vec(),
        database_schema,
        cwe_names: cwe_names.clone(),
        urgent: None,
        dependency_priorities: Vec::new(),
        folder_check: None,
        cwe_notice: if cwe_names.is_empty() {
            String::new()
        } else {
            crate::report::cwe_catalog::catalog().cwe.notice.clone()
        },
    }
}

/// Records the priorities in the export at `path` (ticket #308): the urgent
/// count, the dependencies and what the dependency phase could compare
/// in the folder, known once the system check and the dependency phase
/// are both done, after the scan wrote its data.
pub fn record_priorities(
    path: &Path,
    urgent: usize,
    dependencies: &[crate::report::priorities::DependencyPriority],
    folder: Option<crate::report::priorities::FolderCheck>,
) -> Result<(), String> {
    let mut data = load_export(path)?;
    data.urgent = Some(urgent);
    data.dependency_priorities = dependencies.to_vec();
    data.folder_check = folder;
    let json = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| format!("{}: {e}", path.display()))
}

/// Writes the export to `{datas_dir}/{prefix}-DATA-{timestamp}.json`,
/// creating `datas_dir` if needed.
pub fn write_export(datas_dir: &Path, prefix: &str, data: &ExportData) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(datas_dir)?;
    let path = datas_dir.join(format!("{prefix}-DATA-{}.json", data.timestamp));
    let json = serde_json::to_string_pretty(data)?;
    std::fs::write(&path, json)?;
    Ok(path)
}

fn list_data_files(datas_dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(datas_dir) else {
        return vec![];
    };
    let file_prefix = format!("{prefix}-DATA-");
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&file_prefix) && n.ends_with(".json"))
        })
        .collect();
    files.sort();
    files
}

/// The most recent data file — port of `_find_latest_baseline`.
pub fn find_latest_baseline(datas_dir: &Path, prefix: &str) -> Option<PathBuf> {
    list_data_files(datas_dir, prefix).pop()
}

/// Loads a JSON export from disk.
pub fn load_export(path: &Path) -> Result<ExportData, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&content).map_err(|e| e.to_string())
}

/// Number of scans the trend chart shows — Python's default
/// `reports.max_history` (`_load_history`). The `reports` section of
/// `audit.config.json` is not supported on the Rust side
/// (`project_config::UNSUPPORTED_CONFIG_SECTIONS`), so this is fixed.
pub const MAX_HISTORY: usize = 10;

/// One past scan as the trend chart needs it: when it ran and how many
/// findings of each severity it had.
///
/// Deserialized from an export file, whose other fields (`findings`
/// above all, up to several megabytes per scan) serde skips without
/// building them: reading ten past scans stays cheap.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HistoryPoint {
    /// `YYYY-MM-DD-HH-MM`, as written by the scan.
    pub timestamp: String,
    /// Findings per severity (`HIGH`, `MEDIUM`, …).
    pub totals: BTreeMap<String, usize>,
}

/// History of the last `max_history` scans, oldest first, for the trend
/// chart — port of `_load_history` (`Audit/sca/comparison.py`).
///
/// Python also reads each scan's tests and database statistics; the
/// Rust export carries neither, so the chart's tests and database series
/// are zeros (`html::build_chart_data`). An unreadable or invalid file is
/// skipped, as in Python (`except Exception: continue`).
pub fn load_history(datas_dir: &Path, prefix: &str, max_history: usize) -> Vec<HistoryPoint> {
    let files = list_data_files(datas_dir, prefix);
    let start = files.len().saturating_sub(max_history);
    files[start..]
        .iter()
        .filter_map(|p| {
            let content = std::fs::read_to_string(p).ok()?;
            serde_json::from_str(&content).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: &str, file: &str) -> ReportFinding {
        ReportFinding {
            rule_key: "r".to_string(),
            rule_language: "python".to_string(),
            rule_name: "Rule".to_string(),
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

    fn tmp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-export-{label}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_build_export_data_computes_totals() {
        let findings = vec![
            finding("HIGH", "a.py"),
            finding("HIGH", "b.py"),
            finding("LOW", "c.py"),
        ];
        let data = build_export_data(&findings, "ts1", "2026-08-25", None);
        assert_eq!(data.totals["HIGH"], 2);
        assert_eq!(data.totals["LOW"], 1);
        assert_eq!(data.totals["CRITICAL"], 0);
        assert_eq!(data.findings.len(), 3);
    }

    /// ADR-0070: the names of the cited CWEs, with MITRE's notice; none
    /// and no notice without a CWE the catalog holds.
    #[test]
    fn test_export_names_the_cited_cwe() {
        let mut cited = finding("HIGH", "a.py");
        cited.cwe = vec!["CWE-79".to_string(), "CWE-999999".to_string()];
        let data = build_export_data(&[cited], "ts", "2026-11-26", None);
        let names: Vec<&String> = data.cwe_names.keys().collect();
        assert_eq!(names, vec!["CWE-79"]);
        assert!(data.cwe_notice.contains("The MITRE Corporation"));
        let none = build_export_data(&[finding("LOW", "b.py")], "ts", "2026-11-26", None);
        assert!(none.cwe_names.is_empty() && none.cwe_notice.is_empty());
        let json = serde_json::to_string(&none).unwrap();
        assert!(!json.contains("cwe_names"), "{json}");
    }

    #[test]
    fn test_write_and_load_export_roundtrip() {
        let dir = tmp_dir("roundtrip");
        let findings = vec![finding("CRITICAL", "a.py")];
        let data = build_export_data(&findings, "20260825_120000", "2026-08-25", None);
        let path = write_export(&dir, "SCA", &data).unwrap();
        assert!(path.exists());

        let loaded = load_export(&path).unwrap();
        assert_eq!(loaded.findings.len(), 1);
        assert_eq!(loaded.findings[0].file, "a.py");
        assert_eq!(loaded.totals["CRITICAL"], 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_find_latest_baseline_picks_most_recent() {
        let dir = tmp_dir("latest");
        for ts in ["20260101_000000", "20260301_000000", "20260201_000000"] {
            let data = build_export_data(&[], ts, "2026", None);
            write_export(&dir, "SCA", &data).unwrap();
        }
        let latest = find_latest_baseline(&dir, "SCA").unwrap();
        assert!(latest.to_string_lossy().contains("20260301_000000"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_find_latest_baseline_none_when_empty() {
        let dir = tmp_dir("empty");
        assert!(find_latest_baseline(&dir, "SCA").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_history_respects_max_and_order() {
        let dir = tmp_dir("history");
        for ts in [
            "20260101_000000",
            "20260102_000000",
            "20260103_000000",
            "20260104_000000",
        ] {
            let data = build_export_data(&[], ts, "2026", None);
            write_export(&dir, "SCA", &data).unwrap();
        }
        let history = load_history(&dir, "SCA", 2);
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].timestamp, "20260103_000000");
        assert_eq!(history[1].timestamp, "20260104_000000");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Each point carries the totals of its scan, and a file that is not
    /// a valid export is skipped instead of emptying the history.
    #[test]
    fn test_load_history_reads_totals_and_skips_invalid_files() {
        let dir = tmp_dir("history-totals");
        let data = build_export_data(&[finding("HIGH", "a.py")], "2026-11-18-09-18", "2026", None);
        write_export(&dir, "SCA", &data).unwrap();
        std::fs::write(dir.join("SCA-DATA-2026-11-18-10-00.json"), "{not json").unwrap();
        let history = load_history(&dir, "SCA", MAX_HISTORY);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].timestamp, "2026-11-18-09-18");
        assert_eq!(history[0].totals.get("HIGH"), Some(&1));
        assert_eq!(history[0].totals.get("MEDIUM"), Some(&0));
    }

    #[test]
    fn test_export_data_preserves_database_schema() {
        let dir = tmp_dir("dbschema");
        let mut schema = DatabaseSchema {
            timestamp: "t".to_string(),
            database: "mydb".to_string(),
            ..Default::default()
        };
        schema.enums.insert(
            "status".to_string(),
            vec!["active".to_string(), "inactive".to_string()],
        );
        let data = build_export_data(&[], "20260825_120000", "2026-08-25", Some(schema));
        let path = write_export(&dir, "SCA", &data).unwrap();
        let loaded = load_export(&path).unwrap();
        assert!(loaded.database_schema.is_some());
        assert_eq!(loaded.database_schema.unwrap().database, "mydb");
        std::fs::remove_dir_all(&dir).ok();
    }
}
