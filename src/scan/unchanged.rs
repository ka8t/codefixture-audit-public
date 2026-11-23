//! The check that runs before a scan: has anything the scan reads changed
//! since the last one (ADR-0050)?
//!
//! The per-file cache (`scan_cache`) spares the analysis of unchanged
//! files, but it has to load every rule to know whether a rule changed, and
//! the scan around it still parses every file and writes a new report. This
//! module answers the question for the whole scan, before any rule is read:
//!
//! 1. [`ScanInputs::read`] discovers the files exactly as the scan does
//!    (`orchestrator::discover_files`) and hashes everything a scan reads:
//!    the files, the dependency manifests, the rule pack, the custom rules,
//!    the suppressions, and the options that change the findings.
//! 2. [`LastScan::find_unchanged`] compares the fingerprint of those inputs
//!    with the record of the last scan (`last-scan.json` in the engine's
//!    cache folder) and returns the record when they are equal.
//! 3. After a full scan, [`LastScan::save`] writes the record, with the
//!    fingerprint of the inputs read *before* the scan: a file edited while
//!    the scan ran no longer matches it, so the next run scans again.
//!
//! The only input that needs the rules is the existence of governance files
//! (`file_contains::not_path_has_file`): which names to look for comes from
//! the rules. The record keeps the names of the last scan, which are right
//! as long as the pack's bytes are the same — and the pack is part of the
//! fingerprint.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::scan::engine::file_contains::governance_fingerprint;
use crate::scan::orchestrator::{ScanConfig, discover_files};
use crate::scan::scan_cache::{CacheKey, sha256_hex};

/// Version of the `last-scan.json` layout; a record of another version is
/// ignored, and the scan then runs in full.
const FORMAT: u32 = 1;

/// Name of the record in the engine's cache folder.
const RECORD_FILE: &str = "last-scan.json";

/// Stands for the hash of a file that cannot be read: the scan skips it
/// too, and the day it becomes readable its hash differs.
const UNREADABLE: &str = "unreadable";

/// Everything a scan reads, hashed: two scans with equal inputs produce
/// the same findings. Built before the scan, never from its results.
#[derive(Debug, Clone, Serialize)]
pub struct ScanInputs {
    /// Engine build and report language: the cache key of `scan_cache`.
    engine: CacheKey,
    /// The options that change which rules run or which findings are kept.
    options: ScanOptions,
    /// SHA-256 of the rule pack (or of each `.sca` file of a rules folder,
    /// by path).
    rules: BTreeMap<String, String>,
    /// SHA-256 of each custom rule file, by path (private build).
    custom_rules: BTreeMap<String, String>,
    /// SHA-256 of the suppressions file, `None` without one.
    suppressions: Option<String>,
    /// SHA-256 of each discovered file, by path relative to the project.
    files: BTreeMap<String, String>,
    /// SHA-256 of each dependency manifest, by path relative to the
    /// project: they are not always discovered files (`requirements.txt`).
    manifests: BTreeMap<String, String>,
    /// The discovered files on disk, for the governance check; their
    /// content is already in `files`.
    #[serde(skip)]
    discovered: Vec<PathBuf>,
}

/// The options of [`ScanConfig`] that change the findings. The include and
/// exclude paths are left out: their effect, the list of discovered files,
/// is in [`ScanInputs::files`], while the exclusions themselves hold the
/// timestamped path of each new report.
#[derive(Debug, Clone, Serialize)]
struct ScanOptions {
    target_languages: Option<Vec<String>>,
    only_target_language_files: bool,
    quick_mode: bool,
    with_deps: bool,
    only_category: Option<String>,
    category_overrides: BTreeMap<String, bool>,
    disabled_rules: Vec<String>,
    severity_levels: Option<Vec<String>>,
}

impl ScanInputs {
    /// Discovers and hashes the inputs of a scan of `config`. The files are
    /// hashed in parallel; a file that cannot be read is recorded as such.
    pub fn read(config: &ScanConfig) -> Self {
        let (discovered, _) = discover_files(config);
        let relative = |path: &Path| {
            path.strip_prefix(&config.root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/")
        };
        let files = discovered
            .par_iter()
            .map(|path| (relative(path), hash_file(path)))
            .collect();
        // The lockfiles next to each manifest too (ticket #209): they give
        // the versions checked, so changing one must trigger a scan.
        let manifest_files: Vec<PathBuf> = crate::project::dependencies::find_dependency_files(
            &config.root,
            &config.include_paths,
            &config.exclude_patterns,
        )
        .into_iter()
        .map(|(path, _)| path)
        .collect();
        let lockfiles: Vec<PathBuf> = manifest_files
            .iter()
            .filter_map(|path| path.parent())
            .flat_map(|dir| {
                crate::project::dependencies::LOCKFILE_NAMES
                    .iter()
                    .map(move |name| dir.join(name))
            })
            .filter(|path| path.is_file())
            .collect();
        let manifests = manifest_files
            .iter()
            .chain(&lockfiles)
            .map(|path| (relative(path), hash_file(path)))
            .collect();
        ScanInputs {
            engine: CacheKey::current(&config.lang),
            options: ScanOptions {
                target_languages: config.target_languages.clone(),
                only_target_language_files: config.only_target_language_files,
                quick_mode: config.quick_mode,
                with_deps: config.with_deps,
                only_category: config.only_category.clone(),
                category_overrides: config.category_overrides.clone(),
                disabled_rules: config.disabled_rules.clone(),
                severity_levels: config.severity_levels.clone(),
            },
            rules: hash_tree(&config.rules_path),
            custom_rules: config
                .custom_rules_dir
                .as_deref()
                .map(hash_tree)
                .unwrap_or_default(),
            suppressions: config.suppress_file.as_deref().map(hash_file),
            files,
            manifests,
            discovered,
        }
    }

    /// SHA-256 of these inputs and of which `governance_names` exist around
    /// each discovered file (`file_contains::governance_fingerprint`).
    pub fn fingerprint(&self, governance_names: &[String]) -> String {
        let governance: Vec<String> = self
            .discovered
            .par_iter()
            .map(|path| governance_fingerprint(path, governance_names))
            .collect();
        let hashed = serde_json::json!({
            "inputs": self,
            "governance_names": governance_names,
            "governance": governance,
        });
        sha256_hex(hashed.to_string().as_bytes())
    }
}

/// SHA-256 of the file at `path`, [`UNREADABLE`] when it cannot be read.
fn hash_file(path: &Path) -> String {
    std::fs::read(path).map_or_else(|_| UNREADABLE.to_string(), |bytes| sha256_hex(&bytes))
}

/// SHA-256 of every file under `path` by path, or of `path` itself when it
/// is a file. A rules folder or a custom rules folder is hashed whole: a
/// file the loader skips today costs a needless full scan at worst, never
/// a wrong shortcut. Symbolic links are not followed into folders.
fn hash_tree(path: &Path) -> BTreeMap<String, String> {
    let mut hashes = BTreeMap::new();
    let mut pending = vec![path.to_path_buf()];
    while let Some(current) = pending.pop() {
        let is_dir = std::fs::symlink_metadata(&current).is_ok_and(|m| m.is_dir());
        if !is_dir {
            hashes.insert(current.to_string_lossy().into_owned(), hash_file(&current));
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&current) {
            pending.extend(entries.flatten().map(|entry| entry.path()));
        }
    }
    hashes
}

/// The record of the last full scan, in the engine's cache folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastScan {
    format: u32,
    /// [`ScanInputs::fingerprint`] of the inputs that scan read.
    pub fingerprint: String,
    /// The governance names of that scan's rules
    /// (`ScanReport::governance_names`).
    pub governance_names: Vec<String>,
    /// Its JSON export, holding its findings.
    pub export_path: PathBuf,
    /// Its HTML report, `None` when it wrote another format.
    pub report_path: Option<PathBuf>,
    /// Files it analysed.
    pub files_scanned: usize,
    /// Lines of code it counted.
    pub total_loc: usize,
    /// The SBOM written for these inputs (`--sbom`), `None` until one is.
    /// An SBOM only reads the dependency manifests, which are part of the
    /// fingerprint: an unchanged scan names it instead of writing a copy.
    #[serde(default)]
    pub sbom_path: Option<PathBuf>,
}

impl LastScan {
    /// Builds the record of a full scan that read `inputs`.
    pub fn new(
        inputs: &ScanInputs,
        governance_names: Vec<String>,
        export_path: PathBuf,
        report_path: Option<PathBuf>,
        files_scanned: usize,
        total_loc: usize,
    ) -> Self {
        LastScan {
            format: FORMAT,
            fingerprint: inputs.fingerprint(&governance_names),
            governance_names,
            export_path,
            report_path,
            files_scanned,
            total_loc,
            sbom_path: None,
        }
    }

    /// The record's path for the scans of `config`: in this engine's cache
    /// folder, `None` without a cache (`--no-cache`).
    fn path(config: &ScanConfig) -> Option<PathBuf> {
        let base = config.cache_dir.as_deref()?;
        Some(
            CacheKey::current(&config.lang)
                .engine_dir(base)
                .join(RECORD_FILE),
        )
    }

    /// The last scan when nothing it read has changed: same fingerprint,
    /// its export is still the latest one of the history folder, and its
    /// HTML report still exists when `needs_report`. `None` otherwise,
    /// and the scan runs in full.
    ///
    /// The export must be the latest: a scan run in between (with
    /// `--no-cache`, or with other options) wrote a newer one, and this
    /// record no longer describes the latest results.
    pub fn find_unchanged(
        config: &ScanConfig,
        inputs: &ScanInputs,
        needs_report: bool,
    ) -> Option<Self> {
        let path = Self::path(config)?;
        let record: LastScan = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        let datas_dir = config.datas_dir.as_deref()?;
        let latest =
            crate::report::export_json::find_latest_baseline(datas_dir, &config.brand_prefix)?;
        let unchanged = record.format == FORMAT
            && latest == record.export_path
            && (!needs_report || record.report_path.as_deref().is_some_and(Path::is_file))
            && inputs.fingerprint(&record.governance_names) == record.fingerprint;
        unchanged.then_some(record)
    }

    /// Writes the record for the next scans of `config`, atomically. Does
    /// nothing without a cache.
    pub fn save(&self, config: &ScanConfig) -> std::io::Result<()> {
        let Some(path) = Self::path(config) else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?,
        )?;
        std::fs::rename(&tmp, &path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A project with one Python file, a rules file and a history folder,
    /// in a fresh temporary folder.
    fn project(label: &str) -> (PathBuf, ScanConfig) {
        let root = std::env::temp_dir().join(format!(
            "codefixture-audit-unchanged-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/app.py"), "print('hello')\n").unwrap();
        // A manifest, so that a lockfile added next to it is an input.
        std::fs::write(root.join("requirements.txt"), "flask==2.0\n").unwrap();
        let rules = root.join("rules.cfpack");
        std::fs::write(&rules, b"pack bytes").unwrap();
        let datas = root.join("audit-reports/audit-datas");
        std::fs::create_dir_all(&datas).unwrap();
        let config = ScanConfig {
            root: root.clone(),
            include_paths: vec![".".to_string()],
            rules_path: rules,
            cache_dir: Some(datas.join("cache")),
            exclude_patterns: vec!["audit-reports/".to_string()],
            datas_dir: Some(datas),
            brand_prefix: "SCA".to_string(),
            lang: "en".to_string(),
            ..ScanConfig::default()
        };
        (root, config)
    }

    /// Writes an export file named after `timestamp`, as a scan does.
    fn write_export(config: &ScanConfig, timestamp: &str) -> PathBuf {
        let data = crate::report::export_json::build_export_data(&[], timestamp, "date", None);
        crate::report::export_json::write_export(config.datas_dir.as_deref().unwrap(), "SCA", &data)
            .unwrap()
    }

    /// Saves the record of a scan of `config` that wrote `export` and the
    /// HTML report `report`.
    fn record_scan(config: &ScanConfig, export: PathBuf, report: Option<PathBuf>) {
        let inputs = ScanInputs::read(config);
        LastScan::new(
            &inputs,
            vec!["SECURITY.md".to_string()],
            export,
            report,
            1,
            1,
        )
        .save(config)
        .unwrap();
    }

    fn is_unchanged(config: &ScanConfig, needs_report: bool) -> bool {
        LastScan::find_unchanged(config, &ScanInputs::read(config), needs_report).is_some()
    }

    #[test]
    fn test_a_project_scanned_again_without_change_is_unchanged() {
        let (root, config) = project("same");
        let export = write_export(&config, "2026-11-18-10-00");
        record_scan(&config, export, None);
        assert!(is_unchanged(&config, false));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_each_input_of_the_scan_breaks_the_match() {
        // Each change is made on a fresh project that matched before it.
        type Change = fn(&Path, &mut ScanConfig);
        let changes: [(&str, Change); 8] = [
            ("file", |root, _| {
                std::fs::write(root.join("src/app.py"), "print('bye')\n").unwrap()
            }),
            ("new_file", |root, _| {
                std::fs::write(root.join("src/new.py"), "x = 1\n").unwrap()
            }),
            ("manifest", |root, _| {
                std::fs::write(root.join("requirements.txt"), "flask==3.0\n").unwrap()
            }),
            ("lockfile", |root, _| {
                std::fs::write(root.join("poetry.lock"), "# new lock\n").unwrap()
            }),
            ("pack", |root, _| {
                std::fs::write(root.join("rules.cfpack"), b"other pack").unwrap()
            }),
            ("governance", |root, _| {
                std::fs::write(root.join("src/SECURITY.md"), "policy\n").unwrap()
            }),
            ("suppressions", |root, config| {
                let file = root.join(".sca-suppress.json");
                std::fs::write(&file, "{}").unwrap();
                config.suppress_file = Some(file);
            }),
            ("option", |_, config| {
                config.disabled_rules = vec!["eval_usage".to_string()]
            }),
        ];
        for (label, change) in changes {
            let (root, mut config) = project(&format!("change-{label}"));
            let export = write_export(&config, "2026-11-18-10-00");
            record_scan(&config, export, None);
            assert!(
                is_unchanged(&config, false),
                "{label}: matched before the change"
            );
            change(&root, &mut config);
            assert!(
                !is_unchanged(&config, false),
                "{label}: must break the match"
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn test_a_newer_export_makes_the_record_out_of_date() {
        let (root, config) = project("newer");
        let export = write_export(&config, "2026-11-18-10-00");
        record_scan(&config, export, None);
        write_export(&config, "2026-11-18-11-00");
        assert!(!is_unchanged(&config, false));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_the_html_format_needs_the_recorded_report() {
        let (root, config) = project("report");
        let export = write_export(&config, "2026-11-18-10-00");
        let report = root.join("audit-reports/SCA-REPORT-2026-11-18-10-00.html");
        std::fs::write(&report, "<html></html>").unwrap();
        record_scan(&config, export.clone(), Some(report.clone()));
        assert!(is_unchanged(&config, true));
        std::fs::remove_file(&report).unwrap();
        assert!(
            !is_unchanged(&config, true),
            "a deleted report is rewritten"
        );
        assert!(
            is_unchanged(&config, false),
            "SARIF and text only need the export"
        );
        record_scan(&config, export, None);
        assert!(!is_unchanged(&config, true), "a text run wrote no report");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_no_record_without_a_cache() {
        let (root, mut config) = project("no-cache");
        let export = write_export(&config, "2026-11-18-10-00");
        record_scan(&config, export, None);
        config.cache_dir = None;
        assert!(!is_unchanged(&config, false));
        std::fs::remove_dir_all(root).unwrap();
    }
}
