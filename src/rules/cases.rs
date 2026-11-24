//! Rule test cases (ticket #155, spec #171): for each rule, vulnerable
//! files that must raise it and clean files that must not, listed in one
//! registry. The catalog's is `rules/cases/registry.json` (private
//! repository, `rules test`); a client keeps theirs in their rules
//! folder, `~/.codefixture-audit/custom-rules/cases/registry.json`, in the
//! same format (ADR-0057, ticket #276, `custom-rules test`).
//!
//! The layout follows the Audit engine's test fixtures (`Audit/tests/
//! registry.py` and `tests/fixtures/generic/{vulnerable,clean}`): one
//! entry per case naming the file, where it goes in the test project and
//! the rule expected. The registry is the only source of truth; the
//! Audit's `@audit-fixture` headers are dropped by the conversion.
//!
//! ```text
//! rules/cases/
//! ├── registry.json
//! ├── vulnerable/<language>/<file>
//! └── clean/<language>/<file>
//! ```
//!
//! A case runs through the real engine: a temporary project holding the
//! case file at its `target` path (plus its `extra` files), a temporary
//! catalog holding the single rule under test, then `run_scan`. The
//! rules folder (`catalog_dir` below) is the catalog or the client's
//! folder, laid out alike (`<language>/<category>/<rule>.sca`). The
//! catalog's cases sit outside `rules/builtin`, so no pack ever carries
//! them, and the export removes `rules/`; a client's sit beside their
//! rules, never in the shared repository.
//!
//! Shared by both builds since ticket #276; before it, private. Every
//! message a client reads (a registry that cannot be read, a problem in
//! it, a case that could not run) is a value rendered in the console
//! language (`render`); its `Display` is the English text the catalog's
//! tools and the JSON output have always used.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;
use serde::Deserialize;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde_json::Value;

use crate::i18n::t;
use crate::scan::orchestrator::{ScanConfig, run_scan};

/// Registry layout version this engine reads.
pub const REGISTRY_FORMAT: u64 = 1;

/// Renders a message of the console locale with its `{name}` values.
fn render(locale: &Value, key: &str, values: &[(&str, String)]) -> String {
    values.iter().fold(t(locale, key), |text, (name, value)| {
        text.replace(&format!("{{{name}}}"), value)
    })
}

/// The English console locale, which the `Display` of this module's
/// messages renders with.
fn english() -> Value {
    crate::i18n::load_script_locale("en")
}

/// What a case expects from its rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Expect {
    /// At least one finding of the rule (on one of `lines` when given).
    Detected,
    /// No finding of the rule.
    Clean,
}

/// Another file of a case's test project (cross-file taint).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtraFile {
    /// Path relative to the registry's folder.
    pub file: String,
    /// Path in the test project.
    pub target: String,
}

/// One registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    /// Language folder of the rule (`rules/builtin/<language>/`): the same
    /// id exists in several languages.
    pub language: String,
    /// Rule id, the file name of `<language>/<category>/<rule>.sca`.
    pub rule: String,
    pub expect: Expect,
    /// Case file, relative to the registry's folder.
    pub file: String,
    /// Path of the case file in the temporary test project.
    pub target: String,
    /// For a `detected` case: lines where a finding must be (any line
    /// when empty).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<ExtraFile>,
}

/// Registry entries in file order, duplicates kept so that the check can
/// report them (a JSON object read into a map would keep the last one
/// silently).
struct Entries(Vec<(String, Case)>);

impl<'de> Deserialize<'de> for Entries {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EntriesVisitor;
        impl<'de> Visitor<'de> for EntriesVisitor {
            type Value = Entries;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an object of test cases")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Entries, A::Error> {
                let mut out = Vec::new();
                while let Some((key, case)) = map.next_entry::<String, Case>()? {
                    out.push((key, case));
                }
                Ok(Entries(out))
            }
        }
        deserializer.deserialize_map(EntriesVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistry {
    format: u64,
    cases: Entries,
}

/// A loaded registry.
pub struct Registry {
    /// Folder of `registry.json`: case paths are relative to it.
    pub root: PathBuf,
    /// Entries in file order.
    pub cases: Vec<(String, Case)>,
}

/// Why a registry could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// The file could not be read (missing, no permission).
    Unreadable { path: PathBuf, error: String },
    /// The file is not a registry: invalid JSON, an unknown field, a
    /// missing one (serde's message, which names the line).
    Invalid { path: PathBuf, error: String },
    /// A registry of another format version.
    Format { path: PathBuf, format: u64 },
}

impl RegistryError {
    /// The message in the language of `locale` (a console locale).
    pub fn render(&self, locale: &Value) -> String {
        match self {
            RegistryError::Unreadable { path, error } => render(
                locale,
                "cases_registry_unreadable",
                &[
                    ("path", path.display().to_string()),
                    ("error", error.clone()),
                ],
            ),
            RegistryError::Invalid { path, error } => render(
                locale,
                "cases_registry_invalid",
                &[
                    ("path", path.display().to_string()),
                    ("error", error.clone()),
                ],
            ),
            RegistryError::Format { path, format } => render(
                locale,
                "cases_registry_format",
                &[
                    ("path", path.display().to_string()),
                    ("format", format.to_string()),
                    ("expected", REGISTRY_FORMAT.to_string()),
                ],
            ),
        }
    }
}

/// In English.
impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.render(&english()))
    }
}

/// Reads a registry. The error names the file and the problem.
pub fn read_registry(path: &Path) -> Result<Registry, RegistryError> {
    let text = std::fs::read_to_string(path).map_err(|e| RegistryError::Unreadable {
        path: path.to_path_buf(),
        error: e.to_string(),
    })?;
    let raw: RawRegistry = serde_json::from_str(&text).map_err(|e| RegistryError::Invalid {
        path: path.to_path_buf(),
        error: e.to_string(),
    })?;
    if raw.format != REGISTRY_FORMAT {
        return Err(RegistryError::Format {
            path: path.to_path_buf(),
            format: raw.format,
        });
    }
    Ok(Registry {
        root: path.parent().unwrap_or(Path::new(".")).to_path_buf(),
        cases: raw.cases.0,
    })
}

/// [`read_registry`] with the error in English, for the catalog's tools.
pub fn load_registry(path: &Path) -> Result<Registry, String> {
    read_registry(path).map_err(|error| error.to_string())
}

/// The text of a registry holding `cases`, byte for byte what the case
/// converter writes (`json.dump(..., indent=2, ensure_ascii=False)`, keys
/// sorted, a final newline): `scripts/convert_audit_fixtures.py` and
/// `create-rule --ai` can both write the file without reordering it.
pub fn registry_text(cases: &[(String, Case)]) -> String {
    let mut sorted: Vec<&(String, Case)> = cases.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = format!("{{\n  \"format\": {REGISTRY_FORMAT},\n  \"cases\": {{");
    for (i, (key, case)) in sorted.iter().enumerate() {
        let body = serde_json::to_string_pretty(case).expect("case serializes");
        let body = body.replace('\n', "\n    ");
        let key = serde_json::to_string(key).expect("key serializes");
        out.push_str(if i == 0 { "\n    " } else { ",\n    " });
        out.push_str(&format!("{key}: {body}"));
    }
    out.push_str(if sorted.is_empty() {
        "}\n}\n"
    } else {
        "\n  }\n}\n"
    });
    out
}

/// Adds `new` to the registry at `path` and writes it back (keys sorted,
/// see [`registry_text`]); refuses a key already used.
pub fn add_to_registry(path: &Path, new: &[(String, Case)]) -> Result<(), String> {
    let registry = load_registry(path)?;
    let mut cases = registry.cases;
    for (key, case) in new {
        if cases.iter().any(|(k, _)| k == key) {
            return Err(format!("{}: case {key} already exists", path.display()));
        }
        cases.push((key.clone(), case.clone()));
    }
    std::fs::write(path, registry_text(&cases)).map_err(|e| format!("{}: {e}", path.display()))
}

/// The catalog file of `language`/`rule`
/// (`<catalog>/<language>/<category>/<rule>.sca`), whatever its category.
pub fn catalog_rule_file(catalog_dir: &Path, language: &str, rule: &str) -> Option<PathBuf> {
    let file = format!("{rule}.sca");
    let mut categories: Vec<PathBuf> = std::fs::read_dir(catalog_dir.join(language))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    categories.sort();
    categories
        .into_iter()
        .map(|dir| dir.join(&file))
        .find(|p| p.is_file())
}

/// A relative path that stays inside its root: no `..`, no root, no
/// drive prefix.
fn stays_inside(path: &str) -> bool {
    let p = Path::new(path);
    !path.is_empty() && p.components().all(|c| matches!(c, Component::Normal(_)))
}

/// One problem of a registry against a rules folder (see
/// [`registry_problems`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryProblem {
    /// Two cases under one key: the JSON object would keep the last.
    DuplicateKey { key: String },
    /// A key other than lowercase `snake_case` ASCII.
    BadKey { key: String },
    /// The case names a rule the folder does not hold.
    NoRule {
        key: String,
        language: String,
        rule: String,
        dir: PathBuf,
    },
    /// A case file outside the registry's folder (`..`, an absolute path).
    FileOutside { key: String, file: String },
    /// A case file that does not exist.
    FileMissing { key: String, file: String },
    /// A target path outside the temporary test project.
    TargetOutside { key: String, target: String },
    /// `lines` on a case that expects no finding.
    LinesOnClean { key: String },
    /// A file of `vulnerable/` or `clean/` that no case lists.
    OrphanFile { file: PathBuf },
}

impl RegistryProblem {
    /// The message in the language of `locale` (a console locale).
    pub fn render(&self, locale: &Value) -> String {
        match self {
            RegistryProblem::DuplicateKey { key } => render(
                locale,
                "cases_problem_duplicate_key",
                &[("key", key.clone())],
            ),
            RegistryProblem::BadKey { key } => {
                render(locale, "cases_problem_bad_key", &[("key", key.clone())])
            }
            RegistryProblem::NoRule {
                key,
                language,
                rule,
                dir,
            } => render(
                locale,
                "cases_problem_no_rule",
                &[
                    ("key", key.clone()),
                    ("language", language.clone()),
                    ("rule", rule.clone()),
                    ("dir", dir.display().to_string()),
                ],
            ),
            RegistryProblem::FileOutside { key, file } => render(
                locale,
                "cases_problem_file_outside",
                &[("key", key.clone()), ("file", file.clone())],
            ),
            RegistryProblem::FileMissing { key, file } => render(
                locale,
                "cases_problem_file_missing",
                &[("key", key.clone()), ("file", file.clone())],
            ),
            RegistryProblem::TargetOutside { key, target } => render(
                locale,
                "cases_problem_target_outside",
                &[("key", key.clone()), ("target", target.clone())],
            ),
            RegistryProblem::LinesOnClean { key } => render(
                locale,
                "cases_problem_lines_on_clean",
                &[("key", key.clone())],
            ),
            RegistryProblem::OrphanFile { file } => render(
                locale,
                "cases_problem_orphan_file",
                &[("file", file.display().to_string())],
            ),
        }
    }
}

/// In English.
impl fmt::Display for RegistryProblem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.render(&english()))
    }
}

/// Every problem of a registry against a rules folder, in file order.
/// `rules test` and `custom-rules test` refuse to run while there is
/// one: a case that cannot run would otherwise count as neither passed
/// nor failed.
pub fn registry_problems(registry: &Registry, catalog_dir: &Path) -> Vec<RegistryProblem> {
    let mut problems = Vec::new();
    let mut seen = BTreeSet::new();
    let mut referenced = BTreeSet::new();
    let key_ok = |k: &str| {
        !k.is_empty()
            && k.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    };
    for (key, case) in &registry.cases {
        let key_of = || key.clone();
        if !seen.insert(key.clone()) {
            problems.push(RegistryProblem::DuplicateKey { key: key_of() });
        }
        if !key_ok(key) {
            problems.push(RegistryProblem::BadKey { key: key_of() });
        }
        if catalog_rule_file(catalog_dir, &case.language, &case.rule).is_none() {
            problems.push(RegistryProblem::NoRule {
                key: key_of(),
                language: case.language.clone(),
                rule: case.rule.clone(),
                dir: catalog_dir.to_path_buf(),
            });
        }
        for (file, target) in std::iter::once((&case.file, &case.target))
            .chain(case.extra.iter().map(|x| (&x.file, &x.target)))
        {
            if !stays_inside(file) {
                problems.push(RegistryProblem::FileOutside {
                    key: key_of(),
                    file: file.clone(),
                });
            } else if !registry.root.join(file).is_file() {
                problems.push(RegistryProblem::FileMissing {
                    key: key_of(),
                    file: file.clone(),
                });
            } else {
                referenced.insert(PathBuf::from(file));
            }
            if !stays_inside(target) {
                problems.push(RegistryProblem::TargetOutside {
                    key: key_of(),
                    target: target.clone(),
                });
            }
        }
        if case.expect == Expect::Clean && !case.lines.is_empty() {
            problems.push(RegistryProblem::LinesOnClean { key: key_of() });
        }
    }
    for kind in ["vulnerable", "clean"] {
        for file in files_under(&registry.root, Path::new(kind)) {
            if !referenced.contains(&file) {
                problems.push(RegistryProblem::OrphanFile { file });
            }
        }
    }
    problems
}

/// [`registry_problems`] in English, for the catalog's tools.
pub fn check_registry(registry: &Registry, catalog_dir: &Path) -> Vec<String> {
    let en = english();
    registry_problems(registry, catalog_dir)
        .iter()
        .map(|problem| problem.render(&en))
        .collect()
}

/// Files under `root/rel`, as paths relative to `root`, sorted.
fn files_under(root: &Path, rel: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root.join(rel)) else {
        return out;
    };
    for entry in entries.flatten() {
        let child = rel.join(entry.file_name());
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            out.extend(files_under(root, &child));
        } else if file_type.is_file() && entry.file_name() != ".DS_Store" {
            out.push(child);
        }
    }
    out.sort();
    out
}

/// Why a case failed, for the command to word it in the console
/// language.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Failure {
    /// A `detected` case raised no finding of its rule.
    NoFinding,
    /// A `detected` case raised its rule, but not on any of these lines.
    WrongLines { expected: Vec<usize> },
    /// A `clean` case raised its rule.
    UnexpectedFinding,
    /// The case could not run (file unreadable, rule missing or invalid).
    CouldNotRun { error: String },
}

/// Why a case could not run, rendered in the console language by the
/// commands (`Failure::CouldNotRun` keeps it in English for the JSON).
#[derive(Debug, Clone, PartialEq)]
pub enum CaseError {
    /// The rules folder has no rule `language`/`rule`.
    NoRule { language: String, rule: String },
    /// The rule file sits directly in its language folder, without the
    /// category folder the catalog layout requires.
    OutsideCategory { file: PathBuf },
    /// A file could not be copied into the temporary project or catalog.
    Io { file: String, error: String },
    /// The engine did not load the rule: it does not compile, or cannot
    /// be read.
    Rule {
        path: PathBuf,
        error: Box<crate::rules::catalog::RuleLoadError>,
    },
}

impl CaseError {
    /// The message in the language of `locale` (a console locale).
    pub fn render(&self, locale: &Value) -> String {
        match self {
            CaseError::NoRule { language, rule } => render(
                locale,
                "cases_error_no_rule",
                &[("language", language.clone()), ("rule", rule.clone())],
            ),
            CaseError::OutsideCategory { file } => render(
                locale,
                "cases_error_outside_category",
                &[("file", file.display().to_string())],
            ),
            CaseError::Io { file, error } => render(
                locale,
                "cases_error_io",
                &[("file", file.clone()), ("error", error.clone())],
            ),
            CaseError::Rule { path, error } => render(
                locale,
                "cases_error_io",
                &[
                    ("file", path.display().to_string()),
                    ("error", error.render(locale)),
                ],
            ),
        }
    }
}

/// In English.
impl fmt::Display for CaseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.render(&english()))
    }
}

/// Result of one case.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CaseOutcome {
    pub key: String,
    pub language: String,
    pub rule: String,
    pub expect: Expect,
    pub file: String,
    pub passed: bool,
    /// Lines of the rule's findings in the case file, sorted.
    pub found_lines: Vec<usize>,
    /// Why the case failed, in English (empty when it passed).
    pub detail: String,
    /// Why the case failed, as data (`None` when it passed).
    pub failure: Option<Failure>,
    /// Time of the engine run, in milliseconds: `rules check` flags a
    /// rule whose patterns take too long on its cases (ticket #156).
    pub duration_ms: u64,
    /// Why the case could not run, to word it in the console language
    /// (`None` when it ran). Not in the JSON: `failure` holds it in
    /// English there.
    #[serde(skip)]
    pub error: Option<CaseError>,
}

/// Distinct temporary folders for cases run in parallel.
static CASE_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Runs one case through the engine (see the module doc). An `Err` is a
/// case that could not run (file unreadable, rule missing), reported
/// like a failure by the caller; in English (see [`try_run_case`]).
pub fn run_case(
    registry_root: &Path,
    catalog_dir: &Path,
    key: &str,
    case: &Case,
) -> Result<CaseOutcome, String> {
    try_run_case(registry_root, catalog_dir, key, case).map_err(|error| error.to_string())
}

/// [`run_case`], with why a case could not run as a [`CaseError`].
pub fn try_run_case(
    registry_root: &Path,
    catalog_dir: &Path,
    key: &str,
    case: &Case,
) -> Result<CaseOutcome, CaseError> {
    let rule_file =
        catalog_rule_file(catalog_dir, &case.language, &case.rule).ok_or_else(|| {
            CaseError::NoRule {
                language: case.language.clone(),
                rule: case.rule.clone(),
            }
        })?;
    let category = rule_file
        .parent()
        .and_then(|p| p.file_name())
        .ok_or_else(|| CaseError::OutsideCategory {
            file: rule_file.clone(),
        })?;
    let io = |file: &Path| {
        let file = file.display().to_string();
        move |e: std::io::Error| CaseError::Io {
            file,
            error: e.to_string(),
        }
    };
    let work = std::env::temp_dir().join(format!(
        "sast-case-{}-{}",
        std::process::id(),
        CASE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let project = work.join("project");
    let rules = work.join("rules");
    let result = (|| -> Result<CaseOutcome, CaseError> {
        let rule_dir = rules.join(&case.language).join(category);
        std::fs::create_dir_all(&rule_dir).map_err(io(&rule_dir))?;
        std::fs::copy(&rule_file, rule_dir.join(rule_file.file_name().unwrap()))
            .map_err(io(&rule_file))?;
        for (file, target) in std::iter::once((&case.file, &case.target))
            .chain(case.extra.iter().map(|x| (&x.file, &x.target)))
        {
            let dest = project.join(target);
            let folder = dest.parent().unwrap();
            std::fs::create_dir_all(folder).map_err(io(folder))?;
            std::fs::copy(registry_root.join(file), &dest).map_err(io(Path::new(file)))?;
        }
        let config = ScanConfig {
            root: project.clone(),
            rules_path: rules.clone(),
            target_languages: Some(vec![case.language.clone()]),
            ..ScanConfig::default()
        };
        let started = std::time::Instant::now();
        let report = run_scan(&config);
        let duration_ms = started.elapsed().as_millis() as u64;
        if let Some((path, error)) = report.rule_errors.first() {
            return Err(CaseError::Rule {
                path: path.clone(),
                error: Box::new(error.clone()),
            });
        }
        let target = Path::new(&case.target);
        let mut found_lines: Vec<usize> = report
            .findings
            .iter()
            .filter(|f| f.rule_key == case.rule && Path::new(&f.file) == target)
            .map(|f| f.line)
            .collect();
        found_lines.sort_unstable();
        found_lines.dedup();
        let failure = match case.expect {
            Expect::Detected if found_lines.is_empty() => Some(Failure::NoFinding),
            Expect::Detected
                if !case.lines.is_empty()
                    && !found_lines.iter().any(|l| case.lines.contains(l)) =>
            {
                Some(Failure::WrongLines {
                    expected: case.lines.clone(),
                })
            }
            Expect::Clean if !found_lines.is_empty() => Some(Failure::UnexpectedFinding),
            _ => None,
        };
        let detail = match &failure {
            None => String::new(),
            Some(Failure::NoFinding) => "expected a finding, got none".to_string(),
            Some(Failure::WrongLines { expected }) => {
                format!("expected a finding on line {expected:?}, got lines {found_lines:?}")
            }
            Some(Failure::UnexpectedFinding) => {
                format!("expected no finding, got lines {found_lines:?}")
            }
            Some(Failure::CouldNotRun { error }) => error.clone(),
        };
        Ok(CaseOutcome {
            key: key.to_string(),
            language: case.language.clone(),
            rule: case.rule.clone(),
            expect: case.expect,
            file: case.file.clone(),
            passed: failure.is_none(),
            found_lines,
            detail,
            failure,
            duration_ms,
            error: None,
        })
    })();
    let _ = std::fs::remove_dir_all(&work);
    result
}

/// Runs the cases of `registry` whose `language/rule` is in `only`
/// (every case when `only` is empty), in parallel, in registry order.
pub fn run_cases(
    registry: &Registry,
    catalog_dir: &Path,
    only: &BTreeSet<(String, String)>,
) -> Vec<CaseOutcome> {
    let selected: Vec<&(String, Case)> = registry
        .cases
        .iter()
        .filter(|(_, c)| only.is_empty() || only.contains(&(c.language.clone(), c.rule.clone())))
        .collect();
    selected
        .par_iter()
        .map(|(key, case)| {
            try_run_case(&registry.root, catalog_dir, key, case).unwrap_or_else(|reason| {
                let error = reason.to_string();
                CaseOutcome {
                    key: key.clone(),
                    language: case.language.clone(),
                    rule: case.rule.clone(),
                    expect: case.expect,
                    file: case.file.clone(),
                    passed: false,
                    found_lines: Vec::new(),
                    detail: format!("could not run: {error}"),
                    failure: Some(Failure::CouldNotRun { error }),
                    duration_ms: 0,
                    error: Some(reason),
                }
            })
        })
        .collect()
}

/// Rules of the folder (`language/rule`) lacking a `detected` or a
/// `clean` case, sorted: what spec #171 requires every catalog rule to
/// have (`rules check`, ticket #156), and what `custom-rules test` names
/// for a client's rule (ticket #276).
pub fn rules_without_cases(
    registry: &Registry,
    catalog_dir: &Path,
) -> BTreeMap<(String, String), (bool, bool)> {
    let mut have: BTreeMap<(String, String), (bool, bool)> = BTreeMap::new();
    for (_, case) in &registry.cases {
        let entry = have
            .entry((case.language.clone(), case.rule.clone()))
            .or_default();
        match case.expect {
            Expect::Detected => entry.0 = true,
            Expect::Clean => entry.1 = true,
        }
    }
    let mut out = BTreeMap::new();
    let Ok(languages) = std::fs::read_dir(catalog_dir) else {
        return out;
    };
    for language in languages.flatten().filter(|e| e.path().is_dir()) {
        let lang = language.file_name().to_string_lossy().into_owned();
        for category in std::fs::read_dir(language.path())
            .into_iter()
            .flatten()
            .flatten()
        {
            for rule in std::fs::read_dir(category.path())
                .into_iter()
                .flatten()
                .flatten()
            {
                let path = rule.path();
                if path.extension().and_then(|e| e.to_str()) != Some("sca") {
                    continue;
                }
                let id = path.file_stem().unwrap().to_string_lossy().into_owned();
                let got = have
                    .get(&(lang.clone(), id.clone()))
                    .copied()
                    .unwrap_or_default();
                if !(got.0 && got.1) {
                    out.insert((lang.clone(), id), got);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sast-cases-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const RULE: &str = "rule marker_rule\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  MARKER\n    scope    line\n  end\nend\n";

    /// A catalog with one Python rule raising on `MARKER`, and a cases
    /// folder with one vulnerable and one clean file.
    fn fixture(label: &str) -> (PathBuf, PathBuf, PathBuf) {
        let dir = tmp(label);
        let catalog = dir.join("catalog");
        std::fs::create_dir_all(catalog.join("python/security")).unwrap();
        std::fs::write(catalog.join("python/security/marker_rule.sca"), RULE).unwrap();
        let cases = dir.join("cases");
        std::fs::create_dir_all(cases.join("vulnerable/python")).unwrap();
        std::fs::create_dir_all(cases.join("clean/python")).unwrap();
        std::fs::write(cases.join("vulnerable/python/m.py"), "x = 1\nMARKER = 2\n").unwrap();
        std::fs::write(cases.join("clean/python/m_clean.py"), "x = 1\n").unwrap();
        (dir, catalog, cases)
    }

    fn write_registry(cases: &Path, body: &str) -> PathBuf {
        let path = cases.join("registry.json");
        std::fs::write(&path, format!("{{\"format\": 1, \"cases\": {{{body}}}}}")).unwrap();
        path
    }

    const GOOD: &str = r#"
        "m_py": {"language": "python", "rule": "marker_rule", "expect": "detected",
                 "file": "vulnerable/python/m.py", "target": "src/m.py", "lines": [2]},
        "m_clean_py": {"language": "python", "rule": "marker_rule", "expect": "clean",
                       "file": "clean/python/m_clean.py", "target": "src/m.py"}"#;

    #[test]
    fn test_cases_pass_through_the_engine() {
        let (dir, catalog, cases) = fixture("pass");
        let registry = load_registry(&write_registry(&cases, GOOD)).unwrap();
        let problems = check_registry(&registry, &catalog);
        let outcomes = run_cases(&registry, &catalog, &BTreeSet::new());
        let missing = rules_without_cases(&registry, &catalog);
        std::fs::remove_dir_all(&dir).ok();
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|o| o.passed), "{outcomes:?}");
        assert_eq!(outcomes[0].found_lines, [2]);
        assert!(missing.is_empty(), "{missing:?}");
    }

    /// A vulnerable case not raised and a clean case raised both fail,
    /// with the file named.
    #[test]
    fn test_wrong_expectations_fail_with_detail() {
        let (dir, catalog, cases) = fixture("fail");
        let swapped = GOOD
            .replace("\"expect\": \"detected\"", "\"expect\": \"TMP\"")
            .replace("\"expect\": \"clean\"", "\"expect\": \"detected\"")
            .replace("\"expect\": \"TMP\"", "\"expect\": \"clean\"")
            .replace(", \"lines\": [2]", "");
        let registry = load_registry(&write_registry(&cases, &swapped)).unwrap();
        let outcomes = run_cases(&registry, &catalog, &BTreeSet::new());
        std::fs::remove_dir_all(&dir).ok();
        assert!(outcomes.iter().all(|o| !o.passed), "{outcomes:?}");
        assert!(
            outcomes[0].detail.contains("expected no finding"),
            "{outcomes:?}"
        );
        assert!(outcomes[1].detail.contains("got none"), "{outcomes:?}");
        assert_eq!(outcomes[0].file, "vulnerable/python/m.py");
    }

    #[test]
    fn test_finding_on_another_line_fails() {
        let (dir, catalog, cases) = fixture("line");
        let registry = load_registry(&write_registry(&cases, &GOOD.replace("[2]", "[1]"))).unwrap();
        let outcomes = run_cases(&registry, &catalog, &BTreeSet::new());
        std::fs::remove_dir_all(&dir).ok();
        assert!(!outcomes[0].passed);
        assert!(
            outcomes[0].detail.contains("line [1]"),
            "{}",
            outcomes[0].detail
        );
    }

    /// Every registry problem of spec #171 is reported.
    #[test]
    fn test_check_registry_reports_every_problem() {
        let (dir, catalog, cases) = fixture("check");
        std::fs::write(cases.join("vulnerable/python/orphan.py"), "MARKER\n").unwrap();
        let body = r#"
            "dup": {"language": "python", "rule": "marker_rule", "expect": "detected",
                    "file": "vulnerable/python/m.py", "target": "../m.py"},
            "dup": {"language": "java", "rule": "marker_rule", "expect": "clean",
                    "file": "clean/python/missing.py", "target": "src/m.py", "lines": [1]},
            "Bad-Key": {"language": "python", "rule": "marker_rule", "expect": "clean",
                        "file": "../outside.py", "target": "/abs.py"}"#;
        let registry = load_registry(&write_registry(&cases, body)).unwrap();
        let problems = check_registry(&registry, &catalog).join("\n");
        std::fs::remove_dir_all(&dir).ok();
        for expected in [
            "dup: duplicate key",
            "target ../m.py leaves the test project",
            "no rule java/marker_rule",
            "file clean/python/missing.py not found",
            "lines on a clean case",
            "Bad-Key: key is not lowercase",
            "file ../outside.py leaves the cases folder",
            "target /abs.py leaves the test project",
            "vulnerable/python/orphan.py: file in no case",
            "clean/python/m_clean.py: file in no case",
        ] {
            assert!(problems.contains(expected), "{expected}\n{problems}");
        }
    }

    /// Ticket #276: a client reads the registry problems, the reasons a
    /// case could not run and the registry errors in the console
    /// language; the English text of the catalog's tools is unchanged.
    #[test]
    fn test_messages_are_rendered_in_the_console_language() {
        let (dir, catalog, cases) = fixture("render");
        let path = write_registry(
            &cases,
            r#""k": {"language": "java", "rule": "marker_rule", "expect": "clean",
                     "file": "clean/python/m_clean.py", "target": "src/m.py"}"#,
        );
        let registry = load_registry(&path).unwrap();
        let fr = crate::i18n::load_script_locale("fr");
        let problems: Vec<String> = registry_problems(&registry, &catalog)
            .iter()
            .map(|p| p.render(&fr))
            .collect();
        let outcomes = run_cases(&registry, &catalog, &BTreeSet::new());
        std::fs::write(&path, r#"{"format": 9, "cases": {}}"#).unwrap();
        let format = read_registry(&path).err().expect("format 9 refused");
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            problems
                .iter()
                .any(|p| p.starts_with("k : aucune règle java/marker_rule dans ")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p == "vulnerable/python/m.py : fichier d'aucun cas"),
            "{problems:?}"
        );
        let error = outcomes[0].error.as_ref().expect("could not run");
        assert_eq!(error.render(&fr), "aucune règle java/marker_rule");
        assert_eq!(
            outcomes[0].detail,
            "could not run: no rule java/marker_rule"
        );
        assert!(
            format
                .render(&fr)
                .ends_with("format de registre 9 inconnu, 1 attendu"),
            "{format}"
        );
    }

    #[test]
    fn test_load_registry_refuses_unknown_format_and_fields() {
        let (dir, _catalog, cases) = fixture("format");
        let path = cases.join("registry.json");
        std::fs::write(&path, r#"{"format": 2, "cases": {}}"#).unwrap();
        let format = load_registry(&path).err().unwrap();
        std::fs::write(
            &path,
            r#"{"format": 1, "cases": {"k": {"language": "python", "rule": "r", "expect": "clean", "file": "f", "target": "t", "typo": 1}}}"#,
        )
        .unwrap();
        let field = load_registry(&path).err().unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert!(format.contains("format 2 unknown"), "{format}");
        assert!(field.contains("typo"), "{field}");
    }
}
