//! Detection of unpinned dependencies (`unpinned_dependency`) and
//! license compliance — port of the **static** part of
//! `Audit/sca/dependencies.py` (manifest parsers + unpinned
//! detection + license checking).
//!
//! **Deliberately not ported** (decision of 2026-08-25, cf. memory
//! `project_no_dependency_scanning`): `_check_dependency_tools`/
//! `_scan_with_pip_audit`/`_scan_with_npm_audit` — CVE matching
//! via `pip-audit`/`npm audit` as a subprocess. These optional
//! third-party tools query public databases by default (PyPI JSON
//! API, OSV.dev, npm registry), i.e. outbound network access — the maintainer
//! chose to stay cautious for this specific piece of work and to
//! port only the static detection.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use regex::Regex;

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    /// The version the version rules check: the exact version, the one a
    /// lockfile records, or the declared minimum of a range
    /// (`version_source` says which). `None` = no version to check, an
    /// unpinned dependency (`unpinned_dependency`).
    pub version: Option<String>,
    pub ecosystem: String,
    pub file: PathBuf,
    pub line: usize,
    pub raw_line: String,
    /// Where `version` comes from (ticket #209).
    pub version_source: VersionSource,
}

/// Where the version of a dependency comes from (ticket #209, the maintainer's
/// decision of 2026-11-18): the version a lockfile records as installed
/// when there is one, else the version the manifest pins, else the
/// declared minimum of its range, which the finding then states.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum VersionSource {
    /// The manifest pins the version exactly (or names none: `version`
    /// is then `None`).
    #[default]
    Manifest,
    /// The lockfile `file`, next to the manifest, records the installed
    /// version.
    Lockfile { file: String },
    /// The manifest declares the range `constraint`, and `lock` says why
    /// no lockfile gave the installed version: the lowest version the
    /// range allows is checked.
    DeclaredMinimum {
        constraint: String,
        lock: LockStatus,
    },
}

/// Why no lockfile gave the installed version of a dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockStatus {
    /// No lockfile next to the manifest.
    Absent,
    /// The lockfile `file` does not list the package.
    NotListed { file: String },
    /// The lockfile `file` lists the package with `value`, which is not a
    /// version (a git address, a local path).
    NotAVersion { file: String, value: String },
    /// The lockfile `file` cannot be read, for `reason`.
    Unreadable { file: String, reason: String },
    /// The lockfile `file` has a format this engine does not read yet.
    NotRead { file: String },
}

/// The lockfile next to a manifest, as read.
enum Lock {
    /// None of the ecosystem's lockfiles is there.
    Absent,
    /// A lockfile this engine does not read yet.
    NotRead(String),
    /// A lockfile that cannot be read, with the reason.
    Unreadable(String, String),
    /// The installed versions it records, by package name.
    Read {
        file: String,
        versions: BTreeMap<String, String>,
    },
}

/// The lockfiles of npm, in the order npm itself prefers them, then those
/// of the other JavaScript package managers, not read yet.
const NPM_LOCKFILES: [&str; 2] = ["npm-shrinkwrap.json", "package-lock.json"];
const NPM_OTHER_LOCKFILES: [&str; 4] = ["yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"];
/// The lockfiles of the Python package managers, not read yet.
const PYTHON_LOCKFILES: [&str; 4] = ["poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock"];

/// Every lockfile name this module looks for next to a manifest, for the
/// fingerprint of an unchanged project (ADR-0050): a lockfile change must
/// trigger a new scan, since it changes the versions checked.
pub const LOCKFILE_NAMES: [&str; 11] = [
    "npm-shrinkwrap.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "composer.lock",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "pdm.lock",
];

/// The npm lockfile in `dir`. `package-lock.json` and
/// `npm-shrinkwrap.json` share a format: version 1 lists the packages
/// under `dependencies`, versions 2 and 3 under `packages`, keyed by their
/// folder (`node_modules/<name>`, the top-level one being the installed
/// direct dependency).
fn npm_lock(dir: &Path) -> Lock {
    let Some(name) = NPM_LOCKFILES.iter().find(|n| dir.join(n).is_file()) else {
        return match NPM_OTHER_LOCKFILES.iter().find(|n| dir.join(n).is_file()) {
            Some(other) => Lock::NotRead(other.to_string()),
            None => Lock::Absent,
        };
    };
    let json = match read_lock_json(&dir.join(name)) {
        Ok(json) => json,
        Err(e) => return Lock::Unreadable(name.to_string(), e),
    };
    let mut versions = BTreeMap::new();
    if let Some(serde_json::Value::Object(packages)) = json.get("packages") {
        for (folder, entry) in packages {
            if let Some(package) = folder.strip_prefix("node_modules/")
                && !package.contains("/node_modules/")
                && let Some(version) = entry.get("version").and_then(|v| v.as_str())
            {
                versions.insert(package.to_string(), version.to_string());
            }
        }
    } else if let Some(serde_json::Value::Object(dependencies)) = json.get("dependencies") {
        for (package, entry) in dependencies {
            if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
                versions.insert(package.clone(), version.to_string());
            }
        }
    } else {
        return Lock::Unreadable(
            name.to_string(),
            "neither `packages` nor `dependencies`".into(),
        );
    }
    Lock::Read {
        file: name.to_string(),
        versions,
    }
}

/// `composer.lock` in `dir`: the installed packages under `packages` and
/// `packages-dev`, names in lower case as Composer compares them.
fn composer_lock(dir: &Path) -> Lock {
    const NAME: &str = "composer.lock";
    if !dir.join(NAME).is_file() {
        return Lock::Absent;
    }
    let json = match read_lock_json(&dir.join(NAME)) {
        Ok(json) => json,
        Err(e) => return Lock::Unreadable(NAME.to_string(), e),
    };
    let mut versions = BTreeMap::new();
    let mut sections = 0;
    for section in ["packages", "packages-dev"] {
        let Some(serde_json::Value::Array(packages)) = json.get(section) else {
            continue;
        };
        sections += 1;
        for package in packages {
            if let (Some(name), Some(version)) = (
                package.get("name").and_then(|v| v.as_str()),
                package.get("version").and_then(|v| v.as_str()),
            ) {
                versions.insert(name.to_lowercase(), version.to_string());
            }
        }
    }
    if sections == 0 {
        return Lock::Unreadable(NAME.to_string(), "no `packages` list".into());
    }
    Lock::Read {
        file: NAME.to_string(),
        versions,
    }
}

/// A Python lockfile in `dir`, none of which is read yet.
fn python_lock(dir: &Path) -> Lock {
    match PYTHON_LOCKFILES.iter().find(|n| dir.join(n).is_file()) {
        Some(name) => Lock::NotRead(name.to_string()),
        None => Lock::Absent,
    }
}

fn read_lock_json(path: &Path) -> Result<serde_json::Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

/// The version to check for the package `key` (its name as `lock` keys
/// it) declared with `spec`, read by `constraint`, and where it comes
/// from: the lockfile's version first, then the manifest's exact version,
/// then the declared minimum. `None` when the constraint has no minimum
/// and no lockfile gives a version: the dependency is then unpinned.
fn resolve_version(
    key: &str,
    spec: &str,
    constraint: crate::project::version_constraint::Constraint,
    lock: &Lock,
) -> (Option<String>, VersionSource) {
    use crate::project::version_constraint::Constraint;
    let status = match lock {
        Lock::Absent => LockStatus::Absent,
        Lock::NotRead(file) => LockStatus::NotRead { file: file.clone() },
        Lock::Unreadable(file, reason) => LockStatus::Unreadable {
            file: file.clone(),
            reason: reason.clone(),
        },
        Lock::Read { file, versions } => match versions.get(key) {
            Some(value) => {
                let version = value.strip_prefix('v').unwrap_or(value);
                if version.starts_with(|c: char| c.is_ascii_digit()) {
                    return (
                        Some(version.to_string()),
                        VersionSource::Lockfile { file: file.clone() },
                    );
                }
                LockStatus::NotAVersion {
                    file: file.clone(),
                    value: value.clone(),
                }
            }
            None => LockStatus::NotListed { file: file.clone() },
        },
    };
    match constraint {
        Constraint::Exact(version) => (Some(version), VersionSource::Manifest),
        Constraint::Minimum(version) => (
            Some(version),
            VersionSource::DeclaredMinimum {
                constraint: spec.to_string(),
                lock: status,
            },
        ),
        Constraint::NoMinimum => (None, VersionSource::Manifest),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepFileType {
    Requirements,
    PackageJson,
    PomXml,
    BuildGradle,
    Csproj,
    ComposerJson,
}

fn read_lines(path: &Path) -> Vec<(usize, String)> {
    std::fs::read_to_string(path)
        .map(|content| {
            content
                .lines()
                .enumerate()
                .map(|(i, l)| (i + 1, l.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

const ROOT_DEP_FILES: [(&str, DepFileType); 5] = [
    ("requirements.txt", DepFileType::Requirements),
    ("pyproject.toml", DepFileType::Requirements),
    ("pom.xml", DepFileType::PomXml),
    ("build.gradle", DepFileType::BuildGradle),
    ("composer.json", DepFileType::ComposerJson),
];

fn add_root_files(
    base: &Path,
    dep_files: &mut Vec<(PathBuf, DepFileType)>,
    seen: &mut std::collections::BTreeSet<PathBuf>,
) {
    for (filename, file_type) in ROOT_DEP_FILES {
        let filepath = normalize(&base.join(filename));
        if filepath.exists() && seen.insert(filepath.clone()) {
            dep_files.push((filepath, file_type));
        }
    }
    for entry in glob_csproj(base) {
        let entry = normalize(&entry);
        if seen.insert(entry.clone()) {
            dep_files.push((entry, DepFileType::Csproj));
        }
    }
    for entry in glob_requirements_dir(base) {
        let entry = normalize(&entry);
        if seen.insert(entry.clone()) {
            dep_files.push((entry, DepFileType::Requirements));
        }
    }
}

/// Finds the dependency manifest files of the audited project —
/// port of `_find_dependency_files`.
pub fn find_dependency_files(
    root_dir: &Path,
    include_paths: &[String],
) -> Vec<(PathBuf, DepFileType)> {
    let mut dep_files = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    add_root_files(root_dir, &mut dep_files, &mut seen);

    for base_path in include_paths {
        let full_path = root_dir.join(base_path);
        if !full_path.exists() {
            continue;
        }
        add_root_files(&full_path, &mut dep_files, &mut seen);

        let pkg_json = normalize(&full_path.join("package.json"));
        if pkg_json.exists() && seen.insert(pkg_json.clone()) {
            dep_files.push((pkg_json, DepFileType::PackageJson));
        }
    }

    dep_files
}

fn normalize(path: &Path) -> PathBuf {
    // `Path::components()` already eliminates "." segments (unlike a
    // plain string concatenation) — a sufficient equivalent
    // to `os.path.normpath` for the use `_find_dependency_files` makes
    // of it (deduplicating "root/./requirements.txt" and "root/requirements.txt").
    path.components().collect()
}

fn glob_csproj(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "csproj"))
                .collect()
        })
        .unwrap_or_default()
}

fn glob_requirements_dir(dir: &Path) -> Vec<PathBuf> {
    let req_dir = dir.join("requirements");
    std::fs::read_dir(&req_dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "txt"))
                .collect()
        })
        .unwrap_or_default()
}

/// Port of `_parse_requirements_txt` (delegates to
/// `parse_pyproject_toml` for that specific file, like Python).
pub fn parse_requirements_txt(path: &Path) -> Vec<Dependency> {
    if path.file_name().is_some_and(|n| n == "pyproject.toml") {
        return parse_pyproject_toml(path);
    }
    // Name, optional extras, then the version specifiers (ticket #209):
    // the whole specification is read with PEP 440, not the first number
    // after an operator, which made `<2.0` a version 2.0.
    let requirement_re = Regex::new(r"^([a-zA-Z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*(.*)$").unwrap();
    let lock = path.parent().map_or(Lock::Absent, python_lock);

    let mut deps = Vec::new();
    for (line_num, line) in read_lines(path) {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') || stripped.starts_with('-') {
            continue;
        }
        let Some(caps) = requirement_re.captures(stripped) else {
            continue;
        };
        // An inline comment and an environment marker end the specifiers.
        let spec = caps[2].split([';', '#']).next().unwrap_or_default().trim();
        let name = caps[1].to_lowercase();
        let (version, version_source) = resolve_version(
            &name,
            spec,
            crate::project::version_constraint::pep440(spec),
            &lock,
        );
        deps.push(Dependency {
            name,
            version,
            ecosystem: "PyPI".to_string(),
            file: path.to_path_buf(),
            line: line_num,
            raw_line: stripped.to_string(),
            version_source,
        });
    }
    deps
}

/// Port of `_parse_pyproject_toml` (simplified extraction, not a
/// real TOML parser — same choice as Python).
pub fn parse_pyproject_toml(path: &Path) -> Vec<Dependency> {
    let deps_section_re = Regex::new(r"^dependencies\s*=\s*\[").unwrap();
    // A quoted requirement: name, optional extras, the specifiers up to
    // the marker or the closing quote (ticket #209).
    let requirement_re =
        Regex::new(r#"^\s*"([a-zA-Z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*([^";]*)"#).unwrap();
    let lock = path.parent().map_or(Lock::Absent, python_lock);

    let mut deps = Vec::new();
    let mut in_deps_section = false;
    for (line_num, line) in read_lines(path) {
        let stripped = line.trim();
        if deps_section_re.is_match(stripped) {
            in_deps_section = true;
            continue;
        }
        if !in_deps_section {
            continue;
        }
        if stripped == "]" {
            in_deps_section = false;
            continue;
        }
        let Some(caps) = requirement_re.captures(stripped) else {
            continue;
        };
        let spec = caps[2].trim();
        let name = caps[1].to_lowercase();
        let (version, version_source) = resolve_version(
            &name,
            spec,
            crate::project::version_constraint::pep440(spec),
            &lock,
        );
        deps.push(Dependency {
            name,
            version,
            ecosystem: "PyPI".to_string(),
            file: path.to_path_buf(),
            line: line_num,
            raw_line: stripped
                .trim_matches(|c| c == '"' || c == ',')
                .trim()
                .to_string(),
            version_source,
        });
    }
    deps
}

/// Line of every key of the objects `sections` at the top level of the
/// JSON document `content`, as `(section, key) → line` (1-based).
///
/// Ticket #207: the port read one `"key": "value"` pair per line, the
/// first one, in one map for the whole file. A manifest written on one
/// line gave every dependency but the first line 0, and a package listed
/// in two sections, or named like another key of the file (`name`), got
/// the line of the other one. This walks the document once, with the
/// nesting of its objects and arrays, so each key is found in its own
/// section. Keys are decoded as JSON strings, so `"x\/y"` is `x/y`, as
/// `serde_json` reads it. Called only on a document `serde_json` has
/// already parsed: on anything else it returns what it found.
fn json_section_key_lines(content: &str, sections: &[&str]) -> BTreeMap<(String, String), usize> {
    /// One open object or array, and for an object its last key and
    /// whether the next string is a key.
    enum Frame {
        Object {
            key: Option<String>,
            expects_key: bool,
        },
        Array,
    }
    let bytes = content.as_bytes();
    let mut lines = BTreeMap::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut line = 1;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => line += 1,
            b'{' => stack.push(Frame::Object {
                key: None,
                expects_key: true,
            }),
            b'[' => stack.push(Frame::Array),
            b'}' | b']' => {
                stack.pop();
            }
            b',' => {
                if let Some(Frame::Object { expects_key, .. }) = stack.last_mut() {
                    *expects_key = true;
                }
            }
            b'"' => {
                // The string runs to the next quote that no backslash
                // escapes; JSON strings hold no raw line break.
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                let Some(raw) = content.get(start..=i.min(bytes.len() - 1)) else {
                    break;
                };
                let section = match stack.first() {
                    Some(Frame::Object { key, .. }) if stack.len() == 2 => key.clone(),
                    _ => None,
                };
                if let Some(Frame::Object { key, expects_key }) = stack.last_mut()
                    && *expects_key
                {
                    let name: String = serde_json::from_str(raw).unwrap_or_default();
                    if let Some(section) = section.filter(|s| sections.contains(&s.as_str())) {
                        lines.entry((section, name.clone())).or_insert(line);
                    }
                    *key = Some(name);
                    *expects_key = false;
                }
            }
            _ => {}
        }
        i += 1;
    }
    lines
}

/// The line of `name` in `section` from `json_section_key_lines`; 0 only
/// for a key the walk did not find, which a document `serde_json` parsed
/// does not have.
fn line_of(lines: &BTreeMap<(String, String), usize>, section: &str, name: &str) -> usize {
    lines
        .get(&(section.to_string(), name.to_string()))
        .copied()
        .unwrap_or(0)
}

/// Port of `_parse_package_json`.
pub fn parse_package_json(path: &Path) -> Vec<Dependency> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return vec![];
    };
    let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&content) else {
        return vec![];
    };

    let line_map = json_section_key_lines(&content, &["dependencies", "devDependencies"]);
    let lock = path.parent().map_or(Lock::Absent, npm_lock);
    let mut deps = Vec::new();
    for section in ["dependencies", "devDependencies"] {
        let Some(serde_json::Value::Object(section_deps)) = pkg.get(section) else {
            continue;
        };
        for (name, version_spec) in section_deps {
            let version_spec_str = version_spec.as_str().unwrap_or_default();
            // Ticket #209: the specification read as node-semver, and the
            // version installed according to the lockfile first.
            let (version, version_source) = resolve_version(
                name,
                version_spec_str,
                crate::project::version_constraint::npm(version_spec_str),
                &lock,
            );
            deps.push(Dependency {
                name: name.clone(),
                version,
                ecosystem: "npm".to_string(),
                file: path.to_path_buf(),
                line: line_of(&line_map, section, name),
                raw_line: format!("\"{name}\": \"{version_spec_str}\""),
                version_source,
            });
        }
    }
    deps
}

/// Port of `_parse_pom_xml` (regex over raw text, not an
/// XML parser — same choice as Python).
pub fn parse_pom_xml(path: &Path) -> Vec<Dependency> {
    let lines = read_lines(path);
    let content = lines
        .iter()
        .map(|(_, l)| l.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    let dep_block_re = Regex::new(r"(?s)<dependency>(.*?)</dependency>").unwrap();
    let group_id_re = Regex::new(r"<groupId>(.*?)</groupId>").unwrap();
    let artifact_id_re = Regex::new(r"<artifactId>(.*?)</artifactId>").unwrap();
    let version_re = Regex::new(r"<version>(.*?)</version>").unwrap();
    let pinned_re = Regex::new(r"^[0-9][0-9a-zA-Z._-]*$").unwrap();

    let mut deps = Vec::new();
    for block_caps in dep_block_re.captures_iter(&content) {
        let block = &block_caps[1];
        let Some(artifact_id) = artifact_id_re.captures(block) else {
            continue;
        };
        let artifact_id = artifact_id[1].to_string();
        let group_id = group_id_re.captures(block).map(|c| c[1].to_string());
        let name = match &group_id {
            Some(g) => format!("{g}:{artifact_id}"),
            None => artifact_id.clone(),
        };
        let raw_version = version_re.captures(block).map(|c| c[1].trim().to_string());

        let line_num = lines
            .iter()
            .find(|(_, l)| l.contains(&artifact_id))
            .map(|(n, _)| *n)
            .unwrap_or(0);

        let is_pinned = raw_version
            .as_deref()
            .is_some_and(|v| pinned_re.is_match(v) && !v.contains("${"));
        let version = if is_pinned { raw_version.clone() } else { None };
        deps.push(Dependency {
            name,
            version,
            ecosystem: "Maven".to_string(),
            file: path.to_path_buf(),
            line: line_num,
            raw_line: format!(
                "{} {}",
                deps_name_placeholder(&group_id, &artifact_id),
                raw_version.as_deref().unwrap_or("(no version)")
            ),
            version_source: VersionSource::Manifest,
        });
    }
    deps
}

fn deps_name_placeholder(group_id: &Option<String>, artifact_id: &str) -> String {
    match group_id {
        Some(g) => format!("{g}:{artifact_id}"),
        None => artifact_id.to_string(),
    }
}

/// Port of `_parse_build_gradle`.
pub fn parse_build_gradle(path: &Path) -> Vec<Dependency> {
    let quoted_re = Regex::new(
        r#"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s+['"]([^'"]+:[^'"]+):([^'"]+)['"]"#,
    )
    .unwrap();
    let paren_re = Regex::new(
        r#"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(\s*"([^"]+:[^"]+):([^"]+)""#,
    )
    .unwrap();
    let pinned_re = Regex::new(r"^[0-9][0-9a-zA-Z._-]*$").unwrap();

    let mut deps = Vec::new();
    for (line_num, line) in read_lines(path) {
        let stripped = line.trim();
        let caps = quoted_re
            .captures(stripped)
            .or_else(|| paren_re.captures(stripped));
        if let Some(caps) = caps {
            let name = caps[1].to_string();
            let version = caps[2].trim().to_string();
            let is_pinned = pinned_re.is_match(&version);
            deps.push(Dependency {
                name,
                version: if is_pinned { Some(version) } else { None },
                ecosystem: "Maven".to_string(),
                file: path.to_path_buf(),
                line: line_num,
                raw_line: stripped.to_string(),
                version_source: VersionSource::Manifest,
            });
        }
    }
    deps
}

/// Port of `_parse_csproj`.
pub fn parse_csproj(path: &Path) -> Vec<Dependency> {
    let re =
        Regex::new(r#"<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]*)")?"#).unwrap();
    let pinned_re = Regex::new(r"^[0-9]+\.[0-9]+[0-9a-zA-Z._-]*$").unwrap();

    let mut deps = Vec::new();
    for (line_num, line) in read_lines(path) {
        if let Some(caps) = re.captures(&line) {
            let name = caps[1].to_string();
            let version = caps
                .get(2)
                .map(|m| m.as_str().trim().to_string())
                .filter(|v| !v.is_empty());
            let is_pinned = version
                .as_deref()
                .is_some_and(|v| pinned_re.is_match(v) && !v.contains('*') && !v.contains('['));
            deps.push(Dependency {
                name,
                version: if is_pinned { version } else { None },
                ecosystem: "NuGet".to_string(),
                file: path.to_path_buf(),
                line: line_num,
                raw_line: line.trim().to_string(),
                version_source: VersionSource::Manifest,
            });
        }
    }
    deps
}

/// Port of `_parse_composer_json`.
pub fn parse_composer_json(path: &Path) -> Vec<Dependency> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return vec![];
    };
    let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) else {
        return vec![];
    };

    let line_map = json_section_key_lines(&content, &["require", "require-dev"]);
    let lock = path.parent().map_or(Lock::Absent, composer_lock);

    let mut deps = Vec::new();
    for section in ["require", "require-dev"] {
        let Some(serde_json::Value::Object(section_deps)) = data.get(section) else {
            continue;
        };
        for (name, version_spec) in section_deps {
            if name == "php" || name.starts_with("ext-") {
                continue;
            }
            let version_spec_str = version_spec.as_str().unwrap_or_default();
            // Tickets #206 and #209: the specification read with
            // Composer's syntax (an exact version has one to four
            // numbers, `v` or `=` allowed), and the version installed
            // according to `composer.lock` first.
            let (version, version_source) = resolve_version(
                &name.to_lowercase(),
                version_spec_str,
                crate::project::version_constraint::composer(version_spec_str),
                &lock,
            );
            deps.push(Dependency {
                name: name.clone(),
                version,
                ecosystem: "Packagist".to_string(),
                file: path.to_path_buf(),
                line: line_of(&line_map, section, name),
                raw_line: format!("\"{name}\": \"{version_spec_str}\""),
                version_source,
            });
        }
    }
    deps
}

/// Parses a manifest file according to its type — single entry point
/// combining the 6 parsers (port of the `parsers` dict from
/// `_audit_dependencies`).
pub fn parse_dependency_file(path: &Path, file_type: DepFileType) -> Vec<Dependency> {
    match file_type {
        DepFileType::Requirements => parse_requirements_txt(path),
        DepFileType::PackageJson => parse_package_json(path),
        DepFileType::PomXml => parse_pom_xml(path),
        DepFileType::BuildGradle => parse_build_gradle(path),
        DepFileType::Csproj => parse_csproj(path),
        DepFileType::ComposerJson => parse_composer_json(path),
    }
}

/// Discovers and parses every dependency manifest of the audited
/// project: the root, plus each `paths.include` entry — mirrors
/// `_find_dependency_files` + the per-file parsers, as used both by
/// `_audit_dependencies` (`--with-deps`) and `_export_sbom` (`--sbom`)
/// on the Python side. Shared by both Rust consumers so they can never
/// disagree on which manifests make up the project.
///
/// `include_paths` is `ScanConfig::include_paths` (`["."]` by default).
/// Fix from 2026-11-04: the dependencies phase used to pass `&[]` here
/// (a leftover from before `ScanConfig::include_paths` existed), so a
/// `package.json` under an included subfolder (e.g. `frontend/`) was
/// never seen, unlike Python which walks `paths.include`.
pub fn collect_dependencies(root_dir: &Path, include_paths: &[String]) -> Vec<Dependency> {
    find_dependency_files(root_dir, include_paths)
        .iter()
        .flat_map(|(path, file_type)| parse_dependency_file(path, *file_type))
        .collect()
}

#[derive(Debug, Clone)]
pub struct LicenseIssue {
    pub file: PathBuf,
    pub license: String,
}

/// Checks the compliance of licenses declared in `package.json`/
/// `composer.json` against an allowed SPDX list — port of
/// `_check_licenses`.
pub fn check_licenses(
    dep_files: &[(PathBuf, DepFileType)],
    allowed: &[String],
) -> Vec<LicenseIssue> {
    if allowed.is_empty() {
        return vec![];
    }
    let allowed_upper: Vec<String> = allowed.iter().map(|l| l.to_uppercase()).collect();
    let mut issues = Vec::new();
    for (path, file_type) in dep_files {
        if !matches!(
            file_type,
            DepFileType::PackageJson | DepFileType::ComposerJson
        ) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) else {
            continue;
        };
        let Some(license) = data
            .get("license")
            .and_then(|v| v.as_str())
            .filter(|l| !l.is_empty())
        else {
            continue;
        };
        if !allowed_upper.contains(&license.to_uppercase()) {
            issues.push(LicenseIssue {
                file: path.clone(),
                license: license.to_string(),
            });
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(name: &str, content: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-deps-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn test_parse_requirements_txt_pinned_and_unpinned() {
        let path = write_tmp(
            "requirements.txt",
            "# comment\nDjango==4.2.1\nrequests>=2.0\nflask\n",
        );
        let deps = parse_requirements_txt(&path);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "django");
        assert_eq!(deps[0].version, Some("4.2.1".to_string()));
        assert_eq!(deps[1].name, "requests");
        assert_eq!(deps[1].version, Some("2.0".to_string()));
        assert_eq!(deps[2].name, "flask");
        assert_eq!(deps[2].version, None);
    }

    #[test]
    fn test_parse_pyproject_toml_dependencies_section() {
        let path = write_tmp(
            "pyproject.toml",
            "[project]\ndependencies = [\n  \"django==4.2.1\",\n  \"requests\",\n]\n",
        );
        let deps = parse_pyproject_toml(&path);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].version, Some("4.2.1".to_string()));
        assert_eq!(deps[1].version, None);
    }

    #[test]
    fn test_parse_package_json_strips_caret_prefix() {
        let path = write_tmp(
            "package.json",
            r#"{"dependencies": {"react": "^18.2.0"}, "devDependencies": {"jest": "*"}}"#,
        );
        let deps = parse_package_json(&path);
        let react = deps.iter().find(|d| d.name == "react").unwrap();
        assert_eq!(react.version, Some("18.2.0".to_string()));
        let jest = deps.iter().find(|d| d.name == "jest").unwrap();
        assert_eq!(jest.version, None);
    }

    #[test]
    fn test_parse_pom_xml_extracts_group_and_artifact() {
        let path = write_tmp(
            "pom.xml",
            "<dependency>\n<groupId>org.springframework</groupId>\n<artifactId>spring-core</artifactId>\n<version>5.3.20</version>\n</dependency>",
        );
        let deps = parse_pom_xml(&path);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "org.springframework:spring-core");
        assert_eq!(deps[0].version, Some("5.3.20".to_string()));
    }

    #[test]
    fn test_parse_pom_xml_placeholder_version_is_unpinned() {
        let path = write_tmp(
            "pom2.xml",
            "<dependency>\n<artifactId>lib</artifactId>\n<version>${lib.version}</version>\n</dependency>",
        );
        let deps = parse_pom_xml(&path);
        assert_eq!(deps[0].version, None);
    }

    #[test]
    fn test_parse_build_gradle_quoted_form() {
        let path = write_tmp(
            "build.gradle",
            "implementation 'com.google.guava:guava:31.1-jre'\napi \"org.slf4j:slf4j-api:+\"\n",
        );
        let deps = parse_build_gradle(&path);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].version, Some("31.1-jre".to_string()));
        assert_eq!(deps[1].version, None); // "+" is not a valid pin
    }

    #[test]
    fn test_parse_csproj_package_reference() {
        let path = write_tmp(
            "test.csproj",
            r#"<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />"#,
        );
        let deps = parse_csproj(&path);
        assert_eq!(deps[0].version, Some("13.0.1".to_string()));
    }

    #[test]
    fn test_parse_composer_json_ignores_php_and_ext() {
        let path = write_tmp(
            "composer.json",
            r#"{"require": {"php": ">=8.0", "ext-json": "*", "monolog/monolog": "2.5.0"}}"#,
        );
        let deps = parse_composer_json(&path);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "monolog/monolog");
    }

    /// Tickets #206 and #209: every exact version Composer accepts is read
    /// as that version; a range gives its declared minimum, said as such;
    /// a constraint without minimum leaves the dependency unpinned.
    #[test]
    fn test_parse_composer_json_reads_every_exact_version() {
        let path = write_tmp(
            "composer-exact.json",
            r#"{"require": {
                "a/one": "1", "a/two": "1.1", "a/three": "1.1.0", "a/four": "1.1.0.2",
                "a/v": "v2.3.4", "a/eq": "=2.0", "a/beta": "3.0.0-beta1",
                "r/star": "1.1.*", "r/or": "1.0 || 2.0", "r/range": ">=1.0 <2.0",
                "r/any": "*", "r/dev": "dev-main"
            }}"#,
        );
        let deps: BTreeMap<String, Dependency> = parse_composer_json(&path)
            .into_iter()
            .map(|d| (d.name.clone(), d))
            .collect();
        let exact = [
            ("a/one", "1"),
            ("a/two", "1.1"),
            ("a/three", "1.1.0"),
            ("a/four", "1.1.0.2"),
            ("a/v", "2.3.4"),
            ("a/eq", "2.0"),
            ("a/beta", "3.0.0-beta1"),
        ];
        for (name, version) in exact {
            assert_eq!(deps[name].version.as_deref(), Some(version), "{name}");
            assert_eq!(deps[name].version_source, VersionSource::Manifest, "{name}");
        }
        let minimums = [
            ("r/star", "1.1.0", "1.1.*"),
            ("r/or", "1.0", "1.0 || 2.0"),
            ("r/range", "1.0", ">=1.0 <2.0"),
        ];
        for (name, version, spec) in minimums {
            assert_eq!(deps[name].version.as_deref(), Some(version), "{name}");
            assert_eq!(
                deps[name].version_source,
                VersionSource::DeclaredMinimum {
                    constraint: spec.to_string(),
                    lock: LockStatus::Absent
                },
                "{name}"
            );
        }
        for name in ["r/any", "r/dev"] {
            assert_eq!(deps[name].version, None, "{name}");
        }
    }

    /// Ticket #209: next to a lockfile, the version it records is checked;
    /// a package it does not list keeps its declared minimum, said so; a
    /// lockfile of another package manager is named as not read.
    #[test]
    fn test_lockfiles_give_the_installed_version() {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-deps-lock-{}",
            std::process::id()
        ));
        let write = |name: &str, content: &str| {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(name), content).unwrap();
        };
        write(
            "package.json",
            r#"{"dependencies": {"lodash": "^4.17.0", "left-pad": "^1.0.0", "local": "^2.0.0"}}"#,
        );
        write(
            "package-lock.json",
            r#"{"lockfileVersion": 3, "packages": {
                "": {"name": "demo"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/a/node_modules/left-pad": {"version": "1.3.0"},
                "node_modules/local": {"version": "file:../local"}}}"#,
        );
        let deps: BTreeMap<String, Dependency> = parse_package_json(&dir.join("package.json"))
            .into_iter()
            .map(|d| (d.name.clone(), d))
            .collect();
        assert_eq!(deps["lodash"].version.as_deref(), Some("4.17.21"));
        assert_eq!(
            deps["lodash"].version_source,
            VersionSource::Lockfile {
                file: "package-lock.json".to_string()
            }
        );
        // Only the top-level folder is the direct dependency installed.
        assert_eq!(deps["left-pad"].version.as_deref(), Some("1.0.0"));
        assert_eq!(
            deps["left-pad"].version_source,
            VersionSource::DeclaredMinimum {
                constraint: "^1.0.0".to_string(),
                lock: LockStatus::NotListed {
                    file: "package-lock.json".to_string()
                }
            }
        );
        assert_eq!(
            deps["local"].version_source,
            VersionSource::DeclaredMinimum {
                constraint: "^2.0.0".to_string(),
                lock: LockStatus::NotAVersion {
                    file: "package-lock.json".to_string(),
                    value: "file:../local".to_string()
                }
            }
        );

        // Lockfile version 1 lists the packages under `dependencies`.
        write(
            "package-lock.json",
            r#"{"lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.17.15"}}}"#,
        );
        let lodash = parse_package_json(&dir.join("package.json"))
            .into_iter()
            .find(|d| d.name == "lodash")
            .unwrap();
        assert_eq!(lodash.version.as_deref(), Some("4.17.15"));

        // An unreadable lockfile is named with its reason.
        write("package-lock.json", "{not json");
        let lodash = parse_package_json(&dir.join("package.json"))
            .into_iter()
            .find(|d| d.name == "lodash")
            .unwrap();
        assert!(matches!(
            lodash.version_source,
            VersionSource::DeclaredMinimum {
                lock: LockStatus::Unreadable { .. },
                ..
            }
        ));

        // A yarn project: not read yet, said so.
        std::fs::remove_file(dir.join("package-lock.json")).unwrap();
        write("yarn.lock", "# yarn lockfile v1\n");
        let lodash = parse_package_json(&dir.join("package.json"))
            .into_iter()
            .find(|d| d.name == "lodash")
            .unwrap();
        assert_eq!(
            lodash.version_source,
            VersionSource::DeclaredMinimum {
                constraint: "^4.17.0".to_string(),
                lock: LockStatus::NotRead {
                    file: "yarn.lock".to_string()
                }
            }
        );

        // composer.lock: names compared in lower case, `v` dropped.
        write(
            "composer.json",
            r#"{"require": {"Monolog/Monolog": "^2.0", "symfony/http-kernel": "^5.4"}}"#,
        );
        write(
            "composer.lock",
            r#"{"packages": [{"name": "monolog/monolog", "version": "2.9.1"}],
                "packages-dev": [{"name": "symfony/http-kernel", "version": "v5.4.20"}]}"#,
        );
        let versions: Vec<Option<String>> = parse_composer_json(&dir.join("composer.json"))
            .into_iter()
            .map(|d| d.version)
            .collect();
        assert_eq!(
            versions,
            vec![Some("2.9.1".to_string()), Some("5.4.20".to_string())]
        );

        // PyPI: a range without lockfile is its minimum; `<2.0` has none.
        write(
            "requirements.txt",
            "django>=4.2,<5 ; python_version > '3'\nrequests<2.0\nflask[async]==3.0.0\n",
        );
        let deps: Vec<(String, Option<String>)> =
            parse_requirements_txt(&dir.join("requirements.txt"))
                .into_iter()
                .map(|d| (d.name, d.version))
                .collect();
        assert_eq!(
            deps,
            vec![
                ("django".to_string(), Some("4.2".to_string())),
                ("requests".to_string(), None),
                ("flask".to_string(), Some("3.0.0".to_string())),
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Ticket #207: each dependency gets the line of its own key in its
    /// own section, whatever the layout of the file.
    #[test]
    fn test_manifest_lines_follow_each_key_in_its_section() {
        let path = write_tmp(
            "package-one-line.json",
            r#"{"name": "demo", "dependencies": {"left-pad": "1.0.0", "name": "2.0.0"}}"#,
        );
        let lines: Vec<(String, usize)> = parse_package_json(&path)
            .into_iter()
            .map(|d| (d.name, d.line))
            .collect();
        assert_eq!(
            lines,
            vec![("left-pad".to_string(), 1), ("name".to_string(), 1)]
        );

        let path = write_tmp(
            "composer-two-sections.json",
            "{\n  \"name\": \"a/b\",\n  \"require\": {\n    \"x/y\": \"1.0.0\"\n  },\n  \
             \"require-dev\": {\n    \"x\\/z\": \"2.0.0\",\n    \"x/y\": \"1.0.0\"\n  }\n}\n",
        );
        let lines: Vec<(String, usize)> = parse_composer_json(&path)
            .into_iter()
            .map(|d| (d.name, d.line))
            .collect();
        assert_eq!(
            lines,
            vec![
                ("x/y".to_string(), 4),
                ("x/y".to_string(), 8),
                ("x/z".to_string(), 7),
            ]
        );
    }

    #[test]
    fn test_find_dependency_files_root_requirements() {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-deps-find-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("requirements.txt"), "django==4.0\n").unwrap();
        let files = find_dependency_files(&dir, &[]);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].1, DepFileType::Requirements);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_check_licenses_flags_disallowed() {
        let path = write_tmp("pkg_with_license.json", r#"{"license": "GPL-3.0"}"#);
        let issues = check_licenses(&[(path, DepFileType::PackageJson)], &["MIT".to_string()]);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].license, "GPL-3.0");
    }

    #[test]
    fn test_check_licenses_empty_allowlist_skips_check() {
        let path = write_tmp("pkg_with_license2.json", r#"{"license": "GPL-3.0"}"#);
        let issues = check_licenses(&[(path, DepFileType::PackageJson)], &[]);
        assert!(issues.is_empty());
    }
}
