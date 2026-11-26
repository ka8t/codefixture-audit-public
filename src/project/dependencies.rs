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

use crate::project::lockfiles::{self, Lock};

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
    /// The manifest gives the version through `property` (`${…}` in a
    /// `pom.xml`, a variable in a Gradle script), which it does not
    /// define: no version to check (ticket #212); `version` is `None`.
    UnresolvedProperty { property: String },
    /// The manifest declares the range `constraint`, and `lock` says why
    /// no lockfile gave the installed version: the lowest version the
    /// range allows is checked.
    DeclaredMinimum {
        constraint: String,
        lock: LockStatus,
    },
    /// A package the lockfile `file` installs that no direct dependency
    /// is (ticket #211): `via` names the direct dependencies that bring
    /// it in, empty when `graph` is false (the lockfile does not say,
    /// `Pipfile.lock`) or when none does (a leftover of an older install).
    Transitive {
        file: String,
        via: Vec<String>,
        graph: bool,
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
    /// The lockfile `file` is binary (`bun.lockb`, ticket #210): Bun
    /// writes its text form, `bun.lock`, with
    /// `bun install --save-text-lockfile`.
    Binary { file: String },
}

/// Every lockfile name `lockfiles.rs` looks for next to a manifest, for
/// the fingerprint of an unchanged project (ADR-0050): a lockfile change
/// must trigger a new scan, since it changes the versions checked.
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

/// The version to check for the direct dependency `name` declared with
/// `spec`, read by `constraint`, and where it comes from: the version the
/// lockfile installed first, then the manifest's exact version, then the
/// declared minimum. `None` when the constraint has no minimum and no
/// lockfile gives a version: the dependency is then unpinned.
fn resolve_version(
    name: &str,
    spec: &str,
    constraint: crate::project::version_constraint::Constraint,
    lock: &Lock,
) -> (Option<String>, VersionSource) {
    use crate::project::version_constraint::Constraint;
    let status = match lock {
        Lock::Absent => LockStatus::Absent,
        Lock::Binary(file) => LockStatus::Binary { file: file.clone() },
        Lock::Unreadable(file, reason) => LockStatus::Unreadable {
            file: file.clone(),
            reason: reason.clone(),
        },
        Lock::Read(lockfile) => match lockfile.installed(name, spec) {
            Some(package) => {
                let value = &package.version;
                let version = value.strip_prefix('v').unwrap_or(value);
                if version.starts_with(|c: char| c.is_ascii_digit()) {
                    return (
                        Some(version.to_string()),
                        VersionSource::Lockfile {
                            file: lockfile.file.clone(),
                        },
                    );
                }
                LockStatus::NotAVersion {
                    file: lockfile.file.clone(),
                    value: value.clone(),
                }
            }
            None => LockStatus::NotListed {
                file: lockfile.file.clone(),
            },
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

/// The packages the lockfile `lock`, next to `manifest`, installs that
/// none of `direct` (name and spec, as the manifest declares them) is
/// (ticket #211, the maintainer's decision of 2026-11-18): one dependency each,
/// on the line of its entry in the lockfile, naming the direct
/// dependencies that bring it in. A package whose version is not a
/// version (a git address) is left to the lockfile's own direct entry.
fn transitive_dependencies(
    lock: &Lock,
    manifest: &Path,
    ecosystem: &str,
    direct: &[(String, String)],
) -> Vec<Dependency> {
    let Lock::Read(lockfile) = lock else {
        return Vec::new();
    };
    let file = manifest
        .parent()
        .map_or_else(|| PathBuf::from(&lockfile.file), |d| d.join(&lockfile.file));
    lockfile
        .transitive(direct)
        .into_iter()
        .filter_map(|(package, via)| {
            let version = package
                .version
                .strip_prefix('v')
                .unwrap_or(&package.version);
            version
                .starts_with(|c: char| c.is_ascii_digit())
                .then(|| Dependency {
                    name: package.name.clone(),
                    version: Some(version.to_string()),
                    ecosystem: ecosystem.to_string(),
                    file: file.clone(),
                    line: package.line,
                    raw_line: format!("{} {}", package.name, package.version),
                    version_source: VersionSource::Transitive {
                        file: lockfile.file.clone(),
                        via,
                        graph: lockfile.has_graph,
                    },
                })
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepFileType {
    Requirements,
    PackageJson,
    PomXml,
    BuildGradle,
    Csproj,
    ComposerJson,
    /// Pipenv's `Pipfile` (ticket #213).
    Pipfile,
}

/// The lines of `content`, numbered from 1.
fn numbered_lines(content: &str) -> Vec<(usize, String)> {
    content
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.to_string()))
        .collect()
}

/// The lines of a file that may be absent (`gradle.properties` next to a
/// build script): none when it cannot be read.
fn optional_file_lines(path: &Path) -> Vec<(usize, String)> {
    std::fs::read_to_string(path)
        .map(|content| numbered_lines(&content))
        .unwrap_or_default()
}

/// The text of the manifest `path`, or why it cannot be read (ADR-0070):
/// a manifest that was found but cannot be read is named in the scan's
/// warnings, never taken as a manifest without dependencies. Until
/// 2026-11-26 every parser read an unreadable file, or an invalid JSON
/// one, as empty.
fn read_manifest(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| e.to_string())
}

/// A manifest found under the scanned folders that could not be read
/// (ADR-0070): its dependencies are not checked, and the scan says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableManifest {
    pub file: PathBuf,
    /// Why, in English, as the system or the parser gives it.
    pub reason: String,
}

/// Every dependency of the project's manifests, and the manifests that
/// could not be read (ADR-0070).
#[derive(Debug, Clone, Default)]
pub struct ProjectDependencies {
    pub dependencies: Vec<Dependency>,
    pub unreadable: Vec<UnreadableManifest>,
}

/// Manifest names recognized wherever they sit in the scanned folders,
/// with the parser each one goes to. `*.csproj` and `requirements/*.txt`
/// are recognized by [`manifest_type`] instead, since they have no fixed
/// name.
const MANIFEST_FILES: [(&str, DepFileType); 7] = [
    ("requirements.txt", DepFileType::Requirements),
    ("pyproject.toml", DepFileType::Requirements),
    ("Pipfile", DepFileType::Pipfile),
    ("pom.xml", DepFileType::PomXml),
    ("build.gradle", DepFileType::BuildGradle),
    ("composer.json", DepFileType::ComposerJson),
    ("package.json", DepFileType::PackageJson),
];

/// The manifest type of `path`, or `None` when it is no manifest: one of
/// [`MANIFEST_FILES`], a `*.csproj`, or a `.txt` file in a folder named
/// `requirements` (the `requirements/base.txt` layout).
fn manifest_type(path: &Path) -> Option<DepFileType> {
    let name = path.file_name()?.to_str()?;
    if let Some((_, file_type)) = MANIFEST_FILES.iter().find(|(n, _)| *n == name) {
        return Some(*file_type);
    }
    let extension = path.extension().and_then(|e| e.to_str());
    if extension == Some("csproj") {
        return Some(DepFileType::Csproj);
    }
    let in_requirements_dir = path
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|dir| dir == "requirements");
    (extension == Some("txt") && in_requirements_dir).then_some(DepFileType::Requirements)
}

/// Finds the dependency manifests of the audited project: every manifest
/// under the scanned folders (`paths.include`, the root by default), with
/// the same discovery as the code files, so the same exclusions apply
/// (`paths.exclude`, the default `node_modules/`, `vendor/`…, build output,
/// virtualenvs and documentation folders).
///
/// Deliberate deviation from Python (`_find_dependency_files`, ticket
/// #287): Audit only looked at the root and at the root of each
/// `paths.include` entry, so a manifest one folder lower was ignored
/// without a word. DVWA keeps its `composer.json` in `vulnerabilities/api/`:
/// its dependencies were never checked and its SBOM was empty. A project
/// usually declares its dependencies where its code is, at any depth, and
/// the third-party copies are the folders the exclusions already leave out.
pub fn find_dependency_files(
    root_dir: &Path,
    include_paths: &[String],
    exclude_patterns: &[String],
) -> Vec<(PathBuf, DepFileType)> {
    let config = crate::scan::discovery::FileDiscoveryConfig {
        extensions: vec![".csproj".to_string(), ".txt".to_string()],
        filenames: MANIFEST_FILES.iter().map(|(n, _)| n.to_string()).collect(),
        exclude_patterns: exclude_patterns.to_vec(),
        prune_excludes: exclude_patterns.to_vec(),
        skip_non_project_dirs: true,
    };
    // The manifests at the root come first and are read even when
    // `paths.include` limits the scan to subfolders (`include: ["src/"]`
    // with `build.gradle` at the root), as Audit and the engine always did:
    // the build file of a project sits at its root. They are named one by
    // one, so the rest of the root is not walked; the walk's deduplication
    // keeps each file once. Then come the scanned folders.
    let mut starts: Vec<PathBuf> = root_manifest_starts(root_dir);
    if include_paths.is_empty() {
        starts.push(PathBuf::from("."));
    } else {
        starts.extend(include_paths.iter().map(PathBuf::from));
    }
    let starts: Vec<&Path> = starts.iter().map(PathBuf::as_path).collect();
    // Named apart from the scan's own walk in the debug log (ticket #282).
    let found: Vec<(PathBuf, DepFileType)> =
        crate::scan::discovery::traced_as("discovery_manifests", || {
            crate::scan::discovery::find_files(root_dir, &starts, &config)
        })
        .into_iter()
        .filter_map(|path| manifest_type(&path).map(|t| (normalize(&path), t)))
        .collect();
    // The walk lists a folder's files by name; within one folder the
    // manifests keep Audit's order (`requirements.txt` before
    // `pyproject.toml`…, the order of `MANIFEST_FILES`), so the SBOM and the
    // report of a project whose manifests sit at the root do not change.
    // The folders themselves keep the walk order (a stable sort).
    let folder_rank: Vec<PathBuf> = found.iter().fold(Vec::new(), |mut folders, (path, _)| {
        let folder = path.parent().map(Path::to_path_buf).unwrap_or_default();
        if !folders.contains(&folder) {
            folders.push(folder);
        }
        folders
    });
    let mut found = found;
    found.sort_by_key(|(path, file_type)| {
        let folder = path.parent().map(Path::to_path_buf).unwrap_or_default();
        let folder_index = folder_rank
            .iter()
            .position(|f| *f == folder)
            .unwrap_or(usize::MAX);
        (folder_index, manifest_rank(path, *file_type))
    });
    found
}

/// The manifests at the root of the project, as paths relative to it:
/// the named ones of [`MANIFEST_FILES`], the `*.csproj` files and the
/// `requirements/` folder (walked, for its `*.txt` files).
fn root_manifest_starts(root_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root_dir) else {
        return Vec::new();
    };
    let mut starts: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            (path.is_file() && manifest_type(path).is_some())
                || (path.is_dir() && path.file_name().is_some_and(|n| n == "requirements"))
        })
        .filter_map(|path| path.file_name().map(PathBuf::from))
        .collect();
    starts.sort();
    starts
}

/// Position of a manifest in Audit's order within one folder: the named
/// manifests in the order of [`MANIFEST_FILES`], then `*.csproj`, then the
/// `requirements/*.txt` files.
fn manifest_rank(path: &Path, file_type: DepFileType) -> usize {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if let Some(index) = MANIFEST_FILES.iter().position(|(n, _)| *n == name) {
        return index;
    }
    match file_type {
        DepFileType::Csproj => MANIFEST_FILES.len(),
        _ => MANIFEST_FILES.len() + 1,
    }
}

fn normalize(path: &Path) -> PathBuf {
    // `Path::components()` already eliminates "." segments (unlike a
    // plain string concatenation) — a sufficient equivalent
    // to `os.path.normpath` for the use `_find_dependency_files` makes
    // of it (deduplicating "root/./requirements.txt" and "root/requirements.txt").
    path.components().collect()
}

/// Port of `_parse_requirements_txt` (delegates to
/// `parse_pyproject_toml` for that specific file, like Python).
pub fn parse_requirements_txt(path: &Path) -> Result<Vec<Dependency>, String> {
    if path.file_name().is_some_and(|n| n == "pyproject.toml") {
        return parse_pyproject_toml(path);
    }
    let content = read_manifest(path)?;
    // Name, optional extras, then the version specifiers (ticket #209):
    // the whole specification is read with PEP 440, not the first number
    // after an operator, which made `<2.0` a version 2.0.
    let lock = path.parent().map_or(Lock::Absent, lockfiles::python);

    let mut deps = Vec::new();
    let mut direct: Vec<(String, String)> = Vec::new();
    for (line_num, line) in numbered_lines(&content) {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') || stripped.starts_with('-') {
            continue;
        }
        let Some((name, spec)) = split_requirement(stripped) else {
            continue;
        };
        let name = name.to_lowercase();
        direct.push((name.clone(), spec.clone()));
        let (version, version_source) = resolve_version(
            &name,
            &spec,
            crate::project::version_constraint::pep440(&spec),
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
    deps.extend(transitive_dependencies(&lock, path, "PyPI", &direct));
    Ok(deps)
}

/// Port of `_parse_pyproject_toml` (simplified extraction, not a
/// real TOML parser — same choice as Python).
///
/// Ticket #210 (2026-11-18): the port read the PEP 621 `dependencies`
/// array only, and only written over several lines. Read now, each
/// requirement on its own line: `[project]` `dependencies` (inline or
/// not) and `[project.optional-dependencies]`, PEP 735
/// `[dependency-groups]`, uv's `dev-dependencies` and PDM's
/// `[tool.pdm.dev-dependencies]` (requirement strings, PEP 508), and
/// Poetry's `[tool.poetry.dependencies]`, `dev-dependencies` and group
/// tables (`name = "^1.2"` or `{ version = … }`, read with Composer's
/// grammar, which Poetry's constraints share). Without them a Poetry or
/// uv project's lockfile showed every package as brought in by nothing.
pub fn parse_pyproject_toml(path: &Path) -> Result<Vec<Dependency>, String> {
    let content = read_manifest(path)?;
    let string_re = Regex::new(r#""((?:[^"\\]|\\.)*)"|'([^']*)'"#).unwrap();
    let key_re = Regex::new(r#"^("[^"]+"|'[^']+'|[A-Za-z0-9_.-]+)\s*=\s*(.*)$"#).unwrap();
    let version_re = Regex::new(r#"version\s*=\s*"([^"]*)""#).unwrap();
    let lock = path.parent().map_or(Lock::Absent, lockfiles::python);

    // Whether `key` of `table` is an array of PEP 508 requirements.
    let requirement_array = |table: &str, key: &str| match table {
        "project" => key == "dependencies",
        "project.optional-dependencies" | "dependency-groups" | "tool.pdm.dev-dependencies" => true,
        "tool.uv" => key == "dev-dependencies",
        _ => false,
    };
    let poetry_table = |table: &str| {
        table == "tool.poetry.dependencies"
            || table == "tool.poetry.dev-dependencies"
            || (table.starts_with("tool.poetry.group.") && table.ends_with(".dependencies"))
    };

    let mut deps = Vec::new();
    let mut direct: Vec<(String, String)> = Vec::new();
    let mut push = |name: &str, spec: &str, constraint, line: usize, raw: &str| {
        let name = name.to_lowercase();
        direct.push((name.clone(), spec.to_string()));
        let (version, version_source) = resolve_version(&name, spec, constraint, &lock);
        deps.push(Dependency {
            name,
            version,
            ecosystem: "PyPI".to_string(),
            file: path.to_path_buf(),
            line,
            raw_line: raw.to_string(),
            version_source,
        });
    };
    let mut table = String::new();
    let mut in_array = false;
    for (line_num, line) in numbered_lines(&content) {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let items = if in_array {
            Some(stripped)
        } else if stripped.starts_with('[') {
            table = stripped
                .trim_matches(|c| c == '[' || c == ']')
                .trim()
                .to_string();
            continue;
        } else if let Some(caps) = key_re.captures(stripped) {
            let key = caps[1].trim_matches(|c| c == '"' || c == '\'');
            let value = caps.get(2).map_or("", |m| m.as_str()).trim();
            if requirement_array(&table, key) && value.starts_with('[') {
                in_array = true;
                Some(value)
            } else if poetry_table(&table) && key != "python" {
                // `"^1.2"`, `{ version = "^1.2", … }`, or a list of them
                // for several Python versions (their lowest is checked).
                let versions: Vec<String> = if value.starts_with('"') || value.starts_with('\'') {
                    string_re
                        .captures(value)
                        .map(|c| {
                            c.get(1)
                                .or_else(|| c.get(2))
                                .map_or("", |m| m.as_str())
                                .to_string()
                        })
                        .into_iter()
                        .collect()
                } else {
                    version_re
                        .captures_iter(value)
                        .map(|c| c[1].to_string())
                        .collect()
                };
                let spec = versions.join(" || ");
                push(
                    key,
                    &spec,
                    crate::project::version_constraint::composer(&spec),
                    line_num,
                    stripped,
                );
                None
            } else {
                None
            }
        } else {
            None
        };
        let Some(items) = items else {
            continue;
        };
        for caps in string_re.captures_iter(items) {
            let text = caps
                .get(1)
                .or_else(|| caps.get(2))
                .map_or("", |m| m.as_str());
            if let Some((name, spec)) = split_requirement(text) {
                push(
                    &name,
                    &spec,
                    crate::project::version_constraint::pep440(&spec),
                    line_num,
                    text,
                );
            }
        }
        // The array ends at a `]` outside its strings.
        if string_re.replace_all(items, "").contains(']') {
            in_array = false;
        }
    }
    deps.extend(transitive_dependencies(&lock, path, "PyPI", &direct));
    Ok(deps)
}

/// Pipenv's `Pipfile` (ticket #213): a TOML file whose package tables
/// map a name to its specifier, `requests = "==2.31.0"`, `django = "*"`,
/// or to a table, `flask = { version = ">=2.0", extras = ["async"] }`,
/// possibly written as its own table (`[packages.flask]` then
/// `version = ">=2.0"`). Specifiers follow PEP 440; `*`, a git address or
/// a local path name no version, and the dependency is unpinned.
///
/// The package tables are `[packages]`, `[dev-packages]` and, since
/// Pipenv 2022.10, any custom category (`[docs]`): every top-level table
/// but `[[source]]`, `[requires]`, `[scripts]` and `[pipenv]`, which hold
/// settings. The version installed comes from `Pipfile.lock` first
/// (ADR-0053), never from another lockfile of the folder.
///
/// Simplified reading, like `parse_pyproject_toml`: one key per line,
/// strings in double or single quotes. No equivalent in
/// `Audit/sca/dependencies.py`, which does not read `Pipfile` either.
pub fn parse_pipfile(path: &Path) -> Result<Vec<Dependency>, String> {
    let content = read_manifest(path)?;
    let string_re = Regex::new(r#""((?:[^"\\]|\\.)*)"|'([^']*)'"#).unwrap();
    let key_re = Regex::new(r#"^("[^"]+"|'[^']+'|[A-Za-z0-9_.-]+)\s*=\s*(.*)$"#).unwrap();
    let version_re = Regex::new(r#"(?:^|[{,\s])version\s*=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap();
    let lock = path.parent().map_or(Lock::Absent, lockfiles::pipfile);
    const SETTINGS_TABLES: [&str; 4] = ["source", "requires", "scripts", "pipenv"];
    let first_string = |caps: regex::Captures| {
        caps.get(1)
            .or_else(|| caps.get(2))
            .map_or(String::new(), |m| m.as_str().to_string())
    };

    // The package being read from its own table (`[packages.flask]`):
    // name, line of its header, and the version found so far.
    struct Pending {
        name: String,
        line: usize,
        raw: String,
        spec: String,
    }
    let mut deps = Vec::new();
    let mut direct: Vec<(String, String)> = Vec::new();
    let mut push = |name: &str, spec: &str, line: usize, raw: &str| {
        let name = name.to_lowercase();
        // `*` is Pipenv's "any version": no minimum, as PEP 440 reads it.
        let spec = if spec.trim() == "*" { "" } else { spec.trim() };
        direct.push((name.clone(), spec.to_string()));
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
            line,
            raw_line: raw.to_string(),
            version_source,
        });
    };
    let mut in_packages = false;
    let mut pending: Option<Pending> = None;
    for (line_num, line) in numbered_lines(&content) {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        if stripped.starts_with('[') {
            if let Some(p) = pending.take() {
                push(&p.name, &p.spec, p.line, &p.raw);
            }
            if stripped.starts_with("[[") {
                in_packages = false; // `[[source]]`
                continue;
            }
            let header = stripped.trim_start_matches('[');
            let header = header.split(']').next().unwrap_or_default().trim();
            // `category` or `category.package`, the name possibly quoted.
            let (category, package) = match header.split_once('.') {
                Some((c, p)) => (
                    c.trim(),
                    Some(p.trim().trim_matches(|c| c == '"' || c == '\'')),
                ),
                None => (header, None),
            };
            let category = category.trim_matches(|c| c == '"' || c == '\'');
            let is_category = !SETTINGS_TABLES.contains(&category);
            in_packages = is_category && package.is_none();
            if is_category && let Some(package) = package {
                pending = Some(Pending {
                    name: package.to_string(),
                    line: line_num,
                    raw: stripped.to_string(),
                    spec: String::new(),
                });
            }
            continue;
        }
        if let Some(p) = pending.as_mut() {
            if let Some(caps) = key_re.captures(stripped)
                && caps[1].trim_matches(|c| c == '"' || c == '\'') == "version"
                && let Some(value) = string_re.captures(caps.get(2).map_or("", |m| m.as_str()))
            {
                p.spec = first_string(value);
            }
            continue;
        }
        if !in_packages {
            continue;
        }
        let Some(caps) = key_re.captures(stripped) else {
            continue;
        };
        let name = caps[1].trim_matches(|c| c == '"' || c == '\'');
        let value = caps.get(2).map_or("", |m| m.as_str()).trim();
        let spec = if value.starts_with('"') || value.starts_with('\'') {
            string_re
                .captures(value)
                .map(first_string)
                .unwrap_or_default()
        } else {
            version_re
                .captures(value)
                .map(first_string)
                .unwrap_or_default()
        };
        push(name, &spec, line_num, stripped);
    }
    if let Some(p) = pending.take() {
        push(&p.name, &p.spec, p.line, &p.raw);
    }
    deps.extend(transitive_dependencies(&lock, path, "PyPI", &direct));
    Ok(deps)
}

/// The name and version specifiers of a PEP 508 requirement
/// (`requests[socks]>=2.0 ; python_version > "3"`): extras dropped, the
/// environment marker and a comment cut. `None` for text that does not
/// start with a package name.
fn split_requirement(text: &str) -> Option<(String, String)> {
    let requirement_re =
        Regex::new(r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)\s*(?:\[[^\]]*\])?\s*(.*)$").ok()?;
    let caps = requirement_re.captures(text)?;
    let spec = caps[2].split([';', '#']).next().unwrap_or_default().trim();
    Some((caps[1].to_string(), spec.to_string()))
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
pub fn parse_package_json(path: &Path) -> Result<Vec<Dependency>, String> {
    let content = read_manifest(path)?;
    let pkg = serde_json::from_str::<serde_json::Value>(&content)
        .map_err(|e| format!("invalid JSON: {e}"))?;

    let line_map = json_section_key_lines(&content, &["dependencies", "devDependencies"]);
    let lock = path.parent().map_or(Lock::Absent, lockfiles::npm);
    const ECOSYSTEM: &str = "npm";
    let mut deps = Vec::new();
    let mut direct: Vec<(String, String)> = Vec::new();
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
            direct.push((name.clone(), version_spec_str.to_string()));
        }
    }
    deps.extend(transitive_dependencies(&lock, path, ECOSYSTEM, &direct));
    Ok(deps)
}

/// Port of `_parse_pom_xml`, read as XML (ADR-0070).
///
/// **Deliberate deviation from Python**: `Audit` read the file with
/// regular expressions over `<dependency>…</dependency>` blocks, and so
/// did this port until 2026-11-26. A dependency inside a comment was
/// read, an entity in a value was kept as written, and a `<groupId>` of
/// an `<exclusion>` could be taken for the dependency's own. The file is
/// now read by `project::xml`; a file that is not well-formed XML is an
/// error naming its line, reported by the scan, instead of whatever the
/// expressions happened to match.
///
/// What is read did not change: every `<dependency>` element of the file,
/// wherever it sits (`<dependencies>`, `<dependencyManagement>`, a
/// plugin's or a profile's), in document order, with its own
/// `<groupId>`, `<artifactId>` and `<version>`, on the line of its
/// `<artifactId>`.
///
/// Ticket #212 (2026-11-18): a version written `${log4j.version}` is
/// resolved with the `<properties>` of the same file, chained properties
/// included, and `${project.version}` / `${project.parent.version}` with
/// the project's and the parent's `<version>`. A dependency without
/// `<version>` takes the one the file's `<dependencyManagement>` gives
/// it. A property the file does not define (parent pom, BOM, command
/// line) leaves the dependency unpinned, with the property named in the
/// finding.
pub fn parse_pom_xml(path: &Path) -> Result<Vec<Dependency>, String> {
    let content = read_manifest(path)?;
    let project = crate::project::xml::parse(&content).map_err(|e| format!("invalid XML, {e}"))?;
    let pinned_re = Regex::new(r"^[0-9][0-9a-zA-Z._-]*$").unwrap();
    let properties = pom_properties(&project);
    let managed = pom_managed_versions(&project);

    let mut deps = Vec::new();
    for block in self_and_descendants(&project, "dependency") {
        let Some(artifact) = block.child("artifactId") else {
            continue;
        };
        let artifact_id = artifact.text().trim().to_string();
        let group_id = block.child_text("groupId");
        let name = match &group_id {
            Some(g) => format!("{g}:{artifact_id}"),
            None => artifact_id.clone(),
        };
        let raw_version = block.child_text("version");

        let declared = raw_version.clone().or_else(|| managed.get(&name).cloned());
        let (version, version_source) =
            match declared.map(|v| resolve_placeholders(&v, &properties)) {
                None => (None, VersionSource::Manifest),
                Some(Err(property)) => (None, VersionSource::UnresolvedProperty { property }),
                Some(Ok(v)) if pinned_re.is_match(&v) => (Some(v), VersionSource::Manifest),
                Some(Ok(_)) => (None, VersionSource::Manifest),
            };
        deps.push(Dependency {
            name,
            version,
            ecosystem: "Maven".to_string(),
            file: path.to_path_buf(),
            line: artifact.line,
            raw_line: format!(
                "{} {}",
                deps_name_placeholder(&group_id, &artifact_id),
                raw_version.as_deref().unwrap_or("(no version)")
            ),
            version_source,
        });
    }
    Ok(deps)
}

/// `element` itself when it is named `name`, then every element below it
/// so named, in document order (a test fixture's root may be a lone
/// `<dependency>`).
fn self_and_descendants<'a>(
    element: &'a crate::project::xml::Element,
    name: &'a str,
) -> Vec<&'a crate::project::xml::Element> {
    let mut found = Vec::new();
    if element.name == name {
        found.push(element);
    }
    found.extend(element.descendants_named(name));
    found
}

/// The properties a `pom.xml` defines for its own use: the entries of the
/// project's own `<properties>` (those of a `<profile>` apply only when
/// the profile is active, so they are left out), plus `project.version`,
/// `version`, `pom.version` from the project's `<version>` and
/// `project.parent.version` from its parent's.
fn pom_properties(project: &crate::project::xml::Element) -> BTreeMap<String, String> {
    let mut properties = BTreeMap::new();
    for block in project.children_named("properties") {
        // An entry holding elements is not a string property.
        for entry in block.elements().filter(|e| e.elements().next().is_none()) {
            properties.insert(entry.name.clone(), entry.text().trim().to_string());
        }
    }
    if let Some(version) = project.child_text("version") {
        for key in ["project.version", "version", "pom.version"] {
            properties.insert(key.to_string(), version.clone());
        }
    }
    if let Some(version) = project
        .child("parent")
        .and_then(|parent| parent.child_text("version"))
    {
        properties.insert("project.parent.version".to_string(), version);
    }
    properties
}

/// The versions every `<dependencyManagement>` of a `pom.xml` gives, by
/// `groupId:artifactId`, as written (placeholders not resolved yet).
fn pom_managed_versions(project: &crate::project::xml::Element) -> BTreeMap<String, String> {
    let mut managed = BTreeMap::new();
    for section in self_and_descendants(project, "dependencyManagement") {
        for block in section.descendants_named("dependency") {
            if let (Some(group), Some(artifact), Some(version)) = (
                block.child_text("groupId"),
                block.child_text("artifactId"),
                block.child_text("version"),
            ) {
                managed.insert(format!("{group}:{artifact}"), version);
            }
        }
    }
    managed
}

/// `value` with each `${name}` (and, for Gradle, `$name`) replaced by
/// its property, chains included; the first property not defined when
/// one is missing. Ten rounds at most: a property that refers to itself
/// stays unresolved and is named.
fn resolve_placeholders(
    value: &str,
    properties: &BTreeMap<String, String>,
) -> Result<String, String> {
    let placeholder = Regex::new(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)").expect("valid");
    let mut value = value.to_string();
    for _ in 0..10 {
        let Some(caps) = placeholder.captures(&value) else {
            return Ok(value);
        };
        let whole = caps.get(0).expect("group 0");
        let name = caps
            .get(1)
            .or_else(|| caps.get(2))
            .expect("a name")
            .as_str();
        let Some(replacement) = properties.get(name) else {
            return Err(name.to_string());
        };
        value = format!(
            "{}{replacement}{}",
            &value[..whole.start()],
            &value[whole.end()..]
        );
    }
    match placeholder.captures(&value) {
        Some(caps) => Err(caps
            .get(1)
            .or_else(|| caps.get(2))
            .expect("a name")
            .as_str()
            .to_string()),
        None => Ok(value),
    }
}

fn deps_name_placeholder(group_id: &Option<String>, artifact_id: &str) -> String {
    match group_id {
        Some(g) => format!("{g}:{artifact_id}"),
        None => artifact_id.to_string(),
    }
}

/// Port of `_parse_build_gradle`.
///
/// Ticket #212 (2026-11-18): a version written `$log4jVersion` or
/// `${springVersion}` is resolved with the variables of the same script
/// (`def`, `val`, `var`, `ext.x =`, a plain assignment in an `ext { }`
/// block, `extra["x"] =`, `set("x", …)`) and with the `gradle.properties`
/// next to it. The port reported these dependencies as unpinned and
/// checked none. A reference it cannot resolve (a version catalog
/// `libs.versions…`, a root project's `ext`) leaves the dependency
/// unpinned, with the reference named in the finding.
pub fn parse_build_gradle(path: &Path) -> Result<Vec<Dependency>, String> {
    let content = read_manifest(path)?;
    let quoted_re = Regex::new(
        r#"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s+['"]([^'"]+:[^'"]+):([^'"]+)['"]"#,
    )
    .unwrap();
    let paren_re = Regex::new(
        r#"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(\s*"([^"]+:[^"]+):([^"]+)""#,
    )
    .unwrap();
    let pinned_re = Regex::new(r"^[0-9][0-9a-zA-Z._-]*$").unwrap();
    let lines = numbered_lines(&content);
    let variables = gradle_variables(&lines, path.parent());

    let mut deps = Vec::new();
    for (line_num, line) in &lines {
        let stripped = line.trim();
        let caps = quoted_re
            .captures(stripped)
            .or_else(|| paren_re.captures(stripped));
        if let Some(caps) = caps {
            let name = caps[1].to_string();
            let declared = caps[2].trim().to_string();
            let (version, version_source) = match resolve_placeholders(&declared, &variables) {
                Err(property) => (None, VersionSource::UnresolvedProperty { property }),
                Ok(v) if pinned_re.is_match(&v) => (Some(v), VersionSource::Manifest),
                Ok(_) => (None, VersionSource::Manifest),
            };
            deps.push(Dependency {
                name,
                version,
                ecosystem: "Maven".to_string(),
                file: path.to_path_buf(),
                line: *line_num,
                raw_line: stripped.to_string(),
                version_source,
            });
        }
    }
    Ok(deps)
}

/// The string variables a Gradle script defines for itself, and those of
/// the `gradle.properties` in `dir`; the script's win over the file's.
fn gradle_variables(lines: &[(usize, String)], dir: Option<&Path>) -> BTreeMap<String, String> {
    let mut variables = BTreeMap::new();
    if let Some(dir) = dir {
        let property_re = Regex::new(r"^\s*([A-Za-z0-9_.\-]+)\s*[=:]\s*(.*?)\s*$").expect("valid");
        for (_, line) in optional_file_lines(&dir.join("gradle.properties")) {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') || trimmed.starts_with('!') {
                continue;
            }
            if let Some(caps) = property_re.captures(&line) {
                variables.insert(caps[1].to_string(), caps[2].to_string());
            }
        }
    }
    let assignment_re = Regex::new(
        r#"^\s*(?:def\s+|val\s+|var\s+|ext\.|project\.ext\.)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\s*)?=\s*['"]([^'"$]+)['"]"#,
    )
    .expect("valid");
    let extra_re =
        Regex::new(r#"(?:extra\[\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*\]\s*=|set\(\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*,)\s*"([^"$]+)""#)
            .expect("valid");
    for (_, line) in lines {
        if let Some(caps) = assignment_re.captures(line) {
            variables.insert(caps[1].to_string(), caps[2].to_string());
        } else if let Some(caps) = extra_re.captures(line) {
            let name = caps
                .get(1)
                .or_else(|| caps.get(2))
                .expect("a name")
                .as_str();
            variables.insert(name.to_string(), caps[3].to_string());
        }
    }
    variables
}

/// Port of `_parse_csproj`, read as XML (ADR-0070).
///
/// **Deliberate deviation from Python**: `Audit` matched
/// `<PackageReference Include="…" Version="…"` on one line, and so did
/// this port until 2026-11-26. A reference whose attributes span several
/// lines, whose `Version` comes before `Include`, or whose version is a
/// `<Version>` child element was missed or read without its version. The
/// file is now read by `project::xml`: every `<PackageReference>` element
/// with an `Include` attribute, its version from the `Version` attribute
/// or else the `<Version>` element, on the line of its start tag. A file
/// that is not well-formed XML is an error naming its line.
///
/// A reference without a version (central package management,
/// `Directory.Packages.props`) stays unpinned, as before.
pub fn parse_csproj(path: &Path) -> Result<Vec<Dependency>, String> {
    let content = read_manifest(path)?;
    let project = crate::project::xml::parse(&content).map_err(|e| format!("invalid XML, {e}"))?;
    let pinned_re = Regex::new(r"^[0-9]+\.[0-9]+[0-9a-zA-Z._-]*$").unwrap();

    let mut deps = Vec::new();
    for reference in self_and_descendants(&project, "PackageReference") {
        let Some(name) = reference.attr("Include") else {
            continue;
        };
        let version = reference
            .attr("Version")
            .map(|v| v.trim().to_string())
            .or_else(|| reference.child_text("Version"))
            .filter(|v| !v.is_empty());
        let is_pinned = version
            .as_deref()
            .is_some_and(|v| pinned_re.is_match(v) && !v.contains('*') && !v.contains('['));
        let raw_line = match &version {
            Some(v) => format!("<PackageReference Include=\"{name}\" Version=\"{v}\">"),
            None => format!("<PackageReference Include=\"{name}\">"),
        };
        deps.push(Dependency {
            name: name.to_string(),
            version: if is_pinned { version } else { None },
            ecosystem: "NuGet".to_string(),
            file: path.to_path_buf(),
            line: reference.line,
            raw_line,
            version_source: VersionSource::Manifest,
        });
    }
    Ok(deps)
}

/// Port of `_parse_composer_json`.
pub fn parse_composer_json(path: &Path) -> Result<Vec<Dependency>, String> {
    let content = read_manifest(path)?;
    let data = serde_json::from_str::<serde_json::Value>(&content)
        .map_err(|e| format!("invalid JSON: {e}"))?;

    let line_map = json_section_key_lines(&content, &["require", "require-dev"]);
    let lock = path.parent().map_or(Lock::Absent, lockfiles::composer);
    const ECOSYSTEM: &str = "Packagist";
    let mut deps = Vec::new();
    let mut direct: Vec<(String, String)> = Vec::new();
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
                name,
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
            direct.push((name.clone(), version_spec_str.to_string()));
        }
    }
    deps.extend(transitive_dependencies(&lock, path, ECOSYSTEM, &direct));
    Ok(deps)
}

/// Parses a manifest file according to its type — single entry point
/// combining the parsers (port of the `parsers` dict from
/// `_audit_dependencies`). An error says why the file cannot be read
/// (ADR-0070).
pub fn parse_dependency_file(
    path: &Path,
    file_type: DepFileType,
) -> Result<Vec<Dependency>, String> {
    match file_type {
        DepFileType::Requirements => parse_requirements_txt(path),
        DepFileType::PackageJson => parse_package_json(path),
        DepFileType::PomXml => parse_pom_xml(path),
        DepFileType::BuildGradle => parse_build_gradle(path),
        DepFileType::Csproj => parse_csproj(path),
        DepFileType::ComposerJson => parse_composer_json(path),
        DepFileType::Pipfile => parse_pipfile(path),
    }
}

/// Discovers and parses every dependency manifest of the audited
/// project: every manifest under the scanned folders, outside the excluded
/// ones ([`find_dependency_files`], ticket #287) — mirrors
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
///
/// Ticket #211: two manifests of one folder (`requirements.txt` and
/// `pyproject.toml`) share its lockfile, so each lists its transitive
/// packages. Each is kept once, and a package one manifest declares
/// directly is not also listed as another's transitive one.
///
/// ADR-0070: a manifest that cannot be read is listed in
/// `unreadable`, with the reason, for the scan to name it.
pub fn collect_dependencies(
    root_dir: &Path,
    include_paths: &[String],
    exclude_patterns: &[String],
) -> ProjectDependencies {
    let mut all: Vec<Dependency> = Vec::new();
    let mut unreadable = Vec::new();
    for (path, file_type) in find_dependency_files(root_dir, include_paths, exclude_patterns) {
        match parse_dependency_file(&path, file_type) {
            Ok(deps) => all.extend(deps),
            Err(reason) => unreadable.push(UnreadableManifest { file: path, reason }),
        }
    }
    let key = |dep: &Dependency, dir: Option<&Path>| {
        let name = match dep.ecosystem.as_str() {
            "PyPI" => lockfiles::pep503(&dep.name),
            "Packagist" => dep.name.to_lowercase(),
            _ => dep.name.clone(),
        };
        (
            dep.ecosystem.clone(),
            dir.map(Path::to_path_buf),
            name,
            dep.version.clone(),
        )
    };
    let declared: std::collections::BTreeSet<_> = all
        .iter()
        .filter(|d| !matches!(d.version_source, VersionSource::Transitive { .. }))
        .map(|d| key(d, d.file.parent()))
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    let dependencies = all
        .into_iter()
        .filter(|d| {
            if !matches!(d.version_source, VersionSource::Transitive { .. }) {
                return true;
            }
            let k = key(d, d.file.parent());
            !declared.contains(&k) && seen.insert(k)
        })
        .collect();
    ProjectDependencies {
        dependencies,
        unreadable,
    }
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
        let deps = parse_requirements_txt(&path).unwrap();
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
        let deps = parse_pyproject_toml(&path).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].version, Some("4.2.1".to_string()));
        assert_eq!(deps[1].version, None);
    }

    /// Ticket #210: every place a `pyproject.toml` declares dependencies —
    /// PEP 621 (inline or multi-line, and its optional ones), PEP 735
    /// groups, uv and PDM development ones, Poetry's tables — each on its
    /// own line; `python` and comments are not dependencies.
    #[test]
    fn test_parse_pyproject_toml_reads_every_declaration() {
        let path = write_tmp(
            "pyproject-all.toml",
            r#"[project]
name = "demo"
dependencies = ["django==4.2.1", "requests>=2.0 ; python_version > '3'"]

[project.optional-dependencies]
# a comment
webui = [
    "open-webui==0.10.2",
]

[dependency-groups]
dev = ["pytest>=8"]

[tool.uv]
dev-dependencies = ["ruff==0.4.0"]

[tool.pdm.dev-dependencies]
lint = ["black>=24"]

[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.110.0"
pydantic = { version = "2.6.1", extras = ["email"] }
local = { path = "../local" }

[tool.poetry.group.test.dependencies]
"Pytest-Cov" = "*"
"#,
        );
        let deps: Vec<(String, Option<String>, usize)> = parse_pyproject_toml(&path)
            .unwrap()
            .into_iter()
            .map(|d| (d.name, d.version, d.line))
            .collect();
        let s = |n: &str, v: Option<&str>, l: usize| (n.to_string(), v.map(str::to_string), l);
        assert_eq!(
            deps,
            vec![
                s("django", Some("4.2.1"), 3),
                s("requests", Some("2.0"), 3),
                s("open-webui", Some("0.10.2"), 8),
                s("pytest", Some("8"), 12),
                s("ruff", Some("0.4.0"), 15),
                s("black", Some("24"), 18),
                s("fastapi", Some("0.110.0"), 22),
                s("pydantic", Some("2.6.1"), 23),
                s("local", None, 24),
                s("pytest-cov", None, 27),
            ]
        );
    }

    #[test]
    fn test_parse_package_json_strips_caret_prefix() {
        let path = write_tmp(
            "package.json",
            r#"{"dependencies": {"react": "^18.2.0"}, "devDependencies": {"jest": "*"}}"#,
        );
        let deps = parse_package_json(&path).unwrap();
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
        let deps = parse_pom_xml(&path).unwrap();
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
        let deps = parse_pom_xml(&path).unwrap();
        assert_eq!(deps[0].version, None);
    }

    #[test]
    fn test_parse_build_gradle_quoted_form() {
        let path = write_tmp(
            "build.gradle",
            "implementation 'com.google.guava:guava:31.1-jre'\napi \"org.slf4j:slf4j-api:+\"\n",
        );
        let deps = parse_build_gradle(&path).unwrap();
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
        let deps = parse_csproj(&path).unwrap();
        assert_eq!(deps[0].version, Some("13.0.1".to_string()));
    }

    /// ADR-0070: a `.csproj` read as XML. Attributes on several lines,
    /// `Version` before `Include` and a `<Version>` element all give the
    /// version; a commented reference and an `Update` are not
    /// dependencies; each one is on the line of its start tag. The
    /// one-line expression missed or misread the first three.
    #[test]
    fn test_parse_csproj_reads_every_way_xml_writes_a_reference() {
        let path = write_tmp(
            "forms.csproj",
            r#"<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference
        Include="Serilog"
        Version="3.1.1" />
    <PackageReference Version="6.0.0" Include="Dapper" />
    <PackageReference Include="Polly">
      <Version>8.2.0</Version>
    </PackageReference>
    <!-- <PackageReference Include="Old" Version="1.0.0" /> -->
    <PackageReference Update="Serilog" Version="9.9.9" />
    <PackageReference Include="Floating" Version="1.*" />
  </ItemGroup>
</Project>"#,
        );
        let deps = parse_csproj(&path).unwrap();
        let found: Vec<(&str, Option<&str>, usize)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_deref(), d.line))
            .collect();
        assert_eq!(
            found,
            vec![
                ("Serilog", Some("3.1.1"), 3),
                ("Dapper", Some("6.0.0"), 6),
                ("Polly", Some("8.2.0"), 7),
                ("Floating", None, 12),
            ]
        );
        assert_eq!(
            deps[1].raw_line,
            r#"<PackageReference Include="Dapper" Version="6.0.0">"#
        );
    }

    /// ADR-0070: a `pom.xml` read as XML. A dependency in a comment is not
    /// one, the `<groupId>` of an `<exclusion>` is not the dependency's,
    /// and an entity in a value is resolved; the expressions read all
    /// three as written.
    #[test]
    fn test_parse_pom_xml_reads_xml_not_text() {
        let path = write_tmp(
            "pom-xml.xml",
            r#"<project>
  <dependencies>
    <!-- <dependency><groupId>old</groupId><artifactId>gone</artifactId><version>1.0</version></dependency> -->
    <dependency>
      <artifactId>core</artifactId>
      <exclusions><exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion></exclusions>
      <groupId>org.a&amp;b</groupId>
      <version>2.0.1</version>
    </dependency>
  </dependencies>
</project>"#,
        );
        let deps = parse_pom_xml(&path).unwrap();
        let found: Vec<(&str, Option<&str>, usize)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_deref(), d.line))
            .collect();
        assert_eq!(found, vec![("org.a&b:core", Some("2.0.1"), 5)]);
    }

    /// ADR-0070: a manifest that cannot be read is an error naming why
    /// (its line for XML), never a manifest without dependencies.
    #[test]
    fn test_unreadable_manifests_are_errors() {
        let pom = write_tmp("pom-broken.xml", "<project>\n<dependencies>\n</project>");
        let err = parse_pom_xml(&pom).unwrap_err();
        assert!(err.starts_with("invalid XML, line 3"), "{err}");
        let csproj = write_tmp("broken.csproj", "<Project><ItemGroup></Project>");
        assert!(
            parse_csproj(&csproj)
                .unwrap_err()
                .starts_with("invalid XML")
        );
        let package = write_tmp("package-broken.json", "{\"dependencies\": {");
        assert!(
            parse_package_json(&package)
                .unwrap_err()
                .starts_with("invalid JSON")
        );
        let composer = write_tmp("composer-broken.json", "{");
        assert!(
            parse_composer_json(&composer)
                .unwrap_err()
                .starts_with("invalid JSON")
        );
        let missing = std::env::temp_dir().join("codefixture-audit-no-such-requirements.txt");
        assert!(parse_requirements_txt(&missing).is_err());
    }

    #[test]
    fn test_parse_composer_json_ignores_php_and_ext() {
        let path = write_tmp(
            "composer.json",
            r#"{"require": {"php": ">=8.0", "ext-json": "*", "monolog/monolog": "2.5.0"}}"#,
        );
        let deps = parse_composer_json(&path).unwrap();
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
            .unwrap()
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
        let parsed = parse_package_json(&dir.join("package.json")).unwrap();
        let deps: BTreeMap<String, Dependency> = parsed
            .iter()
            .filter(|d| !matches!(d.version_source, VersionSource::Transitive { .. }))
            .map(|d| (d.name.clone(), d.clone()))
            .collect();
        // Ticket #211: the nested left-pad 1.3.0 is a transitive package,
        // brought in by `a`, which the lockfile installs but the manifest
        // does not declare.
        let transitive: Vec<(&str, Option<&str>, &VersionSource)> = parsed
            .iter()
            .filter(|d| matches!(d.version_source, VersionSource::Transitive { .. }))
            .map(|d| (d.name.as_str(), d.version.as_deref(), &d.version_source))
            .collect();
        assert_eq!(
            transitive,
            vec![(
                "left-pad",
                Some("1.3.0"),
                &VersionSource::Transitive {
                    file: "package-lock.json".to_string(),
                    via: vec![],
                    graph: true
                }
            )]
        );
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
            .unwrap()
            .into_iter()
            .find(|d| d.name == "lodash")
            .unwrap();
        assert_eq!(lodash.version.as_deref(), Some("4.17.15"));

        // An unreadable lockfile is named with its reason.
        write("package-lock.json", "{not json");
        let lodash = parse_package_json(&dir.join("package.json"))
            .unwrap()
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

        // A yarn project is read too (ticket #210): lodash is not in this
        // empty yarn.lock, said so.
        std::fs::remove_file(dir.join("package-lock.json")).unwrap();
        write("yarn.lock", "# yarn lockfile v1\n");
        let lodash = parse_package_json(&dir.join("package.json"))
            .unwrap()
            .into_iter()
            .find(|d| d.name == "lodash")
            .unwrap();
        assert_eq!(
            lodash.version_source,
            VersionSource::DeclaredMinimum {
                constraint: "^4.17.0".to_string(),
                lock: LockStatus::NotListed {
                    file: "yarn.lock".to_string()
                }
            }
        );
        // `bun.lockb` is binary: named, with the minimum checked.
        std::fs::remove_file(dir.join("yarn.lock")).unwrap();
        write("bun.lockb", "\u{0}binary");
        let lodash = parse_package_json(&dir.join("package.json"))
            .unwrap()
            .into_iter()
            .find(|d| d.name == "lodash")
            .unwrap();
        assert!(matches!(
            lodash.version_source,
            VersionSource::DeclaredMinimum {
                lock: LockStatus::Binary { .. },
                ..
            }
        ));
        std::fs::remove_file(dir.join("bun.lockb")).unwrap();

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
            .unwrap()
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
                .unwrap()
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
            .unwrap()
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
            .unwrap()
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

    /// Ticket #212: a Maven version given by a property of the same
    /// `pom.xml` is resolved, chained properties and `${project.version}`
    /// included, and a dependency without version takes the one its
    /// `dependencyManagement` gives; a property defined elsewhere leaves
    /// the dependency unpinned, with the property named.
    #[test]
    fn test_parse_pom_xml_resolves_properties() {
        let path = write_tmp(
            "pom-properties.xml",
            r#"<project>
  <groupId>d</groupId><artifactId>app</artifactId><version>3.1.0</version>
  <parent><groupId>p</groupId><artifactId>parent</artifactId><version>9.9</version></parent>
  <properties>
    <log4j.version>2.14.1</log4j.version>
    <jackson-version>${jackson.base}</jackson-version>
    <jackson.base>2.9.8</jackson.base>
  </properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>m</groupId><artifactId>managed</artifactId><version>1.4.0</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>
    <dependency><groupId>j</groupId><artifactId>jackson</artifactId><version>${jackson-version}</version></dependency>
    <dependency><groupId>d</groupId><artifactId>sibling</artifactId><version>${project.version}</version></dependency>
    <dependency><groupId>m</groupId><artifactId>managed</artifactId></dependency>
    <dependency><groupId>s</groupId><artifactId>spring</artifactId><version>${spring.version}</version></dependency>
  </dependencies>
</project>"#,
        );
        let deps = parse_pom_xml(&path).unwrap();
        let found: Vec<(&str, Option<&str>)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_deref()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("m:managed", Some("1.4.0")),
                ("org.apache.logging.log4j:log4j-core", Some("2.14.1")),
                ("j:jackson", Some("2.9.8")),
                ("d:sibling", Some("3.1.0")),
                ("m:managed", Some("1.4.0")),
                ("s:spring", None),
            ]
        );
        assert_eq!(
            deps[5].version_source,
            VersionSource::UnresolvedProperty {
                property: "spring.version".to_string()
            }
        );
    }

    /// Ticket #212: a Gradle version given by a variable of the same
    /// script or of the `gradle.properties` next to it is resolved; one
    /// defined elsewhere leaves the dependency unpinned, named.
    #[test]
    fn test_parse_build_gradle_resolves_variables() {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-deps-gradle-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("gradle.properties"),
            "jacksonVersion=2.9.8\n# comment\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("build.gradle"),
            "def log4jVersion = '2.14.1'\next {\n    springVersion = \"5.3.1\"\n}\n\
             dependencies {\n\
             implementation \"org.apache.logging.log4j:log4j-core:$log4jVersion\"\n\
             implementation \"org.springframework:spring-core:${springVersion}\"\n\
             implementation \"com.fasterxml.jackson.core:jackson-databind:${jacksonVersion}\"\n\
             implementation \"x:y:${libs.versions.y.get()}\"\n}\n",
        )
        .unwrap();
        let deps = parse_build_gradle(&dir.join("build.gradle")).unwrap();
        let found: Vec<(&str, Option<&str>)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_deref()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("org.apache.logging.log4j:log4j-core", Some("2.14.1")),
                ("org.springframework:spring-core", Some("5.3.1")),
                ("com.fasterxml.jackson.core:jackson-databind", Some("2.9.8")),
                ("x:y", None),
            ]
        );
        assert_eq!(
            deps[3].version_source,
            VersionSource::UnresolvedProperty {
                property: "libs.versions.y.get()".to_string()
            }
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Ticket #213: a `Pipfile` is found as a manifest, each package
    /// table read (custom categories, quoted names, inline and separate
    /// tables), settings tables skipped, versions taken from
    /// `Pipfile.lock` first even when a `poetry.lock` sits beside it.
    #[test]
    fn test_pipfile_is_read_with_its_own_lockfile() {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-deps-pipfile-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("Pipfile"),
            concat!(
                "[[source]]\n",
                "url = \"https://pypi.org/simple\"\n",
                "verify_ssl = true\n",
                "name = \"pypi\"\n",
                "\n",
                "[packages]\n",
                "requests = \"*\"\n",
                "Django = \">=3.2\"\n",
                "\"zope.interface\" = \"==5.4.0\"\n",
                "flask = { version = \"~=2.0\", extras = [\"async\"] }\n",
                "mylib = { git = \"https://example.com/mylib.git\", ref = \"v1\" }\n",
                "\n",
                "[dev-packages]\n",
                "pytest = '==7.4.0'\n",
                "\n",
                "[docs]\n",
                "sphinx = \"*\"\n",
                "\n",
                "[packages.jinja2]\n",
                "version = \">=3.0\"\n",
                "\n",
                "[requires]\n",
                "python_version = \"3.11\"\n",
                "\n",
                "[scripts]\n",
                "serve = \"python app.py\"\n",
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join("Pipfile.lock"),
            concat!(
                "{\n",
                "  \"_meta\": {\"hash\": {\"sha256\": \"x\"}},\n",
                "  \"default\": {\n",
                "    \"requests\": {\"version\": \"==2.31.0\"},\n",
                "    \"urllib3\": {\"version\": \"==2.0.7\"}\n",
                "  },\n",
                "  \"develop\": {},\n",
                "  \"docs\": {\n",
                "    \"sphinx\": {\"version\": \"==7.2.6\"}\n",
                "  }\n",
                "}\n",
            ),
        )
        .unwrap();
        // Belongs to a `pyproject.toml`, not to the `Pipfile`.
        std::fs::write(
            dir.join("poetry.lock"),
            "[[package]]\nname = \"requests\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();

        let files = find_dependency_files(&dir, &[], &[]);
        assert_eq!(files, vec![(dir.join("Pipfile"), DepFileType::Pipfile)]);

        let deps = collect_dependencies(&dir, &[], &[]).dependencies;
        let listed: Vec<(&str, Option<&str>, usize, &VersionSource)> = deps
            .iter()
            .map(|d| {
                (
                    d.name.as_str(),
                    d.version.as_deref(),
                    d.line,
                    &d.version_source,
                )
            })
            .collect();
        let locked = VersionSource::Lockfile {
            file: "Pipfile.lock".to_string(),
        };
        let minimum = |constraint: &str| VersionSource::DeclaredMinimum {
            constraint: constraint.to_string(),
            lock: LockStatus::NotListed {
                file: "Pipfile.lock".to_string(),
            },
        };
        assert_eq!(
            listed,
            vec![
                ("requests", Some("2.31.0"), 7, &locked),
                ("django", Some("3.2"), 8, &minimum(">=3.2")),
                ("zope.interface", Some("5.4.0"), 9, &VersionSource::Manifest),
                ("flask", Some("2.0"), 10, &minimum("~=2.0")),
                ("mylib", None, 11, &VersionSource::Manifest),
                ("pytest", Some("7.4.0"), 14, &VersionSource::Manifest),
                ("sphinx", Some("7.2.6"), 17, &locked),
                ("jinja2", Some("3.0"), 19, &minimum(">=3.0")),
                (
                    "urllib3",
                    Some("2.0.7"),
                    5,
                    &VersionSource::Transitive {
                        file: "Pipfile.lock".to_string(),
                        via: Vec::new(),
                        graph: false,
                    }
                ),
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Ticket #211: `requirements.txt` and `pyproject.toml` of one folder
    /// share its `poetry.lock`; each transitive package is listed once,
    /// and one manifest's direct dependency is not another's transitive.
    #[test]
    fn test_collect_dependencies_lists_each_transitive_package_once() {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-deps-collect-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("requirements.txt"), "requests>=2\n").unwrap();
        std::fs::write(
            dir.join("pyproject.toml"),
            "[project]\ndependencies = [\n  \"urllib3>=2\",\n]\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("poetry.lock"),
            "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[package.dependencies]\nurllib3 = \">=1\"\nidna = \">=2\"\n\n[[package]]\nname = \"urllib3\"\nversion = \"2.0.7\"\n\n[[package]]\nname = \"idna\"\nversion = \"3.6\"\n",
        )
        .unwrap();
        let deps = collect_dependencies(&dir, &[], &[]).dependencies;
        let listed: Vec<(String, Option<String>, bool)> = deps
            .iter()
            .map(|d| {
                (
                    d.name.clone(),
                    d.version.clone(),
                    matches!(d.version_source, VersionSource::Transitive { .. }),
                )
            })
            .collect();
        assert_eq!(
            listed,
            vec![
                ("requests".to_string(), Some("2.31.0".to_string()), false),
                ("idna".to_string(), Some("3.6".to_string()), true),
                ("urllib3".to_string(), Some("2.0.7".to_string()), false),
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// ADR-0070: a manifest that cannot be read is listed with its reason,
    /// and the other manifests are still read.
    #[test]
    fn test_collect_dependencies_names_the_unreadable_manifests() {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-deps-unreadable-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("requirements.txt"), "requests==2.31.0\n").unwrap();
        std::fs::write(dir.join("pom.xml"), "<project><dependencies></project>").unwrap();
        let collected = collect_dependencies(&dir, &[], &[]);
        assert_eq!(collected.dependencies.len(), 1);
        assert_eq!(collected.unreadable.len(), 1);
        assert_eq!(collected.unreadable[0].file, dir.join("pom.xml"));
        assert!(
            collected.unreadable[0].reason.starts_with("invalid XML"),
            "{:?}",
            collected.unreadable[0]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Ticket #287: with `paths.include` limited to `src/`, the manifest at
    /// the root is still read (spring-boot-realworld keeps `build.gradle` at
    /// its root and scans `src/` only), and only once.
    #[test]
    fn test_find_dependency_files_reads_the_root_outside_include_paths() {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-deps-root-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src/web")).unwrap();
        std::fs::write(dir.join("build.gradle"), "dependencies {}\n").unwrap();
        std::fs::write(dir.join("src/web/package.json"), "{}").unwrap();
        let names: Vec<String> = find_dependency_files(&dir, &["src/".to_string()], &[])
            .into_iter()
            .map(|(path, _)| {
                path.strip_prefix(&dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "build.gradle".to_string(),
                "src/web/package.json".to_string()
            ]
        );
        let names_root: Vec<String> = find_dependency_files(&dir, &[".".to_string()], &[])
            .into_iter()
            .map(|(path, _)| {
                path.strip_prefix(&dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(
            names_root,
            vec![
                "build.gradle".to_string(),
                "src/web/package.json".to_string()
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Ticket #287: a manifest one folder below the root is read (DVWA keeps
    /// its `composer.json` in `vulnerabilities/api/`), a manifest inside an
    /// excluded folder is not, a `.txt` that is no manifest is not, and the
    /// `requirements/*.txt` layout is recognized at any depth.
    #[test]
    fn test_find_dependency_files_reads_manifests_below_the_root() {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-deps-nested-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in [
            "api",
            "node_modules/left-pad",
            "backend/requirements",
            "docs-src",
        ] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        std::fs::write(
            dir.join("api/composer.json"),
            r#"{"require":{"a/b":"1.0"}}"#,
        )
        .unwrap();
        std::fs::write(dir.join("node_modules/left-pad/package.json"), "{}").unwrap();
        std::fs::write(dir.join("backend/requirements/base.txt"), "django==4.0\n").unwrap();
        std::fs::write(dir.join("docs-src/notes.txt"), "not a manifest\n").unwrap();
        let excludes = vec!["node_modules".to_string()];
        let found: Vec<(String, DepFileType)> =
            find_dependency_files(&dir, &[".".to_string()], &excludes)
                .into_iter()
                .map(|(path, t)| {
                    let rel = path
                        .strip_prefix(&dir)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    (rel, t)
                })
                .collect();
        assert_eq!(
            found,
            vec![
                ("api/composer.json".to_string(), DepFileType::ComposerJson),
                (
                    "backend/requirements/base.txt".to_string(),
                    DepFileType::Requirements
                ),
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_find_dependency_files_root_requirements() {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-deps-find-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("requirements.txt"), "django==4.0\n").unwrap();
        let files = find_dependency_files(&dir, &[], &[]);
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
