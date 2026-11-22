//! The lockfiles next to the dependency manifests (ADR-0053, tickets #209,
//! #210 and #211): which version of each package is installed, and which
//! package brings in which.
//!
//! Every format is read into the same [`LockFile`]: the installed
//! packages, each with its version, the line of its entry and the
//! packages it depends on. `dependencies.rs` takes from it the installed
//! version of a direct dependency (#209, #210), and the packages no direct
//! dependency is, with the direct dependencies that bring them in (#211).
//!
//! Formats read, as their package managers write them:
//! - npm: `npm-shrinkwrap.json`, then `package-lock.json`, versions 1 to 3.
//!   A dependency is resolved the way Node resolves it: in the package's
//!   own `node_modules`, then in each parent's, then at the top.
//! - Yarn: `yarn.lock`, version 1 and Berry (2 and later). An entry is
//!   found by its descriptors (`lodash@^4.17.0`).
//! - pnpm: `pnpm-lock.yaml`, versions 5, 6 and 9, read with `project::yaml`.
//! - Bun: `bun.lock` (JSON with trailing commas). `bun.lockb`, the binary
//!   format Bun wrote before 1.2, is not read: it is named, with the
//!   command that writes `bun.lock`.
//! - Composer: `composer.lock`.
//! - Python: `poetry.lock`, `uv.lock`, `pdm.lock` (their `[[package]]`
//!   tables) and `Pipfile.lock`, which gives no dependency graph.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use regex::Regex;
use serde_json::Value;

/// One package a lockfile records as installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedPackage {
    /// Its name as the ecosystem writes it.
    pub name: String,
    /// Its installed version, as written (a `v` prefix kept).
    pub version: String,
    /// 1-based line of its entry in the lockfile.
    pub line: usize,
    /// The packages of the lockfile it depends on, by index.
    pub dependencies: Vec<usize>,
}

/// A lockfile read.
#[derive(Debug, Clone, Default)]
pub struct LockFile {
    /// Its file name (`package-lock.json`).
    pub file: String,
    /// Every installed package, in the lockfile's order.
    pub packages: Vec<LockedPackage>,
    /// Whether the format says which package depends on which:
    /// `Pipfile.lock` does not.
    pub has_graph: bool,
    /// Yarn's descriptors (`lodash@^4.17.0`) to their entry.
    descriptors: BTreeMap<String, usize>,
    /// The packages a direct dependency resolves to, by name key.
    direct_by_name: BTreeMap<String, usize>,
    /// How package names compare in this ecosystem.
    key: NameKey,
}

/// How an ecosystem compares package names.
#[derive(Debug, Clone, Copy, Default)]
enum NameKey {
    /// npm: exact.
    #[default]
    Exact,
    /// Composer: case-insensitive.
    Lower,
    /// PyPI: PEP 503 (case-insensitive, `-`, `_` and `.` equivalent).
    Pep503,
}

impl NameKey {
    fn of(self, name: &str) -> String {
        match self {
            NameKey::Exact => name.to_string(),
            NameKey::Lower => name.to_lowercase(),
            NameKey::Pep503 => pep503(name),
        }
    }
}

/// A package name normalized as PEP 503 says.
pub fn pep503(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut separator = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            separator = true;
        } else {
            if separator && !out.is_empty() {
                out.push('-');
            }
            separator = false;
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// The lockfile next to a manifest.
#[derive(Debug, Clone)]
pub enum Lock {
    /// None of the ecosystem's lockfiles is there.
    Absent,
    /// A binary lockfile (`bun.lockb`), which is not read.
    Binary(String),
    /// A lockfile that cannot be read, with the reason.
    Unreadable(String, String),
    /// A lockfile read.
    Read(LockFile),
}

impl LockFile {
    /// The package installed for the direct dependency `name` declared
    /// with `spec`: Yarn finds it by its descriptor, the others by name.
    pub fn installed(&self, name: &str, spec: &str) -> Option<&LockedPackage> {
        let key = self.key.of(name);
        [format!("{key}@{spec}"), format!("{key}@npm:{spec}")]
            .iter()
            .find_map(|d| self.descriptors.get(d))
            .or_else(|| self.direct_by_name.get(&key))
            .map(|&i| &self.packages[i])
    }

    /// The packages that no direct dependency of `direct` (name and spec)
    /// is, each with the names of the direct dependencies whose
    /// dependencies reach it, sorted; empty when the format gives no
    /// graph. A package no direct dependency reaches (a leftover of an
    /// older install) is listed with no name.
    pub fn transitive(&self, direct: &[(String, String)]) -> Vec<(&LockedPackage, Vec<String>)> {
        let roots: Vec<(usize, &str)> = direct
            .iter()
            .filter_map(|(name, spec)| {
                let package = self.installed(name, spec)?;
                let index = self
                    .packages
                    .iter()
                    .position(|p| std::ptr::eq(p, package))?;
                Some((index, name.as_str()))
            })
            .collect();
        let root_set: BTreeSet<usize> = roots.iter().map(|(i, _)| *i).collect();
        let mut via: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
        for (root, name) in &roots {
            let mut seen = BTreeSet::from([*root]);
            let mut queue = VecDeque::from([*root]);
            while let Some(current) = queue.pop_front() {
                for &next in &self.packages[current].dependencies {
                    if seen.insert(next) {
                        queue.push_back(next);
                        if !root_set.contains(&next) {
                            via.entry(next).or_default().insert(name.to_string());
                        }
                    }
                }
            }
        }
        // Direct dependencies are matched by name too: a package of the
        // same name as a direct one, in another version, is transitive.
        self.packages
            .iter()
            .enumerate()
            .filter(|(i, _)| !root_set.contains(i))
            .map(|(i, package)| {
                let names = via
                    .remove(&i)
                    .map(|s| s.into_iter().collect())
                    .unwrap_or_default();
                (package, names)
            })
            .collect()
    }
}

/// The npm lockfile in `dir`: `npm-shrinkwrap.json`, then
/// `package-lock.json`, then those of Yarn, pnpm and Bun.
pub fn npm(dir: &Path) -> Lock {
    for name in ["npm-shrinkwrap.json", "package-lock.json"] {
        if dir.join(name).is_file() {
            return read(dir, name, read_package_lock);
        }
    }
    if dir.join("yarn.lock").is_file() {
        return read(dir, "yarn.lock", read_yarn_lock);
    }
    if dir.join("pnpm-lock.yaml").is_file() {
        return read(dir, "pnpm-lock.yaml", read_pnpm_lock);
    }
    if dir.join("bun.lock").is_file() {
        return read(dir, "bun.lock", read_bun_lock);
    }
    if dir.join("bun.lockb").is_file() {
        return Lock::Binary("bun.lockb".to_string());
    }
    Lock::Absent
}

/// The lockfile of a `Pipfile` in `dir` (ticket #213): `Pipfile.lock`,
/// which Pipenv writes for it, whatever other Python lockfile sits in the
/// same folder. `python` would take a `poetry.lock` first: that file
/// belongs to the `pyproject.toml`, not to the `Pipfile`.
pub fn pipfile(dir: &Path) -> Lock {
    if dir.join("Pipfile.lock").is_file() {
        return read(dir, "Pipfile.lock", read_pipfile_lock);
    }
    Lock::Absent
}

/// `composer.lock` in `dir`.
pub fn composer(dir: &Path) -> Lock {
    if dir.join("composer.lock").is_file() {
        return read(dir, "composer.lock", read_composer_lock);
    }
    Lock::Absent
}

/// The Python lockfile in `dir`: `poetry.lock`, `uv.lock`, `pdm.lock`,
/// `Pipfile.lock`.
pub fn python(dir: &Path) -> Lock {
    for name in ["poetry.lock", "uv.lock", "pdm.lock"] {
        if dir.join(name).is_file() {
            return read(dir, name, read_toml_packages);
        }
    }
    if dir.join("Pipfile.lock").is_file() {
        return read(dir, "Pipfile.lock", read_pipfile_lock);
    }
    Lock::Absent
}

/// Reads `dir/name` with `parse`, which gets its text.
fn read(dir: &Path, name: &str, parse: fn(&str) -> Result<LockFile, String>) -> Lock {
    let text = match std::fs::read_to_string(dir.join(name)) {
        Ok(text) => text,
        Err(e) => return Lock::Unreadable(name.to_string(), e.to_string()),
    };
    match parse(&text) {
        Ok(mut lock) => {
            lock.file = name.to_string();
            Lock::Read(lock)
        }
        Err(e) => Lock::Unreadable(name.to_string(), e),
    }
}

/// `package-lock.json` / `npm-shrinkwrap.json`.
fn read_package_lock(text: &str) -> Result<LockFile, String> {
    let json: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let lines = json_key_lines(text);
    let mut lock = LockFile {
        has_graph: true,
        ..LockFile::default()
    };
    if let Some(Value::Object(packages)) = json.get("packages") {
        // Versions 2 and 3: one entry per installed folder.
        let mut by_path: BTreeMap<&str, usize> = BTreeMap::new();
        for (path, entry) in packages {
            let Some(at) = path.rfind("node_modules/") else {
                continue; // the root or a workspace folder, not installed
            };
            let Some(version) = entry.get("version").and_then(Value::as_str) else {
                continue; // a link to a workspace folder
            };
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(&path[at + "node_modules/".len()..]);
            by_path.insert(path, lock.packages.len());
            lock.packages.push(LockedPackage {
                name: name.to_string(),
                version: version.to_string(),
                line: lines
                    .get(&vec!["packages".to_string(), path.clone()])
                    .copied()
                    .unwrap_or(0),
                dependencies: Vec::new(),
            });
        }
        for (path, entry) in packages {
            let Some(&index) = by_path.get(path.as_str()) else {
                continue;
            };
            let dependencies: Vec<usize> = dependency_names(entry)
                .filter_map(|name| node_resolve(path, name, |p| by_path.get(p).copied()))
                .collect();
            lock.packages[index].dependencies = dependencies;
        }
        for (path, &index) in &by_path {
            if let Some(name) = path.strip_prefix("node_modules/")
                && !name.contains("/node_modules/")
            {
                lock.direct_by_name.insert(name.to_string(), index);
            }
        }
    } else if let Some(Value::Object(dependencies)) = json.get("dependencies") {
        // Version 1: a tree of `dependencies`, each with its `requires`.
        let mut by_path: BTreeMap<Vec<String>, usize> = BTreeMap::new();
        let mut entries: Vec<(Vec<String>, &Value)> = Vec::new();
        let mut stack: Vec<(Vec<String>, &serde_json::Map<String, Value>)> =
            vec![(Vec::new(), dependencies)];
        while let Some((parent, map)) = stack.pop() {
            for (name, entry) in map {
                let mut path = parent.clone();
                path.push(name.clone());
                if let Some(version) = entry.get("version").and_then(Value::as_str) {
                    let mut key = vec!["dependencies".to_string()];
                    for segment in &path[..path.len() - 1] {
                        key.push(segment.clone());
                        key.push("dependencies".to_string());
                    }
                    key.push(name.clone());
                    by_path.insert(path.clone(), lock.packages.len());
                    lock.packages.push(LockedPackage {
                        name: name.clone(),
                        version: version.to_string(),
                        line: lines.get(&key).copied().unwrap_or(0),
                        dependencies: Vec::new(),
                    });
                    entries.push((path.clone(), entry));
                }
                if let Some(Value::Object(nested)) = entry.get("dependencies") {
                    stack.push((path, nested));
                }
            }
        }
        for (path, entry) in &entries {
            let Some(Value::Object(requires)) = entry.get("requires") else {
                continue;
            };
            let index = by_path[path];
            let dependencies: Vec<usize> = requires
                .keys()
                .filter_map(|name| {
                    // Its own nested packages first, then each ancestor's.
                    (0..=path.len()).rev().find_map(|depth| {
                        let mut candidate = path[..depth].to_vec();
                        candidate.push(name.clone());
                        by_path.get(&candidate).copied()
                    })
                })
                .collect();
            lock.packages[index].dependencies = dependencies;
        }
        for (path, &index) in &by_path {
            if let [name] = path.as_slice() {
                lock.direct_by_name.insert(name.clone(), index);
            }
        }
    } else {
        return Err("neither `packages` nor `dependencies`".to_string());
    }
    Ok(lock)
}

/// The names an npm-style entry depends on: `dependencies`,
/// `optionalDependencies` and `peerDependencies`.
fn dependency_names(entry: &Value) -> impl Iterator<Item = &str> {
    ["dependencies", "optionalDependencies", "peerDependencies"]
        .into_iter()
        .filter_map(|field| entry.get(field).and_then(Value::as_object))
        .flat_map(|map| map.keys().map(String::as_str))
}

/// Where Node finds `name` from the package installed at `path`
/// (`node_modules/a/node_modules/b`): in its own `node_modules`, then in
/// each parent's, then at the top.
fn node_resolve(path: &str, name: &str, find: impl Fn(&str) -> Option<usize>) -> Option<usize> {
    let mut base = path.to_string();
    loop {
        let candidate = if base.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{base}/node_modules/{name}")
        };
        if let Some(index) = find(&candidate) {
            return Some(index);
        }
        if base.is_empty() {
            return None;
        }
        base = match base.rfind("/node_modules/") {
            Some(at) => base[..at].to_string(),
            None => String::new(),
        };
    }
}

/// `yarn.lock`, version 1 and Berry. Each entry starts at an unindented
/// line listing its descriptors and ending with `:`; its `version` and
/// `dependencies` follow, indented. Workspace and local entries are left
/// out: they are the project's own code.
fn read_yarn_lock(text: &str) -> Result<LockFile, String> {
    let dependency_re =
        Regex::new(r#"^\s+"?((?:@[^"\s/]+/)?[^"\s:@]+)"?:?\s+"?([^"]*?)"?\s*$"#).expect("valid");
    let version_re = Regex::new(r#"^\s+version:?\s+"?([^"\s]+)"?\s*$"#).expect("valid");
    struct Entry {
        descriptors: Vec<String>,
        version: Option<String>,
        line: usize,
        dependencies: Vec<(String, String)>,
    }
    let mut entries: Vec<Entry> = Vec::new();
    let mut in_dependencies = false;
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            in_dependencies = false;
            let header = line.trim_end().trim_end_matches(':');
            if header == "__metadata" {
                entries.push(Entry {
                    descriptors: Vec::new(),
                    version: None,
                    line: i + 1,
                    dependencies: Vec::new(),
                });
                continue;
            }
            let descriptors = header
                .split(',')
                .map(|d| d.trim().trim_matches('"').to_string())
                .filter(|d| !d.is_empty())
                .collect();
            entries.push(Entry {
                descriptors,
                version: None,
                line: i + 1,
                dependencies: Vec::new(),
            });
            continue;
        }
        let Some(entry) = entries.last_mut() else {
            return Err(format!("line {}: indented line before any entry", i + 1));
        };
        let indent = line.len() - line.trim_start().len();
        if indent <= 2 {
            let field = line.trim().trim_end_matches(':');
            in_dependencies = matches!(field, "dependencies" | "optionalDependencies");
            if let Some(caps) = version_re.captures(line) {
                entry.version = Some(caps[1].to_string());
            }
        } else if in_dependencies && let Some(caps) = dependency_re.captures(line) {
            entry
                .dependencies
                .push((caps[1].to_string(), caps[2].to_string()));
        }
    }
    let local = |d: &str| {
        ["@workspace:", "@link:", "@portal:", "@file:", "@patch:"]
            .iter()
            .any(|marker| d.contains(marker))
    };
    let mut lock = LockFile {
        has_graph: true,
        ..LockFile::default()
    };
    let mut kept: Vec<(usize, &Entry)> = Vec::new();
    for entry in &entries {
        let Some(version) = &entry.version else {
            continue;
        };
        if entry.descriptors.is_empty()
            || entry.descriptors.iter().any(|d| local(d))
            || version.ends_with("use.local")
        {
            continue;
        }
        let index = lock.packages.len();
        let name = descriptor_name(&entry.descriptors[0]).to_string();
        for descriptor in &entry.descriptors {
            lock.descriptors.insert(descriptor.clone(), index);
        }
        lock.direct_by_name.entry(name.clone()).or_insert(index);
        lock.packages.push(LockedPackage {
            name,
            version: version.clone(),
            line: entry.line,
            dependencies: Vec::new(),
        });
        kept.push((index, entry));
    }
    for (index, entry) in kept {
        let dependencies: Vec<usize> = entry
            .dependencies
            .iter()
            .filter_map(|(name, spec)| {
                lock.descriptors
                    .get(&format!("{name}@{spec}"))
                    .or_else(|| lock.descriptors.get(&format!("{name}@npm:{spec}")))
                    .copied()
            })
            .collect();
        lock.packages[index].dependencies = dependencies;
    }
    Ok(lock)
}

/// The package name of an npm descriptor or id (`@scope/name@^1.0`,
/// `name@1.0.0`): up to its last `@` that does not start it.
fn descriptor_name(descriptor: &str) -> &str {
    match descriptor[1..].find('@') {
        Some(at) => &descriptor[..at + 1],
        None => descriptor,
    }
}

/// `pnpm-lock.yaml`, versions 5, 6 and 9. Packages are keyed by id:
/// `/name/1.0.0` (5), `/name@1.0.0(peer@2)` (6), `name@1.0.0(peer@2)` in
/// `snapshots` (9). A dependency names its package by version, from which
/// the id is rebuilt.
fn read_pnpm_lock(text: &str) -> Result<LockFile, String> {
    let yaml = crate::project::yaml::yaml_value(text)?;
    let version = yaml
        .get("lockfileVersion")
        .and_then(Value::as_str)
        .unwrap_or("");
    let v5 = version.starts_with('5');
    let section = if yaml.get("snapshots").is_some() {
        "snapshots"
    } else {
        "packages"
    };
    let lines = yaml_key_lines(text, section);
    let mut lock = LockFile {
        has_graph: true,
        ..LockFile::default()
    };
    let id_of = |name: &str, reference: &str| -> String {
        // An alias names another package: `string-width@4.2.3`.
        if reference.len() > 1 && reference[1..].contains('@') && !reference.starts_with('(') {
            let base = reference.split('(').next().unwrap_or(reference);
            if base[1..].contains('@') {
                return reference.trim_start_matches('/').to_string();
            }
        }
        if v5 {
            format!("{name}/{reference}")
        } else {
            format!("{name}@{reference}")
        }
    };
    let mut by_id: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_bare: BTreeMap<String, usize> = BTreeMap::new();
    let Some(Value::Object(packages)) = yaml.get(section) else {
        return Ok(lock); // nothing installed
    };
    for key in packages.keys() {
        let id = key.trim_start_matches('/');
        let (name, version) = if v5 {
            let at = id.rfind('/').ok_or_else(|| format!("package id {key:?}"))?;
            (
                &id[..at],
                id[at + 1..].split('_').next().unwrap_or_default(),
            )
        } else {
            let base = id.split('(').next().unwrap_or(id);
            let name = descriptor_name(base);
            (name, base.get(name.len() + 1..).unwrap_or_default())
        };
        let index = lock.packages.len();
        by_id.insert(id.to_string(), index);
        by_bare.entry(format!("{name}@{version}")).or_insert(index);
        lock.packages.push(LockedPackage {
            name: name.to_string(),
            version: version.to_string(),
            line: lines.get(key).copied().unwrap_or(0),
            dependencies: Vec::new(),
        });
    }
    let find = |name: &str, reference: &str| -> Option<usize> {
        let id = id_of(name, reference);
        by_id.get(&id).copied().or_else(|| {
            let bare = reference.split(['(', '_']).next().unwrap_or(reference);
            by_bare.get(&format!("{name}@{bare}")).copied()
        })
    };
    for (key, entry) in packages {
        let index = by_id[key.trim_start_matches('/')];
        let dependencies: Vec<usize> = ["dependencies", "optionalDependencies"]
            .iter()
            .filter_map(|field| entry.get(*field).and_then(Value::as_object))
            .flat_map(|map| map.iter())
            .filter_map(|(name, reference)| find(name, reference.as_str()?))
            .collect();
        lock.packages[index].dependencies = dependencies;
    }
    // The project's own direct dependencies: its importer `.` (6, 9) or
    // the top level (5, and 6 without workspace).
    let importer = yaml
        .get("importers")
        .and_then(|i| i.get("."))
        .unwrap_or(&yaml);
    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(Value::Object(map)) = importer.get(field) else {
            continue;
        };
        for (name, value) in map {
            let reference = value
                .get("version")
                .and_then(Value::as_str)
                .or_else(|| value.as_str());
            if let Some(index) = reference.and_then(|r| find(name, r)) {
                lock.direct_by_name.insert(name.clone(), index);
            }
        }
    }
    Ok(lock)
}

/// The line of each key indented by two spaces under the top-level key
/// `section` of a YAML text, quotes and the leading `/` removed.
fn yaml_key_lines(text: &str, section: &str) -> BTreeMap<String, usize> {
    let mut lines = BTreeMap::new();
    let mut inside = false;
    for (i, line) in text.lines().enumerate() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            inside = line.trim_end() == format!("{section}:");
            continue;
        }
        if inside && line.starts_with("  ") && !line.starts_with("   ") {
            // `key:` alone, or `key: {}` with its value on the same line;
            // a quoted key ends at its closing quote.
            let entry = line.trim();
            let key = match entry.chars().next() {
                Some(quote @ ('"' | '\'')) => entry[1..].split(quote).next(),
                _ => entry
                    .strip_suffix(':')
                    .filter(|k| !k.contains(": "))
                    .or_else(|| entry.split_once(": ").map(|(k, _)| k)),
            };
            if let Some(key) = key {
                lines.insert(key.to_string(), i + 1);
            }
        }
    }
    lines
}

/// `bun.lock`: JSON with trailing commas. `packages` maps a key (the
/// package's name, or `parent/name` for one nested under its parent) to
/// `[ "name@version", registry, { dependencies… }, integrity ]`.
fn read_bun_lock(text: &str) -> Result<LockFile, String> {
    let json_text = without_trailing_commas(text);
    let json: Value = serde_json::from_str(&json_text).map_err(|e| e.to_string())?;
    let lines = json_key_lines(&json_text);
    let mut lock = LockFile {
        has_graph: true,
        ..LockFile::default()
    };
    let Some(Value::Object(packages)) = json.get("packages") else {
        return Err("no `packages`".to_string());
    };
    let mut by_key: BTreeMap<&str, usize> = BTreeMap::new();
    for (key, value) in packages {
        let Some(id) = value.get(0).and_then(Value::as_str) else {
            return Err(format!("package {key:?} without id"));
        };
        let name = descriptor_name(id);
        let version = id.get(name.len() + 1..).unwrap_or_default();
        if version.contains(':') {
            continue; // `workspace:`, `link:`, `file:`: the project's own code
        }
        by_key.insert(key, lock.packages.len());
        lock.packages.push(LockedPackage {
            name: name.to_string(),
            version: version.to_string(),
            line: lines
                .get(&vec!["packages".to_string(), key.clone()])
                .copied()
                .unwrap_or(0),
            dependencies: Vec::new(),
        });
    }
    for (key, value) in packages {
        let Some(&index) = by_key.get(key.as_str()) else {
            continue;
        };
        let parents = package_segments(key);
        let dependencies: Vec<usize> = value
            .get(2)
            .map(dependency_names)
            .into_iter()
            .flatten()
            .filter_map(|name| {
                (0..=parents.len()).rev().find_map(|depth| {
                    let mut candidate = parents[..depth].join("/");
                    if !candidate.is_empty() {
                        candidate.push('/');
                    }
                    candidate.push_str(name);
                    by_key.get(candidate.as_str()).copied()
                })
            })
            .collect();
        lock.packages[index].dependencies = dependencies;
    }
    for (key, &index) in &by_key {
        if package_segments(key).len() == 1 {
            lock.direct_by_name.insert(key.to_string(), index);
        }
    }
    Ok(lock)
}

/// The package names a `bun.lock` key is made of: `a/@s/b` is `a`, `@s/b`.
fn package_segments(key: &str) -> Vec<String> {
    let mut segments: Vec<String> = Vec::new();
    let mut parts = key.split('/');
    while let Some(part) = parts.next() {
        if part.starts_with('@') {
            segments.push(format!("{part}/{}", parts.next().unwrap_or_default()));
        } else {
            segments.push(part.to_string());
        }
    }
    segments
}

/// `text` without the commas JSON forbids before `}` and `]`; strings
/// untouched, line breaks kept, so lines stay where they were.
fn without_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 1;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if c == ',' {
            let next = chars[i + 1..].iter().find(|c| !c.is_whitespace());
            if !matches!(next, Some('}') | Some(']')) {
                out.push(c);
            }
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// `composer.lock`: `packages` and `packages-dev`, each package with the
/// names it `require`s.
fn read_composer_lock(text: &str) -> Result<LockFile, String> {
    let json: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let lines = json_key_lines(text);
    let mut lock = LockFile {
        has_graph: true,
        key: NameKey::Lower,
        ..LockFile::default()
    };
    let mut requires: Vec<Vec<String>> = Vec::new();
    let mut sections = 0;
    for section in ["packages", "packages-dev"] {
        let Some(Value::Array(packages)) = json.get(section) else {
            continue;
        };
        sections += 1;
        for (i, package) in packages.iter().enumerate() {
            let (Some(name), Some(version)) = (
                package.get("name").and_then(Value::as_str),
                package.get("version").and_then(Value::as_str),
            ) else {
                return Err(format!("{section}[{i}] without name or version"));
            };
            lock.direct_by_name
                .insert(name.to_lowercase(), lock.packages.len());
            lock.packages.push(LockedPackage {
                name: name.to_string(),
                version: version.to_string(),
                line: lines
                    .get(&vec![
                        section.to_string(),
                        i.to_string(),
                        "name".to_string(),
                    ])
                    .copied()
                    .unwrap_or(0),
                dependencies: Vec::new(),
            });
            requires.push(
                package
                    .get("require")
                    .and_then(Value::as_object)
                    .map(|m| m.keys().map(|k| k.to_lowercase()).collect())
                    .unwrap_or_default(),
            );
        }
    }
    if sections == 0 {
        return Err("no `packages` list".to_string());
    }
    for (index, names) in requires.into_iter().enumerate() {
        lock.packages[index].dependencies = names
            .iter()
            .filter_map(|n| lock.direct_by_name.get(n).copied())
            .collect();
    }
    Ok(lock)
}

/// `poetry.lock`, `uv.lock` and `pdm.lock`: their `[[package]]` tables,
/// each with `name` and `version`, and the names it depends on, from
/// `[package.dependencies]` (Poetry) or a `dependencies` array of
/// `{ name = … }` (uv) or of requirement strings (PDM). A package uv
/// marks as `editable`, `virtual` or `directory` is the project itself.
fn read_toml_packages(text: &str) -> Result<LockFile, String> {
    let key_re = Regex::new(r#"^(name|version)\s*=\s*"([^"]*)""#).expect("valid");
    let uv_name_re = Regex::new(r#"\{\s*name\s*=\s*"([^"]+)""#).expect("valid");
    let pdm_name_re = Regex::new(r#""([A-Za-z0-9][A-Za-z0-9._-]*)"#).expect("valid");
    let table_key_re = Regex::new(r#"^"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*="#).expect("valid");
    #[derive(Default)]
    struct Table {
        name: Option<String>,
        version: Option<String>,
        line: usize,
        local: bool,
        dependencies: Vec<String>,
    }
    let mut tables: Vec<Table> = Vec::new();
    // Where the current line is: a package table, its dependency table
    // or array, or elsewhere.
    #[derive(PartialEq)]
    enum Place {
        Package,
        /// Poetry's `[package.dependencies]`: one key per package.
        DependencyTable,
        /// uv's `[package.optional-dependencies]` and
        /// `[package.dev-dependencies]`: arrays of `{ name = … }` under
        /// each extra or group, whose own names are not packages.
        NamedTable,
        DependencyArray,
        Other,
    }
    let mut place = Place::Other;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('[')
            && !line.starts_with("[[package]]")
            && place == Place::DependencyArray
        {
            place = Place::Other;
        }
        if line == "[[package]]" {
            tables.push(Table {
                line: i + 1,
                ..Table::default()
            });
            place = Place::Package;
            continue;
        }
        if line.starts_with('[') {
            place = match line {
                "[package.dependencies]" => Place::DependencyTable,
                "[package.optional-dependencies]" | "[package.dev-dependencies]" => {
                    Place::NamedTable
                }
                _ => Place::Other,
            };
            continue;
        }
        let Some(table) = tables.last_mut() else {
            continue;
        };
        match place {
            Place::Package => {
                if let Some(caps) = key_re.captures(line) {
                    let value = caps[2].to_string();
                    if &caps[1] == "name" {
                        table.name = Some(value);
                        table.line = i + 1;
                    } else {
                        table.version = Some(value);
                    }
                } else if line.starts_with("source")
                    && ["editable", "virtual", "directory"]
                        .iter()
                        .any(|kind| line.contains(&format!("{kind} =")))
                {
                    table.local = true;
                } else if line.starts_with("dependencies")
                    || line.starts_with("optional-dependencies")
                {
                    let names: Vec<String> = if line.contains("{") {
                        uv_name_re
                            .captures_iter(line)
                            .map(|c| c[1].to_string())
                            .collect()
                    } else {
                        pdm_name_re
                            .captures_iter(line)
                            .map(|c| c[1].to_string())
                            .collect()
                    };
                    table.dependencies.extend(names);
                    if !line.ends_with(']') {
                        place = Place::DependencyArray;
                    }
                }
            }
            Place::DependencyArray => {
                if line.starts_with(']') {
                    place = Place::Package;
                } else if let Some(caps) = uv_name_re.captures(line) {
                    table.dependencies.push(caps[1].to_string());
                } else if let Some(caps) = pdm_name_re.captures(line) {
                    table.dependencies.push(caps[1].to_string());
                }
            }
            Place::DependencyTable => {
                if let Some(caps) = table_key_re.captures(line) {
                    table.dependencies.push(caps[1].to_string());
                }
            }
            Place::NamedTable => {
                // An extra's packages are installed only when the extra
                // is asked for; being in the lockfile, it was.
                table
                    .dependencies
                    .extend(uv_name_re.captures_iter(line).map(|c| c[1].to_string()));
            }
            Place::Other => {}
        }
    }
    let mut lock = LockFile {
        has_graph: true,
        key: NameKey::Pep503,
        ..LockFile::default()
    };
    let mut kept: Vec<&Table> = Vec::new();
    for table in &tables {
        let Some(name) = &table.name else {
            return Err(format!("line {}: package without name", table.line));
        };
        let Some(version) = &table.version else {
            if table.local {
                continue;
            }
            return Err(format!("line {}: {name} without version", table.line));
        };
        if table.local {
            continue;
        }
        lock.direct_by_name
            .insert(pep503(name), lock.packages.len());
        lock.packages.push(LockedPackage {
            name: name.clone(),
            version: version.clone(),
            line: table.line,
            dependencies: Vec::new(),
        });
        kept.push(table);
    }
    for (index, table) in kept.into_iter().enumerate() {
        lock.packages[index].dependencies = table
            .dependencies
            .iter()
            .filter_map(|n| lock.direct_by_name.get(&pep503(n)).copied())
            .collect();
    }
    Ok(lock)
}

/// `Pipfile.lock`: one object per package category, each package with
/// its `==version`. The format says nothing of which package needs which.
///
/// The categories are `default` (the `Pipfile`'s `[packages]`), `develop`
/// (`[dev-packages]`) and, since Pipenv 2022.10, one more per custom
/// category of the `Pipfile` (`[docs]` → `docs`). Every top-level object
/// but `_meta` is therefore a category (ticket #213): reading only the
/// first two left a custom category's packages without their version.
fn read_pipfile_lock(text: &str) -> Result<LockFile, String> {
    let json: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let lines = json_key_lines(text);
    let mut lock = LockFile {
        has_graph: false,
        key: NameKey::Pep503,
        ..LockFile::default()
    };
    let Value::Object(root) = &json else {
        return Err("not a JSON object".to_string());
    };
    // `default` first, then `develop`, then the custom categories by
    // name: a package listed in several keeps the entry read last, as
    // `develop` overrode `default` before.
    let mut categories: Vec<(&String, &Value)> =
        root.iter().filter(|(name, _)| *name != "_meta").collect();
    categories.sort_by_key(|(name, _)| (*name != "default", *name != "develop", *name));
    let mut sections = 0;
    for (section, value) in categories {
        let Value::Object(packages) = value else {
            continue;
        };
        let section = section.as_str();
        sections += 1;
        for (name, entry) in packages {
            let Some(version) = entry.get("version").and_then(Value::as_str) else {
                continue; // a VCS or path requirement: no version
            };
            lock.direct_by_name
                .insert(pep503(name), lock.packages.len());
            lock.packages.push(LockedPackage {
                name: name.clone(),
                version: version.trim_start_matches("==").to_string(),
                line: lines
                    .get(&vec![section.to_string(), name.clone()])
                    .copied()
                    .unwrap_or(0),
                dependencies: Vec::new(),
            });
        }
    }
    if sections == 0 {
        return Err("no package category (`default`, `develop`, …)".to_string());
    }
    Ok(lock)
}

/// The line of every object key of the JSON document `content`, by its
/// path from the root (array items by their index), 1-based. Keys are
/// decoded as JSON strings. Called on a document `serde_json` has
/// parsed: on anything else it returns what it found.
pub fn json_key_lines(content: &str) -> BTreeMap<Vec<String>, usize> {
    enum Frame {
        Object {
            key: Option<String>,
            expects_key: bool,
        },
        Array {
            index: usize,
        },
    }
    let bytes = content.as_bytes();
    let mut lines = BTreeMap::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut line = 1;
    let mut i = 0;
    let path_of = |stack: &[Frame]| -> Vec<String> {
        stack
            .iter()
            .map(|frame| match frame {
                Frame::Object { key, .. } => key.clone().unwrap_or_default(),
                Frame::Array { index } => index.to_string(),
            })
            .collect()
    };
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => line += 1,
            b'{' => stack.push(Frame::Object {
                key: None,
                expects_key: true,
            }),
            b'[' => stack.push(Frame::Array { index: 0 }),
            b'}' | b']' => {
                stack.pop();
            }
            b',' => match stack.last_mut() {
                Some(Frame::Object { expects_key, .. }) => *expects_key = true,
                Some(Frame::Array { index }) => *index += 1,
                None => {}
            },
            b'"' => {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                let is_key = matches!(
                    stack.last(),
                    Some(Frame::Object {
                        expects_key: true,
                        ..
                    })
                );
                if is_key && let Some(raw) = content.get(start..=i.min(bytes.len() - 1)) {
                    let name: String = serde_json::from_str(raw).unwrap_or_default();
                    let parent = path_of(&stack[..stack.len() - 1]);
                    let mut path = parent;
                    path.push(name.clone());
                    lines.entry(path).or_insert(line);
                    if let Some(Frame::Object { key, expects_key }) = stack.last_mut() {
                        *key = Some(name);
                        *expects_key = false;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(label: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-lock-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, content) in files {
            std::fs::write(dir.join(name), content).unwrap();
        }
        dir
    }

    fn read_ok(lock: Lock) -> LockFile {
        match lock {
            Lock::Read(lock) => lock,
            other => panic!("not read: {other:?}"),
        }
    }

    /// What a test checks of a lockfile: the installed version of the
    /// direct dependencies, and the transitive packages with their lines
    /// and the direct dependencies that bring them in.
    /// A transitive package as a test sees it: `name@version`, line, via.
    type Transitive = (String, usize, Vec<String>);

    fn summary(lock: &LockFile, direct: &[(&str, &str)]) -> (Vec<String>, Vec<Transitive>) {
        let installed = direct
            .iter()
            .map(|(n, s)| {
                lock.installed(n, s)
                    .map_or("-".to_string(), |p| format!("{}@{}", p.name, p.version))
            })
            .collect();
        let direct: Vec<(String, String)> = direct
            .iter()
            .map(|(n, s)| (n.to_string(), s.to_string()))
            .collect();
        let transitive = lock
            .transitive(&direct)
            .into_iter()
            .map(|(p, via)| (format!("{}@{}", p.name, p.version), p.line, via))
            .collect();
        (installed, transitive)
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// package-lock v3: the nested copy is the one its parent uses, the
    /// hoisted one the others'.
    #[test]
    fn test_package_lock_v3() {
        let text = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"express": "^4.0.0", "debug": "^4.0.0"}},
    "node_modules/express": {"version": "4.17.1", "dependencies": {"debug": "2.6.9", "qs": "6.7.0"}},
    "node_modules/express/node_modules/debug": {"version": "2.6.9", "dependencies": {"ms": "2.0.0"}},
    "node_modules/debug": {"version": "4.3.4", "dependencies": {"ms": "2.1.2"}},
    "node_modules/ms": {"version": "2.1.2"},
    "node_modules/express/node_modules/ms": {"version": "2.0.0"},
    "node_modules/qs": {"version": "6.7.0"},
    "packages/local": {"version": "1.0.0"},
    "node_modules/local": {"resolved": "packages/local", "link": true}
  }
}"#;
        let lock = read_ok(npm(&dir("v3", &[("package-lock.json", text)])));
        let (installed, transitive) = summary(&lock, &[("express", "^4.0.0"), ("debug", "^4.0.0")]);
        assert_eq!(installed, s(&["express@4.17.1", "debug@4.3.4"]));
        assert_eq!(
            transitive,
            // In the lockfile's key order, which `serde_json` sorts.
            vec![
                ("debug@2.6.9".to_string(), 6, s(&["express"])),
                ("ms@2.0.0".to_string(), 9, s(&["express"])),
                ("ms@2.1.2".to_string(), 8, s(&["debug"])),
                ("qs@6.7.0".to_string(), 10, s(&["express"])),
            ]
        );
    }

    /// package-lock v1: `requires` resolved in the nested tree first.
    #[test]
    fn test_package_lock_v1() {
        let text = r#"{
  "lockfileVersion": 1,
  "dependencies": {
    "express": {"version": "4.17.1", "requires": {"debug": "2.6.9"},
      "dependencies": {"debug": {"version": "2.6.9"}}},
    "debug": {"version": "4.3.4"}
  }
}"#;
        let lock = read_ok(npm(&dir("v1", &[("package-lock.json", text)])));
        let (installed, transitive) = summary(&lock, &[("express", "^4"), ("debug", "^4")]);
        assert_eq!(installed, s(&["express@4.17.1", "debug@4.3.4"]));
        assert_eq!(
            transitive,
            vec![("debug@2.6.9".to_string(), 5, s(&["express"]))]
        );
    }

    /// yarn.lock v1 and Berry: entries found by descriptor.
    #[test]
    fn test_yarn_lock_v1_and_berry() {
        let v1 = "# yarn lockfile v1\n\n\"debug@^2.6.9\":\n  version \"2.6.9\"\n  dependencies:\n    ms \"2.0.0\"\n\ndebug@^4.0.0:\n  version \"4.3.4\"\n  dependencies:\n    ms \"^2.1.2\"\n\nexpress@^4.0.0:\n  version \"4.17.1\"\n  dependencies:\n    debug \"^2.6.9\"\n\nms@2.0.0:\n  version \"2.0.0\"\n\nms@^2.1.2:\n  version \"2.1.3\"\n";
        let lock = read_ok(npm(&dir("yarn1", &[("yarn.lock", v1)])));
        let (installed, transitive) = summary(&lock, &[("express", "^4.0.0"), ("debug", "^4.0.0")]);
        assert_eq!(installed, s(&["express@4.17.1", "debug@4.3.4"]));
        assert_eq!(
            transitive,
            vec![
                ("debug@2.6.9".to_string(), 3, s(&["express"])),
                ("ms@2.0.0".to_string(), 18, s(&["express"])),
                ("ms@2.1.3".to_string(), 21, s(&["debug"])),
            ]
        );

        let berry = "__metadata:\n  version: 6\n\n\"demo@workspace:.\":\n  version: 0.0.0-use.local\n  dependencies:\n    lodash: ^4.17.0\n\n\"lodash@npm:^4.17.0\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n\n\"@scope/a@npm:1.0.0, @scope/a@npm:^1.0.0\":\n  version: 1.0.0\n  dependencies:\n    lodash: ^4.17.0\n";
        let lock = read_ok(npm(&dir("berry", &[("yarn.lock", berry)])));
        let (installed, transitive) = summary(&lock, &[("@scope/a", "^1.0.0")]);
        assert_eq!(installed, s(&["@scope/a@1.0.0"]));
        assert_eq!(
            transitive,
            vec![("lodash@4.17.21".to_string(), 9, s(&["@scope/a"]))]
        );
    }

    /// pnpm-lock.yaml versions 9, 6 and 5.
    #[test]
    fn test_pnpm_lock_versions() {
        let v9 = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      express:\n        specifier: ^4.0.0\n        version: 4.17.1\n\npackages:\n  express@4.17.1:\n    resolution: {integrity: x}\n  debug@2.6.9:\n    resolution: {integrity: y}\n\nsnapshots:\n  express@4.17.1:\n    dependencies:\n      debug: 2.6.9\n  debug@2.6.9: {}\n";
        let lock = read_ok(npm(&dir("pnpm9", &[("pnpm-lock.yaml", v9)])));
        let (installed, transitive) = summary(&lock, &[("express", "^4.0.0")]);
        assert_eq!(installed, s(&["express@4.17.1"]));
        assert_eq!(
            transitive,
            vec![("debug@2.6.9".to_string(), 20, s(&["express"]))]
        );

        let v6 = "lockfileVersion: '6.0'\n\ndependencies:\n  express:\n    specifier: ^4.0.0\n    version: 4.17.1(react@18.2.0)\n\npackages:\n\n  /express@4.17.1(react@18.2.0):\n    dependencies:\n      debug: 2.6.9\n  /debug@2.6.9:\n    dev: false\n";
        let lock = read_ok(npm(&dir("pnpm6", &[("pnpm-lock.yaml", v6)])));
        let (installed, transitive) = summary(&lock, &[("express", "^4.0.0")]);
        assert_eq!(installed, s(&["express@4.17.1"]));
        assert_eq!(
            transitive,
            vec![("debug@2.6.9".to_string(), 13, s(&["express"]))]
        );

        let v5 = "lockfileVersion: 5.4\n\nspecifiers:\n  express: ^4.0.0\n\ndependencies:\n  express: 4.17.1\n\npackages:\n\n  /express/4.17.1:\n    dependencies:\n      debug: 2.6.9\n  /debug/2.6.9:\n    dev: false\n";
        let lock = read_ok(npm(&dir("pnpm5", &[("pnpm-lock.yaml", v5)])));
        let (installed, transitive) = summary(&lock, &[("express", "^4.0.0")]);
        assert_eq!(installed, s(&["express@4.17.1"]));
        assert_eq!(
            transitive,
            vec![("debug@2.6.9".to_string(), 14, s(&["express"]))]
        );
    }

    /// bun.lock (trailing commas) and bun.lockb (binary, named).
    #[test]
    fn test_bun_lock() {
        let text = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"dependencies\": {\n        \"express\": \"^4.0.0\",\n      },\n    },\n  },\n  \"packages\": {\n    \"express\": [\"express@4.17.1\", \"\", { \"dependencies\": { \"debug\": \"2.6.9\" } }, \"sha\"],\n    \"express/debug\": [\"debug@2.6.9\", \"\", {}, \"sha\"],\n    \"debug\": [\"debug@4.3.4\", \"\", {}, \"sha\"],\n  },\n}\n";
        let lock = read_ok(npm(&dir("bun", &[("bun.lock", text)])));
        let (installed, transitive) = summary(&lock, &[("express", "^4.0.0")]);
        assert_eq!(installed, s(&["express@4.17.1"]));
        assert_eq!(
            transitive,
            vec![
                ("debug@4.3.4".to_string(), 13, s(&[])),
                ("debug@2.6.9".to_string(), 12, s(&["express"])),
            ]
        );
        assert!(matches!(
            npm(&dir("bunb", &[("bun.lockb", "\u{0}binary")])),
            Lock::Binary(f) if f == "bun.lockb"
        ));
    }

    /// composer.lock: names compared in lower case.
    #[test]
    fn test_composer_lock() {
        let text = "{\n  \"packages\": [\n    {\"name\": \"symfony/http-kernel\", \"version\": \"v5.4.20\",\n     \"require\": {\"php\": \">=7.2\", \"Psr/Log\": \"^1\"}},\n    {\"name\": \"psr/log\", \"version\": \"1.1.4\"}\n  ],\n  \"packages-dev\": []\n}\n";
        let lock = read_ok(composer(&dir("composer", &[("composer.lock", text)])));
        let (installed, transitive) = summary(&lock, &[("Symfony/HTTP-Kernel", "^5.4")]);
        assert_eq!(installed, s(&["symfony/http-kernel@v5.4.20"]));
        assert_eq!(
            transitive,
            vec![("psr/log@1.1.4".to_string(), 5, s(&["Symfony/HTTP-Kernel"]))]
        );
    }

    /// poetry.lock, uv.lock, pdm.lock and Pipfile.lock.
    #[test]
    fn test_python_lockfiles() {
        let poetry = "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[package.dependencies]\nurllib3 = \">=1.21.1,<3\"\nCharset-Normalizer = \">=2,<4\"\n\n[[package]]\nname = \"urllib3\"\nversion = \"2.0.7\"\n\n[[package]]\nname = \"charset-normalizer\"\nversion = \"3.3.2\"\n\n[metadata]\nlock-version = \"2.0\"\n";
        let lock = read_ok(python(&dir("poetry", &[("poetry.lock", poetry)])));
        let (installed, transitive) = summary(&lock, &[("Requests", ">=2")]);
        assert_eq!(installed, s(&["requests@2.31.0"]));
        assert_eq!(
            transitive,
            vec![
                ("urllib3@2.0.7".to_string(), 10, s(&["Requests"])),
                ("charset-normalizer@3.3.2".to_string(), 14, s(&["Requests"])),
            ]
        );

        // An extra's packages (`[package.optional-dependencies]`) are
        // brought in by the package that declares the extra.
        let uv = "version = 1\n\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\ndependencies = [\n    { name = \"requests\" },\n]\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\ndependencies = [\n    { name = \"urllib3\" },\n]\n\n[package.optional-dependencies]\nsocks = [\n    { name = \"pysocks\" },\n]\n\n[[package]]\nname = \"urllib3\"\nversion = \"2.0.7\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n[[package]]\nname = \"pysocks\"\nversion = \"1.7.1\"\n";
        let lock = read_ok(python(&dir("uv", &[("uv.lock", uv)])));
        let (installed, transitive) = summary(&lock, &[("requests", ">=2")]);
        assert_eq!(installed, s(&["requests@2.31.0"]));
        assert_eq!(
            transitive,
            vec![
                ("urllib3@2.0.7".to_string(), 25, s(&["requests"])),
                ("pysocks@1.7.1".to_string(), 30, s(&["requests"])),
            ]
        );

        let pdm = "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\ndependencies = [\n    \"urllib3<3,>=1.21.1\",\n]\n\n[[package]]\nname = \"urllib3\"\nversion = \"2.0.7\"\n";
        let lock = read_ok(python(&dir("pdm", &[("pdm.lock", pdm)])));
        let (_, transitive) = summary(&lock, &[("requests", ">=2")]);
        assert_eq!(
            transitive,
            vec![("urllib3@2.0.7".to_string(), 9, s(&["requests"]))]
        );

        let pipfile = "{\n  \"default\": {\n    \"requests\": {\"version\": \"==2.31.0\"},\n    \"urllib3\": {\"version\": \"==2.0.7\"}\n  },\n  \"develop\": {}\n}\n";
        let lock = read_ok(python(&dir("pipfile", &[("Pipfile.lock", pipfile)])));
        assert!(!lock.has_graph);
        let (installed, transitive) = summary(&lock, &[("requests", ">=2")]);
        assert_eq!(installed, s(&["requests@2.31.0"]));
        assert_eq!(transitive, vec![("urllib3@2.0.7".to_string(), 4, s(&[]))]);
    }

    /// A lockfile that cannot be read is an error naming its reason.
    #[test]
    fn test_unreadable_lockfiles_are_named() {
        assert!(matches!(
            npm(&dir("bad-npm", &[("package-lock.json", "{}")])),
            Lock::Unreadable(f, _) if f == "package-lock.json"
        ));
        assert!(matches!(
            python(&dir("bad-poetry", &[("poetry.lock", "[[package]]\nname = \"x\"\n")])),
            Lock::Unreadable(f, reason) if f == "poetry.lock" && reason.contains("without version")
        ));
        assert!(matches!(
            npm(&dir("bad-pnpm", &[("pnpm-lock.yaml", "a: &x 1\nb: *x\n")])),
            Lock::Unreadable(f, _) if f == "pnpm-lock.yaml"
        ));
    }

    #[test]
    fn test_pep503() {
        assert_eq!(pep503("Charset_Normalizer"), "charset-normalizer");
        assert_eq!(pep503("zope.interface"), "zope-interface");
        assert_eq!(pep503("a--b__c"), "a-b-c");
    }
}
