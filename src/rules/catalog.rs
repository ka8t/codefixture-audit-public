//! The rule catalog, read at run time (ADR-0040). A scan reads one rule
//! source:
//!
//! - **the catalog pack** `rules.cfpack` next to the running executable
//!   (the default): every rule file of the catalog in one file, encrypted
//!   with the public demo key (`pack_format`). `build.rs` writes it, from
//!   `rules/builtin` in the private repository (full catalog) or from the
//!   committed demo pack in the shared one;
//! - **or `--rules <PATH>`**: another pack, or a folder of plain `.sca`
//!   files laid out by language (`<language>/<category>/<rule>.sca`), for
//!   development and tests.
//!
//! The custom rules folder (`~/.codefixture-audit/custom-rules`) is a plain
//! folder read in addition, labelled as the client's own rules.
//!
//! A scan only keeps the rule files of its target languages
//! ([`is_targeted_rule_path`]): the files of the other languages are
//! counted but never compiled. Every compiled rule carries its origin
//! (`RuleOrigin`) for the report.

use std::path::{Path, PathBuf};

use super::identity::RuleId;
use super::pack_format::{self, PACK_FILE_NAME};

pub use super::pack_format::RuleSource;

/// Language folders of a catalog, which are also the values of a rule's
/// `language` field (`SourceLanguage::rule_tag`). TypeScript has no folder
/// of its own: its files run the `javascript` rules.
pub const RULE_LANGUAGES: [&str; 8] = [
    "csharp",
    "dockerfile",
    "html",
    "java",
    "javascript",
    "php",
    "python",
    "yaml",
];

/// Where a rule comes from, written as `"origin"` on each compiled rule so
/// the report can tell the catalog's rules from the client's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleOrigin {
    /// The catalog: the pack, or the folder given with `--rules`.
    Builtin,
    /// A file of the custom rules folder.
    Client,
}

impl RuleOrigin {
    /// Value of the `"origin"` field of a compiled rule.
    pub fn as_str(self) -> &'static str {
        match self {
            RuleOrigin::Builtin => "builtin",
            RuleOrigin::Client => "client",
        }
    }
}

/// Kind of a rule source: one pack file, or a folder of `.sca` files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSourceKind {
    /// A `.cfpack` file.
    Pack,
    /// A folder of plain `.sca` files.
    Folder,
}

/// One rule file kept for a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedRuleFile {
    /// Path relative to the folder or inside the pack, with `/`
    /// separators.
    pub rel_path: String,
    /// Name given to the compiler, shown in rule errors: the full path of
    /// a plain file, `<pack path>:<relative path>` for a pack entry.
    pub source_name: String,
    /// `.sca` source.
    pub content: String,
    /// Origin written on the compiled rules.
    pub origin: RuleOrigin,
}

/// What a rule source gave a scan: the rule files kept, plus the counts
/// the CLI prints so a reader sees what was actually loaded.
#[derive(Debug)]
pub struct LoadedRules {
    /// The pack file or the folder.
    pub path: PathBuf,
    /// Pack or folder.
    pub kind: RuleSourceKind,
    /// Rule files kept for the target languages, sorted by path.
    pub files: Vec<LoadedRuleFile>,
    /// Rule files the source holds, every language.
    pub files_available: usize,
    /// The pack or files that could not be read or opened, with the
    /// reason. One unreadable file never stops the others.
    pub errors: Vec<(PathBuf, String)>,
}

/// The counts of a [`LoadedRules`], without the rule sources: what the
/// scan report keeps for the CLI's rule lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSourceSummary {
    /// The pack file or the folder.
    pub path: PathBuf,
    /// Pack or folder.
    pub kind: RuleSourceKind,
    /// Rule files the source holds, every language.
    pub files_available: usize,
    /// Rule files kept for the target languages.
    pub files_read: usize,
}

impl LoadedRules {
    /// The counts of this source, for the scan report.
    pub fn summary(&self) -> RuleSourceSummary {
        RuleSourceSummary {
            path: self.path.clone(),
            kind: self.kind,
            files_available: self.files_available,
            files_read: self.files.len(),
        }
    }
}

/// Default catalog: `rules.cfpack` in the folder of the running
/// executable, whatever the current folder (ADR-0040). `None` only if the
/// executable path is unknown.
pub fn default_pack_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(PACK_FILE_NAME)))
}

/// Whether `dir` holds a `.sca` file at any depth. The CLI stops on a
/// rules folder without any, rather than scanning with no rule.
pub fn has_rule_files(dir: &Path) -> bool {
    !sca_paths(dir).is_empty()
}

/// Whether a rule file at `rel_path` (relative, `/` separators) is read
/// for the rule languages `languages`. A file under a language folder
/// (`java/…`) is read only when that language is targeted; any other file
/// (a flat test catalog, a client's custom folder without language
/// folders) is read, and the caller drops its compiled rules whose
/// `language` is not targeted.
pub fn is_targeted_rule_path(rel_path: &str, languages: &[String]) -> bool {
    match rel_path.split_once('/') {
        Some((first, _)) if RULE_LANGUAGES.contains(&first) => languages.iter().any(|l| l == first),
        _ => true,
    }
}

/// Relative paths (`/` separators) of every `.sca` file under `dir`,
/// sorted, without reading them. Symbolic links to folders are not
/// followed, like the scan walk (ticket #147).
fn sca_paths(dir: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                walk(root, &path, out);
            } else if file_type.is_file() && path.extension().is_some_and(|e| e == "sca") {
                let rel = path
                    .strip_prefix(root)
                    .expect("the file comes from root")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(rel);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Every `.sca` file under `dir`, recursively, as [`RuleSource`]s sorted
/// by path. An unreadable file is skipped. For the tests that check the
/// plain catalog itself.
pub fn read_rule_sources(dir: &Path) -> Vec<RuleSource> {
    sca_paths(dir)
        .into_iter()
        .filter_map(|rel| {
            std::fs::read_to_string(dir.join(&rel))
                .ok()
                .map(|content| (rel, content))
        })
        .collect()
}

/// Every rule file of a pack or a folder, every language, sorted by path:
/// what `list-rules` and `rules diff` read. `Err` if the pack cannot be
/// opened or the path is neither a pack nor a folder.
pub fn read_all_rule_sources(path: &Path) -> Result<Vec<RuleSource>, String> {
    if path.is_dir() {
        return pack_format::collect_sca_sources(path);
    }
    let bytes = std::fs::read(path).map_err(|e| format!("unreadable rule pack: {e}"))?;
    pack_format::open_pack(&bytes).map(|(_, files)| files)
}

/// Loads the rule files of `path` for the rule languages `languages`: a
/// pack file, or a folder of `.sca` files. `origin` labels the rules:
/// `Builtin` for the catalog, `Client` for the custom rules folder.
pub fn load_rules(path: &Path, languages: &[String], origin: RuleOrigin) -> LoadedRules {
    if path.is_dir() {
        load_rule_folder(path, languages, origin)
    } else {
        load_rule_pack(path, languages, origin)
    }
}

/// Loads a pack: decrypted once, then only the targeted files are kept.
/// A pack that cannot be read or opened gives no file and one error.
fn load_rule_pack(path: &Path, languages: &[String], origin: RuleOrigin) -> LoadedRules {
    let mut loaded = LoadedRules {
        path: path.to_path_buf(),
        kind: RuleSourceKind::Pack,
        files: Vec::new(),
        files_available: 0,
        errors: Vec::new(),
    };
    let opened = std::fs::read(path)
        .map_err(|e| format!("unreadable rule pack: {e}"))
        .and_then(|bytes| pack_format::open_pack(&bytes));
    let files = match opened {
        Ok((_, files)) => files,
        Err(reason) => {
            loaded.errors.push((path.to_path_buf(), reason));
            return loaded;
        }
    };
    loaded.files_available = files.len();
    loaded.files = files
        .into_iter()
        .filter(|(rel, _)| is_targeted_rule_path(rel, languages))
        .map(|(rel, content)| LoadedRuleFile {
            source_name: format!("{}:{rel}", path.display()),
            rel_path: rel,
            content,
            origin,
        })
        .collect();
    loaded
}

/// Loads a folder of `.sca` files: every file is listed for the counts,
/// only the targeted ones are read from disk.
fn load_rule_folder(dir: &Path, languages: &[String], origin: RuleOrigin) -> LoadedRules {
    let mut loaded = LoadedRules {
        path: dir.to_path_buf(),
        kind: RuleSourceKind::Folder,
        files: Vec::new(),
        files_available: 0,
        errors: Vec::new(),
    };
    let paths = sca_paths(dir);
    loaded.files_available = paths.len();
    for rel in paths {
        if !is_targeted_rule_path(&rel, languages) {
            continue;
        }
        let path = dir.join(&rel);
        match std::fs::read_to_string(&path) {
            Ok(content) => loaded.files.push(LoadedRuleFile {
                source_name: path.to_string_lossy().into_owned(),
                rel_path: rel,
                content,
                origin,
            }),
            Err(e) => loaded
                .errors
                .push((path, format!("unreadable rule file: {e}"))),
        }
    }
    loaded
}

/// Compiles rule sources **entirely in memory** (`compile_sca_to_json`
/// takes a string, not a path): compiled rules plus one error per
/// invalid file.
pub fn compile_catalog(files: &[RuleSource]) -> (Vec<serde_json::Value>, Vec<(PathBuf, String)>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    for (rel_path, content) in files {
        match crate::scan::parser::compile_sca_to_json(content, rel_path) {
            Ok(compiled) => rules.extend(compiled),
            Err(e) => errors.push((PathBuf::from(rel_path), e.to_string())),
        }
    }
    (rules, errors)
}

/// The rules of a scan, each once under its identity ([`RuleId`]).
///
/// Sources are added in order: the catalog first, then the client's
/// rules folder. A rule whose identity is already registered is not run
/// twice:
/// - a client rule replaces the catalog rule of the same identity, at the
///   catalog rule's place: that is how a client adjusts a rule (another
///   severity, a narrower pattern);
/// - a second rule of the same identity in the same source is dropped,
///   the first one kept: two files of one source defining one rule is a
///   mistake of that source.
///
/// Either case is recorded as a [`RuleConflict`], which the scan reports.
/// Before 2026-11-14 both rules ran: two findings on the same line, and
/// the report's texts of one rule mixed with the other's.
#[derive(Default)]
pub struct RuleRegistry {
    /// The compiled rules, in the order they will run.
    rules: Vec<RegisteredRule>,
    /// Position of each identity in `rules`.
    index: std::collections::BTreeMap<RuleId, usize>,
    conflicts: Vec<RuleConflict>,
    errors: Vec<(PathBuf, String)>,
}

/// A rule of the registry, with what the conflict messages need.
struct RegisteredRule {
    json: serde_json::Value,
    origin: RuleOrigin,
    /// The file the rule comes from (`<language>/<category>/<rule>.sca`).
    source_name: String,
}

/// Two rules of one identity met while loading: which file was kept,
/// which one was left out, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleConflict {
    pub id: RuleId,
    pub kind: RuleConflictKind,
    /// The file whose rule runs.
    pub kept: String,
    /// The file whose rule does not run.
    pub dropped: String,
}

/// Why a rule was left out of the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleConflictKind {
    /// A client rule replaced the catalog rule of the same identity.
    ClientReplacesCatalog,
    /// One source defined the same rule twice; the first one is kept.
    DuplicateInSource,
}

impl RuleRegistry {
    /// Compiles the rule files of a loaded source and registers its rules:
    /// each compiled rule gets its `"origin"` field, and a rule whose
    /// `language` is not in `languages` is dropped (a rule without
    /// `language` is kept). One error per invalid file, which never stops
    /// the others.
    pub fn add_source(&mut self, loaded: &LoadedRules, languages: &[String]) {
        let targeted =
            |rule: &serde_json::Value| match rule.get("language").and_then(|v| v.as_str()) {
                Some(language) => languages.iter().any(|l| l == language),
                None => true,
            };
        for file in &loaded.files {
            match crate::scan::parser::compile_sca_to_json(&file.content, &file.source_name) {
                Ok(compiled) => {
                    for mut rule in compiled.into_iter().filter(targeted) {
                        if let Some(obj) = rule.as_object_mut() {
                            obj.insert("origin".to_string(), file.origin.as_str().into());
                        }
                        self.register(RegisteredRule {
                            json: rule,
                            origin: file.origin,
                            source_name: file.source_name.clone(),
                        });
                    }
                }
                Err(e) => self
                    .errors
                    .push((PathBuf::from(&file.source_name), e.to_string())),
            }
        }
    }

    /// Adds one rule, applying the conflict rules of [`RuleRegistry`].
    fn register(&mut self, rule: RegisteredRule) {
        let Some(id) = RuleId::of(&rule.json) else {
            return; // never produced by the compiler: a rule always has an id.
        };
        let Some(&position) = self.index.get(&id) else {
            self.index.insert(id, self.rules.len());
            self.rules.push(rule);
            return;
        };
        let registered = &mut self.rules[position];
        if registered.origin == RuleOrigin::Builtin && rule.origin == RuleOrigin::Client {
            self.conflicts.push(RuleConflict {
                id,
                kind: RuleConflictKind::ClientReplacesCatalog,
                kept: rule.source_name.clone(),
                dropped: std::mem::replace(registered, rule).source_name,
            });
        } else {
            self.conflicts.push(RuleConflict {
                id,
                kind: RuleConflictKind::DuplicateInSource,
                kept: registered.source_name.clone(),
                dropped: rule.source_name,
            });
        }
    }

    /// The registered rules in run order, the conflicts met, and the
    /// files that failed to compile.
    pub fn finish(
        self,
    ) -> (
        Vec<serde_json::Value>,
        Vec<RuleConflict>,
        Vec<(PathBuf, String)>,
    ) {
        let rules = self.rules.into_iter().map(|r| r.json).collect();
        (rules, self.conflicts, self.errors)
    }
}

/// The identities defined by more than one rule of `files`, with the two
/// files of each (first, then the one met again), in catalog order: what
/// `rules pack` refuses to pack, since a scan would run only one of them.
/// Files that do not compile are left to the compile check.
pub fn duplicate_identities(files: &[RuleSource]) -> Vec<(RuleId, String, String)> {
    let mut first_file: std::collections::BTreeMap<RuleId, &str> =
        std::collections::BTreeMap::new();
    let mut duplicates = Vec::new();
    for (rel_path, content) in files {
        let Ok(compiled) = crate::scan::parser::compile_sca_to_json(content, rel_path) else {
            continue;
        };
        for rule in &compiled {
            let Some(id) = RuleId::of(rule) else {
                continue;
            };
            match first_file.get(&id) {
                Some(first) => duplicates.push((id, first.to_string(), rel_path.clone())),
                None => {
                    first_file.insert(id, rel_path);
                }
            }
        }
    }
    duplicates
}

/// Listing metadata of one catalog rule, for `codefixture-audit list-rules`.
#[derive(Debug, Clone)]
pub struct RuleListing {
    /// Rule identity, written `language/name` (`RuleId`).
    pub id: String,
    /// Category = the rule's folder (`security`, `arch`, `ux`, `cicd`…),
    /// NOT the `category` field of the rule — same choice as
    /// `Audit/sca/cli.py::_build_rule_metadata` (`parts[1]` of the path
    /// relative to `rules/builtin`).
    pub category_dir: String,
    /// Compiled `name` block (`{"en": …, "fr": …}`), `Null` if absent.
    pub name: serde_json::Value,
    /// Compiled `risk` block (`{"en": …, "fr": …}`), `Null` if absent.
    pub risk: serde_json::Value,
}

/// One entry per rule identity of `files` (language + name), sorted by
/// identity — port of `_build_rule_metadata`.
///
/// Deliberate deviation from the Python source, which keys its dict by
/// name: a name defined in several languages (`taint_xss` for Python,
/// Java and C#) was listed once, with one language's risk text, and the
/// announced count was lower than the catalog's (2026-11-14). Each
/// language's rule is listed now. Two files of one identity (never in the
/// catalog, which a test checks) keep the first in catalog order.
pub fn rule_listing(files: &[RuleSource]) -> Vec<RuleListing> {
    let mut by_id: std::collections::BTreeMap<RuleId, RuleListing> =
        std::collections::BTreeMap::new();
    for (rel_path, content) in files {
        let category_dir = rel_path
            .split(['/', '\\'])
            .nth(1)
            .unwrap_or("security")
            .to_string();
        let Ok(compiled) = crate::scan::parser::compile_sca_to_json(content, rel_path) else {
            continue;
        };
        for rule in compiled {
            let Some(id) = RuleId::of(&rule) else {
                continue;
            };
            by_id.entry(id.clone()).or_insert_with(|| RuleListing {
                id: id.to_string(),
                category_dir: category_dir.clone(),
                name: rule.get("name").cloned().unwrap_or(serde_json::Value::Null),
                risk: rule.get("risk").cloned().unwrap_or(serde_json::Value::Null),
            });
        }
    }
    by_id.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sast_catalog_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn langs(list: &[&str]) -> Vec<String> {
        list.iter().map(|l| l.to_string()).collect()
    }

    const RULE: &str = "rule pack_rule\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  PACK_MARKER\n    scope    line\n  end\nend\n";

    fn rule_named(id: &str, language: &str) -> String {
        RULE.replace("pack_rule", id).replace("python", language)
    }

    fn kept(loaded: &LoadedRules) -> Vec<String> {
        loaded.files.iter().map(|f| f.rel_path.clone()).collect()
    }

    /// The registry's result for `sources`, added in order.
    fn registered(
        sources: &[&LoadedRules],
        languages: &[String],
    ) -> (
        Vec<serde_json::Value>,
        Vec<RuleConflict>,
        Vec<(PathBuf, String)>,
    ) {
        let mut registry = RuleRegistry::default();
        for source in sources {
            registry.add_source(source, languages);
        }
        registry.finish()
    }

    /// A loaded source made of `files` (`(path, content)`), without disk.
    fn source(origin: RuleOrigin, files: &[(&str, String)]) -> LoadedRules {
        LoadedRules {
            path: PathBuf::new(),
            kind: RuleSourceKind::Folder,
            files: files
                .iter()
                .map(|(path, content)| LoadedRuleFile {
                    rel_path: path.to_string(),
                    source_name: path.to_string(),
                    content: content.clone(),
                    origin,
                })
                .collect(),
            files_available: files.len(),
            errors: Vec::new(),
        }
    }

    /// `(identity, severity)` of each registered rule, in run order.
    fn identities(rules: &[serde_json::Value]) -> Vec<(String, String)> {
        rules
            .iter()
            .map(|r| {
                (
                    RuleId::of(r).unwrap().to_string(),
                    r["severity"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn test_duplicate_identities_names_both_files_and_ignores_other_languages() {
        let files = vec![
            (
                "python/security/a.sca".to_string(),
                rule_named("a", "python"),
            ),
            ("java/security/a.sca".to_string(), rule_named("a", "java")),
            (
                "python/security/a_again.sca".to_string(),
                rule_named("a", "python"),
            ),
        ];
        assert_eq!(
            duplicate_identities(&files),
            [(
                RuleId::new("python", "a"),
                "python/security/a.sca".to_string(),
                "python/security/a_again.sca".to_string()
            )]
        );
    }

    #[test]
    fn test_registry_keeps_one_name_in_two_languages_as_two_rules() {
        let catalog = source(
            RuleOrigin::Builtin,
            &[
                ("python/security/a.sca", rule_named("a", "python")),
                ("java/security/a.sca", rule_named("a", "java")),
            ],
        );
        let (rules, conflicts, _) = registered(&[&catalog], &langs(&["python", "java"]));
        assert_eq!(
            identities(&rules),
            [
                ("python/a".to_string(), "HIGH".to_string()),
                ("java/a".to_string(), "HIGH".to_string())
            ]
        );
        assert!(conflicts.is_empty(), "{conflicts:?}");
    }

    #[test]
    fn test_registry_lets_a_client_rule_replace_the_catalog_rule_in_place() {
        let catalog = source(
            RuleOrigin::Builtin,
            &[
                ("python/security/a.sca", rule_named("a", "python")),
                ("python/security/b.sca", rule_named("b", "python")),
            ],
        );
        let client = source(
            RuleOrigin::Client,
            &[(
                "python/security/a.sca",
                rule_named("a", "python").replace("HIGH", "LOW"),
            )],
        );
        let (rules, conflicts, _) = registered(&[&catalog, &client], &langs(&["python"]));
        // Same place as the catalog rule (run order kept), client's content.
        assert_eq!(
            identities(&rules),
            [
                ("python/a".to_string(), "LOW".to_string()),
                ("python/b".to_string(), "HIGH".to_string())
            ]
        );
        assert_eq!(rules[0]["origin"], "client");
        assert_eq!(
            conflicts,
            [RuleConflict {
                id: RuleId::new("python", "a"),
                kind: RuleConflictKind::ClientReplacesCatalog,
                kept: "python/security/a.sca".to_string(),
                dropped: "python/security/a.sca".to_string(),
            }]
        );
    }

    #[test]
    fn test_registry_keeps_the_first_of_two_rules_of_one_source() {
        let client = source(
            RuleOrigin::Client,
            &[
                ("python/security/first.sca", rule_named("a", "python")),
                (
                    "python/security/second.sca",
                    rule_named("a", "python").replace("HIGH", "LOW"),
                ),
            ],
        );
        let (rules, conflicts, _) = registered(&[&client], &langs(&["python"]));
        assert_eq!(
            identities(&rules),
            [("python/a".to_string(), "HIGH".to_string())]
        );
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].kind, RuleConflictKind::DuplicateInSource);
        assert_eq!(
            (conflicts[0].kept.as_str(), conflicts[0].dropped.as_str()),
            ("python/security/first.sca", "python/security/second.sca")
        );
    }

    #[test]
    fn test_is_targeted_rule_path_filters_language_folders_only() {
        let python = langs(&["python"]);
        assert!(is_targeted_rule_path("python/security/a.sca", &python));
        assert!(!is_targeted_rule_path("java/security/a.sca", &python));
        assert!(is_targeted_rule_path("flat.sca", &python));
        assert!(is_targeted_rule_path("shared/a.sca", &python));
        assert!(!is_targeted_rule_path("python/a.sca", &[]));
    }

    #[test]
    fn test_has_rule_files_and_read_rule_sources() {
        let dir = temp_dir("sources");
        assert!(!has_rule_files(&dir));
        std::fs::create_dir_all(dir.join("python/security")).unwrap();
        std::fs::write(dir.join("python/security/notes.txt"), "x").unwrap();
        assert!(!has_rule_files(&dir), "only .sca files count");
        std::fs::write(dir.join("python/security/b.sca"), "B").unwrap();
        std::fs::write(dir.join("a.sca"), "A").unwrap();
        assert!(has_rule_files(&dir));
        let expected = vec![
            ("a.sca".to_string(), "A".to_string()),
            ("python/security/b.sca".to_string(), "B".to_string()),
        ];
        assert_eq!(read_rule_sources(&dir), expected);
        assert_eq!(read_all_rule_sources(&dir).unwrap(), expected);
        assert!(!has_rule_files(&dir.join("missing")));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Plain folder: only the targeted language folders are kept, the
    /// counts cover every language, and the compiled rules are filtered
    /// on their `language` (a flat Java file is read, then dropped).
    #[test]
    fn test_load_rules_folder_for_target_languages() {
        let dir = temp_dir("plain");
        std::fs::create_dir_all(dir.join("python/security")).unwrap();
        std::fs::create_dir_all(dir.join("java/security")).unwrap();
        std::fs::write(dir.join("python/security/p.sca"), rule_named("p", "python")).unwrap();
        std::fs::write(dir.join("java/security/j.sca"), rule_named("j", "java")).unwrap();
        std::fs::write(dir.join("flat.sca"), rule_named("flat_java", "java")).unwrap();

        let loaded = load_rules(&dir, &langs(&["python"]), RuleOrigin::Builtin);
        let (rules, _, errors) = registered(&[&loaded], &langs(&["python"]));
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(loaded.kind, RuleSourceKind::Folder);
        assert_eq!(loaded.files_available, 3);
        assert_eq!(kept(&loaded), ["flat.sca", "python/security/p.sca"]);
        assert!(errors.is_empty(), "{errors:?}");
        let ids: Vec<&str> = rules.iter().filter_map(|r| r["id"].as_str()).collect();
        assert_eq!(ids, ["p"]);
        assert_eq!(rules[0]["origin"], "builtin");
    }

    /// ADR-0040: a pack is opened with the demo key, only its targeted
    /// files are kept, and its rules carry the given origin.
    #[test]
    fn test_load_rules_pack_for_target_languages() {
        let dir = temp_dir("pack");
        let files = vec![
            (
                "python/security/p.sca".to_string(),
                rule_named("p", "python"),
            ),
            ("java/security/j.sca".to_string(), rule_named("j", "java")),
        ];
        let pack = dir.join(PACK_FILE_NAME);
        std::fs::write(&pack, pack_format::write_pack("builtin", &files, None)).unwrap();

        let loaded = load_rules(&pack, &langs(&["python"]), RuleOrigin::Builtin);
        let (rules, _, errors) = registered(&[&loaded], &langs(&["python"]));
        let all = read_all_rule_sources(&pack).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(loaded.kind, RuleSourceKind::Pack);
        assert!(loaded.errors.is_empty(), "{:?}", loaded.errors);
        assert_eq!(loaded.files_available, 2);
        assert_eq!(kept(&loaded), ["python/security/p.sca"]);
        assert!(
            loaded.files[0]
                .source_name
                .ends_with("rules.cfpack:python/security/p.sca")
        );
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(rules.len(), 1);
        assert_eq!(all.len(), 2, "read_all_rule_sources ignores languages");
    }

    /// A missing, corrupt or foreign-key pack gives no rule and one error
    /// naming the pack.
    #[test]
    fn test_load_rules_pack_errors_are_reported() {
        let dir = temp_dir("pack_errors");
        let files = vec![("python/r.sca".to_string(), RULE.to_string())];
        let mut corrupt = pack_format::write_pack("builtin", &files, None);
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        std::fs::write(dir.join("corrupt.cfpack"), corrupt).unwrap();
        let foreign = pack_format::write_pack_with_key("client", &files, None, &[9u8; 32]);
        std::fs::write(dir.join("client.cfpack"), foreign).unwrap();
        let python = langs(&["python"]);

        let reasons: Vec<String> = ["corrupt.cfpack", "client.cfpack", "missing.cfpack"]
            .iter()
            .map(|name| {
                let loaded = load_rules(&dir.join(name), &python, RuleOrigin::Builtin);
                assert!(loaded.files.is_empty());
                assert_eq!(loaded.errors.len(), 1);
                loaded.errors[0].1.clone()
            })
            .collect();
        std::fs::remove_dir_all(&dir).ok();
        assert!(reasons[0].contains("corrupt"), "{reasons:?}");
        assert!(reasons[1].contains("needs key"), "{reasons:?}");
        assert!(reasons[2].contains("unreadable"), "{reasons:?}");
    }

    #[test]
    fn test_default_pack_path_is_next_to_executable() {
        let path = default_pack_path().expect("current_exe is known in tests");
        assert_eq!(path.file_name().unwrap(), PACK_FILE_NAME);
    }
}
