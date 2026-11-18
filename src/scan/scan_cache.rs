//! Cache of the analysis between two scans of the same folder (issue #183,
//! 2026-11-14): the data-flow (taint) passes and the pattern pass.
//!
//! Layout: `<project>/audit-reports/audit-datas/cache/<engine>/`, one folder
//! per engine build (`CacheContext`), holding `taint-<language>.json.gz` and
//! `patterns.json.gz`. A scan prepares its folder once (`CacheContext::
//! prepare`), marks it as used and removes the folders of the engines used
//! least recently.
//!
//! Every scan used to redo the whole taint pass, the costliest phase (20 s
//! of 33 s on a 600-file Python project), even when nothing had changed.
//! The Python `Audit` had a cache per file (`sca/file_cache.py`), but a
//! per-file cache is wrong for this engine: the taint pass follows calls
//! from file to file, so editing `quotas.py` can change a finding of
//! `router.py`. The maintainer chose (2026-11-14) an invalidation that follows those
//! dependencies:
//!
//! - per file: the hash of its text and its `dependency_fingerprint` (its
//!   functions, the calls and imports it resolves); a file whose hash or
//!   fingerprint differs is *dirty*;
//! - per rule: every function summary and every file's findings of the
//!   previous run. `resolve_summaries_incremental` recomputes the summaries
//!   of dirty files and of the functions whose callees' summaries changed,
//!   and reuses the others; a file is analysed again when it is dirty or
//!   reads a summary that changed, and keeps its previous findings
//!   otherwise;
//! - the whole cache is dropped when the engine binary, the report
//!   language or the format change, and a rule's entry when its definition
//!   changes.
//!
//! Suppressions and `# sca-ignore` are applied after the cache, on every
//! scan, so changing them never needs a fresh analysis. A cache that cannot
//! be read is ignored: the scan is then a full one, never a wrong one.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::scan::dataflow::call_graph::NodeKey;
use crate::scan::dataflow::transfer::{Finding, FunctionSummary};

/// Version of the cache file layout; a different one is ignored.
const FORMAT: u32 = 1;

/// Hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// What makes a whole cache valid: the engine build and the report
/// language (rule messages are written in it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheKey {
    /// `BUILD_VERSION` plus the size and modification time of the running
    /// binary: a rebuild with uncommitted changes keeps the same version
    /// string but must not reuse results of other code.
    pub engine: String,
    /// `--lang` of the scan.
    pub lang: String,
}

/// How many binaries keep their cache folder side by side: the most
/// recently used ones; the others are removed when a scan starts.
pub const KEPT_ENGINE_DIRS: usize = 3;

/// File written in an engine folder at the start of every scan by that
/// engine. Its modification time is the folder's "last used" date: the
/// folder's own date only moves when a file inside is created or renamed,
/// so a binary that only rereads its cache would look unused and could be
/// removed by another binary (found on review, 2026-11-14).
pub const LAST_USED_FILE: &str = "last-used";

/// The cache of one scan: the engine's key and its own folder, prepared
/// once when the scan starts and shared by every pass.
#[derive(Debug, Clone)]
pub struct CacheContext {
    /// Key of the running engine and report language.
    pub key: CacheKey,
    /// This engine's folder inside the project's cache folder.
    pub dir: PathBuf,
}

impl CacheContext {
    /// Prepares the cache of a scan in `base` (the project's cache folder)
    /// for the report language `lang`: creates this engine's folder,
    /// marks it as used now, and removes the folders of the engines used
    /// least recently beyond `KEPT_ENGINE_DIRS`. `None` when the folder
    /// cannot be created: the scan then runs without a cache, never fails.
    ///
    /// `project_root` is the scanned project's root, used as a security
    /// guard: `base` sits under it by default
    /// (`<root>/audit-reports/audit-datas/cache`), and a scanned project is
    /// untrusted. If reaching `base` from the root crosses a symbolic link
    /// the project may have planted, the cache is refused (`None`) rather
    /// than followed — otherwise the folder creation and, above all, the
    /// `remove_dir_all` of the prune would act on a directory *outside* the
    /// project the link points at, deleting unrelated data (found on review
    /// 2026-11-15, confirmed by proof of concept). A `base` outside
    /// `project_root` — an explicit `--data-dir` — is the operator's own
    /// choice and is not second-guessed here.
    pub fn prepare(base: &Path, lang: &str, project_root: &Path) -> Option<Self> {
        if escapes_project_via_symlink(project_root, base) {
            return None;
        }
        let key = CacheKey::current(lang);
        let dir = key.engine_dir(base);
        std::fs::create_dir_all(&dir).ok()?;
        // Rewriting the file moves its modification time to now.
        std::fs::write(dir.join(LAST_USED_FILE), b"").ok()?;
        remove_files_of_the_old_layout(base);
        prune_engine_dirs(base, &dir);
        Some(CacheContext { key, dir })
    }
}

impl CacheKey {
    /// The cache folder of this engine build in `base`: its version and a
    /// short hash of its build stamp (`0.1.0+327.46ee715-3fa2c1d8`). Each
    /// binary has its own folder (the maintainer, 2026-11-14), so that two binaries
    /// used in turn on the same project (the private and the shared one,
    /// two versions) never overwrite each other's cache.
    pub fn engine_dir(&self, base: &Path) -> PathBuf {
        let version: String = crate::BUILD_VERSION
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "+.-".contains(c) {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        base.join(format!(
            "{version}-{}",
            &sha256_hex(self.engine.as_bytes())[..8]
        ))
    }

    /// The key of the running engine for `lang`.
    pub fn current(lang: &str) -> Self {
        let stamp = std::env::current_exe()
            .and_then(std::fs::metadata)
            .map(|m| {
                let modified = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_nanos());
                format!("{}:{modified}", m.len())
            })
            .unwrap_or_default();
        CacheKey {
            engine: format!("{}+{stamp}", crate::BUILD_VERSION),
            lang: lang.to_string(),
        }
    }
}

/// One file as seen by the previous run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileState {
    /// SHA-256 of the file's bytes.
    pub hash: String,
    /// SHA-256 of its `dependency_fingerprint`.
    pub deps: String,
}

/// One taint rule as computed by the previous run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleState {
    /// SHA-256 of the rule's compiled JSON: a changed rule is computed
    /// from scratch.
    pub rule_hash: String,
    /// Every function summary, as `(file, function, summary)`.
    pub summaries: Vec<(String, String, FunctionSummary)>,
    /// Every file's findings, in the order the pass produced them.
    pub findings: BTreeMap<String, Vec<Finding>>,
}

impl RuleState {
    /// The summaries as `resolve_summaries_incremental` reads them.
    pub fn previous_summaries(&self) -> BTreeMap<NodeKey, Arc<FunctionSummary>> {
        self.summaries
            .iter()
            .map(|(f, n, s)| ((f.clone(), n.clone()), Arc::new(s.clone())))
            .collect()
    }
}

/// The cache of one language's taint pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintCache {
    pub format: u32,
    pub key: CacheKey,
    pub files: BTreeMap<String, FileState>,
    /// By rule id.
    pub rules: BTreeMap<String, RuleState>,
}

impl TaintCache {
    /// An empty cache for `key`.
    pub fn new(key: CacheKey) -> Self {
        TaintCache {
            format: FORMAT,
            key,
            files: BTreeMap::new(),
            rules: BTreeMap::new(),
        }
    }

    /// The cache file of `language` in `dir`.
    pub fn path(dir: &Path, language: &str) -> PathBuf {
        dir.join(format!("taint-{language}.json.gz"))
    }

    /// The previous cache, when it exists, reads, and was written by the
    /// same engine for the same language; otherwise why it cannot be used
    /// (full scan).
    pub fn load(path: &Path, key: &CacheKey) -> Result<Self, CacheMiss> {
        let cache: TaintCache = read_cache_file(path)?;
        check_cache(cache.format, &cache.key, key)?;
        Ok(cache)
    }

    /// Writes the cache atomically (temporary file, then rename): an
    /// interrupted scan leaves the previous cache or none, never half of one.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        write_gz_json(path, self)
    }

    /// The files whose text or dependencies changed since this cache, among
    /// `current` (new files included).
    pub fn dirty_files(&self, current: &BTreeMap<String, FileState>) -> BTreeSet<String> {
        current
            .iter()
            .filter(|(path, state)| self.files.get(*path) != Some(state))
            .map(|(path, _)| path.clone())
            .collect()
    }
}

/// One file of the pattern pass (phase B) as computed by the previous run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatternFileState {
    /// SHA-256 of the file's bytes.
    pub hash: String,
    /// `file_contains::governance_fingerprint` of the file: which
    /// governance files (`not_path_has_file`) exist around it.
    pub governance: String,
    /// The rules' findings before suppressions, as `(index of the rule in
    /// the loaded rules, finding)`; valid because the whole cache is
    /// dropped when the loaded rules change.
    pub findings: Vec<(usize, crate::scan::engine::Finding)>,
}

/// The cache of the pattern pass. A pattern rule only reads its own file
/// and the existence of governance files, both in each file's key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternCache {
    pub format: u32,
    pub key: CacheKey,
    /// SHA-256 of every loaded rule, in order.
    pub rules_hash: String,
    pub files: BTreeMap<String, PatternFileState>,
}

impl PatternCache {
    /// An empty cache for `key` and `rules_hash`.
    pub fn new(key: CacheKey, rules_hash: String) -> Self {
        PatternCache {
            format: FORMAT,
            key,
            rules_hash,
            files: BTreeMap::new(),
        }
    }

    /// The cache file in `dir`.
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("patterns.json.gz")
    }

    /// The previous cache when it was written by the same engine, for the
    /// same language and the same rules; otherwise why it cannot be used.
    pub fn load(path: &Path, key: &CacheKey, rules_hash: &str) -> Result<Self, CacheMiss> {
        let cache: PatternCache = read_cache_file(path)?;
        check_cache(cache.format, &cache.key, key)?;
        if cache.rules_hash != rules_hash {
            return Err(CacheMiss::Rules);
        }
        Ok(cache)
    }

    /// Writes the cache atomically.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        write_gz_json(path, self)
    }
}

/// Whether `name` has the shape of an engine cache folder produced by
/// [`CacheKey::engine_dir`] — `<version>-<8 hex>`, ending in a dash and
/// exactly eight hexadecimal characters (the short SHA-256 of the engine
/// key). The prune only ever deletes folders of this shape: a defence in
/// depth on top of [`escapes_project_via_symlink`], so that even a cache
/// directory holding unrelated folders (an explicit `--data-dir` pointed
/// at a populated directory, say) can never have them removed by a scan.
fn looks_like_engine_dir(name: &str) -> bool {
    match name.rsplit_once('-') {
        Some((_, suffix)) => suffix.len() == 8 && suffix.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

/// Whether reaching `base` from `project_root` crosses a symbolic link on
/// a component inside the project. A scanned project is untrusted and may
/// ship `audit-reports/audit-datas/cache` — or any ancestor of it — as a
/// link to a directory outside itself; following it would make the engine
/// create and, through the prune, `remove_dir_all` the cache *there*,
/// deleting unrelated directories. `symlink_metadata` does not resolve the
/// final component, so a link is seen as a link; a component that does not
/// exist yet (the `cache` folder about to be created) is not a link and is
/// fine. `base` outside `project_root` (an explicit `--data-dir`) is the
/// operator's choice and is not inspected.
fn escapes_project_via_symlink(project_root: &Path, base: &Path) -> bool {
    let Ok(rel) = base.strip_prefix(project_root) else {
        return false;
    };
    let mut cur = project_root.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        if std::fs::symlink_metadata(&cur).is_ok_and(|m| m.file_type().is_symlink()) {
            return true;
        }
    }
    false
}

/// Removes the engine folders of `base` used least recently, keeping
/// `current` and the `KEPT_ENGINE_DIRS - 1` others last used most
/// recently. "Last used" is the date of the folder's `LAST_USED_FILE`; a
/// folder without one (written before that file existed) counts as the
/// oldest. Errors are ignored: a folder left behind only costs disk space.
///
/// Only folders shaped like an engine cache dir ([`looks_like_engine_dir`])
/// and that are real directories (not symlinks, excluded through
/// `symlink_metadata`) are ever considered for removal — anything else in
/// `base` is left untouched.
fn prune_engine_dirs(base: &Path, current: &Path) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    let last_used = |dir: &Path| {
        std::fs::metadata(dir.join(LAST_USED_FILE))
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH)
    };
    let mut others: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p != current
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(looks_like_engine_dir)
                // A real directory, not a symlink: `symlink_metadata` does
                // not follow the link, so `is_dir()` is false for one.
                && std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_dir())
        })
        .map(|p| (last_used(&p), p))
        .collect();
    others.sort_by_key(|(used, _)| std::cmp::Reverse(*used));
    for (_, dir) in others.into_iter().skip(KEPT_ENGINE_DIRS.saturating_sub(1)) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Removes the cache files written directly in `base` before each engine
/// had its own folder (the layout of the morning of 2026-11-14): they are
/// never read again.
fn remove_files_of_the_old_layout(base: &Path) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for path in entries.flatten().map(|e| e.path()) {
        let old_cache_file = path.is_file()
            && path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().ends_with(".json.gz"));
        if old_cache_file {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Largest decompressed cache accepted, a bound against a decompression
/// bomb: the cache sits under the scanned (untrusted) project, so a crafted
/// `.json.gz` could otherwise expand without limit and exhaust memory.
/// Planting one is hard — the engine folder's name is keyed to the running
/// binary — so this is defence in depth. 1 GiB is far above any real cache
/// yet stops an unbounded expansion; a cache over the bound is ignored and
/// the scan is simply a full one.
const MAX_CACHE_DECOMPRESSED: u64 = 1 << 30;

/// Why a pass could not reuse the previous cache at all and analysed
/// every file again, for its console line (ticket #204): without it, the
/// line read as if every file had changed since the last scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum CacheMiss {
    /// No cache file: the first scan of the project by this engine build
    /// (each build has its own folder, see `CacheKey::engine_dir`).
    Missing,
    /// A cache file that cannot be read: damaged, over the size bound, or
    /// of a layout this engine cannot decode.
    Unreadable,
    /// A cache file written with another `FORMAT`.
    Format,
    /// A cache written by another engine build. Each build has its own
    /// folder, so this only happens with a folder copied by hand.
    Engine,
    /// A cache written for another report language: the rule messages it
    /// holds are in that language.
    Language { previous: String, current: String },
    /// Pattern pass only: the loaded rules changed.
    Rules,
}

/// Reads the cache file at `path`, telling a missing file from one that
/// cannot be read.
fn read_cache_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, CacheMiss> {
    if !path.exists() {
        return Err(CacheMiss::Missing);
    }
    read_gz_json(path).ok_or(CacheMiss::Unreadable)
}

/// Whether a cache of `format` written under `found` can serve the scan
/// whose key is `expected`.
fn check_cache(format: u32, found: &CacheKey, expected: &CacheKey) -> Result<(), CacheMiss> {
    if format != FORMAT {
        return Err(CacheMiss::Format);
    }
    if found.engine != expected.engine {
        return Err(CacheMiss::Engine);
    }
    if found.lang != expected.lang {
        return Err(CacheMiss::Language {
            previous: found.lang.clone(),
            current: expected.lang.clone(),
        });
    }
    Ok(())
}

fn read_gz_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let file = std::fs::File::open(path).ok()?;
    // Read one byte past the cap so an over-the-cap stream is detected
    // rather than silently truncated into a shorter, parseable-looking one.
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(file)
        .take(MAX_CACHE_DECOMPRESSED + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_CACHE_DECOMPRESSED {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// Temporary file, then rename: an interrupted scan leaves the previous
/// cache or none, never half of one.
fn write_gz_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let file = std::fs::File::create(&tmp)?;
        let mut gz = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        gz.write_all(&serde_json::to_vec(value).map_err(std::io::Error::other)?)?;
        gz.finish()?;
    }
    std::fs::rename(&tmp, path)
}

/// How much of one language's taint pass was redone, for the scan's
/// console line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacheStat {
    /// `python`, … for a taint pass; `patterns` for the pattern pass.
    pub language: String,
    /// Files of the language.
    pub files: usize,
    /// Files whose text or dependencies changed.
    pub dirty: usize,
    /// (rule, file) analyses run, over the total.
    pub analysed: usize,
    pub total: usize,
    /// Why the previous cache was not used at all, `None` when it was:
    /// every file was then analysed again for that reason, not because it
    /// changed.
    pub full: Option<CacheMiss>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_round_trip_and_key_check() {
        let dir = std::env::temp_dir().join(format!("sca-cache-{}", std::process::id()));
        let key = CacheKey {
            engine: "e1".to_string(),
            lang: "fr".to_string(),
        };
        let mut cache = TaintCache::new(key.clone());
        cache.files.insert(
            "a.py".to_string(),
            FileState {
                hash: sha256_hex(b"x"),
                deps: sha256_hex(b""),
            },
        );
        cache.rules.insert("r".to_string(), RuleState::default());
        let path = TaintCache::path(&dir, "python");
        cache.save(&path).unwrap();
        let back = TaintCache::load(&path, &key).unwrap();
        assert_eq!(back.files, cache.files);
        let other = CacheKey {
            engine: "e2".to_string(),
            lang: "fr".to_string(),
        };
        assert_eq!(
            TaintCache::load(&path, &other).unwrap_err(),
            CacheMiss::Engine,
            "another engine: full scan"
        );
        let english = CacheKey {
            engine: "e1".to_string(),
            lang: "en".to_string(),
        };
        assert_eq!(
            TaintCache::load(&path, &english).unwrap_err(),
            CacheMiss::Language {
                previous: "fr".to_string(),
                current: "en".to_string()
            },
            "another language: full scan, named"
        );
        std::fs::write(&path, b"garbage").unwrap();
        assert_eq!(
            TaintCache::load(&path, &key).unwrap_err(),
            CacheMiss::Unreadable,
            "unreadable: full scan"
        );
        assert_eq!(
            TaintCache::load(&dir.join("none.json.gz"), &key).unwrap_err(),
            CacheMiss::Missing,
            "no cache yet: full scan"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    fn key(engine: &str) -> CacheKey {
        CacheKey {
            engine: engine.to_string(),
            lang: "fr".to_string(),
        }
    }

    /// Creates the folder of `engine` in `base`, last used `seconds` after
    /// the epoch (an explicit date: no sleep, no reliance on the file
    /// system's time resolution).
    fn engine_dir_used_at(base: &Path, engine: &str, seconds: u64) -> PathBuf {
        let dir = key(engine).engine_dir(base);
        std::fs::create_dir_all(&dir).unwrap();
        let marker = std::fs::File::create(dir.join(LAST_USED_FILE)).unwrap();
        marker
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds))
            .unwrap();
        dir
    }

    #[test]
    fn test_each_binary_has_its_own_folder() {
        let base = Path::new("/cache");
        let a = key("a").engine_dir(base);
        assert_ne!(a, key("b").engine_dir(base), "two binaries, two folders");
        assert_eq!(a, key("a").engine_dir(base), "same binary, same folder");
        let name = a.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with(&crate::BUILD_VERSION[..5]), "{name}");
    }

    #[test]
    fn test_prune_keeps_the_folders_last_used_most_recently() {
        let base = std::env::temp_dir().join(format!("sca-prune-{}", std::process::id()));
        let oldest = engine_dir_used_at(&base, "e1", 1_000);
        let old = engine_dir_used_at(&base, "e2", 2_000);
        let recent = engine_dir_used_at(&base, "e3", 3_000);
        let newest = engine_dir_used_at(&base, "e4", 4_000);
        let current = engine_dir_used_at(&base, "e5", 5_000);
        prune_engine_dirs(&base, &current);
        let kept: Vec<bool> = [&oldest, &old, &recent, &newest, &current]
            .iter()
            .map(|d| d.exists())
            .collect();
        // KEPT_ENGINE_DIRS = 3: the current folder and the 2 others last used.
        assert_eq!(kept, vec![false, false, true, true, true]);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn test_a_folder_reread_without_being_rewritten_is_still_kept() {
        // The folder itself has not changed for long (its cache was only
        // reread), but its marker says it was used last: it must stay.
        let base = std::env::temp_dir().join(format!("sca-reread-{}", std::process::id()));
        let daily = engine_dir_used_at(&base, "daily", 9_000);
        std::fs::File::open(&daily)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(10))
            .unwrap();
        let other = engine_dir_used_at(&base, "other", 5_000);
        let older = engine_dir_used_at(&base, "older", 4_000);
        let current = engine_dir_used_at(&base, "current", 9_500);
        prune_engine_dirs(&base, &current);
        assert!(
            daily.exists(),
            "used last, kept despite its old folder date"
        );
        assert!(other.exists());
        assert!(!older.exists());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn test_prepare_marks_the_folder_and_removes_the_old_layout() {
        let base = std::env::temp_dir().join(format!("sca-prepare-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("taint-python.json.gz"), b"old layout").unwrap();
        // `project_root = base`: the guard sees no component under the root
        // (`base` itself), so nothing is treated as a planted symlink.
        let context = CacheContext::prepare(&base, "fr", &base).unwrap();
        assert!(context.dir.join(LAST_USED_FILE).is_file());
        assert!(!base.join("taint-python.json.gz").exists());
        std::fs::remove_dir_all(&base).ok();
    }

    /// Security regression (2026-11-15): a scanned project is untrusted and
    /// could ship its cache path as a symlink to an external directory. The
    /// prune's `remove_dir_all` would then delete directories *outside* the
    /// project. `prepare` must refuse such a cache and touch nothing
    /// outside. Without the guard, `prepare` followed the link, created a
    /// folder in `outside` and pruned the data dirs there.
    #[cfg(unix)]
    #[test]
    fn test_prepare_refuses_a_cache_reached_through_a_symlink() {
        use std::os::unix::fs::symlink;
        let tmp = std::env::temp_dir().join(format!("sca-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let project = tmp.join("project");
        let outside = tmp.join("outside");
        std::fs::create_dir_all(project.join("audit-datas")).unwrap();
        // Enough directories in `outside` that the unguarded prune (keeping
        // only KEPT_ENGINE_DIRS) would have deleted some of them.
        for i in 0..4 {
            let d = outside.join(format!("data{i}"));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("keep.txt"), b"keep").unwrap();
        }
        // The malicious repo: `cache` is a link to the external directory.
        let cache = project.join("audit-datas").join("cache");
        symlink(&outside, &cache).unwrap();

        let context = CacheContext::prepare(&cache, "en", &project);

        assert!(context.is_none(), "a symlinked cache path is refused");
        for i in 0..4 {
            assert!(
                outside.join(format!("data{i}")).join("keep.txt").exists(),
                "nothing outside the scanned project is created or deleted"
            );
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Security regression (2026-11-15): the prune must only ever delete
    /// folders shaped like an engine cache dir (`<version>-<8 hex>`). A
    /// neighbour that is not one — even the oldest entry, which the
    /// date-only prune would have removed first — is spared.
    #[test]
    fn test_prune_spares_folders_that_are_not_engine_dirs() {
        let base = std::env::temp_dir().join(format!("sca-prune-shape-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        engine_dir_used_at(&base, "e1", 2_000);
        engine_dir_used_at(&base, "e2", 3_000);
        let current = engine_dir_used_at(&base, "e3", 4_000);
        // Not shaped like an engine dir, and the oldest of all.
        let neighbour = base.join("important-data");
        std::fs::create_dir_all(&neighbour).unwrap();
        std::fs::File::create(neighbour.join(LAST_USED_FILE))
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
            .unwrap();

        prune_engine_dirs(&base, &current);

        assert!(
            neighbour.exists(),
            "a folder not shaped like an engine dir is never pruned"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn test_dirty_files_lists_new_and_changed() {
        let state = |h: &str| FileState {
            hash: h.to_string(),
            deps: String::new(),
        };
        let mut cache = TaintCache::new(CacheKey::current("en"));
        cache.files.insert("same.py".to_string(), state("1"));
        cache.files.insert("edited.py".to_string(), state("1"));
        let current = BTreeMap::from([
            ("same.py".to_string(), state("1")),
            ("edited.py".to_string(), state("2")),
            ("new.py".to_string(), state("3")),
        ]);
        let dirty: Vec<String> = cache.dirty_files(&current).into_iter().collect();
        assert_eq!(dirty, vec!["edited.py".to_string(), "new.py".to_string()]);
    }
}
