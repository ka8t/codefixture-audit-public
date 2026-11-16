//! Rule pack file format (ADR-0037, simplified by ADR-0040, version
//! rules added by ADR-0043): how a catalog travels as one file,
//! `rules.scapack`, and is opened at run time.
//!
//! Layout of a `.scapack` file (format 2):
//!
//! ```text
//! b"SCAPACK2" | header length (u32, little endian) | header (JSON)
//!             | rules section | version rules section (optional)
//! ```
//!
//! - The header is clear JSON: format version, pack name, number of rule
//!   files, the fingerprint of the key that opens the pack and the byte
//!   length of each section.
//! - The **rules section** is the JSON list of `[relative path, .sca
//!   source]` pairs, sorted by path, encrypted with ChaCha20-Poly1305 and
//!   the public demo key.
//! - The **version rules section** (ADR-0043) holds the published
//!   vulnerabilities the dependencies are checked against: package,
//!   ecosystem, affected versions, CVE ids. Its content is an advisory
//!   container (`advisories.sadb` layout, `project::advisory_file`), kept
//!   as bytes here: this module neither compresses nor reads it, so
//!   `build.rs` only copies the editor's file into the pack. Encrypted
//!   apart from the rules, so a scan decrypts it only when its
//!   dependencies phase runs: the full catalog's copy weighs tens of
//!   megabytes. Length 0 when the pack carries none.
//! - Each section is authenticated with the header bytes and its own
//!   name as associated data: changing the header, or swapping the two
//!   sections, makes decryption fail.
//! - Each nonce is derived from the header, the section name and its
//!   content (ADR-0040), not drawn at random: the same rules always give
//!   the same file, so an unchanged catalog leaves the shared repository
//!   unchanged.
//!
//! Format 1 (`SCAPACK1`, rules only) is refused with a message saying to
//! rebuild the pack: a binary and its pack are always delivered together.
//!
//! The demo key is written in the source: the encryption only keeps the
//! rules from being copied as they are, it protects nothing (ADR-0040).
//!
//! Shared with `build.rs` (included there with `#[path]`), which writes
//! the pack of `rules/builtin` next to the compiled binary: this module
//! only uses `super::rules_crypto`, `serde_json`, `sha2` and `std`.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::rules_crypto;

/// File extension of a rule pack, without the dot.
pub const PACK_EXTENSION: &str = "scapack";

/// File name of the catalog pack, next to the binary (ADR-0040).
pub const PACK_FILE_NAME: &str = "rules.scapack";

/// File name of the demo pack a private-repository build writes next to
/// the binary, beside the full one (ticket #153). The export script
/// delivers the same content as the shared repository's
/// `rules/rules.scapack`; the binary itself never reads this file.
pub const DEMO_PACK_FILE_NAME: &str = "rules-demo.scapack";

/// Name stored in the header of the demo pack.
pub const DEMO_PACK_NAME: &str = "demo";

/// Version rules of the full catalog (ADR-0043): the editor's advisory
/// database, at the root of the private repository, written by
/// `codefixture-audit-advisories update` and never committed nor delivered.
pub const FULL_VERSION_RULES_FILE: &str = "advisories.sadb";

/// Version rules of the demo pack (ADR-0043), relative to the rules
/// folder: a small selection of well-known vulnerabilities, committed,
/// written by `codefixture-audit-advisories demo` from the editor's database.
pub const DEMO_VERSION_RULES_FILE: &str = "advisories/demo.sadb";

/// Magic bytes at the start of every pack, version included: a future
/// incompatible layout gets a new magic rather than a guess.
const MAGIC: &[u8; 8] = b"SCAPACK2";

/// Magic of format 1 (ADR-0040, rules only), recognised to name it.
const MAGIC_V1: &[u8; 8] = b"SCAPACK1";

/// Version written in the header's `format` field.
const FORMAT_VERSION: u64 = 2;

/// Upper bound on the clear header, so a corrupt length cannot make the
/// reader allocate or slice past a sane size.
const MAX_HEADER_LEN: usize = 64 * 1024;

/// Associated-data names of the two sections.
const RULES_SECTION: &[u8] = b"rules";
const VERSION_RULES_SECTION: &[u8] = b"version_rules";

/// Nonce (12 bytes) and authentication tag (16 bytes) around each
/// encrypted section (`rules_crypto::encrypt_bytes_with_aad_and_nonce`).
const SECTION_OVERHEAD: usize = 12 + 16;

/// One rule file of a pack: path relative to the catalog root (for
/// example `python/security/eval.sca`) and its `.sca` source.
pub type RuleSource = (String, String);

/// Clear header of a pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackHeader {
    /// Pack name, for messages (`builtin`, `demo`…).
    pub name: String,
    /// Fingerprint of the key that opens the pack ([`key_fingerprint`]).
    pub key_fingerprint: String,
    /// Number of rule files in the rules section.
    pub rule_files: usize,
    /// Encrypted length of the rules section.
    pub rules_bytes: usize,
    /// Encrypted length of the version rules section, 0 without one.
    pub version_rules_bytes: usize,
}

impl PackHeader {
    /// Whether the pack carries version rules (ADR-0043).
    pub fn has_version_rules(&self) -> bool {
        self.version_rules_bytes > 0
    }
}

/// The public demo key (ADR-0037, ADR-0040): written in the source on
/// purpose, it opens every pack.
pub fn demo_key() -> [u8; 32] {
    rules_crypto::derive_key(
        rules_crypto::CATALOG_ROOT_SECRET,
        rules_crypto::SALT_DEMO_UNIVERSAL,
        rules_crypto::DEFAULT_INFO,
    )
}

/// Short public identifier of a key: the first 8 bytes of a domain
/// separated SHA-256, in hex (16 characters). It names the key in a pack
/// header without revealing it.
pub fn key_fingerprint(key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"codefixture-audit-key-fingerprint-v1");
    hasher.update(key);
    hasher.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Builds a pack holding `files` (sorted here by relative path, so the
/// result does not depend on the caller's order) and, when given, the
/// version rules `version_rules` (an advisory container, stored as it
/// is), encrypted with the demo key. Deterministic: the same name, files
/// and version rules give the same bytes.
pub fn write_pack(name: &str, files: &[RuleSource], version_rules: Option<&[u8]>) -> Vec<u8> {
    write_pack_with_key(name, files, version_rules, &demo_key())
}

/// [`write_pack`] with another key: only the tests use it, to check that
/// a pack for an unknown key is refused.
pub fn write_pack_with_key(
    name: &str,
    files: &[RuleSource],
    version_rules: Option<&[u8]>,
    key: &[u8; 32],
) -> Vec<u8> {
    let mut sorted: Vec<&RuleSource> = files.iter().collect();
    sorted.sort();
    let rules_plain = serde_json::to_vec(&sorted).expect("JSON payload");
    // An empty container is no version rules at all.
    let version_plain = version_rules.filter(|bytes| !bytes.is_empty());
    let rules_bytes = rules_plain.len() + SECTION_OVERHEAD;
    let version_rules_bytes = version_plain.map_or(0, |v| v.len() + SECTION_OVERHEAD);
    // Written by hand, keys in alphabetical order: `serde_json::json!`
    // orders keys by insertion or alphabetically depending on the
    // `preserve_order` feature, which differs between `build.rs` and the
    // binary (ticket #153). The bytes must not depend on it: the build's
    // `rules-demo.scapack` and `rules pack --demo` must be identical.
    let header_bytes = format!(
        "{{\"format\":{FORMAT_VERSION},\"key_fingerprint\":{},\"name\":{},\"rule_files\":{},\"rules_bytes\":{rules_bytes},\"version_rules_bytes\":{version_rules_bytes}}}",
        serde_json::Value::from(key_fingerprint(key)),
        serde_json::Value::from(name),
        sorted.len()
    )
    .into_bytes();

    let mut out = Vec::with_capacity(MAGIC.len() + 4 + header_bytes.len() + rules_bytes + version_rules_bytes);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&seal(&header_bytes, RULES_SECTION, &rules_plain, key));
    if let Some(plain) = version_plain {
        out.extend_from_slice(&seal(&header_bytes, VERSION_RULES_SECTION, plain, key));
    }
    out
}

/// Encrypts one section. The associated data is the header followed by
/// the section name; the nonce is derived from both and the content, so
/// it changes whenever any of them changes and never repeats for two
/// different plaintexts.
fn seal(header_bytes: &[u8], section: &[u8], plain: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let aad = [header_bytes, section].concat();
    let mut hasher = Sha256::new();
    hasher.update(b"codefixture-audit-pack-nonce-v2");
    hasher.update((aad.len() as u64).to_le_bytes());
    hasher.update(&aad);
    hasher.update(plain);
    let nonce: [u8; 12] = hasher.finalize()[..12].try_into().expect("12 bytes");
    rules_crypto::encrypt_bytes_with_aad_and_nonce(plain, &aad, key, &nonce)
}

/// Decrypts one section with the demo key, `Err` naming the pack as
/// corrupt when authentication fails.
fn open_section(header_bytes: &[u8], section: &[u8], blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let aad = [header_bytes, section].concat();
    rules_crypto::decrypt_bytes_with_aad(blob, &aad, key).ok_or_else(|| "rule pack is corrupt or was altered".to_string())
}

/// A pack split into its parts: header, raw header bytes (the associated
/// data of both sections) and the two encrypted sections.
struct PackParts<'a> {
    header: PackHeader,
    header_bytes: &'a [u8],
    rules: &'a [u8],
    version_rules: &'a [u8],
}

/// Parses the clear header at the start of `bytes` (magic, length,
/// JSON): the header and the offset where the sections start. Only the
/// first bytes of a pack are needed, so a scan can tell whether a pack
/// carries version rules without reading or decrypting it.
fn parse_header(bytes: &[u8]) -> Result<(PackHeader, usize), String> {
    if bytes.starts_with(MAGIC_V1) {
        return Err("rule pack in format 1, which this engine no longer reads: rebuild it (ADR-0043)".to_string());
    }
    let rest = bytes
        .strip_prefix(MAGIC.as_slice())
        .ok_or_else(|| "not a rule pack (unknown file signature)".to_string())?;
    if rest.len() < 4 {
        return Err("truncated rule pack (no header length)".to_string());
    }
    let (len_bytes, rest) = rest.split_at(4);
    let header_len = u32::from_le_bytes(len_bytes.try_into().expect("4 bytes")) as usize;
    if header_len > MAX_HEADER_LEN || header_len > rest.len() {
        return Err("truncated rule pack (header)".to_string());
    }
    let header: serde_json::Value = serde_json::from_slice(&rest[..header_len])
        .map_err(|e| format!("invalid rule pack header: {e}"))?;
    let format = header.get("format").and_then(|v| v.as_u64());
    if format != Some(FORMAT_VERSION) {
        return Err(format!(
            "unsupported rule pack format {format:?}, expected {FORMAT_VERSION}"
        ));
    }
    let text = |key: &str| {
        header
            .get(key)
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| format!("invalid rule pack header: missing \"{key}\""))
    };
    let number = |key: &str| {
        header
            .get(key)
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .ok_or_else(|| format!("invalid rule pack header: missing \"{key}\""))
    };
    let parsed = PackHeader {
        name: text("name")?,
        key_fingerprint: text("key_fingerprint")?,
        rule_files: number("rule_files")?,
        rules_bytes: number("rules_bytes")?,
        version_rules_bytes: number("version_rules_bytes")?,
    };
    Ok((parsed, MAGIC.len() + 4 + header_len))
}

/// Splits a pack into its parts. `Err` with a short reason if the file is
/// not a pack, is truncated, or is in a format this engine does not read.
fn split_pack(bytes: &[u8]) -> Result<PackParts<'_>, String> {
    let (parsed, body_start) = parse_header(bytes)?;
    let header_bytes = &bytes[MAGIC.len() + 4..body_start];
    let body = &bytes[body_start..];
    // The two sections fill the rest of the file exactly.
    if parsed.rules_bytes.checked_add(parsed.version_rules_bytes) != Some(body.len()) {
        return Err("truncated rule pack (sections)".to_string());
    }
    let (rules, version_rules) = body.split_at(parsed.rules_bytes);
    Ok(PackParts {
        header: parsed,
        header_bytes,
        rules,
        version_rules,
    })
}

/// Checks that the pack is meant for the demo key, the only one this
/// engine has.
fn demo_key_for(header: &PackHeader) -> Result<[u8; 32], String> {
    let key = demo_key();
    if header.key_fingerprint != key_fingerprint(&key) {
        return Err(format!(
            "rule pack needs key {}, this engine only has the demo key {} (ADR-0040)",
            header.key_fingerprint,
            key_fingerprint(&key)
        ));
    }
    Ok(key)
}

/// Reads only the clear header of a pack, without decrypting it.
pub fn read_header(bytes: &[u8]) -> Result<PackHeader, String> {
    split_pack(bytes).map(|parts| parts.header)
}

/// Reads the clear header of the pack file at `path` from its first
/// bytes only: what a scan checks before deciding whether its
/// dependencies phase runs (ADR-0043). The sections are not read, so a
/// truncated pack is only reported when it is opened.
pub fn read_header_from_file(path: &Path) -> Result<PackHeader, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("unreadable rule pack: {e}"))?;
    let mut prefix = Vec::new();
    file.take((MAGIC.len() + 4 + MAX_HEADER_LEN) as u64)
        .read_to_end(&mut prefix)
        .map_err(|e| format!("unreadable rule pack: {e}"))?;
    parse_header(&prefix).map(|(header, _)| header)
}

/// Opens the rules section of a pack with the demo key: its header and
/// its rule files. `Err` if the file is not a valid pack, if it needs
/// another key (a client pack of ADR-0037), or if any byte of the header
/// or of the section was altered. The version rules are not decrypted.
pub fn open_pack(bytes: &[u8]) -> Result<(PackHeader, Vec<RuleSource>), String> {
    let parts = split_pack(bytes)?;
    let key = demo_key_for(&parts.header)?;
    let plain = open_section(parts.header_bytes, RULES_SECTION, parts.rules, &key)?;
    let files: Vec<RuleSource> =
        serde_json::from_slice(&plain).map_err(|e| format!("invalid rule pack content: {e}"))?;
    if files.len() != parts.header.rule_files {
        return Err("rule pack content does not match its header".to_string());
    }
    Ok((parts.header, files))
}

/// Decrypts the version rules section of a pack (ADR-0043): the bytes of
/// its advisory container, `Ok(None)` when the pack carries none.
pub fn open_version_rules(bytes: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let parts = split_pack(bytes)?;
    if !parts.header.has_version_rules() {
        return Ok(None);
    }
    let key = demo_key_for(&parts.header)?;
    open_section(parts.header_bytes, VERSION_RULES_SECTION, parts.version_rules, &key).map(Some)
}

/// Every `.sca` file under `root`, as `(path relative to root with `/`
/// separators, source)` pairs sorted by path. Used by `build.rs` to pack
/// `rules/builtin` and by `codefixture-audit rules pack`. A missing `root` gives
/// an empty list; an unreadable file is an error naming it.
pub fn collect_sca_sources(root: &Path) -> Result<Vec<RuleSource>, String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<RuleSource>) -> Result<(), String> {
        let Ok(read_dir) = std::fs::read_dir(dir) else {
            return Ok(());
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            // Like the scan walk (ticket #147): a symbolic link to a
            // folder is not followed.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                walk(root, &path, out)?;
            } else if file_type.is_file()
                && path.extension().and_then(|e| e.to_str()) == Some("sca")
            {
                let rel = path
                    .strip_prefix(root)
                    .expect("the file comes from root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                out.push((rel, content));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort();
    Ok(out)
}

/// Whether a `.sca` source is a demo rule: one of its lines is
/// `demo_fallback true` (the `requires` block, `src/scan/parser`), the
/// value compared like the parser does (trimmed, case-insensitive).
///
/// A line check rather than the parser, because `build.rs` shares this
/// module and cannot pull the parser in. A test compares this check with
/// the parser on every file of `rules/builtin`, so the two cannot drift
/// apart unnoticed (ticket #153).
pub fn is_demo_rule(source: &str) -> bool {
    source.lines().any(|line| {
        let mut words = line.split_whitespace();
        words.next() == Some("demo_fallback")
            && words
                .next()
                .is_some_and(|value| value.trim_matches('"').eq_ignore_ascii_case("true"))
    })
}

/// The demo rules of a catalog (ticket #153): the only selection of what
/// the shared repository receives, used by `build.rs` for
/// `rules-demo.scapack` and by `codefixture-audit rules pack --demo` for the
/// export, so both give the same pack byte for byte.
pub fn demo_sources(files: &[RuleSource]) -> Vec<RuleSource> {
    files
        .iter()
        .filter(|(_, content)| is_demo_rule(content))
        .cloned()
        .collect()
}

/// Hex SHA-256 of a rule file's source: what `rules diff` and
/// `rules list` compare and print (ADR-0040).
pub fn source_sha256(content: &str) -> String {
    Sha256::digest(content.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Differences between two sets of rule files, by relative path
/// (ADR-0040): what `rules diff` prints.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RuleDiff {
    /// In the second set only (for `rules diff <pack> <folder>`: in the
    /// folder, missing from the pack).
    pub added: Vec<String>,
    /// In the first set only (in the pack, gone from the folder).
    pub removed: Vec<String>,
    /// In both, with a different source.
    pub modified: Vec<String>,
    /// In both, identical.
    pub unchanged: usize,
}

impl RuleDiff {
    /// Whether both sets hold exactly the same rule files.
    pub fn is_identical(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }
}

/// Compares `before` (a pack's files) with `after` (a folder's files),
/// each path listed once in sorted order. Sources are compared by their
/// SHA-256, the value `rules list` prints.
pub fn diff_rule_sources(before: &[RuleSource], after: &[RuleSource]) -> RuleDiff {
    use std::collections::BTreeMap;
    let index = |files: &[RuleSource]| -> BTreeMap<String, String> {
        files
            .iter()
            .map(|(rel, content)| (rel.clone(), source_sha256(content)))
            .collect()
    };
    let (old, new) = (index(before), index(after));
    let mut diff = RuleDiff::default();
    for (rel, hash) in &old {
        match new.get(rel) {
            None => diff.removed.push(rel.clone()),
            Some(other) if other != hash => diff.modified.push(rel.clone()),
            Some(_) => diff.unchanged += 1,
        }
    }
    diff.added = new
        .keys()
        .filter(|rel| !old.contains_key(*rel))
        .cloned()
        .collect();
    diff
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<RuleSource> {
        vec![
            ("python/b.sca".to_string(), "rule b\nend\n".to_string()),
            ("java/a.sca".to_string(), "rule a\nend\n".to_string()),
        ]
    }

    #[test]
    fn test_pack_round_trip_sorts_files_and_keeps_header() {
        let pack = write_pack("demo", &sample(), None);
        let (header, files) = open_pack(&pack).expect("pack opens with the demo key");
        assert_eq!(header.name, "demo");
        assert_eq!(header.rule_files, 2);
        assert_eq!(header.key_fingerprint, key_fingerprint(&demo_key()));
        let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, ["java/a.sca", "python/b.sca"]);
        let header_only = read_header(&pack).expect("header readable without key");
        assert_eq!(header_only, header);
    }

    #[test]
    fn test_pack_payload_is_not_readable_in_clear() {
        let pack = write_pack("demo", &sample(), None);
        let text = String::from_utf8_lossy(&pack);
        assert!(!text.contains("rule a"), "rule source must be encrypted");
    }

    /// ADR-0040: the same rules give the same bytes, whatever the order
    /// they are passed in; one changed character changes the pack.
    #[test]
    fn test_pack_is_deterministic_and_content_dependent() {
        let mut reversed = sample();
        reversed.reverse();
        assert_eq!(write_pack("demo", &sample(), None), write_pack("demo", &reversed, None));
        let mut changed = sample();
        changed[0].1.push(' ');
        assert_ne!(write_pack("demo", &sample(), None), write_pack("demo", &changed, None));
    }

    #[test]
    fn test_open_pack_rejects_other_key_corrupt_and_truncated() {
        let pack = write_pack("demo", &sample(), None);

        let other = write_pack_with_key("client", &sample(), None, &[7u8; 32]);
        assert!(open_pack(&other).unwrap_err().contains("needs key"));

        let mut corrupt = pack.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        assert!(open_pack(&corrupt).unwrap_err().contains("corrupt"));

        assert!(open_pack(&pack[..10]).unwrap_err().contains("truncated"));
        let not_a_pack = open_pack(b"rule x\nend\n");
        assert!(not_a_pack.unwrap_err().contains("not a rule pack"));
    }

    /// The header is authenticated: raising the declared rule count (same
    /// length, so the layout stays valid) breaks decryption.
    #[test]
    fn test_open_pack_rejects_altered_header() {
        let mut bytes = write_pack("demo", &sample(), None);
        let pos = bytes
            .windows(b"\"rule_files\":2".len())
            .position(|w| w == b"\"rule_files\":2")
            .expect("count in header");
        bytes[pos + b"\"rule_files\":".len()] = b'3';
        assert!(open_pack(&bytes).unwrap_err().contains("corrupt"));
    }

    /// A pack of format 1 (ADR-0040, signed ones of ADR-0037 included)
    /// is refused by name, with the way out.
    #[test]
    fn test_format_1_pack_is_refused_with_a_clear_reason() {
        let header = br#"{"format":1,"name":"x","key_fingerprint":"0","rule_files":0}"#;
        let mut bytes = MAGIC_V1.to_vec();
        bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
        bytes.extend_from_slice(header);
        let err = read_header(&bytes).unwrap_err();
        assert!(err.contains("format 1") && err.contains("rebuild"), "{err}");
    }

    /// Ticket #153: the header bytes are fixed (alphabetical keys, no
    /// space), whatever the `serde_json` features of the build.
    #[test]
    fn test_pack_header_bytes_are_fixed() {
        let pack = write_pack("de\"mo", &sample(), None);
        let len = u32::from_le_bytes(pack[8..12].try_into().unwrap()) as usize;
        let header = std::str::from_utf8(&pack[12..12 + len]).unwrap();
        let expected = format!(
            "{{\"format\":2,\"key_fingerprint\":\"{}\",\"name\":\"de\\\"mo\",\"rule_files\":2,\"rules_bytes\":{},\"version_rules_bytes\":0}}",
            key_fingerprint(&demo_key()),
            read_header(&pack).unwrap().rules_bytes
        );
        assert_eq!(header, expected);
        assert_eq!(read_header(&pack).unwrap().name, "de\"mo");
    }

    #[test]
    fn test_demo_sources_keep_demo_fallback_true_only() {
        let files = vec![
            (
                "a.sca".to_string(),
                "requires\n    demo_fallback  true\nend\n".to_string(),
            ),
            (
                "b.sca".to_string(),
                "requires\n    demo_fallback false\nend\n".to_string(),
            ),
            ("c.sca".to_string(), "rule c\nend\n".to_string()),
            ("d.sca".to_string(), "  demo_fallback TRUE\n".to_string()),
            ("e.sca".to_string(), "# demo_fallback true\n".to_string()),
        ];
        let paths: Vec<String> = demo_sources(&files).into_iter().map(|(p, _)| p).collect();
        assert_eq!(paths, ["a.sca", "d.sca"]);
    }

    #[test]
    fn test_key_fingerprint_is_stable_short_and_key_specific() {
        let a = key_fingerprint(&[1u8; 32]);
        let b = key_fingerprint(&[2u8; 32]);
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
        assert_eq!(a, key_fingerprint(&[1u8; 32]));
    }

    #[test]
    fn test_collect_sca_sources_sorted_relative_and_sca_only() {
        let root = std::env::temp_dir().join(format!("sast_pack_collect_{}", std::process::id()));
        std::fs::create_dir_all(root.join("python/security")).unwrap();
        std::fs::write(root.join("python/security/b.sca"), "b").unwrap();
        std::fs::write(root.join("a.sca"), "a").unwrap();
        std::fs::write(root.join("notes.md"), "x").unwrap();
        let files = collect_sca_sources(&root).unwrap();
        std::fs::remove_dir_all(&root).ok();
        let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, ["a.sca", "python/security/b.sca"]);
        let missing = collect_sca_sources(Path::new("/nonexistent/sast/rules")).unwrap();
        assert!(missing.is_empty());
    }

    #[test]
    fn test_diff_rule_sources_added_removed_modified() {
        let before = vec![
            ("a.sca".to_string(), "A".to_string()),
            ("b.sca".to_string(), "B".to_string()),
            ("c.sca".to_string(), "C".to_string()),
        ];
        let after = vec![
            ("a.sca".to_string(), "A".to_string()),
            ("b.sca".to_string(), "B2".to_string()),
            ("d.sca".to_string(), "D".to_string()),
        ];
        let diff = diff_rule_sources(&before, &after);
        assert_eq!(diff.added, ["d.sca"]);
        assert_eq!(diff.removed, ["c.sca"]);
        assert_eq!(diff.modified, ["b.sca"]);
        assert_eq!(diff.unchanged, 1);
        assert!(!diff.is_identical());
        assert!(diff_rule_sources(&before, &before).is_identical());
    }

    #[test]
    fn test_source_sha256_is_hex_of_the_source() {
        assert_eq!(
            source_sha256(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // --- version rules section (ADR-0043) ---

    #[test]
    fn test_version_rules_round_trip_apart_from_the_rules() {
        let container = b"SADB-container-bytes".to_vec();
        let pack = write_pack("builtin", &sample(), Some(&container));
        let header = read_header(&pack).unwrap();
        assert!(header.has_version_rules());
        assert_eq!(header.version_rules_bytes, container.len() + SECTION_OVERHEAD);
        assert_eq!(open_version_rules(&pack).unwrap(), Some(container));
        let (_, files) = open_pack(&pack).unwrap();
        assert_eq!(files.len(), 2, "rules unchanged by the second section");
        assert!(!String::from_utf8_lossy(&pack).contains("SADB-container"), "encrypted");
    }

    #[test]
    fn test_pack_without_version_rules_has_none() {
        for pack in [write_pack("demo", &sample(), None), write_pack("demo", &sample(), Some(b""))] {
            assert!(!read_header(&pack).unwrap().has_version_rules());
            assert_eq!(open_version_rules(&pack).unwrap(), None);
        }
        assert_eq!(write_pack("demo", &sample(), None), write_pack("demo", &sample(), Some(b"")));
    }

    #[test]
    fn test_version_rules_change_the_pack_deterministically() {
        let a = write_pack("demo", &sample(), Some(b"one"));
        assert_eq!(a, write_pack("demo", &sample(), Some(b"one")));
        assert_ne!(a, write_pack("demo", &sample(), Some(b"two")));
    }

    /// Each section is bound to its name and to the header: an altered
    /// byte, or a truncated section, is refused.
    #[test]
    fn test_version_rules_section_is_authenticated() {
        let pack = write_pack("demo", &sample(), Some(b"version rules"));
        let mut corrupt = pack.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        assert!(open_version_rules(&corrupt).unwrap_err().contains("corrupt"));
        assert!(open_pack(&corrupt).is_ok(), "the rules section is intact");
        assert!(open_version_rules(&pack[..pack.len() - 1]).unwrap_err().contains("truncated"));
    }
}
