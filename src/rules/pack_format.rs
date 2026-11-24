//! Rule pack file format (ADR-0037, simplified by ADR-0040, version
//! rules added by ADR-0043): how a catalog travels as one file,
//! `rules.cfpack`, and is opened at run time.
//!
//! Layout of a `.cfpack` file (format 2):
//!
//! ```text
//! b"CFPACK02" | header length (u32, little endian) | header (JSON)
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
//!   container (`advisories.cfdb` layout, `project::advisory_file`), kept
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
//! Packs of the former `.scapack` name (magic `SCAPACK1`, format 1 with
//! rules only, or `SCAPACK2`, the same layout as format 2) are refused
//! with a message saying to get or build a new pack (ADR-0049): a binary
//! and its pack are always delivered together, so no reader is kept for
//! a name the engine no longer writes.
//!
//! The demo key is written in the source: the encryption only keeps the
//! rules from being copied as they are, it protects nothing (ADR-0040).
//!
//! Shared with `build.rs` (included there with `#[path]`), which writes
//! the pack of `rules/builtin` next to the compiled binary: this module
//! only uses `super::rules_crypto`, `serde_json`, `sha2`, `std` and the
//! English console translation (`include_str!`, [`PackError`]).
//!
//! A pack or rule folder that cannot be read gives a [`PackError`]: a key
//! of the console translations (group `pack`) and the values of its
//! placeholders, translated when it is shown (ticket #280), like the rule
//! compiler's messages (`scan::parser::messages`, ticket #279). Before
//! ticket #280 the reasons were English strings whatever the console
//! language: « Règle ignorée (…) : unreadable rule file: … ».

use std::path::Path;
use std::sync::LazyLock;

use sha2::{Digest, Sha256};

use super::rules_crypto;

/// File extension of a rule pack, without the dot.
pub const PACK_EXTENSION: &str = "cfpack";

/// File name of the catalog pack, next to the binary (ADR-0040).
pub const PACK_FILE_NAME: &str = "rules.cfpack";

/// File name of the demo pack a private-repository build writes next to
/// the binary, beside the full one (ticket #153). The export script
/// delivers the same content as the shared repository's
/// `rules/rules.cfpack`; the binary itself never reads this file.
pub const DEMO_PACK_FILE_NAME: &str = "rules-demo.cfpack";

/// Name stored in the header of the demo pack.
pub const DEMO_PACK_NAME: &str = "demo";

/// Version rules of the full catalog (ADR-0043): the editor's advisory
/// database, at the root of the private repository, written by
/// `codefixture-audit-advisories update` and never committed nor delivered.
pub const FULL_VERSION_RULES_FILE: &str = "advisories.cfdb";

/// Version rules of the demo pack (ADR-0043), relative to the rules
/// folder: a small selection of well-known vulnerabilities, committed,
/// written by `codefixture-audit-advisories demo` from the editor's database.
pub const DEMO_VERSION_RULES_FILE: &str = "advisories/demo.cfdb";

/// Magic bytes at the start of every pack, version included: a future
/// incompatible layout gets a new magic rather than a guess.
const MAGIC: &[u8; 8] = b"CFPACK02";

/// Magics of the packs written before the rename to `.cfpack`
/// (ADR-0049): `SCAPACK1` (format 1, ADR-0040, rules only) and
/// `SCAPACK2` (format 2, ADR-0043). Recognized only to name them in the
/// refusal, never read.
const LEGACY_MAGICS: [&[u8; 8]; 2] = [b"SCAPACK1", b"SCAPACK2"];

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

/// The keys of the reasons a pack or a rule folder cannot be read, in the
/// `pack` group of the console translations
/// (`resources/locales/script/*.json`). The English text is given above
/// each one.
pub mod keys {
    /// cannot read {path}: {error}
    pub const CANNOT_READ: &str = "pack.cannot_read";
    /// rule pack content does not match its header
    pub const CONTENT_MISMATCH: &str = "pack.content_mismatch";
    /// rule pack is corrupt or was altered
    pub const CORRUPT: &str = "pack.corrupt";
    /// invalid rule pack content: {error}
    pub const INVALID_CONTENT: &str = "pack.invalid_content";
    /// invalid rule pack header: {error}
    pub const INVALID_HEADER: &str = "pack.invalid_header";
    /// rule pack in the former .scapack format, which this engine no longer reads: use a .cfpack pack built for this engine
    pub const LEGACY_FORMAT: &str = "pack.legacy_format";
    /// invalid rule pack header: missing "{field}"
    pub const MISSING_FIELD: &str = "pack.missing_field";
    /// rule pack needs key {key}, this engine only has the demo key {demo_key} (ADR-0040)
    pub const NEEDS_KEY: &str = "pack.needs_key";
    /// not a rule pack (unknown file signature)
    pub const NOT_A_PACK: &str = "pack.not_a_pack";
    /// truncated rule pack (header)
    pub const TRUNCATED_HEADER: &str = "pack.truncated_header";
    /// truncated rule pack (no header length)
    pub const TRUNCATED_HEADER_LENGTH: &str = "pack.truncated_header_length";
    /// truncated rule pack (sections)
    pub const TRUNCATED_SECTIONS: &str = "pack.truncated_sections";
    /// unreadable rule pack: {error}
    pub const UNREADABLE_PACK: &str = "pack.unreadable_pack";
    /// unreadable rule file: {error} (a plain `.sca` file, `rules::catalog`)
    pub const UNREADABLE_RULE_FILE: &str = "pack.unreadable_rule_file";
    /// unsupported rule pack format {format}, expected {expected}
    pub const UNSUPPORTED_FORMAT: &str = "pack.unsupported_format";

    /// Every key, checked against the four translations by a test.
    pub const ALL: &[&str] = &[
        CANNOT_READ,
        CONTENT_MISMATCH,
        CORRUPT,
        INVALID_CONTENT,
        INVALID_HEADER,
        LEGACY_FORMAT,
        MISSING_FIELD,
        NEEDS_KEY,
        NOT_A_PACK,
        TRUNCATED_HEADER,
        TRUNCATED_HEADER_LENGTH,
        TRUNCATED_SECTIONS,
        UNREADABLE_PACK,
        UNREADABLE_RULE_FILE,
        UNSUPPORTED_FORMAT,
    ];
}

/// Why a pack or a rule folder could not be read (ticket #280): a key of
/// [`keys`] and the values of its `{placeholders}`. [`PackError::render`]
/// gives it in the console's language, `Display` in English.
///
/// Also the reason of an advisory container that cannot be read (the
/// version rules a pack carries, `project::advisory_file`), with the keys
/// of its own group: one type for every reason a rule source gives.
///
/// The same shape as `DslMessage` (ticket #279) but its own type: this
/// module is compiled into `build.rs`, which has neither the parser nor
/// `crate::i18n`. A value taken from the system (`{error}` of a file that
/// cannot be read) stays in the system's words.
///
/// Numbers (`{cap}`, `{format}`, `{expected}`) are kept as numbers, not
/// as text: they are written only when the reason is rendered, in the
/// number format of the console's language (`1 073 741 824` in French,
/// `1.073.741.824` in German), by `super::pack_number_text`. That function
/// is the parent module's, like `super::rules_crypto`: in the library
/// it is `crate::rules::pack_number_text`, which reads the language's
/// formats (`report::locale_format`); in `build.rs`, which has no i18n and
/// only shows its errors to the publisher at build time, it writes the
/// plain digits. Until 2026-11-24 a number was turned into text when the
/// reason was made, and every language showed `1073741824`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackError {
    /// The translation key, one of [`keys`].
    pub key: &'static str,
    /// The value of each text placeholder, by name.
    pub args: Vec<(&'static str, String)>,
    /// The value of each number placeholder, by name, written at
    /// [`PackError::render`] in the language's number format.
    pub numbers: Vec<(&'static str, u64)>,
}

impl PackError {
    /// A reason without placeholder.
    pub fn new(key: &'static str) -> Self {
        PackError {
            key,
            args: Vec::new(),
            numbers: Vec::new(),
        }
    }

    /// Adds the value of text placeholder `{name}`.
    pub fn with(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.args.push((name, value.into()));
        self
    }

    /// Adds the value of number placeholder `{name}`: a size, a count or
    /// a format number, written in the language's number format when
    /// rendered.
    pub fn with_number(mut self, name: &'static str, value: impl Into<u64>) -> Self {
        self.numbers.push((name, value.into()));
        self
    }

    /// The reason in the language of `locale` (a console translation,
    /// `i18n::load_script_locale`). A key missing from `locale` falls
    /// back to English, then to the key itself, as `i18n::t` does; a test
    /// checks that the four languages have every key. The numbers are
    /// written in the number format of `locale`'s language (see
    /// [`PackError`]).
    pub fn render(&self, locale: &serde_json::Value) -> String {
        let template = translation(locale, self.key)
            .or_else(|| translation(&ENGLISH, self.key))
            .unwrap_or(self.key);
        let text = self
            .args
            .iter()
            .fold(template.to_string(), |text, (name, value)| {
                text.replace(&format!("{{{name}}}"), value)
            });
        self.numbers.iter().fold(text, |text, (name, value)| {
            text.replace(
                &format!("{{{name}}}"),
                &super::pack_number_text(locale, *value),
            )
        })
    }
}

/// In English, for the callers without a console language (`build.rs`,
/// tests).
impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render(&ENGLISH))
    }
}

/// The text of the dotted key `key` in a translation, `None` when it is
/// missing or empty. `crate::i18n::get_nested` cannot be used here (see
/// [`PackError`]).
fn translation<'a>(locale: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    key.split('.')
        .try_fold(locale, |node, part| node.get(part))
        .and_then(|value| value.as_str())
        .filter(|text| !text.is_empty())
}

/// The English console translation, read once: the language of
/// `Display`. Embedded by path from this file, so `build.rs` reads the
/// same file.
static ENGLISH: LazyLock<serde_json::Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../resources/locales/script/en.json"))
        .expect("embedded English console translation")
});

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
    // `rules-demo.cfpack` and `rules pack --demo` must be identical.
    let header_bytes = format!(
        "{{\"format\":{FORMAT_VERSION},\"key_fingerprint\":{},\"name\":{},\"rule_files\":{},\"rules_bytes\":{rules_bytes},\"version_rules_bytes\":{version_rules_bytes}}}",
        serde_json::Value::from(key_fingerprint(key)),
        serde_json::Value::from(name),
        sorted.len()
    )
    .into_bytes();

    let mut out = Vec::with_capacity(
        MAGIC.len() + 4 + header_bytes.len() + rules_bytes + version_rules_bytes,
    );
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
fn open_section(
    header_bytes: &[u8],
    section: &[u8],
    blob: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, PackError> {
    let aad = [header_bytes, section].concat();
    rules_crypto::decrypt_bytes_with_aad(blob, &aad, key)
        .ok_or_else(|| PackError::new(keys::CORRUPT))
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
fn parse_header(bytes: &[u8]) -> Result<(PackHeader, usize), PackError> {
    if LEGACY_MAGICS
        .iter()
        .any(|magic| bytes.starts_with(magic.as_slice()))
    {
        return Err(PackError::new(keys::LEGACY_FORMAT));
    }
    let rest = bytes
        .strip_prefix(MAGIC.as_slice())
        .ok_or_else(|| PackError::new(keys::NOT_A_PACK))?;
    if rest.len() < 4 {
        return Err(PackError::new(keys::TRUNCATED_HEADER_LENGTH));
    }
    let (len_bytes, rest) = rest.split_at(4);
    let header_len = u32::from_le_bytes(len_bytes.try_into().expect("4 bytes")) as usize;
    if header_len > MAX_HEADER_LEN || header_len > rest.len() {
        return Err(PackError::new(keys::TRUNCATED_HEADER));
    }
    let header: serde_json::Value = serde_json::from_slice(&rest[..header_len])
        .map_err(|e| PackError::new(keys::INVALID_HEADER).with("error", e.to_string()))?;
    // A missing `format` is named like any other missing field; a present
    // one is shown as written in the header (`1`, `"2"`). Until ticket
    // #280 both were shown as a Rust `Option` (`None`, `Some(1)`).
    match header.get("format") {
        None => return Err(PackError::new(keys::MISSING_FIELD).with("field", "format")),
        Some(format) if format.as_u64() != Some(FORMAT_VERSION) => {
            // `{format}` stays the header's own text (it may be a string,
            // `"2"`); the format this engine reads is a number.
            return Err(PackError::new(keys::UNSUPPORTED_FORMAT)
                .with("format", format.to_string())
                .with_number("expected", FORMAT_VERSION));
        }
        Some(_) => {}
    }
    let missing = |key: &str| PackError::new(keys::MISSING_FIELD).with("field", key);
    let text = |key: &str| {
        header
            .get(key)
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| missing(key))
    };
    let number = |key: &str| {
        header
            .get(key)
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .ok_or_else(|| missing(key))
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
fn split_pack(bytes: &[u8]) -> Result<PackParts<'_>, PackError> {
    let (parsed, body_start) = parse_header(bytes)?;
    let header_bytes = &bytes[MAGIC.len() + 4..body_start];
    let body = &bytes[body_start..];
    // The two sections fill the rest of the file exactly.
    if parsed.rules_bytes.checked_add(parsed.version_rules_bytes) != Some(body.len()) {
        return Err(PackError::new(keys::TRUNCATED_SECTIONS));
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
fn demo_key_for(header: &PackHeader) -> Result<[u8; 32], PackError> {
    let key = demo_key();
    if header.key_fingerprint != key_fingerprint(&key) {
        return Err(PackError::new(keys::NEEDS_KEY)
            .with("key", header.key_fingerprint.clone())
            .with("demo_key", key_fingerprint(&key)));
    }
    Ok(key)
}

/// Reads only the clear header of a pack, without decrypting it.
pub fn read_header(bytes: &[u8]) -> Result<PackHeader, PackError> {
    split_pack(bytes).map(|parts| parts.header)
}

/// Reads the clear header of the pack file at `path` from its first
/// bytes only: what a scan checks before deciding whether its
/// dependencies phase runs (ADR-0043). The sections are not read, so a
/// truncated pack is only reported when it is opened.
pub fn read_header_from_file(path: &Path) -> Result<PackHeader, PackError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| unreadable_pack(&e))?;
    let mut prefix = Vec::new();
    file.take((MAGIC.len() + 4 + MAX_HEADER_LEN) as u64)
        .read_to_end(&mut prefix)
        .map_err(|e| unreadable_pack(&e))?;
    parse_header(&prefix).map(|(header, _)| header)
}

/// The reason of a pack file the system cannot read: `{error}` is the
/// system's message.
pub fn unreadable_pack(error: &std::io::Error) -> PackError {
    PackError::new(keys::UNREADABLE_PACK).with("error", error.to_string())
}

/// Opens the rules section of a pack with the demo key: its header and
/// its rule files. `Err` if the file is not a valid pack, if it needs
/// another key (a client pack of ADR-0037), or if any byte of the header
/// or of the section was altered. The version rules are not decrypted.
pub fn open_pack(bytes: &[u8]) -> Result<(PackHeader, Vec<RuleSource>), PackError> {
    let parts = split_pack(bytes)?;
    let key = demo_key_for(&parts.header)?;
    let plain = open_section(parts.header_bytes, RULES_SECTION, parts.rules, &key)?;
    let files: Vec<RuleSource> = serde_json::from_slice(&plain)
        .map_err(|e| PackError::new(keys::INVALID_CONTENT).with("error", e.to_string()))?;
    if files.len() != parts.header.rule_files {
        return Err(PackError::new(keys::CONTENT_MISMATCH));
    }
    Ok((parts.header, files))
}

/// Decrypts the version rules section of a pack (ADR-0043): the bytes of
/// its advisory container, `Ok(None)` when the pack carries none.
pub fn open_version_rules(bytes: &[u8]) -> Result<Option<Vec<u8>>, PackError> {
    let parts = split_pack(bytes)?;
    if !parts.header.has_version_rules() {
        return Ok(None);
    }
    let key = demo_key_for(&parts.header)?;
    open_section(
        parts.header_bytes,
        VERSION_RULES_SECTION,
        parts.version_rules,
        &key,
    )
    .map(Some)
}

/// Every `.sca` file under `root`, as `(path relative to root with `/`
/// separators, source)` pairs sorted by path. Used by `build.rs` to pack
/// `rules/builtin` and by `codefixture-audit rules pack`. A missing `root` gives
/// an empty list; an unreadable file is an error naming it.
pub fn collect_sca_sources(root: &Path) -> Result<Vec<RuleSource>, PackError> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<RuleSource>) -> Result<(), PackError> {
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
                let content = std::fs::read_to_string(&path).map_err(|e| {
                    PackError::new(keys::CANNOT_READ)
                        .with("path", path.display().to_string())
                        .with("error", e.to_string())
                })?;
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
/// `rules-demo.cfpack` and by `codefixture-audit rules pack --demo` for the
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

    /// The placeholders of a translated text, sorted.
    fn placeholders(text: &str) -> Vec<String> {
        let mut found: Vec<String> = text
            .split('{')
            .skip(1)
            .filter_map(|rest| rest.split_once('}').map(|(name, _)| name.to_string()))
            .collect();
        found.sort();
        found
    }

    /// Ticket #280: every key has a text in the four languages, with the
    /// placeholders of the English one; the `pack` group holds no other
    /// key.
    #[test]
    fn test_every_pack_error_is_translated_with_its_placeholders() {
        let english = crate::i18n::load_script_locale("en");
        for lang in ["en", "fr", "es", "de"] {
            let locale = crate::i18n::load_script_locale(lang);
            let group = locale["pack"].as_object().expect("pack group");
            assert_eq!(group.len(), keys::ALL.len(), "{lang}");
            for key in keys::ALL {
                let text =
                    translation(&locale, key).unwrap_or_else(|| panic!("{lang}: {key} missing"));
                let english_text = translation(&english, key).unwrap();
                assert_eq!(
                    placeholders(text),
                    placeholders(english_text),
                    "{lang}: {key}"
                );
            }
        }
    }

    /// Ticket #280: a reason is shown in the console's language, in
    /// English by `Display`, and falls back to English for a key a
    /// translation lacks.
    #[test]
    fn test_pack_error_is_rendered_in_the_console_language() {
        let french = crate::i18n::load_script_locale("fr");
        let other = write_pack_with_key("client", &sample(), None, &[9u8; 32]);
        let error = open_pack(&other).unwrap_err();
        let demo = key_fingerprint(&demo_key());
        let client = key_fingerprint(&[9u8; 32]);
        assert_eq!(
            error.to_string(),
            format!(
                "rule pack needs key {client}, this engine only has the demo key {demo} (ADR-0040)"
            )
        );
        assert_eq!(
            error.render(&french),
            format!(
                "le pack de règles demande la clé {client}, ce moteur n'a que la clé de démonstration {demo} (ADR-0040)"
            )
        );
        assert_eq!(
            open_pack(b"nothing").unwrap_err().render(&french),
            "ce fichier n'est pas un pack de règles (signature inconnue)"
        );
        assert_eq!(
            PackError::new(keys::CORRUPT).render(&serde_json::json!({})),
            "rule pack is corrupt or was altered"
        );
    }

    /// A header without `format` names the missing field; one of another
    /// format shows the value as written.
    #[test]
    fn test_header_format_is_named_when_missing_or_unsupported() {
        let with_header = |header: &str| {
            let mut bytes = MAGIC.to_vec();
            bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
            bytes.extend_from_slice(header.as_bytes());
            bytes
        };
        assert_eq!(
            read_header(&with_header("{}")).unwrap_err().to_string(),
            "invalid rule pack header: missing \"format\""
        );
        assert_eq!(
            read_header(&with_header("{\"format\":1}"))
                .unwrap_err()
                .to_string(),
            "unsupported rule pack format 1, expected 2"
        );
    }

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
        assert_eq!(
            write_pack("demo", &sample(), None),
            write_pack("demo", &reversed, None)
        );
        let mut changed = sample();
        changed[0].1.push(' ');
        assert_ne!(
            write_pack("demo", &sample(), None),
            write_pack("demo", &changed, None)
        );
    }

    #[test]
    fn test_open_pack_rejects_other_key_corrupt_and_truncated() {
        let pack = write_pack("demo", &sample(), None);

        let other = write_pack_with_key("client", &sample(), None, &[7u8; 32]);
        assert!(
            open_pack(&other)
                .unwrap_err()
                .to_string()
                .contains("needs key")
        );

        let mut corrupt = pack.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        assert!(
            open_pack(&corrupt)
                .unwrap_err()
                .to_string()
                .contains("corrupt")
        );

        assert!(
            open_pack(&pack[..10])
                .unwrap_err()
                .to_string()
                .contains("truncated")
        );
        let not_a_pack = open_pack(b"rule x\nend\n");
        assert!(
            not_a_pack
                .unwrap_err()
                .to_string()
                .contains("not a rule pack")
        );
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
        assert!(
            open_pack(&bytes)
                .unwrap_err()
                .to_string()
                .contains("corrupt")
        );
    }

    /// A pack of the former `.scapack` name, format 1 (ADR-0040, signed
    /// ones of ADR-0037 included) or format 2 (ADR-0043), is refused by
    /// name, with the way out (ADR-0049).
    #[test]
    fn test_legacy_scapack_pack_is_refused_with_a_clear_reason() {
        for (magic, format) in LEGACY_MAGICS.iter().zip([1, 2]) {
            let header =
                format!(r#"{{"format":{format},"name":"x","key_fingerprint":"0","rule_files":0}}"#);
            let mut bytes = magic.to_vec();
            bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
            bytes.extend_from_slice(header.as_bytes());
            let err = read_header(&bytes).unwrap_err().to_string();
            assert!(err.contains(".scapack") && err.contains(".cfpack"), "{err}");
        }
    }

    /// The pack written today starts with the `.cfpack` magic.
    #[test]
    fn test_pack_starts_with_the_cfpack_magic() {
        assert!(write_pack("demo", &sample(), None).starts_with(b"CFPACK02"));
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
        let container = b"CFDB-container-bytes".to_vec();
        let pack = write_pack("builtin", &sample(), Some(&container));
        let header = read_header(&pack).unwrap();
        assert!(header.has_version_rules());
        assert_eq!(
            header.version_rules_bytes,
            container.len() + SECTION_OVERHEAD
        );
        assert_eq!(open_version_rules(&pack).unwrap(), Some(container));
        let (_, files) = open_pack(&pack).unwrap();
        assert_eq!(files.len(), 2, "rules unchanged by the second section");
        assert!(
            !String::from_utf8_lossy(&pack).contains("CFDB-container"),
            "encrypted"
        );
    }

    #[test]
    fn test_pack_without_version_rules_has_none() {
        for pack in [
            write_pack("demo", &sample(), None),
            write_pack("demo", &sample(), Some(b"")),
        ] {
            assert!(!read_header(&pack).unwrap().has_version_rules());
            assert_eq!(open_version_rules(&pack).unwrap(), None);
        }
        assert_eq!(
            write_pack("demo", &sample(), None),
            write_pack("demo", &sample(), Some(b""))
        );
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
        assert!(
            open_version_rules(&corrupt)
                .unwrap_err()
                .to_string()
                .contains("corrupt")
        );
        assert!(open_pack(&corrupt).is_ok(), "the rules section is intact");
        assert!(
            open_version_rules(&pack[..pack.len() - 1])
                .unwrap_err()
                .to_string()
                .contains("truncated")
        );
    }
}
