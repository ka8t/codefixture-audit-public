//! The advisory container (ADR-0042, ticket #177; role changed by
//! ADR-0043): the layout of the editor's database `advisories.cfdb` and
//! of the version rules section of a rule pack.
//!
//! `tools/codefixture-audit-advisories` writes the editor's database at the root of
//! the private repository. It is never delivered: `build.rs` and
//! `rules pack` copy it, or the demo selection written from it, into the
//! version rules section of a pack (`rules/pack_format.rs`), and a scan
//! reads that section (`advisories.rs`). Every side goes through this
//! module, so the layout is written down once. The writer lives here
//! because it is the same layout, and it opens no network connection.
//!
//! Layout, all integers little-endian:
//!
//! ```text
//! b"CFDB"            magic bytes
//! u32                container format (FORMAT_VERSION)
//! u32                header length in bytes
//! header             JSON, UTF-8: Header below
//! body               per ecosystem, one gzip member, in header order
//! ```
//!
//! The header is clear JSON, readable without decompressing anything:
//! format, creation date, source, the databases the records come from
//! with their licenses (ADR-0051), per ecosystem its advisory count, the
//! newest OSV `modified` date and where its gzip member sits in the body,
//! and the same for each table keyed by CVE (KEV, EPSS, ADR-0051), whose
//! members follow the ecosystems' in the body. The sources and the tables
//! are optional: a file written before them reads as having none, and an
//! engine that predates them ignores them. Each member holds the JSON of one ecosystem as
//! `codefixture-audit-advisories` writes it (`tools/codefixture-audit-advisories/src/format.rs`);
//! this module only reads the identifiers of its records, once, when it
//! writes the file: the header then says how many distinct vulnerabilities
//! the records describe (`Header::vulnerabilities`), so that a scan names
//! them without decompressing anything (2026-11-24).
//!
//! **Deterministic**: the same ecosystems give the same bytes. The
//! creation date is the newest OSV `modified` date of the data, not the
//! time of writing, and every gzip member has a zero time and no file
//! name. Not encrypted: the data is public.
//!
//! A file that cannot be read gives a `PackError` (ticket #280): a key
//! of the `advisory_file` group of the console translations and its
//! values, shown in the console's language (`rules list`, the scan's
//! version rules line), in English by `Display` (the editor's tool).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};

use crate::rules::pack_format::PackError;

/// The keys of the reasons a database cannot be read, in the
/// `advisory_file` group of the console translations
/// (`resources/locales/script/*.json`). The English text is given above
/// each one; `{path}` is the database file or the pack that carries it.
pub mod keys {
    /// {path} ({ecosystem}): {error}
    pub const ECOSYSTEM_INVALID: &str = "advisory_file.ecosystem_invalid";
    /// {path}: {ecosystem} lies outside the file
    pub const ECOSYSTEM_OUTSIDE: &str = "advisory_file.ecosystem_outside";
    /// {path}: {ecosystem}: decompressed data exceeds {cap} bytes
    pub const ECOSYSTEM_TOO_LARGE: &str = "advisory_file.ecosystem_too_large";
    /// {path}: {ecosystem}: {error}
    pub const ECOSYSTEM_UNREADABLE: &str = "advisory_file.ecosystem_unreadable";
    /// {path} ({ecosystem}): format {format} not supported by this engine (expected {expected})
    pub const ECOSYSTEM_UNSUPPORTED_FORMAT: &str = "advisory_file.ecosystem_unsupported_format";
    /// {path}: header format {format} not supported
    pub const HEADER_FORMAT_UNSUPPORTED: &str = "advisory_file.header_format_unsupported";
    /// {path}: invalid header: {error}
    pub const INVALID_HEADER: &str = "advisory_file.invalid_header";
    /// {path}: advisory database in the former .sadb format, which this engine no longer reads: rebuild it as a .cfdb database (ADR-0052)
    pub const LEGACY_FORMAT: &str = "advisory_file.legacy_format";
    /// {path}: not an advisory database (cfdb) file
    pub const NOT_A_DATABASE: &str = "advisory_file.not_a_database";
    /// {path} (table {table}): {error}
    pub const TABLE_INVALID: &str = "advisory_file.table_invalid";
    /// {path}: table {table} lies outside the file
    pub const TABLE_OUTSIDE: &str = "advisory_file.table_outside";
    /// {path}: table {table}: decompressed data exceeds {cap} bytes
    pub const TABLE_TOO_LARGE: &str = "advisory_file.table_too_large";
    /// {path}: table {table}: {error}
    pub const TABLE_UNREADABLE: &str = "advisory_file.table_unreadable";
    /// {path} (table {table}): format {format} not supported by this engine (expected {expected})
    pub const TABLE_UNSUPPORTED_FORMAT: &str = "advisory_file.table_unsupported_format";
    /// {path}: truncated header
    pub const TRUNCATED_HEADER: &str = "advisory_file.truncated_header";
    /// {path}: {error}
    pub const UNREADABLE: &str = "advisory_file.unreadable";
    /// {path}: format {format} not supported by this engine (expected {expected})
    pub const UNSUPPORTED_FORMAT: &str = "advisory_file.unsupported_format";

    /// Every key, checked against the four translations by a test.
    pub const ALL: &[&str] = &[
        ECOSYSTEM_INVALID,
        ECOSYSTEM_OUTSIDE,
        ECOSYSTEM_TOO_LARGE,
        ECOSYSTEM_UNREADABLE,
        ECOSYSTEM_UNSUPPORTED_FORMAT,
        HEADER_FORMAT_UNSUPPORTED,
        INVALID_HEADER,
        LEGACY_FORMAT,
        NOT_A_DATABASE,
        TABLE_INVALID,
        TABLE_OUTSIDE,
        TABLE_TOO_LARGE,
        TABLE_UNREADABLE,
        TABLE_UNSUPPORTED_FORMAT,
        TRUNCATED_HEADER,
        UNREADABLE,
        UNSUPPORTED_FORMAT,
    ];
}

/// First bytes of every database file (`CFDB`, for CodeFixture database,
/// since ADR-0052).
pub const MAGIC: &[u8; 4] = b"CFDB";

/// First bytes of the same layout before ADR-0052 (`.sadb` files), refused
/// with a reason rather than as an unknown file.
const LEGACY_MAGIC: &[u8; 4] = b"SADB";

/// Container layout version. A reader refuses any other value rather
/// than misreading the file.
pub const FORMAT_VERSION: u32 = 1;

/// File name of the editor's database (ADR-0043): `codefixture-audit-advisories`
/// writes it in its current folder by default, the root of the private
/// repository, where `build.rs` reads it. The engine never looks for it.
pub const FILE_NAME: &str = "advisories.cfdb";

/// Longest header accepted when reading, against a corrupted length.
const MAX_HEADER_BYTES: u32 = 1 << 20;

/// Largest decompressed size accepted for one ecosystem's gzip member, a
/// bound against a decompression bomb (a corrupted or hostile file whose
/// few bytes expand without limit, exhausting memory). 1 GiB is far above
/// any real OSV ecosystem export (the whole database is ~85 MB compressed
/// for five ecosystems) yet stops an unbounded expansion. A member over
/// the bound is reported as an error, like a length that points outside
/// the file. Same intent as [`MAX_HEADER_BYTES`].
const MAX_ECOSYSTEM_BYTES: u64 = 1 << 30;

/// Why a gzip member could not be decompressed ([`decompress_capped`]):
/// the caller turns it into the reason naming the member.
#[derive(Debug, PartialEq)]
enum DecompressError {
    /// Larger than the cap once decompressed.
    TooLarge,
    /// Not a valid gzip member: the decoder's message.
    Corrupt(String),
}

/// Decompresses `member` (one gzip member), refusing anything larger than
/// `cap` bytes once decompressed. Reads one byte past `cap` so that an
/// over-the-cap stream is detected rather than silently truncated.
fn decompress_capped(member: &[u8], cap: u64) -> Result<Vec<u8>, DecompressError> {
    let mut out = Vec::new();
    GzDecoder::new(member)
        .take(cap + 1)
        .read_to_end(&mut out)
        .map_err(|e| DecompressError::Corrupt(e.to_string()))?;
    if out.len() as u64 > cap {
        return Err(DecompressError::TooLarge);
    }
    Ok(out)
}

/// The reason of a member (an ecosystem or a table) that could not be
/// decompressed: `name_arg` is the placeholder naming it.
fn member_error(
    path: &Path,
    (name_arg, name): (&'static str, &str),
    error: DecompressError,
    too_large: &'static str,
    unreadable: &'static str,
) -> PackError {
    let base = |key| {
        PackError::new(key)
            .with("path", path.display().to_string())
            .with(name_arg, name)
    };
    match error {
        DecompressError::TooLarge => base(too_large).with("cap", MAX_ECOSYSTEM_BYTES.to_string()),
        DecompressError::Corrupt(error) => base(unreadable).with("error", error),
    }
}

/// The clear JSON header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub format: u32,
    /// Newest OSV `modified` date across the ecosystems (RFC 3339): the
    /// date of the data, so that unchanged data keeps the same bytes.
    pub created: String,
    /// Where the advisories come from, in one line.
    pub source: String,
    /// The databases whose data the file holds, with their licenses, for
    /// the credit a redistributed pack owes them (ADR-0051). Empty in a
    /// file written before 2026-11-18.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<DataSource>,
    /// In body order.
    pub ecosystems: Vec<EcosystemEntry>,
    /// Tables keyed by CVE (`kev`, `epss`), in body order after the
    /// ecosystems (ADR-0051). Empty in a file written before 2026-11-18.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<TableEntry>,
    /// Distinct published vulnerabilities the records describe, across
    /// the ecosystems: records sharing an id or an alias are one
    /// vulnerability (the same CVE published by two databases, or
    /// affecting packages of two ecosystems). The record counts of
    /// `ecosystems` are larger: the console used to call them
    /// vulnerabilities (26 records for 21 vulnerabilities in the demo
    /// pack). `None` in a file written before 2026-11-24, or whose records
    /// could not be read when it was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vulnerabilities: Option<usize>,
    /// Among `vulnerabilities`, those with a CVE identifier; the others
    /// are known by another id only (GHSA, a malicious package's MAL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cves: Option<usize>,
}

/// The identifiers of one record, all that [`count_vulnerabilities`]
/// reads of an ecosystem's JSON.
#[derive(Deserialize)]
struct RecordIds {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Deserialize)]
struct EcosystemIds {
    advisories: Vec<RecordIds>,
}

/// The distinct vulnerabilities described by the records of `ecosystems`
/// (their JSON, `tools/codefixture-audit-advisories/src/format.rs`) and
/// how many of them have a CVE identifier, or `None` when one of them is
/// not that JSON. Records sharing an id or an alias are joined (a
/// union-find over the identifiers), as the scan merges them on a
/// dependency (`advisories::VulnerableDependency`).
pub fn count_vulnerabilities<'a>(
    ecosystems: impl Iterator<Item = &'a [u8]>,
) -> Option<(usize, usize)> {
    use std::collections::HashMap;
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut parent: Vec<usize> = Vec::new();
    fn root(parent: &mut [usize], mut x: usize) -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        x
    }
    let slot = |id: &str, index: &mut HashMap<String, usize>, parent: &mut Vec<usize>| {
        *index.entry(id.to_string()).or_insert_with(|| {
            parent.push(parent.len());
            parent.len() - 1
        })
    };
    for json in ecosystems {
        let file: EcosystemIds = serde_json::from_slice(json).ok()?;
        for record in file.advisories {
            let first = slot(&record.id, &mut index, &mut parent);
            for alias in &record.aliases {
                let other = slot(alias, &mut index, &mut parent);
                let (a, b) = (root(&mut parent, first), root(&mut parent, other));
                if a != b {
                    parent[b] = a;
                }
            }
        }
    }
    let mut groups: HashMap<usize, bool> = HashMap::new();
    for (id, &at) in &index {
        let group = root(&mut parent, at);
        *groups.entry(group).or_default() |= id.starts_with("CVE-");
    }
    Some((groups.len(), groups.values().filter(|cve| **cve).count()))
}

/// One database whose data the file holds (ADR-0051).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataSource {
    /// Name to credit (`GitHub Advisory Database`).
    pub name: String,
    /// Where the data is published.
    pub url: String,
    /// SPDX identifier of its license (`CC-BY-4.0`), or a short note when
    /// the source names none.
    pub license: String,
    /// Records or rows of the file that come from it.
    pub records: usize,
}

/// One table of the header: data keyed by CVE, beside the ecosystems.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableEntry {
    /// `kev` or `epss`.
    pub name: String,
    /// Date of the data, as the source gives it.
    pub date: String,
    /// Number of CVEs in the table.
    pub rows: usize,
    /// Offset of its gzip member from the start of the body.
    pub offset: u64,
    /// Length of its gzip member.
    pub length: u64,
}

/// One table to write: its name, date, row count and JSON payload.
#[derive(Debug, Clone)]
pub struct TablePayload {
    pub name: String,
    pub date: String,
    pub rows: usize,
    /// The JSON of the table, uncompressed.
    pub json: Vec<u8>,
}

/// Everything a database file holds, for [`encode`] and [`write`].
#[derive(Debug, Clone, Copy)]
pub struct Contents<'a> {
    /// Where the advisories come from, in one line.
    pub source: &'a str,
    /// The databases of the data, with their licenses.
    pub sources: &'a [DataSource],
    pub ecosystems: &'a [EcosystemPayload],
    pub tables: &'a [TablePayload],
}

/// One ecosystem of the header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemEntry {
    /// OSV ecosystem name (`PyPI`, `npm`, `Maven`, `NuGet`, `Packagist`).
    pub name: String,
    /// Number of advisories in its member.
    pub advisories: usize,
    /// Newest OSV `modified` date of this ecosystem.
    pub last_modified: String,
    /// Offset of its gzip member from the start of the body.
    pub offset: u64,
    /// Length of its gzip member.
    pub length: u64,
}

/// One ecosystem to write: its name, counts and JSON payload.
#[derive(Debug, Clone)]
pub struct EcosystemPayload {
    pub name: String,
    pub advisories: usize,
    pub last_modified: String,
    /// The JSON of the ecosystem, uncompressed.
    pub json: Vec<u8>,
}

/// A database read from disk: its header and its compressed members.
#[derive(Debug, Clone)]
pub struct DatabaseFile {
    pub path: PathBuf,
    pub header: Header,
    body: Vec<u8>,
}

impl DatabaseFile {
    /// The uncompressed JSON of `ecosystem`, `None` when the file does
    /// not hold it.
    pub fn ecosystem_json(&self, ecosystem: &str) -> Option<Result<Vec<u8>, PackError>> {
        let entry = self
            .header
            .ecosystems
            .iter()
            .find(|e| e.name == ecosystem)?;
        let start = entry.offset as usize;
        let end = start.checked_add(entry.length as usize)?;
        let Some(member) = self.body.get(start..end) else {
            return Some(Err(PackError::new(keys::ECOSYSTEM_OUTSIDE)
                .with("path", self.path.display().to_string())
                .with("ecosystem", ecosystem)));
        };
        Some(decompress_capped(member, MAX_ECOSYSTEM_BYTES).map_err(|e| {
            member_error(
                &self.path,
                ("ecosystem", ecosystem),
                e,
                keys::ECOSYSTEM_TOO_LARGE,
                keys::ECOSYSTEM_UNREADABLE,
            )
        }))
    }

    /// The uncompressed JSON of the table `name` (`kev`, `epss`), `None`
    /// when the file does not hold it.
    pub fn table_json(&self, name: &str) -> Option<Result<Vec<u8>, PackError>> {
        let entry = self.header.tables.iter().find(|t| t.name == name)?;
        let start = entry.offset as usize;
        let end = start.checked_add(entry.length as usize)?;
        let Some(member) = self.body.get(start..end) else {
            return Some(Err(PackError::new(keys::TABLE_OUTSIDE)
                .with("path", self.path.display().to_string())
                .with("table", name)));
        };
        Some(decompress_capped(member, MAX_ECOSYSTEM_BYTES).map_err(|e| {
            member_error(
                &self.path,
                ("table", name),
                e,
                keys::TABLE_TOO_LARGE,
                keys::TABLE_UNREADABLE,
            )
        }))
    }
}

/// One gzip member of `json`, with a zero time and no file name, so that
/// the same content always gives the same bytes.
fn gzip_member(json: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::best());
    encoder.write_all(json)?;
    encoder.finish()
}

/// The bytes of a database holding `contents`. Ecosystems, tables and
/// sources are sorted by name, so that the order they are given in does
/// not change the file.
pub fn encode(contents: &Contents<'_>) -> std::io::Result<Vec<u8>> {
    let mut sorted: Vec<&EcosystemPayload> = contents.ecosystems.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut body = Vec::new();
    let mut entries = Vec::new();
    for eco in sorted {
        let member = gzip_member(&eco.json)?;
        entries.push(EcosystemEntry {
            name: eco.name.clone(),
            advisories: eco.advisories,
            last_modified: eco.last_modified.clone(),
            offset: body.len() as u64,
            length: member.len() as u64,
        });
        body.extend_from_slice(&member);
    }
    let mut sorted_tables: Vec<&TablePayload> = contents.tables.iter().collect();
    sorted_tables.sort_by(|a, b| a.name.cmp(&b.name));
    let mut tables = Vec::new();
    for table in sorted_tables {
        let member = gzip_member(&table.json)?;
        tables.push(TableEntry {
            name: table.name.clone(),
            date: table.date.clone(),
            rows: table.rows,
            offset: body.len() as u64,
            length: member.len() as u64,
        });
        body.extend_from_slice(&member);
    }
    let mut sources = contents.sources.to_vec();
    sources.sort_by(|a, b| a.name.cmp(&b.name));
    let created = newest_date(entries.iter().map(|e| e.last_modified.as_str()))
        .unwrap_or("")
        .to_string();
    let counted = count_vulnerabilities(contents.ecosystems.iter().map(|e| e.json.as_slice()));
    let header = Header {
        format: FORMAT_VERSION,
        created,
        source: contents.source.to_string(),
        sources,
        ecosystems: entries,
        tables,
        vulnerabilities: counted.map(|(all, _)| all),
        cves: counted.map(|(_, cves)| cves),
    };
    let header_json = serde_json::to_vec(&header).map_err(std::io::Error::other)?;
    let mut out = Vec::with_capacity(12 + header_json.len() + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_json);
    out.extend_from_slice(&body);
    Ok(out)
}

/// The latest of `dates` (OSV `modified` timestamps, RFC 3339), as
/// written. Compared as instants, not as text (2026-11-15): as text,
/// `2026-11-07T10:00:00.5Z` sorts before `2026-11-07T10:00:00Z` (`.` <
/// `Z`) although it is later, so the header could show an ecosystem's
/// older date. A date that does not parse ranks below every valid one,
/// and among such dates the text order decides, so the result never
/// depends on the order of the ecosystems.
fn newest_date<'a>(dates: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    dates.max_by_key(|d| (chrono::DateTime::parse_from_rfc3339(d).ok(), *d))
}

/// Writes the database to `path` through a temporary file renamed over
/// it, so that a scan running at the same time reads either the old or
/// the new file, never half of one.
pub fn write(path: &Path, contents: &Contents<'_>) -> std::io::Result<()> {
    let bytes = encode(contents)?;
    let tmp = path.with_extension("cfdb.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// Parses database bytes read from `path` (named in the errors).
pub fn decode(path: &Path, bytes: Vec<u8>) -> Result<DatabaseFile, PackError> {
    let fail = |key| PackError::new(key).with("path", path.display().to_string());
    if bytes.starts_with(LEGACY_MAGIC) {
        return Err(fail(keys::LEGACY_FORMAT));
    }
    if bytes.len() < 12 || &bytes[..4] != MAGIC {
        return Err(fail(keys::NOT_A_DATABASE));
    }
    let format = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if format != FORMAT_VERSION {
        return Err(fail(keys::UNSUPPORTED_FORMAT)
            .with("format", format.to_string())
            .with("expected", FORMAT_VERSION.to_string()));
    }
    let header_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if header_len > MAX_HEADER_BYTES || 12 + header_len as usize > bytes.len() {
        return Err(fail(keys::TRUNCATED_HEADER));
    }
    let header_end = 12 + header_len as usize;
    let header: Header = serde_json::from_slice(&bytes[12..header_end])
        .map_err(|e| fail(keys::INVALID_HEADER).with("error", e.to_string()))?;
    if header.format != FORMAT_VERSION {
        return Err(fail(keys::HEADER_FORMAT_UNSUPPORTED).with("format", header.format.to_string()));
    }
    Ok(DatabaseFile {
        path: path.to_path_buf(),
        header,
        body: bytes[header_end..].to_vec(),
    })
}

/// Reads the database at `path`. `Ok(None)` when there is no file.
pub fn read(path: &Path) -> Result<Option<DatabaseFile>, PackError> {
    match std::fs::read(path) {
        Ok(bytes) => decode(path, bytes).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(PackError::new(keys::UNREADABLE)
            .with("path", path.display().to_string())
            .with("error", e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contents with `ecosystems` only, as written before ADR-0051.
    fn plain<'a>(source: &'a str, ecosystems: &'a [EcosystemPayload]) -> Contents<'a> {
        Contents {
            source,
            sources: &[],
            ecosystems,
            tables: &[],
        }
    }

    fn payload(name: &str, n: usize, date: &str) -> EcosystemPayload {
        EcosystemPayload {
            name: name.to_string(),
            advisories: n,
            last_modified: date.to_string(),
            json: format!("{{\"ecosystem\":\"{name}\",\"advisories\":[{n}]}}").into_bytes(),
        }
    }

    /// 2026-11-24: the header counts the distinct vulnerabilities of the
    /// records, across ecosystems, and those with a CVE. Records sharing
    /// an id or an alias are one vulnerability, even through a third
    /// record; a file whose records cannot be read has no count.
    #[test]
    fn test_header_counts_distinct_vulnerabilities() {
        let eco = |name: &str, json: &str| EcosystemPayload {
            name: name.to_string(),
            advisories: 0,
            last_modified: "2026-11-10T00:00:00Z".to_string(),
            json: json.as_bytes().to_vec(),
        };
        let ecosystems = [
            eco(
                "PyPI",
                r#"{"format":1,"advisories":[
                    {"id":"GHSA-1","aliases":["CVE-2021-1"],"summary":"s","severity":"HIGH","packages":[]},
                    {"id":"PYSEC-1","aliases":["CVE-2021-1"]},
                    {"id":"GHSA-2","aliases":[]}]}"#,
            ),
            eco(
                "npm",
                r#"{"format":1,"advisories":[
                    {"id":"GHSA-3","aliases":["CVE-2022-3"]},
                    {"id":"GHSA-4","aliases":["GHSA-3"]},
                    {"id":"MAL-1"}]}"#,
            ),
        ];
        // CVE-2021-1 (2 records), GHSA-2, CVE-2022-3 (2 records), MAL-1.
        assert_eq!(
            count_vulnerabilities(ecosystems.iter().map(|e| e.json.as_slice())),
            Some((4, 2))
        );
        let bytes = encode(&plain("test", &ecosystems)).unwrap();
        let file = decode(Path::new("x.cfdb"), bytes).unwrap();
        assert_eq!(
            (file.header.vulnerabilities, file.header.cves),
            (Some(4), Some(2))
        );
        // A payload that is not records: no count, and the field is left
        // out of the header, as in a file written before.
        let other = [payload("PyPI", 3, "2026-11-10T00:00:00Z")];
        let bytes = encode(&plain("test", &other)).unwrap();
        let header_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let header = String::from_utf8(bytes[12..12 + header_len].to_vec()).unwrap();
        assert!(!header.contains("vulnerabilities"), "{header}");
        assert_eq!(
            decode(Path::new("x.cfdb"), bytes).unwrap().header.cves,
            None
        );
    }

    /// The committed demo selection says its counts: 26 records for 21
    /// vulnerabilities, each with a CVE (`rules/advisories/demo-ids.txt`).
    #[test]
    fn test_demo_selection_counts_its_vulnerabilities() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/advisories/demo.cfdb");
        let Some(file) = read(&path).unwrap() else {
            // The shared repository carries the pack, not the database.
            return;
        };
        let records: usize = file.header.ecosystems.iter().map(|e| e.advisories).sum();
        assert_eq!(
            (records, file.header.vulnerabilities, file.header.cves),
            (26, Some(21), Some(21))
        );
    }

    /// Ticket #177: what is written is read back, ecosystem by
    /// ecosystem; the header is readable without decompressing.
    #[test]
    fn test_write_then_read_gives_the_same_ecosystems() {
        let a = [
            payload("PyPI", 3, "2026-11-10T00:00:00Z"),
            payload("npm", 5, "2026-11-11T00:00:00Z"),
        ];
        let bytes = encode(&plain("OSV", &a)).unwrap();
        let db = decode(Path::new("x.cfdb"), bytes.clone()).unwrap();
        assert_eq!(db.header.created, "2026-11-11T00:00:00Z");
        assert_eq!(db.header.source, "OSV");
        assert_eq!(db.header.ecosystems.len(), 2);
        assert_eq!(db.header.ecosystems[0].name, "PyPI");
        assert_eq!(db.header.ecosystems[1].advisories, 5);
        assert_eq!(db.ecosystem_json("npm").unwrap().unwrap(), a[1].json);
        assert_eq!(db.ecosystem_json("PyPI").unwrap().unwrap(), a[0].json);
        assert!(db.ecosystem_json("Maven").is_none());
        // Clear header right after the 12 fixed bytes.
        let len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let header: serde_json::Value = serde_json::from_slice(&bytes[12..12 + len]).unwrap();
        assert_eq!(header["ecosystems"][0]["name"], "PyPI");
    }

    /// Same input, same bytes, whatever the order and the time.
    #[test]
    fn test_encode_is_deterministic() {
        let a = [
            payload("npm", 5, "2026-11-11T00:00:00Z"),
            payload("PyPI", 3, "2026-11-10T00:00:00Z"),
        ];
        let b = [a[1].clone(), a[0].clone()];
        let first = encode(&plain("OSV", &a)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert_eq!(first, encode(&plain("OSV", &b)).unwrap());
    }

    /// An unknown format, another file or a truncated one is refused
    /// with the path, never misread; a missing file is `None`.
    #[test]
    fn test_unknown_or_broken_files_are_refused() {
        let good = encode(&plain("OSV", &[payload("PyPI", 1, "2026-01-01T00:00:00Z")])).unwrap();
        let mut newer = good.clone();
        newer[4..8].copy_from_slice(&2u32.to_le_bytes());
        let err = decode(Path::new("db.cfdb"), newer).unwrap_err().to_string();
        assert!(err.contains("db.cfdb") && err.contains("format 2"), "{err}");
        assert!(decode(Path::new("x"), b"{\"format\":1}".to_vec()).is_err());
        assert!(decode(Path::new("x"), good[..14].to_vec()).is_err());
        let mut cut = good.clone();
        cut.truncate(good.len() - 5);
        let db = decode(Path::new("x"), cut).unwrap();
        assert!(db.ecosystem_json("PyPI").unwrap().is_err());
        let dir = std::env::temp_dir().join(format!("cfdb-missing-{}", std::process::id()));
        assert!(read(&dir.join(FILE_NAME)).unwrap().is_none());
    }

    /// ADR-0052: a database of the former `.sadb` format is refused with
    /// a reason, not read and not reported as an unknown file.
    #[test]
    fn test_former_sadb_database_is_refused_with_a_clear_reason() {
        let mut old = encode(&plain("OSV", &[payload("PyPI", 1, "2026-01-01T00:00:00Z")])).unwrap();
        old[..4].copy_from_slice(b"SADB");
        let err = decode(Path::new("advisories.sadb"), old)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("former .sadb format") && err.contains(".cfdb"),
            "{err}"
        );
    }

    /// Security regression (2026-11-15): one gzip member is bounded when
    /// decompressed, against a decompression bomb. A member whose content
    /// exceeds the cap is an error, not an unbounded allocation; within the
    /// cap it reads back exactly.
    #[test]
    fn test_decompress_capped_rejects_oversized_member() {
        // A gzip member of 2000 bytes of easily compressible data.
        let plain = vec![b'a'; 2000];
        let mut enc = flate2::GzBuilder::new().write(Vec::new(), Compression::best());
        enc.write_all(&plain).unwrap();
        let member = enc.finish().unwrap();
        assert!(member.len() < 100, "a bomb-like ratio: tiny compressed");
        // Under a tiny cap: refused rather than expanded.
        let err = decompress_capped(&member, 100).unwrap_err();
        assert_eq!(err, DecompressError::TooLarge);
        // Under a generous cap: read back exactly.
        assert_eq!(decompress_capped(&member, 1 << 20).unwrap(), plain);
    }

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
    /// placeholders of the English one; the group holds no other key.
    #[test]
    fn test_every_database_error_is_translated_with_its_placeholders() {
        let english = crate::i18n::load_script_locale("en");
        for lang in ["en", "fr", "es", "de"] {
            let locale = crate::i18n::load_script_locale(lang);
            let group = locale["advisory_file"].as_object().expect("group");
            assert_eq!(group.len(), keys::ALL.len(), "{lang}");
            for key in keys::ALL {
                let text = crate::i18n::get_nested(&locale, key)
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| panic!("{lang}: {key} missing"));
                let english_text = crate::i18n::get_nested(&english, key)
                    .and_then(|v| v.as_str())
                    .unwrap();
                assert_eq!(
                    placeholders(text),
                    placeholders(english_text),
                    "{lang}: {key}"
                );
            }
        }
    }

    /// Ticket #280: a database that cannot be decoded is named in the
    /// console's language, here French.
    #[test]
    fn test_decode_error_is_rendered_in_the_console_language() {
        let french = crate::i18n::load_script_locale("fr");
        let error = decode(Path::new("x.cfdb"), b"not a database".to_vec()).unwrap_err();
        assert_eq!(
            error.render(&french),
            "x.cfdb : ce fichier n'est pas une base de vulnérabilités (cfdb)"
        );
        assert_eq!(
            error.to_string(),
            "x.cfdb: not an advisory database (cfdb) file"
        );
        let good = encode(&plain("OSV", &[payload("PyPI", 1, "2026-01-01T00:00:00Z")])).unwrap();
        let mut cut = good.clone();
        cut.truncate(good.len() - 5);
        let db = decode(Path::new("x.cfdb"), cut).unwrap();
        let member = db.ecosystem_json("PyPI").unwrap().unwrap_err();
        assert_eq!(member.render(&french), "x.cfdb : PyPI est hors du fichier");
        // A member in place whose bytes are not gzip.
        let mut broken = good.clone();
        let last = broken.len() - 1;
        broken[last - 8..=last].fill(0);
        let db = decode(Path::new("x.cfdb"), broken).unwrap();
        let member = db.ecosystem_json("PyPI").unwrap().unwrap_err();
        assert!(
            member.render(&french).starts_with("x.cfdb : PyPI : "),
            "{}",
            member.render(&french)
        );
    }

    #[test]
    fn test_created_is_the_latest_instant_not_the_largest_text() {
        let a = [
            payload("PyPI", 1, "2026-11-07T10:00:00Z"),
            payload("npm", 1, "2026-11-07T10:00:00.5Z"),
        ];
        let db = decode(Path::new("x.cfdb"), encode(&plain("OSV", &a)).unwrap()).unwrap();
        assert_eq!(db.header.created, "2026-11-07T10:00:00.5Z");
        assert_eq!(
            newest_date(["garbage", "2026-01-01T00:00:00+02:00"].into_iter()),
            Some("2026-01-01T00:00:00+02:00")
        );
        assert_eq!(newest_date(std::iter::empty()), None);
    }

    #[test]
    fn test_write_is_atomic_and_readable() {
        let dir = std::env::temp_dir().join(format!("cfdb-write-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE_NAME);
        write(
            &path,
            &plain("OSV", &[payload("NuGet", 2, "2026-01-01T00:00:00Z")]),
        )
        .unwrap();
        let db = read(&path).unwrap().unwrap();
        assert_eq!(db.header.ecosystems[0].name, "NuGet");
        assert!(!dir.join("advisories.cfdb.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ADR-0051: the sources and the tables are written and read back; a
    /// header without them (a file written before) reads as having none.
    #[test]
    fn test_sources_and_tables_are_read_back_and_optional() {
        let ecosystems = [payload("PyPI", 1, "2026-11-10T00:00:00Z")];
        let sources = [DataSource {
            name: "CISA KEV".to_string(),
            url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog".to_string(),
            license: "CC0-1.0".to_string(),
            records: 1,
        }];
        let tables = [TablePayload {
            name: "kev".to_string(),
            date: "2026-11-18".to_string(),
            rows: 1,
            json: br#"{"CVE-2021-44228":{}}"#.to_vec(),
        }];
        let contents = Contents {
            source: "OSV",
            sources: &sources,
            ecosystems: &ecosystems,
            tables: &tables,
        };
        let db = decode(Path::new("x.cfdb"), encode(&contents).unwrap()).unwrap();
        assert_eq!(db.header.sources, sources);
        assert_eq!(db.header.tables[0].rows, 1);
        assert_eq!(db.table_json("kev").unwrap().unwrap(), tables[0].json);
        assert!(db.table_json("epss").is_none());
        assert_eq!(
            db.ecosystem_json("PyPI").unwrap().unwrap(),
            ecosystems[0].json
        );

        let old = decode(
            Path::new("x.cfdb"),
            encode(&plain("OSV", &ecosystems)).unwrap(),
        )
        .unwrap();
        assert!(old.header.sources.is_empty() && old.header.tables.is_empty());
        let header = r#"{"format":1,"created":"","source":"OSV","ecosystems":[]}"#;
        let parsed: Header = serde_json::from_str(header).unwrap();
        assert!(parsed.sources.is_empty() && parsed.tables.is_empty());
    }
}
