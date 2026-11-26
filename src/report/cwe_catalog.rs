//! The CWE and CAPEC catalogs embedded in the engine (ADR-0070): the name
//! and status of every CWE entry, the CAPEC attack patterns each one points
//! to, and the name, typical severity and likelihood of every CAPEC attack
//! pattern.
//!
//! A finding cites its weakness by id (`CWE-79`), from its rule's
//! `metadata` or from the advisories of a dependency. The reports show the
//! name and the attack patterns beside it. The catalog is part of the
//! binary, like the translations, because the advisory database is read
//! by the dependency phase only: a scan with `--quick`, of a project
//! without a manifest, or with a folder of rules, still names every CWE.
//!
//! `resources/mappings/cwe_catalog.json` is written by
//! `codefixture-audit-advisories catalog` from MITRE's XML files, with
//! the types below: writer and reader share one definition, and
//! [`FORMAT_VERSION`] guards it. It holds MITRE's copyright designation and
//! license for each catalog (`notice`), which their terms of use require
//! in every copy; the reports credit them.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

/// Version of the layout below. A catalog of another version is refused
/// by the test that reads the embedded file, so a build never ships one
/// it misreads.
pub const FORMAT_VERSION: u32 = 1;

/// Where the catalog sits in the repository, for the tool that writes it.
pub const FILE: &str = "resources/mappings/cwe_catalog.json";

/// The embedded catalog file.
const EMBEDDED: &str = include_str!("../../resources/mappings/cwe_catalog.json");

/// The two catalogs, as `catalog` writes them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CweCatalog {
    pub format: u32,
    /// The CWE release read (`Weakness_Catalog` `Version` and `Date`).
    pub cwe: Release,
    /// The CAPEC release read (`Attack_Pattern_Catalog`).
    pub capec: Release,
    /// Every CWE entry by id (`CWE-79`): weaknesses, groupings and views.
    pub weaknesses: BTreeMap<String, Weakness>,
    /// Every CAPEC attack pattern by id (`CAPEC-63`).
    pub attack_patterns: BTreeMap<String, AttackPattern>,
}

/// One release of a catalog, with what its terms of use ask to reproduce.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Release {
    pub version: String,
    /// `YYYY-MM-DD`, as the catalog's root element gives it.
    pub date: String,
    /// Where it is published.
    pub url: String,
    /// MITRE's copyright designation and license, verbatim.
    pub notice: String,
}

/// What kind of CWE entry an id names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A weakness (`<Weakness>`).
    Weakness,
    /// A grouping of weaknesses (`<Grouping>`, called a category before
    /// CWE 5.0), such as CWE-1395.
    Grouping,
    /// A view (`<View>`), such as CWE-1000.
    View,
}

/// One CWE entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Weakness {
    /// The name, as MITRE writes it (`Improper Neutralization of Input
    /// During Web Page Generation ('Cross-site Scripting')`).
    pub name: String,
    pub kind: EntryKind,
    /// `Stable`, `Usable`, `Draft`, `Incomplete`, `Obsolete` or
    /// `Deprecated`. A deprecated id is never reused, and keeps its name.
    pub status: String,
    /// The CAPEC attack patterns it points to (`CAPEC-63`), in the
    /// catalog's order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attack_patterns: Vec<String>,
}

impl Weakness {
    /// `true` when MITRE removed this entry from the list.
    pub fn is_deprecated(&self) -> bool {
        self.status == "Deprecated"
    }
}

/// One CAPEC attack pattern.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackPattern {
    pub name: String,
    pub status: String,
    /// `Very High`, `High`, `Medium`, `Low` or `Very Low`, when given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// `High`, `Medium` or `Low`, when given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub likelihood: Option<String>,
}

/// The embedded catalog, read once.
static CATALOG: LazyLock<CweCatalog> = LazyLock::new(|| {
    // The file is checked by `test_embedded_catalog_is_readable`: a
    // build whose catalog does not read never passes its tests.
    serde_json::from_str(EMBEDDED).expect("embedded CWE catalog is valid")
});

/// The catalog embedded in this build.
pub fn catalog() -> &'static CweCatalog {
    &CATALOG
}

/// The CWE entry `id` (`CWE-79`), `None` when the catalog has none: the
/// reports then show the id alone.
pub fn weakness(id: &str) -> Option<&'static Weakness> {
    catalog().weaknesses.get(id.trim())
}

/// The names of the CWE entries among `ids` that the catalog holds, by id,
/// for the exports that list a finding's CWEs by id (JSON, text).
pub fn names_of<'a>(ids: impl IntoIterator<Item = &'a String>) -> BTreeMap<String, String> {
    ids.into_iter()
        .filter_map(|id| Some((id.trim().to_string(), weakness(id)?.name.clone())))
        .collect()
}

/// The attack patterns of the CWE entry `id`, with their CAPEC id, in the
/// catalog's order. An id the CAPEC catalog does not hold is kept, with no
/// pattern, so that the reader still sees it.
pub fn attack_patterns(id: &str) -> Vec<(&'static str, Option<&'static AttackPattern>)> {
    let Some(weakness) = weakness(id) else {
        return Vec::new();
    };
    weakness
        .attack_patterns
        .iter()
        .map(|capec| (capec.as_str(), catalog().attack_patterns.get(capec)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded file reads, in this format, and names the CWEs the
    /// engine itself cites.
    #[test]
    fn test_embedded_catalog_is_readable() {
        let catalog: CweCatalog = serde_json::from_str(EMBEDDED).unwrap();
        assert_eq!(catalog.format, FORMAT_VERSION);
        assert!(catalog.cwe.notice.contains("MITRE"));
        assert!(catalog.capec.notice.contains("MITRE"));
        // CWE-1395 is the default of a dependency finding without a CWE.
        for id in ["CWE-79", "CWE-89", "CWE-1395"] {
            assert!(weakness(id).is_some(), "{id}");
        }
    }

    /// The attack patterns of a weakness come with their CAPEC entry.
    #[test]
    fn test_attack_patterns_of_a_weakness() {
        let patterns = attack_patterns("CWE-89");
        assert!(!patterns.is_empty());
        assert!(patterns.iter().all(|(id, _)| id.starts_with("CAPEC-")));
        assert!(attack_patterns("CWE-0").is_empty());
    }
}
