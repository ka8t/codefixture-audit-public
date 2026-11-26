//! The systems and language runtimes the engine checks it runs on
//! (ADR-0071), and the two tables of the advisory database that describe
//! them: `lifecycle` (release cycles, latest versions, support, from
//! endoflife.date) and `platform` (the CVEs whose NVD configurations mark
//! one of their CPEs vulnerable).
//!
//! [`PRODUCTS`] is the one list of what is followed: the advisories tool
//! reads it to know which endoflife.date products to download and which
//! CPEs to keep from the NVD feeds; the engine reads it to tell what it
//! detected. The row types below are shared by the writer and the reader,
//! like the CWE catalog's (`report::cwe_catalog`).

use serde::{Deserialize, Serialize};

/// Name of the table of release cycles in the database.
pub const LIFECYCLE_TABLE: &str = "lifecycle";

/// Name of the table of platform vulnerabilities in the database.
pub const PLATFORM_TABLE: &str = "platform";

/// What a followed product is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An operating system.
    System,
    /// The runtime of the scanned languages listed (the engine's language
    /// names, as `.sca` rules write them).
    Runtime(&'static [&'static str]),
}

/// One followed product.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Product {
    /// Its endoflife.date product name, the key of its `lifecycle` row.
    pub id: &'static str,
    /// Name shown on the console.
    pub label: &'static str,
    pub kind: Kind,
    /// The NVD CPE products (`part:vendor:product`) whose vulnerable
    /// matches are kept for it. A trailing `*` keeps every product that
    /// starts so (`o:microsoft:windows_11_*`: one CPE product per release).
    pub cpes: &'static [&'static str],
}

/// Every product followed (ADR-0071). The JDK builds that follow
/// OpenJDK's numbers are compared with OpenJDK's CPE and their own
/// vendor's support (the maintainer, 2026-11-26).
pub const PRODUCTS: &[Product] = &[
    Product {
        id: "macos",
        label: "macOS",
        kind: Kind::System,
        cpes: &["o:apple:macos"],
    },
    Product {
        id: "windows",
        label: "Windows",
        kind: Kind::System,
        cpes: &["o:microsoft:windows_10_*", "o:microsoft:windows_11_*"],
    },
    Product {
        id: "windows-server",
        label: "Windows Server",
        kind: Kind::System,
        cpes: &["o:microsoft:windows_server_*"],
    },
    Product {
        id: "ubuntu",
        label: "Ubuntu",
        kind: Kind::System,
        cpes: &["o:canonical:ubuntu_linux"],
    },
    Product {
        id: "debian",
        label: "Debian",
        kind: Kind::System,
        cpes: &["o:debian:debian_linux"],
    },
    Product {
        id: "rhel",
        label: "Red Hat Enterprise Linux",
        kind: Kind::System,
        cpes: &["o:redhat:enterprise_linux"],
    },
    Product {
        id: "fedora",
        label: "Fedora",
        kind: Kind::System,
        cpes: &["o:fedoraproject:fedora"],
    },
    Product {
        id: "alpine-linux",
        label: "Alpine Linux",
        kind: Kind::System,
        cpes: &["o:alpinelinux:alpine_linux"],
    },
    Product {
        id: "amazon-linux",
        label: "Amazon Linux",
        kind: Kind::System,
        cpes: &["o:amazon:linux", "o:amazon:amazon_linux"],
    },
    Product {
        id: "rocky-linux",
        label: "Rocky Linux",
        kind: Kind::System,
        cpes: &["o:rocky:rocky"],
    },
    Product {
        id: "almalinux",
        label: "AlmaLinux",
        kind: Kind::System,
        cpes: &["o:almalinux:almalinux"],
    },
    Product {
        id: "opensuse",
        label: "openSUSE",
        kind: Kind::System,
        cpes: &["o:opensuse:leap", "o:opensuse:opensuse"],
    },
    Product {
        id: "centos-stream",
        label: "CentOS Stream",
        kind: Kind::System,
        cpes: &["o:centos:stream"],
    },
    Product {
        id: "python",
        label: "Python",
        kind: Kind::Runtime(&["python"]),
        cpes: &["a:python:python"],
    },
    Product {
        id: "nodejs",
        label: "Node.js",
        kind: Kind::Runtime(&["javascript", "typescript"]),
        cpes: &["a:nodejs:node.js"],
    },
    Product {
        id: "php",
        label: "PHP",
        kind: Kind::Runtime(&["php"]),
        cpes: &["a:php:php"],
    },
    Product {
        id: "dotnet",
        label: ".NET",
        kind: Kind::Runtime(&["csharp"]),
        cpes: &["a:microsoft:.net", "a:microsoft:.net_core"],
    },
    Product {
        id: "oracle-jdk",
        label: "Oracle JDK",
        kind: Kind::Runtime(&["java"]),
        cpes: &["a:oracle:jdk", "a:oracle:jre"],
    },
    Product {
        id: "openjdk-builds-from-oracle",
        label: "OpenJDK",
        kind: Kind::Runtime(&["java"]),
        cpes: &["a:oracle:openjdk"],
    },
    Product {
        id: "eclipse-temurin",
        label: "Eclipse Temurin",
        kind: Kind::Runtime(&["java"]),
        cpes: &["a:oracle:openjdk", "a:eclipse:temurin"],
    },
    Product {
        id: "amazon-corretto",
        label: "Amazon Corretto",
        kind: Kind::Runtime(&["java"]),
        cpes: &["a:oracle:openjdk", "a:amazon:corretto"],
    },
    Product {
        id: "microsoft-build-of-openjdk",
        label: "Microsoft Build of OpenJDK",
        kind: Kind::Runtime(&["java"]),
        cpes: &["a:oracle:openjdk"],
    },
    Product {
        id: "redhat-build-of-openjdk",
        label: "Red Hat build of OpenJDK",
        kind: Kind::Runtime(&["java"]),
        cpes: &["a:oracle:openjdk"],
    },
    Product {
        id: "sapmachine",
        label: "SapMachine",
        kind: Kind::Runtime(&["java"]),
        cpes: &["a:oracle:openjdk"],
    },
];

/// The product `id`.
pub fn product(id: &str) -> Option<&'static Product> {
    PRODUCTS.iter().find(|p| p.id == id)
}

/// Whether the CPE product `cpe` (`o:microsoft:windows_11_24h2`) is one
/// of `patterns`.
pub fn cpe_matches(patterns: &[&str], cpe: &str) -> bool {
    patterns.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => cpe.starts_with(prefix),
        None => cpe == *p,
    })
}

/// Whether the CPE product `cpe` is followed by any product.
pub fn is_followed(cpe: &str) -> bool {
    PRODUCTS.iter().any(|p| cpe_matches(p.cpes, cpe))
}

/// One row of the `lifecycle` table: a product's release cycles, newest
/// first, as endoflife.date gives them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LifecycleRow {
    pub cycles: Vec<Cycle>,
}

/// One release cycle (`3.12`, `24.04`, `11-24h2-e`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cycle {
    pub name: String,
    /// Its latest version, when endoflife.date gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    /// Still supported by its vendor.
    pub maintained: bool,
    /// End of support (`YYYY-MM-DD`), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eol: Option<String>,
}

/// One vulnerable match of the `platform` table: a CVE, the version range
/// of the CPE product it affects, and its NVD score. The table is keyed by
/// CPE product (`o:apple:macos`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformVulnerability {
    pub cve: String,
    /// An exact version (`3.9.1`), when the match names one instead of a
    /// range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_including: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_excluding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_including: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_excluding: Option<String>,
    /// The NVD's qualitative severity of the CVE, `None` without a score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

impl PlatformVulnerability {
    /// Whether `version` is in this match. A match without any bound and
    /// without an exact version (`*`) covers every version.
    pub fn affects(&self, version: &str) -> bool {
        use std::cmp::Ordering::*;
        let cmp = crate::project::advisories::compare_versions;
        if let Some(exact) = &self.version {
            return cmp(version, exact) == Equal;
        }
        let after = |b: &Option<String>, ok: &[std::cmp::Ordering]| {
            b.as_ref().is_none_or(|b| ok.contains(&cmp(version, b)))
        };
        after(&self.start_including, &[Greater, Equal])
            && after(&self.start_excluding, &[Greater])
            && after(&self.end_including, &[Less, Equal])
            && after(&self.end_excluding, &[Less])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A prefix pattern keeps every release CPE, a plain one its own.
    #[test]
    fn test_cpe_patterns() {
        assert!(is_followed("o:microsoft:windows_11_24h2"));
        assert!(is_followed("a:python:python"));
        assert!(!is_followed("a:python:pip"));
        assert!(!is_followed("o:microsoft:windows"));
    }

    /// Bounds are inclusive or exclusive as named; an exact version only
    /// matches itself; no bound matches all.
    #[test]
    fn test_affects() {
        let range = PlatformVulnerability {
            cve: "CVE-1".into(),
            version: None,
            start_including: Some("3.10".into()),
            start_excluding: None,
            end_including: None,
            end_excluding: Some("3.10.21".into()),
            severity: None,
        };
        assert!(range.affects("3.10.0") && range.affects("3.10.20"));
        assert!(!range.affects("3.10.21") && !range.affects("3.9.9"));
        let build = PlatformVulnerability {
            end_excluding: Some("10.0.26100.8875".into()),
            start_including: None,
            ..range.clone()
        };
        assert!(build.affects("10.0.26100.8000") && !build.affects("10.0.26100.8875"));
        let exact = PlatformVulnerability {
            version: Some("11.0".into()),
            ..range.clone()
        };
        assert!(exact.affects("11") && !exact.affects("12"));
        let all = PlatformVulnerability {
            start_including: None,
            end_excluding: None,
            ..range
        };
        assert!(all.affects("1.0"));
    }
}
