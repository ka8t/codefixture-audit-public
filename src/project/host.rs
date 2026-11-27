//! The system the engine runs on and the runtimes of the scanned
//! languages, checked against the pack (ADR-0071): is each one at the
//! latest version of its release cycle, still supported, hit by a known
//! vulnerability?
//!
//! Nothing here opens a connection. The system is read from files or the
//! registry (macOS `SystemVersion.plist`, Windows `reg.exe query`, Linux
//! `/etc/os-release`); a runtime answers its own version option (`python3
//! --version`). The data come from the `lifecycle` and `platform` tables
//! of the pack's version rules, which `codefixture-audit-advisories` fills
//! from endoflife.date and the NVD, at the date the pack states.
//!
//! **A project cannot run code here.** A runtime is looked up on `PATH`,
//! and a program found inside the scanned folder is skipped: a project
//! must not get its own `python` run by placing it in its root (Windows
//! looks in the current folder first, and a `PATH` may name `.`).
//!
//! **Linux** (the maintainer, 2026-11-26): distributions backport fixes without
//! changing the upstream version, so a vulnerability found for the
//! distribution or a runtime on Linux is marked "to confirm".

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::project::advisories::{Epss, Exploited, compare_versions};
use crate::project::advisory_file::DatabaseFile;
use crate::project::platform::{
    LIFECYCLE_TABLE, LifecycleRow, PLATFORM_TABLE, PlatformVulnerability, Product, product,
};

/// How long a runtime may take to print its version before it is given up.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);

/// Age of the data, in days, beyond which the check says they are old
/// (the maintainer, 2026-11-26: Apple and Microsoft publish fixes every month).
pub const STALE_AFTER_DAYS: i64 = 30;

/// A system or runtime found on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    pub product: &'static Product,
    /// The version shown and compared with the cycle's latest one
    /// (`26.0.1`, `10.0.26100.4349`, `3.12.1`).
    pub version: String,
    /// The release cycle, when the detection names it (Windows:
    /// `11-24h2-w`); otherwise the longest cycle name `version` starts with.
    pub cycle: Option<String>,
    /// The CPE products its vulnerabilities are listed under, exactly
    /// (`o:microsoft:windows_11_24h2`); the product's own CPEs by default.
    pub cpes: Vec<String>,
    /// Running on Linux: a vulnerability found is "to confirm".
    pub on_linux: bool,
    /// The version compared with the NVD's CPE matches, when it is not
    /// `version`: a Linux distribution's release (`24.04`, `13`), which
    /// the NVD names exactly (`ubuntu_linux:24.04`), while `version` holds
    /// its point release (`24.04.5`, `13.7`).
    pub cpe_version: Option<String>,
    /// The version as the console and the report name it: `version`,
    /// except Windows, whose release goes first (`Server 2025
    /// (10.0.26100.33828)`, `11 24H2 (10.0.26100.4349)`), since a build
    /// number alone does not say which Windows it is (seen on a GitHub
    /// runner, 2026-11-26).
    pub shown_version: String,
}

/// Something that could not be detected, named for the console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotDetected {
    /// What was looked for (`Python`, the system).
    pub what: String,
    pub reason: String,
    /// The programs looked for, when none was found on `PATH` outside the
    /// scanned folder: the console says so in its language rather than
    /// show `reason`.
    pub not_found: Option<String>,
    /// The first line a program printed when it gave no version (macOS's
    /// `java` without a JDK: "Unable to locate a Java Runtime"): the
    /// console quotes it in its language rather than show `reason`.
    pub no_version: Option<String>,
}

/// The two tables of the pack, and the KEV and EPSS rows of their CVEs
/// (ADR-0071). The advisories tool keeps the KEV and EPSS rows of the
/// system CVEs too (`Database::cves` names the platform table's), so the
/// report can detail each vulnerability of the system (ADR-0072, amended
/// 2026-11-26).
#[derive(Debug, Clone, Default)]
pub struct Tables {
    pub lifecycle: BTreeMap<String, LifecycleRow>,
    pub platform: BTreeMap<String, Vec<PlatformVulnerability>>,
    /// The CVEs CISA lists as exploited, with the date it added them.
    pub kev: BTreeMap<String, Exploited>,
    /// The EPSS probability of each scored CVE, 0 to 1.
    pub epss: BTreeMap<String, f64>,
    /// Date of the data: the lifecycle table's (`YYYY-MM-DD`).
    pub date: String,
}

/// The tables of the version rules `file`; `None` when the pack holds no
/// lifecycle table (written before ADR-0071). A table that cannot be read
/// is an error naming it.
pub fn load_tables(file: &DatabaseFile) -> Result<Option<Tables>, String> {
    #[derive(serde::Deserialize)]
    struct Table<T> {
        cves: BTreeMap<String, T>,
    }
    fn read<T: serde::de::DeserializeOwned>(
        file: &DatabaseFile,
        name: &str,
    ) -> Result<Option<BTreeMap<String, T>>, String> {
        let Some(json) = file.table_json(name) else {
            return Ok(None);
        };
        let json = json.map_err(|e| e.to_string())?;
        let table: Table<T> =
            serde_json::from_slice(&json).map_err(|e| format!("table {name}: {e}"))?;
        Ok(Some(table.cves))
    }
    let Some(lifecycle) = read::<LifecycleRow>(file, LIFECYCLE_TABLE)? else {
        return Ok(None);
    };
    let platform = read::<Vec<PlatformVulnerability>>(file, PLATFORM_TABLE)?.unwrap_or_default();
    let kev = read::<Exploited>(file, "kev")?.unwrap_or_default();
    let epss = read::<Epss>(file, "epss")?
        .unwrap_or_default()
        .into_iter()
        .map(|(cve, row)| (cve, row.epss))
        .collect();
    let date = file
        .header
        .tables
        .iter()
        .find(|t| t.name == LIFECYCLE_TABLE)
        .map(|t| t.date.clone())
        .unwrap_or_default();
    Ok(Some(Tables {
        lifecycle,
        platform,
        kev,
        epss,
        date,
    }))
}

// ---------------------------------------------------------------------------
// The system
// ---------------------------------------------------------------------------

/// The system this engine runs on.
pub fn detect_system() -> Result<Detected, NotDetected> {
    let fail = |reason: String| NotDetected {
        what: std::env::consts::OS.to_string(),
        reason,
        not_found: None,
        no_version: None,
    };
    match std::env::consts::OS {
        "macos" => {
            let plist = std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist")
                .map_err(|e| fail(format!("SystemVersion.plist: {e}")))?;
            macos_from_plist(&plist).map_err(fail)
        }
        "windows" => {
            let reg = std::env::var_os("SystemRoot")
                .map(|root| PathBuf::from(root).join("System32").join("reg.exe"))
                .ok_or_else(|| fail("SystemRoot is not set".to_string()))?;
            let output = run(
                &reg,
                &[
                    "query",
                    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                ],
            )
            .map_err(fail)?;
            windows_from_registry(&output).map_err(fail)
        }
        "linux" => {
            let release = std::fs::read_to_string("/etc/os-release")
                .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
                .map_err(|e| fail(format!("/etc/os-release: {e}")))?;
            let debian = std::fs::read_to_string("/etc/debian_version").ok();
            linux_from_os_release(&release, debian.as_deref()).map_err(fail)
        }
        other => Err(fail(format!("{other} is not a followed system"))),
    }
}

/// macOS from its `SystemVersion.plist`: the string after the
/// `ProductVersion` key.
fn macos_from_plist(plist: &str) -> Result<Detected, String> {
    let root =
        crate::project::xml::parse(plist).map_err(|e| format!("SystemVersion.plist: {e}"))?;
    let dict = root.child("dict").ok_or("SystemVersion.plist: no <dict>")?;
    let mut items = dict.elements();
    let mut version = None;
    while let Some(item) = items.next() {
        if item.name == "key" && item.text().trim() == "ProductVersion" {
            version = items.next().map(|v| v.text().trim().to_string());
            break;
        }
    }
    let version = version
        .filter(|v| !v.is_empty())
        .ok_or("SystemVersion.plist: no ProductVersion")?;
    Ok(with_defaults(
        product("macos").expect("followed"),
        version,
        false,
    ))
}

/// Windows from `reg query` of `CurrentVersion`: client or server
/// (`InstallationType`), release (`DisplayVersion`, `24H2`), build and
/// revision (`CurrentBuild`, `UBR`), edition (`EditionID`). Windows 11
/// still writes "Windows 10" in `ProductName`: build 22000 and above is
/// Windows 11.
fn windows_from_registry(output: &str) -> Result<Detected, String> {
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[1].starts_with("REG_") {
            values.insert(fields[0].to_string(), fields[2..].join(" "));
        }
    }
    let get = |key: &str| values.get(key).map(String::as_str);
    let build: u64 = get("CurrentBuild")
        .and_then(|b| b.parse().ok())
        .ok_or("the registry gives no CurrentBuild")?;
    let revision = get("UBR")
        .and_then(|u| u64::from_str_radix(u.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    let version = format!("10.0.{build}.{revision}");
    let server = get("InstallationType").is_some_and(|t| t.contains("Server"));
    if server {
        let name = get("ProductName").unwrap_or_default();
        let year = name
            .split_whitespace()
            .find(|w| w.len() == 4 && w.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| format!("Windows Server release not found in {name:?}"))?;
        let mut detected =
            with_defaults(product("windows-server").expect("followed"), version, false);
        detected.shown_version = format!("{year} ({})", detected.version);
        detected.cycle = Some(year.to_string());
        detected.cpes = vec![format!("o:microsoft:windows_server_{year}")];
        return Ok(detected);
    }
    let release = get("DisplayVersion")
        .or_else(|| get("ReleaseId"))
        .ok_or("the registry gives no DisplayVersion")?
        .to_ascii_lowercase();
    let major = if build >= 22000 { "11" } else { "10" };
    let edition = get("EditionID").unwrap_or_default();
    let line = if edition.contains("Enterprise") || edition.contains("Education") {
        "e"
    } else {
        "w"
    };
    let mut detected = with_defaults(product("windows").expect("followed"), version, false);
    detected.shown_version = format!(
        "{major} {} ({})",
        release.to_ascii_uppercase(),
        detected.version
    );
    detected.cycle = Some(format!("{major}-{release}-{line}"));
    detected.cpes = vec![format!("o:microsoft:windows_{major}_{release}")];
    Ok(detected)
}

/// Linux from `/etc/os-release` (`ID`, `VERSION_ID`, `NAME`, and `VERSION`
/// when it extends `VERSION_ID`, as Ubuntu's point release does); Debian's
/// point release from `/etc/debian_version`, which `os-release` lacks.
fn linux_from_os_release(release: &str, debian_version: Option<&str>) -> Result<Detected, String> {
    let fields: BTreeMap<&str, String> = release
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim(), v.trim().trim_matches('"').to_string()))
        .collect();
    let id = fields.get("ID").map(String::as_str).unwrap_or_default();
    let name = fields.get("NAME").map(String::as_str).unwrap_or_default();
    let product_id = match id {
        "ubuntu" | "debian" | "rhel" | "fedora" | "almalinux" => id,
        "alpine" => "alpine-linux",
        "amzn" => "amazon-linux",
        "rocky" => "rocky-linux",
        "opensuse-leap" | "opensuse" => "opensuse",
        "centos" if name.contains("Stream") => "centos-stream",
        other => {
            return Err(format!(
                "Linux distribution {other:?} ({name}) is not followed"
            ));
        }
    };
    let release = fields
        .get("VERSION_ID")
        .cloned()
        .ok_or("/etc/os-release gives no VERSION_ID")?;
    let mut version = release.clone();
    // Ubuntu's point release is in `VERSION` ("24.04.5 LTS (Noble
    // Numbat)"), not in `VERSION_ID` ("24.04"): without it every Ubuntu
    // read as behind (found on the real image, 2026-11-26).
    if let Some(full) = fields
        .get("VERSION")
        .and_then(|v| v.split_whitespace().next())
        .filter(|v| v.starts_with(&format!("{version}.")))
    {
        version = full.to_string();
    }
    if product_id == "debian"
        && let Some(point) = debian_version.map(str::trim)
        && point.starts_with(&format!("{version}."))
    {
        version = point.to_string();
    }
    let mut detected = with_defaults(product(product_id).expect("followed"), version, true);
    detected.cpe_version = Some(release);
    Ok(detected)
}

/// A detection with the product's own CPEs and no named cycle.
fn with_defaults(product: &'static Product, version: String, on_linux: bool) -> Detected {
    Detected {
        product,
        shown_version: version.clone(),
        version,
        cycle: None,
        cpes: product.cpes.iter().map(|c| c.to_string()).collect(),
        on_linux,
        cpe_version: None,
    }
}

// ---------------------------------------------------------------------------
// The runtimes
// ---------------------------------------------------------------------------

/// The runtimes of `languages` (the engine's language names), looked up
/// on `PATH` outside `scanned`. A language whose runtime is not installed
/// gives a [`NotDetected`]; a runtime with several versions (.NET) gives
/// one detection per version.
pub fn detect_runtimes(
    languages: &BTreeSet<String>,
    scanned: &Path,
) -> Vec<Result<Detected, NotDetected>> {
    let on_linux = std::env::consts::OS == "linux";
    let wanted = |language: &str| languages.contains(language);
    let mut found = Vec::new();
    if wanted("python") {
        found.push(
            runtime_version("Python", &["python3", "python"], &["--version"], scanned)
                .and_then(|text| parse_simple(&text, "Python ", "python", on_linux)),
        );
    }
    if wanted("javascript") || wanted("typescript") {
        found.push(
            runtime_version("Node.js", &["node"], &["--version"], scanned)
                .and_then(|text| parse_simple(&text, "v", "nodejs", on_linux)),
        );
    }
    if wanted("php") {
        found.push(
            runtime_version("PHP", &["php"], &["-v"], scanned)
                .and_then(|text| parse_simple(&text, "PHP ", "php", on_linux)),
        );
    }
    if wanted("java") {
        found.push(
            runtime_version(
                "Java",
                &["java"],
                &["-XshowSettings:properties", "-version"],
                scanned,
            )
            .and_then(|text| parse_java(&text, on_linux)),
        );
    }
    if wanted("csharp") {
        match runtime_version(".NET", &["dotnet"], &["--list-runtimes"], scanned) {
            Ok(text) => found.extend(parse_dotnet(&text, on_linux)),
            Err(e) => found.push(Err(e)),
        }
    }
    found
}

/// The output of the first of `names` found on `PATH` outside `scanned`,
/// run with `args`.
fn runtime_version(
    what: &str,
    names: &[&str],
    args: &[&str],
    scanned: &Path,
) -> Result<String, NotDetected> {
    let fail = |reason: String| NotDetected {
        what: what.to_string(),
        reason,
        not_found: None,
        no_version: None,
    };
    let candidates = names
        .iter()
        .flat_map(|name| which::which_all(name).into_iter().flatten());
    let program = outside(candidates, scanned).ok_or_else(|| NotDetected {
        what: what.to_string(),
        reason: format!(
            "{} not found on PATH outside the scanned folder",
            names.join(" or ")
        ),
        not_found: Some(names.join(", ")),
        no_version: None,
    })?;
    run(&program, args).map_err(fail)
}

/// The first of `candidates` that is not inside `scanned`, links resolved.
fn outside(candidates: impl Iterator<Item = PathBuf>, scanned: &Path) -> Option<PathBuf> {
    let scanned = scanned
        .canonicalize()
        .unwrap_or_else(|_| scanned.to_path_buf());
    candidates.into_iter().find(|path| {
        let resolved = path.canonicalize().unwrap_or_else(|_| path.clone());
        !resolved.starts_with(&scanned)
    })
}

/// Runs `program` with `args`, its standard output and error together,
/// given up after [`VERSION_TIMEOUT`].
fn run(program: &Path, args: &[&str]) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {e}", program.display()))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() > VERSION_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{} gave no answer within {} s",
                    program.display(),
                    VERSION_TIMEOUT.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("{}: {e}", program.display())),
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("{}: {e}", program.display()))?;
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// The version after `prefix` on the first line that has one (`Python
/// 3.12.1`, `v22.3.0`, `PHP 8.3.1 (cli)`).
fn parse_simple(
    text: &str,
    prefix: &str,
    product_id: &str,
    on_linux: bool,
) -> Result<Detected, NotDetected> {
    let product = product(product_id).expect("followed");
    let version = text
        .lines()
        .find_map(|l| l.trim().strip_prefix(prefix))
        .and_then(|rest| rest.split_whitespace().next())
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
        .ok_or_else(|| NotDetected {
            what: product.label.to_string(),
            reason: format!(
                "no version in {:?}",
                text.lines().next().unwrap_or_default()
            ),
            not_found: None,
            no_version: first_line(text),
        })?;
    Ok(with_defaults(product, version.to_string(), on_linux))
}

/// The first line of a program's answer that is not blank, for a
/// [`NotDetected::no_version`].
fn first_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

/// A JDK from `java -XshowSettings:properties -version`: `java.version`,
/// and the vendor from `java.vendor` and `java.vm.name`. Oracle's JDK
/// and OpenJDK both say "Oracle Corporation": the VM name tells them
/// apart. A vendor not followed is compared with OpenJDK's CPE and has no
/// support data; the console names it.
fn parse_java(text: &str, on_linux: bool) -> Result<Detected, NotDetected> {
    let property = |key: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(key)?.trim().strip_prefix('='))
            .map(|v| v.trim().to_string())
    };
    let version = property("java.version").ok_or_else(|| NotDetected {
        what: "Java".to_string(),
        reason: "no java.version in the JDK's properties".to_string(),
        not_found: None,
        no_version: first_line(text),
    })?;
    let vendor = property("java.vendor").unwrap_or_default();
    let vm = property("java.vm.name").unwrap_or_default();
    let product_id = match vendor.as_str() {
        "Oracle Corporation" if vm.contains("OpenJDK") => "openjdk-builds-from-oracle",
        "Oracle Corporation" => "oracle-jdk",
        "Eclipse Adoptium" => "eclipse-temurin",
        "Amazon.com Inc." => "amazon-corretto",
        "Microsoft" => "microsoft-build-of-openjdk",
        "Red Hat, Inc." => "redhat-build-of-openjdk",
        "SAP SE" => "sapmachine",
        other => {
            return Err(NotDetected {
                what: "Java".to_string(),
                reason: format!("JDK {version} of vendor {other:?} is not followed"),
                not_found: None,
                no_version: None,
            });
        }
    };
    Ok(with_defaults(
        product(product_id).expect("followed"),
        version,
        on_linux,
    ))
}

/// Every .NET runtime of `dotnet --list-runtimes`
/// (`Microsoft.NETCore.App 8.0.1 [/usr/share/dotnet/…]`).
fn parse_dotnet(text: &str, on_linux: bool) -> Vec<Result<Detected, NotDetected>> {
    let product = product("dotnet").expect("followed");
    let versions: BTreeSet<String> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("Microsoft.NETCore.App "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_string)
        .collect();
    if versions.is_empty() {
        return vec![Err(NotDetected {
            what: product.label.to_string(),
            reason: "dotnet lists no Microsoft.NETCore.App runtime".to_string(),
            not_found: None,
            no_version: None,
        })];
    }
    versions
        .into_iter()
        .map(|v| Ok(with_defaults(product, v, on_linux)))
        .collect()
}

// ---------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------

/// Where a detected version stands in its release cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Support {
    /// The latest version of a supported cycle.
    UpToDate,
    /// A supported cycle whose latest version is newer.
    Behind { latest: String },
    /// A cycle its vendor no longer supports, since `eol` when known.
    Unsupported { eol: Option<String> },
    /// No cycle of the product matches the version: the data say nothing.
    UnknownCycle,
}

/// What the check says of one detection.
#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub detected: Detected,
    pub cycle: Option<String>,
    pub support: Support,
    /// The newest supported cycle and its latest version, when it is not
    /// the detected one (`macOS 27.2.1` for a machine on 26).
    pub newer: Option<(String, String)>,
    /// The vulnerabilities of this version, one per CVE.
    pub vulnerabilities: Vec<PlatformVulnerability>,
    /// How many of them CISA lists as exploited.
    pub exploited: usize,
    /// Their CVEs, in the order of `vulnerabilities` (ticket #308).
    pub exploited_cves: Vec<String>,
    /// The KEV row of each exploited one: since when, and whether
    /// ransomware uses it (the report's detail of the system).
    pub kev: BTreeMap<String, Exploited>,
    /// The EPSS probability of each scored one of `vulnerabilities`.
    pub epss: BTreeMap<String, f64>,
}

/// What the system check saw on this machine (ADR-0071), kept whole for
/// the priorities of the console and the report and for the report's
/// "System" section (ADR-0072, amended 2026-11-26): every detection, the
/// ones that could not be checked too, and why nothing was checked when
/// the pack holds no usable system data.
#[derive(Debug, Clone, Default)]
pub struct HostSurvey {
    /// Set when nothing was checked: the pack has no system data, or they
    /// could not be read. `entries` is then empty.
    pub unavailable: Option<HostUnavailable>,
    /// Date of the data (`YYYY-MM-DD`), empty when `unavailable`.
    pub date: String,
    /// Age of the data in days, when older than [`STALE_AFTER_DAYS`].
    pub stale_days: Option<i64>,
    /// One per detection, the system first, then the runtimes of the
    /// scanned languages.
    pub entries: Vec<HostEntry>,
}

/// One detection of the [`HostSurvey`].
#[derive(Debug, Clone)]
pub struct HostEntry {
    /// The system the engine runs on, not a runtime.
    pub system: bool,
    /// Its check, or why it could not be checked.
    pub result: Result<Check, NotDetected>,
}

/// Why the system check checked nothing.
#[derive(Debug, Clone)]
pub enum HostUnavailable {
    /// The pack carries no system data (built before ADR-0071).
    NoData,
    /// The version rules could not be opened: a pack error, written in
    /// the language of each output that shows it.
    PackUnreadable(crate::rules::pack_format::PackError),
    /// A system table could not be read (`load_tables`).
    TableUnreadable(String),
}

impl HostSurvey {
    /// The checks that could be made, the system first.
    pub fn checks(&self) -> impl Iterator<Item = &Check> {
        self.entries.iter().filter_map(|e| e.result.as_ref().ok())
    }
}

impl HostUnavailable {
    /// Why nothing was checked, in the language of `locale` (a script or
    /// a report locale: both hold the `host_*` texts).
    pub fn text(&self, locale: &serde_json::Value) -> String {
        let say = |key: &str| crate::i18n::t(locale, key);
        match self {
            Self::NoData => say("host_no_data"),
            Self::PackUnreadable(error) => {
                say("host_unreadable").replace("{error}", &error.render(locale))
            }
            Self::TableUnreadable(error) => say("host_unreadable").replace("{error}", error),
        }
    }
}

/// Why `missing` was not checked, in the language of `locale` (a script
/// or a report locale).
pub fn not_detected_text(missing: &NotDetected, locale: &serde_json::Value) -> String {
    let say = |key: &str| crate::i18n::t(locale, key);
    match (&missing.not_found, &missing.no_version) {
        (Some(programs), _) => say("host_not_installed")
            .replace("{what}", &missing.what)
            .replace("{programs}", programs),
        (None, Some(answer)) => say("host_no_version")
            .replace("{what}", &missing.what)
            .replace("{answer}", answer),
        (None, None) => say("host_not_checked")
            .replace("{what}", &missing.what)
            .replace("{reason}", &missing.reason),
    }
}

/// The line that sums `check` up, in the language of `locale` (a script
/// or a report locale): where its version stands in its release, the
/// newest release, its known vulnerabilities and the exploited ones, and
/// the date of the data. `system` picks the system's wording rather than
/// a runtime's. The console prints it; the report's "System" section
/// heads each detection with it (ADR-0072, amended 2026-11-26).
pub fn check_line(check: &Check, system: bool, date: &str, locale: &serde_json::Value) -> String {
    let say = |key: &str| crate::i18n::t(locale, key);
    let status = match &check.support {
        Support::UpToDate => say("host_status_up_to_date"),
        Support::Behind { latest } => say("host_status_behind").replace("{latest}", latest),
        Support::Unsupported { eol: Some(eol) } => {
            say("host_status_unsupported_since").replace("{eol}", eol)
        }
        Support::Unsupported { eol: None } => say("host_status_unsupported"),
        Support::UnknownCycle => say("host_status_unknown_cycle"),
    };
    let newer = check
        .newer
        .as_ref()
        .map(|(cycle, latest)| {
            // "26.10 (26.10)": a release whose latest version is its
            // own name is named once.
            if cycle == latest {
                say("host_newer_same").replace("{latest}", latest)
            } else {
                say("host_newer")
                    .replace("{cycle}", cycle)
                    .replace("{latest}", latest)
            }
        })
        .unwrap_or_default();
    let vulnerabilities = if check.vulnerabilities.is_empty() {
        String::new()
    } else {
        let mut text = say("host_vulnerabilities")
            .replace("{count}", &check.vulnerabilities.len().to_string())
            .replace(
                "{severity}",
                worst_severity(&check.vulnerabilities).unwrap_or("MEDIUM"),
            );
        if check.exploited > 0 {
            text.push_str(&say("host_exploited").replace("{count}", &check.exploited.to_string()));
        }
        if check.detected.on_linux {
            text.push_str(&say("host_to_confirm"));
        }
        text
    };
    let key = if system {
        "host_line_system"
    } else {
        "host_line_runtime"
    };
    say(key)
        .replace("{what}", check.detected.product.label)
        .replace("{version}", &check.detected.shown_version)
        .replace("{status}", &status)
        .replace("{newer}", &newer)
        .replace("{vulnerabilities}", &vulnerabilities)
        .replace("{date}", date)
}

/// Checks `detected` against `tables`.
pub fn check(detected: &Detected, tables: &Tables) -> Check {
    let row = tables.lifecycle.get(detected.product.id);
    let cycle = row.and_then(|row| match &detected.cycle {
        Some(named) => row.cycles.iter().find(|c| c.name == *named),
        None => row
            .cycles
            .iter()
            .filter(|c| {
                detected.version == c.name || detected.version.starts_with(&format!("{}.", c.name))
            })
            .max_by_key(|c| c.name.len()),
    });
    let support = match cycle {
        None => Support::UnknownCycle,
        Some(c) if !c.maintained => Support::Unsupported { eol: c.eol.clone() },
        Some(c) => match &c.latest {
            Some(latest) if compare_versions(&detected.version, latest).is_lt() => {
                Support::Behind {
                    latest: latest.clone(),
                }
            }
            _ => Support::UpToDate,
        },
    };
    let newer = row
        .and_then(|row| row.cycles.iter().find(|c| c.maintained))
        .filter(|newest| cycle.is_none_or(|c| c.name != newest.name))
        .and_then(|newest| Some((newest.name.clone(), newest.latest.clone()?)));
    let mut seen = BTreeSet::new();
    let vulnerabilities: Vec<PlatformVulnerability> = detected
        .cpes
        .iter()
        .filter_map(|cpe| tables.platform.get(cpe))
        .flatten()
        .filter(|v| v.affects(detected.cpe_version.as_deref().unwrap_or(&detected.version)))
        .filter(|v| seen.insert(v.cve.clone()))
        .cloned()
        .collect();
    let exploited_cves: Vec<String> = vulnerabilities
        .iter()
        .filter(|v| tables.kev.contains_key(&v.cve))
        .map(|v| v.cve.clone())
        .collect();
    let exploited = exploited_cves.len();
    let kev = exploited_cves
        .iter()
        .filter_map(|cve| Some((cve.clone(), tables.kev.get(cve)?.clone())))
        .collect();
    let epss = vulnerabilities
        .iter()
        .filter_map(|v| Some((v.cve.clone(), *tables.epss.get(&v.cve)?)))
        .collect();
    Check {
        detected: detected.clone(),
        cycle: cycle.map(|c| c.name.clone()),
        support,
        newer,
        vulnerabilities,
        exploited,
        exploited_cves,
        kev,
        epss,
    }
}

/// The worst NVD severity among `vulnerabilities`, `None` without any
/// scored one.
pub fn worst_severity(vulnerabilities: &[PlatformVulnerability]) -> Option<&'static str> {
    let rank = |s: &str| match s {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" | "NONE" => 1,
        _ => 0,
    };
    vulnerabilities
        .iter()
        .filter_map(|v| v.severity.as_deref())
        .max_by_key(|s| rank(s))
        .map(|s| match s {
            "CRITICAL" => "CRITICAL",
            "HIGH" => "HIGH",
            "MEDIUM" => "MEDIUM",
            _ => "LOW",
        })
}

/// Days from `date` (`YYYY-MM-DD`) to `today` (same form), `None` when
/// either is not a date.
pub fn days_between(date: &str, today: &str) -> Option<i64> {
    let parse = |d: &str| chrono::NaiveDate::parse_from_str(d.get(..10)?, "%Y-%m-%d").ok();
    Some((parse(today)? - parse(date)?).num_days())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::platform::Cycle;

    fn tables() -> Tables {
        let cycles = |list: &[(&str, &str, bool)]| LifecycleRow {
            cycles: list
                .iter()
                .map(|(name, latest, maintained)| Cycle {
                    name: name.to_string(),
                    latest: Some(latest.to_string()),
                    maintained: *maintained,
                    eol: (!maintained).then(|| "2025-01-01".to_string()),
                })
                .collect(),
        };
        let vulnerability = |cve: &str, end: &str, severity: &str| PlatformVulnerability {
            cve: cve.to_string(),
            version: None,
            start_including: None,
            start_excluding: None,
            end_including: None,
            end_excluding: Some(end.to_string()),
            severity: Some(severity.to_string()),
        };
        Tables {
            lifecycle: BTreeMap::from([
                (
                    "macos".to_string(),
                    cycles(&[
                        ("27", "27.2.1", true),
                        ("26", "26.7.3", true),
                        ("14", "14.8.9", false),
                    ]),
                ),
                (
                    "windows".to_string(),
                    cycles(&[("11-24h2-w", "10.0.26100", true)]),
                ),
                ("python".to_string(), cycles(&[("3.12", "3.12.16", true)])),
            ]),
            platform: BTreeMap::from([
                (
                    "o:apple:macos".to_string(),
                    vec![
                        vulnerability("CVE-1", "26.7.3", "HIGH"),
                        vulnerability("CVE-2", "26.5", "CRITICAL"),
                    ],
                ),
                (
                    "o:microsoft:windows_11_24h2".to_string(),
                    vec![vulnerability("CVE-3", "10.0.26100.8875", "HIGH")],
                ),
            ]),
            kev: BTreeMap::from([(
                "CVE-2".to_string(),
                Exploited {
                    added: "2026-10-01".to_string(),
                    ransomware: true,
                },
            )]),
            epss: BTreeMap::from([("CVE-1".to_string(), 0.02)]),
            date: "2026-11-26".to_string(),
        }
    }

    /// macOS behind in its cycle, a newer cycle out, two vulnerabilities,
    /// one exploited; the latest version has none.
    #[test]
    fn test_check_macos() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>ProductBuildVersion</key><string>25B78</string><key>ProductName</key><string>macOS</string><key>ProductVersion</key><string>26.1</string></dict></plist>"#;
        let detected = macos_from_plist(plist).unwrap();
        assert_eq!(detected.version, "26.1");
        let check = check(&detected, &tables());
        assert_eq!(check.cycle.as_deref(), Some("26"));
        assert_eq!(
            check.support,
            Support::Behind {
                latest: "26.7.3".to_string()
            }
        );
        assert_eq!(check.newer, Some(("27".to_string(), "27.2.1".to_string())));
        assert_eq!(check.vulnerabilities.len(), 2);
        assert_eq!(check.exploited, 1);
        // The KEV row of the exploited one and the EPSS of the scored one
        // follow the check, for the report's detail of the system.
        assert_eq!(check.kev["CVE-2"].added, "2026-10-01");
        assert!(check.kev["CVE-2"].ransomware);
        assert_eq!(check.epss.get("CVE-1"), Some(&0.02));
        assert_eq!(check.epss.get("CVE-2"), None);
        assert_eq!(worst_severity(&check.vulnerabilities), Some("CRITICAL"));

        let latest = Detected {
            version: "26.7.3".to_string(),
            ..detected.clone()
        };
        let up = super::check(&latest, &tables());
        assert_eq!(up.support, Support::UpToDate);
        assert!(up.vulnerabilities.is_empty());
        let old = Detected {
            version: "14.8.9".to_string(),
            ..detected
        };
        assert!(matches!(
            super::check(&old, &tables()).support,
            Support::Unsupported { .. }
        ));
    }

    /// Windows 11 from the registry: release cycle, edition, CPE of its
    /// release, build and revision.
    #[test]
    fn test_windows_from_registry() {
        let output = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\r\n    CurrentBuild    REG_SZ    26100\r\n    DisplayVersion    REG_SZ    24H2\r\n    EditionID    REG_SZ    Professional\r\n    InstallationType    REG_SZ    Client\r\n    ProductName    REG_SZ    Windows 10 Pro\r\n    UBR    REG_DWORD    0x10fd\r\n";
        let detected = windows_from_registry(output).unwrap();
        assert_eq!(detected.product.id, "windows");
        assert_eq!(detected.version, "10.0.26100.4349");
        assert_eq!(detected.cycle.as_deref(), Some("11-24h2-w"));
        assert_eq!(detected.cpes, vec!["o:microsoft:windows_11_24h2"]);
        assert_eq!(detected.shown_version, "11 24H2 (10.0.26100.4349)");
        let check = check(&detected, &tables());
        assert_eq!(check.support, Support::UpToDate);
        assert_eq!(check.vulnerabilities[0].cve, "CVE-3");

        let server = "    CurrentBuild    REG_SZ    20348\r\n    InstallationType    REG_SZ    Server\r\n    ProductName    REG_SZ    Windows Server 2022 Datacenter\r\n    UBR    REG_DWORD    0x1\r\n";
        let detected = windows_from_registry(server).unwrap();
        assert_eq!(detected.product.id, "windows-server");
        assert_eq!(detected.cpes, vec!["o:microsoft:windows_server_2022"]);
        assert_eq!(detected.shown_version, "2022 (10.0.20348.1)");
    }

    /// Linux distributions from os-release; Debian's point release; an
    /// unfollowed one is named.
    #[test]
    fn test_linux_from_os_release() {
        let ubuntu =
            linux_from_os_release("NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n", None)
                .unwrap();
        assert_eq!(
            (ubuntu.product.id, ubuntu.version.as_str()),
            ("ubuntu", "24.04")
        );
        assert!(ubuntu.on_linux);
        let debian =
            linux_from_os_release("ID=debian\nVERSION_ID=\"12\"\n", Some("12.8\n")).unwrap();
        assert_eq!(debian.version, "12.8");
        let alpine = linux_from_os_release("ID=alpine\nVERSION_ID=3.20.3\n", None).unwrap();
        assert_eq!(alpine.product.id, "alpine-linux");
        assert!(
            linux_from_os_release("ID=gentoo\nNAME=Gentoo\n", None)
                .unwrap_err()
                .contains("gentoo")
        );
    }

    /// The runtimes' version lines.
    #[test]
    fn test_runtime_versions() {
        let python = parse_simple("Python 3.12.1\n", "Python ", "python", false).unwrap();
        assert_eq!(python.version, "3.12.1");
        assert_eq!(
            check(&python, &tables()).support,
            Support::Behind {
                latest: "3.12.16".into()
            }
        );
        let node = parse_simple("v22.3.0\n", "v", "nodejs", false).unwrap();
        assert_eq!(node.version, "22.3.0");
        let php = parse_simple(
            "PHP 8.3.1 (cli) (built: Jan 1 2026)\nCopyright",
            "PHP ",
            "php",
            false,
        )
        .unwrap();
        assert_eq!(php.version, "8.3.1");
        assert!(parse_simple("command not found", "Python ", "python", false).is_err());
        // macOS's `java` without a JDK answers without any version: the
        // console quotes its answer.
        let stub = parse_java(
            "The operation couldn’t be completed. Unable to locate a Java Runtime.\nPlease visit http://www.java.com for information on installing Java.\n",
            false,
        )
        .unwrap_err();
        assert_eq!(
            stub.no_version.as_deref(),
            Some("The operation couldn’t be completed. Unable to locate a Java Runtime.")
        );

        let temurin = parse_java(
            "Property settings:\n    java.vendor = Eclipse Adoptium\n    java.version = 21.0.2\n    java.vm.name = OpenJDK 64-Bit Server VM\nopenjdk version \"21.0.2\"",
            false,
        )
        .unwrap();
        assert_eq!(
            (temurin.product.id, temurin.version.as_str()),
            ("eclipse-temurin", "21.0.2")
        );
        let openjdk = parse_java(
            "    java.vendor = Oracle Corporation\n    java.version = 25\n    java.vm.name = OpenJDK 64-Bit Server VM\n",
            false,
        )
        .unwrap();
        assert_eq!(openjdk.product.id, "openjdk-builds-from-oracle");
        assert!(
            parse_java(
                "    java.vendor = Azul Systems, Inc.\n    java.version = 17.0.9\n",
                false
            )
            .unwrap_err()
            .reason
            .contains("Azul")
        );

        let dotnet = parse_dotnet(
            "Microsoft.AspNetCore.App 8.0.1 [/usr/share/dotnet]\nMicrosoft.NETCore.App 8.0.1 [/usr/share/dotnet]\nMicrosoft.NETCore.App 9.0.0 [/usr/share/dotnet]\n",
            false,
        );
        let versions: Vec<String> = dotnet.into_iter().map(|d| d.unwrap().version).collect();
        assert_eq!(versions, vec!["8.0.1", "9.0.0"]);
    }

    /// A program placed inside the scanned folder is never chosen; the
    /// one outside is.
    #[test]
    fn test_runtime_inside_the_scanned_folder_is_skipped() {
        let dir = std::env::temp_dir().join(format!("cfa-host-{}", std::process::id()));
        let project = dir.join("project");
        let system = dir.join("bin");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&system).unwrap();
        let planted = project.join("python3");
        let real = system.join("python3");
        std::fs::write(&planted, b"").unwrap();
        std::fs::write(&real, b"").unwrap();
        let chosen = outside(vec![planted.clone(), real.clone()].into_iter(), &project);
        let none = outside(vec![planted].into_iter(), &project);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(
            chosen.map(|p| p.file_name().unwrap().to_owned()),
            Some("python3".into())
        );
        assert!(chosen_is(&real, &system));
        assert_eq!(none, None);
    }

    fn chosen_is(path: &Path, dir: &Path) -> bool {
        path.starts_with(dir)
    }

    /// The age of the data in days.
    #[test]
    fn test_days_between() {
        assert_eq!(days_between("2026-10-27", "2026-11-26"), Some(30));
        assert_eq!(days_between("x", "2026-11-26"), None);
    }
    /// The real `/etc/os-release` of Ubuntu 24.04, Debian 13 (with its
    /// `/etc/debian_version`) and Alpine 3.24, and the real answers of
    /// Python 3.13.18 and Node.js 24.22.3, read from those images on
    /// 2026-11-26.
    #[test]
    fn test_real_linux_systems_and_runtimes() {
        const UBUNTU: &str = "PRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION=\"24.04.5 LTS (Noble Numbat)\"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\nHOME_URL=\"https://www.ubuntu.com/\"\nSUPPORT_URL=\"https://help.ubuntu.com/\"\nBUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\nPRIVACY_POLICY_URL=\"https://www.ubuntu.com/legal/terms-and-policies/privacy-policy\"\nUBUNTU_CODENAME=noble\nLOGO=ubuntu-logo\n";
        const DEBIAN: &str = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nVERSION=\"13 (trixie)\"\nVERSION_CODENAME=trixie\nDEBIAN_VERSION_FULL=13.7\nID=debian\nHOME_URL=\"https://www.debian.org/\"\nSUPPORT_URL=\"https://www.debian.org/support\"\nBUG_REPORT_URL=\"https://bugs.debian.org/\"\n";
        const ALPINE: &str = "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.24.4\nPRETTY_NAME=\"Alpine Linux v3.24\"\nHOME_URL=\"https://alpinelinux.org/\"\nBUG_REPORT_URL=\"https://gitlab.alpinelinux.org/alpine/aports/-/issues\"\n";
        let ubuntu = linux_from_os_release(UBUNTU, None).unwrap();
        assert_eq!(
            (ubuntu.product.id, ubuntu.version.as_str()),
            ("ubuntu", "24.04.5")
        );
        // The NVD names the release, not the point release.
        assert_eq!(ubuntu.cpe_version.as_deref(), Some("24.04"));
        let debian = linux_from_os_release(DEBIAN, Some("13.7\n")).unwrap();
        assert_eq!(
            (debian.product.id, debian.version.as_str()),
            ("debian", "13.7")
        );
        let alpine = linux_from_os_release(ALPINE, None).unwrap();
        assert_eq!(
            (alpine.product.id, alpine.version.as_str()),
            ("alpine-linux", "3.24.4")
        );
        assert!(ubuntu.on_linux && debian.on_linux && alpine.on_linux);
        let python = parse_simple("Python 3.13.18\n", "Python ", "python", true).unwrap();
        assert_eq!(python.version, "3.13.18");
        let node = parse_simple("v24.22.3\n", "v", "nodejs", true).unwrap();
        assert_eq!(node.version, "24.22.3");
    }
}
