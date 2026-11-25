//! CycloneDX SBOM export.
//!
//! Version **1.6** (latest CycloneDX spec to date). Reproduces exactly
//! the structure and scope of the current client-facing SBOM on the
//! Python side (`Audit/sca/comparison.py`, CycloneDX 1.5) — only the
//! `specVersion` value changes. Fields deliberately absent here
//! because they are absent on the Python side today: component hash,
//! license. Adding them would be a new SAST feature, out of scope for
//! this port (cf. "Initial out-of-scope", plan §0).
//!
//! Wired to the CLI by `scan --sbom` (2026-11-04). Unlike Python
//! (`runner.py:722-728`), no license gates it (ADR-0034).
//!
//! Deliberate deviations from Python for the tools that read an SBOM in a
//! pipeline (ticket #296): a `serialNumber` per SBOM, `metadata.tools` in
//! the form of CycloneDX 1.5 and later (`components`, the array of 1.4
//! being deprecated), and no `version` for a project that has none, where
//! Python wrote `""`. The output validates against the official
//! CycloneDX 1.6 schema (`resources/schemas/bom-1.6.schema.json`).
//!
//! The SBOM stays an inventory: it carries no `vulnerabilities`. The
//! vulnerabilities of the dependencies change faster than the inventory
//! (a new CVE, a rescoring), the tools that read an SBOM, such as
//! Dependency-Track, compute them from the PURLs, and the engine already
//! gives them in the report and the SARIF output (ticket #296).

use serde::Serialize;

use crate::project::dependencies::Dependency;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SbomReport {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,

    #[serde(rename = "specVersion")]
    pub spec_version: String,

    /// `urn:uuid:<UUID>`, unique per SBOM, also for two SBOMs of an
    /// unchanged project (CycloneDX: "every BOM generated SHOULD have a
    /// unique serial number"); see [`random_serial_number`].
    #[serde(rename = "serialNumber")]
    pub serial_number: String,

    pub version: u32,

    pub metadata: Metadata,

    pub components: Vec<Component>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Metadata {
    /// ISO 8601 (RFC 3339) timestamp of SBOM generation.
    pub timestamp: String,
    pub tools: Tools,
    pub component: RootComponent,
}

/// `metadata.tools` of CycloneDX 1.5 and later: the tools are components.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Tools {
    pub components: Vec<Tool>,
}

/// The engine, as a tool component of the SBOM.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Tool {
    /// `application`.
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
}

/// The root component — the scanned project itself, not a dependency.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RootComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    /// `None` when the project declares no version: CycloneDX makes it
    /// optional, and an empty version is no version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// A detected dependency of the scanned project.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Component {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    /// The exact version the manifest pins. `None` for a range or an
    /// unpinned dependency: CycloneDX makes `version` optional, and an
    /// absent version is true where a range's lower bound would not be.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub purl: String,
}

impl SbomReport {
    /// Builds an empty SBOM report (0 components) for `project_name`/
    /// `project_version` (empty: none), timestamped at `timestamp` (ISO
    /// 8601) with `serial_number` — the caller supplies the time and the
    /// serial number, this function reads neither the clock nor the random
    /// source: testable determinism, cf. Step 6/9 golden tests.
    pub fn new(
        project_name: impl Into<String>,
        project_version: impl Into<String>,
        tool_name: impl Into<String>,
        tool_version: impl Into<String>,
        timestamp: impl Into<String>,
        serial_number: impl Into<String>,
    ) -> Self {
        let project_version: String = project_version.into();
        SbomReport {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.6".to_string(),
            serial_number: serial_number.into(),
            version: 1,
            metadata: Metadata {
                timestamp: timestamp.into(),
                tools: Tools {
                    components: vec![Tool {
                        component_type: "application".to_string(),
                        name: tool_name.into(),
                        version: tool_version.into(),
                    }],
                },
                component: RootComponent {
                    component_type: "application".to_string(),
                    name: project_name.into(),
                    version: (!project_version.is_empty()).then_some(project_version),
                },
            },
            components: Vec::new(),
        }
    }

    pub fn push_component(&mut self, component: Component) {
        self.components.push(component);
    }

    pub fn to_json_string(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

/// A serial number for a new SBOM: `urn:uuid:` and a random UUID of
/// version 4 (RFC 9562), from the system's random source. `Err` with the
/// reason when that source cannot be read: the SBOM is then not written,
/// never written with a made-up number.
pub fn random_serial_number() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("random source: {e}"))?;
    Ok(serial_number_of(bytes))
}

/// The `urn:uuid:` serial number of 16 random bytes, with the version
/// (4) and variant (RFC 9562) bits set.
fn serial_number_of(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Builds the PURL (Package URL) of a dependency, same convention as
/// `Audit/sca/comparison.py::_export_sbom`: `pkg:<type>/<name>@<version>`,
/// except Maven (`group:artifact`) which becomes `pkg:maven/<group>/<artifact>@<version>`.
/// Without an exact version the PURL has no `@<version>` part (the PURL
/// spec makes it optional), where Python wrote `@unknown`.
pub fn build_purl(purl_type: &str, name: &str, version: Option<&str>) -> String {
    let path = match name.split_once(':') {
        Some((group, artifact)) if purl_type == "maven" => format!("{group}/{artifact}"),
        _ => name.to_string(),
    };
    match version {
        Some(v) => format!("pkg:{purl_type}/{path}@{v}"),
        None => format!("pkg:{purl_type}/{path}"),
    }
}

/// PURL type of a dependency ecosystem — same table as `ecosystem_to_purl`
/// in `Audit/sca/comparison.py::_export_sbom`; unknown ecosystem →
/// `generic`.
pub fn purl_type_for_ecosystem(ecosystem: &str) -> &'static str {
    match ecosystem {
        "PyPI" => "pypi",
        "npm" => "npm",
        "Maven" => "maven",
        "NuGet" => "nuget",
        "Packagist" => "composer",
        _ => "generic",
    }
}

/// Builds the project SBOM from the statically parsed dependencies —
/// port of `_export_sbom`: one `library` component per dependency, in
/// discovery order. No deduplication, like Python (a dependency declared
/// in two manifests appears twice).
///
/// Deliberate deviation from Python (ticket #196): a component carries a
/// version only when the manifest pins it exactly (`advisories::exact_version`).
/// Python wrote the lower bound of a range as the version (`flask>=2.0` →
/// `flask@2.0`) and `unknown` for an unpinned dependency; both are absent
/// here, in the component and in its PURL.
pub fn build_dependency_sbom(
    deps: &[Dependency],
    project_name: &str,
    project_version: &str,
    tool_name: &str,
    tool_version: &str,
    timestamp: &str,
    serial_number: &str,
) -> SbomReport {
    let mut report = SbomReport::new(
        project_name,
        project_version,
        tool_name,
        tool_version,
        timestamp,
        serial_number,
    );
    for dep in deps {
        let version = crate::project::advisories::exact_version(dep).map(str::to_string);
        let purl = build_purl(
            purl_type_for_ecosystem(&dep.ecosystem),
            &dep.name,
            version.as_deref(),
        );
        report.push_component(Component {
            component_type: "library".to_string(),
            name: dep.name.clone(),
            version,
            purl,
        });
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed serial number, for the tests that build an SBOM.
    const SERIAL: &str = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79";

    /// Ticket #296: a version 4 UUID in the `urn:uuid:` form, a new one per
    /// SBOM.
    #[test]
    fn test_serial_number_is_a_random_uuid_v4() {
        assert_eq!(
            serial_number_of([0xff; 16]),
            "urn:uuid:ffffffff-ffff-4fff-bfff-ffffffffffff"
        );
        assert_eq!(
            serial_number_of([0; 16]),
            "urn:uuid:00000000-0000-4000-8000-000000000000"
        );
        let first = random_serial_number().expect("random source");
        let second = random_serial_number().expect("random source");
        assert_ne!(first, second);
        let pattern = regex::Regex::new(
            "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        .unwrap();
        assert!(pattern.is_match(&first), "{first}");
    }

    /// Ticket #296: the tools in the form of CycloneDX 1.5 and later, and
    /// no version for a project without one.
    #[test]
    fn test_metadata_tools_are_components_and_an_empty_version_is_omitted() {
        let json: serde_json::Value = serde_json::from_str(
            &SbomReport::new(
                "p",
                "",
                "codefixture-audit",
                "3.1.0",
                "2026-11-25T08:00:00Z",
                SERIAL,
            )
            .to_json_string()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            json["metadata"]["tools"],
            serde_json::json!({"components": [{"type": "application", "name": "codefixture-audit", "version": "3.1.0"}]})
        );
        assert!(
            json["metadata"]["component"].get("version").is_none(),
            "{json}"
        );
        assert_eq!(json["serialNumber"], SERIAL);
        let with_version = SbomReport::new("p", "2.0", "t", "1", "2026-11-25T08:00:00Z", SERIAL);
        assert_eq!(
            with_version.metadata.component.version.as_deref(),
            Some("2.0")
        );
    }

    /// Ticket #296: an SBOM with every kind of component the engine writes
    /// (exact version, range without version, Maven group, unknown
    /// ecosystem) validates against the official CycloneDX 1.6 schema,
    /// offline: the two schemas it refers to are registered from
    /// `resources/schemas/` under the address its `$id` gives them.
    #[test]
    fn test_sbom_validates_against_the_cyclonedx_schema() {
        let data = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/schemas");
        let read = |name: &str| -> serde_json::Value {
            serde_json::from_str(&std::fs::read_to_string(data.join(name)).expect(name))
                .expect(name)
        };
        let registry = jsonschema::Registry::new()
            .add(
                "http://cyclonedx.org/schema/spdx.schema.json",
                read("spdx.schema.json"),
            )
            .expect("spdx schema")
            .add(
                "http://cyclonedx.org/schema/jsf-0.82.schema.json",
                read("jsf-0.82.schema.json"),
            )
            .expect("jsf schema")
            .prepare()
            .expect("registry");
        let validator = jsonschema::options()
            .with_registry(&registry)
            .build(&read("bom-1.6.schema.json"))
            .expect("CycloneDX 1.6 schema");

        let deps = vec![
            dep("requests", Some("2.31.0"), "PyPI"),
            dep("flask", None, "PyPI"),
            dep("org.springframework:spring-core", Some("6.1.0"), "Maven"),
            dep("weird", Some("1"), "Cargo"),
        ];
        let sbom = build_dependency_sbom(
            &deps,
            "shop",
            "",
            "codefixture-audit",
            "3.1.0",
            "2026-11-25T08:00:00+01:00",
            &random_serial_number().expect("random source"),
        );
        let instance: serde_json::Value =
            serde_json::from_str(&sbom.to_json_string().unwrap()).unwrap();
        let errors: Vec<String> = validator
            .iter_errors(&instance)
            .map(|e| format!("{e} at {}", e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "CycloneDX schema errors: {errors:#?}");

        // The validator does refuse what the schema forbids: a serial
        // number that is not a URN UUID.
        let mut wrong = instance.clone();
        wrong["serialNumber"] = serde_json::json!("not-a-uuid");
        assert!(!validator.is_valid(&wrong));
    }

    fn dep(name: &str, version: Option<&str>, ecosystem: &str) -> Dependency {
        let raw_line = match (ecosystem, version) {
            ("PyPI", Some(v)) => format!("{name}=={v}"),
            (_, Some(v)) => format!("\"{name}\": \"{v}\""),
            (_, None) => name.to_string(),
        };
        dep_line(name, version, ecosystem, &raw_line)
    }

    fn dep_line(name: &str, version: Option<&str>, ecosystem: &str, raw_line: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.map(|v| v.to_string()),
            ecosystem: ecosystem.to_string(),
            file: std::path::PathBuf::from("x"),
            line: 1,
            raw_line: raw_line.to_string(),
            version_source: Default::default(),
        }
    }

    /// A range (`flask>=2.0`, `"lodash": "^4.17.0"`) names no installed
    /// version: the component carries no version and its PURL none either,
    /// instead of the range's lower bound presented as the version.
    #[test]
    fn test_build_dependency_sbom_leaves_ranges_without_version() {
        // Ticket #209: a range keeps its declared minimum in `version`,
        // for the version rules, with the source saying so.
        let minimum = |name: &str, version: &str, ecosystem: &str, spec: &str, line: &str| {
            let mut dep = dep_line(name, Some(version), ecosystem, line);
            dep.version_source = crate::project::dependencies::VersionSource::DeclaredMinimum {
                constraint: spec.to_string(),
                lock: crate::project::dependencies::LockStatus::Absent,
            };
            dep
        };
        let deps = vec![
            minimum("flask", "2.0", "PyPI", ">=2.0", "flask>=2.0"),
            minimum(
                "lodash",
                "4.17.0",
                "npm",
                "^4.17.0",
                "\"lodash\": \"^4.17.0\"",
            ),
            dep_line("express", Some("4.18.2"), "npm", "\"express\": \"4.18.2\""),
        ];
        let sbom = build_dependency_sbom(&deps, "p", "", "codefixture-audit", "3.0.0", "t", SERIAL);
        let json = sbom.to_json_string().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let components = parsed["components"].as_array().unwrap();
        assert_eq!(components[0]["purl"], "pkg:pypi/flask");
        assert!(components[0].get("version").is_none(), "{json}");
        assert_eq!(components[1]["purl"], "pkg:npm/lodash");
        assert!(components[1].get("version").is_none(), "{json}");
        assert_eq!(components[2]["version"], "4.18.2");
        assert_eq!(components[2]["purl"], "pkg:npm/express@4.18.2");
    }

    #[test]
    fn test_build_dependency_sbom_maps_ecosystems_and_unpinned() {
        let deps = vec![
            dep("requests", Some("2.31.0"), "PyPI"),
            dep("org.springframework:spring-core", Some("6.1.0"), "Maven"),
            dep("monolog/monolog", None, "Packagist"),
            dep("weird", Some("1"), "Cargo"),
        ];
        let sbom = build_dependency_sbom(&deps, "p", "", "codefixture-audit", "3.0.0", "t", SERIAL);
        let purls: Vec<&str> = sbom.components.iter().map(|c| c.purl.as_str()).collect();
        assert_eq!(
            purls,
            vec![
                "pkg:pypi/requests@2.31.0",
                "pkg:maven/org.springframework/spring-core@6.1.0",
                "pkg:composer/monolog/monolog",
                "pkg:generic/weird@1",
            ]
        );
        assert!(
            sbom.components
                .iter()
                .all(|c| c.component_type == "library")
        );
    }

    fn sample_report() -> SbomReport {
        let mut report = SbomReport::new(
            "mon-projet",
            "1.0",
            "codefixture-audit",
            "3.0.0",
            "2026-08-24T12:00:00Z",
            SERIAL,
        );
        report.push_component(Component {
            component_type: "library".to_string(),
            name: "requests".to_string(),
            version: Some("2.31.0".to_string()),
            purl: build_purl("pypi", "requests", Some("2.31.0")),
        });
        report
    }

    #[test]
    fn test_spec_version_is_1_6() {
        assert_eq!(sample_report().spec_version, "1.6");
    }

    #[test]
    fn test_bom_format_is_cyclonedx() {
        assert_eq!(sample_report().bom_format, "CycloneDX");
    }

    #[test]
    fn test_empty_report_has_zero_components() {
        let report = SbomReport::new(
            "p",
            "1.0",
            "codefixture-audit",
            "3.0.0",
            "2026-08-24T12:00:00Z",
            SERIAL,
        );
        assert!(report.components.is_empty());
    }

    #[test]
    fn test_json_is_valid_and_round_trips_key_fields() {
        let report = sample_report();
        let json = report.to_json_string().unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["bomFormat"], "CycloneDX");
        assert_eq!(value["specVersion"], "1.6");
        assert_eq!(value["components"][0]["name"], "requests");
    }

    #[test]
    fn test_purl_pypi() {
        assert_eq!(
            build_purl("pypi", "requests", Some("2.31.0")),
            "pkg:pypi/requests@2.31.0"
        );
    }

    #[test]
    fn test_purl_maven_splits_group_artifact() {
        assert_eq!(
            build_purl("maven", "org.springframework:spring-core", Some("6.1.0")),
            "pkg:maven/org.springframework/spring-core@6.1.0"
        );
    }

    #[test]
    fn test_purl_maven_without_colon_falls_back_to_name() {
        // No ':' in name: fallback behavior, same limitation as Python
        // (sca/comparison.py only handles the group:artifact case).
        assert_eq!(
            build_purl("maven", "spring-core", Some("6.1.0")),
            "pkg:maven/spring-core@6.1.0"
        );
    }

    #[test]
    fn test_purl_without_version_has_no_at_part() {
        assert_eq!(build_purl("npm", "lodash", None), "pkg:npm/lodash");
        assert_eq!(
            build_purl("maven", "org.springframework:spring-core", None),
            "pkg:maven/org.springframework/spring-core"
        );
    }

    #[test]
    fn test_no_components_have_hash_or_license_fields() {
        // Verifies the deliberately limited scope (Decision #9): the
        // serialization must not contain any hash/licenses field, not
        // present in the current Python client.
        let json = sample_report().to_json_string().unwrap();
        assert!(!json.contains("\"hashes\""));
        assert!(!json.contains("\"licenses\""));
    }
}
