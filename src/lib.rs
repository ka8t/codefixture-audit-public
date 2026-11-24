//! Library crate of `codefixture-audit`: everything except the command line,
//! which lives in `main.rs`. One module per stage of the product:
//!
//! - [`scan`]: finds the files, runs the rules and the taint analysis.
//! - [`rules`]: the catalog pack next to the binary, plain rule folders
//!   and custom rules.
//! - [`report`]: turns findings into HTML, SARIF, SBOM and JSON output.
//! - [`project`]: what belongs to the scanned project (configuration,
//!   suppressions, dependencies, database schema, its test suite).
//! - [`i18n`]: translations, shared by the CLI and the reports.

pub mod build_version;
pub mod i18n;
pub mod project;
pub mod report;
pub mod rules;
pub mod scan;

/// Build identifier of this binary, `3.0.0+415.588dc34` (ticket #149): the
/// `Cargo.toml` version, commit count and short hash, `-dirty` for a tree
/// with uncommitted changes, `+unknown` without git. Computed by
/// `build.rs` (`build_version::format_build_version`). It names the exact
/// build, so only the diagnostics show it: `--version`, the debug log
/// header and the crash log; the scan cache keys on it. A deliverable
/// shows [`RELEASE_VERSION`] instead.
pub const BUILD_VERSION: &str = env!("CODEFIXTURE_AUDIT_BUILD_VERSION");

/// Release version of the engine, `3.0.0`: the `Cargo.toml` version, the
/// only one a deliverable shows (HTML report, JSON export, SARIF, SBOM,
/// metrics file, the console line that opens a scan). Decided on
/// 2026-11-24: the reports showed "CodeFixture v0.1.0+506.ade3297", and a
/// client has no use for the commit count and hash of the build, which
/// `--version` still gives. `3.0.0` since 2026-11-24 too (ADR-0065): the
/// numbering continues the Python engine's, released 1.0.0 to 2.0.0.
pub const RELEASE_VERSION: &str = env!("CARGO_PKG_VERSION");
