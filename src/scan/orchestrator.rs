//! Scan orchestrator (Step 5) — assembles the already-built building
//! blocks (DSL parser, regex/file_contains/taint executors, file
//! discovery, suppression, LOC counter) into a complete pipeline.
//! Scope: Python + Java (Decision #10, extended on 2026-08-25).
//!
//! **Multi-language**: each discovered file carries its language
//! detected by extension (`.py`→Python, `.java`→Java). The
//! regex/file_contains mode (Phase B) is language-agnostic — a rule
//! only applies to files of ITS declared language
//! (`rule_json["language"]`).
//!
//! **Multi-file taint wired for all 4 languages** (2026-08-25 for
//! Python/Java, 2026-08-30 for JS/TS then PHP): resolved
//! **interprocedurally, one batch per language** —
//! `dataflow::call_graph::CallGraph` over Python files,
//! `dataflow::java_call_graph::JavaCallGraph` over Java files,
//! `dataflow::js_call_graph::JsCallGraph` over JS/TS files,
//! `dataflow::php_call_graph::PhpCallGraph` over PHP files,
//! each built once and then `resolve_summaries` per taint rule of
//! its language (a rule's sources/sinks determine the function
//! summaries, so resolution is repeated per rule, not graph
//! construction). Mirrors `dataflow_adapter.py` (Python) and the
//! spirit of `dataflow_taint_java.py` (Java, but without its internal
//! summary computation — here done once by the orchestrator via
//! `JavaCallGraph`, same split as on the Python side).
//! **JS/TS and PHP have no Python equivalent to mirror** (the
//! reference Python engine has no interprocedural analysis for these
//! two languages, cf. doc of `dataflow::js_call_graph`/`dataflow::
//! php_call_graph`) — fresh development for both, pipeline pattern
//! reused by analogy, call-resolution mechanisms specific to each
//! language. The `type_map` (var/field → declared class, Round 5,
//! Java only) is recomputed per Java file, independently of the
//! graph — MUST stay in sync with the merge done in
//! `JavaCallGraph::build` (same logical dict), cf. doc of
//! `java_summary::collect_java_field_types`.
//!
//! The taint passes live in the `taint` submodule (`orchestrator/taint/`):
//! one file per language for what sets it apart, the shared work (files
//! and rules of the language, cache, merge into the report) written once.
//!
//! `ast` mode and `hook` rules remain out of scope (cf. `engine::dispatch`).
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rayon::prelude::*;
use tree_sitter::Parser as TsParser;

use crate::project::suppress::Suppressions;
use crate::report::exports::sarif::{ReportFinding, TaintFlow, TaintStep};
use crate::scan::counters::{count_java_loc, count_js_loc, count_python_loc};
use crate::scan::dataflow::line_facts::SourceLines;
use crate::scan::dataflow::rule_loader::{extract_cwe, extract_message};
use crate::scan::discovery::{FileDiscoveryConfig, SkippedDir, find_files_and_skipped};
use crate::scan::engine::file_contains::FileLocation;

mod patterns;
mod taint;
use taint::TaintLanguage;

/// Source language of a discovered file, detected by extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceLanguage {
    Python,
    Java,
    JavaScript,
    /// `.ts` only (not yet `.tsx`/JSX, cf. doc of
    /// `js_lowering.rs`) — parsed with `tree-sitter-typescript`, but
    /// fully reuses the JS front-end (`js_lowering`/`js_cfg`/
    /// `js_summary`/`js_taint_scan`, same node kinds for the whole
    /// plain-JS subset) and the same rule catalog
    /// (`rule_tag()` deliberately returns "javascript" — an
    /// Express/Node.js source/sink rule doesn't depend on any type
    /// annotation, duplicating the `.sca` files would add nothing).
    TypeScript,
    Php,
    /// C# (`.cs`) — detection/parsing/`match` mode (prefactor ticket
    /// #69/spec #68) AND native intra-procedural taint engine (tickets
    /// #78-79/spec #77: dedicated CFG, interprocedural summaries). Since
    /// ticket #284 (ADR-0060) a `.sca` rule with `language csharp` in
    /// `taint` mode resolves calls across the files of the project, like
    /// Java, through the C# call graph (`csharp_call_graph.rs`:
    /// namespaces and `using` directives); before, only within the same
    /// file.
    CSharp,
    /// HTML (`.html`/`.htm`).
    Html,
    /// YAML (`.yml`/`.yaml`) — main target: CI/CD pipelines
    /// (GitHub Actions, GitLab CI), mirrors the "yaml" subset of the
    /// Python catalog (`*.yml` files under `.github/workflows/`
    /// notably).
    Yaml,
    /// `Dockerfile` — recognized by EXACT FILE NAME (case-insensitive),
    /// not by extension (no standard extension for this format):
    /// goes through [`SourceLanguage::from_path`], never through
    /// [`SourceLanguage::from_extension`] alone.
    Dockerfile,
    /// `pom.xml`, the Maven build file of a Java project — a
    /// [configuration file](SourceLanguage::is_config_file) read by the
    /// Java rules that name it (ADR-0047).
    MavenPom,
    /// `web.config`, the IIS / ASP.NET configuration file — a
    /// [configuration file](SourceLanguage::is_config_file) read by the
    /// C# rules that name it (ADR-0047).
    WebConfig,
    /// `package.json`, the npm manifest — a
    /// [configuration file](SourceLanguage::is_config_file) read by the
    /// JavaScript rules that name it (ADR-0047).
    PackageJson,
}

impl SourceLanguage {
    /// Recognized Dockerfile file names, case-insensitive comparison —
    /// exact mirror of `Audit/sca/rule_engine.py::
    /// _find_dockerfile_files` (`filename.lower() in (...)`,
    /// `rule_engine.py:1286`): NOT just the literal `Dockerfile`,
    /// the `.dev`/`.prod` variants are also recognized on the Python
    /// side. Fix from 2026-09-01 (found in review of ticket #69):
    /// the first version only matched the exact case
    /// "Dockerfile" and ignored the 2 variants. Constant shared
    /// between `from_path` (language detection, Phase A) and
    /// `run_scan` (building `FileDiscoveryConfig::filenames`,
    /// discovery) so that a single list is authoritative — two
    /// independent lists could have silently diverged.
    pub(crate) const DOCKERFILE_FILENAMES: [&'static str; 3] =
        ["Dockerfile", "Dockerfile.dev", "Dockerfile.prod"];

    /// Configuration files recognized by EXACT NAME (case-insensitive:
    /// `Web.config` is the usual spelling) — ADR-0047, a deliberate
    /// superset of the Audit, which never reads them although three of its
    /// rules target them (`insecure_maven_dependency`,
    /// `missing_x_frame_options_csharp`, `npm_lifecycle_script`). The sole
    /// authoritative list, shared by [`SourceLanguage::from_path`] and the
    /// discovery `filenames` of `run_scan`, like
    /// [`SourceLanguage::DOCKERFILE_FILENAMES`].
    pub(crate) const CONFIG_FILENAMES: [(&'static str, SourceLanguage); 3] = [
        ("pom.xml", SourceLanguage::MavenPom),
        ("web.config", SourceLanguage::WebConfig),
        ("package.json", SourceLanguage::PackageJson),
    ];

    /// Value expected in `rule_json["language"]` for this language. A
    /// configuration file takes the tag of the language whose rules
    /// target it.
    pub(crate) fn rule_tag(self) -> &'static str {
        match self {
            SourceLanguage::Python => "python",
            SourceLanguage::Java | SourceLanguage::MavenPom => "java",
            SourceLanguage::JavaScript
            | SourceLanguage::TypeScript
            | SourceLanguage::PackageJson => "javascript",
            SourceLanguage::Php => "php",
            SourceLanguage::CSharp | SourceLanguage::WebConfig => "csharp",
            SourceLanguage::Html => "html",
            SourceLanguage::Yaml => "yaml",
            SourceLanguage::Dockerfile => "dockerfile",
        }
    }

    /// `true` for a configuration file (`pom.xml`, `web.config`,
    /// `package.json`): it is not code of its rule language, so only the
    /// pattern rules that name it with `path_contains` read it, no taint
    /// pass takes it, and it never shapes the proposed project
    /// configuration (ADR-0047).
    pub(crate) fn is_config_file(self) -> bool {
        matches!(
            self,
            SourceLanguage::MavenPom | SourceLanguage::WebConfig | SourceLanguage::PackageJson
        )
    }

    /// The language whose comment syntax the file is written in, for the
    /// comment stripping of the pattern rules: the rule tag for code, XML
    /// comments (`html`) for `pom.xml` and `web.config`, none for
    /// `package.json` (JSON has no comments; `json` is a tag no stripping
    /// knows). Without it, the Java `//` marker cut every
    /// `<url>http://…` of a `pom.xml`.
    pub(crate) fn comment_syntax(self) -> &'static str {
        match self {
            SourceLanguage::MavenPom | SourceLanguage::WebConfig => "html",
            SourceLanguage::PackageJson => "json",
            other => other.rule_tag(),
        }
    }

    /// [`SourceLanguage::comment_syntax`] for the file at `path`: a Razor
    /// view (`.cshtml`, `.razor`, ADR-0058) is an HTML template whose
    /// `@* … *@` server comments are stripped with its HTML comments
    /// (`razor` syntax, ticket #285); every other file keeps the syntax of
    /// its language.
    pub(crate) fn comment_syntax_for(self, path: &Path) -> &'static str {
        let is_razor_view = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("cshtml" | "razor")
        );
        if self == SourceLanguage::Html && is_razor_view {
            "razor"
        } else {
            self.comment_syntax()
        }
    }

    /// Detects the language by EXTENSION alone. `None` for a format
    /// without a standard extension (`Dockerfile`) — use
    /// [`SourceLanguage::from_path`] for a real file on disk,
    /// this function stays correct in isolation everywhere an
    /// extension is already known otherwise.
    pub(crate) fn from_extension(path: &Path) -> Option<Self> {
        let ext = path.extension().and_then(|e| e.to_str())?;
        Self::EXTENSIONS
            .iter()
            .find(|(e, _)| *e == ext)
            .map(|(_, lang)| *lang)
    }

    /// Recognized file extensions (without the dot) and their language —
    /// the SOLE authoritative list, shared by [`SourceLanguage::from_extension`]
    /// (Phase A detection) and `run_scan` (building
    /// `FileDiscoveryConfig::extensions`), same single-source principle
    /// as [`SourceLanguage::DOCKERFILE_FILENAMES`].
    ///
    /// Mirrors `Audit/sca/runner.py` (`_py_exts`/`_js_exts`/`_html_exts`/
    /// `_java_exts`/`_csharp_exts`/`_php_exts`/`_yaml_exts`). Fix from
    /// 2026-11-04 (Python/Rust differential scan on `Audit/tests/fixtures`):
    /// the Rust lists only held `html`/`htm` for HTML, no `tsx`, no `inc`
    /// — `.vue`/`.svelte`/`.jsp`/`.cshtml`/… templates were never scanned
    /// (e.g. `xss_vue_vhtml`/`xss_svelte_html` never fired). All template
    /// formats go through the HTML grammar exactly like the Python side
    /// applies `language html` rules to them; tree-sitter is error-tolerant
    /// and the HTML rules are line-oriented regexes, so a partial parse of
    /// template syntax never hides a match. Deliberate superset: `cjs`
    /// (CommonJS, absent from Python's list) is kept from the initial port.
    ///
    /// Second deliberate superset (ticket #285, ADR-0058): `razor`, the
    /// Blazor component, absent from Python's list, joins `cshtml` among
    /// the HTML templates. A Razor view mixes HTML and C#: the C# grammar
    /// cannot parse it, so it never goes to the C# taint pass nor to the
    /// C# pattern rules (`file_too_long`, `cs_magic_number`… would misfire
    /// on markup); the rules written for views are `html` rules
    /// (`html/security/razor_html_raw.sca`).
    pub(crate) const EXTENSIONS: [(&'static str, SourceLanguage); 34] = [
        ("py", SourceLanguage::Python),
        ("java", SourceLanguage::Java),
        ("js", SourceLanguage::JavaScript),
        ("jsx", SourceLanguage::JavaScript),
        ("mjs", SourceLanguage::JavaScript),
        ("cjs", SourceLanguage::JavaScript),
        ("ts", SourceLanguage::TypeScript),
        // Parsed with the TSX grammar, not the plain TypeScript one (JSX
        // syntax is a parse error for the latter) — see `ts_grammar_for`.
        ("tsx", SourceLanguage::TypeScript),
        ("php", SourceLanguage::Php),
        ("inc", SourceLanguage::Php),
        ("cs", SourceLanguage::CSharp),
        ("html", SourceLanguage::Html),
        ("htm", SourceLanguage::Html),
        ("xhtml", SourceLanguage::Html),
        ("shtml", SourceLanguage::Html),
        ("vue", SourceLanguage::Html),
        ("svelte", SourceLanguage::Html),
        ("ejs", SourceLanguage::Html),
        ("hbs", SourceLanguage::Html),
        ("njk", SourceLanguage::Html),
        ("jinja", SourceLanguage::Html),
        ("jinja2", SourceLanguage::Html),
        ("twig", SourceLanguage::Html),
        ("liquid", SourceLanguage::Html),
        ("mustache", SourceLanguage::Html),
        ("phtml", SourceLanguage::Html),
        ("erb", SourceLanguage::Html),
        ("jsp", SourceLanguage::Html),
        ("asp", SourceLanguage::Html),
        ("aspx", SourceLanguage::Html),
        ("cshtml", SourceLanguage::Html),
        ("razor", SourceLanguage::Html),
        ("yml", SourceLanguage::Yaml),
        ("yaml", SourceLanguage::Yaml),
    ];

    /// Detects the language of a real file on disk: EXACT NAME first
    /// (formats without a standard extension), then extension
    /// ([`SourceLanguage::from_extension`]) — ticket #69/spec #68.
    /// Mechanism shared by the extension-less formats: `Dockerfile` and
    /// the configuration files of [`SourceLanguage::CONFIG_FILENAMES`]
    /// (whose `.xml`/`.config`/`.json` extensions are not source code).
    /// Entry point to use everywhere a real file path is inspected
    /// (file discovery, scan Phase A).
    pub(crate) fn from_path(path: &Path) -> Option<Self> {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if Self::DOCKERFILE_FILENAMES
                .iter()
                .any(|d| name.eq_ignore_ascii_case(d))
            {
                return Some(SourceLanguage::Dockerfile);
            }
            if let Some((_, lang)) = Self::CONFIG_FILENAMES
                .iter()
                .find(|(n, _)| name.eq_ignore_ascii_case(n))
            {
                return Some(*lang);
            }
        }
        Self::from_extension(path)
    }
}

/// Tree-sitter grammar for a [`SourceLanguage::TypeScript`] file: TSX for
/// `.tsx` (JSX elements are a parse error in the plain TypeScript
/// grammar, which would degrade the AST the JS taint engine walks), plain
/// TypeScript otherwise. The TSX grammar is a superset sharing the same
/// node kinds, so downstream lowering needs no change.
fn ts_grammar_for(path: &Path) -> tree_sitter::Language {
    if path.extension().and_then(|e| e.to_str()) == Some("tsx") {
        tree_sitter_typescript::LANGUAGE_TSX.into()
    } else {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
    }
}

/// Configuration of a scan.
pub struct ScanConfig {
    /// Root of the project to scan.
    pub root: PathBuf,
    /// Starting points for file discovery, relative to
    /// `root` — mirrors `paths.include` (`audit.config.json` on the
    /// Audit side, `sca/config.py`/`projects.py::_auto_detect_project`).
    /// `["."]` (default value, `ScanConfig::default()`) = the whole
    /// directory is scanned, unchanged historical behavior. A
    /// restricted value (e.g. `["sca/", "tests/"]`) avoids walking
    /// into directories that are never relevant (`.venv/`, `videos/`…)
    /// even if they aren't explicitly excluded by
    /// `exclude_patterns` — cf. `project_config.rs`.
    pub include_paths: Vec<String>,
    /// Catalog (ADR-0040): the pack `rules.cfpack` next to the executable
    /// for the CLI, or `--rules <PATH>`, a pack or a folder of plain
    /// `.sca` files laid out by language (`<language>/<category>/<rule>.sca`).
    /// Only the rule files of `target_languages` are kept (`rules::catalog`).
    pub rules_path: PathBuf,
    /// Rule languages declared by the project (`languages` of
    /// `audit.config.json`, as rule tags: `typescript` is `javascript`).
    /// `None`: the languages of the discovered files. With a declared
    /// list, the rules of an undeclared language are never read, even if
    /// files of that language are found; `ScanReport::undeclared_languages`
    /// names them so the CLI can say so.
    pub target_languages: Option<Vec<String>>,
    /// Custom rules directory, loaded IN ADDITION to the catalog of
    /// `rules_dir` (never as a replacement) — ticket #84/spec #82, mirrors
    /// `_load_custom_rules`/`{SCRIPT_DIR}/custom-rules/` on the
    /// Python side (`rule_engine.py:714-731`). Filtered on the target
    /// languages like the catalog; its rules are labelled as client rules
    /// in the report. `None` (default): no custom rule consulted. The CLI
    /// leaves it `None` with `--rules <DIR>`: a user who explicitly
    /// requests an isolated test catalog must never see their custom
    /// rules silently slip in. The CLI default is a folder of the user's
    /// home, outside every build output, so no build or `cargo clean`
    /// ever deletes it (ADR-0039).
    pub custom_rules_dir: Option<PathBuf>,
    /// Stop before reading the files when the scan is expected to take
    /// more memory than the machine has available (ticket #281, `scan::
    /// memory`). On by default; `--skip-memory-check` turns it off.
    pub memory_check: bool,
    /// The most memory the scan may take, in bytes (`--max-memory`),
    /// compared with the estimate as well as the available memory.
    pub memory_limit: Option<u64>,
    /// Path to `.sca-suppress.json`, if it exists.
    pub suppress_file: Option<PathBuf>,
    /// Folder of the taint cache between scans (`scan_cache`); `None`
    /// disables it (`--no-cache`, tests, the default).
    pub cache_dir: Option<PathBuf>,
    /// Exclusion patterns (glob/directory/extension, cf. `discovery`).
    pub exclude_patterns: Vec<String>,
    /// Runs the audited project's test suite (opt-in, executes
    /// arbitrary project code — cf. `testing.rs`).
    pub with_tests: bool,
    /// Explicit test command; if absent and `with_tests`, tries
    /// auto-detection (`testing::auto_detect_test_command`).
    pub test_command: Option<String>,
    /// Runs the dependencies phase even when the rule pack carries no
    /// version rules (private `--with-deps`): unpinned dependencies are
    /// reported, and the scan says the versions were not checked. A pack
    /// with version rules runs the phase anyway (ADR-0043), unless
    /// `quick_mode`. Offline either way (`dependencies.rs`,
    /// `advisories.rs`).
    pub with_deps: bool,
    /// PostgreSQL schema audit (opt-in — network connection to the
    /// audited project's database, cf. `database::live`).
    pub database: Option<crate::project::database::live::DbConfig>,
    /// History directory (JSON export / baseline) — `None`
    /// disables export and baseline comparison.
    pub datas_dir: Option<PathBuf>,
    /// Former history directory, read only as a fallback when
    /// `datas_dir` holds no baseline yet (ticket #133: the default moved
    /// from `docs/audit-reports/audit-datas` to
    /// `audit-reports/audit-datas`). Never written. `None`: no fallback.
    pub legacy_datas_dir: Option<PathBuf>,
    /// Export of the scan to compare with (`--baseline`), instead of the
    /// latest one of the history folder. `None`: the latest. The CLI has
    /// checked that it reads.
    pub baseline_path: Option<PathBuf>,
    /// Naming prefix for history files (`{prefix}-DATA-*.json`).
    pub brand_prefix: String,
    /// `%Y-%m-%d-%H-%M` timestamp shared with the HTML report
    /// (`ReportContext::timestamp`), so that `{prefix}-DATA-*.json`
    /// and `{prefix}-REPORT-*.html` from the same scan carry exactly
    /// the same name — mirrors `self.timestamp` on the Audit side, computed
    /// once at the top of `AuditRunner.__init__`. Empty = computes
    /// its own timestamp (used by callers who don't export an
    /// HTML report, e.g. tests).
    pub timestamp: String,
    /// Fast mode — forces disabling the slow optional phases
    /// (`with_tests`/`with_deps`/`database`) even if they are
    /// otherwise requested, regardless of CLI argument order
    /// (mirrors `AuditRunner.quick_mode`, `runner.py::
    /// _compute_phase_total`/`run` — Python affects ONLY these 3 phases,
    /// never the rules themselves).
    pub quick_mode: bool,
    /// Restricts execution to rules of A SINGLE category
    /// (case-insensitive comparison against `rule_json["category"]`,
    /// e.g. "security") — mirrors `--only-category`/`AuditRunner.
    /// only_category`. `None` = all categories.
    pub only_category: Option<String>,
    /// Enables/disables EACH category independently (key =
    /// `rule_json["category"]` lowercased, e.g. "security"/"arch") —
    /// mirrors `AuditRunner.enabled_categories` (`runner.py:104-112`,
    /// fed by `audit.config.json::categories.<name>.enabled`,
    /// default `True` if the category isn't mentioned). Ticket
    /// #41/spec #27. **Distinct from `only_category` above, never
    /// combined with it**: `runner.py::should_run` (`runner.py:574-578`)
    /// uses one OR the other, never a translation from one to
    /// the other — if `only_category` is set, this map is
    /// entirely ignored (ticket #41 wrongly proposed
    /// "translating" the file into `only_category`, which would have given
    /// a wrong result as soon as disabling doesn't narrow
    /// the set down to exactly one category; confirmed by rereading
    /// `runner.py` directly, decision settled with the maintainer). Empty map
    /// = current behavior unchanged (all categories active).
    pub category_overrides: BTreeMap<String, bool>,
    /// Rule identifiers (`rule_json["id"]`) to never run —
    /// mirrors `--disable-rule`/`AuditRunner.disabled_rules`.
    pub disabled_rules: Vec<String>,
    /// Severities to keep in the final findings (e.g.
    /// `["HIGH", "CRITICAL"]`) — mirrors `--severity`. `None` = all
    /// severities. **Deliberate difference vs Python**: the source
    /// variant (`cli.py`) validates and stores `severity_levels` in
    /// `_cli_options` but never actually uses it afterward to
    /// filter findings (verified — no reference in
    /// `runner.py`); here the filter is actually applied, consistent
    /// with the expected behavior of such a flag.
    pub severity_levels: Option<Vec<String>>,
    /// Language (`en`/`fr`/`es`/`de`) used to resolve the i18n
    /// text of rules (`risk`/`solution`/`benefit`/`message`) right when
    /// findings are built — mirrors `self.lang` on the Audit side
    /// (`AuditRunner`, set once at initialization, before any
    /// finding is created). Deviation found by the maintainer (2026-08-26): this
    /// resolution used to happen without a known language and
    /// always fell back to English, regardless of `--lang` —
    /// rule text (risk/solution/benefit) systematically in
    /// English in an HTML/JSON report that should be in French. `"en"` by
    /// default (unchanged historical behavior if unspecified).
    pub lang: String,
    /// Optional callback invoked right after each phase (same
    /// label/duration as `ScanReport.phase_timings`), for LIVE progress
    /// display on the caller's side — `run_scan` stays free of
    /// direct I/O (no `eprintln!` here), the caller (`main.rs`)
    /// decides the format. A plain function pointer (not
    /// `Box<dyn Fn>`): sufficient for the only current need
    /// (`eprintln!` with no captured state) and trivially `Send + Sync`
    /// for the parallelized sections (`rayon`). `None` by default:
    /// no behavior change for existing callers
    /// (tests, `--quiet`).
    pub on_phase_complete: Option<fn(&str, std::time::Duration)>,
    /// `script` locale (console messages), for translating the phase
    /// labels emitted to `on_phase_complete` — ticket #48. `None`
    /// preserves exactly the historical behavior (hardcoded
    /// French labels): only `main.rs` builds and provides
    /// a real locale for a user scan; the ~1030 unit tests
    /// of this module that build `ScanConfig::default()`
    /// without worrying about it are not affected.
    ///
    /// **Deliberate deviation from this module's established convention**:
    /// until now, `run_scan` never did an i18n lookup
    /// itself — it only carries `lang: String` as
    /// data, leaving it to the caller (e.g. `report/html.rs::
    /// generate_html`) to load its own locale and translate. This
    /// wasn't possible here: the Phase A label is
    /// built dynamically (per-language detail, ticket #46)
    /// *during* the phase itself, before anything makes
    /// it back up to `main.rs` — deferring translation to the caller
    /// would have required making it also carry this label-building
    /// logic, duplicating part of `run_scan`.
    pub script_locale: Option<serde_json::Value>,
    /// Reads only the files of `target_languages` (2026-11-12). `false`
    /// (default, the CLI scan): every source file is discovered, so that
    /// files of an undeclared language are named in a warning
    /// (`ScanReport::undeclared_languages`). `true`: the files of other
    /// languages are not even opened, for a caller that runs the rules
    /// of one language on large folders (a folder synced by a cloud
    /// service downloads each file it opens). No effect without
    /// `target_languages`.
    pub only_target_language_files: bool,
    /// Also hands back each rule's own findings, before the findings of
    /// different rules on one line are merged ([`ScanReport::rule_findings`],
    /// ticket #242). `false` (default): the scan keeps the report findings
    /// only. `rules noise` sets it to measure several rules in one scan:
    /// in the report, a rule's finding can be merged into another rule's
    /// finding of the same line and category, and is then counted under
    /// that other rule.
    pub keep_rule_findings: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::new(),
            include_paths: vec![".".to_string()],
            rules_path: PathBuf::new(),
            target_languages: None,
            custom_rules_dir: None,
            memory_check: true,
            memory_limit: None,
            suppress_file: None,
            cache_dir: None,
            exclude_patterns: Vec::new(),
            with_tests: false,
            test_command: None,
            with_deps: false,
            database: None,
            datas_dir: None,
            legacy_datas_dir: None,
            baseline_path: None,
            brand_prefix: "SCA".to_string(),
            timestamp: String::new(),
            quick_mode: false,
            only_category: None,
            category_overrides: BTreeMap::new(),
            disabled_rules: Vec::new(),
            severity_levels: None,
            lang: "en".to_string(),
            on_phase_complete: None,
            script_locale: None,
            only_target_language_files: false,
            keep_rule_findings: false,
        }
    }
}

/// Most recent baseline export: in `config.datas_dir`, or else in
/// `config.legacy_datas_dir` (ticket #133 — keeps the comparison with
/// the last scan made before the history directory moved). `None` when
/// history is disabled (`datas_dir == None`) or empty in both places.
fn find_baseline(config: &ScanConfig) -> Option<PathBuf> {
    if let Some(chosen) = &config.baseline_path {
        return Some(chosen.clone());
    }
    let datas_dir = config.datas_dir.as_ref()?;
    crate::report::export_json::find_latest_baseline(datas_dir, &config.brand_prefix).or_else(
        || {
            config.legacy_datas_dir.as_ref().and_then(|legacy| {
                crate::report::export_json::find_latest_baseline(legacy, &config.brand_prefix)
            })
        },
    )
}

/// Resolves the text of a phase label — translated via
/// `config.script_locale` if provided (ticket #48), otherwise the
/// historical French text as-is (`config.script_locale == None`,
/// behavior of all callers who don't care about it,
/// notably this module's unit tests).
fn phase_label(config: &ScanConfig, key: &str, french_fallback: &str) -> String {
    match &config.script_locale {
        Some(locale) => crate::i18n::t(locale, key),
        None => french_fallback.to_string(),
    }
}

/// Result of a scan. `Default` is the report of a scan stopped before
/// reading any file ([`ScanReport::stopped_for_memory`]).
#[derive(Default)]
pub struct ScanReport {
    /// The memory the scan was expected to take and what the machine had
    /// (ticket #281), printed by the CLI. Always set by `run_scan`.
    pub memory: Option<crate::scan::memory::MemoryEstimate>,
    /// The scan stopped before reading the files: `memory` does not fit
    /// in the available memory and [`ScanConfig::memory_check`] is on.
    /// Every other field is then empty.
    pub stopped_for_memory: bool,
    pub findings: Vec<ReportFinding>,
    /// The client rule findings dropped because a delivered rule flags
    /// the same line (`drop_custom_duplicates`, epic #278).
    pub custom_rule_duplicates: Vec<CustomRuleDuplicate>,
    pub files_scanned: usize,
    pub total_loc: usize,
    /// `.sca` files whose parsing/compilation failed (path,
    /// error message) — does not interrupt the scan, mirrors the
    /// robustness of `compute_file_summaries` on the Python side (a broken
    /// rule doesn't stop the others).
    pub rule_errors: Vec<(PathBuf, crate::rules::catalog::RuleLoadError)>,
    /// Rules of one identity met twice while loading (a client rule
    /// replacing a catalog rule, a rule defined twice in one source):
    /// printed by the CLI, so no rule is left out without a word.
    pub rule_conflicts: Vec<crate::rules::catalog::RuleConflict>,
    /// Rule languages whose rules were read (ADR-0038), sorted: the
    /// declared `target_languages`, or the languages of the discovered
    /// files.
    pub rule_languages: Vec<String>,
    /// Rule languages of discovered files missing from the declared
    /// `target_languages`, sorted: their files get no rule. Always empty
    /// without a declared list.
    pub undeclared_languages: Vec<String>,
    /// What each rule source gave the scan (ADR-0040): the catalog first,
    /// then the custom rules folder when it exists — rule files available
    /// and kept. Printed by the CLI so a reader sees what was actually
    /// loaded.
    pub rule_sources: Vec<crate::rules::catalog::RuleSourceSummary>,
    /// Compiled rules kept for the target languages, every source merged,
    /// before the category and `--disable-rule` filters.
    pub rules_loaded: usize,
    /// Folders the walk skipped because they hold no project code (build
    /// output, Python virtualenvs, documentation — tickets #148 and #152),
    /// in walk order. Printed by the CLI, so code in a skipped folder never
    /// goes unchecked without a word.
    pub skipped_dirs: Vec<SkippedDir>,
    /// Files skipped because they are minified (ADR-0045, `scan::
    /// minified`), relative to the project, in discovery order. Printed
    /// by the CLI for the same reason as `skipped_dirs`.
    pub skipped_minified: Vec<String>,
    /// Files skipped because they belong to a web page saved from a
    /// browser (ADR-0046, `scan::saved_page`), relative to the project,
    /// in discovery order. Printed by the CLI for the same reason as
    /// `skipped_dirs`.
    pub skipped_saved_pages: Vec<String>,
    /// The lockfiles next to a manifest that gave no version (tickets
    /// #209, #210): unreadable, or binary (`bun.lockb`), as `(lockfile
    /// path relative to the project, reason)`, the reason empty for a
    /// binary one. Their manifests' ranges are checked
    /// at their declared minimum; the CLI names each one once.
    pub lockfiles_not_used: Vec<(String, Option<String>)>,
    /// Catalog of compiled rules, indexed by identity (language + name):
    /// where the reports read each finding's rule texts (risk, solution,
    /// `fix_before`/`fix_after`), see `rules::identity`.
    pub rule_catalog: crate::rules::identity::RuleCatalog,
    /// Results of the audited project's tests, if `with_tests` was active.
    pub test_results: Option<crate::project::testing::TestResults>,
    /// Dependency statistics, if `with_deps` was active.
    pub dependency_stats: Option<DependencyStats>,
    /// The version rules the dependencies were checked against, or why
    /// they were not (ADR-0042, ADR-0043: never "none vulnerable" when
    /// nothing was checked). `None` when the dependencies phase did not run.
    pub version_rules: Option<VersionRulesStatus>,
    /// Extracted schema, if `database` was configured and the connection succeeded.
    pub database_schema: Option<crate::project::database::schema::DatabaseSchema>,
    /// Schema statistics (compared against the baseline if available).
    pub database_stats: Option<crate::project::database::schema::SchemaStats>,
    /// Comparison against the most recent baseline found in `datas_dir`.
    pub comparison: Option<crate::report::comparison::ComparisonResult>,
    /// Path of the JSON export written for this scan, if `datas_dir` was configured.
    pub export_path: Option<PathBuf>,
    /// The last scans of `datas_dir`, this one included, oldest first:
    /// the points of the report's trend chart (`export_json::load_history`).
    /// Empty when `datas_dir` is not configured.
    pub history: Vec<crate::report::export_json::HistoryPoint>,
    /// Languages actually encountered among the scanned files
    /// (`SourceLanguage::rule_tag()`, e.g. "python"/"java"), sorted and
    /// deduplicated — feeds the "audit settings" section of the
    /// HTML report.
    pub languages: Vec<String>,
    /// Duration of each scan phase, in execution order —
    /// internal performance diagnostic. Added on 2026-08-26 to
    /// verify, backed by measurements rather than assumed, where
    /// time is actually spent (rule loading/compilation vs
    /// parsing vs regex vs per-language taint) — cf. memory of the
    /// ongoing perf effort. `String` (not `&'static str`) since
    /// ticket #46: Phase A's label now carries the
    /// per-language file count, computed at call time
    /// and therefore not `'static`.
    pub phase_timings: Vec<(String, std::time::Duration)>,
    /// How much of each language's taint pass the cache spared (empty
    /// without a cache).
    pub cache_stats: Vec<crate::scan::scan_cache::CacheStat>,
    /// Governance file names the loaded rules look for
    /// (`not_path_has_file`), sorted: recorded with the scan so that the
    /// next one can check them without loading the rules (ADR-0050).
    pub governance_names: Vec<String>,
    /// With [`ScanConfig::keep_rule_findings`]: the findings of every
    /// rule as that rule alone gives them, after the suppressions and
    /// inline ignores, before the merge of different rules on one line
    /// (`integrate_taint_finding`), in the order the passes produce them.
    /// A rule's taint finding is here even when the report merged it into
    /// a finding of another rule. Empty otherwise.
    pub rule_findings: Vec<ReportFinding>,
}

#[derive(Debug, Clone, Default)]
pub struct DependencyStats {
    pub total_scanned: usize,
    pub unpinned: usize,
    pub ok: usize,
    /// Dependencies with at least one published vulnerability
    /// (`vulnerable_dependency` findings, ADR-0035).
    pub vulnerable: usize,
}

/// What the dependencies phase found as version rules (ADR-0043): the
/// published vulnerabilities carried by the rule pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionRulesStatus {
    /// Read from the pack at `pack`: creation date (newest OSV data) and
    /// advisories per ecosystem, in pack order.
    Read {
        pack: PathBuf,
        created: String,
        counts: Vec<(String, usize)>,
        /// The databases of the version rules and their licenses, for the
        /// credit of the report (ADR-0051). Empty for a pack built before.
        sources: Vec<crate::project::advisory_file::DataSource>,
    },
    /// The rules come from a pack without version rules, or from a folder
    /// of plain rules: dependencies were not checked against published
    /// vulnerabilities.
    Missing,
    /// Version rules that could not be opened, with why: translated in
    /// the console's language when shown (ticket #280).
    Unreadable {
        error: crate::rules::pack_format::PackError,
    },
}

/// Opens the version rules of the rule pack at `path` (ADR-0043): the
/// advisory container of its version rules section. A folder of plain
/// rules carries none.
fn read_version_rules(
    path: &Path,
) -> Result<Option<crate::project::advisory_file::DatabaseFile>, crate::rules::pack_format::PackError>
{
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = std::fs::read(path).map_err(|e| crate::rules::pack_format::unreadable_pack(&e))?;
    match crate::rules::pack_format::open_version_rules(&bytes)? {
        Some(container) => crate::project::advisory_file::decode(path, container).map(Some),
        None => Ok(None),
    }
}

/// The console line of a version rules file skipped by the scan
/// (`scan_version_rules_skipped`), in the language of `script_locale`,
/// English without one (ticket #280).
fn version_rules_skipped_line(
    error: &crate::rules::pack_format::PackError,
    script_locale: Option<&serde_json::Value>,
) -> String {
    let english;
    let locale = match script_locale {
        Some(locale) => locale,
        None => {
            english = crate::i18n::load_script_locale("en");
            &english
        }
    };
    crate::i18n::t(locale, "scan_version_rules_skipped").replace("{error}", &error.render(locale))
}

/// Texts of the dependency findings (`unpinned_dependency`,
/// `vulnerable_dependency`) in the report language — ticket #189.
///
/// These findings come from no catalog rule, so no rule carries their
/// texts in four languages: they live in the report locale, under
/// `dependency_findings`, with `{name}`-style placeholders. **Deliberate
/// exception to this module's convention** (see `script_locale`): `run_scan`
/// otherwise leaves i18n lookups to the report, but the finding's message
/// and solution are plain strings shared by every output (HTML, SARIF,
/// text), so they are built here, like the catalog texts already are
/// with `config.lang` (`extract_i18n_block`).
struct DependencyTexts {
    locale: serde_json::Value,
}

impl DependencyTexts {
    /// Loads the embedded report locale of `lang` (English for an
    /// unknown language, like the report itself).
    fn new(lang: &str) -> Self {
        Self {
            locale: crate::i18n::load_report_locale(lang),
        }
    }

    /// Text `dependency_findings.<key>`, placeholders left in place.
    fn get(&self, key: &str) -> String {
        crate::i18n::t(&self.locale, &format!("dependency_findings.{key}"))
    }
}

/// `vulnerable_dependency` findings for the dependencies of `deps` hit
/// by the version rules `file` of the pack (ADR-0035, ADR-0043) — one finding
/// per dependency, listing every distinct vulnerability, so a package
/// with ten CVEs does not bury the report under ten lines. The severity
/// is the highest among them, and CRITICAL as soon as one is listed by
/// CISA as exploited in attacks (ADR-0051). Each vulnerability names its
/// KEV mark and its EPSS score when the pack has them. Unreadable database
/// files are reported on stderr and skipped: the rest of the scan does not
/// depend on them.
/// The texts follow the report language (`texts`, ticket #189); the
/// advisory identifiers and OSV summaries stay as published, in English.
/// The lines about unreadable files follow the console language
/// (`script_locale`, ticket #280), English without one.
fn vulnerable_dependency_findings(
    file: &crate::project::advisory_file::DatabaseFile,
    deps: &[crate::project::dependencies::Dependency],
    root: &Path,
    texts: &DependencyTexts,
    script_locale: Option<&serde_json::Value>,
) -> Vec<ReportFinding> {
    use crate::project::advisories;

    let ecosystems: std::collections::BTreeSet<String> =
        deps.iter().map(|d| d.ecosystem.clone()).collect();
    let (db, errors) = advisories::load(file, &ecosystems);
    for error in errors {
        eprintln!(
            "[codefixture-audit] {}",
            version_rules_skipped_line(&error, script_locale)
        );
    }
    let rank = |s: &str| match s {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        _ => 1,
    };
    advisories::find_vulnerable(deps, &db)
        .into_iter()
        .map(|hit| {
            let dep = &hit.dependency;
            // An exploited vulnerability comes first in the report
            // whatever its advisory rates it (ADR-0051).
            let severity = if hit.advisories.iter().any(|a| a.exploited.is_some()) {
                "CRITICAL"
            } else {
                hit.advisories
                    .iter()
                    .map(|a| advisories::engine_severity(a))
                    .max_by_key(|s| rank(s))
                    .unwrap_or("MEDIUM")
            };
            // The 10 most severe with their summary (the list arrives
            // sorted), the rest by identifier only: an old Django pin
            // matches 45 advisories.
            const DETAILED: usize = 10;
            let mut listed: Vec<String> = hit
                .advisories
                .iter()
                .take(DETAILED)
                .map(|a| {
                    format!(
                        "{} ({}): {}",
                        a.display_id(),
                        advisory_marks(a, texts).join(", "),
                        a.summary
                    )
                })
                .collect();
            if hit.advisories.len() > DETAILED {
                let rest: Vec<&str> = hit.advisories[DETAILED..]
                    .iter()
                    .map(|a| a.display_id())
                    .collect();
                listed.push(texts.get("also").replace("{ids}", &rest.join(", ")));
            }
            let mut cwe: Vec<String> = hit.advisories.iter().flat_map(|a| a.cwe.clone()).collect();
            cwe.sort();
            cwe.dedup();
            if cwe.is_empty() {
                // CWE-1395: Dependency on Vulnerable Third-Party Component.
                cwe.push("CWE-1395".to_string());
            }
            // Ticket #211: a transitive package is upgraded through the
            // direct dependencies that bring it in, or forced when the
            // lockfile does not say which do.
            let transitive_via = match &dep.version_source {
                crate::project::dependencies::VersionSource::Transitive { via, .. } => {
                    Some(via.join(", "))
                }
                _ => None,
            };
            let solution = match (&hit.fixed_version, transitive_via.as_deref()) {
                (Some(fixed), Some("")) => texts
                    .get("vulnerable_solution_transitive_force")
                    .replace("{name}", &dep.name)
                    .replace("{fixed}", fixed),
                (None, Some("")) => texts
                    .get("vulnerable_solution_transitive_remove")
                    .replace("{name}", &dep.name),
                (Some(fixed), Some(via)) => texts
                    .get("vulnerable_solution_transitive_upgrade")
                    .replace("{name}", &dep.name)
                    .replace("{fixed}", fixed)
                    .replace("{via}", via),
                (None, Some(via)) => texts
                    .get("vulnerable_solution_transitive_replace")
                    .replace("{name}", &dep.name)
                    .replace("{via}", via),
                (Some(fixed), None) => texts
                    .get("vulnerable_solution_upgrade")
                    .replace("{name}", &dep.name)
                    .replace("{fixed}", fixed),
                (None, None) => texts
                    .get("vulnerable_solution_replace")
                    .replace("{name}", &dep.name),
            };
            let risk_key = if hit.advisories.len() == 1 {
                "vulnerable_risk_one"
            } else {
                "vulnerable_risk_many"
            };
            ReportFinding {
                rule_key: "vulnerable_dependency".to_string(),
                rule_language: String::new(), // no catalog rule: the version rules of the pack.
                rule_name: texts.get("vulnerable_name"),
                category: "DEPENDENCIES".to_string(),
                severity: severity.to_string(),
                // `{list}` last: an OSV summary may itself hold `{…}`.
                risk: texts
                    .get(risk_key)
                    .replace("{name}", &dep.name)
                    .replace(
                        "{version}",
                        &checked_version_label(dep, &hit.version, texts),
                    )
                    .replace("{count}", &hit.advisories.len().to_string())
                    .replace("{list}", &listed.join("; ")),
                file: project_relative_path(root, &dep.file),
                line: dep.line,
                solution: Some(solution),
                cwe,
                owasp: Some("A06:2021".to_string()),
                taint_flow: None,
                taint_flows: vec![],
                // Ticket #194: a manifest line can be long too.
                code: crate::report::text::clip_line(&dep.raw_line, 0),
                context_before: String::new(),
                context_after: String::new(),
                // The version is exact and the range comes from the
                // advisory itself; the remaining doubt is whether the
                // vulnerable code path is used.
                confidence: 90,
                benefit: String::new(),
                committer: None,
                rule_source: "advisory_db".to_string(),
                file_scope: None,
            }
        })
        .collect()
}

/// The version a finding names, with where it comes from when the
/// manifest does not pin it exactly (ticket #209): the lockfile that
/// records it, or the range it is the declared minimum of and why no
/// lockfile gave the installed version.
fn checked_version_label(
    dep: &crate::project::dependencies::Dependency,
    version: &str,
    texts: &DependencyTexts,
) -> String {
    use crate::project::dependencies::{LockStatus, VersionSource};
    match &dep.version_source {
        // An unresolved property gives no version: never in a finding
        // with one.
        VersionSource::Manifest | VersionSource::UnresolvedProperty { .. } => version.to_string(),
        VersionSource::Lockfile { file } => texts
            .get("version_locked")
            .replace("{version}", version)
            .replace("{file}", file),
        // Ticket #211: a package no direct dependency is.
        VersionSource::Transitive { file, via, graph } => {
            let key = match (via.is_empty(), graph) {
                (false, _) => "version_transitive",
                (true, true) => "version_transitive_unreached",
                (true, false) => "version_transitive_no_graph",
            };
            texts
                .get(key)
                .replace("{version}", version)
                .replace("{file}", file)
                .replace("{via}", &via.join(", "))
        }
        VersionSource::DeclaredMinimum { constraint, lock } => {
            let reason = match lock {
                LockStatus::Absent => texts.get("lock_absent"),
                LockStatus::NotListed { file } => {
                    texts.get("lock_not_listed").replace("{file}", file)
                }
                LockStatus::NotAVersion { file, value } => texts
                    .get("lock_not_a_version")
                    .replace("{file}", file)
                    .replace("{value}", value),
                LockStatus::Unreadable { file, .. } => {
                    texts.get("lock_unreadable").replace("{file}", file)
                }
                LockStatus::Binary { file } => texts.get("lock_binary").replace("{file}", file),
            };
            texts
                .get("version_minimum")
                .replace("{version}", version)
                .replace("{reason}", &reason)
                .replace("{constraint}", constraint)
        }
    }
}

/// The lockfiles of `deps` that gave no version because they cannot be
/// read, or are binary (`bun.lockb`), each once, with the reason for an
/// unreadable one (tickets #209, #210).
fn lockfiles_not_used_by(
    deps: &[crate::project::dependencies::Dependency],
    root: &Path,
) -> Vec<(String, Option<String>)> {
    use crate::project::dependencies::{LockStatus, VersionSource};
    let mut found: Vec<(String, Option<String>)> = Vec::new();
    for dep in deps {
        let VersionSource::DeclaredMinimum { lock, .. } = &dep.version_source else {
            continue;
        };
        let (file, reason) = match lock {
            LockStatus::Unreadable { file, reason } => (file, Some(reason.clone())),
            LockStatus::Binary { file } => (file, None),
            _ => continue,
        };
        let path = dep.file.parent().unwrap_or(root).join(file);
        let entry = (project_relative_path(root, &path), reason);
        if !found.contains(&entry) {
            found.push(entry);
        }
    }
    found
}

/// What a finding says of one vulnerability between parentheses: its
/// severity, then its KEV mark and its EPSS score when the pack has them
/// (ADR-0051), in the report language.
fn advisory_marks(
    advisory: &crate::project::advisories::Advisory,
    texts: &DependencyTexts,
) -> Vec<String> {
    let mut marks = vec![crate::project::advisories::engine_severity(advisory).to_string()];
    if let Some(exploited) = &advisory.exploited {
        let key = if exploited.ransomware {
            "exploited_ransomware"
        } else {
            "exploited"
        };
        marks.push(texts.get(key).replace("{date}", &exploited.added));
    }
    if let Some(epss) = advisory.epss {
        let percent = epss_percent(epss.epss).replace('.', &texts.get("decimal_mark"));
        marks.push(texts.get("epss").replace("{percent}", &percent));
    }
    marks
}

/// An EPSS score (0 to 1) as a percentage with one decimal, rounded
/// down: the figure never claims more than the score. Rounded to the
/// nearest, 0.9995 read `100.0` (Log4Shell in 2026-11, ticket #197),
/// although a probability below 1 is never certain.
fn epss_percent(score: f64) -> String {
    // The small margin absorbs the binary error of `score * 1000` (0.973
    // gives 972.9999…), which would otherwise floor one tenth too low.
    let tenths = (score * 1000.0 + 1e-9).floor();
    format!("{:.1}", tenths / 10.0)
}

/// Splits a file's content into lines, keeping their original line
/// terminator (the `readlines()` contract expected by
/// `engine::pattern::execute_regex_rule`).
fn split_lines_with_terminators(content: &str) -> Vec<(usize, String)> {
    content
        .split_inclusive('\n')
        .enumerate()
        .map(|(i, l)| (i + 1, l.to_string()))
        .collect()
}

/// Text of line `line` (1-based; 0 reads the first line, as it always
/// has) without its final `\n`, empty past the last line.
fn line_text(source_lines: &SourceLines, line: usize) -> String {
    source_lines
        .get(line.saturating_sub(1))
        .map(|t| t.trim_end_matches('\n').to_string())
        .unwrap_or_default()
}

pub(crate) fn rule_category(rule_json: &serde_json::Value) -> String {
    rule_json
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Extracts the i18n text of a DSL block (`risk`/`solution`/`benefit`).
///
/// `lang`: target language — tried first, then falls back to `"en"`,
/// then to the first available language. Deviation fixed (2026-08-26,
/// reported by the maintainer): used to ignore `lang` and always fall back to
/// `"en"` regardless of `--lang` — the `risk`/`solution`/`benefit`
/// text of a `--lang fr` report stayed systematically in English
/// despite correctly translated interface labels.
pub(crate) fn extract_i18n_block(rule_json: &serde_json::Value, key: &str, lang: &str) -> String {
    match rule_json.get(key) {
        Some(serde_json::Value::Object(map)) => {
            let target = map
                .get(lang)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            let en = || {
                map.get("en")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
            };
            target
                .or_else(en)
                .map(|s| s.to_string())
                .or_else(|| {
                    map.values()
                        .next()
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_default()
        }
        Some(serde_json::Value::String(s)) if !s.is_empty() => s.clone(),
        _ => String::new(),
    }
}

/// Displayable description of a rule: `message` if present, otherwise
/// falls back to `risk` — many (non-taint) regex rules only carry a
/// `risk` block, `message` being used mostly on the taint side (see
/// real examples from the builtin corpus, `base64_eval.sca` vs
/// `taint_codeinj.sca`).
fn rule_display_message(rule_json: &serde_json::Value, lang: &str) -> String {
    let m = extract_message(rule_json, lang);
    if m.is_empty() {
        extract_i18n_block(rule_json, "risk", lang)
    } else {
        m
    }
}

/// The `language` of a compiled rule, `""` when it has none: written on
/// each of its findings, so the report reads the rule of the finding's
/// own language (`ReportFinding::rule_id`).
fn rule_language(rule_json: &serde_json::Value) -> String {
    rule_json
        .get("language")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn engine_finding_to_report(
    f: &crate::scan::engine::Finding,
    rule_json: &serde_json::Value,
    rel_path: &str,
    source_lines: &SourceLines,
    lang: &str,
) -> ReportFinding {
    use crate::report::text::{clip_line, clip_lines};
    // A whole-file finding has no line around which context means
    // anything: the lines after line 1 would read as the faulty code
    // (ticket #214).
    let (context_before, context_after) = if f.file_scope.is_some() {
        (String::new(), String::new())
    } else {
        crate::report::text::context_lines(|i| source_lines.get(i), f.line, 2)
    };
    ReportFinding {
        rule_key: f.rule_id.clone(),
        rule_language: rule_language(rule_json),
        // The rule's name in the report language (its `name` block), not
        // its key: the report showed `hardcoded_secret_cicd` everywhere
        // (ticket #227). The key stays in `rule_key`.
        rule_name: crate::report::text::rule_display_name(rule_json, lang),
        category: f.category.clone(),
        severity: f.severity.clone(),
        risk: rule_display_message(rule_json, lang),
        file: rel_path.to_string(),
        line: f.line,
        solution: Some(extract_i18n_block(rule_json, "solution", lang)),
        cwe: extract_cwe(rule_json).into_iter().collect(),
        owasp: rule_json
            .get("metadata")
            .and_then(|m| m.get("owasp"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
        taint_flow: None,
        taint_flows: vec![],
        // Ticket #194: a long line is shown clipped around the match, its
        // context lines around the same column.
        code: clip_line(&f.code, f.column),
        context_before: clip_lines(&context_before, f.column),
        context_after: clip_lines(&context_after, f.column),
        confidence: f.confidence,
        benefit: extract_i18n_block(rule_json, "benefit", lang),
        committer: None,
        rule_source: rule_source_of(rule_json).to_string(),
        file_scope: f.file_scope,
    }
}

/// Builds the `TaintFlow` of a taint finding — mirrors the
/// construction of `sca.models.TaintFlow` on the Audit side
/// (`source_kind` excluded, which has no single per-finding equivalent
/// here: it comes from the matched `SourceSpec`, see `f.source_kind`).
/// Safe fallback when `f.flow` does not clearly distinguish
/// source/sink (hybrid text-based engines): uses `f.source_line`/
/// `f.line` directly rather than inventing a step.
fn build_taint_flow(
    f: &crate::scan::dataflow::transfer::Finding,
    rel_path: &str,
    source_lines: &SourceLines,
) -> TaintFlow {
    use crate::report::text::{clip_line, focus_of};
    // Each step with its file and real code line: a step stamped by the
    // call graph carries both; any other one is in this file.
    let steps: Vec<TaintStep> = f
        .flow
        .iter()
        .map(|s| {
            // The report owns its strings: the engine's shared texts are
            // copied once here (ticket #191).
            let code = s
                .code
                .as_deref()
                .map(str::to_string)
                .or_else(|| {
                    s.file
                        .is_none()
                        .then(|| source_lines.get(s.line.wrapping_sub(1)))
                        .flatten()
                        .map(|l| l.trim().to_string())
                })
                .filter(|c| !c.is_empty())
                .unwrap_or_else(|| s.text.to_string());
            // Ticket #194: a long step line is clipped around the step's
            // expression.
            let code = clip_line(&code, focus_of(&code, &s.text));
            TaintStep {
                kind: s.kind.clone(),
                file: s.file.clone().unwrap_or_else(|| rel_path.to_string()),
                line: s.line,
                code,
            }
        })
        .collect();
    let source_step = f.flow.iter().find(|s| s.kind == "source");
    let sink_step = f.flow.iter().rev().find(|s| s.kind == "sink");
    let chain: Vec<(usize, String, String)> = f
        .flow
        .iter()
        .filter(|s| s.kind == "propagation")
        .map(|s| (s.line, String::new(), clip_line(&s.text, 0)))
        .collect();
    TaintFlow {
        rule_key: f.rule_id.clone(),
        source_file: rel_path.to_string(),
        source_line: source_step.map_or_else(|| f.source_line.unwrap_or(f.line), |s| s.line),
        source_expr: source_step.map_or_else(String::new, |s| clip_line(&s.text, 0)),
        chain,
        sink_file: rel_path.to_string(),
        sink_line: f.line,
        sink_expr: clip_line(sink_step.map_or(&f.sink_text, |s| &s.text), 0),
        source_kind: f.source_kind.clone(),
        steps,
    }
}

fn taint_finding_to_report(
    f: &crate::scan::dataflow::transfer::Finding,
    rule_json: &serde_json::Value,
    rel_path: &str,
    source_lines: &SourceLines,
    lang: &str,
) -> ReportFinding {
    use crate::report::text::{clip_line, clip_lines, focus_of};
    let (context_before, context_after) =
        crate::report::text::context_lines(|i| source_lines.get(i), f.line, 2);
    let flow = build_taint_flow(f, rel_path, source_lines);
    // Actual code line displayed in the highlighted block — mirrors
    // `self._get_line_content(flow.sink_file, flow.sink_line)` on the
    // `rule_engine.py::_integrate_taint_flow` side. `f.sink_text`
    // (call/callee name alone, e.g. "render_template_string") was not
    // the right source here — found by the maintainer: the report displayed
    // just the function name instead of the whole line
    // (`return render_template_string(template)`). `sink_text` remains
    // the right source for `TaintFlow.sink_expr` (summarized in the
    // "🔬 Traced" detail), a different need.
    let code = source_lines
        .get(f.line.saturating_sub(1))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| f.sink_text.to_string());
    // Ticket #194: a long sink line is clipped around the sink's callee,
    // its context lines around the same column.
    let focus = focus_of(&code, &f.sink_text);
    let code = clip_line(&code, focus);
    let context_before = clip_lines(&context_before, focus);
    let context_after = clip_lines(&context_after, focus);
    ReportFinding {
        rule_key: f.rule_id.clone(),
        rule_language: rule_language(rule_json),
        // Name in the report language, like `engine_finding_to_report`
        // (ticket #227).
        rule_name: crate::report::text::rule_display_name(rule_json, lang),
        // Category declared by the DSL rule, not a pseudo-category
        // "Taint" — mirrors `cat_key = flow.category.upper()` on the
        // `rule_engine.py::_integrate_taint_flow` side (a taint finding
        // joins the same SECURITY/ARCH/... category as regex findings,
        // a necessary condition for the health score — computed on the
        // SECURITY category alone — to count them).
        category: rule_category(rule_json).to_uppercase(),
        severity: f.severity.clone(),
        risk: f.message.clone(),
        file: rel_path.to_string(),
        line: f.line,
        solution: Some(extract_i18n_block(rule_json, "solution", lang)),
        cwe: f.cwe.clone().into_iter().collect(),
        owasp: None,
        taint_flow: Some(flow.clone()),
        taint_flows: vec![flow],
        code,
        context_before,
        context_after,
        // Fixed at 90, mirrors `sca/rule_engine.py:1131` (confidence=90
        // for any finding coming from a taint flow).
        confidence: 90,
        benefit: extract_i18n_block(rule_json, "benefit", lang),
        committer: None,
        rule_source: rule_source_of(rule_json).to_string(),
        file_scope: None,
    }
}

/// `ReportFinding::rule_source` from the rule's `"origin"` (ticket #143,
/// set by `rules::catalog`): `json_custom` for the client's own rules
/// (custom rules folder), `json_builtin` otherwise (the catalog pack or
/// the `--rules` folder). The `official` origin of the signed packs is
/// gone (ADR-0040) and maps to `json_builtin` like any unknown value.
fn rule_source_of(rule_json: &serde_json::Value) -> &'static str {
    match rule_json.get("origin").and_then(|v| v.as_str()) {
        Some("client") => "json_custom",
        _ => "json_builtin",
    }
}

/// Attaches the flows of a taint finding to an already-present finding
/// — mirrors `_attach(finding, fl)` (internal function of
/// `rule_engine.py::_integrate_taint_flow`). Idempotent per flow
/// `rule_key` (a flow already attached for this rule is not
/// duplicated), sets `taint_flow` (singular) only if it was still
/// empty (the first flow attached wins, as on the Python side), and
/// always raises confidence to 95 — Python calls `_attach` on EVERY
/// integrated flow, including a finding just created with no merge
/// (verified empirically: on
/// `AuditBenchmarks/data/crypto/failles.py`, `taint_sqli`/`taint_xss`
/// — alone on their line, no merge — are at confidence 95 in the
/// Python JSON, not 90).
fn attach_taint_flows(existing: &mut ReportFinding, new_finding: &ReportFinding) {
    for flow in &new_finding.taint_flows {
        if existing
            .taint_flows
            .iter()
            .any(|f| f.rule_key == flow.rule_key)
        {
            continue;
        }
        existing.taint_flows.push(flow.clone());
        if existing.taint_flow.is_none() {
            existing.taint_flow = Some(flow.clone());
        }
    }
    existing.confidence = existing.confidence.max(95);
}

/// Merges a taint finding with an already-present finding on the same
/// (file, line, category) rather than adding a duplicate report line —
/// mirrors `rule_engine.py::_integrate_taint_flow`. Without this
/// mechanism, the same vulnerability detected by two different rules
/// at the same spot produces two findings instead of one on the Rust
/// side, whereas Python merges them. Two real examples
/// (`AuditBenchmarks/data/crypto/failles.py`, triage of 2026-08-26): a
/// `taint_rce` flow on a line already reported by the regex rule
/// `os_system_injection` (the same `os.system(` detected twice,
/// differently); a `taint_xss` flow on a line already reported by
/// `taint_ssti` (`render_template_string(` is a sink listed in both
/// rules — both vulnerabilities are real, only the display must stay
/// unique).
///
/// Two passes, as on the Python side: (1) look for a finding from the
/// same rule "family" already present on this line (identical
/// `rule_key` or common prefix, e.g. `ssrf`/`ssrf_python`) — merge into
/// it if found; (2) otherwise, merge into the first finding found on
/// the line, regardless of its rule. The already-present finding
/// "wins" the display — the merged vulnerability is not lost (its flow
/// joins `taint_flows`), just not duplicated as a report line.
///
/// **Accepted deviation**: which rule "wins" the display on a given
/// line depends on the taint rule processing order — `load_rules` now
/// sorts by alphabetical path, mirroring
/// `sorted(rules_dir.rglob("*.sca"))` on the Python side
/// (`rule_loader.py`), a necessary condition for this tie-break to be
/// identical.
///
/// The findings already on the line are found through `by_line`, which
/// must index `all_findings` (ticket #239): scanning every finding for
/// each new one cost a time growing with the square of the number of
/// findings.
///
/// A finding only merges into a finding of the same origin
/// (`rule_source`: delivered rules, or the client's own), so that a
/// delivered rule's finding is never folded into a client rule's: which
/// one the report keeps on a line both flag is decided afterwards, by
/// [`drop_custom_duplicates`]. Without client rules every finding has
/// the delivered origin and the merge is exactly Audit's.
fn integrate_taint_finding(
    all_findings: &mut Vec<ReportFinding>,
    by_line: &mut FindingsByLine,
    new_finding: ReportFinding,
) {
    let key = (
        new_finding.file.clone(),
        new_finding.line,
        new_finding.category.clone(),
    );
    let same_line: Vec<usize> = by_line
        .0
        .get(&key)
        .map(|positions| {
            positions
                .iter()
                .copied()
                .filter(|&i| all_findings[i].rule_source == new_finding.rule_source)
                .collect()
        })
        .unwrap_or_default();

    if same_line.is_empty() {
        // Mirrors Python: even a freshly created taint finding, with
        // no merge, is immediately "attached" to itself
        // (`_attach(f, flow)` right after `_add_finding`) — confidence
        // goes to 95 in every case.
        let mut new_finding = new_finding;
        new_finding.confidence = new_finding.confidence.max(95);
        all_findings.push(new_finding);
        by_line
            .0
            .entry(key)
            .or_default()
            .push(all_findings.len() - 1);
        return;
    }

    // Pass 1: rule_key from the same family (exact match or common prefix).
    for &i in &same_line {
        let fk = &all_findings[i].rule_key;
        let tk = &new_finding.rule_key;
        if fk == tk || fk.starts_with(tk.as_str()) || tk.starts_with(fk.as_str()) {
            attach_taint_flows(&mut all_findings[i], &new_finding);
            return;
        }
    }
    // Pass 2: merge into the first finding already present on the
    // line — EVEN when `rule_key` is unrelated (e.g. a taint finding
    // merged into an unrelated regex finding). Deliberately checked
    // against the actual execution of Python (not just by reading
    // `rule_engine.py::_integrate_taint_flow`, which this exactly
    // mirrors) on 2026-09-01, ticket #30: a JS file with
    // `eval(req.body.code)` matched both `eval_usage_js` (regex, phase
    // B — a Rust-only bootstrap rule, removed on 2026-11-04 since it had
    // no Python counterpart) and `taint_codeinj` (taint, phase C) on the same line — the
    // actual SARIF output of `run_audit.py` contains only ONE finding
    // on this line (`taint_codeinj`, with a mix of cross-language
    // metadata caused by an id collision between the Python/JS/Java
    // catalogs sharing the same rule name `taint_codeinj` — a separate
    // topic, not addressed here). This is therefore NOT a merge bug
    // introduced by this port: Python also merges two unrelated rules
    // that match the same line+category, as surprising as that may
    // seem to a future reader who discovers that a ported taint rule
    // silently "disappears" from the report when an unrelated regex
    // rule shares its line.
    attach_taint_flows(&mut all_findings[same_line[0]], &new_finding);
}

/// The findings of each (file, line, category), as their positions in the
/// list of findings, in list order: what [`integrate_taint_finding`] merges
/// a taint finding into, found without scanning every finding (ticket
/// #239). A merge only adds flows to a finding, never moves it: the
/// positions stay valid, and a new finding is added by
/// `integrate_taint_finding` itself.
struct FindingsByLine(HashMap<(String, usize, String), Vec<usize>>);

impl FindingsByLine {
    /// Indexes `findings` as they are.
    fn new(findings: &[ReportFinding]) -> Self {
        let mut index: HashMap<(String, usize, String), Vec<usize>> = HashMap::new();
        for (position, f) in findings.iter().enumerate() {
            index
                .entry((f.file.clone(), f.line, f.category.clone()))
                .or_default()
                .push(position);
        }
        FindingsByLine(index)
    }
}

/// A line where a client rule (ADR-0057) flagged what a delivered rule
/// already flags: same file, line and category. The report keeps the
/// delivered rule's finding there and drops the client's; the scan and the
/// report name each such pair so the client knows their rule duplicates a
/// delivered one (epic #278, ADR-0064).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomRuleDuplicate {
    /// The client rule whose finding was dropped.
    pub custom_rule: crate::rules::identity::RuleId,
    /// The delivered rule whose finding was kept (the first on the line).
    pub shipped_rule: crate::rules::identity::RuleId,
    /// Project-relative file of the line.
    pub file: String,
    /// The line.
    pub line: usize,
}

/// Drops every client rule finding on a (file, line, category) that a
/// delivered rule's finding also holds, and returns what was dropped, in
/// findings order. Deliberate deviation from Audit, which merged a taint
/// finding into whichever finding came first on the line and kept two
/// pattern findings side by side: a client rule written for an in-house
/// API could hide a delivered finding, or show twice what the catalog
/// already reports. The delivered finding is the reference (it carries
/// the catalog's texts, mappings and remediation); the client is told
/// instead. Without client findings nothing changes.
fn drop_custom_duplicates(findings: &mut Vec<ReportFinding>) -> Vec<CustomRuleDuplicate> {
    let is_client = |f: &ReportFinding| f.rule_source == "json_custom";
    if !findings.iter().any(is_client) {
        return Vec::new();
    }
    let mut shipped: HashMap<(&str, usize, &str), crate::rules::identity::RuleId> = HashMap::new();
    for f in findings.iter().filter(|f| !is_client(f)) {
        shipped
            .entry((f.file.as_str(), f.line, f.category.as_str()))
            .or_insert_with(|| f.rule_id());
    }
    let mut duplicates = Vec::new();
    let mut keep = Vec::with_capacity(findings.len());
    for f in findings.iter() {
        let covered = is_client(f)
            .then(|| shipped.get(&(f.file.as_str(), f.line, f.category.as_str())))
            .flatten();
        match covered {
            Some(shipped_rule) => {
                duplicates.push(CustomRuleDuplicate {
                    custom_rule: f.rule_id(),
                    shipped_rule: shipped_rule.clone(),
                    file: f.file.clone(),
                    line: f.line,
                });
                keep.push(false);
            }
            None => keep.push(true),
        }
    }
    let mut flags = keep.into_iter();
    findings.retain(|_| flags.next().unwrap_or(true));
    duplicates
}

/// The duplicates of [`drop_custom_duplicates`] grouped by (client rule,
/// delivered rule), with the number of lines of each pair, sorted: what
/// the console and the report print, one line per pair.
pub fn custom_duplicate_pairs(
    duplicates: &[CustomRuleDuplicate],
) -> Vec<(
    crate::rules::identity::RuleId,
    crate::rules::identity::RuleId,
    usize,
)> {
    let mut pairs: BTreeMap<
        (
            crate::rules::identity::RuleId,
            crate::rules::identity::RuleId,
        ),
        usize,
    > = BTreeMap::new();
    for d in duplicates {
        *pairs
            .entry((d.custom_rule.clone(), d.shipped_rule.clone()))
            .or_default() += 1;
    }
    pairs.into_iter().map(|((c, s), n)| (c, s, n)).collect()
}

/// A file already read and parsed, kept in memory for the whole scan
/// duration: its text for the pattern rules, the taint passes and the
/// report, and, until its taint pass takes it, what that pass needs of
/// its tree. The tree itself is never kept (ticket #281).
struct ParsedFile {
    rel_path: String,
    filepath: PathBuf,
    /// The text of the file and its lines (terminators kept), with the
    /// per-line facts shared by every taint rule of the scan (ticket
    /// #240): the one copy of the text the scan keeps (ticket #241). The
    /// pattern pass, the language passes, their call graphs and the
    /// report read it; the passes and call graphs hold the same
    /// allocation.
    source: Arc<SourceLines>,
    /// What the taint pass of the file's language needs of its tree
    /// (`taint::TaintFile`: its prepared functions, imports, calls...),
    /// read by phase A right after parsing, when that pass has a taint
    /// rule; `None` otherwise, and once the pass has taken it. The tree
    /// is dropped as soon as it is read (ticket #281): phase A holds at
    /// most one tree per thread, where the scan used to keep the tree of
    /// every file of a followed language until its pass ended, 38 to 45 %
    /// of the peak memory on the Juliet suites (ticket #241 had already
    /// dropped the trees of the other files once their lines of code were
    /// counted). Boxed: it is several hundred bytes, most files have
    /// none, and phase A moves each file once.
    taint: Option<Box<taint::TaintFile>>,
    language: SourceLanguage,
}

impl ParsedFile {
    /// The bytes of the text, those the tree was parsed from: what the
    /// analyses read a node's text from. A file that is not valid UTF-8
    /// is read with its invalid bytes replaced (`from_utf8_lossy`), and
    /// these are the bytes of that text, not those on disk. The scan used
    /// to hand the analyses the bytes on disk with a tree parsed from the
    /// replaced text: every node after an invalid byte was read two bytes
    /// off per replaced byte, and a Java flow below a Latin-1 comment
    /// was lost (ticket #241). The Audit reads the file the same way
    /// (`errors="replace"`) and parses the bytes of that text.
    fn bytes(&self) -> &[u8] {
        self.source.text().as_bytes()
    }

    /// Both paths of the file, as the pattern rules need them:
    /// project-relative for folder conditions, on-disk for the
    /// governance-file walk (see `FileLocation`).
    fn location(&self) -> FileLocation<'_> {
        FileLocation {
            absolute: &self.filepath,
            relative: &self.rel_path,
        }
    }
}

/// One taint pass of phase C (`taint::run_taint_pass` for one language):
/// it borrows the parsed files mutably while it runs, to drop the trees
/// of its files as soon as it has read them (ticket #281).
type TaintPass = fn(
    &mut [ParsedFile],
    &[serde_json::Value],
    &mut PassContext<'_>,
    &mut taint::SeenTaint,
) -> (String, std::time::Duration);

/// What the passes of phases B and C read from the scan and add to it:
/// one value for the whole scan, handed to the pattern pass (`patterns`)
/// then to each taint pass (`taint`).
struct PassContext<'s> {
    config: &'s ScanConfig,
    /// The user's suppressions (`.sca-suppress.json`).
    suppressions: &'s Suppressions,
    /// Cache folder of this engine, `None` when the scan runs without cache.
    cache: Option<&'s crate::scan::scan_cache::CacheContext>,
    /// The report's findings, in the order the passes add them.
    findings: &'s mut Vec<ReportFinding>,
    /// One line per pass that used the cache, for the console summary.
    cache_stats: &'s mut Vec<crate::scan::scan_cache::CacheStat>,
    /// Each rule's own findings, before any merge, when the scan keeps
    /// them (`ScanConfig::keep_rule_findings`, ticket #242).
    rule_findings: Option<&'s mut Vec<ReportFinding>>,
    /// Taint rules a pass runs at the same time, chosen for the memory
    /// available (`scan::memory::plan`, ticket #281).
    rules_at_once: usize,
}

/// What phase A made of one discovered file.
enum FileOutcome {
    /// Read and parsed, with the lines of code it counts.
    Parsed(usize, ParsedFile),
    /// Skipped as minified (ADR-0045, `scan::minified`): its path
    /// relative to the project, for the report and the console.
    Minified(String),
    /// Skipped as part of a web page saved from a browser (ADR-0046,
    /// `scan::saved_page`): its path relative to the project.
    SavedPage(String),
    /// Unreadable or unparsable: left out of the scan, as before.
    Failed,
}

#[cfg(test)]
impl FileOutcome {
    /// The parsed file, `None` when it was skipped or failed: what a test
    /// fixture expects.
    fn into_parsed(self) -> Option<ParsedFile> {
        match self {
            FileOutcome::Parsed(_, file) => Some(file),
            FileOutcome::Minified(_) | FileOutcome::SavedPage(_) | FileOutcome::Failed => None,
        }
    }
}

/// Reads and parses one discovered file: its text, lines, tree and
/// language, with its path relative to `root`, and the lines of code it
/// counts. A saved web page (ADR-0046) and a minified file (ADR-0045)
/// are recognized right after reading, before any parsing. Phase A runs it on every file in parallel;
/// the tests build their files with it, so they see a file exactly as a
/// scan does. When the file's language is one of `tree_languages`, the
/// taint pass of that language reads the tree here
/// (`taint::TaintFile::extract`, ticket #281); the tree is then dropped,
/// as it is for every other file once its lines of code are counted
/// (ticket #241): no tree outlives this function.
///
/// The debug log (ticket #282) gets the start and end of each file, with
/// its outcome: lines of code, bytes, size of its tree and whether its
/// taint pass read it, or why the file was skipped or failed.
fn parse_file(root: &Path, filepath: &Path, tree_languages: &[SourceLanguage]) -> FileOutcome {
    let step = crate::scan::debug_log::span("phase_a", || {
        format!("file path={:?}", project_relative_path(root, filepath))
    });
    let outcome = match read_and_parse(root, filepath, tree_languages) {
        Ok(outcome) => outcome,
        Err(reason) => {
            crate::debug_log!(
                "phase_a",
                "file_failed path={:?} reason={reason:?}",
                project_relative_path(root, filepath)
            );
            FileOutcome::Failed
        }
    };
    step.end_with(|| match &outcome {
        FileOutcome::Parsed(loc, pf) => format!(
            "outcome=parsed language={} loc={loc} bytes={} taint_read={}",
            pf.language.rule_tag(),
            pf.source.text().len(),
            pf.taint.is_some()
        ),
        FileOutcome::Minified(_) => "outcome=skipped reason=minified".to_string(),
        FileOutcome::SavedPage(_) => "outcome=skipped reason=saved_page".to_string(),
        FileOutcome::Failed => "outcome=failed".to_string(),
    });
    outcome
}

/// Body of [`parse_file`]; an error, the reason, when the file cannot be
/// read or parsed (the reason only goes to the debug log: such a file is
/// left out of the scan, as before).
fn read_and_parse(
    root: &Path,
    filepath: &Path,
    tree_languages: &[SourceLanguage],
) -> Result<FileOutcome, String> {
    // Unknown extension/name: should not happen (discovery already filtered).
    let language = SourceLanguage::from_path(filepath)
        .ok_or_else(|| "no language for this name".to_string())?;
    // Valid UTF-8 (nearly every file) becomes the text without a copy;
    // otherwise the invalid bytes are replaced, as Python's
    // `errors="replace"` does.
    let read_started = crate::scan::debug_log::enabled().then(std::time::Instant::now);
    let bytes = std::fs::read(filepath).map_err(|e| format!("read: {e}"))?;
    let source_text = String::from_utf8(bytes)
        .unwrap_or_else(|invalid| String::from_utf8_lossy(invalid.as_bytes()).into_owned());
    let rel_path = project_relative_path(root, filepath);
    if let Some(started) = read_started {
        crate::debug_log!(
            "phase_a",
            "file_read path={rel_path:?} bytes={} ms={}",
            source_text.len(),
            crate::scan::debug_log::ms_since(started)
        );
    }
    // A saved page first: it is often minified too, and its own reason
    // tells the reader more (ADR-0046).
    if language == SourceLanguage::Html && crate::scan::saved_page::is_saved_page_text(&source_text)
    {
        return Ok(FileOutcome::SavedPage(rel_path));
    }
    if crate::scan::minified::is_minified(filepath, language, &source_text) {
        return Ok(FileOutcome::Minified(rel_path));
    }
    let mut parser = TsParser::new();
    let ts_lang: tree_sitter::Language = match language {
        SourceLanguage::Python => tree_sitter_python::LANGUAGE.into(),
        SourceLanguage::Java => tree_sitter_java::LANGUAGE.into(),
        SourceLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        SourceLanguage::TypeScript => ts_grammar_for(filepath),
        SourceLanguage::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        SourceLanguage::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        SourceLanguage::Html => tree_sitter_html::LANGUAGE.into(),
        SourceLanguage::Yaml => tree_sitter_yaml::LANGUAGE.into(),
        // The only crate with no official org (ticket #69): older
        // API, a `language()` function that already returns
        // `tree_sitter::Language` — no `LanguageFn`/`.into()`
        // like the 8 other grammars in this match.
        SourceLanguage::Dockerfile => tree_sitter_dockerfile_updated::language(),
        // Configuration files (ADR-0047): only line rules read them, the
        // tree only counts their comment lines. XML goes through the
        // error-tolerant HTML grammar (same `<!-- -->` comment node), JSON
        // through the JavaScript one (a JSON document is a JS expression).
        SourceLanguage::MavenPom | SourceLanguage::WebConfig => tree_sitter_html::LANGUAGE.into(),
        SourceLanguage::PackageJson => tree_sitter_javascript::LANGUAGE.into(),
    };
    parser
        .set_language(&ts_lang)
        .map_err(|e| format!("grammar: {e}"))?;
    let parse_started = crate::scan::debug_log::enabled().then(std::time::Instant::now);
    let tree = parser
        .parse(&source_text, None)
        .ok_or_else(|| "the parser gave no tree".to_string())?;
    if let Some(started) = parse_started {
        crate::debug_log!(
            "phase_a",
            "file_parsed path={rel_path:?} tree_nodes={} has_errors={} ms={}",
            tree.root_node().descendant_count(),
            tree.root_node().has_error(),
            crate::scan::debug_log::ms_since(started)
        );
    }
    let source_bytes = source_text.as_bytes();

    let loc = match language {
        SourceLanguage::Python => count_python_loc(source_bytes, &tree),
        SourceLanguage::Java => count_java_loc(source_bytes, &tree),
        // `count_js_loc` operates purely on the "comment"
        // kind-string, identical across JS/TS/PHP/C#/HTML/YAML/
        // Dockerfile (verified empirically on the 4 new
        // grammars, ticket #69: a single "comment" node, no
        // line_comment/block_comment split like in Java) — no
        // need for a dedicated per-language counter.
        SourceLanguage::JavaScript
        | SourceLanguage::TypeScript
        | SourceLanguage::Php
        | SourceLanguage::CSharp
        | SourceLanguage::Html
        | SourceLanguage::Yaml
        | SourceLanguage::Dockerfile
        | SourceLanguage::MavenPom
        | SourceLanguage::WebConfig
        | SourceLanguage::PackageJson => count_js_loc(source_bytes, &tree),
    };
    // Ticket #281: the taint pass of the file's language reads the tree
    // here, once, and the tree is dropped at the end of this function.
    let taint = if tree_languages.contains(&language) {
        let read_started = crate::scan::debug_log::enabled().then(std::time::Instant::now);
        let taint = taint::TaintFile::extract(language, tree.root_node(), source_bytes);
        if let Some(started) = read_started {
            crate::debug_log!(
                "phase_a",
                "file_taint_read path={rel_path:?} ms={}",
                crate::scan::debug_log::ms_since(started)
            );
        }
        Some(Box::new(taint.unwrap_or_else(|| {
            panic!("{rel_path}: {language:?} has no taint pass to read its tree for")
        })))
    } else {
        None
    };
    drop(tree);
    Ok(FileOutcome::Parsed(
        loc,
        ParsedFile {
            rel_path,
            filepath: filepath.to_path_buf(),
            source: Arc::new(SourceLines::from_text(source_text)),
            taint,
            language,
        },
    ))
}

/// Breakdown of already-parsed files by language — `BTreeMap` for a
/// stable (alphabetical) display order, not the order files were
/// encountered in. Computed once, reused by three consumers that used
/// to each independently derive the same information from
/// `parsed_files` (count displayed in phase A, ticket #46; language
/// list for test-command auto-detection; `ScanReport.languages`).
fn files_per_language(parsed_files: &[ParsedFile]) -> BTreeMap<&'static str, usize> {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for pf in parsed_files {
        *counts.entry(pf.language.rule_tag()).or_insert(0) += 1;
    }
    counts
}

/// Kind of file shown in the phase A split (ticket #139): the extension
/// as written on disk, or the file name for formats recognized by name
/// (`Dockerfile`, `Dockerfile.dev`), whose "extension" would be
/// meaningless (`dev`).
fn file_kind(pf: &ParsedFile) -> String {
    let by_name = || {
        pf.filepath
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    // A configuration file too: `pom.xml` says more than `xml`.
    if pf.language == SourceLanguage::Dockerfile || pf.language.is_config_file() {
        return by_name();
    }
    pf.filepath
        .extension()
        .map(|e| e.to_string_lossy().into_owned())
        .unwrap_or_else(by_name)
}

/// Builds the per-language part of the phase A label from
/// `(language tag, file kind)` pairs, one per parsed file.
///
/// A language group can hold several extensions (`html` covers `jsp`,
/// `vue`, `erb`…, `javascript` covers `ts`/`tsx`…): a user who counted
/// only `.html` files from the shell read `html: 351` as a sign that
/// excluded folders were scanned (ticket #139). So a group with more
/// than one kind shows the split, largest first (ties alphabetical):
/// `html: 351 (html 317, jsp 34)`. A single-kind group keeps the plain
/// `java: 3460` form. Languages stay in alphabetical order, as in
/// [`files_per_language`].
fn phase_a_language_summary(files: impl IntoIterator<Item = (&'static str, String)>) -> String {
    let mut groups: BTreeMap<&'static str, BTreeMap<String, usize>> = BTreeMap::new();
    for (lang, kind) in files {
        *groups.entry(lang).or_default().entry(kind).or_insert(0) += 1;
    }
    groups
        .into_iter()
        .map(|(lang, kinds)| {
            let total: usize = kinds.values().sum();
            if kinds.len() < 2 {
                return format!("{lang}: {total}");
            }
            let mut split: Vec<(String, usize)> = kinds.into_iter().collect();
            // Stable sort on a BTreeMap's alphabetical order: ties stay alphabetical.
            split.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
            let detail = split
                .iter()
                .map(|(kind, n)| format!("{kind} {n}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{lang}: {total} ({detail})")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `true` when the scan discovers the files of the rule language
/// `tag`: always, unless `only_target_language_files` limits discovery to
/// `target_languages`.
fn reads_language_files(config: &ScanConfig, tag: &str) -> bool {
    match (&config.target_languages, config.only_target_language_files) {
        (Some(languages), true) => languages.iter().any(|l| l == tag),
        _ => true,
    }
}

/// `path` as every finding names its file: relative to the scanned `root`,
/// with `/` separators on every system. A path outside `root` is kept as
/// it is. The single place of this rule, used for the analysed files and
/// for the dependency findings (which named the absolute path of the
/// user's machine until 2026-11-14).
fn project_relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Discovers the files a scan of `config` reads, and the folders it skips
/// as holding no project code (ticket #152). The single place of the
/// discovery settings: `run_scan` and the unchanged-project check
/// (`scan::unchanged`, ADR-0050) must see exactly the same files.
pub fn discover_files(config: &ScanConfig) -> (Vec<PathBuf>, Vec<SkippedDir>) {
    let discovery_config = FileDiscoveryConfig {
        // Derived from `SourceLanguage::EXTENSIONS`, the sole authoritative
        // list (fix 2026-11-04): a hand-maintained copy here had drifted
        // from Python's `runner.py` lists (no `.vue`/`.svelte`/`.tsx`/`.inc`…).
        extensions: SourceLanguage::EXTENSIONS
            .iter()
            .filter(|(_, lang)| reads_language_files(config, lang.rule_tag()))
            .map(|(e, _)| format!(".{e}"))
            .collect(),
        // `Dockerfile` has no standard extension — recognized by exact
        // case-insensitive name (ticket #69/spec #68, fixed on
        // 2026-09-01 to cover the same 3 names as Python), not via
        // `extensions` above. See `SourceLanguage::
        // DOCKERFILE_FILENAMES`, the sole authoritative list.
        // The configuration files (ADR-0047) are found the same way,
        // under the rule language that reads them.
        filenames: SourceLanguage::DOCKERFILE_FILENAMES
            .iter()
            .filter(|_| reads_language_files(config, SourceLanguage::Dockerfile.rule_tag()))
            .map(|s| s.to_string())
            .chain(
                SourceLanguage::CONFIG_FILENAMES
                    .iter()
                    .filter(|(_, lang)| reads_language_files(config, lang.rule_tag()))
                    .map(|(name, _)| name.to_string()),
            )
            .collect(),
        exclude_patterns: config.exclude_patterns.clone(),
        prune_excludes: config.exclude_patterns.clone(),
        skip_non_project_dirs: true,
    };
    let include_paths: Vec<&Path> = config.include_paths.iter().map(Path::new).collect();
    find_files_and_skipped(&config.root, &include_paths, &discovery_config)
}

/// Runs a full scan on `config.root`.
///
/// Three phases:
///   A. Reading + parsing of all files (once).
///   B. Regex/file_contains, per file (independent of the others).
///   C. Taint, **multi-file**: builds a `CallGraph` over the whole set
///      of files (mirrors `dataflow_adapter.py` — one graph per batch
///      of files analyzed together, here the whole scan since
///      Decision #10 = Python only, hence a single language), resolves
///      the interprocedural summaries per taint rule, then analyzes
///      each file with `specs.summaries` seeded (the file's own
///      summaries + resolved import summaries, own summaries taking
///      priority over imports — mirrors `merged.update(summaries)` on
///      the `dataflow_taint.py` side).
pub fn run_scan(config: &ScanConfig) -> ScanReport {
    // Total number of phases planned for THIS scan — mirrors
    // `runner.py::_compute_phase_total` (already referenced above by
    // `ScanConfig::quick_mode`: "Python only affects these 3 phases").
    // The 3 core phases always run (rules, phase A, phase B), the
    // phase C taint passes (Python/Java/JS-TS/PHP/C#) of the languages
    // present (ticket #134), plus the optional phases actually enabled
    // (dependencies/tests/database), disabled by `--quick` as on the
    // Python side. Computed once, before any phase, so that the live
    // `[n/N]` counter (ticket #45) is correct from the very first
    // message rather than a frozen constant that would go wrong as
    // soon as a phase is added (went from 7 to 8 in ticket #79 when
    // wiring up the C# taint engine).
    // File discovery runs first, outside any timed phase (it used to sit
    // between the rules phase and phase A): the languages it finds
    // decide which phase C passes run, hence the `[n/N]` total printed
    // from the very first phase on (ticket #134).
    // Ticket #282: the settings of the scan, then each step, in the debug
    // log when it is on (`scan::debug_log`).
    crate::debug_log!(
        "scan",
        "scan_config root={:?} include={:?} exclude={:?} target_languages={:?} rules={:?} \
         custom_rules={:?} cache={:?} datas={:?} quick={} only_category={:?} \
         category_overrides={:?} disabled_rules={:?} severity={:?} with_deps={} with_tests={} \
         database={} memory_check={} memory_limit={:?} lang={:?} suppress_file={:?}",
        config.root,
        config.include_paths,
        config.exclude_patterns,
        config.target_languages,
        config.rules_path,
        config.custom_rules_dir,
        config.cache_dir,
        config.datas_dir,
        config.quick_mode,
        config.only_category,
        config.category_overrides,
        config.disabled_rules,
        config.severity_levels,
        config.with_deps,
        config.with_tests,
        config.database.is_some(),
        config.memory_check,
        config.memory_limit,
        config.lang,
        config.suppress_file
    );
    let discovery_step = crate::scan::debug_log::span("discovery", || {
        format!("discover_files root={:?}", config.root)
    });
    let (files, skipped_dirs) = discover_files(config);
    discovery_step
        .end_with(|| format!("files={} skipped_dirs={}", files.len(), skipped_dirs.len()));

    // ADR-0038: the rule languages of the scan — the project's declared
    // list, else the languages of the discovered files. The rules of any
    // other language are never read.
    let discovered_languages: BTreeSet<String> = files
        .iter()
        .filter_map(|f| SourceLanguage::from_path(f))
        .map(|lang| lang.rule_tag().to_string())
        .collect();
    let rule_languages: Vec<String> = match &config.target_languages {
        Some(declared) => declared
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        None => discovered_languages.iter().cloned().collect(),
    };
    let undeclared_languages: Vec<String> = match &config.target_languages {
        Some(_) => discovered_languages
            .iter()
            .filter(|lang| !rule_languages.contains(lang))
            .cloned()
            .collect(),
        None => Vec::new(),
    };

    // Phase C passes whose language has at least one discovered file
    // (ticket #134): a pass over zero files only cost time (31 ms for
    // Java on a Python-only project) and a meaningless console line.
    // Decided on the discovered files, not the parsed ones, so the total
    // is known before phase A; a language whose every file fails to
    // parse still runs its (empty) pass, which stays correct.
    let has_language = |accepted: &[SourceLanguage]| {
        files
            .iter()
            .any(|f| SourceLanguage::from_path(f).is_some_and(|lang| accepted.contains(&lang)))
    };
    // ADR-0038: a language whose rules are not read (undeclared in
    // `audit.config.json`) has no taint rule either, so its pass is skipped.
    let has_language = |accepted: &[SourceLanguage]| {
        has_language(accepted)
            && accepted
                .iter()
                .any(|lang| rule_languages.iter().any(|l| l == lang.rule_tag()))
    };
    // Each pass declares its file languages once (`TaintLanguage::
    // FILE_LANGUAGES`): the pass reads the same list to pick its files.
    let taint_python_active = has_language(taint::PythonTaint::FILE_LANGUAGES);
    let taint_java_active = has_language(taint::JavaTaint::FILE_LANGUAGES);
    let taint_js_active = has_language(taint::JsTaint::FILE_LANGUAGES);
    let taint_php_active = has_language(taint::PhpTaint::FILE_LANGUAGES);
    let taint_csharp_active = has_language(taint::CSharpTaint::FILE_LANGUAGES);
    crate::debug_log!(
        "scan",
        "languages discovered={discovered_languages:?} rule_languages={rule_languages:?} \
         undeclared={undeclared_languages:?} taint_passes python={taint_python_active} \
         java={taint_java_active} javascript={taint_js_active} php={taint_php_active} \
         csharp={taint_csharp_active}"
    );

    // Rules, phase A, phase B — always run.
    const CORE_PHASES: usize = 3;
    // A single source of truth per optional phase, reused both here
    // (computing `total_phases`) and by the `if` guard of its own
    // block further down — prevents the two from drifting apart if one
    // is changed without the other.
    // ADR-0043: a pack carrying version rules checks the dependencies of
    // every scan whose project declares some; its header says so without
    // decrypting anything. A project without any manifest has nothing to
    // check, so it gets no phase and no line about version rules (it got
    // both on 2026-11-15, for every scan of a code-only project).
    // `with_deps` runs the phase anyway. The dependencies read here are
    // the ones the phase checks: they are read once.
    let pack_has_version_rules = config.rules_path.is_file()
        && crate::rules::pack_format::read_header_from_file(&config.rules_path)
            .is_ok_and(|header| header.has_version_rules());
    let mut declared_dependencies = ((config.with_deps || pack_has_version_rules)
        && !config.quick_mode)
        // Every manifest under the scanned folders, with the scan's
        // exclusions — see `dependencies::find_dependency_files` (#287).
        .then(|| {
            crate::project::dependencies::collect_dependencies(
                &config.root,
                &config.include_paths,
                &config.exclude_patterns,
            )
        });
    let deps_phase_active = !config.quick_mode
        && (config.with_deps
            || (pack_has_version_rules
                && declared_dependencies
                    .as_ref()
                    .is_some_and(|d| !d.is_empty())));
    let tests_phase_active = config.with_tests && !config.quick_mode;
    let database_phase_active = config.database.is_some() && !config.quick_mode;
    let total_phases = CORE_PHASES
        + [
            taint_python_active,
            taint_java_active,
            taint_js_active,
            taint_php_active,
            taint_csharp_active,
            deps_phase_active,
            tests_phase_active,
            database_phase_active,
        ]
        .into_iter()
        .filter(|&active| active)
        .count();

    let mut phase_timings: Vec<(String, std::time::Duration)> = Vec::new();
    // `label: &str` (not `&'static str`) since ticket #46: the phase A
    // label is formatted dynamically (per-language count), hence
    // borrowed from a temporary `String` rather than a `'static`
    // literal. The 9 other calls always pass a literal, which coerces
    // fine to `&str`.
    let mut record_phase = |label: &str, elapsed: std::time::Duration| {
        phase_timings.push((label.to_string(), elapsed));
        crate::debug_log!(
            "phase",
            "phase_end n={}/{total_phases} label={label:?} ms={:.3}",
            phase_timings.len(),
            elapsed.as_secs_f64() * 1000.0
        );
        if let Some(cb) = config.on_phase_complete {
            // The label stored in `phase_timings` stays the full label
            // (including the per-language count for phase A) — only
            // the `[n/N]` prefix is added specifically for the LIVE
            // progress callback, not persisted in `phase_timings`.
            let n = phase_timings.len();
            cb(&format!("[{n}/{total_phases}] {label}"), elapsed);
        }
    };
    let t_rules = std::time::Instant::now();
    // ADR-0040: one catalog (the pack, or the `--rules` pack or folder),
    // then the custom rules folder; only the target languages' rule files
    // are kept. A pack that cannot be opened is reported with the invalid
    // rule files.
    // Every rule goes through one registry: each identity (language +
    // name) runs once, a client rule replacing the catalog rule of the
    // same identity (`RuleRegistry`).
    let mut rule_sources = Vec::new();
    let mut registry = crate::rules::catalog::RuleRegistry::default();
    let mut rule_errors: Vec<(PathBuf, crate::rules::catalog::RuleLoadError)> = Vec::new();
    let mut load_source = |path: &Path, origin: crate::rules::catalog::RuleOrigin| {
        let source_step = crate::scan::debug_log::span("rules", || {
            format!("load_source path={path:?} origin={origin:?}")
        });
        let mut loaded = crate::rules::catalog::load_rules(path, &rule_languages, origin);
        source_step.end_with(|| {
            let summary = loaded.summary();
            format!(
                "kind={:?} files_available={} files_read={} errors={}",
                summary.kind,
                summary.files_available,
                summary.files_read,
                loaded.errors.len()
            )
        });
        for (file, error) in &loaded.errors {
            crate::debug_log!(
                "rules",
                "rule_file_refused path={file:?} error={:?}",
                error.to_string()
            );
        }
        registry.add_source(&loaded, &rule_languages);
        rule_errors.append(&mut loaded.errors);
        rule_sources.push(loaded.summary());
    };
    load_source(
        &config.rules_path,
        crate::rules::catalog::RuleOrigin::Builtin,
    );
    // Custom rules (ticket #84/spec #82): additive, same language filter,
    // labelled as the client's own rules in the report (#143). The CLI
    // leaves `custom_rules_dir` empty with `--rules <PATH>`.
    if let Some(custom_dir) = &config.custom_rules_dir
        && custom_dir.is_dir()
    {
        load_source(custom_dir, crate::rules::catalog::RuleOrigin::Client);
    }
    let (loaded_rule_jsons, rule_conflicts, mut compile_errors) = registry.finish();
    for conflict in &rule_conflicts {
        crate::debug_log!(
            "rules",
            "rule_conflict id={} kind={:?} kept={:?} dropped={:?}",
            conflict.id,
            conflict.kind,
            conflict.kept,
            conflict.dropped
        );
    }
    for (file, error) in &compile_errors {
        crate::debug_log!(
            "rules",
            "rule_refused path={file:?} error={:?}",
            error.to_string()
        );
    }
    rule_errors.append(&mut compile_errors);
    let rules_loaded = loaded_rule_jsons.len();
    record_phase(
        &phase_label(
            config,
            "scan_phase_rules",
            "règles (chargement + compilation DSL)",
        ),
        t_rules.elapsed(),
    );

    // `--only-category`/`categories.*.enabled`/`--disable-rule`
    // filtering — applied once here, upstream of all phases
    // (regex/hybrid + taint, all languages): an excluded rule is
    // simply never run, rather than having its findings filtered out
    // afterwards. Mirrors `runner.py::should_run` (ticket #41/spec
    // #27): `only_category` and `category_overrides` are NEVER
    // combined, see the doc comment of the `category_overrides` field
    // above.
    let rule_jsons: Vec<serde_json::Value> = loaded_rule_jsons
        .into_iter()
        .filter(|r| {
            // The debug log names each rule kept and each rule left out,
            // with the reason (ticket #282).
            let rule_name = || {
                crate::rules::identity::RuleId::of(r)
                    .map_or_else(|| "<no id>".to_string(), |id| id.to_string())
            };
            let cat = r.get("category").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(only_cat) = &config.only_category {
                if !cat.eq_ignore_ascii_case(only_cat) {
                    crate::debug_log!(
                        "rules",
                        "rule_left_out id={} reason=only_category category={cat:?}",
                        rule_name()
                    );
                    return false;
                }
            } else if let Some(&enabled) = config.category_overrides.get(&cat.to_lowercase())
                && !enabled
            {
                crate::debug_log!(
                    "rules",
                    "rule_left_out id={} reason=category_disabled category={cat:?}",
                    rule_name()
                );
                return false;
            }
            // A name disables the rule in every language, `language/name`
            // in that language only (`RuleId::is_selected_by`).
            if let Some(id) = crate::rules::identity::RuleId::of(r)
                && config.disabled_rules.iter().any(|d| id.is_selected_by(d))
            {
                crate::debug_log!("rules", "rule_left_out id={id} reason=disable_rule");
                return false;
            }
            crate::debug_log!(
                "rules",
                "rule_kept id={} category={cat:?} taint={}",
                rule_name(),
                crate::scan::dataflow::rule_loader::has_taint_specs(r)
            );
            true
        })
        .collect();

    // Ticket #241: the languages whose parse trees phase C needs, those
    // of a taint pass that has a taint rule. A tree takes about 17 times
    // the size of its file: phase A reads what the pass needs of the tree
    // of these files right after parsing, then drops it (ticket #281),
    // as the other files drop theirs once their lines of code are
    // counted.
    let taint_passes: [(bool, &[SourceLanguage], SourceLanguage, TaintPass); 5] = [
        (
            taint_python_active,
            taint::PythonTaint::FILE_LANGUAGES,
            taint::PythonTaint::RULE_LANGUAGE,
            |files, rules, context, seen| {
                taint::run_taint_pass::<taint::PythonTaint>(files, rules, context, seen)
            },
        ),
        (
            taint_java_active,
            taint::JavaTaint::FILE_LANGUAGES,
            taint::JavaTaint::RULE_LANGUAGE,
            |files, rules, context, seen| {
                taint::run_taint_pass::<taint::JavaTaint>(files, rules, context, seen)
            },
        ),
        (
            taint_js_active,
            taint::JsTaint::FILE_LANGUAGES,
            taint::JsTaint::RULE_LANGUAGE,
            |files, rules, context, seen| {
                taint::run_taint_pass::<taint::JsTaint>(files, rules, context, seen)
            },
        ),
        (
            taint_php_active,
            taint::PhpTaint::FILE_LANGUAGES,
            taint::PhpTaint::RULE_LANGUAGE,
            |files, rules, context, seen| {
                taint::run_taint_pass::<taint::PhpTaint>(files, rules, context, seen)
            },
        ),
        (
            taint_csharp_active,
            taint::CSharpTaint::FILE_LANGUAGES,
            taint::CSharpTaint::RULE_LANGUAGE,
            |files, rules, context, seen| {
                taint::run_taint_pass::<taint::CSharpTaint>(files, rules, context, seen)
            },
        ),
    ];
    let tree_languages: Vec<SourceLanguage> = taint_passes
        .iter()
        .filter(|(active, _, rule_language, _)| {
            *active && taint::language_has_taint_rule(*rule_language, &rule_jsons)
        })
        .flat_map(|(_, file_languages, _, _)| file_languages.iter().copied())
        .collect();

    // Ticket #281: the memory the scan will take, from the size of its
    // files, before any of them is read. A scan expected to exceed the
    // available memory stops here: past it the system swaps, and a
    // Linux laptop froze on a 2.3 GB Java project (16 GB, 12 available).
    let memory = estimate_scan_memory(&files, &tree_languages, config.memory_limit);
    crate::debug_log!(
        "memory",
        "estimate bytes={} fits={:?} rules_at_once={}/{} tree_languages={tree_languages:?} \
         detail={memory:?}",
        memory.bytes,
        memory.fits(),
        memory.rules_at_once,
        memory.max_rules_at_once
    );
    if config.memory_check && memory.fits() == Some(false) {
        return ScanReport {
            memory: Some(memory),
            stopped_for_memory: true,
            skipped_dirs,
            rule_languages,
            ..ScanReport::default()
        };
    }

    let suppressions = config
        .suppress_file
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| Suppressions::load_from_json(&s))
        .unwrap_or_default();

    // Phase A — reading + parsing all files. Parallelized per file
    // (disk reads + tree-sitter parsing are independent; each task
    // creates its own `TsParser` — not shareable across threads). The
    // order of `files` is preserved (explicit indexing): the rest of
    // the pipeline (Phase B/C) and the reports depend on it to be
    // identical to the sequential version.
    let t_phase_a = std::time::Instant::now();
    let phase_a_step =
        crate::scan::debug_log::span("phase_a", || format!("phase_a files={}", files.len()));
    // ADR-0046: the resources folders of saved web pages, found once
    // for all files (one read of the head of each candidate page).
    let saved_page_folders = crate::scan::saved_page::SavedPageFolders::find(&config.root, &files);
    let parsed_results: Vec<FileOutcome> = files
        .par_iter()
        .map(|filepath| {
            if saved_page_folders.contains(filepath) {
                crate::debug_log!(
                    "phase_a",
                    "file_skipped path={:?} reason=saved_page_resources_folder",
                    project_relative_path(&config.root, filepath)
                );
                FileOutcome::SavedPage(project_relative_path(&config.root, filepath))
            } else {
                parse_file(&config.root, filepath, &tree_languages)
            }
        })
        .collect();

    let mut parsed_files: Vec<ParsedFile> = Vec::new();
    // ADR-0045: minified files are skipped, in discovery order.
    let mut skipped_minified: Vec<String> = Vec::new();
    // ADR-0046: so are saved web pages, in discovery order.
    let mut skipped_saved_pages: Vec<String> = Vec::new();
    let mut total_loc = 0usize;
    for outcome in parsed_results {
        match outcome {
            FileOutcome::Parsed(loc, parsed_file) => {
                total_loc += loc;
                parsed_files.push(parsed_file);
            }
            FileOutcome::Minified(rel_path) => skipped_minified.push(rel_path),
            FileOutcome::SavedPage(rel_path) => skipped_saved_pages.push(rel_path),
            FileOutcome::Failed => {}
        }
    }
    phase_a_step.end_with(|| {
        format!(
            "parsed={} minified={} saved_pages={} failed={} loc={total_loc}",
            parsed_files.len(),
            skipped_minified.len(),
            skipped_saved_pages.len(),
            files.len() - parsed_files.len() - skipped_minified.len() - skipped_saved_pages.len()
        )
    });

    // Per-language count (ticket #46), split by extension when a group
    // holds several (ticket #139) — computed here, not in a separate
    // pass: `parsed_files` already knows each file's language
    // (`ParsedFile::language`), phase A has just grouped them.
    let language_summary = phase_a_language_summary(
        parsed_files
            .iter()
            .map(|pf| (pf.language.rule_tag(), file_kind(pf))),
    );
    record_phase(
        &format!(
            "{} — {language_summary}",
            phase_label(config, "scan_phase_a", "phase A (lecture + parsing)")
        ),
        t_phase_a.elapsed(),
    );

    let mut all_findings: Vec<ReportFinding> = Vec::new();
    let mut cache_stats: Vec<crate::scan::scan_cache::CacheStat> = Vec::new();
    // The cache of this scan, prepared once for every pass: this engine's
    // folder, marked as used now, the folders of engines unused for the
    // longest removed. `None` without a cache folder, or when it cannot be
    // created: the scan then runs in full.
    let scan_cache = config.cache_dir.as_deref().and_then(|base| {
        // `config.root`: the symlink guard of `prepare` (a scanned
        // project is untrusted and may plant a link under its cache path).
        crate::scan::scan_cache::CacheContext::prepare(base, &config.lang, &config.root)
    });
    let mut rule_findings: Vec<ReportFinding> = Vec::new();
    let mut passes = PassContext {
        config,
        suppressions: &suppressions,
        cache: scan_cache.as_ref(),
        findings: &mut all_findings,
        cache_stats: &mut cache_stats,
        rule_findings: config.keep_rule_findings.then_some(&mut rule_findings),
        rules_at_once: memory.rules_at_once,
    };

    // Phase B — the pattern rules, one file at a time (`patterns`).
    let (label, elapsed) = patterns::run_pattern_pass(&parsed_files, &rule_jsons, &mut passes);
    record_phase(&label, elapsed);

    // Phase C — the taint passes, one per language, in this order (the
    // order of the findings in the report). What each language does is in
    // its own file of `taint/`; selecting the files and rules, the cache
    // and the merge into the report are shared (`taint::run_taint_pass`).
    // The passes are listed above (`taint_passes`). A pass reads the trees
    // of its files once, before building its call graph, and drops them
    // then (ticket #281): its call graph and the analysis of each rule
    // read no tree.
    let mut seen_taint = taint::SeenTaint::new();
    for (active, _, rule_language, pass) in taint_passes {
        if active {
            let pass_step = crate::scan::debug_log::span("phase_c", || {
                format!("taint_pass language={}", rule_language.rule_tag())
            });
            let (label, elapsed) =
                pass(&mut parsed_files, &rule_jsons, &mut passes, &mut seen_taint);
            drop(pass_step);
            record_phase(&label, elapsed);
        }
    }

    let _ = rule_category; // kept for future use (CLI category filtering)

    // Epic #278: on a line a delivered rule and a client rule both flag,
    // the delivered finding is kept and the pair is named.
    let custom_rule_duplicates = drop_custom_duplicates(&mut all_findings);

    let rule_catalog: crate::rules::identity::RuleCatalog = rule_jsons
        .iter()
        .filter_map(|r| Some((crate::rules::identity::RuleId::of(r)?, r.clone())))
        .collect();

    // --- Dependencies (opt-in, static detection only) --------------
    // `!config.quick_mode`: `--quick` forces the 3 slow optional
    // phases below to be disabled, even if otherwise requested
    // (mirrors `runner.py::_compute_phase_total`/`run`).
    let mut dependency_stats = None;
    let mut version_rules = None;
    let mut lockfiles_not_used = Vec::new();
    if deps_phase_active {
        let _deps_step =
            crate::scan::debug_log::span("dependencies", || "dependencies_phase".to_string());
        let t_deps = std::time::Instant::now();
        let all_deps = declared_dependencies.take().unwrap_or_default();
        lockfiles_not_used = lockfiles_not_used_by(&all_deps, &config.root);
        let unpinned: Vec<_> = all_deps.iter().filter(|d| d.version.is_none()).collect();
        // Ticket #189: the texts follow `--lang`; the unpinned finding had
        // no message and no solution at all before (2026-11-16).
        let texts = DependencyTexts::new(&config.lang);
        let unpinned_findings: Vec<ReportFinding> = unpinned
            .iter()
            .map(|dep| {
                let file = project_relative_path(&config.root, &dep.file);
                ReportFinding {
                    rule_key: "unpinned_dependency".to_string(),
                    rule_language: String::new(), // no catalog rule: a manifest check.
                    rule_name: texts.get("unpinned_name"),
                    category: "DEPENDENCIES".to_string(),
                    severity: "HIGH".to_string(),
                    // Ticket #212: a version given by a property the
                    // manifest does not define names that property.
                    risk: match &dep.version_source {
                        crate::project::dependencies::VersionSource::UnresolvedProperty {
                            property,
                        } => texts
                            .get("unpinned_property_risk")
                            .replace("{name}", &dep.name)
                            .replace("{file}", &file)
                            .replace("{property}", property),
                        _ => texts.get("unpinned_risk").replace("{name}", &dep.name),
                    },
                    solution: Some(match &dep.version_source {
                        crate::project::dependencies::VersionSource::UnresolvedProperty {
                            property,
                        } => texts
                            .get("unpinned_property_solution")
                            .replace("{name}", &dep.name)
                            .replace("{file}", &file)
                            .replace("{property}", property),
                        _ => texts
                            .get("unpinned_solution")
                            .replace("{name}", &dep.name)
                            .replace("{file}", &file),
                    }),
                    file,
                    line: dep.line,
                    cwe: vec![],
                    owasp: None,
                    taint_flow: None,
                    taint_flows: vec![],
                    // Ticket #194: a manifest line can be long too.
                    code: crate::report::text::clip_line(&dep.raw_line, 0),
                    context_before: String::new(),
                    context_after: String::new(),
                    confidence: 90,
                    benefit: String::new(),
                    committer: None,
                    rule_source: "json_builtin".to_string(),
                    file_scope: None,
                }
            })
            .collect();
        let (vulnerable, status) = match read_version_rules(&config.rules_path) {
            Ok(Some(file)) => {
                let status = VersionRulesStatus::Read {
                    pack: config.rules_path.clone(),
                    sources: file.header.sources.clone(),
                    created: file.header.created.clone(),
                    counts: file
                        .header
                        .ecosystems
                        .iter()
                        .map(|e| (e.name.clone(), e.advisories))
                        .collect(),
                };
                (
                    vulnerable_dependency_findings(
                        &file,
                        &all_deps,
                        &config.root,
                        &texts,
                        config.script_locale.as_ref(),
                    ),
                    status,
                )
            }
            Ok(None) => (Vec::new(), VersionRulesStatus::Missing),
            Err(error) => (Vec::new(), VersionRulesStatus::Unreadable { error }),
        };
        version_rules = Some(status);
        let vulnerable_count = vulnerable.len();
        // The report's 🚫 suppressions apply to dependency findings as to
        // every other finding (they never did before 2026-11-14). The
        // counts below stay those of what was detected.
        let not_suppressed =
            |f: &ReportFinding| !suppressions.is_suppressed(&f.rule_key, &f.file, &f.code);
        all_findings.extend(unpinned_findings.into_iter().filter(not_suppressed));
        all_findings.extend(vulnerable.into_iter().filter(not_suppressed));
        dependency_stats = Some(DependencyStats {
            total_scanned: all_deps.len(),
            unpinned: unpinned.len(),
            ok: all_deps.len().saturating_sub(unpinned.len()),
            vulnerable: vulnerable_count,
        });
        record_phase(
            &phase_label(
                config,
                "scan_phase_dependencies",
                "dépendances (détection statique)",
            ),
            t_deps.elapsed(),
        );
    }

    // --- Audited project's unit tests (opt-in) -------------------------
    let mut test_results = None;
    if tests_phase_active {
        let _tests_step = crate::scan::debug_log::span("tests", || "tests_phase".to_string());
        let t_tests = std::time::Instant::now();
        // `BTreeMap::keys()` is already sorted and duplicate-free — no
        // need for separate `sort()`/`dedup()` as before
        // `files_per_language` was introduced (ticket #46).
        let languages: Vec<String> = files_per_language(&parsed_files)
            .keys()
            .map(|lang| lang.to_string())
            .collect();
        let command = config.test_command.clone().or_else(|| {
            crate::project::testing::auto_detect_test_command(&config.root, &languages)
        });
        if let Some(command) = command {
            test_results = crate::project::testing::run_tests(
                &config.root,
                &command,
                std::time::Duration::from_secs(300),
            )
            .ok();
        }
        record_phase(
            &phase_label(
                config,
                "scan_phase_tests",
                "tests unitaires du projet audité",
            ),
            t_tests.elapsed(),
        );
    }

    // --- Database (opt-in, live connection) ---------------------------
    let mut database_schema = None;
    let mut database_stats = None;
    if database_phase_active && let Some(db_config) = &config.database {
        let _database_step =
            crate::scan::debug_log::span("database", || "database_phase".to_string());
        let t_database = std::time::Instant::now();
        match crate::project::database::live::load_db_credentials(db_config, &config.root)
            .and_then(|creds| crate::project::database::live::extract_pg_schema(&creds))
        {
            Ok(schema) => {
                if let Some(baseline_path) = find_baseline(config)
                    && let Ok(baseline) = crate::report::export_json::load_export(&baseline_path)
                    && let Some(baseline_schema) = baseline.database_schema
                {
                    let changes = crate::project::database::schema::compare_schemas(
                        &baseline_schema,
                        &schema,
                        &crate::project::database::schema::SeverityConfig::default(),
                        &crate::project::database::schema::TrackConfig::default(),
                    );
                    database_stats = Some(
                        crate::project::database::schema::calculate_schema_stats(&schema, &changes),
                    );
                } else {
                    database_stats = Some(
                        crate::project::database::schema::calculate_schema_stats(&schema, &[]),
                    );
                }
                database_schema = Some(schema);
            }
            Err(error) => {
                // Connection failure: no dedicated finding for now, see
                // TODO below; named in the debug log (ticket #282).
                crate::debug_log!("database", "database_error error={error:?}");
            }
        }
        record_phase(
            &phase_label(
                config,
                "scan_phase_database",
                "base de données (schéma PostgreSQL)",
            ),
            t_database.elapsed(),
        );
    }

    // --- Injection post-pass (taint dedup + confidence cap) -----------------
    // Same position as the Python call (`runner.py:690`): after every
    // detection phase, before baseline comparison/export.
    adjust_injection_confidence(&mut all_findings);

    // --- `--severity` filter --------------------------------------------------
    // Applied before comparison/export: a finding filtered out here
    // enters neither the exported baseline nor the comparison,
    // consistent with a `--severity` that restricts the scan as a whole.
    if let Some(levels) = &config.severity_levels {
        all_findings.retain(|f| levels.iter().any(|l| l == &f.severity));
    }

    // --- Comparison against baseline + JSON export -----------------------------
    let mut comparison = None;
    let mut export_path = None;
    let mut history = Vec::new();
    if let Some(datas_dir) = &config.datas_dir {
        let _export_step = crate::scan::debug_log::span("report", || {
            format!("comparison_and_export datas={datas_dir:?}")
        });
        if let Some(baseline_path) = find_baseline(config)
            && let Ok(mut baseline) = crate::report::export_json::load_export(&baseline_path)
        {
            // The baseline's findings carry the rule names of the scan that
            // wrote them: the key itself before ticket #227, or another
            // language. The resolved findings listed in this report take
            // the name of the current catalog, in the report's language.
            for f in &mut baseline.findings {
                if let Some(rule) = rule_catalog.get(&f.rule_id()) {
                    f.rule_name = crate::report::text::rule_display_name(rule, &config.lang);
                }
            }
            comparison = Some(crate::report::comparison::compare_with_baseline(
                &all_findings,
                &baseline.findings,
                baseline.timestamp,
                baseline.totals,
            ));
        }
        let timestamp = if config.timestamp.is_empty() {
            chrono::Local::now().format("%Y-%m-%d-%H-%M").to_string()
        } else {
            config.timestamp.clone()
        };
        let export_data = crate::report::export_json::build_export_data(
            &all_findings,
            &timestamp,
            &chrono::Local::now().to_rfc3339(),
            database_schema.clone(),
        );
        let written =
            crate::report::export_json::write_export(datas_dir, &config.brand_prefix, &export_data);
        crate::debug_log!(
            "report",
            "json_export findings={} result={written:?}",
            all_findings.len()
        );
        export_path = written.ok();
        // Read after the export is written, as Python does
        // (`runner.py`: `_export_json` then `_generate_report`): the
        // chart's last point is this scan. Only `datas_dir`, not the
        // legacy directory used for the comparison (ticket #133): the
        // chart starts again with the scans made since the move.
        history = crate::report::export_json::load_history(
            datas_dir,
            &config.brand_prefix,
            crate::report::export_json::MAX_HISTORY,
        );
    }

    let languages: Vec<String> = files_per_language(&parsed_files)
        .keys()
        .map(|lang| lang.to_string())
        .collect();
    let governance_names = patterns::governance_names(&rule_jsons);

    ScanReport {
        memory: Some(memory),
        stopped_for_memory: false,
        governance_names,
        findings: all_findings,
        custom_rule_duplicates,
        files_scanned: parsed_files.len(),
        total_loc,
        rule_errors,
        rule_conflicts,
        rule_languages,
        undeclared_languages,
        rule_sources,
        rules_loaded,
        skipped_dirs,
        skipped_minified,
        skipped_saved_pages,
        lockfiles_not_used,
        rule_catalog,
        test_results,
        dependency_stats,
        version_rules,
        database_schema,
        database_stats,
        comparison,
        export_path,
        history,
        languages,
        phase_timings,
        cache_stats,
        rule_findings,
    }
}

/// The memory a scan of `files` is expected to take (ticket #281): the
/// size of the files of each rule language, those of `tree_languages`
/// (whose data flow is followed) apart, and the machine's memory. A file
/// whose size cannot be read counts for nothing; the scan reads it later
/// and says so if it cannot.
fn estimate_scan_memory(
    files: &[PathBuf],
    tree_languages: &[SourceLanguage],
    limit: Option<u64>,
) -> crate::scan::memory::MemoryEstimate {
    use crate::scan::memory::{LanguageSources, system_memory};
    let mut by_language: BTreeMap<(String, bool), u64> = BTreeMap::new();
    for file in files {
        let Some(language) = SourceLanguage::from_path(file) else {
            continue;
        };
        let bytes = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
        let followed = tree_languages.contains(&language);
        *by_language
            .entry((language.rule_tag().to_string(), followed))
            .or_default() += bytes;
    }
    let mut sources: Vec<LanguageSources> = by_language
        .into_iter()
        .map(|((language, followed), bytes)| LanguageSources {
            language,
            bytes,
            followed,
        })
        .collect();
    sources.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.language.cmp(&b.language)));
    crate::scan::memory::plan(sources, taint::rule_lanes(), system_memory(), limit)
}

/// Rule-id prefixes of the data-flow dependent (injection) families —
/// verbatim copy of `Audit/sca/runner.py::_INJECTION_RULE_PREFIXES`.
const INJECTION_RULE_PREFIXES: &[&str] = &[
    "sql_injection",
    "taint_sqli",
    "xss_",
    "taint_xss",
    "ssrf",
    "taint_ssrf",
    "path_traversal",
    "taint_path",
    "ssti",
    "taint_ssti",
    "ldap_injection",
    "taint_ldap",
    "xpath_injection",
    "taint_xpathi",
    "xxe_injection",
    "taint_xxe",
    "command_injection",
    "unvalidated_input",
    "taint_rce",
    "os_system",
    "dangerous_eval",
    "taint_codeinj",
    "prompt_injection",
    "llm_output_to_sink",
    "insecure_deserialization",
    "taint_deserialization",
    "unsafe_deserialization",
];

/// Confidence ceiling for an injection finding without a taint trace.
const UNTRACED_INJECTION_MAX_CONFIDENCE: i64 = 60;

/// Post-processing of injection findings — port of
/// `Audit/sca/runner.py::_adjust_injection_confidence`, missing from the
/// initial Rust port (found by the Python/Rust differential scan of
/// 2026-11-04: Rust reported e.g. `sql_injection_java_broad` on the same
/// line as a taint-confirmed `sql_injection_concat_java`, Python did not).
///
/// An injection only exists if untrusted data reaches the sink, which a
/// regex alone cannot prove. Two steps, both restricted to findings whose
/// `rule_key` starts with one of [`INJECTION_RULE_PREFIXES`]:
/// 1. collect the `(file, line)` locations of injection findings that DO
///    carry a taint trace;
/// 2. drop every untraced injection finding at one of those locations
///    (redundant: taint already proved it), and cap the confidence of the
///    remaining untraced ones at 60 — below the ≥ 80 bar used for HIGH
///    counting, exactly like Python.
///
/// "Has a taint trace" mirrors Python's `getattr(f, "taint_flow", None)`
/// truthiness: `taint_flow` present (Rust also keeps `taint_flows`, the
/// multi-path list, which is never set without `taint_flow`).
pub(crate) fn adjust_injection_confidence(findings: &mut Vec<ReportFinding>) {
    let is_injection = |f: &ReportFinding| {
        !f.rule_key.is_empty()
            && INJECTION_RULE_PREFIXES
                .iter()
                .any(|p| f.rule_key.starts_with(p))
    };
    let taint_locs: std::collections::HashSet<(String, usize)> = findings
        .iter()
        .filter(|f| f.taint_flow.is_some() && is_injection(f))
        .map(|f| (f.file.clone(), f.line))
        .collect();
    findings.retain_mut(|f| {
        if is_injection(f) && f.taint_flow.is_none() {
            if taint_locs.contains(&(f.file.clone(), f.line)) {
                return false;
            }
            if f.confidence > UNTRACED_INJECTION_MAX_CONFIDENCE {
                f.confidence = UNTRACED_INJECTION_MAX_CONFIDENCE;
            }
        }
        true
    });
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Ticket #209: a finding says where the version it checked comes
    /// from when the manifest does not pin it, in every language.
    #[test]
    fn test_checked_version_label_says_where_the_version_comes_from() {
        use crate::project::dependencies::{Dependency, LockStatus, VersionSource};
        let dep = |source: VersionSource| Dependency {
            name: "lodash".into(),
            version: Some("4.17.0".into()),
            ecosystem: "npm".into(),
            file: PathBuf::from("package.json"),
            line: 1,
            raw_line: String::new(),
            version_source: source,
        };
        let fr = DependencyTexts::new("fr");
        let label = |source| checked_version_label(&dep(source), "4.17.0", &fr);
        assert_eq!(label(VersionSource::Manifest), "4.17.0");
        assert_eq!(
            label(VersionSource::Lockfile {
                file: "package-lock.json".into()
            }),
            "4.17.0 (installée selon package-lock.json)"
        );
        assert_eq!(
            label(VersionSource::DeclaredMinimum {
                constraint: "^4.17.0".into(),
                lock: LockStatus::Absent
            }),
            "4.17.0 (minimum de « ^4.17.0 », aucun fichier de verrouillage)"
        );
        let reasons = [
            LockStatus::Absent,
            LockStatus::NotListed {
                file: "package-lock.json".into(),
            },
            LockStatus::NotAVersion {
                file: "package-lock.json".into(),
                value: "file:../x".into(),
            },
            LockStatus::Unreadable {
                file: "composer.lock".into(),
                reason: "EOF".into(),
            },
            LockStatus::Binary {
                file: "bun.lockb".into(),
            },
        ];
        // Ticket #211: a transitive package names what brings it in.
        assert_eq!(
            label(VersionSource::Transitive {
                file: "package-lock.json".into(),
                via: vec!["express".into(), "koa".into()],
                graph: true
            }),
            "4.17.0 (dépendance indirecte installée selon package-lock.json, via express, koa)"
        );
        for lang in ["en", "fr", "de", "es"] {
            let texts = DependencyTexts::new(lang);
            for (via, graph) in [
                (vec!["express".to_string()], true),
                (vec![], true),
                (vec![], false),
            ] {
                let source = VersionSource::Transitive {
                    file: "Pipfile.lock".into(),
                    via,
                    graph,
                };
                let text = checked_version_label(&dep(source), "4.17.0", &texts);
                assert!(
                    text.contains("Pipfile.lock")
                        && !text.contains('{')
                        && !text.contains("dependency_findings"),
                    "{lang}: {text}"
                );
            }
            for key in [
                "vulnerable_solution_transitive_force",
                "vulnerable_solution_transitive_remove",
                "vulnerable_solution_transitive_upgrade",
                "vulnerable_solution_transitive_replace",
                "lock_binary",
            ] {
                assert!(
                    !texts.get(key).contains("dependency_findings"),
                    "{lang}: {key}"
                );
            }
        }
        for lang in ["en", "fr", "de", "es"] {
            let texts = DependencyTexts::new(lang);
            for lock in &reasons {
                let source = VersionSource::DeclaredMinimum {
                    constraint: "^4.17.0".into(),
                    lock: lock.clone(),
                };
                let text = checked_version_label(&dep(source), "4.17.0", &texts);
                assert!(
                    text.contains("^4.17.0")
                        && !text.contains('{')
                        && !text.contains("dependency_findings"),
                    "{lang}: {text}"
                );
            }
        }
    }

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sast_orch_test_{}_{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// Ticket #133: the current history wins, the pre-#133 location is
    /// only a fallback, and no history directory means no baseline.
    #[test]
    fn test_find_baseline_prefers_current_then_legacy() {
        let root = temp_dir();
        let current = root.join("audit-reports/audit-datas");
        let legacy = root.join("docs/audit-reports/audit-datas");
        std::fs::create_dir_all(&current).unwrap();
        let mut config = ScanConfig {
            root: root.clone(),
            datas_dir: Some(current.clone()),
            legacy_datas_dir: Some(legacy.clone()),
            ..ScanConfig::default()
        };

        let none_anywhere = find_baseline(&config);
        write(&legacy, "SCA-DATA-2000-01-01-00-00.json", "{}");
        let from_legacy = find_baseline(&config);
        write(&current, "SCA-DATA-2026-01-01-00-00.json", "{}");
        write(&current, "SCA-DATA-2026-02-01-00-00.json", "{}");
        let from_current = find_baseline(&config);
        config.datas_dir = None;
        let history_disabled = find_baseline(&config);
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(none_anywhere, None);
        assert_eq!(
            from_legacy,
            Some(legacy.join("SCA-DATA-2000-01-01-00-00.json"))
        );
        assert_eq!(
            from_current,
            Some(current.join("SCA-DATA-2026-02-01-00-00.json"))
        );
        assert_eq!(history_disabled, None);
    }

    /// Whether a rule named `name` is in the report's catalog, in any
    /// language.
    fn has_rule(report: &ScanReport, name: &str) -> bool {
        report.rule_catalog.keys().any(|id| id.name == name)
    }

    fn finding(rule_key: &str, category: &str, file: &str, line: usize) -> ReportFinding {
        ReportFinding {
            rule_key: rule_key.to_string(),
            rule_language: "python".to_string(),
            rule_name: rule_key.to_string(),
            category: category.to_string(),
            severity: "HIGH".to_string(),
            risk: String::new(),
            file: file.to_string(),
            line,
            solution: None,
            cwe: vec![],
            owasp: None,
            taint_flow: None,
            taint_flows: vec![],
            code: String::new(),
            context_before: String::new(),
            context_after: String::new(),
            confidence: 90,
            benefit: String::new(),
            committer: None,
            rule_source: "json_builtin".to_string(),
            file_scope: None,
        }
    }

    /// `integrate_taint_finding` with an index of `all` as it is.
    fn integrate(all: &mut Vec<ReportFinding>, finding: ReportFinding) {
        let mut by_line = FindingsByLine::new(all);
        integrate_taint_finding(all, &mut by_line, finding);
    }

    /// One index kept across several integrations (as a taint pass does):
    /// a finding pushed by the first one is merged into by the next one.
    #[test]
    fn test_integrate_taint_finding_index_follows_the_pushed_findings() {
        let mut all = vec![finding("regex_rule", "SECURITY", "a.py", 3)];
        let mut by_line = FindingsByLine::new(&all);
        integrate_taint_finding(
            &mut all,
            &mut by_line,
            finding("taint_rce", "SECURITY", "a.py", 7),
        );
        integrate_taint_finding(
            &mut all,
            &mut by_line,
            finding("taint_xss", "SECURITY", "a.py", 7),
        );
        integrate_taint_finding(
            &mut all,
            &mut by_line,
            finding("taint_sqli", "SECURITY", "a.py", 3),
        );
        assert_eq!(
            all.len(),
            2,
            "both later findings merged into an existing one"
        );
        assert_eq!(all[1].rule_key, "taint_rce");
        assert_eq!(all[0].rule_key, "regex_rule");
    }

    /// Epic #278: a taint finding only merges into a finding of its own
    /// origin, so a delivered finding is never folded into a client one;
    /// [`drop_custom_duplicates`] then keeps the delivered finding of each
    /// line both flag and names the pair, and keeps a client finding no
    /// delivered rule shares.
    #[test]
    fn test_client_duplicates_of_delivered_findings_are_dropped_and_named() {
        let client = |rule: &str, line| ReportFinding {
            rule_source: "json_custom".to_string(),
            ..finding(rule, "SECURITY", "a.py", line)
        };
        // A client pattern finding first (phase B), then a delivered taint
        // finding on its line, a client taint finding on a delivered line,
        // and a client finding alone.
        let mut all = vec![
            client("my_pattern", 5),
            finding("os_system_injection", "SECURITY", "a.py", 9),
        ];
        let mut by_line = FindingsByLine::new(&all);
        integrate_taint_finding(
            &mut all,
            &mut by_line,
            finding("taint_rce", "SECURITY", "a.py", 5),
        );
        integrate_taint_finding(&mut all, &mut by_line, client("my_flow", 9));
        integrate_taint_finding(&mut all, &mut by_line, client("my_flow", 12));
        assert_eq!(all.len(), 5, "no merge across origins");
        let duplicates = drop_custom_duplicates(&mut all);
        let kept: Vec<(&str, usize)> = all.iter().map(|f| (f.rule_key.as_str(), f.line)).collect();
        assert_eq!(
            kept,
            [
                ("os_system_injection", 9),
                ("taint_rce", 5),
                ("my_flow", 12)
            ]
        );
        let named: Vec<(String, String, usize)> = duplicates
            .iter()
            .map(|d| {
                (
                    d.custom_rule.to_string(),
                    d.shipped_rule.to_string(),
                    d.line,
                )
            })
            .collect();
        assert_eq!(
            named,
            [
                ("python/my_pattern".into(), "python/taint_rce".into(), 5),
                (
                    "python/my_flow".into(),
                    "python/os_system_injection".into(),
                    9
                )
            ]
        );
        assert_eq!(custom_duplicate_pairs(&duplicates).len(), 2);
        // Without client findings nothing changes.
        let mut delivered = vec![finding("taint_rce", "SECURITY", "a.py", 5)];
        assert!(drop_custom_duplicates(&mut delivered).is_empty());
        assert_eq!(delivered.len(), 1);
    }

    #[test]
    fn test_integrate_taint_finding_no_existing_finding_pushes_new() {
        let mut all = Vec::new();
        integrate(&mut all, finding("taint_rce", "SECURITY", "a.py", 41));
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].rule_key, "taint_rce");
    }

    #[test]
    fn test_integrate_taint_finding_merges_into_regex_finding_same_line() {
        // Real case: os_system_injection (regex) already present on
        // line 41, a taint_rce flow arrives on the same line — merged,
        // no 2nd finding.
        let mut all = vec![finding("os_system_injection", "SECURITY", "a.py", 41)];
        integrate(&mut all, finding("taint_rce", "SECURITY", "a.py", 41));
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].rule_key, "os_system_injection");
        assert_eq!(all[0].confidence, 95);
    }

    #[test]
    fn test_integrate_taint_finding_merges_into_earlier_taint_finding_same_line() {
        // Real case: taint_ssti already present on line 18
        // (render_template_string), a taint_xss flow arrives on the
        // same line (same sink listed in both rules) — merged.
        let mut all = vec![finding("taint_ssti", "SECURITY", "a.py", 18)];
        integrate(&mut all, finding("taint_xss", "SECURITY", "a.py", 18));
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].rule_key, "taint_ssti");
    }

    #[test]
    fn test_integrate_taint_finding_same_family_rule_key_attaches_to_matching_finding() {
        // ssrf / ssrf_python: common prefix, considered the same family
        // (Pass 1) — even if another finding also exists on the line.
        let mut all = vec![
            finding("other_rule", "SECURITY", "a.py", 10),
            finding("ssrf", "SECURITY", "a.py", 10),
        ];
        integrate(&mut all, finding("ssrf_python", "SECURITY", "a.py", 10));
        assert_eq!(all.len(), 2);
        // Attached to the "ssrf" finding (same family), not to
        // "other_rule" (first found) — Pass 1 must take priority over Pass 2.
        assert_eq!(all[1].confidence, 95);
        assert_eq!(all[0].confidence, 90);
    }

    #[test]
    fn test_integrate_taint_finding_different_category_does_not_merge() {
        let mut all = vec![finding("rule_a", "SECURITY", "a.py", 5)];
        integrate(&mut all, finding("rule_b", "MAINTENANCE", "a.py", 5));
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_integrate_taint_finding_different_line_does_not_merge() {
        let mut all = vec![finding("rule_a", "SECURITY", "a.py", 5)];
        integrate(&mut all, finding("rule_b", "SECURITY", "a.py", 6));
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_integrate_taint_finding_different_file_does_not_merge() {
        let mut all = vec![finding("rule_a", "SECURITY", "a.py", 5)];
        integrate(&mut all, finding("rule_b", "SECURITY", "b.py", 5));
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_end_to_end_regex_rule_finds_eval_usage() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "eval_usage.sca",
            "rule eval_usage\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  eval\\s*\\(\n    scope    line\n  end\nend\n",
        );
        write(&root, "app.py", "x = eval(user_input)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.files_scanned, 1);
        assert!(
            !report.findings.is_empty(),
            "eval( doit être détecté par la règle regex"
        );
        assert_eq!(report.findings[0].file, "app.py");
        std::fs::remove_dir_all(&root).ok();
    }

    /// ADR-0045: a minified file is skipped before parsing and named in
    /// the report; a hand-written file beside it is scanned as usual.
    #[test]
    fn test_end_to_end_minified_file_is_skipped_and_listed() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "eval_usage.sca",
            "rule eval_usage\n  language  javascript\n  category  security\n  severity  HIGH\n  match\n    pattern  eval\\s*\\(\n    scope    line\n  end\nend\n",
        );
        write(&root, "app.js", "const x = eval(userInput);\n");
        write(&root, "bundle.js", &"eval(a);var b=1;".repeat(200));

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.skipped_minified, vec!["bundle.js".to_string()]);
        assert_eq!(report.files_scanned, 1);
        let files: Vec<&str> = report.findings.iter().map(|f| f.file.as_str()).collect();
        assert_eq!(files, vec!["app.js"]);
        std::fs::remove_dir_all(&root).ok();
    }

    /// Ticket #194: a finding on a line of 100,000 characters shows a
    /// bounded snippet that holds the match. Python, never judged minified
    /// on its content (ADR-0045), keeps the file in the scan.
    #[test]
    fn test_end_to_end_long_line_is_clipped_around_the_match() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "eval_usage.sca",
            "rule eval_usage\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  eval\\s*\\(\n    scope    line\n  end\nend\n",
        );
        let long_line = format!(
            "data = '{}'; x = eval(user_input); y = '{}'\n",
            "a".repeat(50_000),
            "b".repeat(50_000)
        );
        write(&root, "app.py", &long_line);

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        let finding = report
            .findings
            .iter()
            .find(|f| f.rule_key == "eval_usage")
            .expect("eval( is found");
        assert!(
            finding.code.contains("eval(user_input)"),
            "{}",
            finding.code
        );
        assert!(finding.code.starts_with('…') && finding.code.ends_with('…'));
        assert!(finding.code.chars().count() <= crate::report::text::MAX_SHOWN_CHARS + 2);
        std::fs::remove_dir_all(&root).ok();
    }

    /// ADR-0046: a page saved from a browser and the files of its
    /// `<name>_files/` folder are skipped and named; the project's own
    /// page and script beside them are scanned as usual.
    #[test]
    fn test_end_to_end_saved_web_page_is_skipped_and_listed() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "eval_usage.sca",
            "rule eval_usage\n  language  javascript\n  category  security\n  severity  HIGH\n  match\n    pattern  eval\\s*\\(\n    scope    line\n  end\nend\n",
        );
        write(&root, "app.js", "const x = eval(userInput);\n");
        write(
            &root,
            "index.html",
            "<html><body>project page</body></html>\n",
        );
        write(
            &root,
            "writeup.html",
            "<!DOCTYPE html>\n<!-- saved from url=(0023)https://example.com/x -->\n<html></html>\n",
        );
        std::fs::create_dir_all(root.join("writeup_files")).unwrap();
        write(
            &root.join("writeup_files"),
            "main.js",
            "eval(location.hash);\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        let mut skipped = report.skipped_saved_pages.clone();
        skipped.sort();
        assert_eq!(
            skipped,
            vec![
                "writeup.html".to_string(),
                "writeup_files/main.js".to_string()
            ]
        );
        assert!(report.skipped_minified.is_empty());
        let files: Vec<&str> = report.findings.iter().map(|f| f.file.as_str()).collect();
        assert_eq!(files, vec!["app.js"]);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_end_to_end_taint_rule_finds_flow() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "cmd_injection.sca",
            "rule cmd_injection\n  language  python\n  category  security\n  severity  HIGH\n  source  input\\s*\\(  kind=cli\n  sink    os\\.system\\s*\\(\nend\n",
        );
        write(&root, "app.py", "x = input()\nos.system(x)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            !report.findings.is_empty(),
            "flux input()->os.system doit être détecté par le taint"
        );
        // Regression found by the maintainer (2026-08-26): the `code` field used
        // to display just the call name ("os.system") instead of the
        // actual file line ("os.system(x)") — mirrors
        // `self._get_line_content(...)` on the Python side.
        assert_eq!(report.findings[0].code, "os.system(x)");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_suppression_file_removes_finding() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "eval_usage.sca",
            "rule eval_usage\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  eval\\s*\\(\n    scope    line\n  end\nend\n",
        );
        write(&root, "app.py", "x = eval(user_input)\n");
        let suppress_path = root.join(".sca-suppress.json");
        std::fs::write(&suppress_path, r#"{"suppressions": [{"rule_key": "eval_usage", "file": "app.py", "code_hash": null}]}"#).unwrap();

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: Some(suppress_path),
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.is_empty(),
            "finding supprimé par .sca-suppress.json"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// Findings as comparable lines: file, line, rule, severity.
    fn finding_keys(report: &ScanReport) -> Vec<String> {
        let mut keys: Vec<String> = report
            .findings
            .iter()
            .map(|f| format!("{}:{}:{}:{}", f.file, f.line, f.rule_key, f.severity))
            .collect();
        keys.sort();
        keys
    }

    #[test]
    fn test_taint_cache_follows_a_change_into_an_unchanged_caller_file() {
        // `router.py` never changes; only `helpers.py` does. A cached scan
        // must report what a full scan reports at every step, including the
        // finding that appears in, then leaves, the unchanged caller file.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "taint_cmd.sca",
            "rule taint_cmd\n  language  python\n  category  security\n  severity  HIGH\n  source  input\\s*\\(  kind=cli\n  sink    os\\.system\\s*\\(\nend\n",
        );
        write(
            &root,
            "router.py",
            "from helpers import run\n\ndef handler():\n    cmd = input()\n    run(cmd)\n",
        );
        let safe = "import os\n\ndef run(cmd):\n    os.system('ls')\n";
        let unsafe_ = "import os\n\ndef run(cmd):\n    os.system(cmd)\n";
        write(&root, "helpers.py", safe);
        let cache_dir = root.join("cache");
        let config = |cache: bool| ScanConfig {
            root: root.clone(),
            rules_path: rules_dir.clone(),
            exclude_patterns: vec!["cache/".to_string()],
            cache_dir: cache.then(|| cache_dir.clone()),
            ..ScanConfig::default()
        };
        let mut seen_router_finding = false;
        for (step, helpers) in [safe, unsafe_, unsafe_, safe].iter().enumerate() {
            write(&root, "helpers.py", helpers);
            let cached = run_scan(&config(true));
            let full = run_scan(&config(false));
            assert_eq!(finding_keys(&cached), finding_keys(&full), "step {step}");
            seen_router_finding |= cached.findings.iter().any(|f| f.file == "router.py");
            let stat = &cached.cache_stats[0];
            if step == 2 {
                assert_eq!((stat.dirty, stat.analysed), (0, 0), "unchanged: all reused");
            }
        }
        assert!(
            seen_router_finding,
            "the caller file got the cross-file finding"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// Scans `files` four times while `callee` goes safe → unsafe →
    /// unsafe → safe, `caller` never changing: the cached scan must match
    /// a full scan at every step, reuse everything on the unchanged step,
    /// and the cross-file finding must show up in `caller`.
    fn assert_cache_follows_cross_file(
        rule: &str,
        caller: (&str, &str),
        callee: (&str, &str, &str),
    ) {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(&rules_dir, "rule.sca", rule);
        write(&root, caller.0, caller.1);
        let cache_dir = root.join("cache");
        let config = |cache: bool| ScanConfig {
            root: root.clone(),
            rules_path: rules_dir.clone(),
            exclude_patterns: vec!["cache/".to_string()],
            cache_dir: cache.then(|| cache_dir.clone()),
            ..ScanConfig::default()
        };
        let (path, safe, unsafe_) = callee;
        let mut seen_caller_finding = false;
        for (step, text) in [safe, unsafe_, unsafe_, safe].iter().enumerate() {
            write(&root, path, text);
            let cached = run_scan(&config(true));
            let full = run_scan(&config(false));
            assert_eq!(
                finding_keys(&cached),
                finding_keys(&full),
                "{path} step {step}"
            );
            seen_caller_finding |= cached.findings.iter().any(|f| f.file == caller.0);
            if step == 2 {
                let stat = cached
                    .cache_stats
                    .iter()
                    .find(|s| s.language != "patterns")
                    .unwrap();
                assert_eq!(
                    (stat.dirty, stat.analysed),
                    (0, 0),
                    "{path}: unchanged, all reused"
                );
            }
        }
        assert!(
            seen_caller_finding,
            "{}: the cross-file finding reached the caller",
            caller.0
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_taint_cache_follows_cross_file_changes_in_js() {
        assert_cache_follows_cross_file(
            "rule taint_q\n  language  javascript\n  category  security\n  severity  HIGH\n  source  readInput\\s*\\(  kind=cli\n  sink    db\\.query\\s*\\(\nend\n",
            (
                "handler.js",
                "const { run } = require('./helpers');\nfunction handler() {\n  const cmd = readInput();\n  run(cmd);\n}\n",
            ),
            (
                "helpers.js",
                "function run(cmd) {\n  db.query('x');\n}\n",
                "function run(cmd) {\n  db.query(cmd);\n}\n",
            ),
        );
    }

    #[test]
    fn test_taint_cache_follows_cross_file_changes_in_php() {
        assert_cache_follows_cross_file(
            "rule taint_q\n  language  php\n  category  security\n  severity  HIGH\n  source  readInput\\s*\\(  kind=cli\n  sink    \\$db->query\\s*\\(\nend\n",
            (
                "handler.php",
                "<?php\nrequire './helpers.php';\nfunction handler() {\n  $cmd = readInput();\n  run($cmd);\n}\n",
            ),
            (
                "helpers.php",
                "<?php\nfunction run($cmd) {\n  $db->query('x');\n}\n",
                "<?php\nfunction run($cmd) {\n  $db->query($cmd);\n}\n",
            ),
        );
    }

    #[test]
    fn test_taint_cache_follows_cross_file_changes_in_java() {
        assert_cache_follows_cross_file(
            "rule taint_q\n  language  java\n  category  security\n  severity  HIGH\n  source  request\\.getParameter\\s*\\(  kind=http\n  sink    stmt\\.executeQuery\\s*\\(\nend\n",
            (
                "Api.java",
                "package app;\nclass Api {\n  void handle(HttpServletRequest request) {\n    String cmd = request.getParameter(\"q\");\n    Helper h = new Helper();\n    h.run(cmd);\n  }\n}\n",
            ),
            (
                "Helper.java",
                "package app;\nclass Helper {\n  void run(String cmd) {\n    stmt.executeQuery(\"x\");\n  }\n}\n",
                "package app;\nclass Helper {\n  void run(String cmd) {\n    stmt.executeQuery(cmd);\n  }\n}\n",
            ),
        );
    }

    /// Ticket #284: the C# call graph links the files, so the cache must
    /// redo the caller when the callee of another file changes.
    #[test]
    fn test_taint_cache_follows_cross_file_changes_in_csharp() {
        assert_cache_follows_cross_file(
            "rule taint_q\n  language  csharp\n  category  security\n  severity  HIGH\n  source  Request\\.Query\\[  kind=http\n  sink    Process\\.Start\\s*\\(\nend\n",
            (
                "Api.cs",
                "using App.Data;\nnamespace App.Web {\n  class Api {\n    private Helper _helper;\n    void M() {\n      var cmd = Request.Query[\"q\"];\n      _helper.Run(cmd);\n    }\n  }\n}\n",
            ),
            (
                "Helper.cs",
                "namespace App.Data;\nclass Helper {\n  public void Run(string cmd) {\n    Process.Start(\"ls\");\n  }\n}\n",
                "namespace App.Data;\nclass Helper {\n  public void Run(string cmd) {\n    Process.Start(cmd);\n  }\n}\n",
            ),
        );
    }

    #[test]
    fn test_taint_cache_csharp_redoes_only_the_changed_file() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "rule.sca",
            "rule taint_q\n  language  csharp\n  category  security\n  severity  HIGH\n  source  Request\\.Query\\[  kind=http\n  sink    Process\\.Start\\s*\\(\nend\n",
        );
        let body = |arg: &str| {
            format!(
                "class C {{\n  void M() {{\n    var cmd = Request.Query[\"q\"];\n    Process.Start({arg});\n  }}\n}}\n"
            )
        };
        write(&root, "A.cs", &body("cmd"));
        write(&root, "B.cs", &body("\"ls\""));
        let cache_dir = root.join("cache");
        let config = |cache: bool| ScanConfig {
            root: root.clone(),
            rules_path: rules_dir.clone(),
            exclude_patterns: vec!["cache/".to_string()],
            cache_dir: cache.then(|| cache_dir.clone()),
            ..ScanConfig::default()
        };
        run_scan(&config(true));
        write(&root, "B.cs", &body("cmd"));
        let cached = run_scan(&config(true));
        let full = run_scan(&config(false));
        assert_eq!(finding_keys(&cached), finding_keys(&full));
        assert_eq!(
            cached
                .findings
                .iter()
                .filter(|f| f.rule_key == "taint_q")
                .count(),
            2
        );
        let stat = cached
            .cache_stats
            .iter()
            .find(|s| s.language == "csharp")
            .unwrap();
        assert_eq!((stat.dirty, stat.analysed), (1, 1), "only B.cs redone");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_dependency_findings_use_relative_paths_and_obey_suppressions() {
        // A dependency finding named the absolute path of the dependency
        // file (the tester's own machine in the report and in SARIF), and
        // the report's 🚫 button never hid it (2026-11-14).
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(&root, "requirements.txt", "django\n");
        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir.clone(),
            with_deps: true,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        let dep = report
            .findings
            .iter()
            .find(|f| f.rule_key == "unpinned_dependency")
            .expect("unpinned dependency reported");
        assert_eq!(dep.file, "requirements.txt");
        let hash = crate::project::suppress::line_hash(&dep.code);
        let suppress_path = root.join(".sca-suppress.json");
        std::fs::write(
            &suppress_path,
            format!(r#"{{"suppressions": [{{"rule_key": "unpinned_dependency", "file": "requirements.txt", "code_hash": {hash}}}]}}"#),
        )
        .unwrap();
        let report = run_scan(&ScanConfig {
            suppress_file: Some(suppress_path),
            ..config
        });
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.rule_key != "unpinned_dependency")
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// Ticket #197: the EPSS percentage is rounded down, so a score below
    /// 1 never reads 100 %.
    #[test]
    fn test_epss_percent_never_exceeds_the_score() {
        assert_eq!(epss_percent(0.99999), "99.9");
        assert_eq!(epss_percent(0.9995), "99.9");
        assert_eq!(epss_percent(0.97366), "97.3");
        assert_eq!(epss_percent(0.973), "97.3");
        assert_eq!(epss_percent(0.021), "2.1");
        assert_eq!(epss_percent(0.0004), "0.0");
        assert_eq!(epss_percent(1.0), "100.0");
    }

    /// ADR-0051: a vulnerability CISA lists as exploited makes the finding
    /// CRITICAL although its advisory says MEDIUM, and the finding names
    /// the KEV mark and the EPSS score in the report language; the scan
    /// names the credited sources of its version rules.
    #[test]
    fn test_exploited_vulnerability_makes_the_finding_critical_and_is_named() {
        use crate::project::advisory_file::{
            Contents, DataSource, EcosystemPayload, TablePayload, encode,
        };
        let root = temp_dir();
        write(&root, "requirements.txt", "lxml==4.6.2\n");
        let pypi = r#"{"format":1,"ecosystem":"PyPI","last_modified":"2026-11-07T00:00:00Z","advisories":[
              {"id":"GHSA-jq4v-f5q6-mjqq","aliases":["CVE-2021-28957"],"summary":"lxml XSS",
               "severity":"MEDIUM","packages":[{"name":"lxml","ranges":[[{"introduced":"0"},{"fixed":"4.6.3"}]]}]}]}"#;
        let tables = [
            TablePayload {
                name: "kev".into(),
                date: "2026-11-18".into(),
                rows: 1,
                json: br#"{"format":1,"cves":{"CVE-2021-28957":{"added":"2026-11-01","ransomware":true}}}"#
                    .to_vec(),
            },
            TablePayload {
                name: "epss".into(),
                date: "2026-11-18".into(),
                rows: 1,
                json: br#"{"format":1,"cves":{"CVE-2021-28957":{"epss":0.97366,"percentile":0.99}}}"#
                    .to_vec(),
            },
        ];
        let sources = [DataSource {
            name: "CISA Known Exploited Vulnerabilities".into(),
            url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog".into(),
            license: "CC0-1.0".into(),
            records: 1,
        }];
        let container = encode(&Contents {
            source: "test",
            sources: &sources,
            ecosystems: &[EcosystemPayload {
                name: "PyPI".into(),
                advisories: 1,
                last_modified: "2026-11-07T00:00:00Z".into(),
                json: pypi.as_bytes().to_vec(),
            }],
            tables: &tables,
        })
        .unwrap();
        let pack = root.join("rules.cfpack");
        std::fs::write(
            &pack,
            crate::rules::pack_format::write_pack("test", &[], Some(&container)),
        )
        .unwrap();
        let report = run_scan(&ScanConfig {
            root: root.clone(),
            rules_path: pack,
            exclude_patterns: vec![],
            lang: "fr".to_string(),
            ..ScanConfig::default()
        });
        let _ = std::fs::remove_dir_all(&root);
        let finding = report
            .findings
            .iter()
            .find(|f| f.rule_key == "vulnerable_dependency")
            .expect("vulnerable dependency reported");
        assert_eq!(finding.severity, "CRITICAL");
        assert!(
            finding.risk.contains(
                "CVE-2021-28957 (MEDIUM, exploitée dans des attaques, y compris par rançongiciel, \
                 CISA KEV depuis le 2026-11-01, EPSS 97,3 %): lxml XSS"
            ),
            "{}",
            finding.risk
        );
        match &report.version_rules {
            Some(VersionRulesStatus::Read { sources: read, .. }) => assert_eq!(read, &sources),
            other => panic!("version rules read: {other:?}"),
        }
    }

    /// Ticket #189: the dependency findings were in English whatever
    /// `--lang`. Their name, message and solution follow the report
    /// language in the four languages; the advisory identifier and the OSV
    /// summary stay as published.
    #[test]
    fn test_dependency_findings_follow_the_report_language() {
        use crate::project::advisory_file::{Contents, EcosystemPayload, encode};
        let root = temp_dir();
        write(&root, "requirements.txt", "lxml==4.6.2\nrequests\n");
        let pypi = r#"{"format":1,"ecosystem":"PyPI","last_modified":"2026-11-07T00:00:00Z","advisories":[
              {"id":"GHSA-jq4v-f5q6-mjqq","aliases":["CVE-2021-28957"],"summary":"lxml vulnerable to Cross-Site Scripting",
               "severity":"MEDIUM","cwe":["CWE-79"],
               "packages":[{"name":"lxml","ranges":[[{"introduced":"0"},{"fixed":"4.6.3"}]]}]}]}"#;
        let container = encode(&Contents {
            source: "test",
            sources: &[],
            ecosystems: &[EcosystemPayload {
                name: "PyPI".into(),
                advisories: 1,
                last_modified: "2026-11-07T00:00:00Z".into(),
                json: pypi.as_bytes().to_vec(),
            }],
            tables: &[],
        })
        .unwrap();
        let pack = root.join("rules.cfpack");
        std::fs::write(
            &pack,
            crate::rules::pack_format::write_pack("test", &[], Some(&container)),
        )
        .unwrap();
        let scan = |lang: &str| {
            let report = run_scan(&ScanConfig {
                root: root.clone(),
                rules_path: pack.clone(),
                exclude_patterns: vec![],
                lang: lang.to_string(),
                ..ScanConfig::default()
            });
            let find = |key: &str| {
                report
                    .findings
                    .iter()
                    .find(|f| f.rule_key == key)
                    .unwrap_or_else(|| panic!("{lang}: {key} reported"))
                    .clone()
            };
            (find("vulnerable_dependency"), find("unpinned_dependency"))
        };

        let (vulnerable, unpinned) = scan("fr");
        assert_eq!(vulnerable.rule_name, "Dépendance vulnérable");
        assert!(
            vulnerable
                .risk
                .starts_with("lxml 4.6.2 est touchée par 1 vulnérabilité publiée : "),
            "{}",
            vulnerable.risk
        );
        // Identifier and OSV summary: as published.
        assert!(
            vulnerable
                .risk
                .contains("CVE-2021-28957 (MEDIUM): lxml vulnerable to Cross-Site Scripting")
        );
        assert_eq!(
            vulnerable.solution.as_deref(),
            Some("Mettez à jour lxml vers la version 4.6.3 ou plus récente.")
        );
        assert_eq!(unpinned.rule_name, "Dépendance sans version fixée");
        assert!(
            unpinned.risk.starts_with("Sans version fixée, requests "),
            "{}",
            unpinned.risk
        );
        assert_eq!(
            unpinned.solution.as_deref(),
            Some("Indiquez la version exacte de requests dans requirements.txt.")
        );

        // Every language has its own texts, none left as a locale key.
        let mut names = std::collections::BTreeSet::new();
        for lang in ["en", "fr", "es", "de"] {
            let (vulnerable, unpinned) = scan(lang);
            for text in [
                &vulnerable.rule_name,
                &vulnerable.risk,
                vulnerable.solution.as_ref().unwrap(),
                &unpinned.rule_name,
                &unpinned.risk,
                unpinned.solution.as_ref().unwrap(),
            ] {
                assert!(
                    !text.contains("dependency_findings.") && !text.contains('{'),
                    "{lang}: {text}"
                );
            }
            names.insert(vulnerable.rule_name);
        }
        assert_eq!(names.len(), 4, "one name per language: {names:?}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_suppression_from_the_report_removes_an_indented_taint_finding() {
        // The report's 🚫 button hashes the trimmed line (`ReportFinding.
        // code`); the taint pass compared the line with its indentation,
        // so a data-flow finding inside a function never went away
        // (2026-11-14, found while writing the shared install guide).
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "taint_cmd.sca",
            "rule taint_cmd\n  language  python\n  category  security\n  severity  HIGH\n  source  input\\s*\\(  kind=cli\n  sink    os\\.system\\s*\\(\nend\n",
        );
        write(
            &root,
            "app.py",
            "import os\n\ndef handler():\n    cmd = input()\n    os.system(cmd)\n",
        );
        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir.clone(),
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let first = run_scan(&config);
        let finding = first
            .findings
            .iter()
            .find(|f| f.rule_key == "taint_cmd")
            .expect("taint finding before suppression");
        let hash = crate::project::suppress::line_hash(&finding.code);
        let suppress_path = root.join(".sca-suppress.json");
        std::fs::write(
            &suppress_path,
            format!(r#"{{"version": "1.0", "suppressions": [{{"rule_key": "taint_cmd", "file": "app.py", "code_hash": {hash}}}]}}"#),
        )
        .unwrap();
        let report = run_scan(&ScanConfig {
            suppress_file: Some(suppress_path),
            ..config
        });
        assert!(
            report.findings.iter().all(|f| f.rule_key != "taint_cmd"),
            "{:?}",
            report.findings
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_exclude_pattern_skips_directory() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "eval_usage.sca",
            "rule eval_usage\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  eval\\s*\\(\n    scope    line\n  end\nend\n",
        );
        write(&root, "vendor/lib.py", "x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec!["vendor/".to_string()],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.files_scanned, 0, "vendor/ exclu de la découverte");
        std::fs::remove_dir_all(&root).ok();
    }

    fn write_two_category_rules(rules_dir: &Path) {
        write(
            rules_dir,
            "eval_usage.sca",
            "rule eval_usage\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  eval\\s*\\(\n    scope    line\n  end\nend\n",
        );
        write(
            rules_dir,
            "long_function.sca",
            "rule long_function\n  language  python\n  category  maintenance\n  severity  LOW\n  match\n    pattern  def\\s+\\w+\n    scope    line\n  end\nend\n",
        );
    }

    #[test]
    fn test_only_category_restricts_to_matching_rules() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "def f():\n    x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            only_category: Some("security".to_string()),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.findings.len(), 1, "seule la règle security matche");
        assert_eq!(report.findings[0].rule_key, "eval_usage");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_only_category_case_insensitive() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "def f():\n    x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            only_category: Some("SECURITY".to_string()),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.findings.len(), 1);
        std::fs::remove_dir_all(&root).ok();
    }

    // === `category_overrides` (ticket #41/spec #27) — mirrors
    // `AuditRunner.enabled_categories`/`should_run`, distinct from
    // `only_category` above, see the field's doc comment in
    // `ScanConfig`. ===

    #[test]
    fn test_category_overrides_disables_matching_category() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "def f():\n    x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            category_overrides: [("security".to_string(), false)].into_iter().collect(),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().all(|f| f.rule_key != "eval_usage"),
            "security désactivée, eval_usage ne doit jamais apparaître"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_key == "long_function"),
            "maintenance non mentionnée dans la carte, reste active par défaut"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_only_category_ignores_category_overrides_entirely() {
        // Exact mirror of `runner.py::should_run`: when `only_category`
        // is set, `category_overrides` is entirely ignored (never
        // combined) — here the map explicitly disables "security", but
        // `only_category = "security"` must still restrict to...
        // security. If the two were combined (logical AND), no rule
        // would match; the test verifies that this is NOT the case.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "def f():\n    x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            only_category: Some("security".to_string()),
            category_overrides: [("security".to_string(), false)].into_iter().collect(),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(
            report.findings.len(),
            1,
            "only_category doit primer, category_overrides totalement ignorée"
        );
        assert_eq!(report.findings[0].rule_key, "eval_usage");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_disabled_rule_skips_matching_id() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "def f():\n    x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            disabled_rules: vec!["eval_usage".to_string()],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().all(|f| f.rule_key != "eval_usage"),
            "eval_usage désactivée, ne doit jamais apparaître"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_key == "long_function"),
            "long_function reste active"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// `rules.disabled`: a name disables the rule in every language,
    /// `language/name` in that language only.
    #[test]
    fn test_disabled_rule_by_name_or_by_identity() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        for language in ["python", "javascript"] {
            write(
                &rules_dir,
                &format!("{language}/security/eval_usage.sca"),
                &format!(
                    "rule eval_usage\n  language  {language}\n  category  security\n  severity  HIGH\n  match\n    pattern  eval\\s*\\(\n    scope    line\n  end\nend\n"
                ),
            );
        }
        write(&root, "app.py", "x = eval(y)\n");
        write(&root, "app.js", "const x = eval(y);\n");
        let files_with_eval = |disabled: &str| {
            let report = run_scan(&ScanConfig {
                root: root.clone(),
                rules_path: rules_dir.clone(),
                exclude_patterns: vec!["rules/".to_string()],
                disabled_rules: vec![disabled.to_string()],
                ..ScanConfig::default()
            });
            let mut files: Vec<String> = report
                .findings
                .iter()
                .filter(|f| f.rule_key == "eval_usage")
                .map(|f| f.file.clone())
                .collect();
            files.sort();
            files
        };
        assert_eq!(files_with_eval("other_rule"), ["app.js", "app.py"]);
        assert_eq!(files_with_eval("javascript/eval_usage"), ["app.py"]);
        assert_eq!(files_with_eval("eval_usage"), Vec::<String>::new());
        std::fs::remove_dir_all(&root).ok();
    }

    // === Additive custom rules (ticket #84/spec #82): loaded on top of
    // the real catalog. Their exclusion with `--rules <DIR>` is decided by
    // the CLI (`main.rs::resolve_custom_rules_dir`). ===

    /// `adjust_injection_confidence`: an untraced injection finding on a
    /// taint-confirmed line is dropped; elsewhere it is capped at 60;
    /// non-injection and traced findings are untouched.
    #[test]
    fn test_adjust_injection_confidence_dedups_and_caps() {
        let mut traced = finding("sql_injection_concat_java", "SECURITY", "A.java", 18);
        traced.confidence = 95;
        traced.taint_flow = Some(crate::report::exports::sarif::TaintFlow {
            rule_key: "sql_injection_concat_java".to_string(),
            source_file: "A.java".to_string(),
            source_line: 14,
            source_expr: "request.getParameter(\"id\")".to_string(),
            chain: vec![],
            sink_file: "A.java".to_string(),
            sink_line: 18,
            sink_expr: "stmt.executeQuery(...)".to_string(),
            source_kind: "http".to_string(),
            steps: vec![],
        });
        let mut dup = finding("sql_injection_java_broad", "SECURITY", "A.java", 18);
        dup.confidence = 70;
        let mut elsewhere = finding("command_injection_java_broad", "SECURITY", "A.java", 30);
        elsewhere.confidence = 85;
        let mut other = finding("hardcoded_secret", "SECURITY", "A.java", 18);
        other.confidence = 90;
        let mut findings = vec![traced, dup, elsewhere, other];

        adjust_injection_confidence(&mut findings);

        let got: Vec<(&str, usize, i64)> = findings
            .iter()
            .map(|f| (f.rule_key.as_str(), f.line, f.confidence))
            .collect();
        assert_eq!(
            got,
            vec![
                ("sql_injection_concat_java", 18, 95),
                ("command_injection_java_broad", 30, 60),
                ("hardcoded_secret", 18, 90),
            ]
        );
    }

    /// Extension parity with `Audit/sca/runner.py` (fix 2026-11-04):
    /// template formats go to the HTML rules, `.tsx` to JS/TS, `.inc` to
    /// PHP — none of them was even discovered before.
    #[test]
    fn test_extensions_mirror_python_runner_lists() {
        for (file, expected) in [
            ("a.vue", SourceLanguage::Html),
            ("a.svelte", SourceLanguage::Html),
            ("a.jsp", SourceLanguage::Html),
            ("a.cshtml", SourceLanguage::Html),
            // Superset of the Audit (ticket #285, ADR-0058).
            ("a.razor", SourceLanguage::Html),
            ("a.twig", SourceLanguage::Html),
            ("a.tsx", SourceLanguage::TypeScript),
            ("a.inc", SourceLanguage::Php),
            ("a.cjs", SourceLanguage::JavaScript),
        ] {
            assert_eq!(
                SourceLanguage::from_path(Path::new(file)),
                Some(expected),
                "{file}"
            );
        }
        assert_eq!(SourceLanguage::from_path(Path::new("a.txt")), None);
    }

    /// ADR-0040: a catalog pack gives the scan its rules for the target
    /// languages only, the custom rules folder adds the client's own, and
    /// the report keeps the counts the CLI prints for each source.
    #[test]
    fn test_catalog_pack_and_custom_folder_for_target_languages() {
        use crate::rules::catalog::RuleSourceKind;
        use crate::rules::pack_format;
        let root = temp_dir();
        let rule = |id: &str, language: &str| {
            format!(
                "rule {id}\n  language  {language}\n  category  security\n  severity  HIGH\n  match\n    pattern  PACKED\n    scope    line\n  end\nend\n"
            )
        };
        let catalog = vec![
            (
                "python/security/packed.sca".to_string(),
                rule("py_packed", "python"),
            ),
            (
                "java/security/packed.sca".to_string(),
                rule("java_packed", "java"),
            ),
        ];
        let pack = root.join(pack_format::PACK_FILE_NAME);
        std::fs::write(&pack, pack_format::write_pack("builtin", &catalog, None)).unwrap();
        let custom = root.join("custom");
        // On a line of its own: on the delivered rule's line, the client
        // finding would be dropped as its duplicate (ADR-0064).
        write(
            &custom,
            "python/mine.sca",
            &rule("mine", "python").replace("PACKED", "MINE"),
        );
        write(&root, "src/app.py", "MARKER = PACKED\nMINE = 1\n");
        let report = run_scan(&ScanConfig {
            root: root.clone(),
            include_paths: vec!["src".to_string()],
            rules_path: pack.clone(),
            custom_rules_dir: Some(custom.clone()),
            ..ScanConfig::default()
        });
        std::fs::remove_dir_all(&root).ok();

        let mut ids: Vec<String> = report
            .rule_catalog
            .keys()
            .map(|id| id.to_string())
            .collect();
        ids.sort();
        assert_eq!(ids, ["python/mine", "python/py_packed"]);
        assert!(report.rule_errors.is_empty(), "{:?}", report.rule_errors);
        let sources = &report.rule_sources;
        assert_eq!(sources.len(), 2);
        assert_eq!(
            (sources[0].kind, sources[0].path.clone()),
            (RuleSourceKind::Pack, pack)
        );
        assert_eq!((sources[0].files_available, sources[0].files_read), (2, 1));
        assert_eq!(
            (sources[1].kind, sources[1].path.clone()),
            (RuleSourceKind::Folder, custom)
        );
        assert_eq!(report.rules_loaded, 2);
        let source_of = |id: &str| {
            report
                .findings
                .iter()
                .find(|f| f.rule_key == id)
                .map(|f| f.rule_source.clone())
        };
        assert_eq!(source_of("py_packed").as_deref(), Some("json_builtin"));
        assert_eq!(source_of("mine").as_deref(), Some("json_custom"));
    }

    /// Writes one Python and one Java rule in their language folders, as
    /// the real catalog does (ADR-0038).
    fn write_language_rules(rules_dir: &Path) {
        write(
            rules_dir,
            "python/security/py_marker.sca",
            "rule py_marker\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  MARKER\n    scope    line\n  end\nend\n",
        );
        write(
            rules_dir,
            "java/security/java_marker.sca",
            "rule java_marker\n  language  java\n  category  security\n  severity  HIGH\n  match\n    pattern  MARKER\n    scope    line\n  end\nend\n",
        );
    }

    /// ADR-0038: without a declared list, the rules read are those of the
    /// languages of the discovered files — a Java rule is never loaded
    /// for a Python-only project.
    #[test]
    fn test_rules_read_for_detected_languages_only() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        write_language_rules(&rules_dir);
        write(&root, "src/app.py", "MARKER = 1\n");
        let config = ScanConfig {
            root: root.clone(),
            include_paths: vec!["src".to_string()],
            rules_path: rules_dir,
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.rule_languages, vec!["python".to_string()]);
        assert!(report.undeclared_languages.is_empty());
        assert!(has_rule(&report, "py_marker"));
        assert!(!has_rule(&report, "java_marker"));
        assert!(report.findings.iter().any(|f| f.rule_key == "py_marker"));
        std::fs::remove_dir_all(&root).ok();
    }

    /// ADR-0038: a declared list wins over the files found. A Java file of
    /// an undeclared language gets no rule and is reported; a rule placed
    /// outside any language folder is still filtered on its `language`.
    #[test]
    fn test_declared_languages_restrict_rules_and_report_undeclared() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        write_language_rules(&rules_dir);
        write(
            &rules_dir,
            "extra/java_flat.sca",
            "rule java_flat\n  language  java\n  category  security\n  severity  HIGH\n  match\n    pattern  MARKER\n    scope    line\n  end\nend\n",
        );
        write(&root, "src/app.py", "MARKER = 1\n");
        write(&root, "src/App.java", "class App { int MARKER = 1; }\n");
        let config = ScanConfig {
            root: root.clone(),
            include_paths: vec!["src".to_string()],
            rules_path: rules_dir,
            target_languages: Some(vec!["python".to_string()]),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.rule_languages, vec!["python".to_string()]);
        assert_eq!(report.undeclared_languages, vec!["java".to_string()]);
        assert!(has_rule(&report, "py_marker"));
        assert!(!has_rule(&report, "java_marker"));
        assert!(!has_rule(&report, "java_flat"));
        assert!(report.findings.iter().all(|f| f.file != "src/App.java"));
        std::fs::remove_dir_all(&root).ok();
    }

    /// ADR-0038: custom rules go through the same language filter and are
    /// labelled as client rules.
    #[test]
    fn test_custom_rules_filtered_on_target_languages() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        write_two_category_rules(&rules_dir);
        let custom_dir = root.join("custom-rules");
        write_language_rules(&custom_dir);
        write(&root, "src/app.py", "MARKER = 1\n");
        let config = ScanConfig {
            root: root.clone(),
            include_paths: vec!["src".to_string()],
            rules_path: rules_dir,
            custom_rules_dir: Some(custom_dir),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(has_rule(&report, "py_marker"));
        assert!(!has_rule(&report, "java_marker"));
        let custom = report
            .findings
            .iter()
            .find(|f| f.rule_key == "py_marker")
            .expect("custom Python rule fires");
        assert_eq!(custom.rule_source, "json_custom");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_severity_levels_filters_findings() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "def f():\n    x = eval(y)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            severity_levels: Some(vec!["HIGH".to_string()]),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(report.findings.iter().all(|f| f.severity == "HIGH"));
        assert!(
            report.findings.iter().any(|f| f.rule_key == "eval_usage"),
            "HIGH conservé"
        );
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.rule_key != "long_function"),
            "LOW filtré"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_quick_mode_forces_with_deps_off() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "requirements.txt", "flask\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            with_deps: true,
            quick_mode: true,
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.rule_key != "unpinned_dependency"),
            "--quick désactive with_deps même s'il est demandé"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// Verifies the `[n/N]` counter introduced in ticket #45 — `N` must
    /// reflect the phases actually planned (7 base phases + enabled
    /// optional phases), not a constant frozen at 7. `on_phase_complete`
    /// is a plain function pointer (not a closure): captures the
    /// labels in a `static Mutex`, cleared between the two scenarios of
    /// this test to avoid any cross-contamination.
    #[test]
    fn test_total_phases_counter_reflects_optional_phases() {
        use std::sync::Mutex;
        static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());
        fn capture(label: &str, _elapsed: std::time::Duration) {
            CAPTURED.lock().unwrap().push(label.to_string());
        }

        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "x = 1\n");

        // Python-only project, no optional phase: N = 4 (rules, phase
        // A, phase B, phase C - Python). Until ticket #134 the five
        // phase C passes always ran, N = 8 whatever the languages.
        CAPTURED.lock().unwrap().clear();
        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir.clone(),
            on_phase_complete: Some(capture),
            ..ScanConfig::default()
        };
        run_scan(&config);
        let labels = CAPTURED.lock().unwrap().clone();
        assert_eq!(labels.len(), 4, "4 phases expected, got {labels:?}");
        assert!(labels[0].starts_with("[1/4] "), "{:?}", labels[0]);
        assert!(
            labels[3].starts_with("[4/4] phase C - Python"),
            "{:?}",
            labels[3]
        );

        // Adding a Java and a TypeScript file adds exactly their two
        // passes (TypeScript shares the JS/TS pass): N = 6, and no PHP
        // or C# pass is displayed.
        write(&root, "App.java", "class App {}\n");
        write(&root, "app.ts", "const x = 1;\n");
        CAPTURED.lock().unwrap().clear();
        run_scan(&config);
        let labels_multi = CAPTURED.lock().unwrap().clone();
        assert_eq!(labels_multi.len(), 6, "{labels_multi:?}");
        assert!(labels_multi.iter().any(|l| l.contains("phase C - Java")));
        assert!(labels_multi.iter().any(|l| l.contains("phase C - JS/TS")));
        assert!(
            !labels_multi
                .iter()
                .any(|l| l.contains("phase C - PHP") || l.contains("phase C - C#")),
            "{labels_multi:?}"
        );
        std::fs::remove_file(root.join("App.java")).unwrap();
        std::fs::remove_file(root.join("app.ts")).unwrap();

        // With `with_deps` enabled: N = 5, the last phase carries the
        // label dedicated to dependencies.
        write(&root, "requirements.txt", "flask\n");
        CAPTURED.lock().unwrap().clear();
        let config_with_deps = ScanConfig {
            with_deps: true,
            ..config
        };
        run_scan(&config_with_deps);
        let labels_with_deps = CAPTURED.lock().unwrap().clone();
        assert_eq!(
            labels_with_deps.len(),
            5,
            "5 phases expected with with_deps, got {labels_with_deps:?}"
        );
        assert!(
            labels_with_deps[4].starts_with("[5/5] dépendances"),
            "{:?}",
            labels_with_deps[4]
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// A rule's `"origin"` decides the finding's `rule_source`; a former
    /// `official` origin is no longer special (ADR-0040).
    #[test]
    fn test_rule_source_of_maps_origins() {
        let of = |origin: Option<&str>| {
            let mut rule = serde_json::json!({"id": "r"});
            if let Some(o) = origin {
                rule["origin"] = o.into();
            }
            rule_source_of(&rule)
        };
        let mapped = [
            of(Some("client")),
            of(Some("official")),
            of(Some("builtin")),
            of(None),
        ];
        assert_eq!(
            mapped,
            [
                "json_custom",
                "json_builtin",
                "json_builtin",
                "json_builtin"
            ]
        );
    }

    /// Ticket #139: a group with several kinds shows the split, largest
    /// first and ties alphabetical; a single-kind group keeps `lang: N`.
    #[test]
    fn test_phase_a_language_summary_splits_multi_extension_groups() {
        let files = vec![
            ("java", "java".to_string()),
            ("java", "java".to_string()),
            ("html", "jsp".to_string()),
            ("html", "html".to_string()),
            ("html", "html".to_string()),
            ("html", "vue".to_string()),
            ("javascript", "ts".to_string()),
        ];
        let summary = phase_a_language_summary(files);
        assert_eq!(
            summary,
            "html: 4 (html 2, jsp 1, vue 1), java: 2, javascript: 1"
        );

        let empty = phase_a_language_summary(Vec::new());
        assert_eq!(empty, "");
    }

    /// Ticket #139: the kind is the extension, or the file name for a
    /// Dockerfile (`Dockerfile.dev` must not show as `dev`); end to end,
    /// `.html` + `.jsp` files show `html: 3 (html 2, jsp 1)`.
    #[test]
    fn test_phase_a_label_splits_html_templates_and_names_dockerfiles() {
        use std::sync::Mutex;
        static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());
        fn capture(label: &str, _elapsed: std::time::Duration) {
            CAPTURED.lock().unwrap().push(label.to_string());
        }

        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "a.html", "<p>a</p>\n");
        write(&root, "b.html", "<p>b</p>\n");
        write(&root, "c.jsp", "<p>c</p>\n");
        write(&root, "Main.java", "class Main {}\n");
        write(&root, "Dockerfile", "FROM alpine\n");
        write(&root, "Dockerfile.dev", "FROM alpine\n");

        CAPTURED.lock().unwrap().clear();
        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            on_phase_complete: Some(capture),
            ..ScanConfig::default()
        };
        run_scan(&config);
        let labels = CAPTURED.lock().unwrap().clone();
        let phase_a_label = labels
            .iter()
            .find(|l| l.contains("phase A"))
            .unwrap_or_else(|| panic!("no phase A label among {labels:?}"))
            .clone();

        let html_split = phase_a_label.contains("html: 3 (html 2, jsp 1)");
        assert!(html_split, "html split expected: {phase_a_label:?}");
        let docker_split = phase_a_label.contains("dockerfile: 2 (Dockerfile 1, Dockerfile.dev 1)");
        assert!(
            docker_split,
            "Dockerfile kinds by name expected: {phase_a_label:?}"
        );
        let java_plain = phase_a_label.contains("java: 1,") || phase_a_label.ends_with("java: 1");
        assert!(
            java_plain,
            "single-kind group keeps the plain form: {phase_a_label:?}"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// ADR-0047: the three configuration files are recognized by exact
    /// name, whatever the case (`Web.config` is the usual spelling), and
    /// only by exact name: any other `.xml`/`.json`/`.config` stays out.
    #[test]
    fn test_config_files_are_recognized_by_exact_name() {
        let lang = |p: &str| SourceLanguage::from_path(Path::new(p));
        assert_eq!(lang("app/pom.xml"), Some(SourceLanguage::MavenPom));
        assert_eq!(lang("Site/Web.config"), Some(SourceLanguage::WebConfig));
        assert_eq!(lang("web/package.json"), Some(SourceLanguage::PackageJson));
        for other in [
            "settings.xml",
            "package-lock.json",
            "Web.Release.config",
            "tsconfig.json",
        ] {
            assert_eq!(lang(other), None, "{other}");
        }
        assert_eq!(SourceLanguage::MavenPom.rule_tag(), "java");
        assert_eq!(SourceLanguage::WebConfig.comment_syntax(), "html");
        assert!(SourceLanguage::PackageJson.is_config_file());
        assert!(!SourceLanguage::JavaScript.is_config_file());
    }

    /// Ticket #285: a Razor view takes the `razor` comment syntax, any
    /// other HTML template the `html` one, other files their own.
    #[test]
    fn test_razor_views_take_the_razor_comment_syntax() {
        let syntax = |lang: SourceLanguage, file: &str| lang.comment_syntax_for(Path::new(file));
        assert_eq!(syntax(SourceLanguage::Html, "Views/Index.cshtml"), "razor");
        assert_eq!(syntax(SourceLanguage::Html, "Shared/Nav.razor"), "razor");
        assert_eq!(syntax(SourceLanguage::Html, "index.html"), "html");
        assert_eq!(syntax(SourceLanguage::Html, "App.vue"), "html");
        assert_eq!(syntax(SourceLanguage::CSharp, "Home.cs"), "csharp");
        assert_eq!(syntax(SourceLanguage::WebConfig, "web.config"), "html");
    }

    /// ADR-0047, end to end: a scan finds a `pom.xml`, counts it under
    /// `java` by its name, and gives it to the rule that names it only.
    #[test]
    fn test_scan_reads_a_pom_with_the_rule_that_names_it() {
        use std::sync::Mutex;
        static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());
        fn capture(label: &str, _elapsed: std::time::Duration) {
            CAPTURED.lock().unwrap().push(label.to_string());
        }
        let root = temp_dir();
        let rules_dir = root.join("rules");
        write(
            &rules_dir,
            "java/security/maven_http.sca",
            "rule maven_http\n  language  java\n  severity  HIGH\n  category  security\n  match\n    pattern  <url>http://\n  end\n  requires\n    path_contains  pom.xml\n  end\nend\n",
        );
        write(
            &rules_dir,
            "java/security/any_http.sca",
            "rule any_http\n  language  java\n  severity  LOW\n  category  security\n  match\n    pattern  http://\n  end\nend\n",
        );
        write(
            &root,
            "pom.xml",
            "<project>\n  <url>http://repo.example.com/</url>\n</project>\n",
        );
        write(&root, "Main.java", "class Main {}\n");
        CAPTURED.lock().unwrap().clear();
        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            on_phase_complete: Some(capture),
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        let found: Vec<String> = report
            .findings
            .iter()
            .map(|f| format!("{}:{}:{}", f.file, f.line, f.rule_key))
            .collect();
        assert_eq!(found, ["pom.xml:2:maven_http"]);
        let labels = CAPTURED.lock().unwrap().clone();
        assert!(
            labels
                .iter()
                .any(|l| l.contains("java: 2 (java 1, pom.xml 1)")),
            "pom.xml counted under java by its name: {labels:?}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// Ticket #46: the phase A label carries the per-language file
    /// count, computed during the phase itself (no separate counting
    /// pass), on the same line as the `[n/N]` counter from ticket #45.
    #[test]
    fn test_phase_a_label_includes_per_language_file_counts() {
        use std::sync::Mutex;
        static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());
        fn capture(label: &str, _elapsed: std::time::Duration) {
            CAPTURED.lock().unwrap().push(label.to_string());
        }

        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "x = 1\n");
        write(&root, "app2.py", "y = 2\n");
        write(&root, "Main.java", "class Main {}\n");

        // N = 5: rules, A, B, phase C Python and Java only (ticket #134).
        CAPTURED.lock().unwrap().clear();
        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            on_phase_complete: Some(capture),
            ..ScanConfig::default()
        };
        run_scan(&config);
        let labels = CAPTURED.lock().unwrap().clone();
        let phase_a_label = labels
            .iter()
            .find(|l| l.contains("phase A"))
            .unwrap_or_else(|| panic!("aucun libellé de phase A trouvé parmi {labels:?}"));

        assert!(
            phase_a_label.starts_with("[2/5] phase A (lecture + parsing)"),
            "le préfixe [n/N] et le libellé existant doivent rester intacts : {phase_a_label:?}"
        );
        assert!(
            phase_a_label.contains("python: 2"),
            "décompte python attendu : {phase_a_label:?}"
        );
        assert!(
            phase_a_label.contains("java: 1"),
            "décompte java attendu : {phase_a_label:?}"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// Ticket #280: version rules that cannot be used give a reason shown
    /// in the console's language: an altered version rules section (the
    /// pack) or a section that is not an advisory database (its
    /// container); a skipped file is named the same way.
    #[test]
    fn test_unreadable_version_rules_reason_follows_the_console_language() {
        use crate::rules::pack_format;
        let french = crate::i18n::load_script_locale("fr");
        let dir = std::env::temp_dir().join(format!("cfa-version-rules-fr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let files = vec![("python/r.sca".to_string(), "rule r\nend\n".to_string())];
        // The version rules section is the last one: its last byte is
        // part of its authentication tag.
        let mut altered = pack_format::write_pack("builtin", &files, Some(b"CFDB-garbage"));
        let last = altered.len() - 1;
        altered[last] ^= 0xFF;
        let altered_path = dir.join("altered.cfpack");
        std::fs::write(&altered_path, altered).unwrap();
        let garbage_path = dir.join("garbage.cfpack");
        std::fs::write(
            &garbage_path,
            pack_format::write_pack("builtin", &files, Some(b"not a database")),
        )
        .unwrap();
        let altered_reason = read_version_rules(&altered_path).unwrap_err();
        let garbage_reason = read_version_rules(&garbage_path).unwrap_err();
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(
            altered_reason.render(&french),
            "pack de règles corrompu ou modifié"
        );
        assert_eq!(
            garbage_reason.render(&french),
            format!(
                "{} : ce fichier n'est pas une base de vulnérabilités (cfdb)",
                garbage_path.display()
            )
        );
        assert_eq!(
            version_rules_skipped_line(&garbage_reason, Some(&french)),
            format!(
                "règles de version ignorées : {} : ce fichier n'est pas une base de vulnérabilités (cfdb)",
                garbage_path.display()
            )
        );
        assert!(
            version_rules_skipped_line(&garbage_reason, None)
                .starts_with("version rules skipped: "),
            "English without a console language"
        );
    }

    /// Ticket #48: `ScanConfig::script_locale` translates the phase
    /// labels (the `[n/N]` prefix and per-language detail from tickets
    /// #45/#46 stay intact); `None` (historical behavior, all other
    /// tests in this module) keeps producing the hard-coded French text.
    #[test]
    fn test_phase_labels_use_script_locale_when_provided() {
        use std::sync::Mutex;
        static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());
        fn capture(label: &str, _elapsed: std::time::Duration) {
            CAPTURED.lock().unwrap().push(label.to_string());
        }

        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write_two_category_rules(&rules_dir);
        write(&root, "app.py", "x = 1\n");

        CAPTURED.lock().unwrap().clear();
        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            on_phase_complete: Some(capture),
            script_locale: Some(crate::i18n::load_script_locale("de")),
            ..ScanConfig::default()
        };
        run_scan(&config);
        let labels = CAPTURED.lock().unwrap().clone();
        let phase_a_label = labels
            .iter()
            .find(|l| l.contains("python: 1"))
            .unwrap_or_else(|| panic!("aucun libellé de phase A trouvé parmi {labels:?}"));

        assert!(
            phase_a_label.starts_with("[2/4] Phase A (Einlesen + Parsen)"),
            "le libellé de phase A doit être traduit en allemand : {phase_a_label:?}"
        );
        assert!(
            !labels.iter().any(|l| l.contains("phase A (lecture")),
            "le texte français codé en dur ne doit plus apparaître avec une script_locale fournie : {labels:?}"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_invalid_sca_file_reported_but_does_not_crash_scan() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "broken.sca",
            "this is not valid DSL syntax {{{\n",
        );
        write(&root, "app.py", "x = 1\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            !report.rule_errors.is_empty(),
            "le fichier .sca cassé doit être signalé"
        );
        assert_eq!(
            report.files_scanned, 1,
            "le scan continue malgré la règle cassée"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_loc_counted_across_files() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(&root, "a.py", "x = 1\ny = 2\n");
        write(&root, "b.py", "z = 3\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.total_loc, 3);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_cross_file_taint_flow_resolved_via_call_graph() {
        // app.py calls helper() (defined in utils.py, imported) with a
        // tainted source; the sink (os.system) is INSIDE utils.py,
        // never visible from app.py without multi-file interprocedural
        // resolution. Without CallGraph wiring, `helper` stays an
        // opaque call -> no finding. With it, the summary of `helper`
        // (computed on utils.py) is seeded into app.py's specs, and the
        // finding appears at the call site (app.py).
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "cmd_injection.sca",
            "rule cmd_injection\n  language  python\n  category  security\n  severity  HIGH\n  source  input\\s*\\(  kind=cli\n  sink    os\\.system\\s*\\(\nend\n",
        );
        write(
            &root,
            "utils.py",
            "import os\n\ndef helper(cmd):\n    os.system(cmd)\n",
        );
        write(
            &root,
            "app.py",
            "from utils import helper\n\ndef main():\n    helper(input())\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().any(|f| f.file == "app.py"),
            "le flux cross-file (app.py appelle helper() de utils.py, qui atteint os.system) doit être résolu au site d'appel dans app.py ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_intra_file_sink_in_utils_also_detected() {
        // The direct INTRA-file flow (inside utils.py itself: if
        // utils.py also called os.system(tainted) locally) must keep
        // working with no regression after the move to multi-file.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "cmd_injection.sca",
            "rule cmd_injection\n  language  python\n  category  security\n  severity  HIGH\n  source  input\\s*\\(  kind=cli\n  sink    os\\.system\\s*\\(\nend\n",
        );
        write(&root, "app.py", "import os\nx = input()\nos.system(x)\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            !report.findings.is_empty(),
            "flux intra-fichier toujours détecté après le câblage multi-fichiers"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_java_regex_rule_finds_runtime_exec() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "runtime_exec.sca",
            "rule runtime_exec\n  language  java\n  category  security\n  severity  HIGH\n  match\n    pattern  Runtime\\.getRuntime\\(\\)\\.exec\n    scope    line\n  end\nend\n",
        );
        write(
            &root,
            "App.java",
            "class App {\n    void run(String cmd) throws Exception {\n        Runtime.getRuntime().exec(cmd);\n    }\n}\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.files_scanned, 1);
        assert!(
            report.findings.iter().any(|f| f.file == "App.java"),
            "Runtime.exec doit être détecté par la règle regex java ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_rule_language_filtering_is_cross_isolated() {
        // A python rule must never trigger on a java file, and vice
        // versa, even if both files coexist in the same scan with a
        // textually identical pattern.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "py_eval.sca",
            "rule py_eval\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  DANGER_MARKER\n    scope    line\n  end\nend\n",
        );
        write(
            &rules_dir,
            "java_danger.sca",
            "rule java_danger\n  language  java\n  category  security\n  severity  HIGH\n  match\n    pattern  DANGER_MARKER\n    scope    line\n  end\nend\n",
        );
        write(&root, "app.py", "x = DANGER_MARKER\n");
        write(
            &root,
            "App.java",
            "class App { String x = \"DANGER_MARKER\"; }\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.files_scanned, 2);
        let py_finding = report
            .findings
            .iter()
            .find(|f| f.file == "app.py")
            .expect("app.py doit être signalé par py_eval");
        assert_eq!(py_finding.rule_key, "py_eval");
        let java_finding = report
            .findings
            .iter()
            .find(|f| f.file == "App.java")
            .expect("App.java doit être signalé par java_danger");
        assert_eq!(java_finding.rule_key, "java_danger");
        assert_eq!(
            report.findings.len(),
            2,
            "chaque fichier ne doit être touché que par la règle de sa propre langue ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, &f.rule_key))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// Ticket #241: a file that is not valid UTF-8 is analysed as the
    /// text the tree was parsed from (its invalid bytes replaced, as the
    /// Audit's `errors="replace"`). The analyses used to read the nodes in
    /// the bytes on disk: each Latin-1 `é` of the comment shifted every
    /// node below it by two bytes, and the flow was lost.
    #[test]
    fn test_java_taint_flow_below_a_latin1_comment_is_found() {
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "java_cmd_injection.sca",
            "rule java_cmd_injection\n  language  java\n  category  security\n  severity  HIGH\n  source  request\\.getParameter\\s*\\(  kind=http\n  sink    Runtime\\.getRuntime\\(\\)\\.exec\nend\n",
        );
        let mut source = b"class App {\n    // caf\xe9 caf\xe9 caf\xe9\n".to_vec();
        source.extend_from_slice(
            b"    void run(HttpServletRequest request) throws Exception {\n        String cmd = request.getParameter(\"cmd\");\n        Runtime.getRuntime().exec(cmd);\n    }\n}\n",
        );
        assert!(std::str::from_utf8(&source).is_err());
        std::fs::write(root.join("App.java"), source).unwrap();

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(report.rule_errors.is_empty());
        let lines: Vec<(usize, &str)> = report
            .findings
            .iter()
            .map(|f| (f.line, f.code.as_str()))
            .collect();
        assert_eq!(lines, vec![(5, "Runtime.getRuntime().exec(cmd);")]);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_java_taint_rule_detects_real_flow_end_to_end() {
        // Java taint is wired up (JavaCallGraph + java_taint_scan,
        // 2026-08-25) — a real java taint rule must now detect an
        // actual java source->sink flow, as on the Python side.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "java_cmd_injection.sca",
            "rule java_cmd_injection\n  language  java\n  category  security\n  severity  HIGH\n  source  request\\.getParameter\\s*\\(  kind=http\n  sink    Runtime\\.getRuntime\\(\\)\\.exec\nend\n",
        );
        write(
            &root,
            "App.java",
            "class App {\n    void run(HttpServletRequest request) throws Exception {\n        String cmd = request.getParameter(\"cmd\");\n        Runtime.getRuntime().exec(cmd);\n    }\n}\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.rule_errors.is_empty(),
            "la règle doit se charger sans erreur"
        );
        assert!(
            !report.findings.is_empty(),
            "le flux request.getParameter->Runtime.exec doit être détecté ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// Ticket #241: each language keeps its parse trees only when its
    /// pass has a taint rule, and releases them when the pass ends. A
    /// language read only by a pattern rule runs its pass without
    /// building it, and the pass with a taint rule, before or after it,
    /// still finds its flow.
    #[test]
    fn test_taint_pass_runs_beside_a_language_without_taint_rule() {
        let java_taint = "rule java_cmd_injection\n  language  java\n  category  security\n  severity  HIGH\n  source  request\\.getParameter\\s*\\(  kind=http\n  sink    Runtime\\.getRuntime\\(\\)\\.exec\nend\n";
        let python_taint = "rule cmd_injection\n  language  python\n  category  security\n  severity  HIGH\n  source  input\\s*\\(  kind=cli\n  sink    os\\.system\\s*\\(\nend\n";
        let java_pattern = "rule java_exec_call\n  language  java\n  category  security\n  severity  LOW\n  match\n    pattern  \\.exec\\(\n    scope    line\n  end\nend\n";
        let python_pattern = "rule py_system_call\n  language  python\n  category  security\n  severity  LOW\n  match\n    pattern  os\\.system\\(\n    scope    line\n  end\nend\n";
        // Python runs before Java: once with the taint rule on Python,
        // once on Java.
        for (rules, taint_file, pattern_file) in [
            ([python_taint, java_pattern], "app.py", "App.java"),
            ([java_taint, python_pattern], "App.java", "app.py"),
        ] {
            let root = temp_dir();
            let rules_dir = root.join("rules");
            std::fs::create_dir_all(&rules_dir).unwrap();
            write(&rules_dir, "taint.sca", rules[0]);
            write(&rules_dir, "pattern.sca", rules[1]);
            write(&root, "app.py", "import os\nx = input()\nos.system(x)\n");
            write(
                &root,
                "App.java",
                "class App {\n    void run(HttpServletRequest request) throws Exception {\n        String cmd = request.getParameter(\"cmd\");\n        Runtime.getRuntime().exec(cmd);\n    }\n}\n",
            );
            let config = ScanConfig {
                root: root.clone(),
                rules_path: rules_dir,
                suppress_file: None,
                exclude_patterns: vec![],
                ..ScanConfig::default()
            };
            let report = run_scan(&config);
            assert!(report.rule_errors.is_empty(), "{:?}", report.rule_errors);
            let mut found: Vec<(&str, &str)> = report
                .findings
                .iter()
                .map(|f| (f.file.as_str(), f.rule_key.as_str()))
                .collect();
            found.sort();
            let taint_rule = if taint_file == "app.py" {
                "cmd_injection"
            } else {
                "java_cmd_injection"
            };
            let pattern_rule = if pattern_file == "app.py" {
                "py_system_call"
            } else {
                "java_exec_call"
            };
            let mut expected = vec![(taint_file, taint_rule), (pattern_file, pattern_rule)];
            expected.sort();
            assert_eq!(found, expected);
            assert!(
                report
                    .findings
                    .iter()
                    .any(|f| f.file == taint_file && !f.taint_flows.is_empty()),
                "the flow of {taint_file} carries its steps"
            );
            std::fs::remove_dir_all(&root).ok();
        }
    }

    #[test]
    fn test_python_taint_still_works_when_java_files_present() {
        // The Python subset of taint (Phase C) must not be disturbed
        // by the presence of java files in the same scan.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "cmd_injection.sca",
            "rule cmd_injection\n  language  python\n  category  security\n  severity  HIGH\n  source  input\\s*\\(  kind=cli\n  sink    os\\.system\\s*\\(\nend\n",
        );
        write(&root, "app.py", "import os\nx = input()\nos.system(x)\n");
        write(&root, "App.java", "class App {}\n");

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert_eq!(report.files_scanned, 2);
        assert!(
            report.findings.iter().any(|f| f.file == "app.py"),
            "le taint python doit continuer à fonctionner malgré la présence d'App.java"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_java_cross_file_taint_flow_resolved_via_call_graph() {
        // Api.java calls QueryRunner.runQuery() (defined in another
        // file, package + import) with a tainted source; the sink
        // (Statement.execute) is INSIDE QueryRunner.java, never visible
        // from Api.java without multi-file interprocedural resolution
        // via JavaCallGraph.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "java_sqli.sca",
            "rule java_sqli\n  language  java\n  category  security\n  severity  HIGH\n  source  request\\.getParameter\\s*\\(  kind=http\n  sink    \\.execute\\s*\\(\nend\n",
        );
        write(
            &root,
            "QueryRunner.java",
            "package com.acme.util;\nclass QueryRunner {\n    void runQuery(String query, java.sql.Statement db) throws Exception {\n        db.execute(query);\n    }\n}\n",
        );
        write(
            &root,
            "Api.java",
            "package com.acme.service;\nimport com.acme.util.QueryRunner;\nclass Api {\n    void handler(HttpServletRequest request, java.sql.Statement db) throws Exception {\n        String q = request.getParameter(\"q\");\n        QueryRunner qr = new QueryRunner();\n        qr.runQuery(q, db);\n    }\n}\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().any(|f| f.file == "Api.java"),
            "le flux cross-file (Api.java appelle qr.runQuery() de QueryRunner.java via type_map, qui atteint db.execute) doit être résolu au site d'appel dans Api.java ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_java_intra_file_sink_also_detected() {
        // Direct INTRA-file flow (inside App.java itself) — must keep
        // working with no regression after the multi-file wiring.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "java_cmd_injection.sca",
            "rule java_cmd_injection\n  language  java\n  category  security\n  severity  HIGH\n  source  request\\.getParameter\\s*\\(  kind=http\n  sink    Runtime\\.getRuntime\\(\\)\\.exec\nend\n",
        );
        write(
            &root,
            "App.java",
            "class App {\n    void run(HttpServletRequest request) throws Exception {\n        String cmd = request.getParameter(\"cmd\");\n        Runtime.getRuntime().exec(cmd);\n    }\n}\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            !report.findings.is_empty(),
            "flux intra-fichier java toujours détecté après le câblage multi-fichiers"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_js_intra_file_function_to_function_flow_resolved() {
        // JS call graph wired on 08/30 (`js_call_graph.rs`): before this
        // effort, even an A -> B call WITHIN THE SAME FILE wasn't
        // tracked (`specs.summaries` always empty) — this test verifies
        // that this basic flow is now detected.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "js_sqli.sca",
            "rule js_sqli\n  language  javascript\n  category  security\n  severity  HIGH\n  source  req\\.query\\.q  kind=http\n  sink    db\\.query\\s*\\(\nend\n",
        );
        write(
            &root,
            "app.js",
            "function helper(cmd) { db.query(cmd); }\nfunction main(req) { const q = req.query.q; helper(q); }\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().any(|f| f.file == "app.js"),
            "flux main() -> helper() -> db.query() (même fichier) doit être résolu ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_js_cross_file_taint_flow_resolved_via_call_graph() {
        // api.js imports and calls runQuery (utils.js, CommonJS
        // require); the sink (db.query) is INSIDE utils.js, never
        // visible from api.js without multi-file interprocedural
        // resolution via JsCallGraph.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "js_sqli.sca",
            "rule js_sqli\n  language  javascript\n  category  security\n  severity  HIGH\n  source  req\\.query\\.q  kind=http\n  sink    db\\.query\\s*\\(\nend\n",
        );
        write(
            &root,
            "utils.js",
            "function runQuery(cmd) { db.query(cmd); }\n",
        );
        write(
            &root,
            "api.js",
            "const { runQuery } = require('./utils');\nfunction handler(req) { const q = req.query.q; runQuery(q); }\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().any(|f| f.file == "api.js"),
            "le flux cross-file (api.js appelle runQuery() de utils.js via require, qui atteint db.query) doit être résolu au site d'appel dans api.js ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_js_bare_npm_import_does_not_introduce_false_flow() {
        // Non-relative import (npm package): never resolved, must not
        // introduce any false flow even if a method name coincides
        // with a sink-reaching function from ANOTHER scanned file.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "js_sqli.sca",
            "rule js_sqli\n  language  javascript\n  category  security\n  severity  HIGH\n  source  req\\.query\\.q  kind=http\n  sink    db\\.query\\s*\\(\nend\n",
        );
        write(
            &root,
            "danger.js",
            "function query(cmd) { db.query(cmd); }\n",
        );
        write(
            &root,
            "api.js",
            "import lodash from 'lodash';\nfunction handler(req) { const q = req.query.q; lodash.query(q); }\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().all(|f| f.file != "api.js"),
            "import npm bare ('lodash') ne doit jamais être résolu vers danger.js ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_php_intra_file_function_to_function_flow_resolved() {
        // PHP call graph wired on 08/30 (`php_call_graph.rs`): before
        // this effort, even an A -> B call WITHIN THE SAME FILE wasn't
        // tracked (`specs.summaries` always empty).
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "php_sqli.sca",
            "rule php_sqli\n  language  php\n  category  security\n  severity  HIGH\n  source  \\$_GET\\[  kind=http\n  sink    ->query\\s*\\(\nend\n",
        );
        write(
            &root,
            "app.php",
            "<?php\nfunction helper($cmd) { $db->query($cmd); }\nfunction main() { $q = $_GET['q']; helper($q); }\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().any(|f| f.file == "app.php"),
            "flux main() -> helper() -> $db->query() (même fichier) doit être résolu ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_php_cross_file_taint_flow_resolved_via_require() {
        // api.php requires utils.php and calls runQuery(); the sink
        // ($db->query) is INSIDE utils.php, never visible from
        // api.php without multi-file interprocedural resolution via
        // PhpCallGraph (star-merge of the requires).
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "php_sqli.sca",
            "rule php_sqli\n  language  php\n  category  security\n  severity  HIGH\n  source  \\$_GET\\[  kind=http\n  sink    ->query\\s*\\(\nend\n",
        );
        write(
            &root,
            "utils.php",
            "<?php\nfunction runQuery($cmd) { $db->query($cmd); }\n",
        );
        write(
            &root,
            "api.php",
            "<?php\nrequire './utils.php';\nfunction handler() { $q = $_GET['q']; runQuery($q); }\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().any(|f| f.file == "api.php"),
            "le flux cross-file (api.php require utils.php et appelle runQuery(), qui atteint $db->query) doit être résolu au site d'appel dans api.php ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_php_ambiguous_static_class_name_does_not_introduce_false_flow() {
        // Two files each define a Utils class with a query() method
        // reaching the sink — the class name is ambiguous in the scanned
        // corpus and must never be resolved (anti-FP), even though
        // api.php calls Utils::query() without explicitly requiring
        // either file.
        let root = temp_dir();
        let rules_dir = root.join("rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        write(
            &rules_dir,
            "php_sqli.sca",
            "rule php_sqli\n  language  php\n  category  security\n  severity  HIGH\n  source  \\$_GET\\[  kind=http\n  sink    ->query\\s*\\(\nend\n",
        );
        write(
            &root,
            "utils1.php",
            "<?php\nclass Utils {\n  static function query($cmd) { $db->query($cmd); }\n}\n",
        );
        write(
            &root,
            "utils2.php",
            "<?php\nclass Utils {\n  static function query($cmd) { $db->query($cmd); }\n}\n",
        );
        write(
            &root,
            "api.php",
            "<?php\nfunction handler() { $q = $_GET['q']; Utils::query($q); }\n",
        );

        let config = ScanConfig {
            root: root.clone(),
            rules_path: rules_dir,
            suppress_file: None,
            exclude_patterns: vec![],
            ..ScanConfig::default()
        };
        let report = run_scan(&config);
        assert!(
            report.findings.iter().all(|f| f.file != "api.php"),
            "nom de classe ambigu (Utils defini dans 2 fichiers) ne doit jamais etre resolu ; findings = {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.file, f.line))
                .collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
