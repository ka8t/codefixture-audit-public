//! AST for the `.sca` DSL — faithful port of `Audit/sca/dsl/nodes.py`.
//!
//! Intermediate structure between parsing a `.sca` file and its
//! compilation to the JSON format consumed by `rule_loader.py`.

use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MatchRegexBlock {
    pub pattern: String,
    pub is_text: bool,
    pub scope: String,
    pub with_pattern: String,
    pub with_is_text: bool,
    pub pattern_not: String,
    pub pattern_not_is_text: bool,
    pub pattern_inside: String,
    pub pattern_not_inside: String,
    pub line_number: usize,
}

impl MatchRegexBlock {
    pub fn new(line_number: usize) -> Self {
        MatchRegexBlock {
            scope: "line".to_string(),
            line_number,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MatchAstBlock {
    pub pattern: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MatchFileContainsBlock {
    pub has_patterns: Vec<String>,
    pub not_has_patterns: Vec<String>,
    pub scope: String,
    pub line_number: usize,
}

impl MatchFileContainsBlock {
    pub fn new(line_number: usize) -> Self {
        MatchFileContainsBlock {
            scope: "file".to_string(),
            line_number,
            ..Default::default()
        }
    }
}

/// A `match` block — regex, AST (tree-sitter) or file_contains.
#[derive(Debug, Clone, PartialEq)]
pub enum MatchBlock {
    Regex(MatchRegexBlock),
    Ast(MatchAstBlock),
    FileContains(MatchFileContainsBlock),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SourceSpec {
    pub pattern: String,
    pub kind: String,
    pub line_number: usize,
}

/// The arguments of a sink the rule names with `arg_index=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkArguments {
    /// `arg_index=<n>`: the one argument (0-based) that carries the danger
    /// (ticket #221).
    Index(usize),
    /// `arg_index=all`: every argument carries the danger. Written on a
    /// constructor whose dangerous argument is not always the first:
    /// `new Cookie(name, value)`, `new Function("x", body)` (ticket #258).
    All,
}

/// A `sink` line of a data-flow rule: the regular expression of the
/// dangerous call, and the arguments the rule names with `arg_index=`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SinkSpec {
    pub pattern: String,
    /// The arguments that carry the danger, when the rule writes
    /// `arg_index=`: the only ones both the dataflow path and the line
    /// layer check (ticket #221). `None` when not written: the dataflow
    /// path checks argument 0 and the line layer the whole call, as before
    /// the option was a decision of the rule.
    pub arg_index: Option<SinkArguments>,
    /// `arg_name=<name>`, written with `arg_index=<n>`: the same argument
    /// passed by keyword (Python `Response(body, headers=h)`), which the
    /// dataflow path and the line layer check as well (ticket #261).
    pub arg_name: Option<String>,
    /// `kinds=<kind>,<kind>`: the source kinds this sink is reached by
    /// (`kind=` of the `source` lines). Empty when not written: every kind.
    /// A rule whose broad sinks (`\.println\s*\(`) also write files and the
    /// console limits them to the kinds that are visitor data, and lets
    /// its web-output sinks take every kind (taint_xss, www.codefixture.com#5).
    pub kinds: Vec<String>,
    pub line_number: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SanitizerSpec {
    pub pattern: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PassthroughSpec {
    pub pattern: String,
    /// The arguments whose data the result of the call carries, written
    /// `arg_index=` (ticket #256); `None`: every argument, as before.
    pub arg_index: Option<PassthroughArguments>,
    pub line_number: usize,
}

/// The arguments of a passthrough the rule names with `arg_index=`: the
/// data its result carries besides the receiver's (ticket #256).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassthroughArguments {
    /// `arg_index=<n>`: that argument only (0-based), as the document of
    /// `elementpath.select(root, query)`, not its query.
    Index(usize),
    /// `arg_index=none`: no argument, the receiver only, as the document
    /// of `root.xpath(query)` (the query selects a node, it is not in the
    /// result).
    None,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct I18nBlock {
    pub texts: BTreeMap<String, String>,
    pub line_number: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MetadataBlock {
    pub cwe: Vec<String>,
    pub cve: Vec<String>,
    pub owasp: String,
    pub iso27001: Vec<String>,
    pub wcag: Vec<String>,
    pub asvs: Vec<String>,
    // AuditAi provenance (CONSTRAINTS.md C9) — empty for any
    // builtin or manually written custom rule.
    pub generated_by: String,
    pub generated_at: String,
    pub auditai_version: String,
    pub manifest_hash: String,
    pub org_id: String,
    pub signature: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LicenseBlock {
    pub min_tier: String,
    pub features: Vec<String>,
    pub demo_fallback: bool,
    pub line_number: usize,
}

impl Default for LicenseBlock {
    fn default() -> Self {
        LicenseBlock {
            min_tier: "demo".to_string(),
            features: Vec::new(),
            demo_fallback: false,
            line_number: 0,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FileConditionBlock {
    pub has_patterns: Vec<String>,
    pub not_has_patterns: Vec<String>,
    pub path_contains: Vec<String>,
    /// Segments none of which the file's project-relative path may
    /// contain (ticket #229, no Python counterpart).
    pub not_path_contains: Vec<String>,
    pub not_path_has_file: Vec<String>,
    pub min_lines: i64,
    pub scope: String,
    pub line_number: usize,
}

impl FileConditionBlock {
    pub fn new(line_number: usize) -> Self {
        FileConditionBlock {
            scope: "file".to_string(),
            line_number,
            ..Default::default()
        }
    }
}

/// Root node — a complete `.sca` rule (`rule ... end`).
#[derive(Debug, Clone, PartialEq)]
pub struct RuleNode {
    pub id: String,
    pub language: String,
    pub category: String,
    pub severity: String,
    pub confidence: i64,
    /// Optional — inferred by the compiler if absent.
    pub mode: String,
    pub match_blocks: Vec<MatchBlock>,
    pub file_conditions: Vec<FileConditionBlock>,
    pub sources: Vec<SourceSpec>,
    pub sinks: Vec<SinkSpec>,
    pub sanitizers: Vec<SanitizerSpec>,
    pub passthroughs: Vec<PassthroughSpec>,
    /// Display name, per language (`name` block): what the report and
    /// `list-rules` show instead of the identifier.
    pub name: I18nBlock,
    pub message: I18nBlock,
    pub risk: I18nBlock,
    pub solution: I18nBlock,
    pub benefit: I18nBlock,
    pub metadata: MetadataBlock,
    pub license: LicenseBlock,
    pub fix_before: String,
    pub fix_after: String,
    pub hook: String,
    pub line_number: usize,
}

impl RuleNode {
    pub fn new(id: impl Into<String>, line_number: usize) -> Self {
        RuleNode {
            id: id.into(),
            language: String::new(),
            category: String::new(),
            severity: String::new(),
            confidence: 80,
            mode: String::new(),
            match_blocks: Vec::new(),
            file_conditions: Vec::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
            sanitizers: Vec::new(),
            passthroughs: Vec::new(),
            name: I18nBlock::default(),
            message: I18nBlock::default(),
            risk: I18nBlock::default(),
            solution: I18nBlock::default(),
            benefit: I18nBlock::default(),
            metadata: MetadataBlock::default(),
            license: LicenseBlock::default(),
            fix_before: String::new(),
            fix_after: String::new(),
            hook: String::new(),
            line_number,
        }
    }
}
