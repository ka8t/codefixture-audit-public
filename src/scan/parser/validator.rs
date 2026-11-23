//! Semantic validator for `.sca` rules — faithful port of
//! `Audit/sca/dsl/validator.py`.

use super::compiler::text_to_regex;
use super::messages::{DslMessage, keys};
use super::model::{MatchBlock, RuleNode};

pub const VALID_LANGUAGES: &[&str] = &[
    "python",
    "javascript",
    "java",
    "csharp",
    "php",
    "yaml",
    "html",
    "dockerfile",
];
pub const VALID_CATEGORIES: &[&str] = &[
    "security",
    "arch",
    "ui",
    "ux",
    "maintenance",
    "cicd",
    "database",
    "dependencies",
];
pub const VALID_SEVERITIES: &[&str] = &["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
pub const VALID_MODES_DSL: &[&str] = &[
    "regex",
    "taint",
    "regex+taint",
    "ast",
    "file_contains",
    "python_hook",
];
pub const VALID_SOURCE_KINDS: &[&str] = &["http", "cli", "env", "stdin", "file", "network"];
pub const VALID_TIERS: &[&str] = &["demo", "solo", "team", "enterprise"];

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The problems of a parsed rule, as compiler messages (ticket #279):
/// empty when the rule is valid.
pub fn validate_rule(node: &RuleNode) -> Vec<DslMessage> {
    let mut errors = Vec::new();

    if node.id.is_empty() {
        errors.push(DslMessage::new(keys::ID_MISSING));
    } else if !valid_id(&node.id) {
        errors.push(DslMessage::new(keys::ID_INVALID).with("id", node.id.clone()));
    }

    if node.language.is_empty() {
        errors.push(DslMessage::new(keys::LANGUAGE_MISSING));
    } else if !VALID_LANGUAGES.contains(&node.language.as_str()) {
        errors
            .push(DslMessage::new(keys::LANGUAGE_UNKNOWN).with("language", node.language.clone()));
    }

    if !node.category.is_empty() && !VALID_CATEGORIES.contains(&node.category.as_str()) {
        errors
            .push(DslMessage::new(keys::CATEGORY_UNKNOWN).with("category", node.category.clone()));
    }

    if node.severity.is_empty() {
        errors.push(DslMessage::new(keys::SEVERITY_MISSING));
    } else if !VALID_SEVERITIES.contains(&node.severity.as_str()) {
        errors
            .push(DslMessage::new(keys::SEVERITY_UNKNOWN).with("severity", node.severity.clone()));
    }

    if !node.mode.is_empty() && !VALID_MODES_DSL.contains(&node.mode.as_str()) {
        errors.push(DslMessage::new(keys::MODE_UNKNOWN).with("mode", node.mode.clone()));
    }

    if !(0..=100).contains(&node.confidence) {
        errors.push(
            DslMessage::new(keys::CONFIDENCE_OUT_OF_RANGE)
                .with("confidence", node.confidence.to_string()),
        );
    }

    if !node.mode.is_empty() {
        let mode = node.mode.as_str();
        if (mode == "regex" || mode == "regex+taint") && node.match_blocks.is_empty() {
            errors.push(DslMessage::new(keys::MODE_NEEDS_MATCH).with("mode", mode));
        }
        if mode == "taint" || mode == "regex+taint" {
            if node.sources.is_empty() {
                errors.push(DslMessage::new(keys::MODE_NEEDS_SOURCE).with("mode", mode));
            }
            if node.sinks.is_empty() {
                errors.push(DslMessage::new(keys::MODE_NEEDS_SINK).with("mode", mode));
            }
        }
        if mode == "ast" && node.match_blocks.is_empty() {
            errors.push(DslMessage::new(keys::AST_NEEDS_BLOCK));
        }
        if mode == "file_contains"
            && node.match_blocks.is_empty()
            && node.file_conditions.is_empty()
        {
            errors.push(DslMessage::new(keys::FILE_CONTAINS_NEEDS_BLOCK));
        }
        if mode == "python_hook" && node.hook.is_empty() {
            errors.push(DslMessage::new(keys::PYTHON_HOOK_NEEDS_HOOK));
        }
    } else {
        let has_content = !node.match_blocks.is_empty()
            || !node.file_conditions.is_empty()
            || !node.sources.is_empty()
            || !node.sinks.is_empty()
            || !node.hook.is_empty();
        if !has_content {
            errors.push(DslMessage::new(keys::RULE_NEEDS_DETECTION));
        }
    }

    validate_regex_blocks(node, &mut errors);
    validate_file_conditions(node, &mut errors);
    validate_taint_patterns(node, &mut errors);

    if !VALID_TIERS.contains(&node.license.min_tier.as_str()) {
        errors
            .push(DslMessage::new(keys::TIER_UNKNOWN).with("tier", node.license.min_tier.clone()));
    }

    for src in &node.sources {
        if !VALID_SOURCE_KINDS.contains(&src.kind.as_str()) {
            errors.push(DslMessage::new(keys::SOURCE_KIND_UNKNOWN).with("kind", src.kind.clone()));
        }
    }

    errors
}

fn validate_regex_blocks(node: &RuleNode, errors: &mut Vec<DslMessage>) {
    for block in &node.match_blocks {
        match block {
            MatchBlock::Regex(b) => {
                let pat = if b.is_text {
                    text_to_regex(&b.pattern)
                } else {
                    b.pattern.clone()
                };
                try_compile(&pat, if b.is_text { "text" } else { "pattern" }, errors);

                let wp = if b.with_is_text {
                    text_to_regex(&b.with_pattern)
                } else {
                    b.with_pattern.clone()
                };
                try_compile(&wp, "with", errors);

                let np = if b.pattern_not_is_text {
                    text_to_regex(&b.pattern_not)
                } else {
                    b.pattern_not.clone()
                };
                try_compile(
                    &np,
                    if b.pattern_not_is_text {
                        "text-not"
                    } else {
                        "pattern-not"
                    },
                    errors,
                );

                try_compile(&b.pattern_inside, "pattern-inside", errors);
                try_compile(&b.pattern_not_inside, "pattern-not-inside", errors);
            }
            MatchBlock::FileContains(b) => {
                for p in &b.has_patterns {
                    try_compile(p, "has", errors);
                }
                for p in &b.not_has_patterns {
                    try_compile(p, "not_has", errors);
                }
            }
            MatchBlock::Ast(_) => {}
        }
    }
}

fn validate_file_conditions(node: &RuleNode, errors: &mut Vec<DslMessage>) {
    for fc in &node.file_conditions {
        for p in &fc.has_patterns {
            try_compile(p, "requires has", errors);
        }
        for p in &fc.not_has_patterns {
            try_compile(p, "requires not_has", errors);
        }
    }
}

fn validate_taint_patterns(node: &RuleNode, errors: &mut Vec<DslMessage>) {
    for src in &node.sources {
        try_compile(&src.pattern, "source", errors);
    }
    for snk in &node.sinks {
        try_compile(&snk.pattern, "sink", errors);
    }
    for san in &node.sanitizers {
        try_compile(&san.pattern, "sanitizer", errors);
    }
}

/// Compiles via `fancy-regex`, not `regex`: a large share of real
/// rules use lookahead/lookbehind/backreferences (supported by
/// Python's `re`, not by the standard `regex` crate) — confirmed
/// empirically against the corpus of 703 builtin rules (Decision #2),
/// where `regex` wrongly rejected ~30 rules.
fn try_compile(pattern: &str, field_name: &str, errors: &mut Vec<DslMessage>) {
    if pattern.is_empty() {
        return;
    }
    if let Err(e) = fancy_regex::Regex::new(pattern) {
        errors.push(
            DslMessage::new(keys::REGEX_INVALID)
                .with("field", field_name)
                .with("error", e.to_string()),
        );
    }
}
