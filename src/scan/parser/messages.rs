//! Messages of the rule compiler (ticket #279): each error names a key
//! of the console translations (`resources/locales/script/*.json`, group
//! `dsl`) and the values of its `{placeholders}`, and is translated when
//! it is shown, in the language of the console.
//!
//! Before ticket #279 the compiler wrote its messages in French, whatever
//! the language: a client writing their own rules (ADR-0057) read
//! « Bloc 'rule' non fermé » on an English console.

use std::sync::LazyLock;

use serde_json::Value;

/// The keys of the compiler's messages, in the `dsl` group of the console
/// translations. The English text is given above each one.
pub mod keys {
    /// Mode 'ast' needs a 'match ast' block
    pub const AST_NEEDS_BLOCK: &str = "dsl.ast_needs_block";
    /// Keyword 'pattern' expected in 'match ast', found: '{found}'
    pub const AST_PATTERN_EXPECTED: &str = "dsl.ast_pattern_expected";
    /// 'arg_index' must be a whole number of 0 or more, or 'all', found: '{value}'
    pub const BAD_ARG_INDEX: &str = "dsl.bad_arg_index";
    /// 'arg_name' must be a keyword argument name written beside 'arg_index=<n>', found: '{value}'
    pub const BAD_ARG_NAME: &str = "dsl.bad_arg_name";
    /// 'kinds' of a sink must list source kinds among {kinds}, separated by
    /// commas, found: '{value}'
    pub const BAD_SINK_KINDS: &str = "dsl.bad_sink_kinds";
    /// Block '{block}' not closed (missing 'end')
    pub const BLOCK_NOT_CLOSED: &str = "dsl.block_not_closed";
    /// Unknown category: '{category}'
    pub const CATEGORY_UNKNOWN: &str = "dsl.category_unknown";
    /// 'confidence' must be a whole number
    pub const CONFIDENCE_NOT_INTEGER: &str = "dsl.confidence_not_integer";
    /// Confidence out of range: {confidence} (expected: 0-100)
    pub const CONFIDENCE_OUT_OF_RANGE: &str = "dsl.confidence_out_of_range";
    /// Mode 'file_contains' needs a 'match file_contains' block or a 'requires' block (has/not_has)
    pub const FILE_CONTAINS_NEEDS_BLOCK: &str = "dsl.file_contains_needs_block";
    /// Translated text block not closed (missing 'end')
    pub const I18N_BLOCK_NOT_CLOSED: &str = "dsl.i18n_block_not_closed";
    /// Invalid identifier: '{id}' (expected: [a-z0-9_]+)
    pub const ID_INVALID: &str = "dsl.id_invalid";
    /// Missing rule identifier
    pub const ID_MISSING: &str = "dsl.id_missing";
    /// Missing language
    pub const LANGUAGE_MISSING: &str = "dsl.language_missing";
    /// Unknown language: '{language}'
    pub const LANGUAGE_UNKNOWN: &str = "dsl.language_unknown";
    /// Mode '{mode}' needs at least one 'match' block
    pub const MODE_NEEDS_MATCH: &str = "dsl.mode_needs_match";
    /// Mode '{mode}' needs at least one sink
    pub const MODE_NEEDS_SINK: &str = "dsl.mode_needs_sink";
    /// Mode '{mode}' needs at least one source
    pub const MODE_NEEDS_SOURCE: &str = "dsl.mode_needs_source";
    /// Unknown mode: '{mode}'
    pub const MODE_UNKNOWN: &str = "dsl.mode_unknown";
    /// Mode 'python_hook' needs a 'hook'
    pub const PYTHON_HOOK_NEEDS_HOOK: &str = "dsl.python_hook_needs_hook";
    /// Invalid regular expression in {field}: {error}
    pub const REGEX_INVALID: &str = "dsl.regex_invalid";
    /// '{keyword}' is given twice in one 'match' block: the second value would replace the first. Write a single '{slot}' per block, or one 'match' block per pattern.
    pub const REPEATED_IN_MATCH: &str = "dsl.repeated_in_match";
    /// File 'requires' block not closed (missing 'end')
    pub const REQUIRES_FILE_BLOCK_NOT_CLOSED: &str = "dsl.requires_file_block_not_closed";
    /// Missing rule identifier after 'rule'
    pub const RULE_ID_MISSING: &str = "dsl.rule_id_missing";
    /// Rule '{rule}' is invalid: {errors}
    pub const RULE_INVALID: &str = "dsl.rule_invalid";
    /// Keyword 'rule' expected, found: '{found}'
    pub const RULE_KEYWORD_EXPECTED: &str = "dsl.rule_keyword_expected";
    /// The rule must hold at least one 'match', 'requires' (has/not_has), 'taint' or 'hook' block
    pub const RULE_NEEDS_DETECTION: &str = "dsl.rule_needs_detection";
    /// Missing severity
    pub const SEVERITY_MISSING: &str = "dsl.severity_missing";
    /// Unknown severity: '{severity}'
    pub const SEVERITY_UNKNOWN: &str = "dsl.severity_unknown";
    /// Unknown source kind: '{kind}'
    pub const SOURCE_KIND_UNKNOWN: &str = "dsl.source_kind_unknown";
    /// Unclosed string
    pub const STRING_NOT_CLOSED: &str = "dsl.string_not_closed";
    /// A data-flow rule (source and sink) reads only 'has' and 'not_has' in 'requires': '{key}' is not supported there
    pub const TAINT_FILE_CONDITION_UNSUPPORTED: &str = "dsl.taint_file_condition_unsupported";
    /// Text block not closed (missing 'end')
    pub const TEXT_BLOCK_NOT_CLOSED: &str = "dsl.text_block_not_closed";
    /// Missing text after the language code '{language}'
    pub const TEXT_MISSING_AFTER_LANGUAGE: &str = "dsl.text_missing_after_language";
    /// Unknown tier: '{tier}'
    pub const TIER_UNKNOWN: &str = "dsl.tier_unknown";
    /// Unknown keyword in 'match file_contains': '{keyword}'
    pub const UNKNOWN_FILE_CONTAINS_KEYWORD: &str = "dsl.unknown_file_contains_keyword";
    /// Unknown keyword in 'match': '{keyword}'
    pub const UNKNOWN_MATCH_KEYWORD: &str = "dsl.unknown_match_keyword";
    /// Unknown 'match' block type: '{type}'
    pub const UNKNOWN_MATCH_TYPE: &str = "dsl.unknown_match_type";
    /// Unknown 'metadata' key: '{key}'
    pub const UNKNOWN_METADATA_KEY: &str = "dsl.unknown_metadata_key";
    /// Unknown key in a file 'requires' block: '{key}'
    pub const UNKNOWN_REQUIRES_FILE_KEY: &str = "dsl.unknown_requires_file_key";
    /// Unknown 'requires' key: '{key}'
    pub const UNKNOWN_REQUIRES_KEY: &str = "dsl.unknown_requires_key";
    /// Unknown keyword in a rule: '{keyword}'
    pub const UNKNOWN_RULE_KEYWORD: &str = "dsl.unknown_rule_keyword";
    /// Unknown option on a sink: '{option}' (only 'arg_index', 'arg_name'
    /// and 'kinds' exist)
    pub const UNKNOWN_SINK_OPTION: &str = "dsl.unknown_sink_option";
    /// Unknown option on a passthrough: '{option}' (only 'arg_index'
    /// exists, ticket #256)
    pub const UNKNOWN_PASSTHROUGH_OPTION: &str = "dsl.unknown_passthrough_option";
    /// 'arg_index' of a passthrough must be a whole number or 'none':
    /// '{value}' (ticket #256)
    pub const BAD_PASSTHROUGH_ARG_INDEX: &str = "dsl.bad_passthrough_arg_index";
    /// Missing value after '{keyword}'
    pub const VALUE_MISSING: &str = "dsl.value_missing";

    /// Every key, checked against the four translations by a test.
    pub const ALL: &[&str] = &[
        AST_NEEDS_BLOCK,
        AST_PATTERN_EXPECTED,
        BAD_ARG_INDEX,
        BAD_ARG_NAME,
        BAD_SINK_KINDS,
        BLOCK_NOT_CLOSED,
        CATEGORY_UNKNOWN,
        CONFIDENCE_NOT_INTEGER,
        CONFIDENCE_OUT_OF_RANGE,
        FILE_CONTAINS_NEEDS_BLOCK,
        I18N_BLOCK_NOT_CLOSED,
        ID_INVALID,
        ID_MISSING,
        LANGUAGE_MISSING,
        LANGUAGE_UNKNOWN,
        MODE_NEEDS_MATCH,
        MODE_NEEDS_SINK,
        MODE_NEEDS_SOURCE,
        MODE_UNKNOWN,
        PYTHON_HOOK_NEEDS_HOOK,
        REGEX_INVALID,
        REPEATED_IN_MATCH,
        REQUIRES_FILE_BLOCK_NOT_CLOSED,
        RULE_ID_MISSING,
        RULE_INVALID,
        RULE_KEYWORD_EXPECTED,
        RULE_NEEDS_DETECTION,
        SEVERITY_MISSING,
        SEVERITY_UNKNOWN,
        SOURCE_KIND_UNKNOWN,
        STRING_NOT_CLOSED,
        TAINT_FILE_CONDITION_UNSUPPORTED,
        TEXT_BLOCK_NOT_CLOSED,
        TEXT_MISSING_AFTER_LANGUAGE,
        TIER_UNKNOWN,
        UNKNOWN_FILE_CONTAINS_KEYWORD,
        UNKNOWN_MATCH_KEYWORD,
        UNKNOWN_MATCH_TYPE,
        UNKNOWN_METADATA_KEY,
        UNKNOWN_REQUIRES_FILE_KEY,
        UNKNOWN_REQUIRES_KEY,
        UNKNOWN_RULE_KEYWORD,
        UNKNOWN_SINK_OPTION,
        UNKNOWN_PASSTHROUGH_OPTION,
        BAD_PASSTHROUGH_ARG_INDEX,
        VALUE_MISSING,
    ];
}

/// One message of the compiler: a key of [`keys`] and the values of its
/// placeholders.
#[derive(Debug, Clone, PartialEq)]
pub struct DslMessage {
    pub key: &'static str,
    pub args: Vec<(&'static str, String)>,
}

impl DslMessage {
    /// A message without placeholder.
    pub fn new(key: &'static str) -> Self {
        DslMessage {
            key,
            args: Vec::new(),
        }
    }

    /// Adds the value of placeholder `{name}`.
    pub fn with(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.args.push((name, value.into()));
        self
    }

    /// The message in the language of `locale` (a console translation,
    /// `i18n::load_script_locale`).
    pub fn render(&self, locale: &Value) -> String {
        self.args
            .iter()
            .fold(crate::i18n::t(locale, self.key), |text, (name, value)| {
                text.replace(&format!("{{{name}}}"), value)
            })
    }

    /// The message in English, the language of `Display`.
    pub fn english(&self) -> String {
        self.render(&ENGLISH)
    }
}

/// The English console translation, read once.
pub(crate) static ENGLISH: LazyLock<Value> =
    LazyLock::new(|| crate::i18n::load_script_locale("en"));

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

    /// Every key has a text in the four languages, with the placeholders
    /// of the English one; the group holds no other key.
    #[test]
    fn test_every_message_is_translated_with_its_placeholders() {
        let english = crate::i18n::load_script_locale("en");
        for lang in ["en", "fr", "es", "de"] {
            let locale = crate::i18n::load_script_locale(lang);
            let group = locale["dsl"].as_object().expect("dsl group");
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

    #[test]
    fn test_a_message_is_rendered_in_the_console_language() {
        let message = DslMessage::new(keys::BLOCK_NOT_CLOSED).with("block", "rule");
        assert_eq!(message.english(), "Block 'rule' not closed (missing 'end')");
        assert_eq!(
            message.render(&crate::i18n::load_script_locale("fr")),
            "Bloc 'rule' non fermé (manque 'end')"
        );
    }
}
