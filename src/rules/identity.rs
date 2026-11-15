//! The identity of a rule: its language and its name.
//!
//! A rule's name alone does not identify it: the catalog writes the same
//! check once per language under one name (`base64_eval` for Python and
//! for JavaScript, `file_too_long` for four languages; 49 names on
//! 2026-11-14), each with its own patterns and its own texts. Every place
//! that looks a rule up (the report's texts and examples, the SARIF rule
//! list, the scan's rule registry, `rules.disabled`) goes through
//! [`RuleId`], so a finding always reads the rule of its own language.
//!
//! The name stays what users see and write: findings, suppressions and
//! history keep `rule_key` = the name, and the finding's file already
//! tells the language apart.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A rule's identity: unique in a scan, in the catalog and in a pack.
///
/// Ordered by language then name. Written `language/name`
/// (`python/base64_eval`); a rule without `language` (only possible in a
/// hand-written client rule) has an empty language and is written as its
/// name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RuleId {
    /// The rule's `language` (`SourceLanguage::rule_tag`), `""` if absent.
    pub language: String,
    /// The rule's name (`rule <name>` in the `.sca` file).
    pub name: String,
}

impl RuleId {
    /// The identity of `language` and `name`.
    pub fn new(language: &str, name: &str) -> Self {
        RuleId {
            language: language.to_string(),
            name: name.to_string(),
        }
    }

    /// The identity of a compiled rule, from its `id` and `language`
    /// fields; `None` for a rule without `id` (never compiled as such).
    pub fn of(rule: &serde_json::Value) -> Option<Self> {
        let name = rule.get("id")?.as_str()?;
        let language = rule.get("language").and_then(|v| v.as_str()).unwrap_or("");
        Some(RuleId::new(language, name))
    }

    /// Whether `selector`, as written in `rules.disabled` or
    /// `--disable-rule`, designates this rule: its name designates the
    /// rule in every language (the behavior before identities, kept), and
    /// `language/name` this language only.
    pub fn is_selected_by(&self, selector: &str) -> bool {
        match selector.split_once('/') {
            Some((language, name)) => language == self.language && name == self.name,
            None => selector == self.name,
        }
    }
}

/// The compiled rules of a scan by identity: where the reports read a
/// finding's rule texts.
pub type RuleCatalog = std::collections::BTreeMap<RuleId, serde_json::Value>;

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.language.is_empty() {
            write!(f, "{}", self.name)
        } else {
            write!(f, "{}/{}", self.language, self.name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_identity_of_a_compiled_rule() {
        let rule = json!({"id": "base64_eval", "language": "python"});
        assert_eq!(RuleId::of(&rule), Some(RuleId::new("python", "base64_eval")));
        assert_eq!(RuleId::of(&rule).unwrap().to_string(), "python/base64_eval");
        assert_eq!(RuleId::of(&json!({"language": "python"})), None);
    }

    #[test]
    fn test_same_name_in_two_languages_is_two_identities() {
        let python = RuleId::new("python", "base64_eval");
        let javascript = RuleId::new("javascript", "base64_eval");
        assert_ne!(python, javascript);
    }

    #[test]
    fn test_a_name_selects_every_language_and_a_qualified_name_one() {
        let python = RuleId::new("python", "base64_eval");
        let javascript = RuleId::new("javascript", "base64_eval");
        assert!(python.is_selected_by("base64_eval") && javascript.is_selected_by("base64_eval"));
        assert!(python.is_selected_by("python/base64_eval"));
        assert!(!javascript.is_selected_by("python/base64_eval"));
        assert!(!python.is_selected_by("base64"));
    }

    #[test]
    fn test_a_rule_without_language_is_written_as_its_name() {
        let rule = RuleId::of(&json!({"id": "my_rule"})).unwrap();
        assert_eq!(rule.to_string(), "my_rule");
        assert!(rule.is_selected_by("my_rule"));
    }
}
