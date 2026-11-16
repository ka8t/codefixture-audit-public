//! Locale loading and i18n lookup — port of the
//! `_load_locale`/`t_console`/`t_report`/`_get_nested`/`_rule` methods
//! from `Audit/sca/runner.py`.
//!
//! The 8 locale files (`report`/`script` × de/en/es/fr) are static,
//! not editable by the client, and embedded at compile time via
//! `include_str!` — the same choice as for the compliance mappings
//! (`compliance.rs`) and for the report templates/assets
//! (`report_assets.rs`). Not ported: merging with project-specific
//! locales (`_load_locale`, `project_id` block) — there is no
//! per-project customization system on the codefixture-audit side to date.

use serde_json::Value;

const REPORT_DE: &str = include_str!("../../resources/locales/report/de.json");
const REPORT_EN: &str = include_str!("../../resources/locales/report/en.json");
const REPORT_ES: &str = include_str!("../../resources/locales/report/es.json");
const REPORT_FR: &str = include_str!("../../resources/locales/report/fr.json");

const SCRIPT_DE: &str = include_str!("../../resources/locales/script/de.json");
const SCRIPT_EN: &str = include_str!("../../resources/locales/script/en.json");
const SCRIPT_ES: &str = include_str!("../../resources/locales/script/es.json");
const SCRIPT_FR: &str = include_str!("../../resources/locales/script/fr.json");

/// Loads the `report` locale (HTML report) for a language — falls back
/// to English if the language is not one of the 4 supported, like the
/// Python `_load_locale` (falls back to `en.json` if the file doesn't exist).
pub fn load_report_locale(lang: &str) -> Value {
    let raw = match lang {
        "de" => REPORT_DE,
        "es" => REPORT_ES,
        "fr" => REPORT_FR,
        _ => REPORT_EN,
    };
    serde_json::from_str(raw).expect("locale report embarquée invalide")
}

/// Loads the `script` locale (console messages) for a language.
pub fn load_script_locale(lang: &str) -> Value {
    let raw = match lang {
        "de" => SCRIPT_DE,
        "es" => SCRIPT_ES,
        "fr" => SCRIPT_FR,
        _ => SCRIPT_EN,
    };
    serde_json::from_str(raw).expect("locale script embarquée invalide")
}

/// Resolves a dotted-notation key (e.g. `"severity.high"`) in a locale
/// JSON tree — equivalent to `_get_nested` on the Python side, without
/// the final coercion to a string (used as-is by `_rule` to retrieve a
/// sub-object).
pub fn get_nested<'a>(data: &'a Value, key: &str) -> Option<&'a Value> {
    let mut cur = data;
    for part in key.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

/// Translates a key — equivalent to `t_console`/`t_report`: returns
/// the key itself if the resolved value is absent or an empty string
/// (explicit fallback, like `value if value else key` on the Python side).
pub fn t(data: &Value, key: &str) -> String {
    match get_nested(data, key) {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => key.to_string(),
    }
}

// The rule texts (name, risk, solution, benefit) are read from the rule
// itself (`report::text::rule_display_name`, `extract_i18n_block`). The
// report locales held a second copy keyed by name (`rule_i18n`, port of
// `_rule`): 525 of its texts had drifted from the rules, and a name shared
// by two languages could only hold one of them. Removed on 2026-11-14.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_report_locale_all_languages_parse() {
        for lang in ["en", "fr", "es", "de"] {
            let v = load_report_locale(lang);
            assert!(v.is_object());
        }
    }

    #[test]
    fn test_load_script_locale_all_languages_parse() {
        for lang in ["en", "fr", "es", "de"] {
            let v = load_script_locale(lang);
            assert!(v.is_object());
        }
    }

    #[test]
    fn test_unknown_lang_falls_back_to_english() {
        let en = load_report_locale("en");
        let unknown = load_report_locale("xx");
        assert_eq!(t(&en, "title"), t(&unknown, "title"));
    }

    #[test]
    fn test_t_dotted_path_lookup() {
        let en = load_report_locale("en");
        assert_ne!(t(&en, "severity.high"), "severity.high");
    }

    #[test]
    fn test_t_missing_key_falls_back_to_key_itself() {
        let en = load_report_locale("en");
        assert_eq!(t(&en, "this.key.does.not.exist"), "this.key.does.not.exist");
    }

    /// The rule texts live in the rule files only: a `rules` section in a
    /// report locale would be a second copy, keyed by name, bound to drift.
    #[test]
    fn test_report_locales_hold_no_copy_of_the_rule_texts() {
        for lang in ["en", "fr", "es", "de"] {
            assert!(load_report_locale(lang).get("rules").is_none(), "{lang}");
        }
    }

    #[test]
    fn test_all_locales_have_glossary_iso27001_asvs_acronyms() {
        for lang in ["en", "fr", "es", "de"] {
            let v = load_report_locale(lang);
            let acronyms = get_nested(&v, "glossary.acronyms").expect("glossary.acronyms manquant");
            assert!(acronyms.get("iso27001").is_some());
            assert!(acronyms.get("asvs").is_some());
        }
    }

    /// Completeness test (ticket #47): the error keys added to
    /// translate the `scan` path must exist, non-empty, in all 4
    /// languages — not just the one used to write the key. Same
    /// principle as `test_all_locales_have_glossary_iso27001_asvs_acronyms`
    /// above, applied to the `script` locale rather than `report`.
    #[test]
    fn test_all_locales_have_scan_error_keys() {
        const KEYS: &[&str] = &[
            "scan_invalid_path",
            "scan_invalid_severities",
            "scan_unsupported_config_sections",
            // ADR-0042, ADR-0043: version rules named or "not checked".
            "scan_version_rules_read",
            "scan_version_rules_missing",
            "scan_version_rules_unreadable",
            // Ticket #124, then 2026-11-12: interactive creation of
            // audit.config.json (`project::config_wizard`).
            "config_prompt_languages",
            "config_prompt_input_closed",
            "config_prompt_write_error",
            "config_prompt_yes_answers",
            "config_wizard_intro",
            "config_wizard_scope_title",
            "config_wizard_scope_all",
            "config_wizard_scope_some",
            "config_wizard_scope_choice",
            "config_wizard_no_subfolders",
            "config_wizard_folders",
            "config_wizard_pick_include",
            "config_wizard_bad_numbers",
            "config_wizard_exclude_question",
            "config_wizard_no_exclude_candidates",
            "config_wizard_pick_exclude",
            "config_wizard_preview",
            "config_wizard_defaults_note",
            "config_wizard_write_question",
            "config_wizard_written",
            "config_wizard_declined",
        ];
        for lang in ["en", "fr", "es", "de"] {
            let v = load_script_locale(lang);
            for key in KEYS {
                let translated = t(&v, key);
                assert_ne!(
                    translated, *key,
                    "clé {key:?} manquante ou vide pour la langue {lang:?}"
                );
            }
        }
    }

    /// Completeness test (ticket #48): the keys added to translate the
    /// remaining progress of the `scan` path ("Analyzing...", final
    /// summary, phase labels) must exist, non-empty, in
    /// all 4 languages. Same principle as
    /// `test_all_locales_have_scan_error_keys` above.
    #[test]
    fn test_all_locales_have_scan_progress_keys() {
        const KEYS: &[&str] = &[
            "scan_analyzing",
            "scan_summary",
            "scan_phase_rules",
            "scan_phase_a",
            "scan_phase_b",
            "scan_phase_c_python",
            "scan_phase_c_java",
            "scan_phase_c_js",
            "scan_phase_c_php",
            "scan_phase_dependencies",
            "scan_phase_tests",
            "scan_phase_database",
        ];
        for lang in ["en", "fr", "es", "de"] {
            let v = load_script_locale(lang);
            for key in KEYS {
                let translated = t(&v, key);
                assert_ne!(
                    translated, *key,
                    "clé {key:?} manquante ou vide pour la langue {lang:?}"
                );
            }
        }
    }
}
