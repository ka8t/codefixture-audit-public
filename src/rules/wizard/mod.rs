//! The interactive rule wizard, shared by both builds since ADR-0057
//! (ticket #275): the private `create-rule` writes catalog rules with it,
//! the client's `custom-rules create` writes their own rules. Ported from
//! `Audit/sca/rule_wizard.py`; data-flow rules added.
//!
//! - [`prompt`]: the questions on a text console;
//! - [`form`]: the answers and the `.sca` text written from them;
//! - [`flow`]: the steps, parameterized by a [`WizardTarget`].

pub mod flow;
pub mod form;
pub mod prompt;

use std::path::{Path, PathBuf};

pub use flow::{KnownRule, KnownRules, WizardRule, WizardTarget, run_wizard};

/// Languages offered, with their display names (proper nouns, not
/// translated). TypeScript is covered by the JavaScript rules.
pub const LANGUAGES: [(&str, &str); 8] = [
    ("python", "Python"),
    ("javascript", "JavaScript / TypeScript"),
    ("java", "Java"),
    ("csharp", "C#"),
    ("php", "PHP"),
    ("html", "HTML"),
    ("yaml", "YAML / CI-CD"),
    ("dockerfile", "Dockerfile"),
];

/// The languages whose data flow the engine follows: the only ones a
/// data-flow rule is offered for.
pub const TAINT_LANGUAGES: [&str; 5] = ["python", "javascript", "java", "csharp", "php"];

/// Severities offered, highest first; their descriptions come from the
/// locale (`wizard_sev_<severity>`).
pub const SEVERITIES: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/// The file of rule `name` in `language` under `rules_dir`
/// (`<rules_dir>/<language>/<category>/<name>.sca`), whatever its category
/// — ported from `_find_existing_rule`, restricted to one language since
/// the same id exists in several languages.
pub fn find_existing_rule(rules_dir: &Path, language: &str, name: &str) -> Option<PathBuf> {
    let file = format!("{name}.sca");
    let mut categories: Vec<PathBuf> = std::fs::read_dir(rules_dir.join(language))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    categories.sort();
    categories
        .into_iter()
        .map(|dir| dir.join(&file))
        .find(|p| p.is_file())
}

/// Categories of `language` under `rules_dir`: its sub-folders, sorted.
pub fn folder_categories(rules_dir: &Path, language: &str) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(rules_dir.join(language))
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().to_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// The `.sca` files under `dir`, at any depth.
pub fn walk_sca_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_sca_files(&path));
        } else if path.extension().is_some_and(|e| e == "sca") {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// The compiled rules of `language` in the `.sca` files under `dir`, for
/// [`WizardTarget::known_rules`]: each with its path relative to `dir`.
/// Only the files a scan of `language` reads are opened
/// (`catalog::is_targeted_rule_path`): a folder of another language is
/// not this rule's concern. A file that cannot be read or does not
/// compile is named in [`KnownRules::problems`], in the language of
/// `script_locale`, as the scan names it.
pub fn folder_rules(
    dir: &Path,
    language: &str,
    delivered: bool,
    script_locale: &serde_json::Value,
) -> KnownRules {
    let mut known = KnownRules::default();
    let languages = [language.to_string()];
    for file in walk_sca_files(dir) {
        let rel = file
            .strip_prefix(dir)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if !crate::rules::catalog::is_targeted_rule_path(&rel, &languages) {
            continue;
        }
        let source = match std::fs::read_to_string(&file) {
            Ok(source) => source,
            Err(error) => {
                known.problems.push(format!("{}: {error}", file.display()));
                continue;
            }
        };
        let compiled =
            match crate::scan::parser::compile_sca_to_json(&source, &file.to_string_lossy()) {
                Ok(compiled) => compiled,
                Err(error) => {
                    known.problems.push(error.render(script_locale));
                    continue;
                }
            };
        known.rules.extend(
            compiled
                .into_iter()
                .filter(|rule| rule.get("language").and_then(|v| v.as_str()) == Some(language))
                .map(|json| KnownRule {
                    json,
                    place: rel.clone(),
                    delivered,
                }),
        );
    }
    known
}

#[cfg(test)]
mod tests {
    use super::form::{RuleFormData, RuleKind, SinkAnswer, SourceAnswer, build_sca_content};
    use super::*;
    use std::io::{Cursor, Write};

    fn tmp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-shared-wizard-{label}-{}",
            std::process::id()
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn texts(en: &str) -> [String; 4] {
        [en.to_string(), String::new(), String::new(), String::new()]
    }

    fn taint_form() -> RuleFormData {
        RuleFormData {
            lang: "python".to_string(),
            cat: "security".to_string(),
            sev: "HIGH".to_string(),
            kind: RuleKind::Taint,
            sources: vec![SourceAnswer {
                pattern: r"request\.args".to_string(),
                kind: "http".to_string(),
            }],
            sinks: vec![
                SinkAnswer {
                    pattern: r"\.execute\s*\(".to_string(),
                    argument: "0".to_string(),
                },
                SinkAnswer {
                    pattern: r"os\.system\s*\(".to_string(),
                    argument: String::new(),
                },
            ],
            sanitizers: vec![r"\bint\s*\(".to_string()],
            passthroughs: vec![r"\.strip\s*\(".to_string()],
            risk: texts("Injection."),
            solution: texts("Bind the value."),
            ..RuleFormData::default()
        }
    }

    /// Ticket #275: a data-flow rule is written with its four lists, and
    /// it compiles as one.
    #[test]
    fn test_a_data_flow_rule_is_written_and_compiles() {
        let content = build_sca_content("my_sqli", &taint_form());
        assert!(
            content.contains("  source  request\\.args  kind=http"),
            "{content}"
        );
        assert!(
            content.contains("  sink    \\.execute\\s*\\(  arg_index=0"),
            "{content}"
        );
        assert!(
            content.contains("  sink    os\\.system\\s*\\(\n"),
            "{content}"
        );
        assert!(content.contains("  sanitizer  \\bint\\s*\\("), "{content}");
        assert!(
            content.contains("  passthrough  \\.strip\\s*\\("),
            "{content}"
        );
        let rules = crate::scan::parser::compile_sca_to_json(&content, "r.sca").unwrap();
        assert_eq!(rules[0]["mode"], "taint");
        assert_eq!(rules[0]["sinks"].as_array().unwrap().len(), 2);
    }

    /// A written rule reads back as the answers that wrote it: pattern
    /// rules (ported test) and data-flow rules (ticket #275).
    #[test]
    fn test_load_existing_rule_roundtrip() {
        let dir = tmp_dir("load");
        let pattern = RuleFormData {
            lang: "java".to_string(),
            cat: "arch".to_string(),
            sev: "MEDIUM".to_string(),
            pattern: "foo\\(".to_string(),
            neutralizer: "bar".to_string(),
            risk: [
                "Risk EN".to_string(),
                "Risque FR".to_string(),
                String::new(),
                String::new(),
            ],
            solution: texts("Sol EN"),
            fix_before: "foo(x)\nfoo(y)".to_string(),
            fix_after: "safe(x)".to_string(),
            ..RuleFormData::default()
        };
        std::fs::write(dir.join("p.sca"), build_sca_content("p", &pattern)).unwrap();
        std::fs::write(dir.join("t.sca"), build_sca_content("t", &taint_form())).unwrap();
        let read_pattern = form::load_existing_rule(&dir.join("p.sca"));
        let read_taint = form::load_existing_rule(&dir.join("t.sca"));
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(read_pattern.kind, RuleKind::Pattern);
        assert_eq!(
            (read_pattern.lang.as_str(), read_pattern.cat.as_str()),
            ("java", "arch")
        );
        assert_eq!(read_pattern.sev, "MEDIUM");
        assert_eq!(read_pattern.pattern, "foo\\(");
        assert_eq!(read_pattern.neutralizer, "bar");
        assert_eq!(read_pattern.risk[..2], ["Risk EN", "Risque FR"]);
        assert_eq!(read_pattern.solution[0], "Sol EN");
        assert_eq!(read_pattern.fix_before, "foo(x)\nfoo(y)");
        assert_eq!(read_pattern.fix_after, "safe(x)");

        let expected = taint_form();
        assert_eq!(read_taint.kind, RuleKind::Taint);
        assert_eq!(read_taint.sources, expected.sources);
        assert_eq!(read_taint.sinks, expected.sinks);
        assert_eq!(read_taint.sanitizers, expected.sanitizers);
        assert_eq!(read_taint.passthroughs, expected.passthroughs);
    }

    #[test]
    fn test_find_existing_rule_by_language_and_name() {
        let dir = tmp_dir("find");
        std::fs::create_dir_all(dir.join("python/security")).unwrap();
        std::fs::create_dir_all(dir.join("java/security")).unwrap();
        std::fs::write(
            dir.join("python/security/my_rule.sca"),
            "rule my_rule\nend\n",
        )
        .unwrap();
        let found = find_existing_rule(&dir, "python", "my_rule");
        let other_language = find_existing_rule(&dir, "java", "my_rule");
        let missing = find_existing_rule(&dir, "python", "does_not_exist");
        let categories = folder_categories(&dir, "python");
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(found, Some(dir.join("python/security/my_rule.sca")));
        assert!(
            other_language.is_none(),
            "the same id in another language is another rule"
        );
        assert!(missing.is_none());
        assert_eq!(categories, ["security"]);
    }

    /// A client-like target: the valid categories, `known` as the other
    /// rules, no polish, nothing before the confirmation.
    fn run(dir: &Path, known: Vec<(Value, bool)>, input: &str) -> (Option<PathBuf>, String) {
        let locale = crate::i18n::load_script_locale("en");
        let categories = |_: &str| -> Result<Vec<String>, String> {
            Ok(crate::scan::parser::validator::VALID_CATEGORIES
                .iter()
                .map(|c| c.to_string())
                .collect())
        };
        let known_rules = |language: &str| -> KnownRules {
            let mut rules = folder_rules(dir, language, false, &locale);
            rules
                .rules
                .extend(known.iter().map(|(json, delivered)| KnownRule {
                    json: json.clone(),
                    place: "pack".to_string(),
                    delivered: *delivered,
                }));
            rules
        };
        let polish = |sca: &str| sca.to_string();
        let before_confirm = |_: &mut dyn Write, _: &WizardRule| -> std::io::Result<()> { Ok(()) };
        let after_write =
            |_: &mut dyn Write, _: &WizardRule, _: &Path, _: bool| -> std::io::Result<()> {
                Ok(())
            };
        let target = WizardTarget {
            rules_dir: dir,
            exists_key: "wizard_rule_exists_custom",
            categories: &categories,
            known_rules: &known_rules,
            polish: &polish,
            before_confirm: &before_confirm,
            after_write: &after_write,
        };
        let mut output = Vec::new();
        let result = run_wizard(
            &mut Cursor::new(input.as_bytes().to_vec()),
            &mut output,
            &locale,
            &target,
        )
        .unwrap();
        (result, String::from_utf8(output).unwrap())
    }

    use serde_json::{Value, json};

    /// Ticket #275: a data-flow rule created end to end — sources with
    /// their kind, sinks with their argument (an invalid one asked again),
    /// a sanitizer, no passthrough.
    #[test]
    fn test_wizard_creates_a_data_flow_rule() {
        let dir = tmp_dir("taint");
        // Language (python), name, category, severity, kind = taint;
        // source, its kind (default http), end of sources; sink,
        // argument "first" (invalid) then "all", end of sinks; one
        // sanitizer, end; no passthrough; risk, its translations,
        // solution, its translations, no benefit, no fix example; yes.
        let input = "\nmy_flow\n\n\n2\nrequest\\.args\n\n\n\\.execute\\s*\\(\nfirst\nall\n\n\\bint\\s*\\(\n\n\nInjection.\n\n\n\nBind it.\n\n\n\n\n\n\n";
        let (result, out) = run(&dir, Vec::new(), input);
        let content = result.as_ref().map(|p| std::fs::read_to_string(p).unwrap());
        std::fs::remove_dir_all(&dir).ok();
        let content = content.unwrap_or_else(|| panic!("{out}"));
        assert_eq!(result, Some(dir.join("python/security/my_flow.sca")));
        assert!(
            content.contains("source  request\\.args  kind=http"),
            "{content}"
        );
        assert!(
            content.contains("sink    \\.execute\\s*\\(  arg_index=all"),
            "{content}"
        );
        assert!(content.contains("sanitizer  \\bint\\s*\\("), "{content}");
        assert!(!content.contains("passthrough"), "{content}");
        assert!(
            out.contains("Enter a number from 0, 'all', or leave it empty"),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "Rule created: {}",
                dir.join("python/security/my_flow.sca").display()
            )),
            "{out}"
        );
    }

    fn delivered_eval() -> Value {
        json!({"id": "eval_usage", "language": "python",
            "patterns": [{"pattern": crate::scan::parser::compiler::text_to_regex("eval(")}]})
    }

    /// Ticket #275: a client rule named as a delivered rule of its
    /// language is announced as replacing it and asked for; a delivered
    /// rule already searching the same text (compared as the compiler
    /// writes it) is named before the author goes on.
    #[test]
    fn test_wizard_names_the_delivered_rule_replaced_and_the_same_pattern() {
        let dir = tmp_dir("delivered");
        // Language, the delivered name, "y" to replace it, category,
        // severity, kind pattern, text "eval(" (the same), "n" to the
        // overlap question.
        let input = "\neval_usage\ny\n\n\n\neval(\nn\n";
        let (result, out) = run(&dir, vec![(delivered_eval(), true)], input);
        std::fs::remove_dir_all(&dir).ok();
        assert!(result.is_none());
        assert!(
            out.contains("has this name (pack): yours would replace it in every analysis"),
            "{out}"
        );
        assert!(
            out.contains("on the lines both flag, the report keeps the delivered rule's finding"),
            "{out}"
        );
        assert!(out.contains("→ eval_usage  (pack)"), "{out}");
    }

    /// Ticket #275 (duplicates refused against the delivered rules): "no"
    /// to the replacement, the default, asks for another name; the rule
    /// is written under that one.
    #[test]
    fn test_wizard_asks_another_name_when_the_replacement_is_declined() {
        let dir = tmp_dir("declined");
        // Language, the delivered name, empty (default "no"), another
        // name, category, severity, kind, text, neutralizer, risk and its
        // translations, solution and its translations, no benefit, no fix
        // example; yes.
        let input =
            "\neval_usage\n\nmy_eval\n\n\n\nmy_eval_call(\n\nRisk.\n\n\n\nFix.\n\n\n\n\n\n\n";
        let (result, out) = run(&dir, vec![(delivered_eval(), true)], input);
        let written = dir.join("python/security/my_eval.sca");
        let replaced = dir.join("python/security/eval_usage.sca").exists();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(result, Some(written), "{out}");
        assert!(!replaced, "{out}");
        assert_eq!(
            out.matches("Rule name (snake_case): ").count(),
            2,
            "the name is asked again: {out}"
        );
    }

    /// A client rule that does not compile is named before the questions
    /// go on: it is not compared with the new rule, and the author knows
    /// why (Audit skipped it without a word).
    #[test]
    fn test_wizard_names_the_rules_it_cannot_read() {
        let dir = tmp_dir("broken");
        std::fs::create_dir_all(dir.join("python/security")).unwrap();
        std::fs::write(
            dir.join("python/security/broken.sca"),
            "rule broken\n  language  python\n  severity  NOPE\nend\n",
        )
        .unwrap();
        // A rule of another language is not this rule's concern.
        std::fs::create_dir_all(dir.join("java/security")).unwrap();
        std::fs::write(dir.join("java/security/other.sca"), "not a rule\n").unwrap();
        // A new rule, declined at the confirmation.
        let input = "\nx_rule\n\n\n\nfoo(\n\nRisk.\n\n\n\nFix.\n\n\n\n\n\nn\n";
        let (result, out) = run(&dir, Vec::new(), input);
        std::fs::remove_dir_all(&dir).ok();
        assert!(result.is_none(), "{out}");
        assert!(
            out.contains("These rules could not be read; yours is not compared with them:"),
            "{out}"
        );
        assert!(out.contains("broken.sca"), "{out}");
        assert!(!out.contains("other.sca"), "{out}");
    }

    /// The data flow is followed in five languages: a YAML rule is a
    /// pattern rule, without the question.
    #[test]
    fn test_wizard_asks_no_kind_for_a_language_without_data_flow() {
        let dir = tmp_dir("yaml");
        // Language 7 (yaml), name, category, severity, text, neutralizer,
        // risk and its translations, solution and its translations, no
        // benefit, no fix example; yes.
        let input = "7\nmy_yaml\n\n\nprivileged: true\n\nRisk.\n\n\n\nFix.\n\n\n\n\n\n\n";
        let (result, out) = run(&dir, Vec::new(), input);
        let content = result.as_ref().map(|p| std::fs::read_to_string(p).unwrap());
        std::fs::remove_dir_all(&dir).ok();
        assert!(!out.contains("Kind of rule"), "{out}");
        let content = content.unwrap_or_else(|| panic!("{out}"));
        assert!(content.contains("text  privileged: true"), "{content}");
    }

    /// Editing a data-flow rule: `-` removes an offered item, an empty
    /// answer keeps one.
    #[test]
    fn test_wizard_edit_removes_an_item_with_a_dash() {
        let dir = tmp_dir("edit");
        std::fs::create_dir_all(dir.join("python/security")).unwrap();
        let path = dir.join("python/security/my_sqli.sca");
        std::fs::write(&path, build_sca_content("my_sqli", &taint_form())).unwrap();
        // Language, name, yes to edit, category, severity, kind (taint
        // kept); source kept and its kind, end; first sink removed with
        // "-", second sink kept and its argument, end; sanitizer kept,
        // end; passthrough removed, end; texts kept; no benefit; fix
        // example kept empty; yes to the update.
        let input = "\nmy_sqli\n\n\n\n\n\n\n\n-\n\n\n\n\n\n-\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
        let (result, out) = run(&dir, Vec::new(), input);
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(result, Some(path), "{out}");
        assert!(out.contains("'-' removes it"), "{out}");
        assert!(!content.contains("\\.execute"), "{content}");
        assert!(content.contains("os\\.system"), "{content}");
        assert!(content.contains("sanitizer  \\bint"), "{content}");
        assert!(!content.contains("passthrough"), "{content}");
    }

    /// A rule completed by hand with what the wizard does not ask (here a
    /// `metadata` block and a sink's `kinds=`) is not rewritten from the
    /// answers, which would drop that part: the wizard says to edit the
    /// file by hand and asks another name; the file is unchanged.
    #[test]
    fn test_wizard_refuses_to_edit_a_rule_completed_by_hand() {
        let dir = tmp_dir("by-hand");
        std::fs::create_dir_all(dir.join("python/security")).unwrap();
        let path = dir.join("python/security/my_sqli.sca");
        let by_hand = build_sca_content("my_sqli", &taint_form())
            .replace(
                "  sink    os\\.system\\s*\\(\n",
                "  sink    os\\.system\\s*\\(  kinds=http\n",
            )
            .replace("  risk\n", "  metadata\n    cwe    CWE-89\n  end\n  risk\n");
        std::fs::write(&path, &by_hand).unwrap();
        // Language, the rule's name, yes to edit (refused), then a new
        // rule declined at the confirmation.
        let input = "\nmy_sqli\n\nother_rule\n\n\n\nfoo(\n\nRisk.\n\n\n\nFix.\n\n\n\n\n\nn\n";
        let (result, out) = run(&dir, Vec::new(), input);
        let after = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert!(result.is_none(), "{out}");
        assert!(
            out.contains("uses parts of the language the wizard does not ask for"),
            "{out}"
        );
        assert_eq!(after, by_hand);
        assert!(crate::scan::parser::compile_sca_to_json(&by_hand, "r.sca").is_ok());
    }

    /// Every choice the wizard offers has its label in the four console
    /// languages: a source kind added to the language (`database`, ticket
    /// www.codefixture.com#5) without a label would show its key.
    #[test]
    fn test_every_choice_has_a_label_in_each_language() {
        for lang in ["en", "fr", "es", "de"] {
            let locale = crate::i18n::load_script_locale(lang);
            let keys = crate::scan::parser::validator::VALID_SOURCE_KINDS
                .iter()
                .map(|k| format!("wizard_source_kind_{k}"))
                .chain(
                    crate::scan::parser::validator::VALID_CATEGORIES
                        .iter()
                        .map(|c| format!("wizard_cat_{c}")),
                )
                .chain(
                    SEVERITIES
                        .iter()
                        .map(|s| format!("wizard_sev_{}", s.to_lowercase())),
                );
            for key in keys {
                assert!(
                    locale.get(&key).and_then(|v| v.as_str()).is_some(),
                    "{lang}: {key}"
                );
            }
        }
    }
}
