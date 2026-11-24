//! The client's rule wizard, `custom-rules create` (ADR-0057, ticket
//! #275): the shared wizard (`rules::wizard`) writing into the client's
//! rules folder, `<folder>/<language>/<category>/<rule>.sca`, the folder
//! every scan reads them from.
//!
//! What the client's target gives the shared wizard, against the
//! catalog's (`create-rule`, private):
//!
//! - every category of the rule language (`VALID_CATEGORIES`), not the
//!   folders that happen to exist: a client's folder starts empty;
//! - the delivered rules of the language (the pack the scan reads) and the
//!   client's own as the rules a new one is compared with, so that a name
//!   or a text already delivered is seen before the rule is written;
//! - no spelling pass and no measure on reference projects: those belong
//!   to the catalog;
//! - once the rule is written, the skeleton of its test cases
//!   (`skeleton`, ticket #276) and the commands that run them.
//!
//! Lives in the library rather than in `main.rs` so that a test drives the
//! very wizard the command runs, with its answers in a buffer.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::i18n::t;
use crate::rules::catalog::{RuleOrigin, load_rules};
use crate::rules::wizard::{KnownRule, KnownRules, WizardRule, WizardTarget, folder_rules};

/// Runs the wizard for the client: the questions on `reader`/`writer`, the
/// rule written under `rules_dir`, compared with the delivered rules of
/// `pack` (a rule pack, or a folder of `.sca` files in the private build)
/// and with the client's own. Returns the path of the written file, or
/// `None` when the client declined or the rule did not compile (the
/// wizard has said why; nothing is written). End of input is an
/// `UnexpectedEof` error, nothing written.
pub fn run_client_wizard<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    script_locale: &Value,
    rules_dir: &Path,
    pack: &Path,
) -> io::Result<Option<PathBuf>> {
    let categories = |_: &str| -> Result<Vec<String>, String> {
        Ok(crate::scan::parser::validator::VALID_CATEGORIES
            .iter()
            .map(|category| category.to_string())
            .collect())
    };
    let known_rules = |language: &str| -> KnownRules {
        let mut known = delivered_rules(pack, language, script_locale);
        let own = folder_rules(rules_dir, language, false, script_locale);
        known.rules.extend(own.rules);
        known.problems.extend(own.problems);
        known
    };
    let polish = |sca: &str| sca.to_string();
    let before_confirm = |_: &mut dyn Write, _: &WizardRule| -> io::Result<()> { Ok(()) };
    let after_write =
        |writer: &mut dyn Write, rule: &WizardRule, _: &Path, _: bool| -> io::Result<()> {
            next_steps(writer, script_locale, rules_dir, rule)
        };
    let target = WizardTarget {
        rules_dir,
        exists_key: "wizard_rule_exists_custom",
        categories: &categories,
        known_rules: &known_rules,
        polish: &polish,
        before_confirm: &before_confirm,
        after_write: &after_write,
    };
    crate::rules::wizard::run_wizard(reader, writer, script_locale, &target)
}

/// The compiled rules of `language` in the delivered `pack`, marked
/// `delivered`. A pack that cannot be opened, or one of its files that
/// does not compile, is a problem named in the console language, as the
/// scan names it: the wizard then compares with what could be read.
fn delivered_rules(pack: &Path, language: &str, script_locale: &Value) -> KnownRules {
    let loaded = load_rules(pack, &[language.to_string()], RuleOrigin::Builtin);
    let mut known = KnownRules::default();
    for (path, error) in &loaded.errors {
        known.problems.push(format!(
            "{}: {}",
            path.display(),
            error.render(script_locale)
        ));
    }
    for file in &loaded.files {
        match crate::scan::parser::compile_sca_to_json(&file.content, &file.source_name) {
            Ok(compiled) => known.rules.extend(
                compiled
                    .into_iter()
                    .filter(|rule| rule.get("language").and_then(|v| v.as_str()) == Some(language))
                    .map(|json| KnownRule {
                        json,
                        place: file.rel_path.clone(),
                        delivered: true,
                    }),
            ),
            Err(error) => known.problems.push(error.render(script_locale)),
        }
    }
    known
}

/// Once the rule is written: its test case skeleton (ticket #276, see
/// `skeleton`), then what to do next: complete and run the cases, try the
/// rule on a project, and that every scan now runs it. A skeleton that
/// could not be added is said, the rule itself being written.
fn next_steps(
    writer: &mut dyn Write,
    script_locale: &Value,
    rules_dir: &Path,
    rule: &WizardRule,
) -> io::Result<()> {
    let say = |key: &str| t(script_locale, key);
    let registry = super::skeleton::registry_path(rules_dir)
        .display()
        .to_string();
    match super::skeleton::add_case_skeleton(
        rules_dir,
        rule.language,
        rule.name,
        rule.form,
        script_locale,
    ) {
        Ok(added) if added.is_empty() => writeln!(
            writer,
            "\n  {}",
            say("wizard_next_case_kept").replace("{registry}", &registry)
        )?,
        Ok(added) => {
            writeln!(
                writer,
                "\n  {}",
                say("wizard_next_cases").replace("{registry}", &registry)
            )?;
            for case in added {
                let key = match case.expect {
                    crate::rules::cases::Expect::Detected => "wizard_next_case_vulnerable",
                    crate::rules::cases::Expect::Clean => "wizard_next_case_clean",
                };
                let file = case.file.display().to_string();
                let line = say(key).replace("{file}", &file);
                if case.placeholder {
                    writeln!(writer, "    {line} {}", say("wizard_next_case_to_complete"))?;
                } else {
                    writeln!(writer, "    {line}")?;
                }
            }
        }
        Err(error) => writeln!(
            writer,
            "\n  {}",
            say("wizard_skeleton_error").replace("{error}", &error)
        )?,
    }
    let id = format!("{}/{}", rule.language, rule.name);
    writeln!(writer, "\n  {}", say("wizard_next_steps"))?;
    writeln!(
        writer,
        "    {}",
        say("wizard_next_test").replace("{rule}", &id)
    )?;
    writeln!(
        writer,
        "    {}",
        say("wizard_next_try").replace("{rule}", &id)
    )?;
    writeln!(writer, "    {}", say("wizard_next_scan"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn tmp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-client-wizard-{label}-{}",
            std::process::id()
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const DELIVERED: &str = "rule eval_usage\n  language  python\n  category  security\n  severity  HIGH\n  match\n    text  eval(\n  end\n  risk\n    en: Eval.\n  end\n  solution\n    en: No eval.\n  end\nend\n";

    /// Ticket #275: the client's wizard compares a new rule with the
    /// delivered rules of its language (here a folder standing for the
    /// pack, which `load_rules` reads alike) and writes it into the
    /// client's folder, never next to the delivered ones; a delivered file
    /// that does not compile is named.
    #[test]
    fn test_client_wizard_writes_into_the_client_folder_and_compares_with_the_pack() {
        let dir = tmp_dir("pack");
        let pack = dir.join("pack");
        std::fs::create_dir_all(pack.join("python/security")).unwrap();
        std::fs::write(pack.join("python/security/eval_usage.sca"), DELIVERED).unwrap();
        std::fs::write(
            pack.join("python/security/broken.sca"),
            "rule broken\nend\n",
        )
        .unwrap();
        let client = dir.join("client");
        let en = crate::i18n::load_script_locale("en");
        // Language, name, category 8 (dependencies, offered although the
        // client folder is empty), severity, kind, the delivered text
        // ("y" to go on), neutralizer, risk and its translations,
        // solution and its translations, no benefit, no fix example; yes.
        let input = "\nmy_eval\n8\n\n\neval(\ny\n\nRisk.\n\n\n\nFix.\n\n\n\n\n\n\n";
        let mut output = Vec::new();
        let result = run_client_wizard(
            &mut Cursor::new(input.as_bytes().to_vec()),
            &mut output,
            &en,
            &client,
            &pack,
        )
        .unwrap();
        let out = String::from_utf8(output).unwrap();
        let written = client.join("python/dependencies/my_eval.sca");
        let exists = written.is_file();
        let registry = std::fs::read_to_string(client.join("cases/registry.json"));
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(result, Some(written), "{out}");
        assert!(exists);
        assert!(
            out.contains("→ eval_usage  (python/security/eval_usage.sca)"),
            "{out}"
        );
        assert!(out.contains("broken.sca"), "{out}");
        assert!(out.contains("Every analysis now runs it"), "{out}");
        // Ticket #276: the skeleton of its cases, to complete (no fix
        // example was given), and the commands that run them.
        assert!(registry.unwrap().contains("\"my_eval_python_clean\""));
        assert_eq!(
            out.matches("(to complete: replace the comment with code)")
                .count(),
            2,
            "{out}"
        );
        assert!(
            out.contains("codefixture-audit custom-rules test python/my_eval"),
            "{out}"
        );
        assert!(
            out.contains("codefixture-audit custom-rules try python/my_eval <project>"),
            "{out}"
        );
    }
}
