//! The test case skeleton of a client rule (ticket #276): when the wizard
//! writes a rule, one vulnerable file the rule must flag and one clean
//! file it must not, registered in the client's case registry
//! (`<rules folder>/cases/registry.json`, the catalog's format, see
//! `rules::cases`). `custom-rules test` then runs them.
//!
//! A skeleton is the rule's own fix example when the wizard was given one
//! (`fix_before` as the vulnerable case, `fix_after` as the clean one), so
//! that a rule written with an example is tested at once; otherwise a
//! comment asking for the code, in the console language, which fails the
//! vulnerable case until it is replaced: a case never passes by accident.
//!
//! Nothing the client wrote is replaced: a rule that already has a
//! vulnerable (or clean) case gets no new one, and a case file already on
//! disk is registered as it is. Audit had no skeleton: its
//! `--custom-rules-match` only listed the rules without fixtures.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::i18n::t;
use crate::rules::cases::{Case, Expect, read_registry, registry_text};
use crate::rules::wizard::form::RuleFormData;

/// Folder of the client's test cases, inside their rules folder: the
/// registry and the `vulnerable/` and `clean/` files it lists. The scan
/// never reads it: it only reads `.sca` files.
pub const CASES_FOLDER: &str = "cases";

/// The client's case registry inside `rules_dir`.
pub fn registry_path(rules_dir: &Path) -> PathBuf {
    rules_dir.join(CASES_FOLDER).join("registry.json")
}

/// Where a case of `language` goes in its temporary test project: a path
/// the scan reads as that language, as the catalog's cases do
/// (`rules/cases/registry.json`), so that the rule runs on it. A YAML
/// case sits where a CI pipeline does; a Dockerfile is found by its name.
pub fn case_target(language: &str) -> &'static str {
    match language {
        "python" => "src/app.py",
        "javascript" => "src/app.js",
        "java" => "src/App.java",
        "csharp" => "src/App.cs",
        "php" => "src/index.php",
        "html" => "src/index.html",
        "yaml" => "src/.github/workflows/ci.yml",
        "dockerfile" => "Dockerfile",
        _ => "src/app.txt",
    }
}

/// The extension of a case file of `language`, with its dot; none for a
/// Dockerfile, named `<rule>` like the catalog's.
fn case_extension(language: &str) -> &'static str {
    match language {
        "python" => ".py",
        "javascript" => ".js",
        "java" => ".java",
        "csharp" => ".cs",
        "php" => ".php",
        "html" => ".html",
        "yaml" => ".yml",
        _ => "",
    }
}

/// A one-line comment of `language` holding `text`.
fn comment(language: &str, text: &str) -> String {
    match language {
        "python" | "yaml" | "dockerfile" => format!("# {text}"),
        "html" => format!("<!-- {text} -->"),
        _ => format!("// {text}"),
    }
}

/// The content of a case file: the fix example when there is one, else a
/// comment asking for code (`placeholder_key`). A PHP file opens with
/// `<?php`, without which PHP code is plain text to the parser.
fn case_content(language: &str, code: &str, placeholder: &str) -> String {
    let body = if code.trim().is_empty() {
        comment(language, placeholder)
    } else {
        code.trim_end_matches('\n').to_string()
    };
    if language == "php" && !body.trim_start().starts_with("<?php") {
        format!("<?php\n{body}\n")
    } else {
        format!("{body}\n")
    }
}

/// One case of a skeleton.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkeletonCase {
    /// What the case expects.
    pub expect: Expect,
    /// The case file, written or found.
    pub file: PathBuf,
    /// The file is a comment to replace with code (no fix example given).
    pub placeholder: bool,
}

/// Adds the cases rule `language`/`rule` lacks to the client's registry
/// in `rules_dir`, with their files (see the module doc). Returns the
/// cases added, none when the rule has both already. `Err` names what
/// could not be done, in the console language: an unreadable registry is
/// never rewritten.
pub fn add_case_skeleton(
    rules_dir: &Path,
    language: &str,
    rule: &str,
    form: &RuleFormData,
    script_locale: &Value,
) -> Result<Vec<SkeletonCase>, String> {
    let registry_file = registry_path(rules_dir);
    let cases_dir = rules_dir.join(CASES_FOLDER);
    let mut cases = if registry_file.exists() {
        read_registry(&registry_file)
            .map_err(|error| error.render(script_locale))?
            .cases
    } else {
        Vec::new()
    };
    let has = |cases: &[(String, Case)], expect: Expect| {
        cases
            .iter()
            .any(|(_, c)| c.language == language && c.rule == rule && c.expect == expect)
    };
    let mut added = Vec::new();
    for (expect, kind, suffix, code, placeholder_key) in [
        (
            Expect::Detected,
            "vulnerable",
            "",
            form.fix_before.as_str(),
            "cases_skeleton_vulnerable",
        ),
        (
            Expect::Clean,
            "clean",
            "_clean",
            form.fix_after.as_str(),
            "cases_skeleton_clean",
        ),
    ] {
        if has(&cases, expect) {
            continue;
        }
        let rel = format!(
            "{kind}/{language}/{rule}{suffix}{}",
            case_extension(language)
        );
        let file = cases_dir.join(&rel);
        // A fix example is only used when both halves were given: the
        // wizard writes no `fix_after` without a `fix_before`.
        let example = if form.fix_before.is_empty() || form.fix_after.is_empty() {
            ""
        } else {
            code
        };
        let placeholder = example.trim().is_empty();
        if !file.exists() {
            let write = || -> std::io::Result<()> {
                std::fs::create_dir_all(file.parent().expect("<cases>/<kind>/<language>"))?;
                std::fs::write(
                    &file,
                    case_content(language, example, &t(script_locale, placeholder_key)),
                )
            };
            write().map_err(|error| format!("{}: {error}", file.display()))?;
        }
        let mut key = format!("{rule}_{language}{suffix}");
        // A key taken by another rule's case (a rule named like this one
        // plus `_clean`, say) gets a number rather than replacing it.
        let mut n = 2;
        while cases.iter().any(|(k, _)| *k == key) {
            key = format!("{rule}_{language}{suffix}_{n}");
            n += 1;
        }
        cases.push((
            key,
            Case {
                language: language.to_string(),
                rule: rule.to_string(),
                expect,
                file: rel,
                target: case_target(language).to_string(),
                lines: Vec::new(),
                extra: Vec::new(),
            },
        ));
        added.push(SkeletonCase {
            expect,
            file,
            placeholder,
        });
    }
    if !added.is_empty() {
        std::fs::create_dir_all(&cases_dir)
            .and_then(|()| std::fs::write(&registry_file, registry_text(&cases)))
            .map_err(|error| format!("{}: {error}", registry_file.display()))?;
    }
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::cases::{check_registry, run_cases};
    use std::collections::BTreeSet;

    fn tmp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-skeleton-{label}-{}",
            std::process::id()
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const RULE: &str = "rule my_eval\n  language  python\n  category  security\n  severity  HIGH\n  match\n    text  eval(\n  end\n  risk\n    en: Eval.\n  end\n  solution\n    en: No eval.\n  end\nend\n";

    fn rules_dir(label: &str) -> PathBuf {
        let dir = tmp_dir(label);
        std::fs::create_dir_all(dir.join("python/security")).unwrap();
        std::fs::write(dir.join("python/security/my_eval.sca"), RULE).unwrap();
        dir
    }

    /// Ticket #276: a rule written with a fix example gets its two cases
    /// from it, registered in the catalog's format; they pass at once.
    #[test]
    fn test_skeleton_from_the_fix_example_passes() {
        let dir = rules_dir("example");
        let en = crate::i18n::load_script_locale("en");
        let form = RuleFormData {
            fix_before: "eval(user_input)".to_string(),
            fix_after: "int(user_input)".to_string(),
            ..RuleFormData::default()
        };
        let added = add_case_skeleton(&dir, "python", "my_eval", &form, &en).unwrap();
        let registry = read_registry(&registry_path(&dir)).unwrap();
        let problems = check_registry(&registry, &dir);
        let outcomes = run_cases(&registry, &dir, &BTreeSet::new());
        let vulnerable =
            std::fs::read_to_string(dir.join("cases/vulnerable/python/my_eval.py")).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(added.len(), 2);
        assert!(added.iter().all(|c| !c.placeholder));
        assert_eq!(vulnerable, "eval(user_input)\n");
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|o| o.passed), "{outcomes:?}");
        let keys: Vec<&str> = registry.cases.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["my_eval_python", "my_eval_python_clean"]);
    }

    /// Without a fix example, the cases are comments in the console
    /// language: the vulnerable one fails until it is replaced, never a
    /// case that passes by accident. A second call adds nothing.
    #[test]
    fn test_placeholder_skeleton_fails_until_completed_and_is_added_once() {
        let dir = rules_dir("placeholder");
        let fr = crate::i18n::load_script_locale("fr");
        let form = RuleFormData::default();
        let added = add_case_skeleton(&dir, "python", "my_eval", &form, &fr).unwrap();
        let again = add_case_skeleton(&dir, "python", "my_eval", &form, &fr).unwrap();
        let registry = read_registry(&registry_path(&dir)).unwrap();
        let outcomes = run_cases(&registry, &dir, &BTreeSet::new());
        let clean =
            std::fs::read_to_string(dir.join("cases/clean/python/my_eval_clean.py")).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert!(added.iter().all(|c| c.placeholder));
        assert!(again.is_empty());
        assert_eq!(registry.cases.len(), 2);
        assert!(clean.starts_with("# "), "{clean}");
        assert!(clean.contains("Remplacez"), "{clean}");
        let failed: Vec<Expect> = outcomes
            .iter()
            .filter(|o| !o.passed)
            .map(|o| o.expect)
            .collect();
        assert_eq!(failed, [Expect::Detected]);
    }

    /// A registry the client broke is never rewritten: the skeleton says
    /// why it was not added.
    #[test]
    fn test_skeleton_refuses_an_invalid_registry() {
        let dir = rules_dir("invalid");
        std::fs::create_dir_all(dir.join("cases")).unwrap();
        std::fs::write(registry_path(&dir), "{ not json").unwrap();
        let en = crate::i18n::load_script_locale("en");
        let error = add_case_skeleton(&dir, "python", "my_eval", &RuleFormData::default(), &en)
            .unwrap_err();
        let kept = std::fs::read_to_string(registry_path(&dir)).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert!(error.contains("registry.json"), "{error}");
        assert_eq!(kept, "{ not json");
    }

    /// Each language gets a file the scan reads as that language, and PHP
    /// code its opening tag.
    #[test]
    fn test_case_files_are_read_as_their_language() {
        assert_eq!(case_content("php", "eval($x);", "x"), "<?php\neval($x);\n");
        assert_eq!(case_content("html", "", "Fill me"), "<!-- Fill me -->\n");
        assert_eq!(case_target("dockerfile"), "Dockerfile");
        assert_eq!(case_extension("dockerfile"), "");
        for language in crate::rules::catalog::RULE_LANGUAGES {
            assert_ne!(case_target(language), "src/app.txt", "{language}");
        }
    }
}
