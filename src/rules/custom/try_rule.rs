//! One client rule run on a project, to tune it (`custom-rules try`,
//! ticket #276): every line it flags, without a report or a history. The
//! delivered rules of its language run beside it, so that the lines where
//! it duplicates one of them, whose findings the report keeps, are named
//! (ADR-0064). Port of `Audit/sca/rule_tester.py` (`--test-rule`, never
//! wired to Audit's command line), with these deliberate deviations:
//!
//! - the rule runs through the real engine (`run_scan`, the rule as a
//!   client rule beside the delivered pack), so data-flow rules, `requires` conditions and
//!   comment removal behave as in a scan; Audit re-implemented the `match`
//!   loop by hand and ran no data flow;
//! - the rule is named `<language>/<rule>`, or by its name alone when only
//!   one language has it: the same name exists in several languages;
//! - the rule is read from the client rules folder, not `audit-rules/` in
//!   the project.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::rules::cases::catalog_rule_file;
use crate::rules::catalog::RULE_LANGUAGES;
use crate::scan::orchestrator::{ScanConfig, ScanReport, run_scan};

/// A client rule found in the rules folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRule {
    /// Its language folder.
    pub language: String,
    /// Its name (the file name).
    pub name: String,
    /// Its file, `<folder>/<language>/<category>/<name>.sca`.
    pub file: PathBuf,
}

/// Why a rule given to `custom-rules try` was not found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleLookupError {
    /// No rule of that name (in that language, when one was given); the
    /// rules of the folder, as `<language>/<rule>`, sorted.
    NotFound { available: Vec<String> },
    /// The name alone exists in several languages, sorted.
    Ambiguous { languages: Vec<String> },
}

/// Finds the rule `spec` (`<language>/<rule>` or `<rule>`) in the client
/// rules folder `rules_dir`.
pub fn find_client_rule(rules_dir: &Path, spec: &str) -> Result<ClientRule, RuleLookupError> {
    let (languages, name): (Vec<&str>, &str) = match spec.split_once('/') {
        Some((language, name)) => (vec![language], name),
        None => (RULE_LANGUAGES.to_vec(), spec),
    };
    let found: Vec<ClientRule> = languages
        .into_iter()
        .filter_map(|language| {
            catalog_rule_file(rules_dir, language, name).map(|file| ClientRule {
                language: language.to_string(),
                name: name.to_string(),
                file,
            })
        })
        .collect();
    match found.len() {
        1 => Ok(found.into_iter().next().expect("one rule")),
        0 => Err(RuleLookupError::NotFound {
            available: available_rules(rules_dir),
        }),
        _ => Err(RuleLookupError::Ambiguous {
            languages: found.into_iter().map(|rule| rule.language).collect(),
        }),
    }
}

/// Every rule of the client folder, as `<language>/<rule>`, sorted.
fn available_rules(rules_dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for language in RULE_LANGUAGES {
        for category in crate::rules::wizard::folder_categories(rules_dir, language) {
            let Ok(entries) = std::fs::read_dir(rules_dir.join(language).join(category)) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "sca")
                    && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                {
                    out.push(format!("{language}/{stem}"));
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Distinct temporary catalogs for runs in parallel (tests).
static TRY_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Runs `rule` on the project of `base` (its root, include and exclude
/// paths, limits and language), and returns the scan report; its
/// `rule_errors` say why the rule did not run. The rule is copied into a
/// temporary folder of its own, removed afterwards: the client's folder is
/// never read as a whole, so another rule of theirs that does not compile
/// does not stop this one.
///
/// With `pack`, the delivered rules of the rule's language run too, the
/// rule as a client rule beside them (epic #278): the report's findings
/// then hold the delivered ones as well, and its
/// `custom_rule_duplicates` the lines where the rule flags what a
/// delivered rule flags, whose findings the report keeps. The caller keeps
/// the rule's own findings. Without `pack`, the rule runs alone, as the
/// catalog.
pub fn try_rule(
    rule: &ClientRule,
    pack: Option<&Path>,
    base: ScanConfig,
) -> std::io::Result<ScanReport> {
    let category = rule
        .file
        .parent()
        .and_then(|p| p.file_name())
        .expect("<language>/<category>/<rule>.sca");
    let work = std::env::temp_dir().join(format!(
        "codefixture-audit-try-{}-{}",
        std::process::id(),
        TRY_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let rules = work.join("rules");
    let rule_dir = rules.join(&rule.language).join(category);
    let (rules_path, custom_rules_dir) = match pack {
        Some(pack) => (pack.to_path_buf(), Some(rules.clone())),
        None => (rules.clone(), None),
    };
    let result = std::fs::create_dir_all(&rule_dir)
        .and_then(|()| {
            std::fs::copy(&rule.file, rule_dir.join(format!("{}.sca", rule.name))).map(|_| ())
        })
        .map(|()| {
            run_scan(&ScanConfig {
                rules_path,
                target_languages: Some(vec![rule.language.clone()]),
                only_target_language_files: true,
                custom_rules_dir,
                ..base
            })
        });
    let _ = std::fs::remove_dir_all(&work);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "codefixture-audit-try-test-{label}-{}",
            std::process::id()
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const RULE: &str = "rule my_eval\n  language  python\n  category  security\n  severity  HIGH\n  match\n    text  eval(\n  end\n  risk\n    en: Eval.\n  end\n  solution\n    en: No eval.\n  end\nend\n";

    /// Ticket #276: the rule is found by `<language>/<rule>` or by its
    /// name alone, an unknown name lists the folder's rules, a name of
    /// two languages asks for the language.
    #[test]
    fn test_find_client_rule() {
        let dir = tmp_dir("find");
        for language in ["python", "javascript"] {
            std::fs::create_dir_all(dir.join(language).join("security")).unwrap();
            std::fs::write(dir.join(language).join("security/shared.sca"), RULE).unwrap();
        }
        std::fs::write(dir.join("python/security/my_eval.sca"), RULE).unwrap();
        let by_name = find_client_rule(&dir, "my_eval");
        let by_path = find_client_rule(&dir, "javascript/shared");
        let ambiguous = find_client_rule(&dir, "shared");
        let missing = find_client_rule(&dir, "java/my_eval");
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(by_name.unwrap().language, "python");
        assert_eq!(by_path.unwrap().language, "javascript");
        assert_eq!(
            ambiguous.unwrap_err(),
            RuleLookupError::Ambiguous {
                languages: vec!["javascript".into(), "python".into()]
            }
        );
        assert_eq!(
            missing.unwrap_err(),
            RuleLookupError::NotFound {
                available: vec![
                    "javascript/shared".into(),
                    "python/my_eval".into(),
                    "python/shared".into()
                ]
            }
        );
    }

    /// Ticket #276: only the rule tried runs, on the files of its
    /// language; another rule of the folder, even broken, plays no part.
    #[test]
    fn test_try_rule_runs_the_rule_alone() {
        let dir = tmp_dir("run");
        let rules = dir.join("rules");
        std::fs::create_dir_all(rules.join("python/security")).unwrap();
        std::fs::write(rules.join("python/security/my_eval.sca"), RULE).unwrap();
        std::fs::write(
            rules.join("python/security/broken.sca"),
            "rule broken\nend\n",
        )
        .unwrap();
        let project = dir.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("a.py"), "x = 1\neval(x)\n").unwrap();
        std::fs::write(project.join("b.js"), "eval(x)\n").unwrap();
        let rule = find_client_rule(&rules, "my_eval").unwrap();
        let report = try_rule(
            &rule,
            None,
            ScanConfig {
                root: project,
                ..ScanConfig::default()
            },
        )
        .unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert!(report.rule_errors.is_empty(), "{:?}", report.rule_errors);
        let found: Vec<(String, usize)> = report
            .findings
            .iter()
            .map(|f| (f.file.clone(), f.line))
            .collect();
        assert_eq!(found, [("a.py".to_string(), 2)]);
    }
}
