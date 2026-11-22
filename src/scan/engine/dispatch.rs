//! Dispatches a JSON rule to the right executor — faithful port of
//! `Audit/sca/rule_engine.py::_dispatch_rule`. The mode is inferred from the
//! fields present in the compiled JSON, not from a single `mode` field.
#![allow(dead_code)]

use serde_json::Value;

use super::Finding;
use super::file_contains::{
    FileLocation, execute_file_contains_rule, matches as file_contains_matches,
};
use super::pattern::execute_regex_rule_on;
use super::rule_loader::{compile_file_contains_rule_from_json, compile_regex_rule_from_json};

#[derive(Debug, Clone, PartialEq)]
pub enum DispatchOutcome {
    /// Handled separately by the caller: needs the full tree-sitter
    /// tree, not a line-by-line scan (Step 5, not yet wired up).
    Ast,
    /// Handled separately by the caller: cross-file analysis
    /// (`dataflow::worklist::analyze` + `call_graph`).
    Taint,
    /// `hook` (custom code on the Python source side) — out of scope
    /// for the Rust port, no portable generic equivalent.
    Hook,
    /// The rule produced these findings (may be empty: a `file_contains`
    /// combo that doesn't match, or a rule that fails to compile).
    Findings(Vec<Finding>),
}

/// Python truthiness of a JSON value (`bool(x)`) — empty list/object,
/// `null`, empty string, `0`/`0.0` are falsy; everything else is truthy.
fn is_truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_none_or(|f| f != 0.0),
    }
}

/// Dispatches a JSON rule to the right executor. Mode inferred
/// automatically from the fields present (`patterns`/`file_contains`/
/// `hook`/`ast_patterns`/`mode`). `location` carries both the
/// project-relative and the on-disk path of the scanned file: the
/// `file_contains` conditions read one or the other (see `FileLocation`).
///
/// `syntax` is the language whose comment syntax the file is written in,
/// for the comment stripping of `pattern-not`/`with`: the rule's own
/// language for source code, another one for a configuration file read
/// by a code rule (XML comments for a `pom.xml` read by a Java rule,
/// ADR-0047). A deliberate addition to the Audit, which strips by rule
/// language only because it never reads such files.
pub fn dispatch_rule(
    rule_json: &Value,
    location: FileLocation<'_>,
    all_lines: &[(usize, String)],
    content: &str,
    syntax: &str,
) -> DispatchOutcome {
    run_prepared(
        &prepare_rule(rule_json),
        location,
        &FileText::new(all_lines, content, syntax),
    )
}

/// A rule compiled for the pattern pass ([`prepare_rule`]): what
/// [`dispatch_rule`] decides from the rule alone, with its regexes and
/// file conditions compiled.
///
/// The pattern pass prepares each rule once per scan and runs it on every
/// file of its language (ticket #248). It used to compile the rule's
/// regexes again for every file it read: on the 46,793 files of the
/// Juliet Java suite, most of the scan time went to recompiling the same
/// Java rules.
pub struct PreparedRule {
    kind: PreparedKind,
}

enum PreparedKind {
    Ast,
    Taint,
    Hook,
    /// `match` + `requires`: the patterns run only on a file the
    /// conditions accept. `None` for a part that does not compile: the
    /// rule then finds nothing, as before.
    RegexIfFile(
        Option<super::file_contains::CompiledFileContainsRule>,
        Option<super::pattern::CompiledRegexRule>,
    ),
    /// `match` alone.
    Regex(Option<super::pattern::CompiledRegexRule>),
    /// `requires` alone: one finding for the whole file.
    FileContains(Option<super::file_contains::CompiledFileContainsRule>),
    /// Neither: no finding.
    Nothing,
}

/// Compiles `rule_json` for the pattern pass, deciding its mode in the
/// order [`dispatch_rule`] always used.
pub fn prepare_rule(rule_json: &Value) -> PreparedRule {
    let mode = rule_json.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    let has_patterns = is_truthy(rule_json.get("patterns"));
    let has_fc = is_truthy(rule_json.get("file_contains"));
    let has_hook = is_truthy(rule_json.get("hook"));
    let has_ast = is_truthy(rule_json.get("ast_patterns"));
    let kind = if has_ast || mode == "ast" {
        // AST: handled separately (needs the tree, not line-by-line).
        PreparedKind::Ast
    } else if (mode == "taint" || mode == "regex+taint") && !has_patterns {
        // Taint: handled separately (cross-file).
        PreparedKind::Taint
    } else if has_hook {
        // Hook: direct execution on the Python side, out of scope here.
        PreparedKind::Hook
    } else if has_patterns && has_fc {
        PreparedKind::RegexIfFile(
            compile_file_contains_rule_from_json(rule_json),
            compile_regex_rule_from_json(rule_json),
        )
    } else if has_patterns {
        PreparedKind::Regex(compile_regex_rule_from_json(rule_json))
    } else if has_fc {
        PreparedKind::FileContains(compile_file_contains_rule_from_json(rule_json))
    } else {
        PreparedKind::Nothing
    };
    PreparedRule { kind }
}

/// The text of one file as the pattern rules read it: its numbered lines,
/// its content, and its lines without comments, stripped on first use and
/// shared by every rule of the file (ticket #248).
pub struct FileText<'a> {
    all_lines: &'a [(usize, String)],
    content: &'a str,
    /// The language whose comment syntax the file is written in: see
    /// [`dispatch_rule`].
    syntax: &'a str,
    without_comments: std::cell::OnceCell<Vec<(usize, String)>>,
}

impl<'a> FileText<'a> {
    pub fn new(all_lines: &'a [(usize, String)], content: &'a str, syntax: &'a str) -> Self {
        Self {
            all_lines,
            content,
            syntax,
            without_comments: std::cell::OnceCell::new(),
        }
    }

    /// The lines the `pattern-not`/`with` checks of `rule` read.
    fn clean_lines(&self, rule: &super::pattern::CompiledRegexRule) -> &[(usize, String)] {
        if super::pattern::keeps_comments(rule) {
            return self.all_lines;
        }
        self.without_comments
            .get_or_init(|| super::pattern::strip_comments_from_lines(self.all_lines, self.syntax))
    }
}

/// Runs a prepared rule on one file: the outcome [`dispatch_rule`] gives.
pub fn run_prepared(
    rule: &PreparedRule,
    location: FileLocation<'_>,
    file: &FileText<'_>,
) -> DispatchOutcome {
    let regex_findings = |compiled: &Option<super::pattern::CompiledRegexRule>| {
        compiled
            .as_ref()
            .map(|r| execute_regex_rule_on(r, file.all_lines, file.clean_lines(r)))
            .unwrap_or_default()
    };
    match &rule.kind {
        PreparedKind::Ast => DispatchOutcome::Ast,
        PreparedKind::Taint => DispatchOutcome::Taint,
        PreparedKind::Hook => DispatchOutcome::Hook,
        PreparedKind::RegexIfFile(conditions, regex) => {
            let accepted = conditions.as_ref().is_some_and(|fc| {
                file_contains_matches(
                    &fc.file_contains,
                    file.content,
                    Some(location),
                    file.all_lines.len(),
                )
            });
            if accepted {
                DispatchOutcome::Findings(regex_findings(regex))
            } else {
                DispatchOutcome::Findings(Vec::new())
            }
        }
        PreparedKind::Regex(regex) => DispatchOutcome::Findings(regex_findings(regex)),
        PreparedKind::FileContains(conditions) => DispatchOutcome::Findings(
            conditions
                .as_ref()
                .and_then(|r| execute_file_contains_rule(r, location, file.content, file.all_lines))
                .into_iter()
                .collect(),
        ),
        PreparedKind::Nothing => DispatchOutcome::Findings(Vec::new()),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The scanned file of these tests: `f.py` at the project root.
    fn f_py() -> FileLocation<'static> {
        FileLocation {
            absolute: std::path::Path::new("f.py"),
            relative: "f.py",
        }
    }

    fn lines(text: &str) -> Vec<(usize, String)> {
        text.lines()
            .enumerate()
            .map(|(i, l)| (i + 1, format!("{l}\n")))
            .collect()
    }

    #[test]
    fn test_dispatch_ast_mode_returns_ast_outcome() {
        let rule = json!({"id": "r", "mode": "ast", "ast_patterns": [{}]});
        let out = dispatch_rule(&rule, f_py(), &[], "", "python");
        assert_eq!(out, DispatchOutcome::Ast);
    }

    #[test]
    fn test_dispatch_ast_patterns_present_without_mode() {
        let rule = json!({"id": "r", "ast_patterns": [{"pattern": "x"}]});
        let out = dispatch_rule(&rule, f_py(), &[], "", "python");
        assert_eq!(out, DispatchOutcome::Ast);
    }

    #[test]
    fn test_dispatch_taint_mode_without_patterns_returns_taint() {
        let rule = json!({"id": "r", "mode": "taint", "sources": [{"pattern": "input"}], "sinks": [{"pattern": "eval"}]});
        let out = dispatch_rule(&rule, f_py(), &[], "", "python");
        assert_eq!(out, DispatchOutcome::Taint);
    }

    #[test]
    fn test_dispatch_regex_plus_taint_with_patterns_is_not_taint_outcome() {
        // mode "regex+taint" WITH patterns -> treated as regex here
        // (the taint side is handled separately elsewhere, on the
        // same JSON, cf. rule_engine.py which also routes this JSON to
        // the taint pipeline in parallel -- out of scope for this test).
        let rule = json!({
            "id": "r",
            "mode": "regex+taint",
            "patterns": [{"pattern": r"eval\(", "match": "line"}],
            "sources": [{"pattern": "input"}],
            "sinks": [{"pattern": "eval"}],
        });
        let out = dispatch_rule(
            &rule,
            f_py(),
            &lines("x = eval(y)\n"),
            "x = eval(y)\n",
            "python",
        );
        assert!(matches!(out, DispatchOutcome::Findings(_)));
    }

    /// Ticket #248: rules prepared once and run on one file through one
    /// `FileText` (the comments stripped once for all of them) find what
    /// each rule finds when it strips the file itself, for the rule that
    /// keeps the comments too, and for a file in another comment syntax.
    #[test]
    fn test_prepared_rules_share_the_stripped_lines() {
        let rules = [
            json!({"id": "eval_not_safe", "patterns": [{"pattern": r"eval\(", "match": "line", "pattern-not": "safe"}]}),
            json!({"id": "eval_with_todo", "patterns": [{"pattern": r"eval\(", "match": "file", "with": "TODO"}]}),
            json!({"id": "gha_version_comment_missing", "patterns": [{"pattern": r"eval\(", "match": "line", "with": "TODO"}]}),
            json!({"id": "near", "patterns": [{"pattern": r"open\(", "match": "context-2", "with": "close"}]}),
        ];
        for (content, syntax) in [
            (
                "x = eval(y)  # safe TODO\nopen(f)  # close\n/* close */ eval(z)\nf.close()\n",
                "python",
            ),
            (
                "x = eval(y); // safe TODO\nopen(f); /* close\n close */ eval(z);\nf.close();\n",
                "java",
            ),
            (
                "<!-- TODO eval( -->\neval(a) <!-- safe -->\nopen(f)\n<!-- close -->\n",
                "html",
            ),
        ] {
            let all_lines = lines(content);
            let file = FileText::new(&all_lines, content, syntax);
            for rule in &rules {
                let prepared = run_prepared(&prepare_rule(rule), f_py(), &file);
                let mut compiled = compile_regex_rule_from_json(rule).unwrap();
                compiled.language = syntax.to_string();
                let alone = super::super::pattern::execute_regex_rule(&compiled, &all_lines);
                assert_eq!(
                    prepared,
                    DispatchOutcome::Findings(alone),
                    "{} on {syntax}",
                    rule["id"]
                );
            }
        }
    }

    #[test]
    fn test_dispatch_hook_returns_hook_outcome() {
        let rule = json!({"id": "r", "hook": "some_custom_hook"});
        let out = dispatch_rule(&rule, f_py(), &[], "", "python");
        assert_eq!(out, DispatchOutcome::Hook);
    }

    #[test]
    fn test_dispatch_regex_only_produces_findings() {
        let rule = json!({"id": "eval_usage", "category": "Injection", "severity": "HIGH", "patterns": [{"pattern": r"eval\(", "match": "line"}]});
        let content = "x = eval(y)\n";
        let out = dispatch_rule(&rule, f_py(), &lines(content), content, "python");
        match out {
            DispatchOutcome::Findings(f) => assert_eq!(f.len(), 1),
            other => panic!("attendu Findings, eu {other:?}"),
        }
    }

    #[test]
    fn test_dispatch_file_contains_only_produces_finding() {
        let rule = json!({
            "id": "missing_x",
            "file_contains": {"has": [], "not_has": ["forbidden_word"], "scope": "file"},
        });
        let content = "safe content\n";
        let out = dispatch_rule(&rule, f_py(), &lines(content), content, "python");
        match out {
            DispatchOutcome::Findings(f) => assert_eq!(f.len(), 1),
            other => panic!("attendu Findings, eu {other:?}"),
        }
    }

    #[test]
    fn test_dispatch_combo_skipped_when_file_contains_does_not_match() {
        let rule = json!({
            "id": "r",
            "patterns": [{"pattern": r"eval\(", "match": "line"}],
            "file_contains": {"has": ["must_be_present_marker"], "not_has": [], "scope": "file"},
        });
        let content = "x = eval(y)\n"; // doesn't contain the required marker
        let out = dispatch_rule(&rule, f_py(), &lines(content), content, "python");
        match out {
            DispatchOutcome::Findings(f) => assert!(
                f.is_empty(),
                "file_contains ne matche pas -> regex jamais lancée"
            ),
            other => panic!("attendu Findings vide, eu {other:?}"),
        }
    }

    #[test]
    fn test_dispatch_combo_runs_regex_when_file_contains_matches() {
        let rule = json!({
            "id": "r",
            "patterns": [{"pattern": r"eval\(", "match": "line"}],
            "file_contains": {"has": ["must_be_present_marker"], "not_has": [], "scope": "file"},
        });
        let content = "must_be_present_marker\nx = eval(y)\n";
        let out = dispatch_rule(&rule, f_py(), &lines(content), content, "python");
        match out {
            DispatchOutcome::Findings(f) => assert_eq!(f.len(), 1),
            other => panic!("attendu Findings, eu {other:?}"),
        }
    }

    #[test]
    fn test_dispatch_neither_patterns_nor_fc_returns_empty_findings() {
        let rule = json!({"id": "r"});
        let out = dispatch_rule(&rule, f_py(), &[], "", "python");
        assert_eq!(out, DispatchOutcome::Findings(Vec::new()));
    }
}
