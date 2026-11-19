//! `file_contains` executor — faithful port of
//! `Audit/sca/executors/file_check.py`.
//!
//! Two uses, as on the Python side: `matches()` (a predicate, usable
//! as a pre-filter for a `match` + `requires` combo) and
//! `execute_file_contains_rule()` (produces a file-level
//! finding, line 1, if the conditions are met).

use super::{FileScope, Finding};
use fancy_regex::Regex;
use std::path::Path;

/// Already-compiled conditions — mirrors `_compile_rule_patterns` for
/// the `file_contains` subset.
pub struct FileContainsCondition {
    /// ALL must match.
    pub has: Vec<Regex>,
    /// NONE may match.
    pub not_has: Vec<Regex>,
    pub min_lines: i64,
    pub path_contains: Vec<String>,
    /// "Governance" file names whose presence (walking up the
    /// directory tree from the scanned file's folder, up to 5
    /// levels) suppresses the finding.
    pub not_path_has_file: Vec<String>,
}

pub struct CompiledFileContainsRule {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub confidence: i64,
    pub file_contains: FileContainsCondition,
}

/// Where the scanned file is, in the two forms the conditions need.
///
/// The two paths answer different questions, so they travel together and
/// each condition names the one it reads:
/// - `relative` (to the project root, `/` separators) says *what* the file
///   is inside the project: `path_contains` reads it;
/// - `absolute` says *where* it is on disk: `not_path_has_file` walks up
///   the real directories from it.
#[derive(Debug, Clone, Copy)]
pub struct FileLocation<'a> {
    /// Path on disk, used for the governance-file walk.
    pub absolute: &'a Path,
    /// Path from the project root, `/`-separated, used for `path_contains`.
    pub relative: &'a str,
}

fn is_match(re: &Regex, text: &str) -> bool {
    re.is_match(text).unwrap_or(false)
}

/// Checks whether a file's content satisfies the `file_contains`
/// conditions. `location`, when supplied, is used for `path_contains`
/// (against the project-relative path) and `not_path_has_file` (real disk
/// I/O from the absolute path, as on the Python side).
///
/// Deliberate deviation from `file_check.py::matches`: Python documents
/// "the relative path must contain the segment" but is handed the path as
/// collected, which is absolute when the scan target is. A project stored
/// under a folder named `vendor` or `external` then matched the
/// third-party-code rule on every file, and moving the project changed the
/// results. Here `path_contains` only ever sees the path inside the
/// project, which is what the rules mean.
pub fn matches(
    fc: &FileContainsCondition,
    content: &str,
    location: Option<FileLocation<'_>>,
    line_count: usize,
) -> bool {
    for pat in &fc.has {
        if !is_match(pat, content) {
            return false;
        }
    }
    for pat in &fc.not_has {
        if is_match(pat, content) {
            return false;
        }
    }

    if fc.min_lines > 0 && (line_count as i64) < fc.min_lines {
        return false;
    }

    if !fc.path_contains.is_empty()
        && let Some(loc) = location
    {
        // Backslashes still normalised: a caller on Windows may hand a
        // relative path built with native separators.
        let relative_lower = loc.relative.to_lowercase().replace('\\', "/");
        if !fc
            .path_contains
            .iter()
            .any(|seg| relative_lower.contains(&seg.to_lowercase()))
        {
            return false;
        }
    }

    if !fc.not_path_has_file.is_empty()
        && let Some(loc) = location
        && governance_file_found(loc.absolute, &fc.not_path_has_file)
    {
        return false; // governance file present → no finding
    }

    true
}

/// Which of `names` the governance check of `filepath` finds, as one
/// `0`/`1` per name: the only thing outside the file that a pattern rule
/// reads, hence part of the file's key in the scan cache (`scan_cache`).
pub fn governance_fingerprint(filepath: &Path, names: &[String]) -> String {
    names
        .iter()
        .map(|n| {
            if governance_file_found(filepath, std::slice::from_ref(n)) {
                '1'
            } else {
                '0'
            }
        })
        .collect()
}

/// Walks up the directory tree from `filepath`'s folder (up to 5
/// levels) looking for one of the `check_files` — mirrors the
/// Python loop, with an identical anti-traversal guard (rejects any name
/// containing `..` or a path separator: those aren't plain
/// file names).
fn governance_file_found(filepath: &Path, check_files: &[String]) -> bool {
    // Computed once, reused for each check_file (no
    // recomputing filepath.parent() inside the loop).
    let Some(dir) = filepath.parent() else {
        return false;
    };

    for check_file in check_files {
        if check_file.contains("..") || check_file.contains('/') || check_file.contains('\\') {
            continue;
        }
        let mut current = dir.to_path_buf();
        for _ in 0..5 {
            if current.join(check_file).exists() {
                return true;
            }
            match current.parent() {
                Some(parent) if parent != current => current = parent.to_path_buf(),
                _ => break,
            }
        }
    }
    false
}

/// Produces a file-level finding (line 1, `file_contains` convention) if
/// the conditions are met — mirrors `execute()` (file_check.py).
pub fn execute_file_contains_rule(
    rule: &CompiledFileContainsRule,
    location: FileLocation<'_>,
    content: &str,
    all_lines: &[(usize, String)],
) -> Option<Finding> {
    if !matches(
        &rule.file_contains,
        content,
        Some(location),
        all_lines.len(),
    ) {
        return None;
    }

    let code = all_lines
        .iter()
        .find(|(_, text)| !text.trim().is_empty())
        .map(|(_, text)| text.clone())
        .unwrap_or_default();

    Some(Finding {
        rule_id: rule.id.clone(),
        category: rule.category.to_uppercase(),
        severity: rule.severity.clone(),
        line: 1,
        code,
        // A file-level condition points at no spot in the line.
        column: 0,
        confidence: rule.confidence,
        // Deliberate deviation from `file_check.py::execute`, which only
        // stores line 1: the report then showed the first line as the
        // detected code and `file:1` as the place to fix, and readers took
        // the docstring for the fault (ticket #214). The scope says the
        // finding is about the whole file, with what was measured.
        file_scope: Some(FileScope {
            line_count: all_lines.len(),
            min_lines: usize::try_from(rule.file_contains.min_lines)
                .ok()
                .filter(|&n| n > 0),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_condition() -> FileContainsCondition {
        FileContainsCondition {
            has: vec![],
            not_has: vec![],
            min_lines: 0,
            path_contains: vec![],
            not_path_has_file: vec![],
        }
    }

    #[test]
    fn test_has_all_must_match() {
        let mut fc = empty_condition();
        fc.has = vec![Regex::new("flask").unwrap(), Regex::new("import").unwrap()];
        assert!(matches(&fc, "import flask", None, 1));
        assert!(!matches(&fc, "import django", None, 1));
    }

    #[test]
    fn test_not_has_none_must_match() {
        let mut fc = empty_condition();
        fc.not_has = vec![Regex::new("CSRFProtect").unwrap()];
        assert!(matches(&fc, "app = Flask(__name__)", None, 1));
        assert!(!matches(&fc, "from flask_wtf import CSRFProtect", None, 1));
    }

    #[test]
    fn test_min_lines_threshold() {
        let mut fc = empty_condition();
        fc.min_lines = 10;
        assert!(!matches(&fc, "x", None, 5));
        assert!(matches(&fc, "x", None, 10));
        assert!(matches(&fc, "x", None, 11));
    }

    /// Location whose absolute and relative paths are the same string —
    /// enough for the conditions that don't touch the disk.
    fn at(path: &str) -> Option<FileLocation<'_>> {
        Some(FileLocation {
            absolute: Path::new(path),
            relative: path,
        })
    }

    #[test]
    fn test_path_contains_case_insensitive_and_backslash_normalized() {
        let mut fc = empty_condition();
        fc.path_contains = vec!["Migrations".to_string()];
        assert!(matches(&fc, "x", at(r"src\migrations\0001.py"), 1));
        assert!(!matches(&fc, "x", at("src/models/user.py"), 1));
    }

    #[test]
    fn test_path_contains_ignores_the_folders_above_the_project() {
        // The project itself lives under a folder named `external`: only
        // the path inside the project counts, so its own code is not
        // taken for third-party code.
        let mut fc = empty_condition();
        fc.path_contains = vec!["external/".to_string()];
        let inside_own_code = FileLocation {
            absolute: Path::new("/home/dev/external/shop/src/app.py"),
            relative: "src/app.py",
        };
        assert!(!matches(&fc, "x", Some(inside_own_code), 1));

        let inside_vendored_code = FileLocation {
            absolute: Path::new("/home/dev/shop/external/lib/util.py"),
            relative: "external/lib/util.py",
        };
        assert!(matches(&fc, "x", Some(inside_vendored_code), 1));
    }

    #[test]
    fn test_not_path_has_file_walks_up_from_the_absolute_path() {
        // The governance file sits next to the scanned file on disk; the
        // relative path alone could not find it.
        let dir = std::env::temp_dir().join(format!("fc_governance_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("governance.txt"), b"").unwrap();
        let file = dir.join("deploy.yml");

        let mut fc = empty_condition();
        fc.not_path_has_file = vec!["governance.txt".to_string()];
        let location = FileLocation {
            absolute: &file,
            relative: "deploy.yml",
        };
        let blocked = !matches(&fc, "x", Some(location), 1);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            blocked,
            "the governance file found on disk must suppress the finding"
        );
    }

    #[test]
    fn test_path_contains_without_filepath_does_not_block() {
        // Python: `if path_segments and filepath:` — without a filepath, the
        // path_contains condition is ignored (no blocking).
        let mut fc = empty_condition();
        fc.path_contains = vec!["migrations".to_string()];
        assert!(matches(&fc, "x", None, 1));
    }

    #[test]
    fn test_not_path_has_file_rejects_traversal_names() {
        let mut fc = empty_condition();
        fc.not_path_has_file = vec!["../escape".to_string(), "sub/dir".to_string()];
        // Both of these names are rejected by the anti-traversal guard — so
        // they're never looked up on disk, never found → no blocking.
        let dir = std::env::temp_dir();
        let fake_file = dir.join("some_scanned_file.py");
        let location = FileLocation {
            absolute: &fake_file,
            relative: "some_scanned_file.py",
        };
        assert!(matches(&fc, "x", Some(location), 1));
    }

    #[test]
    fn test_execute_produces_finding_at_line_1_with_first_nonempty_line() {
        let rule = CompiledFileContainsRule {
            id: "missing_helmet".to_string(),
            category: "security".to_string(),
            severity: "MEDIUM".to_string(),
            confidence: 80,
            file_contains: {
                let mut fc = empty_condition();
                fc.has = vec![Regex::new("express").unwrap()];
                fc
            },
        };
        let all_lines = vec![
            (1, "".to_string()),
            (2, "const app = express();".to_string()),
        ];
        let finding = execute_file_contains_rule(
            &rule,
            at("app.js").unwrap(),
            "const app = express();",
            &all_lines,
        )
        .expect("finding attendu");
        assert_eq!(finding.line, 1);
        assert_eq!(finding.code, "const app = express();");
        // Ticket #214: a rule without a length threshold still marks the
        // finding as about the whole file.
        assert_eq!(
            finding.file_scope,
            Some(FileScope {
                line_count: 2,
                min_lines: None
            })
        );
    }

    /// Ticket #214: a length rule (`file_too_long`) records the file's
    /// line count and its own threshold, so the report can state both.
    #[test]
    fn test_execute_records_line_count_and_threshold_of_a_length_rule() {
        let rule = CompiledFileContainsRule {
            id: "file_too_long".to_string(),
            category: "arch".to_string(),
            severity: "LOW".to_string(),
            confidence: 80,
            file_contains: {
                let mut fc = empty_condition();
                fc.min_lines = 3;
                fc
            },
        };
        let all_lines: Vec<(usize, String)> = (1..=4).map(|n| (n, format!("x = {n}"))).collect();
        let finding = execute_file_contains_rule(&rule, at("long.py").unwrap(), "x", &all_lines)
            .expect("a 4-line file reaches a 3-line threshold");
        assert_eq!(
            finding.file_scope,
            Some(FileScope {
                line_count: 4,
                min_lines: Some(3)
            })
        );
    }

    #[test]
    fn test_execute_returns_none_when_conditions_not_met() {
        let rule = CompiledFileContainsRule {
            id: "x".to_string(),
            category: "security".to_string(),
            severity: "LOW".to_string(),
            confidence: 80,
            file_contains: {
                let mut fc = empty_condition();
                fc.has = vec![Regex::new("nope").unwrap()];
                fc
            },
        };
        let all_lines = vec![(1, "hello".to_string())];
        assert!(
            execute_file_contains_rule(&rule, at("f.py").unwrap(), "hello", &all_lines).is_none()
        );
    }
}
