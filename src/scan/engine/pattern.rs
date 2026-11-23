//! Regex executor — faithful port of `Audit/sca/executors/regex.py`.
//!
//! Input contract for `all_lines`: each `(number, text)` must
//! carry the **raw text with its original line terminator
//! included** (equivalent of Python's `readlines()`), not un-terminated
//! text (`str::lines()` strips it). Computing line positions
//! for the `context-N` scope depends on counting the `\n` in the
//! reassembled text — losing the terminators would desynchronize the
//! line numbers.

use super::Finding;
use super::pattern_regex::PatternRegex;
use std::collections::BTreeMap;

/// A rule whose pattern (as well as `with`/`pattern-not`) is already
/// compiled — mirrors `_compile_rule_patterns` (rule_loader.py) for
/// the `patterns[]` subset (regex/regex+taint mode). Sources/
/// sinks/sanitizers (taint) and `file_contains` are out of scope for
/// this module.
pub struct CompiledRegexRule {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub confidence: i64,
    pub language: String,
    pub patterns: Vec<CompiledPattern>,
}

/// One pattern of a rule, its `with` and `pattern-not` compiled with
/// their prefilter ([`PatternRegex`], ticket #251).
pub struct CompiledPattern {
    pub match_scope: String,
    pub compiled: PatternRegex,
    pub compiled_with: Option<PatternRegex>,
    pub compiled_pattern_not: Option<PatternRegex>,
}

/// Rules whose `pattern-not`/`with` legitimately depends on the comment
/// syntax itself (the safe case *is* a comment) — cf. the
/// comment on `_COMMENT_STRIP_EXEMPT_RULES` on the Python side: an
/// explicit set rather than a new DSL flag, since only one rule
/// needs it today.
const COMMENT_STRIP_EXEMPT_RULES: &[&str] = &["gha_version_comment_missing"];

fn line_comment_marker(language: &str) -> Option<&'static str> {
    match language {
        "python" | "yaml" | "dockerfile" => Some("#"),
        "javascript" | "java" | "csharp" | "php" => Some("//"),
        _ => None,
    }
}

/// The block comment delimiters of a comment syntax, stripped in this
/// order. `razor` is the syntax of a Razor view (`.cshtml`, `.razor`,
/// ADR-0058): its server comments `@* … *@` are stripped first, then its
/// HTML comments, exactly as HTML comments are (ticket #285). Deliberate
/// deviation from the Audit, which strips only `<!-- -->` from a
/// `.cshtml` and never reads a `.razor`: a Razor comment never reaches
/// the page, so a `pattern-not` or `with` must not read what it holds.
fn block_comment_delims(language: &str) -> &'static [(&'static str, &'static str)] {
    match language {
        "javascript" | "java" | "csharp" | "php" => &[("/*", "*/")],
        "html" => &[("<!--", "-->")],
        "razor" => &[("@*", "*@"), ("<!--", "-->")],
        _ => &[],
    }
}

/// Strips comment content (for the `pattern-not`/`with` checks
/// only — the main `pattern` search and the reported code fragment
/// always use the original, uncleaned `all_lines`: some rules,
/// like `todo_unresolved`, deliberately search *inside* comments).
pub fn strip_comments_from_lines(
    all_lines: &[(usize, String)],
    language: &str,
) -> Vec<(usize, String)> {
    let delims = block_comment_delims(language);
    let stripped_texts: Vec<String> = if delims.is_empty() {
        all_lines.iter().map(|(_, t)| t.clone()).collect()
    } else {
        let mut full_text: String = all_lines.iter().map(|(_, t)| t.as_str()).collect();
        for (open, close) in delims {
            full_text = strip_block_comments(&full_text, open, close);
        }
        full_text.split('\n').map(|s| s.to_string()).collect()
    };

    let final_texts: Vec<String> = if let Some(marker) = line_comment_marker(language) {
        stripped_texts
            .iter()
            .map(|t| strip_line_comment(t, marker))
            .collect()
    } else {
        stripped_texts
    };

    // If stripping block comments re-split the text, the
    // line count may differ from the original line count
    // (a block spanning multiple lines is replaced by the same
    // number of '\n' — cf. strip_block_comments — so in theory the
    // count stays identical; we bound it as a safety net).
    all_lines
        .iter()
        .zip(final_texts.iter().chain(std::iter::repeat(&String::new())))
        .map(|((num, _), text)| (*num, text.clone()))
        .collect()
}

/// Strips `open...close` block comments (non-greedy, like
/// `open.*?close` with DOTALL in Python), replaced by as many `\n`
/// as the removed fragment contained — preserves the alignment of
/// line numbers for everything that follows.
fn strip_block_comments(text: &str, open: &str, close: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        match rest.find(open) {
            Some(start) => {
                result.push_str(&rest[..start]);
                let after_open = &rest[start..];
                match after_open.find(close) {
                    Some(end_rel) => {
                        let matched = &after_open[..end_rel + close.len()];
                        let newlines = matched.matches('\n').count();
                        result.push_str(&"\n".repeat(newlines));
                        rest = &after_open[end_rel + close.len()..];
                    }
                    None => {
                        // No closing delimiter: like the Python regex
                        // (`.*?close`), this fragment never matches —
                        // left as-is.
                        result.push_str(after_open);
                        return result;
                    }
                }
            }
            None => {
                result.push_str(rest);
                return result;
            }
        }
    }
}

/// Strips `marker` and everything after it on the line, preserving a
/// trailing `\n` if present (equivalent of `re.sub(f"{marker}.*$", "", text)`
/// without `DOTALL`: `.` doesn't consume the terminal `\n`).
fn strip_line_comment(text: &str, marker: &str) -> String {
    match text.find(marker) {
        Some(pos) => {
            let mut result = text[..pos].to_string();
            if text.ends_with('\n') {
                result.push('\n');
            }
            result
        }
        None => text.to_string(),
    }
}

fn is_match(re: &PatternRegex, text: &str) -> bool {
    re.is_match(text).unwrap_or(false)
}

/// Byte offset where `re` first matches in `text`, `None` when it does
/// not match (or fails, like [`is_match`]): the column of a finding.
fn match_start(re: &PatternRegex, text: &str) -> Option<usize> {
    re.find(text).ok().flatten().map(|m| m.start())
}

/// Executes a regex rule against a file — one finding per
/// match. Mirrors `execute()` (regex.py). The comments are stripped with
/// the rule's `language`; see [`execute_regex_rule_on`] for lines
/// stripped once and shared by the rules of a file.
pub fn execute_regex_rule(rule: &CompiledRegexRule, all_lines: &[(usize, String)]) -> Vec<Finding> {
    if rule.patterns.is_empty() || all_lines.is_empty() {
        return Vec::new();
    }
    let clean_lines = if keeps_comments(rule) {
        all_lines.to_vec()
    } else {
        strip_comments_from_lines(all_lines, &rule.language)
    };
    execute_regex_rule_on(rule, all_lines, &clean_lines)
}

/// Whether the `pattern-not`/`with` checks of `rule` read the lines with
/// their comments ([`COMMENT_STRIP_EXEMPT_RULES`]).
pub fn keeps_comments(rule: &CompiledRegexRule) -> bool {
    COMMENT_STRIP_EXEMPT_RULES.contains(&rule.id.as_str())
}

/// [`execute_regex_rule`] with the lines its `pattern-not`/`with` checks
/// read already given: `all_lines` without their comments, or `all_lines`
/// themselves for a rule that [`keeps_comments`]. The pattern pass strips
/// a file's comments once and hands them to every rule of the file
/// (ticket #248): each rule used to strip the whole file again.
pub fn execute_regex_rule_on(
    rule: &CompiledRegexRule,
    all_lines: &[(usize, String)],
    clean_lines: &[(usize, String)],
) -> Vec<Finding> {
    if rule.patterns.is_empty() || all_lines.is_empty() {
        return Vec::new();
    }

    let negative_patterns: Vec<&PatternRegex> = rule
        .patterns
        .iter()
        .filter_map(|p| p.compiled_pattern_not.as_ref())
        .collect();

    // Line number → (text the negative patterns are tested on, byte
    // column of the match in the line, ticket #194).
    let mut candidates: BTreeMap<usize, (String, usize)> = BTreeMap::new();

    for p in &rule.patterns {
        if p.match_scope == "file" {
            // Python also computes `full_content` (same construction) but
            // never uses it — the main pattern is matched line
            // by line (loop below), not against the whole text.
            // Dead code on the Python side, not reproduced here.
            let clean_content: String = clean_lines
                .iter()
                .map(|(_, l)| l.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            if let Some(neg) = &p.compiled_pattern_not
                && is_match(neg, &clean_content)
            {
                continue;
            }
            if let Some(with) = &p.compiled_with
                && !is_match(with, &clean_content)
            {
                continue;
            }
            for (line_num, line) in all_lines {
                if let Some(column) = match_start(&p.compiled, line) {
                    candidates.insert(*line_num, (clean_content.clone(), column));
                }
            }
        } else if p.match_scope == "line" {
            for ((line_num, line), (_, clean_line)) in all_lines.iter().zip(clean_lines.iter()) {
                if let Some(column) = match_start(&p.compiled, line) {
                    if let Some(with) = &p.compiled_with
                        && !is_match(with, clean_line)
                    {
                        continue;
                    }
                    candidates.insert(*line_num, (clean_line.clone(), column));
                }
            }
        } else if let Some(window_str) = p.match_scope.strip_prefix("context-") {
            let window: usize = window_str.parse().unwrap_or(6);
            let n_lines = all_lines.len();
            let first_line_num = all_lines[0].0;

            for start_idx in 0..n_lines {
                let block_end = (start_idx + window).min(n_lines);
                let block_text: String = all_lines[start_idx..block_end]
                    .iter()
                    .map(|(_, l)| l.as_str())
                    .collect();
                if block_text.is_empty() {
                    continue;
                }

                let m = match p.compiled.find(&block_text) {
                    Ok(Some(m)) => m,
                    _ => continue,
                };

                let clean_block_text: String = clean_lines[start_idx..block_end]
                    .iter()
                    .map(|(_, l)| l.as_str())
                    .collect();
                if let Some(with) = &p.compiled_with
                    && !is_match(with, &clean_block_text)
                {
                    continue;
                }

                let local_start = m.start();
                let newlines_before = block_text[..local_start].matches('\n').count();
                let start_line = all_lines[start_idx].0 + newlines_before;
                // Column of the match in its own line: past the last line
                // break before it.
                let column = local_start
                    - block_text[..local_start]
                        .rfind('\n')
                        .map_or(0, |newline| newline + 1);

                // block_text only extends forward from
                // start_idx: pattern-not could never see a
                // guard/sanitizer declared on an earlier line.
                // Purely additive addition of a backward window (up to
                // `window` lines before the match line) — the forward
                // scope is unchanged, the backward scope becomes
                // available for pattern-not.
                let match_idx = start_line.saturating_sub(first_line_num);
                let back_start = match_idx.saturating_sub(window);
                let clean_backward_text: String = clean_lines[back_start..match_idx]
                    .iter()
                    .map(|(_, l)| l.as_str())
                    .collect();

                candidates.insert(
                    start_line,
                    (format!("{clean_backward_text}{clean_block_text}"), column),
                );
            }
        }
    }

    if candidates.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let n_lines = all_lines.len();
    for (&line_num, (context_text, column)) in &candidates {
        if line_num < 1 || line_num > n_lines {
            continue;
        }
        if negative_patterns
            .iter()
            .any(|neg| is_match(neg, context_text))
        {
            continue;
        }
        let line_text = &all_lines[line_num - 1].1;
        findings.push(Finding {
            rule_id: rule.id.clone(),
            category: rule.category.to_uppercase(),
            severity: rule.severity.clone(),
            line: line_num,
            code: line_text.clone(),
            column: *column,
            confidence: rule.confidence,
            file_scope: None,
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(texts: &[&str]) -> Vec<(usize, String)> {
        texts
            .iter()
            .enumerate()
            .map(|(i, t)| (i + 1, format!("{t}\n")))
            .collect()
    }

    fn simple_rule(pattern: &str, scope: &str) -> CompiledRegexRule {
        CompiledRegexRule {
            id: "test_rule".to_string(),
            category: "security".to_string(),
            severity: "HIGH".to_string(),
            confidence: 80,
            language: "python".to_string(),
            patterns: vec![CompiledPattern {
                match_scope: scope.to_string(),
                compiled: PatternRegex::new(pattern).unwrap(),
                compiled_with: None,
                compiled_pattern_not: None,
            }],
        }
    }

    #[test]
    fn test_line_scope_basic_match() {
        let rule = simple_rule(r"eval\(", "line");
        let all_lines = lines(&["x = 1", "eval(user_input)", "y = 2"]);
        let findings = execute_regex_rule(&rule, &all_lines);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn test_line_scope_with_condition_filters() {
        let mut rule = simple_rule(r"password\s*=", "line");
        rule.patterns[0].compiled_with = Some(PatternRegex::new(r#""[^"]{8,}""#).unwrap());
        let all_lines = lines(&["password = short", r#"password = "longenoughvalue""#]);
        let findings = execute_regex_rule(&rule, &all_lines);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn test_pattern_not_suppresses_finding() {
        // "safe" in real code (not inside a Python "#" comment, which
        // would be stripped before the pattern-not check — cf.
        // test_comment_stripped_before_pattern_not_check).
        let mut rule = simple_rule(r"\.execute\(", "line");
        rule.patterns[0].compiled_pattern_not = Some(PatternRegex::new(r"parameterized").unwrap());
        let all_lines = lines(&["cursor.execute(parameterized_query)"]);
        let findings = execute_regex_rule(&rule, &all_lines);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_comment_stripped_before_pattern_not_check() {
        // The pattern-not trigger word is inside a comment —
        // must NOT suppress the finding (comment stripping
        // applies to pattern-not, so the word disappears there).
        let mut rule = simple_rule(r"eval\(", "line");
        rule.patterns[0].compiled_pattern_not = Some(PatternRegex::new(r"safe_context").unwrap());
        let all_lines = lines(&["eval(x)  # safe_context supposedly"]);
        let findings = execute_regex_rule(&rule, &all_lines);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_file_scope_pattern_not_skips_whole_pattern() {
        // "ALLOW_TODO" in real code, not inside a Python "#" comment
        // (which would be stripped before the pattern-not check).
        let mut rule = simple_rule(r"TODO", "file");
        rule.patterns[0].compiled_pattern_not = Some(PatternRegex::new(r"ALLOW_TODO").unwrap());
        let all_lines = lines(&["ALLOW_TODO = True", "x = 1  # TODO fix this"]);
        let findings = execute_regex_rule(&rule, &all_lines);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_context_scope_multiline_match() {
        let rule = simple_rule(r"(?s)open\(.*?\).*?without_close", "context-6");
        let all_lines = lines(&["x = 1", "open(f)", "do_stuff()", "without_close()"]);
        let findings = execute_regex_rule(&rule, &all_lines);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn test_no_patterns_no_findings() {
        let rule = CompiledRegexRule {
            id: "empty".to_string(),
            category: "security".to_string(),
            severity: "LOW".to_string(),
            confidence: 80,
            language: "python".to_string(),
            patterns: vec![],
        };
        let all_lines = lines(&["anything"]);
        assert!(execute_regex_rule(&rule, &all_lines).is_empty());
    }

    #[test]
    fn test_strip_block_comment_preserves_line_alignment() {
        let all_lines = lines(&["a", "/* comment", "spanning */ b", "c"]);
        let clean = strip_comments_from_lines(&all_lines, "javascript");
        assert_eq!(clean.len(), 4);
        assert_eq!(clean[3].0, 4); // the last line's number stays correct
    }

    /// Razor views (ticket #285): `@* … *@` is stripped like an HTML
    /// comment, on one line or across lines, line numbers kept; HTML
    /// comments are still stripped; the `html` syntax leaves `@* *@` alone.
    #[test]
    fn test_strip_razor_comments_like_html_comments() {
        let all_lines = lines(&[
            "<p>@* @Html.Raw(a) *@ kept</p>",
            "@*",
            "  @Html.Raw(b)",
            "*@",
            "<!-- @Html.Raw(c) --> @Html.Raw(d)",
        ]);
        let clean = strip_comments_from_lines(&all_lines, "razor");
        let texts: Vec<&str> = clean.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(texts, ["<p> kept</p>", "", "", "", " @Html.Raw(d)"]);
        assert_eq!(clean[4].0, 5);
        let html = strip_comments_from_lines(&all_lines, "html");
        assert!(html[0].1.contains("@Html.Raw(a)"));
    }

    #[test]
    fn test_strip_line_comment_preserves_trailing_newline() {
        let stripped = strip_line_comment("foo # bar\n", "#");
        assert_eq!(stripped, "foo \n");
    }

    #[test]
    fn test_exempt_rule_skips_comment_stripping() {
        let mut rule = simple_rule(r"v4", "line");
        rule.id = "gha_version_comment_missing".to_string();
        rule.patterns[0].compiled_pattern_not = Some(PatternRegex::new(r"pinned").unwrap());
        rule.language = "yaml".to_string();
        // The "pinned" keyword is inside a YAML comment (#) — without
        // the exemption, it would be stripped by the cleanup and
        // wouldn't suppress the finding; with the exemption, it stays
        // visible and suppresses the finding.
        let all_lines = lines(&["uses: action@v4  # pinned"]);
        let findings = execute_regex_rule(&rule, &all_lines);
        assert!(findings.is_empty());
    }
}
