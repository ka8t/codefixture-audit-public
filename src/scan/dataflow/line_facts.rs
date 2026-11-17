//! Per-line facts of the hybrid regex layer (§10bis), computed once per
//! rule and per line instead of once per IR statement (ticket #190).
//!
//! `transfer::aux_match_line` runs after every IR statement and tests the
//! statement's whole source line against every raw regex of the rule
//! (sanitizers, sources, sinks) and against the guard patterns. On code
//! with many statements per physical line (a minified bundle holds a whole
//! program on one line of 0.2 to 3 MB), the same regexes ran thousands of
//! times on the same text, and again on every re-analysis of the summary
//! fixpoint: a 229 KB one-line file took 180 s, `bountybench-main` more
//! than 4 hours (profiled with `sample`, 2026-11-16).
//!
//! What only depends on the text of a line and on the rule is therefore
//! computed on first use and kept in a [`RuleLines`]: which raw regexes
//! match the line, the guard facts of the line, the text the sink search
//! reads. What depends on the dataflow state (which variables are tainted)
//! is still computed by `aux_match_line` at each statement, so the
//! findings do not change.
//!
//! A [`RuleLines`] is bound to ONE rule: the facts read the regexes of
//! the `RuleSpecs` it was created for. The analysis clones that
//! `RuleSpecs` to seed callee summaries (`compute_one` in the call
//! graphs); such a clone keeps the same regex lists, which is why the
//! binding is checked on the rule id and the spec counts, not on the
//! address of the specs.

use std::ops::Deref;
use std::sync::{Arc, LazyLock, OnceLock};

use fancy_regex::Regex;

use super::lattice::SharedText;
use super::transfer::RuleSpecs;

/// Terminator of a sanitizer-guard: the line following
/// `if not <san>(x): ...` must contain one of these calls for the
/// block to be considered a guard (the downstream sink is no longer
/// reached if the predicate fails).
static GUARD_TERMINATOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:abort|raise|return|exit|sys\.exit|os\._exit)\b")
        .expect("regex statique valide")
});

/// Terminators of a guard written on one line in a brace language,
/// `if (!ALLOWED.Contains(cmd)) return Forbid();` — the list of the
/// Audit's lexical engine (`lexical_taint.py::
/// _GUARD_TERMINATOR_RE_MULTILANG`), which is the reference behavior for
/// C#, PHP and JavaScript (ADR-0003, ADR-0007). Ticket #178.
static GUARD_TERMINATOR_SAMELINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:return|throw|raise|break|continue|exit|die|abort|halt|Forbid|Halt|sendError|sendRedirect|RedirectToAction|Response\.End)\b",
    )
    .expect("regex statique valide")
});

/// `!` negation (Java/C#/JS style, e.g. `if (!isValid(x))`) —
/// alternative to Python's `not`/`in`. Excludes `!=` (not a negation
/// of a sanitizer call).
static NEGATION_BANG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"!(?!=)").expect("regex statique valide"));

/// Reassignment to a literal inside a guard
/// `if (!check(x)) x = "literal";` (same physical line as the if).
/// The PHP `$` is part of the captured name: the PHP engine keeps it in
/// its variable names (`$next`). The Audit's pattern allowed `\$?` before
/// the group; the first port had lost it, so a PHP guard
/// `if (!filter_var($next, ...)) { $next = '/'; }` left `$next` tainted
/// (ticket #157).
static GUARD_REASSIGN_SAMELINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\)\s*\{?\s*(\$?[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:["'][^"']*["']|[+-]?[0-9]+|null|None|undefined|true|false)"#,
    )
    .expect("regex statique valide")
});

/// Same idiom, but as a whole following line (multi-line guard body).
/// Anchored at the start of the line (standalone statement, not a
/// continuation of `)`). Same `$` as `GUARD_REASSIGN_SAMELINE_RE`.
static GUARD_REASSIGN_NEXTLINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^\s*(\$?[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:["'][^"']*["']|[+-]?[0-9]+|null|None|undefined|true|false)\s*;"#,
    )
    .expect("regex statique valide")
});

/// String literals (single/double quote), to strip them from the
/// text before a substring search (variable name). Pattern identical
/// to `lexical_taint.py::_STRING_LIT_STRIP_RE` — unambiguous
/// partition (each repetition of `(?:\\.[^"\\]*)*` starts on a
/// literal backslash excluded from the previous group), no
/// exponential backtracking despite the appearance of nested
/// quantifiers.
static STRING_LIT_STRIP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'"#)
        .expect("regex statique valide")
});

/// Longest call the sink search follows past an unbalanced `(`, in
/// lines after the sink line (Python `transfer.py`: 25).
const MAX_CALL_CONTINUATION_LINES: usize = 25;

/// Strips "flat" string literals from `text`, but leaves intact
/// those that interpolate (contain `{`/`}`) — a Python f-string
/// (`f'Hello {bar}'`) or a JS template carries a REAL variable
/// reference inside the quotes, not a textual coincidence: stripping
/// it would break legitimate XSS detection on
/// `return f'...{bar}...'`. A "flat" literal (e.g. SQL text) is
/// indeed stripped.
pub(crate) fn strip_plain_string_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for m in STRING_LIT_STRIP_RE.find_iter(text) {
        let Ok(m) = m else { break };
        out.push_str(&text[last..m.start()]);
        let matched = m.as_str();
        if matched.contains('{') || matched.contains('}') {
            out.push_str(matched);
        } else {
            out.push(' ');
        }
        last = m.end();
    }
    out.push_str(&text[last..]);
    out
}

/// True when `regex` matches `text`; a regex that fails at run time
/// (backtracking limit of `fancy_regex`) counts as no match, as
/// everywhere else in the hybrid layer.
fn matches(regex: &Regex, text: &str) -> bool {
    regex.is_match(text).unwrap_or(false)
}

/// The source lines of one file, with the per-line facts of one rule.
///
/// Dereferences to the lines themselves (`[String]`, line `n` at index
/// `n - 1`), so code that only reads the text keeps indexing it as
/// before. See the module doc for what is cached and why.
pub struct RuleLines<'a> {
    lines: &'a [String],
    rule_id: String,
    spec_counts: (usize, usize, usize),
    /// One slot per line, allocated when the first fact of the file is
    /// asked for: building the table of every file of a project for a
    /// rule costs nothing for the files the rule never reaches.
    facts: OnceLock<Vec<OnceLock<Box<LineFacts>>>>,
}

impl<'a> RuleLines<'a> {
    /// Binds the lines of a file to the rule described by `specs`.
    pub fn new(lines: &'a [String], specs: &RuleSpecs) -> Self {
        Self {
            lines,
            rule_id: specs.rule_id.clone(),
            spec_counts: spec_counts(specs),
            facts: OnceLock::new(),
        }
    }

    /// The raw lines of the file.
    pub fn lines(&self) -> &'a [String] {
        self.lines
    }

    /// Text of line `lineno` (1-based), `None` outside the file.
    pub fn line(&self, lineno: usize) -> Option<&'a str> {
        lineno
            .checked_sub(1)
            .and_then(|i| self.lines.get(i))
            .map(String::as_str)
    }

    /// Facts of line `lineno` (1-based) for the bound rule, computed on
    /// first use; `None` outside the file.
    ///
    /// `specs` must be the rule the table was created for, or a clone
    /// of it (same regexes); checked in debug builds.
    pub fn facts(&self, lineno: usize, specs: &RuleSpecs) -> Option<&LineFacts> {
        debug_assert!(
            specs.rule_id == self.rule_id && spec_counts(specs) == self.spec_counts,
            "RuleLines created for rule {} used with rule {}",
            self.rule_id,
            specs.rule_id
        );
        let text = self.line(lineno)?;
        let slots = self
            .facts
            .get_or_init(|| (0..self.lines.len()).map(|_| OnceLock::new()).collect());
        let slot = &slots[lineno - 1];
        Some(slot.get_or_init(|| Box::new(LineFacts::compute(text, specs))))
    }

    /// Guard facts of line `lineno` (1-based), computed on first use.
    pub fn guard(&self, lineno: usize, specs: &RuleSpecs) -> Option<&GuardFacts> {
        let text = self.line(lineno)?;
        let facts = self.facts(lineno, specs)?;
        Some(facts.guard.get_or_init(|| GuardFacts::compute(text)))
    }

    /// The text the sink search of line `lineno` (1-based) reads, see
    /// [`SinkScan`]; computed on first use.
    pub fn sink_scan(&self, lineno: usize, specs: &RuleSpecs) -> Option<&SinkScan> {
        let facts = self.facts(lineno, specs)?;
        Some(
            facts
                .sink_scan
                .get_or_init(|| SinkScan::compute(self.lines, lineno, specs)),
        )
    }

    /// The line text without its leading and trailing whitespace, shared:
    /// the text the hybrid layer stores in a source, a finding and its
    /// flow steps. Built once per line, so every statement and finding of
    /// a minified line points to the same allocation (ticket #191).
    pub fn trimmed(&self, lineno: usize, specs: &RuleSpecs) -> Option<SharedText> {
        let text = self.line(lineno)?;
        let facts = self.facts(lineno, specs)?;
        Some(Arc::clone(
            facts.trimmed.get_or_init(|| SharedText::from(text.trim())),
        ))
    }

    /// The line text without its flat string literals (see
    /// [`strip_plain_string_literals`]), computed on first use.
    pub fn text_without_literals(&self, lineno: usize, specs: &RuleSpecs) -> Option<&str> {
        let text = self.line(lineno)?;
        let facts = self.facts(lineno, specs)?;
        Some(
            facts
                .without_literals
                .get_or_init(|| strip_plain_string_literals(text)),
        )
    }
}

impl Deref for RuleLines<'_> {
    type Target = [String];

    fn deref(&self) -> &[String] {
        self.lines
    }
}

/// Sizes of the three regex lists of a rule, part of the binding check
/// of [`RuleLines`].
fn spec_counts(specs: &RuleSpecs) -> (usize, usize, usize) {
    (
        specs.sanitizers.len(),
        specs.sources.len(),
        specs.sinks.len(),
    )
}

/// What the hybrid layer reads from one line for one rule.
pub struct LineFacts {
    /// Index in `specs.sanitizers` of the first sanitizer whose raw
    /// regex matches the line (the only one `aux_match_line` uses).
    pub first_sanitizer: Option<usize>,
    /// Indices in `specs.sources` of the sources whose raw regex
    /// matches the line, in rule order.
    pub sources: Vec<usize>,
    /// Indices in `specs.sinks` of the sinks whose raw regex matches
    /// the line, in rule order.
    pub sinks: Vec<usize>,
    guard: OnceLock<GuardFacts>,
    sink_scan: OnceLock<SinkScan>,
    without_literals: OnceLock<String>,
    trimmed: OnceLock<SharedText>,
}

#[cfg(test)]
thread_local! {
    /// Number of `LineFacts::compute` calls on this thread: lets the tests
    /// check that a line is matched once, however many statements it holds.
    static FACT_COMPUTATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl LineFacts {
    fn compute(text: &str, specs: &RuleSpecs) -> Self {
        #[cfg(test)]
        FACT_COMPUTATIONS.with(|count| count.set(count.get() + 1));
        let first_sanitizer = specs
            .sanitizers
            .iter()
            .position(|s| s.raw_regex.as_ref().is_some_and(|rx| matches(rx, text)));
        let sources = specs
            .sources
            .iter()
            .enumerate()
            .filter(|(_, s)| s.raw_regex.as_ref().is_some_and(|rx| matches(rx, text)))
            .map(|(i, _)| i)
            .collect();
        let sinks = specs
            .sinks
            .iter()
            .enumerate()
            .filter(|(_, s)| s.raw_regex.as_ref().is_some_and(|rx| matches(rx, text)))
            .map(|(i, _)| i)
            .collect();
        Self {
            first_sanitizer,
            sources,
            sinks,
            guard: OnceLock::new(),
            sink_scan: OnceLock::new(),
            without_literals: OnceLock::new(),
            trimmed: OnceLock::new(),
        }
    }
}

/// Guard patterns of one line, independent of the rule.
///
/// A line plays two roles in guard detection: the `if` line itself
/// (`starts_*`, `has_not_or_in`, `negation_bang`, `terminator_same_line`,
/// `reassign_same_line`) and one of the up to 8 lines of its body
/// (`is_blank`, `indent`, `terminator`, `reassign_next_line`). Both are
/// computed together the first time a guard reads the line.
pub struct GuardFacts {
    /// Bytes of leading whitespace.
    pub indent: usize,
    /// Only whitespace on the line.
    pub is_blank: bool,
    /// The line starts (after indentation) with `if ` or `elif `.
    pub starts_python_if: bool,
    /// The line starts (after indentation) with `if (` or `if(`.
    pub starts_brace_if: bool,
    /// The line contains ` not ` or ` in ` (Python negation forms).
    pub has_not_or_in: bool,
    /// The line contains a `!` that is not `!=`.
    pub negation_bang: bool,
    /// `GUARD_TERMINATOR_RE` matches: the line can end a guard body.
    pub terminator: bool,
    /// `GUARD_TERMINATOR_SAMELINE_RE` matches: a one-line brace guard
    /// can end on this line.
    pub terminator_same_line: bool,
    /// Variable reset to a literal after the `)` of the `if`.
    pub reassign_same_line: Option<String>,
    /// Variable reset to a literal by the whole line.
    pub reassign_next_line: Option<String>,
}

impl GuardFacts {
    fn compute(text: &str) -> Self {
        let stripped = text.trim_start();
        let capture = |rx: &Regex| {
            rx.captures(text)
                .ok()
                .flatten()
                .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        };
        Self {
            indent: text.len() - stripped.len(),
            is_blank: text.trim().is_empty(),
            starts_python_if: stripped.starts_with("if ") || stripped.starts_with("elif "),
            starts_brace_if: stripped.starts_with("if (") || stripped.starts_with("if("),
            has_not_or_in: text.contains(" not ") || text.contains(" in "),
            negation_bang: matches(&NEGATION_BANG_RE, text),
            terminator: matches(&GUARD_TERMINATOR_RE, text),
            terminator_same_line: matches(&GUARD_TERMINATOR_SAMELINE_RE, text),
            reassign_same_line: capture(&GUARD_REASSIGN_SAMELINE_RE),
            reassign_next_line: capture(&GUARD_REASSIGN_NEXTLINE_RE),
        }
    }
}

/// The text a sink search reads, for a sink matched on one line.
pub struct SinkScan {
    /// A sanitizer of the rule matches the continuation lines of a call
    /// left open on the sink line: the sink is cleared.
    pub continuation_sanitized: bool,
    /// The sink line, followed by the continuation lines of a call left
    /// open on it (until the parentheses balance, at most
    /// `MAX_CALL_CONTINUATION_LINES`), without its flat string literals:
    /// the text in which a tainted variable name is looked for.
    pub text_without_literals: String,
}

impl SinkScan {
    /// Multi-line call: if the sink line opens unbalanced parentheses,
    /// the search text extends to the continuation lines, until
    /// balanced, capped at 25 lines.
    ///
    /// A sanitizer written in the continuation clears the sink, as it
    /// does on a one-line call (the sanitizers check of
    /// `aux_match_line` returns before the sinks). Deliberate deviation
    /// from Python (`transfer.py`), which searched the tainted variable
    /// over the whole call but the sanitizer on its first line only:
    /// every SQLAlchemy `db.execute(\n select(...).where(x == p))` was an
    /// injection (my-ia, 2026-11-14).
    fn compute(lines: &[String], lineno: usize, specs: &RuleSpecs) -> Self {
        let line_text = &lines[lineno - 1];
        let mut paren_depth =
            line_text.matches('(').count() as i64 - line_text.matches(')').count() as i64;
        if paren_depth <= 0 {
            return Self {
                continuation_sanitized: false,
                text_without_literals: strip_plain_string_literals(line_text),
            };
        }
        let mut span: Vec<&str> = vec![line_text];
        let mut j = lineno; // lines[lineno - 1] is the sink line; the next one is lines[lineno]
        let j_end = (lineno + MAX_CALL_CONTINUATION_LINES).min(lines.len());
        while j < j_end && paren_depth > 0 {
            let cont = &lines[j];
            span.push(cont);
            paren_depth += cont.matches('(').count() as i64 - cont.matches(')').count() as i64;
            j += 1;
        }
        let continuation = span[1..].join("\n");
        let continuation_sanitized = specs.sanitizers.iter().any(|san| {
            san.raw_regex
                .as_ref()
                .is_some_and(|rx| matches(rx, &continuation))
        });
        Self {
            continuation_sanitized,
            text_without_literals: strip_plain_string_literals(&span.join("\n")),
        }
    }
}

/// The [`RuleLines`] of every file of a project for one rule, keyed by
/// file path: what the call graphs hand to each summary computation.
pub type RuleLinesByFile<'a> = std::collections::BTreeMap<&'a str, RuleLines<'a>>;

/// Binds the lines of every file in `lines_by_file` to the rule
/// `specs`. Cheap: a file's per-line table is only allocated when a
/// summary of that file first reads a fact.
pub fn rule_lines_by_file<'a>(
    lines_by_file: &'a std::collections::BTreeMap<String, Vec<String>>,
    specs: &RuleSpecs,
) -> RuleLinesByFile<'a> {
    lines_by_file
        .iter()
        .map(|(path, lines)| (path.as_str(), RuleLines::new(lines, specs)))
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::js_taint_scan::run_taint_rule_js;
    use crate::scan::dataflow::transfer::{SanitizerSpec, SinkSpec, SourceSpec};
    use std::collections::BTreeMap;

    fn regex(pattern: &str) -> Regex {
        Regex::new(pattern).expect("test regex")
    }

    /// A JS rule whose source, sink and sanitizer all carry a raw regex,
    /// so that every statement goes through the hybrid layer.
    fn hybrid_specs() -> RuleSpecs {
        RuleSpecs {
            rule_id: "taint_eval_js".to_string(),
            severity: "HIGH".to_string(),
            cwe: Some("CWE-95".to_string()),
            message: "test finding".to_string(),
            sources: vec![
                SourceSpec::new("*.query.*", "http").with_raw_regex(regex(r"\.query\.")),
                SourceSpec::new("*.body.*", "http").with_raw_regex(regex(r"\.body\.")),
            ],
            sinks: vec![SinkSpec::new("eval").with_raw_regex(regex(r"\beval\s*\("))],
            sanitizers: vec![SanitizerSpec::new("escape").with_raw_regex(regex(r"\bescape\s*\("))],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
        }
    }

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(str::to_string).collect()
    }

    fn computations() -> usize {
        FACT_COMPUTATIONS.with(|count| count.get())
    }

    #[test]
    fn test_facts_list_matching_specs_in_rule_order() {
        let specs = hybrid_specs();
        let text = lines("x = eval(req.body.a + req.query.b)\ny = escape(z)\nw = 1");
        let rule_lines = RuleLines::new(&text, &specs);

        let first = rule_lines.facts(1, &specs).unwrap();
        assert_eq!(first.sources, vec![0, 1]);
        assert_eq!(first.sinks, vec![0]);
        assert_eq!(first.first_sanitizer, None);
        assert_eq!(
            rule_lines.facts(2, &specs).unwrap().first_sanitizer,
            Some(0)
        );
        let last = rule_lines.facts(3, &specs).unwrap();
        assert!(last.sources.is_empty() && last.sinks.is_empty());
        assert!(rule_lines.facts(0, &specs).is_none());
        assert!(rule_lines.facts(4, &specs).is_none());
    }

    #[test]
    fn test_facts_are_computed_once_per_line() {
        let specs = hybrid_specs();
        let text = lines("a = req.query.q\nb = 2");
        let rule_lines = RuleLines::new(&text, &specs);
        let before = computations();
        for _ in 0..50 {
            rule_lines.facts(1, &specs);
            rule_lines.facts(2, &specs);
        }
        assert_eq!(computations() - before, 2);
    }

    /// The regression of ticket #190: a minified file holds thousands of
    /// statements on one line, and the hybrid layer matched the whole
    /// line once per statement and per summary pass (a 229 KB line took
    /// 180 s). The line must now be matched once for the rule, and the
    /// flow written on that line still found.
    #[test]
    fn test_one_line_with_many_statements_is_matched_once() {
        let specs = hybrid_specs();
        let mut program = String::new();
        for i in 0..2000 {
            program.push_str(&format!("var v{i} = {i};"));
        }
        program.push_str("function h(req) { var q = req.query.q; eval(q); }");
        let tree = {
            let mut parser = tree_sitter::Parser::new();
            let lang: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
            parser.set_language(&lang).unwrap();
            parser.parse(&program, None).unwrap()
        };
        let text = lines(&program);
        assert_eq!(text.len(), 1);

        let before = computations();
        let findings = run_taint_rule_js(tree.root_node(), program.as_bytes(), &specs, Some(&text));

        assert_eq!(computations() - before, 1, "the line must be matched once");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].line, 1);
    }

    /// The regression of ticket #191: on a line that holds a source, every
    /// assignment of the line is tainted with the whole line as source
    /// text, and the state is cloned at every statement. The text must be
    /// shared, not copied: every taint of the line points to the same
    /// allocation.
    #[test]
    fn test_taints_of_one_line_share_its_text() {
        use crate::scan::dataflow::js_cfg::build_js_cfg;
        use crate::scan::dataflow::lattice::{Taint, empty_state};
        use crate::scan::dataflow::worklist::analyze_js;

        let specs = hybrid_specs();
        let mut program = String::from("var q = req.query.q;");
        for i in 0..200 {
            program.push_str(&format!("var v{i} = {i};"));
        }
        let tree = {
            let mut parser = tree_sitter::Parser::new();
            let lang: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
            parser.set_language(&lang).unwrap();
            parser.parse(&program, None).unwrap()
        };
        let text = lines(&program);
        let rule_lines = RuleLines::new(&text, &specs);
        let cfg = build_js_cfg(tree.root_node(), program.as_bytes());
        let result = analyze_js(
            &cfg,
            program.as_bytes(),
            &specs,
            Some(&empty_state()),
            Some(&rule_lines),
        );

        let line_text = rule_lines.trimmed(1, &specs).unwrap();
        let mut tainted = 0;
        for state in result.state_out.values() {
            for taint in state.values() {
                if let Taint::Tainted { source, .. } = taint {
                    assert!(Arc::ptr_eq(&source.expr, &line_text), "copied source text");
                    tainted += 1;
                }
            }
        }
        assert!(
            tainted > 200,
            "every assignment of the line is tainted: {tainted}"
        );
    }

    #[test]
    fn test_guard_facts_read_the_if_line_and_its_body() {
        let specs = hybrid_specs();
        let text = lines("    if (!ok(x)) x = 'safe';\n        return\n   \n    y = 0;");
        let rule_lines = RuleLines::new(&text, &specs);

        let line = rule_lines.guard(1, &specs).unwrap();
        assert_eq!(line.indent, 4);
        assert!(line.starts_brace_if && line.starts_python_if);
        assert!(line.negation_bang && !line.has_not_or_in);
        assert_eq!(line.reassign_same_line.as_deref(), Some("x"));
        assert!(!line.terminator_same_line);

        let body = rule_lines.guard(2, &specs).unwrap();
        assert!(body.terminator && body.indent == 8 && !body.is_blank);
        assert!(rule_lines.guard(3, &specs).unwrap().is_blank);
        assert_eq!(
            rule_lines
                .guard(4, &specs)
                .unwrap()
                .reassign_next_line
                .as_deref(),
            Some("y")
        );
    }

    #[test]
    fn test_sink_scan_follows_an_open_call_and_its_sanitizer() {
        let specs = hybrid_specs();
        let open = lines("eval(\n  'a' + q,\n  escape(r))\nnext(q)");
        let rule_lines = RuleLines::new(&open, &specs);
        let scan = rule_lines.sink_scan(1, &specs).unwrap();
        assert!(scan.continuation_sanitized);
        assert_eq!(scan.text_without_literals, "eval(\n    + q,\n  escape(r))");

        let closed = lines("eval('a' + q)\nescape(r)");
        let rule_lines = RuleLines::new(&closed, &specs);
        let scan = rule_lines.sink_scan(1, &specs).unwrap();
        assert!(!scan.continuation_sanitized);
        assert_eq!(scan.text_without_literals, "eval(  + q)");
    }
}
