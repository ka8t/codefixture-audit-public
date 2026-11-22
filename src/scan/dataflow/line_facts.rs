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
//! What depends on the text of a line only — its guard facts — is not
//! bound to a rule: a [`SourceLines`] holds it for every rule of the
//! scan, so that a line is examined once per scan instead of once per
//! rule (ticket #240).
//!
//! A [`RuleLines`] is bound to ONE rule: the facts read the regexes of
//! the `RuleSpecs` it was created for. The analysis clones that
//! `RuleSpecs` to seed callee summaries (`compute_one` in the call
//! graphs); such a clone keeps the same regex lists, which is why the
//! binding is checked on the rule id and the spec counts, not on the
//! address of the specs.

use std::ops::{Deref, Index};
use std::sync::{Arc, LazyLock, OnceLock};

use fancy_regex::Regex;

use super::expr_table::{ExprBits, ExprTable};
use super::lattice::SharedText;
use super::transfer::RuleSpecs;

// The fixed patterns of this module (guards, string literals) need no
// look-around: they run on the `regex` crate (automaton, linear time)
// rather than on `fancy_regex`, whose backtracking VM took most of the
// taint time of a C# scan (ticket #240). The answers are the same:
// `fancy_regex` hands a pattern without fancy features to this same
// crate, and the one pattern that had a look-ahead, `!(?!=)`, is now a
// byte search (`has_negation_bang`). `test_guard_engines_agree` keeps
// the former engine as the oracle.

/// Terminator of a sanitizer-guard: the line following
/// `if not <san>(x): ...` must contain one of these calls for the
/// block to be considered a guard (the downstream sink is no longer
/// reached if the predicate fails).
static GUARD_TERMINATOR_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\b(?:abort|raise|return|exit|sys\.exit|os\._exit)\b")
        .expect("regex statique valide")
});

/// Terminators of a guard written on one line in a brace language,
/// `if (!ALLOWED.Contains(cmd)) return Forbid();` — the list of the
/// Audit's lexical engine (`lexical_taint.py::
/// _GUARD_TERMINATOR_RE_MULTILANG`), which is the reference behavior for
/// C#, PHP and JavaScript (ADR-0003, ADR-0007). Ticket #178.
static GUARD_TERMINATOR_SAMELINE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"\b(?:return|throw|raise|break|continue|exit|die|abort|halt|Forbid|Halt|sendError|sendRedirect|RedirectToAction|Response\.End)\b",
    )
    .expect("regex statique valide")
});

/// `!` negation (Java/C#/JS style, e.g. `if (!isValid(x))`) —
/// alternative to Python's `not`/`in`. Excludes `!=` (not a negation
/// of a sanitizer call): a `!` that is not followed by `=`, the pattern
/// `!(?!=)` of the Audit's lexical engine, as a byte search (ticket
/// #240). A byte that follows `!` in UTF-8 is never part of a longer
/// character equal to `=`, so the bytes give the answer of the chars.
fn has_negation_bang(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes
        .iter()
        .enumerate()
        .any(|(i, &b)| b == b'!' && bytes.get(i + 1) != Some(&b'='))
}

/// How a call result is compared in a condition (ticket #250).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Comparison {
    /// `==`, `===`, Python `is`.
    Equal,
    /// `!=`, `!==`, Python `is not`.
    NotEqual,
}

/// The values a failed check returns: `false` for a boolean test,
/// `None`/`null` for a match that found nothing (`re.match(...) is
/// None`). Compared case-insensitively (`False`, `NULL`).
fn is_failure_value(operand: &str) -> bool {
    ["false", "none", "null"]
        .iter()
        .any(|value| operand.eq_ignore_ascii_case(value))
}

/// A byte that belongs to a comparison operand (`0`, `false`, `$base`,
/// `self.base`, `'/var'`, `-1`).
fn is_operand_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$' | b'.' | b'\'' | b'"' | b'-')
}

/// True when a comparison of a check's result with `operand` holds when
/// the check failed: equal to a failure value (`=== false`, `is None`),
/// or different from anything else (`!== 0`, `!= base`, `!= true`).
pub(crate) fn compares_to_failure(comparison: Comparison, operand: &str) -> bool {
    match comparison {
        Comparison::Equal => is_failure_value(operand),
        Comparison::NotEqual => !operand.is_empty() && !is_failure_value(operand),
    }
}

/// The comparison written right after a call's `)`, `rest` being the
/// text that follows it: `!== 0`, `=== false`, `is not None`,
/// `!= base`. The operand is the token that follows the operator.
fn compared_after(rest: &str) -> bool {
    let rest = rest.trim_start();
    // Longest operator first: `===` before `==`, `is not` before `is`.
    let operators = [
        ("!==", Comparison::NotEqual),
        ("===", Comparison::Equal),
        ("!=", Comparison::NotEqual),
        ("==", Comparison::Equal),
        ("is not ", Comparison::NotEqual),
        ("is ", Comparison::Equal),
    ];
    let Some((operator, comparison)) = operators.iter().find(|(op, _)| rest.starts_with(op)) else {
        return false;
    };
    let operand = rest[operator.len()..].trim_start();
    let end = operand
        .bytes()
        .position(|b| !is_operand_byte(b))
        .unwrap_or(operand.len());
    compares_to_failure(*comparison, &operand[..end])
}

/// The comparison written before a call (the "Yoda" order PHP code
/// favors), `before` being the text up to the callee name: `0 !==
/// strpos(...)`, `false === str_starts_with(...)`.
fn compared_before(before: &str) -> bool {
    let before = before.trim_end();
    let operators = [
        ("!==", Comparison::NotEqual),
        ("===", Comparison::Equal),
        ("!=", Comparison::NotEqual),
        ("==", Comparison::Equal),
    ];
    let Some((operator, comparison)) = operators.iter().find(|(op, _)| before.ends_with(op)) else {
        return false;
    };
    let operand = before[..before.len() - operator.len()].trim_end();
    let start = operand
        .bytes()
        .rposition(|b| !is_operand_byte(b))
        .map_or(0, |i| i + 1);
    compares_to_failure(*comparison, &operand[start..])
}

/// Start of the callee written before the `(` at `open`: the name and
/// its receiver (`$this->path.startsWith`, `os.path.commonpath`,
/// `\strpos`), so that what comes before it is the comparison of a Yoda
/// condition.
fn callee_start(bytes: &[u8], open: usize) -> usize {
    let mut start = open;
    while start > 0 && bytes[start - 1].is_ascii_whitespace() {
        start -= 1;
    }
    loop {
        match bytes[..start] {
            [.., b'-', b'>'] => start -= 2,
            [.., b]
                if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$' | b'.' | b':' | b'\\') =>
            {
                start -= 1
            }
            _ => return start,
        }
    }
}

/// Byte offsets of the `(` of every call whose result the line compares
/// to the value of a failed check (ticket #250): `strpos($p, $base) !==
/// 0`, `p.startsWith(base) == false`, `os.path.commonpath([base, p]) !=
/// base`, `re.match(...) is None`, `false === str_starts_with(...)`.
///
/// Such a comparison is the negation of the check written without `!`
/// or `not`: a guard whose body leaves the function when the check fails.
/// The engine reads it on the call of a sanitizer only
/// (`transfer::sanitizer_compared_to_failure`), not anywhere on the line
/// as the `!` negation is: `if (p != null && p.startsWith(base))` holds
/// when the check succeeded, and its `!=` is not a negation of it.
///
/// Calls are found by pairing the parentheses of the line, string
/// literals skipped (a `)` inside quotes closes nothing). A `(` is a call
/// when a name ends right before it; the `(` of the `if` itself is never
/// followed by a comparison. Deliberate deviation from the Audit, whose
/// dataflow engine only took `not`/`in` and a `!` not followed by `=` as
/// the negation of a guard.
fn failure_compared_calls(text: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut open_parens: Vec<usize> = Vec::new();
    let mut calls = Vec::new();
    let mut quote: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' {
                // The escaped byte is skipped with the backslash.
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
        } else {
            match b {
                b'"' | b'\'' | b'`' => quote = Some(b),
                b'(' => open_parens.push(i),
                b')' => {
                    if let Some(open) = open_parens.pop() {
                        let start = callee_start(bytes, open);
                        // A name between the callee start and the `(`.
                        let is_call = bytes[start..open].iter().any(|b| !b.is_ascii_whitespace());
                        if is_call
                            && (compared_after(&text[i + 1..]) || compared_before(&text[..start]))
                        {
                            calls.push(open);
                        }
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    calls
}

/// Reassignment to a literal inside a guard
/// `if (!check(x)) x = "literal";` (same physical line as the if).
/// The PHP `$` is part of the captured name: the PHP engine keeps it in
/// its variable names (`$next`). The Audit's pattern allowed `\$?` before
/// the group; the first port had lost it, so a PHP guard
/// `if (!filter_var($next, ...)) { $next = '/'; }` left `$next` tainted
/// (ticket #157).
static GUARD_REASSIGN_SAMELINE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"\)\s*\{?\s*(\$?[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:["'][^"']*["']|[+-]?[0-9]+|null|None|undefined|true|false)"#,
    )
    .expect("regex statique valide")
});

/// Same idiom, but as a whole following line (multi-line guard body).
/// Anchored at the start of the line (standalone statement, not a
/// continuation of `)`). Same `$` as `GUARD_REASSIGN_SAMELINE_RE`.
static GUARD_REASSIGN_NEXTLINE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"^\s*(\$?[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:["'][^"']*["']|[+-]?[0-9]+|null|None|undefined|true|false)\s*;"#,
    )
    .expect("regex statique valide")
});

/// String literals (single/double quote, and backtick), to strip them
/// from the text before a substring search (variable name). The quote
/// alternatives are those of `lexical_taint.py::_STRING_LIT_STRIP_RE` —
/// unambiguous partition (each repetition of `(?:\\.[^"\\]*)*` starts
/// on a literal backslash excluded from the previous group), no
/// exponential backtracking despite the appearance of nested
/// quantifiers. The backtick alternative is a deliberate addition (ticket
/// #221): a JavaScript template without interpolation is SQL or HTML text
/// like any other literal, and its words (a column `name`) were taken for
/// the variable of the same name; `strip_plain_string_literals` keeps a
/// backtick literal holding a `$`, so a template that interpolates and a
/// PHP shell command (`` `ls $dir` ``) are still searched.
static STRING_LIT_STRIP_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#""[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|`[^`\\]*(?:\\.[^`\\]*)*`"#,
    )
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
/// `return f'...{bar}...'`. A backtick literal holding a `$` is kept
/// too (JS interpolation, PHP shell command). A "flat" literal (e.g. SQL
/// text, a template without interpolation) is indeed stripped.
pub(crate) fn strip_plain_string_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for m in STRING_LIT_STRIP_RE.find_iter(text) {
        out.push_str(&text[last..m.start()]);
        let matched = m.as_str();
        let interpolates = matched.contains('{')
            || matched.contains('}')
            || (matched.starts_with('`') && matched.contains('$'));
        if interpolates {
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

/// The value of `cell`, computed by `init` when the cell is empty,
/// without waiting for another thread (ticket #240).
///
/// The cells of [`SourceLines`] are shared by the rules of a pass, which
/// run in parallel over the same files in the same order: they reach a
/// line together. With `OnceLock::get_or_init`, one rule computed it while
/// the others slept until it was done; waking them up cost more than the
/// computation itself, and on the `Java` project the threads spent more
/// time waiting than working. Here each rule that finds the cell empty
/// computes the value itself and the first one stored is kept. The value
/// only depends on the line, so every rule reads the same answer.
fn get_or_compute<T>(cell: &OnceLock<T>, init: impl FnOnce() -> T) -> &T {
    if let Some(value) = cell.get() {
        return value;
    }
    // Another thread may have stored its value meanwhile: `set` then
    // drops this one, equal to it.
    let _ = cell.set(init());
    cell.get().expect("stored above or by another thread")
}

/// The guard facts of every line of one file, each computed on first
/// use. They do not depend on the rule: a table shared by every rule of
/// a scan computes them once per line instead of once per rule and per
/// line, which was about 18 % of the taint time of a C# scan with 19
/// rules (ticket #240).
#[derive(Default)]
struct GuardTable {
    /// One slot per line, allocated when the first guard of the file is
    /// asked for.
    slots: OnceLock<Box<[OnceLock<GuardFacts>]>>,
}

impl GuardTable {
    /// Guard facts of line `lineno` (1-based) of `lines`, the lines this
    /// table belongs to; `None` outside the file.
    fn get(&self, lines: &SourceLines, lineno: usize) -> Option<&GuardFacts> {
        let text = lineno.checked_sub(1).and_then(|i| lines.get(i))?;
        let slots = get_or_compute(&self.slots, || {
            (0..lines.len()).map(|_| OnceLock::new()).collect()
        });
        Some(get_or_compute(&slots[lineno - 1], || {
            GuardFacts::compute(text)
        }))
    }
}

/// The text of one file and its lines, with the facts of its lines that
/// do not depend on the rule, shared by every rule of the scan (ticket
/// #240): what the scan keeps of each file's text, read by the pattern
/// pass, by the language passes through [`RuleLines::shared`], and by
/// the report.
///
/// The text is kept once (ticket #241): a line is a slice of it, found
/// through the offsets where the lines start. A scan used to keep the
/// text four times per file (the bytes read, the text, and two lists of
/// one `String` per line). Line `n` (1-based) is at index `n - 1`
/// ([`SourceLines::get`], `lines[n - 1]`) and keeps its terminator
/// (`\n`, `\r\n`), as the lines read by Python's `readlines()`.
///
/// The facts are filled while the rules run, from several threads: each
/// slot is a `OnceLock`, so a line is computed once.
pub struct SourceLines {
    text: String,
    /// Offset in `text` where each line starts, then the length of
    /// `text`: line index `i` is `text[bounds[i]..bounds[i + 1]]`. Never
    /// empty.
    bounds: Vec<usize>,
    guards: GuardTable,
    /// The answers of the raw regexes of the pass's rules on each line
    /// (`expr_table.rs`), with the number of the table that computed
    /// them: allocated when the first rule reaches the file.
    exprs: OnceLock<(usize, Box<[OnceLock<ExprBits>]>)>,
}

impl SourceLines {
    /// The lines of `text`, each ending after its `\n` (the last one
    /// without, when the text does not end with one): the split of
    /// `str::split_inclusive('\n')`, which the scan has always used. An
    /// empty text has no line. No fact is computed yet.
    pub fn from_text(text: String) -> Self {
        let mut bounds = vec![0];
        bounds.extend(text.match_indices('\n').map(|(at, _)| at + 1));
        if bounds.last() != Some(&text.len()) {
            bounds.push(text.len());
        }
        Self::with_bounds(text, bounds)
    }

    fn with_bounds(text: String, bounds: Vec<usize>) -> Self {
        Self {
            text,
            bounds,
            guards: GuardTable::default(),
            exprs: OnceLock::new(),
        }
    }

    /// The whole text of the file.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Number of lines.
    pub fn len(&self) -> usize {
        self.bounds.len() - 1
    }

    /// Whether the file has no line (empty text).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The line at `index` (line number `index + 1`), terminator
    /// included; `None` past the last line.
    pub fn get(&self, index: usize) -> Option<&str> {
        let end = *self.bounds.get(index + 1)?;
        Some(&self.text[self.bounds[index]..end])
    }

    /// The lines, in order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &str> + ExactSizeIterator + Clone {
        self.bounds
            .windows(2)
            .map(|bounds| &self.text[bounds[0]..bounds[1]])
    }

    /// The lines numbered from 1, each as its own `String`: the form the
    /// pattern rules read (`engine::dispatch_rule`). Built for one file
    /// at a time and dropped after its rules ran, so the scan does not
    /// keep a second copy of every text (ticket #241).
    pub fn numbered_lines(&self) -> Vec<(usize, String)> {
        self.iter()
            .enumerate()
            .map(|(i, line)| (i + 1, line.to_string()))
            .collect()
    }

    /// Computes the answers of every pattern of `table` on every line,
    /// before the rules run (ticket #240). Left to the first rule that
    /// reaches a line, the rules of a pass, which reach the lines
    /// together, either waited for one another or computed the same line
    /// several times: 90 s of CPU more on the `Java` project. Lines the
    /// file already answered for another table are left alone (the rules
    /// then test their own regexes, see [`SourceLines::expr_bits`]).
    pub fn fill_exprs(&self, table: &ExprTable) {
        for lineno in 1..=self.len() {
            if self.expr_bits(lineno, table).is_none() {
                return;
            }
        }
    }

    /// The answers of every pattern of `table` on line `lineno`
    /// (1-based), computed on first use; `None` outside the file, or
    /// when the answers kept for the file are those of another table (a
    /// file read by two passes: the rule then tests its own regexes).
    fn expr_bits(&self, lineno: usize, table: &ExprTable) -> Option<&ExprBits> {
        let text = lineno.checked_sub(1).and_then(|i| self.get(i))?;
        let (id, slots) = get_or_compute(&self.exprs, || {
            (
                table.id(),
                (0..self.len()).map(|_| OnceLock::new()).collect(),
            )
        });
        (*id == table.id()).then(|| get_or_compute(&slots[lineno - 1], || table.matches(text)))
    }
}

impl Index<usize> for SourceLines {
    type Output = str;

    /// The line at `index`, as [`SourceLines::get`]; panics past the
    /// last line, as a slice index does.
    fn index(&self, index: usize) -> &str {
        self.get(index).unwrap_or_else(|| {
            panic!(
                "line index {index} out of range for a file of {} lines",
                self.len()
            )
        })
    }
}

/// The given lines, kept as they are: a line need not end with `\n`
/// (the tests write lines without terminator), so the text is their
/// concatenation and each line keeps its own bounds.
impl<S: AsRef<str>> FromIterator<S> for SourceLines {
    fn from_iter<I: IntoIterator<Item = S>>(lines: I) -> Self {
        let mut text = String::new();
        let mut bounds = vec![0];
        for line in lines {
            text.push_str(line.as_ref());
            bounds.push(text.len());
        }
        Self::with_bounds(text, bounds)
    }
}

/// The source lines of every file of a language pass, keyed by file
/// path: what the call graphs read to compute the summaries.
pub type LinesByFile = std::collections::BTreeMap<String, Arc<SourceLines>>;

/// The source lines of one file, with the per-line facts of one rule.
///
/// Dereferences to the lines themselves ([`SourceLines`], line `n` at
/// index `n - 1`), so code that only reads the text keeps indexing it as
/// before. See the module doc for what is cached and why.
pub struct RuleLines<'a> {
    lines: &'a SourceLines,
    /// The lines with the facts shared by the rules of the scan
    /// ([`RuleLines::shared`]), else `None` and `own_guards` is used.
    shared: Option<&'a SourceLines>,
    /// The guard table of lines given without one ([`RuleLines::new`]):
    /// a test, or a file the pass did not prepare.
    own_guards: GuardTable,
    rule_id: String,
    spec_counts: (usize, usize, usize),
    /// One slot per line, allocated when the first fact of the file is
    /// asked for: building the table of every file of a project for a
    /// rule costs nothing for the files the rule never reaches.
    facts: OnceLock<Vec<OnceLock<Box<LineFacts>>>>,
}

impl<'a> RuleLines<'a> {
    /// Binds the lines of a file to the rule described by `specs`. The
    /// guard facts are computed for this rule only: see
    /// [`RuleLines::shared`] for lines shared by the rules of a scan.
    pub fn new(lines: &'a SourceLines, specs: &RuleSpecs) -> Self {
        Self {
            lines,
            shared: None,
            own_guards: GuardTable::default(),
            rule_id: specs.rule_id.clone(),
            spec_counts: spec_counts(specs),
            facts: OnceLock::new(),
        }
    }

    /// Binds the lines of a file to the rule described by `specs`,
    /// reading the guard facts and the answers of the raw regexes from
    /// `lines`, shared by every rule (ticket #240).
    pub fn shared(lines: &'a SourceLines, specs: &RuleSpecs) -> Self {
        Self {
            shared: Some(lines),
            ..Self::new(lines, specs)
        }
    }

    /// The raw lines of the file.
    pub fn lines(&self) -> &'a SourceLines {
        self.lines
    }

    /// Text of line `lineno` (1-based), `None` outside the file.
    pub fn line(&self, lineno: usize) -> Option<&'a str> {
        lineno.checked_sub(1).and_then(|i| self.lines.get(i))
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
        Some(slot.get_or_init(|| {
            let bits = self
                .shared
                .zip(specs.exprs.as_ref())
                .and_then(|(lines, exprs)| {
                    lines
                        .expr_bits(lineno, &exprs.table)
                        .map(|bits| (bits, exprs.as_ref()))
                });
            Box::new(LineFacts::compute(text, specs, bits))
        }))
    }

    /// Guard facts of line `lineno` (1-based), computed on first use;
    /// `None` outside the file. They do not depend on the rule.
    pub fn guard(&self, lineno: usize) -> Option<&GuardFacts> {
        self.shared
            .map_or(&self.own_guards, |lines| &lines.guards)
            .get(self.lines, lineno)
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
    type Target = SourceLines;

    fn deref(&self) -> &SourceLines {
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
    /// The specs of `specs` whose raw regex matches `text`. With `bits`,
    /// the answers the line computed for every rule of the pass and the
    /// numbers of this rule's regexes in them (ticket #240); without,
    /// each regex is tested here. Same answers either way.
    fn compute(
        text: &str,
        specs: &RuleSpecs,
        bits: Option<(&ExprBits, &super::expr_table::RuleExprs)>,
    ) -> Self {
        #[cfg(test)]
        FACT_COMPUTATIONS.with(|count| count.set(count.get() + 1));
        // Whether spec `index` of a list, of raw regex `regex` and
        // number `ids[index]` in the table, matches the line.
        let hit = |regex: Option<&Regex>,
                   ids: fn(&super::expr_table::RuleExprs) -> &[Option<usize>],
                   index: usize| {
            let Some(regex) = regex else { return false };
            match bits {
                Some((bits, exprs)) => match ids(exprs).get(index).copied().flatten() {
                    Some(id) => bits.contains(id),
                    None => matches(regex, text),
                },
                None => matches(regex, text),
            }
        };
        let first_sanitizer = specs
            .sanitizers
            .iter()
            .enumerate()
            .position(|(i, s)| hit(s.raw_regex.as_ref(), |e| &e.sanitizers, i));
        let sources = specs
            .sources
            .iter()
            .enumerate()
            .filter(|(i, s)| hit(s.raw_regex.as_ref(), |e| &e.sources, *i))
            .map(|(i, _)| i)
            .collect();
        let sinks = specs
            .sinks
            .iter()
            .enumerate()
            .filter(|(i, s)| hit(s.raw_regex.as_ref(), |e| &e.sinks, *i))
            .map(|(i, _)| i)
            .collect();
        Self {
            first_sanitizer,
            sources,
            sinks,
            sink_scan: OnceLock::new(),
            without_literals: OnceLock::new(),
            trimmed: OnceLock::new(),
        }
    }
}

/// Guard patterns of one line, independent of the rule.
#[cfg_attr(test, derive(Debug, PartialEq))]
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
    /// Byte offsets of the `(` of the calls an `if` line compares to the
    /// value of a failed check (`strpos($p, $base) !== 0`), see
    /// [`failure_compared_calls`]; empty on any other line. Ticket #250.
    pub failure_compared_calls: Vec<usize>,
}

#[cfg(test)]
thread_local! {
    /// Number of `GuardFacts::compute` calls on this thread: lets the
    /// tests check that the rules of a scan share a line's guard facts.
    static GUARD_COMPUTATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl GuardFacts {
    fn compute(text: &str) -> Self {
        #[cfg(test)]
        GUARD_COMPUTATIONS.with(|count| count.set(count.get() + 1));
        let stripped = text.trim_start();
        let capture = |rx: &regex::Regex| {
            rx.captures(text)
                .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        };
        let starts_python_if = stripped.starts_with("if ") || stripped.starts_with("elif ");
        let starts_brace_if = stripped.starts_with("if (") || stripped.starts_with("if(");
        Self {
            indent: text.len() - stripped.len(),
            is_blank: text.trim().is_empty(),
            starts_python_if,
            starts_brace_if,
            has_not_or_in: text.contains(" not ") || text.contains(" in "),
            negation_bang: has_negation_bang(text),
            terminator: GUARD_TERMINATOR_RE.is_match(text),
            terminator_same_line: GUARD_TERMINATOR_SAMELINE_RE.is_match(text),
            reassign_same_line: capture(&GUARD_REASSIGN_SAMELINE_RE),
            reassign_next_line: capture(&GUARD_REASSIGN_NEXTLINE_RE),
            // Only a condition is read for its comparisons.
            failure_compared_calls: if starts_python_if || starts_brace_if {
                failure_compared_calls(text)
            } else {
                Vec::new()
            },
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
    /// The same lines, literals kept: where the arguments of the call are
    /// read for a sink that names its argument (`call_arguments`, ticket
    /// #221).
    pub span: String,
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
    fn compute(lines: &SourceLines, lineno: usize, specs: &RuleSpecs) -> Self {
        let line_text = &lines[lineno - 1];
        let mut paren_depth =
            line_text.matches('(').count() as i64 - line_text.matches(')').count() as i64;
        if paren_depth <= 0 {
            return Self {
                continuation_sanitized: false,
                text_without_literals: strip_plain_string_literals(line_text),
                span: line_text.to_string(),
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
        let span = span.join("\n");
        Self {
            continuation_sanitized,
            text_without_literals: strip_plain_string_literals(&span),
            span,
        }
    }
}

/// The arguments of the call that `sink` matches in `span` (the sink line
/// and the continuation lines of its call), as written, in order.
///
/// The sink is looked for on the first line of `span` only, where the
/// line layer found it: a pattern with a look-ahead over the rest of the
/// line (`\.execute\s*\((?![^)]*,)`) would no longer match once the
/// continuation lines follow. The call opens at the last `(` of the sink's
/// match, or else at the first `(` after it; arguments are split on the commas at the top level of that
/// call, skipping string literals (`'`, `"` and `` ` ``, with backslash
/// escapes) and nested `()`, `[]` and `{}`. `None` when `sink` does not
/// match the sink line, when no `(` follows the match, or when the call does not
/// close within `span`: the caller then searches the whole call, as before
/// ticket #221, so an unreadable call never loses a finding.
///
/// Not a parser: a quote inside a comment of a multi-line call can
/// unbalance the split, which ends as `None` (whole call searched).
pub fn call_arguments(span: &str, sink: &Regex) -> Option<Vec<String>> {
    let sink_line = span.split('\n').next().unwrap_or(span);
    let found = sink.find(sink_line).ok().flatten()?;
    let open = match found.as_str().rfind('(') {
        Some(offset) => found.start() + offset,
        None => found.end() + span[found.end()..].find('(')?,
    };
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in span[open + 1..].chars() {
        if let Some(q) = quote {
            current.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => {
                quote = Some(c);
                current.push(c);
            }
            '(' | '[' | '{' => {
                depth += 1;
                current.push(c);
            }
            ')' | ']' | '}' if depth > 0 => {
                depth -= 1;
                current.push(c);
            }
            ')' => {
                if !current.trim().is_empty() || !arguments.is_empty() {
                    arguments.push(current.trim().to_string());
                }
                return Some(arguments);
            }
            ',' if depth == 0 => {
                arguments.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    None
}

/// The [`RuleLines`] of every file of a project for one rule, keyed by
/// file path: what the call graphs hand to each summary computation.
pub type RuleLinesByFile<'a> = std::collections::BTreeMap<&'a str, RuleLines<'a>>;

/// Binds the lines of every file in `lines_by_file` to the rule
/// `specs`, sharing their guard facts with the other rules. Cheap: a
/// file's per-line table is only allocated when a summary of that file
/// first reads a fact.
pub fn rule_lines_by_file<'a>(
    lines_by_file: &'a LinesByFile,
    specs: &RuleSpecs,
) -> RuleLinesByFile<'a> {
    lines_by_file
        .iter()
        .map(|(path, lines)| (path.as_str(), RuleLines::shared(lines, specs)))
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

    fn arguments(span: &str) -> Option<Vec<String>> {
        call_arguments(span, &regex(r"\.query\s*\("))
    }

    /// The split respects strings holding commas and parentheses, template
    /// literals, nested brackets and continuation lines (ticket #221).
    #[test]
    fn test_call_arguments_splits_at_the_top_level_of_the_call() {
        assert_eq!(
            arguments(r#"db.query("SELECT a, b FROM t WHERE f(x) = $1", [id, other]);"#).unwrap(),
            vec![r#""SELECT a, b FROM t WHERE f(x) = $1""#, "[id, other]"]
        );
        assert_eq!(
            arguments("m.query(\n  `SELECT * WHERE ((n LIKE '%:c%')) ORDER BY n`,\n  { replacements: { c } }\n).then(f)")
                .unwrap(),
            vec!["`SELECT * WHERE ((n LIKE '%:c%')) ORDER BY n`", "{ replacements: { c } }"]
        );
        assert_eq!(
            arguments(r#"db.query('it\'s, (x)', fn(a, b))"#).unwrap(),
            vec![r#"'it\'s, (x)'"#, "fn(a, b)"]
        );
        assert_eq!(arguments("db.query()").unwrap(), Vec::<String>::new());
        // The look-ahead of the sink (Python `taint_sqli`) is read on the
        // sink line only: over the whole call it would not match.
        let with_look_ahead = regex(r"\.execute\s*\((?![^)]*,)");
        assert_eq!(
            call_arguments(
                "cursor.execute(\n    \"SELECT %s\",\n    (term,),\n)",
                &with_look_ahead
            )
            .unwrap(),
            vec!["\"SELECT %s\"", "(term,)", ""]
        );
    }

    /// No call to split: `None`, and the caller searches the whole call.
    #[test]
    fn test_call_arguments_none_when_the_call_cannot_be_read() {
        assert_eq!(arguments("db.query(\"never closed\", [x]"), None);
        assert_eq!(arguments("nothing to see"), None);
        assert_eq!(
            call_arguments("db.CommandText = x", &regex(r"\.CommandText\s*=")),
            None
        );
    }

    /// A template literal without interpolation is stripped like any other
    /// literal; one holding a `$` is kept (JS interpolation, PHP shell
    /// command) (ticket #221).
    #[test]
    fn test_strip_plain_string_literals_handles_backtick_literals() {
        assert_eq!(
            strip_plain_string_literals("q(`SELECT name FROM t`, name)"),
            "q( , name)"
        );
        assert_eq!(
            strip_plain_string_literals("q(`SELECT ${name}`)"),
            "q(`SELECT ${name}`)"
        );
        assert_eq!(
            strip_plain_string_literals("$out = `ls $dir`;"),
            "$out = `ls $dir`;"
        );
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
            summary_fallback: None,
            exprs: None,
        }
    }

    fn lines(text: &str) -> SourceLines {
        text.lines().collect()
    }

    /// Ticket #241: the lines of a text are the slices
    /// `str::split_inclusive('\n')` gives, the split the scan used when
    /// it kept one `String` per line.
    #[test]
    fn test_lines_of_a_text_are_those_of_split_inclusive() {
        for text in [
            "",
            "a",
            "a\n",
            "a\nb",
            "a\r\nb\r\n",
            "\n\n",
            "\n",
            "é\nà€\n𝄞",
            "x = 1\n\n  y\n",
        ] {
            let lines = SourceLines::from_text(text.to_string());
            let expected: Vec<&str> = text.split_inclusive('\n').collect();
            assert_eq!(lines.iter().collect::<Vec<_>>(), expected, "{text:?}");
            assert_eq!(lines.len(), expected.len());
            assert_eq!(lines.text(), text);
            for (index, line) in expected.iter().enumerate() {
                assert_eq!(lines.get(index), Some(*line));
                assert_eq!(&lines[index], *line);
            }
            assert_eq!(lines.get(expected.len()), None);
            let numbered: Vec<(usize, String)> = expected
                .iter()
                .enumerate()
                .map(|(i, l)| (i + 1, l.to_string()))
                .collect();
            assert_eq!(lines.numbered_lines(), numbered);
        }
    }

    /// Lines given one by one keep their own bounds, terminator or not.
    #[test]
    fn test_lines_given_one_by_one_are_kept_as_given() {
        let lines: SourceLines = ["a = 1", "", "b\n", "c"].into_iter().collect();
        assert_eq!(lines.iter().collect::<Vec<_>>(), ["a = 1", "", "b\n", "c"]);
        assert_eq!(lines.text(), "a = 1b\nc");
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

        let line = rule_lines.guard(1).unwrap();
        assert_eq!(line.indent, 4);
        assert!(line.starts_brace_if && line.starts_python_if);
        assert!(line.negation_bang && !line.has_not_or_in);
        assert_eq!(line.reassign_same_line.as_deref(), Some("x"));
        assert!(!line.terminator_same_line);

        let body = rule_lines.guard(2).unwrap();
        assert!(body.terminator && body.indent == 8 && !body.is_blank);
        assert!(rule_lines.guard(3).unwrap().is_blank);
        assert_eq!(
            rule_lines.guard(4).unwrap().reassign_next_line.as_deref(),
            Some("y")
        );
    }

    /// The guard facts and the literal stripping as the former engine
    /// computed them: every fixed pattern on `fancy_regex`, `!` negation
    /// as `!(?!=)` (ticket #240). The oracle of the two tests below.
    fn former_engine(text: &str) -> (GuardFacts, String) {
        /// The fixed patterns compiled on `fancy_regex`, once.
        struct Former {
            negation: Regex,
            terminator: Regex,
            terminator_same_line: Regex,
            reassign_same_line: Regex,
            reassign_next_line: Regex,
            literals: Regex,
        }
        static FORMER: LazyLock<Former> = LazyLock::new(|| Former {
            negation: Regex::new(r"!(?!=)").unwrap(),
            terminator: Regex::new(GUARD_TERMINATOR_RE.as_str()).unwrap(),
            terminator_same_line: Regex::new(GUARD_TERMINATOR_SAMELINE_RE.as_str()).unwrap(),
            reassign_same_line: Regex::new(GUARD_REASSIGN_SAMELINE_RE.as_str()).unwrap(),
            reassign_next_line: Regex::new(GUARD_REASSIGN_NEXTLINE_RE.as_str()).unwrap(),
            literals: Regex::new(STRING_LIT_STRIP_RE.as_str()).unwrap(),
        });
        let former = &*FORMER;
        let capture = |rx: &Regex| {
            rx.captures(text)
                .ok()
                .flatten()
                .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        };
        let stripped = text.trim_start();
        let facts = GuardFacts {
            indent: text.len() - stripped.len(),
            is_blank: text.trim().is_empty(),
            starts_python_if: stripped.starts_with("if ") || stripped.starts_with("elif "),
            starts_brace_if: stripped.starts_with("if (") || stripped.starts_with("if("),
            has_not_or_in: text.contains(" not ") || text.contains(" in "),
            negation_bang: matches(&former.negation, text),
            terminator: matches(&former.terminator, text),
            terminator_same_line: matches(&former.terminator_same_line, text),
            reassign_same_line: capture(&former.reassign_same_line),
            reassign_next_line: capture(&former.reassign_next_line),
            // No former engine: the comparisons are new (ticket #250),
            // computed as `compute` does.
            failure_compared_calls: if stripped.starts_with("if ")
                || stripped.starts_with("elif ")
                || stripped.starts_with("if(")
            {
                failure_compared_calls(text)
            } else {
                Vec::new()
            },
        };
        let literals = &former.literals;
        let mut without = String::new();
        let mut last = 0;
        for m in literals.find_iter(text) {
            let m = m.expect("no backtracking limit on this pattern");
            without.push_str(&text[last..m.start()]);
            let matched = m.as_str();
            if matched.contains('{')
                || matched.contains('}')
                || (matched.starts_with('`') && matched.contains('$'))
            {
                without.push_str(matched);
            } else {
                without.push(' ');
            }
            last = m.end();
        }
        without.push_str(&text[last..]);
        (facts, without)
    }

    fn assert_engines_agree(text: &str) {
        let (facts, without) = former_engine(text);
        assert_eq!(GuardFacts::compute(text), facts, "guard facts of {text:?}");
        assert_eq!(
            strip_plain_string_literals(text),
            without,
            "literals of {text:?}"
        );
    }

    /// Ticket #250: the calls an `if` line compares to the value of a
    /// failed check, by the offset of their `(`; a comparison that holds
    /// when the check succeeded names no call.
    #[test]
    fn test_failure_compared_calls() {
        fn compared(text: &str) -> Vec<&str> {
            GuardFacts::compute(text)
                .failure_compared_calls
                .iter()
                .map(|&open| {
                    let start = callee_start(text.as_bytes(), open);
                    &text[start..open]
                })
                .collect()
        }
        // Compared to a failure value, after or before the call.
        assert_eq!(
            compared("if (strpos($path, $base) !== 0) { exit; }"),
            ["strpos"]
        );
        assert_eq!(
            compared("if (strpos($path, $base) === false) exit;"),
            ["strpos"]
        );
        assert_eq!(
            compared("if (0 !== strpos($path, $base)) exit;"),
            ["strpos"]
        );
        assert_eq!(
            compared("if (false === \\str_starts_with($p, $b)) exit;"),
            ["\\str_starts_with"]
        );
        assert_eq!(
            compared("if os.path.commonpath([base, path]) != base:"),
            ["os.path.commonpath"]
        );
        assert_eq!(
            compared("if (path.startsWith(base) == false) throw new X();"),
            ["path.startsWith"]
        );
        assert_eq!(
            compared("if re.match(r'^[a-z]+$', name) is None:"),
            ["re.match"]
        );
        assert_eq!(compared("if f(x) is not True: return"), ["f"]);
        assert_eq!(
            compared("if ($this->p->starts($b) == FALSE) exit;"),
            ["$this->p->starts"]
        );
        // Nested call: only the compared one.
        assert_eq!(
            compared("if (strpos(realpath($p), $base) !== 0) exit;"),
            ["strpos"]
        );
        // Compared to the value of a check that succeeded.
        assert!(compared("if (strpos($p, $base) === 0) { include $p; }").is_empty());
        assert!(compared("if (strpos($p, '..') !== false) exit;").is_empty());
        assert!(compared("if (p.startsWith(base) == true) return;").is_empty());
        assert!(compared("if m(x) is not None: return").is_empty());
        // A comparison that is not on a call result.
        assert!(compared("if (p != null && p.startsWith(base)) return;").is_empty());
        assert!(compared("if (a !== b) { $next = '/'; }").is_empty());
        // A `)` inside a literal closes nothing.
        assert_eq!(compared("if (f(\")\") != 'x') return;"), ["f"]);
        // Only a condition is read.
        assert!(compared("ok = f(x) != 0").is_empty());
    }

    /// Ticket #240: the `regex` crate and the byte search give the
    /// answers of the former `fancy_regex` patterns, on the edge cases
    /// of each pattern.
    #[test]
    fn test_guard_engines_agree() {
        for text in [
            "",
            "   ",
            "if (!ok(x)) x = 'safe';",
            "if (a != b) return;",
            "if (a !== b) { $next = '/'; }",
            "x = !",
            "!=",
            "!!x",
            "a!é",
            "é!=",
            "if not valid(x): raise Forbidden()",
            "    elif x in allowed: return",
            "returned = 1",
            "sys.exit(1)",
            "os._exit(2)",
            "Response.End();",
            "RedirectToAction(\"Index\")",
            "  $v = null;",
            "  v = -12;",
            "v = \"a\" + b;",
            "  ok = undefined ;",
            "f(\"it\\\"s\", 'a\\'b', `t ${x}`, `plain`, \"{y}\")",
            "`ls $dir` and 'unclosed",
            "émoji 🦀 = \"ü\"; return",
        ] {
            assert_engines_agree(text);
        }
    }

    /// Ticket #240: the same comparison on every line of the reference
    /// corpus (`$CODEFIXTURE_AUDIT_NOISE_CORPUS`, else
    /// `AuditBenchmarks/data` beside the repository). Slow, hence
    /// ignored: `cargo test --release -- --ignored guard_engines`.
    #[test]
    #[ignore]
    fn test_guard_engines_agree_on_the_corpus() {
        let root = std::env::var("CODEFIXTURE_AUDIT_NOISE_CORPUS")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../AuditBenchmarks/data")
            });
        assert!(root.is_dir(), "corpus not found: {}", root.display());
        let extensions = [
            "py", "java", "js", "jsx", "mjs", "cjs", "ts", "tsx", "php", "cs",
        ];
        let mut pending = vec![root];
        let (mut files, mut lines) = (0usize, 0usize);
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("readable folder") {
                let path = entry.expect("readable entry").path();
                if path.is_symlink() {
                    continue;
                }
                if path.is_dir() {
                    pending.push(path);
                } else if path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| extensions.contains(&e))
                {
                    let bytes = std::fs::read(&path).expect("readable file");
                    let text = String::from_utf8_lossy(&bytes);
                    for line in text.lines() {
                        assert_engines_agree(line);
                        lines += 1;
                    }
                    files += 1;
                }
            }
        }
        assert!(files > 0, "no source file in the corpus");
        eprintln!("{files} files, {lines} lines: same answers");
    }

    /// Ticket #240: the rules reading the same [`SourceLines`] compute a
    /// line's guard facts once; lines given without a shared table
    /// compute them for each rule, as before.
    #[test]
    fn test_guard_facts_are_shared_by_the_rules() {
        let first = hybrid_specs();
        let second = RuleSpecs {
            rule_id: "other_rule".to_string(),
            ..hybrid_specs()
        };
        let count = || GUARD_COMPUTATIONS.with(|count| count.get());
        let text = lines("if (!ok(x)) return;\nrun(x)");

        let shared = text.iter().collect::<SourceLines>();
        let before = count();
        for specs in [&first, &second, &first] {
            let rule_lines = RuleLines::shared(&shared, specs);
            assert!(rule_lines.guard(1).unwrap().negation_bang);
            assert!(!rule_lines.guard(2).unwrap().terminator);
        }
        assert_eq!(count() - before, 2, "one computation per line");

        let before = count();
        for specs in [&first, &second] {
            RuleLines::new(&text, specs).guard(1);
        }
        assert_eq!(count() - before, 2, "one computation per rule");
    }

    /// Ticket #240: two rules numbered in one table read the answers
    /// their line computed once, and find the facts each rule finds
    /// testing its own regexes.
    #[test]
    fn test_raw_regex_answers_are_shared_by_the_rules() {
        use crate::scan::dataflow::expr_table::{ExprTable, MATCH_COMPUTATIONS};
        let mut first = hybrid_specs();
        let mut second = RuleSpecs {
            rule_id: "other_rule".to_string(),
            sinks: vec![SinkSpec::new("run").with_raw_regex(regex(r"\brun\s*\((?!0)"))],
            ..hybrid_specs()
        };
        let alone = [first.clone(), second.clone()];
        ExprTable::attach([&mut first, &mut second]);
        let text = lines("x = eval(req.body.a)\nrun(escape(q))\nrun(0)\nw = 1");
        let shared = text.iter().collect::<SourceLines>();
        let count = || MATCH_COMPUTATIONS.with(|count| count.get());
        let before = count();
        for (specs, alone) in [(&first, &alone[0]), (&second, &alone[1])] {
            let with_table = RuleLines::shared(&shared, specs);
            let without = RuleLines::new(&text, alone);
            for lineno in 1..=4 {
                let (a, b) = (
                    with_table.facts(lineno, specs).unwrap(),
                    without.facts(lineno, alone).unwrap(),
                );
                assert_eq!(
                    (a.first_sanitizer, &a.sources, &a.sinks),
                    (b.first_sanitizer, &b.sources, &b.sinks),
                    "{} line {lineno}",
                    specs.rule_id
                );
            }
        }
        assert_eq!(count() - before, 4, "one computation per line");
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
