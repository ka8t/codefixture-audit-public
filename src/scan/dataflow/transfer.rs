//! Transfer functions of the dataflow engine — port of
//! `Audit/sca/dataflow/transfer.py`.
//!
//! **Scope of this component**: the pure semantic core (spec
//! resolution, `eval_rhs`/`eval_call`, applying sink/sanitizer/
//! passthrough, per-statement transfer functions, indexed
//! object/list/receiver mutation methods), the hybrid regex matching
//! layer over the source text
//! (`aux_match_line`/`discard_sinks_failing_raw_regex`, §7/§10bis)
//! **and** interprocedural resolution via function summary ("Part 2"
//! on the Python side, §5.2): `FunctionSummary` and
//! `RuleSpecs.summaries` live here rather than in `summary.rs` —
//! Python types this field as `Any` precisely to break the
//! `transfer.py ↔ summary.py` import cycle; Rust has no such
//! weak-typing escape hatch, so `FunctionSummary` (which references
//! `Finding`, already defined here) is co-located with
//! `RuleSpecs`/`Finding` rather than in `summary.rs`, which re-exports
//! it to stay close to the Python structure. `specs.type_map` (Java
//! resolution, always empty on the Python side) ported on 2026-08-25
//! with the Python+Java extension — Round 5/6 (resolving
//! `scr.method()`/`new X().method()`) in `eval_call` below.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock};

use fancy_regex::Regex;

use super::ir::{
    IrStmt, Lhs, Rhs, canon_callee, canon_lhs, canon_rhs, canon_subscript_key, chained_callee_name,
    pretty_rhs,
};
use super::lattice::{SharedText, SourceInfo, State, Taint, join, state_get, state_put};
use super::line_facts::{RuleLines, SourceLines, call_arguments, strip_plain_string_literals};

// ============================================================================
// §10bis — Hybrid matching over the source text
// ============================================================================
//
// The guard patterns and the string-literal stripping moved to
// `line_facts.rs` with the per-line cache (ticket #190).

/// `\b\w+\b`-style identifiers (ASCII) — used to extract the
/// identifiers mentioned on a guard line (§10bis).
static IDENTIFIER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z_][A-Za-z0-9_]*\b").expect("regex statique valide"));

fn extract_identifiers(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for m in IDENTIFIER_RE.find_iter(text).flatten() {
        out.insert(m.as_str().to_string());
    }
    out
}

/// A character that can continue an identifier in one of the scanned
/// languages: a letter or digit (any script), `_`, or `$` (JavaScript
/// and PHP identifiers, PHP variable names).
fn is_identifier_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '$'
}

/// Whether `text` mentions the state key `name` as a whole identifier:
/// an occurrence counts only when it is not glued to a longer word, so
/// a tainted `id` is not seen in `width`, `uuid` or `valid`, nor a
/// tainted `name` in `filename` (ticket #225).
///
/// The boundary is tested only on an edge of `name` that is itself an
/// identifier character. A state key can be a path (`self.x`, `a[0]`,
/// `(a, b)`, `*rest`, see `canon_lhs`): `a[0]` followed by `.x` or
/// `*rest` preceded by a space still match, as they did before.
///
/// Deliberate deviation from `Audit/sca/dataflow/transfer.py`, which
/// tests `var_name in line` (a plain substring test) in the same three
/// places: the sinks loop and the two guard clean-ups.
pub(crate) fn mentions_identifier(text: &str, name: &str) -> bool {
    let (Some(first), Some(last)) = (name.chars().next(), name.chars().next_back()) else {
        return false;
    };
    let check_before = is_identifier_char(first);
    let check_after = is_identifier_char(last);
    text.match_indices(name).any(|(start, _)| {
        let before_ok = !check_before
            || text[..start]
                .chars()
                .next_back()
                .is_none_or(|c| !is_identifier_char(c));
        let after_ok = !check_after
            || text[start + name.len()..]
                .chars()
                .next()
                .is_none_or(|c| !is_identifier_char(c));
        before_ok && after_ok
    })
}

/// Checks the 10 preceding lines for `<id> = ...<var_name>...` where
/// `<id>` is a guard identifier. Covers the pattern
/// `url = urlparse(bar); if url.netloc in [...]: return; redirect(bar)`.
///
/// **No regex here, deliberately**: this function is called in the
/// hot loop of the taint fixpoint (once per generic `if`/`elif` line,
/// on every worklist iteration). The old version compiled a dynamic
/// regex (`Regex::new`) per `(gid, var_name)` pair × up to 10 lines
/// back — profiled (`sample`) on a real 34k-line scan (`Audit/sca`):
/// regex compilation (fancy-regex parse + regex-automata NFA/DFA
/// builder) dominated total CPU time. Replaced by string operations
/// bit-for-bit equivalent to the old pattern
/// `^\s*{gid}\s*=.*\b{var_name}\b`: `trim_start`/`strip_prefix` for
/// the literal anchor, `extract_identifiers` (static regex already
/// compiled once via `LazyLock`) for the `\b...\b` test.
fn backward_aliased_var(
    var_name: &str,
    guard_ids: &BTreeSet<String>,
    lineno: usize,
    source_lines: &SourceLines,
) -> bool {
    for back in 1..=10i64 {
        let idx_back = lineno as i64 - 1 - back;
        if idx_back < 0 {
            return false;
        }
        let prev = &source_lines[idx_back as usize];
        let trimmed = prev.trim_start();
        for gid in guard_ids {
            let Some(after_gid) = trimmed.strip_prefix(gid.as_str()) else {
                continue;
            };
            let Some(after_eq) = after_gid.trim_start().strip_prefix('=') else {
                continue;
            };
            if extract_identifiers(after_eq).contains(var_name) {
                return true;
            }
        }
    }
    false
}

/// Cleans up tainted variables involved in a guard
/// `if EXPR: …return`. Step 1: directly cleans the tainted variables
/// mentioned on the guard line. Step 2: backward aliasing — for each
/// identifier in the guard, scans the 10 preceding lines for an
/// assignment `<id> = ...<var>...`.
fn apply_guard_cleanup(
    state: &mut State,
    line_text: &str,
    lineno: usize,
    source_lines: &SourceLines,
) {
    // Every key of the state is tainted: a `Clean` taint is never stored.
    state.retain(|var_name, _| !mentions_identifier(line_text, var_name));
    let guard_ids = extract_identifiers(line_text);
    state.retain(|var_name, _| !backward_aliased_var(var_name, &guard_ids, lineno, source_lines));
}

fn kind_str_compatible(kind: &str, sink_kinds: &[String]) -> bool {
    sink_kinds.is_empty() || sink_kinds.iter().any(|k| k == kind)
}

fn stmt_lineno(stmt: &IrStmt) -> usize {
    match stmt {
        IrStmt::Assign { lineno, .. }
        | IrStmt::Call { lineno, .. }
        | IrStmt::Return { lineno, .. }
        | IrStmt::Raise { lineno, .. }
        | IrStmt::Branch { lineno, .. }
        | IrStmt::Noop { lineno } => *lineno,
    }
}

/// Revalidates in place the findings added since index `before`
/// against the `raw_regex` of their originating `SinkSpec` — sink
/// resolution via dotted glob (`**.println` matches ANY receiver) is
/// not revalidated by default: a DSL pattern written with a negative
/// lookbehind to exclude a specific receiver (e.g.
/// `(?<!System\.(?:out|err))\.println\s*\(`) must therefore be
/// revalidated here, otherwise the exclusion has no effect on this
/// path (bug found via the `taint_xss_console_clean` regression —
/// `System.out.println` was wrongly flagged as an XSS sink via the
/// `**.println` glob, even though `raw_regex` explicitly excluded
/// it).
///
/// Only removes a finding if at least one spec whose glob matches its
/// `sink_text` exists AND none of those specs validates `raw_regex`
/// against the relevant text — a spec with no `raw_regex` is never
/// filtered out. Relevant text: `sink_text` or the source line (both
/// forms of sink DSL depend on it). The source-line test reads the
/// per-line cache (`LineFacts::sinks`, ticket #190); a line outside the
/// file is tested as empty text, as before.
fn discard_sinks_failing_raw_regex(
    findings: &mut Vec<Finding>,
    before: usize,
    specs: &RuleSpecs,
    source_lines: &RuleLines,
) {
    if before >= findings.len() {
        return;
    }
    let mut kept: Vec<Finding> = findings[..before].to_vec();
    for f in &findings[before..] {
        let candidates: Vec<(usize, &SinkSpec)> = specs
            .sinks
            .iter()
            .enumerate()
            .filter(|(_, s)| match_pattern(&f.sink_text, &s.compiled))
            .collect();
        if candidates.is_empty() {
            kept.push(f.clone());
            continue;
        }
        let facts = source_lines.facts(f.line, specs);
        let passes = candidates.iter().any(|(index, c)| match &c.raw_regex {
            None => true,
            Some(rx) => {
                let line_matches = match facts {
                    Some(facts) => facts.sinks.contains(index),
                    None => rx.is_match("").unwrap_or(false),
                };
                line_matches || rx.is_match(f.sink_text.as_ref()).unwrap_or(false)
            }
        });
        if passes {
            kept.push(f.clone());
        }
    }
    *findings = kept;
}

/// True when one of the rule's sanitizers names the call whose `(` is
/// at byte `paren` of `line`. A sanitizer match names the call whose
/// `(` it holds last (`\.startsWith\s*\(`, or `\bif\s*\(.*\bstrpos\s*\(`
/// for the `strpos` of an `if` line), or the `(` that follows it after
/// whitespace (`re\.match`, `secure_filename`). Shared by the guard
/// written as a comparison (ticket #250) and the check passed on the
/// TRUE edge of a branch (`passed_check.rs`, ticket #252).
///
/// The patterns are read twice (ticket #254):
///
/// - on the whole line: a pattern that goes on after the `(` of its call
///   (`filter_var\s*\([^)]*FILTER_SANITIZE`) only matches there;
/// - on the line up to `paren`, its `(` included: a match covers the text
///   once, so on the whole line a pattern that spans several calls
///   (`\bif\s*\(.*\bstrpos\s*\(` on `if (strpos($a, $b) === 0 &&
///   strpos($c, $d) === 0)`) names only the last one, its greedy `.*`
///   running to the last `strpos(`. Cut at the first call, it names that
///   one.
///
/// The cut text gives the same answer as the whole line for a pattern
/// that reads nothing after the end of its match: no look-ahead, no `$`,
/// no trailing `\b` (a sanitizer of the catalog never has one, checked by
/// `test_sanitizers_read_nothing_after_their_match`).
pub(crate) fn sanitizer_names_call(line: &str, specs: &RuleSpecs, paren: usize) -> bool {
    let up_to_paren = line.get(..=paren);
    specs
        .sanitizers
        .iter()
        .filter_map(|san| san.raw_regex.as_ref())
        .any(|rx| {
            names_paren(rx, line, paren)
                || up_to_paren.is_some_and(|text| names_paren(rx, text, paren))
        })
}

/// True when a match of `rx` in `text` names the call whose `(` is at
/// byte `paren` (see [`sanitizer_names_call`]).
fn names_paren(rx: &Regex, text: &str, paren: usize) -> bool {
    rx.find_iter(text).flatten().any(|m| {
        let named = match m.as_str().rfind('(') {
            Some(offset) => Some(m.start() + offset),
            None => {
                let after = &text[m.end()..];
                let gap = after.len() - after.trim_start().len();
                after[gap..].starts_with('(').then_some(m.end() + gap)
            }
        };
        named == Some(paren)
    })
}

/// True when the line compares the call of one of the rule's
/// sanitizers to the value of a failed check, `strpos($p, $base) !== 0`
/// or `p.startsWith(base) == false` (ticket #250): the guard written
/// without `!` or `not`. `calls` holds the `(` of the calls the line
/// compares so (`GuardFacts::failure_compared_calls`); which call a
/// sanitizer names: [`sanitizer_names_call`].
fn sanitizer_compared_to_failure(line: &str, specs: &RuleSpecs, calls: &[usize]) -> bool {
    calls
        .iter()
        .any(|&paren| sanitizer_names_call(line, specs, paren))
}

/// True when an assignment writes a literal holding no data that the line
/// layer must not mark (ticket #271): an empty associative array (`{}`,
/// and the reset of a PHP keyed array literal lowered key by key), or a
/// constant written to one entry (`$f['status'] = 'active'`). A constant
/// assigned to a whole variable is still marked, as in the Audit: the layer
/// stands in for what the lowering did not model on that line (a minified
/// line, an expression lowered to a constant).
fn holds_no_data(lhs: &Lhs, rhs: &Rhs) -> bool {
    match rhs {
        Rhs::DictRef(items) => items.is_empty(),
        Rhs::Const(_) => matches!(lhs, Lhs::SubscriptLhs { .. }),
        _ => false,
    }
}

/// Auxiliary regex matching against the raw source line (§10bis).
/// For each sink/sanitizer/source spec carrying a `raw_regex`, tests
/// against the statement's source line; on a match, triggers the
/// corresponding behavior.
///
/// Every test that only depends on the line text (raw regexes, guard
/// patterns, literal stripping, multi-line call span) is read from the
/// per-line cache of `source_lines` (`line_facts.rs`, ticket #190): a
/// line holding thousands of statements (minified code) is matched once
/// per rule instead of once per statement and per fixpoint pass. Only
/// what depends on `state` is computed here.
fn aux_match_line(
    stmt: &IrStmt,
    state: &mut State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    source_lines: &RuleLines,
) {
    let lineno = stmt_lineno(stmt);
    let (Some(line_text), Some(facts)) =
        (source_lines.line(lineno), source_lines.facts(lineno, specs))
    else {
        return;
    };
    // The trimmed line, shared by every source, finding and flow step
    // this statement produces (ticket #191).
    let trimmed = || {
        source_lines
            .trimmed(lineno, specs)
            .expect("the line exists: its facts were found")
    };
    let guard = || {
        source_lines
            .guard(lineno)
            .expect("the line exists: its facts were found")
    };
    let lhs_key: Option<String> = if let IrStmt::Assign { lhs, .. } = stmt {
        Some(canon_lhs(lhs))
    } else {
        None
    };
    // Generic guard (before the sanitizers check) — `if EXPR: body`
    // with a terminator (return/raise/abort) in the body and
    // `not`/`in` in the condition. Cleans any tainted variable
    // mentioned on the line. Covers `if '\'' in bar: return` and
    // `if not bar.startswith(...): return` without depending on a
    // specific sanitizer.
    if guard().starts_python_if && guard().has_not_or_in {
        let if_indent = guard().indent;
        for off in 0..8usize {
            // Body line `lineno + off + 1` (1-based).
            let Some(nxt) = source_lines.guard(lineno + off + 1) else {
                break;
            };
            if nxt.is_blank {
                continue;
            }
            if nxt.indent <= if_indent {
                break;
            }
            if nxt.terminator {
                apply_guard_cleanup(state, line_text, lineno, source_lines);
                return;
            }
        }
    }

    // Sanitizers — kills the LHS taint if the line matches (the first
    // matching sanitizer decides, the body does not depend on which).
    if facts.first_sanitizer.is_some() {
        let line_guard = guard();
        // "sanitizer-guard" case (predicate, §10bis):
        // `if not <sanitizer>(x): abort/raise/return/break/sys.exit`.
        let if_indent = line_guard.indent;
        // A brace-language guard can end on its own line:
        // `if (!ALLOWED.Contains(cmd)) return Forbid();`. The Python
        // dataflow engine only looks at the following, more indented
        // lines (its own syntax); the Audit read C#/PHP/JS guards with its
        // lexical engine, which also tests the guard line (ticket #178).
        let mut terminator_nearby = line_guard.starts_brace_if && line_guard.terminator_same_line;
        let mut reassign_var: Option<String> = line_guard.reassign_same_line.clone();
        for off in 0..8usize {
            if terminator_nearby {
                break;
            }
            let Some(nxt) = source_lines.guard(lineno + off + 1) else {
                break;
            };
            if nxt.is_blank {
                continue;
            }
            if nxt.indent <= if_indent {
                break; // exited the if block
            }
            if nxt.terminator {
                terminator_nearby = true;
                break;
            }
            if reassign_var.is_none() {
                reassign_var = nxt.reassign_next_line.clone();
            }
        }
        let has_negation = line_guard.has_not_or_in || line_guard.negation_bang;
        // `if `/`elif ` or `if(`: `starts_brace_if` adds `if(`, its
        // `if (` is already an `if `. A check compared to its failure
        // value (`strpos($p, $base) !== 0`) is a negation too, read last
        // because it searches the sanitizers again (ticket #250).
        let is_guard = (line_guard.starts_python_if || line_guard.starts_brace_if)
            && (terminator_nearby || reassign_var.is_some())
            && (has_negation
                || sanitizer_compared_to_failure(
                    line_text,
                    specs,
                    &line_guard.failure_compared_calls,
                ));
        if is_guard {
            if terminator_nearby {
                let line_text_no_lit = source_lines
                    .text_without_literals(lineno, specs)
                    .expect("the line exists: its facts were found");
                // Every key of the state is tainted: a `Clean` taint is
                // never stored.
                state.retain(|var_name, _| !mentions_identifier(line_text_no_lit, var_name));
            } else if let Some(rv) = &reassign_var {
                state_put(state, rv, Taint::Clean);
            }
            return;
        }
        if let Some(key) = &lhs_key {
            state_put(state, key, Taint::Clean);
        }
        return; // first sanitizer match is enough
    }

    // Does a user assignment line ALSO contain a sink?
    // (`result = eval(request.args.get(...))`). Excludes lowering
    // temporaries `__t{N}` — otherwise a
    // `return f"...request.args..."` (lowered to `__t0 = f"..."`)
    // would reopen detection on a LITERAL (false positive).
    let assign_line_has_sink = lhs_key
        .as_deref()
        .map(|k| !k.starts_with("__t"))
        .unwrap_or(false)
        && !facts.sinks.is_empty();

    // Sources — marks the LHS as tainted (only the first source that
    // matches the line acts: every branch below leaves the loop).
    if let Some(&first_source) = facts.sources.first() {
        let src = &specs.sources[first_source];
        if let Some(key) = &lhs_key {
            // A statement that assigns a literal holding no data takes no
            // source from its line (ticket #271): `$f = array('name' =>
            // $_GET['name'], 'status' => 'active');` is lowered key by key,
            // `$f` reset to an empty array and `$f['status']` set to a
            // constant, and marking them would taint every entry of the
            // array; the entry that receives the source, `$f['name']`, is
            // marked by the data flow and by this layer. Deviation from the
            // Audit, whose layer marks every target of a line holding a
            // source: an empty array or a constant entry never carries one
            // (see `holds_no_data`).
            if !matches!(stmt, IrStmt::Assign { lhs, rhs, .. } if holds_no_data(lhs, rhs)) {
                state_put(
                    state,
                    key,
                    Taint::tainted(
                        [src.kind.clone()],
                        SourceInfo {
                            line: lineno,
                            expr: trimmed(),
                            kind: src.kind.as_str().into(),
                        },
                    ),
                );
            }
            if !assign_line_has_sink {
                return;
            }
            // Otherwise the sinks loop detects the inline flow.
        } else if !matches!(stmt, IrStmt::Call { .. }) {
            // Part 4 — only for a Call statement (direct call): a source
            // passed as an argument can feed a sink on the same line. For
            // a Return/Branch, a LITERAL source in the text must not open
            // sink detection.
            return;
        }
    }

    // Sinks — emits a finding if a taint is visible on the line.
    for &sink_index in &facts.sinks {
        let sink = &specs.sinks[sink_index];
        let scan = source_lines
            .sink_scan(lineno, specs)
            .expect("the line exists: its facts were found");
        // Multi-line call cleared by a sanitizer in its continuation
        // lines (see `SinkScan::compute`).
        if scan.continuation_sanitized {
            continue;
        }
        // A sink that names its argument (`arg_index=<n>` written in the
        // rule) is searched in that argument only: a tainted value bound
        // as a query parameter (`db.query("… $1", [x])`) is not an
        // injection (ticket #221). When the call cannot be split, the
        // whole call is searched, as for a sink that names no argument.
        let named_arguments: Option<String> = if sink.line_args.is_empty() {
            None
        } else {
            sink.raw_regex
                .as_ref()
                .and_then(|rx| call_arguments(&scan.span, rx))
                .map(|arguments| {
                    // The numbered arguments, and the keyword argument
                    // `arg_name=` names wherever it is written (ticket
                    // #261): `Response(body, headers=h)`.
                    let keyword = sink.arg_name.as_deref().and_then(|name| {
                        arguments
                            .iter()
                            .find(|argument| is_keyword_argument(argument, name))
                    });
                    sink.line_args
                        .iter()
                        .filter_map(|index| arguments.get(*index))
                        .chain(keyword)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n")
                })
        };
        let named_without_literals = named_arguments.as_deref().map(strip_plain_string_literals);
        let scan_text_no_lit = named_without_literals
            .as_deref()
            .unwrap_or(scan.text_without_literals.as_str());
        let mut hit = false;
        for (var_name, var_taint) in state.iter() {
            if mentions_identifier(scan_text_no_lit, var_name) && var_taint.is_tainted() {
                if !kinds_compatible(var_taint, &sink.kinds) {
                    continue;
                }
                let mut source_line = None;
                let mut source_kind = "unknown".to_string();
                let mut flow = Vec::new();
                if let Taint::Tainted { source, .. } = var_taint {
                    source_line = Some(source.line);
                    source_kind = if source.kind.is_empty() {
                        "unknown".to_string()
                    } else {
                        source.kind.to_string()
                    };
                    flow.push(FlowStep {
                        line: source.line,
                        kind: "source".to_string(),
                        text: source.expr.clone(),
                        file: None,
                        code: None,
                    });
                }
                flow.push(FlowStep {
                    line: lineno,
                    kind: "sink".to_string(),
                    text: trimmed(),
                    file: None,
                    code: None,
                });
                findings.push(Finding {
                    rule_id: specs.rule_id.clone(),
                    severity: specs.severity.clone(),
                    line: lineno,
                    column: 0,
                    sink_text: trimmed(),
                    source_line,
                    message: specs.message.clone(),
                    cwe: specs.cwe.clone(),
                    flow,
                    source_kind,
                });
                hit = true;
                break; // one finding per sink line is enough
            }
        }

        // Part 4 — source written DIRECTLY on the sink line, with no
        // intermediate variable.
        if !hit {
            for &source_index in &facts.sources {
                let src = &specs.sources[source_index];
                if !kind_str_compatible(&src.kind, &sink.kinds) {
                    continue;
                }
                // Same restriction for a source written in the call: it
                // must sit in the named argument (ticket #221).
                if let (Some(text), Some(rx)) = (named_arguments.as_deref(), src.raw_regex.as_ref())
                    && !rx.is_match(text).unwrap_or(false)
                {
                    continue;
                }
                findings.push(Finding {
                    rule_id: specs.rule_id.clone(),
                    severity: specs.severity.clone(),
                    line: lineno,
                    column: 0,
                    sink_text: trimmed(),
                    source_line: Some(lineno),
                    message: specs.message.clone(),
                    cwe: specs.cwe.clone(),
                    flow: vec![
                        FlowStep {
                            line: lineno,
                            kind: "source".to_string(),
                            text: trimmed(),
                            file: None,
                            code: None,
                        },
                        FlowStep {
                            line: lineno,
                            kind: "sink".to_string(),
                            text: trimmed(),
                            file: None,
                            code: None,
                        },
                    ],
                    source_kind: src.kind.clone(),
                });
                break; // one source is enough
            }
        }
    }
}

// ============================================================================
// Spec format
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecKind {
    Source,
    Sink,
    Sanitizer,
    Passthrough,
    Unknown,
}

/// Compiles an SCA glob pattern (§7.1).
///
/// Supported syntax:
///   - `foo`        : exact match
///   - `foo.bar`    : exact with dots
///   - `foo.*`      : a direct child of foo (1 segment)
///   - `*.execute`  : any execute method (1 segment before)
///   - `**.execute` : any execute method at any depth
///
/// `*` does not cross dots; `**` does.
///
/// A pattern without `*` is compared by string equality (ticket #240).
/// The others are matched by [`GlobPattern::is_match`] directly, without
/// a regex (ticket #246): their regex (`^.*\.execute$`) ran for every call
/// name, every spec and every fixpoint iteration, about a tenth of the CPU
/// of a Java scan in the regex engine, for names of a few dozen bytes.
/// Same answers as the anchored regex `compile_glob_pattern` built (`**`
/// as `.*`, `*` as `[^.]*`, the rest literal): `test_glob_engines_agree`
/// keeps the former `fancy_regex` glob as the oracle.
pub fn compile_glob_pattern(pattern: &str) -> GlobPattern {
    if !pattern.contains('*') {
        return GlobPattern::Exact(pattern.to_string());
    }
    let mut tokens = Vec::new();
    let mut literal = String::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '*' {
            literal.push(c);
            continue;
        }
        if !literal.is_empty() {
            tokens.push(GlobToken::Literal(std::mem::take(&mut literal)));
        }
        if chars.peek() == Some(&'*') {
            chars.next();
            tokens.push(GlobToken::AnyDepth);
        } else {
            tokens.push(GlobToken::OneSegment);
        }
    }
    if !literal.is_empty() {
        tokens.push(GlobToken::Literal(literal));
    }
    GlobPattern::Wildcard(tokens)
}

/// One piece of a wildcard pattern ([`GlobPattern::Wildcard`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobToken {
    /// Text that must appear as written.
    Literal(String),
    /// `*`: any text without a dot (the regex `[^.]*`, which also takes
    /// a line break).
    OneSegment,
    /// `**`: any text without a line break (the regex `.*`).
    AnyDepth,
}

/// A compiled SCA glob pattern ([`compile_glob_pattern`]).
#[derive(Debug, Clone)]
pub enum GlobPattern {
    /// A pattern without `*`: the name itself.
    Exact(String),
    /// A pattern with `*` or `**`, as its pieces in order.
    Wildcard(Vec<GlobToken>),
    /// No name at all: the spec's regex describes a line, not a call
    /// (`rule_loader::describes_a_line`, ticket #272). Only the line layer
    /// reads such a spec, through its raw regex.
    Nothing,
}

impl GlobPattern {
    /// Whether the dotted name `name` matches the pattern.
    pub fn is_match(&self, name: &str) -> bool {
        match self {
            GlobPattern::Exact(exact) => name == exact,
            GlobPattern::Wildcard(tokens) => glob_match(tokens, name),
            GlobPattern::Nothing => false,
        }
    }
}

/// Whether `tokens` cover the whole of `text`. A star tries every length
/// its class allows, shortest first: the patterns of the rules hold one to
/// three stars and the names a few dozen bytes, so the search stays
/// small.
fn glob_match(tokens: &[GlobToken], text: &str) -> bool {
    let Some((first, rest)) = tokens.split_first() else {
        return text.is_empty();
    };
    match first {
        GlobToken::Literal(literal) => text
            .strip_prefix(literal.as_str())
            .is_some_and(|after| glob_match(rest, after)),
        GlobToken::OneSegment | GlobToken::AnyDepth => {
            let stop = if *first == GlobToken::OneSegment {
                '.'
            } else {
                '\n'
            };
            // The shapes of nearly every rule pattern, answered without
            // trying every length: a star at the end takes the rest of the
            // text, a star before a last literal takes the text before
            // that suffix (`**.execute`, `*.GET`).
            match rest {
                [] => return !text.contains(stop),
                [GlobToken::Literal(suffix)] => {
                    return text
                        .strip_suffix(suffix.as_str())
                        .is_some_and(|before| !before.contains(stop));
                }
                _ => {}
            }
            // Every end of the star's text: before each character it may
            // take, and after the last one it takes.
            let ends = text
                .char_indices()
                .take_while(|&(_, c)| c != stop)
                .map(|(at, _)| at)
                .chain(std::iter::once(text.find(stop).unwrap_or(text.len())));
            for end in ends {
                if glob_match(rest, &text[end..]) {
                    return true;
                }
            }
            false
        }
    }
}

/// Matches a dotted name against a pre-compiled glob pattern (§7.1).
pub fn match_pattern(callee_name: &str, compiled: &GlobPattern) -> bool {
    compiled.is_match(callee_name)
}

#[derive(Debug, Clone)]
pub struct SourceSpec {
    pub pattern: String,
    pub kind: String,
    /// Phase 7 — regex over the raw source line (§10bis, next component).
    pub raw_regex: Option<Regex>,
    /// The dotted pattern dropped part of the rule's regex (a look-around,
    /// the text of the arguments): the data flow takes a name matching it
    /// as this source only when `raw_regex` also matches the line (see
    /// [`Site::confirms`]). Ticket #270.
    pub confirm_on_line: bool,
    /// The rule's regex ends with the `[` of an index (`Request\[`,
    /// `\$_GET\[`, `sys\.argv\[`): the source is that collection, read
    /// whole (`print_r($_GET)`, `subprocess.run(sys.argv)`) or into
    /// (`Request["id"]`), never the receiver of one of its members: with
    /// `Request\[`, `Request.HttpContext.User.Identity.Name` is not request
    /// data. Ticket #268, deliberate deviation from the Audit, whose dotted
    /// pattern drops the bracket and makes every `Request.*` read a source,
    /// the signed-in user's name included (eShopOnWeb logged it). A rule
    /// that also means the members writes them as their own source
    /// (`req\.body`, `request\.cookies\.get`).
    pub subscript_only: bool,
    compiled: GlobPattern,
}

impl SourceSpec {
    pub fn new(pattern: impl Into<String>, kind: impl Into<String>) -> Self {
        let pattern = pattern.into();
        let compiled = compile_glob_pattern(&pattern);
        SourceSpec {
            pattern,
            kind: kind.into(),
            raw_regex: None,
            confirm_on_line: false,
            subscript_only: false,
            compiled,
        }
    }

    pub fn with_raw_regex(mut self, re: Regex) -> Self {
        self.raw_regex = Some(re);
        self
    }

    /// The same spec, named by no dotted pattern: its regex describes a
    /// line ([`GlobPattern::Nothing`], ticket #272).
    pub fn describing_a_line(mut self) -> Self {
        self.compiled = GlobPattern::Nothing;
        self
    }
}

#[derive(Debug, Clone)]
pub struct SinkSpec {
    pub pattern: String,
    /// Empty = all arguments.
    pub args: Vec<usize>,
    /// The arguments the rule named itself (`arg_index=<n>` in the `.sca`
    /// file), which the line layer also restricts its search to (ticket
    /// #221). Empty when the rule wrote none: `args` then holds the
    /// default argument 0 for the dataflow path only, and the line layer
    /// searches the whole call, as the Python §10bis layer does.
    pub line_args: Vec<usize>,
    /// The keyword form of the argument `args` names (`arg_name=` in the
    /// `.sca` file, ticket #261): `Response(body, headers=h)` passes the
    /// headers by keyword, `make_response(body, 200, h)` by position. Both
    /// the dataflow path (`check_sink`) and the line layer check it.
    pub arg_name: Option<String>,
    /// Empty = all kinds.
    pub kinds: Vec<String>,
    pub raw_regex: Option<Regex>,
    compiled: GlobPattern,
}

impl SinkSpec {
    pub fn new(pattern: impl Into<String>) -> Self {
        let pattern = pattern.into();
        let compiled = compile_glob_pattern(&pattern);
        SinkSpec {
            pattern,
            args: Vec::new(),
            line_args: Vec::new(),
            arg_name: None,
            kinds: Vec::new(),
            raw_regex: None,
            compiled,
        }
    }

    pub fn with_args(mut self, args: Vec<usize>) -> Self {
        self.args = args;
        self
    }

    /// Restricts the line layer to these arguments too (see `line_args`).
    pub fn with_line_args(mut self, line_args: Vec<usize>) -> Self {
        self.line_args = line_args;
        self
    }

    pub fn with_kinds(mut self, kinds: Vec<String>) -> Self {
        self.kinds = kinds;
        self
    }

    pub fn with_raw_regex(mut self, re: Regex) -> Self {
        self.raw_regex = Some(re);
        self
    }

    /// The same spec, named by no dotted pattern: its regex describes a
    /// line ([`GlobPattern::Nothing`], ticket #272).
    pub fn describing_a_line(mut self) -> Self {
        self.compiled = GlobPattern::Nothing;
        self
    }
}

#[derive(Debug, Clone)]
pub struct SanitizerSpec {
    pub pattern: String,
    pub args: Vec<usize>,
    pub raw_regex: Option<Regex>,
    /// Same as [`SourceSpec::confirm_on_line`], for a sanitizer:
    /// `filter_var\s*\([^)]*FILTER_SANITIZE` cleans a `filter_var` call only
    /// when its line passes the filter the regex names. Ticket #270.
    pub confirm_on_line: bool,
    compiled: GlobPattern,
}

impl SanitizerSpec {
    pub fn new(pattern: impl Into<String>) -> Self {
        let pattern = pattern.into();
        let compiled = compile_glob_pattern(&pattern);
        SanitizerSpec {
            pattern,
            args: Vec::new(),
            raw_regex: None,
            confirm_on_line: false,
            compiled,
        }
    }

    pub fn with_raw_regex(mut self, re: Regex) -> Self {
        self.raw_regex = Some(re);
        self
    }

    /// The same spec, named by no dotted pattern: its regex describes a
    /// line ([`GlobPattern::Nothing`], ticket #272).
    pub fn describing_a_line(mut self) -> Self {
        self.compiled = GlobPattern::Nothing;
        self
    }
}

/// Target of a passthrough's propagation: the return value, or a
/// mutated argument (positional index).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgOut {
    Return,
    Index(usize),
}

#[derive(Debug, Clone)]
pub struct PassthroughSpec {
    pub pattern: String,
    /// Empty = all arguments, unless `receiver_only`.
    pub args_in: Vec<usize>,
    /// No argument passes: the result carries the data of the receiver
    /// only (`arg_index=none` in the `.sca` file, ticket #256): the nodes
    /// `root.xpath(query)` returns are text of the document `root`, never of
    /// the query that selects them.
    pub receiver_only: bool,
    pub arg_out: ArgOut,
    pub raw_regex: Option<Regex>,
    compiled: GlobPattern,
}

impl PassthroughSpec {
    pub fn new(pattern: impl Into<String>) -> Self {
        let pattern = pattern.into();
        let compiled = compile_glob_pattern(&pattern);
        PassthroughSpec {
            pattern,
            args_in: Vec::new(),
            receiver_only: false,
            arg_out: ArgOut::Return,
            raw_regex: None,
            compiled,
        }
    }

    pub fn with_args_in(mut self, args_in: Vec<usize>) -> Self {
        self.args_in = args_in;
        self
    }
}

/// The complete set of specs for a taint rule.
#[derive(Debug, Clone, Default)]
pub struct RuleSpecs {
    pub rule_id: String,
    pub severity: String,
    pub cwe: Option<String>,
    pub message: String,
    pub sources: Vec<SourceSpec>,
    pub sinks: Vec<SinkSpec>,
    pub sanitizers: Vec<SanitizerSpec>,
    pub passthroughs: Vec<PassthroughSpec>,
    /// Part 2 — interprocedural function summaries, indexed by callee
    /// name. Populated by `call_graph.rs::resolve_summaries` before
    /// the main analysis; consulted in `eval_call` to propagate taint
    /// across calls.
    pub summaries: BTreeMap<String, Arc<FunctionSummary>>,
    /// **Java only** — `variable_name/field -> simple_class_name`
    /// (merge of `collect_java_field_types`/`collect_java_local_types`,
    /// locals take priority). Always empty on the Python side (no
    /// declared typed variable to resolve). Lets `eval_call` resolve
    /// `scr.method()` where `scr` is a local variable/field of known
    /// type, falling back to `"{type}.{attr}"` when the variable name
    /// alone matches no summary (a summary key is always indexed by
    /// CLASS name, never by variable name) — Round 5, cf.
    /// `Audit/sca/dataflow/transfer.py`.
    pub type_map: BTreeMap<String, String>,
    /// Summaries looked up only when `summaries` has no entry for the
    /// callee name ([`RuleSpecs::summary`]). Java, Python, JavaScript
    /// and PHP put here what a file sees of the other files (its
    /// package, its imports, its `require`s), looked up on demand
    /// (ticket #239): copying it into `summaries` for every file cost
    /// memory and time growing with the square of the project size
    /// (about 127 GB on the 46,793 files of the Juliet Java suite). Same
    /// answers as the copy: see `visibility.rs` and
    /// `java_visibility.rs`. `None` for C#, whose files read no summary
    /// of another file.
    pub summary_fallback: Option<Arc<dyn SummaryLookup>>,
    /// The numbers of this rule's raw regexes in the table of its
    /// language pass, whose answers each line computes once for every
    /// rule (ticket #240, `expr_table.rs`). `None` outside a pass (a
    /// test, a rule run on its own): each regex is then tested by the
    /// rule itself, with the same answers.
    pub exprs: Option<Arc<super::expr_table::RuleExprs>>,
}

/// Summaries found by callee name without being copied into
/// [`RuleSpecs::summaries`] (ticket #239): see
/// [`RuleSpecs::summary_fallback`].
pub trait SummaryLookup: std::fmt::Debug + Send + Sync {
    /// The summary of the function that `callee_name` designates, if any.
    fn get(&self, callee_name: &str) -> Option<Arc<FunctionSummary>>;
}

impl RuleSpecs {
    /// The summary of the function that `callee_name` designates: the
    /// entry of `summaries`, else the one of `summary_fallback`.
    pub fn summary(&self, callee_name: &str) -> Option<Arc<FunctionSummary>> {
        match self.summaries.get(callee_name) {
            Some(summary) => Some(summary.clone()),
            None => self
                .summary_fallback
                .as_ref()
                .and_then(|fallback| fallback.get(callee_name)),
        }
    }
}

/// "Summary sheet" of a function's taint behavior — describes how
/// taint flows through its calls.
/// `PartialEq`: used by `call_graph.rs` to detect fixpoint
/// convergence per SCC (correction vs Python, Decision #3).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FunctionSummary {
    pub name: String,
    /// Positional parameters (excluding self/cls).
    pub param_names: Vec<String>,
    /// True if an internal source reaches the `return` regardless of
    /// arguments (e.g. `return request.GET[...]`).
    pub return_tainted_uncond: bool,
    /// Nature of the unconditional return taint (http…).
    pub return_kind: Option<String>,
    /// Index of parameters whose taint reaches the return.
    pub return_taint_params: BTreeSet<usize>,
    /// For each parameter index reaching a sink, a template finding
    /// to re-emit at the call site.
    pub sink_param_findings: BTreeMap<usize, Finding>,
}

// ============================================================================
// Finding
// ============================================================================

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FlowStep {
    pub line: usize,
    /// "source" | "propagation" | "sink".
    pub kind: String,
    pub text: SharedText,
    /// File of the step, relative to the scanned root, when it differs
    /// from the finding's own file: set on the steps of a cross-file
    /// function summary (`call_graph::compute_one`). `None` means the
    /// finding's file.
    pub file: Option<String>,
    /// The source line of the step (trimmed), stamped with `file` so
    /// that the report can show the code of another file without
    /// reading it again. `None`: read from the finding's file.
    pub code: Option<SharedText>,
}

/// A reported taint finding, conforming to CONTRACT-SCA-AUDITAI.md §3.2.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: String,
    pub line: usize,
    pub column: usize,
    pub sink_text: SharedText,
    pub source_line: Option<usize>,
    pub message: String,
    pub cwe: Option<String>,
    pub flow: Vec<FlowStep>,
    pub source_kind: String,
}

// ============================================================================
// Spec resolution
// ============================================================================

/// Result of `resolve_spec` — the variant encodes the `SpecKind`
/// directly (no separate `(kind, spec)` tuple like on the Python side).
pub enum ResolvedSpec<'a> {
    Source(&'a SourceSpec),
    Sink(&'a SinkSpec),
    Sanitizer(&'a SanitizerSpec),
    Passthrough(&'a PassthroughSpec),
    Unknown,
}

/// Resolves a callee name against a rule's specs.
/// Priority (§5.2): SOURCE > SINK > SANITIZER > PASSTHROUGH > UNKNOWN.
///
/// A source or a sanitizer whose dotted pattern dropped part of its regex
/// is taken only when `site` confirms it on the line (ticket #270);
/// otherwise the search goes on with the next spec, as if its name did
/// not match.
pub fn resolve_spec<'a>(
    callee_name: &str,
    specs: &'a RuleSpecs,
    site: Site<'_>,
) -> ResolvedSpec<'a> {
    for s in &specs.sources {
        if match_pattern(callee_name, &s.compiled)
            && site.confirms(s.confirm_on_line, s.raw_regex.as_ref())
        {
            return ResolvedSpec::Source(s);
        }
    }
    for s in &specs.sinks {
        if match_pattern(callee_name, &s.compiled) {
            return ResolvedSpec::Sink(s);
        }
    }
    for s in &specs.sanitizers {
        if match_pattern(callee_name, &s.compiled)
            && site.confirms(s.confirm_on_line, s.raw_regex.as_ref())
        {
            return ResolvedSpec::Sanitizer(s);
        }
    }
    for s in &specs.passthroughs {
        if match_pattern(callee_name, &s.compiled) {
            return ResolvedSpec::Passthrough(s);
        }
    }
    ResolvedSpec::Unknown
}

/// How a name is read where a source may match it (ticket #268).
#[derive(Clone, Copy, PartialEq, Eq)]
enum SourceRead {
    /// The value itself: `print_r($_GET)`, `cookies = req.Cookies`, or the
    /// base of a subscript read, `Request["id"]`.
    Whole,
    /// The receiver of a member: `Request` in `Request.HttpContext`. An
    /// indexed source (`SourceSpec::subscript_only`) is not one there.
    Receiver,
}

/// The source of the rule `name` is, read as `read`. A source written
/// with an index (`SourceSpec::subscript_only`) is not taken for the
/// receiver of a member.
fn check_source_match(
    name: &str,
    read: SourceRead,
    specs: &RuleSpecs,
    site: Site<'_>,
) -> Option<Taint> {
    let lineno = site.line;
    for s in &specs.sources {
        if !(s.subscript_only && read == SourceRead::Receiver)
            && match_pattern(name, &s.compiled)
            && site.confirms(s.confirm_on_line, s.raw_regex.as_ref())
        {
            return Some(Taint::tainted(
                [s.kind.clone()],
                SourceInfo {
                    line: lineno,
                    expr: name.to_string().into(),
                    kind: s.kind.as_str().into(),
                },
            ));
        }
    }
    None
}

/// The source a constant-key read takes from its base, when one of the
/// rule's sources names that base: a variable (`$_GET` in `$_GET['id']`)
/// or an attribute (`request.GET` in `request.GET['q']`). Ticket #271.
///
/// A nested read goes down to the base of its subscripts:
/// `request.json["user"]["name"]` and `$_POST['user']['name']` take the
/// source of `request.json` and `$_POST` (ticket #259; before, a nested
/// subscript gave `None`, and the read was a source for the line layer
/// alone, on the line that shows it). Only the NAME of that base is
/// matched, never the state of the entries: `data["user"]["role"]` stays
/// clean when only `data["user"]["name"]` holds request data. Any other
/// base (a call, a temporary) gives `None`: evaluating it would join the
/// taint of its entries, which a constant key must not do (§9.bis).
fn subscript_base_source(base: &Rhs, specs: &RuleSpecs, site: Site<'_>) -> Option<Taint> {
    match base {
        Rhs::VarRef(name) => check_source_match(name, SourceRead::Whole, specs, site),
        Rhs::AttrRef { .. } => {
            check_source_match(&canon_callee(base), SourceRead::Whole, specs, site)
        }
        Rhs::SubscriptRef { base: inner, .. } => subscript_base_source(inner, specs, site),
        _ => None,
    }
}

fn kinds_compatible(t: &Taint, sink_kinds: &[String]) -> bool {
    if sink_kinds.is_empty() {
        return true;
    }
    match t {
        Taint::Top => true,
        Taint::Tainted { kinds, .. } => kinds
            .iter()
            .any(|k| sink_kinds.iter().any(|sink| sink.as_str() == &**k)),
        Taint::Clean => false,
    }
}

/// Canonical representation of an access key, for state keys
/// (literal `obj['k']` vs dynamic `obj[*]`) — same convention as
/// `ir::canon_subscript_key`.
fn key_repr(rhs: &Rhs) -> String {
    canon_subscript_key(rhs)
}

// ============================================================================
// RHS evaluation (§5.1)
// ============================================================================

/// Where an expression is evaluated: the line of its statement and, when
/// the caller has them, the lines of the file. The data flow reads the
/// line's text for one purpose only: confirming a source or a sanitizer
/// whose dotted pattern dropped part of its regex (ticket #270).
#[derive(Clone, Copy)]
pub struct Site<'a> {
    /// The line (1-based) of the statement.
    pub line: usize,
    lines: Option<&'a RuleLines<'a>>,
}

impl<'a> Site<'a> {
    /// The statement at `line` of the file `lines` holds, when known.
    pub fn new(line: usize, lines: Option<&'a RuleLines<'a>>) -> Self {
        Site { line, lines }
    }

    /// A statement whose file text is not at hand (unit tests, callers
    /// without the file's lines).
    pub fn bare(line: usize) -> Self {
        Site { line, lines: None }
    }

    /// Whether a spec matched by its dotted pattern is confirmed here.
    /// A spec that needs no confirmation always is. One that needs it is
    /// confirmed when its raw regex matches the text of the line; without
    /// that text, it is taken as before ticket #270, as the engine has
    /// nothing to read the dropped part of the regex against.
    ///
    /// The regex is tested here rather than read from the line's cached
    /// facts: the facts keep the first matching sanitizer only, and the
    /// specs that need a confirmation are few (a regex with a look-around
    /// or argument text, about 30 in the catalog), tested only when their
    /// name matched.
    pub fn confirms(&self, confirm_on_line: bool, raw_regex: Option<&Regex>) -> bool {
        if !confirm_on_line {
            return true;
        }
        let (Some(lines), Some(regex)) = (self.lines, raw_regex) else {
            return true;
        };
        lines
            .line(self.line)
            .is_some_and(|text| regex.is_match(text).unwrap_or(false))
    }
}

pub fn eval_rhs(
    rhs: &Rhs,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    site: Site<'_>,
) -> Taint {
    eval_read(rhs, SourceRead::Whole, state, specs, findings, site)
}

/// [`eval_rhs`] for an expression read as `read`: the base of an attribute
/// is read as its receiver, so that an indexed source (`Request\[`) taints
/// `Request["id"]` and not `Request.HttpContext.User.Identity.Name`
/// (ticket #268). Every other sub-expression is read whole.
fn eval_read(
    rhs: &Rhs,
    read: SourceRead,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    site: Site<'_>,
) -> Taint {
    match rhs {
        Rhs::Const(_) => Taint::Clean,
        Rhs::VarRef(name) => {
            if let Some(t) = check_source_match(name, read, specs, site) {
                return t;
            }
            // §9.bis — aggregates indexed sub-entries: if `obj['k']`
            // is tainted, reading `obj` as a whole must pick up that
            // taint.
            let mut base = state_get(state, name);
            // The keys that start with `name` follow `name` in the sorted
            // state: read from there instead of the whole state, and keep
            // those that go on with `[` (ticket #241). The same entries,
            // in the same order, as testing every key against `name[`,
            // without building that text at every read.
            let after_name = (
                std::ops::Bound::Excluded(name.as_str()),
                std::ops::Bound::Unbounded,
            );
            for (_, t) in state
                .range::<str, _>(after_name)
                .take_while(|(key, _)| key.starts_with(name.as_str()))
                .filter(|(key, _)| key.as_bytes().get(name.len()) == Some(&b'['))
            {
                base = join(&base, t);
            }
            base
        }
        Rhs::AttrRef { base, .. } => {
            let attr_name = canon_callee(rhs);
            if let Some(t) = check_source_match(&attr_name, read, specs, site) {
                return t;
            }
            let attr_key = canon_rhs(rhs);
            join(
                &state_get(state, &attr_key),
                &eval_read(base, SourceRead::Receiver, state, specs, findings, site),
            )
        }
        Rhs::SubscriptRef { base, key } => {
            let sub_key = canon_rhs(rhs);
            let base_key = canon_rhs(base);
            let sub_taint = state_get(state, &sub_key);
            if matches!(key.as_ref(), Rhs::Const(_)) {
                if state.contains_key(&*sub_key) {
                    return sub_taint;
                }
                // A constant key read on a source (`$_GET['id']`,
                // `request.GET['q']`) is that source. Deliberate deviation
                // from the Audit (`transfer.py`), which does not evaluate the
                // base of a constant key, so as not to join the taint of its
                // other entries (§9.bis), and so leaves such a read to the
                // line layer alone (ticket #271). Only the NAME of the base is
                // matched here, never the state of its entries: the precision
                // of §9.bis is kept.
                if let Some(t) = subscript_base_source(base, specs, site) {
                    return t;
                }
                let wildcard_taint = state_get(state, &format!("{base_key}[*]"));
                let base_direct = state_get(state, &base_key);
                return join(&wildcard_taint, &base_direct);
            }
            join(
                &join(&sub_taint, &state_get(state, &base_key)),
                &join(
                    &eval_rhs(base, state, specs, findings, site),
                    &eval_rhs(key, state, specs, findings, site),
                ),
            )
        }
        Rhs::BinOp { left, right, .. } => join(
            &eval_rhs(left, state, specs, findings, site),
            &eval_rhs(right, state, specs, findings, site),
        ),
        Rhs::UnaryOp { operand, .. } => eval_rhs(operand, state, specs, findings, site),
        Rhs::Cmp { left, right, .. } => {
            eval_rhs(left, state, specs, findings, site);
            eval_rhs(right, state, specs, findings, site);
            Taint::Clean
        }
        Rhs::Bool { operands, .. } => operands.iter().fold(Taint::Clean, |acc, op| {
            join(&acc, &eval_rhs(op, state, specs, findings, site))
        }),
        Rhs::TupleRef(elements) | Rhs::ListRef(elements) | Rhs::SetRef(elements) => {
            elements.iter().fold(Taint::Clean, |acc, e| {
                join(&acc, &eval_rhs(e, state, specs, findings, site))
            })
        }
        Rhs::DictRef(items) => items.iter().fold(Taint::Clean, |acc, (k, v)| {
            let acc = join(&acc, &eval_rhs(k, state, specs, findings, site));
            join(&acc, &eval_rhs(v, state, specs, findings, site))
        }),
        Rhs::Star { inner, .. } => eval_rhs(inner, state, specs, findings, site),
        Rhs::IfExp { cond, then, orelse } => {
            // §9 — conservative semantics: evaluates the condition for
            // its effects, then joins both branches. Simplification
            // when cond is Const-evaluable is done upstream by
            // `_compute_dead_edges` (const_eval.rs).
            eval_rhs(cond, state, specs, findings, site);
            join(
                &eval_rhs(then, state, specs, findings, site),
                &eval_rhs(orelse, state, specs, findings, site),
            )
        }
        Rhs::LambdaRef { .. } => Taint::Clean,
        // Ticket #253: an expression the lowering does not model carries
        // no taint, as the `Const(None)` it replaces.
        Rhs::Opaque => Taint::Clean,
        Rhs::CallRef {
            callee,
            args,
            kwargs,
        } => eval_call(callee, args, kwargs, state, specs, findings, site),
    }
}

// ============================================================================
// Call evaluation (§5.2)
// ============================================================================

/// Detects a source via regex over the TEXT of a single call argument
/// (§7, part 4). Lets a source passed directly as an argument
/// (`run_query(request.GET["q"])`) be tainted with no intermediate
/// variable. Only consulted when `eval_rhs` has already returned
/// CLEAN for that argument.
fn arg_regex_source(arg: &Rhs, specs: &RuleSpecs, lineno: usize) -> Option<Taint> {
    let mut expr: Option<String> = None;
    for src in &specs.sources {
        let Some(rx) = &src.raw_regex else { continue };
        let e = expr.get_or_insert_with(|| pretty_rhs(arg));
        if rx.is_match(e).unwrap_or(false) {
            return Some(Taint::tainted(
                [src.kind.clone()],
                SourceInfo {
                    line: lineno,
                    expr: e.clone().into(),
                    kind: src.kind.as_str().into(),
                },
            ));
        }
    }
    None
}

pub fn eval_call(
    callee: &Rhs,
    args: &[Rhs],
    kwargs: &[(String, Rhs)],
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    site: Site<'_>,
) -> Taint {
    let lineno = site.line;
    let arg_taints: Vec<Taint> = args
        .iter()
        .map(|arg| {
            let t = eval_rhs(arg, state, specs, findings, site);
            if t.is_clean() {
                arg_regex_source(arg, specs, lineno).unwrap_or(t)
            } else {
                t
            }
        })
        .collect();
    let kw_taints: BTreeMap<String, Taint> = kwargs
        .iter()
        .map(|(name, val)| {
            let t = eval_rhs(val, state, specs, findings, site);
            let t = if t.is_clean() {
                arg_regex_source(val, specs, lineno).unwrap_or(t)
            } else {
                t
            };
            (name.clone(), t)
        })
        .collect();

    let mut callee_name = canon_callee(callee);
    // The receiver is also evaluated for its effects AND its taint
    // (e.g. `request.args` in `request.args.get(...)`) — propagates
    // to the result.
    let callee_taint = eval_rhs(callee, state, specs, findings, site);

    // A method of the result of another call, `<call>.get` for
    // `httpx.AsyncClient().get(url)`, is also looked up by the name of the
    // chain, `httpx.AsyncClient.get` (`ir::chained_callee_name`), which the
    // rules write for such a call (`httpx\.AsyncClient\(\)\.\w+\s*\(`).
    // Ticket #260, deviation from the Audit, which only knows `<call>.get`:
    // the name `<call>.…` is tried first, so that the patterns it met
    // (`**.get`) keep meeting it; the chain only names what it did not.
    let mut resolved = resolve_spec(&callee_name, specs, site);
    if matches!(resolved, ResolvedSpec::Unknown)
        && let Some(chain) = chained_callee_name(callee)
    {
        let by_chain = resolve_spec(&chain, specs, site);
        if !matches!(by_chain, ResolvedSpec::Unknown) {
            resolved = by_chain;
            callee_name = chain.into();
        }
    }

    match resolved {
        ResolvedSpec::Source(spec) => Taint::tainted(
            [spec.kind.clone()],
            SourceInfo {
                line: lineno,
                expr: callee_name.into(),
                kind: spec.kind.as_str().into(),
            },
        ),
        ResolvedSpec::Sink(spec) => {
            check_sink(
                spec,
                &callee_name,
                &arg_taints,
                &kw_taints,
                specs,
                findings,
                lineno,
            );
            Taint::Clean
        }
        ResolvedSpec::Sanitizer(_) => Taint::Clean,
        ResolvedSpec::Passthrough(spec) => {
            let passthrough_result = eval_passthrough(spec, &arg_taints, &kw_taints);
            join(&passthrough_result, &callee_taint)
        }
        ResolvedSpec::Unknown => {
            // Part 2 — call to a summarized user function
            // (interprocedural). Additive: emits sinks reached across
            // the call, and taints the return if the function has an
            // unconditional internal source.
            let mut callee_name = callee_name;
            let mut summary = specs.summary(&callee_name);

            // Round 5 (Java) — `scr.method()` where `scr` is a local
            // variable/field of known type: the direct lookup by
            // variable name always fails (no summary is ever indexed
            // by variable name) — retry via the declared class name.
            // `specs.type_map` is always empty on the Python side (cf.
            // `RuleSpecs` doc), so it has no effect there.
            if summary.is_none()
                && !specs.type_map.is_empty()
                && let Rhs::AttrRef { base, attr } = callee
                && let Rhs::VarRef(var_name) = base.as_ref()
                && let Some(declared_type) = specs.type_map.get(var_name)
            {
                callee_name = format!("{declared_type}.{attr}").into();
                summary = specs.summary(&callee_name);
            }
            // Round 6 — chained call `new ClassName(...).method(...)`:
            // `java_lowering.rs::lower_method_invocation` inlines the
            // constructor's `CallRef` as the base of the `AttrRef`
            // precisely to enable this resolution, as the C# lowering does
            // (ticket #284) and the Python one for `ClassName().method()`
            // (`lowering.rs::lower_callee`, ticket #260: a Python class is
            // called like a function, and its methods are summarized as
            // `ClassName.method`). No language guard needed.
            if summary.is_none()
                && let Rhs::AttrRef { base, attr } = callee
                && let Rhs::CallRef {
                    callee: ctor_callee,
                    ..
                } = base.as_ref()
                && let Rhs::VarRef(ctor_type_name) = ctor_callee.as_ref()
            {
                callee_name = format!("{ctor_type_name}.{attr}").into();
                summary = specs.summary(&callee_name);
            }

            if let Some(s) = &summary {
                findings.extend(apply_summary_at_call(
                    s,
                    &callee_name,
                    &arg_taints,
                    specs,
                    lineno,
                ));
            }

            // §9.bis — precise indexed read, short-circuits the
            // generic over-approximation below.
            if let Some(t) = try_indexed_read(callee, args, state, &arg_taints) {
                return t;
            }

            // UNKNOWN with no summary: over-approximation (SCA-9
            // choice). With a summary: precise positional narrowing
            // via `return_taint_params` (the receiver and kwargs
            // remain over-approximated — not modeled by the probe).
            let mut result = callee_taint;
            if let Some(s) = &summary {
                for (i, t) in arg_taints.iter().enumerate() {
                    if s.return_taint_params.contains(&i) {
                        result = join(&result, t);
                    }
                }
            } else {
                for t in &arg_taints {
                    result = join(&result, t);
                }
            }
            // The environment handed to a child process (`env=` of
            // `subprocess.check_output(cmd, env=dict(os.environ))`) is not
            // data of its output. Ticket #268, deviation from the Audit,
            // which joins every keyword: semgrep's `git_check_output`, which
            // passes a copy of `os.environ`, made the output of every git
            // command an environment source once the kind crossed returns.
            for (name, t) in &kw_taints {
                if name != "env" {
                    result = join(&result, t);
                }
            }
            // Part 2 — unconditional internal source: the return is
            // tainted even with no tainted argument.
            if let Some(s) = &summary
                && s.return_tainted_uncond
            {
                let kind = s.return_kind.clone().unwrap_or_else(|| "http".to_string());
                result = join(
                    &result,
                    &Taint::tainted(
                        [kind.clone()],
                        SourceInfo {
                            line: lineno,
                            expr: format!("{callee_name}()").into(),
                            kind: kind.into(),
                        },
                    ),
                );
            }
            result
        }
    }
}

/// Builds "sink reached through a call" findings from a callee's
/// summary. A tainted argument passed to a parameter that the summary
/// marks as reaching a sink triggers a finding at the call site, with
/// a flow that crosses the call boundary.
fn apply_summary_at_call(
    summary: &FunctionSummary,
    callee_name: &str,
    arg_taints: &[Taint],
    specs: &RuleSpecs,
    lineno: usize,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (&param_idx, template) in &summary.sink_param_findings {
        let Some(arg_t) = arg_taints.get(param_idx) else {
            continue;
        };
        if !arg_t.is_tainted() {
            continue;
        }
        let mut source_line = None;
        let mut source_kind = "unknown".to_string();
        let mut flow = Vec::new();
        if let Taint::Tainted { source, .. } = arg_t {
            source_line = Some(source.line);
            source_kind = if source.kind.is_empty() {
                "unknown".to_string()
            } else {
                source.kind.to_string()
            };
            flow.push(FlowStep {
                line: source.line,
                kind: "source".to_string(),
                text: source.expr.clone(),
                file: None,
                code: None,
            });
        }
        // Explicit interprocedural step (contains "→").
        flow.push(FlowStep {
            line: lineno,
            kind: "propagation".to_string(),
            text: format!("{callee_name}(...) → {}", template.sink_text).into(),
            file: None,
            code: None,
        });
        // The callee's own path (its propagations and its real sink, with
        // their file once `call_graph` stamped them), not just its name:
        // the report must show where the query is actually written
        // (my-ia: `_reponse(...) → get_usage(...)` named the call, never
        // the `db.execute` of `quotas.py`). Its source step is the
        // callee's parameter, replaced by the caller's real source above.
        let inner: Vec<FlowStep> = template
            .flow
            .iter()
            .filter(|s| s.kind != "source")
            .cloned()
            .collect();
        if inner.iter().any(|s| s.kind == "sink") {
            flow.extend(inner);
        } else {
            flow.push(FlowStep {
                line: template.line,
                kind: "sink".to_string(),
                text: template.sink_text.clone(),
                file: None,
                code: None,
            });
        }
        out.push(Finding {
            rule_id: specs.rule_id.clone(),
            severity: specs.severity.clone(),
            line: lineno,
            column: 0,
            sink_text: format!("{callee_name}(...)").into(),
            source_line,
            message: specs.message.clone(),
            cwe: specs.cwe.clone(),
            flow,
            source_kind,
        });
    }
    out
}

/// Whether the text of one call argument passes `name` by keyword:
/// `headers=h`, `headers = h`, but not a comparison `headers == h`.
fn is_keyword_argument(argument: &str, name: &str) -> bool {
    argument
        .trim_start()
        .strip_prefix(name)
        .map(str::trim_start)
        .is_some_and(|rest| rest.starts_with('=') && !rest.starts_with("=="))
}

fn check_sink(
    spec: &SinkSpec,
    callee_name: &str,
    arg_taints: &[Taint],
    kw_taints: &BTreeMap<String, Taint>,
    rule_specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    lineno: usize,
) {
    let indices: Vec<usize> = if spec.args.is_empty() {
        (0..arg_taints.len()).collect()
    } else {
        spec.args.clone()
    };
    // The checked arguments: the positional ones, then the keyword the
    // rule names with `arg_name=` (ticket #261). Deliberate deviation from
    // the Audit, whose `_check_sink` never reads the keyword arguments:
    // `Response(body, headers={"X": value})` passed a tainted header
    // unseen. Only the named keyword is read: `Response(body, status=s)`
    // stays clean for a rule about headers.
    let keyword = spec.arg_name.as_ref().and_then(|name| kw_taints.get(name));
    let checked = indices
        .iter()
        .filter_map(|idx| arg_taints.get(*idx))
        .chain(keyword);
    for t in checked {
        if t.is_clean() {
            continue;
        }
        if !kinds_compatible(t, &spec.kinds) {
            continue;
        }
        let mut source_line = None;
        let mut source_kind = "unknown".to_string();
        let mut flow = Vec::new();
        if let Taint::Tainted { source, .. } = t {
            source_line = Some(source.line);
            source_kind = if source.kind.is_empty() {
                "unknown".to_string()
            } else {
                source.kind.to_string()
            };
            flow.push(FlowStep {
                line: source.line,
                kind: "source".to_string(),
                text: source.expr.clone(),
                file: None,
                code: None,
            });
        }
        flow.push(FlowStep {
            line: lineno,
            kind: "sink".to_string(),
            text: callee_name.to_string().into(),
            file: None,
            code: None,
        });
        findings.push(Finding {
            rule_id: rule_specs.rule_id.clone(),
            severity: rule_specs.severity.clone(),
            line: lineno,
            column: 0,
            sink_text: callee_name.to_string().into(),
            source_line,
            message: rule_specs.message.clone(),
            cwe: rule_specs.cwe.clone(),
            flow,
            source_kind,
        });
        // One finding per tainted argument: no early return, every
        // distinct vector must be flagged.
    }
}

fn eval_passthrough(
    spec: &PassthroughSpec,
    arg_taints: &[Taint],
    kw_taints: &BTreeMap<String, Taint>,
) -> Taint {
    let _ = kw_taints; // signature aligned with Python, kwargs not consulted here (§7.2)
    // Ticket #256: the result carries the receiver's data only, which
    // `eval_call` joins to this result.
    if spec.receiver_only {
        return Taint::Clean;
    }
    let indices: Vec<usize> = if spec.args_in.is_empty() {
        (0..arg_taints.len()).collect()
    } else {
        spec.args_in.clone()
    };
    let mut result = Taint::Clean;
    for idx in indices {
        if let Some(t) = arg_taints.get(idx) {
            result = join(&result, t);
        }
    }
    result
}

// ============================================================================
// Indexed read/write (object mutation, §9.bis)
// ============================================================================

const INDEXED_WRITE_METHODS: &[&str] = &["set", "setdefault", "__setitem__", "put"];
const BULK_UPDATE_METHODS: &[&str] = &["update"];
const ELEMENT_WRITE_METHODS: &[&str] = &["append", "extend", "insert", "add"];
const RECEIVER_WRITE_METHODS: &[&str] = &["write", "writelines"];
const INDEXED_READ_METHODS: &[&str] = &["get", "__getitem__", "setdefault", "pop"];

fn is_mutation_method(m: &str) -> bool {
    INDEXED_WRITE_METHODS.contains(&m)
        || BULK_UPDATE_METHODS.contains(&m)
        || ELEMENT_WRITE_METHODS.contains(&m)
        || RECEIVER_WRITE_METHODS.contains(&m)
}

/// Indexed read for dict/configparser-style methods
/// (`get`/`__getitem__`/`setdefault`/`pop`). Returns `None` if the
/// signature doesn't support a precise indexed read (the caller then
/// falls back to the UNKNOWN over-approximation); `Some(Taint::Clean)`
/// is a valid precise result (a known, untainted read).
fn try_indexed_read(
    callee: &Rhs,
    args: &[Rhs],
    state: &State,
    arg_taints: &[Taint],
) -> Option<Taint> {
    let Rhs::AttrRef { base, attr } = callee else {
        return None;
    };
    if !INDEXED_READ_METHODS.contains(&attr.as_str()) {
        return None;
    }
    let base_key = canon_rhs(base);
    if base_key.is_empty()
        || base_key == "<unknown>"
        || base_key == "<call>"
        || base_key.starts_with('<')
    {
        return None;
    }
    let first_arg = args.first()?;

    let k0 = key_repr(first_arg);
    let one_level = format!("{base_key}[{k0}]");
    let wildcard = format!("{base_key}[*]");
    let base_direct = state_get(state, &base_key);
    let wildcard_taint = state_get(state, &wildcard);

    // configparser-style (section, option) on get/__getitem__.
    if args.len() >= 2 && (attr == "get" || attr == "__getitem__") {
        let k1 = key_repr(&args[1]);
        let two_level = format!("{base_key}[{k0}][{k1}]");
        let two_level_wild = format!("{base_key}[{k0}][*]");
        if state.contains_key(two_level.as_str()) || state.contains_key(two_level_wild.as_str()) {
            let t = join(
                &state_get(state, &two_level),
                &state_get(state, &two_level_wild),
            );
            return Some(join(&join(&t, &base_direct), &wildcard_taint));
        }
    }

    let mut result = state_get(state, &one_level);
    result = join(&result, &wildcard_taint);
    result = join(&result, &base_direct);
    if args.len() >= 2
        && (attr == "get" || attr == "pop" || attr == "setdefault")
        && let Some(t) = arg_taints.get(1)
    {
        result = join(&result, t);
    }
    Some(result)
}

// ============================================================================
// Per-statement transfer functions (§5)
// ============================================================================

/// Canonical target to match against sink patterns for an assignable
/// lhs (`SubscriptLhs`/`AttrLhs` only — `VarLhs`/`TupleLhs`/`StarLhs`
/// are never sinks).
fn lhs_sink_target(lhs: &Lhs) -> Option<String> {
    match lhs {
        Lhs::SubscriptLhs { base, .. } => Some(canon_rhs(base).into_owned()),
        Lhs::AttrLhs { .. } => Some(canon_lhs(lhs)),
        _ => None,
    }
}

fn transfer_assign(
    stmt_lhs: &Lhs,
    stmt_rhs: &Rhs,
    site: Site<'_>,
    state: &mut State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
) {
    let lineno = site.line;
    let rhs_taint = eval_rhs(stmt_rhs, state, specs, findings, site);
    if rhs_taint.is_tainted()
        && let Some(target_name) = lhs_sink_target(stmt_lhs)
    {
        for sink in &specs.sinks {
            if !match_pattern(&target_name, &sink.compiled) {
                continue;
            }
            if !kinds_compatible(&rhs_taint, &sink.kinds) {
                continue;
            }
            let mut source_line = None;
            let mut source_kind = "unknown".to_string();
            let mut flow = Vec::new();
            if let Taint::Tainted { source, .. } = &rhs_taint {
                source_line = Some(source.line);
                source_kind = if source.kind.is_empty() {
                    "unknown".to_string()
                } else {
                    source.kind.to_string()
                };
                flow.push(FlowStep {
                    line: source.line,
                    kind: "source".to_string(),
                    text: source.expr.clone(),
                    file: None,
                    code: None,
                });
            }
            flow.push(FlowStep {
                line: lineno,
                kind: "sink".to_string(),
                text: target_name.clone().into(),
                file: None,
                code: None,
            });
            findings.push(Finding {
                rule_id: specs.rule_id.clone(),
                severity: specs.severity.clone(),
                line: lineno,
                column: 0,
                sink_text: target_name.clone().into(),
                source_line,
                message: specs.message.clone(),
                cwe: specs.cwe.clone(),
                flow,
                source_kind,
            });
            break; // one finding per assignment is enough
        }
    }
    assign_lhs(stmt_lhs, rhs_taint, state);
}

fn assign_lhs(lhs: &Lhs, taint: Taint, state: &mut State) {
    match lhs {
        Lhs::VarLhs(name) => state_put(state, name, taint),
        Lhs::AttrLhs { .. } | Lhs::SubscriptLhs { .. } => state_put(state, &canon_lhs(lhs), taint),
        Lhs::TupleLhs(elements) => {
            for elt in elements {
                assign_lhs(elt, taint.clone(), state);
            }
        }
        Lhs::StarLhs(inner) => assign_lhs(inner, taint, state),
    }
}

fn compute_indexed_write_key(
    callee_attr: &str,
    call_args: &[Rhs],
    base_key: &str,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    site: Site<'_>,
) -> Option<(String, Taint)> {
    if !INDEXED_WRITE_METHODS.contains(&callee_attr) {
        return None;
    }
    if call_args.len() == 2 {
        let kstr = key_repr(&call_args[0]);
        let val_taint = eval_rhs(&call_args[1], state, specs, findings, site);
        return Some((format!("{base_key}[{kstr}]"), val_taint));
    }
    if call_args.len() == 3 && callee_attr == "set" {
        let k0 = key_repr(&call_args[0]);
        let k1 = key_repr(&call_args[1]);
        let val_taint = eval_rhs(&call_args[2], state, specs, findings, site);
        return Some((format!("{base_key}[{k0}][{k1}]"), val_taint));
    }
    None
}

/// A call used as a statement (return value ignored). Models object
/// mutation — `obj.<method>(...tainted...)` — depending on the
/// method's category.
pub fn transfer_call_stmt(
    callee: &Rhs,
    call_args: &[Rhs],
    kwargs: &[(String, Rhs)],
    site: Site<'_>,
    state: &mut State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
) {
    eval_call(callee, call_args, kwargs, state, specs, findings, site);

    let Rhs::AttrRef { base, attr } = callee else {
        return;
    };
    if !is_mutation_method(attr) {
        return;
    }
    let base_key = canon_rhs(base);
    if base_key.is_empty()
        || base_key == "<unknown>"
        || base_key == "<call>"
        || base_key.starts_with('<')
    {
        return;
    }

    if INDEXED_WRITE_METHODS.contains(&attr.as_str()) {
        let Some((slot, val_taint)) =
            compute_indexed_write_key(attr, call_args, &base_key, state, specs, findings, site)
        else {
            return;
        };
        if val_taint.is_tainted() {
            let existing = state_get(state, &slot);
            state_put(state, &slot, join(&existing, &val_taint));
        }
        return;
    }

    if BULK_UPDATE_METHODS.contains(&attr.as_str()) {
        apply_bulk_update(call_args, kwargs, &base_key, state, specs, findings, site);
        return;
    }

    if ELEMENT_WRITE_METHODS.contains(&attr.as_str()) {
        apply_element_write(call_args, kwargs, &base_key, state, specs, findings, site);
        return;
    }

    if RECEIVER_WRITE_METHODS.contains(&attr.as_str()) {
        apply_receiver_write(call_args, kwargs, &base_key, state, specs, findings, site);
    }
}

fn apply_bulk_update(
    call_args: &[Rhs],
    kwargs: &[(String, Rhs)],
    base_key: &str,
    state: &mut State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    site: Site<'_>,
) {
    let mut items: Vec<(String, Rhs)> = Vec::new();
    if let Some(first) = call_args.first() {
        if let Rhs::DictRef(entries) = first {
            for (k, v) in entries {
                items.push((key_repr(k), v.clone()));
            }
        } else {
            let arg_taint = eval_rhs(first, state, specs, findings, site);
            if arg_taint.is_tainted() {
                let wkey = format!("{base_key}[*]");
                let existing = state_get(state, &wkey);
                state_put(state, &wkey, join(&existing, &arg_taint));
            }
        }
    }
    for (kname, v) in kwargs {
        items.push((format!("'{kname}'"), v.clone()));
    }
    for (kstr, v) in &items {
        let slot = format!("{base_key}[{kstr}]");
        let vtaint = eval_rhs(v, state, specs, findings, site);
        if vtaint.is_tainted() {
            let existing = state_get(state, &slot);
            state_put(state, &slot, join(&existing, &vtaint));
        }
    }
}

fn apply_element_write(
    call_args: &[Rhs],
    kwargs: &[(String, Rhs)],
    base_key: &str,
    state: &mut State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    site: Site<'_>,
) {
    let mut arg_taint = Taint::Clean;
    for arg in call_args {
        arg_taint = join(&arg_taint, &eval_rhs(arg, state, specs, findings, site));
    }
    for (_, val) in kwargs {
        arg_taint = join(&arg_taint, &eval_rhs(val, state, specs, findings, site));
    }
    if arg_taint.is_tainted() {
        let wkey = format!("{base_key}[*]");
        let existing = state_get(state, &wkey);
        state_put(state, &wkey, join(&existing, &arg_taint));
    }
}

fn apply_receiver_write(
    call_args: &[Rhs],
    kwargs: &[(String, Rhs)],
    base_key: &str,
    state: &mut State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    site: Site<'_>,
) {
    let mut arg_taint = Taint::Clean;
    for arg in call_args {
        arg_taint = join(&arg_taint, &eval_rhs(arg, state, specs, findings, site));
    }
    for (_, val) in kwargs {
        arg_taint = join(&arg_taint, &eval_rhs(val, state, specs, findings, site));
    }
    if arg_taint.is_tainted() {
        let existing = state_get(state, base_key);
        state_put(state, base_key, join(&existing, &arg_taint));
    }
}

fn transfer_return(
    value: Option<&Rhs>,
    site: Site<'_>,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
) {
    if let Some(v) = value {
        eval_rhs(v, state, specs, findings, site);
    }
}

fn transfer_raise(
    value: Option<&Rhs>,
    site: Site<'_>,
    state: &State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
) {
    if let Some(v) = value {
        eval_rhs(v, state, specs, findings, site);
    }
}

/// Applies the transfer function of a single IR statement, updating
/// `state` in place (ticket #191: returning a new state copied the whole
/// state at every statement).
///
/// `source_lines`: if provided, enables hybrid regex matching against
/// the source line (§10bis) — lets sinks/sanitizers/sources also be
/// detected via the original DSL regexes, in addition to the pointed
/// matching, and enables `raw_regex` revalidation of sinks resolved by
/// glob (`discard_sinks_failing_raw_regex`).
pub fn transfer_stmt(
    stmt: &IrStmt,
    state: &mut State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    source_lines: Option<&RuleLines>,
) {
    let before = findings.len();
    let site = |lineno: &usize| Site::new(*lineno, source_lines);
    match stmt {
        IrStmt::Assign { lhs, rhs, lineno } => {
            transfer_assign(lhs, rhs, site(lineno), state, specs, findings)
        }
        IrStmt::Call {
            callee,
            args,
            kwargs,
            lineno,
        } => transfer_call_stmt(callee, args, kwargs, site(lineno), state, specs, findings),
        IrStmt::Return { value, lineno } => {
            transfer_return(value.as_ref(), site(lineno), state, specs, findings)
        }
        IrStmt::Raise { value, lineno } => {
            transfer_raise(value.as_ref(), site(lineno), state, specs, findings)
        }
        IrStmt::Branch { condition, lineno } => {
            eval_rhs(condition, state, specs, findings, site(lineno));
        }
        IrStmt::Noop { .. } => return,
    }
    if let Some(lines) = source_lines {
        discard_sinks_failing_raw_regex(findings, before, specs, lines);
        aux_match_line(stmt, state, specs, findings, lines);
    }
}

/// Sequentially applies the transfer functions of a list of statements
/// (processes an entire basic block), updating `state` in place. See
/// `transfer_stmt` for `source_lines`.
pub fn transfer_stmts(
    stmts: &[IrStmt],
    state: &mut State,
    specs: &RuleSpecs,
    findings: &mut Vec<Finding>,
    source_lines: Option<&RuleLines>,
) {
    for stmt in stmts {
        transfer_stmt(stmt, state, specs, findings, source_lines);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::ir::ConstValue;
    use crate::scan::dataflow::lattice::{empty_state, state_set};

    fn varref(name: &str) -> Rhs {
        Rhs::VarRef(name.to_string())
    }

    fn call(callee: Rhs, args: Vec<Rhs>) -> Rhs {
        Rhs::CallRef {
            callee: Box::new(callee),
            args,
            kwargs: vec![],
        }
    }

    fn attr(base: Rhs, name: &str) -> Rhs {
        Rhs::AttrRef {
            base: Box::new(base),
            attr: name.to_string(),
        }
    }

    fn specs_with(sources: Vec<SourceSpec>, sinks: Vec<SinkSpec>) -> RuleSpecs {
        RuleSpecs {
            rule_id: "test-rule".to_string(),
            severity: "HIGH".to_string(),
            cwe: Some("CWE-89".to_string()),
            message: "test finding".to_string(),
            sources,
            sinks,
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
            summary_fallback: None,
            exprs: None,
        }
    }

    fn dummy_finding(sink_text: &str, line: usize) -> Finding {
        Finding {
            rule_id: "test-rule".to_string(),
            severity: "HIGH".to_string(),
            line,
            column: 0,
            sink_text: sink_text.to_string().into(),
            source_line: None,
            message: "test finding".to_string(),
            cwe: None,
            flow: vec![],
            source_kind: "unknown".to_string(),
        }
    }

    fn tainted(kind: &str, line: usize) -> Taint {
        Taint::tainted(
            [kind.to_string()],
            SourceInfo {
                line,
                expr: "x".to_string().into(),
                kind: kind.into(),
            },
        )
    }

    /// Ticket #241: reading a variable joins the taints of its indexed
    /// entries (`a[...]`) found by a range of the sorted state, the ones
    /// and in the order a scan of the whole state found them; the
    /// neighbours of `a[` in that order are left out.
    #[test]
    fn test_var_read_joins_its_indexed_entries_only() {
        let mut state = empty_state();
        for (key, kind, line) in [
            ("a", "http", 9),
            ("a.b", "cli", 1),
            ("a[", "env", 4),
            ("a['k']", "file", 3),
            ("a[0]", "db", 3),
            ("aa[1]", "cli", 1),
            ("a\\[", "cli", 1),
            ("A[1]", "cli", 1),
            ("b[0]", "cli", 1),
        ] {
            state.insert(key.into(), tainted(kind, line));
        }
        let mut expected = state_get(&state, "a");
        for (key, t) in state.iter() {
            if key.starts_with("a[") {
                expected = join(&expected, t);
            }
        }
        let specs = specs_with(vec![], vec![]);
        let got = eval_rhs(
            &Rhs::VarRef("a".into()),
            &state,
            &specs,
            &mut vec![],
            Site::bare(1),
        );
        assert_eq!(got, expected);
        let Taint::Tainted { kinds, source } = got else {
            panic!("tainted")
        };
        let kinds: Vec<&str> = kinds.iter().map(|k| &**k).collect();
        assert_eq!(kinds, ["db", "env", "file", "http"]);
        assert_eq!(source.line, 3);
    }

    /// The glob compiled as before ticket #240: an anchored
    /// `fancy_regex` regex, `**` as `.*`, `*` as `[^.]*`, every other
    /// character escaped.
    fn former_glob(pattern: &str) -> Regex {
        let mut out = String::new();
        let chars: Vec<char> = pattern.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '*' && chars.get(i + 1) == Some(&'*') {
                out.push_str(".*");
                i += 2;
            } else if chars[i] == '*' {
                out.push_str("[^.]*");
                i += 1;
            } else {
                out.push_str(&regex::escape(&chars[i].to_string()));
                i += 1;
            }
        }
        Regex::new(&format!("^{out}$")).unwrap()
    }

    /// Ticket #240: the string equality and the `regex` crate give the
    /// answers of the former `fancy_regex` globs, for globs built to
    /// probe their edges.
    #[test]
    fn test_glob_engines_agree() {
        assert_glob_engines_agree(vec![
            "os.system".to_string(),
            "*.execute".to_string(),
            "**.execute".to_string(),
            "a.*.b".to_string(),
            "**".to_string(),
            "*".to_string(),
            "$_GET".to_string(),
            "x[*]".to_string(),
            "é.*".to_string(),
            "***.x".to_string(),
            "*.*".to_string(),
            "**.**".to_string(),
            "a*b".to_string(),
            "*\n*".to_string(),
            "x.*".to_string(),
        ]);
    }

    /// Every glob of `patterns` answers as the former `fancy_regex` glob
    /// on names built around it: the glob itself, its stars replaced by
    /// one and by two segments, with a prefix, a suffix and a newline.
    fn assert_glob_engines_agree(mut patterns: Vec<String>) {
        patterns.sort();
        patterns.dedup();
        let mut names = vec![
            String::new(),
            ".".to_string(),
            "execute".to_string(),
            "a.b".to_string(),
            "a..b".to_string(),
            "x.y\n".to_string(),
            "é.ü".to_string(),
            "a\nb.x".to_string(),
            "\n.x".to_string(),
            "ab".to_string(),
            "a.b.c.d.e".to_string(),
        ];
        for pattern in &patterns {
            for name in [
                pattern.replace("**", "a.b").replace('*', "c"),
                pattern.replace('*', ""),
                pattern.replace('*', "c.d"),
            ] {
                names.push(format!("p.{name}"));
                names.push(format!("{name}x"));
                names.push(format!("{name}\n"));
                names.push(name);
            }
            names.push(pattern.clone());
        }
        names.sort();
        names.dedup();
        for pattern in &patterns {
            let (new, former) = (compile_glob_pattern(pattern), former_glob(pattern));
            for name in &names {
                assert_eq!(
                    new.is_match(name),
                    former.is_match(name).unwrap(),
                    "glob {pattern:?} on {name:?}"
                );
            }
        }
    }

    #[test]
    fn test_compile_glob_pattern_exact() {
        let re = compile_glob_pattern("os.system");
        assert!(match_pattern("os.system", &re));
        assert!(!match_pattern("os.system2", &re));
    }

    #[test]
    fn test_compile_glob_pattern_single_star() {
        let re = compile_glob_pattern("*.execute");
        assert!(match_pattern("cursor.execute", &re));
        assert!(!match_pattern("db.cursor.execute", &re));
    }

    #[test]
    fn test_compile_glob_pattern_double_star() {
        let re = compile_glob_pattern("**.execute");
        assert!(match_pattern("db.cursor.execute", &re));
        // ** requires >=1 segment before a dot; here there is no dot at all.
        assert!(!match_pattern("execute", &re));
    }

    #[test]
    fn test_eval_rhs_const_is_clean() {
        let specs = specs_with(vec![], vec![]);
        let mut findings = Vec::new();
        let t = eval_rhs(
            &Rhs::Const(ConstValue::Int(1)),
            &empty_state(),
            &specs,
            &mut findings,
            Site::bare(1),
        );
        assert!(t.is_clean());
    }

    #[test]
    fn test_eval_rhs_varref_source_match() {
        let specs = specs_with(vec![SourceSpec::new("request", "http")], vec![]);
        let mut findings = Vec::new();
        let t = eval_rhs(
            &varref("request"),
            &empty_state(),
            &specs,
            &mut findings,
            Site::bare(5),
        );
        assert!(t.is_tainted());
    }

    #[test]
    fn test_eval_rhs_attrref_source_match() {
        let specs = specs_with(vec![SourceSpec::new("request.GET", "http")], vec![]);
        let mut findings = Vec::new();
        let expr = attr(varref("request"), "GET");
        let t = eval_rhs(&expr, &empty_state(), &specs, &mut findings, Site::bare(3));
        assert!(t.is_tainted());
    }

    #[test]
    fn test_eval_call_source_via_call() {
        let specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut findings = Vec::new();
        let expr = call(varref("input"), vec![]);
        let t = eval_rhs(&expr, &empty_state(), &specs, &mut findings, Site::bare(1));
        assert!(t.is_tainted());
    }

    #[test]
    fn test_sink_emits_finding_when_arg_tainted() {
        let specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        let mut findings = Vec::new();
        let src = call(varref("input"), vec![]);
        let sink_call = call(attr(varref("os"), "system"), vec![src]);
        let t = eval_rhs(
            &sink_call,
            &empty_state(),
            &specs,
            &mut findings,
            Site::bare(10),
        );
        assert!(t.is_clean(), "le retour d'un sink reste clean par défaut");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 10);
        assert_eq!(findings[0].sink_text, "os.system".into());
    }

    #[test]
    fn test_sink_no_finding_when_arg_clean() {
        let specs = specs_with(vec![], vec![SinkSpec::new("os.system")]);
        let mut findings = Vec::new();
        let sink_call = call(
            attr(varref("os"), "system"),
            vec![Rhs::Const(ConstValue::Str("ls".to_string()))],
        );
        eval_rhs(
            &sink_call,
            &empty_state(),
            &specs,
            &mut findings,
            Site::bare(1),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_sanitizer_clears_return_taint() {
        let mut specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        specs.sanitizers.push(SanitizerSpec::new("shlex.quote"));
        let mut findings = Vec::new();
        let src = call(varref("input"), vec![]);
        let sanitized = call(attr(varref("shlex"), "quote"), vec![src]);
        let t = eval_rhs(
            &sanitized,
            &empty_state(),
            &specs,
            &mut findings,
            Site::bare(1),
        );
        assert!(t.is_clean());
    }

    #[test]
    fn test_passthrough_propagates_arg_taint() {
        let mut specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        specs.passthroughs.push(PassthroughSpec::new("str"));
        let mut findings = Vec::new();
        let src = call(varref("input"), vec![]);
        let wrapped = call(varref("str"), vec![src]);
        let t = eval_rhs(
            &wrapped,
            &empty_state(),
            &specs,
            &mut findings,
            Site::bare(1),
        );
        assert!(t.is_tainted());
    }

    #[test]
    fn test_kinds_compatible_filters_sink() {
        let mut specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        specs
            .sinks
            .push(SinkSpec::new("os.system").with_kinds(vec!["http".to_string()]));
        let mut findings = Vec::new();
        let src = call(varref("input"), vec![]); // kind = cli
        let sink_call = call(attr(varref("os"), "system"), vec![src]);
        eval_rhs(
            &sink_call,
            &empty_state(),
            &specs,
            &mut findings,
            Site::bare(1),
        );
        assert!(
            findings.is_empty(),
            "kind cli ne doit pas matcher un sink filtré sur http"
        );
    }

    #[test]
    fn test_transfer_assign_updates_state() {
        let specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut findings = Vec::new();
        let stmt = IrStmt::Assign {
            lhs: Lhs::VarLhs("x".to_string()),
            rhs: call(varref("input"), vec![]),
            lineno: 1,
        };
        let mut new_state = empty_state();
        transfer_stmt(&stmt, &mut new_state, &specs, &mut findings, None);
        assert!(state_get(&new_state, "x").is_tainted());
    }

    #[test]
    fn test_transfer_assign_subscript_lhs_sink() {
        let mut specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        specs.sinks.push(SinkSpec::new("response.headers"));
        let mut findings = Vec::new();
        let stmt = IrStmt::Assign {
            lhs: Lhs::SubscriptLhs {
                base: Box::new(attr(varref("response"), "headers")),
                key: Box::new(Rhs::Const(ConstValue::Str("X".to_string()))),
            },
            rhs: call(varref("input"), vec![]),
            lineno: 7,
        };
        transfer_stmt(&stmt, &mut empty_state(), &specs, &mut findings, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].sink_text, "response.headers".into());
    }

    #[test]
    fn test_element_write_taints_wildcard_slot() {
        let specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut findings = Vec::new();
        // lst.append(input())
        let stmt = IrStmt::Call {
            callee: attr(varref("lst"), "append"),
            args: vec![call(varref("input"), vec![])],
            kwargs: vec![],
            lineno: 1,
        };
        let mut new_state = empty_state();
        transfer_stmt(&stmt, &mut new_state, &specs, &mut findings, None);
        assert!(state_get(&new_state, "lst[*]").is_tainted());
    }

    /// Ticket #271: a constant key read on a variable or an attribute that
    /// a source names is that source (`$_GET['id']`, `request.GET['q']`);
    /// a constant key read on any other variable keeps reading its own
    /// entry only (§9.bis).
    #[test]
    fn test_const_key_read_on_a_source_is_that_source() {
        let specs = specs_with(
            vec![
                SourceSpec::new("$_GET", "http"),
                SourceSpec::new("request.GET", "http"),
            ],
            vec![],
        );
        let key = || Box::new(Rhs::Const(ConstValue::Str("id".to_string())));
        let read = |base: Rhs| Rhs::SubscriptRef {
            base: Box::new(base),
            key: key(),
        };
        let eval =
            |rhs: &Rhs, state: &State| eval_rhs(rhs, state, &specs, &mut vec![], Site::bare(1));
        let state = empty_state();
        assert!(eval(&read(varref("$_GET")), &state).is_tainted());
        assert!(eval(&read(attr(varref("request"), "GET")), &state).is_tainted());
        assert!(eval(&read(varref("$params")), &state).is_clean());
        // An entry written on the state is read as written.
        let state = state_set(&state, "$params['other']", tainted("http", 1));
        assert!(eval(&read(varref("$params")), &state).is_clean());
    }

    /// Ticket #256: a passthrough that names its argument carries that
    /// argument and the receiver only; one written `arg_index=none`, the
    /// receiver only. The query of `elementpath.select(root, query)` and of
    /// `root.xpath(query)` is not in their result, the document is.
    #[test]
    fn test_passthrough_carries_the_arguments_it_names() {
        let select = PassthroughSpec::new("elementpath.select").with_args_in(vec![0]);
        let mut xpath = PassthroughSpec::new("**.xpath");
        xpath.receiver_only = true;
        let mut specs = specs_with(vec![], vec![]);
        specs.passthroughs = vec![select, xpath];
        let eval =
            |rhs: &Rhs, state: &State| eval_rhs(rhs, state, &specs, &mut vec![], Site::bare(1));
        let state = state_set(&empty_state(), "query", tainted("http", 1));
        let select_call = |root: &str| {
            call(
                attr(varref("elementpath"), "select"),
                vec![varref(root), varref("query")],
            )
        };
        let xpath_call = |root: &str| call(attr(varref(root), "xpath"), vec![varref("query")]);
        assert!(eval(&select_call("root"), &state).is_clean());
        assert!(eval(&xpath_call("root"), &state).is_clean());
        let state = state_set(&state, "posted", tainted("http", 2));
        assert!(eval(&select_call("posted"), &state).is_tainted());
        assert!(eval(&xpath_call("posted"), &state).is_tainted());
    }

    /// Ticket #259: a read by several constant keys takes the source of
    /// the base of its subscripts (`request.json["user"]["name"]`,
    /// `$_POST['user']['name']`), by name only: the other entries of a
    /// local are not joined.
    #[test]
    fn test_nested_const_key_read_on_a_source_is_that_source() {
        let specs = specs_with(
            vec![
                SourceSpec::new("$_POST", "http"),
                SourceSpec::new("request.json", "http"),
            ],
            vec![],
        );
        let read = |base: Rhs, key: &str| Rhs::SubscriptRef {
            base: Box::new(base),
            key: Box::new(Rhs::Const(ConstValue::Str(key.to_string()))),
        };
        let eval =
            |rhs: &Rhs, state: &State| eval_rhs(rhs, state, &specs, &mut vec![], Site::bare(1));
        let state = empty_state();
        let nested = |base: Rhs| read(read(base, "user"), "name");
        assert!(eval(&nested(varref("$_POST")), &state).is_tainted());
        assert!(eval(&nested(attr(varref("request"), "json")), &state).is_tainted());
        // A dynamic key inside goes down to the same base.
        let dynamic = Rhs::SubscriptRef {
            base: Box::new(Rhs::SubscriptRef {
                base: Box::new(varref("$_POST")),
                key: Box::new(varref("$i")),
            }),
            key: Box::new(Rhs::Const(ConstValue::Str("name".to_string()))),
        };
        assert!(eval(&dynamic, &state).is_tainted());
        // A local keeps reading its own entries.
        let state = state_set(&state, "data['user']['name']", tainted("http", 1));
        assert!(eval(&read(read(varref("data"), "user"), "role"), &state).is_clean());
        assert!(eval(&nested(varref("data")), &state).is_tainted());
    }

    #[test]
    fn test_indexed_write_const_key() {
        let specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut findings = Vec::new();
        // d.__setitem__('k', input())  (obj[key] = value is normally
        // already desugared by SubscriptLhs, but a direct __setitem__
        // call is also a real form: configparser.set)
        let stmt = IrStmt::Call {
            callee: attr(varref("d"), "__setitem__"),
            args: vec![
                Rhs::Const(ConstValue::Str("k".to_string())),
                call(varref("input"), vec![]),
            ],
            kwargs: vec![],
            lineno: 1,
        };
        let mut new_state = empty_state();
        transfer_stmt(&stmt, &mut new_state, &specs, &mut findings, None);
        assert!(state_get(&new_state, "d['k']").is_tainted());
    }

    #[test]
    fn test_indexed_read_picks_up_prior_write() {
        let specs = specs_with(vec![], vec![]);
        let mut state = empty_state();
        state = state_set(
            &state,
            "d['k']",
            Taint::tainted(
                ["cli".to_string()],
                SourceInfo {
                    line: 1,
                    expr: "x".to_string().into(),
                    kind: "cli".into(),
                },
            ),
        );
        let mut findings = Vec::new();
        // d.get('k')
        let expr = call(
            attr(varref("d"), "get"),
            vec![Rhs::Const(ConstValue::Str("k".to_string()))],
        );
        let t = eval_rhs(&expr, &state, &specs, &mut findings, Site::bare(1));
        assert!(t.is_tainted());
    }

    #[test]
    fn test_transfer_return_evaluates_effects() {
        let specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        let mut findings = Vec::new();
        let sink_call = call(
            attr(varref("os"), "system"),
            vec![call(varref("input"), vec![])],
        );
        let stmt = IrStmt::Return {
            value: Some(sink_call),
            lineno: 4,
        };
        transfer_stmt(&stmt, &mut empty_state(), &specs, &mut findings, None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_transfer_stmts_sequences_state() {
        let specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut findings = Vec::new();
        let stmts = vec![
            IrStmt::Assign {
                lhs: Lhs::VarLhs("x".to_string()),
                rhs: call(varref("input"), vec![]),
                lineno: 1,
            },
            IrStmt::Assign {
                lhs: Lhs::VarLhs("y".to_string()),
                rhs: varref("x"),
                lineno: 2,
            },
        ];
        let mut out = empty_state();
        transfer_stmts(&stmts, &mut out, &specs, &mut findings, None);
        assert!(
            state_get(&out, "y").is_tainted(),
            "la taint doit se propager de x à y"
        );
    }

    #[test]
    fn test_noop_leaves_state_unchanged() {
        let specs = specs_with(vec![], vec![]);
        let mut findings = Vec::new();
        let state = empty_state();
        let mut out = state.clone();
        transfer_stmt(
            &IrStmt::Noop { lineno: 1 },
            &mut out,
            &specs,
            &mut findings,
            None,
        );
        assert_eq!(out, state);
    }

    // ------------------------------------------------------------------
    // §10bis — hybrid regex matching on the source text
    // ------------------------------------------------------------------

    #[test]
    fn test_strip_plain_string_literals_removes_flat_literal() {
        assert_eq!(strip_plain_string_literals("\"select ip from users\""), " ");
    }

    #[test]
    fn test_strip_plain_string_literals_keeps_interpolated() {
        let out = strip_plain_string_literals("return f'...{bar}...'");
        assert!(
            out.contains("{bar}"),
            "un littéral interpolé ne doit pas être retiré"
        );
    }

    /// A source whose dotted pattern dropped a look-around is taken by the
    /// data flow only when its raw regex matches the line (ticket #270):
    /// `System.getProperty("os.name")`, which the rule excludes, is not a
    /// source; `System.getProperty("upload.dir")` is.
    #[test]
    fn test_source_needing_confirmation_reads_its_line() {
        let mut specs = specs_with(vec![], vec![]);
        let mut source = SourceSpec::new("**.getProperty", "env")
            .with_raw_regex(Regex::new(r#"\.getProperty\s*\(\s*"(?!os\.name)"#).unwrap());
        source.confirm_on_line = true;
        specs.sources.push(source);
        let source_lines: SourceLines = [
            r#"String os = System.getProperty("os.name");"#.to_string(),
            r#"String dir = System.getProperty("upload.dir");"#.to_string(),
        ]
        .into_iter()
        .collect();
        let lines = RuleLines::new(&source_lines, &specs);
        let read = call(
            attr(varref("System"), "getProperty"),
            vec![Rhs::Const(ConstValue::Str("x".into()))],
        );
        let excluded = eval_rhs(
            &read,
            &empty_state(),
            &specs,
            &mut vec![],
            Site::new(1, Some(&lines)),
        );
        assert!(excluded.is_clean(), "os.name is excluded by the rule");
        let kept = eval_rhs(
            &read,
            &empty_state(),
            &specs,
            &mut vec![],
            Site::new(2, Some(&lines)),
        );
        assert!(kept.is_tainted(), "upload.dir is a source");
        // Without the file's text, the source is taken as before.
        let bare = eval_rhs(&read, &empty_state(), &specs, &mut vec![], Site::bare(1));
        assert!(bare.is_tainted());
    }

    /// A sanitizer cut at its call is taken only when its line passes the
    /// filter its regex names (ticket #270).
    #[test]
    fn test_sanitizer_needing_confirmation_reads_its_line() {
        let mut specs = specs_with(vec![], vec![]);
        let mut sanitizer = SanitizerSpec::new("filter_var")
            .with_raw_regex(Regex::new(r"filter_var\s*\([^)]*FILTER_SANITIZE").unwrap());
        sanitizer.confirm_on_line = true;
        specs.sanitizers.push(sanitizer);
        let source_lines: SourceLines = [
            "$id = filter_var($raw, FILTER_SANITIZE_NUMBER_INT);".to_string(),
            "$id = filter_var($raw, FILTER_UNSAFE_RAW);".to_string(),
        ]
        .into_iter()
        .collect();
        let lines = RuleLines::new(&source_lines, &specs);
        let state = state_set(
            &empty_state(),
            "raw",
            Taint::tainted(
                ["http".to_string()],
                SourceInfo {
                    line: 1,
                    expr: "raw".into(),
                    kind: "http".into(),
                },
            ),
        );
        let filtered = call(varref("filter_var"), vec![varref("raw")]);
        let sanitized = eval_rhs(
            &filtered,
            &state,
            &specs,
            &mut vec![],
            Site::new(1, Some(&lines)),
        );
        assert!(sanitized.is_clean(), "FILTER_SANITIZE cleans the value");
        let unsafe_raw = eval_rhs(
            &filtered,
            &state,
            &specs,
            &mut vec![],
            Site::new(2, Some(&lines)),
        );
        assert!(unsafe_raw.is_tainted(), "FILTER_UNSAFE_RAW does not");
    }

    #[test]
    fn test_discard_sinks_failing_raw_regex_drops_excluded_receiver() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sinks.push(
            SinkSpec::new("**.println")
                .with_raw_regex(Regex::new(r"(?<!System\.(?:out|err))\.println\s*\(").unwrap()),
        );
        let source_lines: SourceLines = ["System.out.println(tainted);".to_string()]
            .into_iter()
            .collect();
        let mut findings = vec![dummy_finding("System.out.println", 1)];
        discard_sinks_failing_raw_regex(
            &mut findings,
            0,
            &specs,
            &RuleLines::new(&source_lines, &specs),
        );
        assert!(
            findings.is_empty(),
            "System.out.println doit être exclu par le lookbehind négatif"
        );
    }

    #[test]
    fn test_discard_sinks_failing_raw_regex_keeps_matching_receiver() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sinks.push(
            SinkSpec::new("**.println")
                .with_raw_regex(Regex::new(r"(?<!System\.(?:out|err))\.println\s*\(").unwrap()),
        );
        let source_lines: SourceLines = ["foo.println(tainted);".to_string()].into_iter().collect();
        let mut findings = vec![dummy_finding("foo.println", 1)];
        discard_sinks_failing_raw_regex(
            &mut findings,
            0,
            &specs,
            &RuleLines::new(&source_lines, &specs),
        );
        assert_eq!(findings.len(), 1, "foo.println ne doit pas être exclu");
    }

    #[test]
    fn test_discard_sinks_failing_raw_regex_no_candidate_keeps_finding() {
        let specs = specs_with(vec![], vec![SinkSpec::new("os.system")]);
        let source_lines: SourceLines = ["cursor.execute(tainted)".to_string()]
            .into_iter()
            .collect();
        let mut findings = vec![dummy_finding("cursor.execute", 1)];
        discard_sinks_failing_raw_regex(
            &mut findings,
            0,
            &specs,
            &RuleLines::new(&source_lines, &specs),
        );
        assert_eq!(
            findings.len(),
            1,
            "aucune spec candidate ne matche sink_text -> jamais filtré"
        );
    }

    #[test]
    fn test_aux_match_line_guard_sanitizer_clears_taint_on_terminator() {
        let mut specs = specs_with(vec![], vec![]);
        specs
            .sanitizers
            .push(SanitizerSpec::new("is_safe").with_raw_regex(Regex::new(r"is_safe\(").unwrap()));
        let source_lines: SourceLines =
            ["if not is_safe(bar):".to_string(), "    return".to_string()]
                .into_iter()
                .collect();
        let mut state = empty_state();
        state = state_set(&state, "bar", tainted("cli", 1));
        let stmt = IrStmt::Branch {
            condition: Rhs::Const(ConstValue::Bool(true)),
            lineno: 1,
        };
        let mut findings = Vec::new();
        let mut new_state = state.clone();
        aux_match_line(
            &stmt,
            &mut new_state,
            &specs,
            &mut findings,
            &RuleLines::new(&source_lines, &specs),
        );
        assert!(!state_get(&new_state, "bar").is_tainted());
    }

    /// Ticket #250: a check compared to its failure value is a guard,
    /// whatever side the comparison is written on; compared to the value
    /// of a success, it is not, and the variable stays tainted.
    #[test]
    fn test_aux_match_line_guard_compared_to_failure_value() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sanitizers.push(
            SanitizerSpec::new("starts").with_raw_regex(Regex::new(r"\.startsWith\s*\(").unwrap()),
        );
        specs.sanitizers.push(
            SanitizerSpec::new("strpos")
                .with_raw_regex(Regex::new(r"\bif\s*\(.*\bstrpos\s*\(").unwrap()),
        );
        // The guard clears the tainted variables its line names.
        let cleared = |condition: &str, variable: &str| {
            let source_lines: SourceLines = [condition.to_string(), "    return;".to_string()]
                .into_iter()
                .collect();
            let mut state = state_set(&empty_state(), variable, tainted("http", 1));
            let stmt = IrStmt::Branch {
                condition: Rhs::Const(ConstValue::Bool(true)),
                lineno: 1,
            };
            aux_match_line(
                &stmt,
                &mut state,
                &specs,
                &mut Vec::new(),
                &RuleLines::new(&source_lines, &specs),
            );
            !state_get(&state, variable).is_tainted()
        };
        assert!(cleared("if (p.startsWith(base) == false) {", "p"));
        assert!(cleared("if (strpos($p, $base) !== 0) {", "$p"));
        assert!(cleared("if (0 !== strpos($p, $base)) {", "$p"));
        assert!(!cleared("if (p.startsWith(base) == true) {", "p"));
        assert!(!cleared("if (strpos($p, $base) === 0) {", "$p"));
        // The comparison is on another call than the sanitizer's.
        assert!(!cleared("if (size(p) != 0 && p.startsWith(base)) {", "p"));
    }

    /// Ticket #254: a pattern that spans the line names every call it
    /// can end on, not only the last one; a pattern that goes on after
    /// the `(` of its call still names it.
    #[test]
    fn test_sanitizer_names_call_on_a_line_with_several_calls() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sanitizers.push(
            SanitizerSpec::new("strpos")
                .with_raw_regex(Regex::new(r"\bif\s*\(.*\bstrpos\s*\(").unwrap()),
        );
        specs.sanitizers.push(
            SanitizerSpec::new("filter_var")
                .with_raw_regex(Regex::new(r"filter_var\s*\([^)]*FILTER_SANITIZE").unwrap()),
        );
        let line = "if (strpos($a, $b) === 0 && strpos($c, $d) === 0) {";
        let parens: Vec<usize> = line
            .match_indices("strpos(")
            .map(|(at, _)| at + 6)
            .collect();
        assert_eq!(parens.len(), 2);
        for paren in parens {
            assert!(sanitizer_names_call(line, &specs, paren), "{paren}");
        }
        // The `(` of the `if` is no call of a sanitizer.
        assert!(!sanitizer_names_call(line, &specs, 3));
        let line = "$x = filter_var($v, FILTER_SANITIZE_STRING);";
        assert!(sanitizer_names_call(line, &specs, line.find('(').unwrap()));
    }

    /// Ticket #157: a PHP guard that reassigns the variable to a literal
    /// on the next line clears it; the name keeps its `$`.
    #[test]
    fn test_aux_match_line_php_guard_reassign_clears_dollar_variable() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sanitizers.push(
            SanitizerSpec::new("filter_var")
                .with_raw_regex(Regex::new(r"filter_var.*FILTER_VALIDATE_URL").unwrap()),
        );
        let source_lines: SourceLines = [
            "if (!filter_var($next, FILTER_VALIDATE_URL)) {".to_string(),
            "    $next = '/';".to_string(),
            "}".to_string(),
        ]
        .into_iter()
        .collect();
        let mut state = empty_state();
        state = state_set(&state, "$next", tainted("http", 1));
        let stmt = IrStmt::Branch {
            condition: Rhs::Const(ConstValue::Bool(true)),
            lineno: 1,
        };
        let mut findings = Vec::new();
        let mut new_state = state.clone();
        aux_match_line(
            &stmt,
            &mut new_state,
            &specs,
            &mut findings,
            &RuleLines::new(&source_lines, &specs),
        );
        assert!(!state_get(&new_state, "$next").is_tainted());
    }

    #[test]
    fn test_aux_match_line_generic_guard_clears_without_sanitizer_spec() {
        let specs = specs_with(vec![], vec![]);
        let source_lines: SourceLines = [
            "if not bar.startswith('safe'):".to_string(),
            "    return".to_string(),
        ]
        .into_iter()
        .collect();
        let mut state = empty_state();
        state = state_set(&state, "bar", tainted("cli", 1));
        let stmt = IrStmt::Branch {
            condition: Rhs::Const(ConstValue::Bool(true)),
            lineno: 1,
        };
        let mut findings = Vec::new();
        let mut new_state = state.clone();
        aux_match_line(
            &stmt,
            &mut new_state,
            &specs,
            &mut findings,
            &RuleLines::new(&source_lines, &specs),
        );
        assert!(!state_get(&new_state, "bar").is_tainted());
    }

    #[test]
    fn test_aux_match_line_backward_aliasing_via_guard() {
        // url = urlparse(bar); if url.netloc in [...]: return; redirect(bar)
        let specs = specs_with(vec![], vec![]);
        let source_lines: SourceLines = [
            "url = urlparse(bar)".to_string(),
            "if url.netloc in allowed_hosts:".to_string(),
            "    return".to_string(),
        ]
        .into_iter()
        .collect();
        let mut state = empty_state();
        state = state_set(&state, "bar", tainted("http", 1));
        let stmt = IrStmt::Branch {
            condition: Rhs::Const(ConstValue::Bool(true)),
            lineno: 2,
        };
        let mut findings = Vec::new();
        let mut new_state = state.clone();
        aux_match_line(
            &stmt,
            &mut new_state,
            &specs,
            &mut findings,
            &RuleLines::new(&source_lines, &specs),
        );
        assert!(
            !state_get(&new_state, "bar").is_tainted(),
            "aliasing arrière doit nettoyer bar via url"
        );
    }

    #[test]
    fn test_aux_match_line_source_taints_lhs() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sources.push(
            SourceSpec::new("request.GET", "http")
                .with_raw_regex(Regex::new(r"request\.GET").unwrap()),
        );
        let source_lines: SourceLines = ["x = request.GET['q']".to_string()].into_iter().collect();
        let stmt = IrStmt::Assign {
            lhs: Lhs::VarLhs("x".to_string()),
            rhs: Rhs::Const(ConstValue::Int(0)),
            lineno: 1,
        };
        let mut findings = Vec::new();
        let mut new_state = empty_state();
        aux_match_line(
            &stmt,
            &mut new_state,
            &specs,
            &mut findings,
            &RuleLines::new(&source_lines, &specs),
        );
        assert!(state_get(&new_state, "x").is_tainted());
    }

    /// Ticket #271: the line layer does not mark the target of a literal
    /// holding no data, even on a line holding a source.
    #[test]
    fn test_aux_match_line_source_skips_literal_without_data() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sources.push(
            SourceSpec::new("$_GET", "http").with_raw_regex(Regex::new(r"\$_GET\[").unwrap()),
        );
        let source_lines: SourceLines =
            ["$f = array('name' => $_GET['name'], 'status' => 'active');".to_string()]
                .into_iter()
                .collect();
        let rule_lines = RuleLines::new(&source_lines, &specs);
        let mut state = empty_state();
        let assign = |lhs: Lhs, rhs: Rhs| IrStmt::Assign {
            lhs,
            rhs,
            lineno: 1,
        };
        let entry = |key: &str| Lhs::SubscriptLhs {
            base: Box::new(varref("$f")),
            key: Box::new(Rhs::Const(ConstValue::Str(key.to_string()))),
        };
        for stmt in [
            assign(Lhs::VarLhs("$f".to_string()), Rhs::DictRef(Vec::new())),
            assign(entry("name"), Rhs::Opaque),
            assign(
                entry("status"),
                Rhs::Const(ConstValue::Str("active".to_string())),
            ),
        ] {
            aux_match_line(&stmt, &mut state, &specs, &mut Vec::new(), &rule_lines);
        }
        assert!(state_get(&state, "$f").is_clean());
        assert!(state_get(&state, "$f['status']").is_clean());
        assert!(state_get(&state, "$f['name']").is_tainted());
    }

    #[test]
    fn test_aux_match_line_sink_emits_finding_from_state() {
        let mut specs = specs_with(vec![], vec![]);
        specs
            .sinks
            .push(SinkSpec::new("os.system").with_raw_regex(Regex::new(r"os\.system\(").unwrap()));
        let source_lines: SourceLines = ["os.system(cmd)".to_string()].into_iter().collect();
        let mut state = empty_state();
        state = state_set(&state, "cmd", tainted("cli", 1));
        let stmt = IrStmt::Call {
            callee: Rhs::VarRef("noop".to_string()),
            args: vec![],
            kwargs: vec![],
            lineno: 1,
        };
        let mut findings = Vec::new();
        aux_match_line(
            &stmt,
            &mut state.clone(),
            &specs,
            &mut findings,
            &RuleLines::new(&source_lines, &specs),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].sink_text, "os.system(cmd)".into());
    }

    #[test]
    fn test_aux_match_line_multiline_sink_extends_scan_text() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sinks.push(
            SinkSpec::new("cursor.execute").with_raw_regex(Regex::new(r"\.execute\s*\(").unwrap()),
        );
        let source_lines: SourceLines = [
            "cursor.execute(".to_string(),
            "    query + tainted_var".to_string(),
            ")".to_string(),
        ]
        .into_iter()
        .collect();
        let mut state = empty_state();
        state = state_set(&state, "tainted_var", tainted("cli", 2));
        let stmt = IrStmt::Call {
            callee: Rhs::VarRef("noop".to_string()),
            args: vec![],
            kwargs: vec![],
            lineno: 1,
        };
        let mut findings = Vec::new();
        aux_match_line(
            &stmt,
            &mut state.clone(),
            &specs,
            &mut findings,
            &RuleLines::new(&source_lines, &specs),
        );
        assert_eq!(
            findings.len(),
            1,
            "la taint sur la ligne de continuation doit être détectée"
        );
    }

    #[test]
    fn test_aux_match_line_multiline_sink_cleared_by_sanitizer_in_continuation() {
        // `db.execute(select(...).where(... == status))` on one line is
        // cleared by the `select(` sanitizer; the same call split over
        // several lines must be too (my-ia, SQLAlchemy queries).
        let mut specs = specs_with(vec![], vec![]);
        specs.sinks.push(
            SinkSpec::new("db.execute").with_raw_regex(Regex::new(r"\.execute\s*\(").unwrap()),
        );
        specs.sanitizers.push(
            SanitizerSpec::new("select").with_raw_regex(Regex::new(r"\bselect\s*\(").unwrap()),
        );
        let source_lines: SourceLines = [
            "return await db.execute(".to_string(),
            "    select(Call)".to_string(),
            "    .where(Call.status == status)".to_string(),
            ")".to_string(),
        ]
        .into_iter()
        .collect();
        let mut state = empty_state();
        state = state_set(&state, "status", tainted("http", 1));
        let stmt = IrStmt::Call {
            callee: Rhs::VarRef("noop".to_string()),
            args: vec![],
            kwargs: vec![],
            lineno: 1,
        };
        let mut findings = Vec::new();
        aux_match_line(
            &stmt,
            &mut state.clone(),
            &specs,
            &mut findings,
            &RuleLines::new(&source_lines, &specs),
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn test_aux_match_line_no_finding_when_sink_line_has_no_tainted_var() {
        let mut specs = specs_with(vec![], vec![]);
        specs
            .sinks
            .push(SinkSpec::new("os.system").with_raw_regex(Regex::new(r"os\.system\(").unwrap()));
        let source_lines: SourceLines = ["os.system(cmd)".to_string()].into_iter().collect();
        let stmt = IrStmt::Call {
            callee: Rhs::VarRef("noop".to_string()),
            args: vec![],
            kwargs: vec![],
            lineno: 1,
        };
        let mut findings = Vec::new();
        aux_match_line(
            &stmt,
            &mut empty_state(),
            &specs,
            &mut findings,
            &RuleLines::new(&source_lines, &specs),
        );
        assert!(findings.is_empty());
    }

    /// Runs the line layer on a single `os.system(...)` call line with
    /// `var` tainted, and returns the findings (ticket #225).
    #[test]
    fn test_indexed_source_is_a_subscript_read_only() {
        // Ticket #268: `Request\[` makes `Request["id"]`, `Request[name]`
        // and a whole read of `Request` sources, not the receiver of a
        // member, `Request.HttpContext.User...`.
        let mut source = SourceSpec::new("Request", "http");
        source.subscript_only = true;
        let specs = specs_with(vec![source], vec![]);
        let state = State::default();
        let eval = |rhs: &Rhs| eval_rhs(rhs, &state, &specs, &mut Vec::new(), Site::bare(1));
        let request = || Rhs::VarRef("Request".to_string());
        let constant_key = Rhs::SubscriptRef {
            base: Box::new(request()),
            key: Box::new(Rhs::Const(ConstValue::Str("id".to_string()))),
        };
        let dynamic_key = Rhs::SubscriptRef {
            base: Box::new(request()),
            key: Box::new(Rhs::VarRef("name".to_string())),
        };
        let member = attr(attr(attr(request(), "HttpContext"), "User"), "Name");
        assert!(eval(&constant_key).is_tainted());
        assert!(eval(&dynamic_key).is_tainted());
        assert!(eval(&member).is_clean());
        assert!(eval(&request()).is_tainted());
    }

    #[test]
    fn test_check_sink_reads_the_keyword_the_rule_names() {
        // Ticket #261: `Response(body, headers=h)` with `arg_index=2
        // arg_name=headers`. A tainted body or another keyword is not the
        // header value.
        let specs = specs_with(vec![], vec![]);
        let mut spec = SinkSpec::new("Response").with_args(vec![2]);
        spec.arg_name = Some("headers".to_string());
        let run = |args: &[Taint], keyword: &str| {
            let mut kw = BTreeMap::new();
            kw.insert(keyword.to_string(), tainted("http", 1));
            let mut findings = Vec::new();
            check_sink(&spec, "Response", args, &kw, &specs, &mut findings, 3);
            findings.len()
        };
        assert_eq!(run(&[Taint::Clean], "headers"), 1);
        assert_eq!(run(&[Taint::Clean], "status"), 0);
        assert_eq!(run(&[tainted("http", 1)], "status"), 0);
        assert_eq!(
            run(&[Taint::Clean, Taint::Clean, tainted("http", 1)], "status"),
            1
        );
    }

    #[test]
    fn test_keyword_argument_text() {
        assert!(is_keyword_argument("headers={'X': v}", "headers"));
        assert!(is_keyword_argument(" headers = h", "headers"));
        assert!(!is_keyword_argument("headers == h", "headers"));
        assert!(!is_keyword_argument("headers_extra=h", "headers"));
        assert!(!is_keyword_argument("h", "headers"));
    }

    fn sink_findings_with_tainted(line: &str, var: &str) -> Vec<Finding> {
        let mut specs = specs_with(vec![], vec![]);
        specs
            .sinks
            .push(SinkSpec::new("os.system").with_raw_regex(Regex::new(r"os\.system\(").unwrap()));
        let source_lines: SourceLines = [line.to_string()].into_iter().collect();
        let state = state_set(&empty_state(), var, tainted("cli", 1));
        let stmt = IrStmt::Call {
            callee: Rhs::VarRef("noop".to_string()),
            args: vec![],
            kwargs: vec![],
            lineno: 1,
        };
        let mut findings = Vec::new();
        aux_match_line(
            &stmt,
            &mut state.clone(),
            &specs,
            &mut findings,
            &RuleLines::new(&source_lines, &specs),
        );
        findings
    }

    #[test]
    fn test_aux_match_line_sink_ignores_name_inside_longer_word() {
        // Ticket #225: a tainted `id` is not in `width`, `uuid` or
        // `valid`, a tainted `name` not in `filename`, `$id` not in `$idx`.
        assert!(sink_findings_with_tainted("os.system(width + uuid + valid)", "id").is_empty());
        assert!(sink_findings_with_tainted("os.system(filename)", "name").is_empty());
        assert!(sink_findings_with_tainted("os.system(name_2)", "name").is_empty());
        assert!(sink_findings_with_tainted("os.system($idx)", "$id").is_empty());
        assert!(sink_findings_with_tainted("os.system(a$id)", "id").is_empty());
    }

    #[test]
    fn test_aux_match_line_sink_finds_whole_identifier() {
        // Ticket #225: the whole name, alone or next to punctuation,
        // still reports, as do paths kept as state keys.
        assert_eq!(sink_findings_with_tainted("os.system(id)", "id").len(), 1);
        assert_eq!(
            sink_findings_with_tainted("os.system('ls ' + id)", "id").len(),
            1
        );
        assert_eq!(
            sink_findings_with_tainted("os.system(width + id.strip())", "id").len(),
            1
        );
        assert_eq!(
            sink_findings_with_tainted("os.system(self.name)", "self.name").len(),
            1
        );
        assert_eq!(
            sink_findings_with_tainted("os.system(args[0].x)", "args[0]").len(),
            1
        );
        assert_eq!(sink_findings_with_tainted("os.system($id)", "$id").len(), 1);
        assert_eq!(
            sink_findings_with_tainted("os.system(é_id + id)", "id").len(),
            1
        );
    }

    #[test]
    fn test_aux_match_line_generic_guard_keeps_name_inside_longer_word() {
        // Ticket #225: `if not valid: return` checks `valid`, not a
        // tainted `id`, which stays tainted.
        let specs = specs_with(vec![], vec![]);
        let source_lines: SourceLines = ["if not valid:".to_string(), "    return".to_string()]
            .into_iter()
            .collect();
        let state = state_set(&empty_state(), "id", tainted("cli", 1));
        let stmt = IrStmt::Branch {
            condition: Rhs::Const(ConstValue::Bool(true)),
            lineno: 1,
        };
        let mut findings = Vec::new();
        let mut new_state = state.clone();
        aux_match_line(
            &stmt,
            &mut new_state,
            &specs,
            &mut findings,
            &RuleLines::new(&source_lines, &specs),
        );
        assert!(state_get(&new_state, "id").is_tainted());
    }

    #[test]
    fn test_mentions_identifier_edges() {
        assert!(mentions_identifier("id", "id"));
        assert!(mentions_identifier("x(id)", "id"));
        assert!(mentions_identifier("valid id", "id"));
        assert!(!mentions_identifier("valid", "id"));
        assert!(!mentions_identifier("idx", "id"));
        assert!(!mentions_identifier("", "id"));
        assert!(!mentions_identifier("id", ""));
        // A key whose edge is not an identifier character needs no
        // boundary on that edge.
        assert!(mentions_identifier("f(*rest)", "*rest"));
        assert!(mentions_identifier("(a, b)x", "(a, b)"));
    }

    #[test]
    fn test_transfer_stmt_applies_hybrid_layer_only_when_source_lines_given() {
        let mut specs = specs_with(vec![], vec![]);
        specs.sources.push(
            SourceSpec::new("os.environ", "env")
                .with_raw_regex(Regex::new(r"os\.environ").unwrap()),
        );
        let source_lines: SourceLines = ["x = os.environ['SECRET']".to_string()]
            .into_iter()
            .collect();
        let stmt = IrStmt::Assign {
            lhs: Lhs::VarLhs("x".to_string()),
            rhs: Rhs::Const(ConstValue::Int(0)),
            lineno: 1,
        };

        let mut findings = Vec::new();
        let mut state_none = empty_state();
        transfer_stmt(&stmt, &mut state_none, &specs, &mut findings, None);
        assert!(
            !state_get(&state_none, "x").is_tainted(),
            "sans source_lines, seul le cœur IR (RHS=Const) doit s'appliquer"
        );

        let mut findings2 = Vec::new();
        let mut state_some = empty_state();
        transfer_stmt(
            &stmt,
            &mut state_some,
            &specs,
            &mut findings2,
            Some(&RuleLines::new(&source_lines, &specs)),
        );
        assert!(
            state_get(&state_some, "x").is_tainted(),
            "avec source_lines, le matching hybride doit détecter la source"
        );
    }

    // ------------------------------------------------------------------
    // Part 2 — interprocedural resolution via function summary
    // ------------------------------------------------------------------

    #[test]
    fn test_eval_call_summary_emits_sink_finding_for_tainted_arg() {
        let mut specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut summary = FunctionSummary {
            name: "helper".to_string(),
            param_names: vec!["x".to_string()],
            ..Default::default()
        };
        summary.sink_param_findings.insert(
            0,
            Finding {
                rule_id: "test-rule".to_string(),
                severity: "HIGH".to_string(),
                line: 42,
                column: 0,
                sink_text: "os.system".to_string().into(),
                source_line: None,
                message: String::new(),
                cwe: None,
                flow: vec![],
                source_kind: "unknown".to_string(),
            },
        );
        specs.summaries.insert("helper".to_string(), summary.into());

        let mut findings = Vec::new();
        let src = call(varref("input"), vec![]);
        let call_expr = call(varref("helper"), vec![src]);
        eval_rhs(
            &call_expr,
            &empty_state(),
            &specs,
            &mut findings,
            Site::bare(7),
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].line, 7,
            "le finding est émis au site d'appel, pas dans le résumé"
        );
        assert_eq!(findings[0].sink_text, "helper(...)".into());
        assert!(
            findings[0]
                .flow
                .iter()
                .any(|f| f.kind == "propagation" && f.text.contains('→'))
        );
    }

    #[test]
    fn test_eval_call_summary_no_finding_when_arg_clean() {
        let mut specs = specs_with(vec![], vec![]);
        let mut summary = FunctionSummary {
            name: "helper".to_string(),
            param_names: vec!["x".to_string()],
            ..Default::default()
        };
        summary
            .sink_param_findings
            .insert(0, dummy_finding("os.system", 42));
        specs.summaries.insert("helper".to_string(), summary.into());

        let mut findings = Vec::new();
        let call_expr = call(
            varref("helper"),
            vec![Rhs::Const(ConstValue::Str("safe".to_string()))],
        );
        eval_rhs(
            &call_expr,
            &empty_state(),
            &specs,
            &mut findings,
            Site::bare(7),
        );

        assert!(
            findings.is_empty(),
            "argument clean -> pas de finding via résumé"
        );
    }

    #[test]
    fn test_eval_call_summary_return_tainted_uncond() {
        let mut specs = specs_with(vec![], vec![]);
        let summary = FunctionSummary {
            name: "get_secret".to_string(),
            return_tainted_uncond: true,
            return_kind: Some("http".to_string()),
            ..Default::default()
        };
        specs
            .summaries
            .insert("get_secret".to_string(), summary.into());

        let mut findings = Vec::new();
        let call_expr = call(varref("get_secret"), vec![]);
        let t = eval_rhs(
            &call_expr,
            &empty_state(),
            &specs,
            &mut findings,
            Site::bare(1),
        );
        assert!(
            t.is_tainted(),
            "source interne inconditionnelle -> retour tainté même sans argument tainté"
        );
    }

    #[test]
    fn test_eval_call_summary_return_taint_params_narrows_positional() {
        let mut specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut summary = FunctionSummary {
            name: "identity_first".to_string(),
            param_names: vec!["a".to_string(), "b".to_string()],
            ..Default::default()
        };
        // Only parameter 0 reaches the return (e.g. `def identity_first(a, b): return a`).
        summary.return_taint_params.insert(0);
        specs
            .summaries
            .insert("identity_first".to_string(), summary.into());

        let mut findings = Vec::new();
        // identity_first(input(), input()) -- only arg 0 should taint the
        // return, but since both are identically a source here, we vary: arg1 clean.
        let call_expr = call(
            varref("identity_first"),
            vec![
                call(varref("input"), vec![]),
                Rhs::Const(ConstValue::Str("safe".to_string())),
            ],
        );
        let t = eval_rhs(
            &call_expr,
            &empty_state(),
            &specs,
            &mut findings,
            Site::bare(1),
        );
        assert!(
            t.is_tainted(),
            "l'arg 0 (tainté) atteint le retour d'après le résumé"
        );
    }

    #[test]
    fn test_eval_call_no_summary_falls_back_to_over_approximation() {
        // With no summary for "unknown_fn", historical UNKNOWN behavior
        // (SCA-9 choice): join of all arguments.
        let specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut findings = Vec::new();
        let call_expr = call(varref("unknown_fn"), vec![call(varref("input"), vec![])]);
        let t = eval_rhs(
            &call_expr,
            &empty_state(),
            &specs,
            &mut findings,
            Site::bare(1),
        );
        assert!(t.is_tainted());
    }

    // ------------------------------------------------------------------
    // Round 5/6 (Java) — resolution via type_map / chained constructor call
    // ------------------------------------------------------------------

    #[test]
    fn test_eval_call_round5_resolves_via_type_map() {
        // `scr.method(input())` where `scr` is a local variable of a
        // known type (`type_map["scr"] = "Helper"`) — the direct lookup
        // by "scr.method" always fails (never indexed by variable
        // name), must fall back to "Helper.method".
        let mut specs = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        specs
            .type_map
            .insert("scr".to_string(), "Helper".to_string());
        let mut summary = FunctionSummary {
            name: "Helper.method".to_string(),
            param_names: vec!["x".to_string()],
            ..Default::default()
        };
        summary.sink_param_findings.insert(
            0,
            Finding {
                rule_id: "test-rule".to_string(),
                severity: "HIGH".to_string(),
                line: 42,
                column: 0,
                sink_text: "sink".to_string().into(),
                source_line: None,
                message: String::new(),
                cwe: None,
                flow: vec![],
                source_kind: "unknown".to_string(),
            },
        );
        specs
            .summaries
            .insert("Helper.method".to_string(), summary.into());

        let mut findings = Vec::new();
        let call_expr = call(
            attr(varref("scr"), "method"),
            vec![call(varref("input"), vec![])],
        );
        eval_rhs(
            &call_expr,
            &empty_state(),
            &specs,
            &mut findings,
            Site::bare(7),
        );
        assert_eq!(
            findings.len(),
            1,
            "scr.method() doit se résoudre via type_map vers Helper.method"
        );
    }

    #[test]
    fn test_eval_call_round6_resolves_chained_constructor_call() {
        // `new Test().method(input())` — java_lowering.rs inlines the
        // constructor's CallRef as the AttrRef's base; eval_call must
        // recognize this form and resolve "Test.method" without needing
        // type_map (no language guard, see the comment in eval_call —
        // this form is never produced on the Python side).
        let specs_base = specs_with(vec![SourceSpec::new("input", "cli")], vec![]);
        let mut specs = specs_base;
        let mut summary = FunctionSummary {
            name: "Test.method".to_string(),
            param_names: vec!["x".to_string()],
            ..Default::default()
        };
        summary.sink_param_findings.insert(
            0,
            Finding {
                rule_id: "test-rule".to_string(),
                severity: "HIGH".to_string(),
                line: 1,
                column: 0,
                sink_text: "sink".to_string().into(),
                source_line: None,
                message: String::new(),
                cwe: None,
                flow: vec![],
                source_kind: "unknown".to_string(),
            },
        );
        specs
            .summaries
            .insert("Test.method".to_string(), summary.into());

        let mut findings = Vec::new();
        let ctor_call = call(varref("Test"), vec![]);
        let call_expr = call(
            attr(ctor_call, "method"),
            vec![call(varref("input"), vec![])],
        );
        eval_rhs(
            &call_expr,
            &empty_state(),
            &specs,
            &mut findings,
            Site::bare(3),
        );
        assert_eq!(
            findings.len(),
            1,
            "new Test().method() doit se résoudre vers Test.method via le chaînage constructeur"
        );
    }
}
