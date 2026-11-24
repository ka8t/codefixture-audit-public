//! Compiles a DSL rule (compiled JSON) into `RuleSpecs` — faithful
//! port of `Audit/sca/executors/dataflow_taint.py::
//! rule_json_to_specs`/`regex_to_dotted_patterns` and satellite
//! functions. Python-only scope (Decision #10).
//!
//! Bridge between the JSON produced by `parser::compile_sca_to_json`
//! (already 100% aligned with Python, field names verified) and
//! `RuleSpecs`: each DSL source/sink/sanitizer/passthrough carries a
//! single **regex** pattern; this module derives from it a **dotted**
//! glob (`compiled`, for fast `eval_call` matching) in addition to
//! keeping the raw regex (`raw_regex`, §10bis) — a single JSON entry
//! can produce 0 to N specs (one per expanded `(a|b|c)` alternative).
#![allow(dead_code)]

use std::sync::LazyLock;

use fancy_regex::Regex;
use serde_json::Value;

use super::transfer::{PassthroughSpec, RuleSpecs, SanitizerSpec, SinkSpec, SourceSpec};

fn safe_compile_regex(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

// ============================================================================
// regex → dotted patterns (heuristic, §7.1)
// ============================================================================

/// Opening markers of a lookaround assertion `(?=`, `(?!`, `(?<=`,
/// `(?<!` — anchored at the current position (mirrors
/// `re.Pattern.match(string, pos)` on the Python side).
static LOOKAROUND_OPEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\(\?<?[=!]").expect("regex statique valide"));

/// Regex noise to strip to obtain a readable "dotted" name. A
/// non-capturing group opener `(?:` is not noise: it is read as a plain
/// group `(` beforehand (see `NON_CAPTURING_GROUP_RE`).
static REGEX_NOISE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\\s\*|\\b|\\s\+|\\\(|\\\)|\\\[|\\\]").expect("regex statique valide")
});

/// The opener of a non-capturing group, `(?:`, not escaped. Read as a
/// plain group so that [`expand_alternations`] expands its alternatives.
/// Deviation from the Audit (ticket #266), whose noise pass dropped the
/// opener and kept the closing `)`: `\b(?:eval|exec)\s*\(` gave
/// `eval|exec)`, a name no call has.
static NON_CAPTURING_GROUP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?<!\\)\(\?:").expect("regex statique valide"));

/// An empty call written in a chain, `\(\)` or `\(\s*\)`:
/// `Runtime\.getRuntime\(\)\.exec\s*\(` names `Runtime.getRuntime.exec`.
/// Read as noise, never as the call where a sink's pattern ends.
static EMPTY_CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\\((?:\\s\*)?\\\)").expect("regex statique valide"));

/// A run of non-blank characters, `\S*` or `\S+`: any text, dots
/// included. Becomes `**` (see `ANY_DEPTH`).
static NON_BLANK_RUN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\S[+*]").expect("regex statique valide"));

static WORD_WILDCARD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\w[+*]?").expect("regex statique valide"));
static DOT_WILDCARD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.[+*]").expect("regex statique valide"));
static MULTI_STAR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\*+").expect("regex statique valide"));

/// Stand-in for a literal dot (`\.`, `->`, `::`) while the regex is
/// rewritten into a dotted pattern, turned back into `.` by
/// [`finalize_dotted`] once the regex wildcards are gone. Deliberate
/// deviation from the Audit (ticket #236): `dataflow_taint.py` turns
/// `\.` into `.` first, so the wildcard pass then reads a literal dot
/// followed by `\w+` (already `*`) as the regex `.*` and merges both:
/// `event\.\w+` gave `event*` (any name starting with `event`) instead
/// of `event.*`. A control character never appears in a rule regex.
const LITERAL_DOT: char = '\u{1}';

/// Stand-in for an escaped backslash (`\\` in the regex) while the other
/// escapes are read, turned into one `\` at the end of
/// [`regex_to_dotted_patterns`]. PHP writes a namespaced class with it
/// (`Twig\Environment`), and the PHP conversion names `new
/// Twig\Environment(...)` with that text. Deviation from the Audit (ticket
/// #258), which kept both characters: `Twig\\Environment` named no call.
const LITERAL_BACKSLASH: char = '\u{2}';

/// The `new` keyword followed by blanks, at the start of an alternative:
/// `new\s+File\s*\(`, `(new\s+A|new\s+B)`, `\bnew URL\s*\(`. Captures what
/// precedes it, so that only the keyword and its blanks are dropped.
/// Stand-in for a wildcard of any depth (`\S*`) until the stars are
/// merged by [`finalize_dotted`], which would read `**` as `*`. The
/// optional qualifier of `new\s+(?:\S*\.)?File\s*\(` gives `**.File`,
/// which `java.io.File` meets, besides `File` (ticket #266).
const ANY_DEPTH: char = '\u{3}';

/// Stand-in for the escaped `(` that opens the arguments of a sink's call
/// (`\(`), kept until [`finalize_dotted`] cuts the pattern there. See
/// [`sink_regex_to_dotted_patterns`].
const CALL_PAREN: char = '\u{4}';

/// Stand-in for an escaped dollar (`\$` in the regex) while the regex is
/// rewritten, turned into one `$` at the end of [`to_dotted_patterns`],
/// and kept apart from the unescaped `$` anchor that pass drops. A PHP
/// variable starts with it, and the PHP conversion names `$_GET['id']`
/// after its base `$_GET` and `$xpath->query(...)` `$xpath.query`; a
/// JavaScript name may hold one (`prisma.$queryRaw`). Deviation from the
/// Audit (ticket #271), which kept both characters: `\$_GET` named no
/// variable, and the PHP sources and sinks written with a `$` were read by
/// the line layer alone.
const LITERAL_DOLLAR: char = '\u{5}';

static CONSTRUCTOR_KEYWORD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(^|[|(:]|\\b)new(?:\\s[+*]| +)").expect("regex statique valide"));

/// Entirely strips lookaround groups `(?=...)`, `(?!...)`,
/// `(?<=...)`, `(?<!...)` (including balanced parentheses), not just
/// the opening marker — a lookaround carries a constraint with no
/// equivalent in the "dotted" model (neither negation nor context),
/// an accepted over-approximation. **Historical bug documented on
/// the Python side** (`taint_xss.sca`) if only the opening marker is
/// stripped: the orphaned closing parenthesis and the content (often
/// an `a|b` alternation) get misinterpreted downstream by
/// `expand_alternations`, producing corrupted patterns (e.g.
/// `(?<!System\.(?:out|err))\.print\s*\(` → `<!System.out).print`,
/// `err).print` — zero XSS sink recognized).
fn strip_lookaround_groups(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::new();
    let mut i = 0usize;
    while i < chars.len() {
        // An escaped character is a literal, never the start of a group:
        // `\(?=` is the text `(?=` (ticket #245).
        if chars[i] == '\\' {
            out.extend(chars.get(i..i + 2).unwrap_or(&chars[i..]));
            i += 2;
            continue;
        }
        let rest: String = chars[i..].iter().collect();
        if let Ok(Some(m)) = LOOKAROUND_OPEN_RE.find(&rest) {
            i = lookaround_end(&chars, i + m.end());
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Index just past the `)` that closes the look-around group whose
/// body starts at `start`: nested groups count, an escaped character
/// (`\(`, `\)`) and the content of a character class (`[)(]`) do not.
/// The former count read `\(` as an opening parenthesis: a look-around
/// holding one (`(?<!normalize\()path\.join`) never closed, the rest of
/// the pattern was dropped with it and the rule's sink matched no call
/// (ticket #245). The end of the pattern when the group is not closed.
fn lookaround_end(chars: &[char], start: usize) -> usize {
    let mut depth = 1i32;
    let mut j = start;
    let mut in_class = false;
    while j < chars.len() && depth > 0 {
        match chars[j] {
            '\\' => j += 1, // the escaped character is skipped below
            ']' if in_class => in_class = false,
            '[' if !in_class => in_class = true,
            '(' if !in_class => depth += 1,
            ')' if !in_class => depth -= 1,
            _ => {}
        }
        j += 1;
    }
    j.min(chars.len())
}

/// The alternatives of `pattern` at its top level: split on the `|`
/// that sit outside any group and any character class. An escaped
/// character is taken as written.
fn split_top_level(pattern: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut depth = 0i32;
    let mut in_class = false;
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        let current = parts.last_mut().expect("never empty");
        match c {
            '\\' => {
                current.push(c);
                if let Some(escaped) = chars.next() {
                    current.push(escaped);
                }
                continue;
            }
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => depth += 1,
            ')' if !in_class => depth -= 1,
            '|' if !in_class && depth == 0 => {
                parts.push(String::new());
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    parts
}

/// The index just past the `)` that closes the group opened at `open`,
/// skipping escaped characters and character classes; `None` when the
/// group is never closed.
fn group_end(chars: &[char], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_class = false;
    let mut i = open;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 1,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => depth += 1,
            ')' if !in_class => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Expands the alternatives of a regex into one pattern each: the
/// top-level `a|b` first, then the first group `(...)` and its own
/// alternatives, recursive on the result. A group followed by `?` or `*`
/// is optional: it also gives the pattern without it (`parseXml(String)?`
/// gives `parseXml` and `parseXmlString`); `+` keeps it once.
///
/// Deviation from the Audit (ticket #266), which read the first group
/// only and split its inside on every `|`: a top-level alternative
/// (`\b(?:child_process|cp)\.exec\s*\(|(?<!\.)\bexec\s*\(`) stayed one
/// pattern holding `|`, and an optional group kept its `?` as text.
fn expand_alternations(pattern: &str) -> Vec<String> {
    let alternatives = split_top_level(pattern);
    if alternatives.len() > 1 {
        return alternatives
            .iter()
            .flat_map(|alternative| expand_alternations(alternative))
            .collect();
    }
    let chars: Vec<char> = pattern.chars().collect();
    // The first group opener, outside a character class and not escaped.
    let mut open = None;
    let mut in_class = false;
    let mut i = 0usize;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 1,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => {
                open = Some(i);
                break;
            }
            _ => {}
        }
        i += 1;
    }
    let Some(open) = open else {
        return vec![pattern.to_string()];
    };
    let Some(close) = group_end(&chars, open) else {
        // Unbalanced parenthesis: leave as-is.
        return vec![pattern.to_string()];
    };
    let inside: String = chars[open + 1..close - 1].iter().collect();
    let before: String = chars[..open].iter().collect();
    let (optional, after_start) = match chars.get(close) {
        Some('?') | Some('*') => (true, close + 1),
        Some('+') => (false, close + 1),
        _ => (false, close),
    };
    let after: String = chars[after_start..].iter().collect();
    let mut choices = split_top_level(&inside);
    if optional {
        choices.push(String::new());
    }
    choices
        .iter()
        .flat_map(|choice| expand_alternations(&format!("{before}{choice}{after}")))
        .collect()
}

/// Final cleanup pass on a "dotted" pattern: the regex wildcards
/// (`\w+`, `.*`, `.+`) become `*`, then the literal dots
/// ([`LITERAL_DOT`]) become `.`.
///
/// A literal dot that ends the pattern means "a member of": the regex
/// `req\.query\.` is found in `req.query.id`, and the pattern becomes
/// `req.query.*`. Deliberate deviation from the Audit (ticket #236),
/// which keeps `req.query.`: a dotted pattern is matched against a whole
/// name, no name ends with a dot, and the dataflow path never matched
/// such a source, sink or sanitizer. One segment suffices: the base of an
/// attribute is evaluated too, so `req.query.id.trim` meets the pattern
/// through `req.query.id`.
///
/// An unescaped dot without a quantifier (the regex "any character")
/// stays a dot, as in the Audit: the catalog writes it where a literal
/// dot is meant (`Builders<.*>.Filter.Eq`), and `*`, which does not cross
/// dots, would no longer match `Builders<T>.Filter.Eq`.
fn finalize_dotted(pattern: &str) -> String {
    // A sink's pattern ends at the `(` of its call (see
    // `sink_regex_to_dotted_patterns`).
    let pattern = pattern.split(CALL_PAREN).next().unwrap_or("");
    let p = NON_BLANK_RUN_RE
        .replace_all(pattern, ANY_DEPTH.to_string().as_str())
        .into_owned();
    let p = WORD_WILDCARD_RE.replace_all(&p, "*").into_owned();
    let p = DOT_WILDCARD_RE.replace_all(&p, "*").into_owned();
    let p = p.replace('?', "");
    let p = MULTI_STAR_RE.replace_all(&p, "*").into_owned();
    let p = p.trim();
    let p = match p.strip_suffix(LITERAL_DOT) {
        Some(member_of) => format!("{member_of}{LITERAL_DOT}*"),
        None => p.to_string(),
    };
    let p = p.replace(LITERAL_DOT, ".").replace(ANY_DEPTH, "**");
    if p.is_empty() || p.chars().all(|c| c == '.' || c == '*') {
        return String::new();
    }
    if p.starts_with('.') {
        format!("**{p}")
    } else {
        p
    }
}

/// "Best-effort" conversion of a DSL regex into a list of "dotted"
/// patterns. Returns an empty list if the regex is too opaque.
pub fn regex_to_dotted_patterns(regex_str: &str) -> Vec<String> {
    to_dotted_patterns(regex_str, ArgumentText::Keep).patterns
}

/// [`regex_to_dotted_patterns`] for a sink: the pattern ends at the `(`
/// of the call, so that a regex that also reads the arguments names the
/// call: `setAttribute\s*\(\s*["'](?:role|admin)` gives `setAttribute`,
/// `XmlSerializer\s*\(\s*Type\.GetType\s*\(` gives `XmlSerializer`. An
/// empty call in a chain does not end it (`Runtime\.getRuntime\(\)\.exec`
/// stays `Runtime.getRuntime.exec`, see `EMPTY_CALL_RE`).
/// `new\s+ModelAndView\s*\(.*redirect` gives `ModelAndView`. The
/// arguments stay checked: a sink the data flow reaches is kept only when
/// its raw regex matches the line (`discard_sinks_failing_raw_regex`).
/// Deviation from the Audit (ticket #266), which kept the argument text
/// (`setAttribute["']role`), a name no call has. Sources, sanitizers and
/// passthroughs keep it: nothing would check their arguments afterwards,
/// and `file_get_contents\s*\(\s*['"]php://input` cut to
/// `file_get_contents` would make every call of it a source.
///
/// A sink's pattern also ends at the `[` of a subscript: a sink written
/// as an index write, `Response\.Headers\[.Set-Cookie.\]` or
/// `response\.headers\[.*[Cc]ookie`, names the object written into
/// (`Response.Headers`), which is the name the data flow gives the target
/// of `Response.Headers["Set-Cookie"] = value` (`lhs_sink_target`). The key
/// stays checked by the raw regex on the line, as the arguments of a call
/// are. Deviation from the Audit (ticket #261), which kept the key text
/// (`Response.Headers.Set-Cookie.`): no assignment target has that name,
/// and the data flow never saw those sinks. Only sinks are cut there: a
/// source such as `\[FromQuery\]` or `\.choices\[0\]\.message` would
/// lose its name or its tail.
pub fn sink_regex_to_dotted_patterns(regex_str: &str) -> Vec<String> {
    to_dotted_patterns(regex_str, ArgumentText::CutAtCallOrSubscript).patterns
}

/// The dotted patterns of a source's or a sanitizer's regex, and whether
/// the data flow must confirm a match on the line (ticket #270).
pub struct ConfirmedPatterns {
    /// The dotted patterns, cut at the `(` of the call as for a sink.
    pub patterns: Vec<String>,
    /// The patterns dropped part of the regex: a look-around
    /// (`\.getProperty\s*\(\s*"(?!os\.name|…)`) or the text of the
    /// arguments (`filter_var\s*\([^)]*FILTER_SANITIZE`). The data flow
    /// then takes a name matching them only when the regex matches the
    /// line ([`SourceSpec::confirm_on_line`]).
    pub confirm_on_line: bool,
}

/// [`regex_to_dotted_patterns`] for a source or a sanitizer: the pattern
/// ends at the call, as a sink's does, and what that cut or a
/// look-around dropped is checked on the line instead of being lost.
/// Before ticket #270 the argument text stayed in the pattern
/// (`filter_var[^)]*FILTER_SANITIZE`, a name no call has), and a
/// look-around was dropped silently: `getProperty("os.name")`, which
/// the rule excludes, was a source for the data flow.
pub fn confirmed_regex_to_dotted_patterns(regex_str: &str) -> ConfirmedPatterns {
    let conversion = to_dotted_patterns(regex_str, ArgumentText::CutAtCall);
    ConfirmedPatterns {
        patterns: conversion.patterns,
        confirm_on_line: conversion.dropped_constraint,
    }
}

/// What [`to_dotted_patterns`] does with the text after the `(` of a call.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ArgumentText {
    /// Kept, then read as the rest of the name.
    Keep,
    /// Dropped: the pattern ends at the call.
    CutAtCall,
    /// Dropped: the pattern ends at the call or at the `[` of a
    /// subscript, whichever comes first (sinks, ticket #261).
    CutAtCallOrSubscript,
}

/// What [`to_dotted_patterns`] gives: the patterns, and whether they
/// dropped part of the regex.
struct Conversion {
    patterns: Vec<String>,
    /// A look-around was removed, or an alternative had text after the
    /// `(` of its call (with [`ArgumentText::CutAtCall`]) or after the `[`
    /// of a subscript (with [`ArgumentText::CutAtCallOrSubscript`]).
    dropped_constraint: bool,
}

fn to_dotted_patterns(regex_str: &str, arguments: ArgumentText) -> Conversion {
    if regex_str.is_empty() {
        return Conversion {
            patterns: Vec::new(),
            dropped_constraint: false,
        };
    }
    let stripped = strip_lookaround_groups(regex_str);
    let mut dropped_constraint = stripped != regex_str;
    // `new X(...)` is named after its class by every conversion: Java and
    // C# `type_to_rhs` (`File`, `java.io.File`), the JavaScript
    // `constructor` field (`URL`, `foo.Bar`), the PHP class name
    // (`Twig\Environment`). The keyword is dropped so that the pattern names
    // that class. Deviation from the Audit (ticket #258): removing only the
    // blanks gave `newFile`, a name no call has, and those sinks, sanitizers
    // and passthroughs were read by the line layer alone.
    let stripped = CONSTRUCTOR_KEYWORD_RE.replace_all(&stripped, "$1");
    // An escaped backslash is a literal one, kept apart from the escapes
    // read below (see `LITERAL_BACKSLASH`).
    let stripped = stripped.replace(r"\\", &LITERAL_BACKSLASH.to_string());
    // An escaped dollar is a literal one, read after the escaped backslash
    // so that `\\$` stays a backslash followed by the end anchor (see
    // `LITERAL_DOLLAR`).
    let stripped = stripped.replace(r"\$", &LITERAL_DOLLAR.to_string());
    let stripped = NON_CAPTURING_GROUP_RE
        .replace_all(&stripped, "(")
        .into_owned();
    let stripped = match arguments {
        ArgumentText::CutAtCall => EMPTY_CALL_RE
            .replace_all(&stripped, "")
            .replace(r"\(", &CALL_PAREN.to_string()),
        // The `[` of a subscript ends the name as the `(` of a call does:
        // both are read as `CALL_PAREN`, where `finalize_dotted` cuts.
        ArgumentText::CutAtCallOrSubscript => EMPTY_CALL_RE
            .replace_all(&stripped, "")
            .replace(r"\(", &CALL_PAREN.to_string())
            .replace(r"\[", &CALL_PAREN.to_string()),
        ArgumentText::Keep => stripped,
    };
    let clean = REGEX_NOISE_RE.replace_all(&stripped, "").into_owned();
    // A literal dot is kept apart from the regex `.` until the wildcards
    // are converted (see `LITERAL_DOT`).
    let clean = clean.replace(r"\.", &LITERAL_DOT.to_string());
    // PHP (`->method`/`\->method`) and the static double-colon
    // (`::method`) are normalized to `.` — same semantic role as dot
    // access in Python/Java/JS (member resolution), but absent from
    // the Python source (the original `regex_to_dotted_patterns` only
    // handles `\.` since Audit has no PHP AST engine). codefixture-audit
    // addition, beyond Python parity — without it, NO PHP rule
    // targeting a method call (`sink \->query\s*\(`, the natural form
    // in real PHP syntax) derives a usable "dotted" pattern, and
    // `resolve_spec`/`eval_call` never matches the sink (only the
    // `raw_regex` confirmation filter, built from the SAME
    // unmodified `regex_str`, still validates against the real
    // `->`/`::` syntax of the source file).
    let dot = LITERAL_DOT.to_string();
    let clean = clean.replace(r"\->", &dot).replace("->", &dot);
    let clean = clean.replace(r"\::", &dot).replace("::", &dot);
    let clean = clean.trim_start_matches('^').trim_end_matches('$');
    let clean = clean.split('=').next().unwrap_or("").trim().to_string();
    let alternatives = expand_alternations(&clean);
    dropped_constraint |= alternatives.iter().any(|alternative| {
        alternative
            .split_once(CALL_PAREN)
            .is_some_and(|(_, after)| !after.trim().is_empty())
    });
    let patterns = alternatives
        .into_iter()
        .filter_map(|p| {
            let f = finalize_dotted(&p)
                .replace(LITERAL_BACKSLASH, "\\")
                .replace(LITERAL_DOLLAR, "$");
            if f.is_empty() { None } else { Some(f) }
        })
        .collect();
    Conversion {
        patterns,
        dropped_constraint,
    }
}

// ============================================================================
// Compiled JSON → RuleSpecs
// ============================================================================

fn json_str<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("")
}

/// `pub(crate)`: reused by the orchestrator (Step 5) to populate the
/// `ReportFinding` of the regex/file_contains executors, which do not
/// themselves carry the rule's i18n message.
///
/// `lang`: target language (`"fr"`/`"es"`/`"de"`/...) — tried first,
/// then falls back to `"en"`, then to the first language available in
/// the block. Deviation fixed (2026-08-26): the previous version
/// completely ignored `lang` and always preferred `"en"` — a
/// `--lang fr` scan still produced an English `message` regardless.
pub(crate) fn extract_message(rule_json: &Value, lang: &str) -> String {
    match rule_json.get("message") {
        Some(Value::Object(map)) => {
            let target = map
                .get(lang)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            let en = || {
                map.get("en")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
            };
            target
                .or_else(en)
                .map(|s| s.to_string())
                .or_else(|| {
                    map.values()
                        .next()
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_default()
        }
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => String::new(),
    }
}

/// `pub(crate)`: reused by the orchestrator (Step 5).
pub(crate) fn extract_cwe(rule_json: &Value) -> Option<String> {
    let metadata = rule_json.get("metadata")?;
    match metadata.get("cwe") {
        Some(Value::Array(arr)) => arr.first().and_then(|v| v.as_str()).map(|s| s.to_string()),
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// Whether [`rule_json_to_specs`] gives specs for this rule: at least
/// one source and one sink convert to a dotted pattern. Answers without
/// compiling the rule's regexes, so that the scan can tell, before
/// reading the files, which languages have a taint rule and keep the
/// parse trees of those only (ticket #241). `rule_json_to_specs` asks
/// it first, so the two always agree.
pub fn has_taint_specs(rule_json: &Value) -> bool {
    let converts = |key: &str| {
        rule_json
            .get(key)
            .and_then(|v| v.as_array())
            .is_some_and(|specs| {
                specs.iter().any(|s| {
                    let pattern = json_str(s, "pattern");
                    let dotted = if key == "sinks" {
                        sink_regex_to_dotted_patterns(pattern)
                    } else {
                        confirmed_regex_to_dotted_patterns(pattern).patterns
                    };
                    !dotted.is_empty()
                })
            })
    };
    converts("sources") && converts("sinks")
}

/// Whether a source's regex ends with the escaped `[` of an index
/// (`Request\[`, `\$_GET\[`), trailing blanks aside: the source is that
/// collection, never the receiver of one of its members
/// (`SourceSpec::subscript_only`, ticket #268). An escaped backslash before it (`\\[`) is a literal backslash
/// followed by a character class, not an index.
fn ends_with_index(regex: &str) -> bool {
    let trimmed = regex.trim_end();
    let Some(before) = trimmed.strip_suffix("\\[") else {
        return false;
    };
    // The `\` of `\[` must not itself be escaped: count the backslashes
    // that precede it.
    let preceding = before.chars().rev().take_while(|c| *c == '\\').count();
    preceding % 2 == 0
}

/// Converts a compiled SCA rule (JSON) into dataflow engine
/// `RuleSpecs`. "Best-effort" conversion: each regex pattern
/// generates 1..N dotted patterns. `None` if the rule doesn't have at
/// least one convertible source AND sink ([`has_taint_specs`]).
pub fn rule_json_to_specs(rule_json: &Value, lang: &str) -> Option<RuleSpecs> {
    if !has_taint_specs(rule_json) {
        return None;
    }
    let empty: Vec<Value> = Vec::new();
    let mut sources = Vec::new();
    for s in rule_json
        .get("sources")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty)
    {
        let regex = json_str(s, "pattern");
        let kind = if json_str(s, "kind").is_empty() {
            "unknown"
        } else {
            json_str(s, "kind")
        };
        let compiled = safe_compile_regex(regex);
        let conversion = confirmed_regex_to_dotted_patterns(regex);
        let subscript_only = ends_with_index(regex);
        // The regex ends with a literal dot: "a member of" (see below).
        let member_of = regex.trim_end().ends_with("\\.") && !regex.trim_end().ends_with("\\\\.");
        for dotted in conversion.patterns {
            // A source written as "a member of" (`req\.(query|body)\.`,
            // dotted `req.query.*`) also names the object read whole, as an
            // indexed source does (`SourceSpec::subscript_only`): `return
            // req.query` hands every parameter to the caller, which reads
            // `.cmd` on the result of the call. Ticket #268, deviation from
            // the Audit, whose pattern met the members only.
            let whole = member_of
                .then(|| dotted.strip_suffix(".*"))
                .flatten()
                .filter(|base| !base.is_empty() && !base.ends_with('*'))
                .map(str::to_string);
            for pattern in std::iter::once(dotted).chain(whole) {
                let mut spec = SourceSpec::new(pattern, kind);
                spec.raw_regex = compiled.clone();
                spec.confirm_on_line = conversion.confirm_on_line;
                spec.subscript_only = subscript_only;
                sources.push(spec);
            }
        }
    }

    let mut sinks = Vec::new();
    for s in rule_json
        .get("sinks")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty)
    {
        let regex = json_str(s, "pattern");
        // The .sca DSL produces `arg_index: 0` (int) by default on
        // each sink. `args: [...]` (list of indices) is also accepted
        // for backward compatibility; takes priority if present.
        let args: Vec<usize> = if let Some(arr) = s.get("args").and_then(|v| v.as_array()) {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as usize))
                .collect()
        } else if let Some(idx) = s.get("arg_index").and_then(|v| v.as_u64()) {
            vec![idx as usize]
        } else {
            Vec::new()
        };
        // `arg_explicit`: the rule wrote `arg_index=<n>` itself, so the
        // line layer reads that argument only (ticket #221).
        let line_args = if s.get("arg_explicit").and_then(|v| v.as_bool()) == Some(true) {
            args.clone()
        } else {
            Vec::new()
        };
        let kinds: Vec<String> = s
            .get("kinds")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        // `arg_name`: the keyword form of the numbered argument (ticket #261).
        let arg_name = s
            .get("arg_name")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let compiled = safe_compile_regex(regex);
        for dotted in sink_regex_to_dotted_patterns(regex) {
            let mut spec = SinkSpec::new(dotted)
                .with_args(args.clone())
                .with_line_args(line_args.clone())
                .with_kinds(kinds.clone());
            spec.arg_name = arg_name.clone();
            spec.raw_regex = compiled.clone();
            sinks.push(spec);
        }
    }

    let mut sanitizers = Vec::new();
    for s in rule_json
        .get("sanitizers")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty)
    {
        let regex = json_str(s, "pattern");
        let compiled = safe_compile_regex(regex);
        let conversion = confirmed_regex_to_dotted_patterns(regex);
        for dotted in conversion.patterns {
            let mut spec = SanitizerSpec::new(dotted);
            spec.raw_regex = compiled.clone();
            spec.confirm_on_line = conversion.confirm_on_line;
            sanitizers.push(spec);
        }
    }

    let mut passthroughs = Vec::new();
    for s in rule_json
        .get("passthroughs")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty)
    {
        let regex = json_str(s, "pattern");
        let compiled = safe_compile_regex(regex);
        for dotted in regex_to_dotted_patterns(regex) {
            let mut spec = PassthroughSpec::new(dotted);
            spec.raw_regex = compiled.clone();
            passthroughs.push(spec);
        }
    }

    debug_assert!(
        !sources.is_empty() && !sinks.is_empty(),
        "has_taint_specs said this rule converts"
    );

    let rule_id = rule_json
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| rule_json.get("rule_id").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();
    let severity = rule_json
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("MEDIUM")
        .to_string();

    Some(RuleSpecs {
        rule_id,
        severity,
        cwe: extract_cwe(rule_json),
        message: extract_message(rule_json, lang),
        sources,
        sinks,
        sanitizers,
        passthroughs,
        summaries: Default::default(),
        type_map: Default::default(),
        summary_fallback: None,
        exprs: None,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_empty_regex_produces_no_patterns() {
        assert_eq!(regex_to_dotted_patterns(""), Vec::<String>::new());
    }

    #[test]
    fn test_simple_escaped_dot_pattern() {
        assert_eq!(
            regex_to_dotted_patterns(r"os\.system"),
            vec!["os.system".to_string()]
        );
    }

    #[test]
    fn test_alternation_expands_into_multiple_patterns() {
        let out = regex_to_dotted_patterns(r"os\.(system|popen)");
        assert_eq!(out, vec!["os.system".to_string(), "os.popen".to_string()]);
    }

    #[test]
    fn test_anchors_stripped() {
        assert_eq!(
            regex_to_dotted_patterns(r"^os\.system$"),
            vec!["os.system".to_string()]
        );
    }

    #[test]
    fn test_equals_sign_truncates_pattern() {
        assert_eq!(regex_to_dotted_patterns("foo=bar"), vec!["foo".to_string()]);
    }

    #[test]
    fn test_php_arrow_normalized_to_dot() {
        // `->` (PHP method access) must derive a "dotted" pattern
        // usable by `eval_call`/`resolve_spec`, exactly like `\.` in
        // Python/Java/JS — without this no PHP rule targeting a
        // method call (`sink ->query\(`) ever matches via the AST
        // path (cf. `php_taint_scan.rs`, 25/08 calibration).
        assert_eq!(
            regex_to_dotted_patterns(r"->query\("),
            vec!["**.query".to_string()]
        );
    }

    #[test]
    fn test_php_escaped_arrow_normalized_to_dot() {
        assert_eq!(
            regex_to_dotted_patterns(r"\->execute\("),
            vec!["**.execute".to_string()]
        );
    }

    #[test]
    fn test_static_double_colon_normalized_to_dot() {
        assert_eq!(
            regex_to_dotted_patterns(r"Foo::bar\("),
            vec!["Foo.bar".to_string()]
        );
    }

    #[test]
    fn test_raw_regex_unaffected_by_arrow_normalization() {
        // The `->`→`.` normalization must affect ONLY the "dotted"
        // derivation — `raw_regex` (hybrid matching §10bis,
        // confirmation against the real source text) must keep
        // matching the real PHP `->` syntax, never `.`.
        let compiled = safe_compile_regex(r"->query\(").expect("regex valide");
        assert!(compiled.is_match("$db->query(").unwrap_or(false));
        assert!(!compiled.is_match("$db.query(").unwrap_or(false));
    }

    #[test]
    fn test_word_wildcard_becomes_star() {
        assert_eq!(
            regex_to_dotted_patterns(r"\w+\.execute"),
            vec!["*.execute".to_string()]
        );
    }

    #[test]
    fn test_dot_only_result_filtered_out() {
        assert_eq!(regex_to_dotted_patterns(r"\."), Vec::<String>::new());
    }

    /// Ticket #245: an escaped parenthesis or a character class inside a
    /// look-around does not open or close a group: the look-around goes,
    /// the rest of the pattern stays.
    #[test]
    fn test_lookaround_with_escaped_parenthesis_or_class_is_stripped_alone() {
        for (regex, dotted) in [
            (r"(?<!normalize\()path\.join\s*\(", "path.join"),
            (r"(?<!GetFullPath\()Path\.Combine\s*\(", "Path.Combine"),
            (r"Paths\.get\s*\((?![^;]*\.normalize\s*\()", "Paths.get"),
            (r"Path\s*\((?![^#\n]*\.resolve\s*\()", "Path"),
            (r"(?<![)(])open\s*\(", "open"),
            (r"(?<!a\\)os\.system", "os.system"),
        ] {
            assert_eq!(
                regex_to_dotted_patterns(regex),
                vec![dotted.to_string()],
                "{regex}"
            );
        }
        // The path sinks of #245: their look-arounds leave the call they
        // guard, as the pattern without them gives it.
        for (regex, without) in [
            (
                r"new\s+(?:\S*\.)?File\s*\((?![^;]*getCanonical(?:Path|File)\s*\()",
                r"new\s+(?:\S*\.)?File\s*\(",
            ),
            (
                r"Paths\.get\s*\((?![^;]*(?:\.normalize|toRealPath)\s*\()",
                r"Paths\.get\s*\(",
            ),
            (
                r"(?<!normalize\()path\.resolve\s*\((?![^;]*normalize\s*\()",
                r"path\.resolve\s*\(",
            ),
        ] {
            assert_eq!(
                regex_to_dotted_patterns(regex),
                regex_to_dotted_patterns(without),
                "{regex}"
            );
            assert!(!regex_to_dotted_patterns(without).is_empty());
        }
    }

    #[test]
    fn test_lookaround_stripped_entirely_regression_taint_xss() {
        // Regression case documented on the Python side
        // (taint_xss.sca): the negative lookbehind must be stripped
        // IN ITS ENTIRETY, not just its opening marker, otherwise the
        // orphaned parenthesis and the inner alternation (out|err)
        // corrupt the result.
        let out = regex_to_dotted_patterns(r"(?<!System\.(?:out|err))\.print\s*\(");
        assert_eq!(
            out,
            vec!["**.print".to_string()],
            "le lookbehind entier doit disparaître, laissant .print -> **.print"
        );
    }

    #[test]
    fn test_non_capturing_group_marker_stripped_but_content_kept() {
        // A non-capturing group keeps its content, unlike a lookaround,
        // which disappears with it. The Audit dropped the `(?:` marker
        // only and gave `foo).bar`; since ticket #266 the group is read as
        // a plain group, closing parenthesis included.
        let out = regex_to_dotted_patterns(r"(?:foo)\.bar");
        assert_eq!(out, vec!["foo.bar".to_string()]);
    }

    #[test]
    fn test_rule_json_to_specs_basic() {
        let rule = json!({
            "id": "sql_injection",
            "severity": "HIGH",
            "message": {"en": "SQL injection risk", "fr": "Risque d'injection SQL"},
            "metadata": {"cwe": ["CWE-89"]},
            "sources": [{"pattern": r"request\.GET", "kind": "http"}],
            "sinks": [{"pattern": r"cursor\.execute", "arg_index": 0}],
        });
        let specs = rule_json_to_specs(&rule, "en").expect("sources et sinks présents -> Some");
        assert_eq!(specs.rule_id, "sql_injection");
        assert_eq!(specs.severity, "HIGH");
        assert_eq!(specs.message, "SQL injection risk");
        assert_eq!(specs.cwe.as_deref(), Some("CWE-89"));
        assert_eq!(specs.sources.len(), 1);
        assert_eq!(specs.sources[0].pattern, "request.GET");
        assert_eq!(specs.sources[0].kind, "http");
        assert!(specs.sources[0].raw_regex.is_some());
        assert_eq!(specs.sinks.len(), 1);
        assert_eq!(specs.sinks[0].args, vec![0]);
    }

    #[test]
    fn test_rule_json_to_specs_message_falls_back_when_en_absent() {
        let rule = json!({
            "id": "r",
            "message": {"fr": "seulement en français"},
            "sources": [{"pattern": "input"}],
            "sinks": [{"pattern": "eval"}],
        });
        let specs = rule_json_to_specs(&rule, "en").unwrap();
        assert_eq!(specs.message, "seulement en français");
    }

    #[test]
    fn test_rule_json_to_specs_none_without_sources() {
        let rule = json!({"id": "r", "sinks": [{"pattern": "eval"}]});
        assert!(rule_json_to_specs(&rule, "en").is_none());
    }

    /// Ticket #241: a rule whose only sink converts to no dotted pattern
    /// has no taint specs, and `has_taint_specs` says so without
    /// compiling anything; one convertible sink is enough.
    #[test]
    fn test_has_taint_specs_agrees_with_the_conversion() {
        for (sinks, converts) in [
            (json!([{"pattern": ""}]), false),
            (json!([{"pattern": r"\."}]), false),
            (json!([{"pattern": ""}, {"pattern": "eval"}]), true),
            (json!([]), false),
            (json!("eval"), false),
        ] {
            let rule = json!({"id": "r", "sources": [{"pattern": "input"}], "sinks": sinks});
            assert_eq!(has_taint_specs(&rule), converts, "{sinks}");
            assert_eq!(
                rule_json_to_specs(&rule, "en").is_some(),
                converts,
                "{sinks}"
            );
        }
    }

    #[test]
    fn test_rule_json_to_specs_none_without_sinks() {
        let rule = json!({"id": "r", "sources": [{"pattern": "input"}]});
        assert!(rule_json_to_specs(&rule, "en").is_none());
    }

    #[test]
    fn test_rule_json_to_specs_sink_args_list_takes_priority_over_arg_index() {
        let rule = json!({
            "id": "r",
            "sources": [{"pattern": "input"}],
            "sinks": [{"pattern": "run", "arg_index": 0, "args": [1, 2]}],
        });
        let specs = rule_json_to_specs(&rule, "en").unwrap();
        assert_eq!(specs.sinks[0].args, vec![1, 2]);
    }

    #[test]
    fn test_rule_json_to_specs_sink_kinds_filter() {
        let rule = json!({
            "id": "r",
            "sources": [{"pattern": "input"}],
            "sinks": [{"pattern": "run", "kinds": ["http", "network"]}],
        });
        let specs = rule_json_to_specs(&rule, "en").unwrap();
        assert_eq!(
            specs.sinks[0].kinds,
            vec!["http".to_string(), "network".to_string()]
        );
    }

    #[test]
    fn test_rule_json_to_specs_expands_alternation_into_multiple_specs() {
        let rule = json!({
            "id": "r",
            "sources": [{"pattern": "input"}],
            "sinks": [{"pattern": r"os\.(system|popen)"}],
        });
        let specs = rule_json_to_specs(&rule, "en").unwrap();
        assert_eq!(
            specs.sinks.len(),
            2,
            "une entrée sink JSON avec alternation -> 2 SinkSpec"
        );
    }

    #[test]
    fn test_rule_json_to_specs_invalid_regex_yields_no_raw_regex_but_no_crash() {
        // "(" is an invalid regex (unclosed parenthesis) -- no panic,
        // raw_regex stays None (mirrors _safe_compile_regex which
        // catches re.error and returns None); the "unbalanced
        // parenthesis, leave as-is" fallback of expand_alternations
        // still produces a literal "(" dotted pattern (same behavior
        // as the Python side).
        let rule = json!({
            "id": "r",
            "sources": [{"pattern": "input"}],
            "sinks": [{"pattern": "("}],
        });
        let specs = rule_json_to_specs(&rule, "en")
            .expect("sources et sinks non vides -> Some malgré le regex invalide");
        assert_eq!(specs.sinks.len(), 1);
        assert!(
            specs.sinks[0].raw_regex.is_none(),
            "regex invalide -> raw_regex None, pas de panique"
        );
    }

    #[test]
    fn test_trailing_escaped_dot_means_a_member_of() {
        // Ticket #236: `x\.` is found in `x.a`; kept as `x.` it matched
        // no name, a dotted pattern being matched against the whole name.
        assert_eq!(
            regex_to_dotted_patterns(r"req\.(params|query|body)\."),
            vec!["req.params.*", "req.query.*", "req.body.*"]
        );
        assert_eq!(
            regex_to_dotted_patterns(r"process\.env\."),
            vec!["process.env.*"]
        );
        let member = compile_glob(&regex_to_dotted_patterns(r"req\.(query)\.")[0]);
        assert!(member.is_match("req.query.id"));
        assert!(!member.is_match("req.query"));
    }

    #[test]
    fn test_escaped_dot_before_a_word_wildcard_stays_a_dot() {
        // Ticket #236: `\.\w+` gave `*` merged with the name before it
        // (`event*`, which matches `event` and `events`).
        assert_eq!(regex_to_dotted_patterns(r"event\.\w+"), vec!["event.*"]);
        assert_eq!(
            regex_to_dotted_patterns(r"httpx\.AsyncClient\(\)\.\w+\s*\("),
            vec!["httpx.AsyncClient.*"]
        );
        let field = compile_glob(&regex_to_dotted_patterns(r"event\.\w+")[0]);
        assert!(field.is_match("event.id"));
        assert!(!field.is_match("event"));
        assert!(!field.is_match("eventType"));
    }

    #[test]
    fn test_unescaped_dot_keeps_its_former_reading() {
        // A regex wildcard `.*` is still `*`, and a bare unescaped dot
        // stays a dot (the catalog writes it for a literal dot).
        assert_eq!(regex_to_dotted_patterns(r"foo.*bar"), vec!["foo*bar"]);
        assert_eq!(
            regex_to_dotted_patterns(r"Builders<.*>.Filter.Eq"),
            vec!["Builders<*>.Filter.Eq"]
        );
        assert_eq!(regex_to_dotted_patterns(r"\->query\("), vec!["**.query"]);
    }

    #[test]
    fn test_constructor_pattern_names_its_class() {
        // `new X(...)` is named `X` by the conversions: the keyword goes,
        // with the blanks after it, whatever their spelling.
        assert_eq!(regex_to_dotted_patterns(r"new\s+File\s*\("), vec!["File"]);
        assert_eq!(regex_to_dotted_patterns(r"new URL\s*\("), vec!["URL"]);
        assert_eq!(
            regex_to_dotted_patterns(r"\bnew\s+Function\s*\("),
            vec!["Function"]
        );
        assert_eq!(
            regex_to_dotted_patterns(r"(new\s+FileStream|new\s+StreamReader)\s*\("),
            vec!["FileStream", "StreamReader"]
        );
        assert_eq!(
            regex_to_dotted_patterns(r"new\s+ModelAndView\s*\(.*redirect"),
            vec!["ModelAndView*redirect"]
        );
    }

    #[test]
    fn test_new_inside_a_name_is_kept() {
        // Only the keyword at the start of an alternative is dropped.
        assert_eq!(
            regex_to_dotted_patterns(r"renew\s+Lease"),
            vec!["renewLease"]
        );
        assert_eq!(
            regex_to_dotted_patterns(r"newInstance\s*\("),
            vec!["newInstance"]
        );
        assert_eq!(regex_to_dotted_patterns(r"\.renew\s*\("), vec!["**.renew"]);
    }

    #[test]
    fn test_escaped_backslash_is_a_php_namespace_separator() {
        // The PHP conversion names `new Twig\Environment(...)`
        // `Twig\Environment`: the pattern carries one backslash.
        let patterns = regex_to_dotted_patterns(r"Twig\\Environment\s*\(");
        assert_eq!(patterns, vec![r"Twig\Environment"]);
        assert!(compile_glob(&patterns[0]).is_match(r"Twig\Environment"));
    }

    #[test]
    fn test_escaped_dollar_is_part_of_the_name() {
        // Ticket #271: the PHP conversion names `$_GET['id']` after its
        // base `$_GET`, and `$xpath->query(...)` `$xpath.query`.
        assert_eq!(regex_to_dotted_patterns(r"\$_GET\["), vec!["$_GET"]);
        assert_eq!(
            sink_regex_to_dotted_patterns(r"\$xpath->query\s*\("),
            vec!["$xpath.query"]
        );
        let prisma = sink_regex_to_dotted_patterns(r"\.\$queryRaw\s*\(");
        assert_eq!(prisma, vec!["**.$queryRaw"]);
        assert!(compile_glob(&prisma[0]).is_match("prisma.$queryRaw"));
        // An unescaped `$` is the end anchor, dropped; after an escaped
        // backslash too.
        assert_eq!(regex_to_dotted_patterns(r"^getenv$"), vec!["getenv"]);
        assert_eq!(regex_to_dotted_patterns(r"App\\$"), vec![r"App\"]);
    }

    #[test]
    fn test_sink_with_every_argument_checks_them_all() {
        // `arg_index=all` compiles to an empty `args` list: the dataflow
        // path and the line layer both read every argument (ticket #258).
        let rule = serde_json::json!({
            "id": "t",
            "sources": [{"pattern": r"req\.query", "kind": "http"}],
            "sinks": [{"pattern": r"new\s+Function\s*\(", "args": [], "arg_explicit": true}],
        });
        let specs = rule_json_to_specs(&rule, "javascript").expect("taint specs");
        assert!(specs.sinks[0].args.is_empty());
        assert!(specs.sinks[0].line_args.is_empty());
        assert_eq!(specs.sinks[0].pattern, "Function");
    }

    #[test]
    fn test_non_capturing_group_is_expanded() {
        assert_eq!(
            regex_to_dotted_patterns(r"\b(?:eval|exec|__import__)\s*\("),
            vec!["eval", "exec", "__import__"]
        );
        assert_eq!(
            regex_to_dotted_patterns(r"MVEL\s*\.\s*(?:eval|evalToString)\s*\("),
            vec!["MVEL.eval", "MVEL.evalToString"]
        );
    }

    #[test]
    fn test_optional_group_gives_both_patterns() {
        assert_eq!(
            regex_to_dotted_patterns(r"\bparseXml(?:String)?\s*\((?=[^;]*\bnoent\s*:\s*true)"),
            vec!["parseXmlString", "parseXml"]
        );
        // The optional qualifier of a class: the class written alone or
        // with its package.
        let patterns = regex_to_dotted_patterns(r"new\s+(?:\S*\.)?File\s*\(");
        assert_eq!(patterns, vec!["**.File", "File"]);
        let qualified = compile_glob(&patterns[0]);
        assert!(qualified.is_match("java.io.File"));
        assert!(!qualified.is_match("File"));
        assert!(!qualified.is_match("java.io.FileReader"));
    }

    #[test]
    fn test_top_level_alternative_is_split() {
        assert_eq!(
            regex_to_dotted_patterns(r"\b(?:child_process|cp)\.exec\s*\(|(?<!\.)\bexec\s*\("),
            vec!["child_process.exec", "cp.exec", "exec"]
        );
        // A `|` inside a group or a character class is not top level.
        assert_eq!(
            regex_to_dotted_patterns(r"(a|(b|c))\.run"),
            vec!["a.run", "b.run", "c.run"]
        );
        assert_eq!(regex_to_dotted_patterns(r"run[|]x"), vec!["run[|]x"]);
    }

    #[test]
    fn test_sink_pattern_ends_at_its_call() {
        // The argument text a sink regex reads is left to its raw regex.
        assert_eq!(
            sink_regex_to_dotted_patterns(r#"setAttribute\s*\(\s*["'](?:role|admin)["']"#),
            vec!["setAttribute", "setAttribute"]
        );
        assert_eq!(
            sink_regex_to_dotted_patterns(r"new\s+ModelAndView\s*\(.*redirect"),
            vec!["ModelAndView"]
        );
        assert_eq!(
            sink_regex_to_dotted_patterns(r"cursor\.execute\s*\("),
            vec!["cursor.execute"]
        );
        // An empty call in a chain is part of the name.
        assert_eq!(
            sink_regex_to_dotted_patterns(r"Runtime\.getRuntime\(\)\.exec\s*\("),
            vec!["Runtime.getRuntime.exec"]
        );
        assert_eq!(
            sink_regex_to_dotted_patterns(r"Anthropic\(\s*\)\.messages\.create\s*\("),
            vec!["Anthropic.messages.create"]
        );
        // A source keeps it: cut, it would name every call.
        assert_eq!(
            regex_to_dotted_patterns(r#"file_get_contents\s*\(\s*['"]php://input"#),
            vec![r#"file_get_contents['"]php://input"#]
        );
    }

    #[test]
    fn test_sink_pattern_ends_at_its_subscript() {
        // An index write names the object written into, the target name of
        // `Response.Headers["Set-Cookie"] = value`; the key is left to the
        // raw regex (ticket #261).
        assert_eq!(
            sink_regex_to_dotted_patterns(r"Response\.Headers\[.Set-Cookie.\]"),
            vec!["Response.Headers"]
        );
        assert_eq!(
            sink_regex_to_dotted_patterns(r"response\.headers\[.*[Cc]ookie"),
            vec!["response.headers"]
        );
        assert_eq!(
            sink_regex_to_dotted_patterns(r"\.session\["),
            vec!["**.session"]
        );
        // A `[` inside the arguments of a call comes after the cut.
        assert_eq!(
            sink_regex_to_dotted_patterns(
                r#"header\s*\(\s*\$(?!_SERVER\s*\[\s*['"]SERVER_PROTOCOL)"#
            ),
            vec!["header"]
        );
        // A source is not cut there: `[FromQuery]` keeps its name.
        assert_eq!(
            confirmed_regex_to_dotted_patterns(r"\[FromQuery\]").patterns,
            vec!["FromQuery"]
        );
    }

    #[test]
    fn test_member_of_source_also_names_the_object() {
        // Ticket #268: `req\.query\.` names `req.query.*` and `req.query`.
        let rule = serde_json::json!({
            "id": "t",
            "sources": [
                {"pattern": r"req\.query\.", "kind": "http"},
                {"pattern": r"event\.\w+", "kind": "http"},
            ],
            "sinks": [{"pattern": r"exec\s*\(", "arg_index": 0}],
        });
        let specs = rule_json_to_specs(&rule, "javascript").expect("taint specs");
        let patterns: Vec<&str> = specs.sources.iter().map(|s| s.pattern.as_str()).collect();
        assert_eq!(patterns, vec!["req.query.*", "req.query", "event.*"]);
    }

    #[test]
    fn test_source_ending_with_an_index_is_subscript_only() {
        // Ticket #268.
        assert!(ends_with_index(r"Request\["));
        assert!(ends_with_index(r"\$_GET\[ "));
        assert!(ends_with_index(r"(?<!resp)\.Headers\["));
        assert!(!ends_with_index(r"Request\.Cookies"));
        assert!(!ends_with_index(r"\[FromQuery\]"));
        assert!(!ends_with_index(r"path\\["));
        let rule = serde_json::json!({
            "id": "t",
            "sources": [
                {"pattern": r"Request\[", "kind": "http"},
                {"pattern": r"Request\.Cookies", "kind": "http"},
            ],
            "sinks": [{"pattern": r"\.Execute\s*\(", "arg_index": 0}],
        });
        let specs = rule_json_to_specs(&rule, "csharp").expect("taint specs");
        assert!(specs.sources[0].subscript_only);
        assert!(!specs.sources[1].subscript_only);
    }

    #[test]
    fn test_optional_constructor_keyword_names_the_class() {
        // `(?:new\s+)?CookieOptions\b` (ticket #268): the class, with or
        // without its keyword, and the raw regex accepts the bare name of a
        // target-typed `new()` whose type is not on the line.
        let patterns = sink_regex_to_dotted_patterns(r"(?:new\s+)?CookieOptions\b");
        assert!(!patterns.is_empty());
        assert!(
            patterns.iter().all(|p| p == "CookieOptions"),
            "{patterns:?}"
        );
        let raw = Regex::new(r"(?:new\s+)?CookieOptions\b").unwrap();
        assert!(raw.is_match("CookieOptions").unwrap());
        assert!(!raw.is_match("CookieOptionsBuilder").unwrap());
    }

    #[test]
    fn test_subscript_sink_key_is_checked_on_the_line() {
        // The key of the index write stays in the raw regex: the data flow
        // names both writes `Response.Headers`, the line keeps only the
        // cookie header.
        let rule = serde_json::json!({
            "id": "t",
            "sources": [{"pattern": r"Request\.Query\[", "kind": "http"}],
            "sinks": [{"pattern": r"Response\.Headers\[.Set-Cookie.\]", "arg_index": 0}],
        });
        let specs = rule_json_to_specs(&rule, "csharp").expect("taint specs");
        assert_eq!(specs.sinks[0].pattern, "Response.Headers");
        let raw = specs.sinks[0].raw_regex.as_ref().expect("raw regex");
        assert!(
            raw.is_match(r#"Response.Headers["Set-Cookie"] = v;"#)
                .unwrap()
        );
        assert!(!raw.is_match(r#"Response.Headers["X-Lang"] = v;"#).unwrap());
    }

    #[test]
    fn test_source_or_sanitizer_that_drops_a_constraint_is_confirmed_on_its_line() {
        // A look-around: the excluded keys are checked on the line.
        let property = confirmed_regex_to_dotted_patterns(r#"\.getProperty\s*\(\s*"(?!os\.name)"#);
        assert_eq!(property.patterns, vec!["**.getProperty"]);
        assert!(property.confirm_on_line);
        // Argument text: cut at the call, checked on the line.
        let filter = confirmed_regex_to_dotted_patterns(r"filter_var\s*\([^)]*FILTER_SANITIZE");
        assert_eq!(filter.patterns, vec!["filter_var"]);
        assert!(filter.confirm_on_line);
        // A plain call name drops nothing.
        let plain = confirmed_regex_to_dotted_patterns(r"request\.getParameter\s*\(");
        assert_eq!(plain.patterns, vec!["request.getParameter"]);
        assert!(!plain.confirm_on_line);
        let attribute = confirmed_regex_to_dotted_patterns(r"req\.query\.");
        assert_eq!(attribute.patterns, vec!["req.query.*"]);
        assert!(!attribute.confirm_on_line);
    }

    #[test]
    fn test_loaded_specs_carry_the_confirmation() {
        let rule = serde_json::json!({
            "id": "t",
            "sources": [
                {"pattern": r#"\.getProperty\s*\(\s*"(?!os\.name)"#, "kind": "env"},
                {"pattern": r"request\.getParameter\s*\(", "kind": "http"},
            ],
            "sinks": [{"pattern": r"new\s+File\s*\(", "arg_index": 0}],
            "sanitizers": [{"pattern": r"filter_var\s*\([^)]*FILTER_SANITIZE"}],
        });
        let specs = rule_json_to_specs(&rule, "java").expect("taint specs");
        assert!(specs.sources[0].confirm_on_line);
        assert!(!specs.sources[1].confirm_on_line);
        assert!(specs.sanitizers[0].confirm_on_line);
    }

    fn compile_glob(pattern: &str) -> super::super::transfer::GlobPattern {
        super::super::transfer::compile_glob_pattern(pattern)
    }
}
