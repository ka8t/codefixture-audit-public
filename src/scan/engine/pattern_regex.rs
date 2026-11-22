//! The regex of a pattern rule, with a linear-time prefilter when the
//! pattern needs the backtracking VM (ticket #251).
//!
//! A pattern with a look-around (`(?<!System\.)out\.print`, `eval\s*\(
//! (?!\s*['"])`) or an atomic group cannot run on the automaton of the
//! `regex` crate: `fancy_regex` runs it on its backtracking VM, on every
//! line of every file of the rule's language. On the 46,793 Java files of
//! the Juliet suite that VM was about 55 % of the pattern pass, and nearly
//! every line it read could not match: most lines do not even hold the
//! call the rule is about.
//!
//! The prefilter is the same pattern with its look-arounds replaced by
//! an empty group and its atomic groups made plain groups, compiled on
//! the `regex` crate. Dropping a zero-width condition only lets more
//! texts match, so a text the prefilter rejects cannot match the full
//! pattern: [`PatternRegex`] answers "no match" for it without running
//! the VM, and runs the VM on the other texts, whose answer it returns
//! as is. The findings are therefore the same by construction;
//! `test_prefilter_accepts_every_match` checks the superset on the rule
//! cases, `test_prefilter_accepts_every_match_on_the_corpus` on the
//! reference corpus.
//!
//! A back-reference (`\1`) becomes any text in the relaxed pattern, and a
//! `\K` is dropped: both changes also only let more texts match. A
//! pattern whose relaxed form still needs the VM (a conditional) has no
//! prefilter and runs as before.

use fancy_regex::{Match, Regex};

/// A compiled pattern of a pattern rule: the `fancy_regex` regex that
/// gives the answers, and the prefilter that rejects beforehand the
/// texts it cannot match, when it has one.
pub struct PatternRegex {
    /// The pattern as written in the rule: the answers.
    full: Regex,
    /// The relaxed pattern on the `regex` crate, `None` when the pattern
    /// needs no VM (`fancy_regex` then hands it whole to the `regex`
    /// crate already) or when its relaxed form still needs one.
    prefilter: Option<regex::Regex>,
}

impl PatternRegex {
    /// Compiles `pattern`; the error of `fancy_regex` when the pattern is
    /// invalid.
    pub fn new(pattern: &str) -> Result<Self, fancy_regex::Error> {
        let full = Regex::new(pattern)?;
        // A pattern the `regex` crate accepts as is needs no VM.
        let prefilter = if regex::Regex::new(pattern).is_ok() {
            None
        } else {
            relax(pattern).and_then(|relaxed| regex::Regex::new(&relaxed).ok())
        };
        Ok(Self { full, prefilter })
    }

    /// True when the pattern matches `text`, as [`Regex::is_match`]
    /// answers, a run-time error of the VM included.
    pub fn is_match(&self, text: &str) -> Result<bool, fancy_regex::Error> {
        if self.rejects(text) {
            return Ok(false);
        }
        self.full.is_match(text)
    }

    /// The first match of the pattern in `text`, as [`Regex::find`]
    /// answers.
    pub fn find<'t>(&self, text: &'t str) -> Result<Option<Match<'t>>, fancy_regex::Error> {
        if self.rejects(text) {
            return Ok(None);
        }
        self.full.find(text)
    }

    /// True when the prefilter tells `text` cannot match.
    fn rejects(&self, text: &str) -> bool {
        self.prefilter
            .as_ref()
            .is_some_and(|prefilter| !prefilter.is_match(text))
    }

    /// Whether the pattern has a prefilter (for the tests and the
    /// measures).
    pub fn has_prefilter(&self) -> bool {
        self.prefilter.is_some()
    }

    /// The pattern as written.
    pub fn as_str(&self) -> &str {
        self.full.as_str()
    }
}

/// What a back-reference becomes in the relaxed pattern: any text, line
/// breaks included.
const ANY_TEXT: &str = "(?s:.*?)";

/// `pattern` with every look-around (`(?=…)`, `(?!…)`, `(?<=…)`,
/// `(?<!…)`) replaced by the empty group `(?:)`, every atomic group
/// `(?>…)` opened as a plain group `(?:…)`, every back-reference (`\1`,
/// `\k<name>`) replaced by any text and every `\K` dropped; `None` when
/// the pattern ends inside a group or a class (not a pattern
/// `fancy_regex` accepted). Each change lets more texts match, never
/// fewer.
///
/// The empty group, not nothing, takes the place of a look-around, so
/// that a quantifier written after it (`x(?=a){2}`) still applies to an
/// empty text and not to the atom before it. An escaped character
/// (`\(?=`) and the content of a character class (`[(?=]`) are text, not
/// a group: the scan reads them as such.
fn relax(pattern: &str) -> Option<String> {
    let bytes = pattern.as_bytes();
    let mut out = String::with_capacity(pattern.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                let digits = bytes[i + 1..]
                    .iter()
                    .take_while(|b| b.is_ascii_digit())
                    .count();
                if digits > 0 && bytes[i + 1] != b'0' {
                    // A back-reference `\1` matches the text of its
                    // group, which may be any text.
                    out.push_str(ANY_TEXT);
                    i += 1 + digits;
                } else if pattern[i..].starts_with("\\k<") {
                    // A named back-reference `\k<name>`.
                    let close = pattern[i..].find('>')?;
                    out.push_str(ANY_TEXT);
                    i += close + 1;
                } else if pattern[i..].starts_with("\\K") {
                    // `\K` only moves the start of the match: a text
                    // matches with or without it.
                    i += 2;
                } else {
                    let end = escape_end(pattern, i);
                    out.push_str(&pattern[i..end]);
                    i = end;
                }
            }
            b'[' => {
                let end = class_end(pattern, i)?;
                out.push_str(&pattern[i..end]);
                i = end;
            }
            b'(' => {
                let rest = &pattern[i..];
                if let Some(marker) = ["(?=", "(?!", "(?<=", "(?<!"]
                    .iter()
                    .find(|marker| rest.starts_with(*marker))
                {
                    i = group_end(pattern, i + marker.len())?;
                    out.push_str("(?:)");
                } else if rest.starts_with("(?>") {
                    out.push_str("(?:");
                    i += 3;
                } else {
                    out.push('(');
                    i += 1;
                }
            }
            _ => {
                // Copy the whole character (the pattern is UTF-8).
                let len = pattern[i..].chars().next().map_or(1, char::len_utf8);
                out.push_str(&pattern[i..i + len]);
                i += len;
            }
        }
    }
    Some(out)
}

/// Index just past the escape that starts at `start` (a `\`): the
/// backslash and the character after it.
fn escape_end(pattern: &str, start: usize) -> usize {
    pattern[start + 1..]
        .chars()
        .next()
        .map_or(pattern.len(), |c| start + 1 + c.len_utf8())
}

/// Index just past the `]` that closes the character class opened at
/// `start`; `None` when it is not closed. A `]` right after the `[` or
/// `[^` is a member of the class, escapes are skipped, and a nested
/// class (`[a-z&&[^x]]`, `[[:alpha:]]`) is closed by its own `]`.
fn class_end(pattern: &str, start: usize) -> Option<usize> {
    let bytes = pattern.as_bytes();
    let mut i = start + 1;
    if bytes.get(i) == Some(&b'^') {
        i += 1;
    }
    if bytes.get(i) == Some(&b']') {
        i += 1;
    }
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i = escape_end(pattern, i),
            b'[' => i = class_end(pattern, i)?,
            b']' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// Index just past the `)` that closes the group whose body starts at
/// `start`; `None` when it is not closed. Nested groups count; an escape
/// and the content of a class do not.
fn group_end(pattern: &str, start: usize) -> Option<usize> {
    let bytes = pattern.as_bytes();
    let mut depth = 1usize;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i = escape_end(pattern, i),
            b'[' => i = class_end(pattern, i)?,
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relax_replaces_lookarounds_and_atomic_groups() {
        assert_eq!(
            relax(r"(?<!System\.(?:out|err))\.print\s*\(").as_deref(),
            Some(r"(?:)\.print\s*\(")
        );
        assert_eq!(
            relax(r#"eval\s*\((?!\s*['"])"#).as_deref(),
            Some(r"eval\s*\((?:)")
        );
        assert_eq!(relax(r"x(?=a){2}").as_deref(), Some(r"x(?:){2}"));
        assert_eq!(relax(r"(?>ab|a)c").as_deref(), Some(r"(?:ab|a)c"));
        // Escaped and in a class: text, not a group.
        assert_eq!(relax(r"\(?=x").as_deref(), Some(r"\(?=x"));
        assert_eq!(relax(r"[(?=]x").as_deref(), Some(r"[(?=]x"));
        assert_eq!(relax(r"(?!a[)])b").as_deref(), Some(r"(?:)b"));
        assert_eq!(relax(r"(?![]a])b").as_deref(), Some(r"(?:)b"));
        assert_eq!(relax(r"(?=\))b").as_deref(), Some(r"(?:)b"));
        // Named groups are kept.
        assert_eq!(
            relax(r"(?<n>a)(?P<m>b)").as_deref(),
            Some(r"(?<n>a)(?P<m>b)")
        );
        assert_eq!(relax(r"é(?=ü)").as_deref(), Some(r"é(?:)"));
        assert_eq!(
            relax(r"^([ \t]*)for\n\1x\12").as_deref(),
            Some(r"^([ \t]*)for\n(?s:.*?)x(?s:.*?)")
        );
        assert_eq!(relax(r"(?<n>a)\k<n>").as_deref(), Some(r"(?<n>a)(?s:.*?)"));
        assert_eq!(relax(r"a\Kb").as_deref(), Some(r"ab"));
        // `\0` is not a back-reference, and a class keeps its escapes.
        assert_eq!(relax(r"\0[\1]").as_deref(), Some(r"\0[\1]"));
        // Unclosed: not a pattern.
        assert_eq!(relax(r"(?=a"), None);
        assert_eq!(relax(r"[a"), None);
    }

    #[test]
    fn test_prefilter_only_for_patterns_on_the_vm() {
        assert!(!PatternRegex::new(r"eval\s*\(").unwrap().has_prefilter());
        assert!(
            PatternRegex::new(r"eval\s*\((?!\s*')")
                .unwrap()
                .has_prefilter()
        );
        // A back-reference and `\K` are relaxed too.
        assert!(PatternRegex::new(r"(\w)\1(?=x)").unwrap().has_prefilter());
        assert!(PatternRegex::new(r"a\Kb").unwrap().has_prefilter());
    }

    #[test]
    fn test_pattern_regex_answers_as_the_full_pattern() {
        let rx = PatternRegex::new(r"(?<!System\.)out\.print\s*\(").unwrap();
        assert!(rx.is_match("  out.print(x);").unwrap());
        assert!(!rx.is_match("  System.out.print(x);").unwrap());
        assert!(!rx.is_match("int a = 1;").unwrap());
        assert_eq!(
            rx.find("a; out.print(1)").unwrap().map(|m| m.start()),
            Some(3)
        );
        assert!(rx.find("nothing").unwrap().is_none());
    }
}
