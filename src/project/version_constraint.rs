//! The version constraints of the dependency manifests, read with each
//! ecosystem's own syntax (ticket #209): which version of a dependency the
//! version rules check when the manifest does not pin one.
//!
//! Until 2026-11-18 a range kept, as its version, the first number after
//! an operator (`^1.2.3` gave 1.2.3, but `<2.0` gave 2.0 too), and
//! `advisories::exact_version` then refused it, so a dependency declared
//! with a range was neither checked against the advisories nor reported
//! as unpinned: nothing said it was skipped. The maintainer's decision
//! (2026-11-18): the version installed according to a lockfile when there
//! is one (`dependencies.rs`), else the declared minimum, said in the
//! finding. A constraint with no inclusive lower bound (`<2.0`, `>1.0`,
//! `*`, a git address) has no minimum to check: the dependency is then
//! reported as unpinned, as one without any version.
//!
//! The three grammars read here are those of npm (node-semver), Composer
//! and PyPI (PEP 440). Each splits into alternatives (`||`), each a set of
//! comparators that all apply. An alternative's minimum is the highest of
//! its lower bounds; the constraint's minimum is the lowest of its
//! alternatives', and none when one alternative has none. A wildcard
//! version (`1.2.x`, `1.2.*`) has its lowest version as lower bound
//! (`1.2.0`).

use std::cmp::Ordering;

use regex::Regex;

use crate::project::advisories::compare_versions;

/// What a constraint says of the version to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    /// One version exactly.
    Exact(String),
    /// A range whose lowest allowed version is this one.
    Minimum(String),
    /// No inclusive lower bound: any version, a version below a bound, or
    /// something that is not a version (a git address, a dist-tag).
    NoMinimum,
}

/// One comparator of an alternative, as the alternative's reader found it.
struct Comparator<'a> {
    op: &'a str,
    version: &'a str,
}

/// The constraint of an npm `package.json` entry (node-semver).
pub fn npm(spec: &str) -> Constraint {
    // Comparators, optionally separated from their version by spaces:
    // `>= 1.2.3`. Versions may start with `v` and hold `x`, `X` or `*`.
    let comparator =
        Regex::new(r"(<=|>=|<|>|=|\^|~>|~)?\s*v?([0-9xX*][0-9A-Za-z.\-+*]*)").expect("valid");
    alternatives(spec, &["||"], |alternative| {
        if let Some((low, _)) = alternative.split_once(" - ") {
            // Hyphen range `1.2.3 - 2.3.4`: inclusive both sides.
            return lower_of(&[Comparator {
                op: ">=",
                version: low.trim().trim_start_matches('v'),
            }]);
        }
        read_comparators(alternative, &comparator)
    })
}

/// The constraint of a Composer `composer.json` entry.
pub fn composer(spec: &str) -> Constraint {
    let comparator =
        Regex::new(r"(<=|>=|<|>|!=|==|=|\^|~)?\s*v?([0-9*][0-9A-Za-z.\-+*]*)").expect("valid");
    // `|` alone is an older spelling of `||`.
    alternatives(spec, &["||", "|"], |alternative| {
        // A stability flag (`1.0@dev`, `@stable`) does not move the bound.
        let flags = Regex::new(r"@[A-Za-z]+").expect("valid");
        let alternative = flags.replace_all(alternative, "");
        let alternative = alternative.trim();
        if let Some((low, _)) = alternative.split_once(" - ") {
            return lower_of(&[Comparator {
                op: ">=",
                version: low.trim().trim_start_matches('v'),
            }]);
        }
        read_comparators(&alternative.replace(',', " "), &comparator)
    })
}

/// The constraint of a PyPI requirement (PEP 440), without its name,
/// extras and environment marker: `>=1.0,<2.0`.
pub fn pep440(spec: &str) -> Constraint {
    let comparator =
        Regex::new(r"(===|==|~=|!=|<=|>=|<|>)\s*([0-9][0-9A-Za-z.\-+!*]*)").expect("valid");
    let spec = spec.trim();
    if spec.is_empty() {
        return Constraint::NoMinimum;
    }
    read_comparators(spec, &comparator)
}

/// Splits `spec` into alternatives on the first separator of
/// `separators` found, reads each with `read`, and combines them: the
/// lowest minimum, none when one alternative has none, exact only for one
/// alternative that is exact.
fn alternatives(spec: &str, separators: &[&str], read: impl Fn(&str) -> Constraint) -> Constraint {
    let spec = spec.trim();
    let separator = separators.iter().find(|s| spec.contains(**s));
    let parts: Vec<&str> = match separator {
        Some(separator) => spec.split(separator).map(str::trim).collect(),
        None => vec![spec],
    };
    if parts.len() == 1 {
        return read(parts[0]);
    }
    let mut lowest: Option<String> = None;
    for part in parts {
        let version = match read(part) {
            Constraint::Exact(v) | Constraint::Minimum(v) => v,
            Constraint::NoMinimum => return Constraint::NoMinimum,
        };
        if lowest
            .as_deref()
            .is_none_or(|l| compare_versions(&version, l) == Ordering::Less)
        {
            lowest = Some(version);
        }
    }
    lowest.map_or(Constraint::NoMinimum, Constraint::Minimum)
}

/// Reads the comparators of one alternative. Anything else in it (a git
/// address, a dist-tag such as `latest`, `dev-main`) means no version to
/// check.
fn read_comparators(alternative: &str, comparator: &Regex) -> Constraint {
    let alternative = alternative.trim();
    if alternative.is_empty() {
        return Constraint::NoMinimum;
    }
    let mut comparators = Vec::new();
    let mut rest = alternative.to_string();
    for caps in comparator.captures_iter(alternative) {
        let whole = caps.get(0).expect("group 0");
        rest = rest.replacen(whole.as_str(), "", 1);
        comparators.push(Comparator {
            op: caps.get(1).map_or("", |m| m.as_str()),
            version: caps.get(2).expect("version group").as_str(),
        });
    }
    // Between comparators: spaces, and PEP 440's commas.
    if comparators.is_empty() || !rest.chars().all(|c| c.is_whitespace() || c == ',') {
        return Constraint::NoMinimum;
    }
    lower_of(&comparators)
}

/// The constraint of one alternative's comparators.
fn lower_of(comparators: &[Comparator<'_>]) -> Constraint {
    let mut lower: Option<String> = None;
    let mut exact = None;
    for c in comparators {
        let wildcard = c
            .version
            .split(['.', '-'])
            .any(|p| matches!(p, "x" | "X" | "*"));
        let floor = floor(c.version);
        let bound = match c.op {
            // A version alone, or after `=`/`==`/`===`: exact when it has
            // no wildcard (Composer's `1.1` is 1.1.0 exactly), else the
            // lowest version it covers.
            "" | "=" | "==" | "===" if !wildcard => {
                exact = Some(c.version.to_string());
                Some(c.version.to_string())
            }
            "" | "=" | "==" | ">=" | "^" | "~" | "~>" | "~=" => floor,
            // `>X` excludes X and names no version above it; `<`, `<=`
            // and `!=` bound nothing from below.
            _ => None,
        };
        if let Some(bound) = bound
            && lower
                .as_deref()
                .is_none_or(|l| compare_versions(&bound, l) == Ordering::Greater)
        {
            lower = Some(bound);
        }
    }
    match (exact, lower) {
        (Some(version), _) if comparators.len() == 1 => Constraint::Exact(version),
        (_, Some(lower)) => Constraint::Minimum(lower),
        (_, None) => Constraint::NoMinimum,
    }
}

/// The lowest version `version` covers: its wildcard parts become 0 and
/// what follows them is dropped (`1.2.x` → `1.2.0`, `1.*` → `1.0`).
/// `None` for a version that is only a wildcard (`*`, `x`).
fn floor(version: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in version.split('.') {
        if matches!(part, "x" | "X" | "*") {
            if parts.is_empty() {
                return None;
            }
            parts.push("0");
            break;
        }
        parts.push(part);
    }
    Some(parts.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(v: &str) -> Constraint {
        Constraint::Exact(v.to_string())
    }

    fn minimum(v: &str) -> Constraint {
        Constraint::Minimum(v.to_string())
    }

    /// node-semver: exact versions, the usual ranges, wildcards, hyphen
    /// ranges, alternatives, and what has no minimum.
    #[test]
    fn test_npm_constraints() {
        let cases = [
            ("1.2.3", exact("1.2.3")),
            ("=1.2.3", exact("1.2.3")),
            ("v1.2.3", exact("1.2.3")),
            ("^1.2.3", minimum("1.2.3")),
            ("~1.2.3", minimum("1.2.3")),
            (">=1.2.3 <2.0.0", minimum("1.2.3")),
            (">= 1.2.3", minimum("1.2.3")),
            ("1.2.x", minimum("1.2.0")),
            ("1.x", minimum("1.0")),
            ("^1.x", minimum("1.0")),
            ("1.2.3 - 2.0.0", minimum("1.2.3")),
            ("^1.2.3 || ^2.0.0", minimum("1.2.3")),
            ("^2.0.0 || ^1.4.0", minimum("1.4.0")),
            ("<2.0.0", Constraint::NoMinimum),
            (">1.2.3", Constraint::NoMinimum),
            ("*", Constraint::NoMinimum),
            ("", Constraint::NoMinimum),
            ("latest", Constraint::NoMinimum),
            ("^1.0.0 || latest", Constraint::NoMinimum),
            ("git+https://github.com/a/b.git", Constraint::NoMinimum),
            ("file:../local", Constraint::NoMinimum),
            ("npm:other@^1.0.0", Constraint::NoMinimum),
            ("workspace:*", Constraint::NoMinimum),
        ];
        for (spec, expected) in cases {
            assert_eq!(npm(spec), expected, "{spec:?}");
        }
    }

    /// Composer: exact versions of one to four numbers, `v`, ranges with
    /// commas or spaces, `|` and `||`, stability flags and wildcards.
    #[test]
    fn test_composer_constraints() {
        let cases = [
            ("1.1", exact("1.1")),
            ("1.1.0.2", exact("1.1.0.2")),
            ("v2.3.4", exact("2.3.4")),
            ("=2.0", exact("2.0")),
            ("==2.0", exact("2.0")),
            ("3.0.0-beta1", exact("3.0.0-beta1")),
            ("^8.5", minimum("8.5")),
            ("~1.2", minimum("1.2")),
            (">=1.0,<2.0", minimum("1.0")),
            (">=1.0 <2.0", minimum("1.0")),
            ("1.1.*", minimum("1.1.0")),
            ("^1.0 | ^2.0", minimum("1.0")),
            ("^2.0 || ^1.5", minimum("1.5")),
            ("1.0.0@dev", exact("1.0.0")),
            ("1.0 - 2.0", minimum("1.0")),
            (">=1.0 !=1.5", minimum("1.0")),
            ("<2.0", Constraint::NoMinimum),
            ("*", Constraint::NoMinimum),
            ("dev-main", Constraint::NoMinimum),
            ("@stable", Constraint::NoMinimum),
        ];
        for (spec, expected) in cases {
            assert_eq!(composer(spec), expected, "{spec:?}");
        }
    }

    /// PEP 440: `==` and `===` exact, `==X.*`, `>=` and `~=` minimums,
    /// several specifiers, and what bounds nothing from below.
    #[test]
    fn test_pep440_constraints() {
        let cases = [
            ("==4.2.1", exact("4.2.1")),
            ("===4.2.1", exact("4.2.1")),
            ("== 4.2.1", exact("4.2.1")),
            ("==4.*", minimum("4.0")),
            (">=2.0", minimum("2.0")),
            ("~=1.4.2", minimum("1.4.2")),
            (">=1.0,<2.0", minimum("1.0")),
            (">=1.0, !=1.5, <2.0", minimum("1.0")),
            ("<2.0", Constraint::NoMinimum),
            ("<=2.0", Constraint::NoMinimum),
            (">1.0", Constraint::NoMinimum),
            ("!=1.5", Constraint::NoMinimum),
            ("", Constraint::NoMinimum),
            ("@ https://example.com/p.whl", Constraint::NoMinimum),
        ];
        for (spec, expected) in cases {
            assert_eq!(pep440(spec), expected, "{spec:?}");
        }
    }
}
