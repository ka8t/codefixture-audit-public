//! The raw regexes of every taint rule of a language pass, evaluated once
//! per line for all the rules (ticket #240).
//!
//! The hybrid layer (`line_facts.rs`) tests each line a rule reaches
//! against the raw regexes of the rule's sanitizers, sources and sinks.
//! The rules of a pass share most of them: the Java taint rules hold 825
//! raw regexes, 219 of them distinct; C# 468 and 148. Every rule tested
//! them again on the same lines.
//!
//! An [`ExprTable`] numbers the distinct patterns of the rules of one
//! pass, and [`RuleExprs`] tells, for one rule, the number of each of its
//! specs. The first rule that reaches a line computes the answer of every
//! pattern of the table on it ([`ExprTable::matches`]): the patterns the
//! `regex` crate accepts run together in one `RegexSet` (one scan of the
//! line), the others (look-around, back-references) one by one on their
//! own `fancy_regex`. The line keeps the answers as one bit per pattern
//! (`line_facts::SourceLines`), and every rule reads them.
//!
//! Same answers as the per-rule test: a pattern is the same text compiled
//! by the same rule loader, and `fancy_regex` hands a pattern without
//! fancy features to the `regex` crate. A `fancy_regex` that fails at run
//! time (backtracking limit) counts as no match, as before.
//! `test_set_agrees_with_each_rule_regex` keeps the per-rule test as the
//! oracle.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use fancy_regex::Regex;

use super::transfer::RuleSpecs;

#[cfg(test)]
thread_local! {
    /// Number of `ExprTable::matches` calls on this thread: lets the
    /// tests check that the rules of a pass share a line's answers.
    pub(crate) static MATCH_COMPUTATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Identifies one table, so that the answers stored with a line are only
/// read back with the table that computed them.
static NEXT_TABLE_ID: AtomicUsize = AtomicUsize::new(1);

/// The distinct raw regexes of the rules of one language pass.
#[derive(Debug)]
pub struct ExprTable {
    id: usize,
    len: usize,
    /// The patterns the `regex` crate accepts, all in one set; `None`
    /// when there is none, or when the set cannot be built (its size
    /// limit): those patterns then join `single`.
    set: Option<regex::RegexSet>,
    /// Pattern number of each member of `set`, in set order.
    set_ids: Vec<usize>,
    /// The other patterns, with their pattern number.
    single: Vec<(usize, Regex)>,
}

/// The answers of every pattern of one table on one text: bit `n` is set
/// when pattern `n` matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExprBits(Box<[u64]>);

impl ExprBits {
    /// Whether pattern `id` matched.
    pub fn contains(&self, id: usize) -> bool {
        self.0
            .get(id / 64)
            .is_some_and(|word| word & (1 << (id % 64)) != 0)
    }

    fn set(&mut self, id: usize) {
        self.0[id / 64] |= 1 << (id % 64);
    }
}

/// The pattern numbers of one rule's specs in its pass's [`ExprTable`]:
/// entry `i` of `sanitizers` is the number of `specs.sanitizers[i]`'s raw
/// regex, `None` for a spec without one. Built by [`ExprTable::attach`].
#[derive(Debug)]
pub struct RuleExprs {
    pub table: std::sync::Arc<ExprTable>,
    pub sanitizers: Vec<Option<usize>>,
    pub sources: Vec<Option<usize>>,
    pub sinks: Vec<Option<usize>>,
}

impl ExprTable {
    /// Numbers the distinct raw regexes of `rules` and records, in each
    /// rule (`RuleSpecs::exprs`), the number of each of its specs. A rule
    /// keeps its own regexes too: the table only saves repeating them.
    pub fn attach<'r>(rules: impl IntoIterator<Item = &'r mut RuleSpecs>) {
        let mut rules: Vec<&mut RuleSpecs> = rules.into_iter().collect();
        let mut numbers: HashMap<String, usize> = HashMap::new();
        // A `fancy_regex` clone shares the compiled program.
        let mut patterns: Vec<Regex> = Vec::new();
        let mut ids: Vec<[Vec<Option<usize>>; 3]> = Vec::with_capacity(rules.len());
        for rule in &rules {
            let mut number = |regex: Option<&Regex>| -> Option<usize> {
                let regex = regex?;
                Some(
                    *numbers
                        .entry(regex.as_str().to_string())
                        .or_insert_with(|| {
                            patterns.push(regex.clone());
                            patterns.len() - 1
                        }),
                )
            };
            let sanitizers = rule
                .sanitizers
                .iter()
                .map(|s| number(s.raw_regex.as_ref()))
                .collect();
            let sources = rule
                .sources
                .iter()
                .map(|s| number(s.raw_regex.as_ref()))
                .collect();
            let sinks = rule
                .sinks
                .iter()
                .map(|s| number(s.raw_regex.as_ref()))
                .collect();
            ids.push([sanitizers, sources, sinks]);
        }
        let table = std::sync::Arc::new(Self::build(&patterns));
        for (rule, [sanitizers, sources, sinks]) in rules.iter_mut().zip(ids) {
            rule.exprs = Some(std::sync::Arc::new(RuleExprs {
                table: table.clone(),
                sanitizers,
                sources,
                sinks,
            }));
        }
    }

    /// The table of `patterns`, pattern `n` being `patterns[n]`.
    fn build(patterns: &[Regex]) -> Self {
        let (mut set_ids, mut single) = (Vec::new(), Vec::new());
        for (id, regex) in patterns.iter().enumerate() {
            if regex::Regex::new(regex.as_str()).is_ok() {
                set_ids.push(id);
            } else {
                single.push((id, regex.clone()));
            }
        }
        let set = if set_ids.is_empty() {
            None
        } else {
            regex::RegexSetBuilder::new(set_ids.iter().map(|&id| patterns[id].as_str()))
                .size_limit(256 << 20)
                .dfa_size_limit(64 << 20)
                .build()
                .ok()
        };
        if set.is_none() {
            // No set: every pattern runs on its own regex.
            single.extend(set_ids.drain(..).map(|id| (id, patterns[id].clone())));
            single.sort_by_key(|(id, _)| *id);
        }
        Self {
            id: NEXT_TABLE_ID.fetch_add(1, Ordering::Relaxed),
            len: patterns.len(),
            set,
            set_ids,
            single,
        }
    }

    /// The number of this table, distinct from any other table's.
    pub fn id(&self) -> usize {
        self.id
    }

    /// The answer of every pattern of the table on `text`.
    pub fn matches(&self, text: &str) -> ExprBits {
        #[cfg(test)]
        MATCH_COMPUTATIONS.with(|count| count.set(count.get() + 1));
        let mut bits = ExprBits(vec![0; self.len.div_ceil(64)].into_boxed_slice());
        if let Some(set) = &self.set {
            for index in set.matches(text).iter() {
                bits.set(self.set_ids[index]);
            }
        }
        for (id, regex) in &self.single {
            if regex.is_match(text).unwrap_or(false) {
                bits.set(*id);
            }
        }
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::transfer::{SanitizerSpec, SinkSpec, SourceSpec};

    fn rx(pattern: &str) -> Regex {
        Regex::new(pattern).unwrap()
    }

    fn rule(id: &str, sources: &[&str], sinks: &[&str], sanitizers: &[&str]) -> RuleSpecs {
        RuleSpecs {
            rule_id: id.to_string(),
            sources: sources
                .iter()
                .map(|p| SourceSpec::new("x", "http").with_raw_regex(rx(p)))
                .collect(),
            sinks: sinks
                .iter()
                .map(|p| SinkSpec::new("y").with_raw_regex(rx(p)))
                .collect(),
            sanitizers: sanitizers
                .iter()
                .map(|p| SanitizerSpec::new("z").with_raw_regex(rx(p)))
                .collect(),
            ..RuleSpecs::default()
        }
    }

    /// A pattern shared by two rules gets one number; each spec points to
    /// the number of its own pattern; a spec without a raw regex has none.
    #[test]
    fn test_attach_numbers_each_distinct_pattern_once() {
        let mut first = rule("a", &[r"request\.GET"], &[r"\.execute\s*\("], &[]);
        first.sources.push(SourceSpec::new("plain", "http"));
        let mut second = rule(
            "b",
            &[r"request\.GET"],
            &[r"os\.system\("],
            &[r"\bint\s*\("],
        );
        ExprTable::attach([&mut first, &mut second]);
        let (a, b) = (first.exprs.unwrap(), second.exprs.unwrap());
        assert!(std::sync::Arc::ptr_eq(&a.table, &b.table));
        assert_eq!(a.sources, vec![Some(0), None]);
        assert_eq!(b.sources, vec![Some(0)]);
        assert_eq!(a.sinks, vec![Some(1)]);
        // Numbered in rule order, then sanitizers, sources, sinks.
        assert_eq!(b.sanitizers, vec![Some(2)]);
        assert_eq!(b.sinks, vec![Some(3)]);
        assert_eq!(a.table.len, 4);
    }

    /// The set and the single regexes give the answer of each rule's own
    /// regex, look-arounds and more than 64 patterns included.
    #[test]
    fn test_set_agrees_with_each_rule_regex() {
        let mut patterns: Vec<String> = vec![
            r"(?<!System\.(?:out|err))\.println\s*\(".to_string(),
            r"\.execute\s*\((?![^)]*,)".to_string(),
            r"(?<![Ss]chema)\.execute\s*\(".to_string(),
            r"\bint\s*\(".to_string(),
            r"(?i)select\b".to_string(),
            r"\$_(GET|POST)\[".to_string(),
            r"(\w+)\s*=\s*\1".to_string(),
            r"é\w*".to_string(),
        ];
        patterns.extend((0..70).map(|i| format!(r"\bf{i}\(")));
        let refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
        let mut specs = rule("r", &refs, &[], &[]);
        ExprTable::attach([&mut specs]);
        let exprs = specs.exprs.clone().unwrap();
        assert!(exprs.table.set.is_some() && !exprs.table.single.is_empty());
        for text in [
            "",
            "System.out.println(x)",
            "log.println(x)",
            "cursor.execute(q)",
            "cursor.execute(q, params)",
            "schema.execute(q)",
            "x = int(y)",
            "SELECT a FROM t",
            "$_GET['id']",
            "a = a",
            "a = b",
            "élan",
            "f5(x) + f69(y) + f0 (z)",
        ] {
            let bits = exprs.table.matches(text);
            for (spec, id) in specs.sources.iter().zip(&exprs.sources) {
                let expected = spec.raw_regex.as_ref().unwrap().is_match(text).unwrap();
                assert_eq!(
                    bits.contains(id.unwrap()),
                    expected,
                    "{:?} on {text:?}",
                    spec.raw_regex.as_ref().unwrap().as_str()
                );
            }
        }
    }
}
