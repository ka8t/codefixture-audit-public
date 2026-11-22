//! Taint lattice — faithful port of `Audit/sca/dataflow/lattice.py`.
//!
//! ```text
//! T  ::=  ⊥                          (Clean — untainted)
//!      |  Tainted(kinds, source)     (kinds ⊆ Kinds, source: SourceInfo)
//!      |  ⊤                          (Top — over-approximation)
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Text carried by a taint, a finding or a flow step (source expression,
/// sink text, step text and code). Shared rather than owned: the hybrid
/// layer stores the whole source line there, which on minified code is
/// several MB, and the dataflow state, the findings and the function
/// summaries are cloned at every statement. A clone of a `SharedText` only
/// bumps a reference count (ticket #191). Serialized as a plain string.
pub type SharedText = Arc<str>;

/// Metadata of a taint's source — allows reconstructing the
/// flow (source → sink) for reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceInfo {
    /// Line where the taint was introduced (source).
    pub line: usize,
    /// Textual representation of the source (for reports).
    pub expr: SharedText,
    /// Nature of the taint (http, cli, env, etc.). Shared like the kinds
    /// of [`Taint::Tainted`] (ticket #241).
    pub kind: SharedText,
}

/// The kinds of a taint, shared: see [`Taint`].
pub type Kinds = Arc<BTreeSet<SharedText>>;

/// Lattice element: `⊥` (Clean) | `Tainted(kinds, source)` | `⊤` (Top).
///
/// The kinds are a shared set of [`SharedText`] rather than a
/// `BTreeSet<String>` (ticket #241): the worklist copies the state of
/// every CFG node, and with it every taint; copying the set of kinds and
/// the source kind as owned strings was a sixth of the allocations of a
/// Java scan, and still about a sixth with shared texts in an owned set.
/// A kind is compared by its text and a set by its content, so the order
/// of the kinds and every equality stay those of `BTreeSet<String>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Taint {
    Clean,
    Tainted { kinds: Kinds, source: SourceInfo },
    Top,
}

impl Taint {
    /// Builds a taint — panics if `kinds` is empty (a
    /// `Tainted` without a kind makes no sense; use `Taint::Clean`).
    /// Mirrors `Tainted.__post_init__` (Python raises `ValueError`).
    pub fn tainted<K: Into<SharedText>>(
        kinds: impl IntoIterator<Item = K>,
        source: SourceInfo,
    ) -> Self {
        let kinds: BTreeSet<SharedText> = kinds.into_iter().map(Into::into).collect();
        assert!(
            !kinds.is_empty(),
            "Taint::tainted: kinds ne doit pas être vide (utiliser Taint::Clean)"
        );
        Taint::Tainted {
            kinds: Arc::new(kinds),
            source,
        }
    }

    pub fn is_clean(&self) -> bool {
        matches!(self, Taint::Clean)
    }

    pub fn is_top(&self) -> bool {
        matches!(self, Taint::Top)
    }

    pub fn is_tainted(&self) -> bool {
        !self.is_clean()
    }
}

/// `⊔` — merges two taints at a confluence point of the control
/// flow. Rules (spec §1/§4.3 Python):
/// ```text
/// ⊥ ⊔ x = x        x ⊔ ⊥ = x
/// ⊤ ⊔ x = ⊤        x ⊔ ⊤ = ⊤
/// Tainted(K₁,S₁) ⊔ Tainted(K₂,S₂) = Tainted(K₁ ∪ K₂, earliest_source)
/// ```
pub fn join(a: &Taint, b: &Taint) -> Taint {
    match (a, b) {
        (Taint::Top, _) | (_, Taint::Top) => Taint::Top,
        (Taint::Clean, x) => x.clone(),
        (x, Taint::Clean) => x.clone(),
        (
            Taint::Tainted {
                kinds: k1,
                source: s1,
            },
            Taint::Tainted {
                kinds: k2,
                source: s2,
            },
        ) => Taint::Tainted {
            // The union, sharing one side's set when it already holds the
            // other (ticket #241): the same kinds, without a new set.
            kinds: if k2.is_subset(k1) {
                Arc::clone(k1)
            } else if k1.is_subset(k2) {
                Arc::clone(k2)
            } else {
                Arc::new(k1.union(k2).cloned().collect())
            },
            source: merge_source(s1, s2),
        },
    }
}

/// `⊓` — intersects two taints (rarely used). Rules:
/// ```text
/// ⊥ ⊓ x = ⊥        x ⊓ ⊥ = ⊥
/// ⊤ ⊓ x = x        x ⊓ ⊤ = x
/// Tainted(K₁,S₁) ⊓ Tainted(K₂,S₂) = Tainted(K₁ ∩ K₂, S₁) if non-empty, else ⊥
/// ```
pub fn meet(a: &Taint, b: &Taint) -> Taint {
    match (a, b) {
        (Taint::Clean, _) | (_, Taint::Clean) => Taint::Clean,
        (Taint::Top, x) => x.clone(),
        (x, Taint::Top) => x.clone(),
        (
            Taint::Tainted {
                kinds: k1,
                source: s1,
            },
            Taint::Tainted { kinds: k2, .. },
        ) => {
            let inter: BTreeSet<SharedText> = k1.intersection(k2).cloned().collect();
            if inter.is_empty() {
                Taint::Clean
            } else {
                Taint::Tainted {
                    kinds: Arc::new(inter),
                    source: s1.clone(),
                }
            }
        }
    }
}

/// `⊑` — the lattice's partial order.
/// ```text
/// ⊥ ⊑ x for all x       x ⊑ ⊤ for all x
/// Tainted(K₁,_) ⊑ Tainted(K₂,_) iff K₁ ⊆ K₂
/// ```
pub fn leq(a: &Taint, b: &Taint) -> bool {
    match (a, b) {
        (Taint::Clean, _) => true,
        (_, Taint::Top) => true,
        (_, Taint::Clean) => false, // a non-clean, b clean
        (Taint::Top, _) => false,   // a top, b non-top (and b non-⊤, case already handled above)
        (Taint::Tainted { kinds: k1, .. }, Taint::Tainted { kinds: k2, .. }) => k1.is_subset(k2),
    }
}

/// `∇` — widening operator, forces convergence over unstable
/// loops. Rule: if `iteration > max_iter` and `old != new`,
/// returns `⊤`; otherwise returns `new`.
pub fn widen(old: &Taint, new: &Taint, iteration: u32, max_iter: u32) -> Taint {
    if iteration > max_iter && old != new {
        Taint::Top
    } else {
        new.clone()
    }
}

/// Keeps the source whose line is the earliest (report consistency).
fn merge_source(s1: &SourceInfo, s2: &SourceInfo) -> SourceInfo {
    if s1.line <= s2.line {
        s1.clone()
    } else {
        s2.clone()
    }
}

/// Dataflow state: maps each LValue (canonical name) to its taint.
/// The names are [`SharedText`] (ticket #241): a copy of the state, made
/// for every CFG node, no longer copies the text of every name. They sort
/// by their text, as `String` keys did, so a state iterates in the same
/// order.
/// Keys whose value is `Clean` are absent from the map, to
/// stay compact — mirrors `state_set` (Python removes the key rather
/// than explicitly storing `⊥` in it).
pub type State = BTreeMap<SharedText, Taint>;

pub fn empty_state() -> State {
    BTreeMap::new()
}

pub fn state_get(state: &State, key: &str) -> Taint {
    state.get(key).cloned().unwrap_or(Taint::Clean)
}

/// In-place update: sets the taint of `key`; a `Clean` taint removes
/// the key. What the transfer functions use: the state is updated at
/// every statement, and copying it each time made a basic block of N
/// assignments cost N² (a minified line holds thousands of them, ticket
/// #191).
pub fn state_put(state: &mut State, key: &str, taint: Taint) {
    if taint.is_clean() {
        state.remove(key);
    } else if let Some(slot) = state.get_mut(key) {
        *slot = taint;
    } else {
        state.insert(SharedText::from(key), taint);
    }
}

/// Functional update: returns a new state with `key` updated (see
/// [`state_put`]). Copies the whole state: kept for the places that
/// build an initial state once, not for the transfer functions.
pub fn state_set(state: &State, key: &str, taint: Taint) -> State {
    let mut new_state = state.clone();
    state_put(&mut new_state, key, taint);
    new_state
}

/// `⊔` on states: merges the taint of each key present in either state.
pub fn state_join(s1: &State, s2: &State) -> State {
    let mut result = State::new();
    let keys: BTreeSet<&SharedText> = s1.keys().chain(s2.keys()).collect();
    for k in keys {
        let merged = join(&state_get(s1, k), &state_get(s2, k));
        if !merged.is_clean() {
            result.insert(k.clone(), merged);
        }
    }
    result
}

/// `acc ⊔= other`, in place: what [`state_join`]`(acc, other)` returns,
/// written into `acc` (ticket #241). The worklist merges the states of a
/// node's predecessors one after the other; `state_join` built a new
/// state at each step and copied every taint twice (`state_get`, then
/// `join`), which made state copies and their release the largest share
/// of the allocations of a Java scan. Here a taint of `other` is copied
/// once when `acc` has none for its key, and joined in place otherwise,
/// in the same argument order (`join(acc, other)`, which keeps the
/// source of `acc` on equal lines). A `Clean` value is never kept, as in
/// `state_join`.
pub fn state_join_into(acc: &mut State, other: &State) {
    // `acc` may hold a `Clean` value written by a direct insert: the
    // result of `state_join` never does.
    acc.retain(|_, taint| !taint.is_clean());
    for (key, taint) in other {
        if taint.is_clean() {
            continue;
        }
        match acc.get_mut(key) {
            Some(slot) => *slot = join(slot, taint),
            None => {
                acc.insert(key.clone(), taint.clone());
            }
        }
    }
}

pub fn state_equal(s1: &State, s2: &State) -> bool {
    s1 == s2
}

/// Element-by-element widening of a state relative to its previous iteration.
pub fn state_widen(old: &State, new: &State, iteration: u32, max_iter: u32) -> State {
    let mut result = State::new();
    let keys: BTreeSet<&SharedText> = old.keys().chain(new.keys()).collect();
    for k in keys {
        let v = widen(&state_get(old, k), &state_get(new, k), iteration, max_iter);
        if !v.is_clean() {
            result.insert(k.clone(), v);
        }
    }
    result
}

pub fn pretty_taint(t: &Taint) -> String {
    match t {
        Taint::Clean => "⊥".to_string(),
        Taint::Top => "⊤".to_string(),
        Taint::Tainted { kinds, source } => {
            let kinds_str = kinds.iter().cloned().collect::<Vec<_>>().join(",");
            format!("Tainted{{{kinds_str}}}@{}", source.line)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(line: usize) -> SourceInfo {
        SourceInfo {
            line,
            expr: String::new().into(),
            kind: "http".into(),
        }
    }

    fn tainted(line: usize, kinds: &[&str]) -> Taint {
        Taint::tainted(kinds.iter().map(|s| s.to_string()), src(line))
    }

    /// Ticket #241: merging the states of several predecessors in place
    /// gives the state the fold of `state_join` gave, sources on equal
    /// lines, `Top` and `Clean` values included.
    #[test]
    fn test_state_join_into_matches_state_join() {
        let named = |expr: &str, line: usize, kinds: &[&str]| {
            Taint::tainted(
                kinds.iter().map(|s| s.to_string()),
                SourceInfo {
                    line,
                    expr: expr.into(),
                    kind: kinds[0].into(),
                },
            )
        };
        let states: Vec<State> = vec![
            State::from([
                ("a".into(), named("first", 3, &["http"])),
                ("b".into(), Taint::Top),
                ("c".into(), Taint::Clean),
            ]),
            State::from([
                ("a".into(), named("second", 3, &["cli"])),
                ("c".into(), named("c", 9, &["env"])),
                ("d".into(), Taint::Clean),
            ]),
            State::new(),
            State::from([
                ("a".into(), named("third", 1, &["http"])),
                ("b".into(), named("b", 2, &["file"])),
                ("e".into(), named("e", 5, &["http", "env"])),
            ]),
        ];
        // Every order and every prefix of the predecessors.
        let orders = [[0, 1, 2, 3], [3, 2, 1, 0], [1, 0, 3, 2], [2, 3, 0, 1]];
        for order in orders {
            for len in 1..=order.len() {
                let mut folded = empty_state();
                let mut in_place = empty_state();
                for &i in &order[..len] {
                    folded = state_join(&folded, &states[i]);
                    state_join_into(&mut in_place, &states[i]);
                }
                assert_eq!(in_place, folded, "{:?}", &order[..len]);
            }
        }
        // An accumulator holding a `Clean` value.
        let mut acc = states[0].clone();
        state_join_into(&mut acc, &states[1]);
        assert_eq!(acc, state_join(&states[0], &states[1]));
    }

    #[test]
    fn test_join_clean_identity() {
        let t = tainted(1, &["http"]);
        assert_eq!(join(&Taint::Clean, &t), t);
        assert_eq!(join(&t, &Taint::Clean), t);
    }

    #[test]
    fn test_join_top_absorbs() {
        assert_eq!(join(&Taint::Top, &tainted(1, &["http"])), Taint::Top);
        assert_eq!(join(&tainted(1, &["http"]), &Taint::Top), Taint::Top);
    }

    #[test]
    fn test_join_tainted_unions_kinds_keeps_earliest_source() {
        let a = tainted(5, &["http"]);
        let b = tainted(2, &["cli"]);
        let result = join(&a, &b);
        match result {
            Taint::Tainted { kinds, source } => {
                assert_eq!(*kinds, BTreeSet::from(["http".into(), "cli".into()]));
                assert_eq!(source.line, 2); // the earliest
            }
            _ => panic!("attendu Tainted"),
        }
    }

    #[test]
    fn test_meet_clean_absorbs() {
        assert_eq!(meet(&Taint::Clean, &tainted(1, &["http"])), Taint::Clean);
    }

    #[test]
    fn test_meet_top_identity() {
        let t = tainted(1, &["http"]);
        assert_eq!(meet(&Taint::Top, &t), t);
    }

    #[test]
    fn test_meet_disjoint_kinds_is_clean() {
        let a = tainted(1, &["http"]);
        let b = tainted(1, &["cli"]);
        assert_eq!(meet(&a, &b), Taint::Clean);
    }

    #[test]
    fn test_meet_overlapping_kinds_intersects() {
        let a = tainted(1, &["http", "cli"]);
        let b = tainted(1, &["cli", "env"]);
        match meet(&a, &b) {
            Taint::Tainted { kinds, .. } => assert_eq!(*kinds, BTreeSet::from(["cli".into()])),
            _ => panic!("attendu Tainted"),
        }
    }

    #[test]
    fn test_leq_clean_bottom_of_everything() {
        assert!(leq(&Taint::Clean, &Taint::Clean));
        assert!(leq(&Taint::Clean, &tainted(1, &["http"])));
        assert!(leq(&Taint::Clean, &Taint::Top));
    }

    #[test]
    fn test_leq_top_is_top_of_everything() {
        assert!(leq(&tainted(1, &["http"]), &Taint::Top));
        assert!(leq(&Taint::Top, &Taint::Top));
        assert!(!leq(&Taint::Top, &tainted(1, &["http"])));
    }

    #[test]
    fn test_leq_kinds_subset() {
        let small = tainted(1, &["http"]);
        let big = tainted(1, &["http", "cli"]);
        assert!(leq(&small, &big));
        assert!(!leq(&big, &small));
    }

    #[test]
    fn test_widen_stable_keeps_new() {
        let old = tainted(1, &["http"]);
        let new = tainted(1, &["http"]);
        assert_eq!(widen(&old, &new, 5, 3), new);
    }

    #[test]
    fn test_widen_unstable_past_max_iter_becomes_top() {
        let old = tainted(1, &["http"]);
        let new = tainted(1, &["cli"]);
        assert_eq!(widen(&old, &new, 4, 3), Taint::Top);
    }

    #[test]
    fn test_widen_unstable_before_max_iter_keeps_new() {
        let old = tainted(1, &["http"]);
        let new = tainted(1, &["cli"]);
        assert_eq!(widen(&old, &new, 2, 3), new);
    }

    #[test]
    fn test_state_set_clean_removes_key() {
        let mut state = empty_state();
        state.insert("x".into(), tainted(1, &["http"]));
        let updated = state_set(&state, "x", Taint::Clean);
        assert!(!updated.contains_key("x"));
    }

    #[test]
    fn test_state_get_absent_key_is_clean() {
        let state = empty_state();
        assert_eq!(state_get(&state, "missing"), Taint::Clean);
    }

    #[test]
    fn test_state_join_merges_both_keys() {
        let mut s1 = empty_state();
        s1.insert("x".into(), tainted(1, &["http"]));
        let mut s2 = empty_state();
        s2.insert("y".into(), tainted(2, &["cli"]));
        let joined = state_join(&s1, &s2);
        assert_eq!(joined.len(), 2);
    }

    #[test]
    fn test_state_join_omits_clean_results() {
        // x tainted on one side, absent (so clean) on the other → join =
        // the non-clean value, present in the result (no loss).
        let mut s1 = empty_state();
        s1.insert("x".into(), tainted(1, &["http"]));
        let s2 = empty_state();
        let joined = state_join(&s1, &s2);
        assert!(joined.contains_key("x"));
    }
}
