//! Checks a branch condition proves on its TRUE edge (ticket #252).
//!
//! The guards of `transfer.rs` read the "refuse, then leave" shape of a
//! check: `if not target.is_relative_to(BASE): abort(403)`, after which
//! the rest of the function only runs with a path that passed. The same
//! check is also written the other way round, the safe code inside the
//! `if`:
//!
//! ```python
//! if target.is_relative_to(BASE):
//!     return send_file(target)
//! abort(403)
//! ```
//!
//! Here only the body of the `if` is protected. The taint fixpoint
//! (`worklist.rs`) used to give both edges of a branch the same state,
//! so the body saw `target` tainted and the scan reported a path
//! traversal the check prevents.
//!
//! This module reads the condition of each branch from its syntax tree
//! and lists the sanitizer calls that hold whenever the condition is
//! true:
//!
//! - the call itself, `target.is_relative_to(BASE)`;
//! - the call compared to a success value, `strpos($p, $base) === 0`,
//!   `x.startsWith(b) == true`, `m is not None`, C# `x.StartsWith(b) is
//!   true` (the reverse of the failure comparisons of ticket #250, read
//!   by the same [`compares_to_failure`]);
//! - any of these inside a conjunction (`a && check(x)`, `check(x) and
//!   b`) or parentheses.
//!
//! A disjunction, a negation or a ternary proves nothing about its
//! operands, so they are not read. Nor does a check with a text literal
//! among its arguments: `if (token.startsWith("id=")) data =
//! token.substring(3);` parses a request, it confines nothing, and on
//! `juliet_java` reading it as a passed check hid 42 real path
//! traversals (the `startsWith` sanitizer of the rule is that broad). A
//! check against a value, `p.startsWith(base)`, `is_relative_to(BASE)`,
//! `strpos($p, $base) === 0`, counts; one against a literal, such as
//! `p.startsWith("/srv/files/")` or `re.match(r"^\w+$", name)`, does not,
//! and its body stays tainted (a false positive kept, not a finding
//! lost). The fixpoint then removes, on the
//! TRUE edge only, the tainted variables these calls mention: the same
//! clean-up as the guards, restricted to the text of the checks instead
//! of the whole line.
//!
//! Deliberate deviation from the Audit (`Audit/sca/dataflow/
//! worklist.py`), whose fixpoint reads the TRUE/FALSE labels of the edges
//! only to drop the dead ones (§9) and gives both edges the same state.

use std::collections::{HashMap, HashSet, VecDeque};

use tree_sitter::Node;

use super::cfg::{Cfg, CfgNode, EdgeLabel, NodeKind};
use super::lattice::State;
use super::line_facts::{Comparison, RuleLines, compares_to_failure, strip_plain_string_literals};
use super::transfer::{RuleSpecs, mentions_identifier, sanitizer_names_call};

/// The checks each TRUE edge of a CFG proves, for one rule.
pub(crate) struct PassedChecks {
    /// By `(branch, successor)` edge: the text of each sanitizer call
    /// the condition proves, without its string literals (a tainted name
    /// written inside a literal is not the variable).
    by_edge: HashMap<(usize, usize), Vec<String>>,
    /// The edges no run can take: their condition was settled by an
    /// earlier branch (see [`settled_edges`], ticket #268).
    infeasible: HashSet<(usize, usize)>,
}

impl PassedChecks {
    /// Reads the condition of every branch of `cfg` (see the module
    /// doc). Without the source lines (`source_lines` is `None`: a test
    /// of the bare fixpoint) no edge proves anything; for a rule without a
    /// sanitizer, only the settled conditions are read.
    pub(crate) fn compute(cfg: &Cfg, specs: &RuleSpecs, source_lines: Option<&RuleLines>) -> Self {
        let mut by_edge = HashMap::new();
        let Some(lines) = source_lines else {
            return Self {
                by_edge,
                infeasible: HashSet::new(),
            };
        };
        let text = lines.lines().text();
        let infeasible = settled_edges(cfg, text);
        if specs.sanitizers.iter().all(|san| san.raw_regex.is_none()) {
            return Self {
                by_edge,
                infeasible,
            };
        }
        for node in cfg.nodes.values() {
            let Some(condition) = boolean_condition(node) else {
                continue;
            };
            let checks_of = |calls: Vec<Node<'_>>| -> Vec<String> {
                calls
                    .into_iter()
                    .filter(|&call| {
                        !has_literal_argument(call) && is_sanitizer_call(call, lines, specs)
                    })
                    .filter_map(|call| text.get(call.byte_range()))
                    .map(strip_plain_string_literals)
                    .collect()
            };
            let mut true_calls = Vec::new();
            calls_true_with(condition, text, &mut true_calls);
            let mut false_calls = Vec::new();
            calls_false_with(condition, text, &mut false_calls);
            let by_label = [
                (EdgeLabel::True, checks_of(true_calls)),
                (EdgeLabel::False, checks_of(false_calls)),
            ];
            let edges = cfg.successors(node.id);
            for (label, checks) in by_label {
                if checks.is_empty() {
                    continue;
                }
                for edge in &edges {
                    // An edge that is also the other (or any other) edge
                    // to the same node, `if check(x): pass` with nothing
                    // after, proves nothing.
                    let only_this = edges
                        .iter()
                        .filter(|other| other.dst == edge.dst)
                        .all(|other| other.label == label);
                    if edge.label == label && only_this {
                        by_edge.insert((node.id, edge.dst), checks.clone());
                    }
                }
            }
        }
        Self {
            by_edge,
            infeasible,
        }
    }

    /// The state the edge `src → dst` carries, when it proves checks:
    /// `state` without the tainted variables the checks mention; an empty
    /// state (no taint) on an edge no run can take. `None` when the edge
    /// proves nothing (the state passes unchanged).
    pub(crate) fn refine(&self, src: usize, dst: usize, state: &State) -> Option<State> {
        if self.infeasible.contains(&(src, dst)) {
            return Some(State::default());
        }
        let checks = self.by_edge.get(&(src, dst))?;
        let mut refined = state.clone();
        refined.retain(|var_name, _| {
            !checks
                .iter()
                .any(|check| mentions_identifier(check, var_name))
        });
        Some(refined)
    }
}

/// The statements whose `condition` field is a boolean test, its TRUE
/// edge entering the code run when it holds. Leaves out the `condition`
/// fields that are not one: the subject of a `switch`/`match`, the
/// object of a C# `a?.b` (`conditional_access_expression`).
const CONDITION_STATEMENTS: &[&str] = &[
    "if_statement",
    "elif_clause",
    "else_if_clause",
    "while_statement",
    "do_statement",
    "for_statement",
    "ternary_expression",
    "conditional_expression",
];

/// The boolean condition of a `Branch` or `Loop` node, `None` for any
/// other node. The condition must be the `condition` field of one of
/// [`CONDITION_STATEMENTS`], possibly through parentheses: a `foreach`
/// or `for ... in` loop holds the collection it walks, a Java `switch`
/// branch its subject, a Python `case` none.
fn boolean_condition<'tree>(node: &CfgNode<'tree>) -> Option<Node<'tree>> {
    if !matches!(node.kind, NodeKind::Branch | NodeKind::Loop)
        || node.switch_case_label.is_some()
        || node.for_target.is_some()
    {
        return None;
    }
    let condition = node.condition?;
    let mut field = condition;
    while let Some(parent) = field.parent() {
        if parent.kind() != "parenthesized_expression" {
            break;
        }
        field = parent;
    }
    let statement = field.parent()?;
    let is_condition = CONDITION_STATEMENTS.contains(&statement.kind())
        && statement
            .child_by_field_name("condition")
            .is_some_and(|c| c.id() == field.id());
    is_condition.then_some(condition)
}

/// The call nodes of every syntax the scanned languages use for a call.
const CALL_KINDS: &[&str] = &[
    // Python
    "call",
    // JavaScript, TypeScript
    "call_expression",
    // Java
    "method_invocation",
    // C#
    "invocation_expression",
    // PHP
    "function_call_expression",
    "member_call_expression",
    "nullsafe_member_call_expression",
    "scoped_call_expression",
];

/// Pushes to `out` the calls whose result is truthy (or compared to a
/// success value) whenever `expr` is true. See the module doc for the
/// shapes read.
fn calls_true_with<'tree>(expr: Node<'tree>, text: &str, out: &mut Vec<Node<'tree>>) {
    let kind = expr.kind();
    if kind == "parenthesized_expression" {
        if let Some(inner) = only_named_child(expr) {
            calls_true_with(inner, text, out);
        }
        return;
    }
    if CALL_KINDS.contains(&kind) {
        out.push(expr);
        return;
    }
    if kind == "is_pattern_expression" {
        // C# `x.StartsWith(b) is true`, `m is not null`.
        if let (Some(call), Some(pattern)) = (
            expr.child_by_field_name("expression"),
            expr.child_by_field_name("pattern"),
        ) && let (Some(call), Some(pattern)) = (bare_call(call), node_text(pattern, text))
        {
            let (comparison, operand) = match pattern.strip_prefix("not ") {
                Some(rest) => (Comparison::NotEqual, rest.trim()),
                None => (Comparison::Equal, pattern.trim()),
            };
            if !compares_to_failure(comparison, operand) {
                out.push(call);
            }
        }
        return;
    }
    let (Some(left), Some(right)) = operands(expr) else {
        return;
    };
    let Some(operator) = text.get(left.end_byte()..right.start_byte()).map(str::trim) else {
        return;
    };
    match operator {
        "and" | "&&" => {
            calls_true_with(left, text, out);
            calls_true_with(right, text, out);
        }
        _ => {
            let Some(comparison) = comparison_of(operator) else {
                return;
            };
            // The call on either side, the operand on the other: `strpos(
            // $p, $base) === 0` and `0 === strpos($p, $base)`.
            for (call, operand) in [(left, right), (right, left)] {
                if let (Some(call), Some(operand)) = (bare_call(call), node_text(operand, text))
                    && !compares_to_failure(comparison, operand.trim())
                {
                    out.push(call);
                }
            }
        }
    }
}

/// Pushes to `out` the calls whose result is truthy whenever `expr` is
/// FALSE: the checks of a negation, `!Guid.TryParse(id, out _)` or `not
/// check(x)`, and those of either side of a disjunction (`!a || !b` false
/// means both hold). Ticket #268: eShopOnWeb writes `if
/// (!Guid.TryParse(userName, out var _)) userName = null;`, after which the
/// FALSE edge carries a name that parsed as a GUID.
fn calls_false_with<'tree>(expr: Node<'tree>, text: &str, out: &mut Vec<Node<'tree>>) {
    let expr = strip_parentheses(expr);
    if let Some(inner) = negated(expr, text) {
        calls_true_with(inner, text, out);
        return;
    }
    let (Some(left), Some(right)) = operands(expr) else {
        return;
    };
    let Some(operator) = text.get(left.end_byte()..right.start_byte()).map(str::trim) else {
        return;
    };
    if matches!(operator, "or" | "||") {
        calls_false_with(left, text, out);
        calls_false_with(right, text, out);
    }
}

/// `node` without the parentheses around it.
fn strip_parentheses(node: Node<'_>) -> Node<'_> {
    let mut node = node;
    while node.kind() == "parenthesized_expression" {
        match only_named_child(node) {
            Some(inner) => node = inner,
            None => break,
        }
    }
    node
}

/// The operand of a logical negation (`!e`, Python `not e`), `None` for
/// any other expression. The negation is a `not_operator` (Python), a
/// `prefix_unary_expression` (C#), a `unary_expression` (Java,
/// JavaScript) or a `unary_op_expression` (PHP) whose operator is `!`.
fn negated<'tree>(expr: Node<'tree>, text: &str) -> Option<Node<'tree>> {
    match expr.kind() {
        "not_operator" => expr.child_by_field_name("argument"),
        "prefix_unary_expression" | "unary_expression" | "unary_op_expression" => {
            let operator = expr.child(0)?;
            if node_text(operator, text)? != "!" {
                return None;
            }
            let mut cursor = expr.walk();
            expr.named_children(&mut cursor)
                .filter(|child| child.kind() != "comment")
                .last()
        }
        _ => None,
    }
}

// ----------------------------------------------------------------------
// Settled conditions (ticket #268)
// ----------------------------------------------------------------------

/// The edges no run can take because an earlier branch settled their
/// condition. eShopOnWeb's `GetOrSetBasketCookieAndUserName` returns at
/// once when `Request.HttpContext.User.Identity.IsAuthenticated` holds,
/// then tests `!Request.HttpContext.User.Identity.IsAuthenticated` again
/// before checking the cookie with `Guid.TryParse`: the skip of that second
/// test cannot happen, and the fixpoint, which reads no condition, let the
/// unchecked cookie through it.
///
/// A condition is settled at a branch B by a branch A that tests the same
/// operand (`C` or `!C`, the same text once blanks are removed) when:
///   - every path from the entry to B goes through A (A dominates B);
///   - from one edge of A, B is reached without going back to A, and from
///     the other edge it is not (that edge leaves: a `return`, a `throw`);
///   - the operand reads no call and no name the function assigns
///     ([`settled_operand`]): its value cannot change between A and B.
///
/// B's edge that contradicts the value A's reaching edge gives the operand
/// is then infeasible. Deliberate deviation from the Audit
/// (`Audit/sca/dataflow/worklist.py`), whose fixpoint drops only the edges
/// of a constant condition (§9).
fn settled_edges(cfg: &Cfg, text: &str) -> HashSet<(usize, usize)> {
    let mut infeasible = HashSet::new();
    // Each branch with a settled-able operand: (id, operand text, negated).
    let mut branches: Vec<(usize, String, bool)> = Vec::new();
    for node in cfg.nodes.values() {
        let Some(condition) = boolean_condition(node) else {
            continue;
        };
        let condition = strip_parentheses(condition);
        let (operand, is_negated) = match negated(condition, text) {
            Some(inner) => (strip_parentheses(inner), true),
            None => (condition, false),
        };
        let Some(operand_text) = node_text(operand, text) else {
            continue;
        };
        if !settled_operand(operand, operand_text, cfg, text) {
            continue;
        }
        let key: String = operand_text
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        branches.push((node.id, key, is_negated));
    }
    for (a, key_a, negated_a) in &branches {
        for (b, key_b, negated_b) in &branches {
            if a == b || key_a != key_b {
                continue;
            }
            // A dominates B: B is unreachable from the entry once A is
            // removed.
            if reachable(cfg, cfg.entry, *b, *a) {
                continue;
            }
            let edges_a = cfg.successors(*a);
            let edge_to = |label| edges_a.iter().find(|e| e.label == label).map(|e| e.dst);
            let (Some(true_dst), Some(false_dst)) =
                (edge_to(EdgeLabel::True), edge_to(EdgeLabel::False))
            else {
                continue;
            };
            let from_true = reachable(cfg, true_dst, *b, *a);
            let from_false = reachable(cfg, false_dst, *b, *a);
            // The value of the operand at B: the label of A's edge that
            // reaches B, read through A's negation.
            let operand_value = match (from_true, from_false) {
                (true, false) => !*negated_a,
                (false, true) => *negated_a,
                _ => continue,
            };
            // B's condition is then `operand_value` (or its negation): the
            // edge of the other label is never taken.
            let condition_b = operand_value != *negated_b;
            let dead_label = if condition_b {
                EdgeLabel::False
            } else {
                EdgeLabel::True
            };
            for edge in cfg.successors(*b) {
                if edge.label == dead_label {
                    infeasible.insert((*b, edge.dst));
                }
            }
        }
    }
    infeasible
}

/// Whether `to` is reached from `from` without going through `avoid`
/// (`from` itself may not be `avoid`).
fn reachable(cfg: &Cfg, from: usize, to: usize, avoid: usize) -> bool {
    if from == avoid {
        return false;
    }
    let mut seen = HashSet::from([from]);
    let mut queue = VecDeque::from([from]);
    while let Some(node) = queue.pop_front() {
        if node == to {
            return true;
        }
        for next in cfg.successor_ids(node) {
            if next != avoid && seen.insert(next) {
                queue.push_back(next);
            }
        }
    }
    false
}

/// The node kinds that change a value or may: an assignment, a
/// declaration, an increment, a call.
const WRITE_KINDS: &[&str] = &[
    "assignment",
    "augmented_assignment",
    "assignment_expression",
    "augmented_assignment_expression",
    "variable_declarator",
    "update_expression",
    "postfix_unary_expression",
];

/// Whether the value of `operand` cannot change between two branches of
/// the function: a name or a chain of members (`a.b.c`), no call, no
/// subscript; its first name is assigned nowhere in the statements or
/// conditions of `cfg`, nor passed as `ref`/`out`; and no call of the
/// function has the object of the last member as its receiver
/// (`stack.Pop()` can change `stack.IsEmpty`; `Guard.Against.Null(
/// Request.HttpContext.User.Identity.Name, …)` cannot change
/// `Request.HttpContext.User.Identity.IsAuthenticated`).
fn settled_operand(operand: Node<'_>, operand_text: &str, cfg: &Cfg, text: &str) -> bool {
    let root: String = operand_text
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
        .collect();
    if root.is_empty()
        || !operand_text
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '$' || c == '.' || c.is_whitespace())
        || has_descendant(operand, &|n| CALL_KINDS.contains(&n.kind()))
    {
        return false;
    }
    let assigns_root = |node: Node<'_>| {
        // C#'s null-forgiving `x!` is a `postfix_unary_expression` too: only
        // an increment or a decrement writes.
        let increments = matches!(
            node.kind(),
            "postfix_unary_expression" | "update_expression"
        ) && node_text(node, text)
            .is_some_and(|t| t.contains("++") || t.contains("--"));
        (increments
            || (WRITE_KINDS.contains(&node.kind())
                && !matches!(
                    node.kind(),
                    "postfix_unary_expression" | "update_expression"
                )))
            && node
                .named_child(0)
                .and_then(|target| node_text(target, text))
                .is_some_and(|target| {
                    target.starts_with(root.as_str())
                        && !target[root.len()..]
                            .starts_with(|c: char| c.is_alphanumeric() || c == '_')
                })
    };
    // The object whose member the operand reads: `a.b` for `a.b.c`; none
    // for a bare name.
    let compact: String = operand_text
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let object = compact
        .rsplit_once('.')
        .map(|(object, _)| format!("{object}."));
    let may_change = |node: Node<'_>| {
        if assigns_root(node) {
            return true;
        }
        let Some(node_source) = node_text(node, text) else {
            return false;
        };
        if node.kind() == "argument" {
            let compact_argument: String =
                node_source.split_whitespace().collect::<Vec<_>>().join(" ");
            if compact_argument == format!("ref {root}")
                || compact_argument == format!("out {root}")
            {
                return true;
            }
        }
        if let Some(object) = &object
            && CALL_KINDS.contains(&node.kind())
        {
            // The text before the arguments: `stack.Pop`, `$this->items->pop`.
            let callee = node
                .child_by_field_name("arguments")
                .and_then(|arguments| text.get(node.start_byte()..arguments.start_byte()))
                .unwrap_or("");
            let callee: String = callee.chars().filter(|c| !c.is_whitespace()).collect();
            if callee.starts_with(object.as_str()) {
                return true;
            }
        }
        false
    };
    !cfg.nodes.values().any(|node| {
        node.statements
            .iter()
            .chain(node.condition.iter())
            .any(|statement| has_descendant(*statement, &may_change))
    })
}

/// Whether `node` or one of its descendants satisfies `predicate`.
fn has_descendant(node: Node<'_>, predicate: &dyn Fn(Node<'_>) -> bool) -> bool {
    if predicate(node) {
        return true;
    }
    let mut cursor = node.walk();
    let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
    children
        .into_iter()
        .any(|child| has_descendant(child, predicate))
}

/// The two operands of a binary operation: the `left`/`right` fields
/// (`boolean_operator`, `binary_expression`), or the two named children
/// of a Python `comparison_operator`, which has no such fields. A
/// chained comparison (`a < b < c`, three operands) has none.
fn operands(expr: Node<'_>) -> (Option<Node<'_>>, Option<Node<'_>>) {
    match expr.kind() {
        "boolean_operator" | "binary_expression" => (
            expr.child_by_field_name("left"),
            expr.child_by_field_name("right"),
        ),
        "comparison_operator" if expr.named_child_count() == 2 => {
            (expr.named_child(0), expr.named_child(1))
        }
        _ => (None, None),
    }
}

/// How `operator` compares: `==`, `===`, `is` are an equality; `!=`,
/// `!==`, `<>` (PHP), `is not` an inequality. `None` for anything else
/// (`<`, `instanceof`, `in`).
fn comparison_of(operator: &str) -> Option<Comparison> {
    match operator {
        "==" | "===" | "is" => Some(Comparison::Equal),
        "!=" | "!==" | "<>" => Some(Comparison::NotEqual),
        _ if operator.split_whitespace().eq(["is", "not"]) => Some(Comparison::NotEqual),
        _ => None,
    }
}

/// `node` as a call, through parentheses (`(strpos($p, $b)) === 0`).
fn bare_call(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "parenthesized_expression" => only_named_child(node).and_then(bare_call),
        kind if CALL_KINDS.contains(&kind) => Some(node),
        _ => None,
    }
}

/// The single named child of a parenthesized expression, `None` when it
/// holds several (a C# tuple-like or comment-filled parenthesis).
fn only_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut named = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment");
    let first = named.next()?;
    named.next().is_none().then_some(first)
}

/// True when one of the arguments of `call` is a text literal (a string,
/// a template or interpolated string, a character): see the module doc
/// for why such a check proves nothing. An argument wrapped in an
/// `argument` node (Java, C#, PHP) or a Python `keyword_argument` is
/// read through its value.
fn has_literal_argument(call: Node<'_>) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).any(|argument| {
        let value = match argument.kind() {
            "argument" | "keyword_argument" => argument
                .child_by_field_name("value")
                .or_else(|| argument.named_children(&mut argument.walk()).last()),
            "comment" => None,
            _ => Some(argument),
        };
        value.is_some_and(|value| {
            let kind = value.kind();
            kind.contains("string") || kind == "character_literal"
        })
    })
}

/// The source text of `node`, `None` if its bytes fall outside `text`
/// or not on character boundaries (a tree built from another text).
fn node_text<'a>(node: Node<'_>, text: &'a str) -> Option<&'a str> {
    text.get(node.byte_range())
}

/// True when one of the rule's sanitizers names `call`
/// ([`sanitizer_names_call`]), read on the line of its `(`. The line
/// facts tell first, from their per-line cache, whether a sanitizer
/// matches the line at all.
fn is_sanitizer_call(call: Node<'_>, lines: &RuleLines, specs: &RuleSpecs) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let position = arguments.start_position();
    let lineno = position.row + 1;
    let (Some(line), Some(facts)) = (lines.line(lineno), lines.facts(lineno, specs)) else {
        return false;
    };
    facts.first_sanitizer.is_some()
        && line.as_bytes().get(position.column) == Some(&b'(')
        && sanitizer_names_call(line, specs, position.column)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The text of the calls [`calls_true_with`] reads in the condition
    /// of the first `if` of `source`, parsed with `language`.
    fn proved(language: tree_sitter::Language, source: &str) -> Vec<String> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("valid grammar");
        let tree = parser.parse(source, None).expect("parsed");
        let mut stack = vec![tree.root_node()];
        let mut condition = None;
        while let Some(node) = stack.pop() {
            if node.kind() == "if_statement" {
                condition = node.child_by_field_name("condition");
                break;
            }
            let mut cursor = node.walk();
            let children: Vec<_> = node.children(&mut cursor).collect();
            stack.extend(children.into_iter().rev());
        }
        let mut calls = Vec::new();
        calls_true_with(condition.expect("an if"), source, &mut calls);
        calls
            .iter()
            .map(|call| source[call.byte_range()].to_string())
            .collect()
    }

    #[test]
    fn test_calls_true_with_python() {
        let python = || tree_sitter_python::LANGUAGE.into();
        let check = "if target.is_relative_to(BASE):\n    pass\n";
        assert_eq!(proved(python(), check), ["target.is_relative_to(BASE)"]);
        let both = "if a.ok() and (b.startswith(c)):\n    pass\n";
        assert_eq!(proved(python(), both), ["a.ok()", "b.startswith(c)"]);
        let success = "if os.path.commonpath([b, t]) == b:\n    pass\n";
        assert_eq!(proved(python(), success), ["os.path.commonpath([b, t])"]);
        let found = "if re.match(r, s) is not None:\n    pass\n";
        assert_eq!(proved(python(), found), ["re.match(r, s)"]);
        // Nothing proved: a failure comparison, a negation, a disjunction,
        // a chained comparison.
        for source in [
            "if t.is_relative_to(B) == False:\n    pass\n",
            "if re.match(r, s) is None:\n    pass\n",
            "if not t.is_relative_to(B):\n    pass\n",
            "if t.is_relative_to(B) or x:\n    pass\n",
            "if 0 < f(x) < 3:\n    pass\n",
        ] {
            assert!(proved(python(), source).is_empty(), "{source}");
        }
    }

    /// The text of the calls [`calls_false_with`] reads in the condition
    /// of the first `if` of `source` (ticket #268).
    fn proved_when_false(language: tree_sitter::Language, source: &str) -> Vec<String> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("valid grammar");
        let tree = parser.parse(source, None).expect("parsed");
        let mut stack = vec![tree.root_node()];
        let mut condition = None;
        while let Some(node) = stack.pop() {
            if node.kind() == "if_statement" {
                condition = node.child_by_field_name("condition");
                break;
            }
            let mut cursor = node.walk();
            let children: Vec<_> = node.children(&mut cursor).collect();
            stack.extend(children.into_iter().rev());
        }
        let mut calls = Vec::new();
        calls_false_with(condition.expect("an if"), source, &mut calls);
        calls
            .iter()
            .map(|call| source[call.byte_range()].to_string())
            .collect()
    }

    #[test]
    fn test_calls_false_with_reads_negations() {
        let csharp = || tree_sitter_c_sharp::LANGUAGE.into();
        let negated = "class A { void M() { if (!Guid.TryParse(id, out var _)) { id = null; } } }";
        assert_eq!(
            proved_when_false(csharp(), negated),
            ["Guid.TryParse(id, out var _)"]
        );
        let either = "class A { void M() { if (!a.Ok() || !(b.Ok())) { } } }";
        assert_eq!(proved_when_false(csharp(), either), ["a.Ok()", "b.Ok()"]);
        let python = || tree_sitter_python::LANGUAGE.into();
        assert_eq!(
            proved_when_false(python(), "if not t.is_relative_to(B):\n    pass\n"),
            ["t.is_relative_to(B)"]
        );
        // A plain call or a conjunction proves nothing when false.
        assert!(proved_when_false(csharp(), "class A { void M() { if (a.Ok()) { } } }").is_empty());
        assert!(
            proved_when_false(
                csharp(),
                "class A { void M() { if (!a.Ok() && !b.Ok()) { } } }"
            )
            .is_empty()
        );
    }

    /// The text literal arguments that keep a call from proving a check.
    #[test]
    fn test_has_literal_argument() {
        let literal = |language: tree_sitter::Language, source: &str| -> bool {
            let mut parser = tree_sitter::Parser::new();
            parser.set_language(&language).expect("valid grammar");
            let tree = parser.parse(source, None).expect("parsed");
            let mut stack = vec![tree.root_node()];
            while let Some(node) = stack.pop() {
                if CALL_KINDS.contains(&node.kind()) {
                    return has_literal_argument(node);
                }
                let mut cursor = node.walk();
                stack.extend(node.children(&mut cursor).collect::<Vec<_>>());
            }
            panic!("no call in {source}");
        };
        let python = || tree_sitter_python::LANGUAGE.into();
        assert!(literal(python(), "t.startswith('id=')"));
        assert!(literal(python(), "re.match(r'^\\w+$', name)"));
        assert!(literal(python(), "f(x, prefix=f'{a}/')"));
        assert!(!literal(python(), "t.is_relative_to(BASE)"));
        assert!(!literal(python(), "name.isalnum()"));
        let java: tree_sitter::Language = tree_sitter_java::LANGUAGE.into();
        assert!(literal(
            java.clone(),
            "class A { boolean m() { return t.startsWith(\"id=\"); } }"
        ));
        assert!(!literal(
            java,
            "class A { boolean m() { return p.startsWith(base + File.separator); } }"
        ));
        let php: tree_sitter::Language = tree_sitter_php::LANGUAGE_PHP.into();
        assert!(literal(php.clone(), "<?php strpos($t, 'id=');"));
        assert!(!literal(php, "<?php strpos($p, $base);"));
        let csharp: tree_sitter::Language = tree_sitter_c_sharp::LANGUAGE.into();
        assert!(literal(
            csharp.clone(),
            "class A { bool M() { return p.StartsWith(@\"C:\\data\"); } }"
        ));
        assert!(!literal(
            csharp,
            "class A { bool M() { return p.StartsWith(baseDir, StringComparison.Ordinal); } }"
        ));
        let js: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
        assert!(literal(js.clone(), "p.startsWith(`${root}/`)"));
        assert!(!literal(js, "p.startsWith(root + path.sep)"));
    }

    #[test]
    fn test_calls_true_with_brace_languages() {
        let php: tree_sitter::Language = tree_sitter_php::LANGUAGE_PHP.into();
        let php_yoda = "<?php if (0 === strpos($p, $base) && $ok) {}";
        assert_eq!(proved(php.clone(), php_yoda), ["strpos($p, $base)"]);
        let php_word = "<?php if ($o->has($p) and strpos($p, $b) <> false) {}";
        assert_eq!(
            proved(php.clone(), php_word),
            ["$o->has($p)", "strpos($p, $b)"]
        );
        let php_failure = "<?php if (strpos($p, $base) !== 0) {}";
        assert!(proved(php, php_failure).is_empty());

        let java: tree_sitter::Language = tree_sitter_java::LANGUAGE.into();
        let java_check = "class A { void m() { if (p.startsWith(b) == true) {} } }";
        assert_eq!(proved(java.clone(), java_check), ["p.startsWith(b)"]);
        let java_negated = "class A { void m() { if (!p.startsWith(b)) {} } }";
        assert!(proved(java, java_negated).is_empty());

        let js: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
        let js_check = "if (p?.startsWith(b) || x) {}";
        assert!(proved(js.clone(), js_check).is_empty());
        assert_eq!(proved(js, "if (p.startsWith(b)) {}"), ["p.startsWith(b)"]);

        let csharp: tree_sitter::Language = tree_sitter_c_sharp::LANGUAGE.into();
        let cs_true = "class A { void M() { if (p.StartsWith(b) is true) {} } }";
        assert_eq!(proved(csharp.clone(), cs_true), ["p.StartsWith(b)"]);
        let cs_false = "class A { void M() { if (p.StartsWith(b) is false) {} } }";
        assert!(proved(csharp, cs_false).is_empty());
    }
}
