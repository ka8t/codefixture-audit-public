//! Intermediate representation (IR) of the dataflow engine — faithful port
//! of `Audit/sca/dataflow/ir.py`. Normalized 3-address form,
//! independent of the source language (§3 of the Python spec — the
//! Rust scope remains Python-only, Decision #10, but the IR
//! itself is already designed language-neutral on the Python side).

use std::borrow::Cow;

/// Literal constant value (int, str, bool, None, float).
#[derive(Debug, Clone, PartialEq)]
pub enum ConstValue {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    None,
}

/// RHS (Right-Hand Side) — expressions whose value is read.
#[derive(Debug, Clone, PartialEq)]
pub enum Rhs {
    Const(ConstValue),
    VarRef(String),
    AttrRef {
        base: Box<Rhs>,
        attr: String,
    },
    SubscriptRef {
        base: Box<Rhs>,
        key: Box<Rhs>,
    },
    /// Call used as a value.
    CallRef {
        callee: Box<Rhs>,
        args: Vec<Rhs>,
        kwargs: Vec<(String, Rhs)>,
    },
    BinOp {
        op: String,
        left: Box<Rhs>,
        right: Box<Rhs>,
    },
    UnaryOp {
        op: String,
        operand: Box<Rhs>,
    },
    Cmp {
        op: String,
        left: Box<Rhs>,
        right: Box<Rhs>,
    },
    /// Short-circuited boolean operation: and/or.
    Bool {
        op: String,
        operands: Vec<Rhs>,
    },
    TupleRef(Vec<Rhs>),
    ListRef(Vec<Rhs>),
    DictRef(Vec<(Rhs, Rhs)>),
    SetRef(Vec<Rhs>),
    /// Lambda — opaque (the body is handled separately, out of scope here).
    LambdaRef {
        arg_names: Vec<String>,
    },
    /// Starred argument: *args or **kwargs (on the call side).
    Star {
        inner: Box<Rhs>,
        double: bool,
    },
    /// Ternary expression: `then if cond else orelse`. Kept as a
    /// distinct node (not desugared into `Bool`) so constant
    /// propagation can mark a branch as dead.
    IfExp {
        cond: Box<Rhs>,
        then: Box<Rhs>,
        orelse: Box<Rhs>,
    },
    /// An expression the lowering does not model (a C# `x is not null`
    /// pattern, a Python comprehension, a malformed node): it carries no
    /// taint and has no known value. Ticket #253, deliberate deviation
    /// from the Audit, whose lowerings return `Const(None)` here: the
    /// constant pass (§9) then read the condition `if (user is not null)`
    /// as `None`, always false, marked the TRUE edge dead, and the body of
    /// the `if` was never analysed.
    Opaque,
}

/// LHS (Left-Hand Side) — assignable locations.
#[derive(Debug, Clone, PartialEq)]
pub enum Lhs {
    VarLhs(String),
    AttrLhs {
        base: Box<Rhs>,
        attr: String,
    },
    SubscriptLhs {
        base: Box<Rhs>,
        key: Box<Rhs>,
    },
    /// Tuple target: `a, b = ...` (destructuring).
    TupleLhs(Vec<Lhs>),
    /// Starred target in a destructuring: `*rest = ...`.
    StarLhs(Box<Lhs>),
}

/// Statement IR.
#[derive(Debug, Clone, PartialEq)]
pub enum IrStmt {
    /// `lhs := rhs` — the fundamental dataflow statement.
    Assign {
        lhs: Lhs,
        rhs: Rhs,
        lineno: usize,
    },
    /// Call used as a statement (return value not captured).
    Call {
        callee: Rhs,
        args: Vec<Rhs>,
        kwargs: Vec<(String, Rhs)>,
        lineno: usize,
    },
    Return {
        value: Option<Rhs>,
        lineno: usize,
    },
    Raise {
        value: Option<Rhs>,
        lineno: usize,
    },
    /// Condition of a branch (if, while...) — present only
    /// in CFG Branch/Loop nodes, never in the linear flow
    /// of a Basic block.
    Branch {
        condition: Rhs,
        lineno: usize,
    },
    /// No-op (for `pass` and ignored statements).
    Noop {
        lineno: usize,
    },
}

// ============================================================================
// Canonicalization — state keys for the dataflow (spec §4.4)
// ============================================================================

/// Converts an LHS into its canonical key for the dataflow state. A
/// sub-attribute/subscript access with a non-constant key is aggregated
/// under `[*]`.
///
/// The `canon_*` functions write the whole key into one `String`
/// (ticket #241): the analysis builds these keys at every evaluation of
/// an expression, and the former recursive `format!` allocated one
/// string per level of `a.b.c`, a seventh of the allocations of a Java
/// scan. `canon_rhs` and `canon_callee` lend the name of a plain variable
/// instead of copying it. The text is the same;
/// `test_canon_writers_match_the_former_format` keeps the former functions
/// as the oracle.
pub fn canon_lhs(lhs: &Lhs) -> String {
    let mut out = String::new();
    write_canon_lhs(lhs, &mut out);
    out
}

fn write_canon_lhs(lhs: &Lhs, out: &mut String) {
    match lhs {
        Lhs::VarLhs(name) => out.push_str(name),
        Lhs::AttrLhs { base, attr } => {
            write_canon_rhs(base, out);
            out.push('.');
            out.push_str(attr);
        }
        Lhs::SubscriptLhs { base, key } => {
            write_canon_rhs(base, out);
            write_subscript_key(key, out);
        }
        Lhs::TupleLhs(elements) => {
            out.push('(');
            for (i, element) in elements.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_canon_lhs(element, out);
            }
            out.push(')');
        }
        Lhs::StarLhs(inner) => {
            out.push('*');
            write_canon_lhs(inner, out);
        }
    }
}

/// Converts an RHS into a canonical string, used to build the
/// state keys.
pub fn canon_rhs(rhs: &Rhs) -> Cow<'_, str> {
    if let Rhs::VarRef(name) = rhs {
        return Cow::Borrowed(name);
    }
    let mut out = String::new();
    write_canon_rhs(rhs, &mut out);
    Cow::Owned(out)
}

fn write_canon_rhs(rhs: &Rhs, out: &mut String) {
    match rhs {
        Rhs::VarRef(name) => out.push_str(name),
        Rhs::AttrRef { base, attr } => {
            write_canon_rhs(base, out);
            out.push('.');
            out.push_str(attr);
        }
        Rhs::SubscriptRef { base, key } => {
            write_canon_rhs(base, out);
            write_subscript_key(key, out);
        }
        Rhs::Const(v) => out.push_str(&repr_const(v)),
        // For the other RHS types, no canonical key is possible
        // (they are not lvalues) — a readable representation is
        // returned instead.
        other => {
            out.push('<');
            out.push_str(rhs_variant_name(other));
            out.push('>');
        }
    }
}

/// `[<key>]` of a subscript, as [`canon_subscript_key`] writes the key.
fn write_subscript_key(key: &Rhs, out: &mut String) {
    out.push('[');
    match key {
        Rhs::Const(v) => out.push_str(&repr_const(v)),
        _ => out.push('*'),
    }
    out.push(']');
}

/// `pub(super)`: reused by `transfer.rs::_key_repr` (same
/// convention for the canonical representation of an indexed access key).
pub(super) fn canon_subscript_key(key: &Rhs) -> String {
    match key {
        Rhs::Const(v) => repr_const(v),
        _ => "*".to_string(),
    }
}

/// Converts a callee expression into a dotted name, for resolving
/// the specs (source/sink/sanitizer, §7.1).
pub fn canon_callee(rhs: &Rhs) -> Cow<'_, str> {
    if let Rhs::VarRef(name) = rhs {
        return Cow::Borrowed(name);
    }
    let mut out = String::new();
    write_canon_callee(rhs, &mut out);
    Cow::Owned(out)
}

fn write_canon_callee(rhs: &Rhs, out: &mut String) {
    match rhs {
        Rhs::VarRef(name) => out.push_str(name),
        Rhs::AttrRef { base, attr } => {
            write_canon_callee(base, out);
            out.push('.');
            out.push_str(attr);
        }
        Rhs::CallRef { .. } => out.push_str("<call>"),
        Rhs::SubscriptRef { base, key } => {
            write_canon_callee(base, out);
            write_subscript_key(key, out);
        }
        _ => out.push_str("<unknown>"),
    }
}

/// Equivalent of Python's `repr(value)` for a constant — used
/// as a canonical key (e.g. `repr(0)` = `"0"`, `repr("a")` = `"'a'"`).
fn repr_const(v: &ConstValue) -> String {
    match v {
        ConstValue::Int(i) => i.to_string(),
        ConstValue::Float(f) => f.to_string(),
        ConstValue::Str(s) => format!("'{s}'"),
        ConstValue::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        ConstValue::None => "None".to_string(),
    }
}

fn rhs_variant_name(rhs: &Rhs) -> &'static str {
    match rhs {
        Rhs::Const(_) => "Const",
        Rhs::VarRef(_) => "VarRef",
        Rhs::AttrRef { .. } => "AttrRef",
        Rhs::SubscriptRef { .. } => "SubscriptRef",
        Rhs::CallRef { .. } => "CallRef",
        Rhs::BinOp { .. } => "BinOp",
        Rhs::UnaryOp { .. } => "UnaryOp",
        Rhs::Cmp { .. } => "Cmp",
        Rhs::Bool { .. } => "Bool",
        Rhs::TupleRef(_) => "TupleRef",
        Rhs::ListRef(_) => "ListRef",
        Rhs::DictRef(_) => "DictRef",
        Rhs::SetRef(_) => "SetRef",
        Rhs::LambdaRef { .. } => "LambdaRef",
        Rhs::Star { .. } => "Star",
        Rhs::IfExp { .. } => "IfExp",
        Rhs::Opaque => "Opaque",
    }
}

// ============================================================================
// Readable display (debug)
// ============================================================================

pub fn pretty_rhs(rhs: &Rhs) -> String {
    match rhs {
        Rhs::Const(v) => repr_const(v),
        Rhs::Opaque => "<opaque>".to_string(),
        Rhs::VarRef(name) => name.clone(),
        Rhs::AttrRef { base, attr } => format!("{}.{attr}", pretty_rhs(base)),
        Rhs::SubscriptRef { base, key } => format!("{}[{}]", pretty_rhs(base), pretty_rhs(key)),
        Rhs::CallRef {
            callee,
            args,
            kwargs,
        } => {
            let mut parts: Vec<String> = args.iter().map(pretty_rhs).collect();
            parts.extend(kwargs.iter().map(|(n, v)| format!("{n}={}", pretty_rhs(v))));
            format!("{}({})", pretty_rhs(callee), parts.join(", "))
        }
        Rhs::BinOp { op, left, right } => {
            format!("({} {op} {})", pretty_rhs(left), pretty_rhs(right))
        }
        Rhs::UnaryOp { op, operand } => format!("({op}{})", pretty_rhs(operand)),
        Rhs::Cmp { op, left, right } => {
            format!("({} {op} {})", pretty_rhs(left), pretty_rhs(right))
        }
        Rhs::Bool { op, operands } => {
            format!(
                "({})",
                operands
                    .iter()
                    .map(pretty_rhs)
                    .collect::<Vec<_>>()
                    .join(&format!(" {op} "))
            )
        }
        Rhs::TupleRef(elements) => format!(
            "({},)",
            elements
                .iter()
                .map(pretty_rhs)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Rhs::ListRef(elements) => format!(
            "[{}]",
            elements
                .iter()
                .map(pretty_rhs)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Rhs::DictRef(items) => {
            let rendered: Vec<String> = items
                .iter()
                .map(|(k, v)| format!("{}: {}", pretty_rhs(k), pretty_rhs(v)))
                .collect();
            format!("{{{}}}", rendered.join(", "))
        }
        Rhs::SetRef(elements) => format!(
            "{{{}}}",
            elements
                .iter()
                .map(pretty_rhs)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Rhs::LambdaRef { arg_names } => format!("lambda {}: ...", arg_names.join(", ")),
        Rhs::Star { inner, double } => {
            format!("{}{}", if *double { "**" } else { "*" }, pretty_rhs(inner))
        }
        Rhs::IfExp { cond, then, orelse } => {
            format!(
                "({} if {} else {})",
                pretty_rhs(then),
                pretty_rhs(cond),
                pretty_rhs(orelse)
            )
        }
    }
}

pub fn pretty_lhs(lhs: &Lhs) -> String {
    match lhs {
        Lhs::VarLhs(name) => name.clone(),
        Lhs::AttrLhs { base, attr } => format!("{}.{attr}", pretty_rhs(base)),
        Lhs::SubscriptLhs { base, key } => format!("{}[{}]", pretty_rhs(base), pretty_rhs(key)),
        Lhs::TupleLhs(elements) => {
            format!(
                "({})",
                elements
                    .iter()
                    .map(pretty_lhs)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        Lhs::StarLhs(inner) => format!("*{}", pretty_lhs(inner)),
    }
}

pub fn pretty_stmt(stmt: &IrStmt) -> String {
    match stmt {
        IrStmt::Assign { lhs, rhs, .. } => format!("{} := {}", pretty_lhs(lhs), pretty_rhs(rhs)),
        IrStmt::Call {
            callee,
            args,
            kwargs,
            ..
        } => {
            let mut parts: Vec<String> = args.iter().map(pretty_rhs).collect();
            parts.extend(kwargs.iter().map(|(n, v)| format!("{n}={}", pretty_rhs(v))));
            format!("{}({})", pretty_rhs(callee), parts.join(", "))
        }
        IrStmt::Return { value, .. } => match value {
            Some(v) => format!("return {}", pretty_rhs(v)),
            None => "return".to_string(),
        },
        IrStmt::Raise { value, .. } => match value {
            Some(v) => format!("raise {}", pretty_rhs(v)),
            None => "raise".to_string(),
        },
        IrStmt::Branch { condition, .. } => format!("branch {}", pretty_rhs(condition)),
        IrStmt::Noop { .. } => "noop".to_string(),
    }
}

pub fn pretty_stmts(stmts: &[IrStmt]) -> String {
    stmts.iter().map(pretty_stmt).collect::<Vec<_>>().join("\n")
}

/// One of `values`, without knowing which: a chain of `IfExp` whose
/// conditions are [`Rhs::Opaque`]. It carries the taint of every value
/// (an `IfExp` joins its branches) and has no known value, so the
/// constant pass cannot read it as one of them (a tuple would be read as
/// always true). For a Java `switch` expression (ticket #255).
pub fn one_of(mut values: Vec<Rhs>) -> Rhs {
    let Some(mut acc) = values.pop() else {
        return Rhs::Opaque;
    };
    while let Some(value) = values.pop() {
        acc = Rhs::IfExp {
            cond: Box::new(Rhs::Opaque),
            then: Box::new(value),
            orelse: Box::new(acc),
        };
    }
    acc
}

/// The named children of a syntax node, without the comments.
///
/// Tree-sitter can attach a comment (an "extra" node) between any two
/// tokens: `f(a /* note */, b)` or `( /* note */ $x)`. Read by position,
/// such a comment became an argument of its own, shifting the arguments
/// after it, or replaced the only operand of a parenthesis, and the
/// lowering turned it into an expression it does not model. Every
/// lowering reads the children of a node through this function (ticket
/// #255).
pub fn named_children<'tree>(
    node: tree_sitter::Node<'tree>,
) -> std::vec::IntoIter<tree_sitter::Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !child.is_extra())
        .collect::<Vec<_>>()
        .into_iter()
}

#[cfg(test)]
mod tests {

    /// Ticket #255: a comment is never a child of an expression, in any
    /// grammar; the children keep their order.
    #[test]
    fn test_named_children_skip_comments() {
        let read = |language: tree_sitter::Language, source: &str, kind: &str| -> Vec<String> {
            let mut parser = tree_sitter::Parser::new();
            parser.set_language(&language).expect("valid grammar");
            let tree = parser.parse(source, None).expect("parsed");
            let mut stack = vec![tree.root_node()];
            while let Some(node) = stack.pop() {
                if node.kind() == kind {
                    return named_children(node)
                        .map(|child| source[child.byte_range()].to_string())
                        .collect();
                }
                let mut cursor = node.walk();
                stack.extend(node.children(&mut cursor).collect::<Vec<_>>());
            }
            panic!("no {kind} in {source}");
        };
        let java: tree_sitter::Language = tree_sitter_java::LANGUAGE.into();
        let source = "class A { void m() { f(a /* note */, b); } }";
        assert_eq!(read(java, source, "argument_list"), ["a", "b"]);
        let php: tree_sitter::Language = tree_sitter_php::LANGUAGE_PHP.into();
        assert_eq!(
            read(
                php,
                "<?php $x = ( /* note */ $y);",
                "parenthesized_expression"
            ),
            ["$y"]
        );
        let python: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
        let source = "x = (  # note\n    y\n)\n";
        assert_eq!(read(python, source, "parenthesized_expression"), ["y"]);
    }

    /// Ticket #255: one of several values joins their taint through `IfExp`
    /// branches whose condition has no known value.
    #[test]
    fn test_one_of() {
        assert_eq!(one_of(Vec::new()), Rhs::Opaque);
        let a = Rhs::VarRef("a".to_string());
        assert_eq!(one_of(vec![a.clone()]), a);
        let b = Rhs::VarRef("b".to_string());
        let c = Rhs::VarRef("c".to_string());
        assert_eq!(
            one_of(vec![a.clone(), b.clone(), c.clone()]),
            Rhs::IfExp {
                cond: Box::new(Rhs::Opaque),
                then: Box::new(a),
                orelse: Box::new(Rhs::IfExp {
                    cond: Box::new(Rhs::Opaque),
                    then: Box::new(b),
                    orelse: Box::new(c),
                }),
            }
        );
    }

    use super::*;

    // Ticket #241: the canonical names as the former recursive `format!`
    // wrote them, the oracle of the writers.
    fn former_canon_lhs(lhs: &Lhs) -> String {
        match lhs {
            Lhs::VarLhs(name) => name.clone(),
            Lhs::AttrLhs { base, attr } => format!("{}.{attr}", former_canon_rhs(base)),
            Lhs::SubscriptLhs { base, key } => {
                format!(
                    "{}[{}]",
                    former_canon_rhs(base),
                    former_canon_subscript_key(key)
                )
            }
            Lhs::TupleLhs(elements) => {
                format!(
                    "({})",
                    elements
                        .iter()
                        .map(former_canon_lhs)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Lhs::StarLhs(inner) => format!("*{}", former_canon_lhs(inner)),
        }
    }

    fn former_canon_rhs(rhs: &Rhs) -> String {
        match rhs {
            Rhs::VarRef(name) => name.clone(),
            Rhs::AttrRef { base, attr } => format!("{}.{attr}", former_canon_rhs(base)),
            Rhs::SubscriptRef { base, key } => {
                format!(
                    "{}[{}]",
                    former_canon_rhs(base),
                    former_canon_subscript_key(key)
                )
            }
            Rhs::Const(v) => repr_const(v),
            // For the other RHS types, no canonical key is possible
            // (they are not lvalues) — a readable representation is
            // returned instead.
            other => format!("<{}>", rhs_variant_name(other)),
        }
    }

    fn former_canon_subscript_key(key: &Rhs) -> String {
        match key {
            Rhs::Const(v) => repr_const(v),
            _ => "*".to_string(),
        }
    }

    fn former_canon_callee(rhs: &Rhs) -> String {
        match rhs {
            Rhs::VarRef(name) => name.clone(),
            Rhs::AttrRef { base, attr } => format!("{}.{attr}", former_canon_callee(base)),
            Rhs::CallRef { .. } => "<call>".to_string(),
            Rhs::SubscriptRef { base, key } => {
                format!(
                    "{}[{}]",
                    former_canon_callee(base),
                    former_canon_subscript_key(key)
                )
            }
            _ => "<unknown>".to_string(),
        }
    }

    #[test]
    fn test_canon_writers_match_the_former_format() {
        let var = |n: &str| Rhs::VarRef(n.to_string());
        let attr = |b: Rhs, a: &str| Rhs::AttrRef {
            base: Box::new(b),
            attr: a.to_string(),
        };
        let sub = |b: Rhs, k: Rhs| Rhs::SubscriptRef {
            base: Box::new(b),
            key: Box::new(k),
        };
        let call = |c: Rhs| Rhs::CallRef {
            callee: Box::new(c),
            args: vec![],
            kwargs: vec![],
        };
        let rhs = vec![
            var("x"),
            attr(attr(var("request"), "GET"), "get"),
            sub(
                attr(var("obj"), "items"),
                Rhs::Const(ConstValue::Str("k".into())),
            ),
            sub(var("a"), Rhs::Const(ConstValue::Int(3))),
            sub(sub(var("m"), var("i")), Rhs::Const(ConstValue::Bool(true))),
            attr(call(attr(var("db"), "cursor")), "execute"),
            attr(sub(var("é"), Rhs::Const(ConstValue::None)), "ü"),
            Rhs::Const(ConstValue::Float(1.5)),
            Rhs::TupleRef(vec![]),
            attr(Rhs::ListRef(vec![]), "pop"),
            call(var("f")),
        ];
        for r in &rhs {
            assert_eq!(canon_rhs(r), former_canon_rhs(r), "{r:?}");
            assert_eq!(canon_callee(r), former_canon_callee(r), "{r:?}");
        }
        let mut lhs = vec![
            Lhs::VarLhs("y".into()),
            Lhs::TupleLhs(vec![]),
            Lhs::StarLhs(Box::new(Lhs::VarLhs("rest".into()))),
        ];
        for r in &rhs {
            lhs.push(Lhs::AttrLhs {
                base: Box::new(r.clone()),
                attr: "z".into(),
            });
            lhs.push(Lhs::SubscriptLhs {
                base: Box::new(r.clone()),
                key: Box::new(r.clone()),
            });
        }
        lhs.push(Lhs::TupleLhs(lhs.clone()));
        lhs.push(Lhs::StarLhs(Box::new(Lhs::TupleLhs(vec![
            Lhs::VarLhs("a".into()),
            Lhs::VarLhs("b".into()),
        ]))));
        for l in &lhs {
            assert_eq!(canon_lhs(l), former_canon_lhs(l), "{l:?}");
        }
    }

    fn var(name: &str) -> Rhs {
        Rhs::VarRef(name.to_string())
    }

    #[test]
    fn test_canon_lhs_simple_var() {
        assert_eq!(canon_lhs(&Lhs::VarLhs("x".to_string())), "x");
    }

    #[test]
    fn test_canon_lhs_attr_chain() {
        let lhs = Lhs::AttrLhs {
            base: Box::new(Rhs::AttrRef {
                base: Box::new(var("a")),
                attr: "b".to_string(),
            }),
            attr: "c".to_string(),
        };
        assert_eq!(canon_lhs(&lhs), "a.b.c");
    }

    #[test]
    fn test_canon_lhs_subscript_const_key() {
        let lhs = Lhs::SubscriptLhs {
            base: Box::new(var("a")),
            key: Box::new(Rhs::Const(ConstValue::Int(0))),
        };
        assert_eq!(canon_lhs(&lhs), "a[0]");
    }

    #[test]
    fn test_canon_lhs_subscript_dynamic_key_is_star() {
        let lhs = Lhs::SubscriptLhs {
            base: Box::new(var("a")),
            key: Box::new(var("k")),
        };
        assert_eq!(canon_lhs(&lhs), "a[*]");
    }

    #[test]
    fn test_canon_rhs_opaque_binop() {
        let rhs = Rhs::BinOp {
            op: "+".to_string(),
            left: Box::new(var("a")),
            right: Box::new(var("b")),
        };
        assert_eq!(canon_rhs(&rhs), "<BinOp>");
    }

    #[test]
    fn test_canon_callee_dotted_name() {
        let rhs = Rhs::AttrRef {
            base: Box::new(Rhs::AttrRef {
                base: Box::new(var("subprocess")),
                attr: "run".to_string(),
            }),
            attr: "extra".to_string(),
        };
        assert_eq!(canon_callee(&rhs), "subprocess.run.extra");
    }

    #[test]
    fn test_canon_callee_call_is_call_marker() {
        let rhs = Rhs::CallRef {
            callee: Box::new(var("f")),
            args: vec![],
            kwargs: vec![],
        };
        assert_eq!(canon_callee(&rhs), "<call>");
    }

    #[test]
    fn test_pretty_rhs_call_with_args_and_kwargs() {
        let rhs = Rhs::CallRef {
            callee: Box::new(var("f")),
            args: vec![Rhs::Const(ConstValue::Int(1))],
            kwargs: vec![("x".to_string(), Rhs::Const(ConstValue::Bool(true)))],
        };
        assert_eq!(pretty_rhs(&rhs), "f(1, x=True)");
    }

    #[test]
    fn test_pretty_stmt_assign() {
        let stmt = IrStmt::Assign {
            lhs: Lhs::VarLhs("x".to_string()),
            rhs: Rhs::Const(ConstValue::Int(42)),
            lineno: 1,
        };
        assert_eq!(pretty_stmt(&stmt), "x := 42");
    }

    #[test]
    fn test_pretty_stmt_return_none() {
        let stmt = IrStmt::Return {
            value: None,
            lineno: 1,
        };
        assert_eq!(pretty_stmt(&stmt), "return");
    }

    #[test]
    fn test_pretty_ifexp() {
        let rhs = Rhs::IfExp {
            cond: Box::new(var("c")),
            then: Box::new(Rhs::Const(ConstValue::Int(1))),
            orelse: Box::new(Rhs::Const(ConstValue::Int(2))),
        };
        assert_eq!(pretty_rhs(&rhs), "(1 if c else 2)");
    }
}
