//! `tree-sitter-c-sharp` → IR lowering — mirrors `java_lowering.rs`,
//! a faithful port of `Audit/sca/parsers/csharp_to_ir.py` (ticket #79, spec
//! #77). Same template as `java_lowering.rs`: temporaries
//! `__t0, __t1, ...`, three-address linearization, same shared,
//! language-neutral IR (`ir.rs`).
//!
//! **Scope difference vs `lowering.rs`/`java_lowering.rs`**:
//! this module lowers ONLY the statements that
//! `csharp_cfg.rs::CSharpCfgBuilder` actually stores in a CFG
//! (control-flow graph) node (`Basic`/`Finally`/`RaiseSite` `.statements`, or
//! the condition of a `Branch`/`Loop`) — if/while/do/for/foreach/try/switch/break/
//! continue are entirely intercepted by the CFG builder and
//! never land in a `.statements` list.
//!
//! Tree-sitter node shapes verified empirically (real parsing
//! with `tree-sitter-c-sharp` 0.23.5, never assumed from the
//! Java grammar nor blindly copied from the Python docstring — an
//! actual deviation was in fact found and fixed, see below):
//!   - `variable_declarator` does NOT expose a named `value` field —
//!     the initializer, if present, is the SECOND named child
//!     (`[name]` alone if absent).
//!   - `prefix_unary_expression`/`postfix_unary_expression` are two
//!     DISTINCT types (unlike Java's single `update_expression`,
//!     which also covers unary `-`/`!` via a separate
//!     `unary_expression`) — this grammar has NO `unary_expression` type:
//!     `-x`/`!x`/`~x`/`++x`/`--x` are all `prefix_unary_expression`,
//!     `x++`/`x--` are `postfix_unary_expression`. Neither
//!     exposes a field name — operator/operand distinguished by
//!     position (operator first for prefix, last for
//!     postfix); a single named child (the operand) in both cases.
//!   - `invocation_expression` has `function`/`arguments` fields (not
//!     Java's separate `object`+`name` fields) — the receiver,
//!     if present, is itself a nested `member_access_expression`
//!     reached via `function`, never split off at the call level.
//!   - Each element of an `argument_list` is wrapped in an
//!     `argument` node (unlike Java, whose `argument_list` named
//!     children ARE directly the expressions) — unwrapped
//!     to its single named child.
//!   - `string_literal` fragments are typed
//!     `string_literal_content` (not Java's `string_fragment`);
//!     `character_literal` likewise wraps a
//!     `character_literal_content`. `verbatim_string_literal` (`@"..."`)
//!     is a LEAF with no child — text sliced directly.
//!   - `interpolated_string_expression` (`$"...{expr}..."`, with no
//!     Java equivalent) mixes `string_content` children (literal
//!     text) and `interpolation` children (each wrapping the nested
//!     expression as its single named child, between two anonymous
//!     `interpolation_brace` tokens) — lowered into a chain of
//!     `BinOp("+", ...)` over strings so that the taint of every
//!     `{expr}` propagates to the result, just like ordinary
//!     string concatenation.
//!   - `element_access_expression`: **actual deviation from the Python
//!     docstring** (which handles it via positional/by-type scanning, for
//!     lack of named fields in its grammar version) — this version of
//!     the crate (`tree-sitter-c-sharp` 0.23.5) does expose named
//!     fields `expression`/`subscript` (verified by a real dump of
//!     the tree), used directly here rather than reproducing the
//!     now-unnecessary positional workaround.
//!   - `conditional_access_expression` (`x?.y`/`x?.y()`, the
//!     null-conditional operator, with no Java equivalent): `condition` field for
//!     the base (verified as named, unlike a positional scan),
//!     nested `member_binding_expression` (no field name, scanned by
//!     type) wrapping the `.name` part the same way
//!     `member_access_expression` wraps `name`. Treated as an
//!     ordinary member access for taint purposes — the `?.` short-circuit
//!     itself carries no information relevant to this engine.
//!   - `object_creation_expression` exposes `type`/`arguments`/
//!     `initializer` fields; the `initializer` (`{ Domain = d }`, no Java
//!     equivalent) is an `initializer_expression` whose elements are
//!     `assignment_expression`s (object initializer), plain expressions or
//!     nested `initializer_expression`s (collection initializer). Its
//!     values become arguments of the constructor call — a deviation from
//!     the Python source, which drops them (ticket #268, see
//!     `lower_initializer_values`).
//!   - `cast_expression` exposes `type`/`value` fields (like Java).
//!   - `is_expression` (`x is Foo`, the `instanceof` equivalent) exposes
//!     `left`/`right` fields (same naming as Java's
//!     `instanceof_expression` despite the different node name).
//!   - `conditional_expression` (ternary, NOT Java's `ternary_expression`)
//!     exposes `condition`/`consequence`/
//!     `alternative` fields, as in Java.
//!   - `lambda_expression`: `parameters` field is either a `parameter_list`
//!     (typed/parenthesized form) or an `implicit_parameter` (bare
//!     single-identifier form, `p => p`) — the latter has no
//!     Java equivalent (which uses a bare `identifier`).

use super::cfg::{Cfg, NodeKind};
use super::ir::{ConstValue, IrStmt, Lhs, Rhs, named_children};
use std::collections::BTreeMap;
use tree_sitter::Node;

const CMP_OPS: [&str; 6] = ["==", "!=", "<", "<=", ">", ">="];

fn bool_op_name(op: &str) -> Option<&'static str> {
    match op {
        "&&" => Some("and"),
        "||" => Some("or"),
        _ => None,
    }
}

const LITERAL_KINDS: [&str; 2] = ["integer_literal", "real_literal"];

pub struct CSharpLowerer<'src> {
    source: &'src [u8],
    output: Vec<IrStmt>,
    temp_counter: u32,
}

impl<'src> CSharpLowerer<'src> {
    pub fn new(source: &'src [u8]) -> Self {
        CSharpLowerer {
            source,
            output: Vec::new(),
            temp_counter: 0,
        }
    }

    fn fresh_temp(&mut self) -> String {
        let name = format!("__t{}", self.temp_counter);
        self.temp_counter += 1;
        name
    }

    fn emit(&mut self, stmt: IrStmt) {
        self.output.push(stmt);
    }

    fn text(&self, node: Node<'src>) -> String {
        node.utf8_text(self.source).unwrap_or("").to_string()
    }

    fn line(&self, node: Node<'src>) -> usize {
        node.start_position().row + 1
    }

    // ------------------------------------------------------------ RHS

    /// Lowers a C# expression into a canonical `Rhs`, emitting
    /// any necessary intermediate statements along the way.
    pub fn lower_expr(&mut self, expr: Option<Node<'src>>) -> Rhs {
        let Some(expr) = expr else {
            return Rhs::Const(ConstValue::None);
        };
        let t = expr.kind();

        if t == "identifier" || t == "this" || t == "base" {
            return Rhs::VarRef(self.text(expr));
        }

        if LITERAL_KINDS.contains(&t) {
            return Rhs::Const(parse_csharp_numeric(&self.text(expr)));
        }

        if t == "string_literal" {
            return Rhs::Const(ConstValue::Str(self.string_literal_value(expr)));
        }

        if t == "verbatim_string_literal" {
            // Leaf with no child — strip the `@"` prefix/`"` suffix and
            // unescape doubled quotes (`""` -> `"`, the only
            // escape mechanism for this literal form).
            let raw = self.text(expr);
            let inner =
                if let Some(stripped) = raw.strip_prefix("@\"").and_then(|s| s.strip_suffix('"')) {
                    stripped
                } else {
                    raw.as_str()
                };
            return Rhs::Const(ConstValue::Str(inner.replace("\"\"", "\"")));
        }

        if t == "character_literal" {
            let mut w = expr.walk();
            let content = expr
                .children(&mut w)
                .find(|c| c.kind() == "character_literal_content");
            let value = content.map(|c| self.text(c)).unwrap_or_default();
            return Rhs::Const(ConstValue::Str(value));
        }

        if t == "boolean_literal" {
            return Rhs::Const(ConstValue::Bool(self.text(expr) == "true"));
        }
        if t == "null_literal" {
            return Rhs::Const(ConstValue::None);
        }

        if t == "interpolated_string_expression" {
            return self.lower_interpolated_string(expr);
        }

        if t == "parenthesized_expression" {
            let inner = named_children(expr).next();
            return self.lower_expr(inner);
        }

        if t == "member_access_expression" {
            let base = self.lower_expr(expr.child_by_field_name("expression"));
            let attr = expr
                .child_by_field_name("name")
                .map(|f| self.text(f))
                .unwrap_or_else(|| "?".to_string());
            return Rhs::AttrRef {
                base: Box::new(base),
                attr,
            };
        }

        if t == "conditional_access_expression" {
            let base = self.lower_expr(expr.child_by_field_name("condition"));
            let mut w = expr.walk();
            let binding = expr
                .children(&mut w)
                .find(|c| c.kind() == "member_binding_expression");
            if let Some(binding) = binding {
                let attr = binding
                    .child_by_field_name("name")
                    .map(|f| self.text(f))
                    .unwrap_or_else(|| "?".to_string());
                return Rhs::AttrRef {
                    base: Box::new(base),
                    attr,
                };
            }
            return base;
        }

        if t == "element_access_expression" {
            let base = self.lower_expr(expr.child_by_field_name("expression"));
            let key = self.lower_bracketed_argument(expr.child_by_field_name("subscript"));
            return Rhs::SubscriptRef {
                base: Box::new(base),
                key: Box::new(key),
            };
        }

        if t == "invocation_expression" {
            return self.lower_invocation(expr);
        }

        if t == "object_creation_expression" {
            let type_node = expr.child_by_field_name("type");
            let mut args = self.lower_arg_list(expr.child_by_field_name("arguments"));
            // `new CookieOptions { Domain = d }`: the values of the object
            // initializer are arguments of the constructor, after its own
            // (see `lower_initializer_values`).
            if let Some(init) = expr.child_by_field_name("initializer") {
                args.extend(self.lower_initializer_values(init));
            }
            let callee = self.type_to_rhs(type_node);
            let tmp = self.fresh_temp();
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(tmp.clone()),
                rhs: Rhs::CallRef {
                    callee: Box::new(callee),
                    args,
                    kwargs: Vec::new(),
                },
                lineno: self.line(expr),
            });
            return Rhs::VarRef(tmp);
        }

        if t == "array_creation_expression" || t == "implicit_array_creation_expression" {
            let mut w = expr.walk();
            let init = expr
                .children(&mut w)
                .find(|c| c.kind() == "initializer_expression");
            return match init {
                Some(i) => self.lower_expr(Some(i)),
                None => Rhs::ListRef(Vec::new()),
            };
        }

        if t == "initializer_expression" {
            let elements: Vec<Rhs> = named_children(expr)
                .map(|e| self.lower_expr(Some(e)))
                .collect();
            return Rhs::ListRef(elements);
        }

        if t == "cast_expression" {
            return self.lower_expr(expr.child_by_field_name("value"));
        }

        if t == "conditional_expression" {
            let cond = self.lower_expr(expr.child_by_field_name("condition"));
            let then = self.lower_expr(expr.child_by_field_name("consequence"));
            let orelse = self.lower_expr(expr.child_by_field_name("alternative"));
            let tmp = self.fresh_temp();
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(tmp.clone()),
                rhs: Rhs::IfExp {
                    cond: Box::new(cond),
                    then: Box::new(then),
                    orelse: Box::new(orelse),
                },
                lineno: self.line(expr),
            });
            return Rhs::VarRef(tmp);
        }

        if t == "lambda_expression" {
            let params = expr.child_by_field_name("parameters");
            return Rhs::LambdaRef {
                arg_names: self.lambda_param_names(params),
            };
        }

        if t == "anonymous_method_expression" {
            // `delegate(int x) { ... }` — legacy pre-lambda syntax,
            // rare. Opaque: no value-producing form is modeled
            // here.
            return Rhs::LambdaRef {
                arg_names: Vec::new(),
            };
        }

        if t == "binary_expression" {
            let op = self.binary_op_text(expr);
            let left = self.lower_expr(expr.child_by_field_name("left"));
            let right = self.lower_expr(expr.child_by_field_name("right"));
            let tmp = self.fresh_temp();
            let rhs = if let Some(bool_op) = bool_op_name(&op) {
                Rhs::Bool {
                    op: bool_op.to_string(),
                    operands: vec![left, right],
                }
            } else if CMP_OPS.contains(&op.as_str()) {
                Rhs::Cmp {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                }
            } else {
                // Covers arithmetic/bitwise operators AND `??`
                // (null coalescing) — the latter has no dedicated IR
                // form, but BinOp already propagates the taint of both
                // operands unconditionally, which is exactly the
                // correct over-approximation for `a ?? b` (the result
                // is one operand or the other depending on execution).
                Rhs::BinOp {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                }
            };
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(tmp.clone()),
                rhs,
                lineno: self.line(expr),
            });
            return Rhs::VarRef(tmp);
        }

        if t == "prefix_unary_expression" {
            return self.lower_prefix_unary(expr);
        }

        if t == "postfix_unary_expression" {
            return self.lower_postfix_unary(expr);
        }

        if t == "is_expression" {
            let left = self.lower_expr(expr.child_by_field_name("left"));
            let type_text = expr
                .child_by_field_name("right")
                .map(|n| self.text(n))
                .unwrap_or_else(|| "?".to_string());
            let tmp = self.fresh_temp();
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(tmp.clone()),
                rhs: Rhs::Cmp {
                    op: "instanceof".to_string(),
                    left: Box::new(left),
                    right: Box::new(Rhs::Const(ConstValue::Str(type_text))),
                },
                lineno: self.line(expr),
            });
            return Rhs::VarRef(tmp);
        }

        // Ticket #255: the forms below used to fall to the fallback and
        // lose the taint of their operands (inventory of the corpus, see
        // the ticket). `await GetAsync(x)`: the value of the awaited task.
        if t == "await_expression" {
            return self.lower_expr(named_children(expr).next());
        }

        // `(a, b)`: a tuple of its elements.
        if t == "tuple_expression" {
            let elements = named_children(expr)
                .map(|a| self.lower_wrapped_argument(a))
                .collect();
            return Rhs::TupleRef(elements);
        }

        // `record with { Path = input }`, `new { Name = x, y }`, a LINQ
        // query `from l in lines where ... select l.Trim()`: a value built
        // from its parts, which carries the taint of every one of them. The
        // member names (`Path`, `Name`) are lowered too, as variables no
        // state holds.
        if matches!(
            t,
            "with_expression" | "anonymous_object_creation_expression" | "query_expression"
        ) {
            let parts = self.lower_parts(expr);
            return Rhs::TupleRef(parts);
        }

        // `new(path, mode)`: a constructor call whose type is written on the
        // other side of the assignment. It is named after that type when
        // the code declares it (`target_type`), `new` otherwise.
        if t == "implicit_object_creation_expression" {
            let callee = match self.target_type(expr) {
                Some(type_node) => self.type_to_rhs(Some(type_node)),
                None => Rhs::VarRef("new".to_string()),
            };
            let mut args = Vec::new();
            for child in named_children(expr) {
                match child.kind() {
                    "argument_list" => args.extend(self.lower_arg_list(Some(child))),
                    "initializer_expression" => {
                        args.extend(self.lower_initializer_values(child));
                    }
                    _ => args.push(self.lower_expr(Some(child))),
                }
            }
            let tmp = self.fresh_temp();
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(tmp.clone()),
                rhs: Rhs::CallRef {
                    callee: Box::new(callee),
                    args,
                    kwargs: Vec::new(),
                },
                lineno: self.line(expr),
            });
            return Rhs::VarRef(tmp);
        }

        // `string.Format(...)`, `List<int>.Empty`: a type used as the
        // receiver of a member, named as written (without its type
        // arguments) so the call is named `string.Format`.
        if t == "predefined_type" {
            return Rhs::VarRef(self.text(expr));
        }
        if t == "generic_name" {
            let name = named_children(expr)
                .find(|n| n.kind() == "identifier")
                .map(|n| self.text(n))
                .unwrap_or_else(|| self.text(expr));
            return Rhs::VarRef(name);
        }

        if t == "as_expression" {
            // `x as Foo` — a cast that yields null instead of throwing. For
            // taint purposes: identical to a cast, propagates the operand.
            return self.lower_expr(expr.child_by_field_name("left"));
        }

        if t == "assignment_expression" {
            return self.lower_assignment_expression(expr);
        }

        // Fallback: unknown expression → `Opaque`, no taint and no known
        // value. Ticket #253, deliberate deviation from the Audit, which
        // returns `Const(None)` here: the constant pass (§9) read a
        // condition it did not model as `None`, always false, and dropped
        // the body of the `if` (C# `if (user is not null)`).
        Rhs::Opaque
    }

    fn lower_invocation(&mut self, expr: Node<'src>) -> Rhs {
        let function = expr.child_by_field_name("function");
        let args = self.lower_arg_list(expr.child_by_field_name("arguments"));
        let callee = self.lower_callee(function);
        // Call line: for a `member_access_expression` receiver,
        // prefer the line of the `.name` part (mirrors the
        // Java round-8 fix for call chains spread over
        // several lines) — falls back to the line of the whole invocation
        // otherwise.
        let mut call_lineno = self.line(expr);
        if let Some(f) = function
            && f.kind() == "member_access_expression"
            && let Some(name_node) = f.child_by_field_name("name")
        {
            call_lineno = self.line(name_node);
        }
        let tmp = self.fresh_temp();
        self.emit(IrStmt::Assign {
            lhs: Lhs::VarLhs(tmp.clone()),
            rhs: Rhs::CallRef {
                callee: Box::new(callee),
                args,
                kwargs: Vec::new(),
            },
            lineno: call_lineno,
        });
        Rhs::VarRef(tmp)
    }

    /// The callee of an invocation: `new C(...).M` keeps its class
    /// ([`Self::lower_constructor_chain`]), any other one is an expression.
    fn lower_callee(&mut self, function: Option<Node<'src>>) -> Rhs {
        match function {
            Some(f) if Self::is_constructor_chain(f) => self.lower_constructor_chain(f),
            _ => self.lower_expr(function),
        }
    }

    /// Whether `function`, the callee of an invocation, is `new C(...).M`:
    /// a member of an object created on the spot.
    fn is_constructor_chain(function: Node) -> bool {
        function.kind() == "member_access_expression"
            && function
                .child_by_field_name("expression")
                .is_some_and(|o| o.kind() == "object_creation_expression")
    }

    /// `new Repo(...).Find(...)` (ticket #284), lowered as Java lowers it
    /// (`java_lowering.rs::lower_method_invocation`): the constructor's
    /// `CallRef` is kept as the base of the `AttrRef` instead of a
    /// temporary, so that `transfer.rs::eval_call` reads the class `Repo`
    /// back from it and resolves the summary of `Repo.Find`, and the C# call
    /// graph names the call `Repo.Find` alike. The constructor's arguments
    /// are still evaluated, through the nested `CallRef`.
    fn lower_constructor_chain(&mut self, function: Node<'src>) -> Rhs {
        let creation = function
            .child_by_field_name("expression")
            .expect("checked by is_constructor_chain");
        let ctor_args = self.lower_arg_list(creation.child_by_field_name("arguments"));
        let ctor_callee = self.type_to_rhs(creation.child_by_field_name("type"));
        let attr = function
            .child_by_field_name("name")
            .map(|f| self.text(f))
            .unwrap_or_else(|| "?".to_string());
        Rhs::AttrRef {
            base: Box::new(Rhs::CallRef {
                callee: Box::new(ctor_callee),
                args: ctor_args,
                kwargs: Vec::new(),
            }),
            attr,
        }
    }

    /// Lowers each element of an `argument_list`, unwrapped from its
    /// `argument` node (unlike Java, see module doc).
    fn lower_arg_list(&mut self, arg_list: Option<Node<'src>>) -> Vec<Rhs> {
        let Some(arg_list) = arg_list else {
            return Vec::new();
        };
        named_children(arg_list)
            .map(|a| self.lower_wrapped_argument(a))
            .collect()
    }

    /// Lowers a `bracketed_argument_list` (indexer, `arr[i]`) — same
    /// `argument` wrapper as a call's `argument_list`, a single
    /// element expected.
    fn lower_bracketed_argument(&mut self, arg_list: Option<Node<'src>>) -> Rhs {
        let Some(arg_list) = arg_list else {
            return Rhs::Opaque;
        };
        let first = named_children(arg_list).next();
        match first {
            Some(a) => self.lower_wrapped_argument(a),
            None => Rhs::Opaque,
        }
    }

    /// The values an object or collection initializer stores in the object
    /// it builds, in written order, each lowered: `{ Domain = d, Path = p }`
    /// gives `d`, `p`; `{ a, b }` gives `a`, `b`; `{ ["k"] = v }` gives the
    /// key then `v`; a nested initializer (`Inner = { X = x }`, `{ { k, v } }`)
    /// gives its own values. Its callers pass them as arguments of the
    /// constructor call, after the constructor's own arguments.
    ///
    /// Deliberate deviation from the Audit (ticket #268):
    /// `csharp_to_ir.py` drops the initializer of `new T(...) { ... }`, so
    /// `new CookieOptions { Domain = Request.Query["d"] }` reached the
    /// `new CookieOptions` sink with no argument, and an object built from
    /// request data in its initializer carried no taint. Arguments rather
    /// than member writes on the result: a constructor sink reads the
    /// arguments of its call (a rule writes `arg_index=all` to read the
    /// initializer values, which follow the constructor's own), and an
    /// unknown constructor's result carries the taint of its arguments
    /// either way. The member names (`Domain`) are not lowered: the former
    /// path of `implicit_object_creation_expression` read each `Domain = d`
    /// as an assignment to a local `Domain`, which overwrote a local of
    /// that name.
    fn lower_initializer_values(&mut self, init: Node<'src>) -> Vec<Rhs> {
        let mut values = Vec::new();
        for element in named_children(init) {
            match element.kind() {
                "assignment_expression" => {
                    // `["k"] = v`: the key is part of what is stored too.
                    if let Some(left) = element.child_by_field_name("left")
                        && left.kind() == "element_binding_expression"
                    {
                        for key in named_children(left) {
                            values.push(self.lower_wrapped_argument(key));
                        }
                    }
                    match element.child_by_field_name("right") {
                        Some(right) if right.kind() == "initializer_expression" => {
                            values.extend(self.lower_initializer_values(right));
                        }
                        right => values.push(self.lower_expr(right)),
                    }
                }
                "initializer_expression" => {
                    values.extend(self.lower_initializer_values(element));
                }
                _ => values.push(self.lower_expr(Some(element))),
            }
        }
        values
    }

    /// Every expression under `node`, lowered: the parts of a value built
    /// from several of them (see the `with_expression` arm of
    /// `lower_expr`). A clause (`from_clause`, `where_clause`,
    /// `with_initializer`) is not an expression: its own parts are read.
    fn lower_parts(&mut self, node: Node<'src>) -> Vec<Rhs> {
        let mut parts = Vec::new();
        for child in named_children(node) {
            if child.kind().ends_with("_clause")
                || matches!(child.kind(), "with_initializer" | "argument")
            {
                parts.extend(self.lower_parts(child));
            } else if !child.kind().ends_with("type") {
                parts.push(self.lower_expr(Some(child)));
            }
        }
        parts
    }

    fn lower_wrapped_argument(&mut self, a: Node<'src>) -> Rhs {
        if a.kind() == "argument" {
            // The value is the last named child: a named argument
            // `Open(path: input)` holds the name first (ticket #255: the
            // name was read as the value, and `input` lost its taint).
            let inner = named_children(a).last();
            self.lower_expr(inner)
        } else {
            self.lower_expr(Some(a))
        }
    }

    fn lambda_param_names(&self, params: Option<Node<'src>>) -> Vec<String> {
        let Some(params) = params else {
            return Vec::new();
        };
        if params.kind() == "implicit_parameter" {
            // `p => ...` — single parameter with no parentheses or type,
            // with no Java equivalent (which uses a bare `identifier`).
            return vec![self.text(params)];
        }
        let mut names = Vec::new();
        for p in named_children(params) {
            if p.kind() == "parameter" {
                if let Some(name_node) = p.child_by_field_name("name") {
                    names.push(self.text(name_node));
                }
            } else if p.kind() == "identifier" {
                names.push(self.text(p));
            }
        }
        names
    }

    /// Converts a type node into a chain of `AttrRef` to
    /// match "dotted" patterns (e.g.
    /// `System.Data.SqlClient.SqlCommand` →
    /// `AttrRef(AttrRef(AttrRef(VarRef("System"), "Data"), "SqlClient"), "SqlCommand")`).
    /// Generic arguments (`List<string>` → text `List<string>`)
    /// are stripped before splitting on dots.
    fn type_to_rhs(&self, type_node: Option<Node<'src>>) -> Rhs {
        let Some(type_node) = type_node else {
            return Rhs::VarRef("?".to_string());
        };
        let text = self.text(type_node);
        // A nullable type (`CookieOptions?`) names its underlying type.
        let before_generic = text
            .split('<')
            .next()
            .unwrap_or(&text)
            .trim()
            .trim_end_matches('?');
        let mut parts = before_generic.split('.');
        let Some(first) = parts.next() else {
            return Rhs::VarRef("?".to_string());
        };
        let mut rhs = Rhs::VarRef(first.to_string());
        for part in parts {
            rhs = Rhs::AttrRef {
                base: Box::new(rhs),
                attr: part.to_string(),
            };
        }
        rhs
    }

    /// Lowers `-x`/`!x`/`~x`/`++x`/`--x`. No field name on this
    /// node (verified): `children[0]` is the anonymous operator token,
    /// `named_children[0]` the single named operand.
    fn lower_prefix_unary(&mut self, expr: Node<'src>) -> Rhs {
        let operand_node = named_children(expr).next();
        let Some(operand_node) = operand_node else {
            return Rhs::Opaque;
        };
        let Some(op_child) = expr.child(0) else {
            return Rhs::Opaque;
        };
        let op_text = self.text(op_child);
        if op_text == "++" || op_text == "--" {
            let symbol = &op_text[..1];
            return self.lower_increment(operand_node, symbol, expr);
        }
        let operand = self.lower_expr(Some(operand_node));
        let tmp = self.fresh_temp();
        self.emit(IrStmt::Assign {
            lhs: Lhs::VarLhs(tmp.clone()),
            rhs: Rhs::UnaryOp {
                op: op_text,
                operand: Box::new(operand),
            },
            lineno: self.line(expr),
        });
        Rhs::VarRef(tmp)
    }

    /// Lowers `x++`/`x--`. No field name (verified):
    /// `named_children[0]` the single named operand, the LAST raw
    /// child the anonymous operator token (reverse order from prefix).
    fn lower_postfix_unary(&mut self, expr: Node<'src>) -> Rhs {
        let operand_node = named_children(expr).next();
        let Some(operand_node) = operand_node else {
            return Rhs::Opaque;
        };
        let last_child = {
            let count = expr.child_count();
            if count == 0 {
                None
            } else {
                expr.child((count - 1) as u32)
            }
        };
        let Some(op_child) = last_child else {
            return Rhs::Opaque;
        };
        let op_text = self.text(op_child);
        let symbol = if op_text.starts_with("++") { "+" } else { "-" };
        self.lower_increment(operand_node, symbol, expr)
    }

    /// Shared lowering for `++`/`--`: emits the update assignment,
    /// returns the value BEFORE the increment (an accepted
    /// approximation for both pre AND post, mirroring
    /// `java_lowering.rs::lower_update_expression` — the distinction
    /// only matters if the expression's VALUE itself feeds a sink in
    /// the same statement, a rare idiom).
    fn lower_increment(
        &mut self,
        operand_node: Node<'src>,
        op_symbol: &str,
        expr: Node<'src>,
    ) -> Rhs {
        let operand_rhs = self.lower_expr(Some(operand_node));
        let lhs = self.lower_target(Some(operand_node));
        self.emit(IrStmt::Assign {
            lhs,
            rhs: Rhs::BinOp {
                op: op_symbol.to_string(),
                left: Box::new(operand_rhs.clone()),
                right: Box::new(Rhs::Const(ConstValue::Int(1))),
            },
            lineno: self.line(expr),
        });
        operand_rhs
    }

    /// Lowers `target = expr` (and compound forms `+=`, `??=`...) into
    /// an emitted `Assign`, returning the assigned `Rhs`.
    fn lower_assignment_expression(&mut self, expr: Node<'src>) -> Rhs {
        let left_node = expr.child_by_field_name("left");
        let right_node = expr.child_by_field_name("right");
        let op_text = expr
            .child_by_field_name("operator")
            .map(|n| self.text(n))
            .unwrap_or_else(|| "=".to_string());

        let mut rhs = self.lower_expr(right_node);
        if op_text != "=" {
            let base_op = &op_text[..op_text.len() - 1]; // "+=" -> "+", "??=" -> "??"
            let read_target = self.lower_expr(left_node);
            rhs = Rhs::BinOp {
                op: base_op.to_string(),
                left: Box::new(read_target),
                right: Box::new(rhs),
            };
        }

        let lhs = self.lower_target(left_node);
        self.emit(IrStmt::Assign {
            lhs,
            rhs: rhs.clone(),
            lineno: self.line(expr),
        });
        rhs
    }

    // --- target (LHS) lowering ------------------------------------------------

    fn lower_target(&mut self, target: Option<Node<'src>>) -> Lhs {
        let Some(target) = target else {
            return Lhs::VarLhs("__unknown_target".to_string());
        };
        match target.kind() {
            "identifier" | "this" => Lhs::VarLhs(self.text(target)),
            "member_access_expression" => {
                let base = self.lower_expr(target.child_by_field_name("expression"));
                let attr = target
                    .child_by_field_name("name")
                    .map(|f| self.text(f))
                    .unwrap_or_else(|| "?".to_string());
                Lhs::AttrLhs {
                    base: Box::new(base),
                    attr,
                }
            }
            "element_access_expression" => {
                let base = self.lower_expr(target.child_by_field_name("expression"));
                let key = self.lower_bracketed_argument(target.child_by_field_name("subscript"));
                Lhs::SubscriptLhs {
                    base: Box::new(base),
                    key: Box::new(key),
                }
            }
            // Fallback: synthetic name to avoid panicking.
            _ => Lhs::VarLhs("__unknown_target".to_string()),
        }
    }

    // --- operator text extraction ---------------------------------------------

    fn binary_op_text(&self, expr: Node<'src>) -> String {
        expr.child_by_field_name("operator")
            .map(|n| self.text(n))
            .unwrap_or_else(|| "?".to_string())
    }

    // --- literal reading -------------------------------------------------------

    fn string_literal_value(&self, node: Node<'src>) -> String {
        let mut parts = String::new();
        let mut w = node.walk();
        for c in node.children(&mut w) {
            if c.kind() == "string_literal_content" || c.kind() == "escape_sequence" {
                parts.push_str(&self.text(c));
            }
        }
        parts
    }

    /// Lowers `$"...{expr}..."` into a chain of `BinOp("+", ...)` over
    /// strings, so that the taint of every nested `{expr}` propagates
    /// to the result.
    fn lower_interpolated_string(&mut self, expr: Node<'src>) -> Rhs {
        let mut parts: Vec<Rhs> = Vec::new();
        let mut w = expr.walk();
        for c in expr.children(&mut w) {
            if c.kind() == "string_content" {
                parts.push(Rhs::Const(ConstValue::Str(self.text(c))));
            } else if c.kind() == "interpolation" {
                // `{id,10:N}`: the braces, the alignment and the format are
                // named children too; the value is the one expression. The
                // first named child is the `{` (`interpolation_brace`), which
                // was read as the value before ticket #255: an interpolated
                // string lost the taint of every variable it held.
                let inner = named_children(c).find(|n| {
                    !matches!(
                        n.kind(),
                        "interpolation_brace"
                            | "interpolation_alignment_clause"
                            | "interpolation_format_clause"
                    )
                });
                parts.push(self.lower_expr(inner));
            }
        }
        let Some(first) = parts.first().cloned() else {
            return Rhs::Const(ConstValue::Str(String::new()));
        };
        let mut acc = first;
        for part in parts.into_iter().skip(1) {
            let tmp = self.fresh_temp();
            self.emit(IrStmt::Assign {
                lhs: Lhs::VarLhs(tmp.clone()),
                rhs: Rhs::BinOp {
                    op: "+".to_string(),
                    left: Box::new(acc),
                    right: Box::new(part),
                },
                lineno: self.line(expr),
            });
            acc = Rhs::VarRef(tmp);
        }
        acc
    }

    // --- statement lowering ----------------------------------------------------

    fn lower_stmt(&mut self, stmt: Node<'src>) {
        match stmt.kind() {
            "local_declaration_statement" => self.lower_local_declaration_statement(stmt),
            "variable_declaration" => self.lower_variable_declaration(stmt),
            "expression_statement" => self.lower_expression_statement(stmt),
            "return_statement" => self.lower_return_statement(stmt),
            // Expression body (`=> expr`) of a method/constructor: same
            // IR as `return expr;` (ticket #123, see `csharp_cfg.rs`).
            // Its single named child is the expression, exactly like a
            // `return_statement`. For a `void` method the returned value
            // is simply never read; calls inside are still lowered, so
            // sinks are seen.
            "arrow_expression_clause" => self.lower_return_statement(stmt),
            "throw_statement" => self.lower_throw_statement(stmt),
            "lock_statement" => self.lower_lock_statement(stmt),
            _ => self.emit(IrStmt::Noop {
                lineno: self.line(stmt),
            }),
        }
    }

    fn lower_local_declaration_statement(&mut self, stmt: Node<'src>) {
        let decl = named_children(stmt).find(|c| c.kind() == "variable_declaration");
        match decl {
            Some(d) => self.lower_declarators(d, stmt),
            None => self.emit(IrStmt::Noop {
                lineno: self.line(stmt),
            }),
        }
    }

    /// Lowers a BARE `variable_declaration` — reached when a
    /// `using (var x = ...)` resource is appended directly to a BASIC
    /// CFG node by `CSharpCfgBuilder::visit_using` (the resource clause
    /// has no `local_declaration_statement` wrapper there, unlike an
    /// ordinary top-level declaration).
    fn lower_variable_declaration(&mut self, stmt: Node<'src>) {
        self.lower_declarators(stmt, stmt);
    }

    fn lower_declarators(&mut self, decl: Node<'src>, lineno_src: Node<'src>) {
        let declarators: Vec<Node<'src>> = named_children(decl)
            .filter(|c| c.kind() == "variable_declarator")
            .collect();
        for declarator in declarators {
            let Some(name_node) = declarator.child_by_field_name("name") else {
                continue;
            };
            let name = self.text(name_node);
            // No named `value` field (verified) — the initializer, if
            // present, is the SECOND named child.
            let named: Vec<Node<'src>> = named_children(declarator).collect();
            let value_node = named.get(1).copied();
            match value_node {
                None => self.emit(IrStmt::Noop {
                    lineno: self.line(lineno_src),
                }),
                Some(v) => {
                    let rhs = self.lower_expr(Some(v));
                    self.emit(IrStmt::Assign {
                        lhs: Lhs::VarLhs(name),
                        rhs,
                        lineno: self.line(lineno_src),
                    });
                }
            }
        }
    }

    fn lower_expression_statement(&mut self, stmt: Node<'src>) {
        let inner = named_children(stmt).next();
        let Some(inner) = inner else {
            self.emit(IrStmt::Noop {
                lineno: self.line(stmt),
            });
            return;
        };
        if inner.kind() == "invocation_expression" {
            self.lower_call_as_statement(inner);
            return;
        }
        // assignment_expression / postfix|prefix_unary_expression
        // already emit their Assign via lower_expr (side effect);
        // any other expression is lowered for its side effects, the
        // final result discarded.
        self.lower_expr(Some(inner));
    }

    /// Emits an IR `Call` node (no Assign+temporary) for a call used
    /// as a statement — directly visible to the taint engine as a
    /// potential sink. Shared between `lower_expression_statement` and
    /// `lower_condition` (a Branch/Loop condition that is a direct
    /// call, e.g. `if (IsValid(input))`).
    fn lower_call_as_statement(&mut self, call_node: Node<'src>) {
        let function = call_node.child_by_field_name("function");
        let callee = self.lower_callee(function);
        let args = self.lower_arg_list(call_node.child_by_field_name("arguments"));
        self.emit(IrStmt::Call {
            callee,
            args,
            kwargs: Vec::new(),
            lineno: self.line(call_node),
        });
    }

    fn lower_return_statement(&mut self, stmt: Node<'src>) {
        let value_node = named_children(stmt).next();
        let value = value_node.map(|v| self.lower_expr(Some(v)));
        self.emit(IrStmt::Return {
            value,
            lineno: self.line(stmt),
        });
    }

    fn lower_throw_statement(&mut self, stmt: Node<'src>) {
        let value_node = named_children(stmt).next();
        let value = value_node.map(|v| self.lower_expr(Some(v)));
        self.emit(IrStmt::Raise {
            value,
            lineno: self.line(stmt),
        });
    }

    /// Lowers only the lock expression of a `lock (obj) {...}`. The
    /// body is visited separately by `CSharpCfgBuilder` (its own CFG
    /// nodes) — do NOT descend into it here to avoid double
    /// processing, mirroring
    /// `java_lowering.rs::lower_synchronized_statement`.
    fn lower_lock_statement(&mut self, stmt: Node<'src>) {
        let lock_expr = named_children(stmt).find(|c| c.kind() != "block");
        match lock_expr {
            Some(l) => {
                self.lower_expr(Some(l));
            }
            None => self.emit(IrStmt::Noop {
                lineno: self.line(stmt),
            }),
        }
    }
}

/// Parses a C# numeric literal (hex/binary, with `l`/`u`/`f`/`d`/`m`
/// suffixes and `_` separators) into a `ConstValue`. Falls back to
/// `Str(text)` (the ORIGINAL, uncleaned text) if the cleanup produces
/// an unparsable form — same behavior as `_parse_numeric` on the
/// Python side. Unlike `parse_java_numeric`, no octal heuristic
/// (Python `int("0123")` == 123, no C-style ambiguity here).
fn parse_csharp_numeric(text: &str) -> ConstValue {
    let cleaned = text
        .trim_end_matches(['l', 'L', 'u', 'U', 'f', 'F', 'd', 'D', 'm', 'M'])
        .replace('_', "");
    let lower = cleaned.to_lowercase();
    if let Some(hex) = lower.strip_prefix("0x") {
        let hex_digits = &cleaned[cleaned.len() - hex.len()..];
        return match i64::from_str_radix(hex_digits, 16) {
            Ok(v) => ConstValue::Int(v),
            Err(_) => ConstValue::Str(text.to_string()),
        };
    }
    if let Some(bin) = lower.strip_prefix("0b") {
        let bin_digits = &cleaned[cleaned.len() - bin.len()..];
        return match i64::from_str_radix(bin_digits, 2) {
            Ok(v) => ConstValue::Int(v),
            Err(_) => ConstValue::Str(text.to_string()),
        };
    }
    if cleaned.contains('.') || lower.contains('e') {
        return match cleaned.parse::<f64>() {
            Ok(v) => ConstValue::Float(v),
            Err(_) => ConstValue::Str(text.to_string()),
        };
    }
    match cleaned.parse::<i64>() {
        Ok(v) => ConstValue::Int(v),
        Err(_) => ConstValue::Str(text.to_string()),
    }
}

// ============================================================================
// Target type of `new()` (ticket #268)
// ============================================================================

/// Methods, constructors and local functions: the nodes whose parameters
/// and locals a name inside them can refer to.
const CALLABLE_KINDS: [&str; 3] = [
    "method_declaration",
    "constructor_declaration",
    "local_function_statement",
];

/// Type declarations whose members (fields, properties, methods) a name
/// inside them can refer to.
const TYPE_DECLARATION_KINDS: [&str; 4] = [
    "class_declaration",
    "struct_declaration",
    "record_declaration",
    "interface_declaration",
];

impl<'src> CSharpLowerer<'src> {
    /// The type a target-typed `new(...)` / `new() { ... }` builds, read
    /// from where the expression is written, or `None` when the code does
    /// not say it:
    ///   - the initializer of a declaration, `CookieOptions o = new() {..}`
    ///     (a local or a field; `var` cannot hold a `new()`);
    ///   - the initializer of a property, `CookieOptions O { get; } = new()`;
    ///   - the right side of an assignment to a name whose declaration the
    ///     code holds: a local, a parameter, a field or a property of the
    ///     enclosing type (`o = new() {..}`, `this.o = new() {..}`);
    ///   - an argument of a method of the enclosing type, by position or by
    ///     name, `Remember(new() { Domain = d })`;
    ///   - the value returned by a method or a local function.
    ///
    /// An argument of a library method (`Response.Cookies.Append("k", v,
    /// new() { .. })`) has no declaration in the code: its type stays
    /// unknown and the call keeps the name `new`. The lookup is syntactic
    /// (no overload resolution beyond the argument count): the first
    /// method of that name and arity wins.
    ///
    /// Deliberate deviation from the Audit (ticket #268): `csharp_to_ir.py`
    /// predates target-typed `new` (C# 9) and names every such call `new`,
    /// so a constructor sink (`new\s+CookieOptions\b`) never met it.
    fn target_type(&self, expr: Node<'src>) -> Option<Node<'src>> {
        let parent = expr.parent()?;
        match parent.kind() {
            // `(new() { .. })`: the type of the enclosing expression.
            "parenthesized_expression" => self.target_type(parent),
            "variable_declarator" => {
                let declaration = parent.parent()?;
                explicit_type(declaration.child_by_field_name("type")?)
            }
            "property_declaration" => explicit_type(parent.child_by_field_name("type")?),
            "assignment_expression" => {
                let right = parent.child_by_field_name("right")?;
                if right.id() != expr.id() {
                    return None;
                }
                let left = parent.child_by_field_name("left")?;
                let name = match left.kind() {
                    "identifier" => self.text(left),
                    "member_access_expression"
                        if left
                            .child_by_field_name("expression")
                            .is_some_and(|e| e.kind() == "this") =>
                    {
                        self.text(left.child_by_field_name("name")?)
                    }
                    _ => return None,
                };
                self.declared_type_of(&name, parent)
            }
            "argument" => self.parameter_type(parent),
            "return_statement" => self.return_type(parent),
            "arrow_expression_clause" => {
                let owner = parent.parent()?;
                match owner.kind() {
                    "method_declaration" => explicit_type(owner.child_by_field_name("returns")?),
                    "local_function_statement" | "property_declaration" => {
                        explicit_type(owner.child_by_field_name("type")?)
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// The declared type of `name` as seen from `from`: a local declared in
    /// the enclosing method (before `from`), one of its parameters, then a
    /// field or a property of the enclosing type.
    fn declared_type_of(&self, name: &str, from: Node<'src>) -> Option<Node<'src>> {
        let mut node = from.parent();
        while let Some(current) = node {
            if CALLABLE_KINDS.contains(&current.kind()) {
                if let Some(t) = self.local_type(current, name, from.start_byte()) {
                    return Some(t);
                }
                if let Some(params) = current.child_by_field_name("parameters")
                    && let Some(t) = named_children(params)
                        .filter(|p| p.kind() == "parameter")
                        .find(|p| {
                            p.child_by_field_name("name")
                                .is_some_and(|n| self.text(n) == name)
                        })
                        .and_then(|p| p.child_by_field_name("type"))
                        .and_then(explicit_type)
                {
                    return Some(t);
                }
            }
            if TYPE_DECLARATION_KINDS.contains(&current.kind()) {
                return self.member_type(current, name);
            }
            node = current.parent();
        }
        None
    }

    /// The type of the first local `name` declared in `callable` before the
    /// byte `before`, searched in its whole body.
    fn local_type(&self, callable: Node<'src>, name: &str, before: usize) -> Option<Node<'src>> {
        let body = callable.child_by_field_name("body")?;
        let mut stack = vec![body];
        let mut found: Option<(usize, Node<'src>)> = None;
        while let Some(node) = stack.pop() {
            if node.start_byte() >= before {
                continue;
            }
            // A nested local function or lambda has its own locals.
            if node.id() != body.id()
                && (CALLABLE_KINDS.contains(&node.kind()) || node.kind() == "lambda_expression")
            {
                continue;
            }
            if node.kind() == "variable_declaration"
                && let Some(t) = node.child_by_field_name("type").and_then(explicit_type)
                && named_children(node)
                    .filter(|d| d.kind() == "variable_declarator")
                    .any(|d| {
                        d.child_by_field_name("name")
                            .is_some_and(|n| self.text(n) == name)
                    })
                && found.is_none_or(|(start, _)| node.start_byte() < start)
            {
                found = Some((node.start_byte(), t));
            }
            stack.extend(named_children(node));
        }
        found.map(|(_, t)| t)
    }

    /// The type of the field or property `name` of the type declaration
    /// `owner`.
    fn member_type(&self, owner: Node<'src>, name: &str) -> Option<Node<'src>> {
        let body = owner.child_by_field_name("body")?;
        for member in named_children(body) {
            match member.kind() {
                "field_declaration" => {
                    let Some(declaration) =
                        named_children(member).find(|c| c.kind() == "variable_declaration")
                    else {
                        continue;
                    };
                    let declares = named_children(declaration)
                        .filter(|d| d.kind() == "variable_declarator")
                        .any(|d| {
                            d.child_by_field_name("name")
                                .is_some_and(|n| self.text(n) == name)
                        });
                    if declares {
                        return declaration
                            .child_by_field_name("type")
                            .and_then(explicit_type);
                    }
                }
                "property_declaration"
                    if member
                        .child_by_field_name("name")
                        .is_some_and(|n| self.text(n) == name) =>
                {
                    return member.child_by_field_name("type").and_then(explicit_type);
                }
                _ => {}
            }
        }
        None
    }

    /// The parameter type an `argument` is passed to, when the call names a
    /// method of the enclosing type (`Remember(...)`, `this.Remember(...)`)
    /// declared with that many parameters: by the argument's name when it
    /// has one (`options: new() {..}`), by its position otherwise.
    fn parameter_type(&self, argument: Node<'src>) -> Option<Node<'src>> {
        let list = argument.parent()?;
        let call = list.parent()?;
        if call.kind() != "invocation_expression" {
            return None;
        }
        let function = call.child_by_field_name("function")?;
        let method_name = match function.kind() {
            "identifier" => self.text(function),
            "member_access_expression"
                if function
                    .child_by_field_name("expression")
                    .is_some_and(|e| e.kind() == "this") =>
            {
                self.text(function.child_by_field_name("name")?)
            }
            _ => return None,
        };
        let arguments: Vec<Node<'src>> = named_children(list)
            .filter(|a| a.kind() == "argument")
            .collect();
        let position = arguments.iter().position(|a| a.id() == argument.id())?;
        let argument_name = argument.child_by_field_name("name").map(|n| self.text(n));
        let mut node = call.parent();
        while let Some(current) = node {
            if TYPE_DECLARATION_KINDS.contains(&current.kind()) {
                let body = current.child_by_field_name("body")?;
                for method in named_children(body).filter(|m| m.kind() == "method_declaration") {
                    if !method
                        .child_by_field_name("name")
                        .is_some_and(|n| self.text(n) == method_name)
                    {
                        continue;
                    }
                    let Some(params) = method.child_by_field_name("parameters") else {
                        continue;
                    };
                    let params: Vec<Node<'src>> = named_children(params)
                        .filter(|p| p.kind() == "parameter")
                        .collect();
                    if params.len() != arguments.len() {
                        continue;
                    }
                    let param = match &argument_name {
                        Some(wanted) => params.iter().copied().find(|p| {
                            p.child_by_field_name("name")
                                .is_some_and(|n| &self.text(n) == wanted)
                        }),
                        None => params.get(position).copied(),
                    }?;
                    return param.child_by_field_name("type").and_then(explicit_type);
                }
                return None;
            }
            node = current.parent();
        }
        None
    }

    /// The return type of the method or local function a `return` leaves;
    /// `None` inside a lambda, whose type the code does not write.
    fn return_type(&self, statement: Node<'src>) -> Option<Node<'src>> {
        let mut node = statement.parent();
        while let Some(current) = node {
            match current.kind() {
                "method_declaration" => {
                    return current
                        .child_by_field_name("returns")
                        .and_then(explicit_type);
                }
                "local_function_statement" => {
                    return current.child_by_field_name("type").and_then(explicit_type);
                }
                "lambda_expression" | "anonymous_method_expression" => return None,
                _ => node = current.parent(),
            }
        }
        None
    }
}

/// `type_node` unless it is `var` (`implicit_type`), which names no type.
fn explicit_type(type_node: Node<'_>) -> Option<Node<'_>> {
    (type_node.kind() != "implicit_type").then_some(type_node)
}

// ============================================================================
// Public API
// ============================================================================

/// Lowers a standalone C# expression into an `Rhs` (the auxiliary
/// statements generated along the way are discarded, only the final
/// `Rhs` counts). **Do not use for taint propagation of a Branch/Loop
/// condition** — use `lower_condition` instead.
pub fn lower_expr<'src>(source: &'src [u8], expr: Node<'src>) -> Rhs {
    CSharpLowerer::new(source).lower_expr(Some(expr))
}

/// Variant of [`lower_expr`] for the synthetic condition of a switch
/// `case` with a single literal label (`case 6:`) — typed mirror of
/// `SwitchCaseCondition` on the Python side. Emits `subject == label`.
pub fn lower_expr_switch_case<'src>(
    source: &'src [u8],
    subject: Node<'src>,
    label: Node<'src>,
) -> Rhs {
    let mut lowerer = CSharpLowerer::new(source);
    let left = lowerer.lower_expr(Some(subject));
    let right = lowerer.lower_expr(Some(label));
    Rhs::Cmp {
        op: "==".to_string(),
        left: Box::new(left),
        right: Box::new(right),
    }
}

/// Lowers an expression used as a condition (Branch/Loop) into a list
/// of IR statements — for taint propagation, not just its value. If
/// the expression is a direct call (`invocation_expression`, e.g.
/// `if (IsValid(input))`), emits a `Call` rather than a buried
/// Assign+temporary.
pub fn lower_condition<'src>(source: &'src [u8], expr: Node<'src>) -> Vec<IrStmt> {
    let mut lowerer = CSharpLowerer::new(source);
    // if/while expose their condition wrapped in a
    // `parenthesized_expression` (`if (x)`) — unwrapped before testing
    // for the `invocation_expression` case, otherwise
    // `if (IsValid(input))` would never match.
    let mut unwrapped = expr;
    loop {
        if unwrapped.kind() != "parenthesized_expression" {
            break;
        }
        let Some(inner) = named_children(unwrapped).next() else {
            break;
        };
        unwrapped = inner;
    }
    if unwrapped.kind() == "invocation_expression" {
        lowerer.lower_call_as_statement(unwrapped);
    } else {
        lowerer.lower_expr(Some(expr));
    }
    lowerer.output
}

/// Variant of [`lower_condition`] for a switch `case`'s synthetic
/// condition: emits `__tN := (subject == label)`.
pub fn lower_condition_switch_case<'src>(
    source: &'src [u8],
    subject: Node<'src>,
    label: Node<'src>,
) -> Vec<IrStmt> {
    let mut lowerer = CSharpLowerer::new(source);
    let left = lowerer.lower_expr(Some(subject));
    let right = lowerer.lower_expr(Some(label));
    let tmp = lowerer.fresh_temp();
    lowerer.emit(IrStmt::Assign {
        lhs: Lhs::VarLhs(tmp),
        rhs: Rhs::Cmp {
            op: "==".to_string(),
            left: Box::new(left),
            right: Box::new(right),
        },
        lineno: lowerer.line(subject),
    });
    lowerer.output
}

/// Synthesizes `target := iterable` for a C# for-each loop
/// (`foreach (T target in iterable)`). Without this explicit
/// assignment, the taint of the iterated collection never propagates
/// to the loop variable.
pub fn lower_for_target_assign<'src>(
    source: &'src [u8],
    target: Node<'src>,
    iterable: Node<'src>,
) -> Vec<IrStmt> {
    let mut lowerer = CSharpLowerer::new(source);
    let rhs = lowerer.lower_expr(Some(iterable));
    let lhs = lowerer.lower_target(Some(target));
    lowerer.emit(IrStmt::Assign {
        lhs,
        rhs,
        lineno: lowerer.line(iterable),
    });
    lowerer.output
}

/// Lowers a list of C# statements (the content of a Basic/Finally CFG
/// node) into IR.
pub fn lower_stmts<'src>(source: &'src [u8], stmts: &[Node<'src>]) -> Vec<IrStmt> {
    let mut lowerer = CSharpLowerer::new(source);
    for &stmt in stmts {
        lowerer.lower_stmt(stmt);
    }
    lowerer.output
}

/// Lowers a single C# statement into IR (may produce several `IrStmt`s).
pub fn lower_stmt<'src>(source: &'src [u8], stmt: Node<'src>) -> Vec<IrStmt> {
    let mut lowerer = CSharpLowerer::new(source);
    lowerer.lower_stmt(stmt);
    lowerer.output
}

// ============================================================================
// Lowering a CFG node into IR — C# mirror of
// `java_lowering.rs::lower_node_to_ir`/`lower_all_nodes`, the entry
// point consumed by `worklist::prepare_ir_generic` to instantiate
// `worklist::prepare_csharp_ir`.
// ============================================================================

/// Lowers the statements/condition of a C# CFG node into IR.
pub fn lower_node_to_ir<'tree>(cfg: &Cfg<'tree>, node_id: usize, source: &[u8]) -> Vec<IrStmt> {
    let node = &cfg.nodes[&node_id];
    match node.kind {
        NodeKind::Basic | NodeKind::Finally | NodeKind::RaiseSite => {
            if node.statements.is_empty() {
                Vec::new()
            } else {
                lower_stmts(source, &node.statements)
            }
        }
        NodeKind::Branch | NodeKind::Loop => {
            let Some(cond) = node.condition else {
                return Vec::new();
            };
            // For-each loop: emits the synthetic assignment
            // `target := iter` (without it the iterable's taint would
            // not propagate to the loop variable).
            if node.kind == NodeKind::Loop
                && let Some(target) = node.for_target
            {
                return lower_for_target_assign(source, target, cond);
            }
            if let Some(label) = node.switch_case_label {
                return lower_condition_switch_case(source, cond, label);
            }
            lower_condition(source, cond)
        }
        _ => Vec::new(),
    }
}

/// Lowers all nodes of a C# CFG into IR, in a single pass.
pub fn lower_all_nodes<'tree>(cfg: &Cfg<'tree>, source: &[u8]) -> BTreeMap<usize, Vec<IrStmt>> {
    cfg.nodes
        .keys()
        .map(|&nid| (nid, lower_node_to_ir(cfg, nid, source)))
        .collect()
}

/// Lowers a standalone expression (a Branch/Loop node's condition)
/// into `Rhs` — consumed by `worklist::compute_dead_edges_generic`
/// (dead-edge pruning pre-pass).
pub fn lower_expr_standalone<'src>(source: &'src [u8], expr: Node<'src>) -> (Rhs, Vec<IrStmt>) {
    let mut lowerer = CSharpLowerer::new(source);
    let rhs = lowerer.lower_expr(Some(expr));
    (rhs, lowerer.output)
}

// ============================================================================
// Tests — mirrors `Audit/tests/parsers/test_csharp_to_ir.py` (same
// invariants), with density equivalent to `java_lowering.rs::tests`.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn find_first<'t>(node: Node<'t>, kind: &str) -> Option<Node<'t>> {
        if node.kind() == kind {
            return Some(node);
        }
        let mut w = node.walk();
        for child in node.children(&mut w) {
            if let Some(found) = find_first(child, kind) {
                return Some(found);
            }
        }
        None
    }

    fn parse_csharp(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_c_sharp::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    /// Parses a C# method body and exposes `(source, body_stmts)` to `f`.
    fn with_body_stmts<R>(method_body_src: &str, f: impl FnOnce(&str, &[Node]) -> R) -> R {
        let src = format!("class Foo {{ void t(string input, int n) {{ {method_body_src} }} }}");
        let tree = parse_csharp(&src);
        assert!(
            !tree.root_node().has_error(),
            "syntaxe C# invalide : {method_body_src:?}"
        );
        let method = find_first(tree.root_node(), "method_declaration").unwrap();
        let body = method.child_by_field_name("body").unwrap();
        let stmts: Vec<Node> = body.named_children(&mut body.walk()).collect();
        f(&src, &stmts)
    }

    fn lower(method_body_src: &str) -> Vec<IrStmt> {
        with_body_stmts(method_body_src, |src, stmts| {
            lower_stmts(src.as_bytes(), stmts)
        })
    }

    fn assigns(ir: &[IrStmt]) -> Vec<&IrStmt> {
        ir.iter()
            .filter(|s| matches!(s, IrStmt::Assign { .. }))
            .collect()
    }

    fn calls(ir: &[IrStmt]) -> Vec<&IrStmt> {
        ir.iter()
            .filter(|s| matches!(s, IrStmt::Call { .. }))
            .collect()
    }

    fn var(name: &str) -> Rhs {
        Rhs::VarRef(name.to_string())
    }

    fn attr(base: Rhs, name: &str) -> Rhs {
        Rhs::AttrRef {
            base: Box::new(base),
            attr: name.to_string(),
        }
    }

    // ------------------------------------------------- assignations simples

    #[test]
    fn test_var_assign_constant() {
        let ir = lower("int x = 1;");
        assert_eq!(
            ir,
            vec![IrStmt::Assign {
                lhs: Lhs::VarLhs("x".to_string()),
                rhs: Rhs::Const(ConstValue::Int(1)),
                lineno: 1,
            }]
        );
    }

    #[test]
    fn test_var_assign_var() {
        let ir = lower("int x = n;");
        let IrStmt::Assign { lhs, rhs, .. } = &ir[0] else {
            panic!("expected Assign")
        };
        assert_eq!(*lhs, Lhs::VarLhs("x".to_string()));
        assert_eq!(*rhs, var("n"));
    }

    #[test]
    fn test_implicit_type_var_declaration() {
        let ir = lower("var x = n;");
        let IrStmt::Assign { lhs, rhs, .. } = &ir[0] else {
            panic!("expected Assign")
        };
        assert_eq!(*lhs, Lhs::VarLhs("x".to_string()));
        assert_eq!(*rhs, var("n"));
    }

    #[test]
    fn test_declaration_without_initializer() {
        let ir = lower("int x;");
        assert!(matches!(ir[0], IrStmt::Noop { .. }));
    }

    #[test]
    fn test_multi_declarator() {
        let ir = lower("int x = 1, y = 2;");
        let a = assigns(&ir);
        assert_eq!(a.len(), 2);
        let IrStmt::Assign { lhs: lhs0, .. } = a[0] else {
            panic!()
        };
        let IrStmt::Assign { lhs: lhs1, .. } = a[1] else {
            panic!()
        };
        assert_eq!(*lhs0, Lhs::VarLhs("x".to_string()));
        assert_eq!(*lhs1, Lhs::VarLhs("y".to_string()));
    }

    #[test]
    fn test_field_assign() {
        let ir = lower("this.field = input;");
        let IrStmt::Assign { lhs, rhs, .. } = &ir[0] else {
            panic!("expected Assign")
        };
        assert_eq!(
            *lhs,
            Lhs::AttrLhs {
                base: Box::new(var("this")),
                attr: "field".to_string(),
            }
        );
        assert_eq!(*rhs, var("input"));
    }

    #[test]
    fn test_element_access_assign() {
        let ir = lower("arr[0] = input;");
        let IrStmt::Assign { lhs, .. } = &ir[0] else {
            panic!("expected Assign")
        };
        let Lhs::SubscriptLhs { base, key } = lhs else {
            panic!("expected SubscriptLhs")
        };
        assert_eq!(**base, var("arr"));
        assert_eq!(**key, Rhs::Const(ConstValue::Int(0)));
    }

    #[test]
    fn test_element_access_read() {
        let ir = lower("var y = arr[i];");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(
            *rhs,
            Rhs::SubscriptRef {
                base: Box::new(var("arr")),
                key: Box::new(var("i")),
            }
        );
    }

    // ------------------------------------------------------------- operators

    #[test]
    fn test_binary_arith() {
        let ir = lower("int z = x + y;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::BinOp { op, .. } = rhs else {
            panic!("expected BinOp")
        };
        assert_eq!(op, "+");
    }

    #[test]
    fn test_null_coalescing_is_binop() {
        let ir = lower("var z = x ?? y;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::BinOp { op, .. } = rhs else {
            panic!("expected BinOp")
        };
        assert_eq!(op, "??");
    }

    #[test]
    fn test_comparison() {
        let ir = lower("bool b = x > 0;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::Cmp { op, .. } = rhs else {
            panic!("expected Cmp")
        };
        assert_eq!(op, ">");
    }

    #[test]
    fn test_boolean_and() {
        let ir = lower("bool b = x > 0 && y < 10;");
        let a = assigns(&ir);
        let bool_assign = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::Bool { op, operands } = rhs {
                Some((op, operands))
            } else {
                None
            }
        });
        let (op, operands) = bool_assign.unwrap();
        assert_eq!(op, "and");
        assert_eq!(operands.len(), 2);
    }

    #[test]
    fn test_is_expression() {
        let ir = lower("bool chk = input is string;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::Cmp { op, left, .. } = rhs else {
            panic!("expected Cmp")
        };
        assert_eq!(op, "instanceof");
        assert_eq!(**left, var("input"));
    }

    #[test]
    fn test_as_expression_passthrough() {
        let ir = lower("var r = input as string;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, var("input"));
    }

    // -------------------------------- prefix/postfix unary (distinct types)

    #[test]
    fn test_postfix_increment() {
        let ir = lower("x++;");
        let a = assigns(&ir);
        let IrStmt::Assign { lhs, rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*lhs, Lhs::VarLhs("x".to_string()));
        let Rhs::BinOp { op, .. } = rhs else {
            panic!("expected BinOp")
        };
        assert_eq!(op, "+");
    }

    #[test]
    fn test_prefix_decrement() {
        let ir = lower("--x;");
        let a = assigns(&ir);
        let IrStmt::Assign { lhs, rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*lhs, Lhs::VarLhs("x".to_string()));
        let Rhs::BinOp { op, .. } = rhs else {
            panic!("expected BinOp")
        };
        assert_eq!(op, "-");
    }

    #[test]
    fn test_prefix_negation_is_unary_not_increment() {
        let ir = lower("var y = -x;");
        let a = assigns(&ir);
        let unary = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::UnaryOp { op, .. } = rhs {
                Some(op)
            } else {
                None
            }
        });
        assert_eq!(unary.unwrap(), "-");
    }

    #[test]
    fn test_prefix_logical_not() {
        let ir = lower("bool y = !x;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        let Rhs::UnaryOp { op, .. } = rhs else {
            panic!("expected UnaryOp")
        };
        assert_eq!(op, "!");
    }

    #[test]
    fn test_compound_assignment() {
        let ir = lower("z += 5;");
        let a = assigns(&ir);
        let IrStmt::Assign { lhs, rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*lhs, Lhs::VarLhs("z".to_string()));
        let Rhs::BinOp { op, left, right } = rhs else {
            panic!("expected BinOp")
        };
        assert_eq!(op, "+");
        assert_eq!(**left, var("z"));
        assert_eq!(**right, Rhs::Const(ConstValue::Int(5)));
    }

    #[test]
    fn test_chained_assignment() {
        let ir = lower("x = y = 5;");
        let a = assigns(&ir);
        assert_eq!(a.len(), 2);
        let IrStmt::Assign { lhs: lhs0, .. } = a[0] else {
            panic!()
        };
        let IrStmt::Assign { lhs: lhs1, .. } = a[1] else {
            panic!()
        };
        assert_eq!(*lhs0, Lhs::VarLhs("y".to_string()));
        assert_eq!(*lhs1, Lhs::VarLhs("x".to_string()));
    }

    // --------------------------- calls — statement vs sub-expression

    #[test]
    fn test_call_as_statement() {
        let ir = lower("obj.Method(input);");
        let c = calls(&ir);
        assert_eq!(c.len(), 1);
        let IrStmt::Call { callee, args, .. } = c[0] else {
            panic!()
        };
        assert_eq!(*callee, attr(var("obj"), "Method"));
        assert_eq!(*args, vec![var("input")]);
    }

    #[test]
    fn test_call_without_receiver() {
        let ir = lower("DoIt(input);");
        let c = calls(&ir);
        let IrStmt::Call { callee, .. } = c[0] else {
            panic!()
        };
        assert_eq!(*callee, var("DoIt"));
    }

    #[test]
    fn test_call_as_subexpression_produces_assign_temp() {
        let ir = lower("string s = GetInput(input);");
        let a = assigns(&ir);
        let call_assign = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::CallRef { callee, args, .. } = rhs {
                Some((callee, args))
            } else {
                None
            }
        });
        let (callee, args) = call_assign.unwrap();
        assert_eq!(**callee, var("GetInput"));
        assert_eq!(*args, vec![var("input")]);
        let IrStmt::Assign { lhs, .. } = a[a.len() - 1] else {
            panic!()
        };
        assert_eq!(*lhs, Lhs::VarLhs("s".to_string()));
    }

    #[test]
    fn test_object_creation() {
        let ir = lower("var o = new Foo(input);");
        let a = assigns(&ir);
        let creation = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::CallRef { callee, args, .. } = rhs {
                Some((callee, args))
            } else {
                None
            }
        });
        let (callee, args) = creation.unwrap();
        assert_eq!(**callee, var("Foo"));
        assert_eq!(*args, vec![var("input")]);
    }

    /// The callee and the arguments of the first call built in `ir`.
    fn first_creation(ir: &[IrStmt]) -> (Rhs, Vec<Rhs>) {
        ir.iter()
            .find_map(|s| match s {
                IrStmt::Assign {
                    rhs: Rhs::CallRef { callee, args, .. },
                    ..
                } => Some(((**callee).clone(), args.clone())),
                _ => None,
            })
            .expect("an object creation")
    }

    /// Whether `ir` assigns a local of that name.
    fn assigns_local(ir: &[IrStmt], name: &str) -> bool {
        ir.iter().any(|s| {
            matches!(
                s,
                IrStmt::Assign { lhs: Lhs::VarLhs(local), .. } if local == name
            )
        })
    }

    #[test]
    fn test_object_initializer_values_are_constructor_arguments() {
        // Ticket #268: the property values follow the constructor's own
        // arguments, and the member names are not assigned as locals.
        let ir = lower("var o = new CookieOptions(n) { Domain = input, HttpOnly = true };");
        let (callee, args) = first_creation(&ir);
        assert_eq!(callee, var("CookieOptions"));
        assert_eq!(
            args,
            vec![var("n"), var("input"), Rhs::Const(ConstValue::Bool(true))]
        );
        assert!(!assigns_local(&ir, "Domain"), "{ir:?}");
        assert!(!assigns_local(&ir, "HttpOnly"), "{ir:?}");
    }

    #[test]
    fn test_object_initializer_without_parentheses_over_several_lines() {
        let ir =
            lower("var o = new CookieOptions\n{\n    HttpOnly = true,\n    Domain = input\n};");
        let (callee, args) = first_creation(&ir);
        assert_eq!(callee, var("CookieOptions"));
        assert_eq!(args, vec![Rhs::Const(ConstValue::Bool(true)), var("input")]);
        // The call is on the line of `new`.
        let line = ir.iter().find_map(|s| match s {
            IrStmt::Assign {
                rhs: Rhs::CallRef { .. },
                lineno,
                ..
            } => Some(*lineno),
            _ => None,
        });
        assert_eq!(line, Some(1));
    }

    #[test]
    fn test_collection_and_nested_initializer_values() {
        let ir =
            lower("var d = new Dictionary<string, string> { [\"k\"] = input, { \"a\", \"b\" } };");
        let (callee, args) = first_creation(&ir);
        assert_eq!(callee, var("Dictionary"));
        assert_eq!(
            args,
            vec![
                Rhs::Const(ConstValue::Str("k".to_string())),
                var("input"),
                Rhs::Const(ConstValue::Str("a".to_string())),
                Rhs::Const(ConstValue::Str("b".to_string())),
            ]
        );
        let ir = lower("var p = new Process { StartInfo = { FileName = input } };");
        let (_, args) = first_creation(&ir);
        assert_eq!(args, vec![var("input")]);
        assert!(!assigns_local(&ir, "FileName"), "{ir:?}");
    }

    #[test]
    fn test_implicit_object_creation_initializer_values() {
        let ir = lower("CookieOptions o = new() { Domain = input };");
        let (callee, args) = first_creation(&ir);
        assert_eq!(callee, var("CookieOptions"));
        assert_eq!(args, vec![var("input")]);
        assert!(!assigns_local(&ir, "Domain"), "{ir:?}");
    }

    /// The callee of every target-typed `new(...)` of the class `src`, in
    /// source order.
    fn target_typed_callees(src: &str) -> Vec<Rhs> {
        let tree = parse_csharp(src);
        assert!(
            !tree.root_node().has_error(),
            "syntaxe C# invalide : {src:?}"
        );
        let mut nodes = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "implicit_object_creation_expression" {
                nodes.push(node);
            }
            let mut w = node.walk();
            let children: Vec<Node> = node.children(&mut w).collect();
            stack.extend(children.into_iter().rev());
        }
        nodes
            .into_iter()
            .map(|node| {
                let mut lowerer = CSharpLowerer::new(src.as_bytes());
                lowerer.lower_expr(Some(node));
                first_creation(&lowerer.output).0
            })
            .collect()
    }

    #[test]
    fn test_target_typed_new_takes_the_declared_type() {
        // Ticket #268: a field, a property, a nullable local, a later
        // assignment to a local, a parameter and a field, an argument of a
        // method of the class (by position and by name), a returned value.
        let src = r#"
class C {
    private CookieOptions field = new() { Domain = "a" };
    public Options.Cookie Prop { get; set; } = new();
    CookieOptions Make() { return new() { Domain = "b" }; }
    CookieOptions Arrow() => new();
    void Keep(string key, CookieOptions options) { }
    void T(HttpOptions p) {
        CookieOptions? local = new();
        CookieOptions later;
        later = new() { Domain = "c" };
        p = new();
        this.field = new();
        Keep("k", new());
        Keep(options: new(), key: "k");
    }
}"#;
        assert_eq!(
            target_typed_callees(src),
            vec![
                var("CookieOptions"),
                attr(var("Options"), "Cookie"),
                var("CookieOptions"),
                var("CookieOptions"),
                var("CookieOptions"),
                var("CookieOptions"),
                var("HttpOptions"),
                var("CookieOptions"),
                var("CookieOptions"),
                var("CookieOptions"),
            ]
        );
    }

    #[test]
    fn test_target_typed_new_without_a_declared_type_stays_new() {
        // An argument of a library method, a lambda's return value, an
        // assignment to a name the code does not declare.
        let src = r#"
class C {
    void T() {
        Response.Cookies.Append("k", "v", new() { Domain = "d" });
        Func<CookieOptions> f = () => { return new(); };
        unknown = new();
    }
}"#;
        assert_eq!(
            target_typed_callees(src),
            vec![var("new"), var("new"), var("new")]
        );
    }

    #[test]
    fn test_qualified_object_creation() {
        let ir = lower("var o = new System.IO.FileStream(input);");
        let a = assigns(&ir);
        let callee = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::CallRef { callee, .. } = rhs {
                Some(callee)
            } else {
                None
            }
        });
        assert_eq!(
            **callee.unwrap(),
            attr(attr(var("System"), "IO"), "FileStream")
        );
    }

    #[test]
    fn test_member_access_chained_call() {
        let ir = lower("var r = obj.Method(a, b);");
        let a = assigns(&ir);
        let call = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::CallRef { callee, args, .. } = rhs {
                Some((callee, args))
            } else {
                None
            }
        });
        let (callee, args) = call.unwrap();
        assert_eq!(**callee, attr(var("obj"), "Method"));
        assert_eq!(*args, vec![var("a"), var("b")]);
    }

    /// Ticket #284: `new Repo(x).Find(id)` keeps the constructor call as
    /// the receiver (as Java does), so the class `Repo` can be read back;
    /// no temporary stands for the created object.
    #[test]
    fn test_constructor_chain_keeps_the_class() {
        let ir = lower("var r = new Repo(x).Find(id);");
        let a = assigns(&ir);
        let call = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::CallRef { callee, args, .. } = rhs {
                Some((callee, args))
            } else {
                None
            }
        });
        let (callee, args) = call.unwrap();
        assert_eq!(
            **callee,
            Rhs::AttrRef {
                base: Box::new(Rhs::CallRef {
                    callee: Box::new(var("Repo")),
                    args: vec![var("x")],
                    kwargs: Vec::new(),
                }),
                attr: "Find".to_string(),
            }
        );
        assert_eq!(*args, vec![var("id")]);
    }

    // ---------------------------------------------- conditional access (?.)

    #[test]
    fn test_conditional_access_member() {
        let ir = lower("var y = obj?.field;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, attr(var("obj"), "field"));
    }

    #[test]
    fn test_conditional_access_call() {
        let ir = lower("var z = obj?.Method();");
        let a = assigns(&ir);
        let call = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::CallRef { callee, .. } = rhs {
                Some(callee)
            } else {
                None
            }
        });
        assert_eq!(**call.unwrap(), attr(var("obj"), "Method"));
    }

    // ------------------------------------------------------------- literals

    #[test]
    fn test_string_literal_simple() {
        let ir = lower(r#"string s = "hello";"#);
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Str("hello".to_string())));
    }

    #[test]
    fn test_verbatim_string_literal_unescapes_quotes() {
        let ir = lower(r#"string s = @"a""b";"#);
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Str("a\"b".to_string())));
    }

    #[test]
    fn test_interpolated_string_propagates_taint_via_binop_chain() {
        let ir = lower(r#"string s = $"a{x}b{y}c";"#);
        let a = assigns(&ir);
        // At least two chained BinOp("+", ...) to concatenate 3
        // literal fragments and 2 interpolations.
        let plus_count = a
            .iter()
            .filter(|s| {
                matches!(
                    s,
                    IrStmt::Assign {
                        rhs: Rhs::BinOp { op, .. },
                        ..
                    } if op == "+"
                )
            })
            .count();
        assert!(plus_count >= 2, "plus_count={plus_count}");
    }

    #[test]
    fn test_boolean_literals() {
        let ir = lower("bool a = true; bool b = false;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs: r0, .. } = a[0] else {
            panic!()
        };
        let IrStmt::Assign { rhs: r1, .. } = a[1] else {
            panic!()
        };
        assert_eq!(*r0, Rhs::Const(ConstValue::Bool(true)));
        assert_eq!(*r1, Rhs::Const(ConstValue::Bool(false)));
    }

    #[test]
    fn test_null_literal() {
        let ir = lower("object o = null;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::None));
    }

    #[test]
    fn test_integer_literal() {
        let ir = lower("int x = 42;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Int(42)));
    }

    #[test]
    fn test_long_literal_suffix_stripped() {
        let ir = lower("long l = 10L;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Int(10)));
    }

    #[test]
    fn test_float_literal() {
        let ir = lower("double d = 2.5;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, Rhs::Const(ConstValue::Float(2.5)));
    }

    // ------------------------------------------- containers / composite exprs

    #[test]
    fn test_array_initializer() {
        let ir = lower("int[] arr = {1, 2, 3};");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(
            *rhs,
            Rhs::ListRef(vec![
                Rhs::Const(ConstValue::Int(1)),
                Rhs::Const(ConstValue::Int(2)),
                Rhs::Const(ConstValue::Int(3)),
            ])
        );
    }

    #[test]
    fn test_ternary_conditional_expression() {
        let ir = lower(r#"string a = cond ? input : "safe";"#);
        let a = assigns(&ir);
        let ternary = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::IfExp { cond, then, orelse } = rhs {
                Some((cond, then, orelse))
            } else {
                None
            }
        });
        let (cond, then, orelse) = ternary.unwrap();
        assert_eq!(**cond, var("cond"));
        assert_eq!(**then, var("input"));
        assert_eq!(**orelse, Rhs::Const(ConstValue::Str("safe".to_string())));
    }

    #[test]
    fn test_cast_passthrough() {
        let ir = lower("string r = (string)input;");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(*rhs, var("input"));
    }

    #[test]
    fn test_lambda_parenthesized_no_params() {
        let ir = lower("Action lam = () => DoIt();");
        let a = assigns(&ir);
        let IrStmt::Assign { rhs, .. } = a[0] else {
            panic!()
        };
        assert_eq!(
            *rhs,
            Rhs::LambdaRef {
                arg_names: Vec::new()
            }
        );
    }

    #[test]
    fn test_lambda_implicit_single_param_no_parens() {
        let ir = lower("Action<int> f = p => DoIt(p);");
        let a = assigns(&ir);
        let names = a.iter().find_map(|s| {
            let IrStmt::Assign { rhs, .. } = s else {
                return None;
            };
            if let Rhs::LambdaRef { arg_names } = rhs {
                Some(arg_names)
            } else {
                None
            }
        });
        assert_eq!(*names.unwrap(), vec!["p".to_string()]);
    }

    // -------------------------------------------------------- return / throw

    #[test]
    fn test_return_value() {
        let ir = lower("return input;");
        let IrStmt::Return { value, .. } = &ir[0] else {
            panic!("expected Return")
        };
        assert_eq!(*value, Some(var("input")));
    }

    #[test]
    fn test_return_void() {
        let ir = lower("return;");
        let IrStmt::Return { value, .. } = &ir[0] else {
            panic!("expected Return")
        };
        assert_eq!(*value, None);
    }

    #[test]
    fn test_throw() {
        let ir = lower("throw new Exception(input);");
        let raises: Vec<&IrStmt> = ir
            .iter()
            .filter(|s| matches!(s, IrStmt::Raise { .. }))
            .collect();
        assert_eq!(raises.len(), 1);
        let IrStmt::Raise { value, .. } = raises[0] else {
            panic!()
        };
        assert!(value.is_some());
    }

    // ---------------------------------------------------------- using / lock

    #[test]
    fn test_using_resource_bare_variable_declaration() {
        with_body_stmts("using (var x = Open(input)) { Use(x); }", |src, stmts| {
            let using_stmt = stmts[0];
            let resource = using_stmt
                .named_children(&mut using_stmt.walk())
                .find(|c| c.kind() == "variable_declaration")
                .unwrap();
            let ir = lower_stmt(src.as_bytes(), resource);
            let a = assigns(&ir);
            // Two Assigns: the CallRef temporary for `Open(input)`,
            // then the declarator's actual assignment `x := __t0`.
            let IrStmt::Assign { lhs, .. } = a[a.len() - 1] else {
                panic!()
            };
            assert_eq!(*lhs, Lhs::VarLhs("x".to_string()));
        });
    }

    #[test]
    fn test_lock_lowers_lock_expr_not_body() {
        with_body_stmts("lock (obj) { DoIt(input); }", |src, stmts| {
            let ir = lower_stmt(src.as_bytes(), stmts[0]);
            let c = calls(&ir);
            assert!(!c.iter().any(|s| {
                let IrStmt::Call { callee, .. } = s else {
                    return false;
                };
                *callee == var("DoIt")
            }));
        });
    }

    // -------------------- lower_condition / lower_for_target_assign

    #[test]
    fn test_condition_call_unwraps_parenthesized() {
        with_body_stmts("if (IsValid(input)) { DoIt(); }", |src, stmts| {
            let cond = stmts[0].child_by_field_name("condition").unwrap();
            let ir = lower_condition(src.as_bytes(), cond);
            assert_eq!(ir.len(), 1);
            let IrStmt::Call { callee, .. } = &ir[0] else {
                panic!("expected Call")
            };
            assert_eq!(*callee, var("IsValid"));
        });
    }

    #[test]
    fn test_condition_comparison_keeps_temp() {
        with_body_stmts("if (x > 0) { DoIt(); }", |src, stmts| {
            let cond = stmts[0].child_by_field_name("condition").unwrap();
            let ir = lower_condition(src.as_bytes(), cond);
            assert!(ir.iter().any(|s| matches!(
                s,
                IrStmt::Assign {
                    rhs: Rhs::Cmp { .. },
                    ..
                }
            )));
        });
    }

    #[test]
    fn test_for_target_assign() {
        with_body_stmts("foreach (var s in items) { Use(s); }", |src, stmts| {
            let for_stmt = stmts[0];
            let target = for_stmt.child_by_field_name("left").unwrap();
            let iterable = for_stmt.child_by_field_name("right").unwrap();
            let ir = lower_for_target_assign(src.as_bytes(), target, iterable);
            assert_eq!(ir.len(), 1);
            let IrStmt::Assign { lhs, rhs, .. } = &ir[0] else {
                panic!("expected Assign")
            };
            assert_eq!(*lhs, Lhs::VarLhs("s".to_string()));
            assert_eq!(*rhs, var("items"));
        });
    }

    // ------------------------------------------------------- conservative fallback

    #[test]
    fn test_unknown_statement_type_is_noop() {
        // `goto` is not handled by `lower_stmt` (unmodeled construct,
        // cf. module doc) — Noop fallback.
        let ir = lower("goto done; done: ;");
        assert!(matches!(ir[0], IrStmt::Noop { .. }));
    }
}
