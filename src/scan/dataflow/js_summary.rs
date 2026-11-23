//! Discovery of JS functions and summaries for interprocedural
//! analysis — direct template of `java_summary.rs`.
//!
//! **Maximal reuse, not a port**: `compute_summary_prepared`
//! (`summary.rs`) already carries 100% of the probing algorithm —
//! language-neutral. `compute_js_summary` below only builds and
//! prepares the JS CFG (`prepare_js_file` for a whole file, once per
//! scan, ticket #192) and then delegates to
//! `summary::compute_summary_prepared`; no duplicated logic.
//!
//! **Interprocedural resolution wired in on 08/30** (`js_call_graph.rs`,
//! orchestrator): `js_call_graph.rs::JsCallGraph::build` builds its
//! graph by directly reusing `collect_js_functions`
//! (`JsFunctionInfo`), and `resolve_summaries` calls `compute_js_summary`
//! below for each node — the summary computation written here is
//! therefore no longer pending "groundwork", it is the core of
//! multi-file resolution. This module serves two well-separated needs:
//!   1. `collect_js_functions` — the list of functions/CFGs to scan,
//!      consumed directly by `js_taint_scan.rs` AND by
//!      `js_call_graph.rs` (needed even without a call graph: a scan
//!      must still analyze EVERY function in the file).
//!   2. `compute_js_summary`/`compute_js_file_summaries` — summary
//!      computation, consumed by `js_call_graph.rs::JsCallGraph::compute_one`.
//!
//! **Recursive discovery, not just top-level** (deliberate difference
//! from Java, whose `collect_java_functions` only descends into
//! top-level type declarations): unlike Java, the vast majority of
//! vulnerable JS code in practice lives in anonymous callbacks passed
//! as arguments (`app.get('/x', (req, res) =>
//! {...})` — the dominant Express pattern), not in named top-level
//! functions. `collect_js_functions` therefore walks the whole tree,
//! without limiting itself to top-level statements.
//!
//! **Accepted v1 limitation**: an `arrow_function` with an
//! expression-only body (`x => x + 1`, no `{ ... }`) is NOT collected
//! — `js_cfg.rs::build_js_cfg` requires a `statement_block` node as
//! input (same contract as Java `block`/
//! `constructor_body`). A simple-expression callback containing a
//! direct sink (`req => eval(req.query.q)`) will therefore not be
//! detected by the AST engine in v1 — documented gap, to be closed if
//! calibration reveals this pattern is common in practice (would
//! require a synthetic single-node CFG, not built here for now).

use super::line_facts::{RuleLines, SourceLines};
use super::prepared::{PreparedCfg, PreparedFile, PreparedFunction};
use super::transfer::{FunctionSummary, RuleSpecs};
use super::worklist::prepare_js_ir;
use tree_sitter::Node;

/// Metadata of a JS function (function declaration/expression, block-
/// bodied arrow function, class/object method).
///
/// `name`: best available name for debugging/future summaries — the
/// declaration's name, the name of the carrying variable/property for
/// an anonymous function that is assigned, or `"<anonymous>:<line>:<column>"` as
/// a last resort (callback passed directly as a call argument, e.g.
/// `app.get('/x', (req, res) => {...})`). NOT qualified by an enclosing
/// class in v1 (unlike Java's `Class.method`) — not needed as long as
/// no interprocedural resolution consumes this name.
// Clone: the call graph keeps a copy as its node, next to the
// prepared function that owns the original (ticket #192).
#[derive(Clone)]
pub struct JsFunctionInfo<'tree> {
    pub name: String,
    pub body_node: Node<'tree>,
    pub param_names: Vec<String>,
    pub lineno: usize,
    /// The first parameter of an AWS Lambda handler ([`is_lambda_handler`]),
    /// `None` for any other function. The event a Lambda receives is the
    /// caller's data: the scan seeds this parameter as an `http` source at
    /// the entry of the function (`js_taint_scan.rs`), as Java seeds the
    /// parameters of a Spring route.
    pub lambda_event: Option<String>,
}

const FUNCTION_LIKE_KINDS: [&str; 6] = [
    "function_declaration",
    "generator_function_declaration",
    "function_expression",
    "generator_function",
    "arrow_function",
    "method_definition",
];

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

fn param_names<'tree>(params_node: Option<Node<'tree>>, source: &[u8]) -> Vec<String> {
    let Some(params_node) = params_node else {
        return Vec::new();
    };
    // `x => ...` — single parameter without parentheses, the
    // `parameters` node is directly an `identifier`.
    if params_node.kind() == "identifier" {
        return vec![text(params_node, source)];
    }
    let mut names = Vec::new();
    let mut w = params_node.walk();
    for p in params_node.named_children(&mut w) {
        match p.kind() {
            "identifier" => names.push(text(p, source)),
            "required_parameter" | "optional_parameter" => {
                if let Some(pat) = p.named_children(&mut p.walk()).next()
                    && pat.kind() == "identifier"
                {
                    names.push(text(pat, source));
                }
            }
            "assignment_pattern" => {
                if let Some(left) = p.child_by_field_name("left")
                    && left.kind() == "identifier"
                {
                    names.push(text(left, source));
                }
            }
            "rest_pattern" => {
                if let Some(inner) = p.named_children(&mut p.walk()).next() {
                    names.push(text(inner, source));
                }
            }
            _ => {}
        }
    }
    names
}

/// Best available name for an anonymous function, inferred from the
/// immediate syntactic context (parent node): carrying
/// variable/property (`const foo = function() {...}`/`const foo = () => {...}`)
/// or object key (`{ key: () => {...} }`). `None` if no identifiable
/// named context exists (callback as a direct argument).
fn inferred_name_from_context<'tree>(node: Node<'tree>, source: &[u8]) -> Option<String> {
    let parent = node.parent()?;
    let candidate = match parent.kind() {
        "variable_declarator" => parent.child_by_field_name("name"),
        "pair" => parent.child_by_field_name("key"),
        "assignment_expression" => parent.child_by_field_name("left"),
        _ => None,
    }?;
    if candidate.kind() == "identifier" || candidate.kind() == "property_identifier" {
        Some(text(candidate, source))
    } else {
        None
    }
}

/// Lists all functions/methods of a JS file (full recursive tree walk,
/// see module doc). A function whose body is not a `statement_block`
/// (expression-bodied arrow) is skipped (accepted v1 limitation, see
/// module doc).
pub fn collect_js_functions<'tree>(root: Node<'tree>, source: &[u8]) -> Vec<JsFunctionInfo<'tree>> {
    let mut handler_names = Vec::new();
    collect_exported_handler_names(root, source, &mut handler_names);
    let mut functions = Vec::new();
    collect_functions_rec(root, source, &handler_names, &mut functions);
    functions
}

fn collect_functions_rec<'tree>(
    node: Node<'tree>,
    source: &[u8],
    handler_names: &[String],
    out: &mut Vec<JsFunctionInfo<'tree>>,
) {
    if FUNCTION_LIKE_KINDS.contains(&node.kind())
        && let Some(body) = node.child_by_field_name("body")
        && body.kind() == "statement_block"
    {
        let name = function_name(node, source);
        let param_names = param_names(node.child_by_field_name("parameters"), source);
        let lambda_event = is_lambda_handler(node, source, handler_names)
            .then(|| param_names.first().cloned())
            .flatten();
        out.push(JsFunctionInfo {
            name,
            body_node: body,
            param_names,
            lineno: node.start_position().row + 1,
            lambda_event,
        });
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        collect_functions_rec(child, source, handler_names, out);
    }
}

// ============================================================================
// AWS Lambda handlers (ticket #236)
// ============================================================================

/// Whether `node`, the left side of an assignment, names the exported
/// handler of a CommonJS module: `exports.handler` or
/// `module.exports.handler` (spaces ignored).
fn is_handler_export_target(node: Node, source: &[u8]) -> bool {
    let target: String = text(node, source).split_whitespace().collect();
    target == "exports.handler" || target == "module.exports.handler"
}

/// Whether `node` is the left side `module.exports` of an assignment.
fn is_module_exports(node: Node, source: &[u8]) -> bool {
    let target: String = text(node, source).split_whitespace().collect();
    target == "module.exports"
}

/// The `handler` entry of the object assigned to `module.exports`, when
/// `pair_or_shorthand` is one: `module.exports = { handler: f }` or
/// `module.exports = { handler }`.
fn is_handler_entry_of_module_exports(pair_or_shorthand: Node, source: &[u8]) -> bool {
    let key = match pair_or_shorthand.kind() {
        "pair" => pair_or_shorthand.child_by_field_name("key"),
        "shorthand_property_identifier" => Some(pair_or_shorthand),
        _ => None,
    };
    key.is_some_and(|key| text(key, source) == "handler")
        && pair_or_shorthand
            .parent()
            .filter(|object| object.kind() == "object")
            .and_then(|object| object.parent())
            .filter(|assign| assign.kind() == "assignment_expression")
            .and_then(|assign| assign.child_by_field_name("left"))
            .is_some_and(|left| is_module_exports(left, source))
}

/// The names exported as the Lambda handler by an identifier rather than
/// by a function written in place: `exports.handler = f`,
/// `module.exports.handler = f`, `module.exports = { handler: f }`,
/// `module.exports = { handler }` (the name `handler`). The function of
/// that name in the file is the handler — semgrep's
/// `function $FUNC ($EVENT, ...) {...} ... exports.handler = $FUNC`.
fn collect_exported_handler_names(node: Node, source: &[u8], out: &mut Vec<String>) {
    match node.kind() {
        "assignment_expression" => {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) && right.kind() == "identifier"
                && is_handler_export_target(left, source)
            {
                out.push(text(right, source));
            }
        }
        "pair" => {
            if let Some(value) = node.child_by_field_name("value")
                && value.kind() == "identifier"
                && is_handler_entry_of_module_exports(node, source)
            {
                out.push(text(value, source));
            }
        }
        "shorthand_property_identifier" if is_handler_entry_of_module_exports(node, source) => {
            out.push("handler".to_string());
        }
        _ => {}
    }
    let mut w = node.walk();
    for child in node.named_children(&mut w) {
        collect_exported_handler_names(child, source, out);
    }
}

/// Whether the function `node` is the handler of an AWS Lambda, the
/// function the Lambda runtime calls with the event it received as
/// first argument. The forms of semgrep's `aws-lambda` rules (their
/// `pattern-sources`), plus those of ES modules and of an exported
/// object, which the Lambda runtime of Node.js reads the same way:
///
/// - the function written in place: `exports.handler = function (event)
///   {...}`, `module.exports.handler = async (event) => {...}`,
///   `module.exports = { handler: async (event) => {...} }`;
/// - a function of the file exported by its name
///   ([`collect_exported_handler_names`]): `function f(event) {...}` or
///   `const f = (event) => {...}` or `f = function (event) {...}`, then
///   `exports.handler = f`;
/// - an ES module export named `handler`: `export async function
///   handler(event) {...}`, `export const handler = async (event) =>
///   {...}`.
///
/// A handler exported under another name (the runtime reads the name
/// from the function's configuration, `index.main`) is not recognized:
/// the file does not say it. An expression-bodied arrow is not collected
/// at all (module doc).
fn is_lambda_handler(node: Node, source: &[u8], handler_names: &[String]) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let declared_name = node.child_by_field_name("name").map(|n| text(n, source));
    match parent.kind() {
        "assignment_expression" => parent.child_by_field_name("left").is_some_and(|left| {
            is_handler_export_target(left, source)
                || (left.kind() == "identifier" && handler_names.contains(&text(left, source)))
        }),
        "pair" => is_handler_entry_of_module_exports(parent, source),
        "variable_declarator" => parent.child_by_field_name("name").is_some_and(|name| {
            let name = text(name, source);
            handler_names.contains(&name)
                || (name == "handler"
                    && parent
                        .parent()
                        .and_then(|declaration| declaration.parent())
                        .is_some_and(|p| p.kind() == "export_statement"))
        }),
        "export_statement" => declared_name.as_deref() == Some("handler"),
        _ => declared_name.is_some_and(|name| handler_names.contains(&name)),
    }
}

fn function_name(node: Node, source: &[u8]) -> String {
    if let Some(name_node) = node.child_by_field_name("name") {
        return text(name_node, source);
    }
    if let Some(inferred) = inferred_name_from_context(node, source) {
        return inferred;
    }
    // Line AND column (ticket #193): two anonymous functions on the same
    // line (`a.then(function () {...}).catch(function () {...})`) must not
    // share a name, or the call graph, which keys its nodes by
    // (file, name), would merge them into one node. Deliberate deviation
    // from the line-only name: no call ever resolves to this synthetic
    // name, it only has to be unique within the file.
    let pos = node.start_position();
    format!("<anonymous>:{}:{}", pos.row + 1, pos.column + 1)
}

// ============================================================================
// Summary computation (Phase 3 groundwork, not yet consumed)
// ============================================================================

/// Computes the summary of a JavaScript/TypeScript function: prepares its body,
/// then [`compute_js_summary_with`]. A caller that already holds the prepared
/// body (the call graph, ticket #192) calls [`compute_js_summary_with`].
pub fn compute_js_summary<'tree>(
    fn_info: &JsFunctionInfo<'tree>,
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&RuleLines>,
) -> FunctionSummary {
    let body = PreparedCfg::new(
        super::js_cfg::build_js_cfg(fn_info.body_node, source),
        source,
        prepare_js_ir,
    );
    compute_js_summary_with(fn_info, &body, specs, source_lines)
}

/// Summary of a JavaScript/TypeScript function whose body is already prepared
/// ([`prepare_js_file`]); delegates to the shared
/// probing algorithm (`summary::compute_summary_prepared`).
pub fn compute_js_summary_with(
    fn_info: &JsFunctionInfo,
    body: &PreparedCfg,
    specs: &RuleSpecs,
    source_lines: Option<&RuleLines>,
) -> FunctionSummary {
    super::summary::compute_summary_prepared(
        body,
        &fn_info.name,
        &fn_info.param_names,
        specs,
        source_lines,
        fn_info.lineno,
    )
}

/// Prepares a JavaScript/TypeScript file for every taint rule of the scan (ticket
/// #192): the module top level and every collected function.
pub fn prepare_js_file<'tree>(
    root: Node<'tree>,
    source: &'tree [u8],
) -> PreparedFile<'tree, JsFunctionInfo<'tree>> {
    PreparedFile {
        module: Some(PreparedCfg::new(
            super::js_cfg::build_js_cfg(root, source),
            source,
            prepare_js_ir,
        )),
        functions: collect_js_functions(root, source)
            .into_iter()
            .map(|info| PreparedFunction {
                body: Some(PreparedCfg::new(
                    super::js_cfg::build_js_cfg(info.body_node, source),
                    source,
                    prepare_js_ir,
                )),
                info,
            })
            .collect(),
    }
}

/// Computes the summaries of every function in a JS file. Mirror of
/// `compute_java_file_summaries` — no bare-name alias (unlike Java):
/// JS names are already not qualified by a class in v1, nothing to
/// disambiguate.
pub fn compute_js_file_summaries<'tree>(
    root: Node<'tree>,
    specs: &RuleSpecs,
    source: &'tree [u8],
    source_lines: Option<&SourceLines>,
) -> std::collections::BTreeMap<String, FunctionSummary> {
    // One per-line cache of the hybrid layer for every summary of this
    // rule on this file (ticket #190).
    let rule_lines = source_lines.map(|lines| RuleLines::new(lines, specs));
    let mut summaries = std::collections::BTreeMap::new();
    for fn_info in collect_js_functions(root, source) {
        let summary = compute_js_summary(&fn_info, specs, source, rule_lines.as_ref());
        summaries.insert(fn_info.name.clone(), summary);
    }
    summaries
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_js(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn test_collect_named_function_declaration() {
        let src = "function foo(a, b) { return a + b; }";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "foo");
        assert_eq!(functions[0].param_names, vec!["a", "b"]);
        assert_eq!(functions[0].lineno, 1);
    }

    #[test]
    fn test_collect_arrow_assigned_to_const() {
        let src = "const handler = (req, res) => { res.send(req.query.q); };";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "handler");
        assert_eq!(functions[0].param_names, vec!["req", "res"]);
    }

    #[test]
    fn test_collect_anonymous_callback_gets_synthetic_name() {
        let src = "app.get('/x', function(req, res) { res.send(req.query.q); });";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert!(functions[0].name.starts_with("<anonymous>:"));
    }

    #[test]
    fn test_two_anonymous_callbacks_on_one_line_get_distinct_names() {
        // Ticket #193: the synthetic name carries the column, so two
        // callbacks written on the same line stay two functions.
        let src = "p.then(function (a) { f(a); }).catch(function (e) { g(e); });";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        let names: Vec<&str> = functions.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["<anonymous>:1:8", "<anonymous>:1:38"]);
    }

    #[test]
    fn test_collect_arrow_callback_in_call_argument() {
        let src = "app.get('/x', (req, res) => { res.send(req.query.q); });";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
    }

    #[test]
    fn test_expression_bodied_arrow_not_collected() {
        let src = "const f = (a) => a + 1;";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert!(
            functions.is_empty(),
            "limitation acceptée v1, cf. doc de module"
        );
    }

    #[test]
    fn test_collect_class_method() {
        let src = "class C { method(x) { return x; } }";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "method");
    }

    #[test]
    fn test_collect_object_method_shorthand() {
        let src = "const obj = { m(a) { return a; } };";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "m");
    }

    #[test]
    fn test_collect_nested_functions() {
        let src = "function outer() { function inner() { return 1; } return inner(); }";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 2);
    }

    #[test]
    fn test_collect_generator_declaration() {
        let src = "function* gen() { yield 1; }";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "gen");
    }

    #[test]
    fn test_no_functions_in_plain_statements() {
        let src = "const x = 1; const y = x + 1;";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        assert!(functions.is_empty());
    }

    #[test]
    fn test_compute_js_summary_no_sink_no_findings() {
        let src = "function safe(a) { return a; }";
        let tree = parse_js(src);
        let functions = collect_js_functions(tree.root_node(), src.as_bytes());
        let specs = RuleSpecs {
            rule_id: "test_rule".to_string(),
            severity: "HIGH".to_string(),
            message: String::new(),
            cwe: None,
            sources: vec![],
            sinks: vec![],
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: Default::default(),
            type_map: Default::default(),
            summary_fallback: None,
            exprs: None,
        };
        let summary = compute_js_summary(&functions[0], &specs, src.as_bytes(), None);
        assert_eq!(summary.name, "safe");
        assert_eq!(summary.param_names, vec!["a"]);
    }

    /// The `lambda_event` of every collected function of `src`, by name.
    fn lambda_events(src: &str) -> Vec<(String, Option<String>)> {
        let tree = parse_js(src);
        collect_js_functions(tree.root_node(), src.as_bytes())
            .into_iter()
            .map(|f| (f.name, f.lambda_event))
            .collect()
    }

    #[test]
    fn test_lambda_handler_written_in_place() {
        // Ticket #236: the forms written in place, CommonJS and object.
        for src in [
            "exports.handler = function (event, context) { f(event); };",
            "module.exports.handler = async (event) => { f(event); };",
            "module.exports = { handler: async (event) => { f(event); } };",
        ] {
            let events: Vec<Option<String>> = lambda_events(src)
                .into_iter()
                .map(|(_, event)| event)
                .collect();
            assert_eq!(events, vec![Some("event".to_string())], "{src}");
        }
    }

    #[test]
    fn test_lambda_handler_exported_by_name() {
        // Ticket #236: a function of the file exported by its name, as in
        // semgrep's `exports.handler = $FUNC` patterns.
        for src in [
            "function main(e) { f(e); }\nexports.handler = main;",
            "const main = async (e) => { f(e); };\nmodule.exports.handler = main;",
            "var main;\nmain = function (e) { f(e); };\nexports.handler = main;",
            "const main = async (e) => { f(e); };\nmodule.exports = { handler: main };",
            "const handler = async (e) => { f(e); };\nmodule.exports = { handler };",
        ] {
            let events = lambda_events(src);
            assert_eq!(events.len(), 1, "{src}");
            assert_eq!(events[0].1.as_deref(), Some("e"), "{src}");
        }
    }

    #[test]
    fn test_lambda_handler_of_an_es_module() {
        for src in [
            "export async function handler(event) { f(event); }",
            "export const handler = async (event) => { f(event); };",
        ] {
            let events: Vec<Option<String>> = lambda_events(src)
                .into_iter()
                .map(|(_, event)| event)
                .collect();
            assert_eq!(events, vec![Some("event".to_string())], "{src}");
        }
    }

    #[test]
    fn test_other_functions_are_not_lambda_handlers() {
        // Another exported name, a local `handler` that is not exported,
        // a function nested in a handler, an Express callback.
        for src in [
            "exports.report = function (event) { f(event); };",
            "const handler = (event) => { f(event); };",
            "function handler(event) { f(event); }",
            "app.get('/x', function (req, res) { f(req); });",
            "module.exports = { report: async (event) => { f(event); } };",
            "other.exports.handler = function (event) { f(event); };",
        ] {
            assert!(
                lambda_events(src).iter().all(|(_, event)| event.is_none()),
                "{src}"
            );
        }
        let nested = lambda_events(
            "exports.handler = async (event) => { event.Records.forEach(function (r) { f(r); }); };",
        );
        assert_eq!(nested[0].1.as_deref(), Some("event"));
        assert_eq!(nested[1].1, None);
    }

    #[test]
    fn test_lambda_handler_without_parameter_seeds_nothing() {
        let events = lambda_events("exports.handler = async () => { f(); };");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1, None);
    }
}
