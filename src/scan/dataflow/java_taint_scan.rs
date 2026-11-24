//! Taint scan for a single Java file — faithful port of the
//! central flow of `Audit/sca/executors/dataflow_taint_java.py::
//! run_taint_rule_java` (one CFG per method/constructor — Java has
//! no executable statement outside a method body, unlike
//! Python which has an extra "module level" pass).
//!
//! **Scope of this module**: a single file, `specs.summaries`/
//! `specs.type_map` supplied by the caller — same split as
//! `taint_scan.rs` (Python): this module does NOT itself build the
//! summaries (role of `java_call_graph::JavaCallGraph::resolve_summaries`,
//! wiring left to the orchestrator), unlike
//! `dataflow_taint_java.py::run_taint_rule_java` which computes them
//! internally (`compute_java_file_summaries`/`extra_summaries`) — a split
//! already established on the Rust side for Python (`orchestrator.rs` does this work
//! once per batch of files, not per rule call).
#![allow(dead_code)]

use tree_sitter::Node;

use std::collections::BTreeMap;

use super::java_summary::{JavaFunctionInfo, prepare_java_file};
use super::lattice::{
    SourceInfo, State, Taint, empty_state, join, state_get, state_join, state_put, state_set,
};
use super::line_facts::{RuleLines, SourceLines};
use super::prepared::{PreparedCfg, PreparedFile};
use super::transfer::{Finding, RuleSpecs};

/// Runs a taint rule on an already-parsed Java file.
///
/// Each method/constructor is analyzed as an independent CFG.
/// A Spring route parameter (`@RequestParam`/... or implicit on
/// a mapped handler `@GetMapping`/...) has its entry state seeded
/// tainted `http` — Java equivalent of `route_source_params`
/// (`taint_scan.rs`, Python), computed once by
/// `java_summary::collect_java_functions` (`JavaFunctionInfo::
/// route_param_names`). Final global deduplication by
/// `(rule_id, line, source_line)`.
pub fn run_taint_rule_java<'tree>(
    root: Node<'tree>,
    source: &'tree [u8],
    specs: &RuleSpecs,
    source_lines: Option<&SourceLines>,
) -> Vec<Finding> {
    run_taint_rule_java_prepared(
        &prepare_java_file(root, source),
        specs,
        source_lines.map(|lines| RuleLines::new(lines, specs)),
    )
}

/// [`run_taint_rule_java`] on a file already prepared by
/// `java_summary::prepare_java_file`: the scan prepares each file once
/// for all its rules (ticket #192).
pub fn run_taint_rule_java_prepared(
    file: &PreparedFile<JavaFunctionInfo>,
    specs: &RuleSpecs,
    rule_lines: Option<RuleLines>,
) -> Vec<Finding> {
    let mut all_findings: Vec<Finding> = Vec::new();
    // Taint written into a field of its class by each method, joined per
    // class: the first pass below collects it, the second hands it to the
    // other methods of the class (see `field_taints_at_exit`).
    let mut tainted_fields: BTreeMap<&str, State> = BTreeMap::new();

    for function in &file.functions {
        let Some(prepared) = function.body.as_ref() else {
            continue;
        };
        let fn_info = &function.info;
        let init_state = entry_state(fn_info, specs);
        let result = prepared.analyze(specs, init_state.as_ref(), rule_lines.as_ref());
        let written = field_taints_at_exit(fn_info, prepared, &result.state_in);
        if !written.is_empty() {
            let class = tainted_fields.entry(class_of(fn_info)).or_default();
            *class = state_join(class, &written);
        }
        all_findings.extend(result.findings);
    }

    // Second pass, only for the classes where a method left a field
    // tainted: every method of the class starts with those fields tainted.
    // Juliet's flow variant 45 writes the source into `dataBad` in `bad()`
    // and reads it in `badSink()`, which takes no argument. Deliberate
    // deviation from the Audit, which analyzes each method alone and never
    // follows a field from one method to another. Flow-insensitive on
    // purpose: the order in which the methods run is not known, a field
    // written tainted anywhere is read tainted everywhere in its class. One
    // round only: a field copied from another tainted field in a third
    // method is not followed further. Only the `String` fields of the class
    // (`JavaFunctionInfo::class_fields`). A parameter of the same name as the
    // field (`Foo(String name) { this.name = name; }`) is not seeded: the
    // bare name is the parameter there.
    if !tainted_fields.is_empty() {
        for function in &file.functions {
            let Some(prepared) = function.body.as_ref() else {
                continue;
            };
            let fn_info = &function.info;
            let Some(fields) = tainted_fields.get(class_of(fn_info)) else {
                continue;
            };
            let mut state = entry_state(fn_info, specs).unwrap_or_else(empty_state);
            for (name, taint) in fields {
                if !fn_info.param_names.iter().any(|p| p.as_str() == &**name) {
                    state_put(&mut state, name, taint.clone());
                }
                state_put(&mut state, &format!("this.{name}"), taint.clone());
            }
            let result = prepared.analyze(specs, Some(&state), rule_lines.as_ref());
            all_findings.extend(result.findings);
        }
    }

    let mut seen: std::collections::HashSet<(String, usize, Option<usize>)> =
        std::collections::HashSet::new();
    all_findings.retain(|f| seen.insert((f.rule_id.clone(), f.line, f.source_line)));
    all_findings
}

/// The class of a collected method: its name up to the last dot
/// (`Outer.badSink` → `Outer`).
fn class_of(fn_info: &JavaFunctionInfo) -> &str {
    fn_info
        .name
        .rsplit_once('.')
        .map_or(fn_info.name.as_str(), |(class, _)| class)
}

/// The fields of its class that a method leaves tainted when it returns,
/// read on the state that enters the exit node of its CFG: the bare name
/// (`dataBad = data;`) and the qualified one (`this.dataBad = data;`), both
/// recorded under the bare name. A field named like one of the method's
/// parameters is read only through `this.`: the bare name is the parameter.
fn field_taints_at_exit(
    fn_info: &JavaFunctionInfo,
    prepared: &PreparedCfg,
    state_in: &BTreeMap<usize, State>,
) -> State {
    let mut written = empty_state();
    if fn_info.class_fields.is_empty() {
        return written;
    }
    let Some(exit_state) = state_in.get(&prepared.exit()) else {
        return written;
    };
    for field in &fn_info.class_fields {
        let mut taint = state_get(exit_state, &format!("this.{field}"));
        if !fn_info.param_names.contains(field) {
            taint = join(&taint, &state_get(exit_state, field));
        }
        if taint.is_tainted() {
            state_put(&mut written, field, taint);
        }
    }
    written
}

/// The state a method starts with: its Spring route parameters, and the
/// parameters whose annotation matches a source of the rule, tainted;
/// `None` when there is none.
fn entry_state(fn_info: &JavaFunctionInfo, specs: &RuleSpecs) -> Option<State> {
    let mut state = empty_state();
    let mut seeded = false;
    for pname in &fn_info.route_param_names {
        state = state_set(
            &state,
            pname,
            Taint::tainted(
                ["http".to_string()],
                SourceInfo {
                    line: fn_info.lineno,
                    expr: format!("{}({pname})", fn_info.name).into(),
                    kind: "http".into(),
                },
            ),
        );
        seeded = true;
    }
    // A parameter whose annotation matches a source of the rule
    // (`@FormParam("uid") String uid` for `source @FormParam\s*\(`),
    // tested against its own annotations only, so `@Context
    // HttpServletRequest request` beside it stays clean — the Audit's
    // lexical reading of JAX-RS parameters (`java_summary::
    // annotated_params`). A Spring route parameter keeps its seed.
    for (pname, annotations) in &fn_info.annotated_params {
        if fn_info.route_param_names.contains(pname) {
            continue;
        }
        let matching = specs.sources.iter().find(|src| {
            src.raw_regex
                .as_ref()
                .is_some_and(|re| annotations.iter().any(|a| re.is_match(a).unwrap_or(false)))
        });
        if let Some(src) = matching {
            state = state_set(
                &state,
                pname,
                Taint::tainted(
                    [src.kind.clone()],
                    SourceInfo {
                        line: fn_info.lineno,
                        expr: format!("{}({pname})", fn_info.name).into(),
                        kind: src.kind.as_str().into(),
                    },
                ),
            );
            seeded = true;
        }
    }
    seeded.then_some(state)
}

// ============================================================================
// Tests — mirror the behavior cases (not rule_json/mode, covered
// elsewhere by `dispatch.rs`) of
// `Audit/tests/dataflow/test_dataflow_taint_java_executor.py`: constant
// folding (branches + switch), list simulation, interprocedural
// (summaries supplied + type_map), chained constructor call, Map put/get,
// explicit/implicit Spring route parameters — the requested quality bar
// (parity with or better than the Python engine) is about THIS
// behavior, not the rule_json/dispatch layer.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::transfer::{FunctionSummary, SanitizerSpec, SinkSpec, SourceSpec};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tree_sitter::Parser;

    fn parse(src: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_java::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        let tree = parser.parse(src, None).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "syntaxe Java invalide : {src:?}"
        );
        tree
    }

    fn sqli_specs() -> RuleSpecs {
        RuleSpecs {
            rule_id: "taint_sqli".to_string(),
            severity: "HIGH".to_string(),
            cwe: Some("CWE-89".to_string()),
            message: "test finding".to_string(),
            sources: vec![SourceSpec::new("*.getParameter", "http")],
            sinks: vec![SinkSpec::new("*.execute")],
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: BTreeMap::new(),
            type_map: BTreeMap::new(),
            summary_fallback: None,
            exprs: None,
        }
    }

    fn run(src: &str, specs: &RuleSpecs) -> Vec<Finding> {
        let tree = parse(src);
        let lines: SourceLines = src.lines().collect();
        run_taint_rule_java(tree.root_node(), src.as_bytes(), specs, Some(&lines))
    }

    // ------------------------------------------------------------------
    // Basic: simple flow, clean, no source
    // ------------------------------------------------------------------

    #[test]
    fn test_source_to_sink_detected() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); db.execute(q); } }";
        let findings = run(src, &sqli_specs());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "taint_sqli");
        assert_eq!(findings[0].cwe, Some("CWE-89".to_string()));
    }

    #[test]
    fn test_clean_no_finding() {
        let src = "class Api { void handler(Statement db) { db.execute(\"SELECT 1\"); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_no_source_no_finding() {
        let src = "class Api { void handler(String q, Statement db) { db.execute(q); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_sanitized_no_finding() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = sanitize(req.getParameter(\"q\")); db.execute(q); } }";
        let mut specs = sqli_specs();
        specs.sanitizers.push(SanitizerSpec::new("sanitize"));
        assert!(run(src, &specs).is_empty());
    }

    #[test]
    fn test_flow_trace_present() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); db.execute(q); } }";
        let findings = run(src, &sqli_specs());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].flow.len() >= 2);
        assert_eq!(findings[0].flow[0].kind, "source");
        assert_eq!(findings[0].flow[findings[0].flow.len() - 1].kind, "sink");
    }

    #[test]
    fn test_multiple_methods_isolated() {
        let src = "class Api { void clean(Statement db) { db.execute(\"SELECT 1\"); } void vuln(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); db.execute(q); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    // ------------------------------------------------------------------
    // Constant folding (branches + switch) — OWASP BenchmarkJava calibration
    // ------------------------------------------------------------------

    #[test]
    fn test_arithmetic_constant_condition_eliminates_dead_branch() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); String bar; int num = 86; if ((7 * 42) - num > 200) { bar = \"always_this_branch\"; } else { bar = param; } db.execute(bar); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_constant_condition_still_detects_when_reachable() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); String bar; int num = 86; if ((7 * 42) - num > 200) { bar = param; } else { bar = \"never_this_branch\"; } db.execute(bar); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_non_constant_condition_still_conservative() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); String bar; if (req.getHeader(\"x-flag\") != null) { bar = param; } else { bar = \"safe\"; } db.execute(bar); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_switch_charat_const_eliminates_dead_case() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); String bar; String guess = \"ABC\"; char switchTarget = guess.charAt(1); switch (switchTarget) { case 'A': bar = param; break; case 'B': bar = \"bob\"; break; default: bar = \"bobs_uncle\"; break; } db.execute(bar); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_switch_charat_const_still_detects_active_case() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); String bar; String guess = \"ABC\"; char switchTarget = guess.charAt(1); switch (switchTarget) { case 'A': bar = \"safe\"; break; case 'B': bar = param; break; default: bar = \"bobs_uncle\"; break; } db.execute(bar); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_switch_on_non_constant_stays_conservative() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); String bar; char switchTarget = req.getHeader(\"x-flag\").charAt(0); switch (switchTarget) { case 'A': bar = param; break; default: bar = \"safe\"; break; } db.execute(bar); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    // ------------------------------------------------------------------
    // Positional list simulation
    // ------------------------------------------------------------------

    #[test]
    fn test_list_shuffle_pattern_resolves_clean() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); String bar = \"alsosafe\"; if (param != null) { java.util.List<String> valuesList = new java.util.ArrayList<String>(); valuesList.add(\"safe\"); valuesList.add(param); valuesList.add(\"moresafe\"); valuesList.remove(0); bar = valuesList.get(1); } db.execute(bar); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_list_get_at_tainted_index_still_detected() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); java.util.List<String> valuesList = new java.util.ArrayList<String>(); valuesList.add(\"safe\"); valuesList.add(param); String bar = valuesList.get(1); db.execute(bar); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    #[test]
    fn test_list_with_dynamic_content_stays_conservative() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String param = req.getParameter(\"q\"); java.util.List<String> valuesList = new java.util.ArrayList<String>(); valuesList.add(param); String bar = valuesList.get(0); db.execute(bar); } }";
        assert_eq!(run(src, &sqli_specs()).len(), 1);
    }

    // ------------------------------------------------------------------
    // Interprocedural resolution (summaries already supplied) — the
    // actual wiring of summaries is the role of the orchestrator/
    // `JavaCallGraph`, not of this module; here we just verify that
    // `analyze_java` correctly consults `specs.summaries`/
    // `specs.type_map` once supplied (same contract as the Python
    // test `extra_summaries`).
    // ------------------------------------------------------------------

    #[test]
    fn test_cross_method_summary_via_precomputed() {
        // The actual computation/wiring of intra-file summaries is the role
        // of the orchestrator (via `JavaCallGraph::resolve_summaries`,
        // already tested in `java_call_graph.rs`) — here we directly
        // supply the summary under its bare alias ("runQuery", added
        // by `add_bare_name_aliases` for an unqualified intra-class
        // call) and verify that `analyze_java` consults it
        // correctly.
        let src = "class Api { void runQuery(String query, Statement db) { db.execute(query); } void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); runQuery(q, db); } }";
        let mut specs = sqli_specs();
        let mut summary = FunctionSummary {
            name: "Api.runQuery".to_string(),
            param_names: vec!["query".to_string(), "db".to_string()],
            ..Default::default()
        };
        summary.sink_param_findings.insert(
            0,
            Finding {
                rule_id: "taint_sqli".to_string(),
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
            .insert("runQuery".to_string(), summary.into());
        assert!(!run(src, &specs).is_empty());
    }

    #[test]
    fn test_extra_summaries_cross_file_via_qualified_call() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); QueryRunner.runQuery(q, db); } }";
        let mut specs = sqli_specs();
        let mut summary = FunctionSummary {
            name: "QueryRunner.runQuery".to_string(),
            param_names: vec!["query".to_string(), "db".to_string()],
            ..Default::default()
        };
        summary.sink_param_findings.insert(
            0,
            Finding {
                rule_id: "taint_sqli".to_string(),
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
            .insert("QueryRunner.runQuery".to_string(), summary.into());
        assert!(!run(src, &specs).is_empty());
    }

    #[test]
    fn test_extra_summaries_via_typed_local_variable() {
        // Round 5 (calibration): `qr.runQuery(...)` where `qr` is a
        // typed LOCAL variable — requires RuleSpecs.type_map to
        // resolve to `QueryRunner.runQuery` despite the callee_name
        // "qr.runQuery".
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); QueryRunner qr = new QueryRunner(); qr.runQuery(q, db); } }";
        let mut specs = sqli_specs();
        specs
            .type_map
            .insert("qr".to_string(), "QueryRunner".to_string());
        let mut summary = FunctionSummary {
            name: "QueryRunner.runQuery".to_string(),
            param_names: vec!["query".to_string(), "db".to_string()],
            ..Default::default()
        };
        summary.sink_param_findings.insert(
            0,
            Finding {
                rule_id: "taint_sqli".to_string(),
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
            .insert("QueryRunner.runQuery".to_string(), summary.into());
        assert!(!run(src, &specs).is_empty());
    }

    #[test]
    fn test_typed_local_variable_no_summary_stays_conservative() {
        let src = "class Api { void handler(Statement db) { QueryRunner qr = new QueryRunner(); qr.doSomethingUnrelated(); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    // ------------------------------------------------------------------
    // Nested class + chained constructor call (round 6+7)
    // ------------------------------------------------------------------

    #[test]
    fn test_nested_class_constant_fold_suppresses_taint() {
        // The actual computation of the Test.doSomething summary (constant fold:
        // the return is always "always_this", never the parameter) is
        // the role of `compute_java_summary` (already tested in
        // `java_summary.rs`) — here we directly supply the already
        // computed summary (return_tainted_uncond=false, return_taint_params empty,
        // default values of `FunctionSummary`) and verify that
        // `eval_call` (Round 6, chained constructor call resolution)
        // does respect this narrowing rather than over-approximating.
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); String bar = new Test().doSomething(q); db.execute(bar); } private class Test { String doSomething(String param) { return \"always_this\"; } } }";
        let mut specs = sqli_specs();
        specs.summaries.insert(
            "Test.doSomething".to_string(),
            FunctionSummary {
                name: "Test.doSomething".to_string(),
                param_names: vec!["param".to_string()],
                ..Default::default()
            }
            .into(),
        );
        assert!(run(src, &specs).is_empty());
    }

    #[test]
    fn test_nested_class_passthrough_still_detected() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); String bar = new Test().doSomething(q); db.execute(bar); } private class Test { String doSomething(String param) { return param; } } }";
        assert!(!run(src, &sqli_specs()).is_empty());
    }

    // ------------------------------------------------------------------
    // Map put/get roundtrip (round 7)
    // ------------------------------------------------------------------

    #[test]
    fn test_map_put_get_roundtrip_propagates_taint() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>(); map.put(\"k\", q); String bar = (String) map.get(\"k\"); db.execute(bar); } }";
        assert!(!run(src, &sqli_specs()).is_empty());
    }

    // ------------------------------------------------------------------
    // Spring route parameters — explicit and implicit
    // ------------------------------------------------------------------

    #[test]
    fn test_request_param_seeded_reaches_sink() {
        let src =
            "class Api { void handler(@RequestParam String q, Statement db) { db.execute(q); } }";
        assert!(!run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_unannotated_param_not_seeded() {
        let src = "class Api { void handler(String q, Statement db) { db.execute(q); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_route_param_propagates_through_local_assignment() {
        let src = "class Api { void handler(@RequestParam String account, Statement db) { String q = \"SELECT * FROM t WHERE a = \" + account; db.execute(q); } }";
        assert!(!run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_container_type_param_not_seeded_even_if_annotated() {
        let src = "class Api { void handler(@RequestParam HttpServletRequest req, Statement db) { db.execute(req.toString()); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_unannotated_param_on_mapped_handler_reaches_sink() {
        let src = "class Api { @PostMapping(\"/x\") void handler(String query, Statement db) { db.execute(query); } }";
        assert!(!run(src, &sqli_specs()).is_empty());
    }

    #[test]
    fn test_unannotated_param_not_mapped_handler_no_finding() {
        let src = "class Api { void handler(String query, Statement db) { db.execute(query); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    // ------------------------------------------------------------------
    // JAX-RS / Jakarta EE parameters matched against the rule's sources
    // (ticket #178)
    // ------------------------------------------------------------------

    fn jaxrs_specs() -> RuleSpecs {
        let mut specs = sqli_specs();
        specs.sources.push(
            SourceSpec::new("@FormParam(", "http")
                .with_raw_regex(fancy_regex::Regex::new(r"@FormParam\s*\(").unwrap()),
        );
        specs
    }

    #[test]
    fn test_jaxrs_annotated_param_matching_a_source_reaches_sink() {
        let src = "class Api { void handler(@FormParam(\"uid\") String uid, Statement db) { db.execute(uid); } }";
        assert!(!run(src, &jaxrs_specs()).is_empty());
    }

    /// Only the parameter's own annotations count: `@Context` beside a
    /// `@FormParam` parameter stays clean.
    #[test]
    fn test_other_annotated_param_beside_jaxrs_param_stays_clean() {
        // On separate lines: a source regex also matches the raw line it
        // is written on, as in the Audit (§10bis).
        let src = "class Api {\n  void handler(@FormParam(\"uid\") String uid, @Context HttpServletRequest request, Statement db) {\n    db.execute(request.toString());\n  }\n}";
        assert!(run(src, &jaxrs_specs()).is_empty());
    }

    #[test]
    fn test_jaxrs_annotation_without_matching_source_not_seeded() {
        let src = "class Api { void handler(@FormParam(\"uid\") String uid, Statement db) { db.execute(uid); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    /// Deliberate deviation from the Audit: a second annotation is tested
    /// too (`@NotNull @FormParam(...)`).
    #[test]
    fn test_jaxrs_annotation_after_another_annotation_still_seeded() {
        let src = "class Api { void handler(@NotNull @FormParam(\"uid\") String uid, Statement db) { db.execute(uid); } }";
        assert!(!run(src, &jaxrs_specs()).is_empty());
    }

    #[test]
    fn test_container_type_not_seeded_even_on_mapped_handler() {
        let src = "class Api { @GetMapping(\"/x\") void handler(HttpServletRequest request, Statement db) { db.execute(request.toString()); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    // ------------------------------------------------------------------
    // Fields of the class (Juliet flow variant 45)
    // ------------------------------------------------------------------

    /// `bad()` writes the source into a field, `badSink()`, which takes no
    /// argument, reads it: the finding is at the sink of `badSink()`.
    #[test]
    fn test_field_written_in_one_method_reaches_sink_in_another() {
        let src = "class A {\n  private String dataBad;\n  void bad(HttpServletRequest req) {\n    String d = req.getParameter(\"q\");\n    dataBad = d;\n    badSink();\n  }\n  void badSink() {\n    String d = dataBad;\n    db.execute(d);\n  }\n}";
        let findings = run(src, &sqli_specs());
        assert_eq!(
            findings.iter().map(|f| f.line).collect::<Vec<_>>(),
            vec![10]
        );
    }

    /// The same flow written through `this.`.
    #[test]
    fn test_field_written_through_this_reaches_sink_in_another() {
        let src = "class A {\n  private String dataBad;\n  void bad(HttpServletRequest req) {\n    this.dataBad = req.getParameter(\"q\");\n  }\n  void badSink() {\n    db.execute(this.dataBad);\n  }\n}";
        assert_eq!(
            run(src, &sqli_specs())
                .iter()
                .map(|f| f.line)
                .collect::<Vec<_>>(),
            vec![7]
        );
    }

    /// Juliet's good variant: another field, written with a constant.
    #[test]
    fn test_field_written_with_a_constant_stays_clean() {
        let src = "class A {\n  private String dataBad;\n  private String dataGood;\n  void bad(HttpServletRequest req) {\n    dataBad = req.getParameter(\"q\");\n  }\n  void good() {\n    dataGood = \"foo\";\n  }\n  void goodSink() {\n    db.execute(dataGood);\n  }\n}";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    /// A parameter named like the field is the parameter: it is not
    /// tainted by the field.
    #[test]
    fn test_parameter_named_like_a_tainted_field_stays_clean() {
        let src = "class A {\n  private String name;\n  void set(HttpServletRequest req) {\n    name = req.getParameter(\"q\");\n  }\n  void use(String name) {\n    db.execute(name);\n  }\n}";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    /// Only `String` fields are handed on: an object field is not.
    #[test]
    fn test_object_field_is_not_shared() {
        let src = "class A {\n  private Holder holder;\n  void bad(HttpServletRequest req) {\n    holder = req.getParameter(\"q\");\n  }\n  void sink() {\n    db.execute(holder.describe());\n  }\n}";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    /// A field of another class of the file is not one of this class.
    #[test]
    fn test_field_of_another_class_is_not_shared() {
        let src = "class A {\n  private String data;\n  void bad(HttpServletRequest req) {\n    data = req.getParameter(\"q\");\n  }\n}\nclass B {\n  private String data;\n  void sink() {\n    db.execute(data);\n  }\n}";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    // ------------------------------------------------------------------
    // Calls on a constructor in parentheses, objects whose member is
    // tainted (Juliet flow variants 51 to 54 and 67)
    // ------------------------------------------------------------------

    fn sink_summary(name: &str) -> Arc<FunctionSummary> {
        let mut summary = FunctionSummary {
            name: name.to_string(),
            param_names: vec!["value".to_string(), "db".to_string()],
            ..Default::default()
        };
        summary.sink_param_findings.insert(
            0,
            Finding {
                rule_id: "taint_sqli".to_string(),
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
        summary.into()
    }

    /// `(new Runner()).run(q, db);` on its own line resolves the summary
    /// of `Runner.run`, as `new Runner().run(q, db)` used as a value did.
    #[test]
    fn test_parenthesized_constructor_call_statement_resolves_summary() {
        let mut specs = sqli_specs();
        specs
            .summaries
            .insert("Runner.run".to_string(), sink_summary("Runner.run"));
        let bad = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); (new Runner()).run(q, db); } }";
        assert!(!run(bad, &specs).is_empty());
        let unparenthesized = "class Api { void handler(HttpServletRequest req, Statement db) { String q = req.getParameter(\"q\"); new Runner().run(q, db); } }";
        assert!(!run(unparenthesized, &specs).is_empty());
        let good = "class Api { void handler(HttpServletRequest req, Statement db) { String q = \"foo\"; (new Runner()).run(q, db); } }";
        assert!(run(good, &specs).is_empty());
    }

    /// An object whose member holds the data, passed whole to a method
    /// that reaches a sink with it, carries the taint of that member.
    #[test]
    fn test_object_with_tainted_member_passed_whole_carries_it() {
        let mut specs = sqli_specs();
        specs
            .summaries
            .insert("Runner.run".to_string(), sink_summary("Runner.run"));
        let bad = "class Api { void handler(HttpServletRequest req, Statement db) { Container c = new Container(); c.value = req.getParameter(\"q\"); Runner.run(c, db); } }";
        assert!(!run(bad, &specs).is_empty());
        let good = "class Api { void handler(HttpServletRequest req, Statement db) { Container c = new Container(); c.value = \"foo\"; Runner.run(c, db); } }";
        assert!(run(good, &specs).is_empty());
        // `this` hands the whole state of the object: not its members.
        let this = "class Api { String value; void handler(HttpServletRequest req, Statement db) { this.value = req.getParameter(\"q\"); Runner.run(this, db); } }";
        assert!(run(this, &specs).is_empty());
        // An object whose members are sources of the rule (`request` for
        // `request.getParameter`) hands on the object, not its members.
        specs.sources = vec![SourceSpec::new("request.getParameter", "http")];
        let request = "class Api { void handler(HttpServletRequest request, Statement db) { request.extra = request.getParameter(\"q\"); Runner.run(request, db); } }";
        assert!(run(request, &specs).is_empty());
        let container = "class Api { void handler(HttpServletRequest request, Statement db) { Container c = new Container(); c.value = request.getParameter(\"q\"); Runner.run(c, db); } }";
        assert!(!run(container, &specs).is_empty());
    }

    /// A library call (no summary) keeps the object's own taint: the sink
    /// `db.execute(c)` is not reached by the taint of `c.value`.
    #[test]
    fn test_object_with_tainted_member_passed_to_a_library_call_stays_clean() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { Container c = new Container(); c.value = req.getParameter(\"q\"); db.execute(c); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }

    /// A line read from a reader built over a socket keeps the origin of the
    /// socket (`network`); read from a file, it is `file` data.
    #[test]
    fn test_line_read_from_a_tainted_reader_keeps_its_origin() {
        let mut specs = sqli_specs();
        specs.sources = vec![
            SourceSpec::new("*.getInputStream", "network"),
            SourceSpec::new("*.readLine", "file"),
        ];
        let socket = "class A {\n  void bad(Socket socket, Statement db) {\n    InputStreamReader in = new InputStreamReader(socket.getInputStream());\n    BufferedReader reader = new BufferedReader(in);\n    String d = reader.readLine();\n    db.execute(d);\n  }\n}";
        let findings = run(socket, &specs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source_kind, "network");
        assert_eq!(findings[0].source_line, Some(3));
        let file = "class A {\n  void bad(File f, Statement db) {\n    BufferedReader reader = new BufferedReader(new FileReader(f));\n    String d = reader.readLine();\n    db.execute(d);\n  }\n}";
        let findings = run(file, &specs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source_kind, "file");
        assert_eq!(findings[0].source_line, Some(4));
    }

    /// Calling a method on that object does not give its result the taint
    /// of the member: only the object read whole carries it.
    #[test]
    fn test_method_called_on_object_with_tainted_member_stays_clean() {
        let src = "class Api { void handler(HttpServletRequest req, Statement db) { Container c = new Container(); c.value = req.getParameter(\"q\"); String r = c.describe(); db.execute(r); } }";
        assert!(run(src, &sqli_specs()).is_empty());
    }
}
