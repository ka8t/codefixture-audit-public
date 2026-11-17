//! Taint scan for a single file — faithful port of the central flow of
//! `Audit/sca/executors/dataflow_taint.py::run_taint_rule` (module +
//! per-function sub-analysis, global deduplication). Python-only
//! scope (Decision #10).
//!
//! **Scope of this building block**: a single file, `specs.summaries`
//! supplied by the caller (empty for a purely intra-file rule;
//! populated by `call_graph::CallGraph::resolve_summaries` for
//! multi-file interprocedural resolution, wiring left to the
//! orchestrator).
#![allow(dead_code)]

use tree_sitter::Tree;

use super::lattice::{SourceInfo, Taint, empty_state, state_set};
use super::line_facts::RuleLines;
use super::prepared::PreparedFile;
use super::summary::{FunctionInfo, prepare_python_file, route_source_params, rule_source_kinds};
use super::transfer::{Finding, RuleSpecs};

/// Runs a taint rule on an already-parsed Python file.
///
/// Analyzes the module at the top level, then each function
/// definition as a standalone sub-module (Phase 6 — intra-file
/// interprocedural): a web route handler (FastAPI/Flask/Starlette)
/// has its scalar-annotated path/query parameters seeded as `http`
/// tainted on entry to its sub-analysis (`route_source_params`).
/// Final global deduplication by `(rule_id, line, source_line)`.
pub fn run_taint_rule(
    tree: &Tree,
    source: &[u8],
    specs: &RuleSpecs,
    source_lines: Option<&[String]>,
) -> Vec<Finding> {
    run_taint_rule_prepared(
        &prepare_python_file(tree.root_node(), source),
        source,
        specs,
        source_lines,
    )
}

/// [`run_taint_rule`] on a file already prepared by
/// `summary::prepare_python_file`: the scan prepares each file once for
/// all its rules (ticket #192). `source` is the file's text, read for
/// the route parameters of each function.
pub fn run_taint_rule_prepared(
    file: &PreparedFile<FunctionInfo>,
    source: &[u8],
    specs: &RuleSpecs,
    source_lines: Option<&[String]>,
) -> Vec<Finding> {
    // One per-line cache of the hybrid layer for every analysis of this
    // rule on this file (ticket #190).
    let rule_lines = source_lines.map(|lines| RuleLines::new(lines, specs));

    let mut all_findings: Vec<Finding> = match &file.module {
        Some(module) => module.analyze(specs, None, rule_lines.as_ref()).findings,
        None => Vec::new(),
    };

    let http_rule = rule_source_kinds(specs).iter().any(|k| k == "http");
    for function in &file.functions {
        let Some(sub_cfg) = function.body.as_ref() else {
            continue;
        };
        let fn_info = &function.info;

        // Deliberate deviation from Python (`dataflow_taint.py`, which
        // seeds route parameters for every taint rule): a rule whose
        // sources are not HTTP inputs (`llm_output_to_sink`: LLM answers
        // only) never sees them, otherwise every `.execute(` of a
        // FastAPI handler became "LLM output reaching a sink".
        let route_params = if http_rule {
            route_source_params(fn_info, source)
        } else {
            Vec::new()
        };
        let init_state = if route_params.is_empty() {
            None
        } else {
            let mut state = empty_state();
            for pname in &route_params {
                state = state_set(
                    &state,
                    pname,
                    Taint::tainted(
                        ["http".to_string()],
                        SourceInfo {
                            line: fn_info.lineno,
                            expr: format!("{}({pname})", fn_info.name).into(),
                            kind: "http".to_string(),
                        },
                    ),
                );
            }
            Some(state)
        };

        let sub_result = sub_cfg.analyze(specs, init_state.as_ref(), rule_lines.as_ref());
        all_findings.extend(sub_result.findings);
    }

    // Global deduplication — key (rule_id, line, source_line).
    let mut seen: std::collections::HashSet<(String, usize, Option<usize>)> =
        std::collections::HashSet::new();
    all_findings.retain(|f| seen.insert((f.rule_id.clone(), f.line, f.source_line)));
    all_findings
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::transfer::{SinkSpec, SourceSpec};
    use tree_sitter::Parser;

    fn parse(src: &str) -> Tree {
        let mut parser = Parser::new();
        let lang: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
        parser.set_language(&lang).unwrap();
        parser.parse(src, None).unwrap()
    }

    fn specs_with(sources: Vec<SourceSpec>, sinks: Vec<SinkSpec>) -> RuleSpecs {
        RuleSpecs {
            rule_id: "test-rule".to_string(),
            severity: "HIGH".to_string(),
            cwe: None,
            message: "test finding".to_string(),
            sources,
            sinks,
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: Default::default(),
            type_map: Default::default(),
        }
    }

    #[test]
    fn test_module_level_flow_detected() {
        let src = "x = input()\nos.system(x)\n";
        let tree = parse(src);
        let specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        let findings = run_taint_rule(&tree, src.as_bytes(), &specs, None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_intra_file_function_sub_analysis_detects_flow_inside_body() {
        // The source->sink flow is ENTIRELY inside the function body
        // (no interprocedural summary needed): the Phase 6
        // sub-analysis (function treated as a standalone sub-module)
        // must detect it, even though the real call site
        // (`handler()`) is elsewhere in the module.
        let src = "def handler():\n    os.system(input())\n\nhandler()\n";
        let tree = parse(src);
        let specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        let findings = run_taint_rule(&tree, src.as_bytes(), &specs, None);
        assert_eq!(
            findings.len(),
            1,
            "flux détecté par la sous-analyse du corps de handler"
        );
    }

    #[test]
    fn test_route_handler_params_seeded_as_http_source() {
        let src = "@app.get('/x')\ndef handler(item_id: str):\n    os.system(item_id)\n";
        let tree = parse(src);
        let specs = specs_with(vec![], vec![SinkSpec::new("os.system")]);
        let findings = run_taint_rule(&tree, src.as_bytes(), &specs, None);
        assert_eq!(
            findings.len(),
            1,
            "item_id (paramètre de route) doit être seedé tainté http"
        );
    }

    #[test]
    fn test_route_params_not_seeded_for_a_rule_without_http_source() {
        // `llm_output_to_sink` only takes LLM answers (`kind=network`):
        // a route parameter reaching `.execute(` is not its concern
        // (my-ia, 32 false positives on SQLAlchemy calls, 2026-11-14).
        let src = "@app.get('/x')\ndef handler(item_id: str):\n    db.execute(item_id)\n";
        let tree = parse(src);
        let specs = specs_with(
            vec![SourceSpec::new("response.text", "network")],
            vec![SinkSpec::new("db.execute")],
        );
        let findings = run_taint_rule(&tree, src.as_bytes(), &specs, None);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn test_route_params_typed_as_non_text_scalars_not_seeded() {
        // FastAPI converts `UUID`/`int`/`float`/`bool` parameters
        // before the handler runs: the value cannot hold a payload.
        let src = "@app.get('/x')\ndef handler(a: UUID, b: int, c: float, d: bool, e: str):\n    os.system(a)\n    os.system(b)\n    os.system(c)\n    os.system(d)\n    os.system(e)\n";
        let tree = parse(src);
        let specs = specs_with(vec![], vec![SinkSpec::new("os.system")]);
        let findings = run_taint_rule(&tree, src.as_bytes(), &specs, None);
        let lines: Vec<usize> = findings.iter().map(|f| f.line).collect();
        assert_eq!(lines, vec![7], "only the `str` parameter is a source");
    }

    #[test]
    fn test_non_route_function_params_not_seeded() {
        let src = "def helper(item_id):\n    os.system(item_id)\n";
        let tree = parse(src);
        let specs = specs_with(vec![], vec![SinkSpec::new("os.system")]);
        let findings = run_taint_rule(&tree, src.as_bytes(), &specs, None);
        assert!(
            findings.is_empty(),
            "pas de décorateur de route -> pas de seed automatique"
        );
    }

    #[test]
    fn test_dedup_across_module_and_function_scopes() {
        // A single os.system(x) call site at module level -> a single finding,
        // even if the module AND a possible sub-analysis both cross it.
        let src = "x = input()\nos.system(x)\n";
        let tree = parse(src);
        let specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        let findings = run_taint_rule(&tree, src.as_bytes(), &specs, None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_no_findings_when_clean() {
        let src = "x = 'safe'\nos.system(x)\n";
        let tree = parse(src);
        let specs = specs_with(
            vec![SourceSpec::new("input", "cli")],
            vec![SinkSpec::new("os.system")],
        );
        let findings = run_taint_rule(&tree, src.as_bytes(), &specs, None);
        assert!(findings.is_empty());
    }
}
