//! HTML rendering of findings, grouped by severity → business/deps →
//! category → rule — port of `_generate_fix_suggestion` and the
//! nested functions `render_finding_item`/`render_findings`/
//! `render_by_category` from `_generate_html` (`Audit/sca/report.py`).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::i18n::t;
use crate::project::suppress::line_hash;
use crate::report::exports::sarif::{ReportFinding, TaintFlow};
use crate::report::locale_format::LocaleFormat;
use crate::report::playbook::render_playbook_inline;
use crate::report::report_assets::load_template;
use crate::report::text::{escape, is_dependency, lang_label, linkify_acronyms, rule_display_name};
use crate::rules::identity::{RuleCatalog, RuleId};

/// Icon + i18n key (`category_titles.<key>`) for the 8 fixed
/// categories — mirrors `self.categories`/`cat_i18n_map`
/// (`sca/runner.py`).
pub(crate) const CATEGORIES: [(&str, &str, &str); 8] = [
    ("SECURITY", "🛡️", "security"),
    ("ARCH", "🏗️", "architecture"),
    ("UI", "🎨", "ui"),
    ("UX", "🔔", "ux"),
    ("MAINTENANCE", "♻️", "maintenance"),
    ("DEPENDENCIES", "📦", "dependencies"),
    ("DATABASE", "🗄️", "database"),
    ("CICD", "⚙️", "cicd"),
];

pub(crate) fn category_icon(category: &str) -> &'static str {
    CATEGORIES
        .iter()
        .find(|(k, _, _)| *k == category)
        .map(|(_, icon, _)| *icon)
        .unwrap_or("")
}

pub(crate) fn category_title(report_locale: &Value, category: &str) -> String {
    let i18n_key = CATEGORIES
        .iter()
        .find(|(k, _, _)| *k == category)
        .map(|(_, _, k)| *k);
    match i18n_key {
        Some(k) => t(report_locale, &format!("category_titles.{k}")),
        None => category.to_string(),
    }
}

/// Generates a before/after block (`fix_before`/`fix_after`) from the
/// compiled DSL rule — port of `_generate_fix_suggestion`.
/// `rule_catalog`: rule identity → compiled JSON (same objects as
/// `rule_jsons` in `orchestrator.rs`); `rule` is the identity of the
/// findings' rule, so a name shared by two languages shows the example of
/// the right one.
pub fn generate_fix_suggestion(
    rule_catalog: &RuleCatalog,
    rule_id: &RuleId,
    report_locale: &Value,
) -> String {
    let Some(rule) = rule_catalog.get(rule_id) else {
        return String::new();
    };
    let before = rule
        .get("fix_before")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let after = rule.get("fix_after").and_then(|v| v.as_str()).unwrap_or("");
    if before.is_empty() && after.is_empty() {
        return String::new();
    }
    // Escaped: the name is text of a rule file, a client's included.
    let rule_name = escape(&rule_display_name(rule, &t(report_locale, "locale_code")));
    let lbl = t(report_locale, "taint_fix_title");
    format!(
        r#"<details class="taint-fix"><summary>🔧 {lbl} — {rule_name}</summary><div class="fix-before"><strong>❌ {}</strong><pre><code>{}</code></pre></div><div class="fix-after"><strong>✅ {}</strong><pre><code>{}</code></pre></div></details>"#,
        t(report_locale, "taint_fix_before"),
        escape(before),
        t(report_locale, "taint_fix_after"),
        escape(after),
    )
}

/// Explains a `file_contains` rule (`requires: has/not_has`) in plain
/// terms — these rules have no "offending line" in the strict sense:
/// Python (`file_check.py::execute`) always anchors the finding to
/// line 1, with the first non-empty line of code as the displayed
/// snippet (same convention kept on the Rust side), which can be
/// misleading (e.g. `missing_csp_header` detected on a Flask file
/// shows `import sqlite3` on line 1, unrelated to the actual reason:
/// no CSP anywhere in the file). Rendered once per rule group (same
/// contract as `generate_fix_suggestion`), not per finding instance.
fn render_file_check_explanation(
    rule_catalog: &RuleCatalog,
    rule_id: &RuleId,
    report_locale: &Value,
) -> String {
    let Some(rule) = rule_catalog.get(rule_id) else {
        return String::new();
    };
    let Some(fc) = rule.get("file_contains") else {
        return String::new();
    };
    let has: Vec<String> = fc
        .get("has")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_str())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    let not_has: Vec<String> = fc
        .get("not_has")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_str())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    if has.is_empty() && not_has.is_empty() {
        return String::new();
    }
    let colon = LocaleFormat::of(report_locale).colon().to_string();
    let mut body = format!("<p>{}</p>", t(report_locale, "file_check_scope_note"));
    if !has.is_empty() {
        let items: String = has
            .iter()
            .map(|p| format!("<code>{}</code>", escape(p)))
            .collect::<Vec<_>>()
            .join(", ");
        body.push_str(&format!(
            "<p>✅ {}{colon}{items}</p>",
            t(report_locale, "file_check_has")
        ));
    }
    if !not_has.is_empty() {
        let items: String = not_has
            .iter()
            .map(|p| format!("<code>{}</code>", escape(p)))
            .collect::<Vec<_>>()
            .join(", ");
        body.push_str(&format!(
            "<p>🚫 {}{colon}{items}</p>",
            t(report_locale, "file_check_not_has")
        ));
    }
    format!(
        r#"<details class="file-check-explain"><summary>🔍 {}</summary>{body}</details>"#,
        t(report_locale, "file_check_why")
    )
}

fn render_context_lines(context: &str) -> String {
    if context.is_empty() {
        return String::new();
    }
    context
        .trim_end()
        .split('\n')
        .filter(|l| !l.trim().is_empty())
        .map(|l| format!(r#"<div class="finding-code-context">{}</div>"#, escape(l)))
        .collect()
}

/// The variable a route-parameter source names: the engine writes it
/// `handler(param)`. `None` for any other source (a line of code).
fn source_variable(expr: &str) -> Option<&str> {
    let inner = expr.strip_suffix(')')?.rsplit_once('(')?.1;
    (!inner.is_empty() && inner.chars().all(|c| c.is_alphanumeric() || c == '_')).then_some(inner)
}

/// The "To fix" block of a taint finding: every step of the path with
/// its file, line and real code, the line to change marked, then what to
/// do there with the rule's solution, and how to report a false
/// positive. Added after the my-ia report (2026-11-14): its trace named
/// the called function as the impact point, never the line of the
/// query, and its only fix was the rule's generic before/after example,
/// unrelated to the user's code.
fn render_fix_block(f: &ReportFinding, flow: &TaintFlow, report_locale: &Value) -> String {
    let steps: String = flow
        .steps
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let (icon, label_key) = match s.kind.as_str() {
                "source" => ("🟢", "taint_step_source"),
                "sink" => ("🔴", "taint_step_sink"),
                _ => ("➡️", "taint_step_propagation"),
            };
            let mark = if s.kind == "sink" {
                format!(
                    r#" <span class="taint-fix-mark">← {}</span>"#,
                    t(report_locale, "taint_line_to_change")
                )
            } else {
                String::new()
            };
            format!(
                r#"<li class="taint-fix-step taint-fix-{kind}"><span class="taint-fix-num">{n}.</span> {icon} <strong>{label}</strong> <span class="taint-fix-loc">{file}:{line}</span>{mark}<pre><code>{code}</code></pre></li>"#,
                kind = escape(&s.kind),
                n = i + 1,
                label = t(report_locale, label_key),
                file = escape(&s.file),
                line = s.line,
                code = escape(&s.code),
            )
        })
        .collect();
    let sink = flow.steps.iter().rev().find(|s| s.kind == "sink");
    let location = sink.map_or_else(
        || format!("{}:{}", f.file, f.line),
        |s| format!("{}:{}", s.file, s.line),
    );
    let source_kind = if flow.source_kind.is_empty() {
        "network"
    } else {
        flow.source_kind.as_str()
    };
    let kind_label = t(report_locale, &format!("taint_kind_{source_kind}"));
    let origin = match source_variable(&flow.source_expr) {
        Some(var) => t(report_locale, "taint_variable_origin")
            .replace("{var}", &format!("<code>{}</code>", escape(var)))
            .replace("{kind}", &escape(&kind_label)),
        None => t(report_locale, "taint_data_origin").replace("{kind}", &escape(&kind_label)),
    };
    let solution = f.solution.as_deref().unwrap_or("");
    format!(
        r#"<details class="taint-fix-block" open><summary>🛠️ {title}</summary><ol class="taint-fix-steps">{steps}</ol><p class="taint-fix-todo"><strong>{todo}</strong> {origin} {solution}</p><p class="taint-fix-fp">{fp}</p></details>"#,
        title = t(report_locale, "taint_fix_block_title"),
        todo = escape(&t(report_locale, "taint_what_to_do").replace("{location}", &location)),
        solution = escape(solution),
        fp = escape(&t(report_locale, "taint_false_positive_hint")),
    )
}

fn render_taint_trace(f: &ReportFinding, report_locale: &Value) -> String {
    let Some(flow) = &f.taint_flow else {
        return String::new();
    };
    if !flow.steps.is_empty() {
        return render_fix_block(f, flow, report_locale);
    }
    let chain_items: String = flow
        .chain
        .iter()
        .filter(|(_, var, _)| var != "__sink__" && var != "Sink")
        .map(|(line, var, code)| {
            format!(
                r#"<div class="taint-step"><span class="taint-line">L{line}</span> <span class="taint-var">{}</span> <code>{}</code></div>"#,
                escape(var),
                escape(code)
            )
        })
        .collect();
    let source_kind = if flow.source_kind.is_empty() {
        "network"
    } else {
        flow.source_kind.as_str()
    };
    let kind_label = t(report_locale, &format!("taint_kind_{source_kind}"));
    let trace_summary = t(report_locale, "taint_trace_summary");
    let entry_label = t(report_locale, "taint_entry_point");
    let impact_label = t(report_locale, "taint_impact_point");
    format!(
        r#"<details class="taint-trace"><summary>🔬 {trace_summary} ({kind_label})</summary><div class="taint-source"><strong>🟢 {entry_label}</strong> L{}: <code>{}</code></div><div class="taint-chain">{chain_items}</div><div class="taint-sink"><strong>🔴 {impact_label}</strong> L{}: <code>{}</code></div></details>"#,
        flow.source_line,
        escape(&flow.source_expr),
        flow.sink_line,
        escape(&flow.sink_expr),
    )
}

/// The fix of one finding, written on the user's own line when the rule
/// has a transform (`fix_proposal`), else a sentence saying there is no
/// automatic fix. A traced (taint) finding has its own "To fix" block
/// instead, and a finding without code has nothing to rewrite.
fn render_fix_proposal(f: &ReportFinding, report_locale: &Value) -> String {
    if f.taint_flow.is_some() {
        return String::new();
    }
    // A whole-file finding has no line a fix could rewrite: its `code` is
    // only the file's first line (ticket #214).
    if f.file_scope.is_some() {
        return format!(
            r#"<p class="fix-proposal-none">{}</p>"#,
            escape(&t(report_locale, "fix_none_file"))
        );
    }
    if f.code.trim().is_empty() {
        return String::new();
    }
    match crate::report::fix_proposal::propose_fix(&f.rule_key, &f.code) {
        Some(fix) => {
            let note = fix
                .note_key
                .map(|k| {
                    format!(
                        r#"<p class="fix-proposal-note">{}</p>"#,
                        escape(&t(report_locale, k))
                    )
                })
                .unwrap_or_default();
            format!(
                r#"<div class="fix-proposal"><div class="fix-proposal-title">✅ {}</div><pre><code>{}</code></pre>{note}</div>"#,
                escape(&t(report_locale, "fix_proposed_title")),
                escape(&fix.code),
            )
        }
        None => format!(
            r#"<p class="fix-proposal-none">{}</p>"#,
            escape(&t(report_locale, "fix_none"))
        ),
    }
}

/// Which texts of a rule group differ between its findings, and are
/// therefore shown in each finding rather than once for the group
/// (ticket #205). A code rule writes the same risk and solution for every
/// occurrence. The dependency rules write them per finding: the package,
/// its CVEs with their KEV and EPSS marks, the version to upgrade to.
/// Showing the first finding's texts for the whole group hid the others'.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct OwnTexts {
    risk: bool,
    solution: bool,
}

impl OwnTexts {
    /// The texts that differ between `findings`, one rule group. The risk
    /// counts only without `catalog_risk`, the rule's own risk text, which
    /// is then the one shown for the whole group.
    fn of(findings: &[&ReportFinding], catalog_risk: bool) -> Self {
        let first = findings[0];
        OwnTexts {
            risk: !catalog_risk && findings.iter().any(|f| f.risk != first.risk),
            solution: findings.iter().any(|f| f.solution != first.solution),
        }
    }
}

/// The risk block of a finding or of a group.
fn risk_block(report_locale: &Value, risk: &str) -> String {
    format!(
        r#"<details class="finding-risk-block" open><summary>⚠️ {}</summary><p>{}</p></details>"#,
        t(report_locale, "finding_risk"),
        linkify_acronyms(report_locale, &escape(risk))
    )
}

/// The solution block of a finding or of a group.
fn solution_block(report_locale: &Value, solution: &str) -> String {
    format!(
        r#"<details class="finding-solution-block" open><summary>🛠️ {}</summary><p>{}</p></details>"#,
        t(report_locale, "finding_solution"),
        linkify_acronyms(report_locale, &escape(solution))
    )
}

/// One finding of a group, with the texts of `own` shown in it.
fn render_finding_item(
    f: &ReportFinding,
    severity: &str,
    report_locale: &Value,
    own: OwnTexts,
) -> String {
    let mut item = load_template("finding-item.html").to_string();
    let mut own_html = String::new();
    if own.risk && !f.risk.is_empty() {
        own_html.push_str(&risk_block(report_locale, &f.risk));
    }
    if own.solution
        && let Some(solution) = f.solution.as_deref().filter(|s| !s.is_empty())
    {
        own_html.push_str(&solution_block(report_locale, solution));
    }
    item = item.replace("{{own_texts}}", &own_html);
    item = item.replace("{{severity_class}}", &severity.to_lowercase());
    item = item.replace(
        "{{i18n_suppress_title}}",
        &t(report_locale, "suppress_button_title"),
    );
    item = item.replace("{{rule}}", &escape(&f.rule_name));
    item = item.replace("{{rule_key}}", &escape(&f.rule_key));
    let code_hash = if f.code.is_empty() {
        0
    } else {
        line_hash(&f.code)
    };
    item = item.replace("{{code_hash}}", &code_hash.to_string());
    item = item.replace("{{category_icon}}", category_icon(&f.category));
    item = item.replace(
        "{{category_name}}",
        &category_title(report_locale, &f.category),
    );
    item = item.replace("{{file}}", &escape(&f.file));
    item = item.replace("{{fix_html}}", &render_fix_proposal(f, report_locale));

    let committer_display = match &f.committer {
        Some(c) if !c.is_empty() => {
            format!(
                r#" <span class="finding-committer" title="{}">👤 {}</span>"#,
                t(report_locale, "finding_committer"),
                escape(c)
            )
        }
        _ => String::new(),
    };
    item = item.replace("{{committer_display}}", &committer_display);

    let lang = lang_label(&f.file);
    let language_badge = if lang.is_empty() {
        String::new()
    } else {
        format!(
            r#" <span class="finding-badge finding-badge-lang">{}</span>"#,
            escape(lang)
        )
    };
    item = item.replace("{{language_badge}}", &language_badge);

    let has_taint = f.taint_flow.is_some();
    item = item.replace("{{taint_class}}", if has_taint { "has-taint" } else { "" });

    let mut badges_html = String::new();
    if has_taint {
        let label = t(report_locale, "taint_badge_traced");
        badges_html.push_str(&format!(
            r#" <span class="finding-badge finding-badge-taint" title="{label}">🔬 {label}</span>"#
        ));
    }
    match f.rule_source.as_str() {
        "json_custom" => {
            let label = t(report_locale, "taint_badge_custom");
            badges_html.push_str(&format!(
                r#" <span class="finding-badge finding-badge-custom" title="{label}">📜 {label}</span>"#
            ));
        }
        "json_builtin" => {
            let label = t(report_locale, "taint_badge_builtin");
            badges_html.push_str(&format!(
                r#" <span class="finding-badge finding-badge-builtin" title="{label}">🛡️ {label}</span>"#
            ));
        }
        _ => {}
    }
    item = item.replace("{{taint_badges}}", &badges_html);
    item = item.replace("{{taint_trace}}", &render_taint_trace(f, report_locale));
    // Last: the location and the code block hold the client's file name
    // and code, which must not be read as placeholders by a later replace.
    item = item.replace(
        "{{location}}",
        &escape(&crate::report::text::finding_location(f, report_locale)),
    );
    item = item.replace("{{code_block}}", &render_code_block(f, report_locale));

    item
}

/// The block under a finding's header that shows where it is: the
/// detected line with its context for a finding on a line, or, for a
/// finding about the whole file, the sentence saying what was measured
/// instead of the first line of the file, which is not at fault
/// (ticket #214).
fn render_code_block(f: &ReportFinding, report_locale: &Value) -> String {
    let location = crate::report::text::finding_location(f, report_locale);
    let label = escape(&t(report_locale, "finding_your_code").replace("{location}", &location));
    if let Some(scope) = &f.file_scope {
        return format!(
            r#"<div class="finding-code-block finding-file-scope"><div class="finding-code-label">{label}</div><p class="finding-file-scope-text">📄 {}</p></div>"#,
            escape(&crate::report::text::file_scope_sentence(
                scope,
                report_locale
            ))
        );
    }
    format!(
        r#"<div class="finding-code-block"><div class="finding-code-label">{label}</div>{}<div class="finding-code-highlight" title="{}">{}</div>{}</div>"#,
        render_context_lines(&f.context_before),
        escape(&t(report_locale, "finding_detected_line").replace("{line}", &f.line.to_string())),
        escape(&f.code),
        render_context_lines(&f.context_after),
    )
}

/// Groups a list of findings by rule (first-encounter order), with the
/// shared risk/solution/playbook/fix block rendered only once per group —
/// port of `render_findings`. A group is one rule identity (language +
/// name, `RuleId`), not one name: the Python and JavaScript findings of
/// `base64_eval` are two groups, each with its own rule's texts.
fn render_findings(
    findings: &[&ReportFinding],
    severity: &str,
    report_locale: &Value,
    rule_catalog: &RuleCatalog,
) -> String {
    let mut order: Vec<RuleId> = Vec::new();
    let mut by_rule: BTreeMap<RuleId, Vec<&ReportFinding>> = BTreeMap::new();
    for f in findings {
        // By identity (language + key), not by name: the name is the
        // translated text since ticket #227.
        let id = f.rule_id();
        let entry = by_rule.entry(id.clone()).or_insert_with(|| {
            order.push(id);
            Vec::new()
        });
        entry.push(f);
    }

    let rule_group_tpl = load_template("findings-rule-group.html");

    let mut html = String::new();
    for group in order {
        let rule_findings = &by_rule[&group];
        let first = rule_findings[0];
        let rk = &first.rule_key;
        let rule_id = first.rule_id();

        let mut shared_html = String::new();
        // The rule's own risk text, the one written for the reader (issue
        // #184), rather than `first.risk`: for a data-flow finding that is
        // the rule's short `message`, also used for the console line, and
        // a report showed it instead of the explanation (2026-11-14).
        let lang = t(report_locale, "locale_code");
        let catalog_risk = rule_catalog
            .get(&rule_id)
            .map(|rule| crate::scan::orchestrator::extract_i18n_block(rule, "risk", &lang))
            .filter(|r| !r.is_empty());
        let own = OwnTexts::of(rule_findings, catalog_risk.is_some());
        let risk_text = catalog_risk.unwrap_or_else(|| first.risk.clone());
        if !own.risk && !risk_text.is_empty() {
            shared_html.push_str(&risk_block(report_locale, &risk_text));
        }
        if !own.solution
            && let Some(solution) = first.solution.as_deref().filter(|s| !s.is_empty())
        {
            shared_html.push_str(&solution_block(report_locale, solution));
        }
        // The playbook's code step repeats the solution: with a solution
        // per finding, it points to them rather than to the first one.
        let own_solution_step = t(report_locale, "playbook_step_own_solution");
        let playbook_solution = if own.solution {
            Some(own_solution_step.as_str())
        } else {
            first.solution.as_deref()
        };
        // Every CWE of the group, each once, in order of first sight: a
        // catalog rule gives all its findings the same, but the dependency
        // findings of one group each carry their advisories' own, and the
        // first finding's alone hid the others' (found 2026-11-19, #217).
        let mut group_cwe: Vec<String> = Vec::new();
        for id in rule_findings.iter().flat_map(|f| f.cwe.iter()) {
            if !group_cwe.contains(id) {
                group_cwe.push(id.clone());
            }
        }
        if !rk.is_empty() {
            shared_html.push_str(&render_file_check_explanation(
                rule_catalog,
                &rule_id,
                report_locale,
            ));
            shared_html.push_str(&render_playbook_inline(
                rk,
                report_locale,
                playbook_solution,
                &first.benefit,
                crate::report::playbook::FindingTarget::of(rule_findings),
                &group_cwe,
                rule_catalog.contains_key(&rule_id),
            ));
            shared_html.push_str(&generate_fix_suggestion(
                rule_catalog,
                &rule_id,
                report_locale,
            ));
        }

        let items_html: String = rule_findings
            .iter()
            .map(|f| render_finding_item(f, severity, report_locale, own))
            .collect();

        let group = rule_group_tpl
            .replace("{{rule_name}}", &escape(&first.rule_name))
            .replace(
                "{{count}}",
                &LocaleFormat::of(report_locale).int(rule_findings.len() as u64),
            )
            .replace("{{content}}", &(shared_html + &items_html));
        html.push_str(&group);
    }
    html
}

const CATEGORY_ORDER: [&str; 8] = [
    "SECURITY",
    "ARCH",
    "UI",
    "UX",
    "MAINTENANCE",
    "DEPENDENCIES",
    "DATABASE",
    "CICD",
];

/// Groups a list of findings by category (fixed order) — port of
/// `render_by_category`. `None` if the list is empty.
fn render_by_category(
    findings: &[&ReportFinding],
    severity: &str,
    report_locale: &Value,
    rule_catalog: &RuleCatalog,
) -> Option<String> {
    if findings.is_empty() {
        return None;
    }
    let mut by_cat: BTreeMap<&str, Vec<&ReportFinding>> = BTreeMap::new();
    for f in findings {
        by_cat.entry(f.category.as_str()).or_default().push(f);
    }
    let cat_group_tpl = load_template("findings-category-group.html");
    let mut html = String::new();
    for cat_key in CATEGORY_ORDER {
        let Some(cat_findings) = by_cat.get(cat_key) else {
            continue;
        };
        let cat_html = render_findings(cat_findings, severity, report_locale, rule_catalog);
        let group = cat_group_tpl
            .replace("{{category_key}}", cat_key)
            .replace("{{icon}}", category_icon(cat_key))
            .replace("{{title}}", &category_title(report_locale, cat_key))
            .replace(
                "{{count}}",
                &LocaleFormat::of(report_locale).int(cat_findings.len() as u64),
            )
            .replace("{{content}}", &cat_html);
        html.push_str(&group);
    }
    Some(html)
}

/// The HTML id of the "Dependencies" sub-group of the `severity`
/// section: `deps-HIGH` for `HIGH`.
pub fn dependencies_group_id(severity: &str) -> String {
    format!("deps-{severity}")
}

/// Generates the full HTML for a severity section (business + deps,
/// each grouped by category then by rule) — port of the body of the
/// `for severity in [...]` loop in `_generate_html`.
pub fn render_severity_section(
    severity: &str,
    findings: &[&ReportFinding],
    report_locale: &Value,
    rule_catalog: &RuleCatalog,
) -> String {
    let severity_meta = |sev: &str| -> (&'static str, &'static str, String) {
        match sev {
            "CRITICAL" => (
                "💀",
                "badge-critical",
                t(report_locale, "severity.critical"),
            ),
            "HIGH" => ("🚨", "badge-high", t(report_locale, "severity.high")),
            "MEDIUM" => ("⚠️", "badge-medium", t(report_locale, "severity.medium")),
            "LOW" => ("ℹ️", "badge-low", t(report_locale, "severity.low")),
            _ => ("📝", "badge-info", t(report_locale, "severity.info")),
        }
    };
    let (icon, _badge_class, title) = severity_meta(severity);
    let fmt = LocaleFormat::of(report_locale);

    let findings_html = if !findings.is_empty() {
        let deps_findings: Vec<&ReportFinding> = findings
            .iter()
            .filter(|f| is_dependency(&f.file))
            .copied()
            .collect();
        let business_findings: Vec<&ReportFinding> = findings
            .iter()
            .filter(|f| !is_dependency(&f.file))
            .copied()
            .collect();
        let group_tpl = load_template("findings-group.html");

        let business_html =
            render_by_category(&business_findings, severity, report_locale, rule_catalog)
                .unwrap_or_else(|| {
                    format!(
                        r#"<p class="empty-group">{}</p>"#,
                        t(report_locale, "no_issues_business")
                    )
                });
        let business_group = group_tpl
            .replace("{{group_id}}", "")
            .replace("{{icon}}", "📦")
            .replace("{{title}}", &t(report_locale, "stats.business_code"))
            .replace("{{count}}", &fmt.int(business_findings.len() as u64))
            .replace("{{content}}", &business_html);

        let deps_html = render_by_category(&deps_findings, severity, report_locale, rule_catalog)
            .unwrap_or_else(|| {
                format!(
                    r#"<p class="empty-group">{}</p>"#,
                    t(report_locale, "no_issues_deps")
                )
            });
        // The "Dependencies" stat card of the summary leads here
        // (ticket #222, `dependencies_group_id`).
        let deps_group = group_tpl
            .replace(
                "{{group_id}}",
                &format!(r#" id="{}""#, dependencies_group_id(severity)),
            )
            .replace("{{icon}}", "🔗")
            .replace("{{title}}", &t(report_locale, "stats.dependencies"))
            .replace("{{count}}", &fmt.int(deps_findings.len() as u64))
            .replace("{{content}}", &deps_html);

        format!("{business_group}{deps_group}")
    } else {
        format!(
            r#"<p class="empty-section">✅ {}</p>"#,
            t(report_locale, "no_issues_category")
        )
    };

    load_template("severity-section.html")
        .replace("{{severity_class}}", &severity.to_lowercase())
        .replace("{{severity_id}}", &format!("section-{severity}"))
        .replace("{{icon}}", icon)
        .replace("{{severity}}", &title)
        .replace("{{count}}", &fmt.int(findings.len() as u64))
        .replace("{{issues_label}}", &t(report_locale, "issues_count_label"))
        .replace("{{content}}", &findings_html)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;

    fn finding(category: &str, rule_key: &str, rule_name: &str, file: &str) -> ReportFinding {
        ReportFinding {
            rule_key: rule_key.to_string(),
            rule_language: "python".to_string(),
            rule_name: rule_name.to_string(),
            category: category.to_string(),
            severity: "HIGH".to_string(),
            risk: "Risque de test".to_string(),
            file: file.to_string(),
            line: 42,
            solution: Some("Solution de test".to_string()),
            cwe: vec![],
            owasp: None,
            taint_flow: None,
            taint_flows: vec![],
            code: "cursor.execute(query)".to_string(),
            context_before: "line1\nline2".to_string(),
            context_after: "line3".to_string(),
            confidence: 90,
            benefit: String::new(),
            committer: None,
            rule_source: "json_builtin".to_string(),
            file_scope: None,
        }
    }

    /// Ticket #143: a client rule and a catalog rule get their own badge
    /// (the "official" badge of the signed packs went with them, ADR-0040).
    #[test]
    fn test_render_finding_item_badge_per_rule_source() {
        let en = load_report_locale("en");
        let render = |source: &str| {
            let mut f = finding("SECURITY", "r", "R", "app.py");
            f.rule_source = source.to_string();
            render_finding_item(&f, "HIGH", &en, OwnTexts::default())
        };
        let client = render("json_custom");
        let builtin = render("json_builtin");
        assert!(client.contains("finding-badge-custom"), "{client}");
        assert!(builtin.contains("🛡️ Builtin"), "{builtin}");
    }

    #[test]
    fn test_render_finding_item_labels_the_code_and_proposes_a_real_fix() {
        let fr = load_report_locale("fr");
        let mut f = finding(
            "PERFORMANCE",
            "fstring_in_logging",
            "fstring",
            "app/auth/router.py",
        );
        f.line = 91;
        f.code = r#"        logger.error(f"Error for '{username}': {e}")"#.to_string();
        let html = render_finding_item(&f, "LOW", &fr, OwnTexts::default());
        assert!(
            html.contains("Votre code — app/auth/router.py:91"),
            "{html}"
        );
        assert!(html.contains("Ligne détectée (L91)"), "{html}");
        assert!(html.contains("Correction proposée"), "{html}");
        // Single quotes are HTML-encoded (`&#39;`) since the 2026-11-15
        // security fix in `report::text::escape` (closing a JS-string
        // breakout in the heatmap's inline handler).
        assert!(
            html.contains(r#"logger.error(&quot;Error for &#39;%s&#39;: %s&quot;, username, e)"#),
            "{html}"
        );

        f.rule_key = "xss_unsafe_html_construction".to_string();
        let html = render_finding_item(&f, "HIGH", &fr, OwnTexts::default());
        assert!(html.contains("Pas de correction automatique"), "{html}");
        assert!(!html.contains("Correction proposée"), "{html}");
    }

    /// A whole-file finding as `execute_file_contains_rule` builds it:
    /// line 1, the file's first line as `code`, no context.
    fn whole_file_finding(min_lines: Option<usize>) -> ReportFinding {
        let mut f = finding("ARCH", "file_too_long", "file_too_long", "app/ingest_v2.py");
        f.severity = "LOW".to_string();
        f.line = 1;
        f.code = r#"""""#.to_string();
        f.context_before = String::new();
        f.context_after = String::new();
        f.file_scope = Some(crate::scan::engine::FileScope {
            line_count: 1363,
            min_lines,
        });
        f
    }

    /// Ticket #214: the card of a whole-file finding names the file, says
    /// what was measured, and shows neither line 1 nor the first line of
    /// the file as the detected code.
    #[test]
    fn test_render_finding_item_whole_file_states_the_measure_not_line_1() {
        let fr = load_report_locale("fr");
        let html = render_finding_item(
            &whole_file_finding(Some(500)),
            "LOW",
            &fr,
            OwnTexts::default(),
        );
        assert!(html.contains("app/ingest_v2.py (fichier entier)"), "{html}");
        assert!(!html.contains("app/ingest_v2.py:1"), "{html}");
        assert!(
            html.contains(
                "Ce fichier fait 1363 lignes ; la règle s&#39;applique à partir de 500 lignes."
            ),
            "{html}"
        );
        assert!(!html.contains("Ligne détectée"), "{html}");
        assert!(!html.contains("finding-code-highlight"), "{html}");
        assert!(html.contains("Aucune ligne à corriger"), "{html}");
        assert!(!html.contains("Pas de correction automatique"), "{html}");
        // The suppression identity is unchanged: still the hash of `code`.
        assert!(
            html.contains(&format!(r#"data-code-hash="{}""#, line_hash(r#"""""#))),
            "{html}"
        );
    }

    /// Ticket #214: a whole-file rule without a length threshold (a
    /// governance rule) says the rule is about the whole file.
    #[test]
    fn test_render_finding_item_whole_file_without_threshold() {
        let en = load_report_locale("en");
        let html = render_finding_item(&whole_file_finding(None), "LOW", &en, OwnTexts::default());
        assert!(html.contains("app/ingest_v2.py (whole file)"), "{html}");
        assert!(
            html.contains("This rule is about the whole file, not one of its lines."),
            "{html}"
        );
        assert!(!html.contains("Detected line"), "{html}");
    }

    #[test]
    fn test_render_fix_block_shows_every_step_and_the_line_to_change() {
        use crate::report::exports::sarif::{TaintFlow, TaintStep};
        let fr = load_report_locale("fr");
        let mut f = finding("SECURITY", "taint_sqli", "SQLi", "app/router.py");
        f.solution = Some("Utilisez des requêtes paramétrées.".to_string());
        let step = |kind: &str, file: &str, line, code: &str| TaintStep {
            kind: kind.to_string(),
            file: file.to_string(),
            line,
            code: code.to_string(),
        };
        f.taint_flow = Some(TaintFlow {
            rule_key: "taint_sqli".to_string(),
            source_file: "app/router.py".to_string(),
            source_line: 12,
            source_expr: "list_calls(name)".to_string(),
            chain: vec![],
            sink_file: "app/router.py".to_string(),
            sink_line: 13,
            sink_expr: "_rows(...)".to_string(),
            source_kind: "http".to_string(),
            steps: vec![
                step(
                    "source",
                    "app/router.py",
                    12,
                    "async def list_calls(name: str):",
                ),
                step(
                    "propagation",
                    "app/router.py",
                    13,
                    "return await _rows(db, name)",
                ),
                step(
                    "sink",
                    "app/journal.py",
                    6,
                    "return await db.execute(query)",
                ),
            ],
        });
        let html = render_taint_trace(&f, &fr);
        assert!(html.contains("app/journal.py:6"), "{html}");
        assert!(html.contains("return await db.execute(query)"));
        assert!(html.contains(&t(&fr, "taint_line_to_change")));
        assert!(html.contains("Que faire à app/journal.py:6"));
        assert!(html.contains("<code>name</code>"));
        assert!(html.contains("Utilisez des requêtes paramétrées."));
        assert!(!html.contains("taint-source"), "old trace replaced");
    }

    #[test]
    fn test_render_taint_trace_uses_real_source_kind() {
        use crate::report::exports::sarif::TaintFlow;
        let en = load_report_locale("en");
        let mut f = finding("SECURITY", "taint_rce", "RCE", "app.py");
        f.taint_flow = Some(TaintFlow {
            rule_key: "taint_rce".to_string(),
            source_file: "app.py".to_string(),
            source_line: 5,
            source_expr: "request.args.get('cmd')".to_string(),
            chain: vec![],
            sink_file: "app.py".to_string(),
            sink_line: 10,
            sink_expr: "os.system(cmd)".to_string(),
            source_kind: "http".to_string(),
            steps: vec![],
        });
        let html = render_taint_trace(&f, &en);
        assert!(html.contains(&t(&en, "taint_kind_http")));
    }

    #[test]
    fn test_render_taint_trace_falls_back_to_network_when_source_kind_empty() {
        use crate::report::exports::sarif::TaintFlow;
        let en = load_report_locale("en");
        let mut f = finding("SECURITY", "taint_rce", "RCE", "app.py");
        f.taint_flow = Some(TaintFlow {
            rule_key: "taint_rce".to_string(),
            source_file: "app.py".to_string(),
            source_line: 5,
            source_expr: "x".to_string(),
            chain: vec![],
            sink_file: "app.py".to_string(),
            sink_line: 10,
            sink_expr: "y".to_string(),
            source_kind: String::new(),
            steps: vec![],
        });
        let html = render_taint_trace(&f, &en);
        assert!(html.contains(&t(&en, "taint_kind_network")));
    }

    #[test]
    fn test_render_file_check_explanation_shows_has_and_not_has() {
        use serde_json::json;
        let en = load_report_locale("en");
        let mut catalog = BTreeMap::new();
        let rule = RuleId::new("python", "missing_csp_header");
        catalog.insert(
            rule.clone(),
            json!({
                "id": "missing_csp_header",
                "file_contains": {
                    "has": ["(?:Flask\\s*\\(\\s*__name__|@app\\.route)"],
                    "not_has": ["(?:Talisman|content_security_policy|CSP)"],
                },
            }),
        );
        let html = render_file_check_explanation(&catalog, &rule, &en);
        assert!(html.contains("Why this was detected"));
        assert!(html.contains("whole-file check"));
        assert!(html.contains("Flask"));
        assert!(html.contains("Talisman"));
        assert!(!html.contains("{{"));
    }

    #[test]
    fn test_render_file_check_explanation_empty_without_file_contains() {
        use serde_json::json;
        let en = load_report_locale("en");
        let mut catalog = BTreeMap::new();
        let rule = RuleId::new("python", "taint_sqli");
        catalog.insert(rule.clone(), json!({"id": "taint_sqli"}));
        let html = render_file_check_explanation(&catalog, &rule, &en);
        assert!(html.is_empty());
    }

    #[test]
    fn test_render_file_check_explanation_empty_unknown_rule() {
        let en = load_report_locale("en");
        let html = render_file_check_explanation(
            &RuleCatalog::new(),
            &RuleId::new("python", "unknown_rule"),
            &en,
        );
        assert!(html.is_empty());
    }

    #[test]
    fn test_render_finding_item_contains_core_fields() {
        let en = load_report_locale("en");
        let f = finding(
            "SECURITY",
            "sql_injection_fstring",
            "SQL Injection",
            "src/app.py",
        );
        let html = render_finding_item(&f, "HIGH", &en, OwnTexts::default());
        assert!(html.contains("SQL Injection"));
        assert!(html.contains("src/app.py"));
        assert!(html.contains('🛡')); // category icon SECURITY
        assert!(html.contains("cursor.execute(query)"));
        assert!(html.contains("finding-code-context"));
        assert!(html.contains("finding-badge-builtin"));
    }

    #[test]
    fn test_render_finding_item_no_taint_class_when_no_flow() {
        let en = load_report_locale("en");
        let f = finding("SECURITY", "r1", "Rule", "a.py");
        let html = render_finding_item(&f, "HIGH", &en, OwnTexts::default());
        assert!(!html.contains("has-taint"));
        assert!(!html.contains("finding-badge-taint"));
    }

    #[test]
    fn test_render_findings_groups_by_rule_shows_risk_solution() {
        let en = load_report_locale("en");
        let f1 = finding("SECURITY", "r1", "Rule One", "a.py");
        let f2 = finding("SECURITY", "r1", "Rule One", "b.py");
        let refs = [&f1, &f2];
        let catalog = BTreeMap::new();
        let html = render_findings(&refs, "HIGH", &en, &catalog);
        assert_eq!(html.matches("class=\"rule-group\"").count(), 1); // a single group (same rule_key)
        assert!(html.contains("Risque de test"));
        assert!(html.contains("Solution de test"));
        assert!(html.contains(r#"class="rule-group-badge">2<"#));
    }

    /// Ticket #205: the dependency rules write their risk and solution per
    /// finding. Each finding of the group shows its own, none is shown
    /// for the whole group, and the playbook's code step points to them
    /// instead of repeating the first finding's solution.
    #[test]
    fn test_render_findings_shows_texts_that_differ_in_each_finding() {
        let fr = load_report_locale("fr");
        let dependency = |file: &str, package: &str, fixed: &str| {
            let mut f = finding("DEPENDENCIES", "vulnerable_dependency", "Dépendance", file);
            f.risk = format!("{package} est touchée par CVE-2021-44228 (CISA KEV)");
            f.solution = Some(format!("Upgrade {package} to {fixed} or later."));
            f
        };
        let log4j = dependency("pom.xml", "log4j-core 2.14.1", "2.17.1");
        let drupal = dependency("composer.json", "drupal/core 8.5.0", "8.5.1");
        let refs = [&log4j, &drupal];
        let html = render_findings(&refs, "CRITICAL", &fr, &RuleCatalog::new());
        assert_eq!(html.matches("class=\"rule-group\"").count(), 1);
        for text in [
            "log4j-core 2.14.1 est touchée",
            "drupal/core 8.5.0 est touchée",
            "Upgrade log4j-core 2.14.1 to 2.17.1 or later.",
            "Upgrade drupal/core 8.5.0 to 8.5.1 or later.",
        ] {
            assert_eq!(html.matches(text).count(), 1, "{text} once: {html}");
        }
        // Each finding's texts sit inside that finding, after its header.
        let log4j_item = html.find(r#"data-file="pom.xml""#).unwrap();
        let drupal_item = html.find(r#"data-file="composer.json""#).unwrap();
        let log4j_risk = html.find("log4j-core 2.14.1 est touchée").unwrap();
        let drupal_risk = html.find("drupal/core 8.5.0 est touchée").unwrap();
        assert!(log4j_item < log4j_risk && log4j_risk < drupal_item);
        assert!(drupal_item < drupal_risk);
        assert!(
            html.contains(&t(&fr, "playbook_step_own_solution")),
            "{html}"
        );

        // A group whose findings share their texts keeps one block.
        let one = finding("SECURITY", "r1", "Rule One", "a.py");
        let two = finding("SECURITY", "r1", "Rule One", "b.py");
        let html = render_findings(&[&one, &two], "HIGH", &fr, &RuleCatalog::new());
        assert_eq!(html.matches("Risque de test").count(), 1, "{html}");
        assert_eq!(html.matches("Solution de test").count(), 1, "{html}");
    }

    /// Ticket #217: a catalog rule without a playbook entry shows its CWE
    /// in the playbook derived from it; a key no catalog rule has shows no
    /// playbook.
    #[test]
    fn test_catalog_rule_without_playbook_entry_shows_its_cwe() {
        let en = load_report_locale("en");
        let mut f = finding("MAINTENANCE", "rule_without_entry_xyz", "R", "a.py");
        f.cwe = vec!["CWE-396".to_string()];
        let mut catalog = RuleCatalog::new();
        catalog.insert(
            f.rule_id(),
            serde_json::json!({"id": "rule_without_entry_xyz"}),
        );
        let html = render_findings(&[&f], "LOW", &en, &catalog);
        assert!(html.contains("playbook-details"), "{html}");
        assert!(html.contains("definitions/396.html"), "{html}");
        let html = render_findings(&[&f], "LOW", &en, &RuleCatalog::new());
        assert!(!html.contains("playbook-details"), "{html}");
    }

    /// The group's playbook lists the CWE of every finding, each once: the
    /// dependency findings of one group carry different ones.
    #[test]
    fn test_group_playbook_lists_every_finding_cwe_once() {
        let en = load_report_locale("en");
        let dependency = |file: &str, cwe: &[&str]| {
            let mut f = finding("DEPENDENCIES", "vulnerable_dependency", "Dependency", file);
            f.cwe = cwe.iter().map(|c| c.to_string()).collect();
            f
        };
        let a = dependency("pom.xml", &["CWE-502", "CWE-20"]);
        let b = dependency("composer.json", &["CWE-79", "CWE-502"]);
        let html = render_findings(&[&a, &b], "HIGH", &en, &RuleCatalog::new());
        // The CWE pages only: the CAPEC links (ADR-0070) share the path.
        for n in ["502", "20", "79"] {
            let link = format!("cwe.mitre.org/data/definitions/{n}.html");
            assert_eq!(html.matches(&link).count(), 1, "CWE-{n} once: {html}");
        }
    }

    #[test]
    fn test_risk_block_shows_the_rule_risk_not_the_short_message() {
        // A data-flow finding carries the rule's short `message` in
        // `risk`; the report must explain with the rule's risk text.
        let fr = load_report_locale("fr");
        let mut f = finding("SECURITY", "taint_sqli", "SQLi", "a.py");
        f.risk = "Injection SQL — données non fiables".to_string();
        let refs = [&f];
        let mut catalog = BTreeMap::new();
        catalog.insert(
            RuleId::new("python", "taint_sqli"),
            serde_json::json!({"risk": {"en": "An attacker can read your data.", "fr": "Un attaquant peut lire vos données."}}),
        );
        let html = render_findings(&refs, "HIGH", &fr, &catalog);
        assert!(
            html.contains("Un attaquant peut lire vos données."),
            "{html}"
        );
        assert!(!html.contains("données non fiables"), "{html}");
        let html = render_findings(&refs, "HIGH", &fr, &RuleCatalog::new());
        assert!(
            html.contains("données non fiables"),
            "fallback without the rule"
        );
    }

    #[test]
    fn test_render_by_category_groups_and_orders() {
        let en = load_report_locale("en");
        let sec = finding("SECURITY", "r1", "Rule Sec", "a.py");
        let arch = finding("ARCH", "r2", "Rule Arch", "b.py");
        let refs = [&arch, &sec]; // input order is the reverse of CATEGORY_ORDER
        let catalog = BTreeMap::new();
        let html = render_by_category(&refs, "HIGH", &en, &catalog).unwrap();
        let sec_pos = html.find("Rule Sec").unwrap();
        let arch_pos = html.find("Rule Arch").unwrap();
        assert!(
            sec_pos < arch_pos,
            "SECURITY doit precede ARCH (CATEGORY_ORDER)"
        );
    }

    #[test]
    fn test_render_by_category_empty_is_none() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        assert!(render_by_category(&[], "HIGH", &en, &catalog).is_none());
    }

    #[test]
    fn test_render_severity_section_empty_shows_no_issues() {
        let en = load_report_locale("en");
        let catalog = BTreeMap::new();
        let html = render_severity_section("CRITICAL", &[], &en, &catalog);
        assert!(html.contains("empty-section"));
        assert!(html.contains("section-CRITICAL"));
        assert!(html.contains('0'));
    }

    #[test]
    fn test_render_severity_section_splits_business_vs_deps() {
        let en = load_report_locale("en");
        let business = finding("SECURITY", "r1", "Rule", "src/app.py");
        let dep = finding("SECURITY", "r1", "Rule", "app/vendor/lib.py");
        let refs = [&business, &dep];
        let catalog = BTreeMap::new();
        let html = render_severity_section("HIGH", &refs, &en, &catalog);
        assert!(html.contains(&t(&en, "stats.business_code")));
        assert!(html.contains(&t(&en, "stats.dependencies")));
        // Ticket #222: only the dependency sub-group carries an id, the
        // target of the summary's "Dependencies" card.
        assert_eq!(
            html.matches(r#"<div class="sub-group" id="deps-HIGH">"#)
                .count(),
            1
        );
        assert_eq!(html.matches(r#"<div class="sub-group">"#).count(), 1);
    }

    #[test]
    fn test_generate_fix_suggestion_empty_without_rule_data() {
        let en = load_report_locale("en");
        let catalog = RuleCatalog::new();
        let rule = RuleId::new("python", "no_such_rule");
        assert_eq!(generate_fix_suggestion(&catalog, &rule, &en), "");
    }

    #[test]
    fn test_generate_fix_suggestion_with_fix_before_after() {
        let en = load_report_locale("en");
        let mut catalog = BTreeMap::new();
        let rule = RuleId::new("python", "r1");
        catalog.insert(
            rule.clone(),
            serde_json::json!({"fix_before": "eval(x)", "fix_after": "ast.literal_eval(x)"}),
        );
        let html = generate_fix_suggestion(&catalog, &rule, &en);
        assert!(html.contains("eval(x)"));
        assert!(html.contains("ast.literal_eval(x)"));
        assert!(html.contains("taint-fix"));
    }

    #[test]
    fn test_one_name_in_two_languages_is_two_groups_with_their_own_example() {
        let en = load_report_locale("en");
        let python = finding("SECURITY", "base64_eval", "base64_eval", "app.py");
        let mut javascript = finding("SECURITY", "base64_eval", "base64_eval", "app.js");
        javascript.rule_language = "javascript".to_string();
        let mut catalog = RuleCatalog::new();
        catalog.insert(
            RuleId::new("python", "base64_eval"),
            serde_json::json!({"fix_before": "py_before", "fix_after": "py_after"}),
        );
        catalog.insert(
            RuleId::new("javascript", "base64_eval"),
            serde_json::json!({"fix_before": "js_before", "fix_after": "js_after"}),
        );
        let html = render_findings(&[&python, &javascript], "HIGH", &en, &catalog);
        assert!(
            html.contains("py_after") && html.contains("js_after"),
            "{html}"
        );
        // The JavaScript group comes after the Python one and holds app.js.
        let js_group = &html[html.find("js_after").unwrap()..];
        assert!(
            js_group.contains("app.js") && !js_group.contains("app.py"),
            "{html}"
        );
    }
}
