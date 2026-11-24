//! The answers of the rule wizard and the `.sca` text written from them —
//! ported from `_build_sca_content`/`_load_existing_rule` of
//! `Audit/sca/rule_wizard.py`, with data-flow rules added (ticket #275):
//! Audit's wizard wrote pattern rules only.

use std::path::Path;

use crate::scan::parser::model::SinkArguments;

/// What a rule detects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleKind {
    /// A text searched in the code (`match` block, `text`).
    #[default]
    Pattern,
    /// Data followed from a source to a sink (`source`/`sink` lines).
    Taint,
}

/// A `source` line: its regular expression and the kind of data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceAnswer {
    pub pattern: String,
    pub kind: String,
}

/// A `sink` line: its regular expression and the argument that carries
/// the danger, as written after `arg_index=` (`0`, `all`), empty when
/// the rule names none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkAnswer {
    pub pattern: String,
    pub argument: String,
}

/// Every answer of the wizard for one rule. The texts hold four
/// languages, in the order of [`LANG_CODES`]; English is required.
#[derive(Debug, Clone, Default)]
pub struct RuleFormData {
    pub lang: String,
    pub cat: String,
    pub sev: String,
    pub kind: RuleKind,
    /// Pattern rule: the text searched, and the text that neutralizes it.
    pub pattern: String,
    pub neutralizer: String,
    /// Data-flow rule: its four lists.
    pub sources: Vec<SourceAnswer>,
    pub sinks: Vec<SinkAnswer>,
    pub sanitizers: Vec<String>,
    pub passthroughs: Vec<String>,
    pub risk: [String; 4],
    pub solution: [String; 4],
    pub benefit: [String; 4],
    pub fix_before: String,
    pub fix_after: String,
}

impl RuleFormData {
    /// The answers offered to a new rule.
    pub fn defaults() -> Self {
        Self {
            lang: "python".to_string(),
            cat: "security".to_string(),
            sev: "HIGH".to_string(),
            ..Default::default()
        }
    }
}

/// The languages of a rule's texts, in the order of the form's arrays.
pub const LANG_CODES: [&str; 4] = ["en", "fr", "es", "de"];

/// The full `.sca` text of rule `name` — ported from
/// `_build_sca_content`. A pattern rule gets a `match` block; a
/// data-flow rule its `source`, `sink`, `sanitizer` and `passthrough`
/// lines, the compiler inferring its mode.
pub fn build_sca_content(name: &str, form: &RuleFormData) -> String {
    let mut lines = vec![
        format!("rule {name}"),
        format!("  language  {}", form.lang),
        format!("  category  {}", form.cat),
        format!("  severity  {}", form.sev),
        String::new(),
    ];
    match form.kind {
        RuleKind::Pattern => {
            lines.push("  match".to_string());
            lines.push(format!("    text  {}", form.pattern));
            if !form.neutralizer.is_empty() {
                lines.push(format!("    text-not  {}", form.neutralizer));
            }
            lines.push("  end".to_string());
        }
        RuleKind::Taint => {
            for source in &form.sources {
                lines.push(format!(
                    "  source  {}  kind={}",
                    source.pattern, source.kind
                ));
            }
            for sink in &form.sinks {
                if sink.argument.is_empty() {
                    lines.push(format!("  sink    {}", sink.pattern));
                } else {
                    lines.push(format!(
                        "  sink    {}  arg_index={}",
                        sink.pattern, sink.argument
                    ));
                }
            }
            for sanitizer in &form.sanitizers {
                lines.push(format!("  sanitizer  {sanitizer}"));
            }
            for passthrough in &form.passthroughs {
                lines.push(format!("  passthrough  {passthrough}"));
            }
        }
    }
    lines.push(String::new());

    push_i18n_block(&mut lines, "risk", &form.risk);
    push_i18n_block(&mut lines, "solution", &form.solution);
    if !form.benefit[0].is_empty() {
        push_i18n_block(&mut lines, "benefit", &form.benefit);
    }

    if !form.fix_before.is_empty() && !form.fix_after.is_empty() {
        for (block, code) in [
            ("fix_before", &form.fix_before),
            ("fix_after", &form.fix_after),
        ] {
            lines.push(format!("  {block}"));
            for line in code.lines() {
                lines.push(format!("    {line}"));
            }
            lines.push("  end".to_string());
            lines.push(String::new());
        }
    }

    lines.push("end".to_string());
    lines.push(String::new());
    lines.join("\n")
}

fn push_i18n_block(lines: &mut Vec<String>, block_name: &str, texts: &[String; 4]) {
    lines.push(format!("  {block_name}"));
    lines.push(format!("    en: {}", texts[0]));
    for (i, code) in ["fr", "es", "de"].iter().enumerate() {
        if !texts[i + 1].is_empty() {
            lines.push(format!("    {code}: {}", texts[i + 1]));
        }
    }
    lines.push("  end".to_string());
    lines.push(String::new());
}

/// Whether the answers `data`, read from the rule file at `path`, write
/// the same rule again: the wizard only edits such a rule. A rule written
/// or completed by hand can use what the wizard does not ask (a regex, a
/// `with`, `requires`, `metadata`, a sink's `kinds=` or `arg_name=`, a
/// passthrough's `arg_index=`...): rewriting it from the answers would
/// drop that part without a word. Deliberate deviation from Audit, whose
/// wizard rewrote such a rule from what it had read. Compared as the
/// compiler sees the two texts, so layout and comments do not count.
pub fn writes_back_the_same_rule(path: &Path, name: &str, data: &RuleFormData) -> bool {
    let Ok(original) = std::fs::read_to_string(path) else {
        return false;
    };
    let compile = |text: &str| crate::scan::parser::compile_sca_to_json(text, "rule.sca").ok();
    match (compile(&original), compile(&build_sca_content(name, data))) {
        (Some(before), Some(after)) => before == after,
        _ => false,
    }
}

/// The answers that wrote the rule file at `path`, to edit it — ported
/// from `_load_existing_rule`. Read with the rule language's parser:
/// Audit matched each line with a regex, which a data-flow rule's lines
/// would have escaped. A file that does not parse gives the defaults.
pub fn load_existing_rule(path: &Path) -> RuleFormData {
    let mut data = RuleFormData::defaults();
    let Ok(content) = std::fs::read_to_string(path) else {
        return data;
    };
    let Ok(rules) = crate::scan::parser::parse_sca_file(&content, &path.to_string_lossy()) else {
        return data;
    };
    let Some(rule) = rules.into_iter().next() else {
        return data;
    };
    data.lang = rule.language.clone();
    data.cat = rule.category.clone();
    data.sev = rule.severity.clone();
    if !rule.sources.is_empty() || !rule.sinks.is_empty() {
        data.kind = RuleKind::Taint;
        data.sources = rule
            .sources
            .iter()
            .map(|s| SourceAnswer {
                pattern: s.pattern.clone(),
                kind: s.kind.clone(),
            })
            .collect();
        data.sinks = rule
            .sinks
            .iter()
            .map(|s| SinkAnswer {
                pattern: s.pattern.clone(),
                argument: match s.arg_index {
                    Some(SinkArguments::Index(index)) => index.to_string(),
                    Some(SinkArguments::All) => "all".to_string(),
                    None => String::new(),
                },
            })
            .collect();
        data.sanitizers = rule.sanitizers.iter().map(|s| s.pattern.clone()).collect();
        data.passthroughs = rule
            .passthroughs
            .iter()
            .map(|s| s.pattern.clone())
            .collect();
    } else if let Some(crate::scan::parser::model::MatchBlock::Regex(block)) =
        rule.match_blocks.first()
    {
        // The wizard writes `text` and `text-not`, plain texts. A regex
        // (`pattern`) is not offered as a text: written back as `text`, it
        // would search other code. Audit read the `text` lines only, too.
        if block.is_text {
            data.pattern = block.pattern.clone();
        }
        if block.pattern_not_is_text {
            data.neutralizer = block.pattern_not.clone();
        }
    }
    for (block, target) in [
        (&rule.risk, &mut data.risk),
        (&rule.solution, &mut data.solution),
        (&rule.benefit, &mut data.benefit),
    ] {
        for (i, code) in LANG_CODES.iter().enumerate() {
            if let Some(text) = block.texts.get(*code) {
                target[i] = text.clone();
            }
        }
    }
    data.fix_before = rule.fix_before.trim_matches('\n').to_string();
    data.fix_after = rule.fix_after.trim_matches('\n').to_string();
    data
}
