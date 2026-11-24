//! The steps of the rule wizard — ported from `run_wizard` of
//! `Audit/sca/rule_wizard.py`, shared since ADR-0057 by the catalog's
//! `create-rule` (private) and the client's `custom-rules create`
//! (ticket #275). What differs between the two is a [`WizardTarget`].
//!
//! Deliberate deviations from the Python wizard (ticket #154): the
//! language is asked before the name, so that an existing rule is found by
//! language (the same id exists in several languages); labels and yes/no
//! answers follow `--lang`; the rule is compiled before the confirmation
//! and the parser's error is shown; end of input stops the wizard instead
//! of asking again forever. Ticket #275 adds data-flow rules (Audit wrote
//! pattern rules only) and compares a new text with the compiled patterns
//! of the other rules as the compiler writes them (`text_to_regex`): the
//! text as typed never equalled the regex of a text with a `(`. It also
//! compares with the delivered rules, where Audit compared with the
//! client's own only, and asks before a client rule takes the name of a
//! delivered one (see [`run_wizard`]). The rules that could not be read
//! for the comparison are named (Audit skipped them without a word).

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::form::{
    RuleFormData, RuleKind, SinkAnswer, SourceAnswer, build_sca_content, load_existing_rule,
};
use super::prompt::{prompt, prompt_choice, prompt_yes_no, section};
use super::{LANGUAGES, SEVERITIES, TAINT_LANGUAGES, find_existing_rule};
use crate::i18n::t;
use crate::scan::parser::compile_sca_to_json;
use crate::scan::parser::validator::VALID_SOURCE_KINDS;

/// A compiled rule the wizard compares a new rule with.
pub struct KnownRule {
    /// The compiled rule (`compile_sca_to_json`).
    pub json: Value,
    /// Where it comes from, shown when its pattern is the new one's.
    pub place: String,
    /// A rule delivered in the pack, which a client rule of the same
    /// name replaces (the wizard says so).
    pub delivered: bool,
}

/// The other rules of a language, as [`WizardTarget::known_rules`] gives
/// them: the rules that compile, and one message per file or pack that
/// could not be read or compiled. The wizard prints those messages before
/// it compares anything: a rule left out of the comparison is named,
/// never dropped without a word.
#[derive(Default)]
pub struct KnownRules {
    /// The compiled rules of the language.
    pub rules: Vec<KnownRule>,
    /// What could not be read, one message each, in the console language
    /// (`<file>: <reason>`).
    pub problems: Vec<String>,
}

/// The rule the wizard is about to write, shown to
/// [`WizardTarget::before_confirm`], then, once written, to
/// [`WizardTarget::after_write`].
pub struct WizardRule<'a> {
    /// The `.sca` text, as written.
    pub sca: &'a str,
    /// Its language folder and `language` field.
    pub language: &'a str,
    /// Its category folder and `category` field.
    pub category: &'a str,
    /// Its name, which is also its file name.
    pub name: &'a str,
    /// Every answer it was written from (its fix example, for instance).
    pub form: &'a RuleFormData,
}

/// Where and how the wizard writes a rule: the only differences between
/// the catalog's wizard and the client's.
pub struct WizardTarget<'a> {
    /// The folder written to, laid out as
    /// `<language>/<category>/<rule>.sca`: the catalog (`rules/builtin`)
    /// or the client rules folder.
    pub rules_dir: &'a Path,
    /// The message key shown when a rule of the chosen name exists in
    /// `rules_dir` (`wizard_rule_exists_catalog`, `wizard_rule_exists_custom`).
    pub exists_key: &'a str,
    /// The categories offered for a language, or the message that says
    /// why there is none (the wizard then stops).
    pub categories: &'a dyn Fn(&str) -> Result<Vec<String>, String>,
    /// The other rules of a language, compared with the new one.
    pub known_rules: &'a dyn Fn(&str) -> KnownRules,
    /// A last change of the generated text, shown in the preview (the
    /// catalog's French spelling); the identity for the client.
    pub polish: &'a dyn Fn(&str) -> String,
    /// Shown once the rule compiles, before the confirmation (the
    /// catalog's alert count on reference projects).
    pub before_confirm: &'a dyn Fn(&mut dyn Write, &WizardRule) -> io::Result<()>,
    /// Run once the rule file is written, with its path and whether an
    /// existing rule was edited: the client's test case skeleton and next
    /// steps (ticket #276); nothing for the catalog.
    pub after_write: &'a AfterWrite<'a>,
}

/// The hook [`WizardTarget::after_write`]: the writer, the rule written,
/// the path of its file, and whether an existing rule was edited.
pub type AfterWrite<'a> = dyn Fn(&mut dyn Write, &WizardRule, &Path, bool) -> io::Result<()> + 'a;

/// Runs the wizard end to end — ported from `run_wizard`. Returns the
/// path of the written file, or `None` when the user declined or the rule
/// did not compile (the wizard has said why; nothing is written).
pub fn run_wizard<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    script_locale: &Value,
    target: &WizardTarget,
) -> io::Result<Option<PathBuf>> {
    let say = |key: &str| t(script_locale, key);
    writeln!(writer, "\n  {}", say("wizard_title"))?;
    writeln!(writer, "  {}", "=".repeat(48))?;

    let mut defaults = RuleFormData::defaults();
    let mut edit_mode = false;
    let mut existing_path: Option<PathBuf> = None;

    // --- STEP 1: language, name, category, severity, kind ---------------
    // The language comes first: an existing rule is found by language and
    // name, since the same id exists in several languages.
    section(writer, &format!("1 — {}", say("wizard_name")))?;
    let language = prompt_choice(
        reader,
        writer,
        script_locale,
        &say("wizard_language"),
        &LANGUAGES,
        0,
    )?;
    let KnownRules {
        rules: known,
        problems,
    } = (target.known_rules)(&language);
    if !problems.is_empty() {
        writeln!(writer, "\n    {}", say("wizard_known_rules_problems"))?;
        for problem in &problems {
            writeln!(writer, "      - {problem}")?;
        }
    }

    let name = loop {
        let candidate = prompt(reader, writer, &say("wizard_name"), "")?;
        if candidate.is_empty() {
            writeln!(writer, "    {}", say("wizard_field_required"))?;
            continue;
        }
        if !valid_rule_name(&candidate) {
            writeln!(writer, "    {} : '{candidate}'", say("wizard_invalid_id"))?;
            writeln!(writer, "    {}", say("wizard_id_format"))?;
            continue;
        }
        if let Some(existing) = find_existing_rule(target.rules_dir, &language, &candidate) {
            writeln!(
                writer,
                "\n    {} : {}",
                say(target.exists_key),
                existing.display()
            )?;
            if !prompt_yes_no(
                reader,
                writer,
                script_locale,
                &say("wizard_edit_existing"),
                true,
            )? {
                // Another name, rather than two rules with one id.
                continue;
            }
            let read = load_existing_rule(&existing);
            if !super::form::writes_back_the_same_rule(&existing, &candidate, &read) {
                // Parts the wizard does not ask would be lost: the file
                // is edited by hand, and another name is asked for.
                writeln!(
                    writer,
                    "    {}",
                    say("wizard_edit_by_hand").replace("{file}", &existing.display().to_string())
                )?;
                continue;
            }
            defaults = read;
            edit_mode = true;
            existing_path = Some(existing);
        } else if let Some(delivered) = known
            .iter()
            .find(|rule| rule.delivered && rule_id(&rule.json) == Some(candidate.as_str()))
        {
            // Deliberate deviation from Audit, which refused the name of a
            // builtin rule outright (`_check_builtin_duplicate`): a client
            // rule of the same identity replaces the delivered one in
            // every scan (ADR-0057, `RuleRegistry`), which is how a client
            // adjusts a rule to their code. The wizard never does it
            // silently: it names the rule and asks, "no" by default, and
            // another name is asked for on "no".
            writeln!(
                writer,
                "\n    {}",
                say("wizard_replaces_delivered").replace("{place}", &delivered.place)
            )?;
            if !prompt_yes_no(
                reader,
                writer,
                script_locale,
                &say("wizard_replace_confirm"),
                false,
            )? {
                continue;
            }
        }
        break candidate;
    };

    let categories = match (target.categories)(&language) {
        Ok(categories) if !categories.is_empty() => categories,
        Ok(_) => return Ok(None),
        Err(message) => {
            writeln!(writer, "    {message}")?;
            return Ok(None);
        }
    };
    let category_labels: Vec<String> = categories
        .iter()
        .map(|c| say(&format!("wizard_cat_{c}")))
        .collect();
    let category_choices: Vec<(&str, &str)> = categories
        .iter()
        .map(String::as_str)
        .zip(category_labels.iter().map(String::as_str))
        .collect();
    let default_cat_idx = categories
        .iter()
        .position(|c| *c == defaults.cat)
        .unwrap_or(0);
    let category = prompt_choice(
        reader,
        writer,
        script_locale,
        &say("wizard_category"),
        &category_choices,
        default_cat_idx,
    )?;

    let severity_labels: Vec<String> = SEVERITIES
        .iter()
        .map(|sev| say(&format!("wizard_sev_{}", sev.to_lowercase())))
        .collect();
    let severity_choices: Vec<(&str, &str)> = SEVERITIES
        .iter()
        .copied()
        .zip(severity_labels.iter().map(String::as_str))
        .collect();
    let default_sev_idx = SEVERITIES
        .iter()
        .position(|v| *v == defaults.sev)
        .unwrap_or(1);
    let severity = prompt_choice(
        reader,
        writer,
        script_locale,
        &say("wizard_severity"),
        &severity_choices,
        default_sev_idx,
    )?;

    // The data flow is followed in five languages only: the others get
    // pattern rules, without the question.
    let kind = if TAINT_LANGUAGES.contains(&language.as_str()) {
        let (pattern_label, taint_label) = (say("wizard_kind_pattern"), say("wizard_kind_taint"));
        let kind_choices = [
            ("pattern", pattern_label.as_str()),
            ("taint", taint_label.as_str()),
        ];
        prompt_choice(
            reader,
            writer,
            script_locale,
            &say("wizard_kind"),
            &kind_choices,
            usize::from(defaults.kind == RuleKind::Taint),
        )?
    } else {
        "pattern".to_string()
    };

    let mut form = RuleFormData {
        lang: language.clone(),
        cat: category.clone(),
        sev: severity,
        kind: if kind == "taint" {
            RuleKind::Taint
        } else {
            RuleKind::Pattern
        },
        ..RuleFormData::default()
    };

    // --- STEP 2: detection ---------------------------------------------
    match form.kind {
        RuleKind::Pattern => {
            section(writer, &format!("2 — {}", say("wizard_step_pattern")))?;
            let pattern = loop {
                let candidate = prompt(
                    reader,
                    writer,
                    &say("wizard_pattern_prompt"),
                    &defaults.pattern,
                )?;
                if candidate.is_empty() {
                    writeln!(writer, "    {}", say("wizard_pattern_required"))?;
                    continue;
                }
                break candidate;
            };
            let others: Vec<&KnownRule> = known
                .iter()
                .filter(|rule| !(edit_mode && rule_id(&rule.json) == Some(name.as_str())))
                .collect();
            let dupes = same_pattern(&others, &pattern);
            if !dupes.is_empty() {
                // The delivered rules first, with what a scan does on the
                // lines both flag (epic #278: the delivered finding is
                // kept), then the other rules.
                for (delivered, key) in [
                    (true, "wizard_pattern_duplicate_warning"),
                    (false, "wizard_pattern_duplicate_own"),
                ] {
                    let listed: Vec<&(String, String, bool)> =
                        dupes.iter().filter(|d| d.2 == delivered).collect();
                    if listed.is_empty() {
                        continue;
                    }
                    writeln!(writer, "\n    {}", say(key))?;
                    for (id, place, _) in listed {
                        writeln!(writer, "      → {id}  ({place})")?;
                    }
                }
                if !prompt_yes_no(
                    reader,
                    writer,
                    script_locale,
                    &say("wiz_overlap_continue"),
                    false,
                )? {
                    return Ok(None);
                }
            }
            form.pattern = pattern;
            form.neutralizer = prompt(
                reader,
                writer,
                &say("wizard_neutralizer_prompt"),
                &defaults.neutralizer,
            )?;
        }
        RuleKind::Taint => {
            section(writer, &format!("2 — {}", say("wizard_step_taint")))?;
            ask_taint(reader, writer, script_locale, &defaults, &mut form)?;
        }
    }

    // --- STEPS 3 to 5: risk, solution, benefit -------------------------
    form.risk = ask_texts(
        reader,
        writer,
        &say,
        &format!("3 — {}", say("wizard_step_risk")),
        "wizard_risk",
        &defaults.risk,
        true,
    )?;
    form.solution = ask_texts(
        reader,
        writer,
        &say,
        &format!("4 — {}", say("wizard_step_solution")),
        "wizard_solution",
        &defaults.solution,
        true,
    )?;
    form.benefit = ask_texts(
        reader,
        writer,
        &say,
        &format!("5 — {}", say("wizard_step_benefit")),
        "wizard_benefit",
        &defaults.benefit,
        false,
    )?;

    // --- STEP 6: fix example (optional) --------------------------------
    section(writer, &format!("6 — {}", say("wizard_step_fix")))?;
    form.fix_before = prompt(
        reader,
        writer,
        &say("wizard_fix_before_prompt"),
        &defaults.fix_before,
    )?;
    if !form.fix_before.is_empty() {
        form.fix_after = prompt(
            reader,
            writer,
            &say("wizard_fix_after_prompt"),
            &defaults.fix_after,
        )?;
    }

    // --- STEP 7: generation, preview, validation, confirmation, writing
    let sca_content = (target.polish)(&build_sca_content(&name, &form));
    writeln!(writer, "\n  {}\n", say("wizard_old_preview"))?;
    for line in sca_content.trim().lines() {
        writeln!(writer, "    {line}")?;
    }
    writeln!(writer)?;

    // Compiled before the confirmation, with the parser's own message:
    // before ticket #154 an invalid rule was confirmed first, then
    // refused with no reason given.
    let target_file = target
        .rules_dir
        .join(&language)
        .join(&category)
        .join(format!("{name}.sca"));
    if let Err(error) = compile_sca_to_json(&sca_content, &target_file.to_string_lossy()) {
        writeln!(writer, "  {}", say("wizard_old_errors"))?;
        writeln!(writer, "    {}", error.render(script_locale))?;
        writeln!(writer, "  {}", say("wizard_old_cancelled"))?;
        return Ok(None);
    }

    let rule = WizardRule {
        sca: &sca_content,
        language: &language,
        category: &category,
        name: &name,
        form: &form,
    };
    (target.before_confirm)(writer, &rule)?;

    let confirm_key = if edit_mode {
        "wizard_update_confirm"
    } else {
        "wizard_old_create_confirm"
    };
    if !prompt_yes_no(reader, writer, script_locale, &say(confirm_key), true)? {
        writeln!(writer, "  {}", say("wizard_old_cancelled"))?;
        return Ok(None);
    }

    std::fs::create_dir_all(target_file.parent().expect("<dir>/<language>/<category>"))?;
    std::fs::write(&target_file, &sca_content)?;
    // An edited rule moved to another category leaves no copy behind: one
    // id, one file per language.
    if let Some(old) = existing_path.filter(|old| *old != target_file) {
        std::fs::remove_file(&old)?;
    }

    let result_key = if edit_mode {
        "wizard_updated"
    } else {
        "wizard_old_created"
    };
    writeln!(
        writer,
        "\n  {}",
        say(result_key).replace("{file}", &target_file.display().to_string())
    )?;
    (target.after_write)(writer, &rule, &target_file, edit_mode)?;
    Ok(Some(target_file))
}

/// A rule name the catalog accepts: lowercase letters, digits and
/// underscores, starting with a letter.
fn valid_rule_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The `"id"` of a compiled rule.
fn rule_id(rule: &Value) -> Option<&str> {
    rule.get("id").and_then(|v| v.as_str())
}

/// The rules among `others` whose compiled pattern is the one the
/// compiler writes for `text` (ticket #275, see the module doc): their id,
/// where they come from, and whether they are delivered rules.
fn same_pattern(others: &[&KnownRule], text: &str) -> Vec<(String, String, bool)> {
    let wanted = crate::scan::parser::compiler::text_to_regex(text.trim());
    others
        .iter()
        .filter(|rule| {
            rule.json
                .get("patterns")
                .and_then(|v| v.as_array())
                .is_some_and(|patterns| {
                    patterns.iter().any(|p| {
                        p.get("pattern").and_then(|v| v.as_str()).map(str::trim)
                            == Some(wanted.as_str())
                    })
                })
        })
        .map(|rule| {
            (
                rule_id(&rule.json).unwrap_or("").to_string(),
                rule.place.clone(),
                rule.delivered,
            )
        })
        .collect()
}

/// One required (English) text and three optional translations, under the
/// section `title`; `prefix` names their questions (`wizard_risk_en`…).
/// An optional block left empty in English asks no translation.
fn ask_texts<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    say: &dyn Fn(&str) -> String,
    title: &str,
    prefix: &str,
    defaults: &[String; 4],
    required: bool,
) -> io::Result<[String; 4]> {
    section(writer, title)?;
    let mut texts: [String; 4] = Default::default();
    loop {
        texts[0] = prompt(reader, writer, &say(&format!("{prefix}_en")), &defaults[0])?;
        if texts[0].is_empty() && required {
            writeln!(writer, "    {}", say("wizard_field_required"))?;
            continue;
        }
        break;
    }
    if texts[0].is_empty() {
        return Ok(texts);
    }
    for (i, code) in ["fr", "es", "de"].iter().enumerate() {
        texts[i + 1] = prompt(
            reader,
            writer,
            &say(&format!("{prefix}_{code}")),
            &defaults[i + 1],
        )?;
    }
    Ok(texts)
}

/// The four lists of a data-flow rule: sources (with their kind of data),
/// sinks (with the argument that carries the danger), sanitizers and
/// passthroughs. At least one source and one sink, as the compiler
/// requires; an empty answer ends a list.
///
/// Editing a rule, each item of its lists is offered in turn: an empty
/// answer keeps it, `-` removes it, another answer replaces it; the list
/// then goes on with new items.
fn ask_taint<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    script_locale: &Value,
    defaults: &RuleFormData,
    form: &mut RuleFormData,
) -> io::Result<()> {
    let say = |key: &str| t(script_locale, key);
    if !defaults.sources.is_empty() {
        writeln!(writer, "\n  {}", say("wizard_list_edit_hint"))?;
    }

    writeln!(writer, "\n  {}", say("wizard_sources_title"))?;
    let kind_labels: Vec<String> = VALID_SOURCE_KINDS
        .iter()
        .map(|kind| say(&format!("wizard_source_kind_{kind}")))
        .collect();
    let kind_choices: Vec<(&str, &str)> = VALID_SOURCE_KINDS
        .iter()
        .copied()
        .zip(kind_labels.iter().map(String::as_str))
        .collect();
    let mut offered = 0;
    loop {
        let default = defaults.sources.get(offered);
        offered += 1;
        let question = say("wizard_source_n").replace("{n}", &(form.sources.len() + 1).to_string());
        let Some(pattern) = list_item(
            reader,
            writer,
            &question,
            default.map(|s| s.pattern.as_str()),
        )?
        else {
            continue;
        };
        if pattern.is_empty() {
            if form.sources.is_empty() {
                writeln!(writer, "    {}", say("wizard_source_required"))?;
                continue;
            }
            break;
        }
        let default_kind = default
            .and_then(|s| VALID_SOURCE_KINDS.iter().position(|k| *k == s.kind))
            .unwrap_or(0);
        let kind = prompt_choice(
            reader,
            writer,
            script_locale,
            &say("wizard_source_kind"),
            &kind_choices,
            default_kind,
        )?;
        form.sources.push(SourceAnswer { pattern, kind });
    }

    writeln!(writer, "\n  {}", say("wizard_sinks_title"))?;
    let mut offered = 0;
    loop {
        let default = defaults.sinks.get(offered);
        offered += 1;
        let question = say("wizard_sink_n").replace("{n}", &(form.sinks.len() + 1).to_string());
        let Some(pattern) = list_item(
            reader,
            writer,
            &question,
            default.map(|s| s.pattern.as_str()),
        )?
        else {
            continue;
        };
        if pattern.is_empty() {
            if form.sinks.is_empty() {
                writeln!(writer, "    {}", say("wizard_sink_required"))?;
                continue;
            }
            break;
        }
        let argument = loop {
            let answer = prompt(
                reader,
                writer,
                &say("wizard_sink_argument"),
                default.map_or("", |s| s.argument.as_str()),
            )?;
            if answer.is_empty() || answer == "all" || answer.parse::<usize>().is_ok() {
                break answer;
            }
            writeln!(writer, "    {}", say("wizard_sink_argument_invalid"))?;
        };
        form.sinks.push(SinkAnswer { pattern, argument });
    }

    for (title, question, defaults, list) in [
        (
            "wizard_sanitizers_title",
            "wizard_sanitizer_n",
            &defaults.sanitizers,
            &mut form.sanitizers,
        ),
        (
            "wizard_passthroughs_title",
            "wizard_passthrough_n",
            &defaults.passthroughs,
            &mut form.passthroughs,
        ),
    ] {
        writeln!(writer, "\n  {}", say(title))?;
        let mut offered = 0;
        loop {
            let default = defaults.get(offered).map(String::as_str);
            offered += 1;
            let text = say(question).replace("{n}", &(list.len() + 1).to_string());
            let Some(answer) = list_item(reader, writer, &text, default)? else {
                continue;
            };
            if answer.is_empty() {
                break;
            }
            list.push(answer);
        }
    }
    Ok(())
}

/// One item of a list: `None` when the offered item is removed (`-`),
/// an empty text when the list ends, else the item.
fn list_item<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    question: &str,
    offered: Option<&str>,
) -> io::Result<Option<String>> {
    let answer = prompt(reader, writer, question, offered.unwrap_or(""))?;
    Ok(if offered.is_some() && answer == "-" {
        None
    } else {
        Some(answer)
    })
}
