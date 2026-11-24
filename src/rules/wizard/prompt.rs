//! Questions of the rule wizard on a text console — ported from
//! `_prompt`/`_prompt_choice`/`_prompt_yes_no`/`_section` of
//! `Audit/sca/rule_wizard.py`. Reading and writing go through generic
//! `BufRead`/`Write`, so the wizard runs in tests with boxed input.

use std::io::{self, BufRead, Write};

use serde_json::Value;

use crate::i18n::t;

/// One line of input. End of input is an `UnexpectedEof` error, like
/// Python's `input()` raising `EOFError`: treating it as an empty answer
/// made every required question loop forever on a closed input (ticket
/// #154: 13 MB of prompts in 2 s with `</dev/null`).
pub fn read_line<R: BufRead>(reader: &mut R) -> io::Result<String> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "input closed"));
    }
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// A free answer; an empty answer gives `default`. `colon` ends the
/// question the console language's way (`label_colon` of the console
/// locale: `": "`, French `" : "`); every question was written the French
/// way before 2026-11-24.
pub fn prompt<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    colon: &str,
    question: &str,
    default: &str,
) -> io::Result<String> {
    if !default.is_empty() {
        write!(writer, "  {question} [{default}]{colon}")?;
        writer.flush()?;
        let answer = read_line(reader)?;
        let answer = answer.trim();
        Ok(if answer.is_empty() {
            default.to_string()
        } else {
            answer.to_string()
        })
    } else {
        write!(writer, "  {question}{colon}")?;
        writer.flush()?;
        Ok(read_line(reader)?.trim().to_string())
    }
}

/// One of `choices` (value, description), by number or by value; an empty
/// answer gives the choice at `default_idx`. Asked again until valid.
pub fn prompt_choice<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    script_locale: &Value,
    question: &str,
    choices: &[(&str, &str)],
    default_idx: usize,
) -> io::Result<String> {
    writeln!(writer, "\n  {question}")?;
    for (i, (value, desc)) in choices.iter().enumerate() {
        let marker = if i == default_idx { ">" } else { " " };
        writeln!(writer, "    {marker} {}. {value} — {desc}", i + 1)?;
    }
    loop {
        write!(
            writer,
            "  {} [1-{}, {} {}]{}",
            t(script_locale, "wiz_choice"),
            choices.len(),
            t(script_locale, "wizard_old_default"),
            default_idx + 1,
            t(script_locale, "label_colon")
        )?;
        writer.flush()?;
        let answer = read_line(reader)?;
        let answer = answer.trim();
        if answer.is_empty() {
            return Ok(choices[default_idx].0.to_string());
        }
        if let Ok(n) = answer.parse::<i64>() {
            let idx = n - 1;
            if idx >= 0 && (idx as usize) < choices.len() {
                return Ok(choices[idx as usize].0.to_string());
            }
        } else if let Some((value, _)) =
            choices.iter().find(|(v, _)| v.eq_ignore_ascii_case(answer))
        {
            return Ok(value.to_string());
        }
        writeln!(
            writer,
            "    {}",
            t(script_locale, "wizard_choice_invalid").replace("{max}", &choices.len().to_string())
        )?;
    }
}

/// Yes/no question. The `(Y/n)` hint follows the locale; "yes" is
/// accepted in the four console languages whatever `--lang` is, so a
/// habit from another language never reads as "no".
pub fn prompt_yes_no<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    script_locale: &Value,
    question: &str,
    default: bool,
) -> io::Result<bool> {
    let suffix = t(
        script_locale,
        if default {
            "wizard_yes_no_default_yes"
        } else {
            "wizard_yes_no_default_no"
        },
    );
    let colon = t(script_locale, "label_colon");
    write!(writer, "  {question} {suffix}{colon}")?;
    writer.flush()?;
    let answer = read_line(reader)?.trim().to_lowercase();
    if answer.is_empty() {
        return Ok(default);
    }
    Ok(matches!(
        answer.as_str(),
        "y" | "yes" | "o" | "oui" | "s" | "si" | "sí" | "j" | "ja"
    ))
}

/// The title of a step of the wizard.
pub fn section<W: Write>(writer: &mut W, title: &str) -> io::Result<()> {
    writeln!(writer, "\n  --- {title} ---")
}
