//! Small text utilities for the HTML report — port of `_escape`,
//! `_is_dependency`, `_lang_label`, `_linkify_acronyms`,
//! `_linkify_acronyms_in_html` (`Audit/sca/report.py`) and
//! `get_context` (`Audit/sca/utils.py`).

use fancy_regex::Regex;
use serde_json::Value;

use crate::report::exports::sarif::ReportFinding;
use crate::scan::engine::FileScope;

/// The display name of a compiled rule in `lang`: its `name` block (the
/// rule file is the only source of its texts), in English when `lang` is
/// missing, or the rule's identifier when it has no name at all (a client
/// rule may have none). Not escaped.
pub fn rule_display_name(rule: &Value, lang: &str) -> String {
    let name = crate::scan::orchestrator::extract_i18n_block(rule, "name", lang);
    if !name.is_empty() {
        return name;
    }
    rule.get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Longest code line a finding shows whole, in characters: the limit of
/// the Python engine (`runner.py::_add_finding`, `code.strip()[:200]`).
pub const MAX_SHOWN_CHARS: usize = 200;

/// Characters a clipped line keeps before the spot it is clipped around,
/// so that the start of the match reads with what leads to it.
const LEAD_CHARS: usize = 50;

/// `line` as a finding shows it (ticket #194): unchanged up to
/// [`MAX_SHOWN_CHARS`] characters, otherwise a window of that many
/// characters around `focus` (a byte offset in `line`, 0 when the spot
/// is unknown), marked `…` on each side that was cut.
///
/// **Deliberate deviation from the Python engine**, which keeps the first
/// 200 characters with no mark: on a long line the match can sit past
/// them (a saved page, a long template), and an unmarked cut reads as the
/// whole line. The window starts [`LEAD_CHARS`] before the focus and is
/// moved back when it would run past the end. A `focus` that is not a
/// character boundary is moved back to the previous one.
pub fn clip_line(line: &str, focus: usize) -> String {
    let total = line.chars().count();
    if total <= MAX_SHOWN_CHARS {
        return line.to_string();
    }
    let mut focus = focus.min(line.len());
    while !line.is_char_boundary(focus) {
        focus -= 1;
    }
    let focus_char = line[..focus].chars().count();
    let start = focus_char
        .saturating_sub(LEAD_CHARS)
        .min(total - MAX_SHOWN_CHARS);
    let end = start + MAX_SHOWN_CHARS;
    let mut shown = String::new();
    if start > 0 {
        shown.push('…');
    }
    shown.extend(line.chars().skip(start).take(MAX_SHOWN_CHARS));
    if end < total {
        shown.push('…');
    }
    shown
}

/// [`clip_line`] on each line of a block of context lines, around the
/// same byte column as the finding's line, so that the lines of the block
/// stay aligned.
pub fn clip_lines(block: &str, focus: usize) -> String {
    block
        .split('\n')
        .map(|line| clip_line(line, focus))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Byte offset of `needle` in `line`, 0 when it is absent or empty: where
/// to clip a line around a text the engine knows (the callee of a taint
/// sink, the expression of a flow step) but not its column.
pub fn focus_of(line: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    line.find(needle).unwrap_or(0)
}

/// Escapes special HTML characters — port of `_escape`.
///
/// **Deliberate deviation from the Python `_escape` (security fix,
/// 2026-11-15):** the single quote `'` is escaped too, which Python does
/// not do. A scanned project is untrusted and controls its file and
/// directory names, which end up in the report. The heatmap renders a path
/// inside a single-quoted JavaScript string of an inline handler
/// (`heatmap-item.html`: `onclick="navigateToFile('{{filepath}}')"`); a
/// path containing `'` escaped only against `<>&"` closed that string and
/// injected script that ran when the auditor clicked the file (confirmed by
/// proof of concept). `&#39;` is a numeric entity understood everywhere and
/// is harmless in text or double-quoted attributes. `&` stays first so an
/// escaped character is never re-escaped.
pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Context lines around a detected line (1-indexed), returned as
/// (before, after) joined with `\n` — port of
/// `sca/utils.py::get_context` (`context_size=2` by default: 2 lines
/// before, 2 after). `lines` is 0-indexed (element `i` = line `i+1`).
pub fn context_lines<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    line: usize,
    context_size: usize,
) -> (String, String) {
    let mut before = Vec::new();
    let mut after = Vec::new();
    for (idx, content) in lines.into_iter().enumerate() {
        let ln = idx + 1;
        if line.saturating_sub(context_size) <= ln && ln < line {
            before.push(content.trim_end());
        } else if line < ln && ln <= line + context_size {
            after.push(content.trim_end());
        }
    }
    (before.join("\n"), after.join("\n"))
}

const DEPENDENCY_PATH_PATTERNS: [&str; 8] = [
    "/vendor/",
    "/lib/",
    "/node_modules/",
    "/dist/",
    "/build/",
    "/assets/vendor/",
    ".min.js",
    ".bundle.js",
];
const DEPENDENCY_EXTRA_PATTERNS: [&str; 2] = ["/alembic/", "alembic/"];
const DEPENDENCY_FILENAMES: [&str; 7] = [
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
];

/// Determines whether a file is part of the external dependencies —
/// port of `_is_dependency`.
pub fn is_dependency(filepath: &str) -> bool {
    let lower = filepath.to_lowercase();
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    if DEPENDENCY_FILENAMES.contains(&basename) {
        return true;
    }
    DEPENDENCY_PATH_PATTERNS
        .iter()
        .chain(DEPENDENCY_EXTRA_PATTERNS.iter())
        .any(|p| lower.contains(p))
}

/// Language label inferred from the file extension — port of
/// `_lang_label`.
pub fn lang_label(file: &str) -> &'static str {
    let basename = file.rsplit('/').next().unwrap_or(file);
    if basename.eq_ignore_ascii_case("dockerfile") {
        return "Dockerfile";
    }
    let ext = basename.rsplit_once('.').map(|(_, e)| e.to_lowercase());
    match ext.as_deref() {
        Some("py") | Some("pyw") => "Python",
        Some("js") | Some("jsx") | Some("mjs") | Some("cjs") => "JavaScript",
        Some("ts") | Some("tsx") => "TypeScript",
        Some("java") => "Java",
        Some("cs") => "C#",
        Some("php") => "PHP",
        Some("html") | Some("htm") => "HTML",
        Some("yml") | Some("yaml") => "YAML",
        _ => "",
    }
}

struct AcronymEntry {
    key: String,
    term: String,
    tooltip: String,
}

fn glossary_entries(report_locale: &Value) -> Vec<AcronymEntry> {
    let mut entries = Vec::new();
    if let Some(Value::Object(acronyms)) =
        crate::i18n::get_nested(report_locale, "glossary.acronyms")
    {
        for (key, acr) in acronyms {
            let term = acr
                .get("term")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let full = acr.get("full").and_then(|v| v.as_str()).unwrap_or("");
            let desc = acr.get("desc").and_then(|v| v.as_str()).unwrap_or("");
            entries.push(AcronymEntry {
                key: key.clone(),
                term,
                tooltip: format!("{full} — {desc}"),
            });
        }
    }
    entries.sort_by_key(|a| std::cmp::Reverse(a.term.len()));
    entries
}

/// Replaces known acronyms with links to the glossary, with a
/// tooltip — port of `_linkify_acronyms`. Applies to text that has
/// already been escaped (see `escape`); for full HTML, see
/// `linkify_acronyms_in_html`.
///
/// Deliberate deviation from the Python source (ticket #203, 2026-11-18):
/// Python replaced the terms one after the other, longest first, so a
/// later term was also found inside the `data-tooltip` of a link already
/// inserted when an acronym's definition names another one (EPSS names
/// CVE, XPath and SVG name XML). The link then landed inside the
/// attribute, cut it short, and HTML showed in the report. All the terms
/// are now replaced in one pass of a combined pattern, like
/// `linkify_acronyms_in_html`: a replacement is never searched again. The
/// alternation lists the longest terms first, so HTTPS still wins over
/// HTTP at the same position.
pub fn linkify_acronyms(report_locale: &Value, text: &str) -> String {
    let entries = glossary_entries(report_locale);
    if entries.is_empty() {
        return text.to_string();
    }
    // `glossary_entries` sorts by descending length.
    let all_terms = entries
        .iter()
        .map(|e| fancy_regex::escape(&e.term).into_owned())
        .collect::<Vec<_>>()
        .join("|");
    // Whole word, not right after a tag (`>`) nor inside a path (`/`).
    let combined = Regex::new(&format!(r"(?<![>\w/])({all_terms})(?![<\w])"))
        .expect("valid combined acronym pattern");
    let links: std::collections::HashMap<&str, String> = entries
        .iter()
        .map(|e| {
            (
                e.term.as_str(),
                format!(
                    r##"<a href="#acr-{}" class="glossary-link" data-tooltip="{}">{}</a>"##,
                    e.key,
                    escape(&e.tooltip),
                    e.term
                ),
            )
        })
        .collect();
    combined
        .replace_all(text, |caps: &fancy_regex::Captures<'_, str>| {
            let matched = caps.get(0).expect("group 0 always present").as_str();
            links
                .get(matched)
                .cloned()
                .unwrap_or_else(|| matched.to_string())
        })
        .into_owned()
}

/// Applies acronym linkification to the full report HTML — port of
/// `_linkify_acronyms_in_html`. Only processes visible text content:
/// ignores tags, `<script>`/`<style>`/`<code>`/`<pre>`/`<a>`, and links
/// already in place. Replacement done in a single pass (combined
/// regex) to avoid nested-replacement artifacts in `data-tooltip`
/// attributes.
pub fn linkify_acronyms_in_html(report_locale: &Value, html: &str) -> String {
    let entries = glossary_entries(report_locale);
    if entries.is_empty() {
        return html.to_string();
    }

    let mut term_to_link: std::collections::HashMap<&str, String> =
        std::collections::HashMap::new();
    let mut sorted_terms: Vec<&str> = Vec::with_capacity(entries.len());
    for e in &entries {
        let tooltip = escape(&e.tooltip);
        let link = format!(
            r##"<a href="#acr-{}" class="glossary-link" data-tooltip="{}">{}</a>"##,
            e.key, tooltip, e.term
        );
        term_to_link.insert(e.term.as_str(), link);
        sorted_terms.push(e.term.as_str());
    }
    sorted_terms.sort_by_key(|a| std::cmp::Reverse(a.len()));

    let all_terms = sorted_terms
        .iter()
        .map(|t| fancy_regex::escape(t).into_owned())
        .collect::<Vec<_>>()
        .join("|");
    let combined = Regex::new(&format!(r"(?<![\w/])({all_terms})(?![\w])"))
        .expect("valid combined acronym pattern");

    let tag_re = Regex::new(r"(?s)(<[^>]+>|<!--.*?-->)").expect("valid tag pattern");

    let mut segments: Vec<String> = Vec::new();
    let mut last_end = 0;
    for m in tag_re.find_iter(html) {
        let Ok(m) = m else { continue };
        if m.start() > last_end {
            segments.push(html[last_end..m.start()].to_string());
        }
        segments.push(html[m.start()..m.end()].to_string());
        last_end = m.end();
    }
    if last_end < html.len() {
        segments.push(html[last_end..].to_string());
    }

    const SKIP_TAGS: [&str; 5] = ["script", "style", "code", "pre", "a"];
    let mut skip_depth: i32 = 0;
    let mut glossary_skip = false;

    for segment in segments.iter_mut() {
        if segment.starts_with('<') {
            if segment == "<!-- GLOSSARY_NO_LINKIFY -->" {
                glossary_skip = true;
                continue;
            }
            if segment == "<!-- /GLOSSARY_NO_LINKIFY -->" {
                glossary_skip = false;
                continue;
            }
            let trimmed = segment.trim_start_matches('<');
            let is_closing = trimmed.starts_with('/');
            let name_part = trimmed.trim_start_matches('/');
            let tag_name: String = name_part
                .chars()
                .take_while(|c| c.is_alphanumeric())
                .collect::<String>()
                .to_lowercase();
            if SKIP_TAGS.contains(&tag_name.as_str()) {
                if is_closing {
                    skip_depth = (skip_depth - 1).max(0);
                } else if !segment.ends_with("/>") {
                    skip_depth += 1;
                }
            }
            continue;
        }

        if skip_depth > 0 || glossary_skip || segment.trim().is_empty() {
            continue;
        }

        *segment = combined
            .replace_all(segment, |caps: &fancy_regex::Captures<'_, str>| {
                let matched = caps.get(0).expect("group 0 always present").as_str();
                term_to_link
                    .get(matched)
                    .cloned()
                    .unwrap_or_else(|| matched.to_string())
            })
            .into_owned();
    }

    segments.concat()
}

/// Where a finding is, as the report writes it (not escaped): `file:line`
/// for a finding on a line, `file (whole file)` in the report's language
/// for a finding about the whole file, which has no faulty line to point
/// at (ticket #214).
pub fn finding_location(f: &ReportFinding, report_locale: &Value) -> String {
    if f.file_scope.is_some() {
        crate::i18n::t(report_locale, "finding_whole_file").replace("{file}", &f.file)
    } else {
        format!("{}:{}", f.file, f.line)
    }
}

/// The sentence that says what a whole-file finding measured, in the
/// report's language (not escaped): the file's line count against the
/// rule's threshold for a length rule, otherwise that the rule is about
/// the whole file (ticket #214).
pub fn file_scope_sentence(scope: &FileScope, report_locale: &Value) -> String {
    match scope.min_lines {
        Some(min) => crate::i18n::t(report_locale, "finding_file_lines")
            .replace("{count}", &scope.line_count.to_string())
            .replace("{min}", &min.to_string()),
        None => crate::i18n::t(report_locale, "finding_file_scope"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;

    #[test]
    fn test_context_lines_middle_of_file() {
        let lines: Vec<String> = (1..=10).map(|n| format!("line{n}")).collect();
        let (before, after) = context_lines(lines.iter().map(String::as_str), 5, 2);
        assert_eq!(before, "line3\nline4");
        assert_eq!(after, "line6\nline7");
    }

    #[test]
    fn test_context_lines_at_start_of_file() {
        let lines: Vec<String> = (1..=5).map(|n| format!("line{n}")).collect();
        let (before, after) = context_lines(lines.iter().map(String::as_str), 1, 2);
        assert_eq!(before, "");
        assert_eq!(after, "line2\nline3");
    }

    #[test]
    fn test_context_lines_at_end_of_file() {
        let lines: Vec<String> = (1..=5).map(|n| format!("line{n}")).collect();
        let (before, after) = context_lines(lines.iter().map(String::as_str), 5, 2);
        assert_eq!(before, "line3\nline4");
        assert_eq!(after, "");
    }

    #[test]
    fn test_context_lines_trims_trailing_whitespace() {
        let lines = ["a  ".to_string(), "b\t".to_string(), "c".to_string()];
        let (before, _) = context_lines(lines.iter().map(String::as_str), 3, 2);
        assert_eq!(before, "a\nb");
    }

    #[test]
    fn test_escape_all_special_chars() {
        assert_eq!(
            escape(r#"<a href="x">&'"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }

    /// Security regression (2026-11-15): the single quote must be escaped,
    /// so a value put inside a single-quoted JS string (the heatmap's
    /// `onclick`) cannot break out of it. See `escape`'s doc comment.
    #[test]
    fn test_escape_single_quote() {
        assert_eq!(escape("a'); alert(1); ('"), "a&#39;); alert(1); (&#39;");
        assert!(
            !escape("x'y").contains('\''),
            "no bare single quote survives"
        );
    }

    #[test]
    fn test_escape_preserves_plain_text() {
        assert_eq!(escape("hello world"), "hello world");
    }

    #[test]
    fn test_is_dependency_vendor_path() {
        assert!(is_dependency("app/vendor/lib.js"));
        assert!(is_dependency("src/node_modules/foo/bar.js"));
        assert!(is_dependency("src/foo.min.js"));
    }

    #[test]
    fn test_is_dependency_declaration_files() {
        assert!(is_dependency("requirements.txt"));
        assert!(is_dependency("PACKAGE.JSON"));
    }

    #[test]
    fn test_is_dependency_business_code_is_false() {
        assert!(!is_dependency("src/app/views.py"));
    }

    #[test]
    fn test_lang_label_known_extensions() {
        assert_eq!(lang_label("app.py"), "Python");
        assert_eq!(lang_label("app.tsx"), "TypeScript");
        assert_eq!(lang_label("Dockerfile"), "Dockerfile");
        assert_eq!(lang_label("path/to/Dockerfile"), "Dockerfile");
    }

    #[test]
    fn test_lang_label_unknown_extension_is_empty() {
        assert_eq!(lang_label("data.bin"), "");
    }

    #[test]
    fn test_linkify_acronyms_wraps_known_term() {
        let en = load_report_locale("en");
        let out = linkify_acronyms(&en, "This uses ASVS heavily.");
        assert!(out.contains(r##"href="#acr-asvs""##));
        assert!(out.contains(">ASVS<"));
    }

    #[test]
    fn test_linkify_acronyms_no_match_unchanged() {
        let en = load_report_locale("en");
        let out = linkify_acronyms(&en, "no acronym here");
        assert_eq!(out, "no acronym here");
    }

    #[test]
    fn test_linkify_acronyms_in_html_skips_code_blocks() {
        let en = load_report_locale("en");
        let html = "<p>ASVS coverage</p><pre><code>ASVS</code></pre>";
        let out = linkify_acronyms_in_html(&en, html);
        assert_eq!(out.matches("glossary-link").count(), 1);
        assert!(out.contains("<pre><code>ASVS</code></pre>"));
    }

    #[test]
    fn test_linkify_acronyms_in_html_skips_existing_links() {
        let en = load_report_locale("en");
        let html = r##"<a href="#x">ASVS</a> and ASVS again"##;
        let out = linkify_acronyms_in_html(&en, html);
        assert_eq!(out.matches("glossary-link").count(), 1);
    }

    #[test]
    fn test_linkify_acronyms_in_html_respects_glossary_no_linkify() {
        let en = load_report_locale("en");
        let html = "<!-- GLOSSARY_NO_LINKIFY -->ASVS<!-- /GLOSSARY_NO_LINKIFY --><p>ASVS</p>";
        let out = linkify_acronyms_in_html(&en, html);
        assert_eq!(out.matches("glossary-link").count(), 1);
    }

    /// Ticket #203: the definition of EPSS names CVE, and those of XPath
    /// and SVG name XML. A link is never inserted inside the tooltip of
    /// another: each acronym of the text gets exactly one link, and the
    /// tooltips hold no tag.
    #[test]
    fn test_linkify_acronyms_never_links_inside_a_tooltip() {
        for lang in ["en", "fr", "de", "es"] {
            let locale = load_report_locale(lang);
            let out = linkify_acronyms(
                &locale,
                "CVE-2025-1 (CRITICAL, EPSS 0.6 %); XPath; SVG; JNDI",
            );
            assert_eq!(out.matches("<a ").count(), 5, "{lang}: {out}");
            let tooltip = Regex::new(r#"data-tooltip="([^"]*)""#).unwrap();
            for caps in tooltip.captures_iter(&out) {
                let text = caps.unwrap().get(1).unwrap().as_str();
                assert!(!text.contains('<'), "{lang}: tag in tooltip {text}");
            }
        }
    }

    #[test]
    fn test_linkify_acronyms_prefix_term_not_double_matched() {
        let en = load_report_locale("en");
        // If both HTTP and HTTPS are in the glossary, HTTPS must not
        // get partially re-matched by HTTP once linkified.
        let glossary = crate::i18n::get_nested(&en, "glossary.acronyms").unwrap();
        if glossary.get("http").is_some() && glossary.get("https").is_some() {
            let out = linkify_acronyms(&en, "HTTPS is secure");
            assert_eq!(out.matches("glossary-link").count(), 1);
        }
    }

    /// Ticket #194: a line up to the limit is shown whole.
    #[test]
    fn test_clip_line_keeps_a_short_line_whole() {
        let line = "x".repeat(MAX_SHOWN_CHARS);
        assert_eq!(clip_line(&line, 150), line);
    }

    /// Ticket #194: a line of 100,000 characters shows a bounded window
    /// that holds the spot, marked on both sides.
    #[test]
    fn test_clip_line_bounds_a_long_line_around_the_spot() {
        let line = format!("{}eval(x){}", "a".repeat(50_000), "b".repeat(50_000));
        let shown = clip_line(&line, 50_000);
        assert!(shown.contains("eval(x)"), "{shown}");
        assert!(shown.starts_with('…') && shown.ends_with('…'));
        assert_eq!(shown.chars().count(), MAX_SHOWN_CHARS + 2);
    }

    /// Unknown spot: the window starts at the line start, cut at the end
    /// only. A spot near the end moves the window back.
    #[test]
    fn test_clip_line_window_stays_inside_the_line() {
        let line = "c".repeat(1000);
        let start = clip_line(&line, 0);
        assert!(!start.starts_with('…') && start.ends_with('…'));
        let end = clip_line(&line, 999);
        assert!(end.starts_with('…') && !end.ends_with('…'));
        assert_eq!(end.chars().count(), MAX_SHOWN_CHARS + 1);
    }

    /// A focus inside a multi-byte character does not panic.
    #[test]
    fn test_clip_line_handles_a_focus_inside_a_character() {
        let line = "é".repeat(500);
        assert_eq!(clip_line(&line, 301).chars().count(), MAX_SHOWN_CHARS + 2);
    }

    /// Context lines are clipped one by one around the same column.
    #[test]
    fn test_clip_lines_clips_each_line() {
        let block = format!("short\n{}", "d".repeat(500));
        let shown = clip_lines(&block, 0);
        let lines: Vec<&str> = shown.split('\n').collect();
        assert_eq!(lines[0], "short");
        assert_eq!(lines[1].chars().count(), MAX_SHOWN_CHARS + 1);
    }
}
