//! Detection of minified files, which the scan skips (ADR-0045).
//!
//! A minified file is code compressed onto a few very long lines: a
//! JavaScript bundle, a saved web page. It is not code the project
//! writes or reviews, and its findings point at lines of several
//! megabytes nobody can read. It also dominated the cost of a scan:
//! on `bountybench-main`, about 80 MB of minified JavaScript and saved
//! pages made the scan hold 10 to 12 GB of memory (tree-sitter trees,
//! report lines copied whole, tickets #191 and #192).
//!
//! The engine of reference (`Audit`, Python) has no such detection: it
//! only skips the paths of its exclusion patterns. Skipping minified
//! files is a deliberate deviation, decided on 2026-11-17 (ticket #195).
//!
//! Phase A applies [`is_minified`] right after reading a file, before
//! parsing it; the skipped files are listed in the scan report and on
//! the console, so that no code is left out without a word.

use std::path::Path;

use crate::scan::orchestrator::SourceLanguage;

/// Below this size, a file is never judged on its content: nothing
/// distinguishes a short minified line from a short hand-written one
/// (`module.exports = {...}` on one line), and skipping it would save
/// nothing.
const MIN_BYTES: usize = 1024;

/// Average line length above which a JavaScript or TypeScript file is
/// minified: the rule GitHub Linguist uses for its "minified files".
/// On the 13 test projects, every JavaScript file above it outside
/// `bountybench-main` was a bundle, an obfuscated challenge (DVWA) or
/// generated data (icon fonts, base64 images); hand-written files stay
/// below.
const MAX_AVERAGE_JS: usize = 110;

/// Average line length above which an HTML file is minified. Higher
/// than for JavaScript: ordinary HTML has longer lines (the attribute
/// lists of `owasp_java`'s pages average 121 characters, a juice-shop
/// template with an inline SVG path 110), while minified or saved
/// pages are well above 300.
const MAX_AVERAGE_HTML: usize = 300;

/// True when the file at `path`, of `language`, with content `text`, is
/// minified and must be skipped.
///
/// - A name of the form `<name>.min.<ext>` (`jquery.min.js`) is minified
///   whatever the language: the convention says so.
/// - Otherwise, a JavaScript, TypeScript or HTML file of at least
///   [`MIN_BYTES`] is minified when its average line length exceeds
///   [`MAX_AVERAGE_JS`] or [`MAX_AVERAGE_HTML`]. Other languages are
///   not minified in practice: a long line there is a constant (a key,
///   a base64 blob) inside hand-written code, which must stay scanned.
pub(crate) fn is_minified(path: &Path, language: SourceLanguage, text: &str) -> bool {
    if has_min_suffix(path) {
        return true;
    }
    let max_average = match language {
        SourceLanguage::JavaScript | SourceLanguage::TypeScript => MAX_AVERAGE_JS,
        SourceLanguage::Html => MAX_AVERAGE_HTML,
        _ => return false,
    };
    if text.len() < MIN_BYTES {
        return false;
    }
    let lines = text.lines().count().max(1);
    text.len() / lines > max_average
}

/// True for a file name `<name>.min.<ext>`: `.min` right before the
/// extension, with a non-empty name before it.
fn has_min_suffix(path: &Path) -> bool {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| stem.strip_suffix(".min"))
        .is_some_and(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn js(text: &str) -> bool {
        is_minified(Path::new("src/app.js"), SourceLanguage::JavaScript, text)
    }

    /// A bundle: one line of several kilobytes.
    #[test]
    fn test_one_long_javascript_line_is_minified() {
        let line = "var a=1;".repeat(500);
        assert!(js(&line));
    }

    /// Hand-written code: short lines, even with one long constant.
    #[test]
    fn test_hand_written_javascript_is_not_minified() {
        let mut text = "function f(x) {\n  return x + 1;\n}\n".repeat(60);
        text.push_str(&format!("const KEY = \"{}\";\n", "a".repeat(2000)));
        assert!(!js(&text));
    }

    /// Under `MIN_BYTES`, a one-line file is not judged on its content.
    #[test]
    fn test_small_one_line_file_is_not_minified() {
        assert!(!js(&format!(
            "module.exports = {{ name: \"{}\" }};",
            "x".repeat(150)
        )));
    }

    /// The `.min.` naming convention is enough, in any language.
    #[test]
    fn test_min_suffix_is_minified_in_any_language() {
        let path = Path::new("static/lib.min.html");
        assert!(is_minified(path, SourceLanguage::Html, "<p>hi</p>\n"));
        assert!(!has_min_suffix(Path::new("static/.min.js")));
        assert!(!has_min_suffix(Path::new("static/admin.js")));
    }

    /// HTML has its own, higher threshold: long attribute lines stay
    /// scanned, a saved one-line page does not.
    #[test]
    fn test_html_threshold_is_higher_than_javascript() {
        let attributes = format!("<li><a href='{}'>link</a></li>\n", "p".repeat(100)).repeat(40);
        let path = Path::new("web/index.html");
        assert!(!is_minified(path, SourceLanguage::Html, &attributes));
        assert!(is_minified(
            path,
            SourceLanguage::Html,
            &"<div></div>".repeat(400)
        ));
    }

    /// A Python or Java file with a long line is hand-written code
    /// holding a constant: never skipped on its content.
    #[test]
    fn test_other_languages_are_never_judged_on_content() {
        let text = "x".repeat(5000);
        assert!(!is_minified(
            Path::new("a.py"),
            SourceLanguage::Python,
            &text
        ));
        assert!(!is_minified(
            Path::new("A.java"),
            SourceLanguage::Java,
            &text
        ));
    }
}
