//! HTML/CSS/JS templates, favicons and Chart.js library for the report —
//! port of `_load_template`/`_load_asset` (`Audit/sca/report.py`).
//!
//! Unlike Python (`resources/templates/`/`resources/assets/`/`resources/vendor/` files sitting
//! next to the compiled binary, read at runtime — cf. `SCRIPT_DIR` in
//! compiled mode in `sca/__init__.py`), these resources are embedded
//! here at compile time via `include_str!`/`include_bytes!`: they are
//! static, not editable by the client, and embedding eliminates
//! the "file forgotten next to the binary" failure mode with no
//! extra complexity — the same choice as for locales (`i18n/mod.rs`) and
//! the compliance mappings (`compliance.rs`).

use base64::Engine;

macro_rules! templates {
    ($(($name:literal, $path:literal)),+ $(,)?) => {
        const TEMPLATES: &[(&str, &str)] = &[
            $(($name, include_str!($path))),+
        ];
    };
}

templates! {
    ("audit-params.html", "../../resources/templates/audit-params.html"),
    ("audit.config.template.json", "../../resources/templates/audit.config.template.json"),
    ("category-badge.html", "../../resources/templates/category-badge.html"),
    ("charts.js", "../../resources/templates/charts.js"),
    ("charts.min.js", "../../resources/templates/charts.min.js"),
    ("cli-option-item.html", "../../resources/templates/cli-option-item.html"),
    ("comparison-full.html", "../../resources/templates/comparison-full.html"),
    ("comparison-item.html", "../../resources/templates/comparison-item.html"),
    ("comparison-section.html", "../../resources/templates/comparison-section.html"),
    ("custom-rules-section.html", "../../resources/templates/custom-rules-section.html"),
    ("delta.html", "../../resources/templates/delta.html"),
    ("finding-item.html", "../../resources/templates/finding-item.html"),
    ("finding-mini.html", "../../resources/templates/finding-mini.html"),
    ("findings-category-group.html", "../../resources/templates/findings-category-group.html"),
    ("findings-group.html", "../../resources/templates/findings-group.html"),
    ("findings-rule-group.html", "../../resources/templates/findings-rule-group.html"),
    ("fixture-detail.html", "../../resources/templates/fixture-detail.html"),
    ("fixture-status-span.html", "../../resources/templates/fixture-status-span.html"),
    ("fixture-type-span.html", "../../resources/templates/fixture-type-span.html"),
    ("fixtures-failures-wrapper.html", "../../resources/templates/fixtures-failures-wrapper.html"),
    ("fixtures-list.html", "../../resources/templates/fixtures-list.html"),
    ("fixtures-more.html", "../../resources/templates/fixtures-more.html"),
    ("fixtures-section.html", "../../resources/templates/fixtures-section.html"),
    ("health-category-card.html", "../../resources/templates/health-category-card.html"),
    ("heatmap-item.html", "../../resources/templates/heatmap-item.html"),
    ("report-base.html", "../../resources/templates/report-base.html"),
    ("report.css", "../../resources/templates/report.css"),
    ("report.js", "../../resources/templates/report.js"),
    ("report.min.css", "../../resources/templates/report.min.css"),
    ("report.min.js", "../../resources/templates/report.min.js"),
    ("severity-section.html", "../../resources/templates/severity-section.html"),
    ("successes-section.html", "../../resources/templates/successes-section.html"),
    ("test-failed-item.html", "../../resources/templates/test-failed-item.html"),
    ("tests-failed-list.html", "../../resources/templates/tests-failed-list.html"),
    ("tests-section.html", "../../resources/templates/tests-section.html"),
}

const VENDOR_CHART_JS: &str = include_str!("../../resources/vendor/chart.min.js");

macro_rules! assets {
    ($(($name:literal, $path:literal)),+ $(,)?) => {
        const ASSETS: &[(&str, &[u8])] = &[
            $(($name, include_bytes!($path))),+
        ];
    };
}

assets! {
    ("apple-touch-icon.png", "../../resources/assets/apple-touch-icon.png"),
    ("favicon-16x16.png", "../../resources/assets/favicon-16x16.png"),
    ("favicon-192x192.png", "../../resources/assets/favicon-192x192.png"),
    ("favicon-32x32.png", "../../resources/assets/favicon-32x32.png"),
    ("favicon-512x512.png", "../../resources/assets/favicon-512x512.png"),
    ("favicon-white.svg", "../../resources/assets/favicon-white.svg"),
    ("favicon.ico", "../../resources/assets/favicon.ico"),
    ("favicon.svg", "../../resources/assets/favicon.svg"),
    ("youtube-profile-800x800.png", "../../resources/assets/youtube-profile-800x800.png"),
}

/// Loads a template by its file name — port of `_load_template`
/// (without the `subdir="vendor"` parameter, cf. `load_vendor_chart_js`).
/// Panics on an unknown name: the catalog is fixed at compile time,
/// so a missing name is a typo on the caller's side, not a runtime
/// state to absorb (unlike Python, where the file can be
/// missing next to the binary).
pub fn load_template(name: &str) -> &'static str {
    TEMPLATES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, c)| *c)
        .unwrap_or_else(|| panic!("gabarit inconnu: {name}"))
}

/// Loads a CSS/JS asset, preferring its `.min.*` version if it
/// exists — port of `_load_asset`.
pub fn load_asset(name: &str) -> &'static str {
    if let Some((base, ext)) = name.rsplit_once('.') {
        let min_name = format!("{base}.min.{ext}");
        if TEMPLATES.iter().any(|(n, _)| *n == min_name) {
            return load_template(&min_name);
        }
    }
    load_template(name)
}

/// Vendored Chart.js library — port of
/// `_load_template("chart.min.js", "vendor")`.
pub fn load_vendor_chart_js() -> &'static str {
    VENDOR_CHART_JS
}

/// Loads a binary asset (favicon/logo) by its file name.
pub fn load_asset_bytes(name: &str) -> Option<&'static [u8]> {
    ASSETS.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
}

/// Builds a `data:{mime};base64,...` data URI for an asset —
/// port of the core of `_load_logo`/the favicon fallback in `_generate_html`.
pub fn asset_data_uri(name: &str, mime: &str) -> Option<String> {
    let bytes = load_asset_bytes(name)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    Some(format!("data:{mime};base64,{b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_template_report_base_contains_placeholders() {
        let html = load_template("report-base.html");
        assert!(html.contains("{{"));
    }

    #[test]
    fn test_load_asset_prefers_min_version() {
        assert_eq!(load_asset("report.css"), load_template("report.min.css"));
        assert_eq!(load_asset("report.js"), load_template("report.min.js"));
        assert_eq!(load_asset("charts.js"), load_template("charts.min.js"));
    }

    /// Ticket #243: link targets land below the stuck table-of-contents
    /// bar. The report embeds the hand-kept `.min` copies: both versions
    /// of the stylesheet give the page its `scroll-padding-top`, and both
    /// scripts set the bar height it reads, whatever the bar's state.
    #[test]
    fn test_link_targets_offset_by_the_toc_bar_in_both_versions() {
        for css in ["report.css", "report.min.css"] {
            let text = load_template(css).replace(' ', "");
            assert!(
                text.contains("html{scroll-padding-top:var(--toc-offset,0px)"),
                "{css}"
            );
        }
        for js in ["report.js", "report.min.js"] {
            let text = load_template(js);
            assert!(text.contains("setProperty('--toc-offset'"), "{js}");
            assert!(
                !text.contains("scrollMarginTop"),
                "{js}: the former per-target margin"
            );
            assert!(!text.contains("applyScrollMargins(stuck)"), "{js}");
        }
    }

    /// `text` without its comments and without any whitespace outside its
    /// strings: what a hand-kept `.min` copy must keep of its source.
    /// `line_comments`: `//` starts a comment (JavaScript, not CSS).
    fn code_tokens(text: &str, line_comments: bool) -> String {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::new();
        let mut quote: Option<char> = None;
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if let Some(q) = quote {
                out.push(c);
                if c == '\\' && i + 1 < chars.len() {
                    out.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
                i += 1;
                continue;
            }
            let next = chars.get(i + 1).copied();
            if matches!(c, '\'' | '"' | '`') {
                quote = Some(c);
                out.push(c);
            } else if c == '/' && next == Some('*') {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i += 1;
            } else if line_comments && c == '/' && next == Some('/') {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            } else if !c.is_whitespace() {
                out.push(c);
            }
            i += 1;
        }
        out
    }

    /// The top-level rules of a stylesheet (a `@media` block is one rule),
    /// without comments and whitespace, the `;` before `}` dropped.
    fn css_rules(text: &str) -> Vec<String> {
        let flat = code_tokens(text, false).replace(";}", "}");
        let mut rules = Vec::new();
        let (mut depth, mut start) = (0usize, 0usize);
        for (i, c) in flat.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        rules.push(flat[start..=i].to_string());
                        start = i + 1;
                    }
                }
                _ => {}
            }
        }
        rules
    }

    /// The report embeds the `.min` copies, kept by hand (2026-11-24, after
    /// the language and phone work changed both): each script is its
    /// source without comments and whitespace, and the stylesheet has the
    /// same rules as its source. The stylesheet's rule order may differ:
    /// `report.min.css` has its own, the one the report shows.
    #[test]
    fn test_min_copies_carry_the_code_of_their_sources() {
        for (source, min) in [
            ("report.js", "report.min.js"),
            ("charts.js", "charts.min.js"),
        ] {
            assert_eq!(
                code_tokens(load_template(source), true),
                code_tokens(load_template(min), true),
                "{min} differs from {source}"
            );
        }
        let mut source = css_rules(load_template("report.css"));
        let mut min = css_rules(load_template("report.min.css"));
        source.sort();
        min.sort();
        assert_eq!(
            source, min,
            "report.min.css and report.css hold different rules"
        );
    }

    /// The phone layout (2026-11-24) is in the stylesheet the report
    /// embeds, after every other rule, so that it wins over them.
    #[test]
    fn test_phone_layout_closes_the_embedded_stylesheet() {
        let rules = css_rules(load_asset("report.css"));
        let last = rules.last().expect("rules");
        assert!(last.starts_with("@media(max-width:640px){"), "{last}");
        for rule in [
            ".container{padding:0.75rem}",
            ".health-charts-grid{grid-template-columns:minmax(0,1fr);gap:1rem}",
            ".finding-header{flex-wrap:wrap;",
            ".compliance-matrix,.fixtures-table{display:block;overflow-x:auto}",
        ] {
            assert!(last.contains(rule), "{rule} missing from the phone layout");
        }
    }

    #[test]
    #[should_panic(expected = "gabarit inconnu")]
    fn test_load_template_unknown_name_panics() {
        load_template("does-not-exist.html");
    }

    #[test]
    fn test_vendor_chart_js_not_empty() {
        assert!(load_vendor_chart_js().len() > 1000);
    }

    #[test]
    fn test_asset_data_uri_favicon() {
        let uri = asset_data_uri("favicon.svg", "image/svg+xml").expect("favicon.svg doit exister");
        assert!(uri.starts_with("data:image/svg+xml;base64,"));
    }

    #[test]
    fn test_asset_data_uri_unknown_returns_none() {
        assert!(asset_data_uri("does-not-exist.png", "image/png").is_none());
    }

    #[test]
    fn test_all_35_templates_present() {
        assert_eq!(TEMPLATES.len(), 35);
    }

    #[test]
    fn test_all_9_assets_present() {
        assert_eq!(ASSETS.len(), 9);
    }
}
