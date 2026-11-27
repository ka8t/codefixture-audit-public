//! Language check of the HTML report: a report written in one language
//! shows no text of another one.
//!
//! A report is rendered in each of the four languages with findings that
//! reach every part of the page (a data-flow path, a whole-file finding, a
//! dependency, a comparison with a baseline written in another language,
//! the trend, the audit parameters, a client rule). Its texts are read the
//! way a reader meets them: the text of the page and the attributes a
//! browser shows (`title`, `aria-label`, `alt`, `placeholder`, the glossary
//! tooltips, the section names of the navigation), plus the texts the
//! page's scripts write, which come from its two JSON blocks (the report
//! script's `#report-i18n` and the charts' `CHART_DATA.i18n`). Code and
//! file paths are the project's own and are left out, and so are the
//! passages the page marks with a `lang` of their own (the official
//! English names of the ISO 27001, ASVS and NIST CSF controls).
//!
//! A text fails the check when it holds:
//! - a sentence of another language's report locale that this language's
//!   locale does not have (compared fragment by fragment between the
//!   `{placeholders}`, so a sentence filled with numbers still matches);
//! - a word of a short list written only in French, or only in English,
//!   for the words the locales do not hold (texts written in a template or
//!   a script);
//! - a letter of another language: no accented letter at all in English,
//!   no French-only accent in Spanish and German, no Spanish or German
//!   letter in French.
//!
//! Added on 2026-11-24, after an English report showed its date as
//! `24/11/2026 à 09:47` and its keyboard help as `naviguer • début`.

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::{Value, json};

    use crate::i18n::load_report_locale;
    use crate::report::audit_params::{AuditParamsInfo, DependencyCheck};
    use crate::report::comparison::ComparisonResult;
    use crate::report::compliance_html::HealthThresholds;
    use crate::report::export_json::HistoryPoint;
    use crate::report::exports::sarif::{ReportFinding, TaintFlow, TaintStep};
    use crate::report::html::{ReportContext, generate_html};
    use crate::report::locale_format::parse_scan_timestamp;
    use crate::rules::identity::{RuleCatalog, RuleId};

    const LANGS: [&str; 4] = ["en", "fr", "es", "de"];

    /// Attributes a browser shows to the reader.
    const SHOWN_ATTRIBUTES: [&str; 6] = [
        "title",
        "aria-label",
        "alt",
        "placeholder",
        "data-tooltip",
        "data-nav-section",
    ];

    /// Words that only a French text holds, for the texts no locale has.
    const FRENCH_ONLY: [&str; 12] = [
        "naviguer",
        "début",
        "Retour en haut",
        "précédente",
        "suivante",
        "Généré",
        " à ",
        "suppression(s)",
        "imprimable",
        "Mode normal",
        "par source",
        "par règle",
    ];

    /// Words that only an English text holds, for the texts no locale has
    /// (the severity codes `CRITICAL`, `HIGH`… are identifiers shown in
    /// every language and are not words).
    /// `Fixtures` and the lowercase `baseline` are not listed: the French,
    /// Spanish and German locales use "Fixtures" as their own term, and the
    /// French text quotes the `--baseline` option.
    const ENGLISH_ONLY: [&str; 14] = [
        "Generated on",
        "Back to top",
        "Previous section",
        "Next section",
        "navigate",
        "Print version",
        "Normal view",
        "Findings",
        "Baseline",
        "Builtin",
        "Custom",
        "Flows",
        "finding",
        " High",
    ];

    /// Words the sweep of real reports (DVWA, juice-shop, Java, four
    /// languages, 2026-11-24) flagged although they belong to the text's
    /// own language, with why they are not in the lists above. Kept here
    /// so that nobody adds them back as "foreign" words.
    const NOT_FOREIGN: [(&str, &str); 6] = [
        (
            "des",
            "German article (\"Sicherheit des Quellcodes\"), not only French",
        ),
        ("la", "Spanish article (\"la referencia\"), not only French"),
        (
            "Tests",
            "a French and German word too (\"Tests unitaires\", \"Unit-Tests\")",
        ),
        ("version", "a French word too (\"règles de version\")"),
        (
            "source",
            "a folder name in the project's paths (`vulnerabilities/exec/source/`)",
        ),
        (
            "section",
            "the name of the `data-nav-section` attribute, not its text",
        ),
    ];

    /// Letters that a text of `lang` never holds.
    fn foreign_letters(lang: &str) -> &'static str {
        match lang {
            "en" => "àâçèéêëîïôûùüœæÿñáíóúäöß¿¡",
            "fr" => "ñáíóúäöß¿¡",
            // `é` and `ü` are Spanish too; `à`, `è` and the circumflexes
            // are not.
            "es" => "àâçèêëîïôûùœ",
            // German has no accent but its umlauts and `ß`.
            _ => "àâçèéêëîïôûùœñáíóú¿¡",
        }
    }

    /// Every string of a locale, in key order.
    fn locale_strings(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::String(s) => out.push(s.clone()),
            Value::Object(map) => map.values().for_each(|v| locale_strings(v, out)),
            Value::Array(items) => items.iter().for_each(|v| locale_strings(v, out)),
            _ => {}
        }
    }

    /// The fragments of a locale sentence between its placeholders that
    /// are a language's own words: at least two words and 8 characters (a
    /// lone word such as `Personnel` or `Description` is shared by
    /// several languages), not a format pattern (`%d/%m`).
    fn fragments(sentence: &str) -> Vec<String> {
        let placeholder = regex::Regex::new(r"\{[^}]*\}").expect("valid pattern");
        placeholder
            .split(sentence)
            .map(str::trim)
            .filter(|f| f.chars().count() >= 8 && f.contains(' ') && !f.contains('%'))
            .map(String::from)
            .collect()
    }

    /// The fragments of the locales of the other languages that the
    /// locale of `lang` does not hold anywhere.
    fn foreign_fragments(lang: &str) -> Vec<(String, String)> {
        let mut own = Vec::new();
        locale_strings(&load_report_locale(lang), &mut own);
        let own_text = own.join("\n");
        let mut foreign = Vec::new();
        for other in LANGS.iter().filter(|l| **l != lang) {
            let mut strings = Vec::new();
            locale_strings(&load_report_locale(other), &mut strings);
            for fragment in strings.iter().flat_map(|s| fragments(s)) {
                if !own_text.contains(&fragment) {
                    foreign.push((other.to_string(), fragment));
                }
            }
        }
        foreign
    }

    /// Decodes the character references the report writes.
    fn decode(text: &str) -> String {
        text.replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&nbsp;", "\u{a0}")
            .replace("&amp;", "&")
    }

    /// The `lang` attribute of an element's start tag, if any.
    fn element_lang(start_tag: tree_sitter::Node, html: &str) -> Option<String> {
        attributes(start_tag, html)
            .into_iter()
            .find(|(name, _)| name == "lang")
            .map(|(_, value)| value)
    }

    /// The (name, value) attributes of a start tag.
    fn attributes(start_tag: tree_sitter::Node, html: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut cursor = start_tag.walk();
        for attr in start_tag.children(&mut cursor) {
            if attr.kind() != "attribute" {
                continue;
            }
            let mut name = String::new();
            let mut value = String::new();
            let mut inner = attr.walk();
            for part in attr.children(&mut inner) {
                match part.kind() {
                    "attribute_name" => name = html[part.byte_range()].to_lowercase(),
                    "quoted_attribute_value" | "attribute_value" => {
                        value = html[part.byte_range()]
                            .trim_matches(|c| c == '"' || c == '\'')
                            .to_string();
                    }
                    _ => {}
                }
            }
            out.push((name, decode(&value)));
        }
        out
    }

    /// The texts of the page a reader meets (see the module doc), from
    /// the tree of `html`, skipping code, scripts, styles and passages
    /// whose `lang` is not `lang`. The scripts' JSON blocks are returned
    /// apart.
    fn page_texts(html: &str, lang: &str) -> Vec<String> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_html::LANGUAGE.into())
            .expect("HTML grammar");
        let tree = parser.parse(html, None).expect("parsed report");
        let mut texts = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "script_element" | "style_element" | "comment" | "doctype" => continue,
                "text" | "entity" => {
                    let text = decode(html[node.byte_range()].trim());
                    if !text.is_empty() {
                        texts.push(text);
                    }
                    continue;
                }
                "element" => {
                    if let Some(start) = node.child(0).filter(|c| c.kind() == "start_tag") {
                        let tag = start
                            .child(1)
                            .map(|t| html[t.byte_range()].to_lowercase())
                            .unwrap_or_default();
                        if tag == "code" || tag == "pre" {
                            continue;
                        }
                        if element_lang(start, html).is_some_and(|l| l != lang) {
                            continue;
                        }
                        for (name, value) in attributes(start, html) {
                            if SHOWN_ATTRIBUTES.contains(&name.as_str()) && !value.is_empty() {
                                texts.push(value);
                            }
                        }
                    }
                }
                "start_tag" | "self_closing_tag"
                    if node.parent().is_some_and(|p| p.kind() != "element") =>
                {
                    for (name, value) in attributes(node, html) {
                        if SHOWN_ATTRIBUTES.contains(&name.as_str()) && !value.is_empty() {
                            texts.push(value);
                        }
                    }
                }
                _ => {}
            }
            let mut cursor = node.walk();
            let children: Vec<_> = node.children(&mut cursor).collect();
            stack.extend(children.into_iter().rev());
        }
        texts
    }

    /// The texts the scripts write: every string of the `#report-i18n`
    /// block and of `CHART_DATA.i18n`, without the format codes the
    /// charts read (`locale`, `percentPattern`, `labelColon`).
    fn script_texts(html: &str) -> Vec<String> {
        let mut texts = Vec::new();
        let start = html
            .find(r#"<script id="report-i18n" type="application/json">"#)
            .expect("report-i18n block");
        let block = &html[start..];
        let body = &block
            [block.find('>').expect("tag end") + 1..block.find("</script>").expect("block end")];
        let report_i18n: Value = serde_json::from_str(body).expect("report-i18n JSON");
        locale_strings(&report_i18n, &mut texts);
        let data_at = html.find("const data = ").expect("chart data") + "const data = ".len();
        let chart_data: Value = serde_json::Deserializer::from_str(&html[data_at..])
            .into_iter::<Value>()
            .next()
            .expect("chart data JSON")
            .expect("chart data parsed");
        let mut i18n = chart_data["i18n"].clone();
        for key in ["locale", "percentPattern", "labelColon"] {
            i18n.as_object_mut().expect("i18n object").remove(key);
        }
        locale_strings(&i18n, &mut texts);
        // The trend labels are dates written by the report.
        locale_strings(&chart_data["history"]["labels"], &mut texts);
        texts
    }

    /// A rule of the catalog with its texts in the four languages.
    fn rule(key: &str, language: &str, severity: &str, client: bool) -> Value {
        let mut rule = json!({
            "id": key,
            "language": language,
            "category": "security",
            "severity": severity,
            "name": {
                "en": "Password written in the code",
                "fr": "Mot de passe écrit dans le code",
                "es": "Contraseña escrita en el código",
                "de": "Passwort im Quelltext",
            },
            "risk": {
                "en": "Anyone who reads the code can log in.",
                "fr": "Quiconque lit le code peut se connecter.",
                "es": "Cualquiera que lea el código puede entrar.",
                "de": "Wer den Code liest, kann sich anmelden.",
            },
            "solution": {
                "en": "Read the password from the environment.",
                "fr": "Lisez le mot de passe dans l'environnement.",
                "es": "Lea la contraseña del entorno.",
                "de": "Lesen Sie das Passwort aus der Umgebung.",
            },
            "benefit": {
                "en": "No password in the code.",
                "fr": "Aucun mot de passe dans le code.",
                "es": "Ninguna contraseña en el código.",
                "de": "Kein Passwort im Quelltext.",
            },
            "fix_before": "password = \"x\"",
            "fix_after": "password = os.environ[\"P\"]",
            "file_contains": {"has": ["password"], "not_has": ["environ"]},
        });
        if client {
            rule["origin"] = json!("client");
        }
        rule
    }

    /// A finding of `rule` written in `lang` (the scan writes the rule's
    /// texts in the report's language).
    fn finding(rule: &Value, lang: &str, severity: &str, file: &str) -> ReportFinding {
        let text = |key: &str| rule[key][lang].as_str().unwrap_or("").to_string();
        ReportFinding {
            rule_key: rule["id"].as_str().unwrap_or("").to_string(),
            rule_language: rule["language"].as_str().unwrap_or("").to_string(),
            rule_name: text("name"),
            category: "SECURITY".to_string(),
            severity: severity.to_string(),
            risk: text("risk"),
            file: file.to_string(),
            line: 12,
            solution: Some(text("solution")),
            cwe: vec!["CWE-798".to_string()],
            owasp: None,
            taint_flow: None,
            taint_flows: vec![],
            code: "password = \"hunter2\"".to_string(),
            context_before: "import os".to_string(),
            context_after: "connect(password)".to_string(),
            confidence: 90,
            benefit: text("benefit"),
            committer: None,
            rule_source: if rule.get("origin").is_some() {
                "json_custom".to_string()
            } else {
                "json_builtin".to_string()
            },
            file_scope: None,
        }
    }

    /// A data-flow finding: a value of the request reaches a query.
    fn taint_finding(rule: &Value, lang: &str) -> ReportFinding {
        let mut f = finding(rule, lang, "HIGH", "app/views.py");
        let step = |kind: &str, line: usize, code: &str| TaintStep {
            kind: kind.to_string(),
            file: "app/views.py".to_string(),
            line,
            code: code.to_string(),
        };
        f.taint_flow = Some(TaintFlow {
            rule_key: f.rule_key.clone(),
            source_file: "app/views.py".to_string(),
            source_line: 3,
            source_expr: "show(user_id)".to_string(),
            chain: vec![(5, "query".to_string(), "query = sql + user_id".to_string())],
            sink_file: "app/views.py".to_string(),
            sink_line: 6,
            sink_expr: "cursor.execute(query)".to_string(),
            source_kind: "http".to_string(),
            steps: vec![
                step("source", 3, "def show(user_id):"),
                step("propagation", 5, "query = sql + user_id"),
                step("sink", 6, "cursor.execute(query)"),
            ],
        });
        f
    }

    /// The report of `lang`, with every part filled: findings of each
    /// kind, a baseline written in another language, two past scans, the
    /// audit parameters and a client rule.
    fn report(lang: &str) -> String {
        let catalog_rule = rule("sql_injection_concat", "python", "HIGH", false);
        let other_rule = rule("hardcoded_password", "python", "CRITICAL", false);
        let client_rule = rule("house_secret", "python", "MEDIUM", true);
        let catalog: RuleCatalog = [&catalog_rule, &other_rule, &client_rule]
            .into_iter()
            .filter_map(|r| Some((RuleId::of(r)?, r.clone())))
            .collect();
        let mut whole_file = finding(&other_rule, lang, "CRITICAL", "app/settings.py");
        whole_file.file_scope = Some(crate::scan::engine::FileScope {
            line_count: 700,
            min_lines: Some(500),
        });
        let findings = vec![
            taint_finding(&catalog_rule, lang),
            finding(&catalog_rule, lang, "HIGH", "app/db.py"),
            whole_file,
            finding(&other_rule, lang, "CRITICAL", "node_modules/lib/x.js"),
            finding(&client_rule, lang, "MEDIUM", "app/keys.py"),
            finding(&client_rule, lang, "LOW", "app/low.py"),
        ];
        // The baseline was written by a scan in another language: its
        // resolved finding carries that language's rule name.
        let baseline_lang = if lang == "fr" { "de" } else { "fr" };
        let mut totals = BTreeMap::new();
        totals.insert("CRITICAL".to_string(), 3usize);
        let comparison = ComparisonResult {
            new_findings: vec![findings[0].clone()],
            resolved_findings: vec![finding(&other_rule, baseline_lang, "CRITICAL", "old.py")],
            unchanged_findings: vec![findings[1].clone()],
            baseline_date: "2026-11-23-15-47".to_string(),
            baseline_totals: totals,
        };
        let history = [
            HistoryPoint {
                timestamp: "2026-11-23-15-47".to_string(),
                totals: [("HIGH".to_string(), 4usize)].into_iter().collect(),
            },
            HistoryPoint {
                timestamp: "2026-11-24-09-47".to_string(),
                totals: [("HIGH".to_string(), 2usize)].into_iter().collect(),
            },
        ];
        let ctx = ReportContext {
            project_name: "shop".to_string(),
            project_version: String::new(),
            project_uuid: String::new(),
            project_description: String::new(),
            project_path: "/home/user/shop".to_string(),
            tool_name: "codefixture-audit".to_string(),
            tool_version: "3.0.0".to_string(),
            company_name: "CodeFixture".to_string(),
            report_lang: lang.to_string(),
            generated_at: parse_scan_timestamp("2026-11-24-09-47").expect("valid timestamp"),
            audit_total_time_secs: 1234,
            total_lines_code: 11126,
            total_files_scanned: 187,
            health_thresholds: HealthThresholds::default(),
            rule_catalog: &catalog,
            history: &history,
            custom_rule_duplicates: &[],
            priorities_html: String::new(),
            system_html: String::new(),
        };
        let params = AuditParamsInfo {
            languages: vec!["python".to_string()],
            include_paths: vec![],
            exclude_patterns: vec!["node_modules/".to_string()],
            quick_mode: false,
            only_category: None,
            disabled_rules: vec![],
            with_tests: false,
            with_deps: false,
            dependencies: DependencyCheck::Checked,
            database_configured: false,
            vulnerability_sources: vec![],
            severity_levels: None,
            report_lang: lang.to_string(),
        };
        generate_html(&findings, &ctx, Some(&comparison), Some(&params), None)
    }

    /// Whether `text` holds `word` as a whole word: `navigate` is not in
    /// `navigateurs`.
    fn contains_word(text: &str, word: &str) -> bool {
        text.match_indices(word).any(|(at, _)| {
            let before = text[..at].chars().next_back();
            let after = text[at + word.len()..].chars().next();
            let edge = |c: Option<char>, side: Option<char>| {
                // A word that starts or ends with a space or a sign is its
                // own boundary on that side.
                side.is_some_and(|s| !s.is_alphanumeric()) || !c.is_some_and(char::is_alphanumeric)
            };
            edge(before, word.chars().next()) && edge(after, word.chars().next_back())
        })
    }

    /// The texts of the report of `lang` that hold a text of another
    /// language, each with the reason.
    fn foreign_texts(lang: &str, html: &str) -> Vec<String> {
        let foreign = foreign_fragments(lang);
        let letters = foreign_letters(lang);
        let words: &[&str] = match lang {
            "en" => &FRENCH_ONLY,
            "fr" => &ENGLISH_ONLY,
            _ => &[],
        };
        let mut found = Vec::new();
        let mut texts = page_texts(html, lang);
        texts.extend(script_texts(html));
        for text in &texts {
            for (other, fragment) in &foreign {
                if text.contains(fragment.as_str()) {
                    found.push(format!("{other} sentence {fragment:?} in {text:?}"));
                }
            }
            let mut list: Vec<&str> = words.to_vec();
            if lang == "es" || lang == "de" {
                list.extend(FRENCH_ONLY);
                list.extend(ENGLISH_ONLY);
            }
            for word in list {
                if contains_word(text, word) {
                    found.push(format!("word {word:?} in {text:?}"));
                }
            }
            if let Some(c) = text.chars().find(|c| letters.contains(*c)) {
                found.push(format!("letter {c:?} in {text:?}"));
            }
        }
        found
    }

    /// The report written in each language holds no text of another one,
    /// in its page or in the texts its scripts write.
    #[test]
    fn test_report_shows_no_text_of_another_language() {
        for lang in LANGS {
            let html = report(lang);
            let found = foreign_texts(lang, &html);
            assert!(found.is_empty(), "{lang} report:\n{}", found.join("\n"));
        }
    }

    /// The check itself finds what it is meant to find: the date and the
    /// keyboard help of the English report of 2026-11-24, a French rule
    /// name, a Spanish word in a French report, an English chart label.
    #[test]
    fn test_language_check_finds_a_foreign_text() {
        let wrap = |body: &str| {
            format!(
                r#"<html><body>{body}<script id="report-i18n" type="application/json">{{"printVersion":"Print version"}}</script><script>const data = {{"i18n":{{"locale":"en","total":"Total"}},"history":{{"labels":[]}}}};</script></body></html>"#
            )
        };
        let en = wrap(
            r#"<div class="meta">Generated on 24/11/2026 à 09:47</div><div><kbd>j</kbd> naviguer</div>"#,
        );
        let found = foreign_texts("en", &en);
        assert!(found.iter().any(|f| f.contains("à 09:47")), "{found:#?}");
        assert!(found.iter().any(|f| f.contains("naviguer")), "{found:#?}");
        let fr = wrap(r#"<p title="Contraseña escrita en el código">x</p><p>Print version</p>"#)
            .replace("Print version", "Version imprimable");
        let found = foreign_texts(
            "fr",
            &fr.replace("<p>Version imprimable</p>", "<p>Findings</p>"),
        );
        assert!(found.iter().any(|f| f.contains("letter 'ñ'")), "{found:#?}");
        assert!(found.iter().any(|f| f.contains("Findings")), "{found:#?}");
        // Code and a passage marked as English are not the report's text.
        let quoted = wrap(r#"<code>naviguer</code><td lang="en">Use of cryptography</td>"#)
            .replace("Print version", "Version imprimable");
        assert!(foreign_texts("fr", &quoted).is_empty());
        // A text of the charts is checked like the page.
        let chart = wrap("").replace(r#""total":"Total""#, r#""total":"Flows par règle""#);
        assert!(!foreign_texts("en", &chart).is_empty());
    }

    /// The words of [`NOT_FOREIGN`] are in no list of foreign words, and a
    /// report text holding them in their own language passes the check.
    #[test]
    fn test_words_shared_by_languages_are_not_foreign() {
        for (word, reason) in NOT_FOREIGN {
            assert!(
                !FRENCH_ONLY.contains(&word) && !ENGLISH_ONLY.contains(&word),
                "{word}: {reason}"
            );
        }
        let page = |body: &str| {
            format!(
                r#"<html><body>{body}<script id="report-i18n" type="application/json">{{}}</script><script>const data = {{"i18n":{{}},"history":{{"labels":[]}}}};</script></body></html>"#
            )
        };
        let de = page("<p>Die Sicherheit des Quellcodes</p><p>🧪 Unit-Tests</p>");
        assert!(
            foreign_texts("de", &de).is_empty(),
            "{:?}",
            foreign_texts("de", &de)
        );
        let es = page("<p>Comparación con la referencia</p>");
        assert!(foreign_texts("es", &es).is_empty());
        let fr = page("<p>Règles de version du pack</p><p>Tests unitaires</p>");
        assert!(foreign_texts("fr", &fr).is_empty());
    }

    /// Every chart label is filled from the locale in every language: the
    /// charts no longer carry an English fallback of their own.
    #[test]
    fn test_every_chart_label_comes_from_the_locale() {
        let used = regex::Regex::new(r"i18n\.([A-Za-z_]+)").expect("valid pattern");
        let charts = crate::report::report_assets::load_asset("charts.js");
        for lang in LANGS {
            let html = report(lang);
            let data_at = html.find("const data = ").expect("chart data") + "const data = ".len();
            let chart_data: Value = serde_json::Deserializer::from_str(&html[data_at..])
                .into_iter::<Value>()
                .next()
                .expect("chart data JSON")
                .expect("chart data parsed");
            let i18n = chart_data["i18n"].as_object().expect("i18n");
            // Every `i18n.<key>` the charts read exists, not empty and not
            // a locale key left untranslated.
            for key in used.captures_iter(charts).map(|c| c[1].to_string()) {
                let value = i18n.get(&key).and_then(Value::as_str).unwrap_or("");
                assert!(
                    !value.is_empty() && !value.contains("chart_labels.") && !value.contains('_'),
                    "{lang}: i18n.{key} = {value:?}"
                );
            }
        }
    }

    /// The header and the title give the date the way each language
    /// writes it, and the numbers with its separators.
    #[test]
    fn test_report_dates_and_numbers_per_language() {
        let expected = [
            ("en", "November 24, 2026 at 9:47 AM", "11,126", "1,234"),
            ("fr", "24/11/2026 à 09:47", "11\u{202f}126", "1\u{202f}234"),
            ("es", "24/11/2026 a las 09:47", "11.126", "1234"),
            ("de", "24.11.2026 um 09:47", "11.126", "1.234"),
        ];
        for (lang, date, lines, seconds) in expected {
            let html = report(lang);
            assert!(html.contains(&format!("{date} ")), "{lang}: header date");
            assert!(
                html.contains(&format!("- {date}</title>")),
                "{lang}: title date"
            );
            assert!(
                html.contains(&format!("📝 {lines} ")),
                "{lang}: lines of code"
            );
            assert!(html.contains(&format!("⏱️ {seconds}s")), "{lang}: duration");
        }
    }
}
