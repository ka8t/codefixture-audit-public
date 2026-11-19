//! Parser for the `.sca` DSL.
//!
//! Faithful port of `Audit/sca/dsl/` (lexer.py, parser.py, validator.py,
//! compiler.py) — no Pest grammar: the DSL is intrinsically
//! line-oriented and context-sensitive (the same line tokenizes
//! differently depending on whether we're inside a `fix_before`/`fix_after`
//! block or not, and regex/AST patterns use raw text rather than
//! tokens to preserve quotes/backslashes) — a hand-written lexer +
//! recursive-descent parser, identical to the already proven
//! Python implementation, is more reliable than a
//! PEG grammar forced onto a format that never had one.
#![allow(dead_code)]

pub mod compiler;
pub mod lexer;
pub mod model;
pub mod validator;

use lexer::{DslLexer, DslSyntaxError, Line};
use model::*;
use std::collections::HashSet;

/// Translated text blocks of a rule (`en:`/`fr:`/`es:`/`de:` lines).
/// `name` is the rule's display name: the rule file is its only source
/// since 2026-11-14 (the report locales held a second, name-keyed copy).
const I18N_KEYWORDS: &[&str] = &["name", "message", "risk", "solution", "benefit"];
const PLAINTEXT_KEYWORDS: &[&str] = &["fix_before", "fix_after"];

pub struct DslParser<'a> {
    lines: Vec<Line>,
    filename: &'a str,
    pos: usize,
}

type PResult<T> = Result<T, DslSyntaxError>;

impl<'a> DslParser<'a> {
    pub fn new(lines: Vec<Line>, filename: &'a str) -> Self {
        DslParser {
            lines,
            filename,
            pos: 0,
        }
    }

    pub fn parse(&mut self) -> PResult<Vec<RuleNode>> {
        let mut rules = Vec::new();
        while self.pos < self.lines.len() {
            let kw = self.keyword();
            if kw == "rule" {
                rules.push(self.parse_rule()?);
            } else {
                return Err(self.err(&format!("Mot-clé 'rule' attendu, trouvé : '{kw}'")));
            }
        }
        Ok(rules)
    }

    // --- Utilities ---

    fn keyword(&self) -> String {
        self.lines[self.pos].tokens[0].value.clone()
    }

    fn line(&self) -> &Line {
        &self.lines[self.pos]
    }

    fn advance(&mut self) {
        self.pos += 1;
    }

    fn at_end(&self) -> bool {
        self.pos >= self.lines.len()
    }

    fn err(&self, msg: &str) -> DslSyntaxError {
        let num = self.lines.get(self.pos).map(|l| l.number).unwrap_or(0);
        DslSyntaxError::new(msg, num, self.filename)
    }

    /// Reads all the text after the keyword (via the tokens) and advances.
    /// For structured values (language, category, severity,
    /// scope, i18n text). For raw content (regex, patterns),
    /// see `parse_raw_after_keyword`.
    fn parse_value(&mut self) -> PResult<String> {
        let line = self.line();
        let tokens = &line.tokens[1..];
        if tokens.is_empty() {
            let kw = line.tokens[0].value.clone();
            return Err(self.err(&format!("Valeur manquante après '{kw}'")));
        }
        let result = tokens
            .iter()
            .map(|t| t.value.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        self.advance();
        Ok(result)
    }

    /// Extracts the raw text after the keyword from `raw_content` —
    /// preserves quotes, backslashes and special characters as-is
    /// (regex, AST patterns, source/sink).
    fn parse_raw_after_keyword(&mut self) -> PResult<String> {
        let line = self.line();
        let raw = line.raw_content.clone();
        let kw = line.tokens[0].value.clone();
        let line_number = line.number;
        let rest = match raw.find(kw.as_str()) {
            Some(idx) => raw[idx + kw.len()..].trim().to_string(),
            None => raw.trim().to_string(),
        };
        self.advance();
        if rest.is_empty() {
            return Err(DslSyntaxError::new(
                format!("Valeur manquante après '{kw}'"),
                line_number,
                self.filename,
            ));
        }
        Ok(rest)
    }

    /// Extracts the raw text plus key=value pairs from
    /// `raw_content` (source/sink: the text is the regex pattern, the
    /// key=value pairs are options — kind=http, arg_index=0).
    fn parse_raw_with_kvs(&mut self) -> (String, std::collections::HashMap<String, String>) {
        let line = self.line();
        let raw = &line.raw_content;
        let kw = &line.tokens[0].value;
        let rest = match raw.find(kw.as_str()) {
            Some(idx) => raw[idx + kw.len()..].trim().to_string(),
            None => raw.trim().to_string(),
        };

        let mut kvs = std::collections::HashMap::new();
        let mut text_parts = Vec::new();
        for part in rest.split_whitespace() {
            if let Some(eq) = part.find('=') {
                let (k, v) = (&part[..eq], &part[eq + 1..]);
                if !k.is_empty()
                    && !v.is_empty()
                    && k.chars()
                        .next()
                        .is_some_and(|c| c == '_' || c.is_ascii_lowercase())
                    && k.chars()
                        .all(|c| c == '_' || c.is_ascii_lowercase() || c.is_ascii_digit())
                {
                    kvs.insert(k.to_string(), v.to_string());
                    continue;
                }
            }
            text_parts.push(part);
        }

        self.advance();
        (text_parts.join(" "), kvs)
    }

    // --- Parsing a rule ---

    fn parse_rule(&mut self) -> PResult<RuleNode> {
        let line = self.line();
        let tokens = &line.tokens;
        if tokens.len() < 2 {
            return Err(self.err("Identifiant de règle manquant après 'rule'"));
        }
        let rule_id = tokens[1].value.clone();
        let line_number = line.number;
        let mut node = RuleNode::new(rule_id, line_number);
        self.advance();

        while !self.at_end() {
            let kw = self.keyword();

            match kw.as_str() {
                "end" => {
                    self.advance();
                    return Ok(node);
                }
                "language" => node.language = self.parse_value()?,
                "category" => node.category = self.parse_value()?,
                "severity" => node.severity = self.parse_value()?,
                "confidence" => {
                    let val = self.parse_value()?;
                    node.confidence = val
                        .parse()
                        .map_err(|_| self.err("'confidence' doit être un entier"))?;
                }
                "mode" => node.mode = self.parse_value()?,
                "match" => node.match_blocks.push(self.parse_match_block()?),
                "source" => node.sources.push(self.parse_source()),
                "sink" => node.sinks.push(self.parse_sink()?),
                "sanitizer" => node.sanitizers.push(self.parse_sanitizer()?),
                "passthrough" => node.passthroughs.push(self.parse_passthrough()?),
                _ if I18N_KEYWORDS.contains(&kw.as_str()) => {
                    let block = self.parse_i18n_block()?;
                    match kw.as_str() {
                        "name" => node.name = block,
                        "message" => node.message = block,
                        "risk" => node.risk = block,
                        "solution" => node.solution = block,
                        "benefit" => node.benefit = block,
                        _ => unreachable!(),
                    }
                }
                _ if PLAINTEXT_KEYWORDS.contains(&kw.as_str()) => {
                    let text = self.parse_plaintext_block()?;
                    match kw.as_str() {
                        "fix_before" => node.fix_before = text,
                        "fix_after" => node.fix_after = text,
                        _ => unreachable!(),
                    }
                }
                "metadata" => node.metadata = self.parse_metadata_block()?,
                "requires" => match self.parse_requires_block_unified()? {
                    RequiresResult::License(lic) => node.license = lic,
                    RequiresResult::FileCondition(fc) => node.file_conditions.push(fc),
                },
                "hook" => node.hook = self.parse_value()?,
                _ => return Err(self.err(&format!("Mot-clé inconnu dans une règle : '{kw}'"))),
            }
        }

        Err(self.err("Bloc 'rule' non fermé (manque 'end')"))
    }

    // --- Match blocks ---

    fn parse_match_block(&mut self) -> PResult<MatchBlock> {
        let line = self.line();
        let tokens = &line.tokens;
        let ln = line.number;

        if tokens.len() >= 2 {
            let match_type = tokens[1].value.clone();
            self.advance();
            match match_type.as_str() {
                "regex" => Ok(MatchBlock::Regex(self.parse_match_regex(ln)?)),
                "ast" => Ok(MatchBlock::Ast(self.parse_match_ast(ln)?)),
                "file_contains" => Ok(MatchBlock::FileContains(
                    self.parse_match_file_contains(ln)?,
                )),
                other => Err(DslSyntaxError::new(
                    format!("Type de match inconnu : '{other}'"),
                    ln,
                    self.filename,
                )),
            }
        } else {
            self.advance();
            Ok(MatchBlock::Regex(self.parse_match_regex(ln)?))
        }
    }

    /// Parses the keywords of a regex `match` block up to its `end`.
    ///
    /// Deliberate deviation from Python (ticket #226): a keyword given
    /// twice in one block used to replace the first value without a word.
    /// `path_traversal_os_join` listed three `text-not` and only the last
    /// one applied. Now:
    /// - several `pattern-not`/`text-not` lines are all kept: a line is
    ///   left out as soon as one of them matches (`combine_negatives`);
    /// - any other keyword given twice (`pattern`/`text`, `with`/
    ///   `with-text`, `scope`, `pattern-inside`, `pattern-not-inside`) is
    ///   a syntax error naming it, since two values of one slot have no
    ///   single meaning.
    fn parse_match_regex(&mut self, start_line: usize) -> PResult<MatchRegexBlock> {
        let mut block = MatchRegexBlock::new(start_line);
        // Slots already given in this block; `pattern`/`text` share one,
        // like `with`/`with-text`.
        let mut seen: HashSet<&'static str> = HashSet::new();
        while !self.at_end() {
            let kw = self.keyword();
            let slot = match kw.as_str() {
                "pattern" | "text" => Some("pattern"),
                "with" | "with-text" => Some("with"),
                "scope" => Some("scope"),
                "pattern-inside" => Some("pattern-inside"),
                "pattern-not-inside" => Some("pattern-not-inside"),
                _ => None,
            };
            if let Some(slot) = slot
                && !seen.insert(slot)
            {
                return Err(self.err(&format!(
                    "« {kw} » est donné deux fois dans le même bloc 'match' : la seconde valeur remplacerait la première. Écrivez un seul « {slot} » par bloc, ou un bloc 'match' par motif."
                )));
            }
            if matches!(kw.as_str(), "pattern-not" | "text-not") {
                let is_text = kw == "text-not";
                let value = self.parse_raw_after_keyword()?;
                combine_negatives(&mut block, value, is_text);
                continue;
            }
            match kw.as_str() {
                "end" => {
                    self.advance();
                    return Ok(block);
                }
                "pattern" => {
                    block.pattern = self.parse_raw_after_keyword()?;
                    block.is_text = false;
                }
                "text" => {
                    block.pattern = self.parse_raw_after_keyword()?;
                    block.is_text = true;
                }
                "scope" => block.scope = self.parse_value()?,
                "with" => {
                    block.with_pattern = self.parse_raw_after_keyword()?;
                    block.with_is_text = false;
                }
                "with-text" => {
                    block.with_pattern = self.parse_raw_after_keyword()?;
                    block.with_is_text = true;
                }
                "pattern-inside" => block.pattern_inside = self.parse_raw_after_keyword()?,
                "pattern-not-inside" => {
                    block.pattern_not_inside = self.parse_raw_after_keyword()?
                }
                _ => return Err(self.err(&format!("Mot-cle inconnu dans match : '{kw}'"))),
            }
        }
        Err(self.err("Bloc 'match' non ferme (manque 'end')"))
    }

    fn parse_match_ast(&mut self, start_line: usize) -> PResult<MatchAstBlock> {
        let mut block = MatchAstBlock {
            pattern: String::new(),
            line_number: start_line,
        };
        let mut pattern_parts: Vec<String> = Vec::new();
        let mut in_pattern = false;

        while !self.at_end() {
            let line = self.line().clone();
            let kw = line.tokens[0].value.clone();

            if kw == "end" && !in_pattern {
                if !pattern_parts.is_empty() {
                    block.pattern = pattern_parts.join(" ").trim().to_string();
                }
                self.advance();
                return Ok(block);
            }

            if kw == "end" && in_pattern {
                let joined = pattern_parts.join(" ");
                if count_char(&joined, '(') <= count_char(&joined, ')') {
                    block.pattern = joined.trim().to_string();
                    self.advance();
                    return Ok(block);
                }
                pattern_parts.push(line.raw_content.trim().to_string());
                self.advance();
                continue;
            }

            if kw == "pattern" && !in_pattern {
                let raw = &line.raw_content;
                let rest = match raw.find("pattern") {
                    Some(idx) => raw[idx + "pattern".len()..].trim().to_string(),
                    None => String::new(),
                };
                if !rest.is_empty() {
                    pattern_parts.push(rest);
                }
                in_pattern = true;
                self.advance();
                let joined = pattern_parts.join(" ");
                if !joined.is_empty() && count_char(&joined, '(') <= count_char(&joined, ')') {
                    block.pattern = joined.trim().to_string();
                    in_pattern = false;
                }
            } else if in_pattern {
                pattern_parts.push(line.raw_content.trim().to_string());
                self.advance();
                let joined = pattern_parts.join(" ");
                if count_char(&joined, '(') <= count_char(&joined, ')') {
                    block.pattern = joined.trim().to_string();
                    in_pattern = false;
                }
            } else {
                return Err(self.err(&format!(
                    "Mot-clé 'pattern' attendu dans match ast, trouvé : '{kw}'"
                )));
            }
        }

        Err(self.err("Bloc 'match ast' non fermé (manque 'end')"))
    }

    fn parse_match_file_contains(&mut self, start_line: usize) -> PResult<MatchFileContainsBlock> {
        let mut block = MatchFileContainsBlock::new(start_line);
        while !self.at_end() {
            let kw = self.keyword();
            match kw.as_str() {
                "end" => {
                    self.advance();
                    return Ok(block);
                }
                "has" => block.has_patterns.push(self.parse_raw_after_keyword()?),
                "not_has" => block.not_has_patterns.push(self.parse_raw_after_keyword()?),
                "scope" => block.scope = self.parse_value()?,
                _ => {
                    return Err(self.err(&format!(
                        "Mot-clé inconnu dans match file_contains : '{kw}'"
                    )));
                }
            }
        }
        Err(self.err("Bloc 'match file_contains' non fermé (manque 'end')"))
    }

    // --- Taint elements ---

    fn parse_source(&mut self) -> SourceSpec {
        let ln = self.line().number;
        let (text, kvs) = self.parse_raw_with_kvs();
        SourceSpec {
            pattern: text,
            kind: kvs
                .get("kind")
                .cloned()
                .unwrap_or_else(|| "http".to_string()),
            line_number: ln,
        }
    }

    /// Parses a `sink` line: the regular expression, then its only option,
    /// `arg_index=<n>`. An unknown option or an index that is not a
    /// non-negative integer is an error naming the line: before ticket
    /// #221 both were dropped silently, an index read as 0, which made a
    /// typo in the option indistinguishable from its absence.
    fn parse_sink(&mut self) -> PResult<SinkSpec> {
        let ln = self.line().number;
        let (text, kvs) = self.parse_raw_with_kvs();
        let mut arg_index = None;
        let mut keys: Vec<&String> = kvs.keys().collect();
        keys.sort();
        for key in keys {
            let value = &kvs[key];
            if key != "arg_index" {
                return Err(DslSyntaxError::new(
                    format!(
                        "Option inconnue sur un sink : '{key}={value}' (seule 'arg_index' existe)"
                    ),
                    ln,
                    self.filename,
                ));
            }
            arg_index = Some(value.parse::<usize>().map_err(|_| {
                DslSyntaxError::new(
                    format!("'arg_index' doit être un entier positif ou nul, trouvé : '{value}'"),
                    ln,
                    self.filename,
                )
            })?);
        }
        Ok(SinkSpec {
            pattern: text,
            arg_index,
            line_number: ln,
        })
    }

    fn parse_sanitizer(&mut self) -> PResult<SanitizerSpec> {
        let ln = self.line().number;
        let text = self.parse_raw_after_keyword()?;
        Ok(SanitizerSpec {
            pattern: text,
            line_number: ln,
        })
    }

    fn parse_passthrough(&mut self) -> PResult<PassthroughSpec> {
        let ln = self.line().number;
        let text = self.parse_raw_after_keyword()?;
        Ok(PassthroughSpec {
            pattern: text,
            line_number: ln,
        })
    }

    // --- Structured blocks ---

    fn parse_i18n_block(&mut self) -> PResult<I18nBlock> {
        let ln = self.line().number;
        self.advance();
        let mut block = I18nBlock {
            line_number: ln,
            ..Default::default()
        };

        while !self.at_end() {
            let kw = self.keyword();
            if kw == "end" {
                self.advance();
                return Ok(block);
            }
            let tokens = self.line().tokens.clone();
            let lang_code = tokens[0].value.trim_end_matches(':').to_string();
            if tokens.len() < 2 {
                return Err(self.err(&format!(
                    "Texte manquant après le code langue '{lang_code}'"
                )));
            }
            // The text as written after `<lang>:`, from the full line.
            // Deliberate deviation from `parser.py::_parse_i18n_block`,
            // which joins the lexer's tokens: the lexer strips quotes and
            // merges spaces, so `str_replace(["\r", "\n"], '', $x)` reached
            // the report as `str_replace(["\r", \n ],  , $x)` (2026-11-14;
            // 1,948 text lines of the catalog hold quotes), and cuts at a
            // `#` (`Line::full_content`).
            // A text written as one quoted string (`en: "N+1 query"`) keeps
            // the Python reading: the quotes delimit it.
            let raw = &self.line().full_content;
            let quoted = tokens.len() == 2 && tokens[1].kind == lexer::TokenType::String;
            let text = match raw.strip_prefix(tokens[0].value.as_str()) {
                Some(rest) if !quoted => rest.trim().to_string(),
                _ => tokens[1..]
                    .iter()
                    .map(|t| t.value.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
            };
            block.texts.insert(lang_code, text);
            self.advance();
        }

        Err(self.err("Bloc i18n non fermé (manque 'end')"))
    }

    /// Raw text block (fix_before/fix_after)...end. Uses
    /// `raw_content` (like the patterns/AST blocks) rather than
    /// rebuilding the line from tokens — dedented relative to
    /// the least-indented line of the block, with the absolute indentation
    /// tied to the `.sca` structure itself removed (cf. Python docstring).
    fn parse_plaintext_block(&mut self) -> PResult<String> {
        self.advance();
        let mut raw_lines: Vec<(usize, String)> = Vec::new();
        while !self.at_end() {
            let kw = self.keyword();
            if kw == "end" {
                self.advance();
                if raw_lines.is_empty() {
                    return Ok(String::new());
                }
                let base = raw_lines.iter().map(|(indent, _)| *indent).min().unwrap();
                return Ok(raw_lines
                    .iter()
                    .map(|(indent, content)| format!("{}{}", " ".repeat(indent - base), content))
                    .collect::<Vec<_>>()
                    .join("\n"));
            }
            let line = self.line();
            raw_lines.push((line.indent, line.raw_content.clone()));
            self.advance();
        }
        Err(self.err("Bloc texte non fermé (manque 'end')"))
    }

    fn parse_metadata_block(&mut self) -> PResult<MetadataBlock> {
        let ln = self.line().number;
        self.advance();
        let mut block = MetadataBlock {
            line_number: ln,
            ..Default::default()
        };

        while !self.at_end() {
            let kw = self.keyword();
            match kw.as_str() {
                "end" => {
                    self.advance();
                    return Ok(block);
                }
                "cwe" => {
                    let vals = self.rest_of_line_values();
                    block.cwe.extend(vals);
                    self.advance();
                }
                "cve" => {
                    let vals = self.rest_of_line_values();
                    block.cve.extend(vals);
                    self.advance();
                }
                "owasp" => block.owasp = self.parse_value()?,
                "iso27001" => {
                    block.iso27001 = self.rest_of_line_values();
                    self.advance();
                }
                "asvs" => {
                    block.asvs = self.rest_of_line_values();
                    self.advance();
                }
                "wcag" => {
                    let vals = self.rest_of_line_values();
                    block.wcag.extend(vals);
                    self.advance();
                }
                "generated_by" => block.generated_by = self.parse_value()?,
                "generated_at" => block.generated_at = self.parse_value()?,
                "auditai_version" => block.auditai_version = self.parse_value()?,
                "manifest_hash" => block.manifest_hash = self.parse_value()?,
                "org_id" => block.org_id = self.parse_value()?,
                "signature" => block.signature = self.parse_value()?,
                _ => return Err(self.err(&format!("Clé metadata inconnue : '{kw}'"))),
            }
        }

        Err(self.err("Bloc 'metadata' non fermé (manque 'end')"))
    }

    fn rest_of_line_values(&self) -> Vec<String> {
        self.line().tokens[1..]
            .iter()
            .map(|t| t.value.clone())
            .collect()
    }

    fn parse_requires_block(&mut self) -> PResult<LicenseBlock> {
        let ln = self.line().number;
        self.advance();
        let mut block = LicenseBlock {
            line_number: ln,
            ..Default::default()
        };

        while !self.at_end() {
            let kw = self.keyword();
            match kw.as_str() {
                "end" => {
                    self.advance();
                    return Ok(block);
                }
                "min_tier" => block.min_tier = self.parse_value()?,
                "features" => {
                    block.features = self.rest_of_line_values();
                    self.advance();
                }
                "demo_fallback" => {
                    let val = self.parse_value()?;
                    block.demo_fallback = val.trim().to_lowercase() == "true";
                }
                _ => return Err(self.err(&format!("Clé requires inconnue : '{kw}'"))),
            }
        }

        Err(self.err("Bloc 'requires' non fermé (manque 'end')"))
    }

    /// Automatically detects the `requires` block type: license
    /// (min_tier/features) or file (has/not_has), by pre-scanning
    /// the keywords without consuming the lines.
    fn parse_requires_block_unified(&mut self) -> PResult<RequiresResult> {
        let saved_pos = self.pos;
        self.advance();

        let mut keys_found: HashSet<String> = HashSet::new();
        let mut scan_pos = self.pos;
        while scan_pos < self.lines.len() {
            let scan_line = &self.lines[scan_pos];
            if !scan_line.tokens.is_empty() && scan_line.tokens[0].value == "end" {
                break;
            }
            if !scan_line.tokens.is_empty() {
                keys_found.insert(scan_line.tokens[0].value.clone());
            }
            scan_pos += 1;
        }

        self.pos = saved_pos;

        let file_keys = [
            "has",
            "not_has",
            "scope",
            "min_lines",
            "path_contains",
            "not_path_contains",
            "not_path_has_file",
        ];
        if file_keys.iter().any(|k| keys_found.contains(*k)) {
            Ok(RequiresResult::FileCondition(
                self.parse_file_condition_block()?,
            ))
        } else {
            // Block with explicit license keys (min_tier/features/
            // demo_fallback), or empty/unknown block → default license
            // (backward compat, cf. parser.py).
            Ok(RequiresResult::License(self.parse_requires_block()?))
        }
    }

    fn parse_file_condition_block(&mut self) -> PResult<FileConditionBlock> {
        let ln = self.line().number;
        self.advance();
        let mut block = FileConditionBlock::new(ln);

        while !self.at_end() {
            let line = self.line().clone();
            let kw = line.tokens[0].value.clone();

            match kw.as_str() {
                "end" => {
                    self.advance();
                    return Ok(block);
                }
                "has" => {
                    block
                        .has_patterns
                        .push(rest_after_first_word(&line.raw_content));
                    self.advance();
                }
                "not_has" => {
                    block
                        .not_has_patterns
                        .push(rest_after_first_word(&line.raw_content));
                    self.advance();
                }
                "scope" => block.scope = self.parse_value()?,
                "min_lines" => {
                    let val = rest_after_first_word(&line.raw_content);
                    block.min_lines = if val.is_empty() {
                        0
                    } else {
                        val.parse().unwrap_or(0)
                    };
                    self.advance();
                }
                "path_contains" => {
                    block
                        .path_contains
                        .push(rest_after_first_word(&line.raw_content));
                    self.advance();
                }
                // Deliberate addition to the Python DSL (ticket #229): the
                // reverse of `path_contains`, so that rules can share out
                // one kind of file by its path (a CI workflow, a local
                // configuration, any other configuration) with no file
                // falling between them or under two of them.
                "not_path_contains" => {
                    block
                        .not_path_contains
                        .push(rest_after_first_word(&line.raw_content));
                    self.advance();
                }
                "not_path_has_file" => {
                    block
                        .not_path_has_file
                        .push(rest_after_first_word(&line.raw_content));
                    self.advance();
                }
                _ => return Err(self.err(&format!("Clé requires fichier inconnue : '{kw}'"))),
            }
        }

        Err(self.err("Bloc 'requires' fichier non fermé (manque 'end')"))
    }
}

enum RequiresResult {
    License(LicenseBlock),
    FileCondition(FileConditionBlock),
}

fn rest_after_first_word(raw: &str) -> String {
    let raw = raw.trim();
    match raw.split_once(char::is_whitespace) {
        Some((_, rest)) => rest.trim_start().to_string(),
        None => String::new(),
    }
}

fn count_char(s: &str, c: char) -> usize {
    s.chars().filter(|&ch| ch == c).count()
}

/// Adds one `pattern-not` (`is_text == false`) or `text-not` value to the
/// block's negative pattern (ticket #226). The first value is stored as
/// written, so a block with a single negative compiles exactly as before.
/// A further value turns both into regexes and joins them as alternatives,
/// `(?:first)|(?:second)`: a line is left out as soon as one of them
/// matches. Each side keeps its inline flags, since `(?i)` set inside a
/// group stops at the end of that group.
fn combine_negatives(block: &mut MatchRegexBlock, value: String, is_text: bool) {
    if block.pattern_not.is_empty() {
        block.pattern_not = value;
        block.pattern_not_is_text = is_text;
        return;
    }
    let as_regex = |v: &str, text: bool| {
        if text {
            compiler::text_to_regex(v)
        } else {
            v.to_string()
        }
    };
    let first = as_regex(&block.pattern_not, block.pattern_not_is_text);
    let second = as_regex(&value, is_text);
    block.pattern_not = format!("(?:{first})|(?:{second})");
    block.pattern_not_is_text = false;
}

// --- High-level entry point (mirrors sca/dsl/__init__.py) ---

pub fn parse_sca_file(source: &str, filename: &str) -> PResult<Vec<RuleNode>> {
    let lexer = DslLexer::new(source, filename);
    let lines = lexer.tokenize();
    if lines.is_empty() {
        return Ok(Vec::new());
    }
    let mut parser = DslParser::new(lines, filename);
    parser.parse()
}

/// Parses, validates and compiles a `.sca` file into a list of JSON
/// values compatible with `rule_loader.py` — mirrors
/// `sca.dsl.compile_sca_to_json`.
pub fn compile_sca_to_json(source: &str, filename: &str) -> PResult<Vec<serde_json::Value>> {
    let rules = parse_sca_file(source, filename)?;
    let mut results = Vec::new();
    for rule in rules {
        let errors = validator::validate_rule(&rule);
        if !errors.is_empty() {
            return Err(DslSyntaxError::new(
                format!("Règle '{}' invalide : {}", rule.id, errors.join("; ")),
                rule.line_number,
                filename,
            ));
        }
        results.push(compiler::compile_to_json(&rule));
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE_WITH_NAME: &str = "rule base64_eval\n  language  python\n  category  security\n  severity  HIGH\n  match\n    pattern  eval\\s*\\(\n    scope    line\n  end\n  name\n    en: Obfuscated base64 code execution\n    fr: Exécution de code obfusqué en base64\n  end\n  risk\n    en: Hidden code runs.\n  end\nend\n";

    /// A rule with one `match` block whose body is `body`.
    fn rule_with_match(body: &str) -> String {
        format!(
            "rule r\n  language  python\n  category  security\n  severity  HIGH\n  match\n{body}  end\nend\n"
        )
    }

    /// Several `pattern-not`/`text-not` lines are all kept: a line matching
    /// any of them is left out (ticket #226; before, the last one replaced
    /// the others, and `path_traversal_os_join` lost two of its three).
    #[test]
    fn test_repeated_negatives_are_all_kept() {
        let source = rule_with_match(
            "    text  os.path.join(\n    text-not  realpath\n    pattern-not  (?i)SAFE\n    text-not  startswith\n    scope  line\n",
        );
        let rules = compile_sca_to_json(&source, "python/security/r.sca").unwrap();
        let negative = rules[0]["patterns"][0]["pattern-not"].as_str().unwrap();
        let negative = fancy_regex::Regex::new(negative).unwrap();
        for line in ["p = realpath(x)", "p = safe(x)", "if p.startswith(root):"] {
            assert!(negative.is_match(line).unwrap(), "{line}");
        }
        assert!(!negative.is_match("os.path.join(base, name)").unwrap());
    }

    /// A single negative compiles as written, as before ticket #226.
    #[test]
    fn test_single_negative_is_unchanged() {
        let source = rule_with_match("    pattern  eval\\(\n    pattern-not  (?i)safe\n");
        let rules = compile_sca_to_json(&source, "python/security/r.sca").unwrap();
        assert_eq!(rules[0]["patterns"][0]["pattern-not"], "(?i)safe");
    }

    /// Any other keyword given twice in one block is an error naming it.
    #[test]
    fn test_other_repeated_keyword_is_an_error() {
        for body in [
            "    pattern  a\n    text  b\n",
            "    pattern  a\n    with  b\n    with-text  c\n",
            "    pattern  a\n    scope  line\n    scope  file\n",
        ] {
            let error = compile_sca_to_json(&rule_with_match(body), "python/security/r.sca")
                .unwrap_err()
                .to_string();
            assert!(error.contains("deux fois"), "{body}: {error}");
        }
    }

    #[test]
    fn test_the_name_block_compiles_to_one_text_per_language() {
        let rules = compile_sca_to_json(RULE_WITH_NAME, "python/security/base64_eval.sca").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["name"]["en"], "Obfuscated base64 code execution");
        assert_eq!(
            rules[0]["name"]["fr"],
            "Exécution de code obfusqué en base64"
        );
        assert_eq!(rules[0]["risk"]["en"], "Hidden code runs.");
    }

    const TAINT_RULE: &str = "rule t\n  language  javascript\n  category  security\n  severity  HIGH\n  source  req\\.query  kind=http\n  SINK_LINE\nend\n";

    /// `arg_index=<n>` written on a sink is carried with `arg_explicit`;
    /// a sink without it keeps argument 0 for the dataflow path only
    /// (ticket #221).
    #[test]
    fn test_sink_arg_index_is_explicit_only_when_written() {
        let written = TAINT_RULE.replace("SINK_LINE", "sink    \\.query\\s*\\(  arg_index=1");
        let rules = compile_sca_to_json(&written, "javascript/security/t.sca").unwrap();
        assert_eq!(rules[0]["sinks"][0]["pattern"], "\\.query\\s*\\(");
        assert_eq!(rules[0]["sinks"][0]["arg_index"], 1);
        assert_eq!(rules[0]["sinks"][0]["arg_explicit"], true);

        let default = TAINT_RULE.replace("SINK_LINE", "sink    \\.query\\s*\\(");
        let rules = compile_sca_to_json(&default, "javascript/security/t.sca").unwrap();
        assert_eq!(rules[0]["sinks"][0]["arg_index"], 0);
        assert!(rules[0]["sinks"][0].get("arg_explicit").is_none());
    }

    /// An index that is not a non-negative integer, or an unknown option,
    /// is an error naming the line instead of a silent argument 0.
    #[test]
    fn test_sink_rejects_a_bad_index_or_an_unknown_option() {
        for (line, expected) in [
            (
                "sink    \\.query\\s*\\(  arg_index=first",
                "'arg_index' doit être un entier",
            ),
            (
                "sink    \\.query\\s*\\(  arg_index=-1",
                "'arg_index' doit être un entier",
            ),
            (
                "sink    \\.query\\s*\\(  arg=0",
                "Option inconnue sur un sink : 'arg=0'",
            ),
        ] {
            let rule = TAINT_RULE.replace("SINK_LINE", line);
            let error = compile_sca_to_json(&rule, "javascript/security/t.sca").unwrap_err();
            assert!(error.to_string().contains(expected), "{line}: {error}");
            assert_eq!(error.line, 6, "{line}");
        }
    }

    /// A translated text is kept as written: quotes and code included.
    /// Rebuilt from the lexer's tokens, `str_replace(["\r", "\n"], '', $x)`
    /// lost its quotes in the report (2026-11-14; same in the Python source).
    #[test]
    fn test_a_translated_text_keeps_its_quotes() {
        let text = r#"Strip newlines with str_replace(["\r", "\n"], '', $input) before logging."#;
        let rule = RULE_WITH_NAME.replace("en: Hidden code runs.", &format!("en: {text}"));
        let rules = compile_sca_to_json(&rule, "python/security/base64_eval.sca").unwrap();
        assert_eq!(rules[0]["risk"]["en"], text);
    }

    /// A `#` in a translated text is text: « Use #{} instead of ${} » was
    /// cut to « Use » by the comment rule of the lexer (2026-11-14).
    #[test]
    fn test_a_translated_text_keeps_a_hash() {
        let text = "Use #{} instead of ${} for parameter binding (see ticket #80).";
        let rule = RULE_WITH_NAME.replace("en: Hidden code runs.", &format!("en: {text}"));
        let rules = compile_sca_to_json(&rule, "java/security/mybatis.sca").unwrap();
        assert_eq!(rules[0]["risk"]["en"], text);
    }

    /// A text written as one quoted string loses its delimiting quotes, as
    /// in the Python source.
    #[test]
    fn test_a_quoted_text_loses_its_delimiting_quotes() {
        let rule = RULE_WITH_NAME.replace(
            "en: Hidden code runs.",
            r#"en: "N+1 query: database call inside loop""#,
        );
        let rules = compile_sca_to_json(&rule, "python/arch/n_plus_one.sca").unwrap();
        assert_eq!(
            rules[0]["risk"]["en"],
            "N+1 query: database call inside loop"
        );
    }

    #[test]
    fn test_a_rule_without_name_block_has_no_name_field() {
        let without = RULE_WITH_NAME.replace(
            "  name\n    en: Obfuscated base64 code execution\n    fr: Exécution de code obfusqué en base64\n  end\n",
            "",
        );
        let rules = compile_sca_to_json(&without, "python/security/base64_eval.sca").unwrap();
        assert!(rules[0].get("name").is_none());
    }
}
