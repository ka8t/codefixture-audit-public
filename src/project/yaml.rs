//! A YAML document read as JSON values, with tree-sitter's YAML grammar,
//! which the engine already uses for the projects it scans: no YAML
//! library is added.
//!
//! Written for the FriendsOfPHP records (ADR-0051) in
//! `codefixture-audit-advisories`, moved here on 2026-11-18 when the
//! engine started reading `pnpm-lock.yaml` (ticket #210), so both read
//! YAML the same way. It reads what these files use: mappings, sequences,
//! plain, quoted and block scalars, comments. Anchors, aliases, tags and
//! several documents are errors, named, never misread.

use serde_json::Value;

/// The YAML document `text` as JSON values: mappings become objects,
/// sequences arrays, `~`/`null` null, and every other scalar a string.
/// An error when the text is not valid YAML or uses what these records
/// never do (anchors, aliases, tags, several documents).
pub fn yaml_value(text: &str) -> Result<Value, String> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_yaml::LANGUAGE.into())
        .map_err(|e| e.to_string())?;
    let tree = parser
        .parse(text, None)
        .ok_or_else(|| "YAML not parsed".to_string())?;
    let root = tree.root_node();
    if root.has_error() {
        return Err("invalid YAML".to_string());
    }
    let documents: Vec<tree_sitter::Node> = data_children(root)
        .into_iter()
        .filter(|n| n.kind() == "document")
        .collect();
    let [document] = documents.as_slice() else {
        return Err(format!("{} YAML documents, expected one", documents.len()));
    };
    let body = *data_children(*document)
        .first()
        .ok_or_else(|| "empty YAML document".to_string())?;
    node_value(body, text).ok_or_else(|| {
        "YAML construct not supported (anchor, alias, tag or unknown escape)".to_string()
    })
}

/// The named children of `node` that hold data: comments are left aside,
/// as YAML defines them (they carry no content).
fn data_children<'t>(node: tree_sitter::Node<'t>) -> Vec<tree_sitter::Node<'t>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|n| n.kind() != "comment")
        .collect()
}

/// One YAML node as a JSON value (see [`yaml_value`]).
fn node_value(node: tree_sitter::Node, text: &str) -> Option<Value> {
    let source = |n: tree_sitter::Node| text.get(n.byte_range()).unwrap_or_default();
    match node.kind() {
        "block_node" | "flow_node" => {
            let children = data_children(node);
            let [inner] = children.as_slice() else {
                return None; // an anchor or a tag beside the value
            };
            node_value(*inner, text)
        }
        "block_mapping" | "flow_mapping" => {
            let mut map = serde_json::Map::new();
            for pair in data_children(node) {
                if !matches!(pair.kind(), "block_mapping_pair" | "flow_pair") {
                    return None;
                }
                let key = match node_value(pair.child_by_field_name("key")?, text)? {
                    Value::String(key) => key,
                    _ => return None,
                };
                let value = match pair.child_by_field_name("value") {
                    Some(value) => node_value(value, text)?,
                    None => Value::Null,
                };
                map.insert(key, value);
            }
            Some(Value::Object(map))
        }
        "block_sequence" => data_children(node)
            .into_iter()
            .map(|item| {
                data_children(item)
                    .first()
                    .map_or(Some(Value::Null), |v| node_value(*v, text))
            })
            .collect::<Option<Vec<Value>>>()
            .map(Value::Array),
        "flow_sequence" => data_children(node)
            .into_iter()
            .map(|item| node_value(item, text))
            .collect::<Option<Vec<Value>>>()
            .map(Value::Array),
        "plain_scalar" => {
            if data_children(node)
                .iter()
                .any(|c| c.kind() == "null_scalar")
            {
                Some(Value::Null)
            } else {
                Some(Value::String(fold(source(node).trim(), false)?))
            }
        }
        "single_quote_scalar" => {
            let raw = source(node);
            let inner = raw.strip_prefix('\'')?.strip_suffix('\'')?;
            Some(Value::String(fold(&inner.replace("''", "'"), false)?))
        }
        "double_quote_scalar" => {
            let raw = source(node);
            let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
            Some(Value::String(fold(inner, true)?))
        }
        "block_scalar" => Some(Value::String(block_scalar(source(node)))),
        _ => None,
    }
}

/// A flow scalar's text as YAML 1.2 reads it: a line break with the
/// spaces around it becomes one space, each empty line a line break
/// (line folding, spec 6.5); with `escapes` (double quotes), the escapes
/// of spec 5.7 are decoded and an escaped line break joins the lines
/// without a space. `None` for an escape the spec does not define.
pub(crate) fn fold(text: &str, escapes: bool) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\n' {
            // Trailing spaces of the line are not content.
            while out.ends_with([' ', '\t']) {
                out.pop();
            }
            let mut empty_lines = 0;
            i += 1;
            loop {
                while i < chars.len() && matches!(chars[i], ' ' | '\t') {
                    i += 1;
                }
                if i < chars.len() && chars[i] == '\n' {
                    empty_lines += 1;
                    i += 1;
                } else {
                    break;
                }
            }
            if empty_lines == 0 {
                out.push(' ');
            } else {
                out.extend(std::iter::repeat_n('\n', empty_lines));
            }
            continue;
        }
        if !(escapes && c == '\\') {
            out.push(c);
            i += 1;
            continue;
        }
        let next = *chars.get(i + 1)?;
        i += 2;
        let hex = |len: usize, i: &mut usize| -> Option<char> {
            let digits: String = chars.get(*i..*i + len)?.iter().collect();
            *i += len;
            char::from_u32(u32::from_str_radix(&digits, 16).ok()?)
        };
        match next {
            '0' => out.push('\0'),
            'a' => out.push('\u{7}'),
            'b' => out.push('\u{8}'),
            't' | '\t' => out.push('\t'),
            'n' => out.push('\n'),
            'v' => out.push('\u{b}'),
            'f' => out.push('\u{c}'),
            'r' => out.push('\r'),
            'e' => out.push('\u{1b}'),
            ' ' => out.push(' '),
            '"' => out.push('"'),
            '/' => out.push('/'),
            '\\' => out.push('\\'),
            'N' => out.push('\u{85}'),
            '_' => out.push('\u{a0}'),
            'L' => out.push('\u{2028}'),
            'P' => out.push('\u{2029}'),
            'x' => out.push(hex(2, &mut i)?),
            'u' => out.push(hex(4, &mut i)?),
            'U' => out.push(hex(8, &mut i)?),
            '\n' => {
                // An escaped line break: the lines join without a space.
                while i < chars.len() && matches!(chars[i], ' ' | '\t') {
                    i += 1;
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

/// The text of a block scalar (`|` keeps the line breaks, `>` folds them
/// into spaces): the lines after its header, without their indentation.
fn block_scalar(raw: &str) -> String {
    let mut lines = raw.lines();
    let folded = lines
        .next()
        .is_some_and(|header| header.trim_start().starts_with('>'));
    let body: Vec<&str> = lines.map(str::trim).filter(|l| !l.is_empty()).collect();
    body.join(if folded { " " } else { "\n" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fold_reads_flow_scalars_as_yaml_does() {
        assert_eq!(fold("a\n  b", false).unwrap(), "a b");
        assert_eq!(fold("a  \n\n  b", false).unwrap(), "a\nb");
        assert_eq!(fold("x\\_y\\u00e9\\\"\\\\", true).unwrap(), "x\u{a0}yé\"\\");
        assert_eq!(fold("a\\\n   b", true).unwrap(), "ab");
        assert!(fold("\\q", true).is_none());
    }

    /// Mappings, sequences, quoted scalars and comments, as a pnpm
    /// lockfile writes them.
    #[test]
    fn test_yaml_value_reads_a_lockfile_shape() {
        let text = "lockfileVersion: '9.0'\n# comment\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.0\n        version: 4.17.21\npackages:\n  lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n";
        let value = yaml_value(text).unwrap();
        assert_eq!(value["lockfileVersion"], "9.0");
        assert_eq!(
            value["importers"]["."]["dependencies"]["lodash"]["version"],
            "4.17.21"
        );
        assert_eq!(
            value["packages"]["lodash@4.17.21"]["resolution"]["integrity"],
            "sha512-x"
        );
        assert!(yaml_value("a: &x 1\nb: *x\n").is_err());
    }
}
