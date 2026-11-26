//! The engine's XML reader (ADR-0070): a whole document read into a tree
//! of elements, each with its attributes, its text and the line of its
//! start tag.
//!
//! Until 2026-11-26 the engine read its XML inputs with regular
//! expressions: a `pom.xml` by `<dependency>…</dependency>` blocks, a
//! `.csproj` line by line. Those miss what XML allows and these files
//! use: an attribute on another line, a `<Version>` written as an element,
//! a comment around a dependency, an entity in a value. The CWE and CAPEC
//! catalogs (`tools/codefixture-audit-advisories`, `catalog`) need the
//! same reading. Every XML input now goes through [`parse`].
//!
//! Built on `quick-xml`, which tokenizes; this module checks the
//! structure (one root element, every element closed by its own name) and
//! resolves references. **No DTD is processed**: a `<!DOCTYPE>` is
//! skipped, so no external entity is ever fetched (XXE) and no entity
//! expands into another. The references resolved are the five XML
//! predefines (`&lt;` `&gt;` `&amp;` `&apos;` `&quot;`) and character
//! references (`&#233;`, `&#xE9;`). Any other entity can only come from a
//! DTD: it is an error naming it, never an empty or a guessed value.
//!
//! Element and attribute names are kept without their namespace prefix
//! (`cwe:Weakness` is `Weakness`): the documents read here use one
//! vocabulary each, and their default namespace changes with the schema
//! version (`http://cwe.mitre.org/cwe-8`), which must not change the
//! reading.

use std::fmt;

use quick_xml::XmlVersion;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};

/// One element: its name, the line of its start tag, its attributes and
/// what it contains, in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    /// Local name, without namespace prefix.
    pub name: String,
    /// 1-based line of its start tag (`<` of `<name`).
    pub line: usize,
    /// Attributes in document order, by local name, values with their
    /// references resolved and their whitespace normalized as XML says
    /// (tab, carriage return and line feed become spaces).
    attributes: Vec<(String, String)>,
    /// Child elements and text, in document order.
    children: Vec<Node>,
}

/// Content of an element: a child element, or text (character data,
/// CDATA sections and resolved references, merged when adjacent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Element(Element),
    Text(String),
}

/// A document that is not well-formed XML, or uses a reference this
/// reader does not resolve: the line where reading stopped and why, in
/// English (the caller adds the file and translates the frame).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlError {
    /// 1-based line where the problem was found.
    pub line: usize,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for XmlError {}

impl Element {
    /// The value of attribute `name` (local name), `None` when absent.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The child elements, in document order.
    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            Node::Text(_) => None,
        })
    }

    /// The child elements named `name`, in document order.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.elements().filter(move |e| e.name == name)
    }

    /// The first child element named `name`.
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.elements().find(|e| e.name == name)
    }

    /// The text of the first child element named `name`, trimmed; `None`
    /// when there is no such child.
    pub fn child_text(&self, name: &str) -> Option<String> {
        self.child(name).map(|c| c.text().trim().to_string())
    }

    /// Every element below this one named `name`, depth first in document
    /// order, this element excluded.
    pub fn descendants_named<'a>(&'a self, name: &'a str) -> Vec<&'a Element> {
        let mut found = Vec::new();
        let mut stack: Vec<&Element> = self.elements().collect();
        stack.reverse();
        while let Some(e) = stack.pop() {
            if e.name == name {
                found.push(e);
            }
            let mut below: Vec<&Element> = e.elements().collect();
            below.reverse();
            stack.extend(below);
        }
        found
    }

    /// The text directly inside this element (not that of its children),
    /// as written once references are resolved: whitespace kept.
    pub fn text(&self) -> String {
        self.children
            .iter()
            .filter_map(|n| match n {
                Node::Text(t) => Some(t.as_str()),
                Node::Element(_) => None,
            })
            .collect()
    }
}

/// Byte offsets of the start of every line of `text`, to turn the reader's
/// byte positions into line numbers.
struct Lines(Vec<usize>);

impl Lines {
    fn new(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(i, _)| i + 1));
        Lines(starts)
    }

    /// 1-based line of byte `offset`.
    fn of(&self, offset: u64) -> usize {
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        self.0.partition_point(|&start| start <= offset)
    }
}

/// Reads the document `text` into its root element.
///
/// A UTF-8 byte order mark is skipped. The document must hold exactly one
/// root element; only whitespace, comments, processing instructions, the
/// XML declaration and a skipped `<!DOCTYPE>` may surround it.
pub fn parse(text: &str) -> Result<Element, XmlError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let lines = Lines::new(text);
    let mut reader = quick_xml::Reader::from_str(text);
    // Defaults kept on purpose: end names are checked against their start
    // tag (`check_end_names`), an unmatched end is an error.
    let error = |line: usize, message: String| XmlError { line, message };

    // Elements still open, innermost last.
    let mut open: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    loop {
        let position = reader.buffer_position();
        let event = reader.read_event().map_err(|e| {
            error(
                lines.of(reader.error_position()),
                format!("not well-formed XML: {e}"),
            )
        })?;
        let line = lines.of(position);
        match event {
            Event::Start(start) => {
                let element = element_of(&start, line)?;
                if open.is_empty() && root.is_some() {
                    return Err(error(line, "a second root element".to_string()));
                }
                open.push(element);
            }
            Event::Empty(start) => {
                let element = element_of(&start, line)?;
                match open.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(element)),
                    None if root.is_some() => {
                        return Err(error(line, "a second root element".to_string()));
                    }
                    None => root = Some(element),
                }
            }
            Event::End(_) => {
                // `check_end_names` has already matched the name.
                let element = open.pop().expect("quick-xml matched an open element");
                match open.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(element)),
                    None => root = Some(element),
                }
            }
            Event::Text(t) => {
                // A text event starts right after the previous tag, often
                // on that tag's line: an error names the line of its
                // first character that is not whitespace.
                // Measured on the raw bytes: end-of-line normalization
                // shortens `\r\n`, which would shift the offset.
                let raw: &str = &t;
                let lead = raw.len() - raw.trim_start().len();
                let content = t.xml10_content();
                let line = lines.of(position + lead as u64);
                push_text(&mut open, &content, line)?
            }
            Event::CData(c) => push_text(&mut open, &c.xml10_content(), line)?,
            Event::GeneralRef(r) => {
                let resolved = match r.resolve_char_ref() {
                    Ok(Some(c)) => c.to_string(),
                    Ok(None) => match resolve_predefined_entity(&r) {
                        Some(s) => s.to_string(),
                        None => {
                            return Err(error(
                                line,
                                format!(
                                    "entity &{}; is not one of XML's five, and no DTD is read",
                                    &*r
                                ),
                            ));
                        }
                    },
                    Err(e) => return Err(error(line, format!("&{};: {e}", &*r))),
                };
                push_text(&mut open, &resolved, line)?;
            }
            // Not content: the declaration, comments, processing
            // instructions, and the DTD, skipped unread (see the module
            // comment).
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) | Event::DocType(_) => {}
            Event::Eof => break,
        }
    }
    if let Some(unclosed) = open.last() {
        return Err(error(
            unclosed.line,
            format!("element <{}> is never closed", unclosed.name),
        ));
    }
    root.ok_or_else(|| {
        error(
            lines.of(reader.buffer_position()),
            "no root element".to_string(),
        )
    })
}

/// The element of start tag `start`, at `line`, without content yet.
fn element_of(start: &BytesStart<'_>, line: usize) -> Result<Element, XmlError> {
    let name = start.local_name().as_ref().to_string();
    let mut attributes = Vec::new();
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|e| XmlError {
            line,
            message: format!("<{name}>: malformed attribute: {e}"),
        })?;
        let key = attribute.key.local_name().as_ref().to_string();
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|e| XmlError {
                line,
                message: format!("<{name}> attribute {key}: {e}"),
            })?;
        attributes.push((key, value.into_owned()));
    }
    Ok(Element {
        name,
        line,
        attributes,
        children: Vec::new(),
    })
}

/// Appends `text` to the innermost open element, merged with the text
/// just before it. Outside the root, only whitespace is allowed.
fn push_text(open: &mut [Element], text: &str, line: usize) -> Result<(), XmlError> {
    let Some(parent) = open.last_mut() else {
        if text.trim().is_empty() {
            return Ok(());
        }
        return Err(XmlError {
            line,
            message: "text outside the root element".to_string(),
        });
    };
    match parent.children.last_mut() {
        Some(Node::Text(previous)) => previous.push_str(text),
        _ => parent.children.push(Node::Text(text.to_string())),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Elements, attributes, text and lines are read as written; the
    /// namespace prefix is dropped.
    #[test]
    fn test_tree_attributes_text_and_lines() {
        let root = parse(
            "<?xml version=\"1.0\"?>\n<cwe:Catalog xmlns:cwe=\"urn:x\" Version=\"5.0\">\n  <Weakness ID=\"79\"\n     Name=\"Cross-site &apos;Scripting&apos;\"/>\n  <Note>a &lt; b &#233; &#xE9;</Note>\n</cwe:Catalog>",
        )
        .unwrap();
        assert_eq!(root.name, "Catalog");
        assert_eq!(root.line, 2);
        assert_eq!(root.attr("Version"), Some("5.0"));
        let weakness = root.child("Weakness").unwrap();
        assert_eq!(weakness.line, 3);
        assert_eq!(weakness.attr("Name"), Some("Cross-site 'Scripting'"));
        assert_eq!(root.child_text("Note").as_deref(), Some("a < b é é"));
        assert_eq!(root.attr("missing"), None);
    }

    /// Comments, CDATA and a skipped DTD are not content; CDATA text is
    /// kept as is; text pieces around a reference are merged.
    #[test]
    fn test_comments_cdata_and_doctype() {
        let root = parse(
            "<!DOCTYPE project [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>\n<p><!-- <version>9</version> --><v>1<![CDATA[<2>]]>&amp;3</v></p>",
        )
        .unwrap();
        assert_eq!(root.child_text("v").as_deref(), Some("1<2>&3"));
        assert_eq!(root.elements().count(), 1, "the comment holds no element");
    }

    /// XXE: an entity declared in the DTD is never expanded, and its use
    /// is an error naming it.
    #[test]
    fn test_dtd_entities_are_refused() {
        let err =
            parse("<!DOCTYPE p [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>\n<p>\n<v>&x;</v></p>")
                .unwrap_err();
        assert_eq!(err.line, 3);
        assert!(err.message.contains("&x;"), "{err}");
    }

    /// A document that is not well-formed gives its line and the reason.
    #[test]
    fn test_malformed_documents_are_errors_with_a_line() {
        let cases = [
            ("<a>\n<b></a>", 2),
            ("<a>\n<b>", 2),
            ("<a/><b/>", 1),
            ("<a/>\ntext", 2),
            ("", 1),
            ("<a x=\"1\" x=\"2\"/>", 1),
        ];
        for (text, line) in cases {
            let err = parse(text).unwrap_err();
            assert_eq!(err.line, line, "{text:?}: {err}");
        }
    }

    /// Descendants are found at every depth, in document order.
    #[test]
    fn test_descendants_in_document_order() {
        let root = parse("<r><d n=\"1\"><d n=\"2\"/></d><x><d n=\"3\"/></x></r>").unwrap();
        let found: Vec<&str> = root
            .descendants_named("d")
            .iter()
            .map(|d| d.attr("n").unwrap())
            .collect();
        assert_eq!(found, vec!["1", "2", "3"]);
    }

    /// Windows line ends count one line each, in tags and in text.
    #[test]
    fn test_crlf_lines() {
        let root = parse("<a>\r\n\r\n  <b/>\r\n</a>").unwrap();
        assert_eq!(root.child("b").unwrap().line, 3);
        assert_eq!(parse("<a/>\r\n\r\n x").unwrap_err().line, 3);
    }

    /// A byte order mark does not count as text before the root.
    #[test]
    fn test_byte_order_mark_is_skipped() {
        assert_eq!(parse("\u{feff}<a/>").unwrap().name, "a");
    }
}
