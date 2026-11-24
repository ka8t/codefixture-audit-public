//! What a C# file declares and imports, read from its tree for the C# call
//! graph (ticket #284): the namespaces it opens, the classes it declares
//! (with their namespace and base types) and its `using` directives. The
//! role of `java_module_registry.rs` for Java.
//!
//! **Deliberate addition, no Python source**: the Audit never linked C#
//! files together (its C# pass was disabled), so these rules are C#'s own,
//! read from the C# language specification (§14.5 using directives, §7.6
//! namespace and type names), within the limits listed below.
//!
//! Forms handled:
//!   - block namespaces `namespace A.B { ... }`, nested
//!     (`namespace A { namespace B { ... } }` gives `A.B`);
//!   - the file-scoped namespace `namespace A.B;` (C# 10), which applies to
//!     every declaration after it (tree-sitter leaves those declarations as
//!     siblings of the `file_scoped_namespace_declaration` node);
//!   - `using A.B;`, `using X = A.B.C;`, `using static A.B.C;`, each also
//!     with `global` (C# 10: the directive applies to every file of the
//!     project), at the top of the file or inside a namespace block.
//!
//! Accepted simplifications:
//!   - a `using` written inside a namespace block applies to the whole file,
//!     not only to that block;
//!   - nested types are indexed under their simple name, in the namespace of
//!     their outermost type (the convention of `csharp_summary.rs`, which
//!     names their methods `Inner.Method`);
//!   - declarations wrapped in a top-level `#if` are not read, as
//!     `csharp_summary::collect_csharp_functions` does not read them.

use std::collections::BTreeMap;

use tree_sitter::Node;

use super::csharp_cfg::flatten_preproc_members;

/// Type declarations whose methods the C# summaries collect (same list as
/// `csharp_summary.rs`).
const TYPE_DECLS: [&str; 4] = [
    "class_declaration",
    "struct_declaration",
    "record_declaration",
    "interface_declaration",
];

/// One `using` directive of a C# file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CSharpUsing {
    /// `using A.B;`: every type of namespace `A.B` is visible by its simple
    /// name.
    Namespace(String),
    /// `using X = A.B.C;`: `X` names the type (or namespace) `A.B.C`.
    Alias { alias: String, target: String },
    /// `using static A.B.C;`: the static members of type `A.B.C` are
    /// callable by their bare name.
    Static(String),
}

/// A `using` directive and whether it is `global` (C# 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CSharpUsingInfo {
    /// What the directive imports.
    pub using: CSharpUsing,
    /// `global using ...`: applies to every analyzed file.
    pub global: bool,
}

/// A type declared by a C# file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CSharpClassInfo {
    /// Full name of its namespace (`""`: the global namespace).
    pub namespace: String,
    /// Simple name, without type parameters.
    pub name: String,
    /// Simple names of the types of its base list, in source order (the
    /// base class, when there is one, comes first in C#).
    pub bases: Vec<String>,
}

/// What a C# file declares and imports (see the module doc).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CSharpFileScope {
    /// Full names of the namespaces the file opens, in source order,
    /// without duplicates.
    pub namespaces: Vec<String>,
    /// The types it declares, nested ones included.
    pub classes: Vec<CSharpClassInfo>,
    /// Its `using` directives, in source order.
    pub usings: Vec<CSharpUsingInfo>,
}

fn text(node: Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

/// A name as written (`A.B`, `global::A.B`, `List<int>`), reduced to its
/// dotted form without spaces, `global::` prefix or type arguments.
pub fn normalize_name(raw: &str) -> String {
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let compact = compact.strip_prefix("global::").unwrap_or(&compact);
    let mut out = String::new();
    let mut depth = 0usize;
    for c in compact.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// Joins a namespace and a name (`""` is the global namespace).
pub fn join_namespace(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else if name.is_empty() {
        namespace.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}

/// Reads the scope of a C# file (`compilation_unit`).
pub fn collect_csharp_scope(root: Node, source: &[u8]) -> CSharpFileScope {
    let mut scope = CSharpFileScope::default();
    walk_container(root, "", source, &mut scope);
    scope
}

/// Walks the declarations of a compilation unit or of a namespace body,
/// inside namespace `namespace`. A file-scoped namespace changes the
/// namespace of every following sibling.
fn walk_container(container: Node, namespace: &str, source: &[u8], scope: &mut CSharpFileScope) {
    let mut current = namespace.to_string();
    let mut w = container.walk();
    for child in container.named_children(&mut w) {
        match child.kind() {
            "using_directive" => {
                if let Some(using) = using_info(child, source) {
                    scope.usings.push(using);
                }
            }
            "file_scoped_namespace_declaration" => {
                let name = child
                    .child_by_field_name("name")
                    .map(|n| normalize_name(&text(n, source)))
                    .unwrap_or_default();
                current = join_namespace(namespace, &name);
                push_namespace(scope, &current);
            }
            "namespace_declaration" => {
                let name = child
                    .child_by_field_name("name")
                    .map(|n| normalize_name(&text(n, source)))
                    .unwrap_or_default();
                let inner = join_namespace(&current, &name);
                push_namespace(scope, &inner);
                if let Some(body) = child.child_by_field_name("body") {
                    walk_container(body, &inner, source, scope);
                }
            }
            kind if TYPE_DECLS.contains(&kind) => {
                collect_type(child, &current, source, scope);
            }
            _ => {}
        }
    }
}

fn push_namespace(scope: &mut CSharpFileScope, namespace: &str) {
    if !scope.namespaces.iter().any(|n| n == namespace) {
        scope.namespaces.push(namespace.to_string());
    }
}

/// Records a type declaration and, recursively, the types nested in it
/// (under their simple name, in the same namespace).
fn collect_type(type_decl: Node, namespace: &str, source: &[u8], scope: &mut CSharpFileScope) {
    let Some(name_node) = type_decl.child_by_field_name("name") else {
        return;
    };
    let mut bases = Vec::new();
    let mut w = type_decl.walk();
    for child in type_decl.named_children(&mut w) {
        if child.kind() != "base_list" {
            continue;
        }
        let mut bw = child.walk();
        for base in child.named_children(&mut bw) {
            // A primary-constructor base (`: Base(x)`) wraps the type with
            // its arguments; the type is the first named child.
            let type_node = if base.kind() == "primary_constructor_base_type" {
                match base.named_child(0) {
                    Some(t) => t,
                    None => continue,
                }
            } else {
                base
            };
            let name = normalize_name(&text(type_node, source));
            let simple = name.rsplit('.').next().unwrap_or(&name).to_string();
            if !simple.is_empty() {
                bases.push(simple);
            }
        }
    }
    scope.classes.push(CSharpClassInfo {
        namespace: namespace.to_string(),
        name: text(name_node, source),
        bases,
    });
    if let Some(body) = type_decl.child_by_field_name("body") {
        for member in flatten_preproc_members(body) {
            if TYPE_DECLS.contains(&member.kind()) {
                collect_type(member, namespace, source, scope);
            }
        }
    }
}

/// Reads one `using_directive` node: `global` and `static` are anonymous
/// tokens, the alias is the `name` field, the imported name the other
/// named child.
fn using_info(node: Node, source: &[u8]) -> Option<CSharpUsingInfo> {
    let mut global = false;
    let mut is_static = false;
    let alias = node.child_by_field_name("name");
    let mut target = None;
    let mut w = node.walk();
    for child in node.children(&mut w) {
        if !child.is_named() {
            match child.kind() {
                "global" => global = true,
                "static" => is_static = true,
                _ => {}
            }
            continue;
        }
        if Some(child) == alias {
            continue;
        }
        target = Some(normalize_name(&text(child, source)));
    }
    let target = target.filter(|t| !t.is_empty())?;
    let using = match alias {
        Some(alias) => CSharpUsing::Alias {
            alias: text(alias, source),
            target,
        },
        None if is_static => CSharpUsing::Static(target),
        None => CSharpUsing::Namespace(target),
    };
    Some(CSharpUsingInfo { using, global })
}

/// Simple class name → base type simple names, for the classes of a file
/// (`base.Method()` resolution). On a name collision the last declaration
/// wins, as for `csharp_summary::collect_csharp_field_types`.
pub fn base_types_by_class(scope: &CSharpFileScope) -> BTreeMap<String, Vec<String>> {
    scope
        .classes
        .iter()
        .map(|class| (class.name.clone(), class.bases.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope_of(src: &str) -> CSharpFileScope {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        assert!(!tree.root_node().has_error(), "invalid C#: {src:?}");
        collect_csharp_scope(tree.root_node(), src.as_bytes())
    }

    fn class(namespace: &str, name: &str, bases: &[&str]) -> CSharpClassInfo {
        CSharpClassInfo {
            namespace: namespace.to_string(),
            name: name.to_string(),
            bases: bases.iter().map(|b| b.to_string()).collect(),
        }
    }

    #[test]
    fn test_block_namespaces_nest() {
        let scope = scope_of("namespace A { namespace B.C { class X {} } class Y {} }");
        assert_eq!(scope.namespaces, vec!["A", "A.B.C"]);
        assert_eq!(
            scope.classes,
            vec![class("A.B.C", "X", &[]), class("A", "Y", &[])]
        );
    }

    #[test]
    fn test_file_scoped_namespace_applies_to_following_types() {
        let scope = scope_of("using System;\nnamespace App.Data;\nclass Repo : Base, IRepo {}\n");
        assert_eq!(scope.namespaces, vec!["App.Data"]);
        assert_eq!(
            scope.classes,
            vec![class("App.Data", "Repo", &["Base", "IRepo"])]
        );
    }

    #[test]
    fn test_type_outside_any_namespace_is_global() {
        let scope = scope_of("class X { class Inner {} }");
        assert!(scope.namespaces.is_empty());
        assert_eq!(
            scope.classes,
            vec![class("", "X", &[]), class("", "Inner", &[])]
        );
    }

    #[test]
    fn test_using_forms() {
        let scope = scope_of(
            "using A.B;\nglobal using C;\nusing X = D.E.F;\nusing static G.H;\nglobal using static I;\n\
             namespace N { using J.K; class Z {} }",
        );
        let usings: Vec<(CSharpUsing, bool)> = scope
            .usings
            .into_iter()
            .map(|u| (u.using, u.global))
            .collect();
        assert_eq!(
            usings,
            vec![
                (CSharpUsing::Namespace("A.B".into()), false),
                (CSharpUsing::Namespace("C".into()), true),
                (
                    CSharpUsing::Alias {
                        alias: "X".into(),
                        target: "D.E.F".into()
                    },
                    false
                ),
                (CSharpUsing::Static("G.H".into()), false),
                (CSharpUsing::Static("I".into()), true),
                (CSharpUsing::Namespace("J.K".into()), false),
            ]
        );
    }

    #[test]
    fn test_normalize_name() {
        assert_eq!(normalize_name("global::A . B"), "A.B");
        assert_eq!(normalize_name("List<Dictionary<string, int>>"), "List");
        assert_eq!(normalize_name("A.B<T>.C"), "A.B.C");
    }
}
