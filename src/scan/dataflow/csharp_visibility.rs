//! What a C# file sees of the other analyzed files (ticket #284): the
//! classes of its namespaces and of their enclosing namespaces, those of the
//! namespaces it imports with `using`, its `using` aliases and the static
//! members it imports with `using static`. The C# call graph
//! (`csharp_call_graph.rs`) resolves its edges with it, and the taint
//! analysis of each file looks up the summaries of the methods it sees
//! through it, as Java does with `java_visibility.rs`.
//!
//! **Deliberate addition, no Python source** (the Audit has no C# call
//! graph, ADR-0060). Built like `JavaVisibility` from the start: each file
//! keeps only its own namespaces and directives, and a lookup walks a
//! per-namespace index of the classes, so that memory does not grow with
//! the square of a namespace (the Juliet C# suite puts thousands of files
//! in one namespace, as the Juliet Java suite does in one package).
//!
//! A simple class name `C` used in a file resolves, in this order (C#
//! specification §7.6, simplified):
//!   1. the namespaces of the file, innermost first, then each enclosing
//!      namespace, then the global namespace: the first one that declares a
//!      class `C` (in any analyzed file) wins;
//!   2. a `using C = A.B.D;` alias of the file or a `global using` alias;
//!   3. the namespaces imported by `using A.B;` (the file's or a `global
//!      using`): exactly one of them must declare `C`; two do, nothing is
//!      resolved (the compiler reports that ambiguity, a mixed corpus can
//!      hold it: anti-FP).
//!
//! A method `C.M` of a class declared by several files (a `partial` class,
//! or two projects of one repository declaring the same class) is taken
//! from the file asking, when it defines `C.M`, otherwise from the last
//! file in path order that defines it (the Java rule for a class defined
//! twice in a package).
//!
//! A qualified class name (`A.B.C.M()`) is resolved for the edges of the
//! graph only, not by [`Visibility::binding`]: any file may name any class
//! that way, and [`Visibility::readers_of`] could then not answer less than
//! every file. An edge reaches the analysis through `extra` (the call-site
//! aliases of `class_call_graph.rs`), and its caller is a reader through
//! the graph's caller index.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use super::call_graph::NodeKey;
use super::csharp_namespaces::{CSharpFileScope, CSharpUsing, join_namespace};
use super::visibility::{Visibility, hex};

/// A class: its namespace and its simple name.
pub type ClassRef = (String, String);

/// What each analyzed C# file sees of the others (see the module doc).
/// Built once per scan by `CSharpCallGraph::build`, shared by every rule.
#[derive(Default)]
pub struct CSharpVisibility {
    /// Namespace → simple class name → files declaring it, in path order.
    classes: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    /// Lookup chain of each file: its namespaces, innermost first, each
    /// followed by its enclosing namespaces, then the global namespace `""`.
    chains: BTreeMap<String, Vec<String>>,
    /// The non-global `using` directives of each file, in source order.
    usings: BTreeMap<String, Vec<CSharpUsing>>,
    /// The `global using` directives of every file, in path then source
    /// order: they apply to every file.
    global_usings: Vec<CSharpUsing>,
    /// Namespaces of the classes each file declares.
    namespaces_of_file: BTreeMap<String, BTreeSet<String>>,
    /// Dotted method names (`Class.Method`) defined by each file.
    function_names: BTreeMap<String, BTreeSet<String>>,
    /// SHA-256 of what each namespace exposes, computed on first use.
    namespace_digests: OnceLock<BTreeMap<String, String>>,
    /// Each declared type, with the file declaring it and the simple names
    /// of its base list, in path order (a `partial` class once per file).
    declared_bases: Vec<(ClassRef, String, Vec<String>)>,
    /// Type → the types whose base list names it directly, resolved from
    /// the file declaring them; computed on first use.
    subtypes: OnceLock<BTreeMap<ClassRef, BTreeSet<ClassRef>>>,
}

impl fmt::Debug for CSharpVisibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CSharpVisibility")
            .field("files", &self.chains.len())
            .field("namespaces", &self.classes.len())
            .finish()
    }
}

/// The namespace containing `full` (`"A.B"` for `"A.B.C"`, `""` for `"C"`).
fn parent(full: &str) -> &str {
    full.rsplit_once('.').map(|(p, _)| p).unwrap_or("")
}

/// The lookup chain of a file declaring `namespaces` (see
/// [`CSharpVisibility::chains`]). The deepest namespaces come first, so
/// that `namespace A { namespace B { } }` looks in `A.B` before `A`.
fn lookup_chain(namespaces: &[String]) -> Vec<String> {
    let mut declared: Vec<&String> = namespaces.iter().collect();
    declared.sort_by_key(|n| std::cmp::Reverse(n.split('.').count()));
    let mut chain: Vec<String> = Vec::new();
    for namespace in declared {
        let mut current = namespace.as_str();
        while !current.is_empty() {
            if !chain.iter().any(|n| n == current) {
                chain.push(current.to_string());
            }
            current = parent(current);
        }
    }
    chain.push(String::new());
    chain
}

impl CSharpVisibility {
    /// Indexes the analyzed files. `scopes`: file → what it declares and
    /// imports (`csharp_namespaces::collect_csharp_scope`), in path order;
    /// `function_names`: file → dotted method names.
    pub fn new(
        scopes: &BTreeMap<String, CSharpFileScope>,
        function_names: BTreeMap<String, BTreeSet<String>>,
    ) -> Self {
        let mut visibility = CSharpVisibility::default();
        for (file, scope) in scopes {
            for class in &scope.classes {
                let files = visibility
                    .classes
                    .entry(class.namespace.clone())
                    .or_default()
                    .entry(class.name.clone())
                    .or_default();
                if files.last() != Some(file) {
                    files.push(file.clone());
                }
                visibility
                    .namespaces_of_file
                    .entry(file.clone())
                    .or_default()
                    .insert(class.namespace.clone());
                if !class.bases.is_empty() {
                    visibility.declared_bases.push((
                        (class.namespace.clone(), class.name.clone()),
                        file.clone(),
                        class.bases.clone(),
                    ));
                }
            }
            visibility
                .chains
                .insert(file.clone(), lookup_chain(&scope.namespaces));
            let mut own = Vec::new();
            for using in &scope.usings {
                if using.global {
                    visibility.global_usings.push(using.using.clone());
                } else {
                    own.push(using.using.clone());
                }
            }
            if !own.is_empty() {
                visibility.usings.insert(file.clone(), own);
            }
        }
        visibility.function_names = function_names;
        visibility
    }

    /// The `using` directives that apply to `file`: its own, then the
    /// global ones.
    fn usings_of<'a>(&'a self, file: &str) -> impl Iterator<Item = &'a CSharpUsing> + 'a {
        self.usings
            .get(file)
            .into_iter()
            .flatten()
            .chain(self.global_usings.iter())
    }

    /// The lookup chain of `file` (only the global namespace for a file
    /// the visibility does not know).
    fn chain<'a>(&'a self, file: &str) -> &'a [String] {
        static GLOBAL_ONLY: OnceLock<Vec<String>> = OnceLock::new();
        self.chains
            .get(file)
            .map(Vec::as_slice)
            .unwrap_or_else(|| GLOBAL_ONLY.get_or_init(|| vec![String::new()]))
    }

    fn declares(&self, namespace: &str, cname: &str) -> bool {
        self.classes
            .get(namespace)
            .is_some_and(|by_name| by_name.contains_key(cname))
    }

    /// The class of fully qualified name `full`, if an analyzed file
    /// declares it.
    fn absolute_class(&self, full: &str) -> Option<ClassRef> {
        let (namespace, cname) = full.rsplit_once('.').unwrap_or(("", full));
        self.declares(namespace, cname)
            .then(|| (namespace.to_string(), cname.to_string()))
    }

    /// The class that the dotted name `name` designates in `file`, read as
    /// written from each namespace of its chain (innermost first, the
    /// global namespace last, so an absolute name is found there).
    fn qualified_class(&self, file: &str, name: &str) -> Option<ClassRef> {
        self.chain(file)
            .iter()
            .find_map(|namespace| self.absolute_class(&join_namespace(namespace, name)))
    }

    /// The target of an alias or `using static` directive, as the class
    /// it names: written relative to the namespaces of the file, or
    /// absolute.
    fn directive_class(&self, file: &str, target: &str) -> Option<ClassRef> {
        self.qualified_class(file, target)
    }

    /// The class that the simple name `cname` designates in `file` (rules
    /// 1 to 3 of the module doc).
    pub fn simple_class(&self, file: &str, cname: &str) -> Option<ClassRef> {
        for namespace in self.chain(file) {
            if self.declares(namespace, cname) {
                return Some((namespace.clone(), cname.to_string()));
            }
        }
        for using in self.usings_of(file) {
            if let CSharpUsing::Alias { alias, target } = using
                && alias == cname
            {
                return self.directive_class(file, target);
            }
        }
        let mut found: Option<&str> = None;
        for using in self.usings_of(file) {
            if let CSharpUsing::Namespace(namespace) = using
                && self.declares(namespace, cname)
            {
                match found {
                    None => found = Some(namespace),
                    Some(other) if other != namespace => return None,
                    Some(_) => {}
                }
            }
        }
        found.map(|namespace| (namespace.to_string(), cname.to_string()))
    }

    /// The class that `name`, simple or dotted, designates in `file`: a
    /// dotted name whose first part is an alias of the file goes through
    /// the alias target. Used for the edges of the graph (see the module
    /// doc for why [`Visibility::binding`] does not resolve dotted names).
    pub fn class(&self, file: &str, name: &str) -> Option<ClassRef> {
        let Some((first, rest)) = name.split_once('.') else {
            return self.simple_class(file, name);
        };
        if let Some(target) = self.alias_target(file, first) {
            return self.directive_class(file, &join_namespace(target, rest));
        }
        self.qualified_class(file, name)
    }

    fn alias_target<'a>(&'a self, file: &str, alias: &str) -> Option<&'a str> {
        self.usings_of(file).find_map(|using| match using {
            CSharpUsing::Alias { alias: a, target } if a == alias => Some(target.as_str()),
            _ => None,
        })
    }

    /// The file that defines the method `cname.method` of class `class`,
    /// preferring `prefer` when it does (see the module doc).
    pub fn defining_file(&self, class: &ClassRef, method: &str, prefer: &str) -> Option<String> {
        let (namespace, cname) = class;
        let files = self.classes.get(namespace)?.get(cname)?;
        let key = format!("{cname}.{method}");
        let defines = |file: &str| {
            self.function_names
                .get(file)
                .is_some_and(|names| names.contains(&key))
        };
        if files.iter().any(|f| f == prefer) && defines(prefer) {
            return Some(prefer.to_string());
        }
        files.iter().rev().find(|f| defines(f)).cloned()
    }

    /// The method `Class.method` of `class` as a graph node, as seen from
    /// `file`.
    pub fn method_node(&self, class: &ClassRef, method: &str, file: &str) -> Option<NodeKey> {
        let target = self.defining_file(class, method, file)?;
        Some((target, format!("{}.{method}", class.1)))
    }

    /// The method an instance call `obj.method()` reaches, `obj` of
    /// declared type `class`, as seen from `file` (ticket #284):
    ///   - the body `class` defines (or a file of the `partial` class
    ///     does), as [`Self::method_node`] finds it;
    ///   - otherwise, `class` being an interface or an abstract method
    ///     (no body, so no node), the one implementation among its subtypes
    ///     in the scan, direct or indirect: when exactly one of them
    ///     defines `method`, the call can only run that body. Two or more
    ///     implementations, or none, resolve nothing (a missed flow rather
    ///     than a guessed one; C# picks the body at run time).
    ///
    /// A virtual method with a body in `class` keeps that body even when a
    /// subtype overrides it, as before: the declared body is what the
    /// analysis has always followed.
    pub fn dispatch_method(&self, class: &ClassRef, method: &str, file: &str) -> Option<NodeKey> {
        if let Some(node) = self.method_node(class, method, file) {
            return Some(node);
        }
        let subtypes = self.subtypes();
        let mut seen: BTreeSet<&ClassRef> = BTreeSet::new();
        let mut stack: Vec<&ClassRef> = subtypes.get(class).into_iter().flatten().collect();
        let mut found: Option<NodeKey> = None;
        while let Some(sub) = stack.pop() {
            if sub == class || !seen.insert(sub) {
                continue;
            }
            if let Some(node) = self.method_node(sub, method, file) {
                match &found {
                    None => found = Some(node),
                    Some(other) if *other != node => return None,
                    Some(_) => {}
                }
            }
            stack.extend(subtypes.get(sub).into_iter().flatten());
        }
        found
    }

    /// Type → its direct subtypes ([`Self::subtypes`] field), built once.
    /// A base name the declaring file cannot resolve to an analyzed type
    /// (`Controller`, `IDisposable`) is skipped.
    fn subtypes(&self) -> &BTreeMap<ClassRef, BTreeSet<ClassRef>> {
        self.subtypes.get_or_init(|| {
            let mut out: BTreeMap<ClassRef, BTreeSet<ClassRef>> = BTreeMap::new();
            for (class, file, bases) in &self.declared_bases {
                for base in bases {
                    if let Some(resolved) = self.simple_class(file, base)
                        && &resolved != class
                    {
                        out.entry(resolved).or_default().insert(class.clone());
                    }
                }
            }
            out
        })
    }

    /// The method that the bare name `method` designates in `file` through
    /// its `using static` directives: exactly one imported class must
    /// define it.
    pub fn static_method(&self, file: &str, method: &str) -> Option<NodeKey> {
        let mut found: Option<NodeKey> = None;
        for using in self.usings_of(file) {
            let CSharpUsing::Static(target) = using else {
                continue;
            };
            let Some(class) = self.directive_class(file, target) else {
                continue;
            };
            if let Some(node) = self.method_node(&class, method, file) {
                match &found {
                    None => found = Some(node),
                    Some(other) if *other != node => return None,
                    Some(_) => {}
                }
            }
        }
        found
    }

    /// SHA-256 of the classes of `namespace`, their files and the method
    /// names of those files (`""` for a namespace no file declares a class
    /// in). Computed once for every namespace.
    fn namespace_digest(&self, namespace: &str) -> &str {
        let digests = self.namespace_digests.get_or_init(|| {
            self.classes
                .iter()
                .map(|(namespace, by_name)| {
                    let mut hasher = Sha256::new();
                    let mut files: BTreeSet<&str> = BTreeSet::new();
                    for (cname, defining) in by_name {
                        hasher.update(cname.as_bytes());
                        for file in defining {
                            hasher.update(b"=");
                            hasher.update(file.as_bytes());
                            files.insert(file);
                        }
                        hasher.update(b"\n");
                    }
                    for file in files {
                        hasher.update(file.as_bytes());
                        for name in self.function_names.get(file).into_iter().flatten() {
                            hasher.update(b" ");
                            hasher.update(name.as_bytes());
                        }
                        hasher.update(b"\n");
                    }
                    (namespace.clone(), hex(&hasher.finalize()))
                })
                .collect()
        });
        digests.get(namespace).map(String::as_str).unwrap_or("")
    }

    /// The namespaces where an alias or `using static` target `target`
    /// may resolve from `file` (the target itself as a namespace, or the
    /// namespace of the class it names, written relative to each namespace
    /// of the chain).
    fn directive_namespaces(&self, file: &str, target: &str) -> Vec<String> {
        let mut out = Vec::new();
        for namespace in self.chain(file) {
            let full = join_namespace(namespace, target);
            out.push(parent(&full).to_string());
            out.push(full);
        }
        out
    }

    /// Whether the directive target `target`, resolved relative to any
    /// namespace, may name a class of one of `namespaces` (or that
    /// namespace itself): a superset for [`Visibility::readers_of`].
    fn may_reach(target: &str, namespaces: &BTreeSet<&str>) -> bool {
        let target_parent = parent(target);
        namespaces.iter().any(|n| {
            *n == target
                || n.ends_with(&format!(".{target}"))
                || (!target_parent.is_empty()
                    && (*n == target_parent || n.ends_with(&format!(".{target_parent}"))))
        })
    }

    /// Whether `using` may make a class of `namespaces` visible.
    fn using_reaches(using: &CSharpUsing, namespaces: &BTreeSet<&str>) -> bool {
        match using {
            CSharpUsing::Namespace(namespace) => namespaces.contains(namespace.as_str()),
            CSharpUsing::Alias { target, .. } | CSharpUsing::Static(target) => {
                Self::may_reach(target, namespaces)
            }
        }
    }
}

impl Visibility for CSharpVisibility {
    /// The method that the call key `key` designates in `file` through
    /// what it sees of the other files: a bare name through `using
    /// static`, `C.M` through the class `C` the simple name designates (or
    /// an alias-qualified `X.C.M`). Other dotted prefixes (`this.M`,
    /// `obj.M`, `A.B.C.M`) are left to the edges of the graph.
    fn binding(&self, file: &str, key: &str) -> Option<NodeKey> {
        let Some((prefix, method)) = key.rsplit_once('.') else {
            return self.static_method(file, key);
        };
        let class = match prefix.split_once('.') {
            None => self.simple_class(file, prefix)?,
            Some((first, rest)) => {
                let target = self.alias_target(file, first)?;
                self.directive_class(file, &join_namespace(target, rest))?
            }
        };
        self.method_node(&class, method, file)
    }

    /// The files that may read one of `changed` through
    /// [`Self::binding`], as a superset: every file whose lookup chain
    /// holds a namespace of a class declared by a file defining a changed
    /// method (a change in the global namespace reaches every file), and
    /// every file with a `using` directive that may reach such a namespace
    /// (a `global using` one reaches every file).
    fn readers_of(&self, changed: &BTreeSet<NodeKey>) -> BTreeSet<String> {
        let namespaces: BTreeSet<&str> = changed
            .iter()
            .filter_map(|node| self.namespaces_of_file.get(&node.0))
            .flatten()
            .map(String::as_str)
            .collect();
        if namespaces.is_empty() {
            return BTreeSet::new();
        }
        if self
            .global_usings
            .iter()
            .any(|using| Self::using_reaches(using, &namespaces))
        {
            return self.chains.keys().cloned().collect();
        }
        let mut readers = BTreeSet::new();
        for (file, chain) in &self.chains {
            if chain.iter().any(|n| namespaces.contains(n.as_str())) {
                readers.insert(file.clone());
            }
        }
        for (file, usings) in &self.usings {
            if usings
                .iter()
                .any(|using| Self::using_reaches(using, &namespaces))
            {
                readers.insert(file.clone());
            }
        }
        readers
    }

    /// What `file` sees of the other files, as text for the scan cache:
    /// each namespace of its chain and each directive that applies to it,
    /// with a SHA-256 of the class and method names of every namespace
    /// they may reach. Any change to what [`Self::binding`] answers for
    /// `file` changes this text.
    fn dependency_fingerprint(&self, file: &str) -> String {
        let mut out = String::new();
        for namespace in self.chain(file) {
            out.push_str(&format!(
                "namespace {namespace} {}\n",
                self.namespace_digest(namespace)
            ));
        }
        for using in self.usings_of(file) {
            match using {
                CSharpUsing::Namespace(namespace) => out.push_str(&format!(
                    "using {namespace} {}\n",
                    self.namespace_digest(namespace)
                )),
                CSharpUsing::Alias { alias, target } => {
                    out.push_str(&format!("alias {alias}={target}"));
                    for namespace in self.directive_namespaces(file, target) {
                        out.push_str(&format!(" {}", self.namespace_digest(&namespace)));
                    }
                    out.push('\n');
                }
                CSharpUsing::Static(target) => {
                    out.push_str(&format!("static {target}"));
                    for namespace in self.directive_namespaces(file, target) {
                        out.push_str(&format!(" {}", self.namespace_digest(&namespace)));
                    }
                    out.push('\n');
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::csharp_namespaces::collect_csharp_scope;

    /// The visibility of `files` (`(path, source)`), each method name
    /// listed by hand as `Class.Method`.
    fn visibility(files: &[(&str, &str, &[&str])]) -> CSharpVisibility {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .unwrap();
        let mut scopes = BTreeMap::new();
        let mut names = BTreeMap::new();
        for (path, src, methods) in files {
            let tree = parser.parse(src, None).unwrap();
            assert!(!tree.root_node().has_error(), "invalid C#: {src:?}");
            scopes.insert(
                path.to_string(),
                collect_csharp_scope(tree.root_node(), src.as_bytes()),
            );
            names.insert(
                path.to_string(),
                methods.iter().map(|m| m.to_string()).collect(),
            );
        }
        CSharpVisibility::new(&scopes, names)
    }

    fn node(file: &str, name: &str) -> Option<NodeKey> {
        Some((file.to_string(), name.to_string()))
    }

    #[test]
    fn test_same_namespace_is_visible_without_using() {
        let v = visibility(&[
            ("A.cs", "namespace App { class A {} }", &[]),
            ("B.cs", "namespace App { class B {} }", &["B.Run"]),
        ]);
        assert_eq!(v.binding("A.cs", "B.Run"), node("B.cs", "B.Run"));
        assert_eq!(v.binding("A.cs", "B.Other"), None);
    }

    #[test]
    fn test_enclosing_namespace_is_visible() {
        let v = visibility(&[
            ("A.cs", "namespace App.Web { class A {} }", &[]),
            ("B.cs", "namespace App { class B {} }", &["B.Run"]),
            ("G.cs", "class G {}", &["G.Run"]),
        ]);
        assert_eq!(v.binding("A.cs", "B.Run"), node("B.cs", "B.Run"));
        assert_eq!(v.binding("A.cs", "G.Run"), node("G.cs", "G.Run"));
        // A child namespace is not visible from its parent.
        let v = visibility(&[
            ("A.cs", "namespace App { class A {} }", &[]),
            ("B.cs", "namespace App.Data { class B {} }", &["B.Run"]),
        ]);
        assert_eq!(v.binding("A.cs", "B.Run"), None);
    }

    #[test]
    fn test_using_namespace_alias_and_static() {
        let v = visibility(&[
            (
                "A.cs",
                "using App.Data;\nusing R = App.Data.Repo;\nusing static App.Data.Sql;\nnamespace App.Web { class A {} }",
                &[],
            ),
            (
                "B.cs",
                "namespace App.Data { class Repo {} static class Sql {} }",
                &["Repo.Find", "Sql.Query"],
            ),
        ]);
        assert_eq!(v.binding("A.cs", "Repo.Find"), node("B.cs", "Repo.Find"));
        assert_eq!(v.binding("A.cs", "R.Find"), node("B.cs", "Repo.Find"));
        assert_eq!(v.binding("A.cs", "Query"), node("B.cs", "Sql.Query"));
        assert_eq!(
            v.class("A.cs", "App.Data.Repo"),
            Some(("App.Data".into(), "Repo".into()))
        );
        // Dotted prefixes are left to the edges.
        assert_eq!(v.binding("A.cs", "App.Data.Repo.Find"), None);
    }

    #[test]
    fn test_global_using_applies_to_every_file() {
        let v = visibility(&[
            ("G.cs", "global using App.Data;", &[]),
            ("A.cs", "namespace App.Web { class A {} }", &[]),
            ("B.cs", "namespace App.Data;\nclass Repo {}", &["Repo.Find"]),
        ]);
        assert_eq!(v.binding("A.cs", "Repo.Find"), node("B.cs", "Repo.Find"));
        let changed = BTreeSet::from([("B.cs".to_string(), "Repo.Find".to_string())]);
        assert_eq!(
            v.readers_of(&changed),
            BTreeSet::from(["A.cs".to_string(), "B.cs".to_string(), "G.cs".to_string()])
        );
    }

    #[test]
    fn test_ambiguous_using_resolves_nothing() {
        let v = visibility(&[
            ("A.cs", "using X;\nusing Y;\nclass A {}", &[]),
            ("X.cs", "namespace X { class Repo {} }", &["Repo.Find"]),
            ("Y.cs", "namespace Y { class Repo {} }", &["Repo.Find"]),
        ]);
        assert_eq!(v.binding("A.cs", "Repo.Find"), None);
    }

    #[test]
    fn test_partial_class_method_is_found_in_the_file_defining_it() {
        let v = visibility(&[
            ("P1.cs", "namespace App { partial class P {} }", &["P.One"]),
            ("P2.cs", "namespace App { partial class P {} }", &["P.Two"]),
        ]);
        assert_eq!(v.binding("P2.cs", "P.One"), node("P1.cs", "P.One"));
        assert_eq!(v.binding("P1.cs", "P.Two"), node("P2.cs", "P.Two"));
    }

    #[test]
    fn test_readers_are_the_files_that_may_see_the_namespace() {
        let v = visibility(&[
            ("A.cs", "namespace App { class A {} }", &[]),
            ("B.cs", "namespace App { class B {} }", &["B.Run"]),
            ("C.cs", "using App;\nnamespace Other { class C {} }", &[]),
            ("D.cs", "namespace Other { class D {} }", &[]),
        ]);
        let changed = BTreeSet::from([("B.cs".to_string(), "B.Run".to_string())]);
        assert_eq!(
            v.readers_of(&changed),
            BTreeSet::from(["A.cs".to_string(), "B.cs".to_string(), "C.cs".to_string()])
        );
    }

    #[test]
    fn test_fingerprint_changes_with_the_methods_of_a_visible_namespace() {
        let before = visibility(&[
            ("A.cs", "using App.Data;\nclass A {}", &[]),
            (
                "B.cs",
                "namespace App.Data { class Repo {} }",
                &["Repo.Find"],
            ),
        ]);
        let after = visibility(&[
            ("A.cs", "using App.Data;\nclass A {}", &[]),
            (
                "B.cs",
                "namespace App.Data { class Repo {} }",
                &["Repo.Find", "Repo.Add"],
            ),
        ]);
        assert_ne!(
            before.dependency_fingerprint("A.cs"),
            after.dependency_fingerprint("A.cs")
        );
    }
}
