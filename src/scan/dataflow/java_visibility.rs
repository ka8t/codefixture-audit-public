//! What a Java file sees of the other analyzed files: the classes of its
//! package, those of its imports, and the static members it imports. The
//! call graph (`java_call_graph.rs`) resolves its edges with it, and the
//! taint analysis of each file looks up the summaries of the methods it
//! sees through it (ticket #239).
//!
//! **Deliberate deviation from the Python source and from the first Rust
//! port** (`Audit/sca/dataflow/java_call_graph.py`, which builds the same
//! data): both copied, for every file, a map of everything it sees
//! (`visible_classes`, then `import_bindings` with one entry per method of
//! each visible class), and the taint pass copied it again, with the
//! summaries, for every rule. A class of the same package is visible
//! without an import, so each copy holds the whole package: memory and
//! time grew with the square of the package size. On the Juliet Java suite
//! (46,793 files, packages of up to 1,405 files, 22 taint rules), the scan
//! was killed by macOS at about 127 GB. Here each file keeps only its own
//! imports, and a lookup walks a per-package index of the classes. The
//! answers are those of the copies, in the same order of precedence; the
//! test `test_lookups_match_the_materialized_maps` checks it against the
//! former construction, kept as the test oracle.
//!
//! Order of precedence, as in the former maps (later writes won):
//!   1. a class of the same package, defined in another file (the last
//!      such file in path order when several define it);
//!   2. overridden by the non-static imports, in source order, the last
//!      one that provides the name winning (`import pkg.Class;` when one
//!      analyzed file defines `pkg.Class`, `import pkg.*;` like the
//!      package, from another file);
//!   3. for a method key `Class.method`, the longest visible class prefix
//!      of the key whose file defines that method;
//!   4. overridden by the static imports (`import static pkg.Class.m;`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use super::call_graph::NodeKey;
use super::java_module_registry::{JavaImportInfo, build_static_import_bindings};
use super::visibility::{NameDigests, Visibility, hex};

/// No static import: shared empty map, so that [`JavaVisibility::statics`]
/// can always return a reference.
static NO_STATICS: BTreeMap<String, NodeKey> = BTreeMap::new();

/// A non-static import, resolved once against the analyzed files.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClassImport {
    /// `import pkg.Class;` whose fully qualified name exactly one analyzed
    /// file defines: binds the simple name `cname` to that file. An
    /// ambiguous or unknown name binds nothing (anti-FP, as before).
    Class { cname: String, file: String },
    /// `import pkg.*;`: every class of the package `pkg`.
    Package(String),
}

/// What each analyzed Java file sees of the others (see the module doc).
/// Built once per scan by `JavaCallGraph::build`, shared by every rule.
#[derive(Default)]
pub struct JavaVisibility {
    /// Declared package of each file (`""`: the default package).
    package_of: BTreeMap<String, String>,
    /// Package → simple class name → files defining it, in path order.
    classes: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    /// Non-static imports of each file, in source order.
    imports: BTreeMap<String, Vec<ClassImport>>,
    /// Static imports of each file: bare name → method.
    statics: BTreeMap<String, BTreeMap<String, NodeKey>>,
    /// Dotted method names (`Class.method`) defined by each file.
    function_names: BTreeMap<String, BTreeSet<String>>,
    /// SHA-256 of what each package exposes, computed on first use by
    /// [`Visibility::dependency_fingerprint`].
    package_digests: OnceLock<BTreeMap<String, String>>,
    /// SHA-256 of the method names of each file, computed on first use.
    name_digests: NameDigests,
}

impl fmt::Debug for JavaVisibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JavaVisibility")
            .field("files", &self.package_of.len())
            .field("packages", &self.classes.len())
            .finish()
    }
}

impl JavaVisibility {
    /// Indexes the analyzed files. `class_names_by_file`: file → (package,
    /// simple class names); `imports_by_file`: file → its imports;
    /// `fqcn_index`: fully qualified class name → its only defining file
    /// (`None` when several define it); `function_names`: file → dotted
    /// method names.
    pub fn new(
        class_names_by_file: &BTreeMap<String, (String, Vec<String>)>,
        imports_by_file: &BTreeMap<String, Vec<JavaImportInfo>>,
        fqcn_index: &BTreeMap<String, Option<String>>,
        function_names: BTreeMap<String, BTreeSet<String>>,
    ) -> Self {
        let mut package_of = BTreeMap::new();
        let mut classes: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
        // `class_names_by_file` is in path order: each list of files ends
        // up in path order too, as the former maps iterated them.
        for (file, (package, class_names)) in class_names_by_file {
            package_of.insert(file.clone(), package.clone());
            let by_name = classes.entry(package.clone()).or_default();
            for cname in class_names {
                let files = by_name.entry(cname.clone()).or_default();
                if files.last() != Some(file) {
                    files.push(file.clone());
                }
            }
        }
        let mut imports = BTreeMap::new();
        let mut statics = BTreeMap::new();
        for (file, file_imports) in imports_by_file {
            let resolved: Vec<ClassImport> = file_imports
                .iter()
                .filter(|imp| !imp.is_static)
                .filter_map(|imp| {
                    if imp.wildcard {
                        return Some(ClassImport::Package(imp.path.clone()));
                    }
                    let Some(Some(target)) = fqcn_index.get(&imp.path) else {
                        return None;
                    };
                    let cname = imp.path.rsplit('.').next().unwrap_or(&imp.path);
                    Some(ClassImport::Class {
                        cname: cname.to_string(),
                        file: target.clone(),
                    })
                })
                .collect();
            if !resolved.is_empty() {
                imports.insert(file.clone(), resolved);
            }
            let file_statics =
                build_static_import_bindings(file, file_imports, fqcn_index, &function_names);
            if !file_statics.is_empty() {
                statics.insert(file.clone(), file_statics);
            }
        }
        JavaVisibility {
            package_of,
            classes,
            imports,
            statics,
            function_names,
            package_digests: OnceLock::new(),
            name_digests: NameDigests::default(),
        }
    }

    /// The static imports of `file`: bare name → method.
    pub fn statics(&self, file: &str) -> &BTreeMap<String, NodeKey> {
        self.statics.get(file).unwrap_or(&NO_STATICS)
    }

    /// The last file, in path order, of package `package` that defines the
    /// class `cname`, other than `file`.
    fn last_in_package_except<'a>(
        &'a self,
        package: &str,
        cname: &str,
        file: &str,
    ) -> Option<&'a str> {
        self.classes
            .get(package)?
            .get(cname)?
            .iter()
            .rev()
            .find(|f| f.as_str() != file)
            .map(String::as_str)
    }

    /// The file defining the class that the simple name `cname` designates
    /// in `file`, through its package or its non-static imports (rules 1
    /// and 2 of the module doc); `None` when it sees no such class. A class
    /// of `file` itself is not looked up here: the caller checks it first.
    pub fn visible_class(&self, file: &str, cname: &str) -> Option<&str> {
        for import in self.imports.get(file).into_iter().flatten().rev() {
            match import {
                ClassImport::Class {
                    cname: imported,
                    file: target,
                } if imported == cname => return Some(target),
                ClassImport::Package(package) => {
                    if let Some(target) = self.last_in_package_except(package, cname, file) {
                        return Some(target);
                    }
                }
                ClassImport::Class { .. } => {}
            }
        }
        let package = self.package_of.get(file)?;
        self.last_in_package_except(package, cname, file)
    }

    /// True when `node` is the method that one of the keys of `file`
    /// designates (the former `import_bindings[file]` had it as a value).
    /// A class binding has the method's own dotted name as its key; a
    /// static import binds a bare name.
    #[cfg(test)]
    pub fn is_binding_target(&self, file: &str, node: &NodeKey) -> bool {
        self.binding(file, &node.1).as_ref() == Some(node)
            || self.statics(file).values().any(|target| target == node)
    }

    /// SHA-256 of the classes of `package`, their files and the method
    /// names of those files. Computed once for every package.
    fn package_digest(&self, package: &str) -> &str {
        let digests = self.package_digests.get_or_init(|| {
            self.classes
                .iter()
                .map(|(package, by_name)| {
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
                    (package.clone(), hex(&hasher.finalize()))
                })
                .collect()
        });
        digests.get(package).map(String::as_str).unwrap_or("")
    }
}

impl Visibility for JavaVisibility {
    /// The method that the call key `key` designates in `file` through
    /// what it sees of the other files (rules 3 and 4 of the module doc):
    /// a static import of that bare name, else `Class.method` of the
    /// longest visible class prefix of `key` whose file defines the method.
    fn binding(&self, file: &str, key: &str) -> Option<NodeKey> {
        if let Some(target) = self.statics(file).get(key) {
            return Some(target.clone());
        }
        // Longest prefix first, the former order (a longer class name
        // sorted later and overwrote). The collected class names are
        // simple (top-level classes, last segment of an import), so at
        // most one prefix of a key is a class name today: the order only
        // matters if nested class names are collected one day.
        for (dot, _) in key.rmatch_indices('.') {
            let cname = &key[..dot];
            if let Some(target) = self.visible_class(file, cname)
                && self
                    .function_names
                    .get(target)
                    .is_some_and(|names| names.contains(key))
            {
                return Some((target.to_string(), key.to_string()));
            }
        }
        None
    }

    /// What `file` sees of the other files, as text for the scan cache
    /// (`dependency_fingerprint`): its package and its imports, each with
    /// a SHA-256 of the class and method names it exposes, and its static
    /// imports. Any change to what [`Self::binding`] answers for `file`
    /// changes this text. It also changes when a name changes that `file`
    /// does not use, which only redoes that file in the next scan.
    fn dependency_fingerprint(&self, file: &str) -> String {
        let mut out = String::new();
        if let Some(package) = self.package_of.get(file) {
            out.push_str(&format!(
                "package {package} {}\n",
                self.package_digest(package)
            ));
        }
        for import in self.imports.get(file).into_iter().flatten() {
            match import {
                ClassImport::Class {
                    cname,
                    file: target,
                } => out.push_str(&format!(
                    "import {cname}={target} {}\n",
                    self.name_digests.get(&self.function_names, target)
                )),
                ClassImport::Package(package) => out.push_str(&format!(
                    "import {package}.* {}\n",
                    self.package_digest(package)
                )),
            }
        }
        for (name, target) in self.statics(file) {
            out.push_str(&format!("static {name}={}#{}\n", target.0, target.1));
        }
        out
    }

    /// The files that may read one of `changed`, as a superset (approved
    /// on 2026-11-21, ticket #239): every file of the package of a file
    /// defining a changed method, the files importing that file's class
    /// or that package (`import pkg.*`), and those importing a changed
    /// method statically. The exact answer (a changed method of a class
    /// the file sees) would need, for every file of a package, every class
    /// of it: the square of the package again. A file sees every class of
    /// its package, so the superset only adds the files where another
    /// class of the same name shadows the changed one.
    fn readers_of(&self, changed: &BTreeSet<NodeKey>) -> BTreeSet<String> {
        let changed_files: BTreeSet<&str> = changed.iter().map(|node| node.0.as_str()).collect();
        let packages: BTreeSet<&str> = changed_files
            .iter()
            .filter_map(|file| self.package_of.get(*file).map(String::as_str))
            .collect();
        let mut readers = BTreeSet::new();
        for (file, package) in &self.package_of {
            if packages.contains(package.as_str()) {
                readers.insert(file.clone());
            }
        }
        for (file, imports) in &self.imports {
            let reads = imports.iter().any(|import| match import {
                ClassImport::Class { file: target, .. } => changed_files.contains(target.as_str()),
                ClassImport::Package(package) => packages.contains(package.as_str()),
            });
            if reads {
                readers.insert(file.clone());
            }
        }
        for (file, statics) in &self.statics {
            if statics.values().any(|target| changed.contains(target)) {
                readers.insert(file.clone());
            }
        }
        readers
    }
}
