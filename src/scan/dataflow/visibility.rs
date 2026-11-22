//! What each analyzed file sees of the other files of its language, looked
//! up on demand (ticket #239).
//!
//! A call graph links the files of one language: a call name of a file
//! (`helper`, `utils.helper`, `Klass.method`) designates a function of
//! another file through its imports. The first port materialized, for
//! every file, a map of every name it could call (`import_bindings`), and
//! the taint pass copied that map again, with the summaries, for every
//! rule (`extra`). A file importing a whole module got one entry per
//! function of the module, a PHP file one entry per method of every class
//! of the project, a Java file one per method of every class of its
//! package: memory and time grew with the square of the project (PHP:
//! 20.6 GB for 2,000 files; Java: killed at about 127 GB on the Juliet
//! suite).
//!
//! Here a language keeps what each file imports, in source order, and a
//! [`Visibility`] answers the three questions the analysis asks:
//!
//! - [`Visibility::binding`]: the function a call name designates in a
//!   file, with the precedence of the former maps (each language
//!   documents its own);
//! - [`Visibility::readers_of`]: the files whose analysis reads a summary
//!   that changed, for the scan cache;
//! - [`Visibility::dependency_fingerprint`]: what a file sees of the
//!   others, for the scan cache.
//!
//! The taint analysis of a file finds the summaries it does not define
//! through a [`FileSummaries`] (`RuleSpecs::summary_fallback`), instead of
//! a copy per file and per rule. Each language's tests check its answers
//! against the former construction, kept there as the test oracle.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, OnceLock};

use sha2::{Digest, Sha256};

use super::call_graph::NodeKey;
use super::transfer::{FunctionSummary, SummaryLookup};

/// What the files of one call graph see of each other (see the module doc).
pub trait Visibility: Send + Sync {
    /// The function that the call name `key` designates in `file` through
    /// what `file` imports or sees; `None` when it designates none. The
    /// file's own functions are not looked up here: the caller checks them
    /// first.
    fn binding(&self, file: &str, key: &str) -> Option<NodeKey>;

    /// The files whose analysis reads one of the `changed` functions
    /// through a binding: those for which some call name designates it.
    /// A language may answer more files than that (a superset only
    /// re-analyses them, with the same findings), never fewer. The files
    /// defining a changed function are not included: the caller adds them.
    fn readers_of(&self, changed: &BTreeSet<NodeKey>) -> BTreeSet<String>;

    /// What `file` sees of the other files, as text for the scan cache: it
    /// changes whenever [`Self::binding`] could answer differently for
    /// `file` (it may also change when it does not, which only re-analyses
    /// the file).
    fn dependency_fingerprint(&self, file: &str) -> String;
}

/// The summaries one file sees through a [`Visibility`], looked up on
/// demand among the summaries of one rule ([`SummaryLookup`], set as
/// `RuleSpecs::summary_fallback` for the taint analysis of the file).
pub struct FileSummaries {
    visibility: Arc<dyn Visibility>,
    file: String,
    summaries: Arc<BTreeMap<NodeKey, Arc<FunctionSummary>>>,
}

impl FileSummaries {
    /// The lookup for `file`, among `summaries` (every summary of the rule).
    pub fn new(
        visibility: Arc<dyn Visibility>,
        file: &str,
        summaries: Arc<BTreeMap<NodeKey, Arc<FunctionSummary>>>,
    ) -> Self {
        FileSummaries {
            visibility,
            file: file.to_string(),
            summaries,
        }
    }
}

impl fmt::Debug for FileSummaries {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSummaries")
            .field("file", &self.file)
            .finish()
    }
}

impl SummaryLookup for FileSummaries {
    fn get(&self, callee_name: &str) -> Option<Arc<FunctionSummary>> {
        let target = self.visibility.binding(&self.file, callee_name)?;
        self.summaries.get(&target).cloned()
    }
}

/// The dependency fingerprint of `file` in a call graph: the edges of its
/// functions and their names (the lines of the former
/// `call_graph::dependency_fingerprint_in`), then what it sees of the other
/// files. The functions of `file` are read as a range of the sorted keys:
/// scanning every function of the project for every file cost a time
/// growing with the square of the project (ticket #239).
pub fn graph_fingerprint<T>(
    edges: &BTreeMap<NodeKey, BTreeMap<String, NodeKey>>,
    nodes: &BTreeMap<NodeKey, T>,
    visibility: &dyn Visibility,
    file: &str,
) -> String {
    let start = (file.to_string(), String::new());
    let mut out = String::new();
    for (node, targets) in edges.range(start.clone()..) {
        if node.0 != file {
            break;
        }
        out.push_str(&node.1);
        out.push('>');
        for (name, target) in targets {
            out.push_str(&format!("{name}={}#{};", target.0, target.1));
        }
        out.push('\n');
    }
    for (node, _) in nodes.range(start..) {
        if node.0 != file {
            break;
        }
        out.push_str(&format!("fn {}\n", node.1));
    }
    out.push_str(&visibility.dependency_fingerprint(file));
    out
}

/// Lowercase hexadecimal form of a digest.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of the function names of each file, computed once on first
/// use: the fingerprint of every file importing another reads its digest.
#[derive(Default)]
pub struct NameDigests {
    digests: OnceLock<BTreeMap<String, String>>,
}

impl NameDigests {
    /// The digest of the names of `file` in `function_names`; the digest
    /// of no name when the file has none.
    pub fn get<'a>(
        &'a self,
        function_names: &BTreeMap<String, BTreeSet<String>>,
        file: &str,
    ) -> &'a str {
        let digests = self.digests.get_or_init(|| {
            function_names
                .iter()
                .map(|(file, names)| {
                    let mut hasher = Sha256::new();
                    for name in names {
                        hasher.update(name.as_bytes());
                        hasher.update(b"\n");
                    }
                    (file.clone(), hex(&hasher.finalize()))
                })
                .collect()
        });
        digests.get(file).map(String::as_str).unwrap_or("")
    }
}

/// One import of a file, resolved to an analyzed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportEntry {
    /// A whole module bound to `local` (`import utils`, `const u =
    /// require('./u')`): `local.name` designates each function `name` of
    /// `target`.
    Module { local: String, target: String },
    /// One function `name` of `target` bound to `local` (`from utils import
    /// helper as h`, `const { helper } = require('./u')`). Only built when
    /// `target` defines `name`.
    Function {
        local: String,
        target: String,
        name: String,
    },
}

/// What the files of a Python, JavaScript or PHP call graph see of each
/// other: their imports, in source order, and for PHP the index of the
/// classes of the project.
///
/// [`Visibility::binding`] answers like the former per-file maps:
///
/// 1. a class method `Klass.method` of the class index (PHP), which the
///    former map wrote last (over the `require` bindings): of the class
///    names that prefix the key, the longest wins (written last, in name
///    order);
/// 2. the explicit imports ([`ImportEntry`]), the last one that binds the
///    name winning (each import overwrote the same names of the earlier
///    ones);
/// 3. the star imports (`from m import *`, PHP `require`): a name defined
///    by several of the imported files is dropped (anti-FP), and an
///    explicit import of the same name wins.
#[derive(Default)]
pub struct ImportVisibility {
    entries: BTreeMap<String, Vec<ImportEntry>>,
    star_targets: BTreeMap<String, Vec<String>>,
    /// Class name → its only defining file (`None`: defined by several
    /// files, never bound), PHP only.
    classes: BTreeMap<String, Option<String>>,
    /// Defining file → the class names the index binds to it.
    classes_by_file: BTreeMap<String, Vec<String>>,
    function_names: BTreeMap<String, BTreeSet<String>>,
    /// Whether `local.name` of a module import may designate a dotted
    /// function name (`Klass.method`): JavaScript yes, Python no.
    module_dotted_names: bool,
    /// Whether a star import binds dotted function names: PHP yes, Python
    /// no.
    star_dotted_names: bool,
    /// Imported file → the files importing it (any kind of import).
    importers: BTreeMap<String, BTreeSet<String>>,
    name_digests: NameDigests,
    classes_digest: OnceLock<String>,
}

impl ImportVisibility {
    /// Indexes the imports of every file. `entries` and `star_targets` are
    /// in source order; `function_names` lists the function names of every
    /// file of the graph (files without any included).
    pub fn new(
        entries: BTreeMap<String, Vec<ImportEntry>>,
        star_targets: BTreeMap<String, Vec<String>>,
        classes: BTreeMap<String, Option<String>>,
        function_names: BTreeMap<String, BTreeSet<String>>,
        module_dotted_names: bool,
        star_dotted_names: bool,
    ) -> Self {
        let mut importers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (file, file_entries) in &entries {
            for entry in file_entries {
                let target = match entry {
                    ImportEntry::Module { target, .. } | ImportEntry::Function { target, .. } => {
                        target
                    }
                };
                importers
                    .entry(target.clone())
                    .or_default()
                    .insert(file.clone());
            }
        }
        for (file, targets) in &star_targets {
            for target in targets {
                importers
                    .entry(target.clone())
                    .or_default()
                    .insert(file.clone());
            }
        }
        let mut classes_by_file: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (cname, file) in &classes {
            if let Some(file) = file {
                classes_by_file
                    .entry(file.clone())
                    .or_default()
                    .push(cname.clone());
            }
        }
        ImportVisibility {
            entries,
            star_targets,
            classes,
            classes_by_file,
            function_names,
            module_dotted_names,
            star_dotted_names,
            importers,
            name_digests: NameDigests::default(),
            classes_digest: OnceLock::new(),
        }
    }

    fn defines(&self, file: &str, name: &str) -> bool {
        self.function_names
            .get(file)
            .is_some_and(|names| names.contains(name))
    }

    /// Rule 1: `Klass.method` through the class index, the same for every
    /// file.
    fn class_binding(&self, key: &str) -> Option<NodeKey> {
        for (dot, _) in key.rmatch_indices('.') {
            let (cname, method) = (&key[..dot], &key[dot + 1..]);
            if let Some(Some(file)) = self.classes.get(cname)
                && self.defines(file, method)
            {
                return Some((file.clone(), method.to_string()));
            }
        }
        None
    }

    /// Whether the function `node` is what some call name designates in
    /// `file`: the names that could designate it are checked against
    /// [`Visibility::binding`], so that a name taken by a stronger binding
    /// does not count.
    fn binds(&self, file: &str, node: &NodeKey) -> bool {
        let (target, name) = node;
        let mut keys: Vec<String> = Vec::new();
        for entry in self.entries.get(file).into_iter().flatten() {
            match entry {
                ImportEntry::Module { local, target: t } if t == target => {
                    keys.push(format!("{local}.{name}"));
                }
                ImportEntry::Function {
                    local,
                    target: t,
                    name: n,
                } if t == target && n == name => keys.push(local.clone()),
                _ => {}
            }
        }
        if self
            .star_targets
            .get(file)
            .is_some_and(|targets| targets.contains(target))
        {
            keys.push(name.clone());
        }
        for cname in self.classes_by_file.get(target).into_iter().flatten() {
            keys.push(format!("{cname}.{name}"));
        }
        keys.iter()
            .any(|key| self.binding(file, key).as_ref() == Some(node))
    }
}

impl Visibility for ImportVisibility {
    fn binding(&self, file: &str, key: &str) -> Option<NodeKey> {
        if !self.classes.is_empty()
            && let Some(found) = self.class_binding(key)
        {
            return Some(found);
        }
        for entry in self.entries.get(file).into_iter().flatten().rev() {
            match entry {
                ImportEntry::Function {
                    local,
                    target,
                    name,
                } if local == key => return Some((target.clone(), name.clone())),
                ImportEntry::Module { local, target } => {
                    if let Some(name) = key
                        .strip_prefix(local.as_str())
                        .and_then(|rest| rest.strip_prefix('.'))
                        && (self.module_dotted_names || !name.contains('.'))
                        && self.defines(target, name)
                    {
                        return Some((target.clone(), name.to_string()));
                    }
                }
                ImportEntry::Function { .. } => {}
            }
        }
        if !self.star_dotted_names && key.contains('.') {
            return None;
        }
        let mut found: Option<&String> = None;
        for target in self.star_targets.get(file).into_iter().flatten() {
            if !self.defines(target, key) {
                continue;
            }
            match found {
                None => found = Some(target),
                Some(other) if other != target => return None,
                Some(_) => {}
            }
        }
        found.map(|target| (target.clone(), key.to_string()))
    }

    fn readers_of(&self, changed: &BTreeSet<NodeKey>) -> BTreeSet<String> {
        // A method bound through the class index is bound in every file.
        if changed.iter().any(|node| {
            self.classes_by_file
                .get(&node.0)
                .into_iter()
                .flatten()
                .any(|cname| {
                    self.class_binding(&format!("{cname}.{}", node.1)).as_ref() == Some(node)
                })
        }) {
            return self.function_names.keys().cloned().collect();
        }
        let mut by_target: BTreeMap<&str, Vec<&NodeKey>> = BTreeMap::new();
        for node in changed {
            by_target.entry(node.0.as_str()).or_default().push(node);
        }
        let mut readers = BTreeSet::new();
        for (target, nodes) in by_target {
            for file in self.importers.get(target).into_iter().flatten() {
                if nodes.iter().any(|node| self.binds(file, node)) {
                    readers.insert(file.clone());
                }
            }
        }
        readers
    }

    fn dependency_fingerprint(&self, file: &str) -> String {
        let mut out = String::new();
        for entry in self.entries.get(file).into_iter().flatten() {
            match entry {
                ImportEntry::Module { local, target } => out.push_str(&format!(
                    "module {local}={target} {}\n",
                    self.name_digests.get(&self.function_names, target)
                )),
                ImportEntry::Function {
                    local,
                    target,
                    name,
                } => out.push_str(&format!("function {local}={target}#{name}\n")),
            }
        }
        for target in self.star_targets.get(file).into_iter().flatten() {
            out.push_str(&format!(
                "star {target} {}\n",
                self.name_digests.get(&self.function_names, target)
            ));
        }
        if !self.classes.is_empty() {
            let digest = self.classes_digest.get_or_init(|| {
                let mut hasher = Sha256::new();
                for (cname, file) in &self.classes {
                    hasher.update(cname.as_bytes());
                    hasher.update(b"=");
                    if let Some(file) = file {
                        hasher.update(file.as_bytes());
                        hasher.update(b" ");
                        hasher.update(self.name_digests.get(&self.function_names, file).as_bytes());
                    }
                    hasher.update(b"\n");
                }
                hex(&hasher.finalize())
            });
            out.push_str(&format!("classes {digest}\n"));
        }
        out
    }
}
