//! Rule-independent preparation of the source files for the taint
//! analysis (ticket #192).
//!
//! Before a taint rule can run on a file, the engine collects the
//! file's functions, builds one CFG per function (plus one for the
//! module top level, for the languages that have one), lowers every
//! CFG node to IR and runs the constant pre-pass. None of these steps
//! reads the rule. They used to be redone for every rule (about 170
//! JavaScript rules) and, inside a function summary, for every
//! parameter probe: on `bountybench-main`, lowering alone was about
//! 65 % of the scan time and the function collection 23 %.
//!
//! A [`PreparedFile`] holds the result for one file. The scan builds it
//! once, in phase A right after parsing the file (ticket #281), and every
//! rule of the file's taint pass then reads it. It is read-only once
//! built, so the rules, which run in parallel, share it without copying.
//!
//! **No node of the parse tree (ticket #281)**: a prepared CFG keeps its
//! IR, its shape and what its conditions prove, a prepared function its
//! metadata, but neither the CFG nor any `tree_sitter::Node`. The tree of
//! a file is only read while the file is prepared ([`CollectedFunction`]
//! holds a body node that long), then dropped: the trees, about 17 times
//! the size of their files, were 38 to 45 % of the peak memory of a scan
//! of the Juliet suites when every tree stayed until its pass ended.
//!
//! Cost: the IR of every file of the pass stays in memory until the
//! pass ends, instead of living only while one rule analyzes one file.

use std::collections::BTreeMap;

use super::call_graph::NodeKey;
use super::cfg::Cfg;
use super::lattice::State;
use super::line_facts::RuleLines;
use super::transfer::RuleSpecs;
use super::worklist::{AnalysisResult, PreparedIr, analyze_prepared};

/// One CFG prepared for every taint rule ([`PreparedIr`]): its IR, its
/// shape and what its conditions prove, without the CFG itself, whose
/// nodes point into the parse tree (ticket #281). It outlives the tree
/// of its file: the scan prepares a file then drops its tree.
pub struct PreparedCfg {
    ir: PreparedIr,
}

impl PreparedCfg {
    /// Prepares `cfg` with the language preparation `prepare` (one of
    /// the `worklist::prepare_*ir` functions), then drops the CFG: what
    /// the analysis reads of it is in the preparation.
    pub fn new<'tree>(
        cfg: Cfg<'tree>,
        source: &'tree [u8],
        prepare: fn(&Cfg<'tree>, &'tree [u8]) -> PreparedIr,
    ) -> Self {
        PreparedCfg {
            ir: prepare(&cfg, source),
        }
    }

    /// The preparation of the CFG.
    pub fn ir(&self) -> &PreparedIr {
        &self.ir
    }

    /// The exit node of the CFG, whose entry state an analysis gives in
    /// `AnalysisResult::state_in` (the state a function returns with).
    pub fn exit(&self) -> usize {
        self.ir.exit()
    }

    /// Runs one taint rule on this CFG (`worklist::analyze_prepared`).
    pub fn analyze(
        &self,
        specs: &RuleSpecs,
        initial_state: Option<&State>,
        source_lines: Option<&RuleLines>,
    ) -> AnalysisResult {
        analyze_prepared(&self.ir, specs, initial_state, source_lines)
    }
}

/// A function as the collection reads it from the parse tree: its
/// metadata `F`, which holds no node of the tree, and the node of its body,
/// which the preparation builds the CFG from and the call graph reads the
/// calls of (Java, JavaScript, PHP, C#; Python has its own,
/// `summary::CollectedPythonFunction`). It lives only while the file is
/// prepared (ticket #281): [`PreparedFunction`] keeps the metadata alone.
pub struct CollectedFunction<'tree, F> {
    /// Name, parameters, line…
    pub info: F,
    /// The body (`block`, `constructor_body`, `statement_block`…).
    pub body: tree_sitter::Node<'tree>,
}

/// A collected function reads as its metadata (`function.name`).
impl<F> std::ops::Deref for CollectedFunction<'_, F> {
    type Target = F;

    fn deref(&self) -> &F {
        &self.info
    }
}

/// One collected function of a file and its prepared body. `F` is the
/// language's function metadata (`FunctionInfo`, `JsFunctionInfo`...).
pub struct PreparedFunction<F> {
    /// What the collection found: name, parameters, line, body node.
    pub info: F,
    /// The prepared CFG of the body. `None` only for a Python function
    /// whose body is missing from a malformed tree: the analysis has
    /// always skipped those (`summary::compute_summary`).
    pub body: Option<PreparedCfg>,
}

/// Everything the taint rules need from one file, prepared once.
pub struct PreparedFile<F> {
    /// The module top level, for the languages analyzed there (Python,
    /// JavaScript, PHP); `None` for Java and C#, where executable code
    /// only lives in methods.
    pub module: Option<PreparedCfg>,
    /// Every function in collection order, homonyms included: the call
    /// graph keeps only one function per name, but the taint analysis
    /// of a file has always covered all of them.
    pub functions: Vec<PreparedFunction<F>>,
}

/// The prepared files of a call graph, and where each graph node lives
/// in them. The graph prepares its files once when it is built, then
/// reads them to compute the summaries of every rule and hands them to
/// the taint analysis of each file (ticket #192).
pub struct PreparedFiles<F> {
    files: BTreeMap<String, PreparedFile<F>>,
    /// Graph node → index of its function in its file's `functions`.
    node_index: BTreeMap<NodeKey, usize>,
}

impl<F> Default for PreparedFiles<F> {
    fn default() -> Self {
        PreparedFiles {
            files: BTreeMap::new(),
            node_index: BTreeMap::new(),
        }
    }
}

impl<F> PreparedFiles<F> {
    /// Adds the prepared `file` at `filepath`.
    pub fn insert_file(&mut self, filepath: String, file: PreparedFile<F>) {
        self.files.insert(filepath, file);
    }

    /// Records that graph node `key` is function number `index` of its
    /// file. Called in the same order as the graph inserts its nodes,
    /// so that for homonyms the last function wins in both.
    pub fn index_node(&mut self, key: NodeKey, index: usize) {
        self.node_index.insert(key, index);
    }

    /// The prepared file at `filepath`.
    pub fn file(&self, filepath: &str) -> Option<&PreparedFile<F>> {
        self.files.get(filepath)
    }

    /// The prepared function behind graph node `key`.
    pub fn function(&self, key: &NodeKey) -> Option<&PreparedFunction<F>> {
        let index = *self.node_index.get(key)?;
        self.files.get(&key.0)?.functions.get(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dataflow::cfg::build_cfg;
    use crate::scan::dataflow::worklist::{IR_PREPARATIONS, prepare_ir};

    /// The preparation runs when the `PreparedCfg` is built, never again
    /// when it is analyzed, however many rules or probes read it.
    #[test]
    fn test_analyzing_a_prepared_cfg_does_not_prepare_it_again() {
        let src = "x = input()\nos.system(x)\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let before = IR_PREPARATIONS.with(|count| count.get());
        let prepared =
            PreparedCfg::new(build_cfg(&tree, src.as_bytes()), src.as_bytes(), prepare_ir);
        let specs = RuleSpecs {
            rule_id: "test-rule".to_string(),
            severity: "HIGH".to_string(),
            cwe: None,
            message: "test finding".to_string(),
            sources: vec![crate::scan::dataflow::transfer::SourceSpec::new(
                "input", "http",
            )],
            sinks: vec![crate::scan::dataflow::transfer::SinkSpec::new("os.system")],
            sanitizers: vec![],
            passthroughs: vec![],
            summaries: Default::default(),
            type_map: Default::default(),
            summary_fallback: None,
            exprs: None,
        };
        for _ in 0..3 {
            assert_eq!(prepared.analyze(&specs, None, None).findings.len(), 1);
        }
        assert_eq!(IR_PREPARATIONS.with(|count| count.get()) - before, 1);
    }
}
