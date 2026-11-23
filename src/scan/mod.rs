//! The scan itself: discovers the files, parses the `.sca` rules, runs
//! them, and performs the taint analysis. `orchestrator` drives the
//! whole pipeline described in `docs/ARCHITECTURE.md`.

pub mod counters;
pub mod dataflow;
pub mod debug_log;
pub mod discovery;
pub mod engine;
pub mod memory;
pub mod minified;
pub mod orchestrator;
pub mod parser;
pub mod saved_page;
pub mod scan_cache;
pub mod unchanged;
