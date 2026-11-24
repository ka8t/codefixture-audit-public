//! The share of the machine a scan may take (ticket #281): how many
//! threads it runs, and the most memory it may use. Resolved once, before
//! the scan starts, by the `scan` command, which sizes the thread pool with
//! [`ThreadLimit::threads`] and hands [`MemoryLimit::bytes`] to the memory
//! plan (`scan::memory::plan`).
//!
//! Each limit comes from the first of these sources that gives it:
//!
//! 1. the command-line option (`--cpu`, `--max-memory`);
//! 2. the environment variable of the machine ([`CPU_VARIABLE`],
//!    [`MAX_MEMORY_VARIABLE`]): set once on a shared office machine, it
//!    bounds every scan of every project without editing each command;
//! 3. the prudent default: every core but one ([`default_threads`]), and
//!    [`DEFAULT_MEMORY_PERCENT`] of the installed memory.
//!
//! The project's `audit.config.json` is deliberately not a source: it
//! belongs to the project and is often committed, while these limits
//! belong to the machine the scan runs on (ADR-0061).
//!
//! A value given but not understood is an error naming the source and the
//! value, never skipped for the next source: a user who set a limit
//! expects it to hold. Audit has no such limits (the Python engine runs on
//! one core); this module has no Python counterpart.

use std::ffi::OsString;

/// The command-line option of the thread limit.
pub const CPU_OPTION: &str = "--cpu";

/// The command-line option of the memory limit.
pub const MAX_MEMORY_OPTION: &str = "--max-memory";

/// The environment variable of the thread limit, same syntax as
/// [`CPU_OPTION`].
pub const CPU_VARIABLE: &str = "CODEFIXTURE_AUDIT_CPU";

/// The environment variable of the memory limit, same syntax as
/// [`MAX_MEMORY_OPTION`].
pub const MAX_MEMORY_VARIABLE: &str = "CODEFIXTURE_AUDIT_MAX_MEMORY";

/// The memory a scan may take by default, as a percentage of the installed
/// memory: 12 GB of a 16 GB office machine, leaving 4 GB to the system and
/// the programs open beside the scan. The estimate it is compared with is
/// above every measured peak and at most a third above it
/// (`scan::memory::estimate_bytes`): a scan planned to fit in 75 % takes at
/// most that much. The available memory still bounds the scan when it is
/// lower (`MemoryEstimate::allowed`). A project whose estimate passes it
/// first runs fewer taint rules at a time; with one rule it stops before
/// reading the files, and `--max-memory 100%` lifts the default.
pub const DEFAULT_MEMORY_PERCENT: u32 = 75;

/// One of the two limits, to name its option and variable in messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setting {
    /// The threads of the scan ([`CPU_OPTION`], [`CPU_VARIABLE`]).
    Cpu,
    /// The memory of the scan ([`MAX_MEMORY_OPTION`],
    /// [`MAX_MEMORY_VARIABLE`]).
    MaxMemory,
}

impl Setting {
    /// The command-line option of this limit.
    pub fn option(self) -> &'static str {
        match self {
            Setting::Cpu => CPU_OPTION,
            Setting::MaxMemory => MAX_MEMORY_OPTION,
        }
    }

    /// The environment variable of this limit.
    pub fn variable(self) -> &'static str {
        match self {
            Setting::Cpu => CPU_VARIABLE,
            Setting::MaxMemory => MAX_MEMORY_VARIABLE,
        }
    }
}

/// Where the value of a limit comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitOrigin {
    /// The command-line option.
    Option,
    /// The environment variable.
    Environment,
    /// Nothing was given: the prudent default.
    Default,
}

/// A value given for a limit by the user, as typed, and its source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitInput {
    /// The text as given (`4`, `50%`, `7.5`).
    pub value: String,
    /// [`LimitOrigin::Option`] or [`LimitOrigin::Environment`].
    pub origin: LimitOrigin,
}

impl LimitInput {
    /// The source and value as the user wrote them, for messages:
    /// `--cpu 50%` or `CODEFIXTURE_AUDIT_CPU=50%`.
    pub fn display(&self, setting: Setting) -> String {
        match self.origin {
            LimitOrigin::Environment => format!("{}={}", setting.variable(), self.value),
            _ => format!("{} {}", setting.option(), self.value),
        }
    }
}

/// Why a limit given by the user cannot be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitErrorKind {
    /// The text is neither a count (or GB) nor a percentage in range: `0`,
    /// `150%`, `abc`, an empty or non-UTF-8 variable.
    Invalid,
    /// A percentage of the installed memory on a system that does not tell
    /// it (`scan::memory::system_memory`).
    PercentOfUnknownMemory,
}

/// A limit given by the user that cannot be applied: the scan stops before
/// it starts and names the source and the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitError {
    /// Which limit.
    pub setting: Setting,
    /// The value and its source.
    pub input: LimitInput,
    /// Why it cannot be applied.
    pub kind: LimitErrorKind,
}

impl LimitError {
    /// The option or variable that held the value: what to correct.
    pub fn source_name(&self) -> &'static str {
        match self.input.origin {
            LimitOrigin::Environment => self.setting.variable(),
            _ => self.setting.option(),
        }
    }
}

/// A thread limit as asked: a count of threads or a share of the cores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuRequest {
    /// `N`: N threads, N ≥ 1.
    Threads(usize),
    /// `N%`: N % of the cores, 1 ≤ N ≤ 100.
    Percent(u32),
}

/// A memory limit as asked: a size or a share of the installed memory.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryRequest {
    /// `N`: N GB (GiB, 2^30 bytes, like the console figures), N > 0.
    Gigabytes(f64),
    /// `N%`: N % of the installed memory, 1 ≤ N ≤ 100.
    Percent(u32),
}

/// `N%` with N a whole number from 1 to 100, the syntax shared by both
/// limits; `None` for anything else, including `0%`, `101%`, `50.5%`.
fn parse_percent(text: &str) -> Option<u32> {
    let digits = text.strip_suffix('%')?.trim_end();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u32>().ok().filter(|p| (1..=100).contains(p))
}

/// Parses a thread limit: `N` (a whole number of threads, at least 1) or
/// `N%` (a whole percentage of the cores, 1 to 100). Spaces around the
/// value are ignored; `None` for anything else, such as `0`, `-2`, `2.5`,
/// `150%` or `four`.
pub fn parse_cpu(text: &str) -> Option<CpuRequest> {
    let text = text.trim();
    if text.ends_with('%') {
        return parse_percent(text).map(CpuRequest::Percent);
    }
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<usize>()
        .ok()
        .filter(|n| *n >= 1)
        .map(CpuRequest::Threads)
}

/// Parses a memory limit: `N` (GB, a number above 0 with `.` as the
/// decimal separator, `8` or `7.5`) or `N%` (a whole percentage of the
/// installed memory, 1 to 100). `None` for anything else, such as `0`,
/// `7,5`, `8GB`, `150%`, `inf` or `NaN`.
///
/// Deviation from the option before ticket #281's resource limits: `0`
/// used to mean "no limit" (filtered out silently); it is now an error,
/// and `100%` is the way to let the scan take all the available memory.
pub fn parse_max_memory(text: &str) -> Option<MemoryRequest> {
    let text = text.trim();
    if text.ends_with('%') {
        return parse_percent(text).map(MemoryRequest::Percent);
    }
    // Digits and at most one dot only: `f64::from_str` would also take
    // `inf`, `NaN` and `1e3`, which no one means as a memory size.
    let dots = text.bytes().filter(|b| *b == b'.').count();
    if text.is_empty()
        || dots > 1
        || !text.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        || !text.bytes().any(|b| b.is_ascii_digit())
    {
        return None;
    }
    text.parse::<f64>()
        .ok()
        .filter(|gb| gb.is_finite() && *gb > 0.0)
        .map(MemoryRequest::Gigabytes)
}

/// The value of a limit from its sources, first given first taken: the
/// option, else the environment variable (`environment` is its value as
/// the system gives it, `None` when unset). A variable that is set but
/// empty or not UTF-8 is taken, and then rejected as invalid by the caller:
/// a variable set by mistake is shown, not passed over.
pub fn choose_input(option: Option<&str>, environment: Option<OsString>) -> Option<LimitInput> {
    if let Some(value) = option {
        return Some(LimitInput {
            value: value.to_string(),
            origin: LimitOrigin::Option,
        });
    }
    environment.map(|value| LimitInput {
        value: value.to_string_lossy().into_owned(),
        origin: LimitOrigin::Environment,
    })
}

/// The threads a scan runs, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadLimit {
    /// Threads of the scan's pool: every phase (discovery, A, B, C) runs
    /// on it, and the taint rules run at once are half of it
    /// (`taint::rule_lanes`).
    pub threads: usize,
    /// Cores of the machine (`std::thread::available_parallelism`).
    pub cores: usize,
    /// Where the limit comes from.
    pub origin: LimitOrigin,
    /// The value given, `None` for the default.
    pub input: Option<LimitInput>,
    /// The count given was above the cores and was lowered to them: more
    /// threads than cores only share the same cores and take more memory
    /// (more rules at once).
    pub capped_at_cores: bool,
}

/// The default thread count: every core but one, so that the machine
/// still answers while the scan runs, and at least one.
pub fn default_threads(cores: usize) -> usize {
    cores.saturating_sub(1).max(1)
}

/// The threads of a scan on a machine of `cores` cores, from the value
/// given (`input`) or [`default_threads`]. A percentage is rounded down,
/// to stay within the share asked for, and gives at least one thread.
pub fn resolve_threads(input: Option<LimitInput>, cores: usize) -> Result<ThreadLimit, LimitError> {
    let cores = cores.max(1);
    let Some(input) = input else {
        return Ok(ThreadLimit {
            threads: default_threads(cores),
            cores,
            origin: LimitOrigin::Default,
            input: None,
            capped_at_cores: false,
        });
    };
    let Some(request) = parse_cpu(&input.value) else {
        return Err(LimitError {
            setting: Setting::Cpu,
            input,
            kind: LimitErrorKind::Invalid,
        });
    };
    let (threads, capped_at_cores) = match request {
        CpuRequest::Threads(n) if n > cores => (cores, true),
        CpuRequest::Threads(n) => (n, false),
        CpuRequest::Percent(p) => ((cores * p as usize / 100).max(1), false),
    };
    Ok(ThreadLimit {
        threads,
        cores,
        origin: input.origin,
        input: Some(input),
        capped_at_cores,
    })
}

/// The memory limit of a scan, and why.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryLimit {
    /// The most memory the scan may take, in bytes; `None` only by default
    /// on a system that does not tell its installed memory.
    pub bytes: Option<u64>,
    /// Where the limit comes from.
    pub origin: LimitOrigin,
    /// The value given, `None` for the default.
    pub input: Option<LimitInput>,
    /// The percentage of the installed memory, when the limit is one (the
    /// default or `N%`).
    pub percent: Option<u32>,
}

/// The memory limit of a scan on a machine of `total` installed bytes
/// (`None` when the system does not tell), from the value given (`input`)
/// or [`DEFAULT_MEMORY_PERCENT`]. A percentage on a system that does not
/// tell its memory is an error; the default there is no limit, as before.
pub fn resolve_memory(
    input: Option<LimitInput>,
    total: Option<u64>,
) -> Result<MemoryLimit, LimitError> {
    let share = |total: u64, percent: u32| (total as u128 * percent as u128 / 100) as u64;
    let Some(input) = input else {
        return Ok(MemoryLimit {
            bytes: total.map(|total| share(total, DEFAULT_MEMORY_PERCENT)),
            origin: LimitOrigin::Default,
            input: None,
            percent: total.map(|_| DEFAULT_MEMORY_PERCENT),
        });
    };
    let error = |input: LimitInput, kind| LimitError {
        setting: Setting::MaxMemory,
        input,
        kind,
    };
    match parse_max_memory(&input.value) {
        None => Err(error(input, LimitErrorKind::Invalid)),
        Some(MemoryRequest::Percent(percent)) => match total {
            None => Err(error(input, LimitErrorKind::PercentOfUnknownMemory)),
            Some(total) => Ok(MemoryLimit {
                bytes: Some(share(total, percent)),
                origin: input.origin,
                input: Some(input),
                percent: Some(percent),
            }),
        },
        Some(MemoryRequest::Gigabytes(gb)) => Ok(MemoryLimit {
            bytes: Some((gb * 1_073_741_824.0) as u64),
            origin: input.origin,
            input: Some(input),
            percent: None,
        }),
    }
}

/// The threads and memory a scan may take.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanResources {
    /// The thread limit.
    pub threads: ThreadLimit,
    /// The memory limit.
    pub memory: MemoryLimit,
}

/// Both limits of a scan from their sources: the options given on the
/// command line (`cpu`, `max_memory`), the environment (`variable` reads
/// one by name, `std::env::var_os` in the binary), the machine's `cores`
/// and installed memory (`total`). The thread limit is checked first.
pub fn resolve(
    cpu: Option<&str>,
    max_memory: Option<&str>,
    variable: impl Fn(&str) -> Option<OsString>,
    cores: usize,
    total: Option<u64>,
) -> Result<ScanResources, LimitError> {
    let threads = resolve_threads(choose_input(cpu, variable(CPU_VARIABLE)), cores)?;
    let memory = resolve_memory(
        choose_input(max_memory, variable(MAX_MEMORY_VARIABLE)),
        total,
    )?;
    Ok(ScanResources { threads, memory })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn option(value: &str) -> Option<LimitInput> {
        Some(LimitInput {
            value: value.to_string(),
            origin: LimitOrigin::Option,
        })
    }

    #[test]
    fn test_parse_cpu_takes_a_count_or_a_percentage() {
        assert_eq!(parse_cpu("4"), Some(CpuRequest::Threads(4)));
        assert_eq!(parse_cpu(" 1 "), Some(CpuRequest::Threads(1)));
        assert_eq!(parse_cpu("50%"), Some(CpuRequest::Percent(50)));
        assert_eq!(parse_cpu("100%"), Some(CpuRequest::Percent(100)));
        assert_eq!(parse_cpu("1%"), Some(CpuRequest::Percent(1)));
        assert_eq!(parse_cpu("50 %"), Some(CpuRequest::Percent(50)));
    }

    #[test]
    fn test_parse_cpu_rejects_anything_else() {
        for text in [
            "",
            " ",
            "0",
            "-2",
            "+2",
            "2.5",
            "four",
            "0%",
            "101%",
            "150%",
            "50.5%",
            "%",
            "-5%",
            "4 threads",
            "4%%",
            "99999999999999999999999",
        ] {
            assert_eq!(parse_cpu(text), None, "{text:?}");
        }
    }

    #[test]
    fn test_parse_max_memory_takes_gigabytes_or_a_percentage() {
        assert_eq!(parse_max_memory("8"), Some(MemoryRequest::Gigabytes(8.0)));
        assert_eq!(parse_max_memory("7.5"), Some(MemoryRequest::Gigabytes(7.5)));
        assert_eq!(
            parse_max_memory("0.01"),
            Some(MemoryRequest::Gigabytes(0.01))
        );
        assert_eq!(parse_max_memory(".5"), Some(MemoryRequest::Gigabytes(0.5)));
        assert_eq!(parse_max_memory("75%"), Some(MemoryRequest::Percent(75)));
        assert_eq!(parse_max_memory("100%"), Some(MemoryRequest::Percent(100)));
    }

    #[test]
    fn test_parse_max_memory_rejects_anything_else() {
        for text in [
            "", "0", "0.0", "-8", "7,5", "8GB", "8G", "1e3", "inf", "NaN", "1.2.3", ".", "0%",
            "101%", "7.5%", "lots",
        ] {
            assert_eq!(parse_max_memory(text), None, "{text:?}");
        }
    }

    /// One core left free by default, at least one thread, on machines of
    /// 1 to 64 cores.
    #[test]
    fn test_default_leaves_one_core_free() {
        for (cores, threads) in [(1, 1), (2, 1), (4, 3), (8, 7), (16, 15), (64, 63)] {
            let limit = resolve_threads(None, cores).unwrap();
            assert_eq!(
                (limit.threads, limit.origin, limit.cores),
                (threads, LimitOrigin::Default, cores),
                "{cores} cores"
            );
        }
        // A system that tells no core count is taken for one core.
        assert_eq!(resolve_threads(None, 0).unwrap().threads, 1);
    }

    #[test]
    fn test_threads_from_a_count_or_a_percentage() {
        let threads = |value: &str, cores| resolve_threads(option(value), cores).unwrap();
        assert_eq!(threads("4", 8).threads, 4);
        assert_eq!(threads("1", 8).threads, 1);
        assert_eq!(threads("8", 8).threads, 8);
        // Rounded down, at least one.
        assert_eq!(threads("50%", 8).threads, 4);
        assert_eq!(threads("50%", 7).threads, 3);
        assert_eq!(threads("50%", 1).threads, 1);
        assert_eq!(threads("1%", 8).threads, 1);
        assert_eq!(threads("100%", 8).threads, 8);
        assert_eq!(threads("25%", 16).threads, 4);
        // More threads than cores: lowered to the cores, and said so.
        let above = threads("32", 8);
        assert_eq!((above.threads, above.capped_at_cores), (8, true));
        assert!(!threads("8", 8).capped_at_cores);
    }

    #[test]
    fn test_invalid_thread_limit_names_its_source_and_value() {
        let error = resolve_threads(option("0"), 8).unwrap_err();
        assert_eq!(error.kind, LimitErrorKind::Invalid);
        assert_eq!(error.source_name(), "--cpu");
        assert_eq!(error.input.value, "0");
        let error = resolve_threads(
            Some(LimitInput {
                value: "150%".into(),
                origin: LimitOrigin::Environment,
            }),
            8,
        )
        .unwrap_err();
        assert_eq!(error.source_name(), "CODEFIXTURE_AUDIT_CPU");
        assert_eq!(
            error.input.display(Setting::Cpu),
            "CODEFIXTURE_AUDIT_CPU=150%"
        );
    }

    #[test]
    fn test_memory_limit_default_and_given() {
        let total = Some(16 * GIB);
        let default = resolve_memory(None, total).unwrap();
        assert_eq!(default.bytes, Some(12 * GIB));
        assert_eq!(
            (default.origin, default.percent),
            (LimitOrigin::Default, Some(75))
        );
        // No default limit when the system does not tell its memory.
        assert_eq!(resolve_memory(None, None).unwrap().bytes, None);
        let gb = resolve_memory(option("7.5"), total).unwrap();
        assert_eq!(gb.bytes, Some(7 * GIB + GIB / 2));
        assert_eq!(gb.percent, None);
        // A size works without knowing the installed memory.
        assert_eq!(
            resolve_memory(option("8"), None).unwrap().bytes,
            Some(8 * GIB)
        );
        let percent = resolve_memory(option("50%"), total).unwrap();
        assert_eq!((percent.bytes, percent.percent), (Some(8 * GIB), Some(50)));
        assert_eq!(
            resolve_memory(option("100%"), total).unwrap().bytes,
            Some(16 * GIB)
        );
    }

    #[test]
    fn test_invalid_memory_limit_names_its_source_and_value() {
        let error = resolve_memory(option("0"), Some(16 * GIB)).unwrap_err();
        assert_eq!(
            (error.kind, error.source_name()),
            (LimitErrorKind::Invalid, "--max-memory")
        );
        let error = resolve_memory(option("50%"), None).unwrap_err();
        assert_eq!(error.kind, LimitErrorKind::PercentOfUnknownMemory);
    }

    /// The option first, then the variable, then the default; a variable
    /// set but empty is an error, not a default.
    #[test]
    fn test_option_then_environment_then_default() {
        let env = |cpu: Option<&str>, memory: Option<&str>| {
            let cpu = cpu.map(OsString::from);
            let memory = memory.map(OsString::from);
            move |name: &str| match name {
                CPU_VARIABLE => cpu.clone(),
                MAX_MEMORY_VARIABLE => memory.clone(),
                _ => None,
            }
        };
        let total = Some(32 * GIB);
        let both = resolve(Some("2"), Some("4"), env(Some("6"), Some("50%")), 8, total).unwrap();
        assert_eq!(
            (both.threads.threads, both.threads.origin),
            (2, LimitOrigin::Option)
        );
        assert_eq!(
            (both.memory.bytes, both.memory.origin),
            (Some(4 * GIB), LimitOrigin::Option)
        );
        let environment = resolve(None, None, env(Some("6"), Some("50%")), 8, total).unwrap();
        assert_eq!(
            (environment.threads.threads, environment.threads.origin),
            (6, LimitOrigin::Environment)
        );
        assert_eq!(
            (environment.memory.bytes, environment.memory.origin),
            (Some(16 * GIB), LimitOrigin::Environment)
        );
        let default = resolve(None, None, env(None, None), 8, total).unwrap();
        assert_eq!(
            (default.threads.threads, default.memory.bytes),
            (7, Some(24 * GIB))
        );
        // An invalid variable stops the scan, naming the variable.
        let error = resolve(None, None, env(Some(""), None), 8, total).unwrap_err();
        assert_eq!(error.source_name(), "CODEFIXTURE_AUDIT_CPU");
        let error = resolve(None, None, env(None, Some("lots")), 8, total).unwrap_err();
        assert_eq!(error.source_name(), "CODEFIXTURE_AUDIT_MAX_MEMORY");
        // The option overrides an invalid variable, which is not read.
        assert!(resolve(Some("2"), None, env(Some("lots"), None), 8, total).is_ok());
    }
}
