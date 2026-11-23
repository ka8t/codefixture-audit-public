//! The memory of the machine a scan runs on (ticket #281): what is
//! installed, and what a new process can take without making the system
//! swap. Read before the scan, to stop one whose estimate does not fit
//! (`scan::memory_check`).
//!
//! - Linux: `MemTotal` and `MemAvailable` of `/proc/meminfo`, the kernel's
//!   own estimate of what can be allocated without swapping.
//! - macOS: the installed memory (`hw.memsize`) and the pages a process can
//!   get without the system compressing or swapping: free, inactive,
//!   speculative and purgeable (`host_statistics64`).
//! - Windows: `ullTotalPhys` and `ullAvailPhys` of `GlobalMemoryStatusEx`
//!   (ticket #283), the physical memory installed and what can be used
//!   without writing to the page file (free, standby and zeroed pages).
//! - Other systems: not read. The caller says so; it never takes an
//!   unknown amount for a large one.

/// The memory of the machine, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemMemory {
    /// Installed memory.
    pub total: u64,
    /// What a new process can allocate without the system swapping.
    pub available: u64,
}

/// The memory of this machine, or `None` when this system does not tell.
pub fn system_memory() -> Option<SystemMemory> {
    read_system_memory()
}

#[cfg(target_os = "linux")]
fn read_system_memory() -> Option<SystemMemory> {
    parse_meminfo(&std::fs::read_to_string("/proc/meminfo").ok()?)
}

/// `MemTotal` and `MemAvailable` of a `/proc/meminfo` text (values in
/// kB). `None` when one is missing: kernels before 3.14 have no
/// `MemAvailable`, and summing other fields would only guess it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_meminfo(text: &str) -> Option<SystemMemory> {
    let field = |name: &str| -> Option<u64> {
        text.lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
            .and_then(|rest| rest.split_whitespace().next()?.parse::<u64>().ok())
            .map(|kb| kb * 1024)
    };
    Some(SystemMemory {
        total: field("MemTotal")?,
        available: field("MemAvailable")?,
    })
}

#[cfg(target_os = "macos")]
fn read_system_memory() -> Option<SystemMemory> {
    // Installed memory.
    let mut total: u64 = 0;
    let mut size = std::mem::size_of::<u64>();
    // SAFETY: `hw.memsize` is a 64-bit integer; `total` and `size`
    // describe a buffer of exactly that size.
    let status = unsafe {
        libc::sysctlbyname(
            c"hw.memsize".as_ptr(),
            (&mut total as *mut u64).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 || total == 0 {
        return None;
    }
    // Page counts of the virtual memory system.
    // SAFETY: `vm_statistics64` is plain data; zeroed is a valid value.
    let mut stats: libc::vm_statistics64 = unsafe { std::mem::zeroed() };
    let mut count = libc::HOST_VM_INFO64_COUNT;
    // SAFETY: `stats` is a `vm_statistics64` and `count` its size in
    // `integer_t`, as `host_statistics64` expects for `HOST_VM_INFO64`.
    #[allow(deprecated)]
    let status = unsafe {
        libc::host_statistics64(
            libc::mach_host_self(),
            libc::HOST_VM_INFO64,
            (&mut stats as *mut libc::vm_statistics64).cast(),
            &mut count,
        )
    };
    if status != 0 {
        return None;
    }
    // SAFETY: `sysconf` has no precondition.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 {
        return None;
    }
    let pages = u64::from(stats.free_count)
        + u64::from(stats.inactive_count)
        + u64::from(stats.speculative_count)
        + u64::from(stats.purgeable_count);
    Some(SystemMemory {
        total,
        available: pages * page as u64,
    })
}

/// The Win32 call that tells the memory of a Windows machine (ticket #283).
///
/// Declared here rather than through the `windows-sys` crate: its sources
/// are not in the offline registry of the development machine, and one
/// function and one plain-data structure do not justify a dependency.
/// `kernel32.dll` is linked by the standard library on every Windows
/// target (MSVC and GNU) anyway.
#[cfg(target_os = "windows")]
mod win32 {
    /// `MEMORYSTATUSEX` of `sysinfoapi.h`: two 32-bit fields then seven
    /// 64-bit ones, 64 bytes, with the C layout. `dwLength` must hold its
    /// size before the call.
    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct MemoryStatusEx {
        pub dwLength: u32,
        pub dwMemoryLoad: u32,
        pub ullTotalPhys: u64,
        pub ullAvailPhys: u64,
        pub ullTotalPageFile: u64,
        pub ullAvailPageFile: u64,
        pub ullTotalVirtual: u64,
        pub ullAvailVirtual: u64,
        pub ullAvailExtendedVirtual: u64,
    }

    // The structure must match the C one byte for byte.
    const _: () = assert!(std::mem::size_of::<MemoryStatusEx>() == 64);

    #[link(name = "kernel32")]
    unsafe extern "system" {
        /// `BOOL GlobalMemoryStatusEx(LPMEMORYSTATUSEX)`: non-zero on
        /// success.
        pub fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
    }
}

#[cfg(target_os = "windows")]
fn read_system_memory() -> Option<SystemMemory> {
    // SAFETY: `MemoryStatusEx` is plain data; zeroed is a valid value.
    let mut status: win32::MemoryStatusEx = unsafe { std::mem::zeroed() };
    status.dwLength = std::mem::size_of::<win32::MemoryStatusEx>() as u32;
    // SAFETY: `status` is a `MEMORYSTATUSEX` whose `dwLength` holds its
    // size, as `GlobalMemoryStatusEx` requires; it only writes into it.
    let ok = unsafe { win32::GlobalMemoryStatusEx(&mut status) };
    if ok == 0 || status.ullTotalPhys == 0 {
        return None;
    }
    Some(SystemMemory {
        total: status.ullTotalPhys,
        available: status.ullAvailPhys,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn read_system_memory() -> Option<SystemMemory> {
    None
}

/// Memory every scan takes whatever the project: the binary, the rules,
/// the report. Measured from 0.05 to 0.1 GB on the smallest projects of
/// the reference corpus (2026-11-23); rounded up.
pub const BASE_BYTES: u64 = 200 * 1024 * 1024;

/// Bytes of memory per byte of source of a language whose data flow the
/// scan follows (its trees are kept, ticket #241), for one taint rule at a
/// time. Measured on the Juliet Java suite (253 MB of `.java`,
/// 2026-11-23): one taint rule alone peaks at 8.0 GB (`peak memory
/// footprint`), 32 times its sources. Split then (#281): about 3 GB of
/// parse trees, 2.6 GB of call graph and prepared functions, 1.1 GB of the
/// rule's summaries. Raised to 40: the `Java` reference project (81 MB of
/// Java, 16 MB of JavaScript) peaks at 4.8 GB with 4 rules at a time, 48
/// times its followed sources, which 32 underestimated (4.1 GB). An
/// estimate may be above the peak, never below.
pub const FOLLOWED_FACTOR: u64 = 40;

/// What each taint rule running at the same time as the first adds, in
/// bytes per byte of source: the Juliet Java suite peaks at 10.1 GB with 4
/// rules at a time against 8.0 GB with one (2026-11-23).
pub const PER_EXTRA_RULE_FACTOR: u64 = 3;

/// Bytes of memory per byte of source of a language whose data flow is not
/// followed (no taint rule, or no taint pass: HTML, YAML, Dockerfile): its
/// trees are dropped once its lines are counted. The Juliet Java suite
/// without its taint rules peaks at 1.3 GB, 5 times its sources; rounded
/// up.
pub const OTHER_FACTOR: u64 = 6;

/// The source bytes of one language of a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageSources {
    /// The rule language (`java`, `python`…).
    pub language: String,
    /// Bytes of its discovered files.
    pub bytes: u64,
    /// Whether its data flow is followed (its trees are kept).
    pub followed: bool,
}

/// The memory a scan is expected to take, and what the machine has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryEstimate {
    /// The estimated peak, in bytes ([`estimate_bytes`]).
    pub bytes: u64,
    /// The sources it was estimated from, largest first.
    pub sources: Vec<LanguageSources>,
    /// Taint rules run at the same time, chosen by [`plan`].
    pub rules_at_once: usize,
    /// Taint rules the machine's threads would run at the same time (half
    /// of them): `rules_at_once` is lower when memory is short.
    pub max_rules_at_once: usize,
    /// The machine's memory, `None` when this system does not tell.
    pub system: Option<SystemMemory>,
    /// The most memory the user lets the scan take (`--max-memory`), in
    /// bytes: room left for other programs, or the only bound on a system
    /// that does not tell its memory.
    pub limit: Option<u64>,
}

impl MemoryEstimate {
    /// The memory the scan may take: the smaller of the available memory
    /// and the user's limit; `None` when neither is known.
    pub fn allowed(&self) -> Option<u64> {
        match (self.system.map(|s| s.available), self.limit) {
            (Some(available), Some(limit)) => Some(available.min(limit)),
            (available, limit) => available.or(limit),
        }
    }

    /// Whether the estimate fits in [`Self::allowed`]; `None` when nothing
    /// bounds it.
    pub fn fits(&self) -> Option<bool> {
        self.allowed().map(|allowed| self.bytes <= allowed)
    }
}

/// The estimated peak memory of a scan of `sources` running
/// `rules_at_once` taint rules at a time: [`BASE_BYTES`], plus
/// [`FOLLOWED_FACTOR`] and [`PER_EXTRA_RULE_FACTOR`] per extra rule times
/// the sources of the followed languages, plus [`OTHER_FACTOR`] times the
/// others. Measured with 4 rules at a time (estimated 49 times): the
/// Juliet Java suite 39 times, the Juliet C# suite 37, the `Java` project
/// 48 (Java and JavaScript); applied as such to Python, JavaScript and
/// PHP, whose reference projects are too small to measure the factor
/// apart from the base. File sizes count minified files, which the scan
/// skips: the estimate is then above the real peak, never below.
pub fn estimate_bytes(sources: &[LanguageSources], rules_at_once: usize) -> u64 {
    let followed_factor =
        FOLLOWED_FACTOR + PER_EXTRA_RULE_FACTOR * rules_at_once.saturating_sub(1) as u64;
    sources.iter().fold(BASE_BYTES, |total, language| {
        let factor = if language.followed {
            followed_factor
        } else {
            OTHER_FACTOR
        };
        total.saturating_add(language.bytes.saturating_mul(factor))
    })
}

/// The memory plan of a scan of `sources` (ticket #281, step 2): the most
/// taint rules at a time, from `max_rules_at_once` down to one, whose
/// estimate fits in what the scan may take ([`MemoryEstimate::allowed`]).
/// Each rule at a time keeps its function summaries for the whole project
/// ([`PER_EXTRA_RULE_FACTOR`]): fewer rules at a time take less memory and
/// more time. When even one rule at a time does not fit, the plan keeps
/// one and its estimate, which does not fit: the scan stops.
pub fn plan(
    sources: Vec<LanguageSources>,
    max_rules_at_once: usize,
    system: Option<SystemMemory>,
    limit: Option<u64>,
) -> MemoryEstimate {
    let max_rules_at_once = max_rules_at_once.max(1);
    let mut estimate = MemoryEstimate {
        bytes: 0,
        sources,
        rules_at_once: 1,
        max_rules_at_once,
        system,
        limit,
    };
    let allowed = estimate.allowed();
    let rules_at_once = (1..=max_rules_at_once)
        .rev()
        .find(|rules| {
            allowed.is_none_or(|allowed| estimate_bytes(&estimate.sources, *rules) <= allowed)
        })
        .unwrap_or(1);
    estimate.rules_at_once = rules_at_once;
    estimate.bytes = estimate_bytes(&estimate.sources, rules_at_once);
    estimate
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    /// Fewer rules at a time when memory is short; the most the threads
    /// allow when it is not; one, which does not fit, when even one is too
    /// much.
    #[test]
    fn test_plan_runs_fewer_rules_at_once_when_memory_is_short() {
        let juliet = || vec![sources("java", 253, true)];
        let machine = |available_gb: u64| {
            Some(SystemMemory {
                total: 32 * GIB,
                available: available_gb * GIB,
            })
        };
        let roomy = plan(juliet(), 4, machine(20), None);
        assert_eq!((roomy.rules_at_once, roomy.fits()), (4, Some(true)));
        let short = plan(juliet(), 4, machine(11), None);
        assert_eq!(short.max_rules_at_once, 4);
        assert!(
            short.rules_at_once < 4 && short.rules_at_once >= 1,
            "{short:?}"
        );
        assert_eq!(short.fits(), Some(true));
        let too_small = plan(juliet(), 4, machine(5), None);
        assert_eq!(
            (too_small.rules_at_once, too_small.fits()),
            (1, Some(false))
        );
        // Nothing bounds it: the threads decide.
        let unknown = plan(juliet(), 4, None, None);
        assert_eq!((unknown.rules_at_once, unknown.fits()), (4, None));
        // The limit counts as the available memory.
        let limited = plan(juliet(), 4, machine(20), Some(11 * GIB));
        assert!(limited.rules_at_once < 4 && limited.fits() == Some(true));
    }

    fn sources(language: &str, mb: u64, followed: bool) -> LanguageSources {
        LanguageSources {
            language: language.to_string(),
            bytes: mb * 1024 * 1024,
            followed,
        }
    }

    /// The model against its measures (2026-11-23, `peak memory
    /// footprint`, 4 rules at a time): above each peak, never below, and
    /// at most a third above.
    #[test]
    fn test_estimate_covers_the_measured_peaks() {
        for (name, followed, peak_gib) in [
            ("juliet_java", vec![sources("java", 253, true)], 10.23),
            ("juliet_csharp", vec![sources("csharp", 173, true)], 6.41),
            (
                "Java",
                vec![sources("java", 81, true), sources("javascript", 16, true)],
                4.79,
            ),
        ] {
            let estimate = estimate_bytes(&followed, 4) as f64 / 1_073_741_824.0;
            assert!(
                estimate >= peak_gib && estimate <= peak_gib * 1.34,
                "{name}: estimate {estimate:.2} GiB, peak {peak_gib} GiB"
            );
        }
        let juliet = [sources("java", 253, true)];
        let one = estimate_bytes(&juliet, 1) as f64 / 1e9;
        assert!(one >= 8.0, "one rule at a time peaks at 8.0 GB: {one}");
        let without_taint = estimate_bytes(&[sources("java", 253, false)], 4) as f64 / 1e9;
        assert!((1.3..2.0).contains(&without_taint), "{without_taint}");
    }

    #[test]
    fn test_fits_against_available_memory() {
        let estimate = |available_gb: u64| MemoryEstimate {
            bytes: 10 * 1024 * 1024 * 1024,
            sources: Vec::new(),
            rules_at_once: 4,
            max_rules_at_once: 4,
            limit: None,
            system: Some(SystemMemory {
                total: 16 * 1024 * 1024 * 1024,
                available: available_gb * 1024 * 1024 * 1024,
            }),
        };
        assert_eq!(estimate(12).fits(), Some(true));
        assert_eq!(estimate(8).fits(), Some(false));
        let unknown = MemoryEstimate {
            system: None,
            ..estimate(8)
        };
        assert_eq!(unknown.fits(), None);
        // The user's limit, below the available memory, decides; it is
        // the only bound when the system does not tell its memory.
        let limited = MemoryEstimate {
            limit: Some(9 * 1024 * 1024 * 1024),
            ..estimate(12)
        };
        assert_eq!(limited.fits(), Some(false));
        let limited_unknown = MemoryEstimate {
            system: None,
            limit: Some(11 * 1024 * 1024 * 1024),
            ..estimate(12)
        };
        assert_eq!(limited_unknown.fits(), Some(true));
    }

    #[test]
    fn test_meminfo_gives_total_and_available() {
        let text = "MemTotal:       16303428 kB\nMemFree:         1200000 kB\nMemAvailable:   12582912 kB\n";
        assert_eq!(
            parse_meminfo(text),
            Some(SystemMemory {
                total: 16_303_428 * 1024,
                available: 12_582_912 * 1024,
            })
        );
    }

    /// An old kernel without `MemAvailable` gives no estimate rather than a
    /// guessed one.
    #[test]
    fn test_meminfo_without_available_gives_nothing() {
        assert_eq!(
            parse_meminfo("MemTotal: 16303428 kB\nMemFree: 1 kB\n"),
            None
        );
    }

    /// The machine running the tests tells its memory (Linux, macOS and
    /// Windows), and what is available never exceeds what is installed.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn test_this_machine_tells_its_memory() {
        let memory = system_memory().expect("Linux, macOS and Windows tell their memory");
        assert!(memory.total > 0);
        assert!(memory.available <= memory.total, "{memory:?}");
    }
}
