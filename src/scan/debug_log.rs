//! The scan's debug log (ticket #282): one line per step of the scan,
//! written to a file as the scan goes, so that the last lines tell where a
//! scan stood when it crashed, was killed or froze the machine (ticket
//! #281: a 2.3 GB Java project froze a tester's laptop and nothing said
//! where the scan was).
//!
//! Off unless `scan --debug-log` turns it on ([`start`]). Off, every call
//! of this module costs one relaxed atomic load: the [`debug_log!`]
//! macro and [`span`] check [`enabled`] before formatting anything, so a
//! scan without the option does no logging work at all.
//!
//! # How a line reaches the disk
//!
//! The thread that logs only stamps the event (wall clock, time since the
//! log started, its thread) and sends it to a bounded channel. A dedicated
//! writer thread formats the line, adds the memory of the process, and
//! hands the lines taken so far to the system in one write of whole lines
//! as soon as the channel is empty (or every [`MAX_BATCH`] lines under
//! load): a line is in the operating system's hands microseconds after the
//! event, so a killed process (`kill -9`, the out-of-memory killer) leaves
//! every line written before it, whole. The writer also asks the system to
//! put the file on the disk (`fsync`) at least every [`SYNC_INTERVAL`],
//! which a forced reboot or a frozen machine needs. The channel is bounded ([`CHANNEL_CAPACITY`]): when the
//! scan logs faster than the disk takes it, the scan waits instead of
//! piling lines up in memory, the very resource a frozen scan lacks.
//!
//! A file whose name ends in `.gz` is compressed with gzip, as a series of
//! gzip members (RFC 1952 allows several in one file, and `gzip -dc` reads
//! them in turn): each batch ends with a sync flush, so that the bytes on
//! disk decompress up to the last line written, and a member is closed at
//! each `fsync`. A killed scan's log then holds complete members, which
//! every gzip reader prints, and one open member: zlib reads it to its
//! last line, but the `gzip` tool of macOS stops on its missing end
//! without printing the last part it decompressed (measured on
//! 2026-11-23: 2,234 lines printed out of 2,544 on disk). Closing a member
//! every second bounds what such a reader misses to the last second. Any
//! other name is plain text.
//!
//! # Line format
//!
//! ```text
//! 2026-11-23 20:15:03.123 +12.345s [t5] mem=512.3MiB phase_c start rule language=java rule="sqli"
//! 2026-11-23 20:15:03.611 +12.833s [t5] mem=530.0MiB phase_c end rule language=java rule="sqli" ms=488.102 files=12 analysed=12 findings=3
//! ```
//!
//! Local date and time to the millisecond, seconds since the log started,
//! the thread (`main`, a named thread, or `t<n>` for an unnamed one such as
//! a rayon worker), the memory the process takes ([`process_memory`]:
//! the footprint on macOS, the resident memory on Linux and Windows, read
//! by the writer at most every [`MEMORY_REFRESH`]; `mem=?` when the system
//! does not tell), the phase, then the event and its `key=value` details.
//! A message never spans two lines: line breaks are escaped.
//!
//! A heartbeat thread adds a `heartbeat state` line every [`HEARTBEAT`]
//! whatever the scan does: the memory, the most seen so far, the steps in
//! progress and the threads running them; then one `heartbeat in_progress`
//! line per step ([`span`]) with its thread and how long it has run. A
//! scan stuck in one function keeps logging that step.
//!
//! Deliberate deviation from the Audit (`sca/debug.py`): the Audit has
//! three levels (`--debug`, `--debug=detail`, `--debug=trace`, or
//! `SCA_DEBUG`) and writes through Python's `logging`, buffered, to the
//! console and a file. This log has one level, the most detailed one (the
//! ticket asks for every step), never writes its lines to the console
//! (which only names the file; the console keeps its own progress lines,
//! and copies them into the log), and is written so as to survive
//! a crash, which `logging`'s buffered file does not.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

pub use crate::scan::memory::process_memory;

/// Events the channel holds before a logging thread waits for the writer.
pub const CHANNEL_CAPACITY: usize = 16_384;

/// How often the heartbeat thread logs the state of the scan.
pub const HEARTBEAT: Duration = Duration::from_secs(2);

/// How long the writer reuses a reading of the process memory: reading it
/// costs a system call (macOS, Windows) or a file read (Linux), too much
/// for each of millions of lines.
pub const MEMORY_REFRESH: Duration = Duration::from_millis(20);

/// Most lines the writer takes from the channel before it hands them to
/// the system, when the scan logs faster than the writer writes.
pub const MAX_BATCH: usize = 4_096;

/// Longest time between two `fsync` of the log file while lines arrive;
/// also the longest a gzip member stays open.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(1);

/// Whether the log is on: read by every call before any work.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// The running log, set once by [`start`].
static LOG: OnceLock<Log> = OnceLock::new();

/// Numbers the spans, so that the heartbeat tells them apart.
static NEXT_SPAN: AtomicU64 = AtomicU64::new(0);

/// The running log: the channel to the writer, the steps in progress, and
/// the threads to join at the end.
struct Log {
    sender: SyncSender<Message>,
    started: Instant,
    path: PathBuf,
    /// Steps in progress, by span number, for the heartbeat.
    active: Mutex<BTreeMap<u64, ActiveSpan>>,
    /// The writer and heartbeat threads, taken by [`finish`].
    threads: Mutex<Option<(std::thread::JoinHandle<()>, std::thread::JoinHandle<()>)>>,
    /// Set by [`finish`]: the heartbeat stops.
    stopping: AtomicBool,
    /// The writer thread, which must never wait for itself.
    writer_thread: OnceLock<std::thread::ThreadId>,
}

/// A step in progress, as the heartbeat lists it.
struct ActiveSpan {
    thread: Arc<str>,
    phase: &'static str,
    label: String,
    started: Instant,
}

/// What the logging threads send to the writer.
enum Message {
    /// One event to write.
    Line(Record),
    /// Write everything before, flush, `fsync`, then answer.
    Sync(SyncSender<()>),
    /// Like `Sync`, then end the file (gzip trailer) and stop.
    Close(SyncSender<()>),
}

/// One event, stamped by the thread that logged it.
struct Record {
    wall: SystemTime,
    elapsed: Duration,
    thread: Arc<str>,
    phase: &'static str,
    message: String,
}

thread_local! {
    /// The label of the current thread in the log, computed once.
    static THREAD_LABEL: Arc<str> = thread_label(&std::thread::current()).into();
}

/// `main`, the name of a named thread, or `t<n>` for an unnamed one (a
/// rayon worker): `n` is the number Rust gives the thread
/// (`ThreadId(n)`).
fn thread_label(thread: &std::thread::Thread) -> String {
    match thread.name() {
        Some(name) => name.to_string(),
        None => {
            let id = format!("{:?}", thread.id());
            let number = id
                .trim_start_matches("ThreadId(")
                .trim_end_matches(')')
                .to_string();
            format!("t{number}")
        }
    }
}

/// Whether the debug log is on. One relaxed atomic load: every logging
/// call checks it before doing any work.
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Logs one event of `phase` when the log is on; the message is only
/// formatted then. `debug_log!("phase_a", "file_start path={:?}", path)`.
#[macro_export]
macro_rules! debug_log {
    ($phase:expr, $($arg:tt)*) => {
        if $crate::scan::debug_log::enabled() {
            $crate::scan::debug_log::log($phase, format!($($arg)*));
        }
    };
}

/// Sends one event to the writer (the body of [`debug_log!`]). Does
/// nothing when the log is off or already closed.
pub fn log(phase: &'static str, message: String) {
    let Some(log) = LOG.get().filter(|_| enabled()) else {
        return;
    };
    let record = Record {
        wall: SystemTime::now(),
        elapsed: log.started.elapsed(),
        thread: THREAD_LABEL.with(Arc::clone),
        phase,
        message,
    };
    // The writer is gone (closed, or its disk failed): nothing to do.
    let _ = log.sender.send(Message::Line(record));
}

/// Where the log goes, or `None` when it is off.
pub fn path() -> Option<PathBuf> {
    LOG.get().filter(|_| enabled()).map(|log| log.path.clone())
}

/// Turns the log on, writing to `path` (gzip when its name ends in
/// `.gz`), and starts the writer and heartbeat threads. The folder of
/// `path` is created. Once per process: a second call is an error, as is
/// a file that cannot be created.
pub fn start(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let sink = Sink::new(path)?;
    let (sender, receiver) = sync_channel(CHANNEL_CAPACITY);
    let log = Log {
        sender,
        started: Instant::now(),
        path: path.to_path_buf(),
        active: Mutex::new(BTreeMap::new()),
        threads: Mutex::new(None),
        stopping: AtomicBool::new(false),
        writer_thread: OnceLock::new(),
    };
    if LOG.set(log).is_err() {
        return Err(std::io::Error::other("the debug log is already started"));
    }
    let log = LOG.get().expect("set above");
    let writer = std::thread::Builder::new()
        .name("debug-log-writer".to_string())
        .spawn(move || write_lines(receiver, sink))?;
    let _ = log.writer_thread.set(writer.thread().id());
    let heartbeat = std::thread::Builder::new()
        .name("debug-log-heartbeat".to_string())
        .spawn(heartbeat_loop)?;
    *log.threads.lock().unwrap_or_else(|e| e.into_inner()) = Some((writer, heartbeat));
    ENABLED.store(true, Ordering::Relaxed);
    Ok(())
}

/// Writes everything logged so far to the disk (`fsync`) and waits for it,
/// at most two seconds. For the panic hook, before the process ends.
pub fn sync() {
    let Some(log) = LOG.get().filter(|_| enabled()) else {
        return;
    };
    if log.writer_thread.get() == Some(&std::thread::current().id()) {
        return; // The writer itself panicked: it cannot wait for itself.
    }
    let (ack, done) = sync_channel(1);
    if log.sender.send(Message::Sync(ack)).is_ok() {
        let _ = done.recv_timeout(Duration::from_secs(2));
    }
}

/// Logs the end of the log, writes everything to the disk, ends the file
/// and stops the writer and heartbeat threads. Called once the command is
/// done, panic or not; later calls, and calls with the log off, do
/// nothing. Logging after it does nothing either.
pub fn finish() {
    let Some(state) = LOG.get().filter(|_| enabled()) else {
        return;
    };
    let (peak, now) = (PEAK.load(Ordering::Relaxed), process_memory());
    log(
        "end",
        format!(
            "log_end peak_mem={} mem={}",
            mebibytes(Some(peak).filter(|p| *p > 0)),
            mebibytes(now)
        ),
    );
    ENABLED.store(false, Ordering::Relaxed);
    state.stopping.store(true, Ordering::Relaxed);
    let threads = state
        .threads
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    let (ack, done) = sync_channel(1);
    if state.sender.send(Message::Close(ack)).is_ok() {
        let _ = done.recv_timeout(Duration::from_secs(10));
    }
    if let Some((writer, heartbeat)) = threads {
        heartbeat.thread().unpark();
        let _ = heartbeat.join();
        let _ = writer.join();
    }
}

/// Logs a panic (message and location, as `info` displays them) with the
/// steps the panicking thread was in, then writes everything to the disk.
/// Called by the panic hook of `main.rs`, before the process ends.
pub fn record_panic(info: &std::panic::PanicHookInfo<'_>) {
    if !enabled() {
        return;
    }
    let thread = THREAD_LABEL.with(Arc::clone);
    let steps = LOG.get().map_or_else(String::new, |log| {
        log.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|span| span.thread == thread)
            .map(|span| format!("{} {}", span.phase, span.label))
            .collect::<Vec<_>>()
            .join(" > ")
    });
    log(
        "panic",
        format!("panic {:?} in_steps={steps:?}", info.to_string()),
    );
    sync();
}

/// One step of the scan with a start and an end, made by [`span`]: the
/// start is logged when it is made, the end (with its duration) when it
/// is dropped or ended with [`Span::end_with`]. While it lives, the
/// heartbeat lists it. Empty, and free, when the log is off.
#[must_use = "the step ends when the span is dropped"]
pub struct Span {
    inner: Option<SpanInner>,
}

struct SpanInner {
    id: u64,
    phase: &'static str,
    label: String,
    started: Instant,
}

/// Starts a step of `phase` named by `label` (called only when the log is
/// on): logs `start <label>` and lists the step for the heartbeat until
/// the returned span ends.
pub fn span(phase: &'static str, label: impl FnOnce() -> String) -> Span {
    let Some(log) = LOG.get().filter(|_| enabled()) else {
        return Span { inner: None };
    };
    let label = label();
    let id = NEXT_SPAN.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    log.active.lock().unwrap_or_else(|e| e.into_inner()).insert(
        id,
        ActiveSpan {
            thread: THREAD_LABEL.with(Arc::clone),
            phase,
            label: label.clone(),
            started,
        },
    );
    log_start(phase, &label);
    Span {
        inner: Some(SpanInner {
            id,
            phase,
            label,
            started,
        }),
    }
}

fn log_start(phase: &'static str, label: &str) {
    log(phase, format!("start {label}"));
}

impl Span {
    /// Ends the step now, adding `details` (called only when the log is
    /// on) to its end line: `end <label> ms=… <details>`.
    pub fn end_with(mut self, details: impl FnOnce() -> String) {
        if let Some(inner) = self.inner.take() {
            inner.end(&details());
        }
    }

    /// Whether the span logs (the log was on when it started).
    pub fn is_on(&self) -> bool {
        self.inner.is_some()
    }
}

impl SpanInner {
    fn end(self, details: &str) {
        if let Some(log) = LOG.get() {
            log.active
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&self.id);
        }
        // A step left by a panic did not end: the line says so.
        let event = if std::thread::panicking() {
            "abandoned_by_panic"
        } else {
            "end"
        };
        let ms = self.started.elapsed().as_secs_f64() * 1000.0;
        let separator = if details.is_empty() { "" } else { " " };
        log(
            self.phase,
            format!("{event} {} ms={ms:.3}{separator}{details}", self.label),
        );
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner.end("");
        }
    }
}

/// Milliseconds since `started`, three decimals, for a detail of a line.
pub fn ms_since(started: Instant) -> String {
    format!("{:.3}", started.elapsed().as_secs_f64() * 1000.0)
}

/// The most memory the writer and the heartbeat have seen the process
/// take, in bytes (0 when the system does not tell).
static PEAK: AtomicU64 = AtomicU64::new(0);

/// `512.3MiB`, or `?` when the size is unknown.
pub fn mebibytes(bytes: Option<u64>) -> String {
    match bytes {
        Some(bytes) => format!("{:.1}MiB", bytes as f64 / 1_048_576.0),
        None => "?".to_string(),
    }
}

/// Reads the process memory and keeps the most seen.
fn read_memory() -> Option<u64> {
    let now = process_memory();
    if let Some(bytes) = now {
        PEAK.fetch_max(bytes, Ordering::Relaxed);
    }
    now
}

/// The heartbeat thread: every [`HEARTBEAT`], one line with the memory
/// and the number of steps in progress, then one line per step with its
/// thread and how long it has run, longest first.
fn heartbeat_loop() {
    let Some(state) = LOG.get() else {
        return;
    };
    loop {
        std::thread::park_timeout(HEARTBEAT);
        if state.stopping.load(Ordering::Relaxed) || !enabled() {
            return;
        }
        let memory = read_memory();
        let mut steps: Vec<(Duration, String)> = state
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|span| {
                (
                    span.started.elapsed(),
                    format!("[{}] {} {}", span.thread, span.phase, span.label),
                )
            })
            .collect();
        steps.sort_by_key(|(running, _)| std::cmp::Reverse(*running));
        let threads: std::collections::BTreeSet<&str> = steps
            .iter()
            .filter_map(|(_, step)| step.split(']').next())
            .collect();
        log(
            "heartbeat",
            format!(
                "state mem={} peak_mem={} active_steps={} busy_threads={}",
                mebibytes(memory),
                mebibytes(Some(PEAK.load(Ordering::Relaxed)).filter(|p| *p > 0)),
                steps.len(),
                threads.len()
            ),
        );
        for (running, step) in &steps {
            log(
                "heartbeat",
                format!("in_progress {step} for_s={:.3}", running.as_secs_f64()),
            );
        }
    }
}

/// The file the writer writes to, with the batch of lines not yet in it.
///
/// A batch reaches the file in one write, whole lines only: a buffered
/// writer (or the gzip encoder writing straight to the file) hands the
/// system a full buffer whenever it fills, in the middle of a line.
struct Sink {
    file: std::fs::File,
    /// Plain text: the lines of the batch. Gzip: their compressed bytes.
    pending: Pending,
}

enum Pending {
    Plain(Vec<u8>),
    /// The open gzip member, and whether it holds any line yet.
    Gzip(Box<flate2::write::GzEncoder<Vec<u8>>>, bool),
}

/// A new gzip member, written to memory.
fn gzip_member() -> Box<flate2::write::GzEncoder<Vec<u8>>> {
    Box::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ))
}

impl Sink {
    /// Creates (or empties) the file at `path`: gzip when its name ends in
    /// `.gz`, plain text otherwise.
    fn new(path: &Path) -> std::io::Result<Self> {
        let file = std::fs::File::create(path)?;
        let pending = if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("gz"))
        {
            Pending::Gzip(gzip_member(), false)
        } else {
            Pending::Plain(Vec::new())
        };
        Ok(Sink { file, pending })
    }

    /// Adds bytes to the batch, in memory.
    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match &mut self.pending {
            Pending::Plain(batch) => {
                batch.extend_from_slice(bytes);
                Ok(())
            }
            Pending::Gzip(encoder, used) => {
                *used = true;
                encoder.write_all(bytes)
            }
        }
    }

    /// Hands the batch to the system in one write. For gzip, after a sync
    /// flush, so that the bytes on disk decompress up to the last line.
    fn flush(&mut self) -> std::io::Result<()> {
        let batch = match &mut self.pending {
            Pending::Plain(batch) => batch,
            // A member without any line stays unwritten: flushing it would
            // put an open member (a header and an empty block) at the end
            // of a file whose members were all closed.
            Pending::Gzip(_, false) => return Ok(()),
            Pending::Gzip(encoder, true) => {
                encoder.flush()?;
                encoder.get_mut()
            }
        };
        if !batch.is_empty() {
            self.file.write_all(batch)?;
            batch.clear();
        }
        Ok(())
    }

    /// Writes the batch, closes the open gzip member (its trailer; the
    /// next line starts a new one), and asks the system to put the file on
    /// the disk.
    fn sync(&mut self) -> std::io::Result<()> {
        self.flush()?;
        if let Pending::Gzip(encoder, used) = &mut self.pending
            && *used
        {
            let member = std::mem::replace(encoder, gzip_member());
            *used = false;
            self.file.write_all(&member.finish()?)?;
        }
        self.file.sync_data()
    }

    /// Ends the file: the last member closed, then `fsync`.
    fn close(mut self) -> std::io::Result<()> {
        self.sync()
    }
}

/// The writer thread: takes the events in order, writes each as a line,
/// flushes whenever the channel is empty (or every [`MAX_BATCH`] lines under
/// load), and syncs at least every [`SYNC_INTERVAL`]. A write error ends
/// the log: the scan goes on without it.
fn write_lines(receiver: Receiver<Message>, mut sink: Sink) {
    let mut line = String::with_capacity(256);
    let mut memory: (Option<Instant>, Option<u64>) = (None, None);
    let mut last_sync = Instant::now();
    while let Ok(first) = receiver.recv() {
        let mut next = Some(first);
        let mut batch = 0;
        while let Some(message) = next.take() {
            match message {
                Message::Line(record) => {
                    if memory.0.is_none_or(|at| at.elapsed() >= MEMORY_REFRESH) {
                        memory = (Some(Instant::now()), read_memory());
                    }
                    line.clear();
                    format_line(&mut line, &record, memory.1);
                    if sink.write_all(line.as_bytes()).is_err() {
                        ENABLED.store(false, Ordering::Relaxed);
                        return;
                    }
                }
                Message::Sync(ack) => {
                    let _ = sink.sync();
                    last_sync = Instant::now();
                    let _ = ack.send(());
                }
                Message::Close(ack) => {
                    // Lines sent before the close are already taken: the
                    // channel keeps the order.
                    let _ = sink.close();
                    let _ = ack.send(());
                    return;
                }
            }
            batch += 1;
            if batch < MAX_BATCH {
                next = receiver.try_recv().ok();
            }
        }
        if sink.flush().is_err() {
            ENABLED.store(false, Ordering::Relaxed);
            return;
        }
        if last_sync.elapsed() >= SYNC_INTERVAL {
            let _ = sink.sync();
            last_sync = Instant::now();
        }
    }
    let _ = sink.close();
}

/// Appends the line of `record` to `out`, ending with `\n` (format in the
/// module doc). Line breaks inside the message are escaped, so that one
/// event is one line.
fn format_line(out: &mut String, record: &Record, memory: Option<u64>) {
    let wall = chrono::DateTime::<chrono::Local>::from(record.wall);
    let _ = write!(
        out,
        "{} +{:.3}s [{}] mem={} {} ",
        wall.format("%Y-%m-%d %H:%M:%S%.3f"),
        record.elapsed.as_secs_f64(),
        record.thread,
        mebibytes(memory),
        record.phase,
    );
    for c in record.message.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out.push('\n');
}

/// The default file of the log in the history folder `datas_dir`:
/// `logs/scan-<timestamp>.log.gz`, the timestamp to the second so that two
/// scans in one minute keep two logs.
pub fn default_path(datas_dir: &Path) -> PathBuf {
    datas_dir.join("logs").join(format!(
        "scan-{}.log.gz",
        chrono::Local::now().format("%Y-%m-%d-%H-%M-%S")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(message: &str) -> Record {
        Record {
            wall: SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_123),
            elapsed: Duration::from_millis(12_345),
            thread: "t5".into(),
            phase: "phase_c",
            message: message.to_string(),
        }
    }

    /// The fields of a line, in order; the date is local time, so only
    /// its shape is checked.
    #[test]
    fn test_line_format() {
        let mut out = String::new();
        format_line(
            &mut out,
            &record("rule_start rule=\"java/sqli\""),
            Some(536_870_912),
        );
        let (date, rest) = out.split_at(23);
        assert!(
            date.len() == 23 && date.as_bytes()[10] == b' ' && date.ends_with(".123"),
            "{out:?}"
        );
        assert_eq!(
            rest,
            " +12.345s [t5] mem=512.0MiB phase_c rule_start rule=\"java/sqli\"\n"
        );
        out.clear();
        format_line(&mut out, &record("panic a\nb\r\nc"), None);
        assert!(
            out.ends_with(" mem=? phase_c panic a\\nb\\r\\nc\n"),
            "one event, one line: {out:?}"
        );
        assert_eq!(out.matches('\n').count(), 1);
    }

    #[test]
    fn test_thread_label() {
        let named = std::thread::Builder::new()
            .name("worker".into())
            .spawn(|| thread_label(&std::thread::current()))
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(named, "worker");
        let unnamed = std::thread::spawn(|| thread_label(&std::thread::current()))
            .join()
            .unwrap();
        assert!(
            unnamed.starts_with('t') && unnamed[1..].parse::<u64>().is_ok(),
            "{unnamed}"
        );
    }

    /// Reads a gzip file as far as it goes: a killed writer leaves its last
    /// member open, and everything before it must still read.
    fn gunzip_partial(bytes: &[u8]) -> String {
        use std::io::Read as _;
        let mut decoder = flate2::read::MultiGzDecoder::new(bytes);
        let mut out = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            match decoder.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buffer[..n]),
            }
        }
        String::from_utf8(out).unwrap()
    }

    /// Each batch of lines is on disk once the channel is empty, before
    /// the file is closed: a process killed then leaves every line, gzip
    /// or not; a sync closes the gzip member. The writer runs as in a scan,
    /// on its own thread.
    #[test]
    fn test_lines_are_on_disk_before_the_file_is_closed() {
        let dir = std::env::temp_dir().join(format!("debug_log_flush_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["scan.log", "scan.log.gz"] {
            let path = dir.join(name);
            let sink = Sink::new(&path).unwrap();
            let (sender, receiver) = sync_channel(CHANNEL_CAPACITY);
            let writer = std::thread::spawn(move || write_lines(receiver, sink));
            for n in 0..3 {
                sender
                    .send(Message::Line(record(&format!("event n={n}"))))
                    .unwrap();
            }
            // A sync answers once every line before it is written.
            let (ack, done) = sync_channel(1);
            sender.send(Message::Sync(ack)).unwrap();
            done.recv().unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let text = if name.ends_with(".gz") {
                // The sync closed the member: a strict reader, as the
                // `gzip` tool is, reads it without any error.
                use std::io::Read as _;
                let mut strict = String::new();
                flate2::read::MultiGzDecoder::new(bytes.as_slice())
                    .read_to_string(&mut strict)
                    .expect("complete gzip members after a sync");
                strict
            } else {
                String::from_utf8(bytes).unwrap()
            };
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(lines.len(), 3, "{name}: {text:?}");
            assert!(lines[2].ends_with("phase_c event n=2"), "{name}: {text:?}");
            // Without any sync: the batch is flushed when the channel is
            // empty.
            sender
                .send(Message::Line(record("after the sync")))
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let bytes = std::fs::read(&path).unwrap();
                let text = if name.ends_with(".gz") {
                    gunzip_partial(&bytes)
                } else {
                    String::from_utf8(bytes).unwrap()
                };
                if text.lines().count() == 4 {
                    assert!(text.ends_with("after the sync\n"), "{text:?}");
                    break;
                }
                assert!(Instant::now() < deadline, "{name}: never flushed: {text:?}");
                std::thread::sleep(Duration::from_millis(5));
            }
            drop(sender);
            writer.join().unwrap();
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Off (the state of every test process: `start` is never called by
    /// the unit tests), logging does nothing and never runs the label.
    #[test]
    fn test_off_does_no_work() {
        assert!(!enabled());
        let step = span("phase_a", || panic!("the label must not be built"));
        assert!(!step.is_on());
        step.end_with(|| panic!("nor the details"));
        fn message() -> &'static str {
            panic!("nor the message")
        }
        crate::debug_log!("phase_a", "{}", message());
        assert_eq!(path(), None);
    }

    #[test]
    fn test_default_path_is_in_the_logs_folder() {
        let path = default_path(Path::new("/p/audit-reports/audit-datas"));
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(
            path.starts_with("/p/audit-reports/audit-datas/logs")
                && name.starts_with("scan-")
                && name.ends_with(".log.gz"),
            "{path:?}"
        );
    }
}
