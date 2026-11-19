//! `cups-log` — the scheduler log files (`error_log`, `access_log`,
//! `page_log`, plus enterprise audit and structured JSON output), ported
//! from `scheduler/log.c`:
//!
//! - `error_log`: `L [dd/Mon/yyyy:HH:MM:SS ±ZZZZ] message`
//! - `access_log`: common log format + op/status names
//!   (`host - user [time] "METHOD uri HTTP/x.y" code bytes op status`)
//! - `page_log`: `PageLogFormat` template expansion
//!   (`%p %u %j %T %P %C %{attr}`)
//! - `audit_log`: structured enterprise audit events (text or JSON for SIEM/ELK/Loki)
//!
//! Security & operations hardening:
//! - Multi-threaded safe localtime via pure-Rust `TZif` (RFC 8536) + POSIX `$TZ`
//!   resolution (avoids `time::OffsetDateTime::now_local()` silently falling
//!   back to UTC in multi-threaded Linux processes).
//! - Enforces `LogLevel`, `AccessLogLevel`, `LogFilePerm`, `O_NOFOLLOW`
//!   (rejects symlink targets), and `MaxLogSize` atomic `.O` rotation.
//! - Supports [`Sink::reopen`] for `SIGHUP` / `logrotate`.
//! - Sanitizes `\r`, `\n`, and control characters in all log output to defeat
//!   CRLF log forging.

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use ipp_codec::{Attribute, Value};

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "m68k",
        target_arch = "powerpc",
        target_arch = "powerpc64",
    )
))]
const O_NOFOLLOW: i32 = 0x8000;

#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "m68k",
        target_arch = "powerpc",
        target_arch = "powerpc64",
    ))
))]
const O_NOFOLLOW: i32 = 0x20000;

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const O_NOFOLLOW: i32 = 0x0100;

/// Default log file permission (`0640` — owner read/write, group read).
pub const DEFAULT_LOG_FILE_PERM: u32 = 0o640;

/// Default `MaxLogSize` (1 MiB, matching upstream `CUPS_DEFAULT_MAX_LOG_SIZE`).
pub const DEFAULT_MAX_LOG_SIZE: u64 = 1024 * 1024;

/// `cupsd` log levels — the `levels[]` array order in `cupsdWriteErrorLog`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    /// Emergency (`X`).
    Emergency = 1,
    /// Alert (`A`).
    Alert = 2,
    /// Critical (`C`).
    Crit = 3,
    /// Error (`E`).
    Error = 4,
    /// Warning (`W`).
    Warn = 5,
    /// Notice (`N`).
    Notice = 6,
    /// Info (`I`).
    Info = 7,
    /// Debug (`D`).
    Debug = 8,
    /// Debug2 (`d`).
    Debug2 = 9,
}

impl Level {
    /// Single-letter tag as written to `error_log`.
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::Emergency => 'X',
            Self::Alert => 'A',
            Self::Crit => 'C',
            Self::Error => 'E',
            Self::Warn => 'W',
            Self::Notice => 'N',
            Self::Info => 'I',
            Self::Debug => 'D',
            Self::Debug2 => 'd',
        }
    }

    /// Lowercase severity string for structured JSON logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emerg",
            Self::Alert => "alert",
            Self::Crit => "crit",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Notice => "notice",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Debug2 => "debug2",
        }
    }
}

/// Configured `LogLevel` threshold (includes `None` to suppress all error logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum LogLevelFilter {
    /// Disable `error_log` emission.
    None,
    /// Only Emergency.
    Emergency,
    /// Alert and above.
    Alert,
    /// Critical and above.
    Crit,
    /// Error and above.
    Error,
    /// Warning and above (CUPS default).
    #[default]
    Warn,
    /// Notice and above.
    Notice,
    /// Info and above.
    Info,
    /// Debug and above.
    Debug,
    /// All messages including Debug2.
    Debug2,
}

impl LogLevelFilter {
    /// Parse a `LogLevel` directive value.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "none" => Self::None,
            "emerg" | "emergency" => Self::Emergency,
            "alert" => Self::Alert,
            "crit" | "critical" => Self::Crit,
            "error" => Self::Error,
            "warn" | "warning" => Self::Warn,
            "notice" => Self::Notice,
            "info" => Self::Info,
            "debug" => Self::Debug,
            "debug2" => Self::Debug2,
            _ => return None,
        })
    }

    /// Returns `true` if a message at `level` should be emitted under this filter.
    #[must_use]
    pub const fn allows(self, level: Level) -> bool {
        let max_rank = match self {
            Self::None => 0,
            Self::Emergency => 1,
            Self::Alert => 2,
            Self::Crit => 3,
            Self::Error => 4,
            Self::Warn => 5,
            Self::Notice => 6,
            Self::Info => 7,
            Self::Debug => 8,
            Self::Debug2 => 9,
        };
        (level as u8) <= max_rank
    }
}

/// `AccessLogLevel` setting (`none`, `config`, `actions`, `all`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessLogLevel {
    /// Log nothing to `access_log`.
    None,
    /// Log configuration/admin changes only.
    Config,
    /// Log config + print/job state-changing actions (CUPS default).
    #[default]
    Actions,
    /// Log every HTTP/IPP request including read-only queries.
    All,
}

/// Classification of an HTTP/IPP request for `AccessLogLevel` filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessCategory {
    /// Configuration or printer/class admin mutation.
    Config,
    /// Print/job submission or state-changing action.
    Action,
    /// Read-only query or static asset fetch.
    Query,
}

impl AccessLogLevel {
    /// Parse an `AccessLogLevel` directive value.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "none" => Self::None,
            "config" => Self::Config,
            "actions" => Self::Actions,
            "all" => Self::All,
            _ => return None,
        })
    }

    /// Returns `true` if a request in `category` should be logged.
    #[must_use]
    pub const fn allows(self, category: AccessCategory) -> bool {
        match self {
            Self::None => false,
            Self::Config => matches!(category, AccessCategory::Config),
            Self::Actions => matches!(category, AccessCategory::Config | AccessCategory::Action),
            Self::All => true,
        }
    }
}

/// Output serialization format for logs and audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Classic CUPS / CLF plain text format.
    #[default]
    Text,
    /// Structured single-line JSON (NDJSON) for SIEM/ELK/Loki ingestion.
    Json,
}

/// `LogTimeFormat` variants (upstream `CUPSD_TIME_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeFormat {
    /// `[dd/Mon/yyyy:HH:MM:SS ±ZZZZ]` (upstream default).
    #[default]
    Standard,
    /// Same with `.usecs` appended — `LogTimeFormat usecs`.
    Usecs,
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

static SYSTEM_TZIF: OnceLock<Option<Vec<u8>>> = OnceLock::new();

fn cached_system_tzif() -> Option<&'static [u8]> {
    SYSTEM_TZIF
        .get_or_init(|| std::fs::read("/etc/localtime").ok())
        .as_deref()
}

/// Parse an RFC 8536 `TZif` (v1/v2/v3) binary timezone file and resolve the
/// local [`time::UtcOffset`] for `unix_ts`.
#[must_use]
pub fn parse_tzif_offset(data: &[u8], unix_ts: i64) -> Option<time::UtcOffset> {
    if data.len() < 44 || &data[0..4] != b"TZif" {
        return None;
    }
    let version = data[4];
    let rd32 = |off: usize| -> Option<usize> {
        let b: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
        Some(u32::from_be_bytes(b) as usize)
    };
    let isutcnt = rd32(20)?;
    let isstdcnt = rd32(24)?;
    let leapcnt = rd32(28)?;
    let timecnt = rd32(32)?;
    let typecnt = rd32(36)?;
    let charcnt = rd32(40)?;

    // If v2/v3, skip the 32-bit v1 block and parse the 64-bit block that follows.
    if version >= b'2' {
        let v1_body = timecnt
            .checked_mul(5)?
            .checked_add(typecnt.checked_mul(6)?)?
            .checked_add(charcnt)?
            .checked_add(leapcnt.checked_mul(8)?)?
            .checked_add(isstdcnt)?
            .checked_add(isutcnt)?;
        let v2_start = 44usize.checked_add(v1_body)?;
        if let Some(v2) = data.get(v2_start..) {
            if v2.len() >= 44 && &v2[0..4] == b"TZif" {
                return parse_tzif_block(v2, unix_ts, true);
            }
        }
    }
    parse_tzif_block(data, unix_ts, false)
}

fn parse_tzif_block(block: &[u8], unix_ts: i64, is_64: bool) -> Option<time::UtcOffset> {
    let rd32 = |off: usize| -> Option<usize> {
        let b: [u8; 4] = block.get(off..off + 4)?.try_into().ok()?;
        Some(u32::from_be_bytes(b) as usize)
    };
    let timecnt = rd32(32)?;
    let typecnt = rd32(36)?;
    if typecnt == 0 {
        return None;
    }

    let ts_width = if is_64 { 8usize } else { 4usize };
    let times_start = 44usize;
    let types_start = times_start.checked_add(timecnt.checked_mul(ts_width)?)?;
    let ttinfo_start = types_start.checked_add(timecnt)?;
    let ttinfo_end = ttinfo_start.checked_add(typecnt.checked_mul(6)?)?;
    if block.len() < ttinfo_end {
        return None;
    }

    // Binary search transition timestamps (sorted ascending per RFC 8536).
    let mut lo = 0usize;
    let mut hi = timecnt;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let off = times_start + mid * ts_width;
        let t = if is_64 {
            i64::from_be_bytes(block[off..off + 8].try_into().ok()?)
        } else {
            i64::from(i32::from_be_bytes(block[off..off + 4].try_into().ok()?))
        };
        if t <= unix_ts {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    let tt_idx = if lo > 0 {
        usize::from(block[types_start + lo - 1])
    } else {
        // Before first transition: first non-DST ttinfo, or 0.
        (0..typecnt)
            .find(|&i| block[ttinfo_start + i * 6 + 4] == 0)
            .unwrap_or(0)
    };
    if tt_idx >= typecnt {
        return None;
    }
    let off = ttinfo_start + tt_idx * 6;
    let utoff = i32::from_be_bytes(block[off..off + 4].try_into().ok()?);
    time::UtcOffset::from_whole_seconds(utoff).ok()
}

/// Parse a simple POSIX `TZ` offset string (e.g. `"UTC"`, `"EST5"`, `"CET-1"`, `"IST-5:30"`).
#[must_use]
pub fn parse_posix_tz_offset(tz: &str) -> Option<time::UtcOffset> {
    let s = tz.trim();
    if s.is_empty() {
        return None;
    }
    if s.eq_ignore_ascii_case("UTC") || s.eq_ignore_ascii_case("GMT") || s == "Z" {
        return Some(time::UtcOffset::UTC);
    }
    // Skip alphabetic std abbreviation (or `<...>` quoted abbreviation).
    let rest = if let Some(after_lt) = s.strip_prefix('<') {
        after_lt.split_once('>')?.1
    } else {
        let idx = s.find(|c: char| !c.is_ascii_alphabetic())?;
        &s[idx..]
    };
    if rest.is_empty() {
        return None;
    }
    // POSIX TZ sign is inverted relative to ISO-8601: `EST5` means UTC-5, `CET-1` means UTC+1.
    let (west, digits) = if let Some(r) = rest.strip_prefix('-') {
        (false, r)
    } else if let Some(r) = rest.strip_prefix('+') {
        (true, r)
    } else {
        (true, rest)
    };
    // Take offset component before any DST abbreviation or comma rule.
    let off_end = digits
        .find(|c: char| !(c.is_ascii_digit() || c == ':'))
        .unwrap_or(digits.len());
    let off_str = &digits[..off_end];
    let mut parts = off_str.split(':');
    let h: i32 = parts.next()?.parse().ok()?;
    let m: i32 = parts.next().map_or(Ok(0), str::parse).ok()?;
    let sec: i32 = parts.next().map_or(Ok(0), str::parse).ok()?;
    if h > 24 || m >= 60 || sec >= 60 {
        return None;
    }
    let total = h * 3600 + m * 60 + sec;
    let signed = if west { -total } else { total };
    time::UtcOffset::from_whole_seconds(signed).ok()
}

/// Resolve the local [`time::UtcOffset`] for `unix_ts` safely in multi-threaded processes.
#[must_use]
pub fn local_offset_at(unix_ts: i64) -> time::UtcOffset {
    if let Ok(tz) = std::env::var("TZ") {
        let trimmed = tz.trim();
        if !trimmed.is_empty() {
            let file_path = trimmed.strip_prefix(':').unwrap_or(trimmed);
            let candidate = if file_path.starts_with('/') {
                PathBuf::from(file_path)
            } else {
                Path::new("/usr/share/zoneinfo").join(file_path)
            };
            if let Ok(bytes) = std::fs::read(candidate) {
                if let Some(off) = parse_tzif_offset(&bytes, unix_ts) {
                    return off;
                }
            }
            if let Some(off) = parse_posix_tz_offset(trimmed) {
                return off;
            }
        }
    }
    if let Some(bytes) = cached_system_tzif() {
        if let Some(off) = parse_tzif_offset(bytes, unix_ts) {
            return off;
        }
    }
    time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC)
}

/// Current local time with accurate timezone offset (safe across multiple threads).
#[must_use]
pub fn local_now() -> time::OffsetDateTime {
    let utc = time::OffsetDateTime::now_utc();
    utc.to_offset(local_offset_at(utc.unix_timestamp()))
}

/// Format an arbitrary [`time::OffsetDateTime`] in CUPS CLF format:
/// `[dd/Mon/yyyy:HH:MM:SS[.uuuuuu] ±ZZZZ]`.
#[must_use]
pub fn format_datetime(ts: time::OffsetDateTime, format: TimeFormat) -> String {
    let off = ts.offset();
    let (h, m, _s) = off.as_hms();
    let sign = if off.whole_seconds() < 0 { '-' } else { '+' };
    let mon = MONTHS[ts.month() as usize - 1];
    let mut s = String::with_capacity(40);
    let _ = write!(
        s,
        "[{:02}/{}/{:04}:{:02}:{:02}:{:02}",
        ts.day(),
        mon,
        ts.year(),
        ts.hour(),
        ts.minute(),
        ts.second()
    );
    if format == TimeFormat::Usecs {
        let _ = write!(s, ".{:06}", ts.microsecond());
    }
    let _ = write!(s, " {}{:02}{:02}]", sign, h.abs(), m.abs());
    s
}

/// Format an [`time::OffsetDateTime`] as RFC 3339 (for JSON & SIEM audit logs).
#[must_use]
pub fn format_rfc3339(ts: time::OffsetDateTime, usecs: bool) -> String {
    let off = ts.offset();
    let (h, m, _s) = off.as_hms();
    let mut s = String::with_capacity(36);
    let _ = write!(
        s,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        ts.year(),
        ts.month() as u8,
        ts.day(),
        ts.hour(),
        ts.minute(),
        ts.second()
    );
    if usecs {
        let _ = write!(s, ".{:06}", ts.microsecond());
    }
    if off.whole_seconds() == 0 {
        s.push('Z');
    } else {
        let sign = if off.whole_seconds() < 0 { '-' } else { '+' };
        let _ = write!(s, "{}{:02}:{:02}", sign, h.abs(), m.abs());
    }
    s
}

/// `cupsdGetDateTime()` — `[dd/Mon/yyyy:HH:MM:SS[.uuuuuu] ±ZZZZ]`.
#[must_use]
pub fn datetime(format: TimeFormat) -> String {
    format_datetime(local_now(), format)
}

/// Sanitize a string for single-line log safety: escapes `\r`, `\n`, `\t`,
/// `\0`, ASCII control bytes, and Unicode line/C1 controls to block CRLF log forging.
#[must_use]
pub fn sanitize(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            '\x01'..='\x1f' | '\x7f' => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            '\u{0080}'..='\u{009f}' | '\u{2028}' | '\u{2029}' => {
                let _ = write!(out, "\\u{{{:04x}}}", c as u32);
            }
            _ => out.push(c),
        }
    }
    out
}

fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\x7f' || c == '\u{2028}' || c == '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            _ => out.push(c),
        }
    }
    out.push('"');
}

struct OpenLog {
    file: File,
    size: u64,
}

/// One log sink — a lazily-opened file (or stderr) with `LogFilePerm`,
/// `O_NOFOLLOW`, `MaxLogSize` `.O` rotation, and `SIGHUP` [`Self::reopen`].
pub struct Sink {
    inner: Mutex<Option<OpenLog>>,
    path: PathBuf,
    /// Fallback when the file can't be opened (upstream logs to
    /// stderr when running with `-f`).
    stderr: bool,
    /// File mode (`LogFilePerm`, default `0640`).
    perm: u32,
    /// Rotation threshold (`MaxLogSize`, default 1 MiB; `0` = no rotation).
    max_size: u64,
}

impl Sink {
    /// A file-backed sink with secure defaults (`0640` perms, 1 MiB `MaxLogSize`).
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            inner: Mutex::new(None),
            path: path.into(),
            stderr: false,
            perm: DEFAULT_LOG_FILE_PERM,
            max_size: DEFAULT_MAX_LOG_SIZE,
        }
    }

    /// A file-backed sink with explicit `LogFilePerm` and `MaxLogSize` (`0` = unlimited).
    #[must_use]
    pub fn file_with_options(path: impl Into<PathBuf>, perm: u32, max_size: u64) -> Self {
        Self {
            inner: Mutex::new(None),
            path: path.into(),
            stderr: false,
            perm: perm & 0o777,
            max_size,
        }
    }

    /// Override `LogFilePerm` mode bits on this sink.
    #[must_use]
    pub const fn with_perm(mut self, perm: u32) -> Self {
        self.perm = perm & 0o777;
        self
    }

    /// Override `MaxLogSize` bytes on this sink (`0` disables rotation).
    #[must_use]
    pub const fn with_max_size(mut self, max_size: u64) -> Self {
        self.max_size = max_size;
        self
    }

    /// Stderr sink (foreground mode).
    #[must_use]
    pub fn stderr() -> Self {
        Self {
            inner: Mutex::new(None),
            path: PathBuf::from("/dev/stderr"),
            stderr: true,
            perm: DEFAULT_LOG_FILE_PERM,
            max_size: 0,
        }
    }

    /// Path configured for this sink.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reopen the underlying log file (for `SIGHUP` / external `logrotate`).
    pub fn reopen(&self) -> io::Result<()> {
        if self.stderr {
            return Ok(());
        }
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = None;
        let opened = open_log_file(&self.path, self.perm)?;
        *guard = Some(opened);
        Ok(())
    }

    /// Atomically rotate `<path>` to `<path>.O` and open a fresh log file.
    pub fn rotate(&self) -> io::Result<()> {
        if self.stderr {
            return Ok(());
        }
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        rotate_locked(&self.path, self.perm, &mut guard)
    }

    /// Write one formatted line (sanitizing any embedded CR/LF/NUL); returns `false` on error.
    pub fn write(&self, line: &str) -> bool {
        let clean: std::borrow::Cow<'_, str> =
            if line.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
                std::borrow::Cow::Owned(sanitize(line))
            } else {
                std::borrow::Cow::Borrowed(line)
            };
        if self.stderr {
            let _ = writeln!(io::stderr(), "{clean}");
            return true;
        }
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_none() {
            match open_log_file(&self.path, self.perm) {
                Ok(opened) => *guard = Some(opened),
                Err(_) => return false,
            }
        }
        let line_len = (clean.len() + 1) as u64;
        if self.max_size > 0 {
            let needs_rotate = guard
                .as_ref()
                .is_some_and(|st| st.size > 0 && st.size.saturating_add(line_len) > self.max_size);
            if needs_rotate && rotate_locked(&self.path, self.perm, &mut guard).is_err() {
                return false;
            }
        }
        let Some(st) = guard.as_mut() else {
            return false;
        };
        if st.file.write_all(clean.as_bytes()).is_ok() && st.file.write_all(b"\n").is_ok() {
            st.size = st.size.saturating_add(line_len);
            true
        } else {
            false
        }
    }

    /// Format and write an [`AuditEvent`] in `format` (`Text` or `Json`).
    pub fn write_audit(&self, event: &AuditEvent<'_>, format: LogFormat) -> bool {
        self.write(&audit_event(event, format))
    }
}

fn open_log_file(path: &Path, perm: u32) -> io::Result<OpenLog> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        opts.mode(perm).custom_flags(O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("log target {} is not a regular file", path.display()),
        ));
    }
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(perm))?;
    Ok(OpenLog {
        size: meta.len(),
        file,
    })
}

fn backup_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".O");
    PathBuf::from(os)
}

fn rotate_locked(path: &Path, perm: u32, slot: &mut Option<OpenLog>) -> io::Result<()> {
    if let Some(st) = slot.as_mut() {
        let _ = st.file.flush();
    }
    *slot = None;
    let backup = backup_path(path);
    match std::fs::rename(path, &backup) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    *slot = Some(open_log_file(path, perm)?);
    Ok(())
}

/// `cupsdWriteErrorLog()` — `L [time] message` (sanitized against CRLF injection).
#[must_use]
pub fn error_line(level: Level, tf: TimeFormat, message: &str) -> String {
    format!("{} {} {}", level.letter(), datetime(tf), sanitize(message))
}

/// Structured JSON equivalent of [`error_line`].
#[must_use]
pub fn error_json(level: Level, tf: TimeFormat, message: &str) -> String {
    let ts = format_rfc3339(local_now(), tf == TimeFormat::Usecs);
    let mut out = String::with_capacity(message.len() + 96);
    out.push_str("{\"timestamp\":");
    push_json_str(&mut out, &ts);
    out.push_str(",\"log_type\":\"error\",\"level\":");
    push_json_str(&mut out, level.as_str());
    out.push_str(",\"message\":");
    push_json_str(&mut out, message);
    out.push('}');
    out
}

/// `cupsdLogRequest()` — common log format + `op-name status-name` tail.
#[must_use]
#[allow(clippy::too_many_arguments)] // fixed cupsdLogRequest signature
pub fn access_line(
    host: &str,
    user: Option<&str>,
    tf: TimeFormat,
    method: &str,
    uri: &str,
    version: (u8, u8),
    code: u16,
    bytes: u64,
    op_name: &str,
    status_name: &str,
    con_start: Option<time::OffsetDateTime>,
) -> String {
    let ts = con_start.map_or_else(
        || datetime(tf),
        |t| format_datetime(t.to_offset(local_offset_at(t.unix_timestamp())), tf),
    );
    format!(
        "{} - {} {} \"{} {} HTTP/{}.{}\" {} {} {} {}",
        sanitize(host),
        user.map_or_else(|| "-".to_string(), sanitize),
        ts,
        sanitize(method),
        encode_uri(uri),
        version.0,
        version.1,
        code,
        bytes,
        sanitize(op_name),
        sanitize(status_name)
    )
}

/// Structured JSON equivalent of [`access_line`].
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn access_json(
    host: &str,
    user: Option<&str>,
    tf: TimeFormat,
    method: &str,
    uri: &str,
    version: (u8, u8),
    code: u16,
    bytes: u64,
    op_name: &str,
    status_name: &str,
    con_start: Option<time::OffsetDateTime>,
) -> String {
    let raw_ts = con_start.map_or_else(local_now, |t| {
        t.to_offset(local_offset_at(t.unix_timestamp()))
    });
    let ts = format_rfc3339(raw_ts, tf == TimeFormat::Usecs);
    let mut out = String::with_capacity(256);
    out.push_str("{\"timestamp\":");
    push_json_str(&mut out, &ts);
    out.push_str(",\"log_type\":\"access\",\"host\":");
    push_json_str(&mut out, host);
    out.push_str(",\"user\":");
    match user {
        Some(u) => push_json_str(&mut out, u),
        None => out.push_str("null"),
    }
    out.push_str(",\"method\":");
    push_json_str(&mut out, method);
    out.push_str(",\"uri\":");
    push_json_str(&mut out, uri);
    let _ = write!(
        out,
        ",\"http_version\":\"{}.{}\",\"status\":{},\"bytes\":{},\"operation\":",
        version.0, version.1, code, bytes
    );
    push_json_str(&mut out, op_name);
    out.push_str(",\"ipp_status\":");
    push_json_str(&mut out, status_name);
    out.push('}');
    out
}

/// `_httpEncodeURI` — escape `"` and control/unsafe chars for the
/// quoted request field (upstream escapes `%`, `"`, space, controls).
fn encode_uri(uri: &str) -> String {
    let mut out = String::with_capacity(uri.len() + 8);
    for b in uri.bytes() {
        match b {
            b'"' | b'\\' | b'%' | 0x00..=0x1f | 0x7f..=0xff => {
                let _ = write!(out, "%{b:02X}");
            }
            0x20 => out.push('+'),
            _ => out.push(b as char),
        }
    }
    out
}

/// `cupsdLogPage()` — expand `PageLogFormat` for one printed page.
///
/// `%p` printer, `%u` user, `%j` job-id, `%T` time, `%P` page number,
/// `%C` copies, `%{attr}` job attribute (multi -> comma-joined, absent -> `-`),
/// `%%` literal.
///
/// `page` is the backend's `PAGE:` line tail — `"number copies"` (the
/// `sscanf("%255s%d")` split upstream does).
#[must_use]
pub fn page_line(
    format: &str,
    printer: &str,
    user: Option<&str>,
    job_id: i32,
    page: &str,
    job_attrs: &[Attribute],
    tf: TimeFormat,
) -> String {
    let mut parts = page.split_whitespace();
    let number = sanitize(parts.next().unwrap_or("1"));
    let copies: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(1);
    let clean_printer = sanitize(printer);
    let clean_user = user.map_or_else(|| "-".to_string(), sanitize);

    let mut out = String::with_capacity(256);
    let mut it = format.chars().peekable();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('%') | None => out.push('%'),
            Some('p') => out.push_str(&clean_printer),
            Some('j') => {
                let _ = write!(out, "{job_id}");
            }
            Some('u') => out.push_str(&clean_user),
            Some('T') => out.push_str(&datetime(tf)),
            Some('P') => out.push_str(&number),
            Some('C') => {
                let _ = write!(out, "{copies}");
            }
            Some('{') => {
                let mut name = String::new();
                for c in it.by_ref() {
                    if c == '}' {
                        break;
                    }
                    name.push(c);
                }
                append_page_attr(&mut out, &name, job_attrs);
            }
            Some(other) => {
                out.push('%');
                out.push(other);
            }
        }
    }
    sanitize(&out)
}

fn append_page_attr(out: &mut String, name: &str, job_attrs: &[Attribute]) {
    let lookup = if name == "job-billing" {
        job_attrs
            .iter()
            .find(|a| a.name == "job-billing")
            .or_else(|| job_attrs.iter().find(|a| a.name == "job-account-id"))
    } else if name == "media" {
        job_attrs
            .iter()
            .find(|a| a.name == "media")
            .or_else(|| job_attrs.iter().find(|a| a.name == "media-col/media-size"))
    } else {
        job_attrs.iter().find(|a| a.name == name)
    };
    let Some(attr) = lookup else {
        out.push('-');
        return;
    };
    if attr.values.is_empty() {
        out.push('-');
        return;
    }
    for (i, v) in attr.values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        match v {
            Value::Integer(x) | Value::Enum(x) => {
                let _ = write!(out, "{x}");
            }
            Value::Boolean(b) => {
                let _ = write!(out, "{}", i32::from(*b));
            }
            Value::Text(t)
            | Value::Name(t)
            | Value::Keyword(t)
            | Value::Uri(t)
            | Value::UriScheme(t)
            | Value::Charset(t)
            | Value::NaturalLanguage(t)
            | Value::MimeMediaType(t) => out.push_str(&sanitize(&t.as_str())),
            Value::TextWithLanguage { text, .. } | Value::NameWithLanguage { text, .. } => {
                out.push_str(&sanitize(&text.as_str()));
            }
            _ => out.push('-'),
        }
    }
}

/// Structured JSON equivalent of [`page_line`].
#[must_use]
pub fn page_json(
    printer: &str,
    user: Option<&str>,
    job_id: i32,
    page: &str,
    tf: TimeFormat,
) -> String {
    let mut parts = page.split_whitespace();
    let number = parts.next().unwrap_or("1");
    let copies: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(1);
    let ts = format_rfc3339(local_now(), tf == TimeFormat::Usecs);
    let mut out = String::with_capacity(160);
    out.push_str("{\"timestamp\":");
    push_json_str(&mut out, &ts);
    out.push_str(",\"log_type\":\"page\",\"printer\":");
    push_json_str(&mut out, printer);
    out.push_str(",\"user\":");
    match user {
        Some(u) => push_json_str(&mut out, u),
        None => out.push_str("null"),
    }
    let _ = write!(out, ",\"job_id\":{job_id},\"page\":");
    push_json_str(&mut out, number);
    let _ = write!(out, ",\"copies\":{copies}}}");
    out
}

/// Outcome classification for enterprise security audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// Action succeeded.
    Success,
    /// Action denied by authentication or authorization policy.
    Denied,
    /// Action failed due to client/input error.
    Failure,
    /// Action failed due to internal/system error.
    Error,
}

impl AuditOutcome {
    /// Wire/log string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Failure => "failure",
            Self::Error => "error",
        }
    }
}

/// Dedicated enterprise audit record (print/admin mutations, auth decisions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent<'a> {
    /// Event timestamp (defaults to [`local_now`] when `None`).
    pub timestamp: Option<time::OffsetDateTime>,
    /// Authenticated username or `"anonymous"`.
    pub actor: &'a str,
    /// Remote peer IP address or `"unix"`.
    pub peer_ip: &'a str,
    /// Authentication method (`"basic"`, `"peercred"`, `"mtls"`, `"bearer"`, `"none"`).
    pub auth_method: &'a str,
    /// IPP or HTTP operation (`"Print-Job"`, `"CUPS-Add-Modify-Printer"`, etc.).
    pub operation: &'a str,
    /// Resource URI, printer name, or job target.
    pub target: &'a str,
    /// Authorization/execution outcome.
    pub outcome: AuditOutcome,
    /// Extra non-secret diagnostic detail.
    pub detail: &'a str,
}

/// Format an [`AuditEvent`] in the requested [`LogFormat`] (`Text` or `Json`).
#[must_use]
pub fn audit_event(event: &AuditEvent<'_>, format: LogFormat) -> String {
    match format {
        LogFormat::Text => audit_event_text(event),
        LogFormat::Json => audit_event_json(event),
    }
}

/// Format an [`AuditEvent`] as structured JSON for SIEM/ELK/Loki ingestion.
#[must_use]
pub fn audit_event_json(event: &AuditEvent<'_>) -> String {
    let raw_ts = event.timestamp.map_or_else(local_now, |t| {
        t.to_offset(local_offset_at(t.unix_timestamp()))
    });
    let ts = format_rfc3339(raw_ts, true);
    let mut out = String::with_capacity(256);
    out.push_str("{\"timestamp\":");
    push_json_str(&mut out, &ts);
    out.push_str(",\"log_type\":\"audit\",\"actor\":");
    push_json_str(&mut out, event.actor);
    out.push_str(",\"peer_ip\":");
    push_json_str(&mut out, event.peer_ip);
    out.push_str(",\"auth_method\":");
    push_json_str(&mut out, event.auth_method);
    out.push_str(",\"operation\":");
    push_json_str(&mut out, event.operation);
    out.push_str(",\"target\":");
    push_json_str(&mut out, event.target);
    out.push_str(",\"outcome\":");
    push_json_str(&mut out, event.outcome.as_str());
    out.push_str(",\"detail\":");
    push_json_str(&mut out, event.detail);
    out.push('}');
    out
}

/// Format an [`AuditEvent`] as sanitized single-line key=value text.
#[must_use]
pub fn audit_event_text(event: &AuditEvent<'_>) -> String {
    let raw_ts = event.timestamp.map_or_else(local_now, |t| {
        t.to_offset(local_offset_at(t.unix_timestamp()))
    });
    format!(
        "AUDIT {} actor={} peer_ip={} auth_method={} operation={} target={} outcome={} detail={}",
        format_datetime(raw_ts, TimeFormat::Standard),
        sanitize(event.actor),
        sanitize(event.peer_ip),
        sanitize(event.auth_method),
        sanitize(event.operation),
        sanitize(event.target),
        event.outcome.as_str(),
        sanitize(event.detail),
    )
}

/// High-level scheduler logger combining `error_log`, `access_log`, `page_log`,
/// and `audit_log` sinks with level filtering, format selection, and `SIGHUP` reopen.
pub struct Logger {
    /// `error_log` sink.
    pub error: Sink,
    /// `access_log` sink.
    pub access: Sink,
    /// Optional `page_log` sink.
    pub page: Option<Sink>,
    /// Optional dedicated `audit_log` sink.
    pub audit: Option<Sink>,
    /// `LogLevel` filter.
    pub error_level: LogLevelFilter,
    /// `AccessLogLevel` filter.
    pub access_level: AccessLogLevel,
    /// Timestamp precision (`Standard` vs `Usecs`).
    pub time_format: TimeFormat,
    /// Output format (`Text` vs `Json`).
    pub format: LogFormat,
}

impl Logger {
    /// Emit an `error_log` entry if permitted by `self.error_level`.
    pub fn log_error(&self, level: Level, message: &str) -> bool {
        if !self.error_level.allows(level) {
            return false;
        }
        let line = match self.format {
            LogFormat::Text => error_line(level, self.time_format, message),
            LogFormat::Json => error_json(level, self.time_format, message),
        };
        self.error.write(&line)
    }

    /// Emit an `access_log` entry if permitted by `self.access_level`.
    #[allow(clippy::too_many_arguments)]
    pub fn log_access(
        &self,
        category: AccessCategory,
        host: &str,
        user: Option<&str>,
        method: &str,
        uri: &str,
        version: (u8, u8),
        code: u16,
        bytes: u64,
        op_name: &str,
        status_name: &str,
        con_start: Option<time::OffsetDateTime>,
    ) -> bool {
        if !self.access_level.allows(category) {
            return false;
        }
        let line = match self.format {
            LogFormat::Text => access_line(
                host,
                user,
                self.time_format,
                method,
                uri,
                version,
                code,
                bytes,
                op_name,
                status_name,
                con_start,
            ),
            LogFormat::Json => access_json(
                host,
                user,
                self.time_format,
                method,
                uri,
                version,
                code,
                bytes,
                op_name,
                status_name,
                con_start,
            ),
        };
        self.access.write(&line)
    }

    /// Emit a `page_log` entry when `self.page` is configured.
    pub fn log_page(
        &self,
        page_format: &str,
        printer: &str,
        user: Option<&str>,
        job_id: i32,
        page: &str,
        job_attrs: &[Attribute],
    ) -> bool {
        let Some(sink) = &self.page else {
            return false;
        };
        let line = match self.format {
            LogFormat::Text => page_line(
                page_format,
                printer,
                user,
                job_id,
                page,
                job_attrs,
                self.time_format,
            ),
            LogFormat::Json => page_json(printer, user, job_id, page, self.time_format),
        };
        sink.write(&line)
    }

    /// Emit an enterprise [`AuditEvent`] to `self.audit` (falling back to `self.error`).
    pub fn log_audit(&self, event: &AuditEvent<'_>) -> bool {
        let target = self.audit.as_ref().unwrap_or(&self.error);
        target.write_audit(event, self.format)
    }

    /// Reopen all file-backed sinks (for `SIGHUP`).
    pub fn reopen_all(&self) -> io::Result<()> {
        self.error.reopen()?;
        self.access.reopen()?;
        if let Some(p) = &self.page {
            p.reopen()?;
        }
        if let Some(a) = &self.audit {
            a.reopen()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipp_codec::{tags, Text};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_path(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "yindle-log-test-{}-{label}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn build_minimal_tzif_v2(transitions: &[(i64, u8)], ttinfos: &[(i32, u8)]) -> Vec<u8> {
        // Minimal v1 header (0 transitions, 1 ttinfo) + v2 header + 64-bit block.
        let mut buf = Vec::new();
        // v1 header (44 bytes): 1 ttinfo, 1 char.
        buf.extend_from_slice(b"TZif2");
        buf.extend_from_slice(&[0u8; 15]);
        buf.extend_from_slice(&0u32.to_be_bytes()); // isutcnt
        buf.extend_from_slice(&0u32.to_be_bytes()); // isstdcnt
        buf.extend_from_slice(&0u32.to_be_bytes()); // leapcnt
        buf.extend_from_slice(&0u32.to_be_bytes()); // timecnt
        buf.extend_from_slice(&1u32.to_be_bytes()); // typecnt
        buf.extend_from_slice(&1u32.to_be_bytes()); // charcnt
                                                    // v1 body: 1 ttinfo (6 bytes) + 1 char.
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0]);

        // v2 header (44 bytes).
        buf.extend_from_slice(b"TZif2");
        buf.extend_from_slice(&[0u8; 15]);
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&u32::try_from(transitions.len()).unwrap().to_be_bytes());
        buf.extend_from_slice(&u32::try_from(ttinfos.len()).unwrap().to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        for (ts, _) in transitions {
            buf.extend_from_slice(&ts.to_be_bytes());
        }
        for (_, idx) in transitions {
            buf.push(*idx);
        }
        for (utoff, dst) in ttinfos {
            buf.extend_from_slice(&utoff.to_be_bytes());
            buf.push(*dst);
            buf.push(0);
        }
        buf.push(0);
        buf
    }

    #[test]
    fn tzif_and_posix_localtime_resolution_works_multithreaded() {
        // v2 TZif with winter (-5h) and summer (-4h) DST transitions.
        let tzif = build_minimal_tzif_v2(
            &[(1_000_000, 1), (2_000_000, 0)],
            &[(-18_000, 0), (-14_400, 1)],
        );
        assert_eq!(
            parse_tzif_offset(&tzif, 500_000),
            Some(time::UtcOffset::from_hms(-5, 0, 0).unwrap())
        );
        assert_eq!(
            parse_tzif_offset(&tzif, 1_500_000),
            Some(time::UtcOffset::from_hms(-4, 0, 0).unwrap())
        );
        assert_eq!(
            parse_tzif_offset(&tzif, 2_500_000),
            Some(time::UtcOffset::from_hms(-5, 0, 0).unwrap())
        );
        // Invalid magic / truncated rejected.
        assert_eq!(parse_tzif_offset(b"NOPE", 0), None);

        // v1-only TZif (32-bit transition).
        let mut v1 = Vec::new();
        v1.extend_from_slice(b"TZif\0");
        v1.extend_from_slice(&[0u8; 15]);
        v1.extend_from_slice(&0u32.to_be_bytes());
        v1.extend_from_slice(&0u32.to_be_bytes());
        v1.extend_from_slice(&0u32.to_be_bytes());
        v1.extend_from_slice(&1u32.to_be_bytes());
        v1.extend_from_slice(&1u32.to_be_bytes());
        v1.extend_from_slice(&1u32.to_be_bytes());
        v1.extend_from_slice(&100i32.to_be_bytes());
        v1.push(0);
        v1.extend_from_slice(&3600i32.to_be_bytes());
        v1.extend_from_slice(&[0, 0, 0]);
        assert_eq!(
            parse_tzif_offset(&v1, 200),
            Some(time::UtcOffset::from_hms(1, 0, 0).unwrap())
        );

        // POSIX TZ strings.
        assert_eq!(parse_posix_tz_offset("UTC"), Some(time::UtcOffset::UTC));
        assert_eq!(parse_posix_tz_offset("GMT"), Some(time::UtcOffset::UTC));
        assert_eq!(
            parse_posix_tz_offset("EST5EDT"),
            Some(time::UtcOffset::from_hms(-5, 0, 0).unwrap())
        );
        assert_eq!(
            parse_posix_tz_offset("CET-1"),
            Some(time::UtcOffset::from_hms(1, 0, 0).unwrap())
        );
        assert_eq!(
            parse_posix_tz_offset("IST-5:30"),
            Some(time::UtcOffset::from_hms(5, 30, 0).unwrap())
        );
        assert_eq!(
            parse_posix_tz_offset("<+03>+3"),
            Some(time::UtcOffset::from_hms(-3, 0, 0).unwrap())
        );
        assert_eq!(parse_posix_tz_offset(""), None);
        assert_eq!(parse_posix_tz_offset("BAD99"), None);

        // Verify datetime & RFC 3339 formatting across standard & usecs + negative/UTC offsets.
        let fixed = time::OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap()
            .to_offset(time::UtcOffset::from_hms(-5, 0, 0).unwrap());
        assert_eq!(
            format_datetime(fixed, TimeFormat::Standard),
            "[14/Nov/2023:17:13:20 -0500]"
        );
        assert_eq!(
            format_datetime(fixed, TimeFormat::Usecs),
            "[14/Nov/2023:17:13:20.000000 -0500]"
        );
        assert_eq!(format_rfc3339(fixed, false), "2023-11-14T17:13:20-05:00");
        assert_eq!(
            format_rfc3339(
                time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
                true
            ),
            "2023-11-14T22:13:20.000000Z"
        );

        // Multi-threaded local_now() resolves cleanly (and honors /etc/localtime if present).
        let _ = std::thread::spawn(|| datetime(TimeFormat::Usecs))
            .join()
            .unwrap();
    }

    #[test]
    fn levels_filters_and_sanitization() {
        let all_levels = [
            (Level::Emergency, 'X', "emerg", "emerg"),
            (Level::Alert, 'A', "alert", "alert"),
            (Level::Crit, 'C', "crit", "crit"),
            (Level::Error, 'E', "error", "error"),
            (Level::Warn, 'W', "warn", "warn"),
            (Level::Notice, 'N', "notice", "notice"),
            (Level::Info, 'I', "info", "info"),
            (Level::Debug, 'D', "debug", "debug"),
            (Level::Debug2, 'd', "debug2", "debug2"),
        ];
        for (lvl, ch, name, parse_s) in all_levels {
            assert_eq!(lvl.letter(), ch);
            assert_eq!(lvl.as_str(), name);
            let filt = LogLevelFilter::parse(parse_s).unwrap();
            assert!(filt.allows(lvl));
        }
        assert!(!LogLevelFilter::parse("none")
            .unwrap()
            .allows(Level::Emergency));
        assert!(LogLevelFilter::parse("invalid").is_none());
        assert!(LogLevelFilter::Warn.allows(Level::Error));
        assert!(!LogLevelFilter::Warn.allows(Level::Info));

        assert!(!AccessLogLevel::parse("none")
            .unwrap()
            .allows(AccessCategory::Config));
        assert!(AccessLogLevel::parse("config")
            .unwrap()
            .allows(AccessCategory::Config));
        assert!(!AccessLogLevel::Config.allows(AccessCategory::Action));
        assert!(AccessLogLevel::parse("actions")
            .unwrap()
            .allows(AccessCategory::Action));
        assert!(!AccessLogLevel::Actions.allows(AccessCategory::Query));
        assert!(AccessLogLevel::parse("all")
            .unwrap()
            .allows(AccessCategory::Query));
        assert!(AccessLogLevel::parse("unknown").is_none());

        // CRLF / control character sanitization.
        assert_eq!(
            sanitize("ok\r\nforged\t\0\x07\u{0085}\u{2028}"),
            "ok\\r\\nforged\\t\\0\\x07\\u{0085}\\u{2028}"
        );
        let el = error_line(Level::Warn, TimeFormat::Standard, "bad\r\nE fake");
        assert!(!el.contains('\n'));
        assert!(!el.contains('\r'));
        assert!(el.contains("bad\\r\\nE fake"));
    }

    #[test]
    fn sink_perms_nofollow_rotation_and_reopen() {
        let dir = temp_path("sink");
        let log_path = dir.join("error_log");
        let sink = Sink::file(&log_path).with_perm(0o640).with_max_size(60);
        assert_eq!(sink.path(), log_path.as_path());

        assert!(sink.write("first line of thirty-five bytes!!!!"));
        #[cfg(unix)]
        {
            let mode = std::fs::symlink_metadata(&log_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o640);
        }

        // Second line exceeds 60 bytes -> atomic rotation to error_log.O!
        assert!(sink.write("second line triggers rotation!!!!!!"));
        let backup = dir.join("error_log.O");
        assert!(backup.exists());
        assert!(std::fs::read_to_string(&backup)
            .unwrap()
            .contains("first line"));
        assert!(std::fs::read_to_string(&log_path)
            .unwrap()
            .contains("second line"));

        // Raw CR/LF passed directly to Sink::write is still sanitized.
        assert!(sink.write("a\nb\rc"));
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("a\\nb\\rc"));

        // Explicit rotate() + reopen() (SIGHUP simulation).
        sink.rotate().unwrap();
        assert!(sink.write("after explicit rotate"));
        std::fs::rename(&log_path, dir.join("external.1")).unwrap();
        sink.reopen().unwrap();
        assert!(sink.write("after sighup reopen"));
        assert!(std::fs::read_to_string(&log_path)
            .unwrap()
            .contains("after sighup reopen"));

        // Symlink refused via O_NOFOLLOW!
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = dir.join("victim");
            std::fs::write(&target, "untouched").unwrap();
            let link = dir.join("symlink_log");
            symlink(&target, &link).unwrap();
            let sym_sink = Sink::file_with_options(&link, 0o600, 0);
            assert!(!sym_sink.write("attack"));
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");

            // Directory path also rejected.
            assert!(!Sink::file(&dir).write("bad"));
        }

        // Stderr sink operations succeed cleanly.
        let err_sink = Sink::stderr();
        assert!(err_sink.reopen().is_ok());
        assert!(err_sink.rotate().is_ok());
        assert!(err_sink.write("stderr smoke"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn access_page_json_and_audit_emitters() {
        let fixed = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let acc_txt = access_line(
            "127.0.0.1\r\n",
            Some("alice"),
            TimeFormat::Standard,
            "POST",
            "/printers/my printer\"?a=1",
            (1, 1),
            200,
            512,
            "Print-Job",
            "successful-ok",
            Some(fixed),
        );
        assert!(!acc_txt.contains('\n'));
        assert!(acc_txt.contains("127.0.0.1\\r\\n - alice"));
        assert!(acc_txt.contains("/printers/my+printer%22?a=1"));
        assert!(acc_txt.contains("Print-Job successful-ok"));

        let acc_js = access_json(
            "10.0.0.5",
            None,
            TimeFormat::Usecs,
            "GET",
            "/admin",
            (1, 1),
            401,
            0,
            "-",
            "-",
            Some(fixed),
        );
        assert!(acc_js.contains("\"log_type\":\"access\""));
        assert!(acc_js.contains("\"user\":null"));
        assert!(acc_js.contains("\"status\":401"));

        let err_js = error_json(
            Level::Error,
            TimeFormat::Standard,
            "quote\"slash\\nl\n\x08\x0c\r\t\x01",
        );
        assert!(err_js.contains("\"log_type\":\"error\""));
        assert!(err_js.contains("\"level\":\"error\""));
        assert!(err_js.contains("quote\\\"slash\\\\nl\\n\\b\\f\\r\\t\\u0001"));

        // Page log expansion including aliases, multi-values, missing attrs, and sanitization.
        let attrs = vec![
            Attribute::new(
                "job-account-id",
                tags::NAME,
                vec![Value::Name(Text::from("acct-42\n"))],
            ),
            Attribute::new(
                "media-col/media-size",
                tags::KEYWORD,
                vec![Value::Keyword(Text::from("na_letter")), Value::Integer(1)],
            ),
            Attribute::new("duplex", tags::BOOLEAN, vec![Value::Boolean(true)]),
            Attribute::new(
                "title",
                tags::TEXTLANG,
                vec![Value::TextWithLanguage {
                    lang: Text::from("en"),
                    text: Text::from("Report"),
                }],
            ),
            Attribute::new("raw", tags::STRING, vec![Value::OctetString(vec![1])]),
            Attribute::new("empty", tags::TEXT, vec![]),
        ];
        let pg = page_line(
            "%p %u %j %T %P %C %{job-billing} %{media} %{duplex} %{title} %{raw} %{empty} %{missing} %% %z",
            "office",
            Some("bob"),
            7,
            "3 2",
            &attrs,
            TimeFormat::Standard,
        );
        assert!(pg.starts_with("office bob 7 ["));
        assert!(pg.contains(" 3 2 acct-42\\n na_letter,1 1 Report - - - % %z"));

        let pg_js = page_json("office", Some("bob"), 7, "3 2", TimeFormat::Standard);
        assert!(pg_js.contains("\"log_type\":\"page\""));
        assert!(pg_js.contains("\"job_id\":7"));
        assert!(pg_js.contains("\"copies\":2"));
    }

    #[test]
    fn audit_event_all_outcomes_text_and_json() {
        let fixed = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        // Enterprise audit events (all outcomes, text + JSON).
        for (outcome, label) in [
            (AuditOutcome::Success, "success"),
            (AuditOutcome::Denied, "denied"),
            (AuditOutcome::Failure, "failure"),
            (AuditOutcome::Error, "error"),
        ] {
            let ev = AuditEvent {
                timestamp: Some(fixed),
                actor: "admin",
                peer_ip: "192.0.2.10",
                auth_method: "mtls",
                operation: "CUPS-Add-Modify-Printer",
                target: "ipp://host/printers/laser",
                outcome,
                detail: "added\nline",
            };
            let js = audit_event(&ev, LogFormat::Json);
            assert!(js.contains("\"log_type\":\"audit\""));
            assert!(js.contains(&format!("\"outcome\":\"{label}\"")));
            assert!(js.contains("\"detail\":\"added\\nline\""));
            let txt = audit_event(&ev, LogFormat::Text);
            assert!(txt.starts_with("AUDIT ["));
            assert!(txt.contains("actor=admin"));
            assert!(txt.contains("detail=added\\nline"));
        }
    }

    #[test]
    fn high_level_logger_filtering_json_and_reopen() {
        let dir = temp_path("logger");
        let logger = Logger {
            error: Sink::file(dir.join("error.log")),
            access: Sink::file(dir.join("access.log")),
            page: Some(Sink::file(dir.join("page.log"))),
            audit: Some(Sink::file(dir.join("audit.log"))),
            error_level: LogLevelFilter::Warn,
            access_level: AccessLogLevel::Actions,
            time_format: TimeFormat::Standard,
            format: LogFormat::Json,
        };

        // Filtered out by LogLevel / AccessLogLevel.
        assert!(!logger.log_error(Level::Info, "suppressed"));
        assert!(logger.log_error(Level::Error, "visible error"));
        assert!(!logger.log_access(
            AccessCategory::Query,
            "127.0.0.1",
            None,
            "GET",
            "/",
            (1, 1),
            200,
            10,
            "-",
            "-",
            None,
        ));
        assert!(logger.log_access(
            AccessCategory::Action,
            "127.0.0.1",
            Some("alice"),
            "POST",
            "/printers/lp",
            (1, 1),
            200,
            100,
            "Print-Job",
            "successful-ok",
            None,
        ));
        assert!(logger.log_page("%p %u %j %P %C", "lp", Some("alice"), 1, "1 1", &[]));
        assert!(logger.log_audit(&AuditEvent {
            timestamp: None,
            actor: "alice",
            peer_ip: "127.0.0.1",
            auth_method: "basic",
            operation: "Print-Job",
            target: "lp",
            outcome: AuditOutcome::Success,
            detail: "job 1",
        }));
        logger.reopen_all().unwrap();

        assert!(std::fs::read_to_string(dir.join("error.log"))
            .unwrap()
            .contains("visible error"));
        assert!(std::fs::read_to_string(dir.join("access.log"))
            .unwrap()
            .contains("\"user\":\"alice\""));
        assert!(std::fs::read_to_string(dir.join("page.log"))
            .unwrap()
            .contains("\"printer\":\"lp\""));
        assert!(std::fs::read_to_string(dir.join("audit.log"))
            .unwrap()
            .contains("\"operation\":\"Print-Job\""));

        // Text-mode logger with no page/audit sinks falls back audit to error sink.
        let text_logger = Logger {
            error: Sink::file(dir.join("err_txt.log")),
            access: Sink::file(dir.join("acc_txt.log")),
            page: None,
            audit: None,
            error_level: LogLevelFilter::Info,
            access_level: AccessLogLevel::All,
            time_format: TimeFormat::Usecs,
            format: LogFormat::Text,
        };
        assert!(text_logger.log_error(Level::Info, "hello"));
        assert!(text_logger.log_access(
            AccessCategory::Query,
            "127.0.0.1",
            None,
            "GET",
            "/healthz",
            (1, 1),
            200,
            2,
            "-",
            "-",
            None,
        ));
        assert!(!text_logger.log_page("%p", "lp", None, 1, "1 1", &[]));
        assert!(text_logger.log_audit(&AuditEvent {
            timestamp: None,
            actor: "root",
            peer_ip: "unix",
            auth_method: "peercred",
            operation: "Cancel-Job",
            target: "job/1",
            outcome: AuditOutcome::Success,
            detail: "ok",
        }));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
