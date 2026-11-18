//! CUPS `statbuf` / filter+backend stderr status line parser (`scheduler/statbuf.c`).
//!
//! Filters and backends emit structured status lines on stderr (`STATE:`, `PAGE:`,
//! `ATTR:`, `PPD:`, `INFO:`, `WARNING:`, `ERROR:`, `CRIT:`, `ALERT:`, `EMERG:`,
//! `NOTICE:`, `DEBUG:`, `DEBUG2:`). `StatBuf` reads stderr streams with a hard
//! per-line memory bound and delivers parsed [`StatusEvent`]s to callers.

use std::io::{self, Read};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};

/// Hard maximum byte length of a single stderr status line (`CUPS_MAX_MESSAGE` protection).
pub const MAX_STATBUF_LINE: usize = 8192;

/// Severity level for CUPS stderr log lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogSeverity {
    /// `EMERG:`
    Emerg,
    /// `ALERT:`
    Alert,
    /// `CRIT:`
    Crit,
    /// `ERROR:`
    Error,
    /// `WARNING:`
    Warning,
    /// `NOTICE:`
    Notice,
    /// `INFO:`
    Info,
    /// `DEBUG:` (also default for unprefixed stderr lines)
    Debug,
    /// `DEBUG2:`
    Debug2,
}

/// One printer state-reason mutation parsed from a `STATE:` status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateChange {
    /// `STATE: +reason` — add a printer-state-reason keyword.
    Add(String),
    /// `STATE: -reason` — remove a printer-state-reason keyword.
    Remove(String),
    /// `STATE: reason` — replace reasons with this keyword.
    Set(String),
    /// `STATE: none` — clear all non-persistent reasons.
    Clear,
}

/// Page accounting update parsed from a `PAGE:` status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageEvent {
    /// `PAGE: <page> <copies> [extra...]`
    Sheet {
        /// 1-based sheet/page number.
        page: u32,
        /// Number of copies produced for this sheet.
        copies: u32,
        /// Optional trailing media/job-billing metadata.
        extra: Option<String>,
    },
    /// `PAGE: total <n>` — total page count summary.
    Total(u32),
}

/// Parsed CUPS filter/backend stderr status event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusEvent {
    /// Log message (`INFO:`, `WARNING:`, `ERROR:`, `DEBUG:`, etc.).
    Log {
        /// Severity level.
        severity: LogSeverity,
        /// Message text (trimmed).
        message: String,
    },
    /// `STATE:` printer-state-reasons update.
    State(Vec<StateChange>),
    /// `PAGE:` page-log accounting update.
    Page(PageEvent),
    /// `ATTR:` IPP printer/job attribute update (`key=value` pairs).
    Attr(Vec<(String, String)>),
    /// `PPD:` PPD default option update (`Option=Choice` pairs).
    Ppd(Vec<(String, String)>),
}

/// One status event tagged with the pipeline stage that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusMessage {
    /// Human-readable stage identifier (e.g. `"filter[0]:pdftoraster"` or `"backend:ipp"`).
    pub stage: String,
    /// `true` when emitted by the backend process, `false` for filters.
    pub is_backend: bool,
    /// Parsed event.
    pub event: StatusEvent,
    /// Raw sanitized stderr line.
    pub raw: String,
}

/// Parse a single CUPS stderr status line into a structured [`StatusEvent`].
#[must_use]
pub fn parse_status_line(raw: &str) -> StatusEvent {
    let line = raw.trim_end_matches(['\r', '\n']);

    if let Some(rest) = line.strip_prefix("STATE:") {
        return StatusEvent::State(parse_state_changes(rest));
    }
    if let Some(rest) = line.strip_prefix("PAGE:") {
        if let Some(page) = parse_page_event(rest) {
            return StatusEvent::Page(page);
        }
        return StatusEvent::Log {
            severity: LogSeverity::Debug,
            message: line.to_string(),
        };
    }
    if let Some(rest) = line.strip_prefix("ATTR:") {
        return StatusEvent::Attr(parse_kv_pairs(rest));
    }
    if let Some(rest) = line.strip_prefix("PPD:") {
        return StatusEvent::Ppd(parse_kv_pairs(rest));
    }

    let prefixes: [(&str, LogSeverity); 9] = [
        ("EMERG:", LogSeverity::Emerg),
        ("ALERT:", LogSeverity::Alert),
        ("CRIT:", LogSeverity::Crit),
        ("ERROR:", LogSeverity::Error),
        ("WARNING:", LogSeverity::Warning),
        ("NOTICE:", LogSeverity::Notice),
        ("INFO:", LogSeverity::Info),
        ("DEBUG2:", LogSeverity::Debug2),
        ("DEBUG:", LogSeverity::Debug),
    ];

    for (prefix, severity) in prefixes {
        if let Some(rest) = line.strip_prefix(prefix) {
            return StatusEvent::Log {
                severity,
                message: rest.trim().to_string(),
            };
        }
    }

    StatusEvent::Log {
        severity: LogSeverity::Debug,
        message: line.to_string(),
    }
}

/// Parse `STATE:` payload (`+reason`, `-reason`, `none`, or bare `reason`,
/// separated by commas or whitespace).
#[must_use]
pub fn parse_state_changes(rest: &str) -> Vec<StateChange> {
    let mut out = Vec::new();
    for tok in rest.split(|c: char| c.is_ascii_whitespace() || c == ',') {
        if tok.is_empty() {
            continue;
        }
        if tok.eq_ignore_ascii_case("none") {
            out.push(StateChange::Clear);
        } else if let Some(reason) = tok.strip_prefix('+') {
            if !reason.is_empty() {
                out.push(StateChange::Add(reason.to_string()));
            }
        } else if let Some(reason) = tok.strip_prefix('-') {
            if !reason.is_empty() {
                out.push(StateChange::Remove(reason.to_string()));
            }
        } else {
            out.push(StateChange::Set(tok.to_string()));
        }
    }
    out
}

/// Parse `PAGE:` payload (`total <n>` or `<page> <copies> [extra...]`).
#[must_use]
pub fn parse_page_event(rest: &str) -> Option<PageEvent> {
    let trimmed = rest.trim();
    let mut parts = trimmed.splitn(3, char::is_whitespace);
    let first = parts.next()?.trim();
    let second = parts.next()?.trim();
    if first.eq_ignore_ascii_case("total") {
        let total = second.parse::<u32>().ok()?;
        return Some(PageEvent::Total(total));
    }
    let page = first.parse::<u32>().ok()?;
    let copies = second.parse::<u32>().ok()?;
    let extra = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    Some(PageEvent::Sheet {
        page,
        copies,
        extra,
    })
}

/// Parse CUPS `ATTR:` / `PPD:` `key=value` option lists with single/double
/// quote and backslash escape support (`cupsParseOptions` semantics).
#[must_use]
pub fn parse_kv_pairs(input: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_ascii_whitespace() {
            chars.next();
            continue;
        }

        let mut key = String::new();
        while let Some(&ch) = chars.peek() {
            if ch == '=' || ch.is_ascii_whitespace() {
                break;
            }
            key.push(ch);
            chars.next();
        }

        let mut value = String::new();
        if chars.peek() == Some(&'=') {
            chars.next();
            let mut quote: Option<char> = None;
            while let Some(&ch) = chars.peek() {
                if let Some(q) = quote {
                    chars.next();
                    if ch == '\\' {
                        if let Some(escaped) = chars.next() {
                            value.push(escaped);
                        }
                    } else if ch == q {
                        quote = None;
                    } else {
                        value.push(ch);
                    }
                } else {
                    if ch.is_ascii_whitespace() {
                        break;
                    }
                    chars.next();
                    if ch == '"' || ch == '\'' {
                        quote = Some(ch);
                    } else if ch == '\\' {
                        if let Some(escaped) = chars.next() {
                            value.push(escaped);
                        }
                    } else {
                        value.push(ch);
                    }
                }
            }
        }

        if !key.is_empty() {
            pairs.push((key, value));
        }
    }
    pairs
}

/// Bounded line-oriented stderr reader (`cupsdStatBufUpdate` analogue).
///
/// Enforces a hard [`MAX_STATBUF_LINE`] byte limit per line so a misbehaving
/// filter emitting megabytes without newlines cannot exhaust scheduler RAM.
pub struct StatBuf {
    max_line_len: usize,
}

impl Default for StatBuf {
    fn default() -> Self {
        Self::new(MAX_STATBUF_LINE)
    }
}

impl StatBuf {
    /// Create a `StatBuf` with a custom per-line byte limit (at least 16 bytes).
    #[must_use]
    pub fn new(max_line_len: usize) -> Self {
        Self {
            max_line_len: max_line_len.max(16),
        }
    }

    /// Read all lines from `reader`, invoking `on_event` with each parsed
    /// [`StatusEvent`] and raw line string. Returns total lines parsed.
    pub fn read_all<R, F>(&self, mut reader: R, mut on_event: F) -> io::Result<usize>
    where
        R: Read,
        F: FnMut(StatusEvent, String),
    {
        let mut buf = [0u8; 1024];
        let mut line = Vec::with_capacity(256);
        let mut discarding = false;
        let mut count = 0usize;

        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            for &b in &buf[..n] {
                if b == b'\n' {
                    Self::emit_line(&mut line, &mut on_event);
                    count += 1;
                    discarding = false;
                } else if !discarding {
                    if line.len() < self.max_line_len {
                        line.push(b);
                    } else {
                        discarding = true;
                    }
                }
            }
        }
        if !line.is_empty() {
            Self::emit_line(&mut line, &mut on_event);
            count += 1;
        }
        Ok(count)
    }

    fn emit_line<F>(line: &mut Vec<u8>, on_event: &mut F)
    where
        F: FnMut(StatusEvent, String),
    {
        while line.last() == Some(&b'\r') {
            line.pop();
        }
        let raw = String::from_utf8_lossy(line).into_owned();
        line.clear();
        let event = parse_status_line(&raw);
        on_event(event, raw);
    }
}

/// Spawn a background reader thread pumping a child's stderr into `tx`.
pub fn spawn_stderr_reader<R>(
    reader: R,
    stage: String,
    is_backend: bool,
    tx: mpsc::Sender<StatusMessage>,
) -> JoinHandle<()>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let sb = StatBuf::default();
        let _ = sb.read_all(reader, |event, raw| {
            let _ = tx.send(StatusMessage {
                stage: stage.clone(),
                is_backend,
                event,
                raw,
            });
        });
    })
}
