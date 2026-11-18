//! `cups-lpd` — hardened RFC 1179 LPD mini-server forwarding to local `cupsd`
//! over IPP (`scheduler/cups-lpd.c`).
//!
//! Hardening & protocol completeness:
//!  * Streams incoming data files directly to a bounded temporary spool file
//!    (`0600`, `O_EXCL | O_NOFOLLOW`) instead of allocating `vec![0u8; size]`.
//!  * Supports both control-before-data (`02` then `03`) and data-before-control
//!    (`03` then `02`) transfer orders, plus subcommand `01` abort.
//!  * Parses RFC 1179 control-file metadata (`H`, `P`, `J`, `N`, `l`/`f`/`o`)
//!    and forwards user, job title, format, copies, and originating host to IPP.
//!  * Strictly validates queue names and `IPP_PORT` against URI/HTTP header
//!    injection.
//!  * Implements real `03`/`04` queue state (`Get-Jobs`) and `05` remove jobs
//!    (`Cancel-Job`) forwarding over IPP with timeouts and bounded chunked
//!    HTTP response decoding.

use ipp_codec::{ops, tags, Attribute, Group, IppMessage, Text, Value};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const DEFAULT_MAX_JOB_SIZE: u64 = 100 * 1024 * 1024; // 100 MiB
const MAX_CONTROL_SIZE: usize = 64 * 1024;
const MAX_LINE_LEN: usize = 4096;
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 4 * 1024 * 1024;
const STREAM_BUF_SIZE: usize = 16 * 1024;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Platform-accurate `O_NOFOLLOW` for safe temp spool creation.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "m68k"
    )
))]
const O_NOFOLLOW: i32 = 0x8000;

#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "m68k"
    ))
))]
const O_NOFOLLOW: i32 = 0x20000;

#[cfg(all(unix, not(target_os = "linux")))]
const O_NOFOLLOW: i32 = 0x100;

/// Runtime configuration (injectable for tests).
#[derive(Debug, Clone)]
struct Config {
    ipp_port: u16,
    max_job_size: u64,
    connect_timeout: Duration,
    io_timeout: Duration,
    spool_dir: PathBuf,
}

impl Config {
    fn from_env() -> Option<Self> {
        let ipp_port = parse_ipp_port(env::var("IPP_PORT").ok().as_deref())?;
        let max_job_size = env::var("CUPS_LPD_MAX_SIZE")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_MAX_JOB_SIZE);
        let io_secs = env::var("CUPS_LPD_TIMEOUT")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(60);
        Some(Self {
            ipp_port,
            max_job_size,
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(io_secs),
            spool_dir: env::temp_dir(),
        })
    }
}

/// Strictly parse `IPP_PORT` (`1..=65535`); rejects header-injection payloads.
fn parse_ipp_port(val: Option<&str>) -> Option<u16> {
    let Some(raw) = val else {
        return Some(631);
    };
    let s = raw.trim();
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = s.parse().ok()?;
    (port > 0).then_some(port)
}

/// Validate a CUPS queue name against URI/path/header injection.
fn validate_queue(queue: &str) -> bool {
    !queue.is_empty()
        && queue.len() <= 127
        && !queue.starts_with('-')
        && queue != "."
        && queue != ".."
        && queue
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+'))
}

/// Sanitize a single-line text field from LPD control files or commands.
fn sanitize_text(s: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_len));
    for c in s.chars() {
        if c.is_control() {
            continue;
        }
        if out.len() + c.len_utf8() > max_len {
            break;
        }
        out.push(c);
    }
    out.trim().to_string()
}

/// RAII temporary spool file (`0600`, `O_CREAT | O_EXCL | O_NOFOLLOW`),
/// automatically removed on drop.
struct TempSpool {
    path: PathBuf,
    file: File,
    len: u64,
}

impl TempSpool {
    fn create(dir: &Path) -> io::Result<Self> {
        let pid = std::process::id();
        for _ in 0..128 {
            let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!("cups-lpd-{pid}-{seq}.tmp"));
            let mut opts = OpenOptions::new();
            opts.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600).custom_flags(O_NOFOLLOW);
            }
            match opts.open(&path) {
                Ok(file) => {
                    return Ok(Self { path, file, len: 0 });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot create unique temp spool file",
        ))
    }

    /// Stream exactly `size` bytes from `inp` into the temp file.
    fn fill_exact(&mut self, inp: &mut impl Read, size: u64) -> io::Result<()> {
        let mut remaining = size;
        let mut buf = [0u8; STREAM_BUF_SIZE];
        while remaining > 0 {
            let want = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
            let n = inp.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated LPD data file",
                ));
            }
            self.file.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        self.file.flush()?;
        self.file.seek(SeekFrom::Start(0))?;
        self.len = size;
        Ok(())
    }
}

impl Drop for TempSpool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Parsed RFC 1179 control-file metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ControlMeta {
    host: Option<String>,
    user: Option<String>,
    title: Option<String>,
    filename: Option<String>,
    format: String,
    copies: i32,
}

impl Default for ControlMeta {
    fn default() -> Self {
        Self {
            host: None,
            user: None,
            title: None,
            filename: None,
            format: "application/octet-stream".to_string(),
            copies: 1,
        }
    }
}

/// Parse an RFC 1179 control file (`H`, `P`, `J`, `N`, `l`/`f`/`o`).
fn parse_control_file(text: &str) -> ControlMeta {
    let mut meta = ControlMeta::default();
    let mut print_cmds = 0i32;
    let mut saw_raw = false;
    let mut saw_ps = false;
    let mut saw_text = false;

    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        let mut chars = line.chars();
        let Some(cmd) = chars.next() else {
            continue;
        };
        let val = sanitize_text(chars.as_str(), 255);
        match cmd {
            'H' if !val.is_empty() && meta.host.is_none() => meta.host = Some(val),
            'P' if !val.is_empty() && meta.user.is_none() => meta.user = Some(val),
            'J' if !val.is_empty() && meta.title.is_none() => meta.title = Some(val),
            'N' if !val.is_empty() && meta.filename.is_none() => meta.filename = Some(val),
            'l' => {
                saw_raw = true;
                print_cmds = print_cmds.saturating_add(1);
            }
            'o' => {
                saw_ps = true;
                print_cmds = print_cmds.saturating_add(1);
            }
            'f' | 'p' => {
                saw_text = true;
                print_cmds = print_cmds.saturating_add(1);
            }
            _ => {}
        }
    }
    if saw_raw {
        meta.format = "application/octet-stream".to_string();
    } else if saw_ps {
        meta.format = "application/postscript".to_string();
    } else if saw_text {
        meta.format = "text/plain".to_string();
    }
    if print_cmds > 1 {
        meta.copies = print_cmds.min(100);
    }
    meta
}

// ---------- Local IPP HTTP client ----------

fn ipp_call(
    cfg: &Config,
    resource: &str,
    msg: &IppMessage,
    data: Option<&mut TempSpool>,
) -> Option<IppMessage> {
    let ipp_bytes = ipp_codec::encode(msg).ok()?;
    let data_len = data.as_ref().map_or(0, |d| d.len);
    let total_len = (ipp_bytes.len() as u64).checked_add(data_len)?;

    let addr: SocketAddr = ([127, 0, 0, 1], cfg.ipp_port).into();
    let mut s = TcpStream::connect_timeout(&addr, cfg.connect_timeout).ok()?;
    let _ = s.set_read_timeout(Some(cfg.io_timeout));
    let _ = s.set_write_timeout(Some(cfg.io_timeout));

    let req = format!(
        "POST {resource} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/ipp\r\nContent-Length: {total_len}\r\nConnection: close\r\n\r\n",
        cfg.ipp_port
    );
    s.write_all(req.as_bytes()).ok()?;
    s.write_all(&ipp_bytes).ok()?;
    if let Some(spool) = data {
        spool.file.seek(SeekFrom::Start(0)).ok()?;
        let mut buf = [0u8; STREAM_BUF_SIZE];
        let mut rem = spool.len;
        while rem > 0 {
            let want = usize::try_from(rem.min(buf.len() as u64)).unwrap_or(buf.len());
            let n = spool.file.read(&mut buf[..want]).ok()?;
            if n == 0 {
                return None;
            }
            s.write_all(&buf[..n]).ok()?;
            rem -= n as u64;
        }
    }
    s.flush().ok()?;

    let body = read_http_response_body(&mut s)?;
    ipp_codec::decode(&body).ok().map(|(m, _)| m)
}

fn read_http_line(reader: &mut impl BufRead, budget: &mut usize) -> Option<String> {
    let mut line = Vec::new();
    loop {
        if *budget == 0 {
            return None;
        }
        let avail = reader.fill_buf().ok()?;
        if avail.is_empty() {
            return (!line.is_empty()).then(|| {
                String::from_utf8_lossy(&line)
                    .trim_end_matches(['\r', '\n'])
                    .to_string()
            });
        }
        let take = avail.len().min(*budget);
        if let Some(nl) = avail[..take].iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&avail[..=nl]);
            reader.consume(nl + 1);
            *budget -= nl + 1;
            break;
        }
        line.extend_from_slice(&avail[..take]);
        reader.consume(take);
        *budget -= take;
    }
    Some(
        String::from_utf8_lossy(&line)
            .trim_end_matches(['\r', '\n'])
            .to_string(),
    )
}

fn read_http_response_body(stream: &mut impl Read) -> Option<Vec<u8>> {
    let mut reader = BufReader::new(stream);
    let mut budget = MAX_HTTP_HEADER_BYTES;
    let status_line = read_http_line(&mut reader, &mut budget)?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;
    if !(200..300).contains(&status) {
        return None;
    }
    let mut chunked = false;
    let mut content_len: Option<usize> = None;
    loop {
        let line = read_http_line(&mut reader, &mut budget)?;
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            } else if k.eq_ignore_ascii_case("content-length") {
                let n: usize = v.trim().parse().ok()?;
                if n > MAX_HTTP_BODY_BYTES {
                    return None;
                }
                content_len = Some(n);
            }
        }
    }
    if chunked {
        let mut out = Vec::new();
        let mut chunk_budget = MAX_HTTP_HEADER_BYTES;
        loop {
            let sz_line = read_http_line(&mut reader, &mut chunk_budget)?;
            let hex = sz_line.split(';').next()?.trim();
            let sz = usize::from_str_radix(hex, 16).ok()?;
            if sz == 0 {
                break;
            }
            if out.len().checked_add(sz)? > MAX_HTTP_BODY_BYTES {
                return None;
            }
            let start = out.len();
            out.resize(start + sz, 0);
            reader.read_exact(&mut out[start..]).ok()?;
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).ok()?;
            if crlf != *b"\r\n" {
                return None;
            }
        }
        Some(out)
    } else if let Some(n) = content_len {
        let mut out = vec![0u8; n];
        reader.read_exact(&mut out).ok()?;
        Some(out)
    } else {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out.len().checked_add(n)? > MAX_HTTP_BODY_BYTES {
                        return None;
                    }
                    out.extend_from_slice(&buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
        Some(out)
    }
}

fn printer_uri(port: u16, queue: &str) -> String {
    format!("ipp://localhost:{port}/printers/{queue}")
}

fn op_group(port: u16, queue: &str) -> Group {
    let mut g = Group::new(tags::OPERATION);
    g.attributes.push(Attribute::new(
        "attributes-charset",
        tags::CHARSET,
        vec![Value::Charset(Text::from("utf-8"))],
    ));
    g.attributes.push(Attribute::new(
        "attributes-natural-language",
        tags::LANGUAGE,
        vec![Value::NaturalLanguage(Text::from("en"))],
    ));
    g.attributes.push(Attribute::new(
        "printer-uri",
        tags::URI,
        vec![Value::Uri(Text::from(printer_uri(port, queue)))],
    ));
    g
}

/// Read a bounded `\n`-terminated LPD command line.
fn read_line(inp: &mut impl Read) -> Option<String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        inp.read_exact(&mut b).ok()?;
        if b[0] == b'\n' {
            break;
        }
        if b[0] != b'\r' {
            line.push(b[0]);
        }
        if line.len() > MAX_LINE_LEN {
            return None;
        }
    }
    Some(String::from_utf8_lossy(&line).into_owned())
}

fn send_ack(out: &mut impl Write, ok: bool) {
    let _ = out.write_all(&[u8::from(!ok)]);
    let _ = out.flush();
}

/// Read `<size> <name>` header from subcommand `0x02` or `0x03`.
fn parse_subfile_header(hdr: &str) -> Option<(u64, String)> {
    let (sz_str, name) = hdr.split_once(' ')?;
    let size: u64 = sz_str.trim().parse().ok()?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some((size, name.to_string()))
}

/// `02` — receive a printer job (supports control-before-data AND data-before-control).
#[allow(clippy::too_many_lines)]
fn receive_job(cfg: &Config, inp: &mut impl Read, out: &mut impl Write) {
    let Some(queue) = read_line(inp) else {
        send_ack(out, false);
        return;
    };
    if !validate_queue(&queue) {
        send_ack(out, false);
        return;
    }
    send_ack(out, true);

    let mut control: Option<ControlMeta> = None;
    let mut data_spool: Option<TempSpool> = None;

    loop {
        let mut sub = [0u8; 1];
        match inp.read_exact(&mut sub) {
            Ok(()) => {}
            Err(_) => break, // EOF
        }
        match sub[0] {
            0x01 => {
                // Abort job
                control = None;
                data_spool = None;
                send_ack(out, true);
            }
            0x02 => {
                // Receive control file
                let Some(hdr) = read_line(inp) else {
                    send_ack(out, false);
                    return;
                };
                let Some((size, _name)) = parse_subfile_header(&hdr) else {
                    send_ack(out, false);
                    return;
                };
                let Ok(size_usize) = usize::try_from(size) else {
                    send_ack(out, false);
                    return;
                };
                if size_usize > MAX_CONTROL_SIZE {
                    send_ack(out, false);
                    return;
                }
                send_ack(out, true);
                let mut buf = vec![0u8; size_usize];
                if inp.read_exact(&mut buf).is_err() {
                    send_ack(out, false);
                    return;
                }
                let mut nul = [0u8; 1];
                if inp.read_exact(&mut nul).is_err() || nul[0] != 0 {
                    send_ack(out, false);
                    return;
                }
                control = Some(parse_control_file(&String::from_utf8_lossy(&buf)));

                if let Some(mut spool) = data_spool.take() {
                    let meta = control.take().unwrap_or_default();
                    let ok = submit_print_job(cfg, &queue, &meta, &mut spool);
                    send_ack(out, ok);
                } else {
                    send_ack(out, true);
                }
            }
            0x03 => {
                // Receive data file (streamed to bounded temp spool file)
                let Some(hdr) = read_line(inp) else {
                    send_ack(out, false);
                    return;
                };
                let Some((size, _name)) = parse_subfile_header(&hdr) else {
                    send_ack(out, false);
                    return;
                };
                if size > cfg.max_job_size {
                    send_ack(out, false);
                    return;
                }
                let Ok(mut spool) = TempSpool::create(&cfg.spool_dir) else {
                    send_ack(out, false);
                    return;
                };
                send_ack(out, true);
                if spool.fill_exact(inp, size).is_err() {
                    send_ack(out, false);
                    return;
                }
                let mut nul = [0u8; 1];
                if inp.read_exact(&mut nul).is_err() || nul[0] != 0 {
                    send_ack(out, false);
                    return;
                }
                if let Some(meta) = control.take() {
                    let ok = submit_print_job(cfg, &queue, &meta, &mut spool);
                    send_ack(out, ok);
                } else {
                    data_spool = Some(spool);
                    send_ack(out, true);
                }
            }
            _ => {
                send_ack(out, false);
                return;
            }
        }
    }

    // If EOF arrived with data but no control file, submit with default metadata.
    if let Some(mut spool) = data_spool.take() {
        let meta = control.unwrap_or_default();
        let _ = submit_print_job(cfg, &queue, &meta, &mut spool);
    }
}

fn submit_print_job(cfg: &Config, queue: &str, meta: &ControlMeta, spool: &mut TempSpool) -> bool {
    let mut msg = IppMessage::new(ops::op::PRINT_JOB);
    let mut op = op_group(cfg.ipp_port, queue);
    let user = meta.user.as_deref().unwrap_or("lpd");
    let title = meta
        .title
        .as_deref()
        .or(meta.filename.as_deref())
        .unwrap_or("lpd job");

    op.attributes.push(Attribute::new(
        "requesting-user-name",
        tags::NAME,
        vec![Value::Name(Text::from(user))],
    ));
    op.attributes.push(Attribute::new(
        "job-name",
        tags::NAME,
        vec![Value::Name(Text::from(title))],
    ));
    op.attributes.push(Attribute::new(
        "document-format",
        tags::MIMETYPE,
        vec![Value::MimeMediaType(Text::from(meta.format.clone()))],
    ));
    if let Some(host) = &meta.host {
        op.attributes.push(Attribute::new(
            "job-originating-host-name",
            tags::NAME,
            vec![Value::Name(Text::from(host.clone()))],
        ));
    }
    msg.groups.push(op);

    if meta.copies > 1 {
        let mut job = Group::new(tags::JOB);
        job.attributes.push(Attribute::new(
            "copies",
            tags::INTEGER,
            vec![Value::Integer(meta.copies)],
        ));
        msg.groups.push(job);
    }

    let resource = format!("/printers/{queue}");
    ipp_call(cfg, &resource, &msg, Some(spool)).is_some_and(|r| r.code < 0x0100)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JobSummary {
    id: i32,
    user: String,
    name: String,
    state: i32,
    k_octets: i32,
}

fn attr_str(attr: &Attribute) -> Option<String> {
    attr.values.first().and_then(|v| match v {
        Value::Text(t) | Value::Name(t) | Value::Keyword(t) => {
            Some(String::from_utf8_lossy(&t.0).into_owned())
        }
        _ => None,
    })
}

fn attr_int(attr: &Attribute) -> Option<i32> {
    attr.values.first().and_then(|v| match *v {
        Value::Integer(n) | Value::Enum(n) => Some(n),
        _ => None,
    })
}

/// Extract all job records from a `Get-Jobs` IPP response (handles both
/// separate `tags::JOB` groups and separator-delimited groups).
fn extract_jobs(resp: &IppMessage) -> Vec<JobSummary> {
    let mut jobs = Vec::new();
    for g in &resp.groups {
        if g.tag != tags::JOB {
            continue;
        }
        let mut cur: Option<JobSummary> = None;
        for attr in &g.attributes {
            if attr.is_separator() {
                if let Some(j) = cur.take() {
                    if j.id > 0 {
                        jobs.push(j);
                    }
                }
                continue;
            }
            let entry = cur.get_or_insert_with(|| JobSummary {
                id: 0,
                user: "unknown".into(),
                name: "untitled".into(),
                state: 3,
                k_octets: 0,
            });
            match attr.name.as_str().as_ref() {
                "job-id" => {
                    if let Some(id) = attr_int(attr) {
                        entry.id = id;
                    }
                }
                "job-originating-user-name" => {
                    if let Some(u) = attr_str(attr) {
                        entry.user = sanitize_text(&u, 64);
                    }
                }
                "job-name" => {
                    if let Some(n) = attr_str(attr) {
                        entry.name = sanitize_text(&n, 128);
                    }
                }
                "job-state" => {
                    if let Some(s) = attr_int(attr) {
                        entry.state = s;
                    }
                }
                "job-k-octets" => {
                    if let Some(k) = attr_int(attr) {
                        entry.k_octets = k;
                    }
                }
                _ => {}
            }
        }
        if let Some(j) = cur {
            if j.id > 0 {
                jobs.push(j);
            }
        }
    }
    jobs
}

fn fetch_queue_jobs(cfg: &Config, queue: &str) -> Option<Vec<JobSummary>> {
    let mut msg = IppMessage::new(ops::op::GET_JOBS);
    let mut op = op_group(cfg.ipp_port, queue);
    op.attributes.push(Attribute::new(
        "which-jobs",
        tags::KEYWORD,
        vec![Value::Keyword(Text::from("not-completed"))],
    ));
    op.attributes.push(Attribute::new(
        "requested-attributes",
        tags::KEYWORD,
        vec![
            Value::Keyword(Text::from("job-id")),
            Value::Keyword(Text::from("job-name")),
            Value::Keyword(Text::from("job-originating-user-name")),
            Value::Keyword(Text::from("job-state")),
            Value::Keyword(Text::from("job-k-octets")),
        ],
    ));
    msg.groups.push(op);

    let resp = ipp_call(cfg, &format!("/printers/{queue}"), &msg, None)?;
    if resp.code >= 0x0100 {
        return None;
    }
    Some(extract_jobs(&resp))
}

fn format_rank(idx: usize, state: i32) -> String {
    if state == 5 {
        return "active".to_string();
    }
    let n = idx + 1;
    let suffix = match (n % 10, n % 100) {
        (1, x) if x != 11 => "st",
        (2, x) if x != 12 => "nd",
        (3, x) if x != 13 => "rd",
        _ => "th",
    };
    format!("{n}{suffix}")
}

/// `03`/`04` — send real queue state (`Get-Jobs`) in short or long BSD format.
fn queue_state(cfg: &Config, inp: &mut impl Read, out: &mut impl Write, long: bool) {
    let Some(line) = read_line(inp) else {
        return;
    };
    let mut parts = line.split_whitespace();
    let Some(queue) = parts.next() else {
        let _ = writeln!(out, "invalid queue");
        return;
    };
    if !validate_queue(queue) {
        let _ = writeln!(out, "invalid queue");
        return;
    }
    let filters: Vec<&str> = parts.collect();

    let Some(all_jobs) = fetch_queue_jobs(cfg, queue) else {
        let _ = writeln!(out, "{queue}: daemon unavailable");
        return;
    };
    let jobs: Vec<&JobSummary> = all_jobs
        .iter()
        .filter(|j| {
            filters.is_empty()
                || filters
                    .iter()
                    .any(|&f| f == j.user || f.parse::<i32>().ok() == Some(j.id))
        })
        .collect();

    let _ = writeln!(out, "{queue} is ready");
    if jobs.is_empty() {
        let _ = writeln!(out, "no entries");
        return;
    }
    if long {
        for (i, j) in jobs.iter().enumerate() {
            let rank = format_rank(i, j.state);
            let bytes = i64::from(j.k_octets.max(0)) * 1024;
            let _ = writeln!(out, "{}: {rank} [job {}]", j.user, j.id);
            let _ = writeln!(out, "        {}    {bytes} bytes", j.name);
        }
    } else {
        let _ = writeln!(
            out,
            "Rank    Owner   Job     File(s)                         Total Size"
        );
        for (i, j) in jobs.iter().enumerate() {
            let rank = format_rank(i, j.state);
            let bytes = i64::from(j.k_octets.max(0)) * 1024;
            let _ = writeln!(
                out,
                "{rank:<7} {:<7} {:<7} {:<31} {bytes} bytes",
                j.user, j.id, j.name
            );
        }
    }
}

/// `05` — remove jobs via IPP `Cancel-Job`.
fn remove_jobs(cfg: &Config, inp: &mut impl Read, out: &mut impl Write) {
    let Some(line) = read_line(inp) else {
        send_ack(out, false);
        return;
    };
    let mut parts = line.split_whitespace();
    let Some(queue) = parts.next() else {
        send_ack(out, false);
        return;
    };
    if !validate_queue(queue) {
        send_ack(out, false);
        return;
    }
    let agent = parts
        .next()
        .map_or_else(|| "lpd".to_string(), |a| sanitize_text(a, 127));
    let targets: Vec<&str> = parts.collect();

    let mut job_ids: Vec<i32> = targets
        .iter()
        .filter_map(|t| t.parse::<i32>().ok())
        .filter(|&id| id > 0)
        .collect();

    if job_ids.is_empty() {
        let Some(jobs) = fetch_queue_jobs(cfg, queue) else {
            send_ack(out, false);
            return;
        };
        let cancel_all = targets.contains(&"-all");
        for j in jobs {
            if cancel_all
                || targets.iter().any(|&t| t == j.user)
                || (targets.is_empty() && j.user == agent)
            {
                job_ids.push(j.id);
                if targets.is_empty() {
                    break;
                }
            }
        }
    }

    if job_ids.is_empty() {
        send_ack(out, true);
        return;
    }

    let mut all_ok = true;
    for id in job_ids {
        let mut msg = IppMessage::new(ops::op::CANCEL_JOB);
        let mut op = op_group(cfg.ipp_port, queue);
        op.attributes.push(Attribute::new(
            "job-id",
            tags::INTEGER,
            vec![Value::Integer(id)],
        ));
        op.attributes.push(Attribute::new(
            "requesting-user-name",
            tags::NAME,
            vec![Value::Name(Text::from(agent.clone()))],
        ));
        msg.groups.push(op);
        let ok = ipp_call(cfg, &format!("/printers/{queue}"), &msg, None)
            .is_some_and(|r| r.code < 0x0100);
        if !ok {
            all_ok = false;
        }
    }
    send_ack(out, all_ok);
}

fn session(cfg: &Config, inp: &mut impl Read, out: &mut impl Write) -> std::process::ExitCode {
    let mut cmd = [0u8; 1];
    if inp.read_exact(&mut cmd).is_err() {
        return std::process::ExitCode::FAILURE;
    }
    match cmd[0] {
        // 0x01 (print waiting jobs) — validate queue and ACK.
        0x01 => {
            let valid = read_line(inp).is_some_and(|q| validate_queue(q.trim()));
            send_ack(out, valid);
        }
        0x02 => receive_job(cfg, inp, out),
        0x03 | 0x04 => queue_state(cfg, inp, out, cmd[0] == 0x04),
        0x05 => remove_jobs(cfg, inp, out),
        _ => send_ack(out, false),
    }
    std::process::ExitCode::SUCCESS
}

fn main() -> std::process::ExitCode {
    let Some(cfg) = Config::from_env() else {
        eprintln!("cups-lpd: invalid IPP_PORT configuration");
        return std::process::ExitCode::FAILURE;
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut inp = stdin.lock();
    let mut out = stdout.lock();
    let code = session(&cfg, &mut inp, &mut out);
    let _ = out.flush();
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::thread;

    fn read_http_req(stream: &mut impl Read) -> (String, Vec<u8>) {
        let mut r = BufReader::new(stream);
        let mut hdr = String::new();
        let mut cl = 0usize;
        loop {
            let mut line = String::new();
            let n = r.read_line(&mut line).unwrap();
            if n == 0 || line == "\r\n" {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                if k.eq_ignore_ascii_case("content-length") {
                    cl = v.trim().parse().unwrap_or(0);
                }
            }
            hdr.push_str(&line);
        }
        let mut body = vec![0u8; cl];
        r.read_exact(&mut body).unwrap();
        (hdr, body)
    }

    fn test_cfg(port: u16, max_job_size: u64) -> Config {
        Config {
            ipp_port: port,
            max_job_size,
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(5),
            spool_dir: env::temp_dir(),
        }
    }

    #[test]
    fn validation_and_control_file_parsing() {
        assert_eq!(parse_ipp_port(None), Some(631));
        assert_eq!(parse_ipp_port(Some("8631")), Some(8631));
        assert_eq!(parse_ipp_port(Some("0")), None);
        assert_eq!(parse_ipp_port(Some("631\r\nX-Inject: 1")), None);
        assert_eq!(parse_ipp_port(Some("")), None);

        assert!(validate_queue("office_hp-1.2"));
        for bad in [
            "",
            "-bad",
            "..",
            ".",
            "a/b",
            "q?x=1",
            "q\r\nHost: evil",
            "q with space",
            "q%20x",
        ] {
            assert!(!validate_queue(bad), "expected reject: {bad}");
        }

        let ctrl = "Hclient.lan\nPalice\nJQuarterly Report\nldfA001client\nldfA001client\nUdfA001client\nNreport.pdf\n";
        let m = parse_control_file(ctrl);
        assert_eq!(m.host.as_deref(), Some("client.lan"));
        assert_eq!(m.user.as_deref(), Some("alice"));
        assert_eq!(m.title.as_deref(), Some("Quarterly Report"));
        assert_eq!(m.filename.as_deref(), Some("report.pdf"));
        assert_eq!(m.format, "application/octet-stream");
        assert_eq!(m.copies, 2);

        let ps = parse_control_file("odfA001h\n");
        assert_eq!(ps.format, "application/postscript");
        let txt = parse_control_file("fdfA001h\n");
        assert_eq!(txt.format, "text/plain");
    }

    #[test]
    fn receive_job_supports_both_orders_and_blocks_oversized_oom() {
        // Test 1: Oversized size header immediately NACKs without OOM!
        let cfg_small = test_cfg(631, 1024);
        let wire_oom = b"\x02lp\n\x03999999999999 dfA001h\n";
        let mut out = Vec::new();
        session(&cfg_small, &mut Cursor::new(wire_oom.to_vec()), &mut out);
        assert_eq!(out, vec![0, 1]); // queue ACK, then immediate NACK!

        // Test 2: Data-before-control AND control-before-data both deliver control metadata + data!
        for data_first in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let srv = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                let (hdr, body) = read_http_req(&mut s);
                assert!(hdr.starts_with("POST /printers/office HTTP/1.1\r\n"));
                let (msg, off) = ipp_codec::decode(&body).unwrap();
                assert_eq!(msg.code, ops::op::PRINT_JOB);
                assert_eq!(&body[off..], b"HELLO-LPD-STREAM");
                assert_eq!(
                    msg.find(tags::OPERATION, "requesting-user-name")
                        .unwrap()
                        .values[0],
                    Value::Name(Text::from("bob"))
                );
                assert_eq!(
                    msg.find(tags::OPERATION, "job-name").unwrap().values[0],
                    Value::Name(Text::from("Invoice 9"))
                );
                assert_eq!(
                    msg.find(tags::JOB, "copies").unwrap().values[0],
                    Value::Integer(2)
                );

                // Reply with chunked IPP OK response.
                let reply = ipp_codec::encode(&IppMessage::new(ops::status::OK)).unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                    reply.len()
                );
                s.write_all(resp.as_bytes()).unwrap();
                s.write_all(&reply).unwrap();
                s.write_all(b"\r\n0\r\n\r\n").unwrap();
            });

            let ctrl = b"Hworkstation\nPbob\nJInvoice 9\nldfA001h\nldfA001h\n";
            let data = b"HELLO-LPD-STREAM";
            let mut wire = Vec::new();
            wire.extend_from_slice(b"\x02office\n");
            let push_ctrl = |w: &mut Vec<u8>| {
                w.push(0x02);
                w.extend_from_slice(format!("{} cfA001h\n", ctrl.len()).as_bytes());
                w.extend_from_slice(ctrl);
                w.push(0);
            };
            let push_data = |w: &mut Vec<u8>| {
                w.push(0x03);
                w.extend_from_slice(format!("{} dfA001h\n", data.len()).as_bytes());
                w.extend_from_slice(data);
                w.push(0);
            };
            if data_first {
                push_data(&mut wire);
                push_ctrl(&mut wire);
            } else {
                push_ctrl(&mut wire);
                push_data(&mut wire);
            }

            let mut out = Vec::new();
            let cfg = test_cfg(port, 1024 * 1024);
            session(&cfg, &mut Cursor::new(wire), &mut out);
            assert_eq!(out, vec![0, 0, 0, 0, 0]);
            srv.join().unwrap();
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn queue_state_and_remove_jobs_forward_real_ipp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = thread::spawn(move || {
            // 1. Short Get-Jobs
            // 2. Long Get-Jobs
            for _ in 0..2 {
                let (mut s, _) = listener.accept().unwrap();
                let (_, body) = read_http_req(&mut s);
                let (req, _) = ipp_codec::decode(&body).unwrap();
                assert_eq!(req.code, ops::op::GET_JOBS);

                let mut resp_msg = IppMessage::new(ops::status::OK);
                let mut g = Group::new(tags::JOB);
                g.attributes.push(Attribute::new(
                    "job-id",
                    tags::INTEGER,
                    vec![Value::Integer(11)],
                ));
                g.attributes.push(Attribute::new(
                    "job-originating-user-name",
                    tags::NAME,
                    vec![Value::Name(Text::from("alice"))],
                ));
                g.attributes.push(Attribute::new(
                    "job-name",
                    tags::NAME,
                    vec![Value::Name(Text::from("Doc1"))],
                ));
                g.attributes.push(Attribute::new(
                    "job-state",
                    tags::ENUM,
                    vec![Value::Enum(5)],
                ));
                g.attributes.push(Attribute::new(
                    "job-k-octets",
                    tags::INTEGER,
                    vec![Value::Integer(4)],
                ));
                g.attributes.push(Attribute::separator());
                g.attributes.push(Attribute::new(
                    "job-id",
                    tags::INTEGER,
                    vec![Value::Integer(12)],
                ));
                g.attributes.push(Attribute::new(
                    "job-originating-user-name",
                    tags::NAME,
                    vec![Value::Name(Text::from("bob"))],
                ));
                g.attributes.push(Attribute::new(
                    "job-name",
                    tags::NAME,
                    vec![Value::Name(Text::from("Doc2"))],
                ));
                g.attributes.push(Attribute::new(
                    "job-state",
                    tags::ENUM,
                    vec![Value::Enum(3)],
                ));
                g.attributes.push(Attribute::new(
                    "job-k-octets",
                    tags::INTEGER,
                    vec![Value::Integer(2)],
                ));
                resp_msg.groups.push(g);

                let enc = ipp_codec::encode(&resp_msg).unwrap();
                let hdr = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", enc.len());
                s.write_all(hdr.as_bytes()).unwrap();
                s.write_all(&enc).unwrap();
            }

            // 3. Cancel-Job for explicit job 11
            let (mut s, _) = listener.accept().unwrap();
            let (_, body) = read_http_req(&mut s);
            let (req, _) = ipp_codec::decode(&body).unwrap();
            assert_eq!(req.code, ops::op::CANCEL_JOB);
            assert_eq!(
                req.find(tags::OPERATION, "job-id").unwrap().values[0],
                Value::Integer(11)
            );
            let enc = ipp_codec::encode(&IppMessage::new(ops::status::OK)).unwrap();
            let hdr = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", enc.len());
            s.write_all(hdr.as_bytes()).unwrap();
            s.write_all(&enc).unwrap();
        });

        let cfg = test_cfg(port, 1024 * 1024);

        // Short queue state (0x03)
        let mut out_short = Vec::new();
        session(
            &cfg,
            &mut Cursor::new(b"\x03office\n".to_vec()),
            &mut out_short,
        );
        let short_txt = String::from_utf8(out_short).unwrap();
        assert!(short_txt.contains("office is ready"));
        assert!(short_txt.contains("active"));
        assert!(short_txt.contains("alice"));
        assert!(short_txt.contains("Doc1"));
        assert!(short_txt.contains("2nd"));
        assert!(short_txt.contains("bob"));

        // Long queue state (0x04) filtered to alice
        let mut out_long = Vec::new();
        session(
            &cfg,
            &mut Cursor::new(b"\x04office alice\n".to_vec()),
            &mut out_long,
        );
        let long_txt = String::from_utf8(out_long).unwrap();
        assert!(long_txt.contains("alice: active [job 11]"));
        assert!(!long_txt.contains("bob"));

        // Remove job (0x05)
        let mut out_rm = Vec::new();
        session(
            &cfg,
            &mut Cursor::new(b"\x05office alice 11\n".to_vec()),
            &mut out_rm,
        );
        assert_eq!(out_rm, vec![0]);

        srv.join().unwrap();
    }

    #[test]
    fn command_edge_cases_abort_invalid_and_ranks() {
        assert_eq!(format_rank(0, 5), "active");
        assert_eq!(format_rank(0, 3), "1st");
        assert_eq!(format_rank(1, 3), "2nd");
        assert_eq!(format_rank(2, 3), "3rd");
        assert_eq!(format_rank(3, 3), "4th");
        assert_eq!(format_rank(10, 3), "11th");

        let cfg = test_cfg(1, 1024); // closed port

        // 0x01 print waiting
        let mut out = Vec::new();
        session(&cfg, &mut Cursor::new(b"\x01lp\n".to_vec()), &mut out);
        assert_eq!(out, vec![0]);

        // 0x02 invalid queue & abort subcommand
        let mut out2 = Vec::new();
        session(&cfg, &mut Cursor::new(b"\x02../bad\n".to_vec()), &mut out2);
        assert_eq!(out2, vec![1]);

        let mut out_abort = Vec::new();
        session(
            &cfg,
            &mut Cursor::new(b"\x02lp\n\x01".to_vec()),
            &mut out_abort,
        );
        assert_eq!(out_abort, vec![0, 0]);

        // 0x03 invalid queue & unavailable daemon
        let mut out_q = Vec::new();
        session(&cfg, &mut Cursor::new(b"\x03../bad\n".to_vec()), &mut out_q);
        assert!(String::from_utf8(out_q).unwrap().contains("invalid queue"));

        let mut out_down = Vec::new();
        session(&cfg, &mut Cursor::new(b"\x03lp\n".to_vec()), &mut out_down);
        assert!(String::from_utf8(out_down)
            .unwrap()
            .contains("daemon unavailable"));

        // 0x05 invalid queue & unknown cmd & empty input
        let mut out_rm_bad = Vec::new();
        session(
            &cfg,
            &mut Cursor::new(b"\x05../bad alice\n".to_vec()),
            &mut out_rm_bad,
        );
        assert_eq!(out_rm_bad, vec![1]);

        let mut out_unk = Vec::new();
        session(&cfg, &mut Cursor::new(b"\x99".to_vec()), &mut out_unk);
        assert_eq!(out_unk, vec![1]);

        let mut out_eof = Vec::new();
        assert_eq!(
            session(&cfg, &mut Cursor::new(Vec::new()), &mut out_eof),
            std::process::ExitCode::FAILURE
        );
        let _ = Config::from_env();
    }

    #[test]
    fn http_reader_spool_and_protocol_error_paths() {
        // TempSpool truncated fill_exact & invalid dir error.
        let mut sp = TempSpool::create(&env::temp_dir()).unwrap();
        assert!(sp
            .fill_exact(&mut Cursor::new(b"short".to_vec()), 100)
            .is_err());
        assert!(TempSpool::create(Path::new("/nonexistent-cups-lpd-dir-xyz")).is_err());

        // read_http_response_body: non-200, close-delimited, bad CL, bad chunk CRLF, empty.
        assert!(
            read_http_response_body(&mut Cursor::new(b"HTTP/1.1 500 Err\r\n\r\n".to_vec()))
                .is_none()
        );
        assert_eq!(
            read_http_response_body(&mut Cursor::new(b"HTTP/1.1 200 OK\r\n\r\nraw".to_vec()))
                .unwrap(),
            b"raw"
        );
        assert!(read_http_response_body(&mut Cursor::new(
            b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n".to_vec()
        ))
        .is_none());
        assert!(read_http_response_body(&mut Cursor::new(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabXX".to_vec()
        ))
        .is_none());
        assert!(read_http_response_body(&mut Cursor::new(Vec::new())).is_none());
        // Additional HTTP & line-length & sanitize edge cases.
        let giant_http = format!(
            "HTTP/1.1 200 OK\r\nX: {}\r\n\r\n",
            "a".repeat(MAX_HTTP_HEADER_BYTES + 8)
        );
        assert!(read_http_response_body(&mut Cursor::new(giant_http.into_bytes())).is_none());
        let huge_chunk = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            MAX_HTTP_BODY_BYTES + 1
        );
        assert!(read_http_response_body(&mut Cursor::new(huge_chunk.into_bytes())).is_none());
        assert!(read_http_response_body(&mut Cursor::new(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n".to_vec()
        ))
        .is_none());
        let mut huge_eof = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        huge_eof.resize(huge_eof.len() + MAX_HTTP_BODY_BYTES + 16, b'x');
        assert!(read_http_response_body(&mut Cursor::new(huge_eof)).is_none());
        assert!(read_line(&mut Cursor::new(vec![b'a'; MAX_LINE_LEN + 10])).is_none());
        assert!(parse_subfile_header("5 ").is_none());
        assert_eq!(sanitize_text("ab\x07cd\x00ef", 4), "abcd");
        let ctrl_misc = parse_control_file("\nCbanner\nLalice\n");
        assert_eq!(ctrl_misc.copies, 1);

        // receive_job, queue_state, and remove_jobs EOF / empty-line edge cases.
        let cfg = test_cfg(1, 1024);
        for wire in [
            &b"\x02lp\n\x02"[..],
            &b"\x02lp\n\x02badhdr\n"[..],
            &b"\x02lp\n\x02999999 cfA001h\n"[..],
            &b"\x02lp\n\x025 cfA001h\nabc"[..],
            &b"\x02lp\n\x022 cfA001h\nhi\x01"[..],
            &b"\x02lp\n\x03"[..],
            &b"\x02lp\n\x03badhdr\n"[..],
            &b"\x02lp\n\x035 dfA001h\nabc"[..],
            &b"\x02lp\n\x032 dfA001h\nhi\x01"[..],
            &b"\x02lp\n\x7f"[..],
            &b"\x02"[..],
            &b"\x05"[..],
            &b"\x05\n"[..],
        ] {
            let mut out = Vec::new();
            session(&cfg, &mut Cursor::new(wire.to_vec()), &mut out);
            assert_eq!(out.last().copied(), Some(1), "expected NACK for {wire:?}");
        }
        let mut out_qs_eof = Vec::new();
        session(&cfg, &mut Cursor::new(b"\x03".to_vec()), &mut out_qs_eof);
        assert_eq!(out_qs_eof, [] as [u8; 0]);
        let mut out_qs_empty = Vec::new();
        session(
            &cfg,
            &mut Cursor::new(b"\x03\n".to_vec()),
            &mut out_qs_empty,
        );
        assert!(String::from_utf8(out_qs_empty)
            .unwrap()
            .contains("invalid queue"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn data_only_empty_queue_and_remove_job_fallback() {
        let cfg = test_cfg(1, 1024);

        // Data-only job (EOF without control file) still submits cleanly!
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = thread::spawn(move || {
            // 1. Data-only Print-Job
            let (mut s1, _) = listener.accept().unwrap();
            let (_, body1) = read_http_req(&mut s1);
            let (req1, off1) = ipp_codec::decode(&body1).unwrap();
            assert_eq!(req1.code, ops::op::PRINT_JOB);
            assert_eq!(&body1[off1..], b"solo");
            let r1 = ipp_codec::encode(&IppMessage::new(ops::status::OK)).unwrap();
            s1.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", r1.len()).as_bytes(),
            )
            .unwrap();
            s1.write_all(&r1).unwrap();

            // 2. Empty queue Get-Jobs
            let (mut s2, _) = listener.accept().unwrap();
            let _ = read_http_req(&mut s2);
            let r2 = ipp_codec::encode(&IppMessage::new(ops::status::OK)).unwrap();
            s2.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", r2.len()).as_bytes(),
            )
            .unwrap();
            s2.write_all(&r2).unwrap();

            // 3. remove_jobs (no explicit ID -> Get-Jobs then Cancel-Job)
            let (mut s3, _) = listener.accept().unwrap();
            let _ = read_http_req(&mut s3);
            let mut gj = IppMessage::new(ops::status::OK);
            let mut g = Group::new(tags::JOB);
            g.attributes.push(Attribute::new(
                "job-id",
                tags::INTEGER,
                vec![Value::Integer(77)],
            ));
            g.attributes.push(Attribute::new(
                "job-originating-user-name",
                tags::NAME,
                vec![Value::Name(Text::from("alice"))],
            ));
            gj.groups.push(g);
            let r3 = ipp_codec::encode(&gj).unwrap();
            s3.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", r3.len()).as_bytes(),
            )
            .unwrap();
            s3.write_all(&r3).unwrap();

            let (mut s4, _) = listener.accept().unwrap();
            let (_, b4) = read_http_req(&mut s4);
            let (req4, _) = ipp_codec::decode(&b4).unwrap();
            assert_eq!(req4.code, ops::op::CANCEL_JOB);
            let r4 =
                ipp_codec::encode(&IppMessage::new(ops::status::ERROR_NOT_AUTHORIZED)).unwrap();
            s4.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", r4.len()).as_bytes(),
            )
            .unwrap();
            s4.write_all(&r4).unwrap();

            // 4. remove_jobs with empty queue -> ACK without Cancel-Job.
            let (mut s5, _) = listener.accept().unwrap();
            let _ = read_http_req(&mut s5);
            let r5 = ipp_codec::encode(&IppMessage::new(ops::status::OK)).unwrap();
            s5.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", r5.len()).as_bytes(),
            )
            .unwrap();
            s5.write_all(&r5).unwrap();
        });

        let cfg_live = test_cfg(port, 1024 * 1024);
        let mut out_solo = Vec::new();
        session(
            &cfg_live,
            &mut Cursor::new(b"\x02lp\n\x034 dfA001h\nsolo\0".to_vec()),
            &mut out_solo,
        );
        assert_eq!(out_solo, vec![0, 0, 0]);

        let mut out_empty = Vec::new();
        session(
            &cfg_live,
            &mut Cursor::new(b"\x03lp\n".to_vec()),
            &mut out_empty,
        );
        assert!(String::from_utf8(out_empty).unwrap().contains("no entries"));

        // remove_jobs without explicit ID finds job 77 -> Cancel-Job returns NOT_AUTHORIZED -> NACK(1).
        let mut out_rm_deny = Vec::new();
        session(
            &cfg_live,
            &mut Cursor::new(b"\x05lp alice\n".to_vec()),
            &mut out_rm_deny,
        );
        assert_eq!(out_rm_deny, vec![1]);

        // remove_jobs on empty queue with -all -> ACK(0).
        let mut out_rm_none = Vec::new();
        session(
            &cfg_live,
            &mut Cursor::new(b"\x05lp alice -all\n".to_vec()),
            &mut out_rm_none,
        );
        assert_eq!(out_rm_none, vec![0]);

        // remove_jobs when daemon unreachable -> NACK(1).
        let mut out_rm_down = Vec::new();
        session(
            &cfg,
            &mut Cursor::new(b"\x05lp alice\n".to_vec()),
            &mut out_rm_down,
        );
        assert_eq!(out_rm_down, vec![1]);

        srv.join().unwrap();
    }
}
