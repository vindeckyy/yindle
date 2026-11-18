//! `ipp` backend — forward a job to a remote IPP/IPPS/HTTP/HTTPS printer or queue.
//!
//! Parses `DEVICE_URI` (`ipp://`, `ipps://`, `http://`, `https://`, including
//! IPv6 bracketed hosts and optional Basic Auth credentials), streams the
//! `Print-Job` payload directly from file or stdin without full-job RAM
//! buffering, decodes both `Content-Length` and `Transfer-Encoding: chunked`
//! responses within strict size limits, polls `Get-Job-Attributes` until the
//! remote job reaches a terminal state, and emits `STATE:`/`INFO:`/`PAGE:`
//! updates and accurate `CUPS_BACKEND_*` exit codes.

use backend_common::{self as bc, NetworkUri, SsrfPolicy};
use ipp_codec::{ops, tags, Attribute, Group, IppMessage, Text, Value};
use rustls::pki_types::pem::PemObject;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_TRAILER_LINES: usize = 64;
const STREAM_BUF_SIZE: usize = 16 * 1024;

/// Runtime configuration (injectable for deterministic tests).
struct Config {
    ssrf: SsrfPolicy,
    connect_timeout: Duration,
    io_timeout: Duration,
    poll_interval: Duration,
    max_polls: u32,
    ca_bundle: Option<PathBuf>,
    content_type: Option<String>,
    final_content_type: Option<String>,
    auth_env: Option<(String, String)>,
}

impl Config {
    fn from_env() -> Self {
        let ca_bundle = env::var("CUPS_CA_BUNDLE")
            .ok()
            .or_else(|| env::var("SSL_CERT_FILE").ok())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        let auth_env = match (
            env::var("AUTH_USERNAME").ok(),
            env::var("AUTH_PASSWORD").ok(),
        ) {
            (Some(u), Some(p)) if !u.is_empty() => Some((u, p)),
            _ => None,
        };
        Self {
            ssrf: SsrfPolicy::from_env(),
            connect_timeout: Duration::from_secs(30),
            io_timeout: Duration::from_secs(60),
            poll_interval: Duration::from_secs(2),
            max_polls: 3600,
            ca_bundle,
            content_type: env::var("CONTENT_TYPE").ok(),
            final_content_type: env::var("FINAL_CONTENT_TYPE").ok(),
            auth_env,
        }
    }
}

/// Parsed IPP/HTTP target.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    host: String,
    port: u16,
    resource: String,
    printer_uri: String,
    tls: bool,
    credentials: Option<(String, String)>,
    wait_job: bool,
}

/// Parse `ipp://`, `ipps://`, `http://`, `https://` URI into [`Target`].
fn parse_uri(uri: &str) -> Option<Target> {
    let (scheme_raw, _) = uri.split_once("://")?;
    let (default_port, tls, ipp_scheme) = match scheme_raw.to_ascii_lowercase().as_str() {
        "ipps" => (631, true, "ipps"),
        "ipp" => (631, false, "ipp"),
        "https" => (443, true, "ipps"),
        "http" => (80, false, "ipp"),
        _ => return None,
    };

    let parsed = NetworkUri::parse(uri, default_port)?;
    let credentials = parsed
        .username
        .as_ref()
        .map(|u| (u.clone(), parsed.password.clone().unwrap_or_default()));

    let mut wait_job = true;
    if let Some(q) = &parsed.query {
        for kv in q.split(['&', '+']) {
            if let Some((k, v)) = kv.split_once('=') {
                if k.eq_ignore_ascii_case("waitjob") {
                    if let Some(b) = bc::parse_env_bool(Some(v)) {
                        wait_job = b;
                    }
                }
            }
        }
    }

    let printer_uri = parsed.clean_uri(Some(ipp_scheme));
    Some(Target {
        host: parsed.host,
        port: parsed.port,
        resource: parsed.path,
        printer_uri,
        tls,
        credentials,
        wait_job,
    })
}

/// Standard Base64 encoder (RFC 4648) for HTTP Basic Authorization headers.
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(TABLE[((n >> 18) & 0x3f) as usize]));
        out.push(char::from(TABLE[((n >> 12) & 0x3f) as usize]));
        if chunk.len() > 1 {
            out.push(char::from(TABLE[((n >> 6) & 0x3f) as usize]));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(TABLE[(n & 0x3f) as usize]));
        } else {
            out.push('=');
        }
    }
    out
}

/// Build TLS client config using native OS roots plus an optional explicit CA
/// bundle file (`CUPS_CA_BUNDLE` / `SSL_CERT_FILE`). Never blindly trusts
/// arbitrary files in `$CUPS_SERVERROOT/ssl`.
fn tls_config(ca_bundle: Option<&PathBuf>) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for c in native.certs {
        let _ = roots.add(c);
    }
    if let Some(bundle_path) = ca_bundle {
        match std::fs::read(bundle_path) {
            Ok(data) => {
                let mut added = 0usize;
                for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&data).flatten() {
                    if roots.add(cert).is_ok() {
                        added += 1;
                    }
                }
                bc::debug(format_args!(
                    "ipp: loaded {added} CA cert(s) from {}",
                    bundle_path.display()
                ));
            }
            Err(e) => {
                bc::warn(format_args!(
                    "ipp: cannot read CA bundle {}: {e}",
                    bundle_path.display()
                ));
            }
        }
    }
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Document payload source for streaming HTTP requests.
enum BodySource<'a> {
    Empty,
    File(File, u64),
    Stream(Box<dyn Read + 'a>),
}

fn open_body_source(inv: &bc::Invocation) -> io::Result<BodySource<'static>> {
    match &inv.file {
        Some(path) => {
            let f = File::open(path)?;
            let meta = f.metadata()?;
            if meta.file_type().is_file() {
                Ok(BodySource::File(f, meta.len()))
            } else {
                Ok(BodySource::Stream(Box::new(f)))
            }
        }
        None => Ok(BodySource::Stream(Box::new(io::stdin()))),
    }
}

/// Send an HTTP/1.1 POST carrying `ipp_bytes` followed by `body` (streamed) and
/// decode the bounded HTTP response (supporting `100 Continue`, `Content-Length`,
/// and `Transfer-Encoding: chunked`).
fn http_round_trip(
    stream: &mut (impl Read + Write),
    target: &Target,
    auth: Option<&(String, String)>,
    ipp_bytes: &[u8],
    body: BodySource<'_>,
) -> Result<(u16, Vec<u8>), i32> {
    let host_hdr = bc::format_host_port(&target.host, target.port);
    let auth_hdr = auth.map(|(u, p)| {
        let b64 = base64_encode(format!("{u}:{p}").as_bytes());
        format!("Authorization: Basic {b64}\r\n")
    });
    let auth_str = auth_hdr.as_deref().unwrap_or("");

    match body {
        BodySource::Empty => {
            let req = format!(
                "POST {} HTTP/1.1\r\nHost: {host_hdr}\r\n{auth_str}Content-Type: application/ipp\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                target.resource,
                ipp_bytes.len()
            );
            stream
                .write_all(req.as_bytes())
                .and_then(|()| stream.write_all(ipp_bytes))
                .and_then(|()| stream.flush())
                .map_err(|e| {
                    bc::error(format_args!("ipp: send request failed: {e}"));
                    bc::code::RETRY_CURRENT
                })?;
        }
        BodySource::File(mut file, file_len) => {
            let Some(total_len) = (ipp_bytes.len() as u64).checked_add(file_len) else {
                bc::error(format_args!("ipp: document length overflow"));
                return Err(bc::code::FAILED);
            };
            let req = format!(
                "POST {} HTTP/1.1\r\nHost: {host_hdr}\r\n{auth_str}Content-Type: application/ipp\r\nContent-Length: {total_len}\r\nConnection: close\r\n\r\n",
                target.resource
            );
            stream
                .write_all(req.as_bytes())
                .and_then(|()| stream.write_all(ipp_bytes))
                .map_err(|e| {
                    bc::error(format_args!("ipp: send header failed: {e}"));
                    bc::code::RETRY_CURRENT
                })?;
            stream_exact_to_writer(&mut file, stream, file_len)?;
            let _ = stream.flush();
        }
        BodySource::Stream(mut reader) => {
            let req = format!(
                "POST {} HTTP/1.1\r\nHost: {host_hdr}\r\n{auth_str}Content-Type: application/ipp\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                target.resource
            );
            stream.write_all(req.as_bytes()).map_err(|e| {
                bc::error(format_args!("ipp: send chunked header failed: {e}"));
                bc::code::RETRY_CURRENT
            })?;
            write_chunk(stream, ipp_bytes)?;
            let mut buf = [0u8; STREAM_BUF_SIZE];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => write_chunk(stream, &buf[..n])?,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        bc::error(format_args!("ipp: read document failed: {e}"));
                        return Err(bc::code::FAILED);
                    }
                }
            }
            stream
                .write_all(b"0\r\n\r\n")
                .and_then(|()| stream.flush())
                .map_err(|e| {
                    bc::error(format_args!("ipp: finish chunked body failed: {e}"));
                    bc::code::RETRY_CURRENT
                })?;
        }
    }

    read_http_response(stream)
}

fn stream_exact_to_writer(
    reader: &mut impl Read,
    writer: &mut impl Write,
    expected: u64,
) -> Result<(), i32> {
    let mut remaining = expected;
    let mut buf = [0u8; STREAM_BUF_SIZE];
    while remaining > 0 {
        let want = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
        match reader.read(&mut buf[..want]) {
            Ok(0) => {
                bc::error(format_args!("ipp: document truncated while streaming"));
                return Err(bc::code::FAILED);
            }
            Ok(n) => {
                writer.write_all(&buf[..n]).map_err(|e| {
                    bc::error(format_args!("ipp: write document failed: {e}"));
                    bc::code::RETRY_CURRENT
                })?;
                remaining -= n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                bc::error(format_args!("ipp: read document failed: {e}"));
                return Err(bc::code::FAILED);
            }
        }
    }
    Ok(())
}

fn write_chunk(writer: &mut impl Write, data: &[u8]) -> Result<(), i32> {
    if data.is_empty() {
        return Ok(());
    }
    let hdr = format!("{:x}\r\n", data.len());
    writer
        .write_all(hdr.as_bytes())
        .and_then(|()| writer.write_all(data))
        .and_then(|()| writer.write_all(b"\r\n"))
        .map_err(|e| {
            bc::error(format_args!("ipp: write chunk failed: {e}"));
            bc::code::RETRY_CURRENT
        })
}

/// Read an HTTP/1.x response with bounded header/body sizes and chunked decoding.
fn read_http_response(stream: &mut impl Read) -> Result<(u16, Vec<u8>), i32> {
    let mut reader = BufReader::new(stream);
    let (status, is_chunked, content_length) = loop {
        let (status, headers) = read_header_block(&mut reader)?;
        // Skip interim 1xx (e.g. `100 Continue`) responses.
        if (100..200).contains(&status) {
            continue;
        }
        let mut is_chunked = false;
        let mut content_length: Option<usize> = None;
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("transfer-encoding") {
                if v.split(',')
                    .any(|tok| tok.trim().eq_ignore_ascii_case("chunked"))
                {
                    is_chunked = true;
                }
            } else if k.eq_ignore_ascii_case("content-length") {
                let parsed: usize = v.trim().parse().map_err(|_| {
                    bc::error(format_args!("ipp: invalid Content-Length header"));
                    bc::code::FAILED
                })?;
                if parsed > MAX_BODY_BYTES {
                    bc::error(format_args!(
                        "ipp: response Content-Length {parsed} exceeds limit {MAX_BODY_BYTES}"
                    ));
                    return Err(bc::code::FAILED);
                }
                if let Some(prev) = content_length {
                    if prev != parsed {
                        bc::error(format_args!("ipp: conflicting Content-Length headers"));
                        return Err(bc::code::FAILED);
                    }
                }
                content_length = Some(parsed);
            }
        }
        break (status, is_chunked, content_length);
    };

    let body = if is_chunked {
        read_chunked_body(&mut reader)?
    } else if let Some(len) = content_length {
        read_exact_bounded(&mut reader, len)?
    } else {
        read_to_eof_bounded(&mut reader)?
    };
    Ok((status, body))
}

fn read_bounded_line(reader: &mut impl BufRead, budget: &mut usize) -> Result<String, i32> {
    let mut line = Vec::new();
    loop {
        if *budget == 0 {
            bc::error(format_args!("ipp: HTTP response headers exceed size limit"));
            return Err(bc::code::FAILED);
        }
        let available = match reader.fill_buf() {
            Ok([]) => {
                if line.is_empty() {
                    bc::error(format_args!("ipp: unexpected EOF reading HTTP headers"));
                    return Err(bc::code::RETRY);
                }
                break;
            }
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && !line.is_empty() => break,
            Err(e) => {
                bc::error(format_args!("ipp: read HTTP header failed: {e}"));
                return Err(bc::code::RETRY);
            }
        };
        let take = available.len().min(*budget);
        if let Some(nl) = available[..take].iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&available[..=nl]);
            reader.consume(nl + 1);
            *budget -= nl + 1;
            break;
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        *budget -= take;
    }
    let s = String::from_utf8_lossy(&line);
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

fn read_header_block(reader: &mut impl BufRead) -> Result<(u16, Vec<(String, String)>), i32> {
    let mut budget = MAX_HEADER_BYTES;
    let status_line = read_bounded_line(reader, &mut budget)?;
    let mut parts = status_line.split_whitespace();
    let proto = parts.next().unwrap_or("");
    let code_str = parts.next().unwrap_or("");
    if !proto.starts_with("HTTP/1.") {
        bc::error(format_args!("ipp: invalid HTTP response status line"));
        return Err(bc::code::FAILED);
    }
    let status: u16 = code_str.parse().map_err(|_| {
        bc::error(format_args!("ipp: invalid HTTP status code"));
        bc::code::FAILED
    })?;

    let mut headers = Vec::new();
    loop {
        let line = read_bounded_line(reader, &mut budget)?;
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, headers))
}

fn read_chunked_body(reader: &mut impl BufRead) -> Result<Vec<u8>, i32> {
    let mut out = Vec::new();
    let mut line_budget = MAX_HEADER_BYTES;
    loop {
        let size_line = read_bounded_line(reader, &mut line_budget)?;
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16).map_err(|_| {
            bc::error(format_args!("ipp: invalid chunk size '{hex}'"));
            bc::code::FAILED
        })?;
        if size == 0 {
            // Drain bounded trailer headers until blank line.
            for _ in 0..=MAX_TRAILER_LINES {
                let trailer = read_bounded_line(reader, &mut line_budget)?;
                if trailer.is_empty() {
                    return Ok(out);
                }
            }
            bc::error(format_args!("ipp: too many chunked trailers"));
            return Err(bc::code::FAILED);
        }
        let next_total = out.len().checked_add(size).ok_or(bc::code::FAILED)?;
        if next_total > MAX_BODY_BYTES {
            bc::error(format_args!(
                "ipp: chunked response exceeds limit {MAX_BODY_BYTES}"
            ));
            return Err(bc::code::FAILED);
        }
        let chunk = read_exact_bounded(reader, size)?;
        out.extend_from_slice(&chunk);
        // Expect trailing CRLF after each chunk payload.
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).map_err(|e| {
            bc::error(format_args!("ipp: missing chunk CRLF: {e}"));
            bc::code::FAILED
        })?;
        if crlf != *b"\r\n" {
            bc::error(format_args!("ipp: malformed chunk terminator"));
            return Err(bc::code::FAILED);
        }
    }
}

fn read_exact_bounded(reader: &mut impl Read, len: usize) -> Result<Vec<u8>, i32> {
    let mut out = vec![0u8; len];
    let mut off = 0;
    while off < len {
        match reader.read(&mut out[off..]) {
            Ok(0) => {
                bc::error(format_args!("ipp: truncated response body"));
                return Err(bc::code::RETRY);
            }
            Ok(n) => off += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                bc::error(format_args!("ipp: read response body failed: {e}"));
                return Err(bc::code::RETRY);
            }
        }
    }
    Ok(out)
}

fn read_to_eof_bounded(reader: &mut impl Read) -> Result<Vec<u8>, i32> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let Some(next) = out.len().checked_add(n) else {
                    return Err(bc::code::FAILED);
                };
                if next > MAX_BODY_BYTES {
                    bc::error(format_args!(
                        "ipp: response body exceeds limit {MAX_BODY_BYTES}"
                    ));
                    return Err(bc::code::FAILED);
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                bc::error(format_args!("ipp: read response failed: {e}"));
                return Err(bc::code::RETRY);
            }
        }
    }
    Ok(out)
}

/// Map an HTTP error status code (non-2xx) to a `CUPS_BACKEND_*` code.
fn map_http_status(status: u16) -> i32 {
    match status {
        401 => {
            bc::attr("auth-info-required", "username,password");
            bc::error(format_args!("ipp: HTTP 401 authentication required"));
            bc::code::AUTH_REQUIRED
        }
        404 | 410 => {
            bc::error(format_args!("ipp: HTTP {status} destination not found"));
            bc::code::STOP
        }
        408 | 429 | 500..=599 => {
            bc::error(format_args!("ipp: HTTP {status} temporary failure"));
            bc::code::RETRY
        }
        _ => {
            bc::error(format_args!("ipp: HTTP {status} request failed"));
            bc::code::FAILED
        }
    }
}

/// Map an IPP status code to a `CUPS_BACKEND_*` exit code.
fn map_ipp_status(code: u16) -> i32 {
    use ops::status;
    if code < 0x0100 {
        return bc::code::OK;
    }
    match code {
        status::ERROR_NOT_AUTHENTICATED
        | status::ERROR_NOT_AUTHORIZED
        | status::ERROR_FORBIDDEN
        | status::ERROR_ACCOUNT_INFO_NEEDED
        | status::ERROR_CUPS_ACCOUNT_INFO_NEEDED
        | status::ERROR_ACCOUNT_AUTHORIZATION_FAILED
        | status::ERROR_CUPS_ACCOUNT_AUTHORIZATION_FAILED => {
            bc::attr("auth-info-required", "username,password");
            bc::code::AUTH_REQUIRED
        }
        status::ERROR_JOB_CANCELED => bc::code::CANCEL,
        status::ERROR_DEVICE
        | status::ERROR_PRINTER_IS_DEACTIVATED
        | status::ERROR_NOT_FOUND
        | status::ERROR_GONE => bc::code::STOP,
        status::ERROR_MULTIPLE_JOBS_NOT_SUPPORTED => bc::code::RETRY_CURRENT,
        status::ERROR_NOT_ACCEPTING_JOBS
        | status::ERROR_BUSY
        | status::ERROR_TEMPORARY
        | status::ERROR_SERVICE_UNAVAILABLE
        | status::ERROR_TOO_MANY_JOBS
        | status::ERROR_TIMEOUT => bc::code::RETRY,
        _ => bc::code::FAILED,
    }
}

/// Send an IPP request + streamed body over TCP or TLS and decode the IPP reply.
fn ipp_send(
    target: &Target,
    cfg: &Config,
    msg: &IppMessage,
    body: BodySource<'_>,
) -> Result<IppMessage, i32> {
    let ipp_bytes = ipp_codec::encode(msg).map_err(|_| bc::code::FAILED)?;
    let auth = target.credentials.as_ref().or(cfg.auth_env.as_ref());

    bc::state("+connecting-to-device");
    let (mut tcp, _addr) =
        match cfg
            .ssrf
            .connect_checked(&target.host, target.port, cfg.connect_timeout)
        {
            Ok(pair) => pair,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                bc::state("-connecting-to-device");
                bc::error(format_args!(
                    "ipp: destination {} blocked by policy: {e}",
                    target.printer_uri
                ));
                return Err(bc::code::FAILED);
            }
            Err(e) => {
                bc::state("-connecting-to-device");
                bc::error(format_args!(
                    "ipp: connect {} failed: {e}",
                    target.printer_uri
                ));
                return Err(bc::code::RETRY);
            }
        };
    bc::state("-connecting-to-device");
    let _ = tcp.set_read_timeout(Some(cfg.io_timeout));
    let _ = tcp.set_write_timeout(Some(cfg.io_timeout));

    let (http_status, resp_body) = if target.tls {
        let tls_cfg = tls_config(cfg.ca_bundle.as_ref());
        let Ok(name) = rustls::pki_types::ServerName::try_from(target.host.clone()) else {
            bc::error(format_args!("ipp: bad TLS server name {}", target.host));
            return Err(bc::code::FAILED);
        };
        let mut conn = match rustls::ClientConnection::new(Arc::new(tls_cfg), name) {
            Ok(c) => c,
            Err(e) => {
                bc::error(format_args!("ipp: TLS init failed: {e}"));
                return Err(bc::code::FAILED);
            }
        };
        let mut tls_stream = rustls::Stream::new(&mut conn, &mut tcp);
        http_round_trip(&mut tls_stream, target, auth, &ipp_bytes, body)?
    } else {
        http_round_trip(&mut tcp, target, auth, &ipp_bytes, body)?
    };

    if !(200..300).contains(&http_status) {
        return Err(map_http_status(http_status));
    }

    ipp_codec::decode(&resp_body).map(|(m, _)| m).map_err(|e| {
        bc::error(format_args!("ipp: invalid IPP response: {e}"));
        bc::code::FAILED
    })
}

fn op_group(printer_uri: &str) -> Group {
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
        vec![Value::Uri(Text::from(printer_uri))],
    ));
    g
}

/// Parse CUPS space-separated `key=value` option string (respecting quotes).
fn parse_options(opts: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut chars = opts.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut token = String::new();
        let mut quote: Option<char> = None;
        for ch in chars.by_ref() {
            match quote {
                Some(q) if ch == q => quote = None,
                None if ch == '"' || ch == '\'' => quote = Some(ch),
                None if ch.is_whitespace() => break,
                Some(_) | None => token.push(ch),
            }
        }
        if let Some((k, v)) = token.split_once('=') {
            out.push((k.to_string(), v.to_string()));
        }
    }
    out
}

/// Resolve the MIME `document-format` from `FINAL_CONTENT_TYPE` / `CONTENT_TYPE`
/// and optional explicit `document-format=` job option.
fn resolve_document_format(cfg: &Config, options: &[(String, String)]) -> String {
    if let Some((_, v)) = options
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("document-format"))
    {
        if is_valid_mime(v) {
            return v.clone();
        }
    }
    if let Some(ft) = &cfg.final_content_type {
        let ft = ft.trim();
        if is_valid_mime(ft)
            && !ft.eq_ignore_ascii_case("application/vnd.cups-raw")
            && !ft.starts_with("printer/")
        {
            return ft.to_string();
        }
    }
    if let Some(ct) = &cfg.content_type {
        let ct = ct.trim();
        if is_valid_mime(ct) {
            return ct.to_string();
        }
    }
    "application/octet-stream".to_string()
}

fn is_valid_mime(s: &str) -> bool {
    let Some((ty, sub)) = s.split_once('/') else {
        return false;
    };
    !ty.is_empty()
        && !sub.is_empty()
        && !sub.contains('/')
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\' | b';'))
}

/// Build the IPP `Print-Job` message including document-format, copies, and options.
fn build_print_job(target: &Target, inv: &bc::Invocation, cfg: &Config) -> IppMessage {
    let options = parse_options(&inv.options);
    let doc_format = resolve_document_format(cfg, &options);

    let mut msg = IppMessage::new(ops::op::PRINT_JOB);
    let mut op = op_group(&target.printer_uri);
    if !inv.user.is_empty() {
        op.attributes.push(Attribute::new(
            "requesting-user-name",
            tags::NAME,
            vec![Value::Name(Text::from(inv.user.clone()))],
        ));
    }
    if !inv.title.is_empty() {
        op.attributes.push(Attribute::new(
            "job-name",
            tags::NAME,
            vec![Value::Name(Text::from(inv.title.clone()))],
        ));
    }
    op.attributes.push(Attribute::new(
        "document-format",
        tags::MIMETYPE,
        vec![Value::MimeMediaType(Text::from(doc_format))],
    ));
    msg.groups.push(op);

    let mut job = Group::new(tags::JOB);
    let mut copies_set = false;
    for (k, v) in &options {
        match k.as_str() {
            "copies" => {
                if let Ok(n) = v.parse::<i32>() {
                    if n > 0 {
                        job.attributes.push(Attribute::new(
                            "copies",
                            tags::INTEGER,
                            vec![Value::Integer(n)],
                        ));
                        copies_set = true;
                    }
                }
            }
            "sides" | "media" | "print-color-mode" | "job-hold-until" => {
                job.attributes.push(Attribute::new(
                    k.clone(),
                    tags::KEYWORD,
                    vec![Value::Keyword(Text::from(v.clone()))],
                ));
            }
            "orientation-requested" | "print-quality" => {
                if let Ok(n) = v.parse::<i32>() {
                    job.attributes.push(Attribute::new(
                        k.clone(),
                        tags::ENUM,
                        vec![Value::Enum(n)],
                    ));
                }
            }
            "job-priority" | "number-up" => {
                if let Ok(n) = v.parse::<i32>() {
                    if n > 0 {
                        job.attributes.push(Attribute::new(
                            k.clone(),
                            tags::INTEGER,
                            vec![Value::Integer(n)],
                        ));
                    }
                }
            }
            "page-ranges" => {
                let ranges: Vec<Value> = v
                    .split(',')
                    .filter_map(|part| {
                        let (lo, hi) = part.split_once('-').unwrap_or((part, part));
                        let lo = lo.parse::<i32>().ok()?;
                        let hi = hi.parse::<i32>().ok()?;
                        (lo > 0 && hi >= lo).then_some(Value::Range { low: lo, high: hi })
                    })
                    .collect();
                if !ranges.is_empty() {
                    job.attributes
                        .push(Attribute::new("page-ranges", tags::RANGE, ranges));
                }
            }
            _ => {}
        }
    }
    if !copies_set && inv.copies > 1 {
        job.attributes.push(Attribute::new(
            "copies",
            tags::INTEGER,
            vec![Value::Integer(inv.copies)],
        ));
    }
    if !job.attributes.is_empty() {
        msg.groups.push(job);
    }
    msg
}

fn find_job_int(msg: &IppMessage, name: &str) -> Option<i32> {
    msg.find(tags::JOB, name)?
        .values
        .first()
        .and_then(|v| match *v {
            Value::Integer(n) | Value::Enum(n) => Some(n),
            _ => None,
        })
}

fn find_job_reasons(msg: &IppMessage) -> Vec<String> {
    msg.find(tags::JOB, "job-state-reasons")
        .map(|a| {
            a.values
                .iter()
                .filter_map(|v| match v {
                    Value::Keyword(t) | Value::Name(t) | Value::Text(t) => {
                        Some(String::from_utf8_lossy(&t.0).into_owned())
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn build_get_job_attributes(target: &Target, job_id: i32, user: &str) -> IppMessage {
    let mut msg = IppMessage::new(ops::op::GET_JOB_ATTRIBUTES);
    let mut op = op_group(&target.printer_uri);
    op.attributes.push(Attribute::new(
        "job-id",
        tags::INTEGER,
        vec![Value::Integer(job_id)],
    ));
    if !user.is_empty() {
        op.attributes.push(Attribute::new(
            "requesting-user-name",
            tags::NAME,
            vec![Value::Name(Text::from(user))],
        ));
    }
    op.attributes.push(Attribute::new(
        "requested-attributes",
        tags::KEYWORD,
        vec![
            Value::Keyword(Text::from("job-state")),
            Value::Keyword(Text::from("job-state-reasons")),
            Value::Keyword(Text::from("job-impressions-completed")),
            Value::Keyword(Text::from("job-media-sheets-completed")),
        ],
    ));
    msg.groups.push(op);
    msg
}

/// Poll `Get-Job-Attributes` until the remote job completes, cancels, aborts,
/// or is permanently held.
fn poll_job(
    target: &Target,
    cfg: &Config,
    remote_job_id: i32,
    user: &str,
    initial_state: Option<i32>,
    initial_pages: u32,
) -> i32 {
    let mut last_pages = initial_pages;
    let mut state = initial_state.unwrap_or(3); // 3 = pending
    let mut polls = 0u32;

    loop {
        match state {
            9 => {
                bc::info(format_args!("ipp: remote job {remote_job_id} completed"));
                return bc::code::OK;
            }
            7 => {
                bc::info(format_args!("ipp: remote job {remote_job_id} canceled"));
                return bc::code::CANCEL;
            }
            8 => {
                bc::error(format_args!("ipp: remote job {remote_job_id} aborted"));
                return bc::code::FAILED;
            }
            _ => {}
        }
        if polls >= cfg.max_polls {
            bc::warn(format_args!(
                "ipp: stopped polling remote job {remote_job_id} after {polls} polls"
            ));
            return bc::code::OK;
        }
        if !cfg.poll_interval.is_zero() {
            std::thread::sleep(cfg.poll_interval);
        }
        polls += 1;

        let req = build_get_job_attributes(target, remote_job_id, user);
        let resp = match ipp_send(target, cfg, &req, BodySource::Empty) {
            Ok(r) => r,
            Err(bc::code::STOP) => {
                // Printer returned 404/Gone during polling — job already purged.
                return bc::code::OK;
            }
            Err(code) => return code,
        };
        if resp.code == ops::status::ERROR_NOT_FOUND {
            // Many IPP printers purge completed jobs immediately.
            bc::info(format_args!(
                "ipp: remote job {remote_job_id} no longer present (assumed completed)"
            ));
            return bc::code::OK;
        }
        if resp.code >= 0x0100 {
            return map_ipp_status(resp.code);
        }

        let completed = find_job_int(&resp, "job-impressions-completed")
            .or_else(|| find_job_int(&resp, "job-media-sheets-completed"))
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0);
        if completed > last_pages {
            for p in (last_pages + 1)..=completed {
                bc::page(p, 1);
            }
            last_pages = completed;
        }

        let reasons = find_job_reasons(&resp);
        for r in &reasons {
            if r != "none" && r != "job-printing" && r != "job-completed-successfully" {
                bc::state(&format!("+{r}"));
            }
        }

        state = find_job_int(&resp, "job-state").unwrap_or(9);
        if state == 4 {
            // pending-held
            if reasons
                .iter()
                .any(|r| r.contains("hold") || r.contains("account") || r.contains("auth"))
            {
                bc::info(format_args!("ipp: remote job {remote_job_id} held"));
                return bc::code::HOLD;
            }
        }
    }
}

fn discover_to(out: &mut impl Write) -> i32 {
    let _ = bc::report_to(
        out,
        "network",
        "ipp",
        "Unknown",
        "Internet Printing Protocol (ipp)",
        None,
    );
    let _ = bc::report_to(
        out,
        "network",
        "ipps",
        "Unknown",
        "Internet Printing Protocol (ipps)",
        None,
    );
    let _ = bc::report_to(
        out,
        "network",
        "http",
        "Unknown",
        "World Wide Web (http)",
        None,
    );
    let _ = bc::report_to(
        out,
        "network",
        "https",
        "Unknown",
        "World Wide Web (https)",
        None,
    );
    bc::code::OK
}

fn print_with_config(inv: &bc::Invocation, cfg: &Config) -> i32 {
    let redacted = bc::redact_uri(&inv.device_uri);
    let Some(target) = parse_uri(&inv.device_uri) else {
        bc::error(format_args!("ipp: bad device-uri {redacted}"));
        return bc::code::FAILED;
    };
    let body = match open_body_source(inv) {
        Ok(b) => b,
        Err(e) => {
            bc::error(format_args!("ipp: open document: {e}"));
            return bc::code::FAILED;
        }
    };

    let msg = build_print_job(&target, inv, cfg);
    let resp = match ipp_send(&target, cfg, &msg, body) {
        Ok(r) => r,
        Err(code) => return code,
    };
    if resp.code >= 0x0100 {
        bc::error(format_args!(
            "ipp: remote Print-Job to {redacted} failed status 0x{:04x} ({})",
            resp.code,
            ops::status::name(resp.code)
        ));
        return map_ipp_status(resp.code);
    }

    bc::info(format_args!(
        "ipp: job {} accepted by {redacted}",
        inv.job_id
    ));
    let remote_job_id = find_job_int(&resp, "job-id");
    let initial_state = find_job_int(&resp, "job-state");
    let initial_pages = find_job_int(&resp, "job-impressions-completed")
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0);
    for p in 1..=initial_pages {
        bc::page(p, 1);
    }

    if target.wait_job {
        if let Some(jid) = remote_job_id {
            return poll_job(&target, cfg, jid, &inv.user, initial_state, initial_pages);
        }
    }
    bc::code::OK
}

fn main() {
    bc::run(
        || discover_to(&mut io::stdout().lock()),
        |inv| print_with_config(&inv, &Config::from_env()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::thread;

    fn test_config() -> Config {
        Config {
            ssrf: SsrfPolicy {
                allow_loopback: true,
            },
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(1),
            max_polls: 10,
            ca_bundle: None,
            content_type: Some("application/pdf".into()),
            final_content_type: Some("application/vnd.cups-raw".into()),
            auth_env: None,
        }
    }

    fn ipp_reply(
        status: u16,
        job_id: Option<i32>,
        job_state: Option<i32>,
        pages: Option<i32>,
        reasons: &[&str],
    ) -> Vec<u8> {
        let mut msg = IppMessage::new(status);
        let mut op = Group::new(tags::OPERATION);
        op.attributes.push(Attribute::new(
            "attributes-charset",
            tags::CHARSET,
            vec![Value::Charset(Text::from("utf-8"))],
        ));
        msg.groups.push(op);
        let mut job = Group::new(tags::JOB);
        if let Some(id) = job_id {
            job.attributes.push(Attribute::new(
                "job-id",
                tags::INTEGER,
                vec![Value::Integer(id)],
            ));
        }
        if let Some(st) = job_state {
            job.attributes.push(Attribute::new(
                "job-state",
                tags::ENUM,
                vec![Value::Enum(st)],
            ));
        }
        if let Some(p) = pages {
            job.attributes.push(Attribute::new(
                "job-impressions-completed",
                tags::INTEGER,
                vec![Value::Integer(p)],
            ));
        }
        if !reasons.is_empty() {
            job.attributes.push(Attribute::new(
                "job-state-reasons",
                tags::KEYWORD,
                reasons
                    .iter()
                    .map(|&r| Value::Keyword(Text::from(r)))
                    .collect(),
            ));
        }
        if !job.attributes.is_empty() {
            msg.groups.push(job);
        }
        ipp_codec::encode(&msg).unwrap()
    }

    fn read_http_request(stream: &mut impl Read) -> (String, Vec<u8>) {
        let mut r = BufReader::new(stream);
        let mut hdrs = String::new();
        let mut content_length = None;
        let mut chunked = false;
        loop {
            let mut line = String::new();
            let n = r.read_line(&mut line).unwrap();
            if n == 0 || line == "\r\n" {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                if k.eq_ignore_ascii_case("content-length") {
                    content_length = v.trim().parse::<usize>().ok();
                } else if k.eq_ignore_ascii_case("transfer-encoding")
                    && v.to_ascii_lowercase().contains("chunked")
                {
                    chunked = true;
                }
            }
            hdrs.push_str(&line);
        }
        let body = if chunked {
            read_chunked_body(&mut r).unwrap()
        } else if let Some(len) = content_length {
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).unwrap();
            b
        } else {
            Vec::new()
        };
        (hdrs, body)
    }

    #[test]
    fn parse_uri_schemes_ipv6_creds_and_rejection() {
        let u1 = parse_uri("http://printer.local/ipp/print").unwrap();
        assert_eq!(u1.port, 80);
        assert!(!u1.tls);
        assert_eq!(u1.printer_uri, "ipp://printer.local:80/ipp/print");

        let u2 = parse_uri("https://printer.local/ipp/print").unwrap();
        assert_eq!(u2.port, 443);
        assert!(u2.tls);
        assert_eq!(u2.printer_uri, "ipps://printer.local:443/ipp/print");

        let u3 = parse_uri("ipp://alice:sec%3Aret@[::1]:631/printers/q?waitjob=false").unwrap();
        assert_eq!(u3.host, "::1");
        assert_eq!(u3.port, 631);
        assert!(!u3.tls);
        assert!(!u3.wait_job);
        assert_eq!(u3.credentials, Some(("alice".into(), "sec:ret".into())));
        assert_eq!(u3.printer_uri, "ipp://[::1]:631/printers/q");

        let u4 = parse_uri("ipps://[2001:db8::1]/ipp/print").unwrap();
        assert_eq!(u4.port, 631);
        assert!(u4.tls);

        assert!(parse_uri("lpd://host/q").is_none());
        assert!(parse_uri("ipp://host/p\r\nEvil: 1").is_none());
        assert!(parse_uri("ipp://host:0/p").is_none());
    }

    #[test]
    fn base64_and_options_and_mime_resolution() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"alice:secret"), "YWxpY2U6c2VjcmV0");

        let opts = parse_options("copies=2 sides=\"two-sided-long-edge\" media='iso_a4_210x297mm' orientation-requested=4 print-quality=5 job-priority=50 number-up=2 page-ranges=1-3,5");
        assert_eq!(opts.len(), 8);

        let cfg = test_config();
        assert_eq!(resolve_document_format(&cfg, &opts), "application/pdf");
        let opts_override = vec![("document-format".into(), "image/pwg-raster".into())];
        assert_eq!(
            resolve_document_format(&cfg, &opts_override),
            "image/pwg-raster"
        );

        let mut cfg2 = test_config();
        cfg2.final_content_type = Some("image/urf".into());
        assert_eq!(resolve_document_format(&cfg2, &[]), "image/urf");

        let mut cfg3 = test_config();
        cfg3.final_content_type = None;
        cfg3.content_type = None;
        assert_eq!(
            resolve_document_format(&cfg3, &[]),
            "application/octet-stream"
        );
        assert!(!is_valid_mime("bad"));
        assert!(!is_valid_mime("a/b/c"));
    }

    #[test]
    fn http_chunked_and_100_continue_response_parsing() {
        let ipp_ok = ipp_reply(ops::status::OK, Some(7), Some(9), Some(1), &[]);
        let mid = ipp_ok.len() / 2;
        let mut wire = Vec::new();
        wire.extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
        wire.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        wire.extend_from_slice(format!("{mid:x};ext=1\r\n").as_bytes());
        wire.extend_from_slice(&ipp_ok[..mid]);
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(format!("{:x}\r\n", ipp_ok.len() - mid).as_bytes());
        wire.extend_from_slice(&ipp_ok[mid..]);
        wire.extend_from_slice(b"\r\n0\r\nX-Trailer: ok\r\n\r\n");

        let mut cur = Cursor::new(wire);
        let (status, body) = read_http_response(&mut cur).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, ipp_ok);

        // Close-delimited fallback.
        let mut cur2 = Cursor::new(b"HTTP/1.1 200 OK\r\n\r\nhello".to_vec());
        let (st2, body2) = read_http_response(&mut cur2).unwrap();
        assert_eq!(st2, 200);
        assert_eq!(body2, b"hello");

        // Error cases: bad status line, invalid CL, conflicting CL, oversized CL, bad chunk hex, bad chunk CRLF.
        for bad in [
            &b"NOTHTTP 200 OK\r\n\r\n"[..],
            &b"HTTP/1.1 abc OK\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\na"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabXX"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"[..],
        ] {
            let mut c = Cursor::new(bad.to_vec());
            assert!(read_http_response(&mut c).is_err());
        }
    }

    #[test]
    fn print_job_file_stream_chunked_reply_and_polling_complete() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let srv = thread::spawn(move || {
            // 1. Print-Job request -> chunked response with job-id=55, state=processing(5).
            let (mut s1, _) = listener.accept().unwrap();
            let (hdrs1, body1) = read_http_request(&mut s1);
            assert!(hdrs1.contains("Authorization: Basic "));
            let (req1, doc_off) = ipp_codec::decode(&body1).unwrap();
            assert_eq!(req1.code, ops::op::PRINT_JOB);
            assert_eq!(&body1[doc_off..], b"%PDF-1.7 test document");
            assert_eq!(
                req1.find(tags::OPERATION, "document-format")
                    .unwrap()
                    .values[0],
                Value::MimeMediaType(Text::from("application/pdf"))
            );
            assert_eq!(
                req1.find(tags::JOB, "copies").unwrap().values[0],
                Value::Integer(2)
            );
            let r1 = ipp_reply(
                ops::status::OK,
                Some(55),
                Some(5),
                Some(0),
                &["job-printing"],
            );
            let resp1 = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
                r1.len()
            );
            s1.write_all(resp1.as_bytes()).unwrap();
            s1.write_all(&r1).unwrap();
            s1.write_all(b"\r\n0\r\n\r\n").unwrap();

            // 2. First poll -> processing with 1 page + media-low reason.
            let (mut s2, _) = listener.accept().unwrap();
            let (_, body2) = read_http_request(&mut s2);
            let (req2, _) = ipp_codec::decode(&body2).unwrap();
            assert_eq!(req2.code, ops::op::GET_JOB_ATTRIBUTES);
            let r2 = ipp_reply(ops::status::OK, Some(55), Some(5), Some(1), &["media-low"]);
            let resp2 = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", r2.len());
            s2.write_all(resp2.as_bytes()).unwrap();
            s2.write_all(&r2).unwrap();

            // 3. Second poll -> completed(9) with 2 pages.
            let (mut s3, _) = listener.accept().unwrap();
            let (_, _) = read_http_request(&mut s3);
            let r3 = ipp_reply(
                ops::status::OK,
                Some(55),
                Some(9),
                Some(2),
                &["job-completed-successfully"],
            );
            let resp3 = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", r3.len());
            s3.write_all(resp3.as_bytes()).unwrap();
            s3.write_all(&r3).unwrap();
        });

        let dir = env::temp_dir().join(format!("pw-ipp-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let doc = dir.join("doc.pdf");
        std::fs::write(&doc, b"%PDF-1.7 test document").unwrap();

        let inv = bc::Invocation {
            job_id: 10,
            user: "alice".into(),
            title: "Invoice".into(),
            copies: 2,
            options:
                "sides=two-sided-long-edge orientation-requested=3 job-priority=50 page-ranges=1-2"
                    .into(),
            file: Some(doc.to_string_lossy().into_owned()),
            device_uri: format!("http://alice:pw@127.0.0.1:{port}/ipp/print"),
        };
        let rc = print_with_config(&inv, &test_config());
        assert_eq!(rc, bc::code::OK);
        srv.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chunked_request_stream_and_terminal_states() {
        // Test streaming BodySource::Stream (chunked HTTP request) directly.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let (hdrs, body) = read_http_request(&mut s);
            assert!(hdrs
                .to_ascii_lowercase()
                .contains("transfer-encoding: chunked"));
            let (req, off) = ipp_codec::decode(&body).unwrap();
            assert_eq!(req.code, ops::op::PRINT_JOB);
            assert_eq!(&body[off..], b"streamed-stdin-bytes");
            let r = ipp_reply(ops::status::OK, Some(99), Some(7), Some(0), &[]);
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", r.len());
            s.write_all(resp.as_bytes()).unwrap();
            s.write_all(&r).unwrap();
        });
        let target = parse_uri(&format!("ipp://127.0.0.1:{port}/ipp/print")).unwrap();
        let inv = bc::Invocation {
            job_id: 1,
            user: "bob".into(),
            title: "t".into(),
            copies: 1,
            options: String::new(),
            file: None,
            device_uri: format!("ipp://127.0.0.1:{port}/ipp/print"),
        };
        let cfg = test_config();
        let msg = build_print_job(&target, &inv, &cfg);
        let cursor = Cursor::new(b"streamed-stdin-bytes".to_vec());
        let resp = ipp_send(&target, &cfg, &msg, BodySource::Stream(Box::new(cursor))).unwrap();
        assert_eq!(resp.code, ops::status::OK);
        let rc = poll_job(
            &target,
            &cfg,
            99,
            "bob",
            find_job_int(&resp, "job-state"),
            0,
        );
        assert_eq!(rc, bc::code::CANCEL);
        srv.join().unwrap();
    }

    #[test]
    fn poll_handles_aborted_held_and_purged_not_found() {
        for (reply, expected) in [
            (
                ipp_reply(ops::status::OK, Some(1), Some(8), None, &["job-aborted"]),
                bc::code::FAILED,
            ),
            (
                ipp_reply(
                    ops::status::OK,
                    Some(1),
                    Some(4),
                    None,
                    &["job-hold-until-specified"],
                ),
                bc::code::HOLD,
            ),
            (
                ipp_reply(ops::status::ERROR_NOT_FOUND, None, None, None, &[]),
                bc::code::OK,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let srv = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                let _ = read_http_request(&mut s);
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", reply.len());
                s.write_all(resp.as_bytes()).unwrap();
                s.write_all(&reply).unwrap();
            });
            let target = parse_uri(&format!("ipp://127.0.0.1:{port}/ipp/print")).unwrap();
            let rc = poll_job(&target, &test_config(), 1, "u", Some(5), 0);
            assert_eq!(rc, expected);
            srv.join().unwrap();
        }
    }

    #[test]
    fn status_mapping_auth_ssrf_and_tls_config() {
        assert_eq!(map_http_status(401), bc::code::AUTH_REQUIRED);
        assert_eq!(map_http_status(404), bc::code::STOP);
        assert_eq!(map_http_status(503), bc::code::RETRY);
        assert_eq!(map_http_status(400), bc::code::FAILED);

        assert_eq!(map_ipp_status(ops::status::OK), bc::code::OK);
        assert_eq!(
            map_ipp_status(ops::status::ERROR_NOT_AUTHENTICATED),
            bc::code::AUTH_REQUIRED
        );
        assert_eq!(
            map_ipp_status(ops::status::ERROR_JOB_CANCELED),
            bc::code::CANCEL
        );
        assert_eq!(map_ipp_status(ops::status::ERROR_DEVICE), bc::code::STOP);
        assert_eq!(
            map_ipp_status(ops::status::ERROR_MULTIPLE_JOBS_NOT_SUPPORTED),
            bc::code::RETRY_CURRENT
        );
        assert_eq!(map_ipp_status(ops::status::ERROR_BUSY), bc::code::RETRY);
        assert_eq!(
            map_ipp_status(ops::status::ERROR_BAD_REQUEST),
            bc::code::FAILED
        );

        // SSRF blocks metadata IP before connecting.
        let dir = env::temp_dir().join(format!("pw-ipp-ssrf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let doc = dir.join("d.txt");
        std::fs::write(&doc, b"hi").unwrap();
        let inv = bc::Invocation {
            job_id: 1,
            user: "u".into(),
            title: "t".into(),
            copies: 1,
            options: String::new(),
            file: Some(doc.to_string_lossy().into_owned()),
            device_uri: "ipp://169.254.169.254/latest/meta-data".into(),
        };
        assert_eq!(print_with_config(&inv, &test_config()), bc::code::FAILED);

        // Bad URI fails cleanly.
        let inv_bad = bc::Invocation {
            device_uri: "ftp://host/x".into(),
            ..inv.clone()
        };
        assert_eq!(
            print_with_config(&inv_bad, &test_config()),
            bc::code::FAILED
        );

        // Missing file fails cleanly.
        let inv_nf = bc::Invocation {
            device_uri: "ipp://127.0.0.1:631/ipp/print".into(),
            file: Some(dir.join("missing").to_string_lossy().into_owned()),
            ..inv
        };
        assert_eq!(print_with_config(&inv_nf, &test_config()), bc::code::FAILED);

        // HTTP 401 returns AUTH_REQUIRED end-to-end.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = read_http_request(&mut s);
            s.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let inv_401 = bc::Invocation {
            job_id: 2,
            user: "u".into(),
            title: "t".into(),
            copies: 1,
            options: String::new(),
            file: Some(doc.to_string_lossy().into_owned()),
            device_uri: format!("ipp://127.0.0.1:{port}/ipp/print?waitjob=false"),
        };
        assert_eq!(
            print_with_config(&inv_401, &test_config()),
            bc::code::AUTH_REQUIRED
        );
        srv.join().unwrap();

        // TLS config loads system roots + handles missing and present CA bundle path.
        let _ = tls_config(None);
        let _ = tls_config(Some(&dir.join("nonexistent.pem")));
        let empty_pem = dir.join("empty.pem");
        std::fs::write(&empty_pem, b"").unwrap();
        let _ = tls_config(Some(&empty_pem));

        // Discovery emits all 4 schemes.
        let mut out = Vec::new();
        assert_eq!(discover_to(&mut out), bc::code::OK);
        let txt = String::from_utf8(out).unwrap();
        assert!(txt.contains("network ipp "));
        assert!(txt.contains("network ipps "));
        assert!(txt.contains("network http "));
        assert!(txt.contains("network https "));

        let _ = Config::from_env();
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct FailIo;
    impl Read for FailIo {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read boom"))
        }
    }
    impl Write for FailIo {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "write boom"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn ipp_edge_cases_tls_handshake_limits_and_poll_errors() {
        let dir = env::temp_dir().join(format!("pw-ipp-edge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let doc = dir.join("doc.txt");
        std::fs::write(&doc, b"hello").unwrap();

        // 1. write_chunk empty slice no-op & write/read error paths.
        let mut sink = Vec::new();
        assert_eq!(write_chunk(&mut sink, &[]), Ok(()));
        assert_eq!(write_chunk(&mut FailIo, b"x"), Err(bc::code::RETRY_CURRENT));
        let mut truncated = Cursor::new(b"ab".to_vec());
        assert_eq!(
            stream_exact_to_writer(&mut truncated, &mut sink, 10),
            Err(bc::code::FAILED)
        );
        let mut ok_src = Cursor::new(b"ab".to_vec());
        assert_eq!(
            stream_exact_to_writer(&mut ok_src, &mut FailIo, 2),
            Err(bc::code::RETRY_CURRENT)
        );
        assert_eq!(
            stream_exact_to_writer(&mut FailIo, &mut sink, 2),
            Err(bc::code::FAILED)
        );
        let _ = FailIo.flush();

        // 2. HTTP response bounds: empty EOF, header limit, too many trailers, oversized chunk.
        assert_eq!(
            read_http_response(&mut Cursor::new(Vec::new())),
            Err(bc::code::RETRY)
        );
        let giant_hdr = format!(
            "HTTP/1.1 200 OK\r\nX-Big: {}\r\n\r\n",
            "a".repeat(MAX_HEADER_BYTES + 10)
        );
        assert_eq!(
            read_http_response(&mut Cursor::new(giant_hdr.into_bytes())),
            Err(bc::code::FAILED)
        );
        let mut many_trailers =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
        for i in 0..=MAX_TRAILER_LINES + 2 {
            many_trailers.extend_from_slice(format!("X-T{i}: v\r\n").as_bytes());
        }
        many_trailers.extend_from_slice(b"\r\n");
        assert_eq!(
            read_http_response(&mut Cursor::new(many_trailers)),
            Err(bc::code::FAILED)
        );
        let huge_chunk = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            MAX_BODY_BYTES + 1
        );
        assert_eq!(
            read_http_response(&mut Cursor::new(huge_chunk.into_bytes())),
            Err(bc::code::FAILED)
        );
        // Oversized close-delimited body & read errors in exact/eof readers.
        let mut oversized_eof = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        oversized_eof.resize(oversized_eof.len() + MAX_BODY_BYTES + 16, b'x');
        assert_eq!(
            read_http_response(&mut Cursor::new(oversized_eof)),
            Err(bc::code::FAILED)
        );
        assert_eq!(read_exact_bounded(&mut FailIo, 4), Err(bc::code::RETRY));
        assert_eq!(read_to_eof_bounded(&mut FailIo), Err(bc::code::RETRY));

        // http_round_trip write/read error paths for Empty, File, and Stream bodies.
        let tgt = parse_uri("ipp://127.0.0.1:631/ipp/print?waitjob=maybe").unwrap();
        assert!(tgt.wait_job);
        assert_eq!(
            http_round_trip(&mut FailIo, &tgt, None, b"ipp", BodySource::Empty),
            Err(bc::code::RETRY_CURRENT)
        );
        let f_err = File::open(&doc).unwrap();
        assert_eq!(
            http_round_trip(&mut FailIo, &tgt, None, b"ipp", BodySource::File(f_err, 5)),
            Err(bc::code::RETRY_CURRENT)
        );
        let cur_s = Cursor::new(b"abc".to_vec());
        assert_eq!(
            http_round_trip(
                &mut FailIo,
                &tgt,
                None,
                b"ipp",
                BodySource::Stream(Box::new(cur_s))
            ),
            Err(bc::code::RETRY_CURRENT)
        );
        let mut sink_rw = Cursor::new(Vec::<u8>::new());
        assert_eq!(
            http_round_trip(
                &mut sink_rw,
                &tgt,
                None,
                b"ipp",
                BodySource::Stream(Box::new(FailIo))
            ),
            Err(bc::code::FAILED)
        );

        // open_body_source for stdin (None) and non-regular file (/dev/null).
        let inv_stdin = bc::Invocation {
            job_id: 1,
            user: "u".into(),
            title: "t".into(),
            copies: 1,
            options: String::new(),
            file: None,
            device_uri: "ipp://127.0.0.1/ipp".into(),
        };
        assert!(open_body_source(&inv_stdin).is_ok());
        let inv_devnull = bc::Invocation {
            file: Some("/dev/null".into()),
            ..inv_stdin
        };
        assert!(open_body_source(&inv_devnull).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ipp_tls_handshake_poll_errors_and_ca_bundle() {
        let dir = env::temp_dir().join(format!("pw-ipp-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let doc = dir.join("doc.txt");
        std::fs::write(&doc, b"hello").unwrap();

        // 3. TLS path against non-TLS TCP listener returns clean error (covers TLS branch),
        //    and closed TCP port returns RETRY.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = thread::spawn(move || {
            // 1st conn: abrupt close during TLS handshake
            let (mut s1, _) = listener.accept().unwrap();
            let _ = s1.write_all(b"not-tls");
            drop(s1);
            // 2nd conn: invalid IPP payload bytes -> FAILED
            let (mut s2, _) = listener.accept().unwrap();
            let _ = read_http_request(&mut s2);
            s2.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbad")
                .unwrap();
            // 3rd conn: Print-Job returns ERROR_BUSY -> RETRY
            let (mut s3, _) = listener.accept().unwrap();
            let _ = read_http_request(&mut s3);
            let busy = ipp_reply(ops::status::ERROR_BUSY, None, None, None, &[]);
            s3.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", busy.len()).as_bytes(),
            )
            .unwrap();
            s3.write_all(&busy).unwrap();
            // 4th conn: Print-Job returns completed with 2 initial pages + waitjob=false -> OK
            let (mut s4, _) = listener.accept().unwrap();
            let _ = read_http_request(&mut s4);
            let ok = ipp_reply(ops::status::OK, Some(8), Some(5), Some(2), &[]);
            s4.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", ok.len()).as_bytes(),
            )
            .unwrap();
            s4.write_all(&ok).unwrap();
            // 5th conn: poll returns 404 -> STOP mapped to OK (purged)
            let (mut s5, _) = listener.accept().unwrap();
            let _ = read_http_request(&mut s5);
            s5.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            // 6th conn: poll returns ERROR_INTERNAL -> FAILED
            let (mut s6, _) = listener.accept().unwrap();
            let _ = read_http_request(&mut s6);
            let ie = ipp_reply(ops::status::ERROR_INTERNAL, None, None, None, &[]);
            s6.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", ie.len()).as_bytes(),
            )
            .unwrap();
            s6.write_all(&ie).unwrap();
        });

        let inv_tls = bc::Invocation {
            job_id: 1,
            user: "u".into(),
            title: "t".into(),
            copies: 1,
            options: "copies=3 print-color-mode=color number-up=2".into(),
            file: Some(doc.to_string_lossy().into_owned()),
            device_uri: format!("ipps://127.0.0.1:{port}/ipp/print"),
        };
        let cfg = test_config();
        assert_ne!(print_with_config(&inv_tls, &cfg), bc::code::OK);

        let inv_bad_ipp = bc::Invocation {
            device_uri: format!("ipp://127.0.0.1:{port}/ipp/print"),
            ..inv_tls.clone()
        };
        assert_eq!(print_with_config(&inv_bad_ipp, &cfg), bc::code::FAILED);
        assert_eq!(print_with_config(&inv_bad_ipp, &cfg), bc::code::RETRY);

        let inv_nowait = bc::Invocation {
            device_uri: format!("ipp://127.0.0.1:{port}/ipp/print?waitjob=false"),
            ..inv_tls
        };
        assert_eq!(print_with_config(&inv_nowait, &cfg), bc::code::OK);

        let t_poll = parse_uri(&format!("ipp://127.0.0.1:{port}/ipp/print")).unwrap();
        // 404 during poll -> OK (job purged).
        assert_eq!(poll_job(&t_poll, &cfg, 8, "u", Some(5), 0), bc::code::OK);
        // IPP internal error during poll -> FAILED.
        assert_eq!(
            poll_job(&t_poll, &cfg, 8, "u", Some(5), 0),
            bc::code::FAILED
        );
        // max_polls = 0 returns OK immediately without hitting network.
        let mut cfg_zero = test_config();
        cfg_zero.max_polls = 0;
        assert_eq!(
            poll_job(&t_poll, &cfg_zero, 8, "u", Some(5), 0),
            bc::code::OK
        );

        srv.join().unwrap();

        // Closed port -> RETRY.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        let inv_closed = bc::Invocation {
            job_id: 9,
            user: "u".into(),
            title: "t".into(),
            copies: 1,
            options: String::new(),
            file: Some(doc.to_string_lossy().into_owned()),
            device_uri: format!("ipp://127.0.0.1:{closed_port}/ipp/print"),
        };
        assert_eq!(print_with_config(&inv_closed, &cfg), bc::code::RETRY);

        // Load a real PEM certificate into tls_config (using cups_tls self-signed cert in temp dir).
        let ssl_dir = dir.join("ssl");
        if cups_tls::load_or_create(&ssl_dir, "localhost").is_ok() {
            let _ = tls_config(Some(&ssl_dir.join("server.crt")));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
