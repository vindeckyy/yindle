//! Connection serving — hardened HTTP/1.1 keep-alive request loop.
//!
//! Port of the `client.c`/`httpState` loop with defense against HTTP request
//! smuggling, Slowloris header/body `DoS`, DNS rebinding, response splitting,
//! and large-body OOM via streaming disk spooling.

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf as TokioReadBuf};
use tokio::time::Instant;

use crate::headers::{is_valid_header_name, is_valid_header_value};
use crate::request::{Body, HttpVersion, Method, Request, SpooledBody};
use crate::response::{Response, StatusCode};
use crate::{
    Headers, DEFAULT_MAX_BODY, DEFAULT_SPOOL_THRESHOLD, MAX_HEADER_BLOCK, MAX_TRAILER_BYTES,
    MAX_TRAILER_LINES,
};

/// Default total deadline to receive the complete HTTP header block (30s).
pub const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// Default total deadline to receive a request body (300s).
pub const DEFAULT_BODY_TIMEOUT: Duration = Duration::from_secs(300);
/// Default deadline to write a response to the peer (30s).
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Default keep-alive idle timeout between pipelined/persistent requests (30s).
pub const DEFAULT_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(30);

const MAX_CHUNK_LINE_LEN: usize = 64;
const STREAM_CHUNK_SIZE: usize = 16 * 1024;

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

/// Error class for connection failures.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// Client disconnected (EOF or reset) — normal termination.
    #[error("peer disconnected")]
    Disconnect,
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// Malformed request (a 400/431 was emitted before closing).
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    /// Request body exceeded configured `max_body` (413 was emitted before closing).
    #[error("payload too large")]
    PayloadTooLarge,
    /// Request header block exceeded [`MAX_HEADER_BLOCK`] (431 was emitted before closing).
    #[error("header block too large")]
    HeaderTooLarge,
    /// Header, body, or write deadline expired (408 emitted when appropriate before closing).
    #[error("timeout: {0}")]
    Timeout(&'static str),
}

/// Normal termination outcome of [`serve_connection_with_config`].
#[derive(Debug, PartialEq, Eq)]
pub enum ConnectionOutcome {
    /// Connection closed normally (EOF, `Connection: close`, or `KeepAlive Off`).
    Closed,
    /// Client requested RFC 2817 TLS upgrade and `101 Switching Protocols` was written.
    ///
    /// `leftover` holds any bytes already read ahead from the underlying transport;
    /// wrap the transport in [`PrefixedStream::new(leftover, stream)`] before calling
    /// `TlsAcceptor::accept`.
    UpgradeTls {
        /// Unread bytes that arrived after the `OPTIONS *` upgrade headers.
        leftover: Vec<u8>,
    },
}

/// Stream wrapper that yields preserved read-ahead bytes before reading from `inner`.
///
/// Used after [`ConnectionOutcome::UpgradeTls`] so RFC 2817 TLS handshakes never
/// drop pipelined `ClientHello` bytes that were buffered alongside the HTTP headers.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    /// Wrap `inner` so `prefix` bytes are read first.
    #[must_use]
    pub const fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }

    /// Remaining unconsumed prefix bytes.
    #[must_use]
    pub fn remaining_prefix(&self) -> &[u8] {
        &self.prefix[self.pos..]
    }

    /// Unwrap and return the underlying stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut TokioReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let rem = &self.prefix[self.pos..];
            let n = rem.len().min(buf.remaining());
            buf.put_slice(&rem[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Validates HTTP `Host` headers against `ServerName` / `ServerAlias` to defend
/// against DNS rebinding attacks (CVE-2018-4180 / CUPS `cupsdCheckHost`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostValidator {
    /// Configured `ServerName` (e.g. `"print.example.com"`).
    pub server_name: Option<String>,
    /// Configured `ServerAlias` patterns (exact host, `"*"`, or `"*.domain.tld"`).
    pub server_aliases: Vec<String>,
    /// Allow loopback literals (`localhost`, `localhost.localdomain`, `127.0.0.1`, `::1`).
    pub allow_loopback: bool,
}

impl HostValidator {
    /// Construct a validator allowing loopback + `server_name` + `server_aliases`.
    #[must_use]
    pub fn new(server_name: Option<String>, server_aliases: Vec<String>) -> Self {
        Self {
            server_name,
            server_aliases,
            allow_loopback: true,
        }
    }

    /// Returns `true` if `host_header` is syntactically valid and authorized.
    #[must_use]
    pub fn is_allowed(&self, host_header: &str) -> bool {
        let Some(host) = parse_host_header(host_header) else {
            return false;
        };
        if self.allow_loopback && is_loopback_host(&host) {
            return true;
        }
        if let Some(sn) = &self.server_name {
            if host_pattern_matches(sn, &host) {
                return true;
            }
        }
        self.server_aliases
            .iter()
            .any(|alias| host_pattern_matches(alias, &host))
    }
}

/// Standalone `Host` header validator against `ServerName` and `ServerAlias`
/// (always allows loopback hosts `localhost`, `127.0.0.1`, `[::1]`).
#[must_use]
pub fn validate_host(
    host_header: &str,
    server_name: Option<&str>,
    server_aliases: &[String],
) -> bool {
    let validator = HostValidator::new(server_name.map(str::to_string), server_aliases.to_vec());
    validator.is_allowed(host_header)
}

/// Parse an HTTP `Host` header value into its normalized lowercase host (without port).
fn parse_host_header(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty()
        || s.bytes()
            .any(|b| b <= 0x20 || b == 0x7f || matches!(b, b'@' | b'/' | b'\\' | b'?' | b'#'))
    {
        return None;
    }
    if let Some(rest) = s.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:631`
        let (addr, after) = rest.split_once(']')?;
        if addr.is_empty() || addr.parse::<std::net::Ipv6Addr>().is_err() {
            return None;
        }
        if !after.is_empty() {
            let port_str = after.strip_prefix(':')?;
            if port_str.is_empty()
                || !port_str.bytes().all(|b| b.is_ascii_digit())
                || port_str.parse::<u16>().is_err()
            {
                return None;
            }
        }
        return Some(addr.to_ascii_lowercase());
    }
    let host_part = match s.rsplit_once(':') {
        Some((h, port_str)) => {
            if h.contains(':')
                || port_str.is_empty()
                || !port_str.bytes().all(|b| b.is_ascii_digit())
                || port_str.parse::<u16>().is_err()
            {
                return None;
            }
            h
        }
        None => s,
    };
    let clean = host_part.trim_end_matches('.');
    if clean.is_empty()
        || !clean
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return None;
    }
    Some(clean.to_ascii_lowercase())
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("localhost.localdomain")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    let pat = pattern.trim().trim_end_matches('.');
    if pat.is_empty() {
        return false;
    }
    if pat == "*" {
        return true;
    }
    if let Some(suffix) = pat.strip_prefix("*.") {
        let suffix_lower = suffix.to_ascii_lowercase();
        let dot_suffix = format!(".{suffix_lower}");
        return host.ends_with(&dot_suffix) && host.len() > dot_suffix.len();
    }
    host.eq_ignore_ascii_case(pat)
}

/// Legacy options struct controlling [`serve_connection`] (preserved for
/// backward compatibility with existing callers).
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// `ServerTokens` string (upstream `ServerTokens` directive).
    pub server_tokens: String,
    /// `MaxRequestSize` (0 defaults to [`DEFAULT_MAX_BODY`] = 64 MiB for safety).
    pub max_body: usize,
    /// `Timeout` — idle-connection seconds (upstream `Timeout`/300).
    pub idle_timeout: Duration,
    /// Legacy cap on malformed requests (connections now close on the first framing error).
    pub max_bad_requests: u32,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            server_tokens: "CUPS/2.5 (yindle)".into(),
            max_body: DEFAULT_MAX_BODY,
            idle_timeout: Duration::from_secs(300),
            max_bad_requests: 1,
        }
    }
}

/// Full hardened server configuration for [`serve_connection_with_config`].
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// `ServerTokens` header value.
    pub server_tokens: String,
    /// Maximum request body bytes (`None` = unlimited, recommended only with spooling).
    pub max_body: Option<usize>,
    /// Bodies larger than this stream to a `0600` temporary spool file on disk
    /// (`None` keeps all bodies up to `max_body` in RAM).
    pub spool_threshold: Option<usize>,
    /// Directory for spooled body temp files (defaults to `std::env::temp_dir()`).
    pub spool_dir: Option<PathBuf>,
    /// Idle wait timeout before the first request arrives.
    pub idle_timeout: Duration,
    /// `KeepAlive On/Off`.
    pub keep_alive: bool,
    /// `KeepAliveTimeout` between persistent requests on the same connection.
    pub keep_alive_timeout: Duration,
    /// Total deadline to finish receiving a request's header block (defeats Slowloris).
    pub header_timeout: Duration,
    /// Total deadline to finish receiving a request body.
    pub body_timeout: Duration,
    /// Deadline to write and flush an HTTP response.
    pub write_timeout: Duration,
    /// Optional `Host` header allowlist (`ServerName` / `ServerAlias`) against DNS rebinding.
    pub host_validator: Option<HostValidator>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server_tokens: "CUPS/2.5 (yindle)".into(),
            max_body: Some(DEFAULT_MAX_BODY),
            spool_threshold: Some(DEFAULT_SPOOL_THRESHOLD),
            spool_dir: None,
            idle_timeout: Duration::from_secs(300),
            keep_alive: true,
            keep_alive_timeout: DEFAULT_KEEP_ALIVE_TIMEOUT,
            header_timeout: DEFAULT_HEADER_TIMEOUT,
            body_timeout: DEFAULT_BODY_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            host_validator: None,
        }
    }
}

impl From<&ServerOptions> for ServerConfig {
    fn from(opts: &ServerOptions) -> Self {
        let effective_max = if opts.max_body == 0 {
            DEFAULT_MAX_BODY
        } else {
            opts.max_body
        };
        Self {
            server_tokens: opts.server_tokens.clone(),
            max_body: Some(effective_max),
            // Legacy `serve_connection` callers read `req.body.as_bytes()`,
            // so keep bodies in RAM up to `effective_max` unless ServerConfig is used.
            spool_threshold: None,
            spool_dir: None,
            idle_timeout: opts.idle_timeout,
            keep_alive: true,
            keep_alive_timeout: opts.idle_timeout.min(DEFAULT_KEEP_ALIVE_TIMEOUT),
            header_timeout: DEFAULT_HEADER_TIMEOUT
                .min(opts.idle_timeout.max(Duration::from_secs(1))),
            body_timeout: DEFAULT_BODY_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            host_validator: None,
        }
    }
}

/// Cursor-backed read buffer eliminating O(N²) `Vec::remove(0)` front-shifts
/// and keeping async future frames small (reusable heap scratch buffer).
struct ReadBuf {
    data: Vec<u8>,
    pos: usize,
    scratch: Vec<u8>,
}

impl ReadBuf {
    fn with_capacity(cap: usize) -> Self {
        Self {
            data: Vec::with_capacity(cap),
            pos: 0,
            scratch: vec![0u8; STREAM_CHUNK_SIZE],
        }
    }

    fn from_vec(data: Vec<u8>) -> Self {
        Self {
            data,
            pos: 0,
            scratch: vec![0u8; STREAM_CHUNK_SIZE],
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.data[self.pos..]
    }

    fn len(&self) -> usize {
        self.data.len() - self.pos
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn extend_from_scratch(&mut self, n: usize) {
        self.compact_if_needed();
        self.data.extend_from_slice(&self.scratch[..n]);
    }

    fn consume(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.data.len());
        if self.pos == self.data.len() {
            self.data.clear();
            self.pos = 0;
        } else if self.pos >= 4096 {
            self.data.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn compact_if_needed(&mut self) {
        if self.pos > 0 && self.pos >= self.data.len() / 2 {
            self.data.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn into_remaining(mut self) -> Vec<u8> {
        if self.pos > 0 {
            self.data.drain(..self.pos);
        }
        self.data
    }
}

/// Serve one connection until close using legacy [`ServerOptions`].
///
/// Backward-compatible wrapper around [`serve_connection_with_config`]: on RFC 2817
/// `101 Switching Protocols`, returns `Err(ServeError::Disconnect)`. New callers
/// needing read-ahead buffer handoff or disk spooling should call
/// [`serve_connection_with_config`].
pub async fn serve_connection<S>(
    stream: &mut S,
    opts: &ServerOptions,
    handler: impl FnMut(Request) -> Response + Send,
) -> Result<(), ServeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let cfg = ServerConfig::from(opts);
    match serve_connection_with_config(stream, &cfg, handler).await? {
        ConnectionOutcome::Closed => Ok(()),
        ConnectionOutcome::UpgradeTls { .. } => Err(ServeError::Disconnect),
    }
}

/// Serve one connection with full [`ServerConfig`] hardening (timeouts,
/// anti-smuggling, `KeepAlive`, `Host` validation, disk spooling, and
/// RFC 2817 leftover buffer handoff).
pub async fn serve_connection_with_config<S>(
    stream: &mut S,
    cfg: &ServerConfig,
    mut handler: impl FnMut(Request) -> Response + Send,
) -> Result<ConnectionOutcome, ServeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = ReadBuf::with_capacity(16 * 1024);
    let mut req_count = 0u64;

    loop {
        let wait_timeout = if req_count == 0 {
            cfg.idle_timeout
        } else {
            cfg.keep_alive_timeout
        };
        let mut req = match read_request(stream, &mut buf, wait_timeout, cfg.header_timeout).await {
            Ok(Some(req)) => req,
            Ok(None) => return Ok(ConnectionOutcome::Closed),
            Err(e @ (ServeError::Disconnect | ServeError::Io(_))) => return Err(e),
            Err(e @ ServeError::HeaderTooLarge) => {
                let resp = Response::status(StatusCode::HEADER_FIELDS_TOO_LARGE);
                let _ = write_response(stream, &resp, false, false, cfg.write_timeout).await;
                return Err(e);
            }
            Err(e @ ServeError::Timeout(_)) => {
                let resp = Response::status(StatusCode::REQUEST_TIMEOUT);
                let _ = write_response(stream, &resp, false, false, cfg.write_timeout).await;
                return Err(e);
            }
            Err(e) => {
                let resp = Response::status(StatusCode::BAD_REQUEST);
                let _ = write_response(stream, &resp, false, false, cfg.write_timeout).await;
                return Err(e);
            }
        };
        req_count += 1;

        if req.version == HttpVersion::Other {
            let resp = Response::status(StatusCode::VERSION_NOT_SUPPORTED);
            let _ = write_response(stream, &resp, false, false, cfg.write_timeout).await;
            return Ok(ConnectionOutcome::Closed);
        }

        // Strict Host enforcement on HTTP/1.1 + optional DNS-rebinding check.
        if let Err(e) = validate_request_host(&req, cfg.host_validator.as_ref()) {
            let resp = Response::status(StatusCode::BAD_REQUEST);
            let _ = write_response(stream, &resp, false, false, cfg.write_timeout).await;
            return Err(e);
        }

        // Strict framing validation + body read/spool (closes on any framing/size/timeout error).
        if let Err(e) = read_body_with_config(stream, &mut buf, &mut req, cfg).await {
            let status = match e {
                ServeError::PayloadTooLarge => StatusCode::TOO_LARGE,
                ServeError::Timeout(_) => StatusCode::REQUEST_TIMEOUT,
                ServeError::Disconnect | ServeError::Io(_) => return Err(e),
                _ => StatusCode::BAD_REQUEST,
            };
            let resp = Response::status(status);
            let _ = write_response(stream, &resp, false, false, cfg.write_timeout).await;
            return Err(e);
        }

        let head_only = req.method == Method::Head;
        let client_keep = req.keep_alive && cfg.keep_alive;
        let mut resp = handler(req);
        resp.headers.set("Server", cfg.server_tokens.clone());

        if resp.status == StatusCode::SWITCHING_PROTOCOLS {
            // RFC 2817: ensure Upgrade headers are emitted and hand back leftover bytes.
            if !resp.headers.connection_has("upgrade") {
                resp.headers.set("Connection", "Upgrade");
            }
            if !resp.headers.contains("upgrade") {
                resp.headers.set("Upgrade", "TLS/1.2");
            }
            write_response(stream, &resp, false, true, cfg.write_timeout).await?;
            return Ok(ConnectionOutcome::UpgradeTls {
                leftover: buf.into_remaining(),
            });
        }

        let keep = client_keep && !resp.headers.connection_has("close");
        write_response(stream, &resp, head_only, keep, cfg.write_timeout).await?;
        if !keep {
            return Ok(ConnectionOutcome::Closed);
        }
    }
}

fn validate_request_host(
    req: &Request,
    validator: Option<&HostValidator>,
) -> Result<(), ServeError> {
    let host_count = req.headers.count("host");
    if host_count > 1 {
        return Err(ServeError::BadRequest("duplicate Host header"));
    }
    if req.version == HttpVersion::V11 && host_count == 0 {
        return Err(ServeError::BadRequest("missing Host header"));
    }
    if let Some(host_val) = req.headers.get("host") {
        if parse_host_header(host_val).is_none() {
            return Err(ServeError::BadRequest("malformed Host header"));
        }
        if let Some(v) = validator {
            if !v.is_allowed(host_val) {
                return Err(ServeError::BadRequest("disallowed Host header"));
            }
        }
    }
    Ok(())
}

/// Read one request line + headers enforcing strict `\r\n\r\n` framing and
/// total `header_timeout` (Slowloris defense).
async fn read_request<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut ReadBuf,
    idle_timeout: Duration,
    header_timeout: Duration,
) -> Result<Option<Request>, ServeError> {
    // Wait for the very first byte using idle_timeout; clean EOF returns Ok(None).
    if buf.is_empty() {
        match tokio::time::timeout(idle_timeout, r.read(&mut buf.scratch)).await {
            Ok(Ok(0)) => return Ok(None),
            Ok(Ok(n)) => buf.extend_from_scratch(n),
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(ServeError::Disconnect);
            }
            Ok(Err(e)) => return Err(ServeError::Io(e)),
            Err(_) => return Err(ServeError::Disconnect),
        }
    }

    // Once any byte of a request exists, enforce a hard overall header deadline.
    let deadline = Instant::now() + header_timeout;
    let header_end = loop {
        if let Some(pos) = find_header_end(buf.as_slice()) {
            if pos > MAX_HEADER_BLOCK {
                return Err(ServeError::HeaderTooLarge);
            }
            break pos;
        }
        if buf.len() > MAX_HEADER_BLOCK {
            return Err(ServeError::HeaderTooLarge);
        }
        match tokio::time::timeout_at(deadline, r.read(&mut buf.scratch)).await {
            Ok(Ok(0)) => return Err(ServeError::Disconnect),
            Ok(Ok(n)) => buf.extend_from_scratch(n),
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(ServeError::Disconnect);
            }
            Ok(Err(e)) => return Err(ServeError::Io(e)),
            Err(_) => return Err(ServeError::Timeout("header read deadline exceeded")),
        }
    };

    let head = std::str::from_utf8(&buf.as_slice()[..header_end])
        .map_err(|_| ServeError::BadRequest("non-UTF-8 header block"))?
        .to_string();
    buf.consume(header_end + 4); // strict \r\n\r\n

    parse_request_head(&head).map(Some)
}

fn parse_request_head(head: &str) -> Result<Request, ServeError> {
    let mut lines = head.split("\r\n");
    let reqline = lines
        .next()
        .ok_or(ServeError::BadRequest("empty request line"))?;
    if reqline.contains('\r') || reqline.contains('\n') {
        return Err(ServeError::BadRequest("bare CR/LF in request line"));
    }

    let parts: Vec<&str> = reqline.split(' ').collect();
    let (method_tok, uri, version) = match parts.as_slice() {
        [m, u, v] => {
            let ver = match *v {
                "HTTP/1.0" => HttpVersion::V10,
                "HTTP/1.1" => HttpVersion::V11,
                other => {
                    if is_http_version_syntax(other) {
                        HttpVersion::Other
                    } else {
                        return Err(ServeError::BadRequest("malformed HTTP version"));
                    }
                }
            };
            (*m, *u, ver)
        }
        [m, u] => (*m, *u, HttpVersion::V09),
        _ => return Err(ServeError::BadRequest("malformed request line")),
    };

    if !is_valid_header_name(method_tok)
        || uri.is_empty()
        || uri.bytes().any(|b| b <= 0x20 || b == 0x7f)
    {
        return Err(ServeError::BadRequest("invalid method or URI"));
    }

    let method = Method::parse(method_tok);
    let mut headers = Headers::new();
    for line in lines {
        if line.is_empty() {
            return Err(ServeError::BadRequest("unexpected empty line in headers"));
        }
        if line.contains('\r') || line.contains('\n') {
            return Err(ServeError::BadRequest("bare CR/LF in header line"));
        }
        // Reject obs-fold continuation lines (RFC 9112 §5.2).
        if line.starts_with([' ', '\t']) {
            return Err(ServeError::BadRequest(
                "obs-fold header continuation rejected",
            ));
        }
        let Some((name, raw_val)) = line.split_once(':') else {
            return Err(ServeError::BadRequest("malformed header line"));
        };
        // Reject whitespace before `:` and any non-token header name (smuggling defense).
        if !is_valid_header_name(name) {
            return Err(ServeError::BadRequest("invalid header name"));
        }
        let val = raw_val.trim_matches([' ', '\t']);
        if !is_valid_header_value(val) {
            return Err(ServeError::BadRequest("invalid header value"));
        }
        headers.push(name, val);
    }

    if version == HttpVersion::V09 && headers.iter().next().is_some() {
        return Err(ServeError::BadRequest("headers not allowed on HTTP/0.9"));
    }

    let keep_alive = match version {
        HttpVersion::V11 => !headers.connection_has("close"),
        HttpVersion::V10 => {
            headers.connection_has("keep-alive") && !headers.connection_has("close")
        }
        _ => false,
    };

    let wants_tls_upgrade = method == Method::Options
        && uri == "*"
        && headers.get("upgrade").is_some_and(|v| {
            v.split(',')
                .any(|tok| tok.trim().to_ascii_lowercase().starts_with("tls/"))
        });

    Ok(Request {
        method,
        method_token: method_tok.to_string(),
        uri: uri.to_string(),
        version,
        headers,
        body: Body::Empty,
        keep_alive,
        wants_tls_upgrade,
    })
}

fn is_http_version_syntax(v: &str) -> bool {
    let Some(rest) = v.strip_prefix("HTTP/") else {
        return false;
    };
    let bytes = rest.as_bytes();
    bytes.len() == 3 && bytes[0].is_ascii_digit() && bytes[1] == b'.' && bytes[2].is_ascii_digit()
}

/// Strictly locate `\r\n\r\n` (rejects bare `\n\n` to prevent request smuggling).
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    None,
    ContentLength(usize),
    Chunked,
    UntilEof,
}

/// Validate `Transfer-Encoding` and `Content-Length` strictly per RFC 9112 §6.3.
fn validate_body_framing(req: &Request) -> Result<BodyFraming, ServeError> {
    let te_count = req.headers.count("transfer-encoding");
    let cl_count = req.headers.count("content-length");

    // Smuggling defense: NEVER allow both Transfer-Encoding and Content-Length.
    if te_count > 0 && cl_count > 0 {
        return Err(ServeError::BadRequest(
            "conflicting Transfer-Encoding and Content-Length",
        ));
    }

    if te_count > 0 {
        let mut codings = Vec::new();
        for raw in req.headers.get_all("transfer-encoding") {
            for part in raw.split(',') {
                let t = part.trim();
                if !t.is_empty() {
                    codings.push(t);
                }
            }
        }
        // Only accept a single clean `chunked` transfer coding.
        if codings.len() == 1 && codings[0].eq_ignore_ascii_case("chunked") {
            return Ok(BodyFraming::Chunked);
        }
        return Err(ServeError::BadRequest("unsupported Transfer-Encoding"));
    }

    if cl_count > 1 {
        return Err(ServeError::BadRequest("duplicate Content-Length"));
    }

    if let Some(raw_cl) = req.headers.get("content-length") {
        if raw_cl.is_empty() || !raw_cl.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ServeError::BadRequest("malformed Content-Length"));
        }
        let len = raw_cl
            .parse::<usize>()
            .map_err(|_| ServeError::BadRequest("Content-Length overflow"))?;
        return Ok(BodyFraming::ContentLength(len));
    }

    // Legacy close-delimited body only when Content-Type is present on POST/PUT with Connection: close.
    if matches!(req.method, Method::Post | Method::Put)
        && req.headers.get("content-type").is_some()
        && !req.keep_alive
    {
        return Ok(BodyFraming::UntilEof);
    }

    Ok(BodyFraming::None)
}

/// Public backward-compatible helper to read and frame a request body.
///
/// Enforces anti-smuggling rules, strict `413` (`ServeError::PayloadTooLarge`)
/// when `max_body` is exceeded (`0` defaults to [`DEFAULT_MAX_BODY`]), and
/// [`DEFAULT_BODY_TIMEOUT`].
pub async fn read_body<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    req: &mut Request,
    max_body: usize,
) -> Result<(), ServeError> {
    let mut rbuf = ReadBuf::from_vec(std::mem::take(buf));
    let cfg = ServerConfig {
        max_body: Some(if max_body == 0 {
            DEFAULT_MAX_BODY
        } else {
            max_body
        }),
        spool_threshold: None,
        ..ServerConfig::default()
    };
    let res = read_body_with_config(s, &mut rbuf, req, &cfg).await;
    *buf = rbuf.into_remaining();
    res
}

async fn read_body_with_config<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    buf: &mut ReadBuf,
    req: &mut Request,
    cfg: &ServerConfig,
) -> Result<(), ServeError> {
    let framing = validate_body_framing(req)?;
    if framing == BodyFraming::None {
        return Ok(());
    }

    let limit = cfg.max_body.unwrap_or(usize::MAX);

    // Reject oversized Content-Length BEFORE emitting `100 Continue` (RFC 9110 §10.1.1).
    if let BodyFraming::ContentLength(len) = framing {
        if len > limit {
            return Err(ServeError::PayloadTooLarge);
        }
    }

    if req
        .headers
        .get("expect")
        .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
    {
        write_all_timeout(s, b"HTTP/1.1 100 Continue\r\n\r\n", cfg.write_timeout).await?;
    }

    let deadline = Instant::now() + cfg.body_timeout;
    let mut sink = BodySink::new(cfg.spool_threshold, cfg.spool_dir.clone());

    let res = match framing {
        BodyFraming::None => unreachable!(),
        BodyFraming::ContentLength(len) => {
            read_exact_to_sink(s, buf, len, deadline, &mut sink).await
        }
        BodyFraming::Chunked => read_chunked_to_sink(s, buf, limit, deadline, &mut sink).await,
        BodyFraming::UntilEof => read_to_eof_to_sink(s, buf, limit, deadline, &mut sink).await,
    };

    if let Err(err) = res {
        sink.cleanup();
        return Err(err);
    }

    let body = sink.finish(framing == BodyFraming::UntilEof).await?;
    req.body = body;
    Ok(())
}

/// Adaptive body sink: buffers in RAM up to `spool_threshold`, then transparently
/// spills to a `0600` `O_NOFOLLOW` temp file so large print jobs never OOM RAM.
struct BodySink {
    threshold: Option<usize>,
    spool_dir: Option<PathBuf>,
    mem: Vec<u8>,
    file: Option<(PathBuf, tokio::fs::File)>,
    total: u64,
}

impl BodySink {
    fn new(threshold: Option<usize>, spool_dir: Option<PathBuf>) -> Self {
        Self {
            threshold,
            spool_dir,
            mem: Vec::new(),
            file: None,
            total: 0,
        }
    }

    async fn push(&mut self, bytes: &[u8]) -> Result<(), ServeError> {
        if bytes.is_empty() {
            return Ok(());
        }
        if self.file.is_none() {
            if let Some(thresh) = self.threshold {
                if self.mem.len().saturating_add(bytes.len()) > thresh {
                    let (path, f) = create_spool_file(self.spool_dir.as_deref())?;
                    // Store immediately before awaiting writes so Drop/cleanup always
                    // removes the temp file on write error or task cancellation.
                    self.file = Some((path, f));
                    if !self.mem.is_empty() {
                        if let Some((_, ref mut file)) = self.file {
                            file.write_all(&self.mem).await?;
                        }
                        self.mem.clear();
                        self.mem.shrink_to_fit();
                    }
                }
            }
        }
        if let Some((_, ref mut f)) = self.file {
            f.write_all(bytes).await?;
        } else {
            self.mem.extend_from_slice(bytes);
        }
        self.total = self.total.saturating_add(bytes.len() as u64);
        Ok(())
    }

    fn cleanup(&mut self) {
        if let Some((path, _)) = self.file.take() {
            let _ = std::fs::remove_file(path);
        }
    }

    async fn finish(mut self, until_eof: bool) -> Result<Body, ServeError> {
        if let Some((_, ref mut f)) = self.file {
            f.flush().await?;
        }
        if let Some((path, f)) = self.file.take() {
            drop(f);
            return Ok(Body::Spooled(SpooledBody::new(path, self.total)));
        }
        let mem = std::mem::take(&mut self.mem);
        if mem.is_empty() {
            Ok(Body::Empty)
        } else if until_eof {
            Ok(Body::UntilEof(mem))
        } else {
            Ok(Body::Bytes(mem))
        }
    }
}

impl Drop for BodySink {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn create_spool_file(dir: Option<&Path>) -> io::Result<(PathBuf, tokio::fs::File)> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let base = dir.map_or_else(std::env::temp_dir, Path::to_path_buf);
    for _ in 0..16 {
        let seq = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!("yindle-http-body-{}-{seq}.tmp", std::process::id()));
        let mut opts = std::fs::OpenOptions::new();
        opts.create_new(true).write(true);
        #[cfg(unix)]
        {
            opts.mode(0o600).custom_flags(O_NOFOLLOW);
        }
        match opts.open(&path) {
            Ok(f) => {
                #[cfg(unix)]
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                return Ok((path, tokio::fs::File::from_std(f)));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "unable to create unique spool file",
    ))
}

async fn read_more<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut ReadBuf,
    deadline: Instant,
) -> Result<usize, ServeError> {
    match tokio::time::timeout_at(deadline, r.read(&mut buf.scratch)).await {
        Ok(Ok(0)) => Ok(0),
        Ok(Ok(n)) => {
            buf.extend_from_scratch(n);
            Ok(n)
        }
        Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Err(ServeError::Disconnect),
        Ok(Err(e)) => Err(ServeError::Io(e)),
        Err(_) => Err(ServeError::Timeout("body read deadline exceeded")),
    }
}

async fn read_exact_to_sink<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut ReadBuf,
    mut remaining: usize,
    deadline: Instant,
    sink: &mut BodySink,
) -> Result<(), ServeError> {
    while remaining > 0 {
        if buf.is_empty() && read_more(r, buf, deadline).await? == 0 {
            return Err(ServeError::Disconnect);
        }
        let take = remaining.min(buf.len());
        sink.push(&buf.as_slice()[..take]).await?;
        buf.consume(take);
        remaining -= take;
    }
    Ok(())
}

async fn read_to_eof_to_sink<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut ReadBuf,
    limit: usize,
    deadline: Instant,
    sink: &mut BodySink,
) -> Result<(), ServeError> {
    let mut total = 0usize;
    loop {
        if !buf.is_empty() {
            let n = buf.len();
            let next = total
                .checked_add(n)
                .filter(|&sum| sum <= limit)
                .ok_or(ServeError::PayloadTooLarge)?;
            sink.push(buf.as_slice()).await?;
            buf.consume(n);
            total = next;
        }
        if read_more(r, buf, deadline).await? == 0 {
            break;
        }
    }
    Ok(())
}

/// Read one `\r\n`-terminated line from `buf`/`r` in O(N) time without front-shifts.
async fn read_crlf_line<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut ReadBuf,
    max_len: usize,
    deadline: Instant,
) -> Result<String, ServeError> {
    loop {
        let slice = buf.as_slice();
        if let Some(pos) = slice.windows(2).position(|w| w == b"\r\n") {
            if pos > max_len {
                return Err(ServeError::BadRequest("chunk line too long"));
            }
            if slice[..pos].contains(&b'\r') || slice[..pos].contains(&b'\n') {
                return Err(ServeError::BadRequest("bare CR/LF in chunked framing"));
            }
            let line = std::str::from_utf8(&slice[..pos])
                .map_err(|_| ServeError::BadRequest("non-UTF-8 chunk line"))?
                .to_string();
            buf.consume(pos + 2);
            return Ok(line);
        }
        if slice.len() > max_len + 2 {
            return Err(ServeError::BadRequest("chunk line too long"));
        }
        if read_more(r, buf, deadline).await? == 0 {
            return Err(ServeError::Disconnect);
        }
    }
}

async fn read_chunked_to_sink<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut ReadBuf,
    limit: usize,
    deadline: Instant,
    sink: &mut BodySink,
) -> Result<(), ServeError> {
    let mut total = 0usize;
    loop {
        let line = read_crlf_line(r, buf, MAX_CHUNK_LINE_LEN, deadline).await?;
        let size_str = line.split(';').next().unwrap_or("");
        if size_str.is_empty() || !size_str.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ServeError::BadRequest("bad chunk size"));
        }
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| ServeError::BadRequest("chunk size overflow"))?;

        if size == 0 {
            // Bounded trailers strictly terminated by `\r\n`.
            let mut trailer_lines = 0usize;
            let mut trailer_bytes = 0usize;
            loop {
                let tl = read_crlf_line(r, buf, MAX_TRAILER_BYTES, deadline).await?;
                if tl.is_empty() {
                    break;
                }
                trailer_lines += 1;
                if trailer_lines > MAX_TRAILER_LINES {
                    return Err(ServeError::BadRequest("too many chunked trailer lines"));
                }
                trailer_bytes = trailer_bytes
                    .checked_add(tl.len() + 2)
                    .filter(|&sum| sum <= MAX_TRAILER_BYTES)
                    .ok_or(ServeError::BadRequest("chunked trailers too large"))?;
            }
            break;
        }

        // Checked arithmetic prevents integer overflow wraparound.
        total = total
            .checked_add(size)
            .filter(|&sum| sum <= limit)
            .ok_or(ServeError::PayloadTooLarge)?;

        // Stream chunk bytes into sink in bounded increments.
        read_exact_to_sink(r, buf, size, deadline, sink).await?;

        // Strictly require `\r\n` immediately following chunk data.
        while buf.len() < 2 {
            if read_more(r, buf, deadline).await? == 0 {
                return Err(ServeError::Disconnect);
            }
        }
        if &buf.as_slice()[..2] != b"\r\n" {
            return Err(ServeError::BadRequest("missing CRLF after chunk data"));
        }
        buf.consume(2);
    }
    Ok(())
}

async fn write_all_timeout<W: AsyncWrite + Unpin>(
    w: &mut W,
    bytes: &[u8],
    timeout: Duration,
) -> Result<(), ServeError> {
    match tokio::time::timeout(timeout, async {
        w.write_all(bytes).await?;
        w.flush().await
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(ServeError::Io(e)),
        Err(_) => Err(ServeError::Timeout("response write deadline exceeded")),
    }
}

/// Write an HTTP response under `write_timeout`.
async fn write_response<W: AsyncWrite + Unpin>(
    w: &mut W,
    resp: &Response,
    head_only: bool,
    keep_alive: bool,
    write_timeout: Duration,
) -> Result<(), ServeError> {
    let bytes = resp.encode(head_only, keep_alive);
    write_all_timeout(w, &bytes, write_timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{reason_phrase, HeaderError};
    use tokio::io::duplex;

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    async fn exchange(
        raw_req: &[u8],
        cfg: &ServerConfig,
    ) -> (String, Result<ConnectionOutcome, ServeError>) {
        let (mut client, mut server) = duplex(128 * 1024);
        let req_bytes = raw_req.to_vec();
        let cfg_clone = cfg.clone();

        let srv = tokio::spawn(async move {
            serve_connection_with_config(&mut server, &cfg_clone, |req| {
                let body = req.body.read_all().unwrap_or_default();
                let mut r = Response::with_body(StatusCode::OK, "text/plain", body);
                r.headers.set("X-Method", req.method.as_str());
                r.headers.set(
                    "X-Spooled",
                    if req.body.is_spooled() { "yes" } else { "no" },
                );
                r
            })
            .await
        });

        client.write_all(&req_bytes).await.unwrap();
        client.shutdown().await.unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let outcome = srv.await.unwrap();
        (String::from_utf8_lossy(&resp).into_owned(), outcome)
    }

    #[test]
    fn anti_smuggling_rejections_and_immediate_close() {
        block_on(async {
            let cfg = ServerConfig::default();

            let smuggling_cases: &[(&str, &[u8])] = &[
                (
                    "CL + TE conflict",
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                ),
                (
                    "duplicate Content-Length",
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
                ),
                (
                    "malformed Content-Length",
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: +5\r\n\r\nhello",
                ),
                (
                    "unsupported Transfer-Encoding",
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
                ),
                (
                    "duplicate chunked TE",
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n",
                ),
                (
                    "whitespace before colon",
                    b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length : 0\r\n\r\n",
                ),
                (
                    "obs-fold continuation",
                    b"GET / HTTP/1.1\r\nHost: localhost\r\n folded\r\n\r\n",
                ),
                (
                    "bare LF inside headers",
                    b"GET / HTTP/1.1\nHost: localhost\r\n\r\n",
                ),
                (
                    "missing Host on HTTP/1.1",
                    b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n",
                ),
                (
                    "duplicate Host header",
                    b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
                ),
                (
                    "malformed Host header",
                    b"GET / HTTP/1.1\r\nHost: evil@localhost\r\n\r\n",
                ),
                (
                    "malformed request line",
                    b"GET / HTTP/1.1 EXTRA\r\nHost: localhost\r\n\r\n",
                ),
                (
                    "garbage HTTP version",
                    b"GET / BOGUS\r\nHost: localhost\r\n\r\n",
                ),
                (
                    "missing CRLF after chunk data",
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n",
                ),
                (
                    "bad chunk size hex",
                    b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n\r\n",
                ),
            ];

            for (label, raw) in smuggling_cases {
                let (resp, outcome) = exchange(raw, &cfg).await;
                assert!(
                    resp.starts_with("HTTP/1.1 400 Bad Request\r\n"),
                    "{label}: expected 400, got: {resp:?}"
                );
                assert!(
                    resp.contains("Connection: close\r\n"),
                    "{label}: must close connection"
                );
                assert!(outcome.is_err(), "{label}: must return Err and close");
            }

            // Bare `\n\n` without `\r\n\r\n` is never accepted as header terminator (disconnects on EOF).
            let (_resp, outcome) = exchange(b"GET / HTTP/1.1\nHost: localhost\n\n", &cfg).await;
            assert!(matches!(outcome, Err(ServeError::Disconnect)));

            // HTTP/2.0 rejected with 505 and closed.
            let (resp505, out505) =
                exchange(b"GET / HTTP/2.0\r\nHost: localhost\r\n\r\n", &cfg).await;
            assert!(resp505.starts_with("HTTP/1.1 505 "));
            assert!(resp505.contains("Connection: close\r\n"));
            assert_eq!(out505.unwrap(), ConnectionOutcome::Closed);
        });
    }

    #[test]
    fn payload_too_large_413_content_length_chunked_and_eof() {
        block_on(async {
            let cfg = ServerConfig {
                max_body: Some(10),
                spool_threshold: None,
                ..ServerConfig::default()
            };

            // 1. Oversized Content-Length with Expect: 100-continue -> 413 WITHOUT sending 100 Continue!
            let oversized_cl = b"POST / HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 100\r\n\r\n";
            let (resp, out) = exchange(oversized_cl, &cfg).await;
            assert!(!resp.contains("100 Continue"));
            assert!(resp.starts_with("HTTP/1.1 413 "));
            assert!(resp.contains("Connection: close\r\n"));
            assert!(matches!(out, Err(ServeError::PayloadTooLarge)));

            // 2. Oversized chunked body -> 413 + close.
            let oversized_chunked = b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n123456\r\n6\r\n789012\r\n0\r\n\r\n";
            let (resp, out) = exchange(oversized_chunked, &cfg).await;
            assert!(resp.starts_with("HTTP/1.1 413 "));
            assert!(matches!(out, Err(ServeError::PayloadTooLarge)));

            // 3. Overflowing chunk size (usize::MAX) -> 413 or 400 (never panics!).
            let overflow_chunk = b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n";
            let (resp, out) = exchange(overflow_chunk, &cfg).await;
            assert!(resp.starts_with("HTTP/1.1 413 "));
            assert!(matches!(out, Err(ServeError::PayloadTooLarge)));

            // 4. Oversized close-delimited body -> 413.
            let oversized_eof =
                b"POST / HTTP/1.0\r\nContent-Type: text/plain\r\n\r\n0123456789EXTRA";
            let (resp, out) = exchange(oversized_eof, &cfg).await;
            assert!(resp.starts_with("HTTP/1.1 413 "));
            assert!(matches!(out, Err(ServeError::PayloadTooLarge)));

            // 5. Exact limit close-delimited body succeeds (no off-by-one!).
            let exact_limit_eof = b"POST / HTTP/1.0\r\nContent-Type: text/plain\r\n\r\n0123456789";
            let (resp, out) = exchange(exact_limit_eof, &cfg).await;
            assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(resp.ends_with("0123456789"));
            assert_eq!(out.unwrap(), ConnectionOutcome::Closed);
        });
    }

    #[test]
    fn chunked_trailers_bounded_and_valid_chunked_with_100_continue() {
        block_on(async {
            let cfg = ServerConfig::default();

            // Valid chunked body with chunk-extension, 100-continue, and 2 trailers.
            let raw = b"POST /ipp HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer-1: a\r\nX-Trailer-2: b\r\n\r\n";
            let (resp, out) = exchange(raw, &cfg).await;
            assert!(resp.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"));
            assert!(resp.ends_with("hello world"));
            assert_eq!(out.unwrap(), ConnectionOutcome::Closed);

            // Too many trailer lines (> MAX_TRAILER_LINES) rejected with 400.
            let mut bad_tr =
                b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n"
                    .to_vec();
            for i in 0..=MAX_TRAILER_LINES {
                bad_tr.extend_from_slice(format!("X-T{i}: 1\r\n").as_bytes());
            }
            bad_tr.extend_from_slice(b"\r\n");
            let (resp, out) = exchange(&bad_tr, &cfg).await;
            assert!(resp.starts_with("HTTP/1.1 400 "));
            assert!(matches!(out, Err(ServeError::BadRequest(_))));

            // Oversized header block -> 431 + close.
            let mut huge_hdr = b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Pad: ".to_vec();
            huge_hdr.resize(MAX_HEADER_BLOCK + 100, b'a');
            huge_hdr.extend_from_slice(b"\r\n\r\n");
            let (resp, out) = exchange(&huge_hdr, &cfg).await;
            assert!(resp.starts_with("HTTP/1.1 431 "));
            assert!(matches!(out, Err(ServeError::HeaderTooLarge)));
        });
    }

    #[test]
    fn slowloris_header_timeout_and_body_timeout() {
        block_on(async {
            let cfg = ServerConfig {
                header_timeout: Duration::from_millis(80),
                body_timeout: Duration::from_millis(80),
                ..ServerConfig::default()
            };

            // 1. Slowloris header trickle -> 408 Request Timeout.
            let (mut cli, mut srv) = duplex(4096);
            let cfg1 = cfg.clone();
            let handle = tokio::spawn(async move {
                serve_connection_with_config(&mut srv, &cfg1, |_| Response::status(StatusCode::OK))
                    .await
            });
            cli.write_all(b"GET / HTTP/1.1\r\nHost: local")
                .await
                .unwrap();
            let mut resp = Vec::new();
            cli.read_to_end(&mut resp).await.unwrap();
            let out = handle.await.unwrap();
            assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 408 "));
            assert!(matches!(out, Err(ServeError::Timeout(_))));

            // 2. Slow POST body stall -> 408 Request Timeout.
            let (mut cli2, mut srv2) = duplex(4096);
            let handle2 = tokio::spawn(async move {
                serve_connection_with_config(&mut srv2, &cfg, |_| Response::status(StatusCode::OK))
                    .await
            });
            cli2.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nabc")
                .await
                .unwrap();
            let mut resp2 = Vec::new();
            cli2.read_to_end(&mut resp2).await.unwrap();
            let out2 = handle2.await.unwrap();
            assert!(String::from_utf8_lossy(&resp2).starts_with("HTTP/1.1 408 "));
            assert!(matches!(out2, Err(ServeError::Timeout(_))));
        });
    }

    #[test]
    fn large_body_spools_to_temp_file_and_cleans_up_or_persists() {
        block_on(async {
            let dir =
                std::env::temp_dir().join(format!("yindle-httpd-spool-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();

            let cfg = ServerConfig {
                max_body: Some(1024 * 1024),
                spool_threshold: Some(32),
                spool_dir: Some(dir.clone()),
                ..ServerConfig::default()
            };

            let payload = vec![b'P'; 256];
            let mut raw = format!(
                "POST /printers/lp HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
                payload.len()
            )
            .into_bytes();
            raw.extend_from_slice(&payload);

            let (mut cli, mut srv) = duplex(64 * 1024);
            let persist_dest = dir.join("persisted.job");
            let dest_clone = persist_dest.clone();
            let handle = tokio::spawn(async move {
                serve_connection_with_config(&mut srv, &cfg, move |req| {
                    assert!(req.body.is_spooled());
                    assert_eq!(req.body.byte_len(), 256);
                    assert_eq!(req.body.as_bytes(), &[] as &[u8]);
                    let sp_path = req.body.spooled_path().unwrap().to_path_buf();
                    #[cfg(unix)]
                    {
                        let mode = std::fs::symlink_metadata(&sp_path)
                            .unwrap()
                            .permissions()
                            .mode()
                            & 0o777;
                        assert_eq!(mode, 0o600);
                    }
                    let bytes = req.body.read_all().unwrap();
                    assert_eq!(bytes.len(), 256);
                    let sp = req.body.into_spooled().unwrap();
                    assert!(!sp.is_empty());
                    assert!(sp.open().is_ok());
                    sp.persist(&dest_clone).unwrap();
                    Response::status(StatusCode::OK)
                })
                .await
            });

            cli.write_all(&raw).await.unwrap();
            cli.shutdown().await.unwrap();
            let mut resp = Vec::new();
            cli.read_to_end(&mut resp).await.unwrap();
            handle.await.unwrap().unwrap();
            assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200 OK"));
            assert_eq!(std::fs::read(&persist_dest).unwrap(), payload);

            // Auto-cleanup on Drop when not persisted.
            let (resp2, out2) = exchange(
                &raw,
                &ServerConfig {
                    spool_threshold: Some(32),
                    spool_dir: Some(dir.clone()),
                    ..ServerConfig::default()
                },
            )
            .await;
            assert!(resp2.contains("X-Spooled: yes\r\n"));
            assert_eq!(out2.unwrap(), ConnectionOutcome::Closed);

            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn keep_alive_rfc2817_upgrade_leftover_and_prefixed_stream() {
        block_on(async {
            // 1. Keep-alive serves 2 requests on one connection when enabled.
            let cfg_ka = ServerConfig::default();
            let two_reqs = b"GET /a HTTP/1.1\r\nHost: localhost\r\n\r\nHEAD /b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            let (resp, out) = exchange(two_reqs, &cfg_ka).await;
            assert_eq!(resp.matches("HTTP/1.1 200 OK").count(), 2);
            assert_eq!(out.unwrap(), ConnectionOutcome::Closed);

            // 2. KeepAlive = false closes after 1st request with Connection: close.
            let cfg_noka = ServerConfig {
                keep_alive: false,
                ..ServerConfig::default()
            };
            let (resp_no, out_no) = exchange(two_reqs, &cfg_noka).await;
            assert_eq!(resp_no.matches("HTTP/1.1 200 OK").count(), 1);
            assert!(resp_no.contains("Connection: close\r\n"));
            assert_eq!(out_no.unwrap(), ConnectionOutcome::Closed);

            // 3. RFC 2817 Upgrade preserves pipelined ClientHello bytes in leftover!
            let (mut cli, mut srv) = duplex(4096);
            let cfg_up = ServerConfig::default();
            let handle = tokio::spawn(async move {
                serve_connection_with_config(&mut srv, &cfg_up, |req| {
                    assert!(req.wants_tls_upgrade);
                    Response::status(StatusCode::SWITCHING_PROTOCOLS)
                })
                .await
            });
            cli.write_all(b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: TLS/1.2\r\n\r\nCLIENT_HELLO_BYTES")
                .await
                .unwrap();
            let outcome = handle.await.unwrap().unwrap();
            let mut resp101 = vec![0u8; 512];
            let n = cli.read(&mut resp101).await.unwrap();
            let text101 = String::from_utf8_lossy(&resp101[..n]);
            assert!(text101.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
            assert!(text101.contains("Connection: Upgrade\r\n"));
            assert!(text101.contains("Upgrade: TLS/1.2\r\n"));
            assert!(!text101.contains("Content-Length:"));

            let ConnectionOutcome::UpgradeTls { leftover } = outcome else {
                panic!("expected UpgradeTls");
            };
            assert_eq!(leftover, b"CLIENT_HELLO_BYTES");

            // Verify PrefixedStream yields leftover bytes then live stream bytes + supports writes.
            let (mut peer, inner) = duplex(4096);
            let mut prefixed = PrefixedStream::new(leftover, inner);
            assert_eq!(prefixed.remaining_prefix(), b"CLIENT_HELLO_BYTES");
            peer.write_all(b"_TAIL").await.unwrap();
            peer.shutdown().await.unwrap();
            let mut combined = Vec::new();
            prefixed.read_to_end(&mut combined).await.unwrap();
            assert_eq!(combined, b"CLIENT_HELLO_BYTES_TAIL");
            prefixed.write_all(b"ACK").await.unwrap();
            prefixed.flush().await.unwrap();
            prefixed.shutdown().await.unwrap();
            let mut ack = Vec::new();
            peer.read_to_end(&mut ack).await.unwrap();
            assert_eq!(ack, b"ACK");
            let _ = prefixed.into_inner();
        });
    }

    #[test]
    fn host_validator_headers_security_and_legacy_wrappers() {
        // Host validation (DNS rebinding defense).
        let aliases = vec!["*.corp.example".to_string(), "print.local".to_string()];
        assert!(validate_host(
            "localhost:631",
            Some("srv.example"),
            &aliases
        ));
        assert!(validate_host(
            "127.0.0.1:631",
            Some("srv.example"),
            &aliases
        ));
        assert!(validate_host(
            "127.0.0.2:631",
            Some("srv.example"),
            &aliases
        ));
        assert!(validate_host("[::1]:631", Some("srv.example"), &aliases));
        assert!(validate_host(
            "[0000::1]:631",
            Some("srv.example"),
            &aliases
        ));
        assert!(validate_host("srv.example.", Some("srv.example"), &aliases));
        assert!(validate_host(
            "cups.corp.example:631",
            Some("srv.example"),
            &aliases
        ));
        assert!(validate_host("print.local", Some("srv.example"), &aliases));
        assert!(!validate_host(
            "evil.attacker.com",
            Some("srv.example"),
            &aliases
        ));
        assert!(!validate_host(
            "corp.example",
            Some("srv.example"),
            &aliases
        ));
        assert!(!validate_host(
            "[::1]:notaport",
            Some("srv.example"),
            &aliases
        ));
        assert!(!validate_host("bad/path", Some("srv.example"), &aliases));
        assert!(validate_host("anything.tld", None, &["*".to_string()]));

        // HostValidator wired into ServerConfig rejects rebinding attempts with 400.
        block_on(async {
            let cfg = ServerConfig {
                host_validator: Some(HostValidator::new(Some("print.internal".into()), vec![])),
                ..ServerConfig::default()
            };
            let (resp, out) =
                exchange(b"GET / HTTP/1.1\r\nHost: rebind.evil.com\r\n\r\n", &cfg).await;
            assert!(resp.starts_with("HTTP/1.1 400 "));
            assert!(out.is_err());

            // Legacy serve_connection + ServerOptions + read_body wrapper smoke test.
            let opts = ServerOptions::default();
            assert_eq!(opts.max_body, DEFAULT_MAX_BODY);
            let (mut cli, mut srv) = duplex(4096);
            let h = tokio::spawn(async move {
                serve_connection(&mut srv, &opts, |req| {
                    assert_eq!(req.content_type(), Some("application/ipp"));
                    assert_eq!(req.content_length(), Some(3));
                    assert!(!req.body.is_empty());
                    Response::ipp(StatusCode::OK, req.body.as_bytes().to_vec())
                })
                .await
            });
            cli.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/ipp\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
                .await
                .unwrap();
            let mut r = Vec::new();
            cli.read_to_end(&mut r).await.unwrap();
            h.await.unwrap().unwrap();
            assert!(String::from_utf8_lossy(&r).ends_with("abc"));

            // Direct read_body wrapper.
            let (mut c2, mut s2) = duplex(4096);
            c2.write_all(b"xy").await.unwrap();
            let mut req =
                parse_request_head("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2")
                    .unwrap();
            let mut vbuf = Vec::new();
            read_body(&mut s2, &mut vbuf, &mut req, 0).await.unwrap();
            assert_eq!(req.body.as_bytes(), b"xy");
        });

        // Header CRLF injection blocking & security headers.
        assert!(validate_host("anything.tld", None, &["*".to_string()]));
    }

    #[test]
    fn headers_crlf_defense_security_headers_and_tables() {
        let mut h = Headers::new();
        h.set("X-Good", "ok");
        h.set("X-Good", "bad\r\nInjected: 1"); // refused, preserves "ok"!
        assert_eq!(h.get("X-Good"), Some("ok"));
        h.push("Bad Name", "val");
        assert!(!h.contains("Bad Name"));
        assert_eq!(h.try_set("X-Nul", "a\0b"), Err(HeaderError::InvalidValue));
        assert_eq!(h.try_push("", "a"), Err(HeaderError::InvalidName));
        h.remove("X-Good");
        assert!(!h.contains("X-Good"));

        let resp = Response::with_body(StatusCode::OK, "text/html", b"<h1>hi</h1>".to_vec())
            .with_security_headers();
        let encoded = String::from_utf8(resp.encode(false, true)).unwrap();
        assert!(encoded.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(encoded.contains("X-Frame-Options: DENY\r\n"));
        assert!(encoded
            .contains("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n"));
        assert!(encoded.contains("Referrer-Policy: no-referrer\r\n"));

        // Exercise Method::parse/as_str and reason_phrase table.
        for m in [
            "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "CUSTOM",
        ] {
            let parsed = Method::parse(m);
            let _ = parsed.as_str();
        }
        for code in [
            100, 101, 200, 201, 202, 204, 206, 301, 302, 303, 304, 307, 400, 401, 403, 404, 405,
            408, 411, 413, 414, 417, 426, 431, 500, 501, 502, 503, 505, 418,
        ] {
            assert_ne!(reason_phrase(code), "");
        }
    }

    #[test]
    fn edge_cases_truncation_spool_rollback_and_framing_limits() {
        // Header error branches.
        let mut h = Headers::new();
        assert_eq!(h.try_set("Bad Name", "v"), Err(HeaderError::InvalidName));
        assert_eq!(
            h.try_push("X-Ok", "bad\nval"),
            Err(HeaderError::InvalidValue)
        );
        // Response with explicit Content-Length preserves caller header.
        let mut explicit_cl = Response::status(StatusCode::OK);
        explicit_cl.headers.set("Content-Length", "0");
        assert!(String::from_utf8(explicit_cl.encode(false, true))
            .unwrap()
            .contains("Content-Length: 0\r\n"));

        // Body & Request helper edge cases.
        assert_eq!(Body::Empty.read_all().unwrap(), Vec::<u8>::new());
        assert_eq!(Body::Bytes(vec![1]).spooled_path(), None);
        assert!(Body::Bytes(vec![1]).into_spooled().is_none());
        let mut bad_cl_req = parse_request_head("POST / HTTP/1.1\r\nHost: localhost").unwrap();
        bad_cl_req.headers.push("Content-Length", "1");
        bad_cl_req.headers.push("Content-Length", "2");
        assert_eq!(bad_cl_req.content_length(), None);
        bad_cl_req.headers.remove("Content-Length");
        bad_cl_req.headers.set("Content-Length", "abc");
        assert_eq!(bad_cl_req.content_length(), None);

        // Host header syntax edge cases.
        assert!(!validate_host("", None, &[]));
        assert!(!validate_host("[not-v6]", None, &[]));
        assert!(validate_host("[::1]", None, &[]));
        assert!(!validate_host("::1", None, &[]));
        assert!(!validate_host("host:abc", None, &[]));
        assert!(!validate_host("bad$host", None, &[]));
        assert!(!validate_host("foo.example", Some(""), &[]));

        // ServerOptions with explicit non-zero max_body converts cleanly.
        let explicit_opts = ServerOptions {
            max_body: 4096,
            ..ServerOptions::default()
        };
        assert_eq!(ServerConfig::from(&explicit_opts).max_body, Some(4096));

        block_on(async {
            let cfg = ServerConfig::default();

            // 1. Truncated Content-Length body returns Disconnect (never silently truncates!).
            let (_r, out) = exchange(
                b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 50\r\n\r\nshort",
                &cfg,
            )
            .await;
            assert!(matches!(out, Err(ServeError::Disconnect)));

            // 2. Truncated chunked body (EOF before chunk size / before chunk CRLF).
            let (_r, out) = exchange(
                b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello",
                &cfg,
            )
            .await;
            assert!(matches!(out, Err(ServeError::Disconnect)));
            let (_r, out) = exchange(
                b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5",
                &cfg,
            )
            .await;
            assert!(matches!(out, Err(ServeError::Disconnect)));

            // 3. Oversized chunk-size line (> 64 bytes), bare LF in chunk line, oversized trailers.
            let long_chunk = format!(
                "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1;{}\r\na\r\n0\r\n\r\n",
                "x".repeat(80)
            );
            let (resp, out) = exchange(long_chunk.as_bytes(), &cfg).await;
            assert!(resp.starts_with("HTTP/1.1 400 "));
            assert!(matches!(out, Err(ServeError::BadRequest(_))));

            let (resp, out) = exchange(
                b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1\n\r\na\r\n0\r\n\r\n",
                &cfg,
            )
            .await;
            assert!(resp.starts_with("HTTP/1.1 400 "));
            assert!(matches!(out, Err(ServeError::BadRequest(_))));

            let mut big_trailer =
                b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n"
                    .to_vec();
            for i in 0..4 {
                big_trailer
                    .extend_from_slice(format!("X-Big-{i}: {}\r\n", "z".repeat(3000)).as_bytes());
            }
            big_trailer.extend_from_slice(b"\r\n");
            let (resp, out) = exchange(&big_trailer, &cfg).await;
            assert!(resp.starts_with("HTTP/1.1 400 "));
            assert!(matches!(out, Err(ServeError::BadRequest(_))));

            // 4. HTTP/0.9 with no headers succeeds; HTTP/0.9 with headers rejected with 400.
            let (resp09, out09) = exchange(b"GET /legacy\r\n\r\n", &cfg).await;
            assert!(resp09.starts_with("HTTP/1.1 200 OK"));
            assert_eq!(out09.unwrap(), ConnectionOutcome::Closed);
            let (resp09_bad, out09_bad) =
                exchange(b"GET /legacy\r\nHost: localhost\r\n\r\n", &cfg).await;
            assert!(resp09_bad.starts_with("HTTP/1.1 400 "));
            assert!(out09_bad.is_err());
        });
    }

    #[test]
    fn idle_write_timeouts_and_spool_error_cleanup() {
        block_on(async {
            // 5. Idle timeout before first byte returns Disconnect cleanly.
            let idle_cfg = ServerConfig {
                idle_timeout: Duration::from_millis(40),
                ..ServerConfig::default()
            };
            let (_cli_idle, mut srv_idle) = duplex(1024);
            let out_idle = serve_connection_with_config(&mut srv_idle, &idle_cfg, |_| {
                Response::status(StatusCode::OK)
            })
            .await;
            assert!(matches!(out_idle, Err(ServeError::Disconnect)));

            // 6. Legacy serve_connection returns Err(Disconnect) on RFC 2817 upgrade.
            let (mut cli_u, mut srv_u) = duplex(4096);
            let h_u = tokio::spawn(async move {
                serve_connection(&mut srv_u, &ServerOptions::default(), |_| {
                    Response::status(StatusCode::SWITCHING_PROTOCOLS)
                })
                .await
            });
            cli_u
                .write_all(b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nUpgrade: TLS/1.2\r\n\r\n")
                .await
                .unwrap();
            assert!(matches!(h_u.await.unwrap(), Err(ServeError::Disconnect)));

            // 7. Spooled body cleanup when chunked body errors mid-stream + persist failure rollback
            //    + ReadBuf compaction across > 4096 byte reads.
            let dir =
                std::env::temp_dir().join(format!("yindle-httpd-edge-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();

            let spool_cfg = ServerConfig {
                max_body: Some(64 * 1024),
                spool_threshold: Some(100),
                spool_dir: Some(dir.clone()),
                ..ServerConfig::default()
            };

            // Multi-chunk body > 5 KiB exercises ReadBuf compaction and BodySink spill from mem -> file.
            let (mut cli_s, mut srv_s) = duplex(16 * 1024);
            let h_s = tokio::spawn(async move {
                serve_connection_with_config(&mut srv_s, &spool_cfg, |req| {
                    let sp = req.body.into_spooled().unwrap();
                    // Persist to non-existent directory fails AND restores path so Drop cleans up!
                    assert!(sp
                        .persist(Path::new("/nonexistent-dir-yindle-xyz/file"))
                        .is_err());
                    Response::status(StatusCode::OK)
                })
                .await
            });
            cli_s
                .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n32\r\n")
                .await
                .unwrap();
            cli_s.write_all(&[b'A'; 50]).await.unwrap();
            cli_s.write_all(b"\r\n1400\r\n").await.unwrap();
            cli_s.write_all(&[b'B'; 0x1400]).await.unwrap();
            cli_s.write_all(b"\r\n0\r\n\r\n").await.unwrap();
            cli_s.shutdown().await.unwrap();
            let mut r_s = Vec::new();
            cli_s.read_to_end(&mut r_s).await.unwrap();
            assert!(String::from_utf8_lossy(&r_s).starts_with("HTTP/1.1 200 OK"));
            h_s.await.unwrap().unwrap();

            // Mid-body failure after spooling cleans up temp file automatically.
            let fail_cfg = ServerConfig {
                max_body: Some(64 * 1024),
                spool_threshold: Some(16),
                spool_dir: Some(dir.clone()),
                ..ServerConfig::default()
            };
            let (_rf, out_f) = exchange(
                b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n20\r\n01234567890123456789012345678901XX",
                &fail_cfg,
            )
            .await;
            assert!(matches!(out_f, Err(ServeError::BadRequest(_))));
            // All temp spool files were cleaned up!
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
            let _ = std::fs::remove_dir_all(&dir);

            // 8. Write timeout when peer refuses to read a response larger than duplex buffer.
            let write_cfg = ServerConfig {
                write_timeout: Duration::from_millis(40),
                ..ServerConfig::default()
            };
            let (mut cli_w, mut srv_w) = duplex(64);
            let h_w = tokio::spawn(async move {
                serve_connection_with_config(&mut srv_w, &write_cfg, |_| {
                    Response::with_body(StatusCode::OK, "application/octet-stream", vec![0u8; 4096])
                })
                .await
            });
            cli_w
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
            // Intentionally never read from cli_w so server write blocks past 40ms.
            let out_w = h_w.await.unwrap();
            assert!(matches!(out_w, Err(ServeError::Timeout(_))));
        });
    }

    #[test]
    fn spooled_body_cleaned_up_on_task_cancel() {
        block_on(async {
            let dir =
                std::env::temp_dir().join(format!("yindle-httpd-cancel-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();

            let cancel_cfg = ServerConfig {
                max_body: Some(64 * 1024),
                spool_threshold: Some(16),
                spool_dir: Some(dir.clone()),
                ..ServerConfig::default()
            };
            let (mut cli_c, mut srv_c) = duplex(4096);
            let h_c = tokio::spawn(async move {
                serve_connection_with_config(&mut srv_c, &cancel_cfg, |_| {
                    Response::status(StatusCode::OK)
                })
                .await
            });
            cli_c
                .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000\r\n\r\n01234567890123456789012345678901")
                .await
                .unwrap();
            for _ in 0..50 {
                if std::fs::read_dir(&dir).unwrap().count() > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
            h_c.abort();
            let _ = h_c.await;
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
            let _ = std::fs::remove_dir_all(&dir);
        });
    }
}
