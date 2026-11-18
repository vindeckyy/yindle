//! Shared CUPS backend framework — the argv/env/exit contract every backend
//! honors (`cups/backend.h`, `backend/*.c`), plus shared security helpers for
//! discovery sanitization, URI credential redaction, SSRF enforcement, and
//! safe `/dev/` character-device opening.
//!
//! A backend is run two ways:
//!  * `scheme` (`argv.len() < 6`) — *device discovery*: print one
//!    `class uri "make-model" "info" ["device-id"]` line per found device, exit 0.
//!  * `scheme job-id user title copies options [file]` — print the job from
//!    stdin (or `file`) to `DEVICE_URI`, exit a `CUPS_BACKEND_*` code.

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Component, Path};
use std::time::Duration;

/// `CUPS_BACKEND_*` exit codes (`cups/backend.h`).
pub mod code {
    /// Job completed successfully.
    pub const OK: i32 = 0;
    /// Job failed; apply error-policy.
    pub const FAILED: i32 = 1;
    /// Authentication required.
    pub const AUTH_REQUIRED: i32 = 2;
    /// Hold the job.
    pub const HOLD: i32 = 3;
    /// Stop the queue.
    pub const STOP: i32 = 4;
    /// Cancel the job.
    pub const CANCEL: i32 = 5;
    /// Retry later.
    pub const RETRY: i32 = 6;
    /// Retry immediately.
    pub const RETRY_CURRENT: i32 = 7;
}

/// Platform-accurate `O_NOFOLLOW` flag for `OpenOptionsExt::custom_flags`.
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
pub const O_NOFOLLOW: i32 = 0x8000;

/// Platform-accurate `O_NOFOLLOW` flag for `OpenOptionsExt::custom_flags`.
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
pub const O_NOFOLLOW: i32 = 0x20000;

/// Platform-accurate `O_NOFOLLOW` flag for BSD/macOS.
#[cfg(all(unix, not(target_os = "linux")))]
pub const O_NOFOLLOW: i32 = 0x100;

/// Platform-accurate `O_NOCTTY` flag for `OpenOptionsExt::custom_flags`.
#[cfg(all(target_os = "linux", any(target_arch = "mips", target_arch = "mips64")))]
pub const O_NOCTTY: i32 = 0x800;

/// Platform-accurate `O_NOCTTY` flag for `OpenOptionsExt::custom_flags`.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "sparc", target_arch = "sparc64")
))]
pub const O_NOCTTY: i32 = 0x8000;

/// Platform-accurate `O_NOCTTY` flag for `OpenOptionsExt::custom_flags`.
#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "sparc",
        target_arch = "sparc64"
    ))
))]
pub const O_NOCTTY: i32 = 0x100;

/// Platform-accurate `O_NOCTTY` flag for macOS.
#[cfg(target_os = "macos")]
pub const O_NOCTTY: i32 = 0x20000;

/// Platform-accurate `O_NOCTTY` flag for non-Linux/non-macOS Unix.
#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
pub const O_NOCTTY: i32 = 0x8000;

/// Parsed backend invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// `argv[1]` job id (0 in discovery).
    pub job_id: i32,
    /// `argv[2]` user.
    pub user: String,
    /// `argv[3]` job title.
    pub title: String,
    /// `argv[4]` copies.
    pub copies: i32,
    /// `argv[5]` options string.
    pub options: String,
    /// `argv[6]` document path, if supplied (else read stdin).
    pub file: Option<String>,
    /// `DEVICE_URI` env var.
    pub device_uri: String,
}

/// Parse argv+env for a print invocation; `None` if run in discovery mode
/// (fewer than 6 args).
#[must_use]
pub fn parse<I: Iterator<Item = String>>(argv: I) -> Option<Invocation> {
    parse_with_uri(argv, env::var("DEVICE_URI").unwrap_or_default())
}

/// Parse argv with an explicit `device_uri` (test-friendly variant of [`parse`]).
#[must_use]
pub fn parse_with_uri<I: Iterator<Item = String>>(
    argv: I,
    device_uri: String,
) -> Option<Invocation> {
    let a: Vec<String> = argv.collect();
    if a.len() < 6 {
        return None;
    }
    Some(Invocation {
        job_id: a[1].parse().unwrap_or(0),
        user: a[2].clone(),
        title: a[3].clone(),
        copies: a[4].parse().unwrap_or(1),
        options: a[5].clone(),
        file: a.get(6).cloned(),
        device_uri,
    })
}

/// Open the job document as a reader — `argv[6]` file or stdin.
pub fn document(inv: &Invocation) -> io::Result<Box<dyn Read + Send>> {
    match &inv.file {
        Some(f) => Ok(Box::new(File::open(f)?)),
        None => Ok(Box::new(io::stdin())),
    }
}

/// Sanitize a quoted discovery field (`make-model`, `info`, `device-id`).
///
/// Strips `"` and control characters (replacing `\r`, `\n`, `\t` with spaces)
/// so untrusted mDNS/SNMP/USB responders cannot break out of quotes or inject
/// synthetic discovery lines.
#[must_use]
pub fn sanitize_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => {}
            '\r' | '\n' | '\t' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.trim().to_string()
}

/// Sanitize an unquoted discovery token (`class`, `uri`).
///
/// Strips quotes, whitespace, and all control characters so a token cannot
/// split into extra fields or inject new lines.
#[must_use]
pub fn sanitize_token(s: &str) -> String {
    s.chars()
        .filter(|&c| c != '"' && !c.is_control() && !c.is_whitespace())
        .collect()
}

/// Format one sanitized discovery line (`class uri "make-model" "info" ["device-id"]`).
/// Returns `None` if `class_` or `uri` is empty after sanitization.
#[must_use]
pub fn format_report(
    class_: &str,
    uri: &str,
    make_model: &str,
    info: &str,
    device_id: Option<&str>,
) -> Option<String> {
    let class_ = sanitize_token(class_);
    let uri = sanitize_token(uri);
    if class_.is_empty() || uri.is_empty() {
        return None;
    }
    let make_model = sanitize_field(make_model);
    let info = sanitize_field(info);
    let mut line = format!("{class_} {uri} \"{make_model}\" \"{info}\"");
    if let Some(id) = device_id {
        let id = sanitize_field(id);
        line.push_str(" \"");
        line.push_str(&id);
        line.push('"');
    }
    Some(line)
}

/// Write one sanitized discovery line to `out`.
pub fn report_to(
    out: &mut impl Write,
    class_: &str,
    uri: &str,
    make_model: &str,
    info: &str,
    device_id: Option<&str>,
) -> io::Result<()> {
    if let Some(line) = format_report(class_, uri, make_model, info, device_id) {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// Emit one sanitized discovery line (`class uri "make-model" "info" ["device-id"]`)
/// to stdout.
pub fn report(class_: &str, uri: &str, make_model: &str, info: &str, device_id: Option<&str>) {
    let mut out = io::stdout().lock();
    let _ = report_to(&mut out, class_, uri, make_model, info, device_id);
}

/// Redact `user[:pass]@` credentials from a URI before logging it.
///
/// Leaves URIs without userinfo untouched, and ignores `@` characters that
/// appear in the path, query, or fragment.
#[must_use]
pub fn redact_uri(uri: &str) -> String {
    let Some(scheme_end) = uri.find("://") else {
        return uri.to_string();
    };
    let after_scheme = &uri[scheme_end + 3..];
    let auth_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..auth_end];
    let Some((_, host_port)) = authority.rsplit_once('@') else {
        return uri.to_string();
    };
    format!(
        "{}://***@{}{}",
        &uri[..scheme_end],
        host_port,
        &after_scheme[auth_end..]
    )
}

/// Percent-encode a string for URI path/query/authority components (RFC 3986 unreserved).
#[must_use]
pub fn percent_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// UTF-8-aware percent decoding (`%XX` -> raw bytes -> UTF-8 lossy).
#[must_use]
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Format `host:port`, wrapping bare IPv6 literals in `[...]`.
#[must_use]
pub fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Parsed network URI (`scheme://[user[:pass]@]host[:port][/path][?query]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkUri {
    /// Lowercased URI scheme (`ipp`, `ipps`, `http`, `https`, `lpd`, `socket`).
    pub scheme: String,
    /// Optional percent-decoded username.
    pub username: Option<String>,
    /// Optional percent-decoded password.
    pub password: Option<String>,
    /// Unbracketed hostname or IPv4/IPv6 literal.
    pub host: String,
    /// Non-zero TCP port.
    pub port: u16,
    /// Path starting with `/` (or `/` when absent).
    pub path: String,
    /// Optional raw query string (without leading `?`).
    pub query: Option<String>,
}

impl NetworkUri {
    /// Parse a network URI, rejecting control characters, CRLF injection, empty
    /// hosts, malformed IPv6 brackets, and port `0`.
    #[must_use]
    pub fn parse(uri: &str, default_port: u16) -> Option<Self> {
        if default_port == 0 || uri.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return None;
        }
        let (scheme_raw, rest) = uri.split_once("://")?;
        if scheme_raw.is_empty()
            || !scheme_raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        {
            return None;
        }
        let scheme = scheme_raw.to_ascii_lowercase();
        let rest = rest.split('#').next().unwrap_or(rest);
        let auth_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..auth_end];
        let after_auth = &rest[auth_end..];

        let (path_raw, query) = match after_auth.split_once('?') {
            Some((p, q)) => (p, Some(q.to_string())),
            None => (after_auth, None),
        };
        if path_raw.bytes().any(|b| b.is_ascii_whitespace()) {
            return None;
        }
        let path = if path_raw.is_empty() {
            "/".to_string()
        } else {
            path_raw.to_string()
        };

        let (username, password, hostport) = match authority.rsplit_once('@') {
            Some((userinfo, hp)) => match userinfo.split_once(':') {
                Some((u, p)) => (Some(percent_decode(u)), Some(percent_decode(p)), hp),
                None => (Some(percent_decode(userinfo)), None, hp),
            },
            None => (None, None, authority),
        };

        let (host, port) = parse_host_port(hostport, default_port)?;
        Some(Self {
            scheme,
            username,
            password,
            host,
            port,
            path,
            query,
        })
    }

    /// Return `host:port` (or `[ipv6]:port`) suitable for `Host:` headers and sockets.
    #[must_use]
    pub fn host_port(&self) -> String {
        format_host_port(&self.host, self.port)
    }

    /// Return a sanitized URI without userinfo or query parameters.
    #[must_use]
    pub fn clean_uri(&self, scheme_override: Option<&str>) -> String {
        let scheme = scheme_override.unwrap_or(&self.scheme);
        format!("{scheme}://{}{}", self.host_port(), self.path)
    }
}

fn parse_host_port(hostport: &str, default_port: u16) -> Option<(String, u16)> {
    if hostport.is_empty() || hostport.bytes().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    if let Some(rest) = hostport.strip_prefix('[') {
        let (inside, tail) = rest.split_once(']')?;
        if inside.is_empty() || inside.parse::<Ipv6Addr>().is_err() {
            return None;
        }
        let port = if tail.is_empty() {
            default_port
        } else {
            let p_str = tail.strip_prefix(':')?;
            parse_nonzero_port(p_str)?
        };
        return Some((inside.to_string(), port));
    }
    if hostport.contains('[') || hostport.contains(']') {
        return None;
    }
    let (host, port) = match hostport.split_once(':') {
        Some((h, p)) => {
            if p.contains(':') {
                // Unbracketed IPv6 literal is invalid in a URI authority.
                return None;
            }
            (h, parse_nonzero_port(p)?)
        }
        None => (hostport, default_port),
    };
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

fn parse_nonzero_port(s: &str) -> Option<u16> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = s.parse().ok()?;
    (port > 0).then_some(port)
}

/// Parse a boolean-like configuration/environment string.
#[must_use]
pub fn parse_env_bool(val: Option<&str>) -> Option<bool> {
    let v = val?.trim();
    if v.eq_ignore_ascii_case("yes")
        || v.eq_ignore_ascii_case("true")
        || v.eq_ignore_ascii_case("1")
        || v.eq_ignore_ascii_case("on")
    {
        Some(true)
    } else if v.eq_ignore_ascii_case("no")
        || v.eq_ignore_ascii_case("false")
        || v.eq_ignore_ascii_case("0")
        || v.eq_ignore_ascii_case("off")
    {
        Some(false)
    } else {
        None
    }
}

/// SSRF policy for network backends (`ipp`, `lpd`, `socket`, `snmp`, `dnssd`).
///
/// Always blocks:
///  * Port `0`
///  * Unspecified addresses (`0.0.0.0`, `::`)
///  * Cloud metadata & link-local addresses (`169.254.0.0/16` including
///    `169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`, `fe80::/10`)
///  * IPv4-mapped IPv6 encodings of blocked IPv4 targets (e.g. `::ffff:169.254.169.254`)
///  * Broadcast and multicast addresses
///
/// Loopback (`127.0.0.0/8`, `::1`) is blocked by default unless explicitly
/// enabled via `CUPS_ALLOW_LOOPBACK_BACKENDS=yes|1|true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SsrfPolicy {
    /// Permit loopback destinations (`127.0.0.0/8`, `::1`).
    pub allow_loopback: bool,
}

impl SsrfPolicy {
    /// Build policy from `CUPS_ALLOW_LOOPBACK_BACKENDS`.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_env_value(env::var("CUPS_ALLOW_LOOPBACK_BACKENDS").ok().as_deref())
    }

    /// Build policy from an explicit env-var value (unit-test friendly).
    #[must_use]
    pub fn from_env_value(val: Option<&str>) -> Self {
        Self {
            allow_loopback: parse_env_bool(val).unwrap_or(false),
        }
    }

    /// Validate a single IP address against the SSRF policy.
    pub fn check_ip(self, ip: IpAddr) -> io::Result<()> {
        let normalized = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            IpAddr::V4(v4) => IpAddr::V4(v4),
        };
        match normalized {
            IpAddr::V4(v4) => self.check_v4(v4),
            IpAddr::V6(v6) => self.check_v6(v6),
        }
    }

    fn check_v4(self, v4: Ipv4Addr) -> io::Result<()> {
        if v4.is_unspecified() {
            return Err(ssrf_err("unspecified address is blocked"));
        }
        if v4.is_link_local() {
            return Err(ssrf_err("link-local/metadata address is blocked"));
        }
        if v4 == Ipv4Addr::new(100, 100, 100, 200) {
            return Err(ssrf_err("cloud metadata address is blocked"));
        }
        if v4.is_broadcast() || v4.is_multicast() {
            return Err(ssrf_err("broadcast/multicast address is blocked"));
        }
        if v4.is_loopback() && !self.allow_loopback {
            return Err(ssrf_err(
                "loopback address is blocked (set CUPS_ALLOW_LOOPBACK_BACKENDS=yes to allow)",
            ));
        }
        Ok(())
    }

    fn check_v6(self, v6: Ipv6Addr) -> io::Result<()> {
        if v6.is_unspecified() {
            return Err(ssrf_err("unspecified IPv6 address is blocked"));
        }
        // AWS IPv6 IMDS (`fd00:ec2::254`).
        if v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254) {
            return Err(ssrf_err("IPv6 cloud metadata address is blocked"));
        }
        // IPv6 link-local `fe80::/10` (includes link-local metadata `fe80::a9fe:a9fe`).
        if (v6.segments()[0] & 0xffc0) == 0xfe80 {
            return Err(ssrf_err("IPv6 link-local/metadata address is blocked"));
        }
        if v6.is_multicast() {
            return Err(ssrf_err("IPv6 multicast address is blocked"));
        }
        if v6.is_loopback() && !self.allow_loopback {
            return Err(ssrf_err(
                "IPv6 loopback address is blocked (set CUPS_ALLOW_LOOPBACK_BACKENDS=yes to allow)",
            ));
        }
        Ok(())
    }

    /// Validate a [`SocketAddr`] (port and IP).
    pub fn check_socket_addr(self, addr: SocketAddr) -> io::Result<()> {
        if addr.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid port 0",
            ));
        }
        self.check_ip(addr.ip())
    }

    /// Resolve `host:port` once and validate every resolved address against the
    /// SSRF policy (prevents dual-record / rebinding bypasses).
    pub fn resolve_checked(self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid port 0",
            ));
        }
        if host.is_empty() || host.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid hostname",
            ));
        }
        let target = format_host_port(host, port);
        let addrs: Vec<SocketAddr> = target.to_socket_addrs()?.collect();
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no addresses resolved for {host}"),
            ));
        }
        for &addr in &addrs {
            self.check_socket_addr(addr)?;
        }
        Ok(addrs)
    }

    /// Resolve `host:port`, validate all resolved targets against SSRF policy,
    /// and connect directly to a validated [`SocketAddr`] with `timeout`.
    pub fn connect_checked(
        self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> io::Result<(TcpStream, SocketAddr)> {
        let addrs = self.resolve_checked(host, port)?;
        let mut last_err = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => return Ok((stream, addr)),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("connection failed")))
    }
}

fn ssrf_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("ssrf: {msg}"))
}

/// Reject relative paths, NUL bytes, and `..` traversal components.
pub fn validate_no_traversal(path: &str) -> io::Result<()> {
    if path.is_empty() || path.contains('\0') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid path"));
    }
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be absolute",
        ));
    }
    for comp in p.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "path traversal ('..') is forbidden",
            ));
        }
    }
    Ok(())
}

/// Safely open a character device under `/dev/` (`canonicalize`, `/dev/` prefix,
/// `O_NOFOLLOW`, optional `O_NOCTTY`, and `fstat` `S_ISCHR` verification).
pub fn open_char_device(path: &str, read: bool, write: bool, no_ctty: bool) -> io::Result<File> {
    open_char_device_with_prefixes(path, &["/dev/"], read, write, no_ctty)
}

/// Safely open a character device whose canonical path matches one of
/// `allowed_prefixes` (each should be an absolute `/dev/...` path prefix).
pub fn open_char_device_with_prefixes(
    path: &str,
    allowed_prefixes: &[&str],
    read: bool,
    write: bool,
    no_ctty: bool,
) -> io::Result<File> {
    validate_no_traversal(path)?;
    let canonical = std::fs::canonicalize(path)?;
    let canon_str = canonical.to_string_lossy();
    let allowed = allowed_prefixes.iter().any(|prefix| {
        if prefix.ends_with('/') {
            canon_str.starts_with(prefix) && canon_str.len() > prefix.len()
        } else {
            canon_str.starts_with(prefix)
        }
    });
    if !allowed {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "device path {} outside allowed /dev/ prefix",
                canonical.display()
            ),
        ));
    }

    let mut opts = OpenOptions::new();
    opts.read(read).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let flags = O_NOFOLLOW | if no_ctty { O_NOCTTY } else { 0 };
        opts.custom_flags(flags);
    }
    let file = opts.open(&canonical)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let meta = file.metadata()?;
        if !meta.file_type().is_char_device() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} is not a character device", canonical.display()),
            ));
        }
    }
    Ok(file)
}

fn emit_line(out: &mut impl Write, prefix: &str, msg: &str) {
    let clean = sanitize_field(msg);
    let _ = writeln!(out, "{prefix}: {clean}");
}

/// `DEBUG:` line on stderr (consumed by the scheduler's filter log).
pub fn debug(args: std::fmt::Arguments<'_>) {
    eprintln!("DEBUG: {args}");
}

/// `INFO:` line on stderr → `error_log`.
pub fn info(args: std::fmt::Arguments<'_>) {
    eprintln!("INFO: {args}");
}

/// `WARNING:` line on stderr → `error_log`.
pub fn warn(args: std::fmt::Arguments<'_>) {
    eprintln!("WARNING: {args}");
}

/// `ERROR:` line on stderr → `error_log`.
pub fn error(args: std::fmt::Arguments<'_>) {
    eprintln!("ERROR: {args}");
}

/// `STATE:` printer state-reason update on stderr (sanitized).
pub fn state(reason: &str) {
    let mut err = io::stderr().lock();
    emit_line(&mut err, "STATE", reason);
}

/// `PAGE:` page-accounting update on stderr.
pub fn page(page_num: u32, copies: i32) {
    eprintln!("PAGE: {page_num} {copies}");
}

/// `ATTR:` printer attribute update on stderr (sanitized).
pub fn attr(key: &str, value: &str) {
    let mut err = io::stderr().lock();
    let k = sanitize_token(key);
    let v = sanitize_field(value);
    if !k.is_empty() {
        let _ = writeln!(err, "ATTR: {k}={v}");
    }
}

/// Test-friendly dispatch: returns the `CUPS_BACKEND_*` exit code without calling `exit()`.
pub fn run_with<I, D, P>(argv: I, device_uri: String, discover: D, print: P) -> i32
where
    I: Iterator<Item = String>,
    D: FnOnce() -> i32,
    P: FnOnce(Invocation) -> i32,
{
    match parse_with_uri(argv, device_uri) {
        Some(inv) => print(inv),
        None => discover(),
    }
}

/// Run a backend main: `discover()` when `argv.len() < 6`, else `print(inv)`.
/// `print` returns a `CUPS_BACKEND_*` code.
pub fn run<D, P>(discover: D, print: P) -> !
where
    D: FnOnce() -> i32,
    P: FnOnce(Invocation) -> i32,
{
    let code = run_with(
        env::args(),
        env::var("DEVICE_URI").unwrap_or_default(),
        discover,
        print,
    );
    std::process::exit(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn parse_discovery_and_print() {
        let none = parse_with_uri(["ipp".to_string()].into_iter(), String::new());
        assert!(none.is_none());

        let argv = [
            "ipp",
            "42",
            "alice",
            "Report",
            "3",
            "sides=two-sided-long-edge",
            "/tmp/job.pdf",
        ]
        .into_iter()
        .map(String::from);
        let inv = parse_with_uri(argv, "ipp://printer.local/ipp/print".into()).unwrap();
        assert_eq!(inv.job_id, 42);
        assert_eq!(inv.user, "alice");
        assert_eq!(inv.title, "Report");
        assert_eq!(inv.copies, 3);
        assert_eq!(inv.options, "sides=two-sided-long-edge");
        assert_eq!(inv.file.as_deref(), Some("/tmp/job.pdf"));
        assert_eq!(inv.device_uri, "ipp://printer.local/ipp/print");

        // Also cover parse() wrapper with short argv.
        assert!(parse(["prog".to_string()].into_iter()).is_none());
    }

    #[test]
    fn run_with_dispatches_both_modes() {
        let rc_disc = run_with(
            ["backend".to_string()].into_iter(),
            String::new(),
            || code::OK,
            |_| code::FAILED,
        );
        assert_eq!(rc_disc, code::OK);

        let argv = ["backend", "1", "u", "t", "1", ""]
            .into_iter()
            .map(String::from);
        let rc_print = run_with(
            argv,
            "socket://10.0.0.1".into(),
            || code::FAILED,
            |inv| {
                assert_eq!(inv.job_id, 1);
                code::RETRY
            },
        );
        assert_eq!(rc_print, code::RETRY);
    }

    #[test]
    fn document_reads_file_and_errors_on_missing() {
        let dir = env::temp_dir().join(format!("pw-bc-doc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("sample.txt");
        std::fs::write(&file, b"hello world").unwrap();

        let inv = Invocation {
            job_id: 1,
            user: "u".into(),
            title: "t".into(),
            copies: 1,
            options: String::new(),
            file: Some(file.to_string_lossy().into_owned()),
            device_uri: String::new(),
        };
        let mut r = document(&inv).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello world");

        let inv_stdin = Invocation {
            file: None,
            ..inv.clone()
        };
        assert!(document(&inv_stdin).is_ok());

        let inv_bad = Invocation {
            file: Some(dir.join("missing").to_string_lossy().into_owned()),
            ..inv
        };
        assert!(document(&inv_bad).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discovery_sanitization_blocks_injection() {
        assert_eq!(
            sanitize_field("HP \"Laser\"\r\nnetwork evil://x \"a\" \"b\"\x00\x07"),
            "HP Laser  network evil://x a b"
        );
        assert_eq!(sanitize_token("ipp://h/p\r\n \"bad\""), "ipp://h/pbad");

        let line = format_report(
            "network\n",
            "ipp://10.0.0.5/ipp/print",
            "Evil \"Model\"\nfake line",
            "Info\r\t\"quoted\"",
            Some("MFG:HP;\"MDL:X\n"),
        )
        .unwrap();
        assert!(!line.contains('\n'));
        assert!(!line.contains('\r'));
        assert_eq!(
            line,
            "network ipp://10.0.0.5/ipp/print \"Evil Model fake line\" \"Info  quoted\" \"MFG:HP;MDL:X\""
        );

        assert!(format_report("", "ipp://x", "m", "i", None).is_none());
        assert!(format_report("network", "   ", "m", "i", None).is_none());

        let mut buf = Vec::new();
        report_to(&mut buf, "direct", "usb://hp/lj", "HP", "HP USB", None).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "direct usb://hp/lj \"HP\" \"HP USB\"\n"
        );
        // Empty class writes nothing.
        let mut buf2 = Vec::new();
        report_to(&mut buf2, "", "usb://hp/lj", "HP", "HP USB", None).unwrap();
        assert_eq!(buf2, [] as [u8; 0]);
    }

    #[test]
    fn uri_credential_redaction() {
        assert_eq!(
            redact_uri("ipp://alice:s3cr3t@printer.local:631/ipp/print"),
            "ipp://***@printer.local:631/ipp/print"
        );
        assert_eq!(
            redact_uri("ipps://user:p@ss:word@192.168.1.5/ipp/print?a=b"),
            "ipps://***@192.168.1.5/ipp/print?a=b"
        );
        assert_eq!(
            redact_uri("ipp://printer.local:631/printers/user@dept"),
            "ipp://printer.local:631/printers/user@dept"
        );
        assert_eq!(redact_uri("socket://[::1]:9100"), "socket://[::1]:9100");
        assert_eq!(redact_uri("not-a-uri"), "not-a-uri");
    }

    #[test]
    fn percent_codec_roundtrip() {
        let raw = "HP OfficeJet Pro 9010 (café)/100%";
        let enc = percent_encode(raw);
        assert!(!enc.contains(' '));
        assert!(!enc.contains('/'));
        assert_eq!(percent_decode(&enc), raw);
        // Invalid percent sequences preserved literally.
        assert_eq!(percent_decode("a%ZZb%2"), "a%ZZb%2");
        assert_eq!(percent_decode("%61%62%63%41%46"), "abcAF");
    }

    #[test]
    fn network_uri_parsing_and_rejection() {
        let u = NetworkUri::parse("ipps://alice:p%40ss@[::1]:631/ipp/print?waitjob=false", 631)
            .unwrap();
        assert_eq!(u.scheme, "ipps");
        assert_eq!(u.username.as_deref(), Some("alice"));
        assert_eq!(u.password.as_deref(), Some("p@ss"));
        assert_eq!(u.host, "::1");
        assert_eq!(u.port, 631);
        assert_eq!(u.path, "/ipp/print");
        assert_eq!(u.query.as_deref(), Some("waitjob=false"));
        assert_eq!(u.host_port(), "[::1]:631");
        assert_eq!(u.clean_uri(None), "ipps://[::1]:631/ipp/print");
        assert_eq!(u.clean_uri(Some("ipp")), "ipp://[::1]:631/ipp/print");

        // Default port & user-only userinfo & root path.
        let u2 = NetworkUri::parse("http://bob@printer.example", 80).unwrap();
        assert_eq!(u2.username.as_deref(), Some("bob"));
        assert_eq!(u2.password, None);
        assert_eq!(u2.host, "printer.example");
        assert_eq!(u2.port, 80);
        assert_eq!(u2.path, "/");

        // IPv6 with default port.
        let u3 = NetworkUri::parse("socket://[2001:db8::1]", 9100).unwrap();
        assert_eq!(u3.host, "2001:db8::1");
        assert_eq!(u3.port, 9100);
        assert_eq!(u3.host_port(), "[2001:db8::1]:9100");

        // Reject CRLF, NUL, port 0, bad brackets, unbracketed IPv6, empty host, bad scheme.
        for bad in [
            "ipp://host:631/ipp\r\nX-Inject: 1",
            "ipp://host\n/ipp",
            "ipp://host:0/ipp",
            "ipp://:631/ipp",
            "ipp://[::1:631/ipp",
            "ipp://::1/ipp",
            "ipp://[not-ipv6]/ipp",
            "ipp://host]/ipp",
            "ipp://host:abc/ipp",
            "ipp://host/bad path",
            "://host/ipp",
            "bad scheme://host/ipp",
            "ipp://host :631/ipp",
        ] {
            assert!(
                NetworkUri::parse(bad, 631).is_none(),
                "expected reject: {bad}"
            );
        }
        assert!(NetworkUri::parse("ipp://host/p", 0).is_none());
    }

    #[test]
    fn ssrf_policy_blocks_metadata_and_controls_loopback() {
        let strict = SsrfPolicy::from_env_value(None);
        assert!(!strict.allow_loopback);
        let allow_lo = SsrfPolicy::from_env_value(Some("yes"));
        assert!(allow_lo.allow_loopback);
        assert!(SsrfPolicy::from_env_value(Some("1")).allow_loopback);
        assert!(SsrfPolicy::from_env_value(Some("true")).allow_loopback);
        assert!(SsrfPolicy::from_env_value(Some("on")).allow_loopback);
        assert!(!SsrfPolicy::from_env_value(Some("no")).allow_loopback);
        assert!(!SsrfPolicy::from_env_value(Some("false")).allow_loopback);
        assert!(!SsrfPolicy::from_env_value(Some("0")).allow_loopback);
        assert!(!SsrfPolicy::from_env_value(Some("off")).allow_loopback);
        assert!(!SsrfPolicy::from_env_value(Some("bogus")).allow_loopback);

        // Always blocked even with allow_loopback=true.
        for ip_str in [
            "169.254.169.254",
            "169.254.170.2",
            "100.100.100.200",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.251",
            "::",
            "fd00:ec2::254",
            "fe80::1",
            "fe80::a9fe:a9fe",
            "ff02::fb",
            "::ffff:169.254.169.254",
            "::ffff:0.0.0.0",
        ] {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(strict.check_ip(ip).is_err(), "strict must block {ip_str}");
            assert!(
                allow_lo.check_ip(ip).is_err(),
                "allow_lo must block {ip_str}"
            );
        }

        // Loopback blocked by default, allowed with opt-in.
        for lo in ["127.0.0.1", "127.0.1.1", "::1", "::ffff:127.0.0.1"] {
            let ip: IpAddr = lo.parse().unwrap();
            assert!(strict.check_ip(ip).is_err(), "strict must block {lo}");
            assert!(allow_lo.check_ip(ip).is_ok(), "allow_lo must allow {lo}");
        }

        // Legitimate LAN and global printer IPs allowed by both.
        for ok in [
            "192.168.1.50",
            "10.20.30.40",
            "172.16.0.5",
            "fd12:3456::10",
            "2001:db8::5",
        ] {
            let ip: IpAddr = ok.parse().unwrap();
            assert!(strict.check_ip(ip).is_ok(), "strict must allow {ok}");
        }

        // Port 0 rejected.
        let addr0: SocketAddr = "192.168.1.50:0".parse().unwrap();
        assert!(strict.check_socket_addr(addr0).is_err());
        assert!(strict.resolve_checked("192.168.1.50", 0).is_err());
        assert!(strict.resolve_checked("", 631).is_err());
        assert!(strict.resolve_checked("bad\nhost", 631).is_err());
    }

    #[test]
    fn ssrf_connect_checked_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let strict = SsrfPolicy {
            allow_loopback: false,
        };
        assert_eq!(
            strict
                .connect_checked("127.0.0.1", port, Duration::from_secs(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        let allow = SsrfPolicy {
            allow_loopback: true,
        };
        let (stream, addr) = allow
            .connect_checked("127.0.0.1", port, Duration::from_secs(1))
            .unwrap();
        assert_eq!(addr.port(), port);
        drop(stream);
        let _ = SsrfPolicy::from_env();
    }

    #[test]
    fn char_device_validation() {
        // /dev/null is a real char device under /dev/.
        let f = open_char_device("/dev/null", true, true, true).unwrap();
        drop(f);

        // Traversal and relative paths rejected.
        assert!(open_char_device("/dev/../etc/passwd", true, false, false).is_err());
        assert!(open_char_device("dev/null", true, false, false).is_err());
        assert!(open_char_device("", true, false, false).is_err());
        assert!(open_char_device("/dev/null\0x", true, false, false).is_err());

        // Non-/dev regular file rejected.
        let dir = env::temp_dir().join(format!("pw-bc-dev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let regular = dir.join("regular");
        std::fs::write(&regular, b"x").unwrap();
        assert!(open_char_device(&regular.to_string_lossy(), true, true, false).is_err());

        // Symlink outside /dev pointing to regular file rejected.
        #[cfg(unix)]
        {
            let link = dir.join("link");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(&regular, &link).unwrap();
            assert!(open_char_device(&link.to_string_lossy(), true, true, false).is_err());
        }

        // Prefix without trailing slash also works for custom prefixes.
        let ok = open_char_device_with_prefixes("/dev/null", &["/dev/null"], true, true, false);
        assert!(ok.is_ok());

        // /dev/shm (directory) or file inside /dev/shm if writable is not a char device.
        if Path::new("/dev/shm").is_dir() {
            let shm_file =
                Path::new("/dev/shm").join(format!("pw-bc-nonchr-{}", std::process::id()));
            if std::fs::write(&shm_file, b"test").is_ok() {
                let err =
                    open_char_device(&shm_file.to_string_lossy(), true, true, false).unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
                let _ = std::fs::remove_file(&shm_file);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stderr_helpers_and_report_smoke() {
        let mut buf = Vec::new();
        emit_line(&mut buf, "STATE", "+connecting\r\nfake");
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "STATE: +connecting  fake\n"
        );
        debug(format_args!("d"));
        info(format_args!("i"));
        warn(format_args!("w"));
        error(format_args!("e"));
        state("-connecting");
        page(1, 1);
        attr("auth-info-required", "username,password");
        report("network", "ipp", "Unknown", "IPP", None);
    }
}
