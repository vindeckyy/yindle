//! Hardened asynchronous Web UI CGI/1.1 passthrough (`scheduler/client.c`
//! `cupsdSendCommand` / RFC 3875).
//!
//! Security & reliability hardening:
//! - Safe header separator lookup (zero OOB slice panic on trailing `\n\n`).
//! - `env_clear()` + explicit RFC 3875 allowlist (never inherits daemon env).
//! - Strips `HTTP_PROXY` (`HTTPoxy`), `HTTP_AUTHORIZATION`, `HTTP_PROXY_AUTHORIZATION`,
//!   and hop-by-hop headers before exporting `HTTP_*`.
//! - Never splits attacker-controlled URL paths into process `argv`.
//! - Runs asynchronously via `tokio::process::Command` with concurrent stdin
//!   write and bounded stdout read, eliminating >64 KiB pipe deadlocks.
//! - Canonicalizes and validates CGI executables inside `{ServerBin}/cgi-bin`.

use std::io;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use cups_config::Config;
use httpd::{Method, Request, Response, StatusCode};
use pipeline::{
    build_cups_exec_args, current_euid_egid, resolve_trusted_executable, sandbox_profile_name,
    validate_stage_privilege_drop, SecurityPolicy, SpawnOptions,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// Safe baseline `PATH` for CGI scripts.
const SAFE_CGI_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/bin:/bin";

/// Maximum captured stdout bytes from a CGI script (16 MiB).
pub const MAX_CGI_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Default execution timeout for a CGI script (30s).
pub const DEFAULT_CGI_TIMEOUT: Duration = Duration::from_secs(30);

/// Map a request URI to its CGI binary name and RFC 3875 `PATH_INFO` tail.
/// Returns `None` when the URI is not a CGI route.
#[must_use]
pub fn map_uri(uri: &str) -> Option<(&'static str, &str)> {
    let path_only = uri.split(['?', '#']).next().unwrap_or(uri);
    let (prefix, script) = if path_only == "/" {
        ("", "home.cgi")
    } else if let Some(rest) = strip_segment(path_only, "/admin") {
        (rest, "admin.cgi")
    } else if let Some(rest) = strip_segment(path_only, "/classes") {
        (rest, "classes.cgi")
    } else if let Some(rest) = strip_segment(path_only, "/jobs") {
        (rest, "jobs.cgi")
    } else if let Some(rest) = strip_segment(path_only, "/printers") {
        (rest, "printers.cgi")
    } else {
        (strip_segment(path_only, "/help")?, "help.cgi")
    };
    let path_info = prefix.strip_prefix('/').unwrap_or(prefix);
    Some((script, path_info))
}

fn strip_segment<'a>(path: &'a str, base: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(base)?;
    if rest.is_empty() || rest.starts_with('/') {
        Some(rest)
    } else {
        None
    }
}

/// The `{ServerBin}/cgi-bin` directory.
#[must_use]
pub fn cgi_root(server_bin: &Path) -> PathBuf {
    server_bin.join("cgi-bin")
}

/// Resolve and safety-check a CGI executable strictly inside `{ServerBin}/cgi-bin`.
#[must_use]
pub fn resolve_cgi_binary(server_bin: &Path, script: &str) -> Option<PathBuf> {
    if script.is_empty() || script.contains(['/', '\\', '\0']) || script.contains("..") {
        return None;
    }
    let root = std::fs::canonicalize(cgi_root(server_bin)).ok()?;
    let candidate = root.join(script);
    let canon = std::fs::canonicalize(&candidate).ok()?;
    if !canon.starts_with(&root) {
        return None;
    }
    let meta = std::fs::metadata(&canon).ok()?;
    let mode = meta.permissions().mode();
    if !meta.is_file() || (mode & 0o111) == 0 || (mode & 0o002) != 0 || (mode & 0o6000) != 0 {
        return None;
    }
    Some(canon)
}

/// Metadata passed into CGI execution.
pub struct CgiContext<'a> {
    pub server_bin: &'a Path,
    pub server_root: &'a Path,
    pub cfg: &'a Config,
    pub client_addr: IpAddr,
    pub server_name: &'a str,
    pub port: u16,
    pub encrypted: bool,
    pub remote_user: Option<&'a str>,
    pub auth_type: Option<&'a str>,
    pub timeout: Duration,
}

/// Build the sanitized RFC 3875 CGI/1.1 environment (starting from `env_clear()`).
#[must_use]
pub fn build_cgi_env(
    script: &str,
    path_info: &str,
    req: &Request,
    body_len: usize,
    ctx: &CgiContext<'_>,
) -> Vec<(String, String)> {
    let query_string = req
        .uri
        .split_once('?')
        .map_or("", |(_, q)| q.split('#').next().unwrap_or(q));

    let mut env = vec![
        ("PATH".into(), SAFE_CGI_PATH.into()),
        ("GATEWAY_INTERFACE".into(), "CGI/1.1".into()),
        (
            "SERVER_SOFTWARE".into(),
            ctx.cfg.cupsd.server_header.clone(),
        ),
        ("SERVER_NAME".into(), sanitize_env(ctx.server_name)),
        ("SERVER_PORT".into(), ctx.port.to_string()),
        ("SERVER_PROTOCOL".into(), "HTTP/1.1".into()),
        ("REQUEST_METHOD".into(), req.method.as_str().into()),
        ("SCRIPT_NAME".into(), format!("/cgi-bin/{script}")),
        ("PATH_INFO".into(), sanitize_env(path_info)),
        ("QUERY_STRING".into(), sanitize_env(query_string)),
        ("REMOTE_ADDR".into(), ctx.client_addr.to_string()),
        (
            "REMOTE_USER".into(),
            sanitize_env(ctx.remote_user.unwrap_or("")),
        ),
        (
            "AUTH_TYPE".into(),
            sanitize_env(ctx.auth_type.unwrap_or("")),
        ),
        (
            "CUPS_SERVERROOT".into(),
            ctx.server_root.to_string_lossy().into_owned(),
        ),
    ];

    if let Some(ref data_dir) = ctx.cfg.files.data_dir {
        env.push(("CUPS_DATADIR".into(), sanitize_env(data_dir)));
    }
    if let Some(ref req_root) = ctx.cfg.files.request_root {
        env.push(("CUPS_REQUESTROOT".into(), sanitize_env(req_root)));
    }
    if let Some(ref cache_dir) = ctx.cfg.files.cache_dir {
        env.push(("CUPS_CACHEDIR".into(), sanitize_env(cache_dir)));
    }
    if let Some(ref state_dir) = ctx.cfg.files.state_dir {
        env.push(("CUPS_STATEDIR".into(), sanitize_env(state_dir)));
    }
    if let Some(ref temp_dir) = ctx.cfg.files.temp_dir {
        env.push(("TMPDIR".into(), sanitize_env(temp_dir)));
    }
    if ctx.encrypted {
        env.push(("HTTPS".into(), "on".into()));
    }
    if let Some(ct) = req.content_type() {
        env.push(("CONTENT_TYPE".into(), sanitize_env(ct)));
    }
    if body_len > 0 {
        env.push(("CONTENT_LENGTH".into(), body_len.to_string()));
    }

    for (name, value) in req.headers.iter() {
        if is_stripped_cgi_header(name) {
            continue;
        }
        let mut key = String::with_capacity(5 + name.len());
        key.push_str("HTTP_");
        let mut valid = true;
        for c in name.chars() {
            if c == '-' {
                key.push('_');
            } else if c.is_ascii_alphanumeric() || c == '_' {
                key.push(c.to_ascii_uppercase());
            } else {
                valid = false;
                break;
            }
        }
        if valid && !key.eq_ignore_ascii_case("HTTP_PROXY") {
            env.push((key, sanitize_env(value)));
        }
    }

    env
}

/// Headers that MUST NOT be forwarded to CGI scripts as `HTTP_*`.
fn is_stripped_cgi_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("proxy")
        || name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("content-type")
}

fn sanitize_env(val: &str) -> String {
    val.chars()
        .filter(|c| !matches!(c, '\0' | '\r' | '\n'))
        .collect()
}

/// Prepare the `(program, args)` launch tuple for a CGI binary, enforcing strict
/// executable checks and mandatory `cups-exec` privilege drop whenever `eff_uid == 0`.
///
/// - When `eff_uid == 0`: verifies the CGI binary under `policy` (root-owned,
///   non-group/world-writable in production via [`SecurityPolicy::strict`]),
///   refuses to execute as target `uid == 0`, resolves & verifies `cups-exec`,
///   and returns `(cups_exec, build_cups_exec_args(...))`.
/// - When `eff_uid != 0`: validates the CGI binary inside `{ServerBin}/cgi-bin`
///   and returns direct execution `(bin, [])`.
pub fn build_cgi_command_for_ids(
    server_bin: &Path,
    script: &str,
    cfg: &Config,
    eff_uid: u32,
    policy: &SecurityPolicy,
) -> io::Result<(PathBuf, Vec<String>)> {
    if eff_uid == 0 {
        let bin = resolve_trusted_executable(&cgi_root(server_bin), script, policy)?;
        let opts = SpawnOptions::from_cups_config(cfg);
        let target_uid = opts.sandbox.uid.unwrap_or(0);
        if target_uid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refusing to execute CGI binary as uid 0 (root)",
            ));
        }

        let exec_candidate = server_bin.join("daemon").join("cups-exec");
        let exec_parent = exec_candidate.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cups-exec path has no parent directory",
            )
        })?;
        let exec_name = exec_candidate
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "invalid cups-exec filename",
                )
            })?;
        let cups_exec =
            resolve_trusted_executable(exec_parent, exec_name, policy).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("root CGI privilege drop requires trusted cups-exec: {e}"),
                )
            })?;

        validate_stage_privilege_drop(0, false, &opts.sandbox, true)?;

        let profile = sandbox_profile_name(opts.sandbox.mode, false);
        let group_id = opts.sandbox.gid.unwrap_or(cfg.files.group);
        let bin_str = bin.to_string_lossy();
        let args = build_cups_exec_args(
            profile,
            target_uid,
            group_id,
            opts.sandbox.nice,
            &bin,
            &bin_str,
            &[],
        );
        return Ok((cups_exec, args));
    }

    let bin = resolve_cgi_binary(server_bin, script)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "CGI binary not available"))?;
    Ok((bin, Vec::new()))
}

/// Run a CGI binary asynchronously with concurrent stdin writing and bounded
/// stdout reading (eliminating >64 KiB pipe deadlocks).
pub async fn run_async(
    script: &str,
    path_info: &str,
    req: &Request,
    body: &[u8],
    ctx: &CgiContext<'_>,
) -> Option<Response> {
    let (eff_uid, _) = current_euid_egid();
    let (program, args) = match build_cgi_command_for_ids(
        ctx.server_bin,
        script,
        ctx.cfg,
        eff_uid,
        &SecurityPolicy::strict(),
    ) {
        Ok(pair) => pair,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(_) => return Some(Response::status(StatusCode::FORBIDDEN).with_security_headers()),
    };
    let env_vars = build_cgi_env(script, path_info, req, body.len(), ctx);

    let mut cmd = Command::new(&program);
    cmd.args(&args)
        .env_clear()
        .envs(env_vars)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let mut child = cmd.spawn().ok()?;
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take();

    let run_io = async {
        let write_fut = async {
            if let Some(mut s_in) = stdin.take() {
                if !body.is_empty() {
                    let _ = s_in.write_all(body).await;
                }
                let _ = s_in.shutdown().await;
            }
        };

        let read_fut = async {
            let mut buf = Vec::new();
            if let Some(s_out) = stdout.take() {
                let mut limited = s_out.take((MAX_CGI_OUTPUT_BYTES + 1) as u64);
                let _ = limited.read_to_end(&mut buf).await;
            }
            buf
        };

        let ((), output_bytes) = tokio::join!(write_fut, read_fut);
        let _ = child.wait().await;
        output_bytes
    };

    let Ok(bytes) = tokio::time::timeout(ctx.timeout, run_io).await else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Some(Response::status(StatusCode(504)).with_security_headers());
    };
    if bytes.len() > MAX_CGI_OUTPUT_BYTES {
        Some(Response::status(StatusCode(502)).with_security_headers())
    } else {
        Some(parse_output(&bytes))
    }
}

/// Safely split CGI stdout into headers and body, translating `Status:`,
/// `Content-Type:`, and `Location:` into an HTTP [`Response`] with security headers.
///
/// Safe on all inputs (including trailing `\n\n` with zero following bytes).
#[must_use]
pub fn parse_output(bytes: &[u8]) -> Response {
    let crlf_pos = bytes.windows(4).position(|w| w == b"\r\n\r\n");
    let lf_pos = bytes.windows(2).position(|w| w == b"\n\n");

    let (head, body) = match (crlf_pos, lf_pos) {
        (Some(c), Some(l)) => {
            if c <= l {
                (&bytes[..c], &bytes[c + 4..])
            } else {
                (&bytes[..l], &bytes[l + 2..])
            }
        }
        (Some(c), None) => (&bytes[..c], &bytes[c + 4..]),
        (None, Some(l)) => (&bytes[..l], &bytes[l + 2..]),
        (None, None) => (bytes, &[][..]),
    };

    let mut status = 200u16;
    let mut ctype = "text/html; charset=utf-8".to_string();
    let mut location: Option<String> = None;
    let mut extra_headers: Vec<(String, String)> = Vec::new();

    for raw_line in String::from_utf8_lossy(head).lines() {
        let line = raw_line.trim_end_matches('\r');
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let val = val.trim();
        if name.eq_ignore_ascii_case("status") {
            status = val
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<u16>().ok())
                .filter(|&c| (100..600).contains(&c))
                .unwrap_or(200);
        } else if name.eq_ignore_ascii_case("content-type") {
            if !val.is_empty() {
                ctype = val.to_string();
            }
        } else if name.eq_ignore_ascii_case("location") {
            if !val.is_empty() {
                location = Some(val.to_string());
            }
        } else if name.eq_ignore_ascii_case("cache-control")
            || name.eq_ignore_ascii_case("set-cookie")
            || name.eq_ignore_ascii_case("content-disposition")
        {
            extra_headers.push((name.to_string(), val.to_string()));
        }
    }

    let mut resp = Response::with_body(StatusCode(status), &ctype, body.to_vec());
    for (k, v) in extra_headers {
        resp.headers.push(&k, v);
    }
    if let Some(loc) = location {
        resp.headers.set("Location", loc);
        if status == 200 {
            resp.status = StatusCode(302);
        }
    }
    resp.with_security_headers()
}

/// Route a GET/HEAD/POST to a CGI script when it maps and the binary exists.
pub async fn dispatch_async(req: &Request, body: &[u8], ctx: &CgiContext<'_>) -> Option<Response> {
    let (script, path_info) = map_uri(&req.uri)?;
    if req.method == Method::Post && script == "home.cgi" {
        return None;
    }
    run_async(script, path_info, req, body, ctx).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpd::{Body, Headers, HttpVersion};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_dir(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "yindle-cupsd-cgi-{}-{tag}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn make_req(method: Method, uri: &str) -> Request {
        let mut headers = Headers::new();
        headers.set("Host", "localhost:631");
        headers.set("Proxy", "http://evil.attacker:8080");
        headers.set("Authorization", "Basic c2VjcmV0OnBhc3M=");
        headers.set("Proxy-Authorization", "Basic secret");
        headers.set("X-Custom-Header", "safe-val");
        headers.set("Content-Type", "application/x-www-form-urlencoded");
        Request {
            method,
            method_token: method.as_str().into(),
            uri: uri.into(),
            version: HttpVersion::V11,
            headers,
            body: Body::Empty,
            keep_alive: true,
            wants_tls_upgrade: false,
        }
    }

    #[test]
    fn map_uri_respects_segment_boundaries() {
        assert_eq!(map_uri("/"), Some(("home.cgi", "")));
        assert_eq!(map_uri("/?a=1"), Some(("home.cgi", "")));
        assert_eq!(map_uri("/admin"), Some(("admin.cgi", "")));
        assert_eq!(
            map_uri("/admin/log/error_log"),
            Some(("admin.cgi", "log/error_log"))
        );
        assert_eq!(map_uri("/administer"), None);
        assert_eq!(
            map_uri("/printers/laser1"),
            Some(("printers.cgi", "laser1"))
        );
        assert_eq!(map_uri("/classes/pool"), Some(("classes.cgi", "pool")));
        assert_eq!(map_uri("/jobs?which=all"), Some(("jobs.cgi", "")));
        assert_eq!(
            map_uri("/help/overview.html"),
            Some(("help.cgi", "overview.html"))
        );
        assert_eq!(map_uri("/healthz"), None);
    }

    #[test]
    fn parse_output_never_panics_on_trailing_lflf_and_handles_headers() {
        // Previously panicked with OOB `&bytes[i..i+4]`!
        let r_edge = parse_output(b"Content-Type: text/plain\n\n");
        assert_eq!(r_edge.status, StatusCode::OK);
        assert_eq!(r_edge.headers.get("content-type"), Some("text/plain"));
        assert_eq!(r_edge.body, Vec::<u8>::new());
        assert_eq!(
            r_edge.headers.get("x-content-type-options"),
            Some("nosniff")
        );
        assert_eq!(r_edge.headers.get("x-frame-options"), Some("DENY"));

        // CRLF + Status + Cache-Control + body
        let r_crlf = parse_output(
            b"Status: 201 Created\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\n\r\nhello",
        );
        assert_eq!(r_crlf.status, StatusCode::CREATED);
        assert_eq!(r_crlf.headers.get("cache-control"), Some("no-store"));
        assert_eq!(r_crlf.body, b"hello");

        // LF separator occurring before CRLF in body picks LF
        let r_mixed = parse_output(b"Content-Type: text/plain\n\nbody\r\n\r\nmore");
        assert_eq!(r_mixed.body, b"body\r\n\r\nmore");

        // Location implies 302
        let r_redir = parse_output(b"Location: /printers\r\n\r\n");
        assert_eq!(r_redir.status, StatusCode(302));
        assert_eq!(r_redir.headers.get("location"), Some("/printers"));

        // No separator at all
        let r_bare = parse_output(b"Status: 404 Not Found\n");
        assert_eq!(r_bare.status, StatusCode::NOT_FOUND);
        assert_eq!(r_bare.body, Vec::<u8>::new());
    }

    #[test]
    fn cgi_env_strips_httpoxy_and_authorization() {
        let mut cfg = Config {
            cupsd: cups_config::CupsdConfig::defaults(),
            files: cups_config::CupsFilesConfig::defaults(),
        };
        cfg.files.temp_dir = Some("/tmp".into());
        let req = make_req(Method::Post, "/admin/foo?x=1#frag");
        let ctx = CgiContext {
            server_bin: Path::new("/usr/lib/cups"),
            server_root: Path::new("/etc/cups"),
            cfg: &cfg,
            client_addr: "127.0.0.1".parse().unwrap(),
            server_name: "print.local",
            port: 631,
            encrypted: true,
            remote_user: Some("admin"),
            auth_type: Some("Basic"),
            timeout: DEFAULT_CGI_TIMEOUT,
        };
        let env = build_cgi_env("admin.cgi", "foo", &req, 12, &ctx);
        assert!(env.iter().any(|(k, v)| k == "HTTPS" && v == "on"));
        assert!(env.iter().any(|(k, v)| k == "REMOTE_USER" && v == "admin"));
        assert!(env.iter().any(|(k, v)| k == "QUERY_STRING" && v == "x=1"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "HTTP_X_CUSTOM_HEADER" && v == "safe-val"));
        assert!(!env.iter().any(|(k, _)| k == "HTTP_PROXY"));
        assert!(!env.iter().any(|(k, _)| k == "HTTP_AUTHORIZATION"));
        assert!(!env.iter().any(|(k, _)| k == "HTTP_PROXY_AUTHORIZATION"));
    }

    #[tokio::test]
    async fn async_cgi_handles_large_body_without_pipe_deadlock_and_no_argv_injection() {
        let dir = tmp_dir("exec");
        let cgidir = dir.join("cgi-bin");
        std::fs::create_dir_all(&cgidir).unwrap();

        // Script echoes argv count + env check + stdin verbatim (>128 KiB to prove no pipe deadlock!)
        let script_path = cgidir.join("admin.cgi");
        std::fs::write(
            &script_path,
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\nX-Argc: %d\\r\\n\\r\\nargc=%d proxy=%s auth=%s\\n' \"$#\" \"$#\" \"${HTTP_PROXY:-}\" \"${HTTP_AUTHORIZATION:-}\"\ncat\n",
        )
        .unwrap();
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Slow script to verify timeout handling
        let slow_path = cgidir.join("jobs.cgi");
        std::fs::write(&slow_path, "#!/bin/sh\nsleep 5\n").unwrap();
        std::fs::set_permissions(&slow_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        // World-writable script must be rejected
        let bad_path = cgidir.join("help.cgi");
        std::fs::write(&bad_path, "#!/bin/sh\necho ok\n").unwrap();
        std::fs::set_permissions(&bad_path, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(resolve_cgi_binary(&dir, "help.cgi").is_none());
        assert!(resolve_cgi_binary(&dir, "../escape").is_none());

        let cfg = Config {
            cupsd: cups_config::CupsdConfig::defaults(),
            files: cups_config::CupsFilesConfig::defaults(),
        };
        let ctx = CgiContext {
            server_bin: &dir,
            server_root: &dir,
            cfg: &cfg,
            client_addr: "127.0.0.1".parse().unwrap(),
            server_name: "localhost",
            port: 631,
            encrypted: false,
            remote_user: Some("alice"),
            auth_type: Some("Basic"),
            timeout: Duration::from_secs(5),
        };

        // Attacker attempts whitespace argv splitting in URI + sends 150 KiB body (>64 KiB pipe buf!)
        let req = make_req(Method::Post, "/admin/--flag%20injected%20arg");
        let large_body = vec![b'A'; 150 * 1024];
        let resp = dispatch_async(&req, &large_body, &ctx).await.unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        let text = String::from_utf8(resp.body).unwrap();
        assert!(text.starts_with("argc=0 proxy= auth=\n"));
        assert_eq!(text.len(), "argc=0 proxy= auth=\n".len() + large_body.len());

        // POST to home.cgi returns None
        let home_post = make_req(Method::Post, "/");
        assert!(dispatch_async(&home_post, b"", &ctx).await.is_none());

        // Timeout test
        let short_ctx = CgiContext {
            timeout: Duration::from_millis(120),
            ..ctx
        };
        let slow_req = make_req(Method::Get, "/jobs");
        let slow_resp = dispatch_async(&slow_req, b"", &short_ctx).await.unwrap();
        assert_eq!(slow_resp.status, StatusCode(504));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn root_cgi_enforces_strict_checks_and_cups_exec_privilege_drop() {
        let dir = tmp_dir("root_privdrop");
        let cgidir = dir.join("cgi-bin");
        let daemondir = dir.join("daemon");
        std::fs::create_dir_all(&cgidir).unwrap();
        std::fs::create_dir_all(&daemondir).unwrap();

        let script = cgidir.join("admin.cgi");
        std::fs::write(&script, "#!/bin/sh\necho ok\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut cfg = Config {
            cupsd: cups_config::CupsdConfig::defaults(),
            files: cups_config::CupsFilesConfig::defaults(),
        };
        cfg.files.server_bin = Some(dir.to_string_lossy().into_owned());
        cfg.files.user = 631;
        cfg.files.group = 631;

        // 1. Under `SecurityPolicy::strict()`, non-root-owned or group-writable CGI is rejected!
        let (cur_uid, _) = current_euid_egid();
        if cur_uid != 0 {
            let err =
                build_cgi_command_for_ids(&dir, "admin.cgi", &cfg, 0, &SecurityPolicy::strict())
                    .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        }
        // Group-writable CGI rejected even under `for_current_process()`!
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o775)).unwrap();
        let err_gw = build_cgi_command_for_ids(
            &dir,
            "admin.cgi",
            &cfg,
            0,
            &SecurityPolicy::for_current_process(),
        )
        .unwrap_err();
        assert_eq!(err_gw.kind(), io::ErrorKind::PermissionDenied);
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        // 2. Target uid == 0 is ALWAYS refused when running as root (fail-closed!).
        let mut root_cfg = cfg.clone();
        root_cfg.files.user = 0;
        let err_root = build_cgi_command_for_ids(
            &dir,
            "admin.cgi",
            &root_cfg,
            0,
            &SecurityPolicy::for_current_process(),
        )
        .unwrap_err();
        assert_eq!(err_root.kind(), io::ErrorKind::PermissionDenied);

        // 3. Missing `cups-exec` fails closed with PermissionDenied (never executes CGI as root!).
        let err_no_exec = build_cgi_command_for_ids(
            &dir,
            "admin.cgi",
            &cfg,
            0,
            &SecurityPolicy::for_current_process(),
        )
        .unwrap_err();
        assert_eq!(err_no_exec.kind(), io::ErrorKind::PermissionDenied);

        // 4. Missing CGI script returns NotFound (so non-CGI routes can fall through to static/UI).
        let err_missing = build_cgi_command_for_ids(
            &dir,
            "jobs.cgi",
            &cfg,
            0,
            &SecurityPolicy::for_current_process(),
        )
        .unwrap_err();
        assert_eq!(err_missing.kind(), io::ErrorKind::NotFound);

        // 5. With trusted `cups-exec` present, root CGI wraps execution through `cups-exec`!
        let cups_exec = daemondir.join("cups-exec");
        std::fs::write(&cups_exec, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&cups_exec, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (prog, args) = build_cgi_command_for_ids(
            &dir,
            "admin.cgi",
            &cfg,
            0,
            &SecurityPolicy::for_current_process(),
        )
        .unwrap();
        assert_eq!(prog, std::fs::canonicalize(&cups_exec).unwrap());
        assert_eq!(args[1], "631");
        assert_eq!(args[2], "631");
        assert_eq!(
            args[4],
            std::fs::canonicalize(&script).unwrap().to_string_lossy()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
