//! Hardened async static file server and built-in read-only HTML status Web UI.
//!
//! Security hardening:
//! - Canonical containment inside `DocumentRoot` (rejects symlinks escaping root,
//!   `..` segments, NUL/backslash/control characters).
//! - Rejects non-regular files (directories, FIFOs, sockets, devices) and files
//!   exceeding [`MAX_STATIC_FILE_BYTES`].
//! - Reads asynchronously (`tokio::fs`) so static assets never stall worker threads.
//! - Attaches `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
//!   `Referrer-Policy: no-referrer`, and `Content-Security-Policy` to every response.
//! - Built-in HTML fallback for `/`, `/printers`, `/classes`, and `/jobs` uses
//!   strict XSS-safe HTML entity escaping and redacts `device-uri` credentials.

use std::fmt::Write as _;
use std::io::Read as _;
use std::path::Path;
use std::sync::RwLock;

use cups_config::Config;
use httpd::{Response, StatusCode};
use job::Jobs;
use printer::{pstate, redact_device_uri, Registry};

use crate::cli::VERSION;
use crate::metrics::Metrics;

/// Maximum static asset size served from `DocumentRoot` (16 MiB).
pub const MAX_STATIC_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Default `JobPrivateValues` list when a policy specifies `default`.
const DEFAULT_JOB_PRIVATE_VALUES: &[&str] = &[
    "job-name",
    "job-originating-host-name",
    "job-originating-user-name",
    "phone",
];

/// Core identifying job attributes retained even under `JobPrivateValues all`.
const CORE_PUBLIC_JOB_ATTRS: &[&str] = &[
    "job-id",
    "job-uri",
    "job-printer-uri",
    "job-state",
    "job-state-reasons",
    "job-printer-up-time",
];

/// Serve a static asset asynchronously from `doc_root` with canonical containment,
/// `O_NOFOLLOW` TOCTOU-free fd validation, regular-file enforcement, bounded read,
/// and HTTP security headers.
pub async fn static_get_async(uri: &str, doc_root: &Path) -> Response {
    let path_part = uri.split(['?', '#']).next().unwrap_or("/");
    if !path_part.starts_with('/')
        || path_part.contains("..")
        || path_part.contains('\\')
        || path_part.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return Response::status(StatusCode::FORBIDDEN).with_security_headers();
    }

    let Ok(canon_root) = tokio::fs::canonicalize(doc_root).await else {
        return Response::status(StatusCode::NOT_FOUND).with_security_headers();
    };

    let rel = path_part.trim_start_matches('/');
    let rel_target = if rel.is_empty() { "index.html" } else { rel };
    let candidate = canon_root.join(rel_target);

    let canon_file = match tokio::fs::canonicalize(&candidate).await {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Response::status(StatusCode::NOT_FOUND).with_security_headers();
        }
        Err(_) => return Response::status(StatusCode::FORBIDDEN).with_security_headers(),
    };

    if !canon_file.starts_with(&canon_root) {
        return Response::status(StatusCode::FORBIDDEN).with_security_headers();
    }

    let path_for_read = canon_file.clone();
    let read_res = tokio::task::spawn_blocking(move || read_static_file_nofol(&path_for_read))
        .await
        .unwrap_or(Err(StatusCode::INTERNAL));

    match read_res {
        Ok(bytes) => Response::with_body(StatusCode::OK, mime_guess(&canon_file), bytes)
            .with_security_headers(),
        Err(code) => Response::status(code).with_security_headers(),
    }
}

fn read_static_file_nofol(canon_file: &Path) -> Result<Vec<u8>, StatusCode> {
    let file = match sys::open_readonly_nofollow(canon_file) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::FORBIDDEN),
    };
    let Ok(meta) = file.metadata() else {
        return Err(StatusCode::FORBIDDEN);
    };
    if !meta.is_file() {
        return Err(StatusCode::FORBIDDEN);
    }
    if meta.len() > MAX_STATIC_FILE_BYTES {
        return Err(StatusCode::TOO_LARGE);
    }
    let mut buf = Vec::new();
    let mut limited = file.take(MAX_STATIC_FILE_BYTES + 1);
    if limited.read_to_end(&mut buf).is_err() {
        return Err(StatusCode::FORBIDDEN);
    }
    if buf.len() as u64 > MAX_STATIC_FILE_BYTES {
        return Err(StatusCode::TOO_LARGE);
    }
    Ok(buf)
}

/// MIME type guess for static assets served from `DocumentRoot`.
#[must_use]
pub fn mime_guess(p: &Path) -> &'static str {
    match p
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("ico") => "image/vnd.microsoft.icon",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Escape HTML special characters (`&`, `<`, `>`, `"`, `'`) to prevent XSS.
#[must_use]
pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Render the built-in read-only HTML status Web UI fallback when `WebInterface Yes`
/// and neither a CGI binary nor a static file exists in `DocumentRoot`.
///
/// Handles `/`, `/index.html`, `/printers`, `/printers/<name>`, `/classes`,
/// `/classes/<name>`, and `/jobs`. Enforces `JobPrivateAccess`/`JobPrivateValues`
/// redaction on `/jobs` matching IPP `Get-Jobs`. Returns `None` for non-UI paths.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn render_builtin_ui(
    uri: &str,
    cfg: &Config,
    registry: &RwLock<Registry>,
    jobs: &RwLock<Jobs>,
    metrics: &Metrics,
    server_name: &str,
    auth_user: Option<&str>,
    auth_groups: &[String],
) -> Option<Response> {
    let (path_raw, query) = uri.split_once('?').map_or((uri, ""), |(p, q)| (p, q));
    let path = path_raw.split('#').next().unwrap_or(path_raw);
    let trimmed = path.trim_end_matches('/');
    let norm = if trimmed.is_empty() { "/" } else { trimmed };

    let html = match norm {
        "/" | "/index.html" => render_home(registry, jobs, metrics, server_name),
        "/printers" => render_printers_list(registry, server_name, false),
        "/classes" => render_printers_list(registry, server_name, true),
        "/jobs" => render_jobs_list(
            cfg,
            registry,
            jobs,
            server_name,
            query,
            auth_user,
            auth_groups,
        ),
        other if other.starts_with("/printers/") => {
            let name = &other["/printers/".len()..];
            render_printer_detail(registry, jobs, server_name, name, false)?
        }
        other if other.starts_with("/classes/") => {
            let name = &other["/classes/".len()..];
            render_printer_detail(registry, jobs, server_name, name, true)?
        }
        _ => return None,
    };

    Some(
        Response::with_body(
            StatusCode::OK,
            "text/html; charset=utf-8",
            html.into_bytes(),
        )
        .with_security_headers(),
    )
}

fn page_shell(title: &str, server_name: &str, body: &str) -> String {
    let esc_title = escape_html(title);
    let esc_server = escape_html(server_name);
    let esc_ver = escape_html(VERSION);
    format!(
        "<!DOCTYPE html>\n\
         <html lang=\"en\">\n\
         <head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
         <title>{esc_title} - Yindle ({esc_server})</title>\n\
         </head>\n\
         <body>\n\
         <header>\n\
         <h1>Yindle Print Scheduler {esc_ver} ({esc_server})</h1>\n\
         <nav>\n\
         <a href=\"/\">Home</a> | \
         <a href=\"/printers\">Printers</a> | \
         <a href=\"/classes\">Classes</a> | \
         <a href=\"/jobs\">Jobs</a> | \
         <a href=\"/healthz\">Health</a> | \
         <a href=\"/metrics\">Metrics</a>\n\
         </nav>\n\
         </header>\n\
         <main>\n\
         {body}\n\
         </main>\n\
         </body>\n\
         </html>\n"
    )
}

fn state_label(state: i32) -> &'static str {
    match state {
        pstate::IDLE => "Idle",
        pstate::PROCESSING => "Processing",
        pstate::STOPPED => "Paused / Stopped",
        _ => "Unknown",
    }
}

fn render_home(
    registry: &RwLock<Registry>,
    jobs: &RwLock<Jobs>,
    metrics: &Metrics,
    server_name: &str,
) -> String {
    let (printer_count, class_count, default_name) = {
        let reg = registry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let classes = reg.printers.values().filter(|p| p.is_class()).count();
        let printers = reg.printers.len().saturating_sub(classes);
        (printers, classes, reg.default.clone())
    };
    let (active_jobs, total_jobs) = {
        let jg = jobs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (jg.active().count(), jg.by_id.len())
    };
    let def = default_name
        .as_deref()
        .map_or_else(|| "None".to_string(), escape_html);
    let body = format!(
        "<h2>Server Status</h2>\n\
         <ul>\n\
         <li>Printers: {printer_count}</li>\n\
         <li>Classes: {class_count}</li>\n\
         <li>Default Destination: {def}</li>\n\
         <li>Active Jobs: {active_jobs} (Total retained: {total_jobs})</li>\n\
         <li>Active Clients: {}</li>\n\
         <li>Uptime: {}s</li>\n\
         </ul>",
        metrics.active_clients(),
        metrics.uptime_seconds()
    );
    page_shell("Home", server_name, &body)
}

fn render_printers_list(
    registry: &RwLock<Registry>,
    server_name: &str,
    classes_only: bool,
) -> String {
    let heading = if classes_only { "Classes" } else { "Printers" };
    let prefix = if classes_only {
        "/classes/"
    } else {
        "/printers/"
    };
    let mut body = format!(
        "<h2>{heading}</h2>\n\
         <table>\n\
         <thead><tr><th>Name</th><th>Description</th><th>Location</th><th>Make &amp; Model</th><th>State</th></tr></thead>\n\
         <tbody>\n"
    );
    let reg = registry
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut count = 0usize;
    for p in reg.printers.values() {
        if p.is_class() != classes_only {
            continue;
        }
        count += 1;
        let esc_name = escape_html(&p.name);
        let esc_info = escape_html(p.info.as_deref().unwrap_or(""));
        let esc_loc = escape_html(p.location.as_deref().unwrap_or(""));
        let esc_mm = escape_html(p.make_model.as_deref().unwrap_or(""));
        let accepting = if p.accepting {
            "Accepting Jobs"
        } else {
            "Rejecting Jobs"
        };
        let state = state_label(p.state);
        let _ = writeln!(
            body,
            "<tr><td><a href=\"{prefix}{esc_name}\">{esc_name}</a></td><td>{esc_info}</td><td>{esc_loc}</td><td>{esc_mm}</td><td>{state}, {accepting}</td></tr>"
        );
    }
    if count == 0 {
        let _ = writeln!(
            body,
            "<tr><td colspan=\"5\">No {} configured.</td></tr>",
            heading.to_ascii_lowercase()
        );
    }
    body.push_str("</tbody></table>");
    page_shell(heading, server_name, &body)
}

fn render_printer_detail(
    registry: &RwLock<Registry>,
    jobs: &RwLock<Jobs>,
    server_name: &str,
    name: &str,
    expect_class: bool,
) -> Option<String> {
    let p = {
        let reg = registry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reg.printers.get(name)?.clone()
    };
    if p.is_class() != expect_class {
        return None;
    }
    let esc_name = escape_html(&p.name);
    let esc_info = escape_html(p.info.as_deref().unwrap_or("-"));
    let esc_loc = escape_html(p.location.as_deref().unwrap_or("-"));
    let esc_mm = escape_html(p.make_model.as_deref().unwrap_or("-"));
    let esc_uri = escape_html(&redact_device_uri(&p.device_uri));
    let esc_msg = escape_html(&p.state_message);
    let esc_reasons = if p.reasons.is_empty() {
        "none".to_string()
    } else {
        escape_html(&p.reasons.join(", "))
    };
    let queued = jobs
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .for_printer(&p.name)
        .filter(|j| !j.state.is_final())
        .count();

    let mut body = format!(
        "<h2>{esc_name}</h2>\n\
         <dl>\n\
         <dt>Description</dt><dd>{esc_info}</dd>\n\
         <dt>Location</dt><dd>{esc_loc}</dd>\n\
         <dt>Make and Model</dt><dd>{esc_mm}</dd>\n\
         <dt>State</dt><dd>{} ({})</dd>\n\
         <dt>State Message</dt><dd>{esc_msg}</dd>\n\
         <dt>State Reasons</dt><dd>{esc_reasons}</dd>\n\
         <dt>Queued Jobs</dt><dd>{queued}</dd>\n",
        state_label(p.state),
        if p.accepting {
            "Accepting Jobs"
        } else {
            "Rejecting Jobs"
        }
    );
    if p.is_class() {
        let members = if p.members.is_empty() {
            "none".to_string()
        } else {
            escape_html(&p.members.join(", "))
        };
        let _ = writeln!(body, "<dt>Members</dt><dd>{members}</dd>");
    } else {
        let _ = writeln!(body, "<dt>Device URI</dt><dd>{esc_uri}</dd>");
    }
    body.push_str("</dl>");
    Some(page_shell(&p.name, server_name, &body))
}

/// Evaluate whether `attr_name` (`"job-name"` / `"job-originating-user-name"`)
/// must be redacted on `/jobs` according to the queue's `<Policy>`
/// `JobPrivateAccess` and `JobPrivateValues` directives (failing closed when
/// unauthenticated or when a policy is missing).
#[must_use]
pub fn should_redact_web_job_attr(
    cfg: &Config,
    policy_name: &str,
    job_owner: &str,
    attr_name: &str,
    auth_user: Option<&str>,
    auth_groups: &[String],
) -> bool {
    let is_system_admin = auth_user == Some("root")
        || (auth_user.is_some()
            && auth_groups
                .iter()
                .any(|g| cfg.files.system_group_names.iter().any(|sg| sg == g)));

    let pol = cfg
        .cupsd
        .policies
        .iter()
        .find(|p| p.name == policy_name)
        .or_else(|| cfg.cupsd.policies.iter().find(|p| p.name == "default"));

    let Some(pol) = pol else {
        // Fail closed when policy is absent (only owner or @SYSTEM sees private values).
        if auth_user == Some(job_owner) || is_system_admin {
            return false;
        }
        return DEFAULT_JOB_PRIVATE_VALUES
            .iter()
            .any(|v| v.eq_ignore_ascii_case(attr_name));
    };

    let access_tokens: Vec<&str> = if pol.job_access.is_empty() {
        vec!["@OWNER", "@SYSTEM"]
    } else {
        pol.job_access.iter().map(String::as_str).collect()
    };

    for tok in access_tokens {
        if tok.eq_ignore_ascii_case("all") {
            return false;
        }
        if tok.eq_ignore_ascii_case("none") {
            continue;
        }
        if tok.eq_ignore_ascii_case("default") {
            if auth_user == Some(job_owner) || is_system_admin {
                return false;
            }
            continue;
        }
        if tok == "@OWNER" {
            if auth_user == Some(job_owner) {
                return false;
            }
            continue;
        }
        if tok == "@SYSTEM" {
            if is_system_admin {
                return false;
            }
            continue;
        }
        if let Some(group) = tok.strip_prefix('@') {
            if auth_user.is_some() && !group.is_empty() && auth_groups.iter().any(|g| g == group) {
                return false;
            }
            continue;
        }
        if auth_user == Some(tok) {
            return false;
        }
    }

    // Caller lacks private access: inspect `JobPrivateValues` (defaulting to `default`
    // if empty so web UI never fails open).
    let value_tokens: Vec<&str> = if pol.job_values.is_empty() {
        vec!["default"]
    } else {
        pol.job_values.iter().map(String::as_str).collect()
    };
    for v in value_tokens {
        if v.eq_ignore_ascii_case("none") {
            return false;
        }
        if v.eq_ignore_ascii_case("all") {
            return !CORE_PUBLIC_JOB_ATTRS
                .iter()
                .any(|c| c.eq_ignore_ascii_case(attr_name));
        }
        if v.eq_ignore_ascii_case("default") {
            if DEFAULT_JOB_PRIVATE_VALUES
                .iter()
                .any(|d| d.eq_ignore_ascii_case(attr_name))
            {
                return true;
            }
            continue;
        }
        if v.eq_ignore_ascii_case(attr_name) {
            return true;
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn render_jobs_list(
    cfg: &Config,
    registry: &RwLock<Registry>,
    jobs: &RwLock<Jobs>,
    server_name: &str,
    query: &str,
    auth_user: Option<&str>,
    auth_groups: &[String],
) -> String {
    let show_all = query.contains("which_jobs=all");
    let show_completed = query.contains("which_jobs=completed");
    let mut body = String::from(
        "<h2>Jobs</h2>\n\
         <p><a href=\"/jobs\">Active</a> | <a href=\"/jobs?which_jobs=completed\">Completed</a> | <a href=\"/jobs?which_jobs=all\">All</a></p>\n\
         <table>\n\
         <thead><tr><th>ID</th><th>Printer</th><th>Name</th><th>User</th><th>State</th><th>Reasons</th></tr></thead>\n\
         <tbody>\n",
    );
    let default_policy = cfg
        .cupsd
        .default_policy
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("default");
    let reg = registry
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let jg = jobs
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut count = 0usize;
    for j in jg.by_id.values().rev() {
        let include = if show_all {
            true
        } else if show_completed {
            j.state.is_final()
        } else {
            !j.state.is_final()
        };
        if !include {
            continue;
        }
        count += 1;
        let policy_name = reg
            .find(&j.dest)
            .and_then(|p| p.op_policy.as_deref())
            .filter(|s| !s.is_empty())
            .unwrap_or(default_policy);
        let redact_title = should_redact_web_job_attr(
            cfg,
            policy_name,
            &j.username,
            "job-name",
            auth_user,
            auth_groups,
        );
        let redact_user = should_redact_web_job_attr(
            cfg,
            policy_name,
            &j.username,
            "job-originating-user-name",
            auth_user,
            auth_groups,
        );
        let esc_dest = escape_html(&j.dest);
        let esc_title = if redact_title {
            "Withheld".to_string()
        } else {
            escape_html(if j.title.is_empty() {
                "Untitled"
            } else {
                &j.title
            })
        };
        let esc_user = if redact_user {
            "Withheld".to_string()
        } else {
            escape_html(&j.username)
        };
        let esc_reasons = escape_html(&j.reasons.join(", "));
        let _ = writeln!(
            body,
            "<tr><td>{}</td><td>{esc_dest}</td><td>{esc_title}</td><td>{esc_user}</td><td>{}</td><td>{esc_reasons}</td></tr>",
            j.id,
            j.state.name()
        );
    }
    if count == 0 {
        body.push_str("<tr><td colspan=\"6\">No matching jobs.</td></tr>\n");
    }
    body.push_str("</tbody></table>");
    page_shell("Jobs", server_name, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use job::{Job, JobState};
    use printer::Printer;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_dir(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "yindle-cupsd-web-{}-{tag}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[tokio::test]
    async fn static_get_enforces_containment_symlink_escape_and_headers() {
        let base = tmp_dir("static");
        let root = base.join("doc-root");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("index.html"), b"<h1>hello</h1>").unwrap();
        std::fs::write(root.join("style.css"), b"body{}").unwrap();

        let outside = base.join("secret.txt");
        std::fs::write(&outside, b"TOP_SECRET").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape.txt")).unwrap();

        // Valid index and asset
        let r_idx = static_get_async("/", &root).await;
        assert_eq!(r_idx.status, StatusCode::OK);
        assert_eq!(r_idx.body, b"<h1>hello</h1>");
        assert_eq!(r_idx.headers.get("x-content-type-options"), Some("nosniff"));
        assert_eq!(r_idx.headers.get("x-frame-options"), Some("DENY"));
        assert!(r_idx.headers.get("content-security-policy").is_some());

        let r_css = static_get_async("/style.css?v=1", &root).await;
        assert_eq!(r_css.status, StatusCode::OK);
        assert_eq!(
            r_css.headers.get("content-type"),
            Some("text/css; charset=utf-8")
        );

        // Traversal and symlink escape blocked
        assert_eq!(
            static_get_async("/../secret.txt", &root).await.status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            static_get_async("/escape.txt", &root).await.status,
            StatusCode::FORBIDDEN
        );
        // Directory rejected
        assert_eq!(
            static_get_async("/sub", &root).await.status,
            StatusCode::FORBIDDEN
        );
        // Missing file -> 404
        assert_eq!(
            static_get_async("/missing.html", &root).await.status,
            StatusCode::NOT_FOUND
        );
        // Missing doc_root -> 404
        assert_eq!(
            static_get_async("/", &base.join("no-root")).await.status,
            StatusCode::NOT_FOUND
        );

        // MIME guesses
        assert_eq!(
            mime_guess(Path::new("a.js")),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(mime_guess(Path::new("a.json")), "application/json");
        assert_eq!(mime_guess(Path::new("a.svg")), "image/svg+xml");
        assert_eq!(mime_guess(Path::new("a.png")), "image/png");
        assert_eq!(mime_guess(Path::new("a.gif")), "image/gif");
        assert_eq!(mime_guess(Path::new("a.ico")), "image/vnd.microsoft.icon");
        assert_eq!(mime_guess(Path::new("a.jpg")), "image/jpeg");
        assert_eq!(mime_guess(Path::new("a.txt")), "text/plain; charset=utf-8");
        assert_eq!(mime_guess(Path::new("a.bin")), "application/octet-stream");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn builtin_ui_renders_all_routes_and_escapes_xss_and_credentials() {
        let mut cfg = Config {
            cupsd: cups_config::CupsdConfig::defaults(),
            files: cups_config::CupsFilesConfig::defaults(),
        };
        cfg.cupsd.policies.push(cups_config::default_policy());
        cfg.files.system_group_names = vec!["lpadmin".into()];

        let mut reg = Registry::default();
        let mut p = Printer::new("office", "ipp://alice:supersecret@10.0.0.5/ipp/print");
        p.info = Some("<script>alert(1)</script>".into());
        p.location = Some("Floor 2 & Lab".into());
        p.make_model = Some("Generic \"Laser\"".into());
        p.reasons = vec!["toner-low-warning".into()];
        reg.add(p);
        reg.default = Some("office".into());

        let mut c = Printer::new_class("pool");
        c.add_member("office");
        c.state = pstate::STOPPED;
        c.accepting = false;
        reg.add(c);
        let reg = RwLock::new(reg);

        let mut jobs = Jobs::default();
        let mut j1 = Job::new(1, "office", "<b>alice</b>");
        j1.title = "Doc <1>".into();
        let mut j2 = Job::new(2, "office", "bob");
        j2.state = JobState::Completed;
        jobs.by_id.insert(1, j1);
        jobs.by_id.insert(2, j2);
        let jobs = RwLock::new(jobs);

        let m = Metrics::default();
        let sys_groups = vec!["lpadmin".to_string()];

        // Home
        let home = render_builtin_ui("/", &cfg, &reg, &jobs, &m, "print<host>", None, &[]).unwrap();
        assert_eq!(home.status, StatusCode::OK);
        let home_s = String::from_utf8(home.body).unwrap();
        assert!(home_s.contains("Printers: 1"));
        assert!(home_s.contains("Classes: 1"));
        assert!(home_s.contains("print&lt;host&gt;"));

        // Printers list & detail (XSS escaped + credentials redacted!)
        let plist =
            render_builtin_ui("/printers", &cfg, &reg, &jobs, &m, "srv", None, &[]).unwrap();
        let plist_s = String::from_utf8(plist.body).unwrap();
        assert!(plist_s.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!plist_s.contains("<script>"));

        let pdet =
            render_builtin_ui("/printers/office", &cfg, &reg, &jobs, &m, "srv", None, &[]).unwrap();
        let pdet_s = String::from_utf8(pdet.body).unwrap();
        assert!(pdet_s.contains("***@10.0.0.5"));
        assert!(!pdet_s.contains("supersecret"));
        // Requesting class under /printers/ returns None
        assert!(
            render_builtin_ui("/printers/pool", &cfg, &reg, &jobs, &m, "srv", None, &[]).is_none()
        );

        // Classes list & detail
        let clist = render_builtin_ui("/classes", &cfg, &reg, &jobs, &m, "srv", None, &[]).unwrap();
        assert!(String::from_utf8(clist.body).unwrap().contains("pool"));
        let cdet =
            render_builtin_ui("/classes/pool", &cfg, &reg, &jobs, &m, "srv", None, &[]).unwrap();
        assert!(String::from_utf8(cdet.body).unwrap().contains("office"));

        // Privacy enforcement on `/jobs`:
        // 1. Anonymous caller MUST see "Withheld" for title and username!
        let j_anon = render_builtin_ui(
            "/jobs?which_jobs=all",
            &cfg,
            &reg,
            &jobs,
            &m,
            "srv",
            None,
            &[],
        )
        .unwrap();
        let j_anon_s = String::from_utf8(j_anon.body).unwrap();
        assert!(j_anon_s.contains("<td>1</td>"));
        assert!(j_anon_s.contains("<td>2</td>"));
        assert!(j_anon_s.contains("<td>Withheld</td><td>Withheld</td>"));
        assert!(!j_anon_s.contains("Doc &lt;1&gt;"));
        assert!(!j_anon_s.contains("&lt;b&gt;alice&lt;/b&gt;"));
        assert!(!j_anon_s.contains("<td>bob</td>"));

        // 2. Non-owner authenticated user (`charlie`) MUST also see "Withheld"!
        let j_other = render_builtin_ui(
            "/jobs",
            &cfg,
            &reg,
            &jobs,
            &m,
            "srv",
            Some("charlie"),
            &["users".into()],
        )
        .unwrap();
        let j_other_s = String::from_utf8(j_other.body).unwrap();
        assert!(j_other_s.contains("<td>Withheld</td><td>Withheld</td>"));
        assert!(!j_other_s.contains("Doc &lt;1&gt;"));

        // 3. `@OWNER` sees their own job's title & username (still XSS-escaped), NOT others!
        let j_owner = render_builtin_ui(
            "/jobs?which_jobs=all",
            &cfg,
            &reg,
            &jobs,
            &m,
            "srv",
            Some("<b>alice</b>"),
            &[],
        )
        .unwrap();
        let j_owner_s = String::from_utf8(j_owner.body).unwrap();
        assert!(j_owner_s.contains("Doc &lt;1&gt;"));
        assert!(j_owner_s.contains("&lt;b&gt;alice&lt;/b&gt;"));
        assert!(!j_owner_s.contains("<td>bob</td>"));

        // 4. `@SYSTEM` admin sees all jobs' real titles & usernames (including active/completed filters)!
        let j_act = render_builtin_ui(
            "/jobs",
            &cfg,
            &reg,
            &jobs,
            &m,
            "srv",
            Some("admin"),
            &sys_groups,
        )
        .unwrap();
        let j_act_s = String::from_utf8(j_act.body).unwrap();
        assert!(j_act_s.contains("Doc &lt;1&gt;"));
        assert!(!j_act_s.contains("<td>2</td>"));

        let j_comp = render_builtin_ui(
            "/jobs?which_jobs=completed",
            &cfg,
            &reg,
            &jobs,
            &m,
            "srv",
            Some("admin"),
            &sys_groups,
        )
        .unwrap();
        let j_comp_s = String::from_utf8(j_comp.body).unwrap();
        assert!(j_comp_s.contains("<td>2</td>"));
        assert!(j_comp_s.contains("Untitled"));
        assert!(j_comp_s.contains("<td>bob</td>"));

        // Unknown route -> None
        assert!(
            render_builtin_ui("/does-not-exist", &cfg, &reg, &jobs, &m, "srv", None, &[]).is_none()
        );

        // Empty tables render cleanly
        let empty_reg = RwLock::new(Registry::default());
        let empty_jobs = RwLock::new(Jobs::default());
        assert!(String::from_utf8(
            render_builtin_ui(
                "/printers",
                &cfg,
                &empty_reg,
                &empty_jobs,
                &m,
                "srv",
                None,
                &[]
            )
            .unwrap()
            .body
        )
        .unwrap()
        .contains("No printers configured"));
        assert!(String::from_utf8(
            render_builtin_ui("/jobs", &cfg, &empty_reg, &empty_jobs, &m, "srv", None, &[])
                .unwrap()
                .body
        )
        .unwrap()
        .contains("No matching jobs"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn job_privacy_policy_tokens_and_fail_closed_edge_cases() {
        let mut cfg = Config {
            cupsd: cups_config::CupsdConfig::defaults(),
            files: cups_config::CupsFilesConfig::defaults(),
        };
        cfg.files.system_group_names = vec!["lpadmin".into()];

        // Missing policy fails closed for anonymous/non-owner, allows owner & root.
        assert!(should_redact_web_job_attr(
            &cfg,
            "missing",
            "alice",
            "job-name",
            None,
            &[]
        ));
        assert!(!should_redact_web_job_attr(
            &cfg,
            "missing",
            "alice",
            "job-name",
            Some("alice"),
            &[]
        ));
        assert!(!should_redact_web_job_attr(
            &cfg,
            "missing",
            "alice",
            "job-name",
            Some("root"),
            &[]
        ));

        // Custom policies covering `all`, `none`, `default`, `@group`, named user, and JobPrivateValues variants.
        let mk_pol = |name: &str, access: &[&str], values: &[&str]| cups_config::Policy {
            name: name.into(),
            ops: Vec::new(),
            job_access: access.iter().map(|s| (*s).to_string()).collect(),
            job_values: values.iter().map(|s| (*s).to_string()).collect(),
            sub_access: Vec::new(),
            sub_values: Vec::new(),
        };
        let open = mk_pol("open", &["all"], &[]);
        let custom = mk_pol(
            "custom",
            &["none", "default", "@staff", "auditor"],
            &["job-name"],
        );
        let strict = mk_pol("strict", &["none"], &["all"]);
        let relaxed = mk_pol("relaxed", &["none"], &["none"]);
        cfg.cupsd.policies = vec![open, custom, strict, relaxed];

        assert!(!should_redact_web_job_attr(
            &cfg,
            "open",
            "alice",
            "job-name",
            None,
            &[]
        ));
        assert!(!should_redact_web_job_attr(
            &cfg,
            "custom",
            "alice",
            "job-name",
            Some("bob"),
            &["staff".into()]
        ));
        assert!(!should_redact_web_job_attr(
            &cfg,
            "custom",
            "alice",
            "job-name",
            Some("auditor"),
            &[]
        ));
        assert!(!should_redact_web_job_attr(
            &cfg,
            "custom",
            "alice",
            "job-name",
            Some("alice"),
            &[]
        ));
        // Custom hides only `job-name` for anonymous, not `job-originating-user-name`.
        assert!(should_redact_web_job_attr(
            &cfg,
            "custom",
            "alice",
            "job-name",
            None,
            &[]
        ));
        assert!(!should_redact_web_job_attr(
            &cfg,
            "custom",
            "alice",
            "job-originating-user-name",
            None,
            &[]
        ));
        // `JobPrivateValues all` hides non-core attrs, keeps core attrs.
        assert!(should_redact_web_job_attr(
            &cfg,
            "strict",
            "alice",
            "job-name",
            None,
            &[]
        ));
        assert!(!should_redact_web_job_attr(
            &cfg,
            "strict",
            "alice",
            "job-id",
            None,
            &[]
        ));
        // `JobPrivateValues none` hides nothing.
        assert!(!should_redact_web_job_attr(
            &cfg,
            "relaxed",
            "alice",
            "job-name",
            None,
            &[]
        ));
    }
}
