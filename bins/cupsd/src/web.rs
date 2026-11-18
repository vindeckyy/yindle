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
use std::path::Path;
use std::sync::RwLock;

use httpd::{Response, StatusCode};
use job::Jobs;
use printer::{pstate, redact_device_uri, Registry};

use crate::cli::VERSION;
use crate::metrics::Metrics;

/// Maximum static asset size served from `DocumentRoot` (16 MiB).
pub const MAX_STATIC_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Serve a static asset asynchronously from `doc_root` with canonical containment,
/// regular-file enforcement, size cap, and HTTP security headers.
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

    let Ok(meta) = tokio::fs::metadata(&canon_file).await else {
        return Response::status(StatusCode::FORBIDDEN).with_security_headers();
    };
    if !meta.is_file() {
        return Response::status(StatusCode::FORBIDDEN).with_security_headers();
    }
    if meta.len() > MAX_STATIC_FILE_BYTES {
        return Response::status(StatusCode::TOO_LARGE).with_security_headers();
    }

    match tokio::fs::read(&canon_file).await {
        Ok(bytes) => Response::with_body(StatusCode::OK, mime_guess(&canon_file), bytes)
            .with_security_headers(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Response::status(StatusCode::NOT_FOUND).with_security_headers()
        }
        Err(_) => Response::status(StatusCode::FORBIDDEN).with_security_headers(),
    }
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
/// `/classes/<name>`, and `/jobs`. Returns `None` for non-UI paths.
#[must_use]
pub fn render_builtin_ui(
    uri: &str,
    registry: &RwLock<Registry>,
    jobs: &RwLock<Jobs>,
    metrics: &Metrics,
    server_name: &str,
) -> Option<Response> {
    let (path_raw, query) = uri.split_once('?').map_or((uri, ""), |(p, q)| (p, q));
    let path = path_raw.split('#').next().unwrap_or(path_raw);
    let trimmed = path.trim_end_matches('/');
    let norm = if trimmed.is_empty() { "/" } else { trimmed };

    let html = match norm {
        "/" | "/index.html" => render_home(registry, jobs, metrics, server_name),
        "/printers" => render_printers_list(registry, server_name, false),
        "/classes" => render_printers_list(registry, server_name, true),
        "/jobs" => render_jobs_list(jobs, server_name, query),
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
         <title>{esc_title} - Presswork ({esc_server})</title>\n\
         </head>\n\
         <body>\n\
         <header>\n\
         <h1>Presswork Print Scheduler {esc_ver} ({esc_server})</h1>\n\
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

fn render_jobs_list(jobs: &RwLock<Jobs>, server_name: &str, query: &str) -> String {
    let show_all = query.contains("which_jobs=all");
    let show_completed = query.contains("which_jobs=completed");
    let mut body = String::from(
        "<h2>Jobs</h2>\n\
         <p><a href=\"/jobs\">Active</a> | <a href=\"/jobs?which_jobs=completed\">Completed</a> | <a href=\"/jobs?which_jobs=all\">All</a></p>\n\
         <table>\n\
         <thead><tr><th>ID</th><th>Printer</th><th>Name</th><th>User</th><th>State</th><th>Reasons</th></tr></thead>\n\
         <tbody>\n",
    );
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
        let esc_dest = escape_html(&j.dest);
        let esc_title = escape_html(if j.title.is_empty() {
            "Untitled"
        } else {
            &j.title
        });
        let esc_user = escape_html(&j.username);
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
            "presswork-cupsd-web-{}-{tag}-{id}",
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
    fn builtin_ui_renders_all_routes_and_escapes_xss_and_credentials() {
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

        // Home
        let home = render_builtin_ui("/", &reg, &jobs, &m, "print<host>").unwrap();
        assert_eq!(home.status, StatusCode::OK);
        let home_s = String::from_utf8(home.body).unwrap();
        assert!(home_s.contains("Printers: 1"));
        assert!(home_s.contains("Classes: 1"));
        assert!(home_s.contains("print&lt;host&gt;"));

        // Printers list & detail (XSS escaped + credentials redacted!)
        let plist = render_builtin_ui("/printers", &reg, &jobs, &m, "srv").unwrap();
        let plist_s = String::from_utf8(plist.body).unwrap();
        assert!(plist_s.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!plist_s.contains("<script>"));

        let pdet = render_builtin_ui("/printers/office", &reg, &jobs, &m, "srv").unwrap();
        let pdet_s = String::from_utf8(pdet.body).unwrap();
        assert!(pdet_s.contains("***@10.0.0.5"));
        assert!(!pdet_s.contains("supersecret"));
        // Requesting class under /printers/ returns None
        assert!(render_builtin_ui("/printers/pool", &reg, &jobs, &m, "srv").is_none());

        // Classes list & detail
        let clist = render_builtin_ui("/classes", &reg, &jobs, &m, "srv").unwrap();
        assert!(String::from_utf8(clist.body).unwrap().contains("pool"));
        let cdet = render_builtin_ui("/classes/pool", &reg, &jobs, &m, "srv").unwrap();
        assert!(String::from_utf8(cdet.body).unwrap().contains("office"));

        // Jobs filters (active, completed, all)
        let j_act = render_builtin_ui("/jobs", &reg, &jobs, &m, "srv").unwrap();
        let j_act_s = String::from_utf8(j_act.body).unwrap();
        assert!(j_act_s.contains("Doc &lt;1&gt;"));
        assert!(!j_act_s.contains("<td>2</td>"));

        let j_comp =
            render_builtin_ui("/jobs?which_jobs=completed", &reg, &jobs, &m, "srv").unwrap();
        let j_comp_s = String::from_utf8(j_comp.body).unwrap();
        assert!(j_comp_s.contains("<td>2</td>"));
        assert!(j_comp_s.contains("Untitled"));

        let j_all = render_builtin_ui("/jobs?which_jobs=all", &reg, &jobs, &m, "srv").unwrap();
        let j_all_s = String::from_utf8(j_all.body).unwrap();
        assert!(j_all_s.contains("<td>1</td>"));
        assert!(j_all_s.contains("<td>2</td>"));

        // Unknown route -> None
        assert!(render_builtin_ui("/does-not-exist", &reg, &jobs, &m, "srv").is_none());

        // Empty tables render cleanly
        let empty_reg = RwLock::new(Registry::default());
        let empty_jobs = RwLock::new(Jobs::default());
        assert!(String::from_utf8(
            render_builtin_ui("/printers", &empty_reg, &empty_jobs, &m, "srv")
                .unwrap()
                .body
        )
        .unwrap()
        .contains("No printers configured"));
        assert!(String::from_utf8(
            render_builtin_ui("/jobs", &empty_reg, &empty_jobs, &m, "srv")
                .unwrap()
                .body
        )
        .unwrap()
        .contains("No matching jobs"));
    }
}
