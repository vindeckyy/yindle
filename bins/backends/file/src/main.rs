//! `file` backend — writes the job to `file:///path` (`backend/file.c`-
//! equivalent).
//!
//! Security hardening:
//!  * Enforces `FileDevice` policy (`CUPS_FILE_DEVICE=yes` env var, or
//!    `FileDevice Yes` in `$CUPS_SERVERROOT/cups-files.conf`; fails closed by
//!    default).
//!  * Rejects relative paths, NUL bytes, and `..` path traversal components.
//!  * Opens targets with `O_NOFOLLOW` and `truncate(true)` (mode `0600`) so
//!    jobs overwrite cleanly instead of appending and symlinks are never
//!    followed.
//!  * Verifies via `fstat` that the opened target is a regular file or `/dev/null`.

use backend_common as bc;
use std::env;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// Check `FileDevice` policy:
///  * If `CUPS_FILE_DEVICE` is explicitly set, honor it strictly.
///  * Otherwise, if `CUPS_SERVERROOT` is set, read `cups-files.conf` and check
///    for `FileDevice Yes`.
///  * Fail closed (`false`) otherwise.
fn is_file_device_allowed(env_val: Option<&str>, server_root: Option<&Path>) -> bool {
    if let Some(val) = env_val {
        return bc::parse_env_bool(Some(val)).unwrap_or(false);
    }
    let Some(root) = server_root else {
        return false;
    };
    let conf = root.join("cups-files.conf");
    let Ok(text) = std::fs::read_to_string(conf) else {
        return false;
    };
    let mut allowed = false;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        if let (Some(key), Some(val)) = (parts.next(), parts.next()) {
            if key.eq_ignore_ascii_case("FileDevice") {
                allowed = bc::parse_env_bool(Some(val)).unwrap_or(false);
            }
        }
    }
    allowed
}

/// Extract the filesystem path from `file:///path`, `file://localhost/path`,
/// `file:/path`, or `file://` (empty maps to `/dev/null`).
fn parse_file_uri(uri: &str) -> Option<String> {
    let (scheme, rest) = uri.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("file") {
        return None;
    }
    let path_part = if let Some(after_slashes) = rest.strip_prefix("//") {
        let stripped = after_slashes
            .split(['?', '#'])
            .next()
            .unwrap_or(after_slashes);
        if stripped.is_empty() {
            return Some("/dev/null".to_string());
        }
        if stripped.starts_with('/') {
            stripped
        } else if let Some((host, tail)) = stripped.split_once('/') {
            if !host.eq_ignore_ascii_case("localhost") {
                return None;
            }
            // Keep leading `/` on the local path.
            &stripped[host.len()..host.len() + 1 + tail.len()]
        } else {
            return None;
        }
    } else if rest.starts_with('/') {
        rest.split(['?', '#']).next().unwrap_or(rest)
    } else {
        return None;
    };
    Some(bc::percent_decode(path_part))
}

/// Open the target path with `O_NOFOLLOW`, `O_TRUNC`, `0600` mode, rejecting
/// traversal, symlinks, FIFOs, and non-regular targets (except `/dev/null`)
/// both before open (prevents FIFO hang) and via post-open `fstat`.
fn open_target(path: &str) -> io::Result<File> {
    bc::validate_no_traversal(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() || (!ft.is_file() && path != "/dev/null") {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{path} is not a regular file"),
                ));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(bc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() && path != "/dev/null" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{path} is not a regular file"),
        ));
    }
    Ok(file)
}

fn print_with_policy(
    inv: &bc::Invocation,
    env_val: Option<&str>,
    server_root: Option<&Path>,
) -> i32 {
    if !is_file_device_allowed(env_val, server_root) {
        bc::error(format_args!(
            "file: FileDevice is disabled (set CUPS_FILE_DEVICE=yes or FileDevice Yes)"
        ));
        return bc::code::FAILED;
    }
    let Some(path) = parse_file_uri(&inv.device_uri) else {
        bc::error(format_args!(
            "file: bad device URI {}",
            bc::redact_uri(&inv.device_uri)
        ));
        return bc::code::FAILED;
    };
    let mut out = match open_target(&path) {
        Ok(f) => f,
        Err(e) => {
            bc::error(format_args!("file: cannot open {path}: {e}"));
            return bc::code::FAILED;
        }
    };
    let mut doc = match bc::document(inv) {
        Ok(d) => d,
        Err(e) => {
            bc::error(format_args!("file: cannot open document: {e}"));
            return bc::code::FAILED;
        }
    };
    match io::copy(&mut doc, &mut out) {
        Ok(n) => {
            bc::info(format_args!("file: wrote {n} bytes to {path}"));
            bc::code::OK
        }
        Err(e) => {
            bc::error(format_args!("file: write to {path} failed: {e}"));
            bc::code::FAILED
        }
    }
}

fn main() {
    bc::run(
        || bc::code::OK,
        |inv| {
            let env_val = env::var("CUPS_FILE_DEVICE").ok();
            let server_root = env::var("CUPS_SERVERROOT").ok().map(PathBuf::from);
            print_with_policy(&inv, env_val.as_deref(), server_root.as_deref())
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_enforces_env_and_cups_files_conf() {
        assert!(!is_file_device_allowed(None, None));
        assert!(is_file_device_allowed(Some("yes"), None));
        assert!(is_file_device_allowed(Some("1"), None));
        assert!(!is_file_device_allowed(Some("no"), None));
        assert!(!is_file_device_allowed(Some("invalid"), None));

        let dir = env::temp_dir().join(format!("pw-file-pol-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!is_file_device_allowed(None, Some(&dir)));

        std::fs::write(dir.join("cups-files.conf"), "# comment\nFileDevice Yes\n").unwrap();
        assert!(is_file_device_allowed(None, Some(&dir)));
        // Explicit env "no" overrides cups-files.conf.
        assert!(!is_file_device_allowed(Some("no"), Some(&dir)));

        std::fs::write(
            dir.join("cups-files.conf"),
            "FileDevice Yes\nFileDevice No\n",
        )
        .unwrap();
        assert!(!is_file_device_allowed(None, Some(&dir)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn truncates_rejects_symlink_and_traversal() {
        let dir = env::temp_dir().join(format!("pw-file-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("input.txt");
        let dst = dir.join("out.txt");
        std::fs::write(&src, b"second-job").unwrap();
        std::fs::write(&dst, b"first-job-that-must-be-truncated").unwrap();

        // Policy disabled -> rejected.
        let inv = bc::Invocation {
            job_id: 1,
            user: "u".into(),
            title: "t".into(),
            copies: 1,
            options: String::new(),
            file: Some(src.to_string_lossy().into_owned()),
            device_uri: format!("file://{}", dst.display()),
        };
        assert_eq!(print_with_policy(&inv, None, None), bc::code::FAILED);

        // Single-slash `file:/path` and `file://localhost/path` are supported; remote hosts rejected.
        assert_eq!(
            parse_file_uri("file:/tmp/out.ps").as_deref(),
            Some("/tmp/out.ps")
        );
        assert_eq!(
            parse_file_uri("file://localhost/tmp/out.ps").as_deref(),
            Some("/tmp/out.ps")
        );
        assert!(parse_file_uri("file://remote.example/tmp/out").is_none());
        assert!(parse_file_uri("file://remote").is_none());
        assert!(parse_file_uri("file:relative").is_none());

        // Policy enabled -> truncates and writes exact content (also test `file:/path`).
        assert_eq!(print_with_policy(&inv, Some("yes"), None), bc::code::OK);
        assert_eq!(std::fs::read(&dst).unwrap(), b"second-job");
        let inv_single = bc::Invocation {
            device_uri: format!("file:{}", dst.display()),
            ..inv.clone()
        };
        assert_eq!(
            print_with_policy(&inv_single, Some("yes"), None),
            bc::code::OK
        );

        // FIFO target must be rejected before open without blocking!
        let fifo = dir.join("pipe.fifo");
        let _ = std::fs::remove_file(&fifo);
        if std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|s| s.success())
        {
            let inv_fifo = bc::Invocation {
                device_uri: format!("file://{}", fifo.display()),
                ..inv.clone()
            };
            assert_eq!(
                print_with_policy(&inv_fifo, Some("yes"), None),
                bc::code::FAILED
            );
        }

        // `/dev/null` via `file://` empty path works when allowed.
        let inv_null = bc::Invocation {
            device_uri: "file://".into(),
            ..inv.clone()
        };
        assert_eq!(
            print_with_policy(&inv_null, Some("yes"), None),
            bc::code::OK
        );

        // Traversal rejected.
        let inv_trav = bc::Invocation {
            device_uri: format!("file://{}/../escape.txt", dir.display()),
            ..inv.clone()
        };
        assert_eq!(
            print_with_policy(&inv_trav, Some("yes"), None),
            bc::code::FAILED
        );

        // Symlink rejected (O_NOFOLLOW).
        #[cfg(unix)]
        {
            let link = dir.join("sym.txt");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(&dst, &link).unwrap();
            let inv_sym = bc::Invocation {
                device_uri: format!("file://{}", link.display()),
                ..inv.clone()
            };
            assert_eq!(
                print_with_policy(&inv_sym, Some("yes"), None),
                bc::code::FAILED
            );
        }

        // Non-regular target (/dev/zero is a char device other than /dev/null) rejected.
        let inv_zero = bc::Invocation {
            device_uri: "file:///dev/zero".into(),
            ..inv.clone()
        };
        assert_eq!(
            print_with_policy(&inv_zero, Some("yes"), None),
            bc::code::FAILED
        );

        // Bad URI and missing document file fail cleanly.
        let inv_bad = bc::Invocation {
            device_uri: "ipp://host/p".into(),
            ..inv.clone()
        };
        assert_eq!(
            print_with_policy(&inv_bad, Some("yes"), None),
            bc::code::FAILED
        );
        let inv_nf = bc::Invocation {
            file: Some(dir.join("missing").to_string_lossy().into_owned()),
            ..inv
        };
        assert_eq!(
            print_with_policy(&inv_nf, Some("yes"), None),
            bc::code::FAILED
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
