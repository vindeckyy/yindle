//! `cups-deviced` — hardened device discovery helper (`scheduler/deviced.c`).
//!
//! Security & reliability hardening:
//!  * Validates the backend directory and every backend binary using
//!    `symlink_metadata` (never executes symlinks, skips group/world-writable
//!    files, enforces trusted ownership).
//!  * Runs every backend with `env_clear()` and a minimal safe environment.
//!  * Executes all backends concurrently under a real shared deadline and
//!    actively kills + reaps timed-out children so none leak as orphans.

use std::collections::BTreeMap;
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const MAX_BACKEND_OUTPUT_BYTES: usize = 1024 * 1024;
const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const ENV_ALLOWLIST: &[&str] = &[
    "LANG",
    "TZ",
    "CUPS_SERVERROOT",
    "CUPS_SERVERBIN",
    "CUPS_DATADIR",
    "CUPS_CACHEDIR",
    "CUPS_STATEDIR",
    "TMPDIR",
    "CUPS_ALLOW_LOOPBACK_BACKENDS",
    "SNMP_CONF",
];

#[cfg(unix)]
fn current_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").map_or(0, |m| m.uid())
}

/// Validate that a backend binary is a regular file (not a symlink),
/// executable, neither group- nor world-writable, and owned by root or
/// `trusted_uid`.
#[cfg(unix)]
fn is_safe_backend(path: &Path, trusted_uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.file_type().is_file() {
        return false;
    }
    let mode = meta.mode();
    let is_exec = (mode & 0o111) != 0;
    let is_group_or_world_writable = (mode & 0o022) != 0;
    let uid = meta.uid();
    let trusted_owner = uid == 0 || uid == trusted_uid;
    is_exec && !is_group_or_world_writable && trusted_owner
}

#[cfg(not(unix))]
fn is_safe_backend(path: &Path, _trusted_uid: u32) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

/// Validate the backend directory itself (not a symlink, not world-writable).
#[cfg(unix)]
fn is_safe_backend_dir(dir: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    meta.file_type().is_dir() && (meta.mode() & 0o002) == 0
}

#[cfg(not(unix))]
fn is_safe_backend_dir(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_dir())
}

/// Build the minimal safe environment passed to discovered backend processes.
fn safe_backend_env(parent: &[(String, String)]) -> BTreeMap<String, String> {
    let mut env_map = BTreeMap::new();
    env_map.insert("PATH".to_string(), SAFE_PATH.to_string());
    env_map.insert("LANG".to_string(), "C.UTF-8".to_string());
    for (k, v) in parent {
        if ENV_ALLOWLIST.contains(&k.as_str())
            && !v.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n')
        {
            env_map.insert(k.clone(), v.clone());
        }
    }
    env_map
}

fn collect_backends(dir: &Path, trusted_uid: u32) -> Vec<PathBuf> {
    if !is_safe_backend_dir(dir) {
        eprintln!(
            "cups-deviced: refusing unsafe backend directory {}",
            dir.display()
        );
        return Vec::new();
    }
    let mut backends: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| is_safe_backend(p, trusted_uid))
                .collect()
        })
        .unwrap_or_default();
    backends.sort();
    backends
}

enum Event {
    Line(String),
    Eof(usize),
}

fn sanitize_output_line(line: &str) -> String {
    line.chars()
        .filter(|&c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

/// Spawn all validated backends concurrently, stream valid discovery lines up
/// to `limit` before `timeout`, and kill + reap any children still running when
/// the deadline expires or `limit` is reached.
fn run_discovery(
    dir: &Path,
    limit: usize,
    timeout: Duration,
    trusted_uid: u32,
    parent_env: &[(String, String)],
    out: &mut impl Write,
) -> usize {
    let backends = collect_backends(dir, trusted_uid);
    if backends.is_empty() {
        return 0;
    }

    let safe_env = safe_backend_env(parent_env);
    let (tx, rx) = mpsc::channel::<Event>();
    let mut children: Vec<Option<Child>> = Vec::with_capacity(backends.len());
    let mut readers = Vec::with_capacity(backends.len());
    let mut active = 0usize;

    for b in backends {
        let mut cmd = Command::new(&b);
        cmd.env_clear()
            .envs(&safe_env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        match cmd.spawn() {
            Ok(mut child) => {
                let idx = children.len();
                let stdout = child.stdout.take();
                children.push(Some(child));
                active += 1;
                let tx_i = tx.clone();
                let handle = thread::spawn(move || {
                    if let Some(pipe) = stdout {
                        let mut reader = BufReader::new(pipe);
                        let mut total = 0usize;
                        let mut line = String::new();
                        loop {
                            line.clear();
                            match reader.read_line(&mut line) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    total = total.saturating_add(n);
                                    if total > MAX_BACKEND_OUTPUT_BYTES {
                                        break;
                                    }
                                    let clean = sanitize_output_line(&line);
                                    if !clean.is_empty() && tx_i.send(Event::Line(clean)).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    let _ = tx_i.send(Event::Eof(idx));
                });
                readers.push(handle);
            }
            Err(e) => eprintln!("cups-deviced: cannot run {}: {e}", b.display()),
        }
    }
    drop(tx);

    let deadline = Instant::now() + timeout;
    let mut emitted = 0usize;

    while active > 0 {
        if limit != 0 && emitted >= limit {
            break;
        }
        let rem = deadline.saturating_duration_since(Instant::now());
        if rem.is_zero() {
            break;
        }
        match rx.recv_timeout(rem) {
            Ok(Event::Line(line)) => {
                if line.split_whitespace().count() >= 2 {
                    let _ = writeln!(out, "{line}");
                    emitted += 1;
                }
            }
            Ok(Event::Eof(idx)) => {
                if let Some(mut c) = children[idx].take() {
                    let _ = c.wait();
                }
                active -= 1;
            }
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // Kill and reap every child still running so no orphans or zombies remain.
    for slot in &mut children {
        if let Some(mut c) = slot.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
    // Drop receiver before joining so reader threads unblock immediately.
    drop(rx);
    for h in readers {
        let _ = h.join();
    }
    emitted
}

fn run_cli(args: &[String], out: &mut impl Write) -> i32 {
    if args.len() < 4 {
        let prog = args.first().map_or("cups-deviced", String::as_str);
        eprintln!("Usage: {prog} request-id limit timeout [dir]");
        return 1;
    }
    let _request_id: i32 = args[1].parse().unwrap_or(0);
    let limit: usize = args[2].parse().unwrap_or(0);
    let timeout_secs: u64 = args[3].parse().unwrap_or(30).clamp(1, 300);
    let dir = args
        .get(4)
        .map_or_else(|| PathBuf::from("/usr/lib/cups/backend"), PathBuf::from);
    let parent_env: Vec<(String, String)> = env::vars().collect();
    #[cfg(unix)]
    let uid = current_uid();
    #[cfg(not(unix))]
    let uid = 0;

    let _ = run_discovery(
        &dir,
        limit,
        Duration::from_secs(timeout_secs),
        uid,
        &parent_env,
        out,
    );
    0
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let code = run_cli(&args, &mut std::io::stdout().lock());
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn make_exec(path: &Path, content: &str, mode: u32) {
        std::fs::write(path, content).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn safe_backend_rejects_symlinks_writable_and_nonexec() {
        let dir = env::temp_dir().join(format!("pw-deviced-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let uid = current_uid();
        let good = dir.join("01-good");
        let group_w = dir.join("02-groupw");
        let world_w = dir.join("03-worldw");
        let noexec = dir.join("04-noexec");
        let link = dir.join("05-symlink");

        make_exec(&good, "#!/bin/sh\n", 0o755);
        make_exec(&group_w, "#!/bin/sh\n", 0o775);
        make_exec(&world_w, "#!/bin/sh\n", 0o757);
        make_exec(&noexec, "#!/bin/sh\n", 0o644);
        std::os::unix::fs::symlink(&good, &link).unwrap();

        assert!(is_safe_backend(&good, uid));
        assert!(!is_safe_backend(&group_w, uid));
        assert!(!is_safe_backend(&world_w, uid));
        assert!(!is_safe_backend(&noexec, uid));
        assert!(!is_safe_backend(&link, uid));
        // Wrong owner check (when not root).
        if uid != 0 {
            assert!(!is_safe_backend(&good, uid.wrapping_add(1)));
        }

        let found = collect_backends(&dir, uid);
        assert_eq!(found, vec![good]);

        // World-writable directory rejected.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!is_safe_backend_dir(&dir));
        assert_eq!(collect_backends(&dir, uid), Vec::<PathBuf>::new());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_clear_strips_dangerous_vars_and_keeps_allowlist() {
        let parent = vec![
            ("LD_PRELOAD".into(), "/tmp/evil.so".into()),
            ("LD_LIBRARY_PATH".into(), "/tmp/evil".into()),
            ("HTTP_PROXY".into(), "http://evil".into()),
            ("SECRET_TOKEN".into(), "s3cr3t".into()),
            ("CUPS_SERVERROOT".into(), "/etc/cups".into()),
            ("TZ".into(), "UTC".into()),
            ("TMPDIR".into(), "/tmp\nbad".into()), // control char rejected
        ];
        let env_map = safe_backend_env(&parent);
        assert_eq!(env_map.get("PATH").map(String::as_str), Some(SAFE_PATH));
        assert_eq!(
            env_map.get("CUPS_SERVERROOT").map(String::as_str),
            Some("/etc/cups")
        );
        assert_eq!(env_map.get("TZ").map(String::as_str), Some("UTC"));
        assert!(!env_map.contains_key("LD_PRELOAD"));
        assert!(!env_map.contains_key("LD_LIBRARY_PATH"));
        assert!(!env_map.contains_key("HTTP_PROXY"));
        assert!(!env_map.contains_key("SECRET_TOKEN"));
        assert!(!env_map.contains_key("TMPDIR"));
    }

    #[test]
    fn concurrent_discovery_clears_env_respects_limit_and_kills_timed_out_child() {
        let dir = env::temp_dir().join(format!("pw-deviced-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let pid_file = dir.join("sleeper.pid");
        let fast = dir.join("01-fast");
        let env_check = dir.join("02-envcheck");
        let slow = dir.join("03-slow");

        make_exec(
            &fast,
            "#!/bin/sh\necho 'network ipp://10.0.0.1/ipp \"HP\" \"Fast\"'\necho 'singleword'\n",
            0o755,
        );
        make_exec(
            &env_check,
            "#!/bin/sh\nif [ -z \"$LD_PRELOAD\" ] && [ -z \"$SECRET_LEAK\" ]; then\n  echo 'network socket://10.0.0.2 \"Safe\" \"EnvClean\"'\nfi\n",
            0o755,
        );
        make_exec(
            &slow,
            &format!(
                "#!/bin/sh\necho $$ > \"{}\"\nexec sleep 60\n",
                pid_file.display()
            ),
            0o755,
        );

        let parent_env = vec![
            ("LD_PRELOAD".into(), "/tmp/bad.so".into()),
            ("SECRET_LEAK".into(), "nope".into()),
        ];
        let start = Instant::now();
        let mut out = Vec::new();
        let count = run_discovery(
            &dir,
            0,
            Duration::from_millis(600),
            current_uid(),
            &parent_env,
            &mut out,
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "took too long: {elapsed:?}"
        );
        assert_eq!(count, 2);

        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("network ipp://10.0.0.1/ipp"));
        assert!(text.contains("network socket://10.0.0.2"));
        assert!(!text.contains("singleword"));

        // Verify the timed-out sleeper child was actually killed (not orphaned)!
        if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
            let pid = pid_str.trim();
            // Give the kernel a few ms to clear /proc/<pid>.
            thread::sleep(Duration::from_millis(50));
            assert!(
                !Path::new(&format!("/proc/{pid}")).exists(),
                "timed-out child pid {pid} leaked!"
            );
        }

        // Test limit=1 stops after 1 line and cleans up children.
        let mut out_lim = Vec::new();
        let c_lim = run_discovery(
            &dir,
            1,
            Duration::from_secs(2),
            current_uid(),
            &parent_env,
            &mut out_lim,
        );
        assert_eq!(c_lim, 1);

        // Test run_cli validation and normal invocation.
        let mut cli_out = Vec::new();
        assert_eq!(run_cli(&["cups-deviced".into()], &mut cli_out), 1);
        let empty_dir = dir.join("empty");
        std::fs::create_dir_all(&empty_dir).unwrap();
        std::fs::set_permissions(&empty_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            run_cli(
                &[
                    "cups-deviced".into(),
                    "1".into(),
                    "0".into(),
                    "1".into(),
                    empty_dir.to_string_lossy().into_owned(),
                ],
                &mut cli_out,
            ),
            0
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
