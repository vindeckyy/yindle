//! End-to-end tests driving the real `cupsd` binary: CLI flags, `-t`,
//! `--check-config`, `doctor`, live foreground daemon with `sd_notify`,
//! `SIGHUP` hot-reload, `SIGTERM`/`SIGINT` graceful shutdown, `-l`
//! `IdleExitTimeout` exit, and fail-closed startup.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_cupsd");

fn tmp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!(
        "presswork-cupsd-it-{}-{tag}-{id}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Tree {
    base: PathBuf,
    cupsd_conf: PathBuf,
    files_conf: PathBuf,
    port: u16,
    sock: PathBuf,
}

fn write_tree(tag: &str, extra_cupsd: &str, extra_files: &str) -> Tree {
    let base = tmp_dir(tag);
    let etc = base.join("etc");
    let data = base.join("data");
    for d in [
        etc.clone(),
        base.join("spool"),
        base.join("cache"),
        base.join("logs"),
        base.join("run"),
        data.join("mime"),
        base.join("doc-root"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(
        data.join("mime").join("mime.types"),
        "text/plain txt\napplication/octet-stream\n",
    )
    .unwrap();
    std::fs::write(
        data.join("mime").join("mime.convs"),
        "application/octet-stream application/vnd.cups-raw 0 -\n",
    )
    .unwrap();
    // Name the files-config differently from the sibling default to prove `-s` is honored.
    let files_conf = etc.join("custom-files.conf");
    std::fs::write(
        &files_conf,
        format!(
            "ServerRoot {etc}\nRequestRoot {b}/spool\nCacheDir {b}/cache\nStateDir {b}/run\nDataDir {data}\nDocumentRoot {b}/doc-root\nErrorLog {b}/logs/error_log\nAccessLog {b}/logs/access_log\nPageLog {b}/logs/page_log\n{extra_files}\n",
            etc = etc.display(),
            b = base.display(),
            data = data.display(),
        ),
    )
    .unwrap();
    let port = free_port();
    let sock = base.join("run").join("cups.sock");
    let cupsd_conf = etc.join("cupsd.conf");
    std::fs::write(
        &cupsd_conf,
        format!(
            "LogLevel debug\nServerName localhost\nListen 127.0.0.1:{port}\nListen {}\nBrowsing No\nWebInterface Yes\n{extra_cupsd}\n<Location />\n  Order allow,deny\n  Allow from 127.0.0.1\n</Location>\n",
            sock.display()
        ),
    )
    .unwrap();
    Tree {
        base,
        cupsd_conf,
        files_conf,
        port,
        sock,
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn http_get(addr: SocketAddr, path: &str) -> Option<String> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out)
}

fn wait_ready(addr: SocketAddr, child: &mut Child) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Some(resp) = http_get(addr, "/healthz") {
            if resp.starts_with("HTTP/1.1 200") {
                return resp;
            }
        }
        if let Ok(Some(st)) = child.try_wait() {
            panic!("cupsd exited early: {st:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("cupsd never became ready");
}

fn signal(child: &Child, sig: &str) {
    let st = Command::new("kill")
        .args([sig, &child.id().to_string()])
        .status()
        .unwrap();
    assert!(st.success());
}

fn wait_exit(child: &mut Child, secs: u64) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return st;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("cupsd did not exit within {secs}s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn recv_notifications(sock: &UnixDatagram, want: &str, secs: u64) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut got = Vec::new();
    let mut buf = [0u8; 512];
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    while Instant::now() < deadline {
        if let Ok(n) = sock.recv(&mut buf) {
            let msg = String::from_utf8_lossy(&buf[..n]).into_owned();
            let done = msg.contains(want);
            got.push(msg);
            if done {
                break;
            }
        }
    }
    got
}

#[test]
fn help_version_and_bad_flags() {
    for flag in ["-h", "--help"] {
        let out = run(&[flag]);
        assert!(out.status.success());
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("--check-config"));
        assert!(text.contains("doctor"));
    }
    for flag in ["-v", "-V", "--version"] {
        let out = run(&[flag]);
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).starts_with("cupsd "));
    }
    let out = run(&["--definitely-not-a-flag"]);
    assert_eq!(out.status.code(), Some(1));
    let out = run(&["--log-format", "yaml"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn test_config_check_config_and_doctor() {
    let t = write_tree("cfg", "", "");
    let c = t.cupsd_conf.to_str().unwrap();
    let s = t.files_conf.to_str().unwrap();

    let out = run(&["-t", "-c", c, "-s", s]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run(&["--check-config", "-c", c, "-s", s]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Config check:"), "{text}");
    let out = run(&["--check-config", "--json", "-c", c, "-s", s]);
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.trim_start().starts_with('{'), "{json}");

    let out = run(&["doctor", "-c", c, "-s", s]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("Summary:"));
    let out = run(&["doctor", "--json", "-c", c, "-s", s]);
    assert!(String::from_utf8_lossy(&out.stdout)
        .trim_start()
        .starts_with('{'));

    // Syntax errors make `-t` fail.
    std::fs::write(&t.cupsd_conf, "<Location /\n").unwrap();
    let missing = t.base.join("missing.conf");
    let out = run(&["-t", "-c", missing.to_str().unwrap(), "-s", s]);
    assert_eq!(out.status.code(), Some(1));
    // Daemon refuses to start on an unreadable config.
    let out = run(&["-f", "-c", missing.to_str().unwrap(), "-s", s]);
    assert_eq!(out.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&t.base);
}

#[test]
fn live_daemon_sd_notify_sighup_reload_and_sigterm_shutdown() {
    let t = write_tree("live", "FilterLimit 100", "");
    let notify_path = t.base.join("notify.sock");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    let addr: SocketAddr = format!("127.0.0.1:{}", t.port).parse().unwrap();

    let mut child = Command::new(BIN)
        .args([
            "-f",
            "-c",
            t.cupsd_conf.to_str().unwrap(),
            "-s",
            t.files_conf.to_str().unwrap(),
            "--log-format",
            "json",
        ])
        .env("NOTIFY_SOCKET", &notify_path)
        .env("WATCHDOG_USEC", "200000")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    wait_ready(addr, &mut child);
    let ready = recv_notifications(&notify, "READY=1", 5);
    assert!(ready.iter().any(|m| m.contains("READY=1")), "{ready:?}");
    let wd = recv_notifications(&notify, "WATCHDOG=1", 5);
    assert!(wd.iter().any(|m| m.contains("WATCHDOG=1")), "{wd:?}");

    let metrics = http_get(addr, "/metrics").unwrap();
    assert!(metrics.contains("presswork_filter_limit 100"), "{metrics}");

    // Unix socket listener answers too.
    let mut us = UnixStream::connect(&t.sock).unwrap();
    us.write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    us.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");

    // SIGHUP hot-reload applies the new FilterLimit without dropping the listener.
    let conf = std::fs::read_to_string(&t.cupsd_conf)
        .unwrap()
        .replace("FilterLimit 100", "FilterLimit 250");
    std::fs::write(&t.cupsd_conf, conf).unwrap();
    signal(&child, "-HUP");
    let reload = recv_notifications(&notify, "READY=1", 10);
    assert!(
        reload.iter().any(|m| m.contains("RELOADING=1")),
        "{reload:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let m = http_get(addr, "/metrics").unwrap_or_default();
        if m.contains("presswork_filter_limit 250") {
            break;
        }
        assert!(Instant::now() < deadline, "reload not applied: {m}");
        std::thread::sleep(Duration::from_millis(50));
    }

    // SIGTERM -> STOPPING=1, graceful drain, state flushed, exit 0.
    signal(&child, "-TERM");
    let st = wait_exit(&mut child, 20);
    assert!(st.success(), "{st:?}");
    let stop = recv_notifications(&notify, "STOPPING=1", 2);
    assert!(stop.iter().any(|m| m.contains("STOPPING=1")), "{stop:?}");
    assert!(t.base.join("etc").join("printers.conf").is_file());
    assert!(t.base.join("cache").join("job.cache").is_file());
    let _ = std::fs::remove_dir_all(&t.base);
}

#[test]
fn sigint_shutdown_on_demand_idle_exit_and_fail_closed_startup() {
    // SIGINT graceful shutdown.
    let t = write_tree("sigint", "", "");
    let addr: SocketAddr = format!("127.0.0.1:{}", t.port).parse().unwrap();
    let mut child = Command::new(BIN)
        .args([
            "-F",
            "-c",
            t.cupsd_conf.to_str().unwrap(),
            "-s",
            t.files_conf.to_str().unwrap(),
        ])
        .env_remove("NOTIFY_SOCKET")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_ready(addr, &mut child);
    signal(&child, "-INT");
    assert!(wait_exit(&mut child, 20).success());
    let _ = std::fs::remove_dir_all(&t.base);

    // `-l` on-demand mode exits by itself after IdleExitTimeout.
    let t = write_tree("ondemand", "IdleExitTimeout 1", "");
    let addr: SocketAddr = format!("127.0.0.1:{}", t.port).parse().unwrap();
    let mut child = Command::new(BIN)
        .args([
            "-l",
            "-f",
            "-c",
            t.cupsd_conf.to_str().unwrap(),
            "-s",
            t.files_conf.to_str().unwrap(),
        ])
        .env("PRESSWORK_LOG_FORMAT", "json")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_ready(addr, &mut child);
    assert!(wait_exit(&mut child, 30).success());
    let _ = std::fs::remove_dir_all(&t.base);

    // Explicit SSLListen with no certificate and CreateSelfSignedCerts No fails closed.
    let ssl_port = free_port();
    let t = write_tree(
        "failclosed",
        &format!("SSLListen 127.0.0.1:{ssl_port}"),
        "CreateSelfSignedCerts No",
    );
    let out = Command::new(BIN)
        .args([
            "-f",
            "-c",
            t.cupsd_conf.to_str().unwrap(),
            "-s",
            t.files_conf.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("startup failed"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&t.base);
}
