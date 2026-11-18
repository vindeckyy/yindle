//! `socket` backend — AppSocket/JetDirect `:9100` (`backend/socket.c`).
//!
//! `socket://host[:port][?waiteof=true|false]` — streams the document raw over
//! TCP to the printer with full IPv6 bracket support, SSRF enforcement,
//! connect/read/write timeouts, and optional `waiteof` EOF drain.

use backend_common::{self as bc, NetworkUri, SsrfPolicy};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::time::Duration;

const STREAM_BUF_SIZE: usize = 16 * 1024;
const MAX_WAITEOF_DRAIN: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    host: String,
    port: u16,
    wait_eof: bool,
}

struct Config {
    ssrf: SsrfPolicy,
    connect_timeout: Duration,
    write_timeout: Duration,
    waiteof_timeout: Duration,
}

impl Config {
    fn from_env() -> Self {
        Self {
            ssrf: SsrfPolicy::from_env(),
            connect_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(60),
            waiteof_timeout: Duration::from_secs(30),
        }
    }
}

/// Parse `socket://host[:port][?waiteof=true|false]`, supporting IPv6 brackets.
fn parse_uri(uri: &str) -> Option<Target> {
    if !uri.starts_with("socket://") && !uri.starts_with("SOCKET://") {
        return None;
    }
    let parsed = NetworkUri::parse(uri, 9100)?;
    let mut wait_eof = true;
    if let Some(q) = &parsed.query {
        for kv in q.split(['&', '+']) {
            if let Some((k, v)) = kv.split_once('=') {
                if k.eq_ignore_ascii_case("waiteof") {
                    if let Some(b) = bc::parse_env_bool(Some(v)) {
                        wait_eof = b;
                    }
                }
            }
        }
    }
    Some(Target {
        host: parsed.host,
        port: parsed.port,
        wait_eof,
    })
}

fn discover_to(out: &mut impl Write) -> i32 {
    let _ = bc::report_to(
        out,
        "network",
        "socket",
        "Unknown",
        "AppSocket/HP JetDirect",
        None,
    );
    bc::code::OK
}

fn stream_document(doc: &mut impl Read, stream: &mut impl Write) -> Result<u64, i32> {
    let mut buf = [0u8; STREAM_BUF_SIZE];
    let mut total = 0u64;
    loop {
        match doc.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                if let Err(e) = stream.write_all(&buf[..n]) {
                    bc::error(format_args!("socket: write failed: {e}"));
                    return Err(bc::code::RETRY);
                }
                total += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                bc::error(format_args!("socket: read failed: {e}"));
                return Err(bc::code::FAILED);
            }
        }
    }
}

fn print_with_config(inv: &bc::Invocation, cfg: &Config) -> i32 {
    let redacted = bc::redact_uri(&inv.device_uri);
    let Some(target) = parse_uri(&inv.device_uri) else {
        bc::error(format_args!("socket: bad device URI {redacted}"));
        return bc::code::FAILED;
    };

    let mut doc = match bc::document(inv) {
        Ok(d) => d,
        Err(e) => {
            bc::error(format_args!("socket: cannot open document: {e}"));
            return bc::code::FAILED;
        }
    };

    bc::state("+connecting-to-device");
    let (mut stream, addr) =
        match cfg
            .ssrf
            .connect_checked(&target.host, target.port, cfg.connect_timeout)
        {
            Ok(pair) => pair,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                bc::state("-connecting-to-device");
                bc::error(format_args!("socket: {redacted} blocked by policy: {e}"));
                return bc::code::FAILED;
            }
            Err(e) => {
                bc::state("-connecting-to-device");
                bc::error(format_args!("socket: cannot connect to {redacted}: {e}"));
                return bc::code::RETRY;
            }
        };
    bc::state("-connecting-to-device");
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(cfg.write_timeout));
    let _ = stream.set_read_timeout(Some(cfg.waiteof_timeout));

    let total = match stream_document(&mut doc, &mut stream) {
        Ok(n) => n,
        Err(code) => return code,
    };
    let _ = stream.flush();
    // Half-close write side so the printer observes EOF on this job.
    let _ = stream.shutdown(Shutdown::Write);

    if target.wait_eof {
        let mut drained = 0usize;
        let mut drain_buf = [0u8; 1024];
        while drained < MAX_WAITEOF_DRAIN {
            match stream.read(&mut drain_buf) {
                Ok(0) => break,
                Ok(n) => drained += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    }

    bc::info(format_args!("socket: sent {total} bytes to {addr}"));
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
    use std::net::TcpListener;
    use std::thread;

    fn test_cfg() -> Config {
        Config {
            ssrf: SsrfPolicy {
                allow_loopback: true,
            },
            connect_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            waiteof_timeout: Duration::from_secs(2),
        }
    }

    #[test]
    fn parse_uri_ipv4_ipv6_and_waiteof() {
        let t1 = parse_uri("socket://192.168.1.50").unwrap();
        assert_eq!(t1.host, "192.168.1.50");
        assert_eq!(t1.port, 9100);
        assert!(t1.wait_eof);

        let t2 = parse_uri("socket://[::1]:9101/?waiteof=false").unwrap();
        assert_eq!(t2.host, "::1");
        assert_eq!(t2.port, 9101);
        assert!(!t2.wait_eof);

        let t3 = parse_uri("socket://[2001:db8::9]?waiteof=yes").unwrap();
        assert_eq!(t3.host, "2001:db8::9");
        assert_eq!(t3.port, 9100);
        assert!(t3.wait_eof);

        for bad in [
            "ipp://host:9100",
            "socket://:9100",
            "socket://host:0",
            "socket://::1",
            "socket://host\r\n",
        ] {
            assert!(parse_uri(bad).is_none(), "expected reject: {bad}");
        }
    }

    #[test]
    fn socket_stream_waiteof_and_ssrf() {
        for wait_q in ["waiteof=true", "waiteof=false"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let srv = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                let mut got = Vec::new();
                s.read_to_end(&mut got).unwrap();
                assert_eq!(got, b"raw-jetdirect-bytes");
                let _ = s.write_all(b"OK\n");
            });

            let dir = std::env::temp_dir().join(format!("pw-sock-{}-{wait_q}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let doc = dir.join("job.pcl");
            std::fs::write(&doc, b"raw-jetdirect-bytes").unwrap();

            let inv = bc::Invocation {
                job_id: 1,
                user: "u".into(),
                title: "t".into(),
                copies: 1,
                options: String::new(),
                file: Some(doc.to_string_lossy().into_owned()),
                device_uri: format!("socket://127.0.0.1:{port}?{wait_q}"),
            };
            assert_eq!(print_with_config(&inv, &test_cfg()), bc::code::OK);
            srv.join().unwrap();
            let _ = std::fs::remove_dir_all(&dir);
        }

        // SSRF blocks metadata IP and strict loopback.
        let dir = std::env::temp_dir().join(format!("pw-sock-err-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let doc = dir.join("j");
        std::fs::write(&doc, b"x").unwrap();

        let inv_meta = bc::Invocation {
            job_id: 2,
            user: "u".into(),
            title: "t".into(),
            copies: 1,
            options: String::new(),
            file: Some(doc.to_string_lossy().into_owned()),
            device_uri: "socket://169.254.169.254:9100".into(),
        };
        assert_eq!(print_with_config(&inv_meta, &test_cfg()), bc::code::FAILED);

        // Unreachable port returns RETRY.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = listener.local_addr().unwrap().port();
        drop(listener);
        let inv_closed = bc::Invocation {
            device_uri: format!("socket://127.0.0.1:{closed_port}"),
            ..inv_meta.clone()
        };
        assert_eq!(print_with_config(&inv_closed, &test_cfg()), bc::code::RETRY);

        // Bad URI and missing file return FAILED.
        let inv_bad = bc::Invocation {
            device_uri: "lpd://host/q".into(),
            ..inv_meta.clone()
        };
        assert_eq!(print_with_config(&inv_bad, &test_cfg()), bc::code::FAILED);
        let inv_nf = bc::Invocation {
            device_uri: "socket://127.0.0.1:9100".into(),
            file: Some(dir.join("missing").to_string_lossy().into_owned()),
            ..inv_meta
        };
        assert_eq!(print_with_config(&inv_nf, &test_cfg()), bc::code::FAILED);

        let mut out = Vec::new();
        assert_eq!(discover_to(&mut out), bc::code::OK);
        assert!(String::from_utf8(out).unwrap().contains("network socket "));
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
    fn stream_document_handles_read_and_write_errors() {
        let mut cur = io::Cursor::new(b"abc".to_vec());
        assert_eq!(stream_document(&mut cur, &mut FailIo), Err(bc::code::RETRY));
        let mut sink = Vec::new();
        assert_eq!(
            stream_document(&mut FailIo, &mut sink),
            Err(bc::code::FAILED)
        );
        let _ = FailIo.flush();
    }
}
