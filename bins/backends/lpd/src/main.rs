//! `lpd` backend — forward a job to a remote RFC 1179 LPD print server.
//!
//! Parses `DEVICE_URI` (`lpd://[user@]host[:port]/queue[?format=l&order=control,data]`),
//! enforces SSRF protection and connect/read/write timeouts, builds a spec-compliant
//! RFC 1179 control file (`cfA<NNN><host>`) paired with the matching data file
//! (`dfA<NNN><host>`), sanitizes user/title/queue/host fields against control-file
//! command injection, and streams regular files without buffering them in RAM.

use backend_common::{self as bc, NetworkUri, SsrfPolicy};
use std::fs::File;
use std::io::{self, Read, Write};
use std::time::Duration;

const MAX_CTRL_FIELD_LEN: usize = 255;
const MAX_HOST_LEN: usize = 31;
const STREAM_BUF_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendOrder {
    ControlFirst,
    DataFirst,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    host: String,
    port: u16,
    queue: String,
    user_override: Option<String>,
    format_code: char,
    order: SendOrder,
}

struct Config {
    ssrf: SsrfPolicy,
    connect_timeout: Duration,
    io_timeout: Duration,
    client_host: String,
}

impl Config {
    fn from_env() -> Self {
        let raw_host = std::env::var("HOSTNAME")
            .ok()
            .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
            .unwrap_or_else(|| "localhost".into());
        Self {
            ssrf: SsrfPolicy::from_env(),
            connect_timeout: Duration::from_secs(30),
            io_timeout: Duration::from_secs(60),
            client_host: sanitize_lpd_host(&raw_host),
        }
    }
}

/// Sanitize an LPD control-file field value (strip CR/LF/NUL and control chars).
fn sanitize_lpd_field(s: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_len));
    for c in s.chars() {
        if c.is_control() {
            continue;
        }
        if out.len() + c.len_utf8() > max_len {
            break;
        }
        out.push(c);
    }
    out
}

/// Sanitize a hostname for RFC 1179 `H` / `cfA` / `dfA` names (max 31 printable
/// non-whitespace ASCII chars).
fn sanitize_lpd_host(host: &str) -> String {
    let mut out: String = host
        .trim()
        .chars()
        .filter(|c| c.is_ascii_graphic() && !matches!(c, '/' | '\\'))
        .take(MAX_HOST_LEN)
        .collect();
    if out.is_empty() {
        out.push_str("localhost");
    }
    out
}

/// Validate an LPD queue name (non-empty, no CR/LF/NUL/whitespace/slashes).
fn is_valid_queue(q: &str) -> bool {
    !q.is_empty()
        && q.len() <= 127
        && q.bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'/' | b'\\'))
}

/// Parse `lpd://[user@]host[:port]/queue[?format=l|f|o&order=control,data|data,control]`.
fn parse_uri(uri: &str) -> Option<Target> {
    if !uri.starts_with("lpd://") && !uri.starts_with("LPD://") {
        return None;
    }
    let parsed = NetworkUri::parse(uri, 515)?;
    let queue_raw = parsed.path.trim_start_matches('/');
    let queue = bc::percent_decode(queue_raw);
    if !is_valid_queue(&queue) {
        return None;
    }

    let mut format_code = 'l';
    let mut order = SendOrder::ControlFirst;
    if let Some(q) = &parsed.query {
        for kv in q.split(['&', '+']) {
            if let Some((k, v)) = kv.split_once('=') {
                if k.eq_ignore_ascii_case("format") {
                    if let Some(ch) = v.chars().next() {
                        if matches!(ch, 'l' | 'f' | 'o' | 'p' | 'r') {
                            format_code = ch;
                        }
                    }
                } else if k.eq_ignore_ascii_case("order") {
                    if v.eq_ignore_ascii_case("data,control") {
                        order = SendOrder::DataFirst;
                    } else if v.eq_ignore_ascii_case("control,data") {
                        order = SendOrder::ControlFirst;
                    }
                }
            }
        }
    }

    Some(Target {
        host: parsed.host,
        port: parsed.port,
        queue,
        user_override: parsed.username,
        format_code,
        order,
    })
}

/// Build an RFC 1179 `(control_filename, data_filename, control_bytes)` triple.
fn build_control_file(
    client_host: &str,
    inv: &bc::Invocation,
    user_override: Option<&str>,
    format_code: char,
) -> (String, String, String) {
    let host = sanitize_lpd_host(client_host);
    let job_num = inv.job_id.unsigned_abs() % 1000;
    let cname = format!("cfA{job_num:03}{host}");
    let dname = format!("dfA{job_num:03}{host}");

    let raw_user = user_override.unwrap_or(&inv.user);
    let mut user = sanitize_lpd_field(raw_user, MAX_CTRL_FIELD_LEN);
    if user.is_empty() {
        user.push_str("anonymous");
    }
    let mut title = sanitize_lpd_field(&inv.title, MAX_CTRL_FIELD_LEN);
    if title.is_empty() {
        title.push_str("untitled");
    }
    let copies = inv.copies.clamp(1, 100);

    let mut ctrl = format!("H{host}\nP{user}\nJ{title}\n");
    for _ in 0..copies {
        ctrl.push(format_code);
        ctrl.push_str(&dname);
        ctrl.push('\n');
    }
    ctrl.push('U');
    ctrl.push_str(&dname);
    ctrl.push('\n');
    ctrl.push('N');
    ctrl.push_str(&title);
    ctrl.push('\n');

    (cname, dname, ctrl)
}

/// Read exactly one status byte; LPD `0` means OK.
fn read_ack(s: &mut impl Read) -> io::Result<()> {
    let mut b = [0u8; 1];
    s.read_exact(&mut b)?;
    if b[0] == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "lpd: server rejected command (ack {})",
            b[0]
        )))
    }
}

enum DataPayload {
    File(File, u64),
    Buffer(Vec<u8>),
}

impl DataPayload {
    fn len(&self) -> u64 {
        match self {
            Self::File(_, n) => *n,
            Self::Buffer(v) => v.len() as u64,
        }
    }

    fn write_to(&mut self, w: &mut impl Write) -> io::Result<()> {
        match self {
            Self::Buffer(v) => w.write_all(v),
            Self::File(f, expected) => {
                let mut rem = *expected;
                let mut buf = [0u8; STREAM_BUF_SIZE];
                while rem > 0 {
                    let want = usize::try_from(rem.min(buf.len() as u64)).unwrap_or(buf.len());
                    let n = f.read(&mut buf[..want])?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "document truncated while sending",
                        ));
                    }
                    w.write_all(&buf[..n])?;
                    rem -= n as u64;
                }
                Ok(())
            }
        }
    }
}

fn open_payload(inv: &bc::Invocation) -> io::Result<DataPayload> {
    if let Some(path) = &inv.file {
        let f = File::open(path)?;
        let meta = f.metadata()?;
        if meta.file_type().is_file() {
            return Ok(DataPayload::File(f, meta.len()));
        }
    }
    let mut doc = bc::document(inv)?;
    let mut buf = Vec::new();
    doc.read_to_end(&mut buf)?;
    Ok(DataPayload::Buffer(buf))
}

fn send_control(s: &mut (impl Read + Write), cname: &str, ctrl: &str) -> io::Result<()> {
    s.write_all(&[0x02])?;
    s.write_all(format!("{} {cname}\n", ctrl.len()).as_bytes())?;
    s.flush()?;
    read_ack(s)?;
    s.write_all(ctrl.as_bytes())?;
    s.write_all(&[0])?;
    s.flush()?;
    read_ack(s)
}

fn send_data(
    s: &mut (impl Read + Write),
    dname: &str,
    payload: &mut DataPayload,
) -> io::Result<()> {
    s.write_all(&[0x03])?;
    s.write_all(format!("{} {dname}\n", payload.len()).as_bytes())?;
    s.flush()?;
    read_ack(s)?;
    payload.write_to(s)?;
    s.write_all(&[0])?;
    s.flush()?;
    read_ack(s)
}

fn send_lpd(
    s: &mut (impl Read + Write),
    target: &Target,
    cfg: &Config,
    inv: &bc::Invocation,
    payload: &mut DataPayload,
) -> io::Result<()> {
    // 02 <queue>\n — receive a printer job.
    s.write_all(&[0x02])?;
    s.write_all(target.queue.as_bytes())?;
    s.write_all(b"\n")?;
    s.flush()?;
    read_ack(s)?;

    let (cname, dname, ctrl) = build_control_file(
        &cfg.client_host,
        inv,
        target.user_override.as_deref(),
        target.format_code,
    );

    match target.order {
        SendOrder::ControlFirst => {
            send_control(s, &cname, &ctrl)?;
            send_data(s, &dname, payload)?;
        }
        SendOrder::DataFirst => {
            send_data(s, &dname, payload)?;
            send_control(s, &cname, &ctrl)?;
        }
    }
    Ok(())
}

fn discover_to(out: &mut impl Write) -> i32 {
    let _ = bc::report_to(
        out,
        "network",
        "lpd",
        "Unknown",
        "LPD/LPR Host or Printer",
        None,
    );
    bc::code::OK
}

fn print_with_config(inv: &bc::Invocation, cfg: &Config) -> i32 {
    let redacted = bc::redact_uri(&inv.device_uri);
    let Some(target) = parse_uri(&inv.device_uri) else {
        bc::error(format_args!("lpd: bad device-uri {redacted}"));
        return bc::code::FAILED;
    };
    let mut payload = match open_payload(inv) {
        Ok(p) => p,
        Err(e) => {
            bc::error(format_args!("lpd: open document: {e}"));
            return bc::code::FAILED;
        }
    };

    bc::state("+connecting-to-device");
    let (mut stream, _addr) =
        match cfg
            .ssrf
            .connect_checked(&target.host, target.port, cfg.connect_timeout)
        {
            Ok(pair) => pair,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                bc::state("-connecting-to-device");
                bc::error(format_args!("lpd: {redacted} blocked by policy: {e}"));
                return bc::code::FAILED;
            }
            Err(e) => {
                bc::state("-connecting-to-device");
                bc::error(format_args!("lpd: connect {redacted}: {e}"));
                return bc::code::RETRY;
            }
        };
    bc::state("-connecting-to-device");
    let _ = stream.set_read_timeout(Some(cfg.io_timeout));
    let _ = stream.set_write_timeout(Some(cfg.io_timeout));

    match send_lpd(&mut stream, &target, cfg, inv, &mut payload) {
        Ok(()) => {
            bc::info(format_args!(
                "lpd: job {} sent to {}/{}",
                inv.job_id,
                bc::format_host_port(&target.host, target.port),
                target.queue
            ));
            bc::code::OK
        }
        Err(e) => {
            bc::error(format_args!("lpd: transfer to {redacted} failed: {e}"));
            bc::code::RETRY
        }
    }
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
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::thread;

    fn test_cfg() -> Config {
        Config {
            ssrf: SsrfPolicy {
                allow_loopback: true,
            },
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(5),
            client_host: "workstation".into(),
        }
    }

    #[test]
    fn parse_uri_valid_ipv6_options_and_rejects_bad() {
        let t1 = parse_uri("lpd://printer.local/raw").unwrap();
        assert_eq!(t1.host, "printer.local");
        assert_eq!(t1.port, 515);
        assert_eq!(t1.queue, "raw");
        assert_eq!(t1.format_code, 'l');
        assert_eq!(t1.order, SendOrder::ControlFirst);

        let t2 = parse_uri("lpd://alice@[::1]:5150/lp1?format=f&order=data,control").unwrap();
        assert_eq!(t2.host, "::1");
        assert_eq!(t2.port, 5150);
        assert_eq!(t2.queue, "lp1");
        assert_eq!(t2.user_override.as_deref(), Some("alice"));
        assert_eq!(t2.format_code, 'f');
        assert_eq!(t2.order, SendOrder::DataFirst);

        let t3 = parse_uri("lpd://10.0.0.2/lp?order=control,data").unwrap();
        assert_eq!(t3.order, SendOrder::ControlFirst);

        for bad in [
            "ipp://host/q",
            "lpd://host/",
            "lpd://host/a/b",
            "lpd://host/q\r\ninject",
            "lpd://host:0/q",
            "lpd://host/q%0ainject",
        ] {
            assert!(parse_uri(bad).is_none(), "expected reject: {bad}");
        }
    }

    #[test]
    fn control_file_format_and_injection_sanitization() {
        let inv = bc::Invocation {
            job_id: 1042,
            user: "alice\nMevil\r".into(),
            title: "Q1 Report\nU/etc/passwd".into(),
            copies: 2,
            options: String::new(),
            file: None,
            device_uri: "lpd://host/raw".into(),
        };
        let (cname, dname, ctrl) = build_control_file("client\n.local", &inv, None, 'l');
        assert_eq!(cname, "cfA042client.local");
        assert_eq!(dname, "dfA042client.local");
        assert!(!ctrl.contains("fdfA###"));
        let lines: Vec<&str> = ctrl.lines().collect();
        assert_eq!(
            lines,
            vec![
                "Hclient.local",
                "PaliceMevil",
                "JQ1 ReportU/etc/passwd",
                "ldfA042client.local",
                "ldfA042client.local",
                "UdfA042client.local",
                "NQ1 ReportU/etc/passwd",
            ]
        );

        // Empty user/title/host fallbacks.
        let inv_empty = bc::Invocation {
            job_id: -7,
            user: "\r\n".into(),
            title: "\x00".into(),
            copies: 0,
            options: String::new(),
            file: None,
            device_uri: String::new(),
        };
        let (c2, d2, ctrl2) = build_control_file("   ", &inv_empty, None, 'f');
        assert_eq!(c2, "cfA007localhost");
        assert_eq!(d2, "dfA007localhost");
        assert!(ctrl2.contains("Panonymous\n"));
        assert!(ctrl2.contains("Juntitled\n"));
        assert!(ctrl2.contains("fdfA007localhost\n"));
    }

    #[test]
    fn end_to_end_lpd_both_orders_and_errors() {
        for (order_q, expect_first_cmd) in [
            ("order=control,data", 0x02u8),
            ("order=data,control", 0x03u8),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let srv = thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                // Receive queue command: 02 raw\n
                let mut cmd = [0u8; 1];
                r.read_exact(&mut cmd).unwrap();
                assert_eq!(cmd[0], 0x02);
                let mut q = String::new();
                r.read_line(&mut q).unwrap();
                assert_eq!(q, "raw\n");
                s.write_all(&[0]).unwrap();

                let mut seen = Vec::new();
                for _ in 0..2 {
                    let mut sub = [0u8; 1];
                    r.read_exact(&mut sub).unwrap();
                    seen.push(sub[0]);
                    let mut hdr = String::new();
                    r.read_line(&mut hdr).unwrap();
                    let mut parts = hdr.trim().split(' ');
                    let sz: usize = parts.next().unwrap().parse().unwrap();
                    let fname = parts.next().unwrap().to_string();
                    s.write_all(&[0]).unwrap();
                    let mut buf = vec![0u8; sz];
                    r.read_exact(&mut buf).unwrap();
                    let mut nul = [0u8; 1];
                    r.read_exact(&mut nul).unwrap();
                    assert_eq!(nul[0], 0);
                    s.write_all(&[0]).unwrap();
                    if sub[0] == 0x02 {
                        assert!(fname.starts_with("cfA012"));
                        let text = String::from_utf8(buf).unwrap();
                        assert!(text.contains("ldfA012workstation\n"));
                    } else {
                        assert!(fname.starts_with("dfA012"));
                        assert_eq!(buf, b"print payload");
                    }
                }
                assert_eq!(seen[0], expect_first_cmd);
            });

            let dir = std::env::temp_dir()
                .join(format!("pw-lpd-{}-{expect_first_cmd}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let doc = dir.join("job.bin");
            std::fs::write(&doc, b"print payload").unwrap();

            let inv = bc::Invocation {
                job_id: 12,
                user: "alice".into(),
                title: "Doc".into(),
                copies: 1,
                options: String::new(),
                file: Some(doc.to_string_lossy().into_owned()),
                device_uri: format!("lpd://127.0.0.1:{port}/raw?{order_q}"),
            };
            assert_eq!(print_with_config(&inv, &test_cfg()), bc::code::OK);
            srv.join().unwrap();
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn end_to_end_lpd_errors_ssrf_and_discovery() {
        // Server NACK returns RETRY.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf);
            s.write_all(&[1]).unwrap();
        });
        let dir = std::env::temp_dir().join(format!("pw-lpd-nack-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let doc = dir.join("job.bin");
        std::fs::write(&doc, b"x").unwrap();
        let inv = bc::Invocation {
            job_id: 1,
            user: "u".into(),
            title: "t".into(),
            copies: 1,
            options: String::new(),
            file: Some(doc.to_string_lossy().into_owned()),
            device_uri: format!("lpd://127.0.0.1:{port}/raw"),
        };
        assert_eq!(print_with_config(&inv, &test_cfg()), bc::code::RETRY);
        srv.join().unwrap();

        // SSRF blocks metadata IP.
        let inv_ssrf = bc::Invocation {
            device_uri: "lpd://169.254.169.254/raw".into(),
            ..inv.clone()
        };
        assert_eq!(print_with_config(&inv_ssrf, &test_cfg()), bc::code::FAILED);

        // Bad URI & missing file.
        let inv_bad = bc::Invocation {
            device_uri: "http://host/raw".into(),
            ..inv.clone()
        };
        assert_eq!(print_with_config(&inv_bad, &test_cfg()), bc::code::FAILED);
        let inv_nf = bc::Invocation {
            file: Some(dir.join("missing").to_string_lossy().into_owned()),
            ..inv
        };
        assert_eq!(print_with_config(&inv_nf, &test_cfg()), bc::code::FAILED);

        // Truncation of long field (> 255 bytes).
        let long = "a".repeat(300);
        assert_eq!(
            sanitize_lpd_field(&long, MAX_CTRL_FIELD_LEN).len(),
            MAX_CTRL_FIELD_LEN
        );

        // Unknown format/order values fall back safely.
        let t_fb = parse_uri("lpd://10.0.0.2/lp?format=z&order=weird").unwrap();
        assert_eq!(t_fb.format_code, 'l');
        assert_eq!(t_fb.order, SendOrder::ControlFirst);

        // Closed port connect failure returns RETRY.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        let inv_closed = bc::Invocation {
            device_uri: format!("lpd://127.0.0.1:{closed_port}/raw"),
            file: Some(doc.to_string_lossy().into_owned()),
            ..inv_bad
        };
        assert_eq!(print_with_config(&inv_closed, &test_cfg()), bc::code::RETRY);

        // Truncated file payload errors cleanly.
        let f = File::open(&doc).unwrap();
        let mut trunc = DataPayload::File(f, 999);
        let mut sink2 = Vec::new();
        assert!(trunc.write_to(&mut sink2).is_err());

        // Discovery + Buffer payload test + Config::from_env.
        let mut out = Vec::new();
        assert_eq!(discover_to(&mut out), bc::code::OK);
        assert!(String::from_utf8(out).unwrap().contains("network lpd "));
        let mut buf_payload = DataPayload::Buffer(b"abc".to_vec());
        let mut sink = Vec::new();
        assert_eq!(buf_payload.len(), 3);
        buf_payload.write_to(&mut sink).unwrap();
        assert_eq!(sink, b"abc");
        let _ = Config::from_env();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
