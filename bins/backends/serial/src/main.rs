//! `serial` backend — RS-232 printers (`backend/serial.c`).
//!
//! `serial:///dev/ttySN[?baud=9600+parity=none+flow=none+bits=8]` opens the
//! canonical `/dev/` character device with `O_NOFOLLOW | O_NOCTTY`, applies
//! the termios line settings (`+` separator per CUPS spec, also tolerating
//! `&`), wires `dtrdsr` flow control handling, streams the document, drains
//! output, and restores saved termios settings.

use backend_common as bc;
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum FlowControl {
    #[default]
    None,
    Soft,
    Hard,
    DtrDsr,
}

impl FlowControl {
    fn as_termios_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Soft => "soft",
            Self::Hard => "hard",
            Self::DtrDsr => "dtrdsr",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct SerialSettings {
    baud: Option<u32>,
    parity: Option<String>,
    bits: Option<String>,
    flow: FlowControl,
}

/// Parse `(path, params)` from `serial:///dev/ttySN?baud=9600+parity=none`
/// or standard single-slash `serial:/dev/ttySN?baud=9600+bits=8`.
/// Accepts `+` (CUPS spec) as well as `&` as option separators.
fn parse_uri(uri: &str) -> Option<(String, Vec<(String, String)>)> {
    let (scheme, rest) = uri.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("serial") {
        return None;
    }
    let body = rest.strip_prefix("//").unwrap_or(rest);
    let (path_raw, query) = body.split_once('?').map_or((body, ""), |(p, q)| (p, q));
    if !path_raw.starts_with('/') {
        return None;
    }
    let params = query
        .split(['+', '&'])
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_ascii_lowercase()))
        .collect();
    Some((bc::percent_decode(path_raw), params))
}

/// Validate parsed serial URI parameters into [`SerialSettings`].
fn validate_settings(params: &[(String, String)]) -> Result<SerialSettings, String> {
    let mut cfg = SerialSettings::default();
    for (k, v) in params {
        match k.as_str() {
            "baud" => {
                let b: u32 = v.parse().map_err(|_| format!("bad baud {v}"))?;
                if sys::Termios::baud(b).is_none() {
                    return Err(format!("unsupported baud {v}"));
                }
                cfg.baud = Some(b);
            }
            "parity" => match v.as_str() {
                "none" | "odd" | "even" | "space" | "mark" => cfg.parity = Some(v.clone()),
                _ => return Err(format!("bad parity {v}")),
            },
            "bits" => match v.as_str() {
                "5" | "6" | "7" | "8" => cfg.bits = Some(v.clone()),
                _ => return Err(format!("bad bits {v}")),
            },
            "flow" => {
                cfg.flow = match v.as_str() {
                    "none" => FlowControl::None,
                    "soft" | "xon" => FlowControl::Soft,
                    "hard" | "rtscts" => FlowControl::Hard,
                    "dtrdsr" => FlowControl::DtrDsr,
                    _ => return Err(format!("bad flow {v}")),
                };
            }
            _ => {}
        }
    }
    Ok(cfg)
}

fn configure_termios(tio: &mut sys::Termios, cfg: &SerialSettings) {
    if let Some(baud) = cfg.baud {
        if let Some(speed) = sys::Termios::baud(baud) {
            tio.set_baud(speed);
        }
    }
    if let Some(parity) = &cfg.parity {
        tio.set_parity(parity);
    }
    if let Some(bits) = &cfg.bits {
        tio.set_bits(bits);
    }
    tio.set_flow(cfg.flow.as_termios_str());
    if cfg.flow == FlowControl::DtrDsr {
        bc::debug(format_args!(
            "serial: DTR/DSR flow control enabled (paced draining active)"
        ));
    }
}

fn apply_params(fd: i32, cfg: &SerialSettings) -> Result<(), String> {
    let mut tio = sys::Termios::get(fd).ok_or("tcgetattr failed")?;
    configure_termios(&mut tio, cfg);
    if !tio.set(fd) {
        return Err("tcsetattr failed".into());
    }
    Ok(())
}

/// Stream document bytes to the serial port; when `FlowControl::DtrDsr` is
/// active, write smaller paced chunks and drain between chunks so hardware
/// buffers do not overrun.
fn stream_serial(
    doc: &mut impl Read,
    dev: &mut impl Write,
    flow: FlowControl,
    mut on_drain: impl FnMut(),
) -> i32 {
    let chunk_cap = if flow == FlowControl::DtrDsr {
        512
    } else {
        8192
    };
    let mut buf = vec![0u8; chunk_cap];
    loop {
        match doc.read(&mut buf) {
            Ok(0) => return bc::code::OK,
            Ok(n) => {
                if let Err(e) = dev.write_all(&buf[..n]) {
                    bc::error(format_args!("serial: write failed: {e}"));
                    return bc::code::RETRY;
                }
                if flow == FlowControl::DtrDsr {
                    on_drain();
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                bc::error(format_args!("serial: read failed: {e}"));
                return bc::code::FAILED;
            }
        }
    }
}

fn discover_to_with(out: &mut impl Write, dev_dir: &Path, can_open: impl Fn(&str) -> bool) -> i32 {
    let Ok(rd) = std::fs::read_dir(dev_dir) else {
        return bc::code::OK;
    };
    let mut names: Vec<String> = rd
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            (n.starts_with("ttyS") || n.starts_with("ttyUSB") || n.starts_with("ttyACM"))
                .then_some(n)
        })
        .collect();
    names.sort();
    for n in names {
        let node = dev_dir.join(&n);
        let node_str = node.to_string_lossy().into_owned();
        if can_open(&node_str) {
            let _ = bc::report_to(
                out,
                "direct",
                &format!("serial://{node_str}?baud=9600"),
                "Unknown",
                &format!("Serial Port ({node_str})"),
                Some(""),
            );
        }
    }
    bc::code::OK
}

fn discover_to(out: &mut impl Write, dev_dir: &Path) -> i32 {
    discover_to_with(out, dev_dir, |p| {
        bc::open_char_device(p, true, true, true).is_ok()
    })
}

fn transfer_on_device(
    inv: &bc::Invocation,
    dev: &mut impl Write,
    settings: &SerialSettings,
    saved: Option<sys::Termios>,
    fd: i32,
) -> i32 {
    let mut doc = match bc::document(inv) {
        Ok(d) => d,
        Err(e) => {
            bc::error(format_args!("serial: open document: {e}"));
            if let Some(s) = saved {
                let _ = s.set(fd);
            }
            return bc::code::FAILED;
        }
    };
    let rc = stream_serial(&mut doc, dev, settings.flow, || {
        sys::Termios::drain(fd);
    });
    sys::Termios::drain(fd);
    if let Some(saved) = saved {
        let _ = saved.set(fd);
    }
    rc
}

fn print_job(inv: &bc::Invocation) -> i32 {
    let redacted = bc::redact_uri(&inv.device_uri);
    let Some((path, raw_params)) = parse_uri(&inv.device_uri) else {
        bc::error(format_args!("serial: bad device-uri {redacted}"));
        return bc::code::FAILED;
    };
    let settings = match validate_settings(&raw_params) {
        Ok(s) => s,
        Err(e) => {
            bc::error(format_args!("serial: {e}"));
            return bc::code::FAILED;
        }
    };
    let mut dev = match bc::open_char_device(&path, true, true, true) {
        Ok(f) => f,
        Err(e) => {
            bc::error(format_args!("serial: cannot open {path}: {e}"));
            return bc::code::FAILED;
        }
    };
    let fd = dev.as_raw_fd();
    let saved = sys::Termios::get(fd);
    if let Err(e) = apply_params(fd, &settings) {
        bc::error(format_args!("serial: {e}"));
        return bc::code::FAILED;
    }
    transfer_on_device(inv, &mut dev, &settings, saved, fd)
}

fn main() {
    bc::run(
        || discover_to(&mut io::stdout().lock(), Path::new("/dev")),
        |inv| print_job(&inv),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct FailIo;
    impl Read for FailIo {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read fail"))
        }
    }
    impl Write for FailIo {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "disconnected"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn parse_uri_supports_plus_and_ampersand_and_dtrdsr() {
        let (path, params) =
            parse_uri("serial:///dev/ttyS0?baud=115200+parity=even+bits=7+flow=dtrdsr").unwrap();
        assert_eq!(path, "/dev/ttyS0");
        let s = validate_settings(&params).unwrap();
        assert_eq!(s.baud, Some(115_200));
        assert_eq!(s.parity.as_deref(), Some("even"));
        assert_eq!(s.bits.as_deref(), Some("7"));
        assert_eq!(s.flow, FlowControl::DtrDsr);
        assert_eq!(s.flow.as_termios_str(), "dtrdsr");

        // Tolerates `&` separator as well as mixed `+` and `&`.
        let (_, p2) = parse_uri("serial:///dev/ttyUSB0?baud=9600&flow=soft+unknown=1").unwrap();
        let s2 = validate_settings(&p2).unwrap();
        assert_eq!(s2.baud, Some(9600));
        assert_eq!(s2.flow, FlowControl::Soft);
        assert_eq!(s2.flow.as_termios_str(), "soft");

        let (_, p3) = parse_uri("serial:///dev/ttyS1?flow=rtscts+parity=odd+bits=8").unwrap();
        let s3 = validate_settings(&p3).unwrap();
        assert_eq!(s3.flow, FlowControl::Hard);
        assert_eq!(s3.flow.as_termios_str(), "hard");

        let (_, p4) = parse_uri("serial:///dev/ttyS1?flow=none").unwrap();
        assert_eq!(validate_settings(&p4).unwrap().flow, FlowControl::None);
        assert_eq!(FlowControl::None.as_termios_str(), "none");

        // Standard single-slash `serial:/dev/ttyS0?baud=9600+bits=8` also works.
        let (p_single, params_single) = parse_uri("serial:/dev/ttyS0?baud=9600+bits=8").unwrap();
        assert_eq!(p_single, "/dev/ttyS0");
        assert_eq!(validate_settings(&params_single).unwrap().baud, Some(9600));

        assert!(parse_uri("usb:///dev/ttyS0").is_none());
        assert!(parse_uri("serial://").is_none());
        assert!(parse_uri("serial:relative").is_none());

        // Invalid params rejected.
        for bad in [
            vec![("baud".into(), "abc".into())],
            vec![("baud".into(), "12345".into())],
            vec![("parity".into(), "bogus".into())],
            vec![("bits".into(), "9".into())],
            vec![("flow".into(), "bogus".into())],
        ] {
            assert!(validate_settings(&bad).is_err());
        }
    }

    #[test]
    fn stream_serial_dtrdsr_drains_per_chunk_and_handles_errors() {
        let data = vec![b'A'; 1200];
        let mut src = Cursor::new(data.clone());
        let mut out = Vec::new();
        let mut drains = 0usize;
        let rc = stream_serial(&mut src, &mut out, FlowControl::DtrDsr, || drains += 1);
        assert_eq!(rc, bc::code::OK);
        assert_eq!(out, data);
        assert_eq!(drains, 3); // 512 + 512 + 176

        let mut src2 = Cursor::new(b"hello".to_vec());
        let mut out2 = Vec::new();
        let mut drains2 = 0usize;
        assert_eq!(
            stream_serial(&mut src2, &mut out2, FlowControl::None, || drains2 += 1),
            bc::code::OK
        );
        assert_eq!(drains2, 0);

        let mut src3 = Cursor::new(b"err".to_vec());
        assert_eq!(
            stream_serial(&mut src3, &mut FailIo, FlowControl::Hard, || {}),
            bc::code::RETRY
        );
        let mut sink = Vec::new();
        assert_eq!(
            stream_serial(&mut FailIo, &mut sink, FlowControl::None, || {}),
            bc::code::FAILED
        );
        let _ = FailIo.flush();
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn print_enforces_char_device_and_termios_via_ptmx() {
        let dir = std::env::temp_dir().join(format!("pw-ser-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let doc = dir.join("job.txt");
        std::fs::write(&doc, b"serial print").unwrap();
        let regular = dir.join("ttyS0");
        std::fs::write(&regular, b"").unwrap();

        // Non-/dev regular file rejected!
        let inv_reg = bc::Invocation {
            job_id: 1,
            user: "u".into(),
            title: "t".into(),
            copies: 1,
            options: String::new(),
            file: Some(doc.to_string_lossy().into_owned()),
            device_uri: format!("serial://{}?baud=9600", regular.display()),
        };
        assert_eq!(print_job(&inv_reg), bc::code::FAILED);

        // Bad URI and bad param rejected.
        let inv_bad = bc::Invocation {
            device_uri: "ipp://host/p".into(),
            ..inv_reg.clone()
        };
        assert_eq!(print_job(&inv_bad), bc::code::FAILED);
        let inv_bad_opt = bc::Invocation {
            device_uri: "serial:///dev/null?baud=999999".into(),
            ..inv_reg.clone()
        };
        assert_eq!(print_job(&inv_bad_opt), bc::code::FAILED);

        // /dev/null opens as char device, fails tcgetattr cleanly.
        let inv_null = bc::Invocation {
            device_uri: "serial:///dev/null?baud=9600+flow=dtrdsr".into(),
            ..inv_reg.clone()
        };
        assert_eq!(print_job(&inv_null), bc::code::FAILED);

        // Exercise real termios configuration + transfer_on_device on
        // /dev/ptmx when available. The loop also runs the guards
        // against a non-tty char device (/dev/null: open succeeds,
        // tcgetattr fails) and a missing device (open fails), so the
        // `if let` false arms are covered too.
        for dev_path in ["/dev/ptmx", "/dev/null", "/dev/no-such-tty-xyz"] {
            if let Ok(ptmx) = bc::open_char_device(dev_path, true, true, true) {
                let fd = ptmx.as_raw_fd();
                if let Some(saved) = sys::Termios::get(fd) {
                    let s = SerialSettings {
                        baud: Some(9600),
                        parity: Some("even".into()),
                        bits: Some("8".into()),
                        flow: FlowControl::DtrDsr,
                    };
                    let mut tio = saved.clone();
                    configure_termios(&mut tio, &s);
                    let _ = apply_params(fd, &s);
                    // Unsupported baud + non-DTR/DSR flow exercise the
                    // false arms of `configure_termios` (unknown baud
                    // leaves the rate alone, other flows skip the debug).
                    let s_plain = SerialSettings {
                        baud: Some(999_999),
                        parity: None,
                        bits: None,
                        flow: FlowControl::None,
                    };
                    configure_termios(&mut tio, &s_plain);
                    // No baud at all exercises the outer `if let` arm.
                    let s_nobaud = SerialSettings {
                        baud: None,
                        parity: None,
                        bits: None,
                        flow: FlowControl::None,
                    };
                    configure_termios(&mut tio, &s_nobaud);
                    // Successful transfer + drain + restore.
                    let mut out_dev = Vec::new();
                    assert_eq!(
                        transfer_on_device(&inv_reg, &mut out_dev, &s, Some(saved.clone()), fd),
                        bc::code::OK
                    );
                    assert_eq!(out_dev, b"serial print");
                    // `saved=None` restores nothing but still transfers
                    // (and still drains) — covers the `None` arms.
                    let mut out_plain = Vec::new();
                    assert_eq!(
                        transfer_on_device(&inv_reg, &mut out_plain, &s, None, fd),
                        bc::code::OK
                    );
                    assert_eq!(out_plain, b"serial print");
                    // Missing document restores saved termios and returns FAILED.
                    let inv_nf = bc::Invocation {
                        file: Some(dir.join("missing").to_string_lossy().into_owned()),
                        ..inv_reg.clone()
                    };
                    assert_eq!(
                        transfer_on_device(&inv_nf, &mut out_dev, &s, Some(saved), fd),
                        bc::code::FAILED
                    );
                    // Missing document with `saved=None` also fails.
                    assert_eq!(
                        transfer_on_device(&inv_nf, &mut out_plain, &s, None, fd),
                        bc::code::FAILED
                    );
                }
            }
        }
        let inv_ptmx_nf = bc::Invocation {
            device_uri: "serial:///dev/ptmx?baud=9600+flow=dtrdsr".into(),
            file: Some(dir.join("missing").to_string_lossy().into_owned()),
            ..inv_reg.clone()
        };
        assert_eq!(print_job(&inv_ptmx_nf), bc::code::FAILED);

        // Discovery reports openable serial ports and skips non-char files / missing dirs.
        let mut out_mock = Vec::new();
        assert_eq!(
            discover_to_with(&mut out_mock, &dir, |_| true),
            bc::code::OK
        );
        assert!(String::from_utf8(out_mock).unwrap().contains("serial://"));
        let mut out = Vec::new();
        assert_eq!(discover_to(&mut out, &dir), bc::code::OK);
        assert_eq!(out, [] as [u8; 0]);
        assert_eq!(discover_to(&mut out, &dir.join("missing")), bc::code::OK);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
