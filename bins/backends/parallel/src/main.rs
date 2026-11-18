//! `parallel` backend — IEEE-1284 parallel port (`backend/parallel.c`).
//!
//! `parallel:///dev/lpN` streams the document to the port after canonical
//! `/dev/` character-device validation (`O_NOFOLLOW | O_NOCTTY` + `S_ISCHR`).
//! Discovery safely enumerates `/dev/lp*` and `/dev/parport/*` without unsafe
//! string slicing panics.

use backend_common as bc;
use std::io::{self, Read, Write};
use std::path::Path;

/// Extract parallel port number safely from a `/dev/lpN` or `/dev/parport/N`
/// filename without unchecked indexing.
fn port_number(name: &str, is_parport_dir: bool) -> Option<&str> {
    let digits = if is_parport_dir {
        name
    } else {
        name.strip_prefix("lp")?
    };
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

fn enumerate_in(dev_dir: &Path, parport_dir: &Path, sysfs_dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (dir, is_parport) in [(dev_dir, false), (parport_dir, true)] {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(port_num) = port_number(&name, is_parport) else {
                continue;
            };
            let node = e.path().to_string_lossy().into_owned();
            let devid = [
                sysfs_dir.join(format!("parport{port_num}/device/ieee1284_id")),
                sysfs_dir.join(format!(
                    "parport{port_num}/devices/lp{port_num}/ieee1284_id"
                )),
                sysfs_dir.join(format!("{name}/device/ieee1284_id")),
            ]
            .iter()
            .find_map(|c| std::fs::read_to_string(c).ok())
            .map_or_else(String::new, |v| v.trim().to_string());
            out.push((node, devid));
        }
    }
    out
}

/// Extract device path from `parallel:///dev/lpN` or `parallel:/dev/lpN`.
fn parse_parallel_uri(uri: &str) -> Option<String> {
    let (scheme, rest) = uri.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("parallel") {
        return None;
    }
    let path_raw = rest.strip_prefix("//").unwrap_or(rest);
    let path = path_raw.split(['?', '#']).next().unwrap_or(path_raw);
    if !path.starts_with('/') {
        return None;
    }
    Some(bc::percent_decode(path))
}

fn discover_to(out: &mut impl Write, dev_dir: &Path, parport_dir: &Path, sysfs_dir: &Path) -> i32 {
    for (node, devid) in enumerate_in(dev_dir, parport_dir, sysfs_dir) {
        let _ = bc::report_to(
            out,
            "direct",
            &format!("parallel://{node}"),
            "Unknown",
            &format!("Parallel Port ({node})"),
            Some(&devid),
        );
    }
    bc::code::OK
}

fn stream_to_writer(doc: &mut impl Read, dev: &mut impl Write) -> i32 {
    let mut buf = [0u8; 8192];
    loop {
        match doc.read(&mut buf) {
            Ok(0) => return bc::code::OK,
            Ok(n) => {
                if let Err(e) = dev.write_all(&buf[..n]) {
                    bc::error(format_args!("parallel: write failed: {e}"));
                    return bc::code::RETRY;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                bc::error(format_args!("parallel: read failed: {e}"));
                return bc::code::FAILED;
            }
        }
    }
}

fn print_job(inv: &bc::Invocation) -> i32 {
    let Some(path) = parse_parallel_uri(&inv.device_uri) else {
        bc::error(format_args!(
            "parallel: bad device-uri {}",
            bc::redact_uri(&inv.device_uri)
        ));
        return bc::code::FAILED;
    };
    let mut dev = match bc::open_char_device(&path, false, true, true) {
        Ok(f) => f,
        Err(e) => {
            bc::error(format_args!("parallel: cannot open {path}: {e}"));
            return bc::code::FAILED;
        }
    };
    let mut doc = match bc::document(inv) {
        Ok(d) => d,
        Err(e) => {
            bc::error(format_args!("parallel: open document: {e}"));
            return bc::code::FAILED;
        }
    };
    stream_to_writer(&mut doc, &mut dev)
}

fn main() {
    bc::run(
        || {
            discover_to(
                &mut io::stdout().lock(),
                Path::new("/dev"),
                Path::new("/dev/parport"),
                Path::new("/sys/class/parport"),
            )
        },
        |inv| print_job(&inv),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn short_parport_names_do_not_panic() {
        assert_eq!(port_number("0", true), Some("0"));
        assert_eq!(port_number("12", true), Some("12"));
        assert_eq!(port_number("", true), None);
        assert_eq!(port_number("a", true), None);
        assert_eq!(port_number("lp0", false), Some("0"));
        assert_eq!(port_number("lp", false), None);
        assert_eq!(port_number("lpa", false), None);
        assert_eq!(port_number("tty0", false), None);
    }

    #[test]
    fn enumerate_handles_parport_0_and_sysfs_devid() {
        let base = std::env::temp_dir().join(format!("pw-par-{}", std::process::id()));
        let dev = base.join("dev");
        let parport = base.join("parport");
        let sysfs = base.join("sysfs");
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::create_dir_all(&parport).unwrap();
        std::fs::create_dir_all(sysfs.join("parport0/devices/lp0")).unwrap();
        std::fs::create_dir_all(sysfs.join("parport1/device")).unwrap();

        std::fs::write(dev.join("lp0"), b"").unwrap();
        std::fs::write(dev.join("lp"), b"").unwrap();
        std::fs::write(dev.join("sda"), b"").unwrap();
        // Short 1-char name `0` that previously panicked on `&name[2..]`!
        std::fs::write(parport.join("1"), b"").unwrap();
        std::fs::write(parport.join("bad"), b"").unwrap();

        std::fs::write(
            sysfs.join("parport0/devices/lp0/ieee1284_id"),
            "MFG:HP;MDL:LaserJet 4;\n",
        )
        .unwrap();
        std::fs::write(
            sysfs.join("parport1/device/ieee1284_id"),
            "MFG:Epson;MDL:LX-300;\n",
        )
        .unwrap();

        let mut out = Vec::new();
        assert_eq!(discover_to(&mut out, &dev, &parport, &sysfs), bc::code::OK);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("MFG:HP;MDL:LaserJet 4;"));
        assert!(text.contains("MFG:Epson;MDL:LX-300;"));
        assert!(!text.contains("sda"));
        assert!(!text.contains("/bad"));
        // Missing dirs handled gracefully.
        let mut empty_out = Vec::new();
        assert_eq!(
            discover_to(&mut empty_out, &base.join("no1"), &base.join("no2"), &sysfs),
            bc::code::OK
        );
        assert_eq!(empty_out, [] as [u8; 0]);
        let _ = std::fs::remove_dir_all(&base);
    }

    struct FailIo;
    impl Read for FailIo {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read fail"))
        }
    }
    impl Write for FailIo {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "offline"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn print_enforces_char_device_and_streams() {
        let base = std::env::temp_dir().join(format!("pw-par-p-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let doc = base.join("doc.raw");
        std::fs::write(&doc, b"hello parallel").unwrap();

        // /dev/null is a real char device under /dev/.
        let inv_ok = bc::Invocation {
            job_id: 1,
            user: "u".into(),
            title: "t".into(),
            copies: 1,
            options: String::new(),
            file: Some(doc.to_string_lossy().into_owned()),
            device_uri: "parallel:///dev/null".into(),
        };
        assert_eq!(print_job(&inv_ok), bc::code::OK);

        // Regular file outside /dev rejected!
        let target = base.join("notadev");
        std::fs::write(&target, b"").unwrap();
        let inv_reg = bc::Invocation {
            device_uri: format!("parallel://{}", target.display()),
            ..inv_ok.clone()
        };
        assert_eq!(print_job(&inv_reg), bc::code::FAILED);

        // Bad URI & missing document rejected.
        let inv_bad = bc::Invocation {
            device_uri: "usb:///dev/usb/lp0".into(),
            ..inv_ok.clone()
        };
        assert_eq!(print_job(&inv_bad), bc::code::FAILED);
        // Standard single-slash `parallel:/dev/lp0` and triple-slash both accepted.
        assert_eq!(
            parse_parallel_uri("parallel:/dev/lp0").as_deref(),
            Some("/dev/lp0")
        );
        assert_eq!(
            parse_parallel_uri("parallel:///dev/lp0").as_deref(),
            Some("/dev/lp0")
        );
        assert!(parse_parallel_uri("parallel://").is_none());
        assert!(parse_parallel_uri("parallel:relative").is_none());

        let inv_nf = bc::Invocation {
            file: Some(base.join("missing").to_string_lossy().into_owned()),
            ..inv_ok
        };
        assert_eq!(print_job(&inv_nf), bc::code::FAILED);

        // Stream helper write error -> RETRY, read error -> FAILED.
        let mut src = Cursor::new(b"abc".to_vec());
        assert_eq!(stream_to_writer(&mut src, &mut FailIo), bc::code::RETRY);
        let mut sink = Vec::new();
        assert_eq!(stream_to_writer(&mut FailIo, &mut sink), bc::code::FAILED);
        let _ = FailIo.flush();

        let _ = std::fs::remove_dir_all(&base);
    }
}
