//! `usb` backend — USB printer transport (`backend/usb.c`-equivalent).
//!
//! `usb://<make>/<model>?serial=<ser>` resolves a `/dev/usb/lp*` or
//! `/dev/usblp*` node matching the printer's IEEE-1284 device ID;
//! `usb:///dev/usb/lpN` addresses a node directly.
//!
//! Security hardening:
//!  * Validates direct and resolved nodes via canonical `/dev/usb/lp*` /
//!    `/dev/usblp*` prefix + `O_NOFOLLOW | O_NOCTTY` + `fstat` `S_ISCHR`.
//!  * Sanitizes all IEEE-1284 discovery strings via `backend_common`.

use backend_common as bc;
use std::io::{self, Read, Write};
use std::path::Path;

const ALLOWED_USB_PREFIXES: &[&str] = &["/dev/usb/lp", "/dev/usblp"];

/// One discovered USB printer node with its IEEE-1284 id fields.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UsbDev {
    node: String,  // /dev/usb/lpN
    devid: String, // MFG:..;MDL:..;...
    uri: String,   // usb://mfg/mdl?serial=s
    make_model: String,
    info: String,
}

/// Parse `MFG:x;MDL:y;SER:z;` IEEE-1284 device-id strings (exact key match).
fn id_field<'a>(id: &'a str, key: &str) -> Option<&'a str> {
    id.split(';')
        .filter_map(|f| f.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(key))
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

fn is_usb_lp_name(name: &str, in_dev_usb: bool) -> bool {
    let digits = if in_dev_usb {
        name.strip_prefix("lp")
    } else {
        name.strip_prefix("usblp")
    };
    digits.is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

fn enumerate_in(
    dev_usb_dir: &Path,
    dev_dir: &Path,
    usbmisc_sysfs: &Path,
    usb_sysfs: &Path,
) -> Vec<UsbDev> {
    let mut out = Vec::new();
    for (dir, in_dev_usb) in [(dev_usb_dir, true), (dev_dir, false)] {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            if !is_usb_lp_name(&name, in_dev_usb) {
                continue;
            }
            let node = e.path().to_string_lossy().into_owned();
            let devid = [
                usbmisc_sysfs.join(format!("{name}/device/ieee1284_id")),
                usb_sysfs.join(format!("{name}/device/ieee1284_id")),
            ]
            .iter()
            .find_map(|cand| std::fs::read_to_string(cand).ok())
            .map_or_else(String::new, |v| bc::sanitize_field(v.trim()));

            let mfg = id_field(&devid, "MFG")
                .or_else(|| id_field(&devid, "MANUFACTURER"))
                .unwrap_or("Unknown");
            let mdl = id_field(&devid, "MDL")
                .or_else(|| id_field(&devid, "MODEL"))
                .unwrap_or("Unknown");
            let ser = id_field(&devid, "SER")
                .or_else(|| id_field(&devid, "SERN"))
                .unwrap_or("");
            let make_model = format!("{mfg} {mdl}");
            let uri = if ser.is_empty() {
                format!(
                    "usb://{}/{}",
                    bc::percent_encode(mfg),
                    bc::percent_encode(mdl)
                )
            } else {
                format!(
                    "usb://{}/{}?serial={}",
                    bc::percent_encode(mfg),
                    bc::percent_encode(mdl),
                    bc::percent_encode(ser)
                )
            };
            out.push(UsbDev {
                node,
                devid,
                uri,
                make_model: make_model.clone(),
                info: format!("{make_model} ({name})"),
            });
        }
    }
    out
}

/// Resolve a `usb://` URI to a device node path: direct `/dev/...` path or
/// make/model/serial match against discovered devices.
fn resolve_node(uri: &str, devices: &[UsbDev]) -> Option<String> {
    let rest = uri
        .strip_prefix("usb://")
        .or_else(|| uri.strip_prefix("USB://"))?;
    if rest.starts_with('/') {
        let direct = rest.split(['?', '#']).next().unwrap_or(rest);
        let decoded = bc::percent_decode(direct);
        bc::validate_no_traversal(&decoded).ok()?;
        return Some(decoded);
    }
    let (path, query) = rest.split_once('?').map_or((rest, ""), |(p, q)| (p, q));
    let mut seg = path.split('/');
    let mfg = bc::percent_decode(seg.next().unwrap_or_default());
    let mdl = bc::percent_decode(seg.next().unwrap_or_default());
    if mfg.is_empty() && mdl.is_empty() {
        return None;
    }
    let want_serial = query
        .split(['&', '+'])
        .find_map(|kv| kv.strip_prefix("serial="))
        .map(bc::percent_decode);

    for d in devices {
        let dmfg = id_field(&d.devid, "MFG")
            .or_else(|| id_field(&d.devid, "MANUFACTURER"))
            .unwrap_or_default();
        let dmdl = id_field(&d.devid, "MDL")
            .or_else(|| id_field(&d.devid, "MODEL"))
            .unwrap_or_default();
        let dser = id_field(&d.devid, "SER")
            .or_else(|| id_field(&d.devid, "SERN"))
            .unwrap_or_default();
        if !mfg.is_empty() && !dmfg.eq_ignore_ascii_case(&mfg) {
            continue;
        }
        if !mdl.is_empty() && !dmdl.eq_ignore_ascii_case(&mdl) {
            continue;
        }
        if let Some(s) = &want_serial {
            if !dser.eq_ignore_ascii_case(s) {
                continue;
            }
        }
        return Some(d.node.clone());
    }
    None
}

fn discover_to(
    out: &mut impl Write,
    dev_usb_dir: &Path,
    dev_dir: &Path,
    usbmisc_sysfs: &Path,
    usb_sysfs: &Path,
) -> i32 {
    for d in enumerate_in(dev_usb_dir, dev_dir, usbmisc_sysfs, usb_sysfs) {
        let _ = bc::report_to(
            out,
            "direct",
            &d.uri,
            &d.make_model,
            &d.info,
            Some(&d.devid),
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
                    bc::error(format_args!("usb: write failed: {e}"));
                    return bc::code::RETRY;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                bc::error(format_args!("usb: read failed: {e}"));
                return bc::code::FAILED;
            }
        }
    }
}

fn print_with(inv: &bc::Invocation, devices: &[UsbDev], allowed_prefixes: &[&str]) -> i32 {
    let redacted = bc::redact_uri(&inv.device_uri);
    let Some(node) = resolve_node(&inv.device_uri, devices) else {
        bc::error(format_args!(
            "usb: cannot resolve {redacted} to a USB printer device"
        ));
        return bc::code::FAILED;
    };
    bc::info(format_args!("usb: opening {node}"));
    let mut dev =
        match bc::open_char_device_with_prefixes(&node, allowed_prefixes, false, true, true) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                bc::error(format_args!("usb: device {node} not connected: {e}"));
                return bc::code::RETRY;
            }
            Err(e) => {
                bc::error(format_args!("usb: cannot open {node}: {e}"));
                return bc::code::FAILED;
            }
        };
    let mut doc = match bc::document(inv) {
        Ok(d) => d,
        Err(e) => {
            bc::error(format_args!("usb: open document: {e}"));
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
                Path::new("/dev/usb"),
                Path::new("/dev"),
                Path::new("/sys/class/usbmisc"),
                Path::new("/sys/class/usb"),
            )
        },
        |inv| {
            let devs = enumerate_in(
                Path::new("/dev/usb"),
                Path::new("/dev"),
                Path::new("/sys/class/usbmisc"),
                Path::new("/sys/class/usb"),
            );
            print_with(&inv, &devs, ALLOWED_USB_PREFIXES)
        },
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
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "unplugged"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn id_field_exact_key_and_enumeration() {
        let id = "MFG_EXTRA:Wrong;MFG:HP;MDL:LaserJet Pro;SER:CN12345;";
        assert_eq!(id_field(id, "MFG"), Some("HP"));
        assert_eq!(id_field(id, "MDL"), Some("LaserJet Pro"));
        assert_eq!(id_field(id, "SER"), Some("CN12345"));
        assert_eq!(id_field(id, "CMD"), None);

        assert!(is_usb_lp_name("lp0", true));
        assert!(!is_usb_lp_name("lp", true));
        assert!(is_usb_lp_name("usblp1", false));
        assert!(!is_usb_lp_name("lp0", false));

        let base = std::env::temp_dir().join(format!("pw-usb-{}", std::process::id()));
        let dev_usb = base.join("dev_usb");
        let dev = base.join("dev");
        let usbmisc = base.join("usbmisc");
        let usb_cls = base.join("usb_cls");
        std::fs::create_dir_all(&dev_usb).unwrap();
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::create_dir_all(usbmisc.join("lp0/device")).unwrap();
        std::fs::create_dir_all(usb_cls.join("usblp1/device")).unwrap();

        std::fs::write(dev_usb.join("lp0"), b"").unwrap();
        std::fs::write(dev_usb.join("ignored"), b"").unwrap();
        std::fs::write(dev.join("usblp1"), b"").unwrap();
        std::fs::write(
            usbmisc.join("lp0/device/ieee1284_id"),
            "MFG:HP;MDL:OfficeJet 9010;SER:SN001;\n",
        )
        .unwrap();
        std::fs::write(
            usb_cls.join("usblp1/device/ieee1284_id"),
            "MANUFACTURER:Brother;MODEL:HL-L2350DW;\n",
        )
        .unwrap();

        let devs = enumerate_in(&dev_usb, &dev, &usbmisc, &usb_cls);
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].uri, "usb://HP/OfficeJet%209010?serial=SN001");
        assert_eq!(devs[1].uri, "usb://Brother/HL-L2350DW");

        // Resolve by make/model/serial and direct path.
        assert_eq!(
            resolve_node("usb://HP/OfficeJet%209010?serial=SN001", &devs),
            Some(devs[0].node.clone())
        );
        assert_eq!(
            resolve_node("usb://HP/OfficeJet%209010?serial=WRONG", &devs),
            None
        );
        assert_eq!(
            resolve_node("usb://Brother/HL-L2350DW", &devs),
            Some(devs[1].node.clone())
        );
        assert_eq!(
            resolve_node("usb:///dev/usb/lp0", &devs),
            Some("/dev/usb/lp0".into())
        );
        // Reject traversal & non-usb schemes.
        assert_eq!(resolve_node("usb:///dev/usb/../../etc/passwd", &devs), None);
        assert_eq!(resolve_node("ipp://host/p", &devs), None);
        assert_eq!(resolve_node("usb://", &devs), None);

        let mut out = Vec::new();
        assert_eq!(
            discover_to(&mut out, &dev_usb, &dev, &usbmisc, &usb_cls),
            bc::code::OK
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("usb://HP/OfficeJet%209010?serial=SN001"));
        assert!(text.contains("usb://Brother/HL-L2350DW"));

        assert_eq!(resolve_node("usb://Brother/WrongModel", &devs), None);
        assert_eq!(
            enumerate_in(
                &base.join("missing1"),
                &base.join("missing2"),
                &usbmisc,
                &usb_cls
            ),
            Vec::<UsbDev>::new()
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn print_validates_char_device_prefix_and_streams() {
        let base = std::env::temp_dir().join(format!("pw-usb-p-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let doc = base.join("job.pcl");
        std::fs::write(&doc, b"usb payload").unwrap();
        let reg = base.join("fake_lp0");
        std::fs::write(&reg, b"").unwrap();

        let inv_null = bc::Invocation {
            job_id: 1,
            user: "u".into(),
            title: "t".into(),
            copies: 1,
            options: String::new(),
            file: Some(doc.to_string_lossy().into_owned()),
            device_uri: "usb:///dev/null".into(),
        };
        // Rejected by strict ALLOWED_USB_PREFIXES (/dev/null is not /dev/usb/lp* or /dev/usblp*).
        assert_eq!(
            print_with(&inv_null, &[], ALLOWED_USB_PREFIXES),
            bc::code::FAILED
        );
        // Succeeds when /dev/ prefix is explicitly permitted (tests full open + stream path).
        assert_eq!(print_with(&inv_null, &[], &["/dev/"]), bc::code::OK);

        // Missing USB device returns RETRY (printer unplugged).
        let inv_missing = bc::Invocation {
            device_uri: "usb:///dev/usb/lp9999".into(),
            ..inv_null.clone()
        };
        assert_eq!(
            print_with(&inv_missing, &[], ALLOWED_USB_PREFIXES),
            bc::code::RETRY
        );

        // Regular file outside /dev rejected.
        let inv_reg = bc::Invocation {
            device_uri: format!("usb://{}", reg.display()),
            ..inv_null.clone()
        };
        assert_eq!(
            print_with(&inv_reg, &[], ALLOWED_USB_PREFIXES),
            bc::code::FAILED
        );

        // Unresolvable make/model URI rejected.
        let inv_unres = bc::Invocation {
            device_uri: "usb://NoSuch/Printer".into(),
            ..inv_null.clone()
        };
        assert_eq!(
            print_with(&inv_unres, &[], ALLOWED_USB_PREFIXES),
            bc::code::FAILED
        );

        // Missing document file returns FAILED.
        let inv_nodoc = bc::Invocation {
            file: Some(base.join("missing").to_string_lossy().into_owned()),
            ..inv_null
        };
        assert_eq!(print_with(&inv_nodoc, &[], &["/dev/"]), bc::code::FAILED);

        // Write error -> RETRY, read error -> FAILED.
        let mut src = Cursor::new(b"abc".to_vec());
        assert_eq!(stream_to_writer(&mut src, &mut FailIo), bc::code::RETRY);
        let mut sink = Vec::new();
        assert_eq!(stream_to_writer(&mut FailIo, &mut sink), bc::code::FAILED);
        let _ = FailIo.flush();

        let _ = std::fs::remove_dir_all(&base);
    }
}
