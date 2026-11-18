//! `dnssd` backend — DNS-SD remote printer discovery + `dnssd://` forwarding.
//!
//! ## Discovery mode (`cups-deviced`, `argv.len() < 6`)
//! Browses `_ipp._tcp` / `_ipps._tcp` and emits properly percent-encoded
//! `dnssd://<instance>._ipp[s]._tcp.local./<rp>` URIs with sanitized responder
//! metadata.
//!
//! ## Print mode
//! Resolves `dnssd://...` to a real `ipp://` or `ipps://` URI, validates the
//! resolved target against scheme allowlist + SSRF policy (preventing rogue
//! LAN mDNS responders from redirecting jobs to cloud metadata or loopback),
//! and execs the sibling `ipp` backend.

use backend_common::{self as bc, NetworkUri, SsrfPolicy};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Percent-encode a resource path while preserving `/` segment separators.
fn encode_resource_path(rp: &str) -> String {
    rp.trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(bc::percent_encode)
        .collect::<Vec<_>>()
        .join("/")
}

/// Convert a discovered [`dnssd::RemotePrinter`] into a proper `dnssd://` URI
/// (instead of emitting a raw `ipp://` URI).
fn build_dnssd_uri(remote: &dnssd::RemotePrinter) -> Option<String> {
    let raw_name = remote.name.trim();
    if raw_name.is_empty() {
        return None;
    }
    let is_ipps = raw_name.contains("._ipps.")
        || remote.uri.starts_with("ipps://")
        || remote.uri.starts_with("IPPS://");
    let regtype = if is_ipps {
        "_ipps._tcp.local."
    } else {
        "_ipp._tcp.local."
    };

    // Strip known service/domain suffixes to isolate the instance name.
    let instance = raw_name
        .strip_suffix("._ipps._tcp.local.")
        .or_else(|| raw_name.strip_suffix("._ipp._tcp.local."))
        .or_else(|| raw_name.strip_suffix("._ipps._tcp.local"))
        .or_else(|| raw_name.strip_suffix("._ipp._tcp.local"))
        .or_else(|| raw_name.strip_suffix(".local."))
        .or_else(|| raw_name.strip_suffix(".local"))
        .unwrap_or(raw_name);
    if instance.is_empty() {
        return None;
    }

    // Extract resource path (`rp`) from the resolved URI.
    let rp = remote
        .uri
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('/'))
        .map_or("", |(_, path)| {
            path.split(['?', '#']).next().unwrap_or(path)
        });
    let encoded_inst = bc::percent_encode(instance);
    let encoded_rp = encode_resource_path(rp);

    if encoded_rp.is_empty() {
        Some(format!("dnssd://{encoded_inst}.{regtype}/"))
    } else {
        Some(format!("dnssd://{encoded_inst}.{regtype}/{encoded_rp}"))
    }
}

/// Validate a `dnssd://` device URI (scheme, non-empty authority, no raw or
/// percent-encoded control chars) while keeping percent-encoding intact for
/// `dnssd::resolve_uri` (preventing `%2F` path corruption and `%25` double-decoding).
fn prepare_resolve_uri(device_uri: &str) -> Option<String> {
    if device_uri.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    let (scheme, rest) = device_uri.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("dnssd") {
        return None;
    }
    let (raw_auth, raw_tail) = match rest.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (rest, None),
    };
    let decoded_auth = bc::percent_decode(raw_auth);
    if raw_auth.is_empty()
        || decoded_auth.is_empty()
        || decoded_auth.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return None;
    }
    if let Some(tail) = raw_tail {
        let decoded_tail = bc::percent_decode(tail);
        if decoded_tail.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return None;
        }
    }
    Some(format!("dnssd://{rest}"))
}

/// Validate a resolved target URI against scheme allowlist (`ipp://`/`ipps://`)
/// and SSRF policy before handing off to the sibling `ipp` backend.
fn validate_resolved_uri(real_uri: &str, ssrf: SsrfPolicy) -> Result<NetworkUri, String> {
    let is_ipp = real_uri.starts_with("ipps://")
        || real_uri.starts_with("IPPS://")
        || real_uri.starts_with("ipp://")
        || real_uri.starts_with("IPP://");
    if !is_ipp {
        return Err("resolved URI must use ipp:// or ipps://".into());
    }
    let parsed =
        NetworkUri::parse(real_uri, 631).ok_or_else(|| "resolved URI is malformed".to_string())?;
    ssrf.resolve_checked(&parsed.host, parsed.port)
        .map_err(|e| format!("resolved target blocked by SSRF policy: {e}"))?;
    Ok(parsed)
}

fn discover_printers_to(out: &mut impl Write, printers: &[dnssd::RemotePrinter]) -> i32 {
    let mut seen = HashSet::new();
    for r in printers {
        let Some(dnssd_uri) = build_dnssd_uri(r) else {
            continue;
        };
        if seen.insert(dnssd_uri.clone()) {
            let make_model = if r.make_model.trim().is_empty() {
                "IPP Printer".to_string()
            } else {
                bc::sanitize_field(&r.make_model)
            };
            let info = if r.make_model.trim().is_empty() {
                bc::sanitize_field(&r.name)
            } else {
                make_model.clone()
            };
            let _ = bc::report_to(out, "network", &dnssd_uri, &make_model, &info, None);
        }
    }
    bc::code::OK
}

fn locate_ipp_backend(current_exe: Option<&Path>, server_bin: Option<&str>) -> PathBuf {
    current_exe
        .and_then(|p| p.parent().map(|d| d.join("ipp")))
        .filter(|p| p.is_file())
        .or_else(|| {
            server_bin
                .map(|d| PathBuf::from(d).join("backend").join("ipp"))
                .filter(|p| p.is_file())
        })
        .unwrap_or_else(|| PathBuf::from("/usr/lib/cups/backend/ipp"))
}

fn print_with(
    argv: &[String],
    inv: &bc::Invocation,
    ssrf: SsrfPolicy,
    resolve_fn: impl FnOnce(&str) -> Option<String>,
    exec_fn: impl FnOnce(&[String], &str) -> i32,
) -> i32 {
    let redacted = bc::redact_uri(&inv.device_uri);
    let Some(query_uri) = prepare_resolve_uri(&inv.device_uri) else {
        bc::error(format_args!("dnssd: bad device-uri {redacted}"));
        return bc::code::FAILED;
    };
    let Some(real_uri) = resolve_fn(&query_uri) else {
        bc::error(format_args!(
            "dnssd: could not resolve {redacted} to an IPP address"
        ));
        return bc::code::RETRY;
    };
    if let Err(reason) = validate_resolved_uri(&real_uri, ssrf) {
        bc::error(format_args!(
            "dnssd: rejecting resolved target {}: {reason}",
            bc::redact_uri(&real_uri)
        ));
        return bc::code::FAILED;
    }
    exec_fn(argv, &real_uri)
}

#[cfg(unix)]
fn forward_to(ipp: &Path, argv: &[String], real_uri: &str) -> i32 {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(ipp)
        .args(argv.iter().skip(1))
        .env("DEVICE_URI", real_uri)
        .exec();
    bc::error(format_args!("dnssd: cannot exec {}: {err}", ipp.display()));
    bc::code::FAILED
}

#[cfg(unix)]
fn forward(argv: &[String], real_uri: &str) -> i32 {
    let exe = std::env::current_exe().ok();
    let server_bin = std::env::var("CUPS_SERVERBIN").ok();
    let ipp = locate_ipp_backend(exe.as_deref(), server_bin.as_deref());
    forward_to(&ipp, argv, real_uri)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let browse_ms = std::env::var("DNSSD_BROWSE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1500);
    let resolve_ms = std::env::var("DNSSD_RESOLVE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3000);
    bc::run(
        || {
            let printers = dnssd::browse_ipp(Duration::from_millis(browse_ms));
            discover_printers_to(&mut std::io::stdout().lock(), &printers)
        },
        |inv| {
            print_with(
                &args,
                &inv,
                SsrfPolicy::from_env(),
                |u| dnssd::resolve_uri(u, Duration::from_millis(resolve_ms)),
                forward,
            )
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_dnssd_uri_encodes_properly_and_uses_dnssd_scheme() {
        let p1 = dnssd::RemotePrinter {
            uri: "ipp://printer.local:631/ipp/print".into(),
            name: "Office HP @ Server._ipp._tcp.local.".into(),
            make_model: "HP LaserJet".into(),
        };
        assert_eq!(
            build_dnssd_uri(&p1).as_deref(),
            Some("dnssd://Office%20HP%20%40%20Server._ipp._tcp.local./ipp/print")
        );

        let p2 = dnssd::RemotePrinter {
            uri: "ipps://secure.local:631/printers/Color Queue".into(),
            name: "Secure Printer._ipps._tcp.local.".into(),
            make_model: String::new(),
        };
        assert_eq!(
            build_dnssd_uri(&p2).as_deref(),
            Some("dnssd://Secure%20Printer._ipps._tcp.local./printers/Color%20Queue")
        );

        let p3 = dnssd::RemotePrinter {
            uri: "ipp://h:631/".into(),
            name: "Solo".into(),
            make_model: "M".into(),
        };
        assert_eq!(
            build_dnssd_uri(&p3).as_deref(),
            Some("dnssd://Solo._ipp._tcp.local./")
        );

        let empty = dnssd::RemotePrinter {
            uri: "ipp://h:631/ipp".into(),
            name: "   ".into(),
            make_model: String::new(),
        };
        assert!(build_dnssd_uri(&empty).is_none());

        let only_suffix = dnssd::RemotePrinter {
            uri: "ipp://h:631/ipp".into(),
            name: "._ipp._tcp.local.".into(),
            make_model: String::new(),
        };
        assert!(build_dnssd_uri(&only_suffix).is_none());
    }

    #[test]
    fn discovery_dedups_and_sanitizes_responder_metadata() {
        let printers = vec![
            dnssd::RemotePrinter {
                uri: "ipp://p1.local:631/ipp/print".into(),
                name: "Evil \"Printer\"\nfake._ipp._tcp.local.".into(),
                make_model: "HP \"Laser\"\r\nnetwork evil://x".into(),
            },
            // Duplicate instance -> deduplicated.
            dnssd::RemotePrinter {
                uri: "ipp://p1.local:631/ipp/print".into(),
                name: "Evil \"Printer\"\nfake._ipp._tcp.local.".into(),
                make_model: "HP".into(),
            },
            dnssd::RemotePrinter {
                uri: "ipps://p2.local:631/ipp/print".into(),
                name: "Clean._ipps._tcp.local.".into(),
                make_model: String::new(),
            },
            dnssd::RemotePrinter {
                uri: "ipp://bad:631/".into(),
                name: String::new(),
                make_model: String::new(),
            },
        ];
        let mut out = Vec::new();
        assert_eq!(discover_printers_to(&mut out, &printers), bc::code::OK);
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("network dnssd://"));
        assert!(!lines[0].contains("network ipp://"));
        assert!(lines[0].contains("\"HP Laser  network evil://x\""));
        assert!(lines[1].starts_with("network dnssd://Clean._ipps._tcp.local./ipp/print"));
        assert!(lines[1].contains("\"IPP Printer\""));
    }

    #[test]
    fn resolve_preparation_and_ssrf_enforcement() {
        // Preserves percent-encoding (%20, %2F, %25) intact so dnssd::resolve_uri
        // splits authority/path cleanly without double-decoding or `/` corruption.
        assert_eq!(
            prepare_resolve_uri("dnssd://Office%20HP._ipp._tcp.local./ipp/print").as_deref(),
            Some("dnssd://Office%20HP._ipp._tcp.local./ipp/print")
        );
        assert_eq!(
            prepare_resolve_uri("DNSSD://A%2FB%20100%25._ipp._tcp.local./ipp/print").as_deref(),
            Some("dnssd://A%2FB%20100%25._ipp._tcp.local./ipp/print")
        );
        assert_eq!(
            prepare_resolve_uri("dnssd://Printer._ipp._tcp.local.").as_deref(),
            Some("dnssd://Printer._ipp._tcp.local.")
        );
        assert!(prepare_resolve_uri("ipp://host/ipp").is_none());
        assert!(prepare_resolve_uri("dnssd:///ipp/print").is_none());
        assert!(prepare_resolve_uri("dnssd://bad\r\n._ipp._tcp.local./ipp").is_none());
        assert!(prepare_resolve_uri("dnssd://bad%0a._ipp._tcp.local./ipp").is_none());
        assert!(prepare_resolve_uri("dnssd://ok._ipp._tcp.local./bad%0a").is_none());

        let strict = SsrfPolicy {
            allow_loopback: false,
        };
        let allow_lo = SsrfPolicy {
            allow_loopback: true,
        };

        // Block rogue mDNS redirects to file://, cloud metadata, or loopback.
        assert!(validate_resolved_uri("file:///etc/passwd", allow_lo).is_err());
        assert!(validate_resolved_uri("http://192.168.1.5/ipp", allow_lo).is_err());
        assert!(validate_resolved_uri("ipp://169.254.169.254:631/latest", allow_lo).is_err());
        assert!(validate_resolved_uri("ipp://127.0.0.1:631/ipp/print", strict).is_err());
        assert!(validate_resolved_uri("ipp://127.0.0.1:0/ipp/print", allow_lo).is_err());
        // Valid IPP/IPPS targets succeed.
        assert!(validate_resolved_uri("ipp://127.0.0.1:631/ipp/print", allow_lo).is_ok());
        assert!(validate_resolved_uri("ipps://192.168.1.10:631/ipp/print", strict).is_ok());
    }

    #[test]
    fn print_with_and_locate_backend() {
        let inv = bc::Invocation {
            job_id: 1,
            user: "u".into(),
            title: "t".into(),
            copies: 1,
            options: String::new(),
            file: None,
            device_uri: "dnssd://Office%20HP._ipp._tcp.local./ipp/print".into(),
        };
        let args = vec!["dnssd".into(), "1".into()];
        let allow_lo = SsrfPolicy {
            allow_loopback: true,
        };

        // Valid resolution forwards cleanly.
        let mut forwarded = String::new();
        let rc = print_with(
            &args,
            &inv,
            allow_lo,
            |q| {
                assert_eq!(q, "dnssd://Office%20HP._ipp._tcp.local./ipp/print");
                Some("ipp://127.0.0.1:631/ipp/print".into())
            },
            |_a, real| {
                forwarded = real.to_string();
                bc::code::OK
            },
        );
        assert_eq!(rc, bc::code::OK);
        assert_eq!(forwarded, "ipp://127.0.0.1:631/ipp/print");

        // SSRF block rejects before exec.
        let mut called = false;
        let rc_ssrf = print_with(
            &args,
            &inv,
            allow_lo,
            |_| Some("ipp://169.254.169.254:631/ipp".into()),
            |_, _| {
                called = true;
                bc::code::OK
            },
        );
        assert_eq!(rc_ssrf, bc::code::FAILED);
        assert!(!called);

        // forward_to returns FAILED when target binary does not exist.
        assert_eq!(
            forward_to(
                Path::new("/nonexistent/ipp-backend-xyz"),
                &args,
                "ipp://10.0.0.1/ipp"
            ),
            bc::code::FAILED
        );

        // Unresolved service returns RETRY.
        let rc_unres = print_with(&args, &inv, allow_lo, |_| None, |_, _| bc::code::OK);
        assert_eq!(rc_unres, bc::code::RETRY);

        // Bad URI returns FAILED.
        let inv_bad = bc::Invocation {
            device_uri: "socket://host:9100".into(),
            ..inv
        };
        assert_eq!(
            print_with(&args, &inv_bad, allow_lo, |_| None, |_, _| bc::code::OK),
            bc::code::FAILED
        );

        // locate_ipp_backend prefers sibling, then CUPS_SERVERBIN, then stock path.
        let dir = std::env::temp_dir().join(format!("pw-dnssd-loc-{}", std::process::id()));
        let bin_dir = dir.join("backend");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let fake_ipp = bin_dir.join("ipp");
        std::fs::write(&fake_ipp, b"#!/bin/sh\n").unwrap();
        assert_eq!(
            locate_ipp_backend(Some(&bin_dir.join("dnssd")), None),
            fake_ipp
        );
        assert_eq!(
            locate_ipp_backend(None, Some(&dir.to_string_lossy())),
            fake_ipp
        );
        assert_eq!(
            locate_ipp_backend(None, None),
            PathBuf::from("/usr/lib/cups/backend/ipp")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
