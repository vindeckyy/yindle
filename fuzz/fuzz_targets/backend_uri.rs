#![no_main]
//! Fuzz `backend-common`: `NetworkUri::parse`, `redact_uri`, `percent_encode` /
//! `percent_decode`, `sanitize_field` / `sanitize_token` / `format_report`,
//! `validate_no_traversal`, and `SsrfPolicy` (including IPv4-mapped IPv6
//! equivalence and cloud-metadata / port-0 blocking).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use backend_common::{
    format_host_port, format_report, parse_env_bool, percent_decode, percent_encode, redact_uri,
    sanitize_field, sanitize_token, validate_no_traversal, NetworkUri, SsrfPolicy,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    // 1. NetworkUri::parse (port 0 must always be rejected; valid URIs satisfy invariants).
    assert!(NetworkUri::parse(&text, 0).is_none());
    if let Some(parsed) = NetworkUri::parse(&text, 631) {
        assert!(parsed.port > 0);
        assert!(!parsed.scheme.is_empty());
        assert!(!parsed.host.is_empty());
        assert!(parsed.path.starts_with('/'));
        assert!(!parsed
            .host
            .bytes()
            .any(|b| b < 0x20 || b == 0x7f || b.is_ascii_whitespace()));
        let _ = parsed.host_port();
        let clean = parsed.clean_uri(None);
        assert!(clean.starts_with(&format!("{}://", parsed.scheme)));
        let _ = parsed.clean_uri(Some("ipps"));
    }

    // Also test with synthesized scheme prefixes so authority/IPv6/port/path paths get hammered.
    let prefixed = format!("ipp://{text}");
    let _ = NetworkUri::parse(&prefixed, 631);

    // 2. redact_uri must never panic and must strip authority credentials.
    let _ = redact_uri(&text);
    const SECRET: &str = "s3cr3tP4ssW0rd";
    let safe_path = sanitize_token(&text);
    if !safe_path.contains(SECRET) {
        let cred_uri = format!("ipp://alice:{SECRET}@printer.example.com/{safe_path}");
        let redacted = redact_uri(&cred_uri);
        assert!(!redacted.contains(SECRET));
        assert!(redacted.starts_with("ipp://***@"));
    }

    // 3. percent_decode / percent_encode round-trip and malformed input safety.
    let _ = percent_decode(&text);
    let encoded = percent_encode(&text);
    assert_eq!(percent_decode(&encoded), text);

    // 4. Discovery field/token sanitization and report formatting.
    let field = sanitize_field(&text);
    assert!(!field.contains('"'));
    assert!(!field.chars().any(char::is_control));

    let token = sanitize_token(&text);
    assert!(!token.contains('"'));
    assert!(!token.chars().any(|c| c.is_control() || c.is_whitespace()));

    if let Some(line) = format_report(&text, &text, &text, &text, Some(&text)) {
        assert!(!line.contains('\r') && !line.contains('\n'));
    }

    // 5. Env bool, host:port formatting, and path traversal guard.
    let _ = parse_env_bool(Some(&text));
    let _ = format_host_port(&text, 631);
    let trav_res = validate_no_traversal(&text);
    if text.contains('\0') {
        assert!(trav_res.is_err());
    }

    // 6. SsrfPolicy: direct byte-constructed IPv4, IPv4-mapped IPv6, IPv6, and parsed IP strings.
    let strict_ssrf = SsrfPolicy {
        allow_loopback: false,
    };
    let loopback_ssrf = SsrfPolicy {
        allow_loopback: true,
    };
    let _ = SsrfPolicy::from_env_value(Some(&text));

    let port = u16::from_be_bytes([
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
    ]);

    if data.len() >= 4 {
        let v4 = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
        let ip4 = IpAddr::V4(v4);
        let mapped = IpAddr::V6(v4.to_ipv6_mapped());

        // IPv4-mapped IPv6 must never bypass IPv4 SSRF checks.
        assert_eq!(
            strict_ssrf.check_ip(ip4).is_ok(),
            strict_ssrf.check_ip(mapped).is_ok()
        );
        assert_eq!(
            loopback_ssrf.check_ip(ip4).is_ok(),
            loopback_ssrf.check_ip(mapped).is_ok()
        );

        // Port 0 is always forbidden.
        assert!(strict_ssrf
            .check_socket_addr(SocketAddr::new(ip4, 0))
            .is_err());
        assert!(loopback_ssrf
            .check_socket_addr(SocketAddr::new(ip4, 0))
            .is_err());
        let _ = strict_ssrf.check_socket_addr(SocketAddr::new(ip4, port));
        let _ = loopback_ssrf.check_socket_addr(SocketAddr::new(ip4, port));

        // Unspecified, link-local/IMDS, broadcast, and multicast are always blocked.
        if v4.is_unspecified()
            || v4.is_link_local()
            || v4 == Ipv4Addr::new(100, 100, 100, 200)
            || v4.is_broadcast()
            || v4.is_multicast()
        {
            assert!(strict_ssrf.check_ip(ip4).is_err());
            assert!(loopback_ssrf.check_ip(ip4).is_err());
        }
        if v4.is_loopback() {
            assert!(strict_ssrf.check_ip(ip4).is_err());
        }
    }

    if data.len() >= 16 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&data[..16]);
        let v6 = Ipv6Addr::from(octets);
        let ip6 = IpAddr::V6(v6);

        let _ = strict_ssrf.check_ip(ip6);
        let _ = loopback_ssrf.check_ip(ip6);
        assert!(strict_ssrf
            .check_socket_addr(SocketAddr::new(ip6, 0))
            .is_err());
        let _ = strict_ssrf.check_socket_addr(SocketAddr::new(ip6, port));

        if v6.is_unspecified()
            || v6.is_multicast()
            || (v6.segments()[0] & 0xffc0) == 0xfe80
            || v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
        {
            assert!(strict_ssrf.check_ip(ip6).is_err());
            assert!(loopback_ssrf.check_ip(ip6).is_err());
        }
        if v6.is_loopback() {
            assert!(strict_ssrf.check_ip(ip6).is_err());
        }
    }

    if let Ok(ip) = text.trim().parse::<IpAddr>() {
        let _ = strict_ssrf.check_ip(ip);
        let _ = loopback_ssrf.check_ip(ip);
    }
    if let Ok(sa) = text.trim().parse::<SocketAddr>() {
        let _ = strict_ssrf.check_socket_addr(sa);
        let _ = loopback_ssrf.check_socket_addr(sa);
    }
});
