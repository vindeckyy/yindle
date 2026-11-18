#![no_main]
//! Fuzz `dnssd`: `parse_dnssd_uri`, `percent_decode`, `service_matches`, and
//! pure in-memory TXT/subtype/PDL builders — especially multi-byte UTF-8 slice
//! boundary safety and case-insensitive prefix/suffix matching.

use dnssd::{
    build_txt_record_for, default_urf, effective_pdl, parse_dnssd_uri, parse_subtypes,
    pdl_from_mime_types, percent_decode, service_matches, service_regtype, ParsedDnssdUri,
    SharedPrinter,
};
use libfuzzer_sys::fuzz_target;

fn verify_parsed(parsed: &ParsedDnssdUri, fuzz_fullname: &str, fuzz_uuid: &str) {
    assert!(!parsed.instance.is_empty());
    assert!(parsed.regtype == "_ipp._tcp.local." || parsed.regtype == "_ipps._tcp.local.");
    assert_eq!(parsed.secure, parsed.regtype == "_ipps._tcp.local.");
    if let Some(rp) = &parsed.resource_path {
        assert!(!rp.is_empty() && !rp.starts_with('/'));
    }

    // Self-match invariants against exact reconstructed service fullname.
    let exact_fullname = format!("{}.{}", parsed.instance, parsed.regtype);
    match &parsed.uuid {
        None => {
            assert!(service_matches(parsed, &exact_fullname, None));
        }
        Some(u) => {
            // Missing TXT UUID must fail when the URI demands a UUID.
            assert!(!service_matches(parsed, &exact_fullname, None));
            // Unless the decoded UUID itself begins with another nested `urn:uuid:` prefix,
            // both bare and `urn:uuid:`-prefixed TXT values must match.
            if !(u.len() >= 9 && u.as_bytes()[..9].eq_ignore_ascii_case(b"urn:uuid:")) {
                assert!(service_matches(parsed, &exact_fullname, Some(u)));
                let urn = format!("urn:uuid:{u}");
                assert!(service_matches(parsed, &exact_fullname, Some(&urn)));
            }
        }
    }

    // Arbitrary UTF-8 fullname & TXT UUID inputs must never panic.
    let _ = service_matches(parsed, fuzz_fullname, None);
    let _ = service_matches(parsed, fuzz_fullname, Some(fuzz_uuid));
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    // 1. Direct percent_decode on arbitrary UTF-8 / malformed %XX sequences.
    let _ = percent_decode(&text);

    // Split input into up to 3 parts for URI / fullname / TXT UUID fuzzing.
    let mut parts = text.splitn(3, '\0');
    let p0 = parts.next().unwrap_or("");
    let p1 = parts.next().unwrap_or(p0);
    let p2 = parts.next().unwrap_or(p1);

    // 2. Direct parse_dnssd_uri on raw input (exercises UTF-8 boundaries on prefix/suffix).
    if let Some(parsed) = parse_dnssd_uri(&text) {
        verify_parsed(&parsed, p1, p2);
    }
    if let Some(parsed) = parse_dnssd_uri(p0) {
        verify_parsed(&parsed, p1, p2);
    }

    // 3. Synthesized dnssd:// variants so fuzzer immediately reaches deep path/query/UUID logic.
    let synth_ipp = format!("dnssd://{p0}._ipp._tcp.local./{p1}?uuid={p2}");
    if let Some(parsed) = parse_dnssd_uri(&synth_ipp) {
        verify_parsed(&parsed, p1, p2);
    }
    let synth_ipps = format!("dnssd://{p0}._ipps._tcp/?uuid=urn:uuid:{p2}");
    if let Some(parsed) = parse_dnssd_uri(&synth_ipps) {
        verify_parsed(&parsed, p1, p2);
    }

    // 4. Pure in-memory DNS-SD helpers (subtypes, PDL, URF, TXT record construction).
    let subtypes = parse_subtypes(Some(p0));
    let _ = service_regtype("_ipp._tcp.local.", &subtypes);
    let _ = effective_pdl(p0);
    let _ = pdl_from_mime_types(&[p0, p1]);
    let ptype = u32::from_be_bytes([
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
    ]);
    let _ = default_urf(ptype);
    let sp = SharedPrinter {
        name: p0.to_string(),
        info: p1.to_string(),
        make_model: p1.to_string(),
        location: p2.to_string(),
        pdl: p0.to_string(),
        printer_type: ptype,
        printer_state: 3,
        uuid: p2.to_string(),
        is_class: data.len().is_multiple_of(2),
        is_fax: data.len().is_multiple_of(3),
    };
    let _ = build_txt_record_for(&sp, p1, data.len() % 2 == 1, Some(p2), true);
});
