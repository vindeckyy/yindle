//! `snmp` backend — SNMP network-printer discovery (`backend/snmp.c`).
//!
//! Reads `snmp.conf` (`Address`, `Community`, `DebugLevel`, `MaxRunTime`),
//! sends properly BER-encoded `SNMPv1` `GetRequest` probes for `sysDescr.0`
//! and IEEE-1284 printer MIB OIDs, strictly decodes ASN.1 BER `GetResponse`
//! varbinds (never confusing the community string with `sysDescr`), validates
//! responder IPs against SSRF policy, probes candidate printer ports (`9100`,
//! `631`, `515`), and emits sanitized printable `socket://`/`ipp://`/`lpd://`
//! discovery lines.

use backend_common::{self as bc, SsrfPolicy};
use std::collections::HashSet;
use std::env;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const OID_SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
const OID_HR_DEVICE_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 25, 3, 2, 1, 3, 1];
const OID_PWG_DEVICE_ID: &[u32] = &[1, 3, 6, 1, 4, 1, 2699, 1, 2, 1, 2, 1, 1, 3, 1];
const OID_HP_DEVICE_ID: &[u32] = &[1, 3, 6, 1, 4, 1, 11, 2, 3, 9, 1, 1, 7, 0];
const MAX_BER_DEPTH: usize = 16;

const DEFAULT_PROBE_PORTS: &[(u16, &str)] = &[(9100, "socket"), (631, "ipp"), (515, "lpd")];

/// Parsed `snmp.conf` settings.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SnmpConfig {
    addresses: Vec<String>,
    communities: Vec<String>,
    debug_level: u32,
    max_run_time: Duration,
}

impl Default for SnmpConfig {
    fn default() -> Self {
        Self {
            addresses: vec!["255.255.255.255".to_string()],
            communities: vec!["public".to_string()],
            debug_level: 0,
            max_run_time: Duration::from_secs(3),
        }
    }
}

/// Parse CUPS `snmp.conf` directives (`Address`, `Community`, `DebugLevel`, `MaxRunTime`).
fn parse_snmp_conf(text: &str) -> SnmpConfig {
    let mut addresses = Vec::new();
    let mut communities = Vec::new();
    let mut debug_level = 0u32;
    let mut max_run_time = Duration::from_secs(3);

    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(val) = parts.next() else {
            continue;
        };
        if key.eq_ignore_ascii_case("Address") {
            let addr = if val.eq_ignore_ascii_case("@LOCAL")
                || val.to_ascii_uppercase().starts_with("@IF(")
            {
                "255.255.255.255".to_string()
            } else {
                val.to_string()
            };
            if !addresses.contains(&addr) {
                addresses.push(addr);
            }
        } else if key.eq_ignore_ascii_case("Community") {
            let comm = val.to_string();
            if !comm.is_empty() && !communities.contains(&comm) {
                communities.push(comm);
            }
        } else if key.eq_ignore_ascii_case("DebugLevel") {
            if let Ok(lvl) = val.parse::<u32>() {
                debug_level = lvl;
            }
        } else if key.eq_ignore_ascii_case("MaxRunTime") {
            if let Ok(secs) = val.parse::<u64>() {
                max_run_time = Duration::from_secs(secs.clamp(1, 300));
            }
        }
    }

    if addresses.is_empty() {
        addresses.push("255.255.255.255".to_string());
    }
    if communities.is_empty() {
        communities.push("public".to_string());
    }
    SnmpConfig {
        addresses,
        communities,
        debug_level,
        max_run_time,
    }
}

fn load_snmp_conf(override_path: Option<&Path>, server_root: Option<&Path>) -> SnmpConfig {
    let path = override_path.map_or_else(
        || {
            server_root
                .unwrap_or_else(|| Path::new("/etc/cups"))
                .join("snmp.conf")
        },
        Path::to_path_buf,
    );
    std::fs::read_to_string(path).map_or_else(|_| SnmpConfig::default(), |t| parse_snmp_conf(&t))
}

// ---------- ASN.1 BER codec ----------

fn encode_ber_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = len.to_be_bytes();
        let first_nz = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        let slice = &bytes[first_nz..];
        out.push(0x80 | u8::try_from(slice.len()).unwrap_or(1));
        out.extend_from_slice(slice);
    }
}

fn encode_tlv(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(tag);
    encode_ber_len(payload.len(), &mut out);
    out.extend_from_slice(payload);
    out
}

fn encode_int(val: i32) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let mut start = 0;
    while start < 3 {
        let b0 = bytes[start];
        let b1 = bytes[start + 1];
        if (b0 == 0x00 && (b1 & 0x80) == 0) || (b0 == 0xff && (b1 & 0x80) != 0) {
            start += 1;
        } else {
            break;
        }
    }
    encode_tlv(0x02, &bytes[start..])
}

fn encode_oid(arcs: &[u32]) -> Vec<u8> {
    let mut payload = Vec::new();
    if arcs.len() >= 2 {
        payload.push(u8::try_from(arcs[0] * 40 + arcs[1]).unwrap_or(0));
        for &arc in &arcs[2..] {
            let mut tmp = [0u8; 5];
            let mut n = 0usize;
            let mut v = arc;
            tmp[n] = (v & 0x7f) as u8;
            n += 1;
            v >>= 7;
            while v > 0 {
                tmp[n] = ((v & 0x7f) as u8) | 0x80;
                n += 1;
                v >>= 7;
            }
            for i in (0..n).rev() {
                payload.push(tmp[i]);
            }
        }
    }
    encode_tlv(0x06, &payload)
}

/// Build an `SNMPv1` `GetRequest` packet for the requested OIDs.
fn build_get_request(community: &[u8], req_id: i32, oids: &[&[u32]]) -> Vec<u8> {
    let mut varlist_body = Vec::new();
    for oid in oids {
        let mut vb = encode_oid(oid);
        vb.extend_from_slice(&[0x05, 0x00]); // NULL
        varlist_body.extend_from_slice(&encode_tlv(0x30, &vb));
    }
    let varlist = encode_tlv(0x30, &varlist_body);

    let mut pdu_body = Vec::new();
    pdu_body.extend_from_slice(&encode_int(req_id));
    pdu_body.extend_from_slice(&encode_int(0)); // error-status
    pdu_body.extend_from_slice(&encode_int(0)); // error-index
    pdu_body.extend_from_slice(&varlist);
    let pdu = encode_tlv(0xa0, &pdu_body);

    let mut msg_body = Vec::new();
    msg_body.extend_from_slice(&encode_int(0)); // version = v1
    msg_body.extend_from_slice(&encode_tlv(0x04, community));
    msg_body.extend_from_slice(&pdu);
    encode_tlv(0x30, &msg_body)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BerValue {
    Integer(i64),
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(Vec<u32>),
    Sequence(Vec<BerValue>),
    Context(u8, Vec<BerValue>),
    Other(u8, Vec<u8>),
}

fn decode_ber_len(input: &[u8]) -> Option<(usize, &[u8])> {
    let (&first, rest) = input.split_first()?;
    if first < 0x80 {
        return Some((usize::from(first), rest));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 || rest.len() < count {
        return None;
    }
    let mut len = 0usize;
    for &b in &rest[..count] {
        len = (len << 8) | usize::from(b);
    }
    Some((len, &rest[count..]))
}

fn decode_oid(bytes: &[u8]) -> Option<Vec<u32>> {
    let (&first, rest) = bytes.split_first()?;
    let mut arcs = Vec::with_capacity(rest.len() + 2);
    let first_u32 = u32::from(first);
    if first_u32 < 40 {
        arcs.push(0);
        arcs.push(first_u32);
    } else if first_u32 < 80 {
        arcs.push(1);
        arcs.push(first_u32 - 40);
    } else {
        arcs.push(2);
        arcs.push(first_u32 - 80);
    }
    let mut cur = 0u32;
    let mut in_arc = false;
    for &b in rest {
        cur = cur.checked_shl(7)?.checked_add(u32::from(b & 0x7f))?;
        in_arc = true;
        if b & 0x80 == 0 {
            arcs.push(cur);
            cur = 0;
            in_arc = false;
        }
    }
    if in_arc {
        return None;
    }
    Some(arcs)
}

fn decode_int(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let mut val: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in bytes {
        val = (val << 8) | i64::from(b);
    }
    Some(val)
}

fn decode_ber_seq(mut slice: &[u8], depth: usize) -> Option<Vec<BerValue>> {
    let mut items = Vec::new();
    while !slice.is_empty() {
        let (item, rem) = decode_ber(slice, depth + 1)?;
        items.push(item);
        slice = rem;
    }
    Some(items)
}

fn decode_ber(input: &[u8], depth: usize) -> Option<(BerValue, &[u8])> {
    if depth > MAX_BER_DEPTH {
        return None;
    }
    let (&tag, after_tag) = input.split_first()?;
    let (len, after_len) = decode_ber_len(after_tag)?;
    if after_len.len() < len {
        return None;
    }
    let (payload, rem) = after_len.split_at(len);
    let val = match tag {
        0x02 => BerValue::Integer(decode_int(payload)?),
        0x04 => BerValue::OctetString(payload.to_vec()),
        0x05 => {
            if !payload.is_empty() {
                return None;
            }
            BerValue::Null
        }
        0x06 => BerValue::ObjectIdentifier(decode_oid(payload)?),
        0x30 => BerValue::Sequence(decode_ber_seq(payload, depth)?),
        // Constructed context-specific tags (e.g. GetResponse-PDU = 0xa2).
        t if (t & 0xe0) == 0xa0 => BerValue::Context(t, decode_ber_seq(payload, depth)?),
        other => BerValue::Other(other, payload.to_vec()),
    };
    Some((val, rem))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnmpResponse {
    community: String,
    request_id: i64,
    error_status: i64,
    varbinds: Vec<(Vec<u32>, BerValue)>,
}

/// Strictly parse an SNMPv1/v2c `GetResponse-PDU` packet.
fn parse_snmp_response(pkt: &[u8], expected_req_id: Option<i32>) -> Option<SnmpResponse> {
    let (BerValue::Sequence(top), _) = decode_ber(pkt, 0)? else {
        return None;
    };
    if top.len() < 3 {
        return None;
    }
    let BerValue::Integer(version) = top[0] else {
        return None;
    };
    if version != 0 && version != 1 {
        return None;
    }
    let BerValue::OctetString(comm_bytes) = &top[1] else {
        return None;
    };
    let BerValue::Context(0xa2, pdu_items) = &top[2] else {
        return None;
    };
    if pdu_items.len() < 4 {
        return None;
    }
    let BerValue::Integer(request_id) = pdu_items[0] else {
        return None;
    };
    if let Some(want) = expected_req_id {
        if request_id != i64::from(want) {
            return None;
        }
    }
    let BerValue::Integer(error_status) = pdu_items[1] else {
        return None;
    };
    if error_status != 0 {
        return None;
    }
    let BerValue::Sequence(raw_vbs) = &pdu_items[3] else {
        return None;
    };

    let mut varbinds = Vec::new();
    for vb in raw_vbs {
        if let BerValue::Sequence(pair) = vb {
            if pair.len() == 2 {
                if let BerValue::ObjectIdentifier(oid) = &pair[0] {
                    varbinds.push((oid.clone(), pair[1].clone()));
                }
            }
        }
    }
    Some(SnmpResponse {
        community: String::from_utf8_lossy(comm_bytes).into_owned(),
        request_id,
        error_status,
        varbinds,
    })
}

/// Extract sanitized `(make_model, device_id)` from decoded SNMP varbinds.
fn extract_printer_info(resp: &SnmpResponse) -> (String, String) {
    let mut sys_descr = String::new();
    let mut hr_descr = String::new();
    let mut device_id = String::new();

    for (oid, val) in &resp.varbinds {
        let BerValue::OctetString(bytes) = val else {
            continue;
        };
        let clean = bc::sanitize_field(&String::from_utf8_lossy(bytes));
        if clean.is_empty() {
            continue;
        }
        if oid.as_slice() == OID_SYS_DESCR && sys_descr.is_empty() {
            sys_descr = clean;
        } else if oid.as_slice() == OID_HR_DEVICE_DESCR && hr_descr.is_empty() {
            hr_descr = clean;
        } else if (oid.as_slice() == OID_PWG_DEVICE_ID || oid.as_slice() == OID_HP_DEVICE_ID)
            && device_id.is_empty()
        {
            device_id = clean;
        }
    }

    let make_model = if !hr_descr.is_empty() {
        hr_descr
    } else if !sys_descr.is_empty() {
        sys_descr
    } else {
        "Unknown".to_string()
    };
    (make_model, device_id)
}

/// Format a printable URI for a discovered host + open port/scheme.
fn format_printer_uri(ip: IpAddr, port: u16, scheme: &str) -> String {
    let host = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    match scheme {
        "socket" => {
            if port == 9100 {
                format!("socket://{host}")
            } else {
                format!("socket://{host}:{port}")
            }
        }
        "ipp" => {
            if port == 631 {
                format!("ipp://{host}/ipp/print")
            } else {
                format!("ipp://{host}:{port}/ipp/print")
            }
        }
        "lpd" => {
            if port == 515 {
                format!("lpd://{host}/")
            } else {
                format!("lpd://{host}:{port}/")
            }
        }
        other => format!("{other}://{host}:{port}"),
    }
}

/// Probe candidate printer TCP ports on `ip` after verifying SSRF policy.
fn probe_printer_uri(
    ip: IpAddr,
    ports: &[(u16, &str)],
    timeout: Duration,
    ssrf: SsrfPolicy,
) -> Option<String> {
    if ssrf.check_ip(ip).is_err() {
        return None;
    }
    for &(port, scheme) in ports {
        let addr = SocketAddr::new(ip, port);
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return Some(format_printer_uri(ip, port, scheme));
        }
    }
    None
}

/// Send a single-OID unicast `SNMPv1` follow-up `GetRequest` to `dest`,
/// tolerating `noSuchName` (`error_status != 0`) or timeouts cleanly.
fn query_single_oid(
    dest: SocketAddr,
    community: &[u8],
    req_id: i32,
    oid: &[u32],
    timeout: Duration,
) -> Option<(Vec<u32>, BerValue)> {
    let bind_addr = if dest.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind_addr).ok()?;
    let _ = sock.set_read_timeout(Some(timeout));
    let pkt = build_get_request(community, req_id, &[oid]);
    sock.send_to(&pkt, dest).ok()?;
    let mut buf = [0u8; 4096];
    let (n, from) = sock.recv_from(&mut buf).ok()?;
    if from.ip() != dest.ip() {
        return None;
    }
    let resp = parse_snmp_response(&buf[..n], Some(req_id))?;
    resp.varbinds.into_iter().next()
}

/// Discover SNMP responders via single-OID `sysDescr.0` broadcast (RFC 1157
/// compliant — avoids `noSuchName` failures on non-HP printers), follow up
/// individually for optional printer MIB OIDs, and probe candidate printer ports.
fn discover_with(
    cfg: &SnmpConfig,
    snmp_port: u16,
    probe_ports: &[(u16, &str)],
    probe_timeout: Duration,
    ssrf: SsrfPolicy,
) -> Vec<(String, String, String, String)> {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return Vec::new();
    };
    let _ = sock.set_broadcast(true);
    let _ = sock.set_read_timeout(Some(Duration::from_millis(150)));

    let req_id: i32 = 0x7054_6c75;
    for community in &cfg.communities {
        // Broadcast only `sysDescr.0` so SNMPv1 devices without vendor OIDs respond.
        let pkt = build_get_request(community.as_bytes(), req_id, &[OID_SYS_DESCR]);
        for target in &cfg.addresses {
            let dest = if target.contains(':') && !target.starts_with('[') {
                format!("[{target}]:{snmp_port}")
            } else {
                format!("{target}:{snmp_port}")
            };
            if cfg.debug_level > 0 {
                bc::debug(format_args!("snmp: sending GetRequest to {dest}"));
            }
            let _ = sock.send_to(&pkt, &dest);
        }
    }

    let deadline = Instant::now() + cfg.max_run_time;
    let mut seen = HashSet::new();
    let mut found = Vec::new();
    let mut buf = [0u8; 4096];
    let mut follow_id = req_id.wrapping_add(1);

    loop {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            break;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let ip = from.ip();
                if seen.contains(&ip) {
                    continue;
                }
                let Some(mut resp) = parse_snmp_response(&buf[..n], Some(req_id)) else {
                    continue;
                };
                // Mark host seen only AFTER a valid SNMP response is parsed.
                seen.insert(ip);
                let Some(uri) = probe_printer_uri(ip, probe_ports, probe_timeout, ssrf) else {
                    continue;
                };
                // Individually query optional printer MIB OIDs so `noSuchName`
                // on one vendor OID never discards the device or other OIDs.
                for oid in [OID_HR_DEVICE_DESCR, OID_PWG_DEVICE_ID, OID_HP_DEVICE_ID] {
                    follow_id = follow_id.wrapping_add(1);
                    if let Some(vb) = query_single_oid(
                        from,
                        resp.community.as_bytes(),
                        follow_id,
                        oid,
                        probe_timeout,
                    ) {
                        resp.varbinds.push(vb);
                    }
                }
                let (make_model, device_id) = extract_printer_info(&resp);
                let info = format!("{make_model} ({ip})");
                found.push((uri, make_model, info, device_id));
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    found
}

fn discover_to(
    out: &mut impl Write,
    cfg: &SnmpConfig,
    snmp_port: u16,
    probe_ports: &[(u16, &str)],
    probe_timeout: Duration,
    ssrf: SsrfPolicy,
) -> i32 {
    for (uri, make_model, info, device_id) in
        discover_with(cfg, snmp_port, probe_ports, probe_timeout, ssrf)
    {
        let _ = bc::report_to(out, "network", &uri, &make_model, &info, Some(&device_id));
    }
    bc::code::OK
}

fn print_reject(inv: &bc::Invocation) -> i32 {
    bc::error(format_args!(
        "snmp: {} is a discovery backend, not a print transport",
        bc::redact_uri(&inv.device_uri)
    ));
    bc::code::FAILED
}

fn main() {
    bc::run(
        || {
            let override_path = env::var("SNMP_CONF").ok().map(PathBuf::from);
            let server_root = env::var("CUPS_SERVERROOT").ok().map(PathBuf::from);
            let cfg = load_snmp_conf(override_path.as_deref(), server_root.as_deref());
            discover_to(
                &mut std::io::stdout().lock(),
                &cfg,
                161,
                DEFAULT_PROBE_PORTS,
                Duration::from_millis(400),
                SsrfPolicy::from_env(),
            )
        },
        |inv| print_reject(&inv),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn build_get_response(
        community: &[u8],
        req_id: i32,
        error_status: i32,
        varbinds: &[(&[u32], &[u8])],
    ) -> Vec<u8> {
        let mut vb_list = Vec::new();
        for (oid, val) in varbinds {
            let mut vb = encode_oid(oid);
            vb.extend_from_slice(&encode_tlv(0x04, val));
            vb_list.extend_from_slice(&encode_tlv(0x30, &vb));
        }
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&encode_int(req_id));
        pdu.extend_from_slice(&encode_int(error_status));
        pdu.extend_from_slice(&encode_int(0));
        pdu.extend_from_slice(&encode_tlv(0x30, &vb_list));

        let mut msg = Vec::new();
        msg.extend_from_slice(&encode_int(0)); // v1
        msg.extend_from_slice(&encode_tlv(0x04, community));
        msg.extend_from_slice(&encode_tlv(0xa2, &pdu)); // GetResponse-PDU
        encode_tlv(0x30, &msg)
    }

    #[test]
    fn snmp_conf_parsing_and_loading() {
        let text = "
            # Sample snmp.conf
            Address @LOCAL
            Address 192.168.1.255
            Address @IF(eth0)
            Community private
            Community public
            DebugLevel 2
            MaxRunTime 15
        ";
        let cfg = parse_snmp_conf(text);
        assert_eq!(cfg.addresses, vec!["255.255.255.255", "192.168.1.255"]);
        assert_eq!(cfg.communities, vec!["private", "public"]);
        assert_eq!(cfg.debug_level, 2);
        assert_eq!(cfg.max_run_time, Duration::from_secs(15));

        let def = parse_snmp_conf("# empty\n");
        assert_eq!(def, SnmpConfig::default());

        let dir = env::temp_dir().join(format!("pw-snmp-conf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let conf_file = dir.join("snmp.conf");
        std::fs::write(&conf_file, "Community corp\nMaxRunTime 2\n").unwrap();
        let loaded = load_snmp_conf(Some(&conf_file), None);
        assert_eq!(loaded.communities, vec!["corp"]);
        let loaded2 = load_snmp_conf(None, Some(&dir));
        assert_eq!(loaded2.communities, vec!["corp"]);
        let fallback = load_snmp_conf(Some(&dir.join("missing")), None);
        assert_eq!(fallback, SnmpConfig::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ber_decoder_ignores_community_and_decodes_long_lengths() {
        let long_descr = "HP LaserJet Enterprise M608 ".repeat(8); // > 128 bytes (long BER len!)
        let pkt = build_get_response(
            b"public",
            42,
            0,
            &[
                (OID_SYS_DESCR, long_descr.as_bytes()),
                (OID_PWG_DEVICE_ID, b"MFG:HP;MDL:M608;CMD:PDF;"),
            ],
        );
        let resp = parse_snmp_response(&pkt, Some(42)).unwrap();
        assert_eq!(resp.community, "public");
        assert_eq!(resp.request_id, 42);
        let (mm, devid) = extract_printer_info(&resp);
        assert!(mm.starts_with("HP LaserJet Enterprise M608"));
        assert!(!mm.eq("public"));
        assert_eq!(devid, "MFG:HP;MDL:M608;CMD:PDF;");

        // Mismatched req_id or nonzero error_status rejected.
        assert!(parse_snmp_response(&pkt, Some(99)).is_none());
        let err_pkt = build_get_response(b"public", 42, 2, &[]);
        assert!(parse_snmp_response(&err_pkt, Some(42)).is_none());

        // Malformed / truncated packets rejected without panics.
        for bad in [
            &[][..],
            &[0x30, 0x80][..],
            &[0x30, 0x05, 0x02, 0x01][..],
            &[0x05, 0x01, 0x00][..],
            &[0x06, 0x02, 0x2b, 0x81][..],
        ] {
            assert!(parse_snmp_response(bad, None).is_none());
        }

        // Negative int, Other tag (Counter32 = 0x41), Null, & OID arc edge cases.
        let neg = encode_int(-1);
        assert_eq!(decode_ber(&neg, 0).unwrap().0, BerValue::Integer(-1));
        assert_eq!(decode_ber(&[0x05, 0x00], 0).unwrap().0, BerValue::Null);
        assert_eq!(
            decode_ber(&[0x41, 0x01, 0x2a], 0).unwrap().0,
            BerValue::Other(0x41, vec![0x2a])
        );
        assert!(decode_ber(&[0x02, 0x00], 0).is_none()); // empty int
        assert!(decode_ber(&[0x06, 0x00], 0).is_none()); // empty oid
        assert!(decode_ber(&[0x30, 0x00], MAX_BER_DEPTH + 1).is_none());
        assert_eq!(decode_oid(&[0x05]).unwrap(), vec![0, 5]);
        assert_eq!(decode_oid(&[0x55]).unwrap(), vec![2, 5]);
        // Request encoding round-trips cleanly.
        let req = build_get_request(b"public", 123, &[OID_SYS_DESCR, OID_HP_DEVICE_ID]);
        assert!(decode_ber(&req, 0).is_some());
        // Non-GetResponse PDU (GetRequest = 0xa0) rejected by parse_snmp_response.
        assert!(parse_snmp_response(&req, None).is_none());
        // Unsupported SNMP version (v3 = 3) rejected.
        let mut bad_ver = Vec::new();
        bad_ver.extend_from_slice(&encode_int(3));
        bad_ver.extend_from_slice(&encode_tlv(0x04, b"public"));
        bad_ver.extend_from_slice(&encode_tlv(0xa2, &[]));
        assert!(parse_snmp_response(&encode_tlv(0x30, &bad_ver), None).is_none());
        // Missing varbind descr falls back to "Unknown".
        let empty_resp = SnmpResponse {
            community: "public".into(),
            request_id: 1,
            error_status: 0,
            varbinds: vec![(OID_SYS_DESCR.to_vec(), BerValue::Null)],
        };
        assert_eq!(
            extract_printer_info(&empty_resp),
            ("Unknown".into(), String::new())
        );
        // Unknown scheme fallback in format_printer_uri & closed port probe returns None.
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            format_printer_uri(lo, 9999, "custom"),
            "custom://127.0.0.1:9999"
        );
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        assert!(probe_printer_uri(
            lo,
            &[(closed_port, "socket")],
            Duration::from_millis(50),
            SsrfPolicy {
                allow_loopback: true
            },
        )
        .is_none());
        // Malformed snmp.conf line without value is ignored cleanly.
        assert_eq!(
            parse_snmp_conf("Address\nCommunity\n"),
            SnmpConfig::default()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn format_uri_and_live_udp_discovery_with_port_probe() {
        let v4: IpAddr = "192.168.1.20".parse().unwrap();
        let v6: IpAddr = "2001:db8::5".parse().unwrap();
        assert_eq!(
            format_printer_uri(v4, 9100, "socket"),
            "socket://192.168.1.20"
        );
        assert_eq!(
            format_printer_uri(v4, 631, "ipp"),
            "ipp://192.168.1.20/ipp/print"
        );
        assert_eq!(format_printer_uri(v4, 515, "lpd"), "lpd://192.168.1.20/");
        assert_eq!(
            format_printer_uri(v6, 9100, "socket"),
            "socket://[2001:db8::5]"
        );
        assert_eq!(
            format_printer_uri(v4, 9101, "socket"),
            "socket://192.168.1.20:9101"
        );
        assert_eq!(
            format_printer_uri(v4, 8631, "ipp"),
            "ipp://192.168.1.20:8631/ipp/print"
        );
        assert_eq!(
            format_printer_uri(v4, 5150, "lpd"),
            "lpd://192.168.1.20:5150/"
        );

        // Metadata IP is blocked by SSRF before probing.
        assert!(probe_printer_uri(
            "169.254.169.254".parse().unwrap(),
            DEFAULT_PROBE_PORTS,
            Duration::from_millis(50),
            SsrfPolicy {
                allow_loopback: true
            },
        )
        .is_none());

        // Mock UDP SNMP responder + mock TCP printer port.
        let tcp_printer = TcpListener::bind("127.0.0.1:0").unwrap();
        let printer_port = tcp_printer.local_addr().unwrap().port();
        let udp_srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let snmp_port = udp_srv.local_addr().unwrap().port();
        let _ = udp_srv.set_read_timeout(Some(Duration::from_secs(2)));

        let t = thread::spawn(move || {
            let mut buf = [0u8; 1024];
            // 1. Initial discovery broadcast receives single-OID sysDescr request.
            let (n, from) = udp_srv.recv_from(&mut buf).unwrap();
            let (BerValue::Sequence(top), _) = decode_ber(&buf[..n], 0).unwrap() else {
                panic!("expected sequence");
            };
            let BerValue::Context(0xa0, pdu) = &top[2] else {
                panic!("expected GetRequest");
            };
            let BerValue::Sequence(vbs) = &pdu[3] else {
                panic!("expected varbind list");
            };
            // Must broadcast single-OID sysDescr.0 (not multi-OID).
            assert_eq!(vbs.len(), 1);

            // First send a bogus wrong-reqid packet to verify premature `seen.insert` does NOT drop host!
            let bogus = build_get_response(b"public", 999, 0, &[]);
            udp_srv.send_to(&bogus, from).unwrap();

            // Then send real sysDescr.0 response.
            let reply = build_get_response(
                b"public",
                0x7054_6c75,
                0,
                &[(OID_SYS_DESCR, b"Brother \"HL-L2350DW\"\nnetwork evil://x")],
            );
            udp_srv.send_to(&reply, from).unwrap();

            let _ = tcp_printer.accept();

            // 2. Answer the 3 individual unicast follow-up OID queries:
            //    - OID_HR_DEVICE_DESCR -> noSuchName (error-status = 2)
            //    - OID_PWG_DEVICE_ID   -> valid IEEE-1284 ID
            //    - OID_HP_DEVICE_ID    -> noSuchName (error-status = 2)
            for _ in 0..3 {
                let (m, qfrom) = udp_srv.recv_from(&mut buf).unwrap();
                let (BerValue::Sequence(qtop), _) = decode_ber(&buf[..m], 0).unwrap() else {
                    continue;
                };
                let BerValue::Context(0xa0, qpdu) = &qtop[2] else {
                    continue;
                };
                let BerValue::Integer(qrid) = qpdu[0] else {
                    continue;
                };
                let BerValue::Sequence(qvbs) = &qpdu[3] else {
                    continue;
                };
                let BerValue::Sequence(qpair) = &qvbs[0] else {
                    continue;
                };
                let BerValue::ObjectIdentifier(queried_oid) = &qpair[0] else {
                    continue;
                };
                let qrid_i32 = i32::try_from(qrid).unwrap();
                let resp_pkt = if queried_oid.as_slice() == OID_PWG_DEVICE_ID {
                    build_get_response(
                        b"public",
                        qrid_i32,
                        0,
                        &[(OID_PWG_DEVICE_ID, b"MFG:Brother;MDL:HL-L2350DW;")],
                    )
                } else {
                    // Simulate SNMPv1 printer returning error-status=2 (noSuchName) for unsupported OIDs!
                    build_get_response(b"public", qrid_i32, 2, &[(queried_oid.as_slice(), b"")])
                };
                udp_srv.send_to(&resp_pkt, qfrom).unwrap();
            }
        });

        let cfg = SnmpConfig {
            addresses: vec!["127.0.0.1".into()],
            communities: vec!["public".into()],
            debug_level: 1,
            max_run_time: Duration::from_millis(350),
        };
        let mut out = Vec::new();
        let rc = discover_to(
            &mut out,
            &cfg,
            snmp_port,
            &[(printer_port, "socket")],
            Duration::from_millis(500),
            SsrfPolicy {
                allow_loopback: true,
            },
        );
        assert_eq!(rc, bc::code::OK);
        t.join().unwrap();

        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with(&format!("network socket://127.0.0.1:{printer_port} ")));
        assert!(!lines[0].contains("snmp://"));
        assert!(lines[0].contains("Brother HL-L2350DW"));
        assert!(lines[0].contains("MFG:Brother;MDL:HL-L2350DW;"));

        // Print mode rejects snmp:// URI cleanly.
        let inv = bc::Invocation {
            job_id: 1,
            user: "u".into(),
            title: "t".into(),
            copies: 1,
            options: String::new(),
            file: None,
            device_uri: "snmp://192.168.1.20".into(),
        };
        assert_eq!(print_reject(&inv), bc::code::FAILED);
    }
}
