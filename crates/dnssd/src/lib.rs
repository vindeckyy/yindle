//! DNS-SD (mDNS/Bonjour) printer advertisement + discovery — a port of
//! `scheduler/dirsvc.c`'s `dnssdRegisterPrinter` + `cupsdStartBrowsing`.
//!
//! Uses the pure-Rust `mdns-sd` responder (no Avahi/D-Bus runtime dep) so
//! presswork can advertise and discover printers self-contained on Linux.
//!
//! ## Advertisement (`cupsdRegisterPrinter`)
//! For each shared printer we register, per upstream:
//!  * `_printer._tcp` — the LPD reservation record (empty TXT, port 0),
//!  * `_ipp._tcp`   — IPP service with the full TXT record (and configured
//!    subtypes such as `_universal._sub._ipp._tcp` for `AirPrint`),
//!  * `_ipps._tcp`  — IPPS service when TLS is enabled,
//!  * `_fax-ipp._tcp` — when the queue is a fax,
//!  * `_http._tcp`   — the web interface (`CUPS @ <computer>`) when `BrowseWebIF` is enabled.
//!
//! ## Discovery (`dnssd` backend)
//! [`browse_ipp`] resolves remote `_ipp._tcp`/`_ipps._tcp` services into
//! [`RemotePrinter`] entries for the `cups-deviced` device list, and
//! [`resolve_uri`] resolves `dnssd://` URIs (including percent-encoded
//! instance names and `?uuid=` selectors) to concrete `ipp{s}://` URIs.

#![forbid(unsafe_code)]

use mdns_sd::{RecvTimeoutError, ServiceDaemon, ServiceEvent, ServiceInfo};
use printer::ptype;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Default PDL list advertised when a printer does not specify `pdl`,
/// covering IPP Everywhere, Mopria, and Apple `AirPrint` (`image/urf`).
pub const DEFAULT_PDL: &str =
    "application/pdf,application/postscript,image/jpeg,image/pwg-raster,image/urf";

/// Default `BrowseDNSSDSubTypes` list matching upstream CUPS.
pub const DEFAULT_SUBTYPES: &str = "_cups,_print,_universal";

/// Per-printer data needed to build the service TXT record — mirrors the
/// fields `dnssdBuildTxtRecord` reads off `cupsd_printer_t`.
#[derive(Clone, Debug, Default)]
pub struct SharedPrinter {
    pub name: String,
    /// `printer-info` — used in the instance name when set.
    pub info: String,
    /// `make_model` for `ty=` (falls back to "Unknown").
    pub make_model: String,
    /// `printer-location` for `note=`.
    pub location: String,
    /// `pdl` (comma-separated MIME types; defaults to [`DEFAULT_PDL`] when empty).
    pub pdl: String,
    /// `printer-type` bitmask (`printer::ptype::*` / `CUPS_PRINTER_*`).
    pub printer_type: u32,
    /// `printer-state` (idle=3, processing=4, stopped=5).
    pub printer_state: i32,
    /// `printer-uuid` tail (after `"urn:uuid:"`).
    pub uuid: String,
    /// Class (not printer) — flips `rp`/`adminurl` to `/classes/`.
    pub is_class: bool,
    /// Fax queue — registers `_fax-ipp._tcp`.
    pub is_fax: bool,
}

/// Configuration for [`Advertiser::start_with_config`], mirroring CUPS's
/// `DNSSDHostName`, `DNSSDComputerName`, `BrowseWebIF`, `BrowseIPPSOnly`,
/// and `BrowseDNSSDSubTypes` directives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvertiserConfig {
    /// `DNSSDHostName` — host advertised for mDNS resolution (`<host>.local.`).
    pub host: String,
    /// `DNSSDComputerName` — human-readable `@ <computer>` suffix.
    pub computer: String,
    /// IPP/IPPS listening port.
    pub port: u16,
    /// Whether TLS (`_ipps._tcp` + `TLS=1.3`) is enabled.
    pub tls: bool,
    /// `BrowseWebIF` — advertise `_http._tcp` web interface when true.
    pub browse_web_if: bool,
    /// `BrowseIPPSOnly` — suppress unencrypted `_ipp._tcp` / `_printer._tcp`
    /// and only advertise `_ipps._tcp` when true.
    pub browse_ipps_only: bool,
    /// Parsed `BrowseDNSSDSubTypes` tokens (e.g. `["_cups", "_print", "_universal"]`).
    pub subtypes: Vec<String>,
}

impl Default for AdvertiserConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            computer: String::new(),
            port: 631,
            tls: false,
            browse_web_if: false,
            browse_ipps_only: false,
            subtypes: parse_subtypes(Some(DEFAULT_SUBTYPES)),
        }
    }
}

/// A discovered remote IPP printer (for the `dnssd` backend).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemotePrinter {
    /// `ipp{s}://host:port/<rp>` device URI.
    pub uri: String,
    /// Instance full-name (`<info> @ <computer>._ipp._tcp.local.`).
    pub name: String,
    /// `ty=` make/model for the device `info` field.
    pub make_model: String,
}

/// Parsed components of a `dnssd://` device URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedDnssdUri {
    /// Percent-decoded service instance name (before `._ipp._tcp` / `._ipps._tcp`).
    pub instance: String,
    /// Service registration type (`"_ipp._tcp.local."` or `"_ipps._tcp.local."`).
    pub regtype: &'static str,
    /// `true` for `_ipps._tcp`, `false` for `_ipp._tcp`.
    pub secure: bool,
    /// Explicit resource path if present in the URI (percent-decoded, without leading `/`).
    pub resource_path: Option<String>,
    /// Optional `uuid=` query parameter (normalized without `"urn:uuid:"`).
    pub uuid: Option<String>,
}

/// The mDNS advertiser (`DNSSDContext` + per-printer `dnssd` services).
pub struct Advertiser {
    daemon: ServiceDaemon,
    /// `DNSSDHostName` — `host.local.` the services resolve to.
    host: String,
    /// `DNSSDComputerName` — the `@ <name>` instance suffix.
    computer: String,
    port: u16,
    /// Register `_ipps._tcp` + emit `TLS=` TXT when true.
    tls: bool,
    /// `BrowseWebIF` setting.
    browse_web_if: bool,
    /// `BrowseIPPSOnly` setting.
    browse_ipps_only: bool,
    /// `BrowseDNSSDSubTypes` tokens.
    subtypes: Vec<String>,
    /// printer name -> its registered service full-names (for unregister).
    registered: HashMap<String, Vec<String>>,
    /// The `_http._tcp` web interface service full-name.
    webif: Option<String>,
}

impl Advertiser {
    /// Start the mDNS daemon + register the web interface (backward-compatible
    /// constructor; enables `BrowseWebIF` and default `_universal` subtype).
    pub fn start(host: &str, computer: &str, port: u16, tls: bool) -> std::io::Result<Self> {
        Self::start_with_config(AdvertiserConfig {
            host: host.to_string(),
            computer: computer.to_string(),
            port,
            tls,
            browse_web_if: true,
            browse_ipps_only: false,
            subtypes: parse_subtypes(Some(DEFAULT_SUBTYPES)),
        })
    }

    /// Start the mDNS daemon honoring full [`AdvertiserConfig`] filtering
    /// (`BrowseWebIF`, `BrowseIPPSOnly`, `BrowseDNSSDSubTypes`).
    pub fn start_with_config(config: AdvertiserConfig) -> std::io::Result<Self> {
        let daemon =
            ServiceDaemon::new().map_err(|e| std::io::Error::other(format!("mdns-sd: {e}")))?;
        let mut adv = Self {
            daemon,
            host: normalize_local(&config.host),
            computer: config.computer,
            port: config.port,
            tls: config.tls,
            browse_web_if: config.browse_web_if,
            browse_ipps_only: config.browse_ipps_only,
            subtypes: config.subtypes,
            registered: HashMap::new(),
            webif: None,
        };
        if adv.browse_web_if {
            adv.publish_webif()?;
        }
        Ok(adv)
    }

    /// Build the DNS-SD TXT record for `p` (`dnssdBuildTxtRecord`).
    #[must_use]
    pub fn build_txt_record(
        &self,
        p: &SharedPrinter,
        secure: bool,
        urf: Option<&str>,
    ) -> HashMap<String, String> {
        let has_universal = self
            .subtypes
            .iter()
            .any(|s| s.eq_ignore_ascii_case("_universal"));
        build_txt_record_for(p, &self.adminurl(p), secure, urf, has_universal)
    }

    /// `adminurl` — `http{s}://<host>:<port>/<printers|classes>/<name>`.
    fn adminurl(&self, p: &SharedPrinter) -> String {
        format!(
            "{scheme}://{host}:{port}/{sub}/{name}",
            scheme = if self.tls { "https" } else { "http" },
            host = self.host,
            port = self.port,
            sub = if p.is_class { "classes" } else { "printers" },
            name = p.name,
        )
    }

    /// Instance name `"<info|name> @ <computer>"`.
    fn instance(&self, p: &SharedPrinter) -> String {
        let base = if p.info.is_empty() { &p.name } else { &p.info };
        if self.computer.is_empty() {
            base.clone()
        } else {
            format!("{base} @ {}", self.computer)
        }
    }

    /// `cupsdRegisterPrinter` — register a shared printer's services.
    /// Unregisters any prior registration for the same name first.
    pub fn publish(&mut self, p: &SharedPrinter) -> std::io::Result<()> {
        self.publish_with_urf(p, None)
    }

    /// Register a shared printer with an optional explicit `AirPrint` `URF=` value.
    pub fn publish_with_urf(
        &mut self,
        p: &SharedPrinter,
        urf: Option<&str>,
    ) -> std::io::Result<()> {
        self.unpublish(&p.name);
        let instance = self.instance(p);
        let mut names = Vec::new();
        let is_fax = p.is_fax || (p.printer_type & ptype_bit(ptype::FAX) != 0);

        if !self.browse_ipps_only {
            // 1. `_printer._tcp` reservation (empty TXT, port 0).
            names.push(self.register(&instance, "_printer._tcp.local.", 0, HashMap::new())?);

            // 2. `_fax-ipp._tcp` for fax queues.
            if is_fax {
                names.push(self.register(
                    &instance,
                    "_fax-ipp._tcp.local.",
                    self.port,
                    self.build_txt_record(p, false, urf),
                )?);
            }

            // 3. `_ipp._tcp` (with `_universal` / configured subtype) + full TXT record.
            let ipp_reg = service_regtype("_ipp._tcp.local.", &self.subtypes);
            names.push(self.register(
                &instance,
                &ipp_reg,
                self.port,
                self.build_txt_record(p, false, urf),
            )?);
        }

        // 4. `_ipps._tcp` when TLS is enabled (`TLS=` in TXT).
        if self.tls {
            let ipps_reg = service_regtype("_ipps._tcp.local.", &self.subtypes);
            names.push(self.register(
                &instance,
                &ipps_reg,
                self.port,
                self.build_txt_record(p, true, urf),
            )?);
        }

        self.registered.insert(p.name.clone(), names);
        Ok(())
    }

    /// `cupsdDeregisterPrinter` — stop advertising a printer.
    pub fn unpublish(&mut self, name: &str) {
        if let Some(services) = self.registered.remove(name) {
            for full in services {
                let _ = self.daemon.unregister(&full);
            }
        }
    }

    /// `cupsdUpdateDNSSDName` — register the `_http._tcp` web UI.
    pub fn publish_webif(&mut self) -> std::io::Result<()> {
        let name = if self.computer.is_empty() {
            "CUPS".to_string()
        } else {
            format!("CUPS @ {}", self.computer)
        };
        let full = self.register(&name, "_http._tcp.local.", self.port, HashMap::new())?;
        self.webif = Some(full);
        Ok(())
    }

    /// Number of printers currently advertised.
    #[must_use]
    pub fn count(&self) -> usize {
        self.registered.len()
    }

    /// Full service names registered for `printer_name` (empty if not advertised).
    #[must_use]
    pub fn registered_services(&self, printer_name: &str) -> &[String] {
        self.registered.get(printer_name).map_or(&[], Vec::as_slice)
    }

    /// Whether the `_http._tcp` web interface service is currently published.
    #[must_use]
    pub fn has_webif(&self) -> bool {
        self.webif.is_some()
    }

    /// Register one service; returns its full-name for unregister.
    fn register(
        &self,
        instance: &str,
        regtype: &str,
        port: u16,
        txt: HashMap<String, String>,
    ) -> std::io::Result<String> {
        let info = ServiceInfo::new(
            regtype, instance, &self.host,
            "", // no static ip — let mdns-sd pick the host addrs
            port, txt,
        )
        .map_err(|e| std::io::Error::other(format!("service info: {e}")))?;
        let full = info.get_fullname().to_string();
        self.daemon
            .register(info)
            .map_err(|e| std::io::Error::other(format!("register {regtype}: {e}")))?;
        Ok(full)
    }

    /// Shut down — unregister all services.
    pub fn shutdown(self) {
        let _ = self.daemon.shutdown();
    }
}

const fn ptype_bit(bit: i32) -> u32 {
    bit.cast_unsigned()
}

/// Normalize a printer's `pdl` string, forwarding real MIME types verbatim
/// and falling back to [`DEFAULT_PDL`] when empty.
#[must_use]
pub fn effective_pdl(pdl: &str) -> String {
    let parts: Vec<&str> = pdl
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        DEFAULT_PDL.to_string()
    } else {
        parts.join(",")
    }
}

/// Build a comma-separated `pdl=` TXT value from a list of supported MIME types.
#[must_use]
pub fn pdl_from_mime_types(mime_types: &[&str]) -> String {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for &m in mime_types {
        let trimmed = m.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_ascii_lowercase()) {
            out.push(trimmed);
        }
    }
    out.join(",")
}

/// Compute an AirPrint-compatible `URF=` TXT record value from CUPS `printer-type` flags.
#[must_use]
pub fn default_urf(printer_type: u32) -> String {
    let mut tokens = vec!["W8"];
    if printer_type & ptype_bit(ptype::COLOR) != 0 {
        tokens.push("SRGB24");
    }
    if printer_type & ptype_bit(ptype::COPIES) != 0 {
        tokens.push("CP255");
    } else {
        tokens.push("CP1");
    }
    tokens.push("RS600");
    if printer_type & ptype_bit(ptype::DUPLEX) != 0 {
        tokens.push("DM1");
    }
    tokens.join(",")
}

/// Parse a `BrowseDNSSDSubTypes` directive string (e.g. `"_cups,_print,_universal"`).
#[must_use]
pub fn parse_subtypes(directive: Option<&str>) -> Vec<String> {
    let Some(raw) = directive else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for tok in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let t = tok.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("none") || t.eq_ignore_ascii_case("all") {
            continue;
        }
        let normalized = if t.starts_with('_') {
            t.to_ascii_lowercase()
        } else {
            format!("_{}", t.to_ascii_lowercase())
        };
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out
}

/// Format the mDNS registration type including the primary subtype when configured.
///
/// Prefers `_universal` when present so `AirPrint` clients browsing
/// `_universal._sub._ipp._tcp.local.` discover the queue.
#[must_use]
pub fn service_regtype(base_regtype: &str, subtypes: &[String]) -> String {
    let primary = subtypes
        .iter()
        .find(|s| s.eq_ignore_ascii_case("_universal"))
        .or_else(|| subtypes.first());
    match primary {
        Some(sub) => format!("{sub}._sub.{base_regtype}"),
        None => base_regtype.to_string(),
    }
}

/// Build the full CUPS DNS-SD TXT record map for a printer.
#[must_use]
pub fn build_txt_record_for(
    p: &SharedPrinter,
    adminurl: &str,
    secure: bool,
    urf: Option<&str>,
    include_universal_urf: bool,
) -> HashMap<String, String> {
    let mut t = HashMap::new();
    let resource_path = format!(
        "{}/{}",
        if p.is_class { "classes" } else { "printers" },
        p.name
    );
    t.insert("txtvers".into(), "1".into());
    t.insert("qtotal".into(), "1".into());
    t.insert("rp".into(), resource_path.clone());
    t.insert(
        "ty".into(),
        if p.make_model.is_empty() {
            "Unknown".into()
        } else {
            p.make_model.clone()
        },
    );
    t.insert("adminurl".into(), adminurl.to_string());
    if !p.location.is_empty() {
        t.insert("note".into(), p.location.clone());
    }
    t.insert("priority".into(), "0".into());

    let pdl = effective_pdl(&p.pdl);
    let pdl_has_urf = pdl
        .split(',')
        .any(|m| m.trim().eq_ignore_ascii_case("image/urf"));
    t.insert("pdl".into(), pdl);

    if let Some(u) = urf.map(str::trim).filter(|s| !s.is_empty()) {
        t.insert("URF".into(), u.to_string());
    } else if pdl_has_urf || include_universal_urf {
        t.insert("URF".into(), default_urf(p.printer_type));
    }

    if !p.uuid.is_empty() {
        t.insert("UUID".into(), p.uuid.trim_start_matches("urn:uuid:").into());
    }
    if secure {
        t.insert("TLS".into(), "1.3".into());
    }

    // Official CUPS CUPS_PRINTER_* / printer::ptype::* capability bitmasks.
    let cap = |bit: i32| {
        if p.printer_type & ptype_bit(bit) != 0 {
            "T"
        } else {
            "F"
        }
    };
    t.insert("Color".into(), cap(ptype::COLOR).into());
    t.insert("Duplex".into(), cap(ptype::DUPLEX).into());
    t.insert("Staple".into(), cap(ptype::STAPLE).into());
    t.insert("Copies".into(), cap(ptype::COPIES).into());
    t.insert("Collate".into(), cap(ptype::COLLATE).into());
    t.insert("Punch".into(), cap(ptype::PUNCH).into());
    t.insert("Bind".into(), cap(ptype::BIND).into());
    t.insert("Sort".into(), cap(ptype::SORT).into());
    if p.printer_type & ptype_bit(ptype::SCANNER) != 0 {
        t.insert("Scan".into(), "T".into());
    }
    if p.is_fax || (p.printer_type & ptype_bit(ptype::FAX) != 0) {
        t.insert("Fax".into(), "T".into());
        t.insert("rfo".into(), resource_path);
    }
    t.insert("printer-type".into(), format!("{:#010x}", p.printer_type));
    t.insert("printer-state".into(), p.printer_state.to_string());
    t.insert("mopria-certified".into(), "1.3".into());
    t
}

/// Percent-decode a URI component (`%20` -> space, UTF-8 multi-byte sequences preserved).
#[must_use]
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse a `dnssd://<instance>._ipp(s)._tcp[.local.][/<rp>][?uuid=<id>]` URI.
#[must_use]
pub fn parse_dnssd_uri(device_uri: &str) -> Option<ParsedDnssdUri> {
    let rest = strip_prefix_ignore_ascii_case(device_uri, "dnssd://")?;
    let (without_query, query) = match rest.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (rest, None),
    };
    let (raw_authority, raw_path) = match without_query.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (without_query, None),
    };
    let authority = percent_decode(raw_authority);
    let authority_trimmed = authority.trim_end_matches('.');
    let without_local =
        strip_suffix_ignore_ascii_case(authority_trimmed, ".local").unwrap_or(authority_trimmed);

    let (instance, regtype, secure) =
        if let Some(inst) = strip_suffix_ignore_ascii_case(without_local, "._ipps._tcp") {
            (inst.to_string(), "_ipps._tcp.local.", true)
        } else {
            let inst = strip_suffix_ignore_ascii_case(without_local, "._ipp._tcp")?;
            (inst.to_string(), "_ipp._tcp.local.", false)
        };

    if instance.is_empty() {
        return None;
    }

    let resource_path = raw_path
        .map(percent_decode)
        .map(|p| p.trim_start_matches('/').to_string())
        .filter(|p| !p.is_empty());

    let uuid = query.and_then(|q| {
        q.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k.eq_ignore_ascii_case("uuid") && !v.is_empty() {
                let decoded = percent_decode(v);
                Some(
                    strip_prefix_ignore_ascii_case(&decoded, "urn:uuid:")
                        .unwrap_or(&decoded)
                        .to_string(),
                )
            } else {
                None
            }
        })
    });

    Some(ParsedDnssdUri {
        instance,
        regtype,
        secure,
        resource_path,
        uuid,
    })
}

fn strip_suffix_ignore_ascii_case<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    let sb = s.as_bytes();
    let suf = suffix.as_bytes();
    if sb.len() >= suf.len() {
        let split = sb.len() - suf.len();
        if sb[split..].eq_ignore_ascii_case(suf) && s.is_char_boundary(split) {
            return Some(&s[..split]);
        }
    }
    None
}

fn strip_prefix_ignore_ascii_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let sb = s.as_bytes();
    let pre = prefix.as_bytes();
    if sb.len() >= pre.len()
        && sb[..pre.len()].eq_ignore_ascii_case(pre)
        && s.is_char_boundary(pre.len())
    {
        Some(&s[pre.len()..])
    } else {
        None
    }
}

/// Check whether a resolved mDNS service full-name and optional TXT `UUID` match `parsed`.
#[must_use]
pub fn service_matches(parsed: &ParsedDnssdUri, fullname: &str, txt_uuid: Option<&str>) -> bool {
    let reg_suffix = format!(".{}", parsed.regtype);
    let Some(inst) = strip_suffix_ignore_ascii_case(fullname, &reg_suffix) else {
        return false;
    };
    if !inst.eq_ignore_ascii_case(&parsed.instance) {
        return false;
    }
    if let Some(expected_uuid) = &parsed.uuid {
        let Some(actual) = txt_uuid else {
            return false;
        };
        let actual = strip_prefix_ignore_ascii_case(actual, "urn:uuid:").unwrap_or(actual);
        if !actual.eq_ignore_ascii_case(expected_uuid) {
            return false;
        }
    }
    true
}

fn format_ipp_uri(secure: bool, host: &str, port: u16, rp: &str) -> String {
    let scheme = if secure { "ipps" } else { "ipp" };
    let clean_host = host.trim_end_matches('.');
    let clean_rp = rp.trim_start_matches('/');
    format!("{scheme}://{clean_host}:{port}/{clean_rp}")
}

fn collect_browse_pollers<F>(
    deadline: Instant,
    pollers: &mut [(bool, F, bool)],
) -> Vec<RemotePrinter>
where
    F: FnMut(Duration) -> Result<ServiceEvent, RecvTimeoutError>,
{
    let mut out = Vec::new();
    let mut seen_uris = HashSet::new();

    while Instant::now() < deadline && pollers.iter().any(|p| p.2) {
        for (secure, poll, alive) in pollers.iter_mut() {
            if !*alive {
                continue;
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            let slice = remaining.min(Duration::from_millis(25));
            match poll(slice) {
                Ok(ServiceEvent::ServiceResolved(info)) => {
                    if let Some(rp) = info.get_property_val_str("rp") {
                        let uri = format_ipp_uri(*secure, info.get_hostname(), info.get_port(), rp);
                        if seen_uris.insert(uri.clone()) {
                            out.push(RemotePrinter {
                                uri,
                                name: info.get_fullname().to_string(),
                                make_model: info
                                    .get_property_val_str("ty")
                                    .unwrap_or_default()
                                    .to_string(),
                            });
                        }
                    }
                }
                Ok(_) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => *alive = false,
            }
        }
    }
    out
}

/// `cupsdStartBrowsing`-style discovery — resolve `_ipp._tcp` and `_ipps._tcp`
/// services on the local network concurrently until `timeout` elapses, returning
/// deduplicated [`RemotePrinter`] entries.
#[must_use]
pub fn browse_ipp(timeout: Duration) -> Vec<RemotePrinter> {
    let Ok(daemon) = ServiceDaemon::new() else {
        return Vec::new();
    };
    let mut active_types = Vec::new();
    let mut pollers = Vec::new();
    for (regtype, secure) in [("_ipp._tcp.local.", false), ("_ipps._tcp.local.", true)] {
        if let Ok(rx) = daemon.browse(regtype) {
            active_types.push(regtype);
            pollers.push((secure, move |d| rx.recv_timeout(d), true));
        }
    }

    let out = collect_browse_pollers(Instant::now() + timeout, &mut pollers);
    for regtype in active_types {
        let _ = daemon.stop_browse(regtype);
    }
    let _ = daemon.shutdown();
    out
}

/// `hostname.local.` — ensure the mDNS host has the `.local.` suffix.
fn normalize_local(host: &str) -> String {
    let h = host.trim_end_matches('.');
    if h.to_ascii_lowercase().ends_with(".local") {
        format!("{h}.")
    } else {
        format!("{h}.local.")
    }
}

fn resolve_with_poller<F>(parsed: &ParsedDnssdUri, deadline: Instant, mut poll: F) -> Option<String>
where
    F: FnMut(Duration) -> Result<ServiceEvent, RecvTimeoutError>,
{
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let slice = remaining.min(Duration::from_millis(25));
        match poll(slice) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let txt_uuid = info
                    .get_property_val_str("UUID")
                    .or_else(|| info.get_property_val_str("uuid"));
                if service_matches(parsed, info.get_fullname(), txt_uuid) {
                    let rp = parsed
                        .resource_path
                        .as_deref()
                        .or_else(|| info.get_property_val_str("rp"))
                        .unwrap_or("ipp/print");
                    return Some(format_ipp_uri(
                        parsed.secure,
                        info.get_hostname(),
                        info.get_port(),
                        rp,
                    ));
                }
            }
            Ok(_) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    None
}

/// Resolve a `dnssd://<instance>._ipp._tcp.local./<rp>` device URI to a real
/// `ipp{s}://host:port/<rp>` URI — the dnssd backend's print-path resolution
/// (upstream `backend/dnssd.c` `cupsBackendResolve`).
///
/// Decodes percent-encoded instance/path components, honors optional `?uuid=`,
/// and waits until `timeout` elapses rather than stopping on brief mDNS silence.
#[must_use]
pub fn resolve_uri(device_uri: &str, timeout: Duration) -> Option<String> {
    let parsed = parse_dnssd_uri(device_uri)?;
    let daemon = ServiceDaemon::new().ok()?;
    let receiver = daemon.browse(parsed.regtype).ok()?;
    let found = resolve_with_poller(&parsed, Instant::now() + timeout, |d| {
        receiver.recv_timeout(d)
    });
    let _ = daemon.stop_browse(parsed.regtype);
    let _ = daemon.shutdown();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_host() {
        assert_eq!(normalize_local("server"), "server.local.");
        assert_eq!(normalize_local("server.local."), "server.local.");
        assert_eq!(normalize_local("server.local"), "server.local.");
    }

    #[test]
    fn txt_record_printer_type_bitmasks_match_cups_constants() {
        // Verify BW (0x04) and DEFAULT (0x20000) do NOT set Color or Scan!
        let bw_only = SharedPrinter {
            name: "mono".into(),
            printer_type: ptype_bit(ptype::BW) | ptype_bit(ptype::DEFAULT),
            ..Default::default()
        };
        let t_bw = build_txt_record_for(
            &bw_only,
            "http://h.local.:631/printers/mono",
            false,
            None,
            false,
        );
        assert_eq!(t_bw["Color"], "F");
        assert_eq!(t_bw["Duplex"], "F");
        assert_eq!(t_bw["Staple"], "F");
        assert_eq!(t_bw["Copies"], "F");
        assert_eq!(t_bw["Collate"], "F");
        assert_eq!(t_bw["Punch"], "F");
        assert_eq!(t_bw["Bind"], "F");
        assert_eq!(t_bw["Sort"], "F");
        assert!(!t_bw.contains_key("Scan"));
        assert!(!t_bw.contains_key("Fax"));
        assert_eq!(t_bw["ty"], "Unknown");
        assert_eq!(t_bw["pdl"], DEFAULT_PDL);
        assert_eq!(t_bw["URF"], "W8,CP1,RS600");

        // Verify every official capability bit individually and combined.
        let full = SharedPrinter {
            name: "office".into(),
            info: "Office MFP".into(),
            make_model: "HP LaserJet".into(),
            location: "Floor 3".into(),
            pdl: "application/pdf, image/urf, image/pwg-raster".into(),
            printer_type: ptype_bit(ptype::COLOR)
                | ptype_bit(ptype::DUPLEX)
                | ptype_bit(ptype::STAPLE)
                | ptype_bit(ptype::COPIES)
                | ptype_bit(ptype::COLLATE)
                | ptype_bit(ptype::PUNCH)
                | ptype_bit(ptype::BIND)
                | ptype_bit(ptype::SORT)
                | ptype_bit(ptype::SCANNER)
                | ptype_bit(ptype::FAX),
            printer_state: 3,
            uuid: "urn:uuid:abc-123".into(),
            is_class: true,
            is_fax: false,
        };
        let t = build_txt_record_for(
            &full,
            "https://h.local.:631/classes/office",
            true,
            None,
            true,
        );
        assert_eq!(t["rp"], "classes/office");
        assert_eq!(t["ty"], "HP LaserJet");
        assert_eq!(t["note"], "Floor 3");
        assert_eq!(t["TLS"], "1.3");
        assert_eq!(t["UUID"], "abc-123");
        assert_eq!(t["Color"], "T");
        assert_eq!(t["Duplex"], "T");
        assert_eq!(t["Staple"], "T");
        assert_eq!(t["Copies"], "T");
        assert_eq!(t["Collate"], "T");
        assert_eq!(t["Punch"], "T");
        assert_eq!(t["Bind"], "T");
        assert_eq!(t["Sort"], "T");
        assert_eq!(t["Scan"], "T");
        assert_eq!(t["Fax"], "T");
        assert_eq!(t["rfo"], "classes/office");
        assert_eq!(t["pdl"], "application/pdf,image/urf,image/pwg-raster");
        assert_eq!(t["URF"], "W8,SRGB24,CP255,RS600,DM1");

        // Explicit URF override and non-URF PDL without universal subtype.
        let custom = SharedPrinter {
            name: "raw".into(),
            pdl: "application/postscript".into(),
            ..Default::default()
        };
        let t_no_urf =
            build_txt_record_for(&custom, "http://h:631/printers/raw", false, None, false);
        assert!(!t_no_urf.contains_key("URF"));
        let t_override = build_txt_record_for(
            &custom,
            "http://h:631/printers/raw",
            false,
            Some("W8,RS300"),
            false,
        );
        assert_eq!(t_override["URF"], "W8,RS300");
    }

    #[test]
    fn pdl_and_subtype_helpers() {
        assert_eq!(effective_pdl(""), DEFAULT_PDL);
        assert_eq!(effective_pdl(" , "), DEFAULT_PDL);
        assert_eq!(
            effective_pdl("application/pdf, image/jpeg "),
            "application/pdf,image/jpeg"
        );
        assert_eq!(
            pdl_from_mime_types(&["application/pdf", "IMAGE/URF", "image/urf", ""]),
            "application/pdf,IMAGE/URF"
        );

        assert_eq!(
            parse_subtypes(Some("_cups,_print,_universal,none,all,custom")),
            vec!["_cups", "_print", "_universal", "_custom"]
        );
        assert_eq!(parse_subtypes(None), Vec::<String>::new());
        assert_eq!(
            service_regtype(
                "_ipp._tcp.local.",
                &parse_subtypes(Some("_cups,_universal"))
            ),
            "_universal._sub._ipp._tcp.local."
        );
        assert_eq!(
            service_regtype("_ipp._tcp.local.", &parse_subtypes(Some("_cups"))),
            "_cups._sub._ipp._tcp.local."
        );
        assert_eq!(service_regtype("_ipp._tcp.local.", &[]), "_ipp._tcp.local.");
    }

    #[test]
    fn percent_decode_and_parse_dnssd_uri() {
        assert_eq!(
            percent_decode("HP%20LaserJet%20%40%20Office"),
            "HP LaserJet @ Office"
        );
        assert_eq!(percent_decode("caf%C3%A9%ZZ%2"), "café%ZZ%2");

        let parsed = parse_dnssd_uri(
            "dnssd://HP%20Office%20%40%20server._ipps._tcp.local./printers/my%20queue?uuid=urn:uuid:1111-2222",
        )
        .unwrap();
        assert_eq!(parsed.instance, "HP Office @ server");
        assert_eq!(parsed.regtype, "_ipps._tcp.local.");
        assert!(parsed.secure);
        assert_eq!(parsed.resource_path.as_deref(), Some("printers/my queue"));
        assert_eq!(parsed.uuid.as_deref(), Some("1111-2222"));

        assert!(service_matches(
            &parsed,
            "HP Office @ server._ipps._tcp.local.",
            Some("urn:uuid:1111-2222")
        ));
        assert!(!service_matches(
            &parsed,
            "HP Office @ server._ipps._tcp.local.",
            Some("9999-0000")
        ));
        assert!(!service_matches(
            &parsed,
            "HP Office @ server._ipps._tcp.local.",
            None
        ));
        assert!(!service_matches(
            &parsed,
            "Other._ipps._tcp.local.",
            Some("1111-2222")
        ));
        assert!(!service_matches(
            &parsed,
            "HP Office @ server._ipp._tcp.local.",
            Some("1111-2222")
        ));

        let simple = parse_dnssd_uri("DNSSD://Printer%201._ipp._tcp.local/?uuid=abcd").unwrap();
        assert_eq!(simple.instance, "Printer 1");
        assert!(!simple.secure);
        assert_eq!(simple.resource_path, None);
        assert_eq!(simple.uuid.as_deref(), Some("abcd"));

        let no_path = parse_dnssd_uri("dnssd://Lab._ipp._tcp").unwrap();
        assert_eq!(no_path.instance, "Lab");
        assert_eq!(no_path.resource_path, None);
        assert_eq!(no_path.uuid, None);

        assert!(parse_dnssd_uri("ipp://localhost/printers/x").is_none());
        assert!(parse_dnssd_uri("dnssd://._ipp._tcp.local.").is_none());
        assert!(parse_dnssd_uri("dnssd://bad._http._tcp.local.").is_none());

        // Multi-byte UTF-8 straddling ASCII slice boundaries must never panic.
        assert!(parse_dnssd_uri("aéééé://bad").is_none());
        assert!(parse_dnssd_uri("dnssd://aéééééééé").is_none());
        let utf8_uri = parse_dnssd_uri(
            "dnssd://Caf%C3%A9%20%E3%83%97%E3%83%AA%E3%83%B3%E3%82%BF._ipp._tcp.local./?uuid=%C3%A9%C3%A9%C3%A9%C3%A9%C3%A9",
        )
        .unwrap();
        assert_eq!(utf8_uri.instance, "Café プリンタ");
        assert_eq!(utf8_uri.uuid.as_deref(), Some("ééééé"));
        assert!(!service_matches(
            &utf8_uri,
            "aéééééééééééééééé",
            Some("aééééééé")
        ));
        assert!(service_matches(
            &utf8_uri,
            "Café プリンタ._ipp._tcp.local.",
            Some("ééééé")
        ));
    }

    #[test]
    fn advertiser_config_filtering_and_publish_lifecycle() {
        // Default config has BrowseWebIF = false, BrowseIPPSOnly = false.
        let cfg = AdvertiserConfig {
            host: "testhost".into(),
            computer: "Lab".into(),
            port: 10631,
            tls: true,
            browse_web_if: false,
            browse_ipps_only: true,
            ..Default::default()
        };
        let mut adv_ipps = Advertiser::start_with_config(cfg).unwrap();
        assert!(!adv_ipps.has_webif());
        let p = SharedPrinter {
            name: "secureq".into(),
            info: "Secure Queue".into(),
            make_model: "PWG Printer".into(),
            location: "Server Room".into(),
            pdl: "application/pdf,image/urf".into(),
            printer_type: ptype_bit(ptype::COLOR) | ptype_bit(ptype::DUPLEX),
            printer_state: 3,
            uuid: "urn:uuid:deadbeef".into(),
            is_class: false,
            is_fax: true,
        };
        adv_ipps.publish(&p).unwrap();
        assert_eq!(adv_ipps.count(), 1);
        // BrowseIPPSOnly suppresses _printer._tcp, _fax-ipp._tcp, and _ipp._tcp.
        let svcs = adv_ipps.registered_services("secureq");
        assert_eq!(svcs.len(), 1);
        assert!(svcs[0].contains("_ipps._tcp.local."));
        let txt = adv_ipps.build_txt_record(&p, true, None);
        assert_eq!(txt["Color"], "T");
        assert_eq!(txt["Duplex"], "T");
        assert_eq!(txt["TLS"], "1.3");
        adv_ipps.unpublish("secureq");
        assert_eq!(adv_ipps.count(), 0);
        assert_eq!(adv_ipps.registered_services("secureq"), &[] as &[String]);
        adv_ipps.shutdown();

        // Standard Advertiser::start enables webif + publishes _printer, _fax-ipp, _ipp, _ipps.
        let mut adv = Advertiser::start("testhost", "", 10632, true).unwrap();
        assert!(adv.has_webif());
        assert_eq!(
            adv.instance(&SharedPrinter {
                name: "q".into(),
                ..Default::default()
            }),
            "q"
        );
        adv.publish(&p).unwrap();
        let svcs = adv.registered_services("secureq");
        assert_eq!(svcs.len(), 4);
        adv.shutdown();

        let adv2 = Advertiser::start("h", "Workstation", 631, false).unwrap();
        assert_eq!(
            adv2.instance(&SharedPrinter {
                name: "q".into(),
                info: "My Printer".into(),
                ..Default::default()
            }),
            "My Printer @ Workstation"
        );
        adv2.shutdown();
    }

    #[test]
    fn browse_and_resolve_respect_deadline() {
        // Publish a unique local printer so browse_ipp / resolve_uri can also
        // exercise live mDNS resolution if multicast loopback is available,
        // and verify deadline enforcement (never exits prematurely on brief silence).
        let unique_name = format!("pwtest{}", std::process::id());
        let mut adv = Advertiser::start("pwtesthost", "TestBox", 16631, true).unwrap();
        let p = SharedPrinter {
            name: unique_name.clone(),
            info: format!("PW Test {}", std::process::id()),
            make_model: "Presswork Test".into(),
            pdl: "application/pdf,image/urf".into(),
            printer_type: ptype_bit(ptype::COLOR),
            printer_state: 3,
            uuid: "urn:uuid:12345678-1234-1234-1234-123456789abc".into(),
            ..Default::default()
        };
        adv.publish(&p).unwrap();

        let start = Instant::now();
        let found = browse_ipp(Duration::from_millis(250));
        // Must wait for the full deadline (at least ~200ms), NOT bail at 120ms!
        assert!(start.elapsed() >= Duration::from_millis(200));
        let _ = found;

        // Invalid URI returns immediately without waiting.
        assert!(resolve_uri("http://not-dnssd", Duration::from_millis(500)).is_none());

        // Non-existent service waits full deadline and returns None.
        let r_start = Instant::now();
        let miss = resolve_uri(
            "dnssd://No%20Such%20Printer%20999._ipp._tcp.local./printers/none",
            Duration::from_millis(200),
        );
        assert!(miss.is_none());
        assert!(r_start.elapsed() >= Duration::from_millis(180));

        // Attempt live resolve of the published service (may succeed on multicast-enabled hosts).
        let encoded = format!("dnssd://PW%20Test%20{}%20%40%20TestBox._ipp._tcp.local./?uuid=12345678-1234-1234-1234-123456789abc", std::process::id());
        let _ = resolve_uri(&encoded, Duration::from_millis(300));

        adv.shutdown();
    }

    #[test]
    fn browse_and_resolve_event_loops_with_synthetic_services() {
        type Poller = Box<dyn FnMut(Duration) -> Result<ServiceEvent, RecvTimeoutError>>;

        let mut txt1 = HashMap::new();
        txt1.insert("rp".into(), "printers/office".into());
        txt1.insert("ty".into(), "HP LaserJet".into());
        txt1.insert("UUID".into(), "aaa-111".into());
        let info1 = ServiceInfo::new(
            "_ipp._tcp.local.",
            "Office HP @ srv",
            "srv.local.",
            "127.0.0.1",
            631,
            txt1,
        )
        .unwrap()
        .as_resolved_service();

        let mut txt2 = HashMap::new();
        txt2.insert("rp".into(), "ipp/print".into());
        txt2.insert("ty".into(), "Canon IPPS".into());
        let info2 = ServiceInfo::new(
            "_ipps._tcp.local.",
            "Canon Secure",
            "canon.local.",
            "127.0.0.1",
            443,
            txt2,
        )
        .unwrap()
        .as_resolved_service();

        // Feed duplicate + timeout + disconnect through collect_browse_pollers.
        let mut q1 = std::collections::VecDeque::from([
            Err(RecvTimeoutError::Timeout),
            Ok(ServiceEvent::SearchStarted("_ipp._tcp.local.".into())),
            Ok(ServiceEvent::ServiceResolved(Box::new(info1.clone()))),
            Ok(ServiceEvent::ServiceResolved(Box::new(info1.clone()))),
            Err(RecvTimeoutError::Disconnected),
        ]);
        let mut q2 = std::collections::VecDeque::from([
            Ok(ServiceEvent::ServiceResolved(Box::new(info2.clone()))),
            Err(RecvTimeoutError::Disconnected),
        ]);
        let mut pollers: Vec<(bool, Poller, bool)> = vec![
            (
                false,
                Box::new(move |_| {
                    q1.pop_front()
                        .unwrap_or(Err(RecvTimeoutError::Disconnected))
                }),
                true,
            ),
            (
                true,
                Box::new(move |_| {
                    q2.pop_front()
                        .unwrap_or(Err(RecvTimeoutError::Disconnected))
                }),
                true,
            ),
        ];
        let found = collect_browse_pollers(Instant::now() + Duration::from_secs(1), &mut pollers);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].uri, "ipps://canon.local:443/ipp/print");
        assert_eq!(found[0].make_model, "Canon IPPS");
        assert_eq!(found[1].uri, "ipp://srv.local:631/printers/office");
        assert_eq!(found[1].make_model, "HP LaserJet");

        // Resolve via percent-encoded instance + UUID + fallback to TXT `rp`.
        let parsed =
            parse_dnssd_uri("dnssd://Office%20HP%20%40%20srv._ipp._tcp.local./?uuid=aaa-111")
                .unwrap();
        let mut rq = std::collections::VecDeque::from([
            Err(RecvTimeoutError::Timeout),
            Ok(ServiceEvent::SearchStarted("_ipp._tcp.local.".into())),
            Ok(ServiceEvent::ServiceResolved(Box::new(info1))),
        ]);
        let resolved =
            resolve_with_poller(&parsed, Instant::now() + Duration::from_secs(1), |_| {
                rq.pop_front()
                    .unwrap_or(Err(RecvTimeoutError::Disconnected))
            });
        assert_eq!(
            resolved.as_deref(),
            Some("ipp://srv.local:631/printers/office")
        );

        // Disconnected receiver returns None promptly.
        let none = resolve_with_poller(&parsed, Instant::now() + Duration::from_secs(1), |_| {
            Err(RecvTimeoutError::Disconnected)
        });
        assert_eq!(none, None);
    }
}
