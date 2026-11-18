//! `<Location>`/`<Limit>`/`<LimitExcept>` model + `parse_aaa` — the
//! authentication/authorization/access-control directive parser ported
//! from `scheduler/conf.c`.

use crate::lexer::ConfLine;
use crate::types::{limit, AuthLevel, AuthType, Encryption, HostMask, IpNet, OrderType, Satisfy};

/// One `<Location>` (or one `<Limit>` variant of it, or one `<Policy>`
/// operation limit — same structure upstream).
#[derive(Debug, Clone)]
pub struct Location {
    /// Path this location applies to (`/`, `/admin`, `/printers/x`…),
    /// or the policy op name inside `<Policy>` blocks.
    pub path: String,
    /// HTTP-method bitmask this location limits (`CUPSD_AUTH_LIMIT_*`).
    pub limit: u32,
    /// `Order` — which of allow/deny wins.
    pub order: OrderType,
    /// `Allow` host masks.
    pub allow: Vec<HostMask>,
    /// `Deny` host masks.
    pub deny: Vec<HostMask>,
    /// `AuthType`.
    pub auth_type: AuthType,
    /// Auth level required (anon/user/group).
    pub auth_level: AuthLevel,
    /// Required user/group names (`Require user a b`, `Require group g`,
    /// `@SYSTEM`, `@OWNER`, `valid-user` marker, etc.).
    pub names: Vec<String>,
    /// `Encryption` level required.
    pub encryption: Encryption,
    /// `Satisfy` mode.
    pub satisfy: Satisfy,
}

impl Location {
    /// New location with cupsd's implicit defaults
    /// (`limit ALL`, `Order deny,allow`, `Encryption` from `DefaultEncryption`).
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            limit: limit::ALL,
            order: OrderType::default(),
            allow: Vec::new(),
            deny: Vec::new(),
            auth_type: AuthType::Default,
            auth_level: AuthLevel::Anon,
            names: Vec::new(),
            encryption: Encryption::default(),
            satisfy: Satisfy::default(),
        }
    }

    /// Add a name to the `Require` list (dedup not performed upstream).
    pub fn add_name(&mut self, name: impl Into<String>) {
        self.names.push(name.into());
    }
}

/// Diagnostic sink shared by all parsers.
pub trait Diag {
    /// Emit a message at `severity` for `linenum`.
    fn log(&mut self, severity: Severity, linenum: usize, msg: String);
}

/// Log severity, mapped from `CUPSD_LOG_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Fatal error — parse aborts if the matching `FatalErrors` bit is set.
    Error,
    /// Warning — parse continues.
    Warn,
    /// Informational.
    Info,
}

/// Result of parsing one aaa directive.
pub enum AaaResult {
    /// Directive handled.
    Ok,
    /// Unknown directive.
    Unknown,
    /// Error; `fatal` = whether `FatalErrors & CONFIG` should abort.
    Error,
}

/// `parse_aaa()` — handle one directive inside a `<Location>`/`<Limit>`/
/// `<Policy><Limit>` block. Returns `Unknown` for anything it doesn't own.
#[allow(clippy::too_many_lines)]
pub fn parse_aaa<D: Diag>(
    loc: &mut Location,
    line: &ConfLine,
    diags: &mut D,
    filename: &str,
) -> AaaResult {
    let name = line.name.as_str();
    let value = if let Some(v) = &line.value {
        v.as_str()
    } else {
        diags.log(
            Severity::Error,
            line.linenum,
            format!("Missing value on line {} of {}.", line.linenum, filename),
        );
        return AaaResult::Error;
    };
    let l = line.linenum;

    if eq(name, "Encryption") {
        if eq(value, "never") {
            loc.encryption = Encryption::Never;
        } else if eq(value, "always") {
            diags.log(Severity::Error, l, format!(
                "Encryption value \"{value}\" on line {l} of {filename} is invalid in this context. Using \"required\" instead."));
            loc.encryption = Encryption::Required;
        } else if eq(value, "required") {
            loc.encryption = Encryption::Required;
        } else if eq(value, "ifrequested") {
            loc.encryption = Encryption::IfRequested;
        } else {
            diags.log(
                Severity::Error,
                l,
                format!("Unknown Encryption value {value} on line {l} of {filename}."),
            );
            return AaaResult::Error;
        }
    } else if eq(name, "Order") {
        if value.len() >= 4 && value.as_bytes()[..4].eq_ignore_ascii_case(b"deny") {
            loc.order = OrderType::Allow; // deny evaluated first → allow wins
        } else if value.len() >= 5 && value.as_bytes()[..5].eq_ignore_ascii_case(b"allow") {
            loc.order = OrderType::Deny; // allow evaluated first → deny wins
        } else {
            diags.log(
                Severity::Error,
                l,
                format!("Unknown Order value {value} on line {l} of {filename}."),
            );
            return AaaResult::Error;
        }
    } else if eq(name, "Allow") || eq(name, "Deny") {
        let is_allow = eq(name, "Allow");
        for token in HostMask::parse_list(value) {
            match token {
                Ok(m) => {
                    if is_allow {
                        loc.allow.push(m);
                    } else {
                        loc.deny.push(m);
                    }
                }
                Err(e) => {
                    diags.log(
                        Severity::Error,
                        l,
                        format!("{e} on line {l} of {filename}."),
                    );
                    return AaaResult::Error;
                }
            }
        }
    } else if eq(name, "AuthType") {
        if eq(value, "none") {
            loc.auth_type = AuthType::None;
            loc.auth_level = AuthLevel::Anon;
        } else {
            let t = if eq(value, "basic") {
                Some(AuthType::Basic)
            } else if eq(value, "bearer") {
                Some(AuthType::Bearer)
            } else if eq(value, "default") {
                Some(AuthType::Default)
            } else if eq(value, "negotiate") {
                Some(AuthType::Negotiate)
            } else {
                None
            };
            if let Some(t) = t {
                loc.auth_type = t;
                if loc.auth_level == AuthLevel::Anon {
                    loc.auth_level = AuthLevel::ValidUser;
                }
            } else {
                diags.log(
                    Severity::Warn,
                    l,
                    format!("Unknown authorization type {value} on line {l} of {filename}."),
                );
                return AaaResult::Error;
            }
        }
    } else if eq(name, "AuthClass") {
        if eq(value, "anonymous") {
            loc.auth_type = AuthType::None;
            loc.auth_level = AuthLevel::Anon;
            diags.log(
                Severity::Warn,
                l,
                format!("\"AuthClass {value}\" is deprecated; consider removing it from line {l}."),
            );
        } else if eq(value, "user") {
            loc.auth_level = AuthLevel::ValidUser;
            diags.log(Severity::Warn, l, format!(
                "\"AuthClass {value}\" is deprecated; consider using \"Require valid-user\" on line {l} of {filename}."));
        } else if eq(value, "group") {
            loc.auth_level = AuthLevel::Group;
            diags.log(Severity::Warn, l, format!(
                "\"AuthClass {value}\" is deprecated; consider using \"Require user @groupname\" on line {l} of {filename}."));
        } else if eq(value, "system") {
            loc.auth_level = AuthLevel::Group;
            loc.add_name("@SYSTEM");
            diags.log(Severity::Warn, l, format!(
                "\"AuthClass {value}\" is deprecated; consider using \"Require user @SYSTEM\" on line {l} of {filename}."));
        } else {
            diags.log(
                Severity::Warn,
                l,
                format!("Unknown authorization class {value} on line {l} of {filename}."),
            );
            return AaaResult::Error;
        }
    } else if eq(name, "AuthGroupName") {
        loc.add_name(value);
        diags.log(Severity::Warn, l, format!(
            "\"AuthGroupName {value}\" directive is deprecated; consider using \"Require user @{value}\" on line {l} of {filename}."));
    } else if eq(name, "Require") {
        let mut words = split_require(value);
        let kind = if words.is_empty() {
            ""
        } else {
            words.remove(0)
        };
        if eq(kind, "valid-user") {
            if matches!(loc.auth_level, AuthLevel::Anon | AuthLevel::ValidUser) {
                loc.auth_level = AuthLevel::ValidUser;
            }
        } else if eq(kind, "user") {
            if words.is_empty() {
                diags.log(
                    Severity::Error,
                    l,
                    format!("Missing username for Require user on line {l} of {filename}."),
                );
                return AaaResult::Error;
            }
            if loc.auth_level == AuthLevel::Group {
                // Convert previously collected `Require group` names to `@group`
                // tokens before switching to `AuthLevel::User` so group names
                // never match usernames and user names never match groups.
                for existing in &mut loc.names {
                    if !existing.starts_with('@') {
                        existing.insert(0, '@');
                    }
                }
                loc.auth_level = AuthLevel::User;
            } else if matches!(loc.auth_level, AuthLevel::Anon | AuthLevel::ValidUser) {
                loc.auth_level = AuthLevel::User;
            }
            for w in words {
                loc.add_name(w);
            }
        } else if eq(kind, "group") {
            if words.is_empty() {
                diags.log(
                    Severity::Error,
                    l,
                    format!("Missing group name for Require group on line {l} of {filename}."),
                );
                return AaaResult::Error;
            }
            if matches!(loc.auth_level, AuthLevel::Anon | AuthLevel::ValidUser) {
                loc.auth_level = AuthLevel::Group;
                for w in words {
                    loc.add_name(w);
                }
            } else if loc.auth_level == AuthLevel::User {
                // Mixed `Require user ...` + `Require group ...`: prefix `@` so
                // `authz` checks group membership rather than username equality.
                for w in words {
                    if w.starts_with('@') {
                        loc.add_name(w);
                    } else {
                        loc.add_name(format!("@{w}"));
                    }
                }
            } else {
                for w in words {
                    loc.add_name(w);
                }
            }
        } else {
            diags.log(
                Severity::Warn,
                l,
                format!("Unknown Require type {kind} on line {l} of {filename}."),
            );
            return AaaResult::Error;
        }
    } else if eq(name, "Satisfy") {
        if eq(value, "all") {
            loc.satisfy = Satisfy::All;
        } else if eq(value, "any") {
            loc.satisfy = Satisfy::Any;
        } else {
            diags.log(
                Severity::Warn,
                l,
                format!("Unknown Satisfy value {value} on line {l} of {filename}."),
            );
            return AaaResult::Error;
        }
    } else {
        return AaaResult::Unknown;
    }
    AaaResult::Ok
}

/// Case-insensitive compare (matches `_cups_strcasecmp`).
fn eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Split a `Require` value into words honoring `'…'`/`"…"` quoting.
///
/// Upstream also supports `@AUTHKEY(name)` on macOS; we keep the token
/// verbatim so authz can decide.
fn split_require(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let q = bytes[i];
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != q {
                j += 1;
            }
            out.push(&value[start..j]);
            i = j + usize::from(j < bytes.len());
        } else {
            let start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            out.push(&value[start..i]);
        }
    }
    out
}

impl HostMask {
    /// Parse an `Allow`/`Deny` value list (`[from] host …`).
    ///
    /// Port of the `parse_aaa` allow/deny branch + `get_addr_and_mask`.
    pub fn parse_list(value: &str) -> impl Iterator<Item = Result<Self, String>> + '_ {
        let mut tokens: Vec<String> = value.split_whitespace().map(ToString::to_string).collect();
        // Strip leading "from".
        if tokens
            .first()
            .is_some_and(|t| t.eq_ignore_ascii_case("from"))
        {
            tokens.remove(0);
        }
        tokens.into_iter().map(|tok| Self::parse_one(&tok))
    }

    /// Parse one allow/deny address token.
    ///
    /// Forms (upstream `parse_aaa`):
    /// `all`, `none`, `*.domain.com`, `.domain.com`, `host.domain.com`,
    /// `nnn.*`, `nnn.nnn.*`, `nnn.nnn.nnn.*`, `a.b.c.d`, `a.b.c.d/mm`,
    /// `a.b.c.d/m.m.m.m`, `[v6]`, `v6/mask`, `@LOCAL`, `@IF(name)`.
    pub fn parse_one(tok: &str) -> Result<Self, String> {
        if tok.is_empty() {
            return Err("Empty address/mask value".to_string());
        }
        if tok.eq_ignore_ascii_case("all") {
            return Ok(Self::All);
        }
        if tok.eq_ignore_ascii_case("none") {
            return Ok(Self::None);
        }
        let first = tok.as_bytes()[0];
        if first == b'@' {
            return Ok(Self::Name(tok.to_string()));
        }
        if first == b'*' || first == b'.' {
            let name = tok.strip_prefix('*').unwrap_or(tok);
            return Ok(Self::Name(name.to_string()));
        }
        // IPv6 literals contain ':' (e.g. `::1`, `fe80::/10`, `[::1]/128`) and
        // IPv4 literals start with an ASCII digit.
        if first == b'[' || tok.contains(':') || first.is_ascii_digit() {
            return parse_ip_mask(tok);
        }
        Ok(Self::Name(tok.to_string()))
    }

    /// Does `addr` satisfy this mask? (Host side of `cupsdCheckAuth`.)
    ///
    /// - `All` matches every IPv4 and IPv6 address; `None` matches nothing.
    /// - `Ip` masks normalize IPv4-mapped IPv6 (`::ffff:a.b.c.d`) against IPv4 masks.
    /// - `@LOCAL` matches loopback plus all up local interface subnets (`getifaddrs`).
    /// - `@IF(name)` matches subnets of the named up local interface (`getifaddrs`).
    #[must_use]
    pub fn matches(&self, addr: &std::net::IpAddr) -> bool {
        match self {
            Self::All => true,
            Self::Ip { addr: net, mask } => ip_match(addr, net, mask),
            Self::Name(name) if name.starts_with('@') => {
                #[cfg(unix)]
                let ifaces = sys::local_interfaces();
                #[cfg(not(unix))]
                let ifaces: Vec<sys::LocalInterface> = Vec::new();
                self.matches_with_interfaces(addr, &ifaces)
            }
            Self::None | Self::Name(_) => false,
        }
    }

    /// Deterministic version of [`Self::matches`] accepting an explicit list
    /// of local network interfaces (used for testing `@LOCAL` and `@IF(name)`
    /// and for callers that cache `sys::local_interfaces()`).
    #[cfg(unix)]
    #[must_use]
    pub fn matches_with_interfaces(
        &self,
        addr: &std::net::IpAddr,
        ifaces: &[sys::LocalInterface],
    ) -> bool {
        match self {
            Self::All => true,
            Self::None => false,
            Self::Ip { addr: net, mask } => ip_match(addr, net, mask),
            Self::Name(name) => {
                if name.eq_ignore_ascii_case("@LOCAL") {
                    if is_loopback_normalized(addr) {
                        return true;
                    }
                    return ifaces
                        .iter()
                        .filter(|iface| iface.is_up)
                        .any(|iface| addr_in_interface_subnet(addr, iface));
                }
                if let Some(target_if) = extract_if_name(name) {
                    return ifaces
                        .iter()
                        .filter(|iface| iface.is_up && iface.name == target_if)
                        .any(|iface| addr_in_interface_subnet(addr, iface));
                }
                false
            }
        }
    }

    /// Does `hostname` satisfy this name mask (suffix match like cupsd)?
    ///
    /// Special `@LOCAL` / `@IF(...)` tokens never match literal hostnames.
    #[must_use]
    pub fn matches_name(&self, hostname: &str) -> bool {
        match self {
            Self::Name(pattern) => {
                if pattern.starts_with('@') || hostname.is_empty() {
                    return false;
                }
                if pattern.starts_with('.') {
                    hostname
                        .to_ascii_lowercase()
                        .ends_with(&pattern.to_ascii_lowercase())
                } else {
                    hostname.eq_ignore_ascii_case(pattern)
                }
            }
            Self::All | Self::None | Self::Ip { .. } => false,
        }
    }
}

/// Extract `name` from `@IF(name)` (case-insensitive `@IF(` prefix).
fn extract_if_name(token: &str) -> Option<&str> {
    if token.len() < 6 {
        return None;
    }
    if token.as_bytes()[..4].eq_ignore_ascii_case(b"@IF(") && token.ends_with(')') {
        let inner = &token[4..token.len() - 1];
        if !inner.is_empty() {
            return Some(inner);
        }
    }
    None
}

/// True for IPv4 loopback (`127.0.0.0/8`), IPv6 loopback (`::1`), or
/// IPv4-mapped loopback (`::ffff:127.0.0.0/104`).
fn is_loopback_normalized(addr: &std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Check if `addr` falls within `iface`'s `(addr, netmask)` subnet.
#[cfg(unix)]
fn addr_in_interface_subnet(addr: &std::net::IpAddr, iface: &sys::LocalInterface) -> bool {
    match (iface.addr, iface.netmask) {
        (std::net::IpAddr::V4(if_v4), Some(std::net::IpAddr::V4(mask_v4))) => {
            let m = mask_v4.octets();
            let mut n = if_v4.octets();
            for i in 0..4 {
                n[i] &= m[i];
            }
            ip_match(addr, &IpNet::V4(n), &IpNet::V4(m))
        }
        (std::net::IpAddr::V6(if_v6), Some(std::net::IpAddr::V6(mask_v6))) => {
            let m = mask_v6.octets();
            let mut n = if_v6.octets();
            for i in 0..16 {
                n[i] &= m[i];
            }
            ip_match(addr, &IpNet::V6(n), &IpNet::V6(m))
        }
        (std::net::IpAddr::V4(if_v4), None) => {
            ip_match(addr, &IpNet::V4(if_v4.octets()), &IpNet::V4([0xff; 4]))
        }
        (std::net::IpAddr::V6(if_v6), None) => {
            ip_match(addr, &IpNet::V6(if_v6.octets()), &IpNet::V6([0xff; 16]))
        }
        _ => false,
    }
}

/// Masked-compare an address against `net`/`mask` bytes, normalizing
/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) against IPv4 masks.
fn ip_match(addr: &std::net::IpAddr, net: &IpNet, mask: &IpNet) -> bool {
    match (addr, net, mask) {
        (std::net::IpAddr::V4(a), IpNet::V4(n), IpNet::V4(m)) => {
            let a = u32::from_be_bytes(a.octets());
            let n = u32::from_be_bytes(*n);
            let m = u32::from_be_bytes(*m);
            (a & m) == (n & m)
        }
        (std::net::IpAddr::V6(a6), IpNet::V4(n4), IpNet::V4(m4)) => {
            // Normalize dual-stack IPv4-mapped IPv6 (`::ffff:a.b.c.d`) against IPv4 masks.
            let Some(a4) = a6.to_ipv4_mapped() else {
                return false;
            };
            let a = u32::from_be_bytes(a4.octets());
            let n = u32::from_be_bytes(*n4);
            let m = u32::from_be_bytes(*m4);
            (a & m) == (n & m)
        }
        (std::net::IpAddr::V6(a), IpNet::V6(n), IpNet::V6(m)) => {
            let a = a.octets();
            for i in 0..16 {
                if (a[i] & m[i]) != (n[i] & m[i]) {
                    return false;
                }
            }
            true
        }
        (std::net::IpAddr::V4(a4), IpNet::V6(n6), IpNet::V6(m6)) => {
            // v4-in-v6: cupsd maps to ::ffff:a.b.c.d
            let a = a4.to_ipv6_mapped().octets();
            for i in 0..16 {
                if (a[i] & m6[i]) != (n6[i] & m6[i]) {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

/// `get_addr_and_mask()` — parse `nnn.*`, `a.b.c.d`, `a.b.c.d/nn`,
/// `a.b.c.d/m.m.m.m`, `[v6]`, `v6:…/nn` forms, masking host bits in `addr`.
fn parse_ip_mask(value: &str) -> Result<HostMask, String> {
    let (addr_part, mask_part) = match value.split_once('/') {
        Some((a, m)) => (a, Some(m)),
        None => (value, None),
    };

    // IPv6 literal in brackets or with colons.
    if addr_part.starts_with('[') || addr_part.contains(':') {
        let cleaned = addr_part.trim_start_matches('[').trim_end_matches(']');
        let v6: std::net::Ipv6Addr = cleaned
            .parse()
            .map_err(|_| format!("Bad netmask value {value}"))?;
        let mask_bytes = match mask_part {
            None => [0xffu8; 16],
            Some(m) => {
                if let Ok(bits) = m.parse::<u32>() {
                    if bits > 128 {
                        return Err(format!("Bad netmask value {value}"));
                    }
                    prefix_mask_v6(bits)
                } else {
                    let mv: std::net::Ipv6Addr = m
                        .parse()
                        .map_err(|_| format!("Bad netmask value {value}"))?;
                    mv.octets()
                }
            }
        };
        let mut addr_bytes = v6.octets();
        for i in 0..16 {
            addr_bytes[i] &= mask_bytes[i];
        }
        return Ok(HostMask::Ip {
            addr: IpNet::V6(addr_bytes),
            mask: IpNet::V6(mask_bytes),
        });
    }

    // IPv4 forms incl. `nnn.*` wildcards.
    let mut addr = [0u8; 4];
    let mut mask = [0xffu8; 4];
    let mut i = 0;
    for (idx, piece) in addr_part.split('.').enumerate() {
        if idx >= 4 {
            return Err(format!("Bad netmask value {value}"));
        }
        if piece == "*" {
            mask[idx] = 0;
        } else {
            addr[idx] = piece
                .parse::<u8>()
                .map_err(|_| format!("Bad netmask value {value}"))?;
        }
        i = idx + 1;
    }
    if i == 0 {
        return Err(format!("Bad netmask value {value}"));
    }

    // cupsd treats `nnn.*` as nnn.0.0.0/255.0.0.0 — i.e. wildcard pieces
    // zero the mask at that position (already done) and everything
    // after. Trailing omitted octets (e.g. `10.*`) stay 0/masked too.
    for m in mask.iter_mut().skip(i) {
        *m = 0;
    }

    if let Some(m) = mask_part {
        let m = m.trim();
        if let Ok(bits) = m.parse::<u32>() {
            if bits > 32 {
                return Err(format!("Bad netmask value {value}"));
            }
            mask = prefix_mask_v4(bits);
        } else if m.starts_with("0x") || m.starts_with("0X") {
            let raw = u32::from_str_radix(&m[2..], 16)
                .map_err(|_| format!("Bad netmask value {value}"))?;
            mask = raw.to_be_bytes();
        } else {
            let parts: Vec<&str> = m.split('.').collect();
            if parts.len() != 4 {
                return Err(format!("Bad netmask value {value}"));
            }
            for (i, p) in parts.iter().enumerate() {
                mask[i] = p
                    .parse::<u8>()
                    .map_err(|_| format!("Bad netmask value {value}"))?;
            }
        }
    }

    // Mask out host bits so `192.168.1.5/24` normalizes to `192.168.1.0/24`.
    for k in 0..4 {
        addr[k] &= mask[k];
    }

    Ok(HostMask::Ip {
        addr: IpNet::V4(addr),
        mask: IpNet::V4(mask),
    })
}

fn prefix_mask_v4(bits: u32) -> [u8; 4] {
    if bits == 0 {
        return [0; 4];
    }
    (u32::MAX << (32 - bits)).to_be_bytes()
}

fn prefix_mask_v6(bits: u32) -> [u8; 16] {
    if bits == 0 {
        return [0u8; 16];
    }
    if bits >= 128 {
        return [0xffu8; 16];
    }
    (!0u128 << (128 - bits)).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct VecDiag(Vec<(Severity, usize, String)>);
    impl Diag for VecDiag {
        fn log(&mut self, severity: Severity, linenum: usize, msg: String) {
            self.0.push((severity, linenum, msg));
        }
    }

    fn line(name: &str, value: Option<&str>) -> ConfLine {
        ConfLine {
            linenum: 1,
            name: name.to_string(),
            value: value.map(ToString::to_string),
        }
    }

    #[test]
    fn allow_all_none_both_v4_and_v6() {
        let all = HostMask::parse_one("all").unwrap();
        assert_eq!(all, HostMask::All);
        assert!(all.matches(&"1.2.3.4".parse().unwrap()));
        assert!(all.matches(&"2001:db8::1".parse().unwrap()));
        assert!(all.matches(&"::1".parse().unwrap()));
        assert!(!all.matches_name("example.com"));

        let none = HostMask::parse_one("none").unwrap();
        assert_eq!(none, HostMask::None);
        assert!(!none.matches(&"1.2.3.4".parse().unwrap()));
        assert!(!none.matches(&"2001:db8::1".parse().unwrap()));
        assert!(!none.matches_name("example.com"));
    }

    #[test]
    fn parse_one_empty_returns_err_instead_of_panic() {
        assert!(HostMask::parse_one("").is_err());
    }

    #[test]
    fn ipv4_mapped_ipv6_and_host_bit_masking() {
        // Host bits in 192.168.1.55/24 must be masked to 192.168.1.0/24.
        let m = HostMask::parse_one("192.168.1.55/24").unwrap();
        assert!(m.matches(&"192.168.1.1".parse().unwrap()));
        assert!(m.matches(&"192.168.1.254".parse().unwrap()));
        assert!(!m.matches(&"192.168.2.1".parse().unwrap()));
        // Dual-stack IPv4-mapped IPv6 MUST match IPv4 mask!
        assert!(m.matches(&"::ffff:192.168.1.42".parse().unwrap()));
        assert!(!m.matches(&"::ffff:10.0.0.1".parse().unwrap()));
        // Pure IPv6 does not match IPv4 mask.
        assert!(!m.matches(&"2001:db8::1".parse().unwrap()));

        // Dotted and hex IPv4 masks + /0
        let dotted = HostMask::parse_one("172.16.5.9/255.255.0.0").unwrap();
        assert!(dotted.matches(&"172.16.99.1".parse().unwrap()));
        assert!(!dotted.matches(&"172.17.0.1".parse().unwrap()));

        let hex = HostMask::parse_one("10.1.2.3/0xffff0000").unwrap();
        assert!(hex.matches(&"10.1.99.99".parse().unwrap()));
        assert!(!hex.matches(&"10.2.0.1".parse().unwrap()));

        let zero4 = HostMask::parse_one("0.0.0.0/0").unwrap();
        assert!(zero4.matches(&"8.8.8.8".parse().unwrap()));
        assert!(zero4.matches(&"::ffff:8.8.8.8".parse().unwrap()));
        assert!(!zero4.matches(&"2001:db8::1".parse().unwrap()));

        // IPv6 host-bit masking, bare IPv6, bracketed IPv6, prefix 0/64/128, full mask
        let v6_zero = HostMask::parse_one("[::]/0").unwrap();
        assert!(v6_zero.matches(&"2001:db8::1".parse().unwrap()));
        assert!(v6_zero.matches(&"1.2.3.4".parse().unwrap()));

        let v6_64 = HostMask::parse_one("2001:db8:abcd::dead:beef/64").unwrap();
        assert!(v6_64.matches(&"2001:db8:abcd::1".parse().unwrap()));
        assert!(!v6_64.matches(&"2001:db8:abce::1".parse().unwrap()));

        let v6_bare = HostMask::parse_one("::1").unwrap();
        assert!(v6_bare.matches(&"::1".parse().unwrap()));
        assert!(!v6_bare.matches(&"::2".parse().unwrap()));

        let v6_ll = HostMask::parse_one("fe80::1234/10").unwrap();
        assert!(v6_ll.matches(&"fe80::abcd".parse().unwrap()));
        assert!(!v6_ll.matches(&"2001:db8::1".parse().unwrap()));

        let v6_fullmask = HostMask::parse_one("[2001:db8::1]/ffff:ffff::").unwrap();
        assert!(v6_fullmask.matches(&"2001:db8::99".parse().unwrap()));
        assert!(!v6_fullmask.matches(&"2001:db9::1".parse().unwrap()));

        let v6_128 = HostMask::parse_one("2001:db8::1/128").unwrap();
        assert!(v6_128.matches(&"2001:db8::1".parse().unwrap()));

        // v4-in-v6 explicit mapped prefix
        let v6_mapped = HostMask::parse_one("::ffff:10.0.0.0/104").unwrap();
        assert!(v6_mapped.matches(&"10.5.6.7".parse().unwrap()));
        assert!(!v6_mapped.matches(&"11.5.6.7".parse().unwrap()));

        // Invalid IP masks
        assert!(HostMask::parse_one("10.0.0.1/33").is_err());
        assert!(HostMask::parse_one("10.0.0.1/0xzzzz").is_err());
        assert!(HostMask::parse_one("10.0.0.1/255.255").is_err());
        assert!(HostMask::parse_one("10.0.0.1/255.255.255.999").is_err());
        assert!(HostMask::parse_one("1.2.3.4.5").is_err());
        assert!(HostMask::parse_one("999.0.0.1").is_err());
        assert!(HostMask::parse_one("[::1]/129").is_err());
        assert!(HostMask::parse_one("[::1]/badmask").is_err());
        assert!(HostMask::parse_one("[not-v6]").is_err());
    }

    #[test]
    fn wildcard_v4() {
        let m = HostMask::parse_one("192.168.*").unwrap();
        assert!(m.matches(&"192.168.7.9".parse().unwrap()));
        assert!(!m.matches(&"192.169.7.9".parse().unwrap()));
    }

    #[test]
    fn cidr() {
        let m = HostMask::parse_one("10.0.0.0/8").unwrap();
        assert!(m.matches(&"10.44.1.2".parse().unwrap()));
        assert!(!m.matches(&"11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn name_masks_local_and_interface_subnets() {
        let m = HostMask::parse_one("*.example.com").unwrap();
        assert!(m.matches_name("a.example.com"));
        assert!(!m.matches_name("example.com"));
        assert!(!m.matches(&"127.0.0.1".parse().unwrap()));

        let exact = HostMask::parse_one("printer.corp.local").unwrap();
        assert!(exact.matches_name("PRINTER.CORP.LOCAL"));
        assert!(!exact.matches_name("other.corp.local"));
        assert!(!exact.matches_name(""));

        // `@LOCAL` matches loopback + UP interface subnets, never literal hostname "@LOCAL".
        let local = HostMask::parse_one("@LOCAL").unwrap();
        assert!(!local.matches_name("@LOCAL"));
        assert!(local.matches(&"127.0.0.1".parse().unwrap()));
        assert!(local.matches(&"::1".parse().unwrap()));
        assert!(local.matches(&"::ffff:127.0.0.1".parse().unwrap()));
        // RFC 5737 TEST-NET-2 is not a local interface address.
        assert!(!local.matches(&"198.51.100.5".parse().unwrap()));

        let fake_ifaces = vec![
            sys::LocalInterface {
                name: "eth0".into(),
                addr: "192.0.2.10".parse().unwrap(),
                netmask: Some("255.255.255.0".parse().unwrap()),
                is_loopback: false,
                is_up: true,
            },
            sys::LocalInterface {
                name: "eth1".into(),
                addr: "198.51.100.10".parse().unwrap(),
                netmask: Some("255.255.255.0".parse().unwrap()),
                is_loopback: false,
                is_up: false, // down interface must NOT match!
            },
            sys::LocalInterface {
                name: "eth0".into(),
                addr: "fd00:1234::1".parse().unwrap(),
                netmask: Some("ffff:ffff::".parse().unwrap()),
                is_loopback: false,
                is_up: true,
            },
            sys::LocalInterface {
                name: "wg0".into(),
                addr: "10.200.0.1".parse().unwrap(),
                netmask: None,
                is_loopback: false,
                is_up: true,
            },
            sys::LocalInterface {
                name: "wg6".into(),
                addr: "fd99::1".parse().unwrap(),
                netmask: None,
                is_loopback: false,
                is_up: true,
            },
        ];

        assert!(local.matches_with_interfaces(&"192.0.2.55".parse().unwrap(), &fake_ifaces));
        assert!(local.matches_with_interfaces(&"::ffff:192.0.2.55".parse().unwrap(), &fake_ifaces));
        assert!(local.matches_with_interfaces(&"fd00:1234::99".parse().unwrap(), &fake_ifaces));
        assert!(local.matches_with_interfaces(&"10.200.0.1".parse().unwrap(), &fake_ifaces));
        assert!(local.matches_with_interfaces(&"fd99::1".parse().unwrap(), &fake_ifaces));
        assert!(!local.matches_with_interfaces(&"198.51.100.55".parse().unwrap(), &fake_ifaces));

        let if_eth0 = HostMask::parse_one("@IF(eth0)").unwrap();
        assert!(!if_eth0.matches_name("@IF(eth0)"));
        assert!(if_eth0.matches_with_interfaces(&"192.0.2.99".parse().unwrap(), &fake_ifaces));
        assert!(if_eth0.matches_with_interfaces(&"fd00:1234::2".parse().unwrap(), &fake_ifaces));
        assert!(!if_eth0.matches_with_interfaces(&"127.0.0.1".parse().unwrap(), &fake_ifaces));
        assert!(!if_eth0.matches_with_interfaces(&"10.200.0.1".parse().unwrap(), &fake_ifaces));

        // Down interface & malformed @IF() do not match.
        let if_down = HostMask::parse_one("@IF(eth1)").unwrap();
        assert!(!if_down.matches_with_interfaces(&"198.51.100.55".parse().unwrap(), &fake_ifaces));
        let if_empty = HostMask::parse_one("@IF()").unwrap();
        assert!(!if_empty.matches_with_interfaces(&"192.0.2.99".parse().unwrap(), &fake_ifaces));
        let if_bad = HostMask::parse_one("@UNKNOWN").unwrap();
        assert!(!if_bad.matches_with_interfaces(&"192.0.2.99".parse().unwrap(), &fake_ifaces));

        // Direct `matches_with_interfaces` on All/None/Ip
        assert!(HostMask::All.matches_with_interfaces(&"1.2.3.4".parse().unwrap(), &[]));
        assert!(!HostMask::None.matches_with_interfaces(&"1.2.3.4".parse().unwrap(), &[]));
        let ip_m = HostMask::parse_one("10.0.0.0/8").unwrap();
        assert!(ip_m.matches_with_interfaces(&"10.1.1.1".parse().unwrap(), &[]));
    }

    #[test]
    fn require_split_quoting() {
        let v = split_require("user alice 'bob smith' \"carol jones\" @lpadmin");
        assert_eq!(
            v,
            vec!["user", "alice", "bob smith", "carol jones", "@lpadmin"]
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn parse_aaa_all_directives_and_error_paths() {
        let mut loc = Location::new("/test");
        let mut d = VecDiag::default();

        // Missing value
        assert!(matches!(
            parse_aaa(&mut loc, &line("Order", None), &mut d, "f"),
            AaaResult::Error
        ));

        // Encryption variants + invalid
        assert!(matches!(
            parse_aaa(&mut loc, &line("Encryption", Some("never")), &mut d, "f"),
            AaaResult::Ok
        ));
        assert_eq!(loc.encryption, Encryption::Never);
        assert!(matches!(
            parse_aaa(&mut loc, &line("Encryption", Some("always")), &mut d, "f"),
            AaaResult::Ok
        ));
        assert_eq!(loc.encryption, Encryption::Required);
        assert!(matches!(
            parse_aaa(&mut loc, &line("Encryption", Some("required")), &mut d, "f"),
            AaaResult::Ok
        ));
        assert!(matches!(
            parse_aaa(
                &mut loc,
                &line("Encryption", Some("ifrequested")),
                &mut d,
                "f"
            ),
            AaaResult::Ok
        ));
        assert!(matches!(
            parse_aaa(&mut loc, &line("Encryption", Some("bogus")), &mut d, "f"),
            AaaResult::Error
        ));

        // Order variants + invalid
        assert!(matches!(
            parse_aaa(&mut loc, &line("Order", Some("deny,allow")), &mut d, "f"),
            AaaResult::Ok
        ));
        assert_eq!(loc.order, OrderType::Allow);
        assert!(matches!(
            parse_aaa(&mut loc, &line("Order", Some("allow,deny")), &mut d, "f"),
            AaaResult::Ok
        ));
        assert_eq!(loc.order, OrderType::Deny);
        assert!(matches!(
            parse_aaa(&mut loc, &line("Order", Some("weird")), &mut d, "f"),
            AaaResult::Error
        ));

        // Allow / Deny valid + invalid
        assert!(matches!(
            parse_aaa(
                &mut loc,
                &line("Allow", Some("from @LOCAL 10.0.0.0/8")),
                &mut d,
                "f"
            ),
            AaaResult::Ok
        ));
        assert!(matches!(
            parse_aaa(&mut loc, &line("Deny", Some("from all")), &mut d, "f"),
            AaaResult::Ok
        ));
        assert!(matches!(
            parse_aaa(
                &mut loc,
                &line("Allow", Some("from 10.0.0.1/99")),
                &mut d,
                "f"
            ),
            AaaResult::Error
        ));

        // AuthType variants + invalid
        for (val, expected) in [
            ("none", AuthType::None),
            ("basic", AuthType::Basic),
            ("bearer", AuthType::Bearer),
            ("default", AuthType::Default),
            ("negotiate", AuthType::Negotiate),
        ] {
            assert!(matches!(
                parse_aaa(&mut loc, &line("AuthType", Some(val)), &mut d, "f"),
                AaaResult::Ok
            ));
            assert_eq!(loc.auth_type, expected);
        }
        assert!(matches!(
            parse_aaa(&mut loc, &line("AuthType", Some("digest")), &mut d, "f"),
            AaaResult::Error
        ));

        // AuthClass + AuthGroupName deprecated variants + invalid
        for val in ["anonymous", "user", "group", "system"] {
            assert!(matches!(
                parse_aaa(&mut loc, &line("AuthClass", Some(val)), &mut d, "f"),
                AaaResult::Ok
            ));
        }
        assert!(matches!(
            parse_aaa(&mut loc, &line("AuthClass", Some("unknown")), &mut d, "f"),
            AaaResult::Error
        ));
        assert!(matches!(
            parse_aaa(&mut loc, &line("AuthGroupName", Some("staff")), &mut d, "f"),
            AaaResult::Ok
        ));

        // Require: valid-user, user, group, mixed user+group, missing args, unknown
        let mut l2 = Location::new("/r");
        assert!(matches!(
            parse_aaa(&mut l2, &line("Require", Some("valid-user")), &mut d, "f"),
            AaaResult::Ok
        ));
        assert_eq!(l2.auth_level, AuthLevel::ValidUser);
        assert!(matches!(
            parse_aaa(&mut l2, &line("Require", Some("user")), &mut d, "f"),
            AaaResult::Error
        ));
        assert!(matches!(
            parse_aaa(&mut l2, &line("Require", Some("group")), &mut d, "f"),
            AaaResult::Error
        ));
        assert!(matches!(
            parse_aaa(&mut l2, &line("Require", Some("user alice")), &mut d, "f"),
            AaaResult::Ok
        ));
        assert_eq!(l2.auth_level, AuthLevel::User);
        // Mixing Require group into Require user prefixes `@`
        assert!(matches!(
            parse_aaa(
                &mut l2,
                &line("Require", Some("group ops @admins")),
                &mut d,
                "f"
            ),
            AaaResult::Ok
        ));
        assert_eq!(l2.names, vec!["alice", "@ops", "@admins"]);

        let mut l3 = Location::new("/g");
        assert!(matches!(
            parse_aaa(&mut l3, &line("Require", Some("group wheel")), &mut d, "f"),
            AaaResult::Ok
        ));
        assert_eq!(l3.auth_level, AuthLevel::Group);
        assert!(matches!(
            parse_aaa(
                &mut l3,
                &line("Require", Some("group lpadmin")),
                &mut d,
                "f"
            ),
            AaaResult::Ok
        ));
        assert_eq!(l3.names, vec!["wheel", "lpadmin"]);
        // Mixing `Require user` after `Require group` converts existing groups to `@group`.
        assert!(matches!(
            parse_aaa(&mut l3, &line("Require", Some("user alice")), &mut d, "f"),
            AaaResult::Ok
        ));
        assert_eq!(l3.auth_level, AuthLevel::User);
        assert_eq!(l3.names, vec!["@wheel", "@lpadmin", "alice"]);
        assert!(matches!(
            parse_aaa(&mut l3, &line("Require", Some("bogus foo")), &mut d, "f"),
            AaaResult::Error
        ));

        // Satisfy variants + invalid + unknown directive
        assert!(matches!(
            parse_aaa(&mut l3, &line("Satisfy", Some("all")), &mut d, "f"),
            AaaResult::Ok
        ));
        assert_eq!(l3.satisfy, Satisfy::All);
        assert!(matches!(
            parse_aaa(&mut l3, &line("Satisfy", Some("any")), &mut d, "f"),
            AaaResult::Ok
        ));
        assert_eq!(l3.satisfy, Satisfy::Any);
        assert!(matches!(
            parse_aaa(&mut l3, &line("Satisfy", Some("maybe")), &mut d, "f"),
            AaaResult::Error
        ));
        assert!(matches!(
            parse_aaa(&mut l3, &line("NoSuchDir", Some("x")), &mut d, "f"),
            AaaResult::Unknown
        ));
    }

    #[test]
    fn order_and_if_multibyte_utf8_no_panic() {
        let mut d = VecDiag::default();
        let mut l = Location::new("/");
        // Multi-byte UTF-8 straddling byte index 4 and byte index 5 in Order directive.
        assert!(matches!(
            parse_aaa(&mut l, &line("Order", Some("abc\u{00e9}")), &mut d, "f"),
            AaaResult::Error
        ));
        assert!(matches!(
            parse_aaa(&mut l, &line("Order", Some("abcd\u{00e9}")), &mut d, "f"),
            AaaResult::Error
        ));
        // Multi-byte UTF-8 straddling byte index 4 in @IF(...) interface syntax.
        assert_eq!(extract_if_name("abc\u{00e9})"), None);
        assert_eq!(extract_if_name("\u{00e9}\u{00e9}\u{00e9})"), None);
        assert_eq!(extract_if_name("@IF(eth0)"), Some("eth0"));
        assert!(matches!(
            parse_aaa(
                &mut l,
                &line("Allow", Some("from abc\u{00e9})")),
                &mut d,
                "f"
            ),
            AaaResult::Ok
        ));
    }
}
