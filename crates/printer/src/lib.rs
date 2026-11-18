//! `printer` — the destination registry and `printers.conf`/`classes.conf`
//! persistence, ported from `scheduler/printers.c` and `scheduler/classes.c`.
//!
//! A "printer" and a "class" share one record upstream
//! (`cupsd_printer_t` + `CUPS_PTYPE_CLASS` bit + member array); this
//! crate keeps the same shape so the op layer can treat both uniformly.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use ipp_codec::{tags, Attribute, Value};
use thiserror::Error;

/// Default permissions for `printers.conf` and `classes.conf` (`0640`).
/// Never world-readable so `DeviceURI` credentials are protected.
pub const CONFIG_FILE_MODE: u32 = 0o640;

/// Maximum printer/class queue name length in bytes (CUPS `IPP_MAX_NAME - 1`).
pub const MAX_PRINTER_NAME_LEN: usize = 127;

/// Maximum `device-uri` length in bytes (CUPS `HTTP_MAX_URI - 1`).
pub const MAX_DEVICE_URI_LEN: usize = 1023;

/// Platform `O_NOFOLLOW` flag for `OpenOptionsExt::custom_flags`.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    )
))]
const O_NOFOLLOW: i32 = 0o100_000;

#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    ))
))]
const O_NOFOLLOW: i32 = 0o400_000;

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const O_NOFOLLOW: i32 = 0x0100;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static UUID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Validation errors for queue names and device URIs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("printer name must not be empty")]
    EmptyName,
    #[error("printer name exceeds {MAX_PRINTER_NAME_LEN} bytes ({0})")]
    NameTooLong(usize),
    #[error("printer name contains disallowed path traversal sequence")]
    NamePathTraversal,
    #[error("printer name contains disallowed character {0:?}")]
    InvalidNameChar(char),
    #[error("device URI must not be empty")]
    EmptyUri,
    #[error("device URI exceeds {MAX_DEVICE_URI_LEN} bytes ({0})")]
    UriTooLong(usize),
    #[error("device URI contains disallowed whitespace or control character {0:?}")]
    InvalidUriChar(char),
    #[error("device URI is missing a valid scheme")]
    InvalidScheme,
    #[error("device URI is missing a target host or path")]
    MissingTarget,
    #[error("device URI contains disallowed path traversal segment")]
    UriPathTraversal,
    #[error("file: device URIs are disabled by FileDevice policy")]
    FileDeviceDisallowed,
    #[error("file: device URI must specify an absolute path")]
    FileDeviceNotAbsolute,
}

/// Validate a CUPS printer or class queue name.
///
/// Rejects empty strings, lengths > 127 bytes, `.` / `..` traversal,
/// `/`, `\`, `#`, `?`, whitespace, and control characters.
///
/// # Errors
/// Returns a [`ValidationError`] describing why `name` is invalid.
pub fn validate_printer_name(name: &str) -> Result<(), ValidationError> {
    if name.is_empty() {
        return Err(ValidationError::EmptyName);
    }
    if name.len() > MAX_PRINTER_NAME_LEN {
        return Err(ValidationError::NameTooLong(name.len()));
    }
    if name == "." || name.contains("..") {
        return Err(ValidationError::NamePathTraversal);
    }
    for c in name.chars() {
        if matches!(c, '/' | '\\' | '#' | '?') || c.is_whitespace() || c.is_control() {
            return Err(ValidationError::InvalidNameChar(c));
        }
    }
    Ok(())
}

/// Validate a CUPS `device-uri` against injection, traversal, and `FileDevice` policy.
///
/// Set `allow_file_device` to `cfg.files.file_device` (`false` by default).
///
/// # Errors
/// Returns a [`ValidationError`] describing why `uri` is invalid or disallowed.
pub fn validate_device_uri(uri: &str, allow_file_device: bool) -> Result<(), ValidationError> {
    if uri.is_empty() {
        return Err(ValidationError::EmptyUri);
    }
    if uri.len() > MAX_DEVICE_URI_LEN {
        return Err(ValidationError::UriTooLong(uri.len()));
    }
    for c in uri.chars() {
        if c.is_whitespace() || c.is_control() {
            return Err(ValidationError::InvalidUriChar(c));
        }
    }
    let Some((scheme, rest)) = uri.split_once(':') else {
        return Err(ValidationError::InvalidScheme);
    };
    if !is_valid_scheme(scheme) {
        return Err(ValidationError::InvalidScheme);
    }
    if rest.is_empty() {
        return Err(ValidationError::MissingTarget);
    }

    let scheme_lower = scheme.to_ascii_lowercase();
    if scheme_lower == "file" {
        if !allow_file_device {
            return Err(ValidationError::FileDeviceDisallowed);
        }
        let path = rest
            .strip_prefix("//localhost")
            .or_else(|| rest.strip_prefix("//"))
            .unwrap_or(rest);
        if !path.starts_with('/') {
            return Err(ValidationError::FileDeviceNotAbsolute);
        }
        if has_traversal_segment(path) {
            return Err(ValidationError::UriPathTraversal);
        }
        return Ok(());
    }

    if matches!(
        scheme_lower.as_str(),
        "ipp" | "ipps" | "http" | "https" | "socket" | "lpd" | "smb" | "dnssd"
    ) {
        let Some(after_slashes) = rest.strip_prefix("//") else {
            return Err(ValidationError::MissingTarget);
        };
        let authority_end = after_slashes
            .find(['/', '?'])
            .unwrap_or(after_slashes.len());
        let authority = &after_slashes[..authority_end];
        let hostport = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
        if hostport.is_empty() || hostport.starts_with(':') {
            return Err(ValidationError::MissingTarget);
        }
        let path_part = &after_slashes[authority_end..];
        if has_traversal_segment(path_part.split('?').next().unwrap_or(path_part)) {
            return Err(ValidationError::UriPathTraversal);
        }
        return Ok(());
    }

    let path_only = rest.split('?').next().unwrap_or(rest);
    if path_only.is_empty() || path_only == "//" {
        return Err(ValidationError::MissingTarget);
    }
    if has_traversal_segment(path_only) {
        return Err(ValidationError::UriPathTraversal);
    }
    Ok(())
}

fn is_valid_scheme(scheme: &str) -> bool {
    let bytes = scheme.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 || !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    if scheme.contains("..") {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

fn has_traversal_segment(path: &str) -> bool {
    path.split(['/', '\\']).any(|seg| seg == "..")
}

/// Redact `userinfo@` credentials from a `device-uri` for safe logging.
#[must_use]
pub fn redact_device_uri(uri: &str) -> String {
    let Some(scheme_end) = uri.find("://") else {
        return uri.to_string();
    };
    let auth_start = scheme_end + 3;
    let rest = &uri[auth_start..];
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let Some(at) = authority.rfind('@') else {
        return uri.to_string();
    };
    let mut out = String::with_capacity(uri.len());
    out.push_str(&uri[..auth_start]);
    out.push_str("***@");
    out.push_str(&rest[at + 1..]);
    out
}

/// IPP `printer-state` enum values.
pub mod pstate {
    /// Idle.
    pub const IDLE: i32 = 3;
    /// Processing a job.
    pub const PROCESSING: i32 = 4;
    /// Stopped (paused).
    pub const STOPPED: i32 = 5;
}

/// `printer-type` bitfield (upstream `cups_ptype_t`).
pub mod ptype {
    /// Local destination.
    pub const LOCAL: i32 = 0x0000_0000;
    /// Implicit class.
    pub const IMPLICIT: i32 = 0x0001_0000;
    /// Class.
    pub const CLASS: i32 = 0x0000_0001;
    /// Remote queue.
    pub const REMOTE: i32 = 0x0000_0002;
    /// Default destination (computed at emit, not stored).
    pub const DEFAULT: i32 = 0x0002_0000;
    /// Not accepting jobs (computed).
    pub const REJECTING: i32 = 0x0008_0000;
    /// Not shared (computed).
    pub const NOT_SHARED: i32 = 0x0020_0000;
    /// Temporary queue.
    pub const TEMPORARY: i32 = 0x1000_0000;
    /// Delete pending (internal).
    pub const DELETE: i32 = 0x0010_0000;
    /// B&W capable.
    pub const BW: i32 = 0x0000_0004;
    /// Color.
    pub const COLOR: i32 = 0x0000_0008;
    /// Duplex.
    pub const DUPLEX: i32 = 0x0000_0010;
    /// Copies.
    pub const COPIES: i32 = 0x0000_0040;
    /// Collate.
    pub const COLLATE: i32 = 0x0000_0080;
    /// Staple.
    pub const STAPLE: i32 = 0x0000_0020;
    /// Punch.
    pub const PUNCH: i32 = 0x0000_0100;
    /// Cover.
    pub const COVER: i32 = 0x0000_0200;
    /// Bind.
    pub const BIND: i32 = 0x0000_0400;
    /// Sort.
    pub const SORT: i32 = 0x0000_0800;
    /// Small media.
    pub const SMALL: i32 = 0x0000_1000;
    /// Medium media.
    pub const MEDIUM: i32 = 0x0000_2000;
    /// Large media.
    pub const LARGE: i32 = 0x0000_4000;
    /// Variable-size media.
    pub const VARIABLE: i32 = 0x0000_8000;
    /// Fax.
    pub const FAX: i32 = 0x0004_0000;
    /// Discovered (network browse) queue.
    pub const DISCOVERED: i32 = 0x0100_0000;
    /// Scanner.
    pub const SCANNER: i32 = 0x0200_0000;
    /// MFP.
    pub const MFP: i32 = 0x0400_0000;
    /// 3D printer.
    pub const PRINT3D: i32 = 0x0400_0000;
}

/// One destination (printer or class).
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // flat PTYPE flag surface mirrors upstream
pub struct Printer {
    /// Queue name (sans `ipp://host/printers/`).
    pub name: String,
    /// `printer-id` (stable 1-based; assigned on first save).
    pub printer_id: i32,
    /// `printer-uuid` (`urn:uuid:…`).
    pub uuid: String,
    /// `printer-info` (description).
    pub info: Option<String>,
    /// `printer-location`.
    pub location: Option<String>,
    /// `printer-geo-location` (geo: URI).
    pub geo_location: Option<String>,
    /// `printer-make-and-model`.
    pub make_model: Option<String>,
    /// `printer-organization`.
    pub organization: Option<String>,
    /// `printer-organizational-unit`.
    pub organizational_unit: Option<String>,
    /// `device-uri` — backend target.
    pub device_uri: String,
    /// `PortMonitor` directive.
    pub port_monitor: Option<String>,
    /// IPP `printer-state` (3/4/5).
    pub state: i32,
    /// `printer-state-message`.
    pub state_message: String,
    /// `printer-state-change-time` (epoch).
    pub state_time: i64,
    /// `printer-config-change-time` (epoch).
    pub config_time: i64,
    /// `printer-state-reasons` keywords.
    pub reasons: Vec<String>,
    /// `printer-type` bitmask.
    pub ptype: i32,
    /// `printer-is-accepting-jobs`.
    pub accepting: bool,
    /// `printer-is-shared` (browse/publish).
    pub shared: bool,
    /// Temporary queue (auto-created by driverless discovery).
    pub temporary: bool,
    /// `job-sheets` (start, end banner names).
    pub job_sheets: (String, String),
    /// `QuotaPeriod`.
    pub quota_period: i32,
    /// `PageLimit`.
    pub page_limit: i32,
    /// `KLimit` (kbytes).
    pub k_limit: i32,
    /// `AllowUser`/`DenyUser` names (`deny_users` picks semantics).
    pub users: Vec<String>,
    /// `true` when `users` are a deny list.
    pub deny_users: bool,
    /// `printer-op-policy` name.
    pub op_policy: Option<String>,
    /// `printer-error-policy` name.
    pub error_policy: Option<String>,
    /// `Option name value` job-default options.
    pub options: Vec<(String, String)>,
    /// `auth-info-required` (up to 3 keywords).
    pub auth_info_required: Vec<String>,
    /// `printer-alert` octet string.
    pub alert: Option<String>,
    /// `printer-alert-description`.
    pub alert_description: Option<String>,
    /// Marker attributes (supplies): name→values stored verbatim.
    pub marker_colors: Vec<String>,
    /// `marker-levels`.
    pub marker_levels: Vec<i32>,
    /// `marker-low-levels`.
    pub marker_low_levels: Vec<i32>,
    /// `marker-high-levels`.
    pub marker_high_levels: Vec<i32>,
    /// `marker-message`.
    pub marker_message: String,
    /// `marker-names`.
    pub marker_names: Vec<String>,
    /// `marker-types`.
    pub marker_types: Vec<String>,
    /// `marker-change-time` (epoch).
    pub marker_time: i64,
    /// `printer-dns-sd-name` (DNS-SD registration).
    pub reg_name: Option<String>,
    /// Class members (printer names); empty for real printers.
    pub members: Vec<String>,
}

impl Printer {
    /// Bare new queue — `accepting`, `idle`, unshared, `local` type.
    #[must_use]
    pub fn new(name: impl Into<String>, device_uri: impl Into<String>) -> Self {
        let name = name.into();
        let t = now();
        Self {
            uuid: format!("urn:uuid:{}", uuid_v4()),
            name,
            printer_id: 0,
            info: None,
            location: None,
            geo_location: None,
            make_model: None,
            organization: None,
            organizational_unit: None,
            device_uri: device_uri.into(),
            port_monitor: None,
            state: pstate::IDLE,
            state_message: String::new(),
            state_time: t,
            config_time: t,
            reasons: Vec::new(),
            ptype: ptype::LOCAL | ptype::BW,
            accepting: true,
            shared: false,
            temporary: false,
            job_sheets: ("none".into(), "none".into()),
            quota_period: 0,
            page_limit: 0,
            k_limit: 0,
            users: Vec::new(),
            deny_users: false,
            op_policy: None,
            error_policy: None,
            options: Vec::new(),
            auth_info_required: Vec::new(),
            alert: None,
            alert_description: None,
            marker_colors: Vec::new(),
            marker_levels: Vec::new(),
            marker_low_levels: Vec::new(),
            marker_high_levels: Vec::new(),
            marker_message: String::new(),
            marker_names: Vec::new(),
            marker_types: Vec::new(),
            marker_time: 0,
            reg_name: None,
            members: Vec::new(),
        }
    }

    /// Bare new printer class (`CUPS_PTYPE_CLASS`).
    #[must_use]
    pub fn new_class(name: impl Into<String>) -> Self {
        let mut p = Self::new(name, "");
        p.ptype = ptype::LOCAL | ptype::CLASS;
        p
    }

    /// Add a member printer name to a class (deduplicated).
    pub fn add_member(&mut self, member: impl Into<String>) {
        let m = member.into();
        if !m.is_empty() && !self.members.iter().any(|x| x == &m) {
            self.members.push(m);
        }
    }

    /// Remove a member printer name from a class; returns `true` if removed.
    pub fn remove_member(&mut self, member: &str) -> bool {
        let before = self.members.len();
        self.members.retain(|x| x != member);
        self.members.len() != before
    }

    /// `true` for classes (`CUPS_PTYPE_CLASS` bit).
    #[must_use]
    pub fn is_class(&self) -> bool {
        self.ptype & ptype::CLASS != 0
    }

    /// Whether `user` may submit — `AllowUser`/`DenyUser` semantics
    /// (upstream `user_allowed()`): empty list = everyone allowed;
    /// otherwise allow-list wins, deny-list blocks.
    #[must_use]
    pub fn user_allowed(&self, username: &str) -> bool {
        if self.users.is_empty() {
            return true;
        }
        let listed = self
            .users
            .iter()
            .any(|u| u.eq_ignore_ascii_case(username) || u == "@ALL");
        if self.deny_users {
            !listed
        } else {
            listed
        }
    }

    /// Effective `printer-type` at emit time (adds the dynamic bits).
    #[must_use]
    pub fn effective_ptype(&self, is_default: bool) -> i32 {
        let mut t = self.ptype;
        if is_default {
            t |= ptype::DEFAULT;
        }
        if !self.accepting {
            t |= ptype::REJECTING;
        }
        if !self.shared {
            t |= ptype::NOT_SHARED;
        }
        t
    }
}

/// The full registry — sorted by name upstream (`cupsArray` sorted by
/// name), so `BTreeMap` gives the same iteration order for
/// `CUPS-Get-Printers`.
#[derive(Debug, Default)]
pub struct Registry {
    /// Destinations by name (both printers and classes).
    pub printers: BTreeMap<String, Printer>,
    /// Default queue name (`<DefaultPrinter>` or `<DefaultClass>`).
    pub default: Option<String>,
    /// `NextPrinterId` counter.
    pub next_printer_id: i32,
    /// Next `job-id` counter (from `classes.conf`/cupsd state; kept
    /// here until the `job` crate owns it).
    pub next_job_id: i32,
}

impl Registry {
    /// Look up a destination by name or URI path (`/printers/x`,
    /// `/classes/x`, bare `x`, or any path ending in `/printers/x` — the
    /// resource segment can follow an authority or socket-path prefix).
    #[must_use]
    pub fn find(&self, name_or_path: &str) -> Option<&Printer> {
        let mut name = name_or_path;
        for seg in ["/printers/", "/classes/"] {
            if let Some(i) = name_or_path.rfind(seg) {
                name = &name_or_path[i + seg.len()..];
                break;
            }
        }
        let name = name.split('?').next().unwrap_or(name);
        self.printers.get(name)
    }

    /// Mutable lookup by exact destination name.
    pub fn find_mut(&mut self, name: &str) -> Option<&mut Printer> {
        self.printers.get_mut(name)
    }

    /// The default destination, if any.
    #[must_use]
    pub fn default_printer(&self) -> Option<&Printer> {
        self.default.as_deref().and_then(|n| self.printers.get(n))
    }

    /// Iterate all registered classes.
    pub fn classes(&self) -> impl Iterator<Item = &Printer> {
        self.printers.values().filter(|p| p.is_class())
    }

    /// Resolve a class destination to an accepting, non-stopped concrete
    /// member printer (preferring `IDLE` over `PROCESSING`). Guards against
    /// circular class references.
    #[must_use]
    pub fn resolve_class_member(&self, class_name: &str) -> Option<&Printer> {
        let mut visited = HashSet::new();
        let mut candidates = Vec::new();
        self.collect_class_members(class_name, &mut visited, &mut candidates);
        candidates
            .iter()
            .copied()
            .find(|p| p.accepting && p.state == pstate::IDLE)
            .or_else(|| {
                candidates
                    .into_iter()
                    .find(|p| p.accepting && p.state != pstate::STOPPED)
            })
    }

    fn collect_class_members<'a>(
        &'a self,
        dest: &str,
        visited: &mut HashSet<String>,
        out: &mut Vec<&'a Printer>,
    ) {
        if !visited.insert(dest.to_string()) {
            return;
        }
        let Some(p) = self.printers.get(dest) else {
            return;
        };
        if p.is_class() {
            if !p.accepting || p.state == pstate::STOPPED {
                return;
            }
            for member in &p.members {
                self.collect_class_members(member, visited, out);
            }
        } else {
            out.push(p);
        }
    }

    /// `cupsdValidateDest()` — resolve a `printer-uri`/`job-uri` to the
    /// destination. Accepts `ipp(s)://host[:port]/printers|classes/NAME`
    /// and bare `/printers/NAME` paths.
    #[must_use]
    pub fn validate_dest<'a>(&'a self, uri: &str) -> Option<(&'a Printer, bool)> {
        let path = if let Some(rest) = uri
            .strip_prefix("ipp://")
            .or_else(|| uri.strip_prefix("ipps://"))
            .or_else(|| uri.strip_prefix("http://"))
            .or_else(|| uri.strip_prefix("https://"))
        {
            &rest[rest.find('/')?..]
        } else if uri.starts_with('/') {
            uri
        } else {
            return None;
        };
        let p = self.find(path)?;
        Some((p, p.is_class()))
    }

    /// Insert/replace a printer or class; first insertion wins `printer_id`.
    pub fn add(&mut self, mut p: Printer) {
        if p.printer_id <= 0 {
            if self.next_printer_id <= 0 {
                self.next_printer_id = 1;
            }
            p.printer_id = self.next_printer_id;
            self.next_printer_id += 1;
        } else if p.printer_id >= self.next_printer_id {
            self.next_printer_id = p.printer_id + 1;
        }
        self.printers.insert(p.name.clone(), p);
    }

    /// Remove a printer or class by name and prune it from any class member
    /// lists and `default`.
    pub fn remove(&mut self, name: &str) -> Option<Printer> {
        let removed = self.printers.remove(name);
        if removed.is_some() {
            if self.default.as_deref() == Some(name) {
                self.default = None;
            }
            for p in self.printers.values_mut() {
                if p.is_class() {
                    p.remove_member(name);
                }
            }
        }
        removed
    }

    /// Load `printers.conf` (and `classes.conf` — same block format).
    /// `<DefaultPrinter>` / `<DefaultClass>` sets `default`. Tolerates the
    /// upstream "directives outside a block are ignored" behavior.
    pub fn load_printers_conf<R: io::BufRead>(&mut self, r: R) -> Vec<String> {
        self.load_conf_inner(r, "printers.conf")
    }

    /// Load `classes.conf` (`<Class>` / `<DefaultClass>` + `Printer <member>`).
    pub fn load_classes_conf<R: io::BufRead>(&mut self, r: R) -> Vec<String> {
        self.load_conf_inner(r, "classes.conf")
    }

    fn load_conf_inner<R: io::BufRead>(&mut self, r: R, filename: &str) -> Vec<String> {
        let mut errors = Vec::new();
        let mut cur: Option<(Printer, bool)> = None;
        let mut is_default_block = false;

        for line in cups_config::conf_lines(r).map_while(Result::ok) {
            let name = line.name.as_str();
            let val = line.value.as_deref().unwrap_or("");

            if name.eq_ignore_ascii_case("NextPrinterId") {
                if let Ok(n) = val.parse::<i32>() {
                    self.next_printer_id = self.next_printer_id.max(n.max(1));
                }
            } else if name.eq_ignore_ascii_case("NextJobId") {
                if let Ok(n) = val.parse::<i32>() {
                    self.next_job_id = self.next_job_id.max(n.max(1));
                }
            } else if name.eq_ignore_ascii_case("<DefaultPrinter")
                || name.eq_ignore_ascii_case("<Printer")
                || name.eq_ignore_ascii_case("<Class")
                || name.eq_ignore_ascii_case("<DefaultClass")
            {
                if cur.is_none() && !val.is_empty() {
                    let is_class = name.eq_ignore_ascii_case("<Class")
                        || name.eq_ignore_ascii_case("<DefaultClass");
                    let mut p = if is_class {
                        Printer::new_class(val)
                    } else {
                        Printer::new(val, "")
                    };
                    p.accepting = true;
                    p.state = pstate::IDLE;
                    is_default_block = name.eq_ignore_ascii_case("<DefaultPrinter")
                        || name.eq_ignore_ascii_case("<DefaultClass");
                    cur = Some((p, is_class));
                } else {
                    errors.push(format!(
                        "Syntax error on line {} of {filename}.",
                        line.linenum
                    ));
                }
            } else if name.starts_with("</") {
                if let Some((mut p, is_class)) = cur.take() {
                    if is_class {
                        p.ptype |= ptype::CLASS;
                    }
                    if p.printer_id <= 0 {
                        if self.next_printer_id <= 0 {
                            self.next_printer_id = 1;
                        }
                        p.printer_id = self.next_printer_id;
                        self.next_printer_id += 1;
                    } else if p.printer_id >= self.next_printer_id {
                        self.next_printer_id = p.printer_id + 1;
                    }
                    if is_default_block {
                        self.default = Some(p.name.clone());
                    }
                    self.printers.insert(p.name.clone(), p);
                }
                is_default_block = false;
            } else if let Some((p, is_class)) = cur.as_mut() {
                apply_printer_directive(p, *is_class, name, val);
            }
        }
        errors
    }

    /// Serialize non-class, non-temporary printers to `printers.conf` —
    /// byte-compatible field order with `cupsdSaveAllPrinters`.
    #[must_use]
    pub fn save_printers_conf(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("# Printer configuration file for CUPS v2.5-rust\n");
        out.push_str("# Written by cupsd\n");
        out.push_str("# DO NOT EDIT THIS FILE WHEN CUPSD IS RUNNING\n\n");
        let _ = writeln!(out, "NextPrinterId {}", self.next_printer_id.max(1));

        for p in self.printers.values() {
            if p.is_class() || p.temporary {
                continue;
            }
            write_printer_block(&mut out, p, self.default.as_deref() == Some(&*p.name));
        }
        out.into_bytes()
    }

    /// Serialize classes to `classes.conf` (`cupsdSaveAllClasses`).
    #[must_use]
    pub fn save_classes_conf(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("# Class configuration file for CUPS v2.5-rust\n");
        out.push_str("# Written by cupsd\n");
        out.push_str("# DO NOT EDIT THIS FILE WHEN CUPSD IS RUNNING\n\n");

        for p in self.printers.values() {
            if !p.is_class() || p.temporary {
                continue;
            }
            write_printer_block(&mut out, p, self.default.as_deref() == Some(&*p.name));
        }
        out.into_bytes()
    }

    /// Parse `printers.conf` from a file path (with `O_NOFOLLOW`).
    ///
    /// # Errors
    /// Propagates I/O errors other than `NotFound`.
    pub fn load_printers_file(&mut self, path: &Path) -> io::Result<Vec<String>> {
        match open_read_nofollow(path) {
            Ok(f) => Ok(self.load_printers_conf(io::BufReader::new(f))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Parse `classes.conf` from a file path (with `O_NOFOLLOW`).
    ///
    /// # Errors
    /// Propagates I/O errors other than `NotFound`.
    pub fn load_classes_file(&mut self, path: &Path) -> io::Result<Vec<String>> {
        match open_read_nofollow(path) {
            Ok(f) => Ok(self.load_classes_conf(io::BufReader::new(f))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Atomically write `printers.conf` with default mode `0640`.
    ///
    /// # Errors
    /// Propagates filesystem creation, write, sync, or rename errors.
    pub fn save_printers_file(&self, path: &Path) -> io::Result<()> {
        self.save_printers_file_with_mode(path, CONFIG_FILE_MODE)
    }

    /// Atomically write `printers.conf` with an explicit permission mode
    /// (e.g., `ConfigFilePerm`).
    ///
    /// # Errors
    /// Propagates filesystem creation, write, sync, or rename errors.
    pub fn save_printers_file_with_mode(&self, path: &Path, mode: u32) -> io::Result<()> {
        write_atomic(path, &self.save_printers_conf(), mode)
    }

    /// Atomically write `classes.conf` with default mode `0640`.
    ///
    /// # Errors
    /// Propagates filesystem creation, write, sync, or rename errors.
    pub fn save_classes_file(&self, path: &Path) -> io::Result<()> {
        self.save_classes_file_with_mode(path, CONFIG_FILE_MODE)
    }

    /// Atomically write `classes.conf` with an explicit permission mode.
    ///
    /// # Errors
    /// Propagates filesystem creation, write, sync, or rename errors.
    pub fn save_classes_file_with_mode(&self, path: &Path, mode: u32) -> io::Result<()> {
        write_atomic(path, &self.save_classes_conf(), mode)
    }

    /// Atomically save both `printers.conf` and `classes.conf` into `server_root`.
    ///
    /// # Errors
    /// Propagates filesystem creation, write, sync, or rename errors.
    pub fn save_all(&self, server_root: &Path, mode: u32) -> io::Result<()> {
        self.save_printers_file_with_mode(&server_root.join("printers.conf"), mode)?;
        self.save_classes_file_with_mode(&server_root.join("classes.conf"), mode)
    }
}

/// One `<Printer name>` or `<Class name>` block in CUPS order.
#[allow(clippy::too_many_lines, clippy::format_push_string)]
fn write_printer_block(out: &mut String, p: &Printer, is_default: bool) {
    let (open, close) = match (p.is_class(), is_default) {
        (true, true) => ("<DefaultClass", "</DefaultClass>\n"),
        (true, false) => ("<Class", "</Class>\n"),
        (false, true) => ("<DefaultPrinter", "</DefaultPrinter>\n"),
        (false, false) => ("<Printer", "</Printer>\n"),
    };
    out.push_str(&format!("{open} {}>\n", esc(&p.name)));
    if p.printer_id != 0 {
        out.push_str(&format!("PrinterId {}\n", p.printer_id));
    }
    out.push_str(&format!("UUID {}\n", esc(&p.uuid)));
    if !p.auth_info_required.is_empty() {
        out.push_str(&format!(
            "AuthInfoRequired {}\n",
            esc(&p.auth_info_required.join(","))
        ));
    }
    if let Some(v) = &p.info {
        out.push_str(&format!("Info {}\n", esc(v)));
    }
    if let Some(v) = &p.location {
        out.push_str(&format!("Location {}\n", esc(v)));
    }
    if let Some(v) = &p.geo_location {
        out.push_str(&format!("GeoLocation {}\n", esc(v)));
    }
    if let Some(v) = &p.make_model {
        out.push_str(&format!("MakeModel {}\n", esc(v)));
    }
    if let Some(v) = &p.organization {
        out.push_str(&format!("Organization {}\n", esc(v)));
    }
    if let Some(v) = &p.organizational_unit {
        out.push_str(&format!("OrganizationalUnit {}\n", esc(v)));
    }
    if !p.is_class() {
        out.push_str(&format!("DeviceURI {}\n", esc(&p.device_uri)));
        if let Some(v) = &p.port_monitor {
            out.push_str(&format!("PortMonitor {}\n", esc(v)));
        }
    }
    if p.state == pstate::STOPPED {
        out.push_str("State Stopped\n");
        if !p.state_message.is_empty() {
            out.push_str(&format!("StateMessage {}\n", esc(&p.state_message)));
        }
    } else {
        out.push_str("State Idle\n");
    }
    out.push_str(&format!("StateTime {}\n", p.state_time));
    out.push_str(&format!("ConfigTime {}\n", p.config_time));
    for r in &p.reasons {
        if r != "connecting-to-device"
            && r != "cups-insecure-filter-warning"
            && r != "cups-missing-filter-warning"
        {
            out.push_str(&format!("Reason {}\n", esc(r)));
        }
    }
    out.push_str(&format!("Type {}\n", p.ptype));
    out.push_str(if p.accepting {
        "Accepting Yes\n"
    } else {
        "Accepting No\n"
    });
    out.push_str(if p.shared {
        "Shared Yes\n"
    } else {
        "Shared No\n"
    });
    out.push_str(&format!(
        "JobSheets {}\n",
        esc(&format!("{} {}", p.job_sheets.0, p.job_sheets.1))
    ));
    out.push_str(&format!("QuotaPeriod {}\n", p.quota_period));
    out.push_str(&format!("PageLimit {}\n", p.page_limit));
    out.push_str(&format!("KLimit {}\n", p.k_limit));
    for u in &p.users {
        out.push_str(&format!(
            "{} {}\n",
            if p.deny_users {
                "DenyUser"
            } else {
                "AllowUser"
            },
            esc(u)
        ));
    }
    if let Some(v) = &p.op_policy {
        out.push_str(&format!("OpPolicy {}\n", esc(v)));
    }
    if let Some(v) = &p.error_policy {
        out.push_str(&format!("ErrorPolicy {}\n", esc(v)));
    }
    if p.is_class() {
        for m in &p.members {
            out.push_str(&format!("Printer {}\n", esc(m)));
        }
    }
    for (n, v) in &p.options {
        out.push_str(&format!("Option {}\n", esc(&format!("{n} {v}"))));
    }
    if !p.marker_colors.is_empty() {
        out.push_str(&format!(
            "Attribute marker-colors {}\n",
            esc(&p.marker_colors.join(","))
        ));
    }
    if !p.marker_levels.is_empty() {
        out.push_str(&format!(
            "Attribute marker-levels {}\n",
            int_list(&p.marker_levels)
        ));
    }
    if !p.marker_low_levels.is_empty() {
        out.push_str(&format!(
            "Attribute marker-low-levels {}\n",
            int_list(&p.marker_low_levels)
        ));
    }
    if !p.marker_high_levels.is_empty() {
        out.push_str(&format!(
            "Attribute marker-high-levels {}\n",
            int_list(&p.marker_high_levels)
        ));
    }
    if !p.marker_message.is_empty() {
        out.push_str(&format!(
            "Attribute marker-message {}\n",
            esc(&p.marker_message)
        ));
    }
    if !p.marker_names.is_empty() {
        out.push_str(&format!(
            "Attribute marker-names {}\n",
            esc(&p.marker_names.join(","))
        ));
    }
    if !p.marker_types.is_empty() {
        out.push_str(&format!(
            "Attribute marker-types {}\n",
            esc(&p.marker_types.join(","))
        ));
    }
    if p.marker_time != 0 {
        out.push_str(&format!("Attribute marker-change-time {}\n", p.marker_time));
    }
    out.push_str(close);
    out.push('\n');
}

fn int_list(v: &[i32]) -> String {
    v.iter().map(i32::to_string).collect::<Vec<_>>().join(",")
}

/// `cupsFilePutConf` escaping: `\` → `\\`, `#` → `\#`, newline → `\n`,
/// CR → `\r` (no quoting ever).
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '#' => o.push_str("\\#"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            c => o.push(c),
        }
    }
    o
}

/// Apply one directive inside a `<Printer>` or `<Class>` block.
#[allow(clippy::ignored_unit_patterns, clippy::too_many_lines)]
fn apply_printer_directive(p: &mut Printer, is_class: bool, name: &str, val: &str) {
    let yes = |v: &str| {
        v.eq_ignore_ascii_case("yes")
            || v.eq_ignore_ascii_case("on")
            || v.eq_ignore_ascii_case("true")
    };
    match () {
        _ if name.eq_ignore_ascii_case("PrinterId") => {
            p.printer_id = val.parse().unwrap_or(0);
        }
        _ if name.eq_ignore_ascii_case("UUID") => p.uuid = val.to_string(),
        _ if name.eq_ignore_ascii_case("AuthInfoRequired") => {
            p.auth_info_required = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        _ if name.eq_ignore_ascii_case("Info") => p.info = Some(val.to_string()),
        _ if name.eq_ignore_ascii_case("Location") => p.location = Some(val.to_string()),
        _ if name.eq_ignore_ascii_case("GeoLocation") => {
            p.geo_location = Some(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("MakeModel") => {
            p.make_model = Some(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("Organization") => {
            p.organization = Some(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("OrganizationalUnit") => {
            p.organizational_unit = Some(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("DeviceURI") => p.device_uri = val.to_string(),
        _ if name.eq_ignore_ascii_case("PortMonitor") => {
            if val.eq_ignore_ascii_case("none") {
                p.port_monitor = None;
            } else {
                p.port_monitor = Some(val.to_string());
            }
        }
        _ if name.eq_ignore_ascii_case("Printer") => {
            p.add_member(val);
        }
        _ if name.eq_ignore_ascii_case("Option") => {
            if let Some((n, v)) = val.split_once(' ') {
                p.options.push((n.to_string(), v.to_string()));
            }
        }
        _ if name.eq_ignore_ascii_case("Reason") => {
            if !p.reasons.iter().any(|r| r == val) {
                p.reasons.push(val.to_string());
            }
        }
        _ if name.eq_ignore_ascii_case("State") => {
            if val.eq_ignore_ascii_case("idle") {
                p.state = pstate::IDLE;
            } else if val.eq_ignore_ascii_case("stopped") {
                p.state = pstate::STOPPED;
            }
        }
        _ if name.eq_ignore_ascii_case("StateMessage") => {
            p.state_message = val.to_string();
        }
        _ if name.eq_ignore_ascii_case("StateTime") => {
            p.state_time = val.parse().unwrap_or(0);
        }
        _ if name.eq_ignore_ascii_case("ConfigTime") => {
            p.config_time = val.parse().unwrap_or(0);
        }
        _ if name.eq_ignore_ascii_case("Accepting") => p.accepting = yes(val),
        _ if name.eq_ignore_ascii_case("Type") => {
            p.ptype = val.parse().unwrap_or(ptype::LOCAL);
            if is_class {
                p.ptype |= ptype::CLASS;
            }
        }
        _ if name.eq_ignore_ascii_case("Shared") => p.shared = yes(val),
        _ if name.eq_ignore_ascii_case("JobSheets") => {
            let mut it = val.splitn(2, ' ');
            let a = it.next().unwrap_or("none").to_string();
            let b = it.next().unwrap_or("none").to_string();
            p.job_sheets = (a, b);
        }
        _ if name.eq_ignore_ascii_case("AllowUser") => {
            p.deny_users = false;
            p.users.push(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("DenyUser") => {
            p.deny_users = true;
            p.users.push(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("QuotaPeriod") => {
            p.quota_period = val.parse().unwrap_or(0);
        }
        _ if name.eq_ignore_ascii_case("PageLimit") => {
            p.page_limit = val.parse().unwrap_or(0);
        }
        _ if name.eq_ignore_ascii_case("KLimit") => {
            p.k_limit = val.parse().unwrap_or(0);
        }
        _ if name.eq_ignore_ascii_case("OpPolicy") => {
            p.op_policy = Some(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("ErrorPolicy") => {
            p.error_policy = Some(val.to_string());
        }
        _ if name.eq_ignore_ascii_case("Attribute") => {
            if let Some((an, av)) = val.split_once(' ') {
                match an {
                    "marker-colors" => {
                        p.marker_colors = av.split(',').map(str::to_string).collect();
                    }
                    "marker-levels" => {
                        p.marker_levels = av.split(',').filter_map(|s| s.parse().ok()).collect();
                    }
                    "marker-low-levels" => {
                        p.marker_low_levels =
                            av.split(',').filter_map(|s| s.parse().ok()).collect();
                    }
                    "marker-high-levels" => {
                        p.marker_high_levels =
                            av.split(',').filter_map(|s| s.parse().ok()).collect();
                    }
                    "marker-message" => p.marker_message = av.to_string(),
                    "marker-names" => {
                        p.marker_names = av.split(',').map(str::to_string).collect();
                    }
                    "marker-types" => {
                        p.marker_types = av.split(',').map(str::to_string).collect();
                    }
                    "marker-change-time" => p.marker_time = av.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

// ---------- hardened atomic file I/O ----------

fn open_read_nofollow(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    opts.custom_flags(O_NOFOLLOW);
    opts.open(path)
}

/// Atomically write `data` to `path` via a unique temp file in the same
/// directory created with `O_CREAT | O_EXCL | O_NOFOLLOW` and `mode`,
/// then `fchmod`, `fsync`, `rename`, and best-effort parent-dir `fsync`.
///
/// # Errors
/// Propagates filesystem creation, write, permission, sync, or rename errors.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let base = path.file_name().and_then(|n| n.to_str()).unwrap_or("conf");
    let pid = std::process::id();

    let mut tmp_path = PathBuf::new();
    let mut file = None;
    for _ in 0..64 {
        let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{base}.tmp.{pid}.{seq}"));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(mode).custom_flags(O_NOFOLLOW);
        match opts.open(&candidate) {
            Ok(f) => {
                tmp_path = candidate;
                file = Some(f);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    let mut f =
        file.ok_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "tmp collision"))?;

    let write_res = (|| -> io::Result<()> {
        #[cfg(unix)]
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_res {
        drop(f);
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(f);

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Wall-clock epoch seconds.
#[must_use]
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// RFC 4122 version 4 UUID generated from OS CSPRNG (`/dev/urandom`).
#[must_use]
pub fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    let mut src = File::open("/dev/urandom").ok();
    fill_random_bytes(src.as_mut(), &mut bytes);
    format_uuid_v4(bytes)
}

fn fill_random_bytes<R: Read>(src: Option<&mut R>, out: &mut [u8; 16]) {
    if let Some(r) = src {
        if r.read_exact(out).is_ok() {
            return;
        }
    }
    let c = UUID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let pid = u64::from(std::process::id());
    let mut h1 = RandomState::new().build_hasher();
    h1.write_u64(c);
    h1.write_u128(nanos);
    h1.write_u64(pid);
    let a = h1.finish();
    let mut h2 = RandomState::new().build_hasher();
    h2.write_u64(a ^ 0x9e37_79b9_7f4a_7c15);
    h2.write_u64(c.wrapping_add(1));
    let b = h2.finish();
    out[..8].copy_from_slice(&a.to_le_bytes());
    out[8..].copy_from_slice(&b.to_le_bytes());
}

fn format_uuid_v4(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// Build the `printer-state-reasons` IPP attribute (keyword list, or
/// "none" when empty — upstream `add_printer_state_reasons`).
#[must_use]
pub fn state_reasons_attr(p: &Printer) -> Attribute {
    if p.reasons.is_empty() {
        Attribute::new(
            "printer-state-reasons",
            tags::KEYWORD,
            vec![Value::Keyword("none".into())],
        )
    } else {
        Attribute::new(
            "printer-state-reasons",
            tags::KEYWORD,
            p.reasons
                .iter()
                .map(|r| Value::Keyword(r.as_str().into()))
                .collect(),
        )
    }
}

/// Compose an IPP `dateTime` value from epoch seconds (UTC — upstream
/// uses `ippTimeToDate` which is local-time; UTC is the documented
/// deviation for v1, logged in deviations.md).
#[must_use]
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::similar_names
)] // bounded civil fields
pub fn ipp_datetime(epoch: i64) -> Value {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    Value::DateTime([
        (y >> 8) as u8,
        (y & 0xff) as u8,
        m as u8,
        d as u8,
        (secs / 3600) as u8,
        ((secs % 3600) / 60) as u8,
        (secs % 60) as u8,
        0,
        b'+',
        0,
        0,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "presswork-printer-test-{}-{}-{id}",
            std::process::id(),
            tag
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn uuid_v4_csprng_unique_within_same_second() {
        let mut set = HashSet::new();
        for _ in 0..256 {
            let u = uuid_v4();
            assert_eq!(u.len(), 36);
            let b = u.as_bytes();
            assert_eq!(b[14], b'4');
            assert!(matches!(b[19], b'8' | b'9' | b'a' | b'b'));
            assert!(set.insert(u), "UUID collision within same second");
        }
        // Test fallback path too.
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        fill_random_bytes::<io::Empty>(None, &mut a);
        let mut empty = io::empty();
        fill_random_bytes(Some(&mut empty), &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn validate_printer_name_rules() {
        for ok in [
            "laser",
            "HP_LaserJet-4000.local",
            "floor2-color",
            &"a".repeat(127),
        ] {
            assert_eq!(validate_printer_name(ok), Ok(()), "should accept {ok}");
        }
        assert_eq!(validate_printer_name(""), Err(ValidationError::EmptyName));
        assert_eq!(
            validate_printer_name(&"a".repeat(128)),
            Err(ValidationError::NameTooLong(128))
        );
        assert_eq!(
            validate_printer_name("."),
            Err(ValidationError::NamePathTraversal)
        );
        assert_eq!(
            validate_printer_name(".."),
            Err(ValidationError::NamePathTraversal)
        );
        assert_eq!(
            validate_printer_name("foo..bar"),
            Err(ValidationError::NamePathTraversal)
        );
        for bad in [
            "a/b", "a\\b", "a#b", "a?b", "a b", "a\tb", "a\nb", "a\rb", "a\x00b", "a\x1fb",
        ] {
            assert!(
                matches!(
                    validate_printer_name(bad),
                    Err(ValidationError::InvalidNameChar(_))
                ),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn validate_device_uri_rules_and_redaction() {
        for ok in [
            "ipp://printer.example.com:631/ipp/print",
            "ipps://user:secret@192.0.2.10/ipp/print",
            "socket://192.0.2.20:9100",
            "lpd://192.0.2.30/lp",
            "dnssd://HP%20Laser._ipp._tcp.local/",
            "usb://HP/LaserJet?serial=1234",
            "serial:/dev/ttyS0?baud=9600+bits=8",
            "parallel:/dev/lp0",
        ] {
            assert_eq!(validate_device_uri(ok, false), Ok(()), "should accept {ok}");
        }
        // file: blocked when FileDevice=No, allowed when FileDevice=Yes & absolute.
        assert_eq!(
            validate_device_uri("file:///dev/null", false),
            Err(ValidationError::FileDeviceDisallowed)
        );
        assert_eq!(validate_device_uri("file:///dev/null", true), Ok(()));
        assert_eq!(
            validate_device_uri("file://localhost/tmp/out", true),
            Ok(())
        );
        assert_eq!(
            validate_device_uri("file:relative/path", true),
            Err(ValidationError::FileDeviceNotAbsolute)
        );
        assert_eq!(
            validate_device_uri("file:///tmp/../etc/shadow", true),
            Err(ValidationError::UriPathTraversal)
        );

        assert_eq!(
            validate_device_uri("", false),
            Err(ValidationError::EmptyUri)
        );
        assert!(matches!(
            validate_device_uri(&format!("ipp://h/{}", "a".repeat(1024)), false),
            Err(ValidationError::UriTooLong(_))
        ));
        assert!(matches!(
            validate_device_uri("ipp://host/a\r\nb", false),
            Err(ValidationError::InvalidUriChar(_))
        ));
        assert!(matches!(
            validate_device_uri("ipp://host/a b", false),
            Err(ValidationError::InvalidUriChar(_))
        ));
        for bad_scheme in [
            "no-colon",
            "1bad://host",
            "/bin/sh:arg",
            "a..b://host",
            ":foo",
        ] {
            assert_eq!(
                validate_device_uri(bad_scheme, false),
                Err(ValidationError::InvalidScheme),
                "bad scheme {bad_scheme:?}"
            );
        }
        for missing in [
            "ipp:",
            "ipp://",
            "ipp:///path",
            "ipp://:631/p",
            "ipp:/no-slashes",
            "custom://",
        ] {
            assert_eq!(
                validate_device_uri(missing, false),
                Err(ValidationError::MissingTarget),
                "missing target {missing:?}"
            );
        }
        assert_eq!(
            validate_device_uri("ipp://host/../../admin", false),
            Err(ValidationError::UriPathTraversal)
        );
        assert_eq!(
            validate_device_uri("parallel:/dev/../etc/passwd", false),
            Err(ValidationError::UriPathTraversal)
        );

        assert_eq!(
            redact_device_uri("ipps://alice:s3cr3t@printer.local:631/ipp/print"),
            "ipps://***@printer.local:631/ipp/print"
        );
        assert_eq!(
            redact_device_uri("ipp://printer.local:631/ipp/print"),
            "ipp://printer.local:631/ipp/print"
        );
        assert_eq!(redact_device_uri("parallel:/dev/lp0"), "parallel:/dev/lp0");
    }

    fn sample_registry() -> Registry {
        let mut reg = Registry::default();

        let mut p1 = Printer::new("laser1", "ipps://u:pw@192.0.2.1/ipp/print");
        p1.info = Some("Main #1\\Room\nLine2".into());
        p1.location = Some("Floor 2".into());
        p1.geo_location = Some("geo:37.0,-122.0".into());
        p1.make_model = Some("Generic PDF".into());
        p1.organization = Some("Acme".into());
        p1.organizational_unit = Some("Eng".into());
        p1.port_monitor = Some("tbcp".into());
        p1.state = pstate::STOPPED;
        p1.state_message = "Paper jam".into();
        p1.reasons = vec!["media-empty".into(), "connecting-to-device".into()];
        p1.accepting = false;
        p1.shared = true;
        p1.job_sheets = ("classified".into(), "standard".into());
        p1.quota_period = 86400;
        p1.page_limit = 500;
        p1.k_limit = 10_000;
        p1.users = vec!["alice".into(), "bob".into()];
        p1.deny_users = false;
        p1.op_policy = Some("authenticated".into());
        p1.error_policy = Some("retry-job".into());
        p1.options = vec![("sides".into(), "two-sided-long-edge".into())];
        p1.auth_info_required = vec!["username".into(), "password".into()];
        p1.marker_colors = vec!["#000000".into(), "#00FFFF".into()];
        p1.marker_levels = vec![80, 45];
        p1.marker_low_levels = vec![10, 10];
        p1.marker_high_levels = vec![100, 100];
        p1.marker_message = "Low cyan".into();
        p1.marker_names = vec!["Black".into(), "Cyan".into()];
        p1.marker_types = vec!["toner".into(), "toner".into()];
        p1.marker_time = 1_700_000_000;
        reg.add(p1);

        let mut p2 = Printer::new("laser2", "socket://192.0.2.2:9100");
        p2.deny_users = true;
        p2.users = vec!["mallory".into()];
        reg.add(p2);

        let mut tmp_p = Printer::new("temp_q", "ipp://192.0.2.9/ipp");
        tmp_p.temporary = true;
        reg.add(tmp_p);

        let mut cls = Printer::new_class("office-pool");
        cls.info = Some("Office Pool".into());
        cls.add_member("laser1");
        cls.add_member("laser2");
        cls.add_member("laser1"); // duplicate ignored
        reg.add(cls);
        reg.default = Some("office-pool".into());
        reg
    }

    #[test]
    fn printers_and_classes_conf_roundtrip_and_atomic_save() {
        let dir = temp_dir("classes-roundtrip");
        let reg = sample_registry();

        // Verify printers.conf omits classes and temporary queues, classes.conf writes <DefaultClass> + Printer members.
        let pconf = String::from_utf8(reg.save_printers_conf()).unwrap();
        assert!(pconf.contains("<Printer laser1>"));
        assert!(pconf.contains("<Printer laser2>"));
        assert!(!pconf.contains("office-pool"));
        assert!(!pconf.contains("temp_q"));

        let cconf = String::from_utf8(reg.save_classes_conf()).unwrap();
        assert!(cconf.contains("<DefaultClass office-pool>"));
        assert!(cconf.contains("</DefaultClass>"));
        assert!(cconf.contains("Printer laser1\n"));
        assert!(cconf.contains("Printer laser2\n"));
        assert!(!cconf.contains("DeviceURI"));

        // Atomic save_all with mode 0640.
        reg.save_all(&dir, CONFIG_FILE_MODE).unwrap();
        #[cfg(unix)]
        {
            let pm = fs::metadata(dir.join("printers.conf"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let cm = fs::metadata(dir.join("classes.conf"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(pm, 0o640);
            assert_eq!(cm, 0o640);
        }

        // Reload into a fresh registry.
        let mut reg2 = Registry::default();
        assert_eq!(
            reg2.load_printers_file(&dir.join("printers.conf")).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            reg2.load_classes_file(&dir.join("classes.conf")).unwrap(),
            Vec::<String>::new()
        );
        // Missing file returns Ok(empty).
        assert_eq!(
            reg2.load_classes_file(&dir.join("missing.conf")).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            reg2.load_printers_file(&dir.join("missing.conf")).unwrap(),
            Vec::<String>::new()
        );

        let lp1 = reg2.find("laser1").unwrap();
        assert!(!lp1.is_class());
        assert_eq!(lp1.info.as_deref(), Some("Main #1\\Room\nLine2"));
        assert_eq!(lp1.location.as_deref(), Some("Floor 2"));
        assert_eq!(lp1.geo_location.as_deref(), Some("geo:37.0,-122.0"));
        assert_eq!(lp1.make_model.as_deref(), Some("Generic PDF"));
        assert_eq!(lp1.organization.as_deref(), Some("Acme"));
        assert_eq!(lp1.organizational_unit.as_deref(), Some("Eng"));
        assert_eq!(lp1.port_monitor.as_deref(), Some("tbcp"));
        assert_eq!(lp1.state, pstate::STOPPED);
        assert_eq!(lp1.state_message, "Paper jam");
        assert_eq!(lp1.reasons, vec!["media-empty".to_string()]);
        assert!(!lp1.accepting);
        assert!(lp1.shared);
        assert_eq!(lp1.job_sheets, ("classified".into(), "standard".into()));
        assert_eq!(lp1.quota_period, 86400);
        assert_eq!(lp1.page_limit, 500);
        assert_eq!(lp1.k_limit, 10_000);
        assert!(lp1.user_allowed("ALICE"));
        assert!(!lp1.user_allowed("eve"));
        assert_eq!(lp1.op_policy.as_deref(), Some("authenticated"));
        assert_eq!(lp1.error_policy.as_deref(), Some("retry-job"));
        assert_eq!(
            lp1.options,
            vec![("sides".into(), "two-sided-long-edge".into())]
        );
        assert_eq!(lp1.auth_info_required, vec!["username", "password"]);
        assert_eq!(lp1.marker_colors, vec!["#000000", "#00FFFF"]);
        assert_eq!(lp1.marker_levels, vec![80, 45]);
        assert_eq!(lp1.marker_low_levels, vec![10, 10]);
        assert_eq!(lp1.marker_high_levels, vec![100, 100]);
        assert_eq!(lp1.marker_message, "Low cyan");
        assert_eq!(lp1.marker_names, vec!["Black", "Cyan"]);
        assert_eq!(lp1.marker_types, vec!["toner", "toner"]);
        assert_eq!(lp1.marker_time, 1_700_000_000);

        let lp2 = reg2.find("/printers/laser2?foo=1").unwrap();
        assert!(!lp2.user_allowed("mallory"));
        assert!(lp2.user_allowed("alice"));

        let lcls = reg2.find("/classes/office-pool").unwrap();
        assert!(lcls.is_class());
        assert_eq!(lcls.members, vec!["laser1", "laser2"]);
        assert_eq!(reg2.default_printer().unwrap().name, "office-pool");
        assert_eq!(reg2.classes().count(), 1);

        // Class member resolution skips stopped/rejecting laser1 and picks idle laser2.
        assert_eq!(
            reg2.resolve_class_member("office-pool").unwrap().name,
            "laser2"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn class_routing_nested_cycles_and_states() {
        let mut reg = Registry::default();
        let mut p1 = Printer::new("p1", "socket://192.0.2.1:9100");
        p1.state = pstate::PROCESSING;
        let mut p2 = Printer::new("p2", "socket://192.0.2.2:9100");
        p2.state = pstate::IDLE;
        reg.add(p1);
        reg.add(p2);

        let mut c1 = Printer::new_class("c1");
        c1.add_member("p1");
        c1.add_member("c2");
        let mut c2 = Printer::new_class("c2");
        c2.add_member("c1"); // cycle!
        c2.add_member("p2");
        reg.add(c1);
        reg.add(c2);

        // Prefers IDLE p2 over PROCESSING p1 and doesn't infinite-loop on cycle.
        assert_eq!(reg.resolve_class_member("c1").unwrap().name, "p2");

        // Stop p2 -> falls back to PROCESSING p1.
        reg.find_mut("p2").unwrap().state = pstate::STOPPED;
        assert_eq!(reg.resolve_class_member("c1").unwrap().name, "p1");

        // Stop class c1 -> resolves to None.
        reg.find_mut("c1").unwrap().state = pstate::STOPPED;
        assert!(reg.resolve_class_member("c1").is_none());

        // Removing p1 prunes it from class members and clears default if matching.
        reg.default = Some("p1".into());
        assert!(reg.remove("p1").is_some());
        assert!(reg.default.is_none());
        assert!(!reg.find("c1").unwrap().members.iter().any(|m| m == "p1"));
    }

    #[test]
    fn validate_dest_effective_ptype_state_reasons_and_datetime() {
        let mut reg = Registry::default();
        let mut p = Printer::new("dp", "ipp://host/ipp");
        p.accepting = false;
        p.shared = false;
        reg.add(p);
        reg.default = Some("dp".into());

        let (found, is_cls) = reg
            .validate_dest("ipp://localhost:631/printers/dp")
            .unwrap();
        assert!(!is_cls);
        assert_eq!(found.name, "dp");
        assert!(reg.validate_dest("ipps://localhost/printers/dp").is_some());
        assert!(reg.validate_dest("/printers/dp").is_some());
        assert!(reg.validate_dest("ftp://localhost/printers/dp").is_none());

        let eff = found.effective_ptype(true);
        assert_ne!(eff & ptype::DEFAULT, 0);
        assert_ne!(eff & ptype::REJECTING, 0);
        assert_ne!(eff & ptype::NOT_SHARED, 0);

        // Empty reasons -> "none".
        let attr_none = state_reasons_attr(found);
        assert_eq!(attr_none.values, vec![Value::Keyword("none".into())]);
        let mut p2 = found.clone();
        p2.reasons = vec!["toner-low".into()];
        let attr_some = state_reasons_attr(&p2);
        assert_eq!(attr_some.values, vec![Value::Keyword("toner-low".into())]);

        // Empty users list allows everyone.
        assert!(found.user_allowed("anyone"));

        // IPP dateTime for 2024-01-15T12:34:56Z (1705322096).
        assert_eq!(
            ipp_datetime(1_705_322_096),
            Value::DateTime([7, 232, 1, 15, 12, 34, 56, 0, b'+', 0, 0])
        );
        // Also test month >= March (2024-07-04T00:00:00Z = 1720051200).
        assert_eq!(
            ipp_datetime(1_720_051_200),
            Value::DateTime([7, 232, 7, 4, 0, 0, 0, 0, b'+', 0, 0])
        );
    }

    #[test]
    fn parser_edge_cases_and_default_printer_save() {
        let conf = "\
NextPrinterId 5
NextJobId 12
<DefaultPrinter dp1>
DeviceURI socket://192.0.2.1:9100
PortMonitor none
State Idle
Type 4
Attribute unknown-attr foo
UnknownDirective bar
<Printer nested_err>
</DefaultPrinter>
<class pool1>
Type 0
Printer dp1
</class>
";
        let mut reg = Registry::default();
        let errs = reg.load_printers_conf(io::Cursor::new(conf.as_bytes()));
        assert_eq!(errs.len(), 1);
        assert_eq!(reg.next_job_id, 12);
        assert_eq!(reg.default.as_deref(), Some("dp1"));
        assert!(reg.find("dp1").unwrap().port_monitor.is_none());
        let cls = reg.find("pool1").unwrap();
        // Type 0 inside <class> still preserves CLASS bit!
        assert!(cls.is_class());
        assert_eq!(cls.members, vec!["dp1"]);

        let out_p = String::from_utf8(reg.save_printers_conf()).unwrap();
        assert!(out_p.contains("<DefaultPrinter dp1>"));
        let out_c = String::from_utf8(reg.save_classes_conf()).unwrap();
        assert!(out_c.contains("<Class pool1>"));

        let dir = temp_dir("convenience-save");
        reg.save_printers_file(&dir.join("printers.conf")).unwrap();
        reg.save_classes_file(&dir.join("classes.conf")).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn nofollow_rejects_symlinks_on_conf_load() {
        use std::os::unix::fs::symlink;
        let dir = temp_dir("symlink");
        let real = dir.join("real.conf");
        fs::write(&real, b"NextPrinterId 1\n").unwrap();
        let link = dir.join("printers.conf");
        symlink(&real, &link).unwrap();
        let mut reg = Registry::default();
        let err = reg.load_printers_file(&link).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(40)); // ELOOP
        let err2 = reg.load_classes_file(&link).unwrap_err();
        assert_eq!(err2.raw_os_error(), Some(40)); // ELOOP
        let _ = fs::remove_dir_all(&dir);
    }
}
