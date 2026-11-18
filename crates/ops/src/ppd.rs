//! Hardened PPD validation, sanitization, atomic persistence, path-contained
//! reading, and capability parsing.
//!
//! Defends against:
//! - PPD directive & newline injection via `cups*` IPP attributes
//! - `*cupsFilter` / `*cupsFilter2` / `*cupsPreFilter` / `*FoomaticRIPCommandLine`
//!   path traversal and shell command injection
//! - Symlink attacks on `{ServerRoot}/ppd/{name}.ppd` (`O_NOFOLLOW` + atomic rename)
//! - Arbitrary file reads via `CUPS-Get-PPD` `file:` paths (`/etc/shadow`, `..`)

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Maximum accepted PPD file size (4 MiB).
pub const MAX_PPD_BYTES: usize = 4 * 1024 * 1024;

/// Mode applied to queue PPD files (`0644`).
pub const PPD_FILE_MODE: u32 = 0o644;

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

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Error returned when resolving a `file:` PPD request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PpdLookupError {
    /// Path escaped allowed PPD directories or contained traversal tokens.
    Forbidden,
    /// Target file does not exist or could not be read safely.
    NotFound,
}

/// Capabilities extracted from a printer's PPD file so `Get-Printer-Attributes`
/// reflects actual queue capabilities instead of static defaults.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PpdCapabilities {
    pub color_device: Option<bool>,
    pub default_media: Option<String>,
    pub media_supported: Vec<String>,
    pub duplex_supported: Option<bool>,
    pub default_duplex: Option<String>,
    pub resolutions: Vec<(i32, i32)>,
    pub default_resolution: Option<(i32, i32)>,
    pub filter_formats: Vec<String>,
}

/// Validate uploaded PPD bytes before saving them to `{ServerRoot}/ppd/`.
///
/// Rejects empty or oversized files, NUL bytes, missing `*PPD-Adobe:` header,
/// `*FoomaticRIPCommandLine` execution directives, and untrusted `*cupsFilter` /
/// `*cupsFilter2` / `*cupsPreFilter` filter program paths (path traversal,
/// absolute paths, or shell metacharacters).
pub fn validate_ppd_bytes(data: &[u8]) -> Result<(), String> {
    if data.is_empty() {
        return Err("PPD file is empty.".into());
    }
    if data.len() > MAX_PPD_BYTES {
        return Err(format!("PPD file exceeds {MAX_PPD_BYTES} bytes."));
    }
    if data.contains(&0) {
        return Err("PPD file contains NUL bytes.".into());
    }
    let text = String::from_utf8_lossy(data);
    let trimmed = text.trim_start_matches('\u{feff}');
    // Split on BOTH `\r` and `\n` so classic CR-only PPD 4.3 lines cannot hide directives.
    let first_non_empty = trimmed
        .split(['\r', '\n'])
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    if !first_non_empty.starts_with("*PPD-Adobe:") {
        return Err("Missing \"*PPD-Adobe:\" header.".into());
    }

    for (idx, raw_line) in trimmed.split(['\r', '\n']).enumerate() {
        let line = raw_line.trim();
        let Some((lhs, _)) = line.split_once(':') else {
            continue;
        };
        let kw = lhs
            .split(|c: char| c == '/' || c.is_ascii_whitespace())
            .next()
            .unwrap_or(lhs)
            .to_ascii_lowercase();
        if kw.starts_with("*foomaticripcommandline") || kw == "*foomaticripoptionsetting" {
            return Err(format!(
                "Disallowed Foomatic execution directive on line {}.",
                idx + 1
            ));
        }
        if matches!(
            kw.as_str(),
            "*cupsfilter" | "*cupsfilter2" | "*cupsprefilter"
        ) {
            validate_cups_filter_line(line, &kw, idx + 1)?;
        }
    }
    Ok(())
}

fn validate_cups_filter_line(line: &str, kw_lower: &str, linenum: usize) -> Result<(), String> {
    let Some((_, rhs)) = line.split_once(':') else {
        return Err(format!("Malformed filter directive on line {linenum}."));
    };
    let rhs = rhs.trim();
    let spec = rhs
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(rhs);
    if has_shell_metachar(spec) {
        return Err(format!(
            "Disallowed shell metacharacter in filter directive on line {linenum}."
        ));
    }
    let parts: Vec<&str> = spec.split_whitespace().collect();
    // *cupsFilter / *cupsPreFilter: "mime cost program" (3 tokens)
    // *cupsFilter2: "src dst cost program" (4 tokens)
    let min_tokens = if kw_lower == "*cupsfilter2" { 4 } else { 3 };
    if parts.len() != min_tokens {
        return Err(format!("Malformed filter specification on line {linenum}."));
    }
    let Some(&prog) = parts.last() else {
        return Err(format!("Missing filter program on line {linenum}."));
    };
    if prog == "-" {
        return Ok(());
    }
    if !is_safe_filter_name(prog) {
        return Err(format!(
            "Unsafe filter program \"{prog}\" on line {linenum}."
        ));
    }
    Ok(())
}

fn has_shell_metachar(s: &str) -> bool {
    s.bytes().any(|b| {
        matches!(
            b,
            b';' | b'|' | b'&' | b'`' | b'$' | b'(' | b')' | b'<' | b'>' | b'\\' | b'\r' | b'\n'
        )
    })
}

fn is_safe_filter_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains("..")
        && !name.contains('/')
        && !name.contains('\\')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
}

/// Validate a `cups*` IPP attribute name & value before patching into a PPD.
///
/// Forbids patching executable filter directives (`cupsFilter`, `cupsFilter2`,
/// `cupsPreFilter`) and rejects CR/LF/NUL injection in names or values.
pub fn validate_cups_patch_attr(name: &str, value: &str) -> Result<(), String> {
    if !name.starts_with("cups")
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(format!("Invalid PPD attribute name \"{name}\"."));
    }
    let lower = name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "cupsfilter" | "cupsfilter2" | "cupsprefilter"
    ) {
        return Err(format!(
            "Patching \"{name}\" via IPP attributes is forbidden."
        ));
    }
    if value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(format!(
            "Disallowed control character in PPD attribute \"{name}\"."
        ));
    }
    Ok(())
}

/// Apply validated `(name, value)` `cups*` patches to PPD text.
pub fn patch_ppd_cups_attrs(
    ppd_text: &str,
    patches: &[(String, String)],
) -> Result<String, String> {
    let mut text = ppd_text.to_string();
    for (name, raw_val) in patches {
        validate_cups_patch_attr(name, raw_val)?;
        let val = match raw_val.as_str() {
            "true" => "True",
            "false" => "False",
            v => v,
        };
        let key = format!("*{name}:");
        let mut replaced = false;
        let mut rebuilt = String::with_capacity(text.len() + key.len() + val.len() + 2);
        for line in text.split_inclusive('\n') {
            if !replaced && line.starts_with(&key) {
                rebuilt.push_str(&key);
                rebuilt.push(' ');
                rebuilt.push_str(val);
                rebuilt.push('\n');
                replaced = true;
            } else {
                rebuilt.push_str(line);
            }
        }
        if !replaced {
            if !rebuilt.is_empty() && !rebuilt.ends_with('\n') {
                rebuilt.push('\n');
            }
            rebuilt.push_str(&key);
            rebuilt.push(' ');
            rebuilt.push_str(val);
            rebuilt.push('\n');
        }
        text = rebuilt;
    }
    Ok(text)
}

/// Atomically write `{server_root}/ppd/{printer_name}.ppd` using
/// `O_CREAT | O_EXCL | O_NOFOLLOW`, `sync_all`, and atomic `rename`.
pub fn atomic_write_ppd(
    server_root: &Path,
    printer_name: &str,
    bytes: &[u8],
) -> io::Result<PathBuf> {
    printer::validate_printer_name(printer_name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let ppd_dir = server_root.join("ppd");
    if let Ok(meta) = fs::symlink_metadata(&ppd_dir) {
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ppd directory is a symlink",
            ));
        }
    } else {
        fs::create_dir_all(&ppd_dir)?;
    }

    let target = ppd_dir.join(format!("{printer_name}.ppd"));
    if let Ok(meta) = fs::symlink_metadata(&target) {
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "target PPD path is a symlink",
            ));
        }
    }

    let pid = std::process::id();
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = ppd_dir.join(format!(".{printer_name}.ppd.tmp.{pid}.{seq}"));

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(PPD_FILE_MODE);
        opts.custom_flags(O_NOFOLLOW);
    }

    let mut file = opts.open(&tmp)?;
    let write_res = (|| -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        #[cfg(unix)]
        fs::set_permissions(&tmp, fs::Permissions::from_mode(PPD_FILE_MODE))?;
        Ok(())
    })();
    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    drop(file);

    if let Err(e) = fs::rename(&tmp, &target) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(target)
}

/// Safely read a regular file with `O_NOFOLLOW` and a hard byte cap.
pub fn read_file_nofollow_bounded(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        opts.custom_flags(O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a regular file",
        ));
    }
    let mut buf = Vec::new();
    let cap = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    file.take(cap.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds maximum allowed size",
        ));
    }
    Ok(buf)
}

/// Strip ASCII prefix case-insensitively without slicing inside multi-byte UTF-8.
fn strip_prefix_ignore_ascii_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let n = prefix.len();
    s.get(..n)
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .and_then(|_| s.get(n..))
}

/// Validate a non-`file:` `ppd-name` before forwarding to `cups-driverd cat`.
pub fn validate_driverd_ppd_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 1024 {
        return Err("Invalid ppd-name length.".into());
    }
    if strip_prefix_ignore_ascii_case(name, "file:").is_some() {
        return Err("file: scheme is not permitted in driverd ppd-name.".into());
    }
    if name.starts_with('/') || name.contains('\\') || name.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("Invalid characters in ppd-name.".into());
    }
    // Strip `drv:///` / `drv://` case-insensitively and reject empty, absolute
    // (e.g. `drv:////etc/...`), or `..` traversal paths.
    let stripped = strip_prefix_ignore_ascii_case(name, "drv:///")
        .or_else(|| strip_prefix_ignore_ascii_case(name, "drv://"))
        .unwrap_or(name);
    if stripped.is_empty()
        || stripped.starts_with('/')
        || stripped.split('/').any(|seg| seg == "..")
    {
        return Err("Path traversal or absolute path in ppd-name.".into());
    }
    Ok(())
}

/// Strictly resolve a `file:` PPD request under `allowed_roots`
/// (`{ServerRoot}/ppd`, `{DataDir}/ppd`, `/usr/share/ppd`).
///
/// Rejects path traversal (`..`), NUL/control bytes, and any canonical target
/// outside `allowed_roots` with [`PpdLookupError::Forbidden`].
pub fn resolve_safe_file_ppd(
    raw_name: &str,
    allowed_roots: &[PathBuf],
) -> Result<Vec<u8>, PpdLookupError> {
    let target_spec = strip_prefix_ignore_ascii_case(raw_name, "file://localhost")
        .or_else(|| strip_prefix_ignore_ascii_case(raw_name, "file://"))
        .or_else(|| strip_prefix_ignore_ascii_case(raw_name, "file:"))
        .unwrap_or(raw_name);

    if target_spec.is_empty()
        || target_spec.contains('\\')
        || target_spec.bytes().any(|b| b < 0x20 || b == 0x7f)
        || target_spec.split('/').any(|seg| seg == "..")
    {
        return Err(PpdLookupError::Forbidden);
    }

    let canon_roots: Vec<PathBuf> = allowed_roots
        .iter()
        .filter_map(|r| fs::canonicalize(r).ok())
        .collect();

    if target_spec.starts_with('/') {
        let Ok(canon) = fs::canonicalize(target_spec) else {
            // Absolute path outside allowed roots fails closed as Forbidden if
            // it doesn't even share an allowed prefix, or NotFound if under one.
            let under_allowed = allowed_roots
                .iter()
                .any(|r| Path::new(target_spec).starts_with(r));
            return Err(if under_allowed {
                PpdLookupError::NotFound
            } else {
                PpdLookupError::Forbidden
            });
        };
        if !canon_roots.iter().any(|root| canon.starts_with(root)) {
            return Err(PpdLookupError::Forbidden);
        }
        return read_file_nofollow_bounded(&canon, MAX_PPD_BYTES)
            .map_err(|_| PpdLookupError::NotFound);
    }

    // Relative name (e.g. `file:myqueue` or `file:subdir/model.ppd`).
    let mut saw_escape = false;
    for root in &canon_roots {
        let candidates = if Path::new(target_spec)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("ppd"))
        {
            vec![root.join(target_spec)]
        } else {
            vec![
                root.join(format!("{target_spec}.ppd")),
                root.join(target_spec),
            ]
        };
        for cand in candidates {
            if let Ok(canon) = fs::canonicalize(&cand) {
                if !canon.starts_with(root) {
                    saw_escape = true;
                    continue;
                }
                return read_file_nofollow_bounded(&canon, MAX_PPD_BYTES)
                    .map_err(|_| PpdLookupError::NotFound);
            }
        }
    }
    Err(if saw_escape {
        PpdLookupError::Forbidden
    } else {
        PpdLookupError::NotFound
    })
}

/// Load and parse capabilities from `{server_root}/ppd/{printer_name}.ppd` if
/// present and safely contained.
#[must_use]
pub fn load_queue_ppd_capabilities(
    server_root: &Path,
    printer_name: &str,
) -> Option<PpdCapabilities> {
    if printer::validate_printer_name(printer_name).is_err() {
        return None;
    }
    let path = server_root.join("ppd").join(format!("{printer_name}.ppd"));
    let bytes = read_file_nofollow_bounded(&path, MAX_PPD_BYTES).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    Some(parse_ppd_capabilities(&text))
}

/// Extract printer capabilities from PPD text.
#[must_use]
pub fn parse_ppd_capabilities(text: &str) -> PpdCapabilities {
    let mut caps = PpdCapabilities::default();
    let mut saw_duplex_non_none = false;

    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("*ColorDevice:") {
            let v = rest.trim();
            if v.eq_ignore_ascii_case("true") {
                caps.color_device = Some(true);
            } else if v.eq_ignore_ascii_case("false") {
                caps.color_device = Some(false);
            }
        } else if let Some(rest) = line.strip_prefix("*DefaultPageSize:") {
            if let Some(pwg) = ppd_media_to_pwg(rest.trim()) {
                caps.default_media = Some(pwg);
            }
        } else if let Some(rest) = line.strip_prefix("*PageSize ") {
            if let Some(name) = rest.split(['/', ':']).next().map(str::trim) {
                if let Some(pwg) = ppd_media_to_pwg(name) {
                    if !caps.media_supported.contains(&pwg) {
                        caps.media_supported.push(pwg);
                    }
                }
            }
        } else if let Some(rest) = line.strip_prefix("*DefaultDuplex:") {
            caps.default_duplex = match rest.trim() {
                "DuplexNoTumble" => Some("two-sided-long-edge".into()),
                "DuplexTumble" => Some("two-sided-short-edge".into()),
                "None" => Some("one-sided".into()),
                _ => None,
            };
        } else if let Some(rest) = line.strip_prefix("*Duplex ") {
            if let Some(opt) = rest.split(['/', ':']).next().map(str::trim) {
                if matches!(opt, "DuplexNoTumble" | "DuplexTumble") {
                    saw_duplex_non_none = true;
                }
            }
        } else if let Some(rest) = line.strip_prefix("*DefaultResolution:") {
            if let Some(r) = parse_ppd_resolution(rest.trim()) {
                caps.default_resolution = Some(r);
                if !caps.resolutions.contains(&r) {
                    caps.resolutions.push(r);
                }
            }
        } else if let Some(rest) = line.strip_prefix("*Resolution ") {
            if let Some(tok) = rest.split(['/', ':']).next().map(str::trim) {
                if let Some(r) = parse_ppd_resolution(tok) {
                    if !caps.resolutions.contains(&r) {
                        caps.resolutions.push(r);
                    }
                }
            }
        } else if let Some(rest) = line
            .strip_prefix("*cupsFilter:")
            .or_else(|| line.strip_prefix("*cupsFilter2:"))
        {
            let spec = rest.trim().trim_matches('"');
            if let Some(mime) = spec.split_whitespace().next() {
                if mime.contains('/') && !caps.filter_formats.iter().any(|m| m == mime) {
                    caps.filter_formats.push(mime.to_string());
                }
            }
        }
    }

    if saw_duplex_non_none {
        caps.duplex_supported = Some(true);
    } else if caps.default_duplex.as_deref() == Some("one-sided") {
        caps.duplex_supported = Some(false);
    }
    caps
}

fn ppd_media_to_pwg(name: &str) -> Option<String> {
    let mapped = match name.to_ascii_lowercase().as_str() {
        "letter" => "na_letter_8.5x11in",
        "legal" => "na_legal_8.5x14in",
        "a4" => "iso_a4_210x297mm",
        "a3" => "iso_a3_297x420mm",
        "a5" => "iso_a5_148x210mm",
        "env10" | "com10" => "na_number-10_4.125x9.5in",
        "executive" => "na_executive_7.25x10.5in",
        "tabloid" | "ledger" => "na_ledger_11x17in",
        other if other.contains('_') && other.len() <= 64 => return Some(other.to_string()),
        _ => return None,
    };
    Some(mapped.to_string())
}

fn parse_ppd_resolution(tok: &str) -> Option<(i32, i32)> {
    let lower = tok.to_ascii_lowercase();
    let base = lower.strip_suffix("dpi")?;
    if let Some((x, y)) = base.split_once('x') {
        let xv = x.parse::<i32>().ok()?;
        let yv = y.parse::<i32>().ok()?;
        (xv > 0 && yv > 0).then_some((xv, yv))
    } else {
        let v = base.parse::<i32>().ok()?;
        (v > 0).then_some((v, v))
    }
}
