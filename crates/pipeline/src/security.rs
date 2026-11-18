//! Executable path validation, URI scheme validation, and environment
//! sanitization for the filter+backend pipeline.

use std::collections::HashMap;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Maximum length of a URI scheme (RFC 3986).
const MAX_URI_SCHEME_LEN: usize = 64;

/// Parse effective `(uid, gid)` from Linux `/proc/self/status` contents.
#[must_use]
pub fn parse_proc_status_ids(status: &str) -> Option<(u32, u32)> {
    let mut eff_user = None;
    let mut eff_group = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            eff_user = rest.split_whitespace().nth(1).and_then(|s| s.parse().ok());
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            eff_group = rest.split_whitespace().nth(1).and_then(|s| s.parse().ok());
        }
    }
    match (eff_user, eff_group) {
        (Some(u), Some(g)) => Some((u, g)),
        _ => None,
    }
}

/// Return the current process's effective `(euid, egid)` without `unsafe`.
#[must_use]
pub fn current_euid_egid() -> (u32, u32) {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        if let Some(ids) = parse_proc_status_ids(&status) {
            return ids;
        }
    }
    std::fs::metadata("/proc/self").map_or((u32::MAX, u32::MAX), |m| (m.uid(), m.gid()))
}

/// Strictly validate a CUPS device URI scheme per RFC 3986 (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`).
///
/// Rejects missing `:`, empty schemes, `/`, `..`, whitespace, control characters,
/// and non-ASCII bytes before the backend executable name is resolved.
pub fn validate_uri_scheme(device_uri: &str) -> io::Result<String> {
    if device_uri.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device URI contains control characters",
        ));
    }
    let Some((scheme, _rest)) = device_uri.split_once(':') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device URI missing ':' scheme separator",
        ));
    };
    if scheme.is_empty() || scheme.len() > MAX_URI_SCHEME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device URI scheme is empty or too long",
        ));
    }
    let bytes = scheme.as_bytes();
    if !bytes[0].is_ascii_alphabetic() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device URI scheme must start with an ASCII letter",
        ));
    }
    if !bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device URI scheme contains disallowed characters",
        ));
    }
    if scheme.contains("..") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device URI scheme contains '..'",
        ));
    }
    Ok(scheme.to_ascii_lowercase())
}

/// Resolve and validate the backend program name for `device_uri`.
///
/// Maps CUPS's historical aliases (`http`, `https`, `ipps` -> `ipp`).
pub fn try_backend_for_uri(device_uri: &str) -> io::Result<String> {
    let scheme = validate_uri_scheme(device_uri)?;
    Ok(match scheme.as_str() {
        "http" | "https" | "ipps" => "ipp".to_string(),
        _ => scheme,
    })
}

/// Policy governing ownership, permissions, symlink handling, and trusted
/// directories for filter and backend executables.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct SecurityPolicy {
    /// Require executables to be owned by `uid 0` (root).
    /// Automatically enabled when running as root (`euid == 0`).
    pub require_root_owner: bool,
    /// Allowed owner UIDs when `require_root_owner` is `false`.
    pub allowed_uids: Vec<u32>,
    /// Reject executables writable by group or others (`mode & 0o022 != 0`).
    pub reject_group_or_world_writable: bool,
    /// Reject setuid/setgid executables (`mode & 0o6000 != 0`).
    pub reject_setuid_setgid: bool,
    /// Reject symlinks as filter/backend target paths.
    pub reject_symlinks: bool,
    /// Additional trusted directories explicitly allowed for absolute executable paths.
    pub allow_extra_trusted_dirs: Vec<PathBuf>,
}

impl SecurityPolicy {
    /// Strict production policy: root-owned only, non-group/world-writable,
    /// no setuid/setgid, no symlinks, no extra directories.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            require_root_owner: true,
            allowed_uids: vec![0],
            reject_group_or_world_writable: true,
            reject_setuid_setgid: true,
            reject_symlinks: true,
            allow_extra_trusted_dirs: Vec::new(),
        }
    }

    /// Default policy for the current process: strict root-only when running as
    /// root (`euid == 0`), or allowing root + current `euid` in unprivileged
    /// development/test runs while keeping all permission/symlink/containment checks.
    #[must_use]
    pub fn for_current_process() -> Self {
        let (euid, _) = current_euid_egid();
        Self::for_euid(euid)
    }

    /// Construct a policy for a specific effective UID (testable helper).
    #[must_use]
    pub fn for_euid(euid: u32) -> Self {
        if euid == 0 {
            Self::strict()
        } else {
            Self {
                require_root_owner: false,
                allowed_uids: vec![0, euid],
                reject_group_or_world_writable: true,
                reject_setuid_setgid: true,
                reject_symlinks: true,
                allow_extra_trusted_dirs: Vec::new(),
            }
        }
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::for_current_process()
    }
}

/// Validate a raw filter or backend program name before resolving it on disk.
pub fn validate_program_name(program: &str) -> io::Result<()> {
    if program.is_empty() || program == "-" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty or passthrough '-' executable name",
        ));
    }
    if program
        .bytes()
        .any(|b| b == 0 || b < 0x20 || b == 0x7f || b.is_ascii_whitespace())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "executable name contains control or whitespace characters",
        ));
    }
    if program.contains('\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "executable name contains backslash",
        ));
    }
    for comp in Path::new(program).components() {
        if matches!(comp, Component::ParentDir) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "executable path traversal ('..') is forbidden",
            ));
        }
    }
    Ok(())
}

/// Resolve and security-verify a filter or backend executable under `trusted_dir`.
///
/// - Bare filenames (e.g. `"pdftoraster"`, `"ipp"`) are resolved inside `trusted_dir`.
/// - Relative paths containing `/` (e.g. `"sub/foo"`, `"../evil"`) are rejected.
/// - Absolute paths are rejected unless they canonicalize inside `trusted_dir` or
///   one of `policy.allow_extra_trusted_dirs`.
/// - Verifies the target is not a symlink (when `reject_symlinks`), is a regular file,
///   has execute bits, is not group/world-writable, is not setuid/setgid, and satisfies
///   the policy's UID ownership check.
pub fn resolve_trusted_executable(
    trusted_dir: &Path,
    program: &str,
    policy: &SecurityPolicy,
) -> io::Result<PathBuf> {
    validate_program_name(program)?;

    let candidate = if program.starts_with('/') {
        PathBuf::from(program)
    } else if program.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "relative executable paths containing '/' are forbidden",
        ));
    } else {
        trusted_dir.join(program)
    };

    let mut allowed_roots = Vec::with_capacity(1 + policy.allow_extra_trusted_dirs.len());
    if let Ok(canon_dir) = std::fs::canonicalize(trusted_dir) {
        allowed_roots.push(canon_dir);
    }
    for extra in &policy.allow_extra_trusted_dirs {
        if let Ok(canon_extra) = std::fs::canonicalize(extra) {
            allowed_roots.push(canon_extra);
        }
    }
    if allowed_roots.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "trusted executable directory not found: {}",
                trusted_dir.display()
            ),
        ));
    }

    verify_executable_path(&candidate, &allowed_roots, policy)
}

/// Verify an executable path against canonicalized `allowed_roots` and `policy`.
pub fn verify_executable_path(
    candidate: &Path,
    allowed_roots: &[PathBuf],
    policy: &SecurityPolicy,
) -> io::Result<PathBuf> {
    let sym_meta = std::fs::symlink_metadata(candidate)?;
    if policy.reject_symlinks && sym_meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to execute symlink: {}", candidate.display()),
        ));
    }

    let canon = std::fs::canonicalize(candidate)?;
    if !allowed_roots.iter().any(|root| canon.starts_with(root)) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "executable escapes trusted directory: {}",
                candidate.display()
            ),
        ));
    }

    let meta = std::fs::metadata(&canon)?;
    verify_executable_metadata(&canon, meta.is_file(), meta.mode(), meta.uid(), policy)?;
    Ok(canon)
}

/// Pure metadata permission & ownership verification (unit-testable for root,
/// setuid, world-writable, non-regular, and non-executable cases without root).
pub fn verify_executable_metadata(
    path: &Path,
    is_file: bool,
    mode: u32,
    owner_uid: u32,
    policy: &SecurityPolicy,
) -> io::Result<()> {
    if !is_file {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("executable is not a regular file: {}", path.display()),
        ));
    }
    if (mode & 0o111) == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("executable lacks execute permission: {}", path.display()),
        ));
    }
    if policy.reject_group_or_world_writable && (mode & 0o022) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing group- or world-writable executable: {}",
                path.display()
            ),
        ));
    }
    if policy.reject_setuid_setgid && (mode & 0o6000) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing setuid/setgid executable: {}", path.display()),
        ));
    }
    if policy.require_root_owner {
        if owner_uid != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "executable not owned by root (uid {owner_uid}): {}",
                    path.display()
                ),
            ));
        }
    } else if !policy.allowed_uids.contains(&owner_uid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "executable owned by untrusted uid {owner_uid}: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Strip NUL bytes from an environment variable value.
#[must_use]
pub fn sanitize_env_value(val: &str) -> String {
    val.replace('\0', "")
}

/// Filter user/config extra environment variables (`PassEnv`/`SetEnv`), removing
/// prohibited, dynamic-linker (`LD_*`), shell/interpreter injection, credential,
/// and malformed variables.
#[must_use]
pub fn sanitize_extra_env<S: std::hash::BuildHasher>(
    raw: &HashMap<String, String, S>,
) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (k, v) in raw {
        if k.is_empty()
            || k.contains('=')
            || k.contains('\0')
            || v.contains('\0')
            || cups_config::is_prohibited_env(k)
        {
            continue;
        }
        out.insert(k.clone(), v.clone());
    }
    out
}
