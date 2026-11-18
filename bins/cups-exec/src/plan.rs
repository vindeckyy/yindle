//! Argument parsing, profile loading, path verification, and Linux Landlock
//! ruleset planning for `cups-exec`.

use std::collections::HashMap;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use sys::{landlock_access, LandlockRule, Rlimits};

/// Default file creation umask enforced by `cups-exec` (`077`).
pub const DEFAULT_UMASK: u32 = 0o077;

/// Maximum profile file size read from disk (64 KiB).
const MAX_PROFILE_BYTES: u64 = 64 * 1024;

/// Parsed sandbox profile mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileMode {
    /// No Landlock or `NO_NEW_PRIVS` enforcement (`none` / `off`).
    Off,
    /// Relaxed Landlock enforcement (`relaxed` / `relaxed-backend`).
    Relaxed {
        /// `true` for backend processes (allows device writes under `/dev`).
        is_backend: bool,
    },
    /// Strict Landlock enforcement (`strict` / `strict-backend`).
    Strict {
        /// `true` for backend processes (allows device writes under `/dev`).
        is_backend: bool,
    },
}

impl ProfileMode {
    /// Returns `true` if this profile targets a backend process.
    #[must_use]
    pub const fn is_backend(self) -> bool {
        match self {
            Self::Off => false,
            Self::Relaxed { is_backend } | Self::Strict { is_backend } => is_backend,
        }
    }

    /// Returns `true` if sandboxing (`NO_NEW_PRIVS` + Landlock) is active.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// Extra rules parsed from a profile file (or empty for built-in named profiles).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSpec {
    /// Sandbox enforcement mode.
    pub mode: ProfileMode,
    /// Umask to apply (`0o077` default).
    pub umask: u32,
    /// Resource limits to apply (`Rlimits::filter_default()` default).
    pub rlimits: Rlimits,
    /// Extra read-only Landlock paths.
    pub allow_read: Vec<PathBuf>,
    /// Extra read-write Landlock paths.
    pub allow_write: Vec<PathBuf>,
    /// Extra read-exec Landlock paths.
    pub allow_exec: Vec<PathBuf>,
}

impl ProfileSpec {
    /// Create a default [`ProfileSpec`] for a named [`ProfileMode`].
    #[must_use]
    pub const fn for_mode(mode: ProfileMode) -> Self {
        Self {
            mode,
            umask: DEFAULT_UMASK,
            rlimits: Rlimits::filter_default(),
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            allow_exec: Vec::new(),
        }
    }
}

/// Parsed CLI arguments for `cups-exec`:
/// `cups-exec <sandbox-profile> <uid> <gid> <nice> <path> [argv0 args...]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    /// Resolved profile specification.
    pub profile: ProfileSpec,
    /// Requested target UID (`None` when `"-"` / `"-1"`).
    pub uid: Option<u32>,
    /// Requested target GID (`None` when `"-"` / `"-1"`).
    pub gid: Option<u32>,
    /// Clamped niceness (`0..=19`).
    pub nice: i32,
    /// Absolute path to executable to launch.
    pub program: PathBuf,
    /// `argv[0]` to pass to the target executable.
    pub argv0: String,
    /// Arguments (`argv[1..]`) to pass to the target executable.
    pub args: Vec<String>,
}

/// Complete sandbox execution plan derived from [`ExecRequest`] + environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPlan {
    /// Sandbox mode.
    pub mode: ProfileMode,
    /// Target UID (`None` = keep current).
    pub uid: Option<u32>,
    /// Target GID (`None` = keep current).
    pub gid: Option<u32>,
    /// Clamped niceness (`0..=19`).
    pub nice: i32,
    /// File creation mask.
    pub umask: u32,
    /// Resource limits.
    pub rlimits: Rlimits,
    /// Linux Landlock ruleset (empty when `mode == ProfileMode::Off`).
    pub landlock_rules: Vec<LandlockRule>,
    /// Executable path.
    pub program: PathBuf,
    /// `argv[0]`.
    pub argv0: String,
    /// Remaining arguments.
    pub args: Vec<String>,
}

/// Parse effective `(uid, gid)` from `/proc/self/status` contents.
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

/// Return current process effective `(uid, gid)` safely.
#[must_use]
pub fn current_euid_egid() -> (u32, u32) {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        if let Some(ids) = parse_proc_status_ids(&status) {
            return ids;
        }
    }
    std::fs::metadata("/proc/self").map_or((u32::MAX, u32::MAX), |m| (m.uid(), m.gid()))
}

/// Parse a named profile or load a profile file from disk.
pub fn parse_profile(token: &str) -> io::Result<ProfileSpec> {
    if token.is_empty() || token.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty or NUL sandbox profile",
        ));
    }

    match token.to_ascii_lowercase().as_str() {
        "none" | "off" => return Ok(ProfileSpec::for_mode(ProfileMode::Off)),
        "strict" | "strict-filter" => {
            return Ok(ProfileSpec::for_mode(ProfileMode::Strict {
                is_backend: false,
            }));
        }
        "strict-backend" => {
            return Ok(ProfileSpec::for_mode(ProfileMode::Strict {
                is_backend: true,
            }));
        }
        "relaxed" | "relaxed-filter" => {
            return Ok(ProfileSpec::for_mode(ProfileMode::Relaxed {
                is_backend: false,
            }));
        }
        "relaxed-backend" => {
            return Ok(ProfileSpec::for_mode(ProfileMode::Relaxed {
                is_backend: true,
            }));
        }
        _ => {}
    }

    if token.starts_with('/') {
        let path = Path::new(token);
        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "sandbox profile path contains '..'",
            ));
        }
        let file = sys::open_readonly_nofollow(path)?;
        let mut text = String::new();
        file.take(MAX_PROFILE_BYTES).read_to_string(&mut text)?;
        return parse_profile_text(&text);
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("unknown sandbox profile '{token}'"),
    ))
}

/// Parse key-value directives from a sandbox profile file.
///
/// Supports `mode=strict|relaxed|off|strict-backend|relaxed-backend`,
/// `allow-read=/path`, `allow-write=/path`, `allow-exec=/path`, `umask=077`,
/// `rlimit-cpu=N`, `rlimit-as=N`, `rlimit-fsize=N`, `rlimit-nofile=N`,
/// `rlimit-core=N`. Comments (`#`, `;`) and legacy Seatbelt S-expressions (`(`)
/// are ignored cleanly with `Strict` as the safe default.
pub fn parse_profile_text(text: &str) -> io::Result<ProfileSpec> {
    let mut spec = ProfileSpec::for_mode(ProfileMode::Strict { is_backend: false });
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with('(')
        {
            continue;
        }
        let Some((key, val)) = line.split_once('=') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("malformed profile line: '{line}'"),
            ));
        };
        let key = key.trim().to_ascii_lowercase();
        let val = val.trim();
        apply_profile_directive(&mut spec, &key, val)?;
    }
    Ok(spec)
}

fn apply_profile_directive(spec: &mut ProfileSpec, key: &str, val: &str) -> io::Result<()> {
    match key {
        "mode" => {
            spec.mode = match val.to_ascii_lowercase().as_str() {
                "none" | "off" => ProfileMode::Off,
                "strict" | "strict-filter" => ProfileMode::Strict { is_backend: false },
                "strict-backend" => ProfileMode::Strict { is_backend: true },
                "relaxed" | "relaxed-filter" => ProfileMode::Relaxed { is_backend: false },
                "relaxed-backend" => ProfileMode::Relaxed { is_backend: true },
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid profile mode '{val}'"),
                    ));
                }
            };
        }
        "umask" => {
            let trimmed = val.strip_prefix("0o").unwrap_or(val);
            spec.umask = u32::from_str_radix(trimmed, 8).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid umask '{val}'"),
                )
            })?;
        }
        "allow-read" => spec.allow_read.push(validate_abs_rule_path(val)?),
        "allow-write" => spec.allow_write.push(validate_abs_rule_path(val)?),
        "allow-exec" => spec.allow_exec.push(validate_abs_rule_path(val)?),
        "rlimit-cpu" => spec.rlimits.cpu_secs = Some(parse_u64_field(key, val)?),
        "rlimit-as" => spec.rlimits.address_space_bytes = Some(parse_u64_field(key, val)?),
        "rlimit-fsize" => spec.rlimits.file_size_bytes = Some(parse_u64_field(key, val)?),
        "rlimit-nofile" => spec.rlimits.nofile = Some(parse_u64_field(key, val)?),
        "rlimit-core" => spec.rlimits.core_bytes = Some(parse_u64_field(key, val)?),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown profile directive '{key}'"),
            ));
        }
    }
    Ok(())
}

fn parse_u64_field(key: &str, val: &str) -> io::Result<u64> {
    val.parse::<u64>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid numeric value for {key}: '{val}'"),
        )
    })
}

fn validate_abs_rule_path(val: &str) -> io::Result<PathBuf> {
    if !val.starts_with('/') || val.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("profile path must be absolute: '{val}'"),
        ));
    }
    let p = PathBuf::from(val);
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("profile path contains '..': '{val}'"),
        ));
    }
    Ok(p)
}

fn parse_optional_id(raw: &str, label: &str) -> io::Result<Option<u32>> {
    if raw == "-" || raw == "-1" {
        return Ok(None);
    }
    raw.parse::<u32>().map(Some).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {label} '{raw}'"),
        )
    })
}

/// Validate target executable path syntax (absolute, no NUL, no control chars, no `..`).
pub fn validate_program_path_syntax(raw: &str) -> io::Result<PathBuf> {
    if raw.is_empty()
        || !raw.starts_with('/')
        || raw.bytes().any(|b| b == 0 || b < 0x20 || b == 0x7f)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("program path must be a clean absolute path: '{raw}'"),
        ));
    }
    let path = PathBuf::from(raw);
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("program path traversal ('..') rejected: '{raw}'"),
        ));
    }
    Ok(path)
}

/// Verify on-disk safety of the target executable (not a symlink, regular file,
/// executable, non-group/world-writable, non-setuid/setgid, trusted owner).
pub fn validate_program_on_disk(path: &Path, eff_user: u32) -> io::Result<()> {
    let sym = std::fs::symlink_metadata(path)?;
    if sym.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to execute symlink: {}", path.display()),
        ));
    }
    let meta = std::fs::metadata(path)?;
    validate_program_metadata(path, meta.is_file(), meta.mode(), meta.uid(), eff_user)
}

/// Pure metadata check for target executable (testable without root).
pub fn validate_program_metadata(
    path: &Path,
    is_file: bool,
    mode: u32,
    owner_uid: u32,
    eff_user: u32,
) -> io::Result<()> {
    if !is_file {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("target is not a regular file: {}", path.display()),
        ));
    }
    if (mode & 0o111) == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("target is not executable: {}", path.display()),
        ));
    }
    if (mode & 0o022) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing group- or world-writable target: {}",
                path.display()
            ),
        ));
    }
    if (mode & 0o6000) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing setuid/setgid target: {}", path.display()),
        ));
    }
    if eff_user == 0 {
        if owner_uid != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "root cups-exec requires root-owned target: {}",
                    path.display()
                ),
            ));
        }
    } else if owner_uid != 0 && owner_uid != eff_user {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "target owned by untrusted uid {owner_uid}: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Parse full `cups-exec` argv supporting both:
/// - Positional form: `cups-exec <sandbox-profile> <uid> <gid> <nice> <path> [argv0 args...]`
/// - Flag form (CUPS 2.4+): `cups-exec [-g gid] [-n nice] [-u uid] <sandbox-profile> <path> [argv0 args...]`
pub fn parse_args(argv: &[String]) -> io::Result<ExecRequest> {
    if argv.len() >= 2 && matches!(argv[1].as_str(), "-g" | "-n" | "-u") {
        return parse_flag_args(argv);
    }
    if argv.len() < 6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: cups-exec <sandbox-profile> <uid> <gid> <nice> <path> [argv0 args...]",
        ));
    }

    let profile = parse_profile(&argv[1])?;
    let uid = parse_optional_id(&argv[2], "uid")?;
    let gid = parse_optional_id(&argv[3], "gid")?;
    let raw_nice: i32 = argv[4].parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid nice value '{}'", argv[4]),
        )
    })?;
    let nice = raw_nice.clamp(0, 19);
    let program = validate_program_path_syntax(&argv[5])?;

    let (argv0, child_args) = if argv.len() >= 7 {
        (argv[6].clone(), argv[7..].to_vec())
    } else {
        (program.to_string_lossy().into_owned(), Vec::new())
    };

    Ok(ExecRequest {
        profile,
        uid,
        gid,
        nice,
        program,
        argv0,
        args: child_args,
    })
}

fn parse_flag_args(argv: &[String]) -> io::Result<ExecRequest> {
    let mut uid = None;
    let mut gid = None;
    let mut nice = 0i32;
    let mut idx = 1usize;

    while idx < argv.len() {
        match argv[idx].as_str() {
            "-u" => {
                idx += 1;
                let v = argv.get(idx).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "option '-u' requires uid")
                })?;
                uid = parse_optional_id(v, "uid")?;
                idx += 1;
            }
            "-g" => {
                idx += 1;
                let v = argv.get(idx).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "option '-g' requires gid")
                })?;
                gid = parse_optional_id(v, "gid")?;
                idx += 1;
            }
            "-n" => {
                idx += 1;
                let v = argv.get(idx).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "option '-n' requires nice")
                })?;
                let raw: i32 = v.parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid nice '{v}'"))
                })?;
                nice = raw.clamp(0, 19);
                idx += 1;
            }
            _ => break,
        }
    }

    if argv.len().saturating_sub(idx) < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: cups-exec [-g gid] [-n nice] [-u uid] <sandbox-profile> <path> [argv0 args...]",
        ));
    }

    let profile = parse_profile(&argv[idx])?;
    let program = validate_program_path_syntax(&argv[idx + 1])?;
    let (argv0, child_args) = if argv.len() > idx + 2 {
        (argv[idx + 2].clone(), argv[idx + 3..].to_vec())
    } else {
        (program.to_string_lossy().into_owned(), Vec::new())
    };

    Ok(ExecRequest {
        profile,
        uid,
        gid,
        nice,
        program,
        argv0,
        args: child_args,
    })
}

/// Build the full [`SandboxPlan`] (including Linux Landlock rules) from a parsed
/// [`ExecRequest`] and environment snapshot.
#[must_use]
pub fn build_plan<S: std::hash::BuildHasher>(
    req: ExecRequest,
    env: &HashMap<String, String, S>,
) -> SandboxPlan {
    let landlock_rules = if req.profile.mode.is_enabled() {
        build_landlock_rules(&req, env)
    } else {
        Vec::new()
    };

    SandboxPlan {
        mode: req.profile.mode,
        uid: req.uid,
        gid: req.gid,
        nice: req.nice,
        umask: req.profile.umask,
        rlimits: req.profile.rlimits,
        landlock_rules,
        program: req.program,
        argv0: req.argv0,
        args: req.args,
    }
}

fn build_landlock_rules<S: std::hash::BuildHasher>(
    req: &ExecRequest,
    env: &HashMap<String, String, S>,
) -> Vec<LandlockRule> {
    let mut rules = Vec::new();
    let is_backend = req.profile.mode.is_backend();
    let is_relaxed = matches!(req.profile.mode, ProfileMode::Relaxed { .. });

    push_system_rules(&mut rules, is_relaxed);
    push_cups_and_profile_rules(&mut rules, req, env, is_backend, is_relaxed);
    rules
}

fn push_system_rules(rules: &mut Vec<LandlockRule>, is_relaxed: bool) {
    for p in ["/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin"] {
        rules.push(LandlockRule {
            path: PathBuf::from(p),
            access: landlock_access::READ_EXEC,
        });
    }

    for p in [
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/alternatives",
        "/etc/fonts",
        "/etc/ssl",
        "/etc/pki",
        "/etc/ca-certificates",
        "/etc/localtime",
        "/etc/nsswitch.conf",
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/protocols",
        "/etc/services",
        "/etc/passwd",
        "/etc/group",
        "/proc/self",
        "/dev/zero",
        "/dev/urandom",
        "/dev/random",
    ] {
        rules.push(LandlockRule {
            path: PathBuf::from(p),
            access: landlock_access::READ_ONLY,
        });
    }

    rules.push(LandlockRule {
        path: PathBuf::from("/dev/null"),
        access: landlock_access::READ_FILE | landlock_access::WRITE_FILE,
    });

    if is_relaxed {
        for p in ["/etc", "/opt", "/var/lib"] {
            rules.push(LandlockRule {
                path: PathBuf::from(p),
                access: landlock_access::READ_ONLY,
            });
        }
    }
}

fn push_cups_and_profile_rules<S: std::hash::BuildHasher>(
    rules: &mut Vec<LandlockRule>,
    req: &ExecRequest,
    env: &HashMap<String, String, S>,
    is_backend: bool,
    is_relaxed: bool,
) {
    // Grant execute/read access to the target executable itself.
    rules.push(LandlockRule {
        path: req.program.clone(),
        access: landlock_access::READ_EXEC,
    });

    if let Some(sb) = env.get("CUPS_SERVERBIN").filter(|s| s.starts_with('/')) {
        rules.push(LandlockRule {
            path: PathBuf::from(sb),
            access: landlock_access::READ_EXEC,
        });
    }
    for key in ["CUPS_DATADIR", "CUPS_SERVERROOT"] {
        if let Some(dir) = env.get(key).filter(|s| s.starts_with('/')) {
            rules.push(LandlockRule {
                path: PathBuf::from(dir),
                access: landlock_access::READ_ONLY,
            });
        }
    }
    if let Some(ppd) = env.get("PPD").filter(|s| s.starts_with('/')) {
        rules.push(LandlockRule {
            path: PathBuf::from(ppd),
            access: landlock_access::READ_FILE,
        });
    }

    // If the final CUPS filter argument is an absolute file path (argv[6] spool file),
    // grant read-only access to it.
    if req.args.len() >= 6 {
        let candidate = &req.args[5];
        if candidate.starts_with('/') {
            rules.push(LandlockRule {
                path: PathBuf::from(candidate),
                access: landlock_access::READ_FILE,
            });
        }
    }

    let tmp_dir = env
        .get("TMPDIR")
        .filter(|s| s.starts_with('/'))
        .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
    rules.push(LandlockRule {
        path: tmp_dir,
        access: landlock_access::READ_WRITE,
    });

    if let Some(cache) = env.get("CUPS_CACHEDIR").filter(|s| s.starts_with('/')) {
        rules.push(LandlockRule {
            path: PathBuf::from(cache),
            access: if is_backend || is_relaxed {
                landlock_access::READ_WRITE
            } else {
                landlock_access::READ_ONLY
            },
        });
    }

    if is_backend {
        rules.push(LandlockRule {
            path: PathBuf::from("/dev"),
            access: landlock_access::READ_FILE
                | landlock_access::WRITE_FILE
                | landlock_access::IOCTL_DEV,
        });
    }

    for p in &req.profile.allow_read {
        rules.push(LandlockRule {
            path: p.clone(),
            access: landlock_access::READ_ONLY,
        });
    }
    for p in &req.profile.allow_write {
        rules.push(LandlockRule {
            path: p.clone(),
            access: landlock_access::READ_WRITE,
        });
    }
    for p in &req.profile.allow_exec {
        rules.push(LandlockRule {
            path: p.clone(),
            access: landlock_access::READ_EXEC,
        });
    }
}

/// Filter dangerous dynamic-linker / shell-injection variables from an environment
/// map before `execv` (defense-in-depth when `cups-exec` is invoked directly).
#[must_use]
pub fn scrub_exec_env<S: std::hash::BuildHasher>(
    env: &HashMap<String, String, S>,
) -> HashMap<String, String> {
    const DANGEROUS: &[&str] = &[
        "BASH_ENV",
        "CDPATH",
        "ENV",
        "GCONV_PATH",
        "GETCONF_DIR",
        "HOSTALIASES",
        "IFS",
        "LOCPATH",
        "MALLOC_TRACE",
        "NODE_OPTIONS",
        "PERL5LIB",
        "PERL5OPT",
        "PERLLIB",
        "PS4",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "RES_OPTIONS",
        "RESOLV_HOST_CONF",
        "RUBYLIB",
        "RUBYOPT",
        "SHELLOPTS",
    ];
    let mut out = HashMap::new();
    for (k, v) in env {
        let bytes = k.as_bytes();
        let is_ld = bytes
            .get(..3)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"LD_"));
        let is_dyld = bytes
            .get(..5)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"DYLD_"));
        let is_bad = is_ld || is_dyld || DANGEROUS.iter().any(|d| d.eq_ignore_ascii_case(k));
        if !is_bad && !k.contains('\0') && !v.contains('\0') {
            out.insert(k.clone(), v.clone());
        }
    }
    out
}
