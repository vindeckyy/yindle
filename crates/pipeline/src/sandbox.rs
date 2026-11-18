//! Filter and backend sandboxing configuration, Linux Landlock ruleset
//! construction, `presswork-sys::sandbox` orchestration, and `cups-exec`
//! invocation planning.

use std::io;
use std::path::{Path, PathBuf};

use cups_config::{Config, Sandboxing};
use sys::{landlock_access, LandlockRule, LandlockStatus, Rlimits};

use crate::security::current_euid_egid;

/// Default umask for filter and backend subprocesses (CUPS `077`).
pub const DEFAULT_FILTER_UMASK: u32 = 0o077;

/// Sandboxing configuration for pipeline subprocesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxConfig {
    /// CUPS `Sandboxing` level (`Strict`, `Relaxed`, `Off`).
    pub mode: Sandboxing,
    /// Target user UID (`User` from `cups-files.conf`).
    pub uid: Option<u32>,
    /// Target group GID (`Group` from `cups-files.conf`).
    pub gid: Option<u32>,
    /// Optional username for `initgroups(3)` during privilege drop.
    pub username: Option<String>,
    /// `FilterNice` niceness (`0..=19`).
    pub nice: i32,
    /// File creation umask (default `0o077`).
    pub umask: u32,
    /// Resource limits (`Rlimits::filter_default()` by default).
    pub rlimits: Option<Rlimits>,
    /// Optional explicit path to the `cups-exec` sandbox launcher binary.
    pub cups_exec_path: Option<PathBuf>,
    /// Additional read-only paths granted in Landlock rulesets.
    pub extra_read_paths: Vec<PathBuf>,
    /// Additional read-write paths granted in Landlock rulesets.
    pub extra_write_paths: Vec<PathBuf>,
    /// Allow device writes under `/dev` for backends (e.g. usb/serial/parallel).
    pub allow_device_write: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mode: Sandboxing::Strict,
            uid: None,
            gid: None,
            username: None,
            nice: 0,
            umask: DEFAULT_FILTER_UMASK,
            rlimits: Some(Rlimits::filter_default()),
            cups_exec_path: None,
            extra_read_paths: Vec::new(),
            extra_write_paths: Vec::new(),
            allow_device_write: true,
        }
    }
}

impl SandboxConfig {
    /// Construct a [`SandboxConfig`] directly from a loaded [`cups_config::Config`].
    #[must_use]
    pub fn from_cups_config(cfg: &Config) -> Self {
        let server_bin = cfg.files.server_bin.as_deref().unwrap_or("/usr/lib/cups");
        let cups_exec_candidate = PathBuf::from(server_bin).join("daemon").join("cups-exec");
        let cups_exec_path = cups_exec_candidate.is_file().then_some(cups_exec_candidate);
        let uid = (cfg.files.user != 0).then_some(cfg.files.user);
        let gid = (cfg.files.group != 0).then_some(cfg.files.group);
        let username = uid.and_then(sys::name_of_uid);

        Self {
            mode: cfg.files.sandboxing,
            uid,
            gid,
            username,
            nice: cfg.cupsd.filter_nice.clamp(0, 19),
            umask: DEFAULT_FILTER_UMASK,
            rlimits: Some(Rlimits::filter_default()),
            cups_exec_path,
            extra_read_paths: Vec::new(),
            extra_write_paths: Vec::new(),
            allow_device_write: true,
        }
    }
}

/// Path context used to generate a stage's Linux Landlock filesystem ruleset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LandlockContext {
    /// `CUPS_SERVERBIN` directory (filters/backends/daemons).
    pub server_bin: Option<PathBuf>,
    /// `CUPS_DATADIR` directory (MIME, fonts, banners, PPDs).
    pub data_dir: Option<PathBuf>,
    /// `CUPS_SERVERROOT` directory (PPDs, configs).
    pub server_root: Option<PathBuf>,
    /// `CUPS_CACHEDIR` directory.
    pub cache_dir: Option<PathBuf>,
    /// Temporary writable directory (`TMPDIR`).
    pub temp_dir: Option<PathBuf>,
    /// Input spool data file (read-only).
    pub spool_file: Option<PathBuf>,
    /// Queue PPD file (read-only).
    pub ppd_file: Option<PathBuf>,
    /// Extra read-only paths.
    pub extra_read_paths: Vec<PathBuf>,
    /// Extra read-write paths.
    pub extra_write_paths: Vec<PathBuf>,
    /// Allow backend access to `/dev` character devices.
    pub allow_device_write: bool,
}

/// Build the Linux Landlock ruleset for a filter or backend stage.
///
/// Returns an empty rule list when `mode == Sandboxing::Off`.
#[must_use]
pub fn build_landlock_rules(
    mode: Sandboxing,
    is_backend: bool,
    ctx: &LandlockContext,
) -> Vec<LandlockRule> {
    if mode == Sandboxing::Off {
        return Vec::new();
    }

    let mut rules = Vec::new();
    push_system_landlock_rules(&mut rules, mode);
    push_cups_landlock_rules(&mut rules, mode, is_backend, ctx);
    rules
}

fn push_system_landlock_rules(rules: &mut Vec<LandlockRule>, mode: Sandboxing) {
    // System libraries, runtime binaries, and dynamic loader.
    for path in ["/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin"] {
        rules.push(LandlockRule {
            path: PathBuf::from(path),
            access: landlock_access::READ_EXEC,
        });
    }

    // Minimal system read-only metadata needed by libc, TLS, DNS, fonts, and locales.
    for path in [
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
            path: PathBuf::from(path),
            access: landlock_access::READ_ONLY,
        });
    }

    // `/dev/null` must be readable and writable.
    rules.push(LandlockRule {
        path: PathBuf::from("/dev/null"),
        access: landlock_access::READ_FILE | landlock_access::WRITE_FILE,
    });

    if mode == Sandboxing::Relaxed {
        for path in ["/etc", "/opt", "/var/lib"] {
            rules.push(LandlockRule {
                path: PathBuf::from(path),
                access: landlock_access::READ_ONLY,
            });
        }
    }
}

fn push_cups_landlock_rules(
    rules: &mut Vec<LandlockRule>,
    mode: Sandboxing,
    is_backend: bool,
    ctx: &LandlockContext,
) {
    if let Some(ref server_bin) = ctx.server_bin {
        rules.push(LandlockRule {
            path: server_bin.clone(),
            access: landlock_access::READ_EXEC,
        });
    }
    for p in [&ctx.data_dir, &ctx.server_root].into_iter().flatten() {
        rules.push(LandlockRule {
            path: p.clone(),
            access: landlock_access::READ_ONLY,
        });
    }
    for p in [&ctx.spool_file, &ctx.ppd_file].into_iter().flatten() {
        rules.push(LandlockRule {
            path: p.clone(),
            access: landlock_access::READ_FILE,
        });
    }
    for p in &ctx.extra_read_paths {
        rules.push(LandlockRule {
            path: p.clone(),
            access: landlock_access::READ_ONLY,
        });
    }

    // Writable scratch / temp / cache directories.
    let temp_dir = ctx
        .temp_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    rules.push(LandlockRule {
        path: temp_dir,
        access: landlock_access::READ_WRITE,
    });
    if let Some(ref cache_dir) = ctx.cache_dir {
        rules.push(LandlockRule {
            path: cache_dir.clone(),
            access: if is_backend || mode == Sandboxing::Relaxed {
                landlock_access::READ_WRITE
            } else {
                landlock_access::READ_ONLY
            },
        });
    }
    for p in &ctx.extra_write_paths {
        rules.push(LandlockRule {
            path: p.clone(),
            access: landlock_access::READ_WRITE,
        });
    }

    if is_backend && ctx.allow_device_write {
        rules.push(LandlockRule {
            path: PathBuf::from("/dev"),
            access: landlock_access::READ_FILE
                | landlock_access::WRITE_FILE
                | landlock_access::IOCTL_DEV,
        });
    }
}

/// Map `(Sandboxing, is_backend)` to the profile argument passed to `cups-exec`.
#[must_use]
pub const fn sandbox_profile_name(mode: Sandboxing, is_backend: bool) -> &'static str {
    match (mode, is_backend) {
        (Sandboxing::Off, _) => "none",
        (Sandboxing::Relaxed, false) => "relaxed",
        (Sandboxing::Relaxed, true) => "relaxed-backend",
        (Sandboxing::Strict, false) => "strict",
        (Sandboxing::Strict, true) => "strict-backend",
    }
}

/// Build the `cups-exec` command-line argument vector:
/// `<profile> <uid> <gid> <nice> <path> <argv0> [args...]`.
#[must_use]
pub fn build_cups_exec_args(
    profile: &str,
    uid: u32,
    gid: u32,
    nice: i32,
    program: &Path,
    argv0: &str,
    stage_args: &[String],
) -> Vec<String> {
    let mut out = Vec::with_capacity(6 + stage_args.len());
    out.push(profile.to_string());
    out.push(uid.to_string());
    out.push(gid.to_string());
    out.push(nice.clamp(0, 19).to_string());
    out.push(program.to_string_lossy().into_owned());
    out.push(argv0.to_string());
    out.extend(stage_args.iter().cloned());
    out
}

/// Outcome report returned by [`apply_current_process_sandbox`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct SandboxReport {
    /// Previous process umask before applying `cfg.umask`.
    pub umask_prev: u32,
    /// Whether `set_nice` succeeded.
    pub nice_applied: bool,
    /// Whether `set_rlimits` was applied.
    pub rlimits_applied: bool,
    /// Whether `drop_privileges` executed.
    pub privdrop_applied: bool,
    /// Whether privilege drop was skipped because the caller is already unprivileged.
    pub privdrop_skipped_unprivileged: bool,
    /// Whether `PR_SET_NO_NEW_PRIVS` was enabled.
    pub no_new_privs_applied: bool,
    /// Landlock enforcement outcome (`None` when `Sandboxing::Off`).
    pub landlock_status: Option<LandlockStatus>,
}

/// Abstraction over `presswork-sys::sandbox` syscalls for deterministic testing.
pub trait SandboxOps {
    /// Return current effective `(uid, gid)`.
    fn current_euid_egid(&self) -> (u32, u32);
    /// Apply `umask(2)`.
    fn set_umask(&mut self, mask: u32) -> u32;
    /// Apply `setpriority`.
    fn set_nice(&mut self, nice: i32) -> io::Result<()>;
    /// Apply `setrlimit`.
    fn set_rlimits(&mut self, limits: &Rlimits) -> io::Result<()>;
    /// Permanently drop privileges to `(uid, gid)`.
    fn drop_privileges(&mut self, uid: u32, gid: u32, username: Option<&str>) -> io::Result<()>;
    /// Enable `PR_SET_NO_NEW_PRIVS`.
    fn set_no_new_privs(&mut self) -> io::Result<()>;
    /// Apply Linux Landlock ruleset.
    fn apply_landlock(&mut self, rules: &[LandlockRule]) -> io::Result<LandlockStatus>;
}

/// Live OS implementation backed by `presswork-sys::sandbox`.
pub struct OsSandboxOps;

impl SandboxOps for OsSandboxOps {
    fn current_euid_egid(&self) -> (u32, u32) {
        current_euid_egid()
    }

    fn set_umask(&mut self, mask: u32) -> u32 {
        sys::set_umask(mask)
    }

    fn set_nice(&mut self, nice: i32) -> io::Result<()> {
        sys::set_nice(nice)
    }

    fn set_rlimits(&mut self, limits: &Rlimits) -> io::Result<()> {
        sys::set_rlimits(limits)
    }

    fn drop_privileges(&mut self, uid: u32, gid: u32, username: Option<&str>) -> io::Result<()> {
        sys::drop_privileges(uid, gid, username)
    }

    fn set_no_new_privs(&mut self) -> io::Result<()> {
        sys::set_no_new_privs()
    }

    fn apply_landlock(&mut self, rules: &[LandlockRule]) -> io::Result<LandlockStatus> {
        sys::apply_landlock(rules)
    }
}

/// Apply the full [`SandboxConfig`] to the current process using `ops`.
///
/// Order of operations:
/// 1. `umask` (`0o077` default).
/// 2. `set_nice` (clamped `0..=19`; EACCES/EPERM degrades gracefully when unprivileged).
/// 3. `set_rlimits` (if configured).
/// 4. `drop_privileges` (strictly enforced when running as root; gracefully skipped when
///    already running unprivileged in dev/tests).
/// 5. `set_no_new_privs` (always enabled unless `Sandboxing::Off` and privdrop skipped).
/// 6. `apply_landlock` (when `mode != Sandboxing::Off`).
pub fn apply_sandbox_with_ops<O: SandboxOps>(
    cfg: &SandboxConfig,
    is_backend: bool,
    ctx: &LandlockContext,
    ops: &mut O,
) -> io::Result<SandboxReport> {
    let umask_prev = ops.set_umask(cfg.umask);

    let nice_applied = match ops.set_nice(cfg.nice.clamp(0, 19)) {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => false,
        Err(e) => return Err(e),
    };

    let rlimits_applied = if let Some(ref rl) = cfg.rlimits {
        ops.set_rlimits(rl)?;
        true
    } else {
        false
    };

    let (eff_user, eff_group) = ops.current_euid_egid();
    let mut privdrop_applied = false;
    let mut privdrop_skipped_unprivileged = false;
    let mut no_new_privs_applied = false;

    if let (Some(target_uid), Some(target_gid)) = (cfg.uid, cfg.gid) {
        if eff_user == 0 {
            // Running as root: privilege drop MUST succeed (fail closed).
            ops.drop_privileges(target_uid, target_gid, cfg.username.as_deref())?;
            privdrop_applied = true;
            no_new_privs_applied = true;
        } else if target_uid != eff_user || target_gid != eff_group {
            // Running unprivileged in dev/tests: cannot switch to another UID,
            // degrade gracefully and still lock down NO_NEW_PRIVS + Landlock.
            privdrop_skipped_unprivileged = true;
        }
    }

    if !no_new_privs_applied && cfg.mode != Sandboxing::Off {
        ops.set_no_new_privs()?;
        no_new_privs_applied = true;
    }

    let landlock_status = if cfg.mode == Sandboxing::Off {
        None
    } else {
        let rules = build_landlock_rules(cfg.mode, is_backend, ctx);
        Some(ops.apply_landlock(&rules)?)
    };

    Ok(SandboxReport {
        umask_prev,
        nice_applied,
        rlimits_applied,
        privdrop_applied,
        privdrop_skipped_unprivileged,
        no_new_privs_applied,
        landlock_status,
    })
}

/// Apply [`SandboxConfig`] to the live calling process via `presswork-sys::sandbox`.
pub fn apply_current_process_sandbox(
    cfg: &SandboxConfig,
    is_backend: bool,
    ctx: &LandlockContext,
) -> io::Result<SandboxReport> {
    apply_sandbox_with_ops(cfg, is_backend, ctx, &mut OsSandboxOps)
}
