//! Process privilege drop, resource limits (`setrlimit`), process niceness /
//! umask, `PR_SET_NO_NEW_PRIVS`, and best-effort Linux Landlock sandboxing.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::nss::name_of_uid;

/// Set `PR_SET_NO_NEW_PRIVS` on the calling thread (prevents privilege
/// escalation via setuid/setgid/file capabilities across `execve`).
pub fn set_no_new_privs() -> io::Result<()> {
    // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` has no pointer arguments.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Set the process file creation mask (`umask(2)`) and return the previous mask.
#[must_use]
pub fn set_umask(mask: u32) -> u32 {
    // SAFETY: `umask(2)` always succeeds and has no memory-safety preconditions.
    unsafe { libc::umask(mask as libc::mode_t) }
}

/// Adjust process scheduling priority (`setpriority(PRIO_PROCESS, 0, niceness)`).
/// Values are clamped to `0..=19` (only lowering priority).
pub fn set_nice(niceness: i32) -> io::Result<()> {
    let clamped = niceness.clamp(0, 19);
    // SAFETY: `setpriority` takes plain integers and adjusts current process priority.
    let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, clamped) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) trait PrivDropOps {
    fn initgroups(&mut self, user: &CStr, gid: u32) -> io::Result<()>;
    fn clear_groups(&mut self) -> io::Result<()>;
    fn setgid(&mut self, gid: u32) -> io::Result<()>;
    fn setuid(&mut self, uid: u32) -> io::Result<()>;
    fn get_effective_ids(&self) -> (u32, u32);
    fn no_new_privs(&mut self) -> io::Result<()>;
}

pub(crate) struct OsPrivDropOps;

impl PrivDropOps for OsPrivDropOps {
    fn initgroups(&mut self, user: &CStr, gid: u32) -> io::Result<()> {
        // SAFETY: `user` is a valid NUL-terminated C string.
        if unsafe { libc::initgroups(user.as_ptr(), gid as libc::gid_t) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn clear_groups(&mut self) -> io::Result<()> {
        // SAFETY: clearing supplementary groups with count 0 and null list is valid.
        if unsafe { libc::setgroups(0, std::ptr::null()) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn setgid(&mut self, gid: u32) -> io::Result<()> {
        // SAFETY: `setgid` takes a plain integer GID.
        if unsafe { libc::setgid(gid as libc::gid_t) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn setuid(&mut self, uid: u32) -> io::Result<()> {
        // SAFETY: `setuid` permanently drops effective/saved/real UID when root.
        if unsafe { libc::setuid(uid as libc::uid_t) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn get_effective_ids(&self) -> (u32, u32) {
        // SAFETY: `geteuid`/`getegid` always succeed.
        unsafe { (libc::geteuid(), libc::getegid()) }
    }

    fn no_new_privs(&mut self) -> io::Result<()> {
        set_no_new_privs()
    }
}

pub(crate) fn drop_privileges_with_ops<O: PrivDropOps>(
    uid: u32,
    gid: u32,
    username: Option<&str>,
    ops: &mut O,
) -> io::Result<()> {
    if uid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to drop privileges to uid 0 (root)",
        ));
    }

    let resolved_name;
    let user_opt = match username {
        Some(u) if !u.is_empty() => Some(u),
        _ => {
            resolved_name = name_of_uid(uid);
            resolved_name.as_deref()
        }
    };

    if let Some(u) = user_opt {
        let c_user = CString::new(u)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "username contains NUL"))?;
        ops.initgroups(&c_user, gid)?;
    } else {
        ops.clear_groups()?;
    }

    ops.setgid(gid)?;
    ops.setuid(uid)?;

    let (actual_user, actual_group) = ops.get_effective_ids();
    if actual_user != uid || actual_group != gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "privilege drop verification failed",
        ));
    }

    ops.no_new_privs()
}

/// Permanently drop process privileges to `(uid, gid)` and lock out privilege
/// re-acquisition via `PR_SET_NO_NEW_PRIVS`.
///
/// Order of operations:
/// 1. Rejects `uid == 0` (refuses to run unprivileged workers as root).
/// 2. Updates supplementary groups via `initgroups` (if `username` is given or
///    resolvable from `uid`) or clears them with `setgroups(0, NULL)`.
/// 3. Calls `setgid(gid)` then `setuid(uid)`.
/// 4. Verifies `geteuid() == uid && getegid() == gid`.
/// 5. Enables `PR_SET_NO_NEW_PRIVS`.
pub fn drop_privileges(uid: u32, gid: u32, username: Option<&str>) -> io::Result<()> {
    drop_privileges_with_ops(uid, gid, username, &mut OsPrivDropOps)
}

/// Process resource limits applied via `setrlimit(2)`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rlimits {
    /// `RLIMIT_CPU` — maximum CPU seconds.
    pub cpu_secs: Option<u64>,
    /// `RLIMIT_AS` — maximum virtual address space in bytes.
    pub address_space_bytes: Option<u64>,
    /// `RLIMIT_FSIZE` — maximum file size written in bytes.
    pub file_size_bytes: Option<u64>,
    /// `RLIMIT_NOFILE` — maximum open file descriptors.
    pub nofile: Option<u64>,
    /// `RLIMIT_NPROC` — maximum processes/threads for the user.
    pub nproc: Option<u64>,
    /// `RLIMIT_CORE` — maximum core dump size in bytes (`Some(0)` disables core dumps).
    pub core_bytes: Option<u64>,
}

impl Rlimits {
    /// Safe default resource limits for untrusted filter/backend subprocesses.
    #[must_use]
    pub const fn filter_default() -> Self {
        Self {
            cpu_secs: Some(300),
            address_space_bytes: Some(2 * 1024 * 1024 * 1024), // 2 GiB
            file_size_bytes: Some(1024 * 1024 * 1024),         // 1 GiB
            nofile: Some(256),
            nproc: None,
            core_bytes: Some(0),
        }
    }
}

/// Apply one `rlimit`, clamping against the existing hard limit so unprivileged
/// callers can safely lower limits without hitting `EPERM`.
pub(crate) fn apply_one_rlimit(resource: libc::__rlimit_resource_t, limit: u64) -> io::Result<()> {
    let mut cur = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `cur` is a valid writable `libc::rlimit`.
    if unsafe { libc::getrlimit(resource, &raw mut cur) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let capped = if cur.rlim_max == libc::RLIM_INFINITY {
        limit
    } else {
        limit.min(cur.rlim_max)
    };
    let next = libc::rlimit {
        rlim_cur: capped,
        rlim_max: capped,
    };
    // SAFETY: `next` is a valid initialized `libc::rlimit`.
    if unsafe { libc::setrlimit(resource, &raw const next) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Apply all configured resource limits in `limits` to the current process.
pub fn set_rlimits(limits: &Rlimits) -> io::Result<()> {
    let entries = [
        (libc::RLIMIT_CPU, limits.cpu_secs),
        (libc::RLIMIT_AS, limits.address_space_bytes),
        (libc::RLIMIT_FSIZE, limits.file_size_bytes),
        (libc::RLIMIT_NOFILE, limits.nofile),
        (libc::RLIMIT_NPROC, limits.nproc),
        (libc::RLIMIT_CORE, limits.core_bytes),
    ];
    for (res, val) in entries {
        if let Some(v) = val {
            apply_one_rlimit(res, v)?;
        }
    }
    Ok(())
}

/// Linux Landlock filesystem access-right bitflags (`<linux/landlock.h>`).
pub mod landlock_access {
    /// Execute a file (`LANDLOCK_ACCESS_FS_EXECUTE`).
    pub const EXECUTE: u64 = 1 << 0;
    /// Open a file with write access (`LANDLOCK_ACCESS_FS_WRITE_FILE`).
    pub const WRITE_FILE: u64 = 1 << 1;
    /// Open a file with read access (`LANDLOCK_ACCESS_FS_READ_FILE`).
    pub const READ_FILE: u64 = 1 << 2;
    /// Open/list a directory (`LANDLOCK_ACCESS_FS_READ_DIR`).
    pub const READ_DIR: u64 = 1 << 3;
    /// Remove/rename an empty directory (`LANDLOCK_ACCESS_FS_REMOVE_DIR`).
    pub const REMOVE_DIR: u64 = 1 << 4;
    /// Unlink/rename a file (`LANDLOCK_ACCESS_FS_REMOVE_FILE`).
    pub const REMOVE_FILE: u64 = 1 << 5;
    /// Create a character device (`LANDLOCK_ACCESS_FS_MAKE_CHAR`).
    pub const MAKE_CHAR: u64 = 1 << 6;
    /// Create a directory (`LANDLOCK_ACCESS_FS_MAKE_DIR`).
    pub const MAKE_DIR: u64 = 1 << 7;
    /// Create a regular file (`LANDLOCK_ACCESS_FS_MAKE_REG`).
    pub const MAKE_REG: u64 = 1 << 8;
    /// Create a UNIX socket (`LANDLOCK_ACCESS_FS_MAKE_SOCK`).
    pub const MAKE_SOCK: u64 = 1 << 9;
    /// Create a FIFO (`LANDLOCK_ACCESS_FS_MAKE_FIFO`).
    pub const MAKE_FIFO: u64 = 1 << 10;
    /// Create a block device (`LANDLOCK_ACCESS_FS_MAKE_BLOCK`).
    pub const MAKE_BLOCK: u64 = 1 << 11;
    /// Create a symlink (`LANDLOCK_ACCESS_FS_MAKE_SYM`).
    pub const MAKE_SYM: u64 = 1 << 12;
    /// Link/rename across directories — ABI v2+ (`LANDLOCK_ACCESS_FS_REFER`).
    pub const REFER: u64 = 1 << 13;
    /// Truncate files — ABI v3+ (`LANDLOCK_ACCESS_FS_TRUNCATE`).
    pub const TRUNCATE: u64 = 1 << 14;
    /// Device ioctl — ABI v5+ (`LANDLOCK_ACCESS_FS_IOCTL_DEV`).
    pub const IOCTL_DEV: u64 = 1 << 15;

    /// Convenience mask: read files and directories.
    pub const READ_ONLY: u64 = READ_FILE | READ_DIR;
    /// Convenience mask: read and execute binaries/libraries.
    pub const READ_EXEC: u64 = READ_FILE | READ_DIR | EXECUTE;
    /// Convenience mask: read, write, create, remove, and truncate files/dirs.
    pub const READ_WRITE: u64 = READ_FILE
        | READ_DIR
        | WRITE_FILE
        | REMOVE_FILE
        | REMOVE_DIR
        | MAKE_REG
        | MAKE_DIR
        | TRUNCATE;

    /// Access bits valid on non-directory (regular file / device) `parent_fd` targets.
    pub(crate) const FILE_ONLY_MASK: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;
}

/// One filesystem hierarchy permission rule for [`apply_landlock`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockRule {
    /// Directory or file path to grant access beneath.
    pub path: PathBuf,
    /// Bitmask of [`landlock_access`] rights to grant.
    pub access: u64,
}

/// Outcome of calling [`apply_landlock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockStatus {
    /// Landlock ruleset was created and enforced for the calling thread.
    Enforced {
        /// Kernel Landlock ABI version detected.
        abi: u32,
    },
    /// Kernel does not support Landlock (`ENOSYS`) or Landlock LSM is disabled (`EOPNOTSUPP`).
    Unsupported,
}

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Compute the full handled filesystem access bitmask supported by `abi`.
#[must_use]
pub(crate) const fn landlock_handled_fs_for_abi(abi: u32) -> u64 {
    use landlock_access as ll;
    let mut mask = ll::EXECUTE
        | ll::WRITE_FILE
        | ll::READ_FILE
        | ll::READ_DIR
        | ll::REMOVE_DIR
        | ll::REMOVE_FILE
        | ll::MAKE_CHAR
        | ll::MAKE_DIR
        | ll::MAKE_REG
        | ll::MAKE_SOCK
        | ll::MAKE_FIFO
        | ll::MAKE_BLOCK
        | ll::MAKE_SYM;
    if abi >= 2 {
        mask |= ll::REFER;
    }
    if abi >= 3 {
        mask |= ll::TRUNCATE;
    }
    if abi >= 5 {
        mask |= ll::IOCTL_DEV;
    }
    mask
}

/// Probe the running Linux kernel's Landlock ABI version (`>= 1`), or `None`
/// if Landlock is unavailable or disabled.
#[must_use]
pub fn landlock_abi_version() -> Option<u32> {
    // SAFETY: querying ABI version passes NULL attr, size 0, and
    // `LANDLOCK_CREATE_RULESET_VERSION` per `landlock_create_ruleset(2)`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc >= 1 {
        u32::try_from(rc).ok()
    } else {
        None
    }
}

/// Apply a best-effort Linux Landlock filesystem sandbox to the calling thread.
///
/// - If the kernel does not support Landlock or it is disabled, returns
///   `Ok(LandlockStatus::Unsupported)`.
/// - Missing paths in `rules` (`ENOENT`) are skipped so distro-portable rule
///   lists (e.g. `/usr/local/lib`, `/lib64`) work seamlessly.
/// - Automatically masks directory-only access flags when a rule targets a
///   non-directory file, enables `PR_SET_NO_NEW_PRIVS`, and calls
///   `landlock_restrict_self(2)`.
pub fn apply_landlock(rules: &[LandlockRule]) -> io::Result<LandlockStatus> {
    let Some(abi) = landlock_abi_version() else {
        return Ok(LandlockStatus::Unsupported);
    };

    let handled = landlock_handled_fs_for_abi(abi);
    let attr = LandlockRulesetAttr {
        handled_access_fs: handled,
    };

    // SAFETY: `attr` is a valid `LandlockRulesetAttr` with size 8 bytes
    // (compatible with all Landlock ABI versions >= 1).
    let ruleset_raw = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if ruleset_raw < 0 {
        let err = io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::ENOSYS | libc::EOPNOTSUPP)) {
            return Ok(LandlockStatus::Unsupported);
        }
        return Err(err);
    }
    let ruleset_fd_num =
        i32::try_from(ruleset_raw).map_err(|_| io::Error::other("invalid landlock ruleset fd"))?;
    // SAFETY: `ruleset_fd_num` is a freshly returned Landlock ruleset fd.
    let ruleset_fd = unsafe { OwnedFd::from_raw_fd(ruleset_fd_num) };

    for rule in rules {
        let Ok(c_path) = CString::new(rule.path.as_os_str().as_bytes()) else {
            continue;
        };
        // SAFETY: `c_path` is a valid NUL-terminated path string.
        let path_raw = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if path_raw < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                continue;
            }
            return Err(err);
        }
        // SAFETY: `path_raw` is a newly opened `O_PATH` file descriptor.
        let path_fd = unsafe { OwnedFd::from_raw_fd(path_raw) };

        // Determine if target is a directory; non-directories reject dir-only bits.
        // SAFETY: `libc::stat` is a plain POD struct.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `path_fd` is valid; `st` is a valid writable `stat` buffer.
        if unsafe { libc::fstat(path_fd.as_raw_fd(), &raw mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let mut allowed = rule.access & handled;
        if !is_dir {
            allowed &= landlock_access::FILE_ONLY_MASK;
        }
        if allowed == 0 {
            continue;
        }

        let path_attr = LandlockPathBeneathAttr {
            allowed_access: allowed,
            parent_fd: path_fd.as_raw_fd(),
        };
        // SAFETY: `ruleset_fd` and `path_attr` are valid for `landlock_add_rule`.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset_fd.as_raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &raw const path_attr,
                0u32,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    set_no_new_privs()?;

    // SAFETY: `ruleset_fd` is a valid Landlock ruleset fd and `NO_NEW_PRIVS` is set.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            ruleset_fd.as_raw_fd(),
            0u32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(LandlockStatus::Enforced { abi })
}
