//! Hardened filesystem helpers: symlink-safe `O_NOFOLLOW | O_CLOEXEC` opens,
//! atomic secure file writes with explicit permissions (`0600`/`0640`), and
//! character-device opens (`O_NOCTTY`).

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static ATOMIC_SEQ: AtomicU64 = AtomicU64::new(0);

fn path_to_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains interior NUL"))
}

fn fstat_fd(fd: &OwnedFd) -> io::Result<libc::stat> {
    // SAFETY: `libc::stat` is a plain POD struct.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is a valid open descriptor and `st` is writable.
    if unsafe { libc::fstat(fd.as_raw_fd(), &raw mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

/// Open a regular file with `O_NOFOLLOW | O_CLOEXEC`.
///
/// Rejects symlinks (`ELOOP`) and non-regular files (e.g. FIFOs, devices,
/// directories). When `create` is `true`, passes `mode` to `open(2)` (subject
/// to process umask); use [`atomic_write_secure`] when exact umask-independent
/// permissions are required.
pub fn open_nofollow(path: &Path, write: bool, create: bool, mode: u32) -> io::Result<File> {
    let c_path = path_to_cstring(path)?;
    let mut flags = libc::O_NOFOLLOW | libc::O_CLOEXEC;
    flags |= if write { libc::O_RDWR } else { libc::O_RDONLY };
    if create {
        flags |= libc::O_CREAT;
    }

    // SAFETY: `c_path` is a valid NUL-terminated C string.
    let raw = unsafe { libc::open(c_path.as_ptr(), flags, mode as libc::c_uint) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a newly opened valid file descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };

    let st = fstat_fd(&owned)?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target is not a regular file",
        ));
    }
    Ok(File::from(owned))
}

/// Open an existing regular file read-only with `O_NOFOLLOW | O_CLOEXEC`.
pub fn open_readonly_nofollow(path: &Path) -> io::Result<File> {
    open_nofollow(path, false, false, 0)
}

/// Open a regular file for append with `O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC`
/// and explicit permissions `mode` (e.g. `0o640` or `0o600`).
pub fn open_append_nofollow(path: &Path, mode: u32) -> io::Result<File> {
    let c_path = path_to_cstring(path)?;
    let flags =
        libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    // SAFETY: `c_path` is a valid NUL-terminated C string.
    let raw = unsafe { libc::open(c_path.as_ptr(), flags, mode as libc::c_uint) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a newly opened valid file descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };

    let st = fstat_fd(&owned)?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "append target is not a regular file",
        ));
    }
    Ok(File::from(owned))
}

/// RAII cleanup guard removing a temporary file unless disarmed after rename.
struct TempCleanup(Option<PathBuf>);

impl Drop for TempCleanup {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Atomically write `data` to `path` with explicit permission `mode` (e.g.
/// `0o600` or `0o640`), impervious to symlink races and umask loosening.
///
/// Creates an unpredictable temporary file in `path`'s parent directory using
/// `O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC`, sets exact `mode`
/// via `fchmod`, writes all bytes, optionally `fsync`s the file and parent
/// directory, and atomically renames into place. Cleans up the temporary file
/// on any error.
pub fn atomic_write_secure(path: &Path, data: &[u8], mode: u32, sync: bool) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no filename"))?;

    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());

    let mut tmp_path = PathBuf::new();
    let mut created_fd: Option<OwnedFd> = None;

    for _ in 0..32 {
        let seq = ATOMIC_SEQ.fetch_add(1, Ordering::Relaxed);
        tmp_path = parent.join(format!(".{file_name}.tmp.{pid}.{nanos}.{seq}"));
        let c_tmp = path_to_cstring(&tmp_path)?;
        let flags =
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: `c_tmp` is a valid NUL-terminated C string.
        let raw = unsafe { libc::open(c_tmp.as_ptr(), flags, mode as libc::c_uint) };
        if raw >= 0 {
            // SAFETY: `raw` is a newly created valid file descriptor.
            created_fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
            break;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(err);
        }
    }

    let owned = created_fd.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "failed to create unique temporary file",
        )
    })?;
    let mut cleanup = TempCleanup(Some(tmp_path.clone()));

    // Enforce exact permissions independent of process umask.
    // SAFETY: `owned` is a valid open file descriptor.
    if unsafe { libc::fchmod(owned.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut file = File::from(owned);
    file.write_all(data)?;
    if sync {
        file.sync_all()?;
    }
    drop(file);

    std::fs::rename(&tmp_path, path)?;
    cleanup.0 = None;

    if sync {
        // Best-effort directory fsync for rename durability.
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Open a character device with `O_NOCTTY | O_NOFOLLOW | O_CLOEXEC`,
/// verifying via `fstat` that it is indeed a character special device
/// (`S_ISCHR`). Intended for `serial`, `parallel`, and `usb` device backends.
pub fn open_char_device_noctty(path: &Path, write: bool) -> io::Result<File> {
    let c_path = path_to_cstring(path)?;
    let mut flags = libc::O_NOCTTY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    flags |= if write { libc::O_RDWR } else { libc::O_RDONLY };

    // SAFETY: `c_path` is a valid NUL-terminated C string.
    let raw = unsafe { libc::open(c_path.as_ptr(), flags) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a newly opened valid file descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };

    let st = fstat_fd(&owned)?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFCHR {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target is not a character device",
        ));
    }
    Ok(File::from(owned))
}
