//! systemd integration (`sd_listen_fds`, `sd_notify`) and POSIX `gethostname`.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Set `FD_CLOEXEC` on `fd`. Returns `true` if `fd` was valid and updated.
pub(crate) fn set_cloexec(fd: RawFd) -> bool {
    // SAFETY: `fcntl(F_GETFD)` and `fcntl(F_SETFD)` on any fd fail harmlessly
    // with `EBADF` if closed and otherwise only toggle the close-on-exec flag.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 {
            return false;
        }
        libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) == 0
    }
}

/// Adopt `count` consecutive descriptors starting at `base_fd`, setting
/// `FD_CLOEXEC` on each valid fd before wrapping it in `OwnedFd`.
pub(crate) fn adopt_listen_fds(base_fd: RawFd, count: i32) -> Vec<OwnedFd> {
    let clamped = count.clamp(0, 4096);
    let mut out = Vec::with_capacity(usize::try_from(clamped).unwrap_or(0));
    for i in 0..clamped {
        let fd = base_fd + i;
        if !set_cloexec(fd) {
            continue;
        }
        // SAFETY: `fd` is verified open via `fcntl(F_GETFD)` above and owned
        // exclusively by this activation handoff.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        out.push(owned);
    }
    out
}

/// systemd socket activation (`sd_listen_fds(3)`): when `LISTEN_PID`
/// equals our pid and `LISTEN_FDS` is set, systemd has passed pre-bound
/// listener sockets on fds `3..=3+N-1`.
///
/// Marks every adopted descriptor `FD_CLOEXEC` and unsets `LISTEN_PID`,
/// `LISTEN_FDS`, and `LISTEN_FDNAMES` so inherited descriptors and activation
/// variables never leak into child processes (filters/backends/CGIs).
///
/// Call once during single-threaded startup before spawning worker threads.
#[must_use]
pub fn sd_listen_fds() -> Vec<OwnedFd> {
    let pid_ok = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|p| p.parse::<u32>().ok())
        .is_some_and(|p| p == std::process::id());
    let n: i32 = if pid_ok {
        std::env::var("LISTEN_FDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
            .max(0)
    } else {
        0
    };

    // Always clear activation variables when present (matches `sd_listen_fds(1)`).
    if std::env::var_os("LISTEN_PID").is_some() {
        std::env::remove_var("LISTEN_PID");
    }
    if std::env::var_os("LISTEN_FDS").is_some() {
        std::env::remove_var("LISTEN_FDS");
    }
    if std::env::var_os("LISTEN_FDNAMES").is_some() {
        std::env::remove_var("LISTEN_FDNAMES");
    }

    if !pid_ok || n <= 0 {
        return Vec::new();
    }
    adopt_listen_fds(3, n)
}

/// Notify systemd of daemon readiness/reloading/watchdog state via
/// `$NOTIFY_SOCKET` (supports filesystem `/...` and Linux abstract `@...`
/// datagram sockets).
///
/// Returns `Ok(true)` if the datagram was sent, `Ok(false)` if `NOTIFY_SOCKET`
/// is unset/empty, or `Err` on socket/send failure.
pub fn sd_notify(state: &str) -> io::Result<bool> {
    sd_notify_unset_env(state, false)
}

/// Like [`sd_notify`], optionally unsetting `NOTIFY_SOCKET` afterwards
/// (matching `sd_notify(unset_environment, state)`).
pub fn sd_notify_unset_env(state: &str, unset_env: bool) -> io::Result<bool> {
    let sock_path = std::env::var("NOTIFY_SOCKET").ok();
    if unset_env && sock_path.is_some() {
        std::env::remove_var("NOTIFY_SOCKET");
    }
    let Some(path) = sock_path else {
        return Ok(false);
    };
    if path.is_empty() || state.is_empty() {
        return Ok(false);
    }
    sd_notify_to_socket(&path, state).map(|()| true)
}

/// Send a raw `sd_notify` datagram to a specific Unix datagram address
/// (`/...` filesystem path or `@...` Linux abstract socket name).
pub fn sd_notify_to_socket(socket_path: &str, state: &str) -> io::Result<()> {
    let path_bytes = socket_path.as_bytes();
    let is_abstract = path_bytes.first() == Some(&b'@');
    let is_fs = path_bytes.first() == Some(&b'/');
    if (!is_abstract && !is_fs) || path_bytes.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET must start with '/' or '@' and be non-empty",
        ));
    }

    // SAFETY: `sockaddr_un` is a plain POD struct.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = u16::try_from(libc::AF_UNIX).unwrap_or(1);

    let max_path = addr.sun_path.len();
    // Filesystem paths need a trailing NUL byte; abstract names do not.
    if (is_fs && path_bytes.len() >= max_path) || (is_abstract && path_bytes.len() > max_path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET path exceeds sockaddr_un capacity",
        ));
    }

    for (idx, (dst, &src)) in addr.sun_path.iter_mut().zip(path_bytes.iter()).enumerate() {
        *dst = if is_abstract && idx == 0 {
            0
        } else {
            // Cast u8 -> c_char bit-for-bit across signed/unsigned c_char platforms.
            #[allow(clippy::cast_possible_wrap)]
            {
                src as libc::c_char
            }
        };
    }

    let sun_path_offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    let addr_len = if is_abstract {
        sun_path_offset + path_bytes.len()
    } else {
        sun_path_offset + path_bytes.len() + 1
    };
    let socklen = libc::socklen_t::try_from(addr_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socklen overflow"))?;

    // SAFETY: creates a fresh datagram Unix socket with `SOCK_CLOEXEC`.
    let raw_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw_fd` is a newly created valid file descriptor.
    let sock = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let payload = state.as_bytes();
    // SAFETY: `sock` is a valid datagram socket, `payload` is a valid buffer,
    // and `addr` is properly initialized for `socklen` bytes.
    let sent = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            payload.as_ptr().cast::<libc::c_void>(),
            payload.len(),
            libc::MSG_NOSIGNAL,
            (&raw const addr).cast::<libc::sockaddr>(),
            socklen,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Return the system hostname via POSIX `gethostname(2)`.
#[must_use]
pub fn gethostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is a valid writable 256-byte buffer; we pass `len - 1` so
    // the trailing byte stays NUL even on truncation.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast::<libc::c_char>(), buf.len() - 1) };
    if rc != 0 {
        return None;
    }
    buf[buf.len() - 1] = 0;
    // SAFETY: `buf` is guaranteed NUL-terminated.
    let name = unsafe { CStr::from_ptr(buf.as_ptr().cast::<libc::c_char>()) }
        .to_string_lossy()
        .into_owned();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}
