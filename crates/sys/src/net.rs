//! Socket credential/family queries and local interface IP/subnet enumeration
//! via `getifaddrs(3)` (for `@LOCAL` and `@IF(name)` ACL matching).

use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;
use std::ptr;

/// A local network interface address & netmask discovered via `getifaddrs(3)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalInterface {
    /// Interface name (e.g. `"lo"`, `"eth0"`, `"wlan0"`).
    pub name: String,
    /// Interface IP address.
    pub addr: IpAddr,
    /// Associated subnet mask, if reported by the kernel.
    pub netmask: Option<IpAddr>,
    /// True if `IFF_LOOPBACK` is set.
    pub is_loopback: bool,
    /// True if `IFF_UP` is set.
    pub is_up: bool,
}

/// Convert a `sockaddr` pointer (`AF_INET` or `AF_INET6`) to `IpAddr`.
unsafe fn sockaddr_to_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: `sa` was verified non-null and comes from `getifaddrs(3)`.
    let family = i32::from(unsafe { (*sa).sa_family });
    if family == libc::AF_INET {
        // SAFETY: `AF_INET` guarantees `sa` points to a valid `sockaddr_in`.
        let sin = unsafe { &*(sa.cast::<libc::sockaddr_in>()) };
        Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
            sin.sin_addr.s_addr,
        ))))
    } else if family == libc::AF_INET6 {
        // SAFETY: `AF_INET6` guarantees `sa` points to a valid `sockaddr_in6`.
        let sin6 = unsafe { &*(sa.cast::<libc::sockaddr_in6>()) };
        Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
    } else {
        None
    }
}

/// RAII guard for `getifaddrs(3)` list freeing.
struct IfAddrsGuard(*mut libc::ifaddrs);

impl Drop for IfAddrsGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by `getifaddrs(3)`.
            unsafe {
                libc::freeifaddrs(self.0);
            }
        }
    }
}

/// Enumerate all local IPv4 and IPv6 interface addresses and subnet masks via
/// `getifaddrs(3)`.
#[must_use]
pub fn local_interfaces() -> Vec<LocalInterface> {
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: `head` is a valid out-pointer for `getifaddrs(3)`.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 || head.is_null() {
        return Vec::new();
    }
    let _guard = IfAddrsGuard(head);

    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` walks a valid linked list returned by `getifaddrs(3)`.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_name.is_null() {
            // SAFETY: `ifa.ifa_addr` is checked for null inside `sockaddr_to_ip`.
            if let Some(addr) = unsafe { sockaddr_to_ip(ifa.ifa_addr) } {
                // SAFETY: `ifa.ifa_name` is a NUL-terminated kernel interface name.
                let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
                    .to_string_lossy()
                    .into_owned();
                // SAFETY: `ifa.ifa_netmask` is checked for null inside `sockaddr_to_ip`.
                let netmask = unsafe { sockaddr_to_ip(ifa.ifa_netmask) };
                let flags = ifa.ifa_flags;
                let is_loopback = (flags & u32::try_from(libc::IFF_LOOPBACK).unwrap_or(0)) != 0;
                let is_up = (flags & u32::try_from(libc::IFF_UP).unwrap_or(0)) != 0;
                out.push(LocalInterface {
                    name,
                    addr,
                    netmask,
                    is_loopback,
                    is_up,
                });
            }
        }
        cur = ifa.ifa_next;
    }
    out
}

/// `SO_PEERCRED` on an `AF_UNIX` stream socket — the `(pid, uid, gid)` of
/// the connected peer, the `cupsdAuthorize`/`PeerCred` path that lets local
/// clients authenticate as their real user without a password.
/// Returns `None` when the socket is not `AF_UNIX` or `getsockopt` fails.
#[must_use]
pub fn peer_cred(fd: RawFd) -> Option<(i32, u32, u32)> {
    // SAFETY: `ucred` is a plain POD; all-zero is a valid bit pattern.
    let mut uc: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .unwrap_or(libc::socklen_t::MAX);
    // SAFETY: `uc`/`len` are valid out-params; `fd` may be any fd.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut uc).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc == 0 {
        Some((uc.pid, uc.uid, uc.gid))
    } else {
        None
    }
}

/// `getsockname(2)` `sa_family` for an fd — `AF_UNIX` vs `AF_INET`/`AF_INET6`.
/// Returns the family constant, or `-1` on error.
#[must_use]
pub fn socket_family(fd: RawFd) -> i32 {
    // SAFETY: `sockaddr_storage` is a plain POD; all-zero is a valid pattern.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>())
        .unwrap_or(libc::socklen_t::MAX);
    // SAFETY: `ss`/`len` are valid out-params; `fd` may be any fd.
    let rc = unsafe { libc::getsockname(fd, (&raw mut ss).cast::<libc::sockaddr>(), &raw mut len) };
    if rc == 0 {
        i32::from(ss.ss_family)
    } else {
        -1
    }
}
