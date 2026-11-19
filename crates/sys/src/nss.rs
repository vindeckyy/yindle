//! Reentrant NSS lookups (`getgrnam_r`, `getpwnam_r`, `getpwuid_r`,
//! `getgrgid_r`, `getgrouplist`) and hardened shadow password verification
//! (`getspnam_r` + dynamically resolved `crypt_r`).

use std::ffi::{CStr, CString};
use std::io;
use std::ptr;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Initial scratch buffer size for reentrant `*_r` NSS calls.
const INITIAL_BUF_LEN: usize = 1024;
/// Upper bound on dynamic `ERANGE` buffer growth (4 MiB).
const MAX_BUF_LEN: usize = 4 * 1024 * 1024;
/// Size of our heap-allocated `crypt_data` workspace in `u64` words (256 KiB).
/// Comfortably exceeds glibc (~131 KiB), libxcrypt (32 KiB), and musl (260 B).
const CRYPT_DATA_WORDS: usize = 32_768;

/// Valid SHA-512 crypt setting used to equalize timing when a user is unknown,
/// locked, expired, or `/etc/shadow` cannot be read.
const DUMMY_SHADOW_HASH: &CStr = c"$6$yindledummy00001$5nQ8xK2vR9mL4pW7jT1yC6bH3fD0sA8eG2kN5uV9wX1zM4qP7rS0tB3vY6nJ8cL2mK5pQ8rT1wX4yZ7aB0cD1eF/";

/// Function signature of `crypt_r(3)`.
type CryptRFn = unsafe extern "C" fn(
    key: *const libc::c_char,
    salt: *const libc::c_char,
    data: *mut libc::c_void,
) -> *mut libc::c_char;

/// Cached dynamic lookup result for `crypt_r`.
/// The `dlopen` handle is intentionally leaked for process lifetime so the
/// resolved function pointer remains valid across all threads.
static CRYPT_R_SYM: OnceLock<Option<CryptRFn>> = OnceLock::new();

/// Resolve `sym_name` by probing each library in `candidates` via `dlopen`,
/// then falling back to `RTLD_DEFAULT` (covers musl / static / preloaded libc).
pub(crate) fn resolve_sym_dynamic(
    candidates: &[&CStr],
    sym_name: &CStr,
) -> Option<*mut libc::c_void> {
    for lib in candidates {
        // SAFETY: `lib` and `sym_name` are valid NUL-terminated C strings.
        // On success, the library handle is intentionally retained for the
        // lifetime of the process so the returned symbol pointer stays valid.
        unsafe {
            let handle = libc::dlopen(lib.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
            if handle.is_null() {
                continue;
            }
            let ptr = libc::dlsym(handle, sym_name.as_ptr());
            if !ptr.is_null() {
                return Some(ptr);
            }
            libc::dlclose(handle);
        }
    }

    // Fallback for musl / static libc / preloaded environments.
    // SAFETY: `RTLD_DEFAULT` and `sym_name` are valid arguments to `dlsym`.
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, sym_name.as_ptr()) };
    if ptr.is_null() {
        None
    } else {
        Some(ptr)
    }
}

/// Resolve `crypt_r` dynamically at runtime without linking a hardcoded soname.
/// Search order: `libcrypt.so.2` -> `libcrypt.so.1` -> `libcrypt.so` -> `RTLD_DEFAULT`.
fn resolve_crypt_r() -> Option<CryptRFn> {
    *CRYPT_R_SYM.get_or_init(|| {
        const CANDIDATES: &[&CStr] = &[c"libcrypt.so.2", c"libcrypt.so.1", c"libcrypt.so"];
        let ptr = resolve_sym_dynamic(CANDIDATES, c"crypt_r")?;
        // SAFETY: `crypt_r` matches the C ABI signature `CryptRFn`.
        Some(unsafe { std::mem::transmute::<*mut libc::c_void, CryptRFn>(ptr) })
    })
}

/// Zeroize a byte slice using volatile writes so the compiler cannot elide it.
pub(crate) fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf {
        // SAFETY: `b` is a valid, aligned, mutable reference to a `u8`.
        unsafe {
            ptr::write_volatile(b, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Zeroize a `u64` slice using volatile writes.
fn zeroize_words(buf: &mut [u64]) {
    for w in buf {
        // SAFETY: `w` is a valid, aligned, mutable reference to a `u64`.
        unsafe {
            ptr::write_volatile(w, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Constant-time byte-slice equality check (evaluates every byte even when
/// lengths differ, avoiding early-exit timing side channels).
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let ba = if i < a.len() { a[i] } else { 0 };
        let bb = if i < b.len() { b[i] } else { 0 };
        diff |= usize::from(ba ^ bb);
    }
    std::hint::black_box(diff) == 0
}

/// Compute a password hash using dynamically resolved reentrant `crypt_r`.
///
/// Returns `None` if `crypt_r` is unavailable, inputs contain interior NULs,
/// or `crypt_r` rejects the setting/salt (returns `NULL` or an error token
/// starting with `*`).
#[must_use]
pub fn crypt_r_hash(password: &str, setting: &str) -> Option<String> {
    let crypt_fn = resolve_crypt_r()?;
    let c_pass = CString::new(password).ok()?;
    let c_salt = CString::new(setting).ok()?;
    crypt_r_cstr(crypt_fn, &c_pass, &c_salt)
}

fn crypt_r_cstr(crypt_fn: CryptRFn, c_pass: &CStr, c_salt: &CStr) -> Option<String> {
    // Heap-allocate zeroed, 8-byte aligned storage for `struct crypt_data`
    // (`initialized == 0` in all implementations).
    let mut data: Vec<u64> = vec![0u64; CRYPT_DATA_WORDS];
    // SAFETY: `c_pass` and `c_salt` are NUL-terminated C strings; `data` is a
    // zeroed, 8-byte-aligned 256 KiB buffer larger than `struct crypt_data` on
    // glibc, libxcrypt, and musl; `crypt_fn` is the resolved `crypt_r` symbol.
    let res = unsafe {
        let ptr = crypt_fn(
            c_pass.as_ptr(),
            c_salt.as_ptr(),
            data.as_mut_ptr().cast::<libc::c_void>(),
        );
        if ptr.is_null() {
            None
        } else {
            let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            // libxcrypt returns "*0" or "*1" on malformed salt rather than NULL.
            if s.is_empty() || s.starts_with('*') {
                None
            } else {
                Some(s)
            }
        }
    };
    zeroize_words(&mut data);
    res
}

/// Check if an error code / `errno` indicates `ERANGE`.
fn is_erange(rc: libc::c_int) -> bool {
    rc == libc::ERANGE
        || (rc != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ERANGE))
}

/// Look up a group id by name using reentrant `getgrnam_r` with dynamic
/// `ERANGE` buffer growth.
///
/// Returns `None` if the group does not exist or lookup fails.
#[must_use]
pub fn gid_of(name: &str) -> Option<u32> {
    gid_of_with_buf(name, INITIAL_BUF_LEN)
}

pub(crate) fn gid_of_with_buf(name: &str, initial_buf_len: usize) -> Option<u32> {
    let c = CString::new(name).ok()?;
    let mut buf_len = initial_buf_len.max(1);
    loop {
        let mut buf = vec![0u8; buf_len];
        // SAFETY: `libc::group` is a plain C POD struct.
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = ptr::null_mut();
        // SAFETY: `c` is a valid C string; `grp`, `buf`, and `result` are valid
        // caller-owned out-parameters for `getgrnam_r`.
        let rc = unsafe {
            libc::getgrnam_r(
                c.as_ptr(),
                &raw mut grp,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &raw mut result,
            )
        };
        if rc == 0 {
            return if result.is_null() {
                None
            } else {
                Some(grp.gr_gid)
            };
        }
        if is_erange(rc) && buf_len < MAX_BUF_LEN {
            buf_len = (buf_len.saturating_mul(2)).min(MAX_BUF_LEN);
            continue;
        }
        return None;
    }
}

/// Look up a group name by id using reentrant `getgrgid_r` with dynamic
/// `ERANGE` buffer growth.
#[must_use]
pub fn group_name_of_gid(gid: u32) -> Option<String> {
    group_name_of_gid_with_buf(gid, INITIAL_BUF_LEN)
}

pub(crate) fn group_name_of_gid_with_buf(gid: u32, initial_buf_len: usize) -> Option<String> {
    let mut buf_len = initial_buf_len.max(1);
    loop {
        let mut buf = vec![0u8; buf_len];
        // SAFETY: `libc::group` is a plain C POD struct.
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = ptr::null_mut();
        // SAFETY: `grp`, `buf`, and `result` are valid caller-owned buffers for `getgrgid_r`.
        let rc = unsafe {
            libc::getgrgid_r(
                gid,
                &raw mut grp,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &raw mut result,
            )
        };
        if rc == 0 {
            if result.is_null() || grp.gr_name.is_null() {
                return None;
            }
            // SAFETY: `getgrgid_r` succeeded with non-null `result`, so `grp.gr_name`
            // points to a valid NUL-terminated string inside `buf`.
            return Some(unsafe { CStr::from_ptr(grp.gr_name).to_string_lossy().into_owned() });
        }
        if is_erange(rc) && buf_len < MAX_BUF_LEN {
            buf_len = (buf_len.saturating_mul(2)).min(MAX_BUF_LEN);
            continue;
        }
        return None;
    }
}

/// Look up `(uid, gid)` for a username using reentrant `getpwnam_r`.
pub(crate) fn passwd_ids_of_with_buf(name: &str, initial_buf_len: usize) -> Option<(u32, u32)> {
    let c = CString::new(name).ok()?;
    let mut buf_len = initial_buf_len.max(1);
    loop {
        let mut buf = vec![0u8; buf_len];
        // SAFETY: `libc::passwd` is a plain C POD struct.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = ptr::null_mut();
        // SAFETY: `c` is a valid C string; `pwd`, `buf`, and `result` are valid
        // caller-owned out-parameters for `getpwnam_r`.
        let rc = unsafe {
            libc::getpwnam_r(
                c.as_ptr(),
                &raw mut pwd,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &raw mut result,
            )
        };
        if rc == 0 {
            return if result.is_null() {
                None
            } else {
                Some((pwd.pw_uid, pwd.pw_gid))
            };
        }
        if is_erange(rc) && buf_len < MAX_BUF_LEN {
            buf_len = (buf_len.saturating_mul(2)).min(MAX_BUF_LEN);
            continue;
        }
        return None;
    }
}

/// Look up a user id by name using reentrant `getpwnam_r` with dynamic
/// `ERANGE` buffer growth.
///
/// Returns `None` if the user does not exist or lookup fails.
#[must_use]
pub fn uid_of(name: &str) -> Option<u32> {
    passwd_ids_of_with_buf(name, INITIAL_BUF_LEN).map(|(uid, _)| uid)
}

/// Look up a user's primary group id by username using reentrant `getpwnam_r`.
#[must_use]
pub fn user_primary_gid(name: &str) -> Option<u32> {
    passwd_ids_of_with_buf(name, INITIAL_BUF_LEN).map(|(_, gid)| gid)
}

/// Look up a user name by id using reentrant `getpwuid_r` with dynamic
/// `ERANGE` buffer growth.
#[must_use]
pub fn name_of_uid(uid: u32) -> Option<String> {
    name_of_uid_with_buf(uid, INITIAL_BUF_LEN)
}

pub(crate) fn name_of_uid_with_buf(uid: u32, initial_buf_len: usize) -> Option<String> {
    let mut buf_len = initial_buf_len.max(1);
    loop {
        let mut buf = vec![0u8; buf_len];
        // SAFETY: `libc::passwd` is a plain C POD struct.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = ptr::null_mut();
        // SAFETY: `pwd`, `buf`, and `result` are valid caller-owned buffers for `getpwuid_r`.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &raw mut pwd,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &raw mut result,
            )
        };
        if rc == 0 {
            if result.is_null() || pwd.pw_name.is_null() {
                return None;
            }
            // SAFETY: `getpwuid_r` succeeded with non-null `result`, so `pwd.pw_name`
            // points to a valid NUL-terminated string inside `buf`.
            return Some(unsafe { CStr::from_ptr(pwd.pw_name).to_string_lossy().into_owned() });
        }
        if is_erange(rc) && buf_len < MAX_BUF_LEN {
            buf_len = (buf_len.saturating_mul(2)).min(MAX_BUF_LEN);
            continue;
        }
        return None;
    }
}

/// Group names a user belongs to (`getpwnam_r` + `getgrouplist` + `getgrgid_r`).
///
/// Fully thread-safe: uses no non-reentrant static NSS buffers.
#[must_use]
pub fn groups_of(user: &str) -> Vec<String> {
    groups_of_with_cap(user, 16)
}

pub(crate) fn groups_of_with_cap(user: &str, initial_cap: libc::c_int) -> Vec<String> {
    let Ok(c) = CString::new(user) else {
        return Vec::new();
    };
    let Some((_, primary_gid)) = passwd_ids_of_with_buf(user, INITIAL_BUF_LEN) else {
        return Vec::new();
    };

    let mut ngroups: libc::c_int = initial_cap.max(0);
    let mut gids = vec![0 as libc::gid_t; usize::try_from(ngroups).unwrap_or(0)];

    // Retry if the user belongs to more groups than the current capacity.
    for _ in 0..4 {
        let mut count = ngroups;
        // SAFETY: `c` is a valid C string; `gids` has room for `count` entries.
        let rc = unsafe {
            libc::getgrouplist(c.as_ptr(), primary_gid, gids.as_mut_ptr(), &raw mut count)
        };
        if rc >= 0 {
            let n = usize::try_from(count.max(0)).unwrap_or(0).min(gids.len());
            gids.truncate(n);
            return gids.into_iter().filter_map(group_name_of_gid).collect();
        }
        if count <= 0 || count > 65_536 {
            return Vec::new();
        }
        ngroups = count;
        gids.resize(usize::try_from(count).unwrap_or(0), 0);
    }
    Vec::new()
}

/// Validate a shadow password hash string and shadow expiry fields (`shadow(5)`).
///
/// Rejects:
/// - Empty hashes (passwordless accounts)
/// - Locked/disabled hashes starting with `!` or `*` (e.g., `!`, `!!`, `*`, `*LK*`, `!$6$...`)
/// - Placeholder `"x"`
/// - Accounts whose `sp_expire` date (`>= 0`) is on or before `today_days`
/// - Accounts forced to change password (`sp_lstchg == 0`)
/// - Accounts expired via password max-age + inactivity (`sp_lstchg > 0 && sp_max >= 0 && sp_inact >= 0 && today_days > sp_lstchg + sp_max + sp_inact`)
#[must_use]
pub fn is_shadow_entry_usable(
    pwdp: &str,
    lstchg: i64,
    max: i64,
    inact: i64,
    expire: i64,
    today_days: i64,
) -> bool {
    if pwdp.is_empty()
        || pwdp == "x"
        || pwdp.starts_with('!')
        || pwdp.starts_with('*')
        || (!pwdp.starts_with('$') && pwdp.len() < 13)
    {
        return false;
    }
    // Account expiration (`sp_expire` is days since 1970-01-01; -1 = never expires).
    if expire >= 0 && today_days >= expire {
        return false;
    }
    // Forced password change on next login (`sp_lstchg == 0`).
    if lstchg == 0 {
        return false;
    }
    // Inactivity lock after password max age.
    if lstchg > 0 && max >= 0 && inact >= 0 {
        let deadline = lstchg.saturating_add(max).saturating_add(inact);
        if today_days > deadline {
            return false;
        }
    }
    true
}

/// Current UTC day number since 1970-01-01 (matches `shadow(5)` day fields).
fn current_epoch_days() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    i64::try_from(secs / 86_400).unwrap_or(i64::MAX)
}

/// Reentrant `getspnam_r` lookup returning owned shadow metadata, zeroizing
/// the scratch buffer before returning.
#[cfg(target_os = "linux")]
pub(crate) struct ShadowEntry {
    pub(crate) pwdp: String,
    pub(crate) lstchg: i64,
    pub(crate) max: i64,
    pub(crate) inact: i64,
    pub(crate) expire: i64,
}

#[cfg(target_os = "linux")]
impl Drop for ShadowEntry {
    fn drop(&mut self) {
        // SAFETY: clearing the underlying UTF-8 bytes to all-zero (valid UTF-8 NULs)
        // before the `String` is deallocated.
        unsafe {
            zeroize_bytes(self.pwdp.as_bytes_mut());
        }
    }
}

#[cfg(target_os = "linux")]
fn lookup_shadow_with_buf(user: &CStr, initial_buf_len: usize) -> Option<ShadowEntry> {
    let mut buf_len = initial_buf_len.max(1);
    loop {
        let mut buf = vec![0u8; buf_len];
        // SAFETY: `libc::spwd` is a plain C POD struct.
        let mut sp: libc::spwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::spwd = ptr::null_mut();
        // SAFETY: `user` is a valid C string; `sp`, `buf`, and `result` are valid
        // caller-owned out-parameters for `getspnam_r`.
        let rc = unsafe {
            libc::getspnam_r(
                user.as_ptr(),
                &raw mut sp,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &raw mut result,
            )
        };
        if rc == 0 {
            let out = if result.is_null() || sp.sp_pwdp.is_null() {
                None
            } else {
                // SAFETY: `getspnam_r` succeeded with non-null `result` and `sp.sp_pwdp`,
                // pointing to a valid NUL-terminated string within `buf`.
                let pwdp = unsafe { CStr::from_ptr(sp.sp_pwdp).to_string_lossy().into_owned() };
                #[allow(clippy::unnecessary_cast)]
                Some(ShadowEntry {
                    pwdp,
                    lstchg: sp.sp_lstchg as i64,
                    max: sp.sp_max as i64,
                    inact: sp.sp_inact as i64,
                    expire: sp.sp_expire as i64,
                })
            };
            zeroize_bytes(&mut buf);
            return out;
        }
        zeroize_bytes(&mut buf);
        if is_erange(rc) && buf_len < MAX_BUF_LEN {
            buf_len = (buf_len.saturating_mul(2)).min(MAX_BUF_LEN);
            continue;
        }
        return None;
    }
}

/// Verify `pass` against an already-fetched optional `ShadowEntry` at day `today`.
/// Always runs `crypt_r` (with a dummy SHA-512 setting when entry is absent or
/// unusable) and compares hashes in constant time.
#[cfg(target_os = "linux")]
pub(crate) fn verify_shadow_entry(entry: Option<ShadowEntry>, pass: &str, today: i64) -> bool {
    let Some(crypt_fn) = resolve_crypt_r() else {
        return false;
    };
    let dummy_salt = DUMMY_SHADOW_HASH;
    let Ok(cp) = CString::new(pass) else {
        let _ = crypt_r_cstr(crypt_fn, c"", dummy_salt);
        return false;
    };

    let Some(entry) = entry else {
        let _ = crypt_r_cstr(crypt_fn, &cp, dummy_salt);
        return false;
    };

    let usable = !pass.is_empty()
        && is_shadow_entry_usable(
            &entry.pwdp,
            entry.lstchg,
            entry.max,
            entry.inact,
            entry.expire,
            today,
        );

    if !usable {
        let _ = crypt_r_cstr(crypt_fn, &cp, dummy_salt);
        return false;
    }

    let Ok(stored_cstr) = CString::new(entry.pwdp.as_str()) else {
        let _ = crypt_r_cstr(crypt_fn, &cp, dummy_salt);
        return false;
    };

    let Some(mut hashed) = crypt_r_cstr(crypt_fn, &cp, &stored_cstr) else {
        return false;
    };
    let matched = constant_time_eq(hashed.as_bytes(), entry.pwdp.as_bytes());
    // SAFETY: clearing the hash string bytes to zero before drop.
    unsafe {
        zeroize_bytes(hashed.as_bytes_mut());
    }
    matched
}

/// Verify a local password against `/etc/shadow` using reentrant `getspnam_r`
/// and dynamically resolved `crypt_r`.
///
/// Security properties:
/// - Rejects empty/locked (`!`, `*`, `!!`) and expired accounts (`sp_expire`, etc.).
/// - Always executes `crypt_r` (using a dummy SHA-512 setting when the user is
///   unknown, locked, expired, or `/etc/shadow` is unreadable) so callers cannot
///   enumerate valid usernames via response timing.
/// - Compares password hashes in constant time.
#[must_use]
pub fn check_password(user: &str, pass: &str) -> bool {
    let today = current_epoch_days();
    #[cfg(target_os = "linux")]
    let entry = CString::new(user)
        .ok()
        .and_then(|cu| lookup_shadow_with_buf(&cu, INITIAL_BUF_LEN));
    #[cfg(target_os = "linux")]
    {
        verify_shadow_entry(entry, pass, today)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (user, pass, today);
        false
    }
}
