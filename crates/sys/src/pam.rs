//! Runtime-loaded PAM authentication via `dlopen("libpam.so.0")`.
//!
//! No compile-time dependency on `libpam-dev` is required. When `libpam.so.0`
//! (or `libpam.so`) is absent, calls cleanly return `PamOutcome::Unavailable`
//! so callers can decide whether to fall back to local shadow verification or
//! fail closed.

use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::OnceLock;

use crate::nss::zeroize_bytes;

// Linux-PAM constants (`<security/_pam_types.h>`).
const PAM_SUCCESS: libc::c_int = 0;
const PAM_BUF_ERR: libc::c_int = 5;
const PAM_CONV_ERR: libc::c_int = 19;

pub(crate) const PAM_PROMPT_ECHO_OFF: libc::c_int = 1;
pub(crate) const PAM_PROMPT_ECHO_ON: libc::c_int = 2;
pub(crate) const PAM_ERROR_MSG: libc::c_int = 3;
pub(crate) const PAM_TEXT_INFO: libc::c_int = 4;

const PAM_SILENT: libc::c_int = 0x8000;
const PAM_DISALLOW_NULL_AUTHTOK: libc::c_int = 0x0001;

/// Opaque PAM handle.
#[repr(C)]
pub(crate) struct PamHandle {
    _opaque: [u8; 0],
}

/// `struct pam_message`.
#[repr(C)]
pub(crate) struct PamMessage {
    pub(crate) msg_style: libc::c_int,
    pub(crate) msg: *const libc::c_char,
}

/// `struct pam_response`.
#[repr(C)]
pub(crate) struct PamResponse {
    pub(crate) resp: *mut libc::c_char,
    pub(crate) resp_retcode: libc::c_int,
}

type PamConvFn = unsafe extern "C" fn(
    num_msg: libc::c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut libc::c_void,
) -> libc::c_int;

/// `struct pam_conv`.
#[repr(C)]
pub(crate) struct PamConv {
    pub(crate) conv: Option<PamConvFn>,
    pub(crate) appdata_ptr: *mut libc::c_void,
}

type PamStartFn = unsafe extern "C" fn(
    service_name: *const libc::c_char,
    user: *const libc::c_char,
    pam_conversation: *const PamConv,
    pamh: *mut *mut PamHandle,
) -> libc::c_int;

type PamAuthenticateFn =
    unsafe extern "C" fn(pamh: *mut PamHandle, flags: libc::c_int) -> libc::c_int;

type PamAcctMgmtFn = unsafe extern "C" fn(pamh: *mut PamHandle, flags: libc::c_int) -> libc::c_int;

type PamEndFn = unsafe extern "C" fn(pamh: *mut PamHandle, pam_status: libc::c_int) -> libc::c_int;

#[derive(Clone, Copy)]
pub(crate) struct PamApi {
    pub(crate) start: PamStartFn,
    pub(crate) authenticate: PamAuthenticateFn,
    pub(crate) acct_mgmt: PamAcctMgmtFn,
    pub(crate) end: PamEndFn,
}

static PAM_API: OnceLock<Option<PamApi>> = OnceLock::new();

pub(crate) fn load_pam_from(candidates: &[&CStr]) -> Option<PamApi> {
    for lib in candidates {
        // SAFETY: `lib` and symbol names are valid NUL-terminated C strings.
        // On success, the library handle is intentionally kept loaded for the
        // process lifetime so function pointers remain valid across threads.
        unsafe {
            let handle = libc::dlopen(lib.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
            if handle.is_null() {
                continue;
            }
            let p_start = libc::dlsym(handle, c"pam_start".as_ptr());
            let p_auth = libc::dlsym(handle, c"pam_authenticate".as_ptr());
            let p_acct = libc::dlsym(handle, c"pam_acct_mgmt".as_ptr());
            let p_end = libc::dlsym(handle, c"pam_end".as_ptr());
            if !p_start.is_null() && !p_auth.is_null() && !p_acct.is_null() && !p_end.is_null() {
                return Some(PamApi {
                    start: std::mem::transmute::<*mut libc::c_void, PamStartFn>(p_start),
                    authenticate: std::mem::transmute::<*mut libc::c_void, PamAuthenticateFn>(
                        p_auth,
                    ),
                    acct_mgmt: std::mem::transmute::<*mut libc::c_void, PamAcctMgmtFn>(p_acct),
                    end: std::mem::transmute::<*mut libc::c_void, PamEndFn>(p_end),
                });
            }
            libc::dlclose(handle);
        }
    }
    None
}

fn load_pam_api() -> Option<PamApi> {
    *PAM_API.get_or_init(|| load_pam_from(&[c"libpam.so.0", c"libpam.so"]))
}

/// Outcome of a PAM authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PamOutcome {
    /// Both `pam_authenticate` and `pam_acct_mgmt` returned `PAM_SUCCESS`.
    Authenticated,
    /// PAM was available and rejected authentication or account validity
    /// with the given PAM return code.
    Denied(i32),
    /// `libpam.so.0` could not be loaded on this system.
    Unavailable,
}

/// Returns `true` if `libpam.so.0` (or `libpam.so`) is dynamically loadable.
#[must_use]
pub fn pam_available() -> bool {
    load_pam_api().is_some()
}

/// Application data passed into the PAM conversation callback.
pub(crate) struct ConvData {
    user: Vec<u8>,
    pass: Vec<u8>,
}

impl ConvData {
    pub(crate) fn new(user: &CStr, pass: &CStr) -> Self {
        Self {
            user: user.to_bytes_with_nul().to_vec(),
            pass: pass.to_bytes_with_nul().to_vec(),
        }
    }
}

impl Drop for ConvData {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.pass);
        zeroize_bytes(&mut self.user);
    }
}

/// Allocate a NUL-terminated copy using C `malloc` because Linux-PAM frees
/// every non-null `pam_response.resp` with C `free(3)`.
unsafe fn c_dup_bytes(bytes_with_nul: &[u8]) -> *mut libc::c_char {
    // SAFETY: caller ensures `bytes_with_nul` ends with NUL; `libc::malloc`
    // returns either NULL or a valid allocation of `bytes_with_nul.len()` bytes.
    let ptr = unsafe { libc::malloc(bytes_with_nul.len()) };
    if ptr.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ptr` is freshly allocated for `bytes_with_nul.len()` bytes and
    // non-overlapping with `bytes_with_nul`.
    unsafe {
        ptr::copy_nonoverlapping(
            bytes_with_nul.as_ptr(),
            ptr.cast::<u8>(),
            bytes_with_nul.len(),
        );
    }
    ptr.cast::<libc::c_char>()
}

/// PAM conversation callback feeding username/password non-interactively.
pub(crate) unsafe extern "C" fn pam_conv_cb(
    num_msg: libc::c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut libc::c_void,
) -> libc::c_int {
    if num_msg <= 0 || msg.is_null() || resp.is_null() || appdata_ptr.is_null() {
        return PAM_CONV_ERR;
    }
    let Ok(count) = usize::try_from(num_msg) else {
        return PAM_CONV_ERR;
    };
    // Cap to avoid absurd allocations from a misbehaving module.
    if count > 128 {
        return PAM_CONV_ERR;
    }

    // SAFETY: `appdata_ptr` points to a live `ConvData` for the duration of
    // `pam_authenticate`/`pam_acct_mgmt`.
    let data = unsafe { &*appdata_ptr.cast::<ConvData>() };

    // SAFETY: `calloc` allocates `count` zeroed `PamResponse` entries using the
    // C allocator as required by the Linux-PAM ABI (`pam_end`/module calls `free`).
    let out =
        unsafe { libc::calloc(count, std::mem::size_of::<PamResponse>()) }.cast::<PamResponse>();
    if out.is_null() {
        return PAM_BUF_ERR;
    }

    for i in 0..count {
        // SAFETY: `msg` points to an array of `count` `*const PamMessage` pointers.
        let m_ptr = unsafe { *msg.add(i) };
        if m_ptr.is_null() {
            // SAFETY: freeing `out` and any previously allocated responses.
            unsafe { free_responses(out, i) };
            return PAM_CONV_ERR;
        }
        // SAFETY: `m_ptr` was checked non-null and provided by PAM.
        let style = unsafe { (*m_ptr).msg_style };
        // SAFETY: `out` has `count` elements, `i < count`.
        let slot = unsafe { &mut *out.add(i) };
        match style {
            PAM_PROMPT_ECHO_OFF => {
                // SAFETY: `data.pass` is NUL-terminated.
                let dup = unsafe { c_dup_bytes(&data.pass) };
                if dup.is_null() {
                    // SAFETY: freeing `out` and any previously allocated responses.
                    unsafe { free_responses(out, i) };
                    return PAM_BUF_ERR;
                }
                slot.resp = dup;
                slot.resp_retcode = 0;
            }
            PAM_PROMPT_ECHO_ON => {
                // SAFETY: `data.user` is NUL-terminated.
                let dup = unsafe { c_dup_bytes(&data.user) };
                if dup.is_null() {
                    // SAFETY: freeing `out` and any previously allocated responses.
                    unsafe { free_responses(out, i) };
                    return PAM_BUF_ERR;
                }
                slot.resp = dup;
                slot.resp_retcode = 0;
            }
            PAM_ERROR_MSG | PAM_TEXT_INFO => {
                slot.resp = ptr::null_mut();
                slot.resp_retcode = 0;
            }
            _ => {
                // SAFETY: freeing `out` and any previously allocated responses.
                unsafe { free_responses(out, i) };
                return PAM_CONV_ERR;
            }
        }
    }

    // SAFETY: `resp` was verified non-null by the check above.
    unsafe {
        *resp = out;
    }
    PAM_SUCCESS
}

/// Zeroize and free a partially populated `PamResponse` array allocated with `calloc`/`malloc`.
pub(crate) unsafe fn free_responses(arr: *mut PamResponse, populated: usize) {
    for i in 0..populated {
        // SAFETY: `arr` has at least `populated` entries allocated via `calloc`.
        let resp_ptr = unsafe { (*arr.add(i)).resp };
        if !resp_ptr.is_null() {
            // SAFETY: `resp_ptr` is a NUL-terminated C string allocated via `libc::malloc`.
            unsafe {
                let len = libc::strlen(resp_ptr);
                if len > 0 {
                    zeroize_bytes(std::slice::from_raw_parts_mut(resp_ptr.cast::<u8>(), len));
                }
                libc::free(resp_ptr.cast::<libc::c_void>());
            }
        }
    }
    // SAFETY: `arr` was allocated with `libc::calloc`.
    unsafe { libc::free(arr.cast::<libc::c_void>()) };
}

/// RAII guard ensuring `pam_end` is always called on an initialized `PamHandle`.
struct PamGuard {
    api: PamApi,
    handle: *mut PamHandle,
    last_status: libc::c_int,
}

impl Drop for PamGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: `self.handle` was initialized by `pam_start` and has not
            // yet been closed.
            unsafe {
                (self.api.end)(self.handle, self.last_status);
            }
        }
    }
}

/// Authenticate `(user, pass)` against PAM `service` (typically `"cups"`).
///
/// Runs `pam_start` -> `pam_authenticate(PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK)`
/// -> `pam_acct_mgmt(PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK)` -> `pam_end`.
#[must_use]
pub fn pam_authenticate(service: &str, user: &str, pass: &str) -> PamOutcome {
    let Some(api) = load_pam_api() else {
        return PamOutcome::Unavailable;
    };
    run_pam_with_api(api, service, user, pass)
}

pub(crate) fn run_pam_with_api(api: PamApi, service: &str, user: &str, pass: &str) -> PamOutcome {
    if service.is_empty() || user.is_empty() || pass.is_empty() {
        return PamOutcome::Denied(PAM_CONV_ERR);
    }
    let (Ok(c_service), Ok(c_user), Ok(c_pass)) = (
        CString::new(service),
        CString::new(user),
        CString::new(pass),
    ) else {
        return PamOutcome::Denied(PAM_CONV_ERR);
    };

    let mut conv_data = ConvData::new(&c_user, &c_pass);
    let conv = PamConv {
        conv: Some(pam_conv_cb),
        appdata_ptr: (&raw mut conv_data).cast::<libc::c_void>(),
    };

    let mut handle: *mut PamHandle = ptr::null_mut();
    // SAFETY: `c_service`, `c_user`, `conv`, and `handle` are valid pointers
    // with lifetimes spanning the PAM session.
    let start_rc = unsafe {
        (api.start)(
            c_service.as_ptr(),
            c_user.as_ptr(),
            &raw const conv,
            &raw mut handle,
        )
    };
    if start_rc != PAM_SUCCESS || handle.is_null() {
        return PamOutcome::Denied(start_rc);
    }

    let mut guard = PamGuard {
        api,
        handle,
        last_status: start_rc,
    };

    let flags = PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK;
    // SAFETY: `guard.handle` is a valid active PAM handle; `conv_data` stays
    // alive until after `guard` drops.
    let auth_rc = unsafe { (api.authenticate)(guard.handle, flags) };
    guard.last_status = auth_rc;
    if auth_rc != PAM_SUCCESS {
        return PamOutcome::Denied(auth_rc);
    }

    // SAFETY: `guard.handle` is a valid authenticated PAM handle.
    let acct_rc = unsafe { (api.acct_mgmt)(guard.handle, flags) };
    guard.last_status = acct_rc;
    if acct_rc != PAM_SUCCESS {
        return PamOutcome::Denied(acct_rc);
    }

    PamOutcome::Authenticated
}

/// Convenience wrapper calling [`pam_authenticate`] for the `"cups"` PAM service.
#[must_use]
pub fn pam_authenticate_cups(user: &str, pass: &str) -> PamOutcome {
    pam_authenticate("cups", user, pass)
}
