//! sys — the only workspace crate permitted to contain `unsafe` code:
//! reentrant NSS lookups, dynamically loaded `crypt_r` & PAM, privilege drop,
//! resource limits, Linux Landlock sandboxing, symlink-safe file I/O, systemd
//! socket activation / notifications, local interface enumeration, and termios.
//!
//! Everything else in the workspace is `#![forbid(unsafe_code)]`.
//! Keep this crate small and audit-friendly.

#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(unix)]
mod fs;
#[cfg(unix)]
mod net;
#[cfg(unix)]
mod nss;
#[cfg(unix)]
mod pam;
#[cfg(unix)]
mod sandbox;
#[cfg(unix)]
mod systemd;
#[cfg(unix)]
mod termios;

#[cfg(unix)]
pub use fs::{
    atomic_write_secure, open_append_nofollow, open_char_device_noctty, open_nofollow,
    open_readonly_nofollow,
};
#[cfg(unix)]
pub use net::{local_interfaces, peer_cred, socket_family, LocalInterface};
#[cfg(unix)]
pub use nss::{
    check_password, constant_time_eq, crypt_r_hash, gid_of, group_name_of_gid, groups_of,
    is_shadow_entry_usable, name_of_uid, uid_of, user_primary_gid,
};
#[cfg(unix)]
pub use pam::{pam_authenticate, pam_authenticate_cups, pam_available, PamOutcome};
#[cfg(unix)]
pub use sandbox::{
    apply_landlock, drop_privileges, landlock_abi_version, landlock_access, set_nice,
    set_no_new_privs, set_rlimits, set_umask, LandlockRule, LandlockStatus, Rlimits,
};
#[cfg(unix)]
pub use systemd::{
    gethostname, sd_listen_fds, sd_notify, sd_notify_to_socket, sd_notify_unset_env,
};
#[cfg(unix)]
pub use termios::Termios;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::sync::Mutex;

    /// Serializes tests that temporarily mutate process environment variables.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn root_and_missing_nss_lookups() {
        assert_eq!(uid_of("root"), Some(0));
        assert_eq!(gid_of("root"), Some(0));
        assert_eq!(user_primary_gid("root"), Some(0));
        assert_eq!(name_of_uid(0).as_deref(), Some("root"));
        assert_eq!(group_name_of_gid(0).as_deref(), Some("root"));
        assert_eq!(uid_of("definitely-not-a-user-xyz"), None);
        assert_eq!(gid_of("definitely-not-a-group-xyz"), None);
        assert_eq!(name_of_uid(u32::MAX - 7), None);
        assert_eq!(group_name_of_gid(u32::MAX - 7), None);
        assert!(uid_of("bad\0user").is_none());
        assert!(gid_of("bad\0group").is_none());
        assert_eq!(groups_of("definitely-not-a-user-xyz"), Vec::<String>::new());
        assert_eq!(groups_of("bad\0user"), Vec::<String>::new());
        assert_ne!(groups_of("root"), Vec::<String>::new());
    }

    #[test]
    fn erange_dynamic_buffer_growth() {
        // Start with tiny 4-byte scratch buffer to force ERANGE retries.
        assert_eq!(nss::gid_of_with_buf("root", 4), Some(0));
        assert_eq!(nss::passwd_ids_of_with_buf("root", 4), Some((0, 0)));
        assert_eq!(nss::name_of_uid_with_buf(0, 4).as_deref(), Some("root"));
        assert_eq!(
            nss::group_name_of_gid_with_buf(0, 4).as_deref(),
            Some("root")
        );
        // Exercise `getgrouplist` growth loop starting with capacity 0.
        assert_ne!(nss::groups_of_with_cap("root", 0), Vec::<String>::new());
        // Exercise dynamic symbol resolver fallback chain (missing lib, missing sym, RTLD_DEFAULT).
        assert!(
            nss::resolve_sym_dynamic(&[c"libnonexistent_pw_99.so"], c"no_such_sym_pw").is_none()
        );
        assert!(nss::resolve_sym_dynamic(&[c"libcrypt.so.1"], c"no_such_sym_pw").is_none());
        assert!(nss::resolve_sym_dynamic(&[], c"strlen").is_some());
        // Exercise PAM dynamic loader missing-library & wrong-library fallback paths.
        assert!(pam::load_pam_from(&[c"libnonexistent_pam_99.so"]).is_none());
        assert!(pam::load_pam_from(&[c"libcrypt.so.1"]).is_none());
    }

    #[test]
    fn shadow_entry_end_to_end_verification() {
        let salt = "$6$testverify012345$";
        let real_hash = crypt_r_hash("CorrectHorse99!", salt).expect("crypt_r hash");
        let make_entry = |pwdp: &str, expire: i64| nss::ShadowEntry {
            pwdp: pwdp.to_string(),
            lstchg: 19_000,
            max: 99_999,
            inact: -1,
            expire,
        };

        assert!(nss::verify_shadow_entry(
            Some(make_entry(&real_hash, -1)),
            "CorrectHorse99!",
            20_000
        ));
        assert!(!nss::verify_shadow_entry(
            Some(make_entry(&real_hash, -1)),
            "WrongPassword!",
            20_000
        ));
        assert!(!nss::verify_shadow_entry(
            Some(make_entry(&real_hash, -1)),
            "",
            20_000
        ));
        assert!(!nss::verify_shadow_entry(
            Some(make_entry(&real_hash, 19_500)),
            "CorrectHorse99!",
            20_000
        ));
        assert!(!nss::verify_shadow_entry(
            Some(make_entry("!locked", -1)),
            "CorrectHorse99!",
            20_000
        ));
        assert!(!nss::verify_shadow_entry(
            Some(make_entry("$6$bad\0hash", -1)),
            "CorrectHorse99!",
            20_000
        ));
        assert!(!nss::verify_shadow_entry(
            Some(make_entry("$invalid$hash", -1)),
            "CorrectHorse99!",
            20_000
        ));
        assert!(!nss::verify_shadow_entry(None, "CorrectHorse99!", 20_000));
        assert!(!nss::verify_shadow_entry(
            Some(make_entry(&real_hash, -1)),
            "bad\0pass",
            20_000
        ));
    }

    #[test]
    fn concurrent_nss_and_crypt_thread_safety() {
        let handles: Vec<_> = (0..8)
            .map(|i| {
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        assert_eq!(uid_of("root"), Some(0));
                        assert_eq!(gid_of("root"), Some(0));
                        assert_eq!(name_of_uid(0).as_deref(), Some("root"));
                        assert_eq!(group_name_of_gid(0).as_deref(), Some("root"));
                        assert_ne!(groups_of("root"), Vec::<String>::new());
                        let salt = format!("$6$saltthread{i:04}$");
                        let h = crypt_r_hash("hunter2", &salt).expect("crypt_r must succeed");
                        assert!(h.starts_with(&salt));
                        assert_eq!(crypt_r_hash("hunter2", &h).as_deref(), Some(h.as_str()));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("worker thread panicked");
        }
    }

    #[test]
    fn constant_time_and_shadow_validation() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(!constant_time_eq(b"abc", b"abcdef"));

        let valid_hash = "$6$saltsalt$abcdefghijklmnop";
        assert!(is_shadow_entry_usable(
            valid_hash, 19_000, 99_999, -1, -1, 20_000
        ));
        // Empty, locked, placeholder, malformed
        assert!(!is_shadow_entry_usable("", 19_000, 99_999, -1, -1, 20_000));
        assert!(!is_shadow_entry_usable("!", 19_000, 99_999, -1, -1, 20_000));
        assert!(!is_shadow_entry_usable(
            "!!", 19_000, 99_999, -1, -1, 20_000
        ));
        assert!(!is_shadow_entry_usable("*", 19_000, 99_999, -1, -1, 20_000));
        assert!(!is_shadow_entry_usable(
            "!$6$locked",
            19_000,
            99_999,
            -1,
            -1,
            20_000
        ));
        assert!(!is_shadow_entry_usable("x", 19_000, 99_999, -1, -1, 20_000));
        assert!(!is_shadow_entry_usable(
            "short", 19_000, 99_999, -1, -1, 20_000
        ));
        // Account expired (`sp_expire`)
        assert!(!is_shadow_entry_usable(
            valid_hash, 19_000, 99_999, -1, 20_000, 20_000
        ));
        assert!(!is_shadow_entry_usable(
            valid_hash, 19_000, 99_999, -1, 19_999, 20_000
        ));
        assert!(is_shadow_entry_usable(
            valid_hash, 19_000, 99_999, -1, 20_001, 20_000
        ));
        // Forced password change (`sp_lstchg == 0`)
        assert!(!is_shadow_entry_usable(
            valid_hash, 0, 99_999, -1, -1, 20_000
        ));
        // Password max-age + inactivity expired
        assert!(!is_shadow_entry_usable(
            valid_hash, 19_000, 90, 10, -1, 19_101
        ));
        assert!(is_shadow_entry_usable(
            valid_hash, 19_000, 90, 10, -1, 19_100
        ));

        // Unknown / NUL / empty inputs fail cleanly without panicking
        assert!(!check_password("definitely-not-a-user-xyz", "wrong"));
        assert!(!check_password("root", ""));
        assert!(!check_password("bad\0user", "pass"));
        assert!(!check_password("root", "bad\0pass"));
        assert!(crypt_r_hash("pass", "bad\0salt").is_none());
        assert!(crypt_r_hash("pass", "$invalid$").is_none());
    }

    #[test]
    fn pam_runtime_authenticate() {
        let avail = pam_available();
        let res = pam_authenticate_cups("definitely-not-a-user-xyz", "wrongpass");
        if avail {
            assert!(matches!(res, PamOutcome::Denied(_)));
            assert!(matches!(
                pam_authenticate("", "user", "pass"),
                PamOutcome::Denied(_)
            ));
            assert!(matches!(
                pam_authenticate("cups", "bad\0user", "pass"),
                PamOutcome::Denied(_)
            ));
        } else {
            assert_eq!(res, PamOutcome::Unavailable);
        }
    }

    #[test]
    fn pam_session_state_machine() {
        use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

        static START_RC: AtomicI32 = AtomicI32::new(0);
        static AUTH_RC: AtomicI32 = AtomicI32::new(0);
        static ACCT_RC: AtomicI32 = AtomicI32::new(0);
        static END_CALLS: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn fake_start(
            _svc: *const libc::c_char,
            _user: *const libc::c_char,
            _conv: *const pam::PamConv,
            pamh: *mut *mut pam::PamHandle,
        ) -> libc::c_int {
            let rc = START_RC.load(Ordering::SeqCst);
            if rc == 0 {
                // SAFETY: non-null sentinel pointer; only passed back to `fake_auth`/`fake_end`.
                unsafe {
                    *pamh = std::ptr::dangling_mut::<pam::PamHandle>();
                }
            }
            rc
        }
        unsafe extern "C" fn fake_auth(_h: *mut pam::PamHandle, _f: libc::c_int) -> libc::c_int {
            AUTH_RC.load(Ordering::SeqCst)
        }
        unsafe extern "C" fn fake_acct(_h: *mut pam::PamHandle, _f: libc::c_int) -> libc::c_int {
            ACCT_RC.load(Ordering::SeqCst)
        }
        unsafe extern "C" fn fake_end(_h: *mut pam::PamHandle, _s: libc::c_int) -> libc::c_int {
            END_CALLS.fetch_add(1, Ordering::SeqCst);
            0
        }

        let api = pam::PamApi {
            start: fake_start,
            authenticate: fake_auth,
            acct_mgmt: fake_acct,
            end: fake_end,
        };

        // 1. Full success
        START_RC.store(0, Ordering::SeqCst);
        AUTH_RC.store(0, Ordering::SeqCst);
        ACCT_RC.store(0, Ordering::SeqCst);
        END_CALLS.store(0, Ordering::SeqCst);
        assert_eq!(
            pam::run_pam_with_api(api, "cups", "alice", "secret"),
            PamOutcome::Authenticated
        );
        assert_eq!(END_CALLS.load(Ordering::SeqCst), 1);

        // 2. Account management failure (e.g., expired account)
        ACCT_RC.store(13, Ordering::SeqCst);
        assert_eq!(
            pam::run_pam_with_api(api, "cups", "alice", "secret"),
            PamOutcome::Denied(13)
        );
        assert_eq!(END_CALLS.load(Ordering::SeqCst), 2);

        // 3. Authentication failure
        AUTH_RC.store(7, Ordering::SeqCst);
        assert_eq!(
            pam::run_pam_with_api(api, "cups", "alice", "secret"),
            PamOutcome::Denied(7)
        );
        assert_eq!(END_CALLS.load(Ordering::SeqCst), 3);

        // 4. pam_start failure (pam_end must NOT be called)
        START_RC.store(26, Ordering::SeqCst);
        assert_eq!(
            pam::run_pam_with_api(api, "cups", "alice", "secret"),
            PamOutcome::Denied(26)
        );
        assert_eq!(END_CALLS.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn drop_privileges_ordering_and_verification() {
        struct MockOps {
            log: Vec<&'static str>,
            euid: u32,
            egid: u32,
        }
        impl sandbox::PrivDropOps for MockOps {
            fn initgroups(&mut self, _u: &std::ffi::CStr, _g: u32) -> std::io::Result<()> {
                self.log.push("initgroups");
                Ok(())
            }
            fn clear_groups(&mut self) -> std::io::Result<()> {
                self.log.push("clear_groups");
                Ok(())
            }
            fn setgid(&mut self, _g: u32) -> std::io::Result<()> {
                self.log.push("setgid");
                Ok(())
            }
            fn setuid(&mut self, _u: u32) -> std::io::Result<()> {
                self.log.push("setuid");
                Ok(())
            }
            fn get_effective_ids(&self) -> (u32, u32) {
                (self.euid, self.egid)
            }
            fn no_new_privs(&mut self) -> std::io::Result<()> {
                self.log.push("no_new_privs");
                Ok(())
            }
        }

        let mut ops = MockOps {
            log: Vec::new(),
            euid: 1000,
            egid: 1000,
        };
        sandbox::drop_privileges_with_ops(1000, 1000, Some("lp"), &mut ops).unwrap();
        assert_eq!(
            ops.log,
            vec!["initgroups", "setgid", "setuid", "no_new_privs"]
        );

        // Unknown uid with no username clears supplementary groups via setgroups(0).
        let mut ops2 = MockOps {
            log: Vec::new(),
            euid: 999_991,
            egid: 999_991,
        };
        sandbox::drop_privileges_with_ops(999_991, 999_991, None, &mut ops2).unwrap();
        assert_eq!(
            ops2.log,
            vec!["clear_groups", "setgid", "setuid", "no_new_privs"]
        );

        // Verification mismatch fails closed.
        let mut ops3 = MockOps {
            log: Vec::new(),
            euid: 0,
            egid: 1000,
        };
        assert_eq!(
            sandbox::drop_privileges_with_ops(1000, 1000, Some("lp"), &mut ops3)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );

        // NUL username rejected.
        let mut ops4 = MockOps {
            log: Vec::new(),
            euid: 1000,
            egid: 1000,
        };
        assert_eq!(
            sandbox::drop_privileges_with_ops(1000, 1000, Some("bad\0u"), &mut ops4)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn pam_conversation_callback() {
        // Directly test PAM conversation callback across all message styles.
        let user = CString::new("alice").unwrap();
        let pass = CString::new("s3cr3t").unwrap();
        let mut data = pam::ConvData::new(&user, &pass);
        let msgs = [
            pam::PamMessage {
                msg_style: pam::PAM_PROMPT_ECHO_OFF,
                msg: c"Password:".as_ptr(),
            },
            pam::PamMessage {
                msg_style: pam::PAM_PROMPT_ECHO_ON,
                msg: c"Login:".as_ptr(),
            },
            pam::PamMessage {
                msg_style: pam::PAM_ERROR_MSG,
                msg: c"err".as_ptr(),
            },
            pam::PamMessage {
                msg_style: pam::PAM_TEXT_INFO,
                msg: c"info".as_ptr(),
            },
        ];
        let mut msg_ptrs: Vec<*const pam::PamMessage> =
            msgs.iter().map(std::ptr::from_ref).collect();
        let mut resp_ptr: *mut pam::PamResponse = std::ptr::null_mut();

        // SAFETY: `msg_ptrs`, `resp_ptr`, and `data` match Linux-PAM callback contract.
        let rc = unsafe {
            pam::pam_conv_cb(
                i32::try_from(msg_ptrs.len()).unwrap(),
                msg_ptrs.as_mut_ptr(),
                &raw mut resp_ptr,
                (&raw mut data).cast::<libc::c_void>(),
            )
        };
        assert_eq!(rc, 0);
        assert!(!resp_ptr.is_null());
        // SAFETY: `resp_ptr` has 4 responses allocated by `pam_conv_cb`.
        unsafe {
            let r0 = std::ffi::CStr::from_ptr((*resp_ptr.add(0)).resp)
                .to_str()
                .unwrap();
            let r1 = std::ffi::CStr::from_ptr((*resp_ptr.add(1)).resp)
                .to_str()
                .unwrap();
            assert_eq!(r0, "s3cr3t");
            assert_eq!(r1, "alice");
            assert!((*resp_ptr.add(2)).resp.is_null());
            assert!((*resp_ptr.add(3)).resp.is_null());
            pam::free_responses(resp_ptr, 4);
        }

        // Error paths in callback: invalid count, null message, unknown style.
        // SAFETY: testing null/invalid argument rejection.
        unsafe {
            assert_ne!(
                pam::pam_conv_cb(
                    0,
                    msg_ptrs.as_mut_ptr(),
                    &raw mut resp_ptr,
                    std::ptr::null_mut()
                ),
                0
            );
            assert_ne!(
                pam::pam_conv_cb(
                    200,
                    msg_ptrs.as_mut_ptr(),
                    &raw mut resp_ptr,
                    (&raw mut data).cast::<libc::c_void>()
                ),
                0
            );
            let mut null_msg = [std::ptr::null::<pam::PamMessage>()];
            assert_ne!(
                pam::pam_conv_cb(
                    1,
                    null_msg.as_mut_ptr(),
                    &raw mut resp_ptr,
                    (&raw mut data).cast::<libc::c_void>()
                ),
                0
            );
            let bad_msg = pam::PamMessage {
                msg_style: 99,
                msg: std::ptr::null(),
            };
            let mut bad_ptrs = [std::ptr::from_ref(&bad_msg)];
            assert_ne!(
                pam::pam_conv_cb(
                    1,
                    bad_ptrs.as_mut_ptr(),
                    &raw mut resp_ptr,
                    (&raw mut data).cast::<libc::c_void>()
                ),
                0
            );
        }
    }

    #[test]
    fn systemd_listen_fds_cloexec_and_env_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        // Wrong PID clears env and returns empty.
        std::env::set_var("LISTEN_PID", "99999999");
        std::env::set_var("LISTEN_FDS", "2");
        std::env::set_var("LISTEN_FDNAMES", "a:b");
        assert!(sd_listen_fds().is_empty());
        assert!(std::env::var_os("LISTEN_PID").is_none());
        assert!(std::env::var_os("LISTEN_FDS").is_none());
        assert!(std::env::var_os("LISTEN_FDNAMES").is_none());

        // Matching PID with 0 or invalid fds clears env.
        std::env::set_var("LISTEN_PID", std::process::id().to_string());
        std::env::set_var("LISTEN_FDS", "0");
        assert!(sd_listen_fds().is_empty());
        assert!(std::env::var_os("LISTEN_PID").is_none());
        std::env::set_var("LISTEN_PID", std::process::id().to_string());
        std::env::set_var("LISTEN_FDS", "-3");
        assert!(sd_listen_fds().is_empty());
        assert!(std::env::var_os("LISTEN_FDS").is_none());

        // Test `adopt_listen_fds` on a fresh pipe descriptor without touching fd 3.
        let mut fds = [0i32; 2];
        // SAFETY: `fds` is a valid 2-int array for `pipe(2)`.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: closing write end immediately; read end will be adopted.
        let _write_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let adopted = systemd::adopt_listen_fds(fds[0], 1);
        assert_eq!(adopted.len(), 1);
        // SAFETY: checking `FD_CLOEXEC` flag on adopted valid fd.
        let flags = unsafe { libc::fcntl(adopted[0].as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        // Adopting an invalid fd is skipped safely.
        assert!(systemd::adopt_listen_fds(999_999, 1).is_empty());
    }

    #[test]
    fn systemd_notify_fs_and_abstract_sockets() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("NOTIFY_SOCKET");
        assert!(!sd_notify("READY=1").unwrap());
        std::env::set_var("NOTIFY_SOCKET", "");
        assert!(!sd_notify("READY=1").unwrap());
        assert!(!sd_notify_unset_env("", true).unwrap());
        assert!(std::env::var_os("NOTIFY_SOCKET").is_none());

        let dir = std::env::temp_dir().join(format!("pw-sys-notify-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock_path = dir.join("notify.sock");
        let _ = std::fs::remove_file(&sock_path);
        let srv = UnixDatagram::bind(&sock_path).unwrap();

        std::env::set_var("NOTIFY_SOCKET", &sock_path);
        assert!(sd_notify_unset_env("READY=1", true).unwrap());
        assert!(std::env::var_os("NOTIFY_SOCKET").is_none());

        let mut buf = [0u8; 64];
        let n = srv.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
        let _ = std::fs::remove_file(&sock_path);
        let _ = std::fs::remove_dir(&dir);

        // Abstract namespace validation & invalid socket rejection.
        assert!(sd_notify_to_socket("relative/path", "READY=1").is_err());
        assert!(sd_notify_to_socket("/", "READY=1").is_err());
        let too_long = format!("/{}", "a".repeat(200));
        assert!(sd_notify_to_socket(&too_long, "READY=1").is_err());
        // Unbound abstract socket exercises the abstract path builder and fails with ECONNREFUSED.
        let abstract_name = format!("@presswork-nonexistent-test-{}", std::process::id());
        assert!(sd_notify_to_socket(&abstract_name, "READY=1").is_err());
    }

    #[test]
    fn hostname_and_network_helpers() {
        let h = gethostname().expect("gethostname must return non-empty name");
        assert_ne!(h, "");

        let ifaces = local_interfaces();
        assert!(
            ifaces.iter().any(|i| i.is_loopback && i.addr.is_loopback()),
            "expected loopback interface from getifaddrs"
        );

        let (a, _b) = UnixStream::pair().unwrap();
        let (pid, uid, gid) = peer_cred(a.as_raw_fd()).expect("peer_cred on unix socket");
        assert_eq!(pid, i32::try_from(std::process::id()).unwrap());
        // SAFETY: `getuid`/`getgid` always succeed.
        unsafe {
            assert_eq!(uid, libc::getuid());
            assert_eq!(gid, libc::getgid());
        }
        assert!(peer_cred(-1).is_none());

        assert_eq!(socket_family(a.as_raw_fd()), libc::AF_UNIX);
        assert_eq!(socket_family(-1), -1);
    }

    #[test]
    fn sandbox_helpers_umask_nice_rlimits_privdrop_and_landlock() {
        let prev = set_umask(0o077);
        assert_eq!(set_umask(prev), 0o077);

        // Niceness 0 should always succeed.
        set_nice(0).expect("set_nice(0) should succeed");

        // `drop_privileges` refuses uid 0 and handles unprivileged EPERM cleanly.
        assert_eq!(
            drop_privileges(0, 0, Some("root")).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        // SAFETY: `geteuid` always succeeds.
        if unsafe { libc::geteuid() } != 0 {
            assert!(drop_privileges(65534, 65534, None).is_err());
            assert!(drop_privileges(65534, 65534, Some("nobody")).is_err());
        }

        // Exercise real OsPrivDropOps methods safely with our own current IDs.
        {
            use sandbox::PrivDropOps;
            let mut os_ops = sandbox::OsPrivDropOps;
            let (cur_user, cur_group) = os_ops.get_effective_ids();
            assert!(os_ops.setgid(cur_group).is_ok());
            assert!(os_ops.setuid(cur_user).is_ok());
            if cur_user != 0 {
                assert!(os_ops.setgid(0).is_err());
                assert!(os_ops.setuid(0).is_err());
            }
        }
        // Invalid rlimit resource returns EINVAL cleanly.
        assert!(sandbox::apply_one_rlimit(999_999, 10).is_err());

        // `Rlimits` default (no-op) & applying safe limits.
        set_rlimits(&Rlimits::default()).expect("empty Rlimits is a no-op");
        let def = Rlimits::filter_default();
        assert_eq!(def.core_bytes, Some(0));
        let soft = Rlimits {
            core_bytes: Some(0),
            cpu_secs: Some(u64::MAX),
            address_space_bytes: Some(u64::MAX),
            file_size_bytes: Some(u64::MAX),
            nofile: Some(u64::MAX),
            nproc: Some(u64::MAX),
        };
        set_rlimits(&soft).expect("set_rlimits capped to existing hard limits should succeed");

        // Landlock ABI helper coverage across ABI versions 1..=5.
        let m1 = sandbox::landlock_handled_fs_for_abi(1);
        let m2 = sandbox::landlock_handled_fs_for_abi(2);
        let m3 = sandbox::landlock_handled_fs_for_abi(3);
        let m5 = sandbox::landlock_handled_fs_for_abi(5);
        assert_ne!(m1, 0);
        assert!(m2 > m1);
        assert!(m3 > m2);
        assert!(m5 > m3);
    }

    #[test]
    fn sandbox_landlock_isolation() {
        // Verify non-ENOENT path error propagation in `apply_landlock` (e.g. ENOTDIR).
        let tmp = std::env::temp_dir().join(format!("pw-landlock-{}", std::process::id()));
        let allowed_dir = tmp.join("allowed");
        let denied_dir = tmp.join("denied");
        std::fs::create_dir_all(&allowed_dir).unwrap();
        std::fs::create_dir_all(&denied_dir).unwrap();
        let allowed_file = allowed_dir.join("ok.txt");
        let denied_file = denied_dir.join("secret.txt");
        std::fs::write(&allowed_file, b"ok").unwrap();
        std::fs::write(&denied_file, b"no").unwrap();

        if landlock_abi_version().is_some() {
            let not_dir_err = apply_landlock(&[LandlockRule {
                path: allowed_file.join("child"), // ENOTDIR
                access: landlock_access::READ_ONLY,
            }]);
            assert!(not_dir_err.is_err());
        }

        let rules = vec![
            LandlockRule {
                path: allowed_dir.clone(),
                access: landlock_access::READ_ONLY,
            },
            LandlockRule {
                path: allowed_file.clone(),
                access: landlock_access::READ_ONLY,
            },
            LandlockRule {
                path: tmp.join("does-not-exist"),
                access: landlock_access::READ_ONLY,
            },
            LandlockRule {
                path: std::path::PathBuf::from("bad\0path"),
                access: landlock_access::READ_ONLY,
            },
            LandlockRule {
                path: allowed_file.clone(),
                access: landlock_access::READ_DIR, // masked to 0 for regular file -> skipped
            },
        ];

        let af = allowed_file.clone();
        let df = denied_file.clone();
        let status = std::thread::spawn(move || {
            use sandbox::PrivDropOps;
            let mut os_ops = sandbox::OsPrivDropOps;
            os_ops
                .no_new_privs()
                .expect("PR_SET_NO_NEW_PRIVS on worker thread");
            let st = apply_landlock(&rules).expect("apply_landlock should not fail");
            if let LandlockStatus::Enforced { abi } = st {
                assert!(abi >= 1);
                assert!(std::fs::read(&af).is_ok());
                assert!(std::fs::read(&df).is_err());
            }
            st
        })
        .join()
        .unwrap();

        if landlock_abi_version().is_some() {
            assert!(matches!(status, LandlockStatus::Enforced { .. }));
        } else {
            assert_eq!(status, LandlockStatus::Unsupported);
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn secure_fs_helpers_nofollow_atomic_and_chardev() {
        let dir = std::env::temp_dir().join(format!("pw-sys-fs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let target = dir.join("secret.conf");
        atomic_write_secure(&target, b"first", 0o600, true).unwrap();
        let meta = std::fs::metadata(&target).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&target).unwrap(), b"first");

        // Atomic overwrite with 0o640.
        atomic_write_secure(&target, b"second", 0o640, false).unwrap();
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"second");

        // `open_readonly_nofollow` succeeds on regular file, fails on symlink and directory.
        let mut f = open_readonly_nofollow(&target).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "second");

        let link = dir.join("sym.conf");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_readonly_nofollow(&link).is_err());
        assert!(open_readonly_nofollow(&dir).is_err());
        assert!(open_readonly_nofollow(std::path::Path::new("bad\0path")).is_err());
        assert!(open_append_nofollow(&link, 0o600).is_err());
        assert!(open_append_nofollow(&dir, 0o600).is_err());
        assert!(atomic_write_secure(&dir, b"x", 0o600, false).is_err());
        assert!(atomic_write_secure(&dir.join("no-such-dir/file"), b"x", 0o600, false).is_err());
        assert!(atomic_write_secure(&dir.join("bad\0name"), b"x", 0o600, false).is_err());
        assert!(open_nofollow(&target, true, false, 0o600).is_ok());

        // `open_append_nofollow` appends cleanly on regular file.
        {
            use std::io::Write;
            let mut af = open_append_nofollow(&target, 0o640).unwrap();
            af.write_all(b"-more").unwrap();
        }
        assert_eq!(std::fs::read(&target).unwrap(), b"second-more");

        // `open_nofollow` create mode works.
        let created = dir.join("created.txt");
        let _cf = open_nofollow(&created, true, true, 0o600).unwrap();
        assert!(created.exists());

        // `open_char_device_noctty`: `/dev/null` is a char device; regular file is rejected.
        let devnull = open_char_device_noctty(std::path::Path::new("/dev/null"), true).unwrap();
        drop(devnull);
        assert!(open_char_device_noctty(&target, false).is_err());
        assert!(open_char_device_noctty(std::path::Path::new("/nonexistent/dev"), false).is_err());
        assert!(atomic_write_secure(std::path::Path::new("/"), b"x", 0o600, false).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn termios_baud_parity_bits_flow_and_pty() {
        for rate in [
            50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38_400,
            57_600, 115_200, 230_400,
        ] {
            assert!(Termios::baud(rate).is_some(), "rate {rate}");
        }
        assert!(Termios::baud(12345).is_none());

        // Invalid fd checks
        assert!(Termios::get(-1).is_none());
        assert!(Termios::get_modem_bits(-1).is_none());
        assert!(!Termios::set_dtr(-1, true));
        assert!(Termios::is_dsr_ready(-1).is_none());
        Termios::drain(-1);

        // Open a real PTY master via `/dev/ptmx` to exercise tcgetattr/tcsetattr/drain.
        // SAFETY: `open("/dev/ptmx", ...)` returns a valid PTY fd or -1.
        let ptmx_raw = unsafe {
            libc::open(
                c"/dev/ptmx".as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        if ptmx_raw >= 0 {
            // SAFETY: `ptmx_raw` is a newly opened valid fd.
            let ptmx = unsafe { OwnedFd::from_raw_fd(ptmx_raw) };
            let mut tio = Termios::get(ptmx.as_raw_fd()).expect("tcgetattr on ptmx");
            tio.set_baud(Termios::baud(115_200).unwrap());
            for p in ["odd", "even", "space", "mark", "none"] {
                tio.set_parity(p);
            }
            for b in ["5", "6", "7", "8"] {
                tio.set_bits(b);
            }
            tio.set_flow("soft");
            assert!(!tio.is_dtrdsr());
            tio.set_flow("hard");
            assert!(!tio.is_dtrdsr());
            tio.set_flow("none");
            assert!(!tio.is_dtrdsr());
            tio.set_flow("dtrdsr");
            assert!(tio.is_dtrdsr());
            assert!(tio.set(ptmx.as_raw_fd()));
            Termios::drain(ptmx.as_raw_fd());
            let _ = Termios::is_dsr_ready(ptmx.as_raw_fd());
            let _ = Termios::set_dtr(ptmx.as_raw_fd(), false);
        }
    }
}
