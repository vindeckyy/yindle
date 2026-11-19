//! `cups-exec` — Yindle sandbox launcher matching CUPS `scheduler/cups-exec.c`.
//!
//! Usage:
//!   `cups-exec <sandbox-profile> <uid> <gid> <nice> <path> [argv0 args...]`
//!
//! Applies process hardening in order:
//! 1. Validates CLI arguments, profile, and executable path safety.
//! 2. `set_nice` (clamped `0..=19`) and `set_umask(0o077)`.
//! 3. `set_rlimits` (`Rlimits::filter_default()` or profile overrides).
//! 4. `drop_privileges` (strictly enforced when running as root; fails closed
//!    if a non-root process requests a different uid/gid).
//! 5. `set_no_new_privs` (`PR_SET_NO_NEW_PRIVS`).
//! 6. Linux Landlock (`apply_landlock` for `strict`/`relaxed` profiles).
//! 7. `execv` with sanitized environment and requested `argv0`.

mod plan;

use std::collections::HashMap;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode};

use plan::{
    build_plan, current_euid_egid, parse_args, scrub_exec_env, validate_program_on_disk,
    SandboxPlan,
};
use sys::{LandlockRule, LandlockStatus, Rlimits};

/// Abstraction over OS sandboxing and `exec` syscalls for deterministic testing.
trait ExecOps {
    fn current_euid_egid(&self) -> (u32, u32);
    fn validate_target(&self, path: &Path, eff_user: u32) -> io::Result<()>;
    fn set_nice(&mut self, nice: i32) -> io::Result<()>;
    fn set_umask(&mut self, mask: u32) -> u32;
    fn set_rlimits(&mut self, limits: &Rlimits) -> io::Result<()>;
    fn drop_privileges(&mut self, uid: u32, gid: u32) -> io::Result<()>;
    fn set_no_new_privs(&mut self) -> io::Result<()>;
    fn apply_landlock(&mut self, rules: &[LandlockRule]) -> io::Result<LandlockStatus>;
    fn exec_program(
        &mut self,
        program: &Path,
        argv0: &str,
        args: &[String],
        env: &HashMap<String, String>,
    ) -> io::Result<()>;
}

struct OsExecOps;

impl ExecOps for OsExecOps {
    fn current_euid_egid(&self) -> (u32, u32) {
        current_euid_egid()
    }

    fn validate_target(&self, path: &Path, eff_user: u32) -> io::Result<()> {
        validate_program_on_disk(path, eff_user)
    }

    fn set_nice(&mut self, nice: i32) -> io::Result<()> {
        sys::set_nice(nice)
    }

    fn set_umask(&mut self, mask: u32) -> u32 {
        sys::set_umask(mask)
    }

    fn set_rlimits(&mut self, limits: &Rlimits) -> io::Result<()> {
        sys::set_rlimits(limits)
    }

    fn drop_privileges(&mut self, uid: u32, gid: u32) -> io::Result<()> {
        sys::drop_privileges(uid, gid, None)
    }

    fn set_no_new_privs(&mut self) -> io::Result<()> {
        sys::set_no_new_privs()
    }

    fn apply_landlock(&mut self, rules: &[LandlockRule]) -> io::Result<LandlockStatus> {
        sys::apply_landlock(rules)
    }

    fn exec_program(
        &mut self,
        program: &Path,
        argv0: &str,
        args: &[String],
        env: &HashMap<String, String>,
    ) -> io::Result<()> {
        let err = Command::new(program)
            .arg0(argv0)
            .args(args)
            .env_clear()
            .envs(env)
            .exec();
        Err(err)
    }
}

/// Execute a validated [`SandboxPlan`] through `ops`.
fn execute_plan<O: ExecOps>(
    plan: &SandboxPlan,
    env: &HashMap<String, String>,
    ops: &mut O,
) -> io::Result<()> {
    let (eff_user, eff_group) = ops.current_euid_egid();
    ops.validate_target(&plan.program, eff_user)?;

    match ops.set_nice(plan.nice) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {}
        Err(e) => return Err(e),
    }

    let _ = ops.set_umask(plan.umask);
    ops.set_rlimits(&plan.rlimits)?;

    let mut no_new_privs_done = false;
    if eff_user == 0 {
        let drop_user = plan.uid.unwrap_or(0);
        let drop_group = plan.gid.unwrap_or(eff_group);
        if drop_user == 0 {
            if !plan.mode.is_backend() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing to execute filter as uid 0 (root)",
                ));
            }
        } else {
            ops.drop_privileges(drop_user, drop_group)?;
            no_new_privs_done = true;
        }
    } else {
        if let Some(u) = plan.uid {
            if u != eff_user {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("cannot drop privileges to uid {u} while running as uid {eff_user}"),
                ));
            }
        }
        if let Some(g) = plan.gid {
            if g != eff_group {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("cannot drop privileges to gid {g} while running as gid {eff_group}"),
                ));
            }
        }
    }

    if plan.mode.is_enabled() {
        if !no_new_privs_done {
            ops.set_no_new_privs()?;
        }
        let _ = ops.apply_landlock(&plan.landlock_rules)?;
    }

    let clean_env = scrub_exec_env(env);
    ops.exec_program(&plan.program, &plan.argv0, &plan.args, &clean_env)
}

/// Top-level testable CLI runner returning a UNIX exit code.
fn run_with_ops<O: ExecOps, W: Write>(
    argv: &[String],
    env: &HashMap<String, String>,
    ops: &mut O,
    err_out: &mut W,
) -> u8 {
    let req = match parse_args(argv) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(err_out, "cups-exec: {e}");
            return 1;
        }
    };
    let plan = build_plan(req, env);
    match execute_plan(&plan, env, ops) {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(err_out, "cups-exec: {e}");
            1
        }
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let env: HashMap<String, String> = std::env::vars().collect();
    let mut ops = OsExecOps;
    let mut stderr = io::stderr();
    ExitCode::from(run_with_ops(&argv, &env, &mut ops, &mut stderr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use plan::{
        parse_proc_status_ids, parse_profile, parse_profile_text, validate_program_metadata,
        validate_program_path_syntax, ProfileMode, DEFAULT_UMASK,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("pw-exec-unit-{tag}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("mkdir");
        d
    }

    type RecordedExec = (PathBuf, String, Vec<String>, HashMap<String, String>);

    struct MockExecOps {
        ids: (u32, u32),
        target_ok: bool,
        nice_err: Option<io::ErrorKind>,
        umask_set: Option<u32>,
        rlimits_set: Option<Rlimits>,
        dropped: Option<(u32, u32)>,
        nnp_called: bool,
        landlock_rules: Option<usize>,
        exec_called: Option<RecordedExec>,
    }

    impl MockExecOps {
        fn new(uid: u32, gid: u32) -> Self {
            Self {
                ids: (uid, gid),
                target_ok: true,
                nice_err: None,
                umask_set: None,
                rlimits_set: None,
                dropped: None,
                nnp_called: false,
                landlock_rules: None,
                exec_called: None,
            }
        }
    }

    impl ExecOps for MockExecOps {
        fn current_euid_egid(&self) -> (u32, u32) {
            self.ids
        }
        fn validate_target(&self, _path: &Path, _eff_user: u32) -> io::Result<()> {
            if self.target_ok {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "bad target",
                ))
            }
        }
        fn set_nice(&mut self, _nice: i32) -> io::Result<()> {
            match self.nice_err {
                Some(k) => Err(io::Error::new(k, "nice err")),
                None => Ok(()),
            }
        }
        fn set_umask(&mut self, mask: u32) -> u32 {
            self.umask_set = Some(mask);
            0o022
        }
        fn set_rlimits(&mut self, limits: &Rlimits) -> io::Result<()> {
            self.rlimits_set = Some(*limits);
            Ok(())
        }
        fn drop_privileges(&mut self, uid: u32, gid: u32) -> io::Result<()> {
            self.dropped = Some((uid, gid));
            Ok(())
        }
        fn set_no_new_privs(&mut self) -> io::Result<()> {
            self.nnp_called = true;
            Ok(())
        }
        fn apply_landlock(&mut self, rules: &[LandlockRule]) -> io::Result<LandlockStatus> {
            self.landlock_rules = Some(rules.len());
            Ok(LandlockStatus::Enforced { abi: 3 })
        }
        fn exec_program(
            &mut self,
            program: &Path,
            argv0: &str,
            args: &[String],
            env: &HashMap<String, String>,
        ) -> io::Result<()> {
            self.exec_called = Some((
                program.to_path_buf(),
                argv0.to_string(),
                args.to_vec(),
                env.clone(),
            ));
            Ok(())
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn profile_and_arg_parsing() {
        assert_eq!(parse_profile("none").expect("ok").mode, ProfileMode::Off);
        assert_eq!(parse_profile("off").expect("ok").mode, ProfileMode::Off);
        assert_eq!(
            parse_profile("strict").expect("ok").mode,
            ProfileMode::Strict { is_backend: false }
        );
        assert_eq!(
            parse_profile("strict-backend").expect("ok").mode,
            ProfileMode::Strict { is_backend: true }
        );
        assert_eq!(
            parse_profile("relaxed").expect("ok").mode,
            ProfileMode::Relaxed { is_backend: false }
        );
        assert_eq!(
            parse_profile("relaxed-backend").expect("ok").mode,
            ProfileMode::Relaxed { is_backend: true }
        );
        assert!(parse_profile("").is_err());
        assert!(parse_profile("bad\0prof").is_err());
        assert!(parse_profile("bogus").is_err());
        assert!(parse_profile("/etc/../etc/passwd").is_err());

        let parsed = parse_profile_text(
            r"
# comment
; semicolon comment
(version 1)
mode=relaxed-backend
umask=0o077
allow-read=/opt/read
allow-write=/var/tmp/write
allow-exec=/opt/bin
rlimit-cpu=60
rlimit-as=1048576
rlimit-fsize=2048
rlimit-nofile=128
rlimit-core=0
",
        )
        .expect("parse profile text");
        assert_eq!(parsed.mode, ProfileMode::Relaxed { is_backend: true });
        assert_eq!(parsed.umask, 0o077);
        assert_eq!(parsed.rlimits.cpu_secs, Some(60));
        assert_eq!(parsed.rlimits.address_space_bytes, Some(1_048_576));
        assert_eq!(parsed.rlimits.file_size_bytes, Some(2048));
        assert_eq!(parsed.rlimits.nofile, Some(128));
        assert_eq!(parsed.rlimits.core_bytes, Some(0));
        assert_eq!(parsed.allow_read, vec![PathBuf::from("/opt/read")]);
        assert_eq!(parsed.allow_write, vec![PathBuf::from("/var/tmp/write")]);
        assert_eq!(parsed.allow_exec, vec![PathBuf::from("/opt/bin")]);

        // Test remaining mode variants in profile files.
        assert_eq!(
            parse_profile_text("mode=off").expect("ok").mode,
            ProfileMode::Off
        );
        assert_eq!(
            parse_profile_text("mode=strict").expect("ok").mode,
            ProfileMode::Strict { is_backend: false }
        );
        assert_eq!(
            parse_profile_text("mode=strict-backend").expect("ok").mode,
            ProfileMode::Strict { is_backend: true }
        );
        assert_eq!(
            parse_profile_text("mode=relaxed").expect("ok").mode,
            ProfileMode::Relaxed { is_backend: false }
        );

        for bad in [
            "no_equals_sign",
            "mode=bogus",
            "umask=999",
            "allow-read=relative/path",
            "allow-write=/tmp/../escape",
            "rlimit-cpu=abc",
            "unknown-key=1",
        ] {
            assert!(parse_profile_text(bad).is_err(), "expected err for {bad}");
        }

        // Profile file from disk
        let dir = temp_dir("prof");
        let prof_file = dir.join("custom.sb");
        fs::write(&prof_file, "mode=strict\nallow-read=/tmp\n").expect("write");
        let loaded = parse_profile(prof_file.to_str().expect("str")).expect("load");
        assert_eq!(loaded.mode, ProfileMode::Strict { is_backend: false });
        let _ = fs::remove_dir_all(&dir);

        // CLI parse_args
        let argv = |xs: &[&str]| xs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        assert!(parse_args(&argv(&["cups-exec", "strict"])).is_err());
        assert!(parse_args(&argv(&[
            "cups-exec",
            "strict",
            "bad",
            "0",
            "0",
            "/bin/true"
        ]))
        .is_err());
        assert!(parse_args(&argv(&[
            "cups-exec",
            "strict",
            "0",
            "bad",
            "0",
            "/bin/true"
        ]))
        .is_err());
        assert!(parse_args(&argv(&[
            "cups-exec",
            "strict",
            "0",
            "0",
            "bad",
            "/bin/true"
        ]))
        .is_err());

        let req = parse_args(&argv(&[
            "cups-exec",
            "strict",
            "-1",
            "-",
            "-5",
            "/usr/lib/cups/filter/f1",
        ]))
        .expect("ok");
        assert_eq!(req.uid, None);
        assert_eq!(req.gid, None);
        assert_eq!(req.nice, 0);
        assert_eq!(req.argv0, "/usr/lib/cups/filter/f1");
        assert_eq!(req.args, Vec::<String>::new());

        let req2 = parse_args(&argv(&[
            "cups-exec",
            "relaxed",
            "7",
            "7",
            "99",
            "/usr/lib/cups/filter/f1",
            "myq",
            "1",
            "alice",
            "title",
            "1",
            "",
            "/var/spool/cups/d00001-001",
        ]))
        .expect("ok2");
        assert_eq!(req2.uid, Some(7));
        assert_eq!(req2.gid, Some(7));
        assert_eq!(req2.nice, 19);
        assert_eq!(req2.argv0, "myq");
        assert_eq!(req2.args.len(), 6);

        // Upstream CUPS 2.4+ flag form (`-g`, `-n`, `-u`)
        let req_flag = parse_args(&argv(&[
            "cups-exec",
            "-g",
            "7",
            "-u",
            "7",
            "-n",
            "10",
            "strict",
            "/usr/lib/cups/filter/f1",
            "myq",
            "arg1",
        ]))
        .expect("flag form");
        assert_eq!(req_flag.uid, Some(7));
        assert_eq!(req_flag.gid, Some(7));
        assert_eq!(req_flag.nice, 10);
        assert_eq!(req_flag.argv0, "myq");
        assert_eq!(req_flag.args, vec!["arg1"]);

        let req_flag_no_argv0 = parse_args(&argv(&[
            "cups-exec",
            "-u",
            "-",
            "off",
            "/usr/lib/cups/filter/f1",
        ]))
        .expect("flag form no argv0");
        assert_eq!(req_flag_no_argv0.argv0, "/usr/lib/cups/filter/f1");

        assert!(parse_args(&argv(&["cups-exec", "-u"])).is_err());
        assert!(parse_args(&argv(&["cups-exec", "-g"])).is_err());
        assert!(parse_args(&argv(&["cups-exec", "-n"])).is_err());
        assert!(parse_args(&argv(&["cups-exec", "-n", "bad", "strict", "/bin/true"])).is_err());
        assert!(parse_args(&argv(&["cups-exec", "-u", "7", "strict"])).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn path_validation_plan_and_env_scrubbing() {
        assert!(validate_program_path_syntax("").is_err());
        assert!(validate_program_path_syntax("relative/bin").is_err());
        assert!(validate_program_path_syntax("/bin/bad\0x").is_err());
        assert!(validate_program_path_syntax("/bin/bad\nx").is_err());
        assert!(validate_program_path_syntax("/usr/lib/../bin/sh").is_err());
        assert!(validate_program_path_syntax("/usr/bin/true").is_ok());

        let p = Path::new("/usr/lib/cups/filter/f1");
        assert!(validate_program_metadata(p, true, 0o755, 0, 0).is_ok());
        assert!(validate_program_metadata(p, false, 0o755, 0, 0).is_err());
        assert!(validate_program_metadata(p, true, 0o644, 0, 0).is_err());
        assert!(validate_program_metadata(p, true, 0o775, 0, 0).is_err());
        assert!(validate_program_metadata(p, true, 0o4755, 0, 0).is_err());
        assert!(validate_program_metadata(p, true, 0o755, 1000, 0).is_err());
        assert!(validate_program_metadata(p, true, 0o755, 1000, 1000).is_ok());
        assert!(validate_program_metadata(p, true, 0o755, 0, 1000).is_ok());
        assert!(validate_program_metadata(p, true, 0o755, 2000, 1000).is_err());

        // On-disk validation (symlink rejected, regular exec accepted)
        let dir = temp_dir("disk");
        let bin = dir.join("tool");
        fs::write(&bin, "#!/bin/sh\nexit 0\n").expect("write");
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).expect("chmod");
        let (euid, _) = current_euid_egid();
        assert!(validate_program_on_disk(&bin, euid).is_ok());
        let link = dir.join("sym");
        std::os::unix::fs::symlink(&bin, &link).expect("symlink");
        assert!(validate_program_on_disk(&link, euid).is_err());
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(
            parse_proc_status_ids("Uid:\t0\t7\t7\t7\nGid:\t0\t8\t8\t8\n"),
            Some((7, 8))
        );
        assert_eq!(parse_proc_status_ids("empty"), None);

        // Plan building across modes with full CUPS env + spool file arg + profile paths
        let mut env = HashMap::new();
        env.insert("CUPS_SERVERBIN".into(), "/usr/lib/cups".into());
        env.insert("CUPS_DATADIR".into(), "/usr/share/cups".into());
        env.insert("CUPS_SERVERROOT".into(), "/etc/cups".into());
        env.insert("CUPS_CACHEDIR".into(), "/var/cache/cups".into());
        env.insert("TMPDIR".into(), "/var/spool/cups/tmp".into());
        env.insert("PPD".into(), "/etc/cups/ppd/q.ppd".into());
        env.insert("LD_PRELOAD".into(), "/evil.so".into());
        env.insert("DYLD_INSERT_LIBRARIES".into(), "/evil.dylib".into());
        env.insert("BASH_ENV".into(), "/evil.sh".into());
        env.insert("SHELLOPTS".into(), "xtrace".into());
        env.insert("PS4".into(), "$(id)".into());
        env.insert("PYTHONHOME".into(), "/tmp/py".into());
        env.insert("MALLOC_TRACE".into(), "/tmp/trace".into());
        // Multi-byte UTF-8 keys crossing byte index 3 and 5 must never panic!
        env.insert("abé".into(), "utf8-ok-1".into());
        env.insert("éx".into(), "utf8-ok-2".into());
        env.insert("abcdé".into(), "utf8-ok-3".into());
        env.insert("PRINTER".into(), "q".into());

        let clean = scrub_exec_env(&env);
        assert!(!clean.contains_key("LD_PRELOAD"));
        assert!(!clean.contains_key("DYLD_INSERT_LIBRARIES"));
        assert!(!clean.contains_key("BASH_ENV"));
        assert!(!clean.contains_key("SHELLOPTS"));
        assert!(!clean.contains_key("PS4"));
        assert!(!clean.contains_key("PYTHONHOME"));
        assert!(!clean.contains_key("MALLOC_TRACE"));
        assert_eq!(clean.get("abé").map(String::as_str), Some("utf8-ok-1"));
        assert_eq!(clean.get("éx").map(String::as_str), Some("utf8-ok-2"));
        assert_eq!(clean.get("abcdé").map(String::as_str), Some("utf8-ok-3"));
        assert_eq!(clean.get("PRINTER").map(String::as_str), Some("q"));

        let argv_vec = |xs: &[&str]| xs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        let req_strict = parse_args(&argv_vec(&[
            "cups-exec",
            "strict-backend",
            "7",
            "7",
            "0",
            "/usr/lib/cups/backend/ipp",
            "q",
            "1",
            "u",
            "t",
            "1",
            "",
            "/var/spool/cups/d00001-001",
        ]))
        .expect("req");
        let plan_b = build_plan(req_strict, &env);
        assert!(plan_b
            .landlock_rules
            .iter()
            .any(|r| r.path == Path::new("/dev")));
        assert!(plan_b
            .landlock_rules
            .iter()
            .any(|r| r.path == Path::new("/var/spool/cups/d00001-001")));

        let req_off = parse_args(&argv_vec(&[
            "cups-exec",
            "off",
            "-",
            "-",
            "0",
            "/usr/lib/cups/filter/f1",
        ]))
        .expect("off");
        assert_eq!(build_plan(req_off, &env).landlock_rules, Vec::new());

        let mut req_rel = parse_args(&argv_vec(&[
            "cups-exec",
            "relaxed",
            "-",
            "-",
            "0",
            "/usr/lib/cups/filter/f1",
        ]))
        .expect("rel");
        req_rel.profile.allow_read.push(PathBuf::from("/opt/r"));
        req_rel.profile.allow_write.push(PathBuf::from("/opt/w"));
        req_rel.profile.allow_exec.push(PathBuf::from("/opt/e"));
        let plan_r = build_plan(req_rel, &env);
        assert!(plan_r
            .landlock_rules
            .iter()
            .any(|r| r.path == Path::new("/etc")));
        assert!(plan_r
            .landlock_rules
            .iter()
            .any(|r| r.path == Path::new("/opt/r")));
        assert!(plan_r
            .landlock_rules
            .iter()
            .any(|r| r.path == Path::new("/opt/w")));
        assert!(plan_r
            .landlock_rules
            .iter()
            .any(|r| r.path == Path::new("/opt/e")));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn execute_plan_all_privilege_and_error_paths() {
        let env = HashMap::from([
            ("PRINTER".to_string(), "p1".to_string()),
            ("LD_PRELOAD".to_string(), "/evil.so".to_string()),
        ]);
        let argv = |xs: &[&str]| xs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        let mut err = Vec::new();

        // 1. Root drops privileges to 7:7 for strict filter.
        let mut ops_root = MockExecOps::new(0, 0);
        assert_eq!(
            run_with_ops(
                &argv(&[
                    "cups-exec",
                    "strict",
                    "7",
                    "7",
                    "5",
                    "/usr/lib/cups/filter/f",
                    "p1",
                    "a"
                ]),
                &env,
                &mut ops_root,
                &mut err,
            ),
            0
        );
        assert_eq!(ops_root.umask_set, Some(DEFAULT_UMASK));
        assert_eq!(ops_root.dropped, Some((7, 7)));
        assert!(!ops_root.nnp_called); // already done by drop_privileges
        assert!(ops_root.landlock_rules.is_some());
        let (prog, argv0, child_args, child_env) = ops_root.exec_called.expect("exec");
        assert_eq!(prog, PathBuf::from("/usr/lib/cups/filter/f"));
        assert_eq!(argv0, "p1");
        assert_eq!(child_args, vec!["a"]);
        assert!(!child_env.contains_key("LD_PRELOAD"));
        assert_eq!(child_env.get("PRINTER").map(String::as_str), Some("p1"));

        // 2. Root refuses to run a filter as uid 0.
        let mut ops_root_filter0 = MockExecOps::new(0, 0);
        err.clear();
        assert_eq!(
            run_with_ops(
                &argv(&[
                    "cups-exec",
                    "strict",
                    "0",
                    "0",
                    "0",
                    "/usr/lib/cups/filter/f"
                ]),
                &env,
                &mut ops_root_filter0,
                &mut err,
            ),
            1
        );
        assert!(String::from_utf8_lossy(&err).contains("uid 0"));

        // 3. Root permits strict-backend as uid 0 (for root-owned device backends) with NNP + Landlock.
        let mut ops_root_backend0 = MockExecOps::new(0, 0);
        assert_eq!(
            run_with_ops(
                &argv(&[
                    "cups-exec",
                    "strict-backend",
                    "0",
                    "0",
                    "0",
                    "/usr/lib/cups/backend/usb"
                ]),
                &env,
                &mut ops_root_backend0,
                &mut err,
            ),
            0
        );
        assert!(ops_root_backend0.nnp_called);
        assert!(ops_root_backend0.landlock_rules.is_some());

        // 4. Unprivileged rejects different uid or different gid.
        let mut ops_u = MockExecOps::new(1000, 1000);
        assert_eq!(
            run_with_ops(
                &argv(&[
                    "cups-exec",
                    "strict",
                    "7",
                    "1000",
                    "0",
                    "/usr/lib/cups/filter/f"
                ]),
                &env,
                &mut ops_u,
                &mut err,
            ),
            1
        );
        assert_eq!(
            run_with_ops(
                &argv(&[
                    "cups-exec",
                    "strict",
                    "1000",
                    "7",
                    "0",
                    "/usr/lib/cups/filter/f"
                ]),
                &env,
                &mut ops_u,
                &mut err,
            ),
            1
        );

        // 5. Unprivileged matching uid/gid + nice EACCES degrades gracefully.
        ops_u.nice_err = Some(io::ErrorKind::PermissionDenied);
        assert_eq!(
            run_with_ops(
                &argv(&[
                    "cups-exec",
                    "strict",
                    "1000",
                    "1000",
                    "5",
                    "/usr/lib/cups/filter/f"
                ]),
                &env,
                &mut ops_u,
                &mut err,
            ),
            0
        );
        assert!(ops_u.nnp_called);

        // 6. Non-permission nice error propagates.
        ops_u.nice_err = Some(io::ErrorKind::InvalidInput);
        assert_eq!(
            run_with_ops(
                &argv(&[
                    "cups-exec",
                    "strict",
                    "1000",
                    "1000",
                    "5",
                    "/usr/lib/cups/filter/f"
                ]),
                &env,
                &mut ops_u,
                &mut err,
            ),
            1
        );

        // 7. Off mode skips NNP and Landlock.
        let mut ops_off = MockExecOps::new(1000, 1000);
        assert_eq!(
            run_with_ops(
                &argv(&["cups-exec", "off", "-", "-", "0", "/usr/lib/cups/filter/f"]),
                &env,
                &mut ops_off,
                &mut err,
            ),
            0
        );
        assert!(!ops_off.nnp_called);
        assert!(ops_off.landlock_rules.is_none());

        // 8. Target validation failure & arg parse failure return 1.
        let mut ops_bad = MockExecOps::new(1000, 1000);
        ops_bad.target_ok = false;
        assert_eq!(
            run_with_ops(
                &argv(&[
                    "cups-exec",
                    "strict",
                    "-",
                    "-",
                    "0",
                    "/usr/lib/cups/filter/f"
                ]),
                &env,
                &mut ops_bad,
                &mut err,
            ),
            1
        );
        assert_eq!(
            run_with_ops(&argv(&["cups-exec"]), &env, &mut ops_bad, &mut err),
            1
        );
    }
}
