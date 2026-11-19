use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

#[test]
#[allow(clippy::too_many_lines)]
fn cups_exec_cli_sandbox_enforcement_and_execv() {
    let bin = env!("CARGO_BIN_EXE_cups-exec");

    // Missing arguments -> exit 1 with usage message.
    let usage = Command::new(bin).output().expect("run usage");
    assert_eq!(usage.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&usage.stderr).contains("usage:"));

    let id = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("pw-cupsexec-cli-{}-{id}", std::process::id()));
    let forbidden_dir =
        std::env::temp_dir().join(format!("pw-cupsexec-secret-{}-{id}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&forbidden_dir);
    fs::create_dir_all(&dir).expect("mkdir");
    fs::create_dir_all(&forbidden_dir).expect("mkdir secret");

    let secret_file = forbidden_dir.join("secret.txt");
    fs::write(&secret_file, b"TOP_SECRET").expect("write secret");

    let script = dir.join("probe.sh");
    // Pure POSIX shell builtins (no subshell forks) so `/proc/self/status` stays on
    // the exec'd PID granted by `/proc/self` under strict Landlock.
    fs::write(
        &script,
        r#"#!/bin/sh
set -eu
nnp=""
while IFS= read -r line; do
    case "$line" in
        NoNewPrivs:*) nnp="${line#NoNewPrivs:}" ;;
    esac
done < /proc/self/status
um=$(umask)
printf 'args=%s,%s printer=%s bashenv=%s nnp=%s umask=%s\n' \
    "$1" "$2" "${PRINTER:-}" "${BASH_ENV:-}" "$(printf '%s' "$nnp" | tr -d ' \t')" "$um"
"#,
    )
    .expect("write script");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");

    // 1. Run under `strict` profile keeping current uid/gid (`- -`), verifying umask 0077,
    //    NoNewPrivs=1, BASH_ENV stripped, PRINTER kept, and custom argv0 passed.
    let out = Command::new(bin)
        .args([
            "strict",
            "-",
            "-",
            "5",
            script.to_str().expect("str"),
            "custom-argv0",
            "hello",
            "world",
        ])
        .env("PRINTER", "laser1")
        .env("BASH_ENV", "/tmp/injected.sh")
        .env("TMPDIR", &dir)
        .output()
        .expect("run strict");
    assert!(
        out.status.success(),
        "cups-exec strict failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("args=hello,world"), "stdout={stdout}");
    assert!(stdout.contains("printer=laser1"), "stdout={stdout}");
    assert!(stdout.contains("bashenv= "), "stdout={stdout}");
    assert!(stdout.contains("nnp=1"), "stdout={stdout}");
    assert!(stdout.contains("umask=0077"), "stdout={stdout}");

    // 2. When the kernel supports Landlock, verify reading a file outside allowed
    //    Landlock paths is actually blocked (`EACCES`).
    if sys::landlock_abi_version().is_some() {
        let reader_script = dir.join("read_secret.sh");
        fs::write(
            &reader_script,
            format!("#!/bin/sh\ncat \"{}\"\n", secret_file.display()),
        )
        .expect("write reader");
        fs::set_permissions(&reader_script, fs::Permissions::from_mode(0o755)).expect("chmod");

        let blocked = Command::new(bin)
            .args([
                "strict",
                "-",
                "-",
                "0",
                reader_script.to_str().expect("str"),
            ])
            .env("TMPDIR", &dir)
            .output()
            .expect("run blocked");
        assert!(
            !blocked.status.success(),
            "expected Landlock to deny reading {}",
            secret_file.display()
        );
    }

    // 3. Run under `off` profile.
    let off = Command::new(bin)
        .args([
            "off",
            "-",
            "-",
            "0",
            script.to_str().expect("str"),
            "myjob",
            "a",
            "b",
        ])
        .output()
        .expect("run off");
    assert!(off.status.success());

    // 4. Reject symlink target.
    let sym = dir.join("sym.sh");
    std::os::unix::fs::symlink(&script, &sym).expect("symlink");
    let bad_sym = Command::new(bin)
        .args(["strict", "-", "-", "0", sym.to_str().expect("str")])
        .output()
        .expect("run sym");
    assert_eq!(bad_sym.status.code(), Some(1));

    // 5. Reject world-writable executable.
    let ww = dir.join("ww.sh");
    fs::write(&ww, "#!/bin/sh\nexit 0\n").expect("write");
    fs::set_permissions(&ww, fs::Permissions::from_mode(0o777)).expect("chmod");
    let bad_ww = Command::new(bin)
        .args(["strict", "-", "-", "0", ww.to_str().expect("str")])
        .output()
        .expect("run ww");
    assert_eq!(bad_ww.status.code(), Some(1));

    // 6. Executable with nonexistent interpreter passes all sandbox setup (nice, umask,
    //    rlimits, no_new_privs, Landlock) and fails cleanly at execv with exit 1.
    let bad_interp = dir.join("bad_interp.sh");
    fs::write(&bad_interp, "#!/nonexistent/yindle-interp-xyz\n").expect("write");
    fs::set_permissions(&bad_interp, fs::Permissions::from_mode(0o755)).expect("chmod");
    let bad_exec = Command::new(bin)
        .args(["strict", "-", "-", "0", bad_interp.to_str().expect("str")])
        .env("TMPDIR", &dir)
        .output()
        .expect("run bad interp");
    assert_eq!(bad_exec.status.code(), Some(1));

    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&forbidden_dir);
}
