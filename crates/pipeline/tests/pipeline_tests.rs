use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use cups_config::{Config, CupsFilesConfig, CupsdConfig, Sandboxing};
use mime_db::Conv;
use pipeline::{
    apply_current_process_sandbox, apply_sandbox_with_ops, backend_for_uri, build_cups_exec_args,
    build_landlock_rules, current_euid_egid, format_job_options, kill_pid, kill_process_group,
    parse_kv_pairs, parse_page_event, parse_ppd_filters, parse_proc_status_ids,
    parse_state_changes, parse_status_line, resolve_trusted_executable, sandbox_profile_name,
    sanitize_env_value, sanitize_extra_env, try_backend_for_uri, validate_program_name,
    validate_stage_privilege_drop, validate_uri_scheme, verify_executable_metadata, BackChannel,
    BackendExit, FilterExit, JobDocument, JobSpec, KillSignal, LandlockContext, LogSeverity,
    OsSandboxOps, OsSignalSender, PageEvent, PipelineExit, PpdFilter, SandboxConfig, SandboxOps,
    SecurityPolicy, SideChannel, SideChannelCommand, SideChannelMessage, SideChannelStatus,
    SignalSender, SpawnOptions, StatBuf, StateChange, StatusEvent, CUPS_BC_FD, CUPS_SC_FD,
};
use sys::{LandlockRule, LandlockStatus, Rlimits};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new(prefix: &str) -> Self {
        let id = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("pw-pipe-{prefix}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    fs::create_dir_all(dir).expect("mkdir");
    let path = dir.join(name);
    fs::write(&path, body).expect("write script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod 755");
    path
}

fn base_spec(root: &Path, data_file: PathBuf, backend: &str, uri: &str) -> JobSpec {
    JobSpec {
        printer: "testq".into(),
        job_id: 42,
        username: "alice".into(),
        title: "Quarterly Report".into(),
        copies: 2,
        options: "media=letter sides=two-sided-long-edge".into(),
        data_file,
        src_type: "text/plain".into(),
        dst_type: "application/vnd.cups-raw".into(),
        device_uri: uri.into(),
        filter_dir: root.join("filter"),
        backend_dir: root.join("backend"),
        backend: backend.into(),
        env: HashMap::new(),
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn multi_filter_pipeline_fixes_argv6_strips_device_uri_and_parses_statbuf() {
    let td = TestDir::new("multifilter");
    let filter_dir = td.path().join("filter");
    let backend_dir = td.path().join("backend");
    let spool = td.path().join("d00042-001");
    let out_file = td.path().join("backend_out.txt");
    fs::write(&spool, b"PAYLOAD").expect("write spool");

    // Stage 1: MUST receive 6 args (data_file as $6), NO DEVICE_URI, NO LD_PRELOAD, safe PATH.
    write_script(
        &filter_dir,
        "f1",
        r#"#!/bin/sh
set -eu
if [ "$#" -ne 6 ]; then echo "ERROR: f1 expected 6 args got $#" >&2; exit 11; fi
if [ -n "${DEVICE_URI:-}" ]; then echo "ERROR: f1 saw DEVICE_URI" >&2; exit 12; fi
if [ -n "${LD_PRELOAD:-}" ]; then echo "ERROR: f1 saw LD_PRELOAD" >&2; exit 13; fi
if [ "${CUSTOM_OK:-}" != "yes" ]; then echo "ERROR: f1 missing CUSTOM_OK" >&2; exit 14; fi
echo "INFO: stage 1 started" >&2
echo "STATE: +marker-supply-low-warning" >&2
echo "PAGE: 1 1 media=letter" >&2
echo "ATTR: marker-levels=50 job-media-sheets=1" >&2
echo "PPD: PageSize=Letter" >&2
printf '%s:f1' "$(cat "$6")"
"#,
    );

    // Stage 2: MUST receive 5 args (NO $6!), reads stdin from f1, NO DEVICE_URI.
    write_script(
        &filter_dir,
        "f2",
        r#"#!/bin/sh
set -eu
if [ "$#" -ne 5 ]; then echo "ERROR: f2 expected 5 args got $#" >&2; exit 21; fi
if [ -n "${DEVICE_URI:-}" ]; then echo "ERROR: f2 saw DEVICE_URI" >&2; exit 22; fi
echo "WARNING: stage 2 warning" >&2
echo "DEBUG: stage 2 debug" >&2
printf '%s:f2' "$(cat)"
"#,
    );

    // Stage 3: MUST receive 5 args, reads stdin from f2.
    write_script(
        &filter_dir,
        "f3",
        r#"#!/bin/sh
set -eu
if [ "$#" -ne 5 ]; then echo "ERROR: f3 expected 5 args got $#" >&2; exit 31; fi
echo "NOTICE: stage 3 notice" >&2
echo "PAGE: total 2" >&2
printf '%s:f3' "$(cat)"
"#,
    );

    // Backend: MUST receive 5 args (preceded by filters), MUST receive DEVICE_URI!
    write_script(
        &backend_dir,
        "ipp",
        &format!(
            r#"#!/bin/sh
set -eu
if [ "$#" -ne 5 ]; then echo "ERROR: backend expected 5 args got $#" >&2; exit 41; fi
if [ "${{DEVICE_URI:-}}" != "ipps://user:secret@printer.local:631/ipp/print" ]; then
    echo "ERROR: backend missing DEVICE_URI" >&2
    exit 42
fi
echo "STATE: -marker-supply-low-warning" >&2
echo "DEBUG2: backend trace" >&2
echo "unprefixed backend diagnostic" >&2
printf 'backend-stdout-ok'
printf '%s:backend' "$(cat)" > "{}"
"#,
            out_file.display()
        ),
    );

    let mut spec = base_spec(
        td.path(),
        spool,
        "ipp",
        "ipps://user:secret@printer.local:631/ipp/print",
    );
    spec.env.insert("LD_PRELOAD".into(), "/evil.so".into());
    spec.env.insert("PATH".into(), "/evil/bin".into());
    spec.env
        .insert("DEVICE_URI".into(), "evil://injected".into());
    spec.env.insert("CUSTOM_OK".into(), "yes".into());

    let chain = vec![
        Conv {
            src: "text/plain".into(),
            dst: "application/pdf".into(),
            cost: 10,
            program: "f1".into(),
        },
        Conv {
            src: "application/pdf".into(),
            dst: "application/pdf".into(),
            cost: 0,
            program: "-".into(), // passthrough skipped cleanly
        },
        Conv {
            src: "application/pdf".into(),
            dst: "image/pwg-raster".into(),
            cost: 10,
            program: "f2".into(),
        },
        Conv {
            src: "*/*".into(),
            dst: "*/*".into(),
            cost: 10,
            program: "f3".into(),
        },
    ];

    let opts = SpawnOptions {
        enable_backchannel: true,
        enable_sidechannel: true,
        ppd: Some(td.path().join("test.ppd")),
        printer_info: Some("Lobby Laser".into()),
        printer_location: Some("Floor 3".into()),
        server_root: Some(td.path().to_path_buf()),
        server_bin: Some(td.path().to_path_buf()),
        data_dir: Some(td.path().to_path_buf()),
        cache_dir: Some(td.path().to_path_buf()),
        request_root: Some(td.path().to_path_buf()),
        state_dir: Some(td.path().to_path_buf()),
        temp_dir: Some(td.path().to_path_buf()),
        rip_max_cache: Some("64m".into()),
        document_number: Some(1),
        document_name: Some("doc1.txt".into()),
        capture_backend_stdout: true,
        ..SpawnOptions::default()
    };

    let mut pipe = spec.spawn_with_options(&chain, &opts).expect("spawn");
    assert!(pipe.pgid().is_some());
    assert_eq!(pipe.pids().len(), 4);
    assert!(pipe.backchannel().is_some());
    assert!(pipe.sidechannel().is_some());
    assert!(pipe.take_backchannel().is_some());
    assert!(pipe.take_sidechannel().is_some());

    let mut b_out = String::new();
    pipe.take_backend_stdout()
        .expect("backend stdout")
        .read_to_string(&mut b_out)
        .expect("read backend stdout");
    assert_eq!(b_out, "backend-stdout-ok");

    let rx = pipe.take_status_receiver().expect("status rx");
    let exit = pipe.wait_all().expect("wait_all");
    assert!(exit.is_ok(), "unexpected exit: {exit:?}");
    assert_eq!(exit.backend, BackendExit::Ok);
    assert_eq!(exit.filters.len(), 3);

    // Crucial P0 verification: data flowed through f1 -> f2 -> f3 -> backend sequentially!
    let result = fs::read_to_string(&out_file).expect("read backend out");
    assert_eq!(result, "PAYLOAD:f1:f2:f3:backend");

    let events: Vec<_> = rx.try_iter().collect();
    assert!(events.iter().any(|m| {
        !m.is_backend
            && m.event
                == StatusEvent::Log {
                    severity: LogSeverity::Info,
                    message: "stage 1 started".into(),
                }
    }));
    assert!(events.iter().any(|m| {
        m.event == StatusEvent::State(vec![StateChange::Add("marker-supply-low-warning".into())])
    }));
    assert!(events.iter().any(|m| {
        m.event
            == StatusEvent::Page(PageEvent::Sheet {
                page: 1,
                copies: 1,
                extra: Some("media=letter".into()),
            })
    }));
    assert!(events
        .iter()
        .any(|m| m.event == StatusEvent::Page(PageEvent::Total(2))));
    assert!(events.iter().any(|m| {
        m.is_backend
            && m.event
                == StatusEvent::State(vec![StateChange::Remove(
                    "marker-supply-low-warning".into(),
                )])
    }));
}

#[test]
fn empty_chain_passes_data_file_to_backend_and_drain_status_works() {
    let td = TestDir::new("empty-chain");
    let backend_dir = td.path().join("backend");
    let spool = td.path().join("d00001-001");
    let out_file = td.path().join("direct.txt");
    fs::write(&spool, b"DIRECT-RAW").expect("write spool");

    write_script(
        &backend_dir,
        "socket",
        &format!(
            r#"#!/bin/sh
set -eu
if [ "$#" -ne 6 ]; then exit 99; fi
echo "INFO: direct print" >&2
cat "$6" > "{}"
"#,
            out_file.display()
        ),
    );

    let spec = base_spec(td.path(), spool, "", "socket://127.0.0.1:9100");
    let mut pipe = spec.spawn(&[]).expect("spawn direct");
    assert!(pipe.filters.is_empty());
    let status = pipe.backend.wait().expect("wait backend");
    assert!(status.success());
    // Wait briefly for stderr thread then drain internal status receiver directly.
    std::thread::sleep(Duration::from_millis(40));
    let drained = pipe.drain_status_events();
    assert!(drained.iter().any(|m| m.is_backend));
    assert_eq!(fs::read_to_string(&out_file).expect("read"), "DIRECT-RAW");
}

#[test]
fn spawn_with_external_status_tx_and_cups_exec_wrapper() {
    let td = TestDir::new("cupsexec");
    let filter_dir = td.path().join("filter");
    let backend_dir = td.path().join("backend");
    let daemon_dir = td.path().join("daemon");
    let spool = td.path().join("d00002-001");
    let out_file = td.path().join("exec_out.txt");
    fs::write(&spool, b"EXEC-DATA").expect("write spool");

    // Mock cups-exec: verifies 6+ args (<profile> <uid> <gid> <nice> <prog> <argv0> [args...])
    // and execs `<prog>` with `[args...]`.
    let mock_exec = write_script(
        &daemon_dir,
        "cups-exec",
        r#"#!/bin/sh
set -eu
profile="$1"; uid="$2"; gid="$3"; nice="$4"; prog="$5"; argv0="$6"
shift 6
echo "DEBUG: cups-exec profile=$profile uid=$uid gid=$gid nice=$nice argv0=$argv0" >&2
exec "$prog" "$@"
"#,
    );

    write_script(
        &filter_dir,
        "upper",
        r#"#!/bin/sh
tr 'a-z' 'A-Z' < "$6"
"#,
    );
    write_script(
        &backend_dir,
        "file",
        &format!(
            r#"#!/bin/sh
cat > "{}"
"#,
            out_file.display()
        ),
    );

    let spec = base_spec(td.path(), spool, "file", "file:///dev/null");
    let (tx, rx) = mpsc::channel();
    let mut opts = SpawnOptions {
        status_tx: Some(tx),
        enable_backchannel: false,
        ..SpawnOptions::default()
    };
    opts.sandbox.cups_exec_path = Some(mock_exec);
    opts.sandbox.mode = Sandboxing::Strict;
    opts.sandbox.nice = 5;

    let chain = vec![Conv {
        src: "text/plain".into(),
        dst: "application/vnd.cups-raw".into(),
        cost: 10,
        program: "upper".into(),
    }];

    let pipe = spec
        .spawn_with_options(&chain, &opts)
        .expect("spawn via cups-exec");
    assert_eq!(pipe.drain_status_events(), Vec::new()); // external tx owns events
    let exit = pipe.wait_all().expect("wait");
    assert!(exit.is_ok());
    assert_eq!(fs::read_to_string(&out_file).expect("read"), "EXEC-DATA");

    let msgs: Vec<_> = rx.try_iter().collect();
    assert!(msgs
        .iter()
        .any(|m| m.raw.contains("cups-exec profile=strict ")));
    assert!(msgs
        .iter()
        .any(|m| m.raw.contains("cups-exec profile=strict-backend ")));

    // Sandboxing::Off bypasses cups-exec even if path is configured.
    opts.sandbox.mode = Sandboxing::Off;
    let pipe_off = spec.spawn_with_options(&chain, &opts).expect("spawn off");
    assert!(pipe_off.wait_all().expect("wait off").is_ok());

    // Invalid cups_exec_path ("/") fails cleanly before spawning.
    opts.sandbox.mode = Sandboxing::Strict;
    opts.sandbox.cups_exec_path = Some(PathBuf::from("/"));
    assert!(spec.spawn_with_options(&chain, &opts).is_err());

    // Mid-chain spawn error (nonexistent interpreter in stage 2 / backend) cleans up stage 1.
    write_script(&filter_dir, "bad_f2", "#!/nonexistent/interp-xyz\n");
    write_script(&backend_dir, "bad_be", "#!/nonexistent/interp-xyz\n");
    let mut clean_opts = SpawnOptions::default();
    clean_opts.sandbox.mode = Sandboxing::Off;
    let bad_chain = vec![
        Conv {
            src: "text/plain".into(),
            dst: "text/mid".into(),
            cost: 10,
            program: "upper".into(),
        },
        Conv {
            src: "text/mid".into(),
            dst: "application/vnd.cups-raw".into(),
            cost: 10,
            program: "bad_f2".into(),
        },
    ];
    assert!(spec.spawn_with_options(&bad_chain, &clean_opts).is_err());
    assert!(spec
        .spawn_filters_only(&bad_chain, &clean_opts, Stdio::piped())
        .is_err());

    let mut bad_be_spec = spec.clone();
    bad_be_spec.backend = "bad_be".into();
    bad_be_spec.device_uri = "bad-be://host".into();
    assert!(bad_be_spec.spawn_with_options(&chain, &clean_opts).is_err());
}

#[test]
fn spawn_filters_only_and_multi_document_helper() {
    let td = TestDir::new("filters-only");
    let filter_dir = td.path().join("filter");
    let doc1 = td.path().join("doc1");
    fs::write(&doc1, b"hello").expect("write doc");

    write_script(
        &filter_dir,
        "wrap1",
        r#"#!/bin/sh
echo "INFO: wrap1" >&2
printf '[%s]' "$(cat "$6")"
"#,
    );
    write_script(
        &filter_dir,
        "wrap2",
        r#"#!/bin/sh
printf '<%s>' "$(cat)"
"#,
    );

    let base = base_spec(
        td.path(),
        PathBuf::from("/unused"),
        "file",
        "file:///dev/null",
    );
    let jdoc = JobDocument {
        number: 2,
        name: Some("second.txt".into()),
        data_file: doc1,
        src_type: "text/plain".into(),
        chain: vec![
            Conv {
                src: "text/plain".into(),
                dst: "text/step1".into(),
                cost: 10,
                program: "wrap1".into(),
            },
            Conv {
                src: "text/step1".into(),
                dst: "text/step2".into(),
                cost: 10,
                program: "wrap2".into(),
            },
        ],
    };

    let (doc_spec, doc_opts) = base.for_document(&jdoc, &SpawnOptions::default());
    assert_eq!(doc_opts.document_number, Some(2));
    assert_eq!(doc_opts.document_name.as_deref(), Some("second.txt"));

    // Empty filter chain errors cleanly.
    assert!(doc_spec
        .spawn_filters_only(&[], &doc_opts, Stdio::piped())
        .is_err());

    let mut run = doc_spec
        .spawn_filters_only(&jdoc.chain, &doc_opts, Stdio::piped())
        .expect("spawn_filters_only");
    assert!(run.pgid().is_some());
    let rx = run.take_status_receiver().expect("rx");
    let mut output = String::new();
    run.stdout
        .take()
        .expect("stdout")
        .read_to_string(&mut output)
        .expect("read");
    let exits = run.wait_all().expect("wait");
    assert_eq!(exits.len(), 2);
    assert!(exits.iter().all(|e| e.success()));
    assert_eq!(output, "<[hello]>");
    assert!(rx.try_iter().any(|m| m.raw.contains("wrap1")));
}

struct RecordingSender(Vec<(u32, KillSignal)>);

impl SignalSender for RecordingSender {
    fn signal_group(&mut self, _pgid: i32, _sig: KillSignal) -> io::Result<()> {
        Ok(())
    }
    fn signal_pid(&mut self, pid: u32, sig: KillSignal) -> io::Result<()> {
        self.0.push((pid, sig));
        kill_pid(pid, sig)
    }
}

#[test]
fn kill_job_graceful_sigterm_and_sigkill_escalation() {
    let td = TestDir::new("killjob");
    let filter_dir = td.path().join("filter");
    let backend_dir = td.path().join("backend");
    let spool = td.path().join("spool");
    fs::write(&spool, b"data").expect("write");

    // Case 1: graceful SIGTERM exit (exec replaces shell so no stray subshell holds pipes).
    write_script(&filter_dir, "sleeper", "#!/bin/sh\nexec sleep 30\n");
    write_script(&backend_dir, "socket", "#!/bin/sh\nexec sleep 30\n");

    let spec = base_spec(
        td.path(),
        spool.clone(),
        "socket",
        "socket://127.0.0.1:9100",
    );
    let chain = vec![Conv {
        src: "text/plain".into(),
        dst: "application/vnd.cups-raw".into(),
        cost: 10,
        program: "sleeper".into(),
    }];
    let mut pipe = spec.spawn(&chain).expect("spawn");
    let exit = pipe
        .kill_job(Duration::from_secs(2))
        .expect("kill_job graceful");
    assert!(!exit.is_ok());
    assert!(matches!(exit.backend, BackendExit::Signal(_)));

    // Case 2: BOTH filter and backend ignore SIGTERM -> escalates to SIGKILL after delay.
    write_script(
        &filter_dir,
        "stubborn_f",
        "#!/bin/sh\ntrap '' TERM\nsleep 30\n",
    );
    write_script(
        &backend_dir,
        "stubborn",
        "#!/bin/sh\ntrap '' TERM\nsleep 30\n",
    );
    let mut spec2 = base_spec(td.path(), spool.clone(), "stubborn", "stubborn://host");
    let chain_stubborn = vec![Conv {
        src: "text/plain".into(),
        dst: "application/vnd.cups-raw".into(),
        cost: 10,
        program: "stubborn_f".into(),
    }];
    let opts2 = SpawnOptions {
        process_group: true,
        ..SpawnOptions::default()
    };
    let mut pipe2 = spec2
        .spawn_with_options(&chain_stubborn, &opts2)
        .expect("spawn stubborn");
    // Give shells a tiny moment to install trap.
    std::thread::sleep(Duration::from_millis(50));
    let exit2 = pipe2
        .kill_job(Duration::from_millis(80))
        .expect("kill_job escalate");
    assert!(!exit2.is_ok());
    assert_eq!(exit2.filters.len(), 1);

    // Case 3: `process_group: false` exercises per-PID signaling path via custom SignalSender.
    spec2.backend = "socket".into();
    spec2.device_uri = "socket://127.0.0.1:9100".into();
    let opts3 = SpawnOptions {
        process_group: false,
        ..SpawnOptions::default()
    };
    let mut pipe3 = spec2
        .spawn_with_options(&chain, &opts3)
        .expect("spawn no pg");
    assert!(pipe3.pgid().is_none());
    let mut rec = RecordingSender(Vec::new());
    let exit3 = pipe3
        .kill_job_with_sender(Duration::from_secs(1), &mut rec)
        .expect("kill no pg");
    assert!(!exit3.is_ok());
    assert_eq!(rec.0.len(), 2);
    assert!(rec.0.iter().all(|(_, s)| *s == KillSignal::Term));

    // Safety guard: unsafe pgid/pid values rejected; nonexistent pid returns kill error.
    assert!(kill_process_group(0, KillSignal::Term).is_err());
    assert!(kill_process_group(1, KillSignal::Kill).is_err());
    assert!(kill_process_group(-5, KillSignal::Term).is_err());
    assert!(kill_pid(0, KillSignal::Term).is_err());
    assert!(kill_pid(1, KillSignal::Kill).is_err());
    let mut os_sender = OsSignalSender;
    assert!(os_sender.signal_pid(999_999_999, KillSignal::Term).is_err());
}

#[test]
#[allow(clippy::too_many_lines)]
fn security_uri_scheme_path_traversal_permissions_and_env() {
    // URI schemes
    assert_eq!(validate_uri_scheme("ipp://h/p").expect("ok"), "ipp");
    assert_eq!(validate_uri_scheme("HTTPS://h/p").expect("ok"), "https");
    assert_eq!(validate_uri_scheme("x+v1.2-a:foo").expect("ok"), "x+v1.2-a");
    assert_eq!(try_backend_for_uri("http://h/p").expect("ok"), "ipp");
    assert_eq!(try_backend_for_uri("https://h/p").expect("ok"), "ipp");
    assert_eq!(try_backend_for_uri("ipps://h/p").expect("ok"), "ipp");
    assert_eq!(
        try_backend_for_uri("socket://h:9100").expect("ok"),
        "socket"
    );
    assert_eq!(backend_for_uri("lpd://h/q"), "lpd");
    assert_eq!(backend_for_uri("/bin/sh:x"), "");

    for bad in [
        "noscheme",
        ":empty",
        "1bad://x",
        "/bin/sh:foo",
        "../evil:bar",
        "a..b:foo",
        "bad/scheme:x",
        "bad scheme:x",
        "bad\x00:x",
        "ipp://host/p\r\nEvil: 1",
        &format!("{}:x", "a".repeat(65)),
    ] {
        assert!(
            validate_uri_scheme(bad).is_err(),
            "expected err for {bad:?}"
        );
    }

    // Program names
    assert!(validate_program_name("pdftoraster").is_ok());
    for bad in [
        "",
        "-",
        "../evil",
        "a/../b",
        "bad\0name",
        "bad name",
        "bad\n",
        "a\\b",
    ] {
        assert!(
            validate_program_name(bad).is_err(),
            "expected err for {bad:?}"
        );
    }

    // On-disk resolution security checks
    let td = TestDir::new("sec");
    let trusted = td.path().join("filter");
    let outside = td.path().join("outside");
    let ok_bin = write_script(&trusted, "good", "#!/bin/sh\nexit 0\n");
    let outside_bin = write_script(&outside, "evil", "#!/bin/sh\nexit 0\n");

    let policy = SecurityPolicy::for_current_process();
    assert_eq!(
        resolve_trusted_executable(&trusted, "good", &policy).expect("ok"),
        fs::canonicalize(&ok_bin).expect("canon")
    );
    // Absolute path inside trusted dir allowed.
    assert!(resolve_trusted_executable(&trusted, ok_bin.to_str().expect("str"), &policy).is_ok());
    // Absolute path outside trusted dir rejected.
    assert!(
        resolve_trusted_executable(&trusted, outside_bin.to_str().expect("str"), &policy).is_err()
    );
    // Explicitly allowed extra trusted dir permits it.
    let mut extra_pol = policy.clone();
    extra_pol.allow_extra_trusted_dirs.push(outside.clone());
    assert!(
        resolve_trusted_executable(&trusted, outside_bin.to_str().expect("str"), &extra_pol)
            .is_ok()
    );
    // Relative path with '/' rejected.
    assert!(resolve_trusted_executable(&trusted, "sub/good", &policy).is_err());
    // Missing trusted dir rejected.
    assert!(resolve_trusted_executable(&td.path().join("no-such-dir"), "good", &policy).is_err());

    // Symlink executable rejected.
    let link = trusted.join("sym_evil");
    std::os::unix::fs::symlink(&outside_bin, &link).expect("symlink");
    assert!(resolve_trusted_executable(&trusted, "sym_evil", &policy).is_err());

    // Non-executable rejected.
    let noexec = trusted.join("noexec");
    fs::write(&noexec, b"hi").expect("write");
    fs::set_permissions(&noexec, fs::Permissions::from_mode(0o644)).expect("chmod");
    assert!(resolve_trusted_executable(&trusted, "noexec", &policy).is_err());

    // Group/world-writable rejected.
    let gw = write_script(&trusted, "gw", "#!/bin/sh\n");
    fs::set_permissions(&gw, fs::Permissions::from_mode(0o775)).expect("chmod");
    assert!(resolve_trusted_executable(&trusted, "gw", &policy).is_err());

    // Pure metadata checks (root-owner, setuid, non-regular, untrusted uid).
    let strict = SecurityPolicy::strict();
    assert_eq!(SecurityPolicy::for_euid(0), strict);
    assert!(verify_executable_metadata(Path::new("/x"), true, 0o755, 0, &strict).is_ok());
    assert!(verify_executable_metadata(Path::new("/x"), true, 0o755, 1000, &strict).is_err());
    assert!(verify_executable_metadata(Path::new("/x"), false, 0o755, 0, &strict).is_err());
    assert!(verify_executable_metadata(Path::new("/x"), true, 0o644, 0, &strict).is_err());
    assert!(verify_executable_metadata(Path::new("/x"), true, 0o775, 0, &strict).is_err());
    assert!(verify_executable_metadata(Path::new("/x"), true, 0o4755, 0, &strict).is_err());
    assert!(verify_executable_metadata(Path::new("/x"), true, 0o2755, 0, &strict).is_err());
    let nonroot = SecurityPolicy::for_euid(1000);
    assert!(verify_executable_metadata(Path::new("/x"), true, 0o755, 1000, &nonroot).is_ok());
    assert!(verify_executable_metadata(Path::new("/x"), true, 0o755, 2000, &nonroot).is_err());

    // Spool symlink rejected during spawn.
    let backend_dir = td.path().join("backend");
    write_script(&backend_dir, "file", "#!/bin/sh\nexit 0\n");
    let real_spool = td.path().join("real_spool");
    fs::write(&real_spool, b"abc").expect("write");
    let sym_spool = td.path().join("sym_spool");
    std::os::unix::fs::symlink(&real_spool, &sym_spool).expect("symlink");
    let sym_spec = base_spec(td.path(), sym_spool, "file", "file:///dev/null");
    assert!(sym_spec.spawn(&[]).is_err());

    // Environment sanitization.
    let mut raw_env = HashMap::new();
    raw_env.insert("LD_PRELOAD".into(), "/bad.so".into());
    raw_env.insert("LD_LIBRARY_PATH".into(), "/bad".into());
    raw_env.insert("PATH".into(), "/bad".into());
    raw_env.insert("DEVICE_URI".into(), "ipp://secret".into());
    raw_env.insert("AUTH_PASSWORD".into(), "pw".into());
    raw_env.insert(String::new(), "empty".into());
    raw_env.insert("BAD=KEY".into(), "x".into());
    raw_env.insert("NUL\0K".into(), "x".into());
    raw_env.insert("OK_K".into(), "nul\0v".into());
    raw_env.insert("SAFE_VAR".into(), "hello".into());
    let cleaned = sanitize_extra_env(&raw_env);
    assert_eq!(cleaned.len(), 1);
    assert_eq!(cleaned.get("SAFE_VAR").map(String::as_str), Some("hello"));
    assert_eq!(sanitize_env_value("a\0b"), "ab");

    // `/proc/self/status` parser
    assert_eq!(
        parse_proc_status_ids(
            "Name:\ttest\nUid:\t1000\t1001\t1001\t1001\nGid:\t100\t101\t101\t101\n"
        ),
        Some((1001, 101))
    );
    assert_eq!(parse_proc_status_ids("Name:\ttest\n"), None);
    let (euid, _egid) = current_euid_egid();
    assert_ne!(euid, u32::MAX);
}

#[test]
#[allow(clippy::too_many_lines)]
fn status_parser_and_bounded_statbuf() {
    assert_eq!(
        parse_status_line("EMERG: disk full\r\n"),
        StatusEvent::Log {
            severity: LogSeverity::Emerg,
            message: "disk full".into()
        }
    );
    assert_eq!(
        parse_status_line("ALERT: hot"),
        StatusEvent::Log {
            severity: LogSeverity::Alert,
            message: "hot".into()
        }
    );
    assert_eq!(
        parse_status_line("CRIT: fault"),
        StatusEvent::Log {
            severity: LogSeverity::Crit,
            message: "fault".into()
        }
    );
    assert_eq!(
        parse_status_line("ERROR: fail"),
        StatusEvent::Log {
            severity: LogSeverity::Error,
            message: "fail".into()
        }
    );
    assert_eq!(
        parse_status_line("WARNING: warn"),
        StatusEvent::Log {
            severity: LogSeverity::Warning,
            message: "warn".into()
        }
    );
    assert_eq!(
        parse_status_line("NOTICE: note"),
        StatusEvent::Log {
            severity: LogSeverity::Notice,
            message: "note".into()
        }
    );
    assert_eq!(
        parse_status_line("INFO: ready"),
        StatusEvent::Log {
            severity: LogSeverity::Info,
            message: "ready".into()
        }
    );
    assert_eq!(
        parse_status_line("DEBUG: trace"),
        StatusEvent::Log {
            severity: LogSeverity::Debug,
            message: "trace".into()
        }
    );
    assert_eq!(
        parse_status_line("DEBUG2: verbose"),
        StatusEvent::Log {
            severity: LogSeverity::Debug2,
            message: "verbose".into()
        }
    );
    assert_eq!(
        parse_status_line("plain text"),
        StatusEvent::Log {
            severity: LogSeverity::Debug,
            message: "plain text".into()
        }
    );

    assert_eq!(
        parse_state_changes(" +toner-low,-media-empty,none,connecting-to-device + - "),
        vec![
            StateChange::Add("toner-low".into()),
            StateChange::Remove("media-empty".into()),
            StateChange::Clear,
            StateChange::Set("connecting-to-device".into()),
        ]
    );

    assert_eq!(parse_page_event(" total 12 "), Some(PageEvent::Total(12)));
    assert_eq!(parse_page_event("total   42"), Some(PageEvent::Total(42)));
    assert_eq!(parse_page_event("total\t\t7"), Some(PageEvent::Total(7)));
    assert_eq!(
        parse_page_event("2 3"),
        Some(PageEvent::Sheet {
            page: 2,
            copies: 3,
            extra: None
        })
    );
    assert_eq!(
        parse_page_event("1  2"),
        Some(PageEvent::Sheet {
            page: 1,
            copies: 2,
            extra: None
        })
    );
    assert_eq!(
        parse_page_event("1\t\t3   media=a4  extra"),
        Some(PageEvent::Sheet {
            page: 1,
            copies: 3,
            extra: Some("media=a4  extra".into())
        })
    );
    assert_eq!(
        parse_page_event("1 1 job-billing=acme"),
        Some(PageEvent::Sheet {
            page: 1,
            copies: 1,
            extra: Some("job-billing=acme".into())
        })
    );
    assert_eq!(parse_page_event("bad"), None);
    assert_eq!(parse_page_event("   "), None);
    assert_eq!(
        parse_status_line("PAGE: bad"),
        StatusEvent::Log {
            severity: LogSeverity::Debug,
            message: "PAGE: bad".into()
        }
    );

    assert_eq!(
        parse_kv_pairs(r#"a=1 b="hello \"world\"" c='two words' d=foo\ bar bare"#),
        vec![
            ("a".into(), "1".into()),
            ("b".into(), "hello \"world\"".into()),
            ("c".into(), "two words".into()),
            ("d".into(), "foo bar".into()),
            ("bare".into(), String::new()),
        ]
    );
    assert_eq!(
        parse_status_line("ATTR: marker-colors=#000000"),
        StatusEvent::Attr(vec![("marker-colors".into(), "#000000".into())])
    );
    assert_eq!(
        parse_status_line("PPD: Duplex=DuplexNoTumble"),
        StatusEvent::Ppd(vec![("Duplex".into(), "DuplexNoTumble".into())])
    );

    // Bounded StatBuf truncates huge lines without OOM and recovers on next newline.
    let sb = StatBuf::new(24);
    let input = format!("INFO: {}\nWARNING: ok\r\nDEBUG: tail", "x".repeat(200));
    let mut seen = Vec::new();
    let count = sb
        .read_all(input.as_bytes(), |ev, raw| seen.push((ev, raw)))
        .expect("read_all");
    assert_eq!(count, 3);
    assert_eq!(seen[0].1.len(), 24);
    assert_eq!(
        seen[1].0,
        StatusEvent::Log {
            severity: LogSeverity::Warning,
            message: "ok".into()
        }
    );
    assert_eq!(
        seen[2].0,
        StatusEvent::Log {
            severity: LogSeverity::Debug,
            message: "tail".into()
        }
    );
}

#[test]
fn backchannel_and_sidechannel_protocol_and_ipc() {
    assert_eq!(CUPS_BC_FD, 3);
    assert_eq!(CUPS_SC_FD, 4);

    // Backchannel pipe
    let mut bc = BackChannel::new().expect("backchannel");
    assert!(bc.read_fd() >= 0);
    assert!(bc.write_fd() >= 0);
    let _ = bc.reader();
    let _ = bc.writer();
    bc.write_all(b"printer-ack").expect("write");
    let mut buf = [0u8; 32];
    let n = bc.read(&mut buf).expect("read");
    assert_eq!(&buf[..n], b"printer-ack");
    let (_r, _w) = bc.split();

    // Sidechannel enum round-trips
    for v in 0..=8u8 {
        let cmd = SideChannelCommand::from_u8(v).expect("valid cmd");
        assert_eq!(cmd.as_u8(), v);
    }
    assert_eq!(SideChannelCommand::from_u8(99), None);

    for v in 0..=7u8 {
        let st = SideChannelStatus::from_u8(v).expect("valid status");
        assert_eq!(st.as_u8(), v);
    }
    assert_eq!(SideChannelStatus::from_u8(99), None);

    // Codec edge cases
    let msg = SideChannelMessage::response(
        SideChannelCommand::GetDeviceId,
        SideChannelStatus::Ok,
        b"MFG:ACME;MDL:Laser;".to_vec(),
    );
    let wire = msg.encode().expect("encode");
    assert_eq!(SideChannelMessage::decode(&wire).expect("decode"), msg);

    let too_big = SideChannelMessage::request(SideChannelCommand::SnmpGet, vec![0u8; 70_000]);
    assert!(too_big.encode().is_err());
    assert!(SideChannelMessage::decode(&[1, 2]).is_err());
    assert!(SideChannelMessage::decode(&[99, 0, 0, 0]).is_err());
    assert!(SideChannelMessage::decode(&[1, 99, 0, 0]).is_err());
    assert!(SideChannelMessage::decode(&[1, 0, 0, 5, 1, 2]).is_err());

    // Live AF_UNIX SOCK_DGRAM socketpair request/response
    let sc = SideChannel::new().expect("sidechannel");
    assert!(sc.filter_end().raw_fd() >= 0);
    assert!(sc.backend_end().raw_fd() >= 0);
    let (filter_end, backend_end) = sc.split();

    let server = std::thread::spawn(move || {
        let req = backend_end
            .recv(Some(Duration::from_secs(2)))
            .expect("recv req");
        assert_eq!(req.command, SideChannelCommand::GetDeviceId);
        let resp = SideChannelMessage::response(
            SideChannelCommand::GetDeviceId,
            SideChannelStatus::Ok,
            b"ID=123".to_vec(),
        );
        backend_end.send(&resp).expect("send resp");

        // Second request: intentionally send mismatched command to test validation.
        let _req2 = backend_end
            .recv(Some(Duration::from_secs(2)))
            .expect("recv req2");
        backend_end
            .send(&SideChannelMessage::response(
                SideChannelCommand::SoftReset,
                SideChannelStatus::Ok,
                Vec::new(),
            ))
            .expect("send mismatch");
    });

    let reply = filter_end
        .do_request(SideChannelCommand::GetDeviceId, b"", Duration::from_secs(2))
        .expect("do_request");
    assert_eq!(reply.status, SideChannelStatus::Ok);
    assert_eq!(reply.data, b"ID=123");

    let mismatch = filter_end.do_request(SideChannelCommand::GetState, b"", Duration::from_secs(2));
    assert!(mismatch.is_err());
    server.join().expect("join");
}

struct MockOps {
    ids: (u32, u32),
    nice_err: Option<io::ErrorKind>,
    fail_drop: bool,
    dropped: Option<(u32, u32)>,
    nnp: bool,
    ll_rules: usize,
}

impl SandboxOps for MockOps {
    fn current_euid_egid(&self) -> (u32, u32) {
        self.ids
    }
    fn set_umask(&mut self, _mask: u32) -> u32 {
        0o022
    }
    fn set_nice(&mut self, _nice: i32) -> io::Result<()> {
        match self.nice_err {
            Some(k) => Err(io::Error::new(k, "nice err")),
            None => Ok(()),
        }
    }
    fn set_rlimits(&mut self, _limits: &Rlimits) -> io::Result<()> {
        Ok(())
    }
    fn drop_privileges(&mut self, uid: u32, gid: u32, _u: Option<&str>) -> io::Result<()> {
        if self.fail_drop {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "drop fail"));
        }
        self.dropped = Some((uid, gid));
        Ok(())
    }
    fn set_no_new_privs(&mut self) -> io::Result<()> {
        self.nnp = true;
        Ok(())
    }
    fn apply_landlock(&mut self, rules: &[LandlockRule]) -> io::Result<LandlockStatus> {
        self.ll_rules = rules.len();
        Ok(LandlockStatus::Enforced { abi: 3 })
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn sandbox_rules_ops_exit_codes_and_ppd_options() {
    // Landlock rule builder across all modes
    let ctx = LandlockContext {
        server_bin: Some(PathBuf::from("/usr/lib/cups")),
        data_dir: Some(PathBuf::from("/usr/share/cups")),
        server_root: Some(PathBuf::from("/etc/cups")),
        cache_dir: Some(PathBuf::from("/var/cache/cups")),
        temp_dir: Some(PathBuf::from("/var/spool/cups/tmp")),
        spool_file: Some(PathBuf::from("/var/spool/cups/d00001-001")),
        ppd_file: Some(PathBuf::from("/etc/cups/ppd/p.ppd")),
        extra_read_paths: vec![PathBuf::from("/opt/fonts")],
        extra_write_paths: vec![PathBuf::from("/var/tmp/cups-extra")],
        allow_device_write: true,
    };
    assert_eq!(
        build_landlock_rules(Sandboxing::Off, false, &ctx),
        Vec::new()
    );
    let strict_filter = build_landlock_rules(Sandboxing::Strict, false, &ctx);
    assert!(!strict_filter.iter().any(|r| r.path == Path::new("/dev")));
    assert!(!strict_filter.iter().any(|r| r.path == Path::new("/etc")));
    let strict_backend = build_landlock_rules(Sandboxing::Strict, true, &ctx);
    assert!(strict_backend.iter().any(|r| r.path == Path::new("/dev")));
    let relaxed = build_landlock_rules(Sandboxing::Relaxed, false, &ctx);
    assert!(relaxed.iter().any(|r| r.path == Path::new("/etc")));

    assert_eq!(sandbox_profile_name(Sandboxing::Off, false), "none");
    assert_eq!(sandbox_profile_name(Sandboxing::Relaxed, false), "relaxed");
    assert_eq!(
        sandbox_profile_name(Sandboxing::Relaxed, true),
        "relaxed-backend"
    );
    assert_eq!(sandbox_profile_name(Sandboxing::Strict, false), "strict");
    assert_eq!(
        sandbox_profile_name(Sandboxing::Strict, true),
        "strict-backend"
    );

    let exec_args = build_cups_exec_args(
        "strict",
        7,
        7,
        -5,
        Path::new("/usr/lib/cups/filter/f1"),
        "myprinter",
        &["1".into(), "alice".into()],
    );
    assert_eq!(
        exec_args,
        vec![
            "strict",
            "7",
            "7",
            "0",
            "/usr/lib/cups/filter/f1",
            "myprinter",
            "1",
            "alice"
        ]
    );

    // SandboxConfig + SpawnOptions from cups_config::Config
    let mut cfg = Config {
        cupsd: CupsdConfig::defaults(),
        files: CupsFilesConfig::defaults(),
    };
    cfg.cupsd.filter_nice = 10;
    cfg.files.sandboxing = Sandboxing::Relaxed;
    let scfg = SandboxConfig::from_cups_config(&cfg);
    assert_eq!(scfg.mode, Sandboxing::Relaxed);
    assert_eq!(scfg.nice, 10);
    let sopts = SpawnOptions::from_cups_config(&cfg);
    assert_eq!(sopts.sandbox.mode, Sandboxing::Relaxed);

    // Mock SandboxOps covering root privdrop, unprivileged degradation, nice EACCES, Off mode
    let mut sb_cfg = SandboxConfig {
        mode: Sandboxing::Strict,
        uid: Some(7),
        gid: Some(7),
        username: Some("lp".into()),
        nice: 5,
        ..SandboxConfig::default()
    };

    // Root mode -> drops privileges cleanly.
    let mut ops_root = MockOps {
        ids: (0, 0),
        nice_err: None,
        fail_drop: false,
        dropped: None,
        nnp: false,
        ll_rules: 0,
    };
    let rep = apply_sandbox_with_ops(&sb_cfg, false, &ctx, &mut ops_root).expect("root sandbox");
    assert!(rep.privdrop_applied);
    assert!(!rep.privdrop_skipped_unprivileged);
    assert!(rep.no_new_privs_applied);
    assert!(rep.rlimits_applied);
    assert_eq!(
        rep.landlock_status,
        Some(LandlockStatus::Enforced { abi: 3 })
    );
    assert_eq!(ops_root.dropped, Some((7, 7)));

    // Root mode failing privdrop -> fails closed.
    ops_root.fail_drop = true;
    assert!(apply_sandbox_with_ops(&sb_cfg, false, &ctx, &mut ops_root).is_err());

    // Unprivileged mode -> skips privdrop gracefully, handles nice EACCES, enforces NNP + Landlock.
    let mut ops_user = MockOps {
        ids: (1000, 1000),
        nice_err: Some(io::ErrorKind::PermissionDenied),
        fail_drop: false,
        dropped: None,
        nnp: false,
        ll_rules: 0,
    };
    let rep_u = apply_sandbox_with_ops(&sb_cfg, true, &ctx, &mut ops_user).expect("user sandbox");
    assert!(!rep_u.nice_applied);
    assert!(!rep_u.privdrop_applied);
    assert!(rep_u.privdrop_skipped_unprivileged);
    assert!(rep_u.no_new_privs_applied);
    assert!(ops_user.nnp);

    // Non-EACCES nice error propagates.
    ops_user.nice_err = Some(io::ErrorKind::InvalidInput);
    assert!(apply_sandbox_with_ops(&sb_cfg, false, &ctx, &mut ops_user).is_err());

    // Sandboxing::Off + rlimits: None skips NNP/Landlock/rlimits.
    sb_cfg.mode = Sandboxing::Off;
    sb_cfg.rlimits = None;
    sb_cfg.uid = Some(1000);
    sb_cfg.gid = Some(1000);
    ops_user.nice_err = None;
    let rep_off = apply_sandbox_with_ops(&sb_cfg, false, &ctx, &mut ops_user).expect("off");
    assert!(!rep_off.rlimits_applied);
    assert!(!rep_off.privdrop_skipped_unprivileged);
    assert!(!rep_off.no_new_privs_applied);
    assert_eq!(rep_off.landlock_status, None);

    // Default temp_dir fallback in build_landlock_rules
    let default_ctx = LandlockContext::default();
    let default_rules = build_landlock_rules(Sandboxing::Strict, false, &default_ctx);
    assert!(default_rules.iter().any(|r| r.path == Path::new("/tmp")));

    // Live OsSandboxOps & apply_current_process_sandbox (safe no-op Off mode, restores umask).
    let mut os_ops = OsSandboxOps;
    let (live_u, live_g) = os_ops.current_euid_egid();
    assert_ne!(live_u, u32::MAX);
    assert!(os_ops.set_rlimits(&Rlimits::default()).is_ok());
    assert!(os_ops.drop_privileges(0, 0, None).is_err());
    let live_off_cfg = SandboxConfig {
        mode: Sandboxing::Off,
        uid: Some(live_u),
        gid: Some(live_g),
        rlimits: None,
        umask: 0o077,
        ..SandboxConfig::default()
    };
    let live_rep =
        apply_current_process_sandbox(&live_off_cfg, false, &default_ctx).expect("live off");
    let _ = os_ops.set_umask(live_rep.umask_prev); // restore test process umask
    assert_eq!(live_rep.landlock_status, None);

    // BackendExit classification
    let cases = [
        (
            0,
            BackendExit::Ok,
            true,
            false,
            false,
            false,
            false,
            "job-completed-successfully",
        ),
        (
            1,
            BackendExit::Failed,
            false,
            false,
            false,
            false,
            false,
            "job-aborted-by-system",
        ),
        (
            2,
            BackendExit::AuthRequired,
            false,
            false,
            false,
            true,
            false,
            "cups-held-for-authentication",
        ),
        (
            3,
            BackendExit::Hold,
            false,
            false,
            false,
            true,
            false,
            "job-hold-until-specified",
        ),
        (
            4,
            BackendExit::Stop,
            false,
            false,
            true,
            false,
            false,
            "job-aborted-by-system",
        ),
        (
            5,
            BackendExit::Cancel,
            false,
            false,
            false,
            false,
            true,
            "job-canceled-at-device",
        ),
        (
            6,
            BackendExit::Retry,
            false,
            true,
            false,
            false,
            false,
            "job-restartable",
        ),
        (
            7,
            BackendExit::RetryCurrent,
            false,
            true,
            false,
            false,
            false,
            "job-restartable",
        ),
        (
            42,
            BackendExit::Unknown(42),
            false,
            false,
            false,
            false,
            false,
            "job-aborted-by-system",
        ),
    ];
    for (code, expected, ok, retry, stop, hold, cancel, reason) in cases {
        let ex = BackendExit::from_code(code);
        assert_eq!(ex, expected);
        assert_eq!(ex.is_ok(), ok);
        assert_eq!(ex.should_retry(), retry);
        assert_eq!(ex.should_stop_printer(), stop);
        assert_eq!(ex.should_hold_job(), hold);
        assert_eq!(ex.should_cancel_job(), cancel);
        assert_eq!(ex.ipp_job_state_reason(), reason);
    }
    assert_eq!(
        BackendExit::Signal(9).ipp_job_state_reason(),
        "job-aborted-by-system"
    );
    let p_exit = PipelineExit {
        backend: BackendExit::Ok,
        filters: vec![
            FilterExit {
                index: 0,
                pid: 100,
                code: Some(0),
                signal: None,
            },
            FilterExit {
                index: 1,
                pid: 101,
                code: Some(1),
                signal: None,
            },
        ],
    };
    assert!(!p_exit.is_ok());

    // PPD filter parsing & option formatting
    let ppd = r#"
*PPD-Adobe: "4.3"
*cupsFilter: "application/vnd.cups-raster 50 rastertofoo"
*cupsFilter2: "application/pdf application/vnd.cups-pdf 10 pdftopdf"
*cupsFilter: "application/octet-stream 0 -"
*cupsFilter: "application/pdf 10 ../evil"
*cupsFilter: "invalid-mime 10 foo"
*cupsFilter: "application/pdf notanumber foo"
*cupsFilter: "too short"
*cupsFilter2: "too short 1"
*cupsFilter no-colon
"#;
    let parsed = parse_ppd_filters(ppd);
    assert_eq!(
        parsed,
        vec![
            PpdFilter {
                src: "application/vnd.cups-raster".into(),
                dst: "application/vnd.cups-raw".into(),
                cost: 50,
                program: "rastertofoo".into(),
            },
            PpdFilter {
                src: "application/pdf".into(),
                dst: "application/vnd.cups-pdf".into(),
                cost: 10,
                program: "pdftopdf".into(),
            },
            PpdFilter {
                src: "application/octet-stream".into(),
                dst: "application/vnd.cups-raw".into(),
                cost: 0,
                program: "-".into(),
            },
        ]
    );

    let formatted = format_job_options(&[
        ("media".into(), "iso_a4".into()),
        ("job-sheets".into(), "top \"secret\" \\x".into()),
        ("landscape".into(), String::new()),
        (String::new(), "ignored".into()),
    ]);
    assert_eq!(
        formatted,
        r#"media=iso_a4 job-sheets="top \"secret\" \\x" landscape"#
    );

    // Root privilege-drop & fail-closed validation (no supplementary group leak / no root filter).
    let strict_root_filter = SandboxConfig {
        mode: Sandboxing::Strict,
        uid: None,
        gid: None,
        ..SandboxConfig::default()
    };
    assert!(validate_stage_privilege_drop(0, false, &strict_root_filter, true).is_err());
    assert!(validate_stage_privilege_drop(0, false, &strict_root_filter, false).is_err());
    // Root backend under Strict requires cups-exec; allowed when cups-exec is present.
    assert!(validate_stage_privilege_drop(0, true, &strict_root_filter, false).is_err());
    assert!(validate_stage_privilege_drop(0, true, &strict_root_filter, true).is_ok());

    let strict_dropped = SandboxConfig {
        mode: Sandboxing::Strict,
        uid: Some(7),
        gid: Some(7),
        ..SandboxConfig::default()
    };
    // Without cups-exec, dropping from root is refused so root's supplementary group 0 cannot leak.
    assert!(validate_stage_privilege_drop(0, false, &strict_dropped, false).is_err());
    assert!(validate_stage_privilege_drop(0, false, &strict_dropped, true).is_ok());

    let off_with_drop = SandboxConfig {
        mode: Sandboxing::Off,
        uid: Some(7),
        gid: Some(7),
        ..SandboxConfig::default()
    };
    assert!(validate_stage_privilege_drop(0, false, &off_with_drop, false).is_err());
    assert!(validate_stage_privilege_drop(0, false, &off_with_drop, true).is_ok());

    let off_no_drop = SandboxConfig {
        mode: Sandboxing::Off,
        uid: None,
        gid: None,
        ..SandboxConfig::default()
    };
    assert!(validate_stage_privilege_drop(0, false, &off_no_drop, false).is_ok());
    assert!(validate_stage_privilege_drop(1000, false, &strict_root_filter, false).is_ok());
}

#[test]
fn verbose_backend_stdout_never_deadlocks_default_or_uncaptured_wait() {
    let td = TestDir::new("stdout-deadlock");
    let backend_dir = td.path().join("backend");
    let spool = td.path().join("spool");
    fs::write(&spool, b"hi").expect("write");

    // Backend writes 128 KiB (> Linux 64 KiB pipe buffer) to stdout.
    write_script(
        &backend_dir,
        "noisy",
        "#!/bin/sh\ndd if=/dev/zero bs=1024 count=128 2>/dev/null\nexit 0\n",
    );

    let spec = base_spec(td.path(), spool, "noisy", "noisy://host");

    // 1. Default (`capture_backend_stdout == false`): stdout goes to /dev/null -> never deadlocks.
    let mut pipe1 = spec.spawn(&[]).expect("spawn default");
    assert!(pipe1.take_backend_stdout().is_none());
    let exit1 = pipe1.wait_all().expect("wait default");
    assert!(exit1.is_ok());

    // 2. Opted-in (`capture_backend_stdout == true`) where caller calls `wait_all()` without
    //    draining stdout: `wait_all` closes pipe first -> backend gets SIGPIPE/EPIPE, never hangs.
    let opts = SpawnOptions {
        capture_backend_stdout: true,
        ..SpawnOptions::default()
    };
    let pipe2 = spec.spawn_with_options(&[], &opts).expect("spawn captured");
    let _exit2 = pipe2.wait_all().expect("wait captured without draining");
}
