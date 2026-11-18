use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

#[test]
fn cupsfilter_cli_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_cupsfilter");

    let help = Command::new(bin).arg("--help").output().expect("help");
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage: cupsfilter"));

    let id = SEQ.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("pw-cfilter-cli-{}-{id}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("share/mime")).expect("mkdir mime");
    fs::create_dir_all(root.join("lib/filter")).expect("mkdir filter");
    fs::create_dir_all(root.join("etc")).expect("mkdir etc");
    fs::create_dir_all(root.join("tmp")).expect("mkdir tmp");

    fs::write(
        root.join("share/mime/mime.types"),
        "text/plain txt printable(0,1024)\napplication/pdf pdf string(0,%PDF)\n",
    )
    .expect("write types");
    fs::write(
        root.join("share/mime/mime.convs"),
        "text/plain application/pdf 10 txt2pdf\n",
    )
    .expect("write convs");

    let filt = root.join("lib/filter/txt2pdf");
    fs::write(
        &filt,
        "#!/bin/sh\nprintf '%%PDF-1.4:%s' \"$(cat \"$6\")\"\n",
    )
    .expect("write filt");
    fs::set_permissions(&filt, fs::Permissions::from_mode(0o755)).expect("chmod");

    // 1. `--list-filters`
    let list = Command::new(bin)
        .args([
            "--list-filters",
            "-i",
            "text/plain",
            "-m",
            "application/pdf",
        ])
        .env("CUPS_DATADIR", root.join("share"))
        .env("CUPS_SERVERROOT", root.join("etc"))
        .env("CUPS_SERVERBIN", root.join("lib"))
        .output()
        .expect("list");
    assert!(list.status.success());
    assert_eq!(String::from_utf8_lossy(&list.stdout), "txt2pdf\n");

    // 2. Stdin -> filter -> stdout
    let mut child = Command::new(bin)
        .args(["-m", "application/pdf"])
        .env("CUPS_DATADIR", root.join("share"))
        .env("CUPS_SERVERROOT", root.join("etc"))
        .env("CUPS_SERVERBIN", root.join("lib"))
        .env("TMPDIR", root.join("tmp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"HELLO")
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "%PDF-1.4:HELLO");

    let _ = fs::remove_dir_all(&root);
}
