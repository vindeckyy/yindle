use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn cups_lpd_cli_valid_and_invalid_ipp_port() {
    let bin = env!("CARGO_BIN_EXE_cups-lpd");

    // Invalid IPP_PORT (header injection attempt) must fail closed.
    let bad = Command::new(bin)
        .env("IPP_PORT", "631\r\nX-Injected: 1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!bad.status.success());

    // Valid 0x01 print-waiting command exits 0 and writes 0x00 ACK.
    let mut child = Command::new(bin)
        .env("IPP_PORT", "631")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"\x01lp\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, vec![0]);
}
