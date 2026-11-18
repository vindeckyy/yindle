use std::process::Command;

#[test]
fn ipp_cli_discovery_and_bad_uri() {
    let bin = env!("CARGO_BIN_EXE_ipp");
    let out = Command::new(bin).output().unwrap();
    assert!(out.status.success());
    let txt = String::from_utf8_lossy(&out.stdout);
    assert!(txt.contains("network ipp "));
    assert!(txt.contains("network ipps "));
    assert!(txt.contains("network http "));
    assert!(txt.contains("network https "));

    let fail = Command::new(bin)
        .args(["1", "u", "t", "1", ""])
        .env("DEVICE_URI", "ftp://invalid/queue")
        .env("AUTH_USERNAME", "alice")
        .env("AUTH_PASSWORD", "secret")
        .output()
        .unwrap();
    assert_eq!(fail.status.code(), Some(1));
}
