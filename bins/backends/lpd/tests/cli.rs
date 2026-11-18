use std::process::Command;

#[test]
fn lpd_cli_discovery_and_bad_uri() {
    let bin = env!("CARGO_BIN_EXE_lpd");
    let out = Command::new(bin).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("network lpd "));

    let fail = Command::new(bin)
        .args(["1", "u", "t", "1", ""])
        .env("DEVICE_URI", "bad://uri")
        .output()
        .unwrap();
    assert_eq!(fail.status.code(), Some(1));
}
