use std::process::Command;

#[test]
fn file_cli_discovery_and_policy_block() {
    let bin = env!("CARGO_BIN_EXE_file");
    let out = Command::new(bin).output().unwrap();
    assert!(out.status.success());

    let fail = Command::new(bin)
        .args(["1", "u", "t", "1", ""])
        .env("DEVICE_URI", "file:///tmp/blocked.out")
        .env_remove("CUPS_FILE_DEVICE")
        .env_remove("CUPS_SERVERROOT")
        .output()
        .unwrap();
    assert_eq!(fail.status.code(), Some(1));
}
