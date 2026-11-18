use std::process::Command;

#[test]
fn parallel_cli_discovery_and_bad_uri() {
    let bin = env!("CARGO_BIN_EXE_parallel");
    let out = Command::new(bin).output().unwrap();
    assert!(out.status.success());

    let fail = Command::new(bin)
        .args(["1", "u", "t", "1", ""])
        .env("DEVICE_URI", "bad://uri")
        .output()
        .unwrap();
    assert_eq!(fail.status.code(), Some(1));
}
