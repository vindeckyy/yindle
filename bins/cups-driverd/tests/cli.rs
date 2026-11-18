use std::process::Command;

#[test]
fn cups_driverd_cli_list_cat_and_traversal_reject() {
    let bin = env!("CARGO_BIN_EXE_cups-driverd");

    let list = Command::new(bin)
        .args(["list", "1", "5", "include-schemes=drv"])
        .output()
        .unwrap();
    assert!(list.status.success());
    assert!(String::from_utf8_lossy(&list.stdout).contains("\"everywhere\""));

    let cat = Command::new(bin)
        .args(["cat", "everywhere"])
        .output()
        .unwrap();
    assert!(cat.status.success());
    assert!(String::from_utf8_lossy(&cat.stdout).contains("*PPD-Adobe:"));

    let evil = Command::new(bin)
        .args(["cat", "/etc/passwd"])
        .env("PPDDIR", "/tmp")
        .output()
        .unwrap();
    assert_eq!(evil.status.code(), Some(1));
    assert_eq!(evil.stdout, [] as [u8; 0]);
}
