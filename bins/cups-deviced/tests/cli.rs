use std::process::Command;

#[test]
fn cups_deviced_cli_usage_and_empty_dir() {
    let bin = env!("CARGO_BIN_EXE_cups-deviced");

    let bad = Command::new(bin).output().unwrap();
    assert_eq!(bad.status.code(), Some(1));

    let dir = std::env::temp_dir().join(format!("pw-deviced-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let ok = Command::new(bin)
        .args(["1", "0", "1", &dir.to_string_lossy()])
        .output()
        .unwrap();
    assert!(ok.status.success());
    let _ = std::fs::remove_dir_all(&dir);
}
