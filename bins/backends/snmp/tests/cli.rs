use std::process::Command;

#[test]
fn snmp_cli_print_reject_and_discovery() {
    let bin = env!("CARGO_BIN_EXE_snmp");

    // Print mode rejects snmp:// URI cleanly.
    let fail = Command::new(bin)
        .args(["1", "u", "t", "1", ""])
        .env("DEVICE_URI", "snmp://192.168.1.10")
        .output()
        .unwrap();
    assert_eq!(fail.status.code(), Some(1));

    // Discovery mode with 1s MaxRunTime targeting 127.0.0.1 exits 0 cleanly.
    let dir = std::env::temp_dir().join(format!("pw-snmp-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("snmp.conf");
    std::fs::write(&conf, "Address 127.0.0.1\nCommunity public\nMaxRunTime 1\n").unwrap();
    let ok = Command::new(bin).env("SNMP_CONF", &conf).output().unwrap();
    assert!(ok.status.success());
    let _ = std::fs::remove_dir_all(&dir);
}
