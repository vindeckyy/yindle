use std::process::Command;

#[test]
fn dnssd_cli_discovery_and_print_errors() {
    let bin = env!("CARGO_BIN_EXE_dnssd");

    // Fast discovery smoke test.
    let disc = Command::new(bin)
        .env("DNSSD_BROWSE_MS", "50")
        .output()
        .unwrap();
    assert!(disc.status.success());

    // Invalid scheme exits FAILED (1).
    let bad = Command::new(bin)
        .args(["1", "u", "t", "1", ""])
        .env("DEVICE_URI", "socket://10.0.0.1:9100")
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));

    // Unresolvable dnssd URI exits RETRY (6).
    let unres = Command::new(bin)
        .args(["1", "u", "t", "1", ""])
        .env(
            "DEVICE_URI",
            "dnssd://NoSuchPrinter99999._ipp._tcp.local./ipp/print",
        )
        .env("DNSSD_RESOLVE_MS", "50")
        .output()
        .unwrap();
    assert_eq!(unres.status.code(), Some(6));
}
