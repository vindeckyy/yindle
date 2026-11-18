#![no_main]
//! Run the `cupsFileGetConf` lexer, both config parsers (`cupsd.conf` and
//! `cups-files.conf`), and the Wave-1 security config auditor over arbitrary
//! bytes; a panic is a bug.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Lexer alone.
    for line in cups_config::conf_lines(data) {
        let _ = line;
    }
    // Full parsers (exercise the lexer, ACL/IP mask parsing, and directive dispatch).
    let (cupsd, _diags) = cups_config::parse_cupsd_conf(std::io::Cursor::new(data), "fuzz");
    let (files, _fatal, _fdiags) =
        cups_config::parse_cups_files_conf(std::io::Cursor::new(data), "fuzz", "/tmp");

    // In-memory security audit engine + summary rendering.
    let report = cups_config::audit_config(&cups_config::Config { cupsd, files });
    let _ = report.has_errors();
    let _ = report.has_warnings();
    let _ = report.has_high_findings();
    let _ = report.summary();

    // Prohibited environment variable matcher.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = cups_config::is_prohibited_env(text);
    }
});
