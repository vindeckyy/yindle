#![no_main]
//! Fuzz `printers.conf`/`classes.conf` parsing and Wave-1 queue/URI validators —
//! `Registry::load_printers_conf` and `Registry::load_classes_conf` must accept
//! any byte stream without panicking, and a save→load round-trip must be clean.

use libfuzzer_sys::fuzz_target;
use printer::{redact_device_uri, validate_device_uri, validate_printer_name, Registry};

fuzz_target!(|data: &[u8]| {
    let mut reg = Registry::default();
    let _ = reg.load_printers_conf(data);
    let _ = reg.load_classes_conf(data);

    // Exercise class resolution (circular class reference guard).
    for name in reg.printers.keys().take(8) {
        let _ = reg.resolve_class_member(name);
    }

    // Serializing whatever state parsed must not panic.
    let out_printers = reg.save_printers_conf();
    let out_classes = reg.save_classes_conf();

    // A re-parse of our own emitted confs must be clean too.
    let mut reg2 = Registry::default();
    let _ = reg2.load_printers_conf(&out_printers[..]);
    let _ = reg2.load_classes_conf(&out_classes[..]);

    // Wave-1 queue name, device URI, credential redaction, and destination validators.
    let text = String::from_utf8_lossy(data);
    let _ = validate_printer_name(&text);
    let res_no_file = validate_device_uri(&text, false);
    if text.len() >= 5 && text.as_bytes()[..5].eq_ignore_ascii_case(b"file:") {
        assert!(res_no_file.is_err());
    }
    let _ = validate_device_uri(&text, true);
    let _ = redact_device_uri(&text);
    let _ = reg.validate_dest(&text);
    let _ = reg.find(&text);
});
