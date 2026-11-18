#![no_main]
//! Fuzz `mime-db`: parse fuzzed `mime.types`/`mime.convs` streams, sort types,
//! then run type detection and filter-chain resolution over whatever loaded —
//! the magic-rule evaluator, bounded regex engine, and Dijkstra graph search
//! are the panic and DoS surfaces.

use libfuzzer_sys::fuzz_target;
use mime_db::MimeDb;

fuzz_target!(|data: &[u8]| {
    let mut db = MimeDb::default();
    // Feed the same bytes to both parsers — neither may panic.
    let _ = db.load_types_reader(data);
    let _ = db.load_convs_reader(data);
    db.sort_types();

    // Detect a type for both a fixed filename and a fuzzed filename + leading bytes.
    let _ = db.detect("doc", data);
    let fname = String::from_utf8_lossy(&data[..data.len().min(64)]);
    let _ = db.detect(&fname, data);

    // Resolve chains between arbitrary pairs drawn from the loaded conversions.
    let names: Vec<String> = db
        .convs
        .iter()
        .flat_map(|c| [c.src.clone(), c.dst.clone()])
        .take(8)
        .collect();
    for s in &names {
        let _ = db.get(s);
        for d in &names {
            let _ = db.filter_chain(s, d, 0);
            let _ = db.filter_chain(s, d, 100);
        }
    }
});
