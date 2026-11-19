use mime_db::MimeDb;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "yindle-mimedb-test-{}-{}-{id}",
        std::process::id(),
        tag
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn stock_db() -> MimeDb {
    MimeDb::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")).unwrap()
}

fn run_fuzz_harness(data: &[u8]) {
    let mut db = MimeDb::default();
    let _ = db.load_types_reader(data);
    let _ = db.load_convs_reader(data);
    let _ = db.detect("doc", data);
    let names: Vec<String> = db
        .convs
        .iter()
        .flat_map(|c| [c.src.clone(), c.dst.clone()])
        .take(8)
        .collect();
    for s in &names {
        for d in &names {
            let _ = db.filter_chain(s, d, 0);
        }
    }
}

#[test]
fn fuzz_artifact_regressions() {
    // Exact bytes from fuzz/artifacts/mime_db/*
    let crash_5bc3: &[u8] = &[0x0b, 0x2f, 0x2b, 0x0b, 0x0b, 0x28];
    let crash_c6cc: &[u8] = &[
        0x0b, 0x2f, 0x2c, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x73, 0x28,
    ];
    let oom_74ae: &[u8] = &[
        0x2f, 0x00, 0x0b, 0x5f, 0x0f, 0x3b, 0x29, 0x2f, 0x01, 0x2c, 0x2f,
    ];
    let oom_f4b7: &[u8] = &[
        0x0a, 0x2f, 0x01, 0x2f, 0x0c, 0x2b, 0x29, 0x0b, 0x00, 0x00, 0x00,
    ];

    for sample in [crash_5bc3, crash_c6cc, oom_74ae, oom_f4b7] {
        run_fuzz_harness(sample);
    }

    // Additional adversarial inputs: UTF-8 continuation bytes 0x85 / 0xA0,
    // i64::MIN offset, u32::MAX conv overflow, deep nesting, ReDoS regex, Latin-1.
    let deep_parens = format!("a/b {}", "(".repeat(500));
    let deep_nots = format!("a/b {}foo", "!".repeat(500));
    let huge_regex = format!("a/b regex(0,\"{}\")", "(a|b)".repeat(600));
    let redos_regex = "a/b regex(0,\"^((a+)+)b\")\n";
    let utf8_tricky = "a/b \u{00c5}\u{00a0} string(0,\"\u{00c5}\") ) + ! \n";
    let overflow_rules = "\
a/b contains(0,18446744073709551615,\"x\") string(-9223372036854775808,\"a\")
c/d ascii(-9223372036854775808,10) printable(999999999999,10)
e/f regex(0,\"[a-z\\\\n\\\\r\\\\t]^*+?([z-a]\\\\\")
g/h regex(0,\"((((((((((((((((((((((((((((((((((((((a))))))))))))))))))))))))))))))))))))))\")
";
    let overflow_convs = "\
a/b c/d 4294967295 f1
c/d e/f 4294967295 f2
bad/line notanumber f3
incomplete/line
";
    let latin1 = b"# Copyright \xa9 2026\na/b string(0,\"ok\")\\\n+ printable(0,10)\n";

    for sample in [
        deep_parens.as_bytes(),
        deep_nots.as_bytes(),
        huge_regex.as_bytes(),
        redos_regex.as_bytes(),
        utf8_tricky.as_bytes(),
        overflow_rules.as_bytes(),
        overflow_convs.as_bytes(),
        latin1.as_slice(),
    ] {
        run_fuzz_harness(sample);
    }

    // Confirm ReDoS pattern finishes fast and returns None on non-match.
    let mut db = MimeDb::default();
    db.load_types_reader(Cursor::new(redos_regex)).unwrap();
    let non_matching = format!("{}c", "a".repeat(200));
    assert!(db.detect("f", non_matching.as_bytes()).is_none());
}

#[test]
fn empty_and_oob_slices_never_false_match() {
    let rules = "\
test/istr istring(0,\"<HTML>\")
test/ascii ascii(0,1024)
test/print printable(0,1024)
test/short short(0,0)
test/int int(0,0)
test/char char(10,0)
test/str string(0,\"abc\")
test/regex regex(0,\"^.*$\")
";
    let mut db = MimeDb::default();
    db.load_types_reader(Cursor::new(rules)).unwrap();

    // Empty file must NOT match any content rule.
    assert!(db.detect("noext", b"").is_none());

    // Short binary file (< 1024 bytes) must NOT match ascii(0,1024) or printable(0,1024).
    assert!(db.detect("noext", b"\x00\x01\x02\x03").is_none());
    // Non-NUL non-printable binary must also fail ascii/printable/short/int/istr/str.
    let mut no_rx = MimeDb::default();
    no_rx
        .load_types_reader(Cursor::new(
            "t/ascii ascii(0,1024)\nt/print printable(0,1024)\n",
        ))
        .unwrap();
    assert!(no_rx.detect("noext", b"\x01\x02\x03\x7f").is_none());

    // Short text file (< 1024 bytes) DOES match ascii(0,1024).
    let t = db.detect("noext", b"hello world\n").unwrap();
    assert_eq!(t.name(), "test/ascii");

    // 8-bit printable (0x80..=0xfe) fails ascii, matches printable.
    let t2 = db.detect("noext", b"caf\xe9\n").unwrap();
    assert_eq!(t2.name(), "test/print");

    // Case-insensitive match works when bytes exist, fails when shorter.
    assert_eq!(db.detect("noext", b"<html>").unwrap().name(), "test/istr");
    assert_eq!(db.detect("noext", b"<ht").unwrap().name(), "test/ascii");

    // Exact 2-byte zero matches short(0,0), 1-byte zero does NOT.
    assert!(db.detect("noext", b"\x00").is_none());
    assert_eq!(
        db.detect("noext", b"\x00\x00").unwrap().name(),
        "test/short"
    );
}

#[test]
fn contains_works_on_files_shorter_than_range_plus_lit() {
    let db = stock_db();
    // PJL-wrapped PostScript far shorter than 8192 bytes!
    let ps = b"\x1b%-12345X\n@PJL ENTER LANGUAGE=POSTSCRIPT\n%!PS\n";
    let t = db.detect("job", ps).unwrap();
    assert_eq!(t.name(), "application/postscript");

    // PJL-wrapped PCL (must NOT match postscript because of !contains("ENTER LANGUAGE")).
    let pcl = b"\x1b%-12345X\n@PJL ENTER LANGUAGE=PCL\n%!\n";
    let t2 = db.detect("job", pcl).unwrap();
    assert_eq!(t2.name(), "application/vnd.cups-raw");

    // Empty literal in contains() does not match everything.
    let mut empty_lit = MimeDb::default();
    empty_lit
        .load_types_reader(Cursor::new("test/empty contains(0,10,\"\")\n"))
        .unwrap();
    assert!(empty_lit.detect("x", b"anything").is_none());
}

#[test]
fn multibyte_hex_literals_and_single_quotes() {
    let db = stock_db();
    // JPEG detected purely from magic bytes <FFD8FF> + char(3, 0xe0) without .jpg extension!
    let jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF";
    assert_eq!(db.detect("unnamed", jpeg).unwrap().name(), "image/jpeg");

    // TIFF big-endian MM<002A> and little-endian II<2A00>.
    assert_eq!(
        db.detect("unnamed", b"MM\x00\x2a\x00\x00\x00\x08")
            .unwrap()
            .name(),
        "image/tiff"
    );
    assert_eq!(
        db.detect("unnamed", b"II\x2a\x00\x08\x00\x00\x00")
            .unwrap()
            .name(),
        "image/tiff"
    );

    // Sun raster 4-byte hex <59a66a95>.
    assert_eq!(
        db.detect("unnamed", b"\x59\xa6\x6a\x95\x00\x00")
            .unwrap()
            .name(),
        "image/x-sun-raster"
    );

    // Single-quoted CUPS banner & command literals.
    assert_eq!(
        db.detect("unnamed", b"#CUPS-BANNER\nShow job-id\n")
            .unwrap()
            .name(),
        "application/vnd.cups-banner"
    );
    assert_eq!(
        db.detect("unnamed", b"#CUPS-COMMAND\nReportLevels\n")
            .unwrap()
            .name(),
        "application/vnd.cups-command"
    );

    // HTML angle brackets <HTML> are NOT misparsed as hex.
    assert_eq!(
        db.detect("unnamed", b"<html><body>hello</body></html>")
            .unwrap()
            .name(),
        "text/html"
    );
}

#[test]
fn negation_operator_rules() {
    let db = stock_db();
    // PWG Raster has priority 150 and matches RaS2 + PwgRaster\0.
    assert_eq!(
        db.detect("unnamed", b"RaS2PwgRaster\x00rest")
            .unwrap()
            .name(),
        "image/pwg-raster"
    );
    // CUPS Raster v2 matches RaS2 + !PwgRaster\0.
    assert_eq!(
        db.detect("unnamed", b"RaS2OtherHeader\x00").unwrap().name(),
        "application/vnd.cups-raster"
    );
    // BMP matches BM + !printable(2,14); printable text starting with "BM" must NOT be BMP.
    assert_eq!(
        db.detect(
            "unnamed",
            b"BM\x00\x01\x02\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        .unwrap()
        .name(),
        "image/x-bitmap"
    );
    assert_eq!(
        db.detect("unnamed", b"BMhello world text!!\n")
            .unwrap()
            .name(),
        "text/plain"
    );
    // `! css` (space after `!`): CSS file starting with `/*` must NOT match application/x-csource.
    assert_eq!(
        db.detect("style.css", b"/* comment */\nbody { color: red; }\n")
            .unwrap()
            .name(),
        "text/css"
    );
    assert_eq!(
        db.detect("main.txt", b"/* comment */\n#include <stdio.h>\n")
            .unwrap()
            .name(),
        "application/x-csource"
    );
}

#[test]
fn regex_groups_alternation_quantifiers_and_leading_newlines() {
    // Stock PDF rule: `regex(0,^[\n\r]*%PDF)` with leading CR/LF!
    let db = stock_db();
    assert_eq!(
        db.detect("unnamed", b"\r\n\n%PDF-1.7\n").unwrap().name(),
        "application/pdf"
    );
    assert_ne!(
        db.detect("unnamed", b"junk\n%PDF-1.7\n").unwrap().name(),
        "application/pdf"
    );

    let rules = "\
test/group regex(0,\"^(foo|bar)+baz$\")
test/unquoted_rx regex(0,^(alpha|beta))
test/unquoted_str string(0,(abc))
test/stray_rparen regex(0,\"^foo)bar$\")
test/opt regex(0,\"^colou?r\\.txt$\")
test/unanch regex(2,\"[0-9]+-[a-z][^0-9]\")
test/any regex(0,\"^a.c(d|)e\\tf$\")
test/cls regex(0,\"^[z-a][a-\\z][]x]$\")
test/stray regex(0,\"^*ok$\")
test/deep regex(0,\"((((((((((((((((((((((((((((((((((((a))))))))))))))))))))))))))))))))))))\")
test/huge_star regex(0,\"(a){HUGE}*\")
";
    let rules = rules.replace("{HUGE}", &"a".repeat(2100));
    let mut custom = MimeDb::default();
    custom.load_types_reader(Cursor::new(rules)).unwrap();

    // Group + alternation + plus quantifier MUST actually match group contents!
    assert_eq!(
        custom.detect("x", b"foobarfoobaz").unwrap().name(),
        "test/group"
    );
    assert!(custom.detect("x", b"baz").is_none());
    assert!(custom.detect("x", b"quxbaz").is_none());
    assert!(custom.detect("x", b"foobarbazextra").is_none());

    // Unquoted rules ending in `)` preserve the inner `)`.
    assert_eq!(
        custom.detect("x", b"alpha").unwrap().name(),
        "test/unquoted_rx"
    );
    assert_eq!(
        custom.detect("x", b"beta").unwrap().name(),
        "test/unquoted_rx"
    );
    assert!(custom.detect("x", b"gamma").is_none());
    assert_eq!(
        custom.detect("x", b"(abc)").unwrap().name(),
        "test/unquoted_str"
    );
    assert!(custom.detect("x", b"(abc").is_none());

    // Stray `)` at depth 0 is matched literally (must not truncate pattern).
    assert!(custom.detect("x", b"foo").is_none());
    assert_eq!(
        custom.detect("x", b"foo)bar").unwrap().name(),
        "test/stray_rparen"
    );

    // Optional `?` and escaped `\.`
    assert_eq!(custom.detect("x", b"color.txt").unwrap().name(), "test/opt");
    assert_eq!(
        custom.detect("x", b"colour.txt").unwrap().name(),
        "test/opt"
    );
    assert!(custom.detect("x", b"colorXtxt").is_none());

    // Non-zero offset + unanchored + char range + negated class.
    assert_eq!(
        custom.detect("x", b"XXhello 42-a!").unwrap().name(),
        "test/unanch"
    );
    assert!(custom.detect("x", b"XXhello 42-a9").is_none());

    // `.` wildcard, empty alt branch `(d|)`, `\t` escape, reversed/escaped char classes, stray `*`.
    assert_eq!(custom.detect("x", b"axce\tf").unwrap().name(), "test/any");
    assert_eq!(custom.detect("x", b"axcde\tf").unwrap().name(), "test/any");
    assert_eq!(custom.detect("x", b"mm]").unwrap().name(), "test/cls");
    assert_eq!(custom.detect("x", b"ok").unwrap().name(), "test/stray");
    // Deeply nested / over-state-limit patterns fail closed without panicking.
    assert!(custom.detect("x", b"a").is_none());
}

#[test]
fn filter_chain_wildcards_passthrough_and_max_cost() {
    let convs = "\
image/*               image/pwg-raster        50  imagetoraster
image/png             image/pwg-raster        50  pngtoraster
*/*                   application/pdf         100 any2pdf
application/pdf       application/vnd.cups-pdf 25 pdftopdf
application/octet-stream application/vnd.cups-raw 0 -
image/pwg-raster      application/vnd.cups-raw 0 -
text/plain            text/mid                10  fast1
text/plain            text/slow               5   slow1
text/slow             text/mid                20  slow2
text/mid              text/final              1   finish
";
    let mut db = MimeDb::default();
    db.load_convs_reader(Cursor::new(convs)).unwrap();

    // Diamond graph exercises stale higher-cost heap entries in Dijkstra.
    let diamond = db.filter_chain("text/plain", "text/final", 0).unwrap();
    assert_eq!(diamond.len(), 2);
    assert_eq!(diamond[0].program, "fast1");
    assert_eq!(diamond[1].program, "finish");

    // Non-slash invalid type names return None cleanly.
    assert!(db.filter_chain("notamime", "alsoinvalid", 0).is_none());

    // `*/*` wildcard matches arbitrary source types.
    let chain = db
        .filter_chain("text/markdown", "application/vnd.cups-pdf", 0)
        .unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].program, "any2pdf");
    assert_eq!(chain[1].program, "pdftopdf");

    // `max_cost` rejects paths exceeding the cap and accepts within cap.
    assert!(db
        .filter_chain("text/markdown", "application/vnd.cups-pdf", 124)
        .is_none());
    assert!(db
        .filter_chain("text/markdown", "application/vnd.cups-pdf", 125)
        .is_some());

    // `image/*` matches `image/webp`, and `-` passthrough edge adds 0 filter programs.
    let img_chain = db
        .filter_chain("image/webp", "application/vnd.cups-raw", 0)
        .unwrap();
    assert_eq!(img_chain.len(), 1);
    assert_eq!(img_chain[0].program, "imagetoraster");

    // On equal cost, specific `image/png` beats wildcard `image/*`.
    let png_chain = db.filter_chain("image/png", "image/pwg-raster", 0).unwrap();
    assert_eq!(png_chain.len(), 1);
    assert_eq!(png_chain[0].program, "pngtoraster");

    // Direct `-` passthrough returns Some(vec![]) and can_convert == true.
    let raw = db
        .filter_chain("application/octet-stream", "application/vnd.cups-raw", 0)
        .unwrap();
    assert_eq!(raw.len(), 0);
    assert!(db.can_convert("application/octet-stream", "application/vnd.cups-raw"));
    assert!(db.can_convert("image/png", "image/*"));
    assert!(db.can_convert("text/plain", "*/*"));
}

#[test]
fn fhs_load_data_dir_with_mime_subdir_and_local_overrides() {
    let root = temp_dir("fhs");
    let data_dir = root.join("share/cups");
    let mime_sub = data_dir.join("mime");
    let server_root = root.join("etc/cups");
    fs::create_dir_all(&mime_sub).unwrap();
    fs::create_dir_all(&server_root).unwrap();

    fs::write(
        mime_sub.join("mime.types"),
        "application/x-demo demo string(0,\"DEMO\") priority(100)\n",
    )
    .unwrap();
    fs::write(
        mime_sub.join("mime.convs"),
        "application/x-demo application/pdf 50 demotopdf\n",
    )
    .unwrap();
    fs::write(
        server_root.join("local.types"),
        "application/x-demo string(0,\"ALT!\") priority(200)\napplication/x-local loc\n",
    )
    .unwrap();
    fs::write(
        server_root.join("local.convs"),
        "application/x-local application/pdf 10 localtopdf\n",
    )
    .unwrap();

    // Passing DataDir (/usr/share/cups) automatically loads DataDir/mime!
    let db_data = MimeDb::load(&data_dir).unwrap();
    assert!(db_data.get("application/x-demo").is_some());
    assert_eq!(db_data.get("application/x-demo").unwrap().priority, 100);
    assert!(db_data.can_convert("application/x-demo", "application/pdf"));

    // Nonexistent directory still returns error on MimeDb::load.
    assert!(MimeDb::load(&root.join("does-not-exist")).is_err());

    // load_standard loads DataDir/mime -> DataDir -> ServerRoot (local overrides!).
    let db_std = MimeDb::load_standard(&data_dir, &server_root).unwrap();
    let demo = db_std.get("application/x-demo").unwrap();
    assert_eq!(demo.priority, 200);
    assert_eq!(
        db_std.detect("x", b"DEMO").unwrap().name(),
        "application/x-demo"
    );
    assert_eq!(
        db_std.detect("x", b"ALT!").unwrap().name(),
        "application/x-demo"
    );
    assert_eq!(
        db_std.detect("file.loc", b"").unwrap().name(),
        "application/x-local"
    );
    assert!(db_std.can_convert("application/x-local", "application/pdf"));

    // load_dirs skips missing directories gracefully and deduplicates overlapping paths.
    let db_dedup =
        MimeDb::load_dirs(&[mime_sub.clone(), mime_sub.clone(), root.join("missing_dir")]).unwrap();
    assert_eq!(db_dedup.convs.len(), 1);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn glob_negative_offset_int_locale_and_true_rules() {
    let rules = "\
test/int int(0,0x12345678)
test/neg string(-3,\"END\")
test/glob match(\"report-?.t*t\")
test/trail match(\"prefix*\")
test/sub match(\"Makefile\")
test/loc locale(\"c\") + string(0,\"LOC\")
test/deferred
test/deferred string(0,\"DEFERRED\")
test/any true\\";
    let mut db = MimeDb::default();
    db.load_types_reader(Cursor::new(rules)).unwrap();

    assert_eq!(
        db.detect("x", b"\x12\x34\x56\x78").unwrap().name(),
        "test/int"
    );
    assert_eq!(db.detect("x", b"prefixEND").unwrap().name(), "test/neg");
    assert_eq!(
        db.detect("/tmp/report-7.text", b"").unwrap().name(),
        "test/glob"
    );
    assert_eq!(db.detect("/tmp/prefix", b"").unwrap().name(), "test/trail");
    assert_eq!(db.detect("MyMakefile.in", b"").unwrap().name(), "test/sub");
    assert_eq!(
        db.detect("other", b"DEFERRED").unwrap().name(),
        "test/deferred"
    );
    // Non-matching glob falls through to `true` catch-all (also tests trailing `\` EOF).
    assert_eq!(db.detect("report-7.pdf", b"zz").unwrap().name(), "test/any");
    // Exercise locale rule (passes if LANG contains 'c' or defaults to C; either way no panic).
    let _ = db.detect("other", b"LOC");
    assert!(format!("{db}").contains("types"));
}
