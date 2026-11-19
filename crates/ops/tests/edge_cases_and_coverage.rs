#![allow(clippy::too_many_lines, clippy::similar_names)]

mod common;

use common::{
    block_on, find_attr_int, find_attr_text, gzip_stored, ipp_req, valid_sample_ppd, with_job_attr,
    with_job_uri, with_op_attr, with_printer_attr, with_printer_uri, with_sub_group, write_file,
    Harness, HookRecorder,
};
use cups_config::{AuthLevel, Location, OrderType, Policy, PolicyOp};
use ipp_codec::{ops::op, ops::status, tags, Attribute, Group, Value};
use job::{Job, JobState};
use ops::{
    atomic_write_ppd, decompress_gzip, decompress_gzip_with_limits, dispatch, dispatch_async,
    dispatch_outcome, parse_ppd_capabilities, resolve_safe_file_ppd, validate_driverd_ppd_name,
    validate_ppd_bytes, GzipError, PpdLookupError,
};
use printer::{ptype, Printer};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

/// Bit-level LSB writer for synthesizing arbitrary RFC 1951 DEFLATE streams in tests.
struct BitWriter {
    bytes: Vec<u8>,
    bitbuf: u32,
    bitcnt: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bitbuf: 0,
            bitcnt: 0,
        }
    }

    fn write_bits(&mut self, val: u32, n: u8) {
        self.bitbuf |= (val & ((1u32 << n) - 1)) << self.bitcnt;
        self.bitcnt += n;
        while self.bitcnt >= 8 {
            #[allow(clippy::cast_possible_truncation)]
            self.bytes.push((self.bitbuf & 0xff) as u8);
            self.bitbuf >>= 8;
            self.bitcnt -= 8;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bitcnt > 0 {
            #[allow(clippy::cast_possible_truncation)]
            self.bytes.push((self.bitbuf & 0xff) as u8);
        }
        self.bytes
    }
}

fn wrap_gzip(deflate_body: &[u8], payload_for_trailer: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    out.extend_from_slice(deflate_body);
    let crc = common::crc32_test(payload_for_trailer);
    out.extend_from_slice(&crc.to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    out.extend_from_slice(&(payload_for_trailer.len() as u32).to_le_bytes());
    out
}

#[test]
fn gzip_dynamic_huffman_and_malformed_edge_cases() {
    // 1. Real dynamic-Huffman gzip stream produced by system `gzip -9` over a
    // rich 24 KiB payload (exercises dynamic tables, repeat codes 16/17/18,
    // and extra length/distance bits).
    let mut rich = Vec::with_capacity(24 * 1024);
    for i in 0..300u32 {
        let _ = writeln!(
            rich,
            "Yindle IPP job line {i:04}: alpha beta gamma delta epsilon zeta eta theta {i} {}",
            "X".repeat((i as usize % 37) + 1)
        );
    }
    if let Ok(mut child) = Command::new("gzip")
        .arg("-9")
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        child.stdin.take().unwrap().write_all(&rich).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let decoded = decompress_gzip(&output.stdout, 1024 * 1024).unwrap();
        assert_eq!(decoded, rich);
    }

    // 2. Truncated FEXTRA / FNAME / FCOMMENT / FHCRC header error paths.
    // Truncated FEXTRA length:
    let mut bad_fextra_len = vec![0x1f, 0x8b, 8, 0x04, 0, 0, 0, 0, 0, 3];
    bad_fextra_len.extend_from_slice(&[0u8; 8]); // trailer only -> pos+2 > body_end
    assert!(matches!(
        decompress_gzip(&bad_fextra_len, 1024),
        Err(GzipError::Corrupt(_))
    ));

    // Truncated FEXTRA payload:
    let mut bad_fextra_data = vec![0x1f, 0x8b, 8, 0x04, 0, 0, 0, 0, 0, 3, 50, 0, 1, 2];
    bad_fextra_data.extend_from_slice(&[0u8; 8]);
    assert!(matches!(
        decompress_gzip(&bad_fextra_data, 1024),
        Err(GzipError::Corrupt(_))
    ));

    // Unterminated FNAME:
    let mut bad_fname = vec![0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0, 3, b'a', b'b', b'c'];
    bad_fname.extend_from_slice(&[0u8; 8]);
    assert!(matches!(
        decompress_gzip(&bad_fname, 1024),
        Err(GzipError::Corrupt(_))
    ));

    // Truncated FHCRC:
    let mut bad_fhcrc = vec![0x1f, 0x8b, 8, 0x02, 0, 0, 0, 0, 0, 3, 0xaa];
    bad_fhcrc.extend_from_slice(&[0u8; 8]);
    assert!(matches!(
        decompress_gzip(&bad_fhcrc, 1024),
        Err(GzipError::Corrupt(_))
    ));

    // 3. Stored block hitting output size limit & truncated stored block.
    let big_stored = gzip_stored(&[b'A'; 100]);
    assert!(matches!(
        decompress_gzip_with_limits(&big_stored, 50, 100, 50),
        Err(GzipError::LimitExceeded(_))
    ));

    // Truncated stored block body (claims len=10, only 2 bytes present):
    let mut trunc_stored = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    trunc_stored.extend_from_slice(&[1, 10, 0, !10, !0, b'x', b'y']);
    trunc_stored.extend_from_slice(&[0u8; 8]);
    assert!(matches!(
        decompress_gzip(&trunc_stored, 1024),
        Err(GzipError::Corrupt(_))
    ));

    // Two stored blocks (exercises bfinal=0 loop + bitbuf byte drain when bitcnt >= 8).
    let mut two_blocks = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    // Block 1 (bfinal=0, btype=0), len=2 "hi"
    two_blocks.extend_from_slice(&[0, 2, 0, !2, !0, b'h', b'i']);
    // Block 2 (bfinal=1, btype=0), len=2 "!!"
    two_blocks.extend_from_slice(&[1, 2, 0, !2, !0, b'!', b'!']);
    let crc = common::crc32_test(b"hi!!");
    two_blocks.extend_from_slice(&crc.to_le_bytes());
    two_blocks.extend_from_slice(&4u32.to_le_bytes());
    assert_eq!(decompress_gzip(&two_blocks, 1024).unwrap(), b"hi!!");

    // 4. Fixed-Huffman block hitting literal output limit.
    let mut bw = BitWriter::new();
    bw.write_bits(1, 1); // bfinal=1
    bw.write_bits(1, 2); // btype=1 (fixed)
                         // Emit literal 'A' (65 -> fixed 8-bit code 0x30+65 = 113 = 0b0111_0001, MSB-first reversed -> 0b1000_1110)
    let lit_a = (0x30u8 + b'A').reverse_bits();
    bw.write_bits(u32::from(lit_a), 8);
    bw.write_bits(u32::from(lit_a), 8);
    bw.write_bits(0, 7); // EOB (256 -> 0000000)
    let gz_two_a = wrap_gzip(&bw.finish(), b"AA");
    assert_eq!(decompress_gzip(&gz_two_a, 1024).unwrap(), b"AA");
    assert!(matches!(
        decompress_gzip_with_limits(&gz_two_a, 1, 100, 1),
        Err(GzipError::LimitExceeded(_))
    ));

    // 5. Fixed-Huffman invalid back-reference (distance > out.len()).
    let mut bw = BitWriter::new();
    bw.write_bits(1, 1); // bfinal
    bw.write_bits(1, 2); // fixed
                         // Length symbol 257 (code 0b0000001 MSB-first -> 0b1000000 LSB)
    bw.write_bits(0b100_0000, 7);
    // Distance symbol 0 (5 bits = 0 -> dist=1, but out is empty!)
    bw.write_bits(0, 5);
    bw.write_bits(0, 7);
    let gz_bad_dist = wrap_gzip(&bw.finish(), b"");
    assert!(matches!(
        decompress_gzip(&gz_bad_dist, 1024),
        Err(GzipError::Corrupt(_))
    ));

    // 6. Fixed-Huffman invalid length symbol 286 (code 11000110 MSB -> 01100011 LSB).
    let mut bw = BitWriter::new();
    bw.write_bits(1, 1);
    bw.write_bits(1, 2);
    bw.write_bits(u32::from(0b1100_0110u8.reverse_bits()), 8);
    let gz_bad_len = wrap_gzip(&bw.finish(), b"");
    assert!(matches!(
        decompress_gzip(&gz_bad_len, 1024),
        Err(GzipError::Corrupt(_))
    ));

    // 7. Fixed-Huffman invalid distance symbol 30 (5-bit code 30 = 0b11110 MSB -> 0b01111 LSB).
    let mut bw = BitWriter::new();
    bw.write_bits(1, 1);
    bw.write_bits(1, 2);
    bw.write_bits(u32::from(lit_a), 8); // emit 1 literal so out is non-empty
    bw.write_bits(0b100_0000, 7); // len 257 (length 3)
    bw.write_bits(0b01111, 5); // dist sym 30 (invalid!)
    let gz_bad_dsym = wrap_gzip(&bw.finish(), b"");
    assert!(matches!(
        decompress_gzip(&gz_bad_dsym, 1024),
        Err(GzipError::Corrupt(_))
    ));

    // 8. Dynamic-Huffman invalid counts (hlit = 30 + 257 = 287 > 286).
    let mut bw = BitWriter::new();
    bw.write_bits(1, 1);
    bw.write_bits(2, 2); // dynamic
    bw.write_bits(30, 5); // hlit = 287 (OOB!)
    bw.write_bits(0, 5);
    bw.write_bits(0, 4);
    let gz_dyn_oob = wrap_gzip(&bw.finish(), b"");
    assert!(matches!(
        decompress_gzip(&gz_dyn_oob, 1024),
        Err(GzipError::Corrupt(_))
    ));

    // 9. Dynamic-Huffman oversubscribed code-length tree (all 4 code-length symbols len=1).
    let mut bw = BitWriter::new();
    bw.write_bits(1, 1);
    bw.write_bits(2, 2); // dynamic
    bw.write_bits(0, 5); // hlit = 257
    bw.write_bits(0, 5); // hdist = 1
    bw.write_bits(0, 4); // hclen = 4
    for _ in 0..4 {
        bw.write_bits(1, 3); // four 1-bit codes -> oversubscribed!
    }
    let gz_oversub = wrap_gzip(&bw.finish(), b"");
    assert!(matches!(
        decompress_gzip(&gz_oversub, 1024),
        Err(GzipError::Corrupt(_))
    ));

    // 10. Dynamic-Huffman code-length repeat symbol 16 with no prior length.
    // ORDER[0] = 16 -> give symbol 16 length 1 (code 0), symbol 0 (ORDER[3]) length 1 (code 1).
    let mut bw = BitWriter::new();
    bw.write_bits(1, 1);
    bw.write_bits(2, 2);
    bw.write_bits(0, 5); // hlit=257
    bw.write_bits(0, 5); // hdist=1
    bw.write_bits(0, 4); // hclen=4 (ORDER: 16, 17, 18, 0)
    bw.write_bits(1, 3); // sym 16: len 1 (code 1)
    bw.write_bits(0, 3); // sym 17: len 0
    bw.write_bits(0, 3); // sym 18: len 0
    bw.write_bits(1, 3); // sym 0:  len 1 (code 0)
                         // Emit code 1 -> symbol 16 right at start with empty `lens`!
    bw.write_bits(1, 1);
    let gz_rep16_empty = wrap_gzip(&bw.finish(), b"");
    assert!(matches!(
        decompress_gzip(&gz_rep16_empty, 1024),
        Err(GzipError::Corrupt(_))
    ));

    // 11. Dynamic-Huffman repeat symbol 17 & 18 overflow + unexpected EOF.
    // Give sym 17 len 1 (code 0), sym 18 len 1 (code 1).
    for (bit_for_sym, extra_bits) in [(0u32, 3u8), (1u32, 7u8)] {
        let mut bw = BitWriter::new();
        bw.write_bits(1, 1);
        bw.write_bits(2, 2);
        bw.write_bits(0, 5); // hlit=257
        bw.write_bits(0, 5); // hdist=1 (total = 258)
        bw.write_bits(0, 4); // hclen=4
        bw.write_bits(0, 3); // sym 16
        bw.write_bits(1, 3); // sym 17 -> code 0
        bw.write_bits(1, 3); // sym 18 -> code 1
        bw.write_bits(0, 3); // sym 0
                             // Repeat max zeros until > 258:
        for _ in 0..40 {
            bw.write_bits(bit_for_sym, 1);
            bw.write_bits((1u32 << extra_bits) - 1, extra_bits);
        }
        let gz_ov = wrap_gzip(&bw.finish(), b"");
        assert!(matches!(
            decompress_gzip(&gz_ov, 1024),
            Err(GzipError::Corrupt(_))
        ));
    }

    // Repeat symbol 16 overflow (emit one 0-length then sym 16 repeating past 258).
    let mut bw = BitWriter::new();
    bw.write_bits(1, 1);
    bw.write_bits(2, 2);
    bw.write_bits(0, 5); // hlit=257
    bw.write_bits(0, 5); // hdist=1 (total = 258)
    bw.write_bits(0, 4); // hclen=4
    bw.write_bits(1, 3); // sym 16 -> code 1
    bw.write_bits(0, 3);
    bw.write_bits(0, 3);
    bw.write_bits(1, 3); // sym 0 -> code 0
    bw.write_bits(0, 1); // sym 0 -> 1 entry
    for _ in 0..50 {
        bw.write_bits(1, 1); // sym 16
        bw.write_bits(3, 2); // rep 6 -> 1 + 50*6 = 301 > 258
    }
    let gz_rep16_ov = wrap_gzip(&bw.finish(), b"");
    assert!(matches!(
        decompress_gzip(&gz_rep16_ov, 1024),
        Err(GzipError::Corrupt(_))
    ));

    // Unexpected EOF inside bitstream:
    let eof_stream = wrap_gzip(&[0x03], b"");
    assert!(matches!(
        decompress_gzip(&eof_stream, 1024),
        Err(GzipError::Corrupt(_))
    ));
}

#[test]
fn ppd_edge_cases_capabilities_and_containment() {
    let h = Harness::new("ppd-edges");

    // 1. Whitespace/qualifier bypass attempts on *cupsFilter / *FoomaticRIPCommandLine blocked!
    let spaced_filter = "*PPD-Adobe: \"4.3\"\n*cupsFilter : \"application/pdf 0 /bin/sh\"\n";
    assert!(validate_ppd_bytes(spaced_filter.as_bytes()).is_err());
    let qual_foomatic = "*PPD-Adobe: \"4.3\"\n*FoomaticRIPCommandLine/en: \"id\"\n";
    assert!(validate_ppd_bytes(qual_foomatic.as_bytes()).is_err());

    // 2. Oversized PPD (> 4 MiB) rejected cleanly.
    let mut huge = b"*PPD-Adobe: \"4.3\"\n".to_vec();
    huge.resize(4 * 1024 * 1024 + 1, b'A');
    assert!(validate_ppd_bytes(&huge).is_err());

    // 3. `validate_driverd_ppd_name` rejects `file:` (case-insensitively) and UTF-8 edge cases.
    assert!(validate_driverd_ppd_name("file:///etc/shadow").is_err());
    assert!(validate_driverd_ppd_name("FILE:laser1").is_err());
    assert!(validate_driverd_ppd_name("ééé").is_ok());

    // 4. Case-insensitive `FILE:` prefix in `resolve_safe_file_ppd`:
    write_file(
        &h.server_root.join("ppd/laser1.ppd"),
        valid_sample_ppd().as_bytes(),
    );
    let roots = h.ctx().ppd_roots();
    assert_eq!(
        resolve_safe_file_ppd("FILE:///etc/passwd", &roots),
        Err(PpdLookupError::Forbidden)
    );
    assert_eq!(
        resolve_safe_file_ppd("FILE:///nonexistent/outside.ppd", &roots),
        Err(PpdLookupError::Forbidden)
    );
    assert!(resolve_safe_file_ppd("FILE:laser1", &roots).is_ok());
    assert_eq!(
        resolve_safe_file_ppd("file:missing_rel", &roots),
        Err(PpdLookupError::NotFound)
    );

    // 5. `CUPS-Get-PPD` rejects reading a directory or oversized PPD inside ppd root.
    std::fs::create_dir_all(h.server_root.join("ppd/subdir.ppd")).unwrap();
    assert_eq!(
        resolve_safe_file_ppd("file:subdir.ppd", &roots),
        Err(PpdLookupError::NotFound)
    );
    write_file(&h.server_root.join("ppd/huge.ppd"), &huge);
    assert_eq!(
        resolve_safe_file_ppd("file:huge.ppd", &roots),
        Err(PpdLookupError::NotFound)
    );

    // 6. `atomic_write_ppd` creates `ppd/` when absent and rejects symlinked `ppd/` dir.
    let fresh_root = h.tmp.path.join("fresh_root");
    std::fs::create_dir_all(&fresh_root).unwrap();
    let written = atomic_write_ppd(&fresh_root, "q1", valid_sample_ppd().as_bytes()).unwrap();
    assert!(written.is_file());

    #[cfg(unix)]
    {
        let sym_root = h.tmp.path.join("sym_root");
        std::fs::create_dir_all(&sym_root).unwrap();
        let outside = h.tmp.path.join("outside_ppd");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, sym_root.join("ppd")).unwrap();
        assert!(atomic_write_ppd(&sym_root, "q1", valid_sample_ppd().as_bytes()).is_err());
    }

    // 8. `parse_ppd_capabilities` covers every media keyword, mono, DuplexTumble, Duplex None, XxY dpi.
    let rich_ppd = concat!(
        "*PPD-Adobe: \"4.3\"\n",
        "*ColorDevice: False\n",
        "*DefaultPageSize: A3\n",
        "*PageSize A3/A3: \"\"\n",
        "*PageSize A5/A5: \"\"\n",
        "*PageSize Env10/Env10: \"\"\n",
        "*PageSize Executive/Exec: \"\"\n",
        "*PageSize Tabloid/Tabloid: \"\"\n",
        "*PageSize custom_100x200mm/Custom: \"\"\n",
        "*PageSize UnknownWeirdSize/Unknown: \"\"\n",
        "*DefaultDuplex: None\n",
        "*Duplex None/Off: \"\"\n",
        "*DefaultResolution: 300x600dpi\n",
        "*Resolution 300x600dpi/300x600: \"\"\n",
        "*Resolution badres/Bad: \"\"\n",
        "*cupsFilter: \"application/vnd.test 0 pdftopdf\"\n",
    );
    let caps = parse_ppd_capabilities(rich_ppd);
    assert_eq!(caps.color_device, Some(false));
    assert_eq!(caps.duplex_supported, Some(false));
    assert_eq!(caps.default_duplex.as_deref(), Some("one-sided"));
    assert_eq!(caps.default_media.as_deref(), Some("iso_a3_297x420mm"));
    assert_eq!(caps.default_resolution, Some((300, 600)));
    assert!(caps
        .media_supported
        .contains(&"iso_a5_148x210mm".to_string()));
    assert!(caps
        .media_supported
        .contains(&"na_number-10_4.125x9.5in".to_string()));
    assert!(caps
        .media_supported
        .contains(&"na_executive_7.25x10.5in".to_string()));
    assert!(caps
        .media_supported
        .contains(&"na_ledger_11x17in".to_string()));
    assert!(caps
        .media_supported
        .contains(&"custom_100x200mm".to_string()));

    let tumble_ppd =
        "*PPD-Adobe: \"4.3\"\n*DefaultDuplex: DuplexTumble\n*Duplex DuplexTumble: \"\"\n";
    let tcaps = parse_ppd_capabilities(tumble_ppd);
    assert_eq!(
        tcaps.default_duplex.as_deref(),
        Some("two-sided-short-edge")
    );
    assert_eq!(tcaps.duplex_supported, Some(true));
}

#[test]
fn common_printer_attrs_markers_alerts_filters_and_ctx_helpers() {
    let h = Harness::new("common-ctx");
    {
        let mut reg = h.registry.write().unwrap();
        let p = reg.printers.get_mut("laser1").unwrap();
        p.marker_time = 1_700_000_000;
        p.marker_names = vec!["Black".into(), "Cyan".into()];
        p.marker_levels = vec![80, 40];
        p.marker_low_levels = vec![10, 10];
        p.marker_high_levels = vec![100, 100];
        p.marker_types = vec!["toner".into(), "toner".into()];
        p.marker_colors = vec!["#000000".into(), "#00FFFF".into()];
        p.marker_message = "Toner OK".into();
        p.alert = Some("code=tonerLow".into());
        p.alert_description = Some("Black toner low".into());
        p.reg_name = Some("Office-Laser-DNS".into());
        p.error_policy = Some("retry-job".into());
        p.auth_info_required = vec!["username".into(), "password".into()];
        p.reasons = vec!["toner-low-warning".into()];
        p.geo_location = Some("geo:37.77,-122.42".into());
        p.organization = Some("Yindle".into());
        p.organizational_unit = Some("Infra".into());
    }

    // Write a monochrome non-duplex PPD to exercise mono/non-duplex branches in common.rs!
    write_file(
        &h.server_root.join("ppd/laser1.ppd"),
        b"*PPD-Adobe: \"4.3\"\n*ColorDevice: False\n*DefaultDuplex: None\n*DefaultPageSize: Letter\n*PageSize Letter: \"\"\n*DefaultResolution: 300dpi\n*cupsFilter: \"application/pdf 0 -\"\n",
    );

    let mut ctx = h.ctx();
    ctx.is_encrypted = true;
    ctx.classification = "confidential".into();
    ctx.notifiers = vec!["mailto".into()];
    ctx.max_lease_duration = 0;
    let hooks = HookRecorder::attach(&mut ctx);

    // 1. Test `requested-attributes` group filters + full attribute emission.
    for group_filter in [
        "all",
        "job-template",
        "printer-description",
        "printer-defaults",
        "document-format",
        "media-col-database",
    ] {
        let req = with_op_attr(
            with_printer_uri(
                ipp_req(op::GET_PRINTER_ATTRIBUTES),
                "ipps://localhost:631/printers/laser1",
            ),
            "requested-attributes",
            tags::KEYWORD,
            Value::Keyword(group_filter.into()),
        );
        let resp = block_on(dispatch_async(&req, &ctx)).response;
        assert_eq!(resp.code, status::OK, "filter {group_filter} failed");
        if group_filter == "all" {
            assert!(resp.find(tags::PRINTER, "marker-change-time").is_some());
            assert!(resp.find(tags::PRINTER, "marker-names").is_some());
            assert!(resp.find(tags::PRINTER, "marker-levels").is_some());
            assert!(resp.find(tags::PRINTER, "marker-message").is_some());
            assert!(resp.find(tags::PRINTER, "printer-alert").is_some());
            assert!(resp
                .find(tags::PRINTER, "printer-alert-description")
                .is_some());
            assert!(resp.find(tags::PRINTER, "printer-dns-sd-name").is_some());
            assert!(resp.find(tags::PRINTER, "printer-error-policy").is_some());
            assert!(resp.find(tags::PRINTER, "auth-info-required").is_some());
            assert_eq!(
                find_attr_text(&resp, tags::PRINTER, "uri-security-supported").as_deref(),
                Some("tls")
            );
        }
    }

    // 2. Test `ctx.build_shared_printer`, `ctx.event_with_state` (with reasons / missing / None),
    // and `ctx.driverd_env()` when `{data_dir}/ppd` does not exist.
    {
        let p = h.registry.read().unwrap().find("laser1").unwrap().clone();
        let sp = ctx.build_shared_printer(&p);
        assert_eq!(sp.pdl, "application/pdf");
        assert!(!sp.is_class);
        assert!(!sp.is_fax);

        let mut fax_p = Printer::new("fax1", "ipp://fax.local/ipp");
        fax_p.ptype |= ptype::FAX;
        let sp_fax = ctx.build_shared_printer(&fax_p);
        assert!(sp_fax.is_fax);
        assert_eq!(sp_fax.pdl, dnssd::DEFAULT_PDL);
    }
    ctx.event(
        events::Event::PrinterStateChanged,
        Some("laser1"),
        None,
        "has reasons".into(),
    );
    ctx.event(
        events::Event::PrinterStateChanged,
        Some("nonexistent_q"),
        None,
        "missing printer".into(),
    );
    ctx.event(events::Event::ServerStarted, None, None, "server up".into());
    assert!(hooks.events.lock().unwrap().len() >= 3);

    let mut ctx_no_ppddir = h.ctx();
    ctx_no_ppddir.data_dir = h.tmp.path.join("no_such_share");
    let env_fallback = ctx_no_ppddir.driverd_env();
    assert!(env_fallback.iter().any(|(k, _)| k == "PPDDIR"));

    // 3. `dispatch.rs` read-query edge cases: nonexistent printer, no default,
    // `CUPS-Get-Printers` filters (`first-printer-name`, `limit`, `printer-id`,
    // `printer-type`/`mask`, `printer-location`, `!is_local`, `AllowUser`, empty registry).
    let no_p = with_printer_uri(
        ipp_req(op::GET_PRINTER_ATTRIBUTES),
        "http://localhost/printers/does_not_exist",
    );
    assert_eq!(dispatch(&no_p, &ctx).code, status::ERROR_NOT_FOUND);
    let no_sv = with_printer_uri(
        ipp_req(op::GET_PRINTER_SUPPORTED_VALUES),
        "https://localhost/printers/does_not_exist",
    );
    assert_eq!(dispatch(&no_sv, &ctx).code, status::ERROR_NOT_FOUND);

    // Add a second printer & unshared printer & user-restricted printer.
    {
        let mut reg = h.registry.write().unwrap();
        let mut p2 = Printer::new("laser2", "ipp://p2.local/ipp");
        p2.shared = false;
        p2.location = Some("Lab 2".into());
        reg.add(p2);

        let mut p3 = Printer::new("restricted", "ipp://p3.local/ipp");
        p3.shared = true;
        p3.users = vec!["onlyboss".into()];
        p3.deny_users = false;
        reg.add(p3);
    }

    // Bad printer-id (<= 0):
    let bad_pid = with_op_attr(
        ipp_req(op::CUPS_GET_PRINTERS),
        "printer-id",
        tags::INTEGER,
        Value::Integer(0),
    );
    assert_eq!(
        dispatch(&bad_pid, &ctx).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );

    // Filter with `first-printer-name`, `limit`, `printer-id`, `printer-location`, `printer-type-mask`, `!is_local`:
    let mut remote_alice = h.user_ctx("alice");
    remote_alice.is_local = false;
    let filtered = with_op_attr(
        with_op_attr(
            ipp_req(op::CUPS_GET_PRINTERS),
            "first-printer-name",
            tags::NAME,
            Value::Name("laser1".into()),
        ),
        "limit",
        tags::INTEGER,
        Value::Integer(1),
    );
    let fresp = dispatch(&filtered, &remote_alice);
    assert_eq!(fresp.code, status::OK);
    // Remote caller sees shared `laser1`, not unshared `laser2` or restricted `restricted`:
    assert_eq!(
        fresp
            .groups
            .iter()
            .filter(|g| g.tag == tags::PRINTER)
            .count(),
        1
    );

    // Filter by location mismatch & match, and printer-id mismatch, and printer-type mask mismatch:
    let loc_req = with_op_attr(
        ipp_req(op::CUPS_GET_PRINTERS),
        "printer-location",
        tags::TEXT,
        Value::Text("Room 101".into()),
    );
    assert_eq!(dispatch(&loc_req, &h.user_ctx("alice")).code, status::OK);

    let pid_req = with_op_attr(
        ipp_req(op::CUPS_GET_PRINTERS),
        "printer-id",
        tags::INTEGER,
        Value::Integer(99_999),
    );
    let pid_resp = dispatch(&pid_req, &ctx);
    assert_eq!(pid_resp.code, status::OK);
    assert_eq!(
        pid_resp
            .groups
            .iter()
            .filter(|g| g.tag == tags::PRINTER)
            .count(),
        0
    );

    let ptype_req = with_op_attr(
        with_op_attr(
            ipp_req(op::CUPS_GET_PRINTERS),
            "printer-type",
            tags::ENUM,
            Value::Enum(ptype::FAX),
        ),
        "printer-type-mask",
        tags::ENUM,
        Value::Enum(ptype::FAX),
    );
    assert_eq!(dispatch(&ptype_req, &ctx).code, status::OK);

    // No default printer & empty registry:
    {
        let mut reg = h.registry.write().unwrap();
        reg.default = None;
        reg.printers.clear();
    }
    assert_eq!(
        dispatch(&ipp_req(op::CUPS_GET_DEFAULT), &ctx).code,
        status::ERROR_NOT_FOUND
    );
    assert_eq!(
        dispatch(&ipp_req(op::CUPS_GET_PRINTERS), &ctx).code,
        status::ERROR_NOT_FOUND
    );
}

#[test]
fn security_custom_policy_fallback_missing_policy_and_limits() {
    let mut h = Harness::new("sec-edges");

    // 1. Custom policy with EXPLICIT `<Limit Cancel-Document>` allowing alice (overrides fallback).
    let mut explicit_pol = Policy {
        name: "explicit-doc".into(),
        ops: Vec::new(),
        job_access: Vec::new(),
        job_values: Vec::new(),
        sub_access: Vec::new(),
        sub_values: Vec::new(),
    };
    let mut loc = Location::new("<policy>");
    loc.order = OrderType::Allow;
    loc.auth_level = AuthLevel::User;
    loc.names = vec!["alice".into()];
    explicit_pol.ops.push(PolicyOp {
        op: u32::from(op::CANCEL_DOCUMENT),
        loc,
    });
    h.cfg.cupsd.policies.push(explicit_pol);
    h.registry
        .write()
        .unwrap()
        .printers
        .get_mut("laser1")
        .unwrap()
        .op_policy = Some("explicit-doc".into());

    // Submit a job owned by bob; alice can cancel doc 1 under `explicit-doc` policy!
    let mut bob_ctx = h.user_ctx("bob");
    bob_ctx.document = b"doc1";
    let pj = with_printer_uri(
        ipp_req(op::PRINT_JOB),
        "ipp://localhost:631/printers/laser1",
    );
    // Allow Print-Job via default policy first:
    h.registry
        .write()
        .unwrap()
        .printers
        .get_mut("laser1")
        .unwrap()
        .op_policy = None;
    let jid = find_attr_int(&dispatch(&pj, &bob_ctx), tags::JOB, "job-id").unwrap();
    h.registry
        .write()
        .unwrap()
        .printers
        .get_mut("laser1")
        .unwrap()
        .op_policy = Some("explicit-doc".into());

    let cdoc = with_op_attr(
        with_op_attr(
            with_printer_uri(
                ipp_req(op::CANCEL_DOCUMENT),
                "ipp://localhost:631/printers/laser1",
            ),
            "job-id",
            tags::INTEGER,
            Value::Integer(jid),
        ),
        "document-number",
        tags::INTEGER,
        Value::Integer(1),
    );
    assert_eq!(dispatch(&cdoc, &h.user_ctx("alice")).code, status::OK);

    // 2. `@ALL` in `AllowUser` / `DenyUser` and global `MaxJobs`.
    {
        let mut reg = h.registry.write().unwrap();
        let p = reg.printers.get_mut("laser1").unwrap();
        p.op_policy = None;
        p.users = vec!["@ALL".into()];
        p.deny_users = true;
    }
    let val_req = with_printer_uri(
        ipp_req(op::VALIDATE_JOB),
        "ipp://localhost:631/printers/laser1",
    );
    assert_eq!(
        dispatch(&val_req, &h.user_ctx("alice")).code,
        status::ERROR_NOT_AUTHORIZED
    );

    // Clear deny_users and test global MaxJobs = 1 (we already have active job `jid`).
    h.registry
        .write()
        .unwrap()
        .printers
        .get_mut("laser1")
        .unwrap()
        .users
        .clear();
    let mut ctx_max = h.user_ctx("alice");
    ctx_max.max_jobs = 1;
    assert_eq!(
        dispatch(&val_req, &ctx_max).code,
        status::ERROR_TOO_MANY_JOBS
    );
}

#[test]
fn subscriptions_error_paths_limits_and_sync_wait_timeout() {
    let h = Harness::new("sub-edges");
    let alice = h.user_ctx("alice");
    let anon = h.ctx();

    // 1. Missing `notify-subscription-id` on get/renew/cancel -> ERROR_BAD_REQUEST.
    for code in [
        op::GET_SUBSCRIPTION_ATTRIBUTES,
        op::RENEW_SUBSCRIPTION,
        op::CANCEL_SUBSCRIPTION,
    ] {
        assert_eq!(
            dispatch(&ipp_req(code), &alice).code,
            status::ERROR_BAD_REQUEST
        );
    }

    // 2. Missing `notify-subscription-ids` -> ERROR_BAD_REQUEST; all unknown -> ERROR_NOT_FOUND.
    assert_eq!(
        dispatch(&ipp_req(op::GET_NOTIFICATIONS), &alice).code,
        status::ERROR_BAD_REQUEST
    );
    let unknown_gn = with_op_attr(
        ipp_req(op::GET_NOTIFICATIONS),
        "notify-subscription-ids",
        tags::INTEGER,
        Value::Integer(999),
    );
    // Anonymous caller on unknown sub still hits AuthRequired (not 404 oracle!).
    assert!(dispatch_outcome(&unknown_gn, &anon).need_auth);
    assert_eq!(
        dispatch(&unknown_gn, &h.admin_ctx()).code,
        status::ERROR_NOT_FOUND
    );

    // 3. `Create-Printer-Subscriptions` error & feature paths:
    // No subscription group -> ERROR_BAD_REQUEST.
    let no_seg = with_printer_uri(
        ipp_req(op::CREATE_PRINTER_SUBSCRIPTIONS),
        "ipp://localhost:631/printers/laser1",
    );
    assert_eq!(dispatch(&no_seg, &alice).code, status::ERROR_BAD_REQUEST);

    // Segment without pull-method or recipient-uri -> ERROR_BAD_REQUEST.
    let no_method = with_sub_group(
        with_printer_uri(
            ipp_req(op::CREATE_PRINTER_SUBSCRIPTIONS),
            "ipp://localhost:631/printers/laser1",
        ),
        vec![Attribute::new(
            "notify-events",
            tags::KEYWORD,
            vec![Value::Keyword("printer-state-changed".into())],
        )],
    );
    assert_eq!(dispatch(&no_method, &alice).code, status::ERROR_BAD_REQUEST);

    // Server-wide sub without `notify-events` -> ERROR_BAD_REQUEST.
    let server_no_ev = with_sub_group(
        with_printer_uri(
            ipp_req(op::CREATE_PRINTER_SUBSCRIPTIONS),
            "ipp://localhost:631/",
        ),
        vec![Attribute::new(
            "notify-pull-method",
            tags::KEYWORD,
            vec![Value::Keyword("ippget".into())],
        )],
    );
    assert_eq!(
        dispatch(&server_no_ev, &alice).code,
        status::ERROR_BAD_REQUEST
    );

    // Printer sub with omitted `notify-events` defaults to `printer-state-changed`,
    // plus push `notify-recipient-uri` AND multi-segment with `Attribute::separator()`.
    let mut multi_sub = with_printer_uri(
        ipp_req(op::CREATE_PRINTER_SUBSCRIPTIONS),
        "ipp://localhost:631/printers/laser1",
    );
    let mut sg = Group::new(tags::SUBSCRIPTION);
    sg.attributes = vec![
        Attribute::new(
            "notify-pull-method",
            tags::KEYWORD,
            vec![Value::Keyword("ippget".into())],
        ),
        Attribute::separator(),
        Attribute::new(
            "notify-recipient-uri",
            tags::URI,
            vec![Value::Uri("mailto:ops@example.com".into())],
        ),
        Attribute::new(
            "notify-events",
            tags::KEYWORD,
            vec![Value::Keyword("printer-modified".into())],
        ),
    ];
    multi_sub.groups.push(sg);
    let ms_resp = dispatch(&multi_sub, &alice);
    assert_eq!(ms_resp.code, status::OK);
    let sub_ids: Vec<i32> = ms_resp
        .groups
        .iter()
        .filter(|g| g.tag == tags::SUBSCRIPTION)
        .filter_map(|g| g.find("notify-subscription-id").and_then(Attribute::int))
        .collect();
    assert_eq!(sub_ids.len(), 2);

    // Inspect push sub & `Get-Subscriptions` with `my-subscriptions=true`, `limit=1`, `is_encrypted=true`.
    let mut alice_tls = h.user_ctx("alice");
    alice_tls.is_encrypted = true;
    let gs_req = with_op_attr(
        with_op_attr(
            ipp_req(op::GET_SUBSCRIPTIONS),
            "my-subscriptions",
            tags::BOOLEAN,
            Value::Boolean(true),
        ),
        "limit",
        tags::INTEGER,
        Value::Integer(1),
    );
    let gs_resp = dispatch(&gs_req, &alice_tls);
    assert_eq!(gs_resp.code, status::OK);
    assert_eq!(
        gs_resp
            .groups
            .iter()
            .filter(|g| g.tag == tags::SUBSCRIPTION)
            .count(),
        1
    );

    // Also inspect the push sub (second id) directly so `notify-recipient-uri` branch is covered!
    let get_push = with_op_attr(
        ipp_req(op::GET_SUBSCRIPTION_ATTRIBUTES),
        "notify-subscription-id",
        tags::INTEGER,
        Value::Integer(sub_ids[1]),
    );
    let push_resp = dispatch(&get_push, &alice_tls);
    assert_eq!(push_resp.code, status::OK);
    assert_eq!(
        find_attr_text(&push_resp, tags::SUBSCRIPTION, "notify-recipient-uri").as_deref(),
        Some("mailto:ops@example.com")
    );

    // 4. `MaxSubscriptions`, `MaxSubscriptionsPerUser`, `MaxSubscriptionsPerPrinter`, `MaxSubscriptionsPerJob`:
    let mk_printer_sub = || {
        with_sub_group(
            with_printer_uri(
                ipp_req(op::CREATE_PRINTER_SUBSCRIPTIONS),
                "ipp://localhost:631/printers/laser1",
            ),
            vec![Attribute::new(
                "notify-pull-method",
                tags::KEYWORD,
                vec![Value::Keyword("ippget".into())],
            )],
        )
    };
    let mut lim_global = h.user_ctx("alice");
    lim_global.max_subscriptions = 2;
    assert_eq!(
        dispatch(&mk_printer_sub(), &lim_global).code,
        status::ERROR_TOO_MANY_SUBSCRIPTIONS
    );
    let mut lim_user = h.user_ctx("alice");
    lim_user.max_subscriptions_per_user = 2;
    assert_eq!(
        dispatch(&mk_printer_sub(), &lim_user).code,
        status::ERROR_TOO_MANY_SUBSCRIPTIONS
    );
    let mut lim_printer = h.user_ctx("bob");
    lim_printer.max_subscriptions_per_printer = 2;
    assert_eq!(
        dispatch(&mk_printer_sub(), &lim_printer).code,
        status::ERROR_TOO_MANY_SUBSCRIPTIONS
    );

    // 5. `Create-Job-Subscriptions` missing job (anon -> need_auth, admin -> NOT_FOUND) & per-job limit.
    let bad_jsub = with_sub_group(
        with_op_attr(
            with_printer_uri(
                ipp_req(op::CREATE_JOB_SUBSCRIPTIONS),
                "ipp://localhost:631/printers/laser1",
            ),
            "job-id",
            tags::INTEGER,
            Value::Integer(4242),
        ),
        vec![Attribute::new(
            "notify-pull-method",
            tags::KEYWORD,
            vec![Value::Keyword("ippget".into())],
        )],
    );
    assert!(dispatch_outcome(&bad_jsub, &anon).need_auth);
    assert_eq!(
        dispatch(&bad_jsub, &h.admin_ctx()).code,
        status::ERROR_NOT_FOUND
    );

    // Submit a job with embedded sub that hits per-job limit + segment without method:
    let mut print_ctx = h.user_ctx("alice");
    print_ctx.document = b"hello";
    print_ctx.max_subscriptions_per_job = 1;
    let pj = with_sub_group(
        with_sub_group(
            with_sub_group(
                with_printer_uri(
                    ipp_req(op::PRINT_JOB),
                    "ipp://localhost:631/printers/laser1",
                ),
                vec![Attribute::new(
                    "notify-events",
                    tags::KEYWORD,
                    vec![Value::Keyword("job-completed".into())],
                )], // skipped (no pull/recipient)
            ),
            vec![Attribute::new(
                "notify-pull-method",
                tags::KEYWORD,
                vec![Value::Keyword("ippget".into())],
            )],
        ),
        vec![Attribute::new(
            "notify-pull-method",
            tags::KEYWORD,
            vec![Value::Keyword("ippget".into())],
        )], // hits per-job limit=1 and breaks
    );
    let pj_resp = dispatch(&pj, &print_ctx);
    assert_eq!(pj_resp.code, status::OK);
    let jid = find_attr_int(&pj_resp, tags::JOB, "job-id").unwrap();

    // Standalone `Create-Job-Subscriptions` hitting per-job limit -> ERROR_TOO_MANY_SUBSCRIPTIONS.
    let extra_jsub = with_sub_group(
        with_op_attr(
            with_printer_uri(
                ipp_req(op::CREATE_JOB_SUBSCRIPTIONS),
                "ipp://localhost:631/printers/laser1",
            ),
            "job-id",
            tags::INTEGER,
            Value::Integer(jid),
        ),
        vec![Attribute::new(
            "notify-pull-method",
            tags::KEYWORD,
            vec![Value::Keyword("ippget".into())],
        )],
    );
    assert_eq!(
        dispatch(&extra_jsub, &print_ctx).code,
        status::ERROR_TOO_MANY_SUBSCRIPTIONS
    );

    // 6. Sync & async `Get-Notifications` with `notify-wait=true` timing out cleanly!
    let mut wait_ctx = h.user_ctx("alice");
    wait_ctx.notify_wait_timeout = Duration::from_millis(25);
    let gn_wait = with_op_attr(
        with_op_attr(
            with_op_attr(
                ipp_req(op::GET_NOTIFICATIONS),
                "notify-subscription-ids",
                tags::INTEGER,
                Value::Integer(sub_ids[0]),
            ),
            "notify-sequence-numbers",
            tags::INTEGER,
            Value::Integer(999),
        ),
        "notify-wait",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    let sync_to = dispatch(&gn_wait, &wait_ctx);
    assert_eq!(sync_to.code, status::OK);
    let async_to = block_on(dispatch_async(&gn_wait, &wait_ctx)).response;
    assert_eq!(async_to.code, status::OK);
}

#[test]
fn admin_ops_all_attrs_classes_and_error_paths() {
    let h = Harness::new("admin-edges");
    let admin = h.admin_ctx();

    // Install mock cups-driverd that returns valid PPD on `cat good.ppd` and fails otherwise.
    let sample_ppd = valid_sample_ppd();
    let driverd_script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"cat\" ] && [ \"$2\" = \"good.ppd\" ]; then\ncat <<'EOF'\n{sample_ppd}EOF\nexit 0\nfi\nif [ \"$1\" = \"list\" ]; then\necho 'ignored line'\necho 'ppd \"\" \"empty\"'\necho 'ppd \"good.ppd\" \"Good Model\" \"MFG:P;\" \"(Good)\" \"(3010) 0\" \"postscript\"'\nexit 0\nfi\nexit 1\n"
    );
    h.install_mock_script("daemon/cups-driverd", &driverd_script);

    // 1. `CUPS-Add-Modify-Printer`: set ALL common dest attributes + ppd-name fetch!
    let mut add_full = with_printer_uri(
        ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
        "ipp://localhost:631/printers/laser1",
    );
    for (name, tag, vals) in [
        (
            "printer-make-and-model",
            tags::TEXT,
            vec![Value::Text("LaserPro 9000".into())],
        ),
        (
            "printer-organizational-unit",
            tags::TEXT,
            vec![Value::Text("Engineering".into())],
        ),
        (
            "printer-is-accepting-jobs",
            tags::BOOLEAN,
            vec![Value::Boolean(true)],
        ),
        (
            "printer-is-shared",
            tags::BOOLEAN,
            vec![Value::Boolean(false)],
        ),
        (
            "printer-is-temporary",
            tags::BOOLEAN,
            vec![Value::Boolean(true)],
        ),
        ("printer-state", tags::ENUM, vec![Value::Enum(3)]),
        (
            "printer-op-policy",
            tags::NAME,
            vec![Value::Name("default".into())],
        ),
        (
            "printer-error-policy",
            tags::NAME,
            vec![Value::Name("abort-job".into())],
        ),
        (
            "job-quota-period",
            tags::INTEGER,
            vec![Value::Integer(3600)],
        ),
        ("job-k-limit", tags::INTEGER, vec![Value::Integer(4096)]),
        ("job-page-limit", tags::INTEGER, vec![Value::Integer(100)]),
        (
            "requesting-user-name-allowed",
            tags::NAME,
            vec![Value::Name("alice".into()), Value::Name("bob".into())],
        ),
        (
            "job-sheets-default",
            tags::NAME,
            vec![
                Value::Name("classified".into()),
                Value::Name("secret".into()),
            ],
        ),
        (
            "auth-info-required",
            tags::KEYWORD,
            vec![Value::Keyword("username".into())],
        ),
        ("ppd-name", tags::NAME, vec![Value::Name("good.ppd".into())]),
    ] {
        add_full.push(tags::PRINTER, Attribute::new(name, tag, vals));
    }
    assert_eq!(dispatch(&add_full, &admin).code, status::OK);
    assert!(h.server_root.join("ppd/laser1.ppd").is_file());

    // Deny-users branch & invalid `printer-state` (99) rejected:
    let deny_req = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
            "ipp://localhost:631/printers/laser1",
        ),
        "requesting-user-name-denied",
        tags::NAME,
        Value::Name("mallory".into()),
    );
    assert_eq!(dispatch(&deny_req, &admin).code, status::OK);
    assert!(
        h.registry
            .read()
            .unwrap()
            .find("laser1")
            .unwrap()
            .deny_users
    );

    let bad_state = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
            "ipp://localhost:631/printers/laser1",
        ),
        "printer-state",
        tags::ENUM,
        Value::Enum(99),
    );
    assert_eq!(
        dispatch(&bad_state, &admin).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );

    // Bad `ppd-name` traversal / `file:` rejected:
    for bad_ppd in ["../etc/passwd", "file:///etc/passwd"] {
        let req = with_printer_attr(
            with_printer_uri(
                ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
                "ipp://localhost:631/printers/laser1",
            ),
            "ppd-name",
            tags::NAME,
            Value::Name(bad_ppd.into()),
        );
        assert_eq!(dispatch(&req, &admin).code, status::ERROR_BAD_REQUEST);
    }

    // Bad printer-uri (no /printers/ segment):
    let bad_uri = with_printer_uri(
        ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
        "ipp://localhost:631/wrong/x",
    );
    assert_eq!(dispatch(&bad_uri, &admin).code, status::ERROR_BAD_REQUEST);

    // 2. Class lifecycle, collision with printer (MUST NOT write PPD!), & class state ops:
    let mk_class = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_CLASS),
            "ipp://localhost:631/classes/pool",
        ),
        "member-uris",
        tags::URI,
        Value::Uri("ipp://localhost:631/printers/laser1".into()),
    );
    assert_eq!(dispatch(&mk_class, &admin).code, status::OK);

    // Modify existing class with `printer-is-shared=false` and bad member URI / bad state:
    let mod_class = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_CLASS),
            "ipp://localhost:631/classes/pool",
        ),
        "printer-is-shared",
        tags::BOOLEAN,
        Value::Boolean(false),
    );
    assert_eq!(dispatch(&mod_class, &admin).code, status::OK);

    let bad_member = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_CLASS),
            "ipp://localhost:631/classes/pool",
        ),
        "member-uris",
        tags::URI,
        Value::Uri("/".into()),
    );
    assert_eq!(
        dispatch(&bad_member, &admin).code,
        status::ERROR_BAD_REQUEST
    );

    let bad_cstate = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_CLASS),
            "ipp://localhost:631/classes/pool",
        ),
        "printer-state",
        tags::ENUM,
        Value::Enum(42),
    );
    assert_eq!(
        dispatch(&bad_cstate, &admin).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );

    // Attempting `CUPS-Add-Modify-Printer` onto existing class `pool` with PPD fails AND does NOT write pool.ppd!
    let mut admin_ppd = h.admin_ctx();
    admin_ppd.document = sample_ppd.as_bytes();
    let collide = with_printer_uri(
        ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
        "ipp://localhost:631/printers/pool",
    );
    assert_eq!(
        dispatch(&collide, &admin_ppd).code,
        status::ERROR_NOT_POSSIBLE
    );
    assert!(!h.server_root.join("ppd/pool.ppd").exists());

    // Class variants of state/accept/hold/release/set-printer-attrs/identify (covers `save_classes` branches!):
    let pause_c = with_op_attr(
        with_printer_uri(
            ipp_req(op::PAUSE_PRINTER),
            "ipp://localhost:631/classes/pool",
        ),
        "printer-state-message",
        tags::TEXT,
        Value::Text("maintenance".into()),
    );
    assert_eq!(dispatch(&pause_c, &admin).code, status::OK);

    let rej_c = with_op_attr(
        with_op_attr(
            with_printer_uri(
                ipp_req(op::CUPS_REJECT_JOBS),
                "ipp://localhost:631/classes/pool",
            ),
            "printer-state-message",
            tags::TEXT,
            Value::Text("full".into()),
        ),
        "printer-state-reasons",
        tags::KEYWORD,
        Value::Keyword("media-empty".into()),
    );
    assert_eq!(dispatch(&rej_c, &admin).code, status::OK);

    assert_eq!(
        dispatch(
            &with_printer_uri(
                ipp_req(op::HOLD_NEW_JOBS),
                "ipp://localhost:631/classes/pool"
            ),
            &admin
        )
        .code,
        status::OK
    );
    assert_eq!(
        dispatch(
            &with_printer_uri(
                ipp_req(op::RELEASE_HELD_NEW_JOBS),
                "ipp://localhost:631/classes/pool"
            ),
            &admin
        )
        .code,
        status::OK
    );
    let set_c = with_printer_attr(
        with_printer_uri(
            ipp_req(op::SET_PRINTER_ATTRIBUTES),
            "ipp://localhost:631/classes/pool",
        ),
        "printer-is-shared",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    assert_eq!(dispatch(&set_c, &admin).code, status::OK);

    // 3. `CUPS-Create-Local-Printer` edge cases:
    assert_eq!(
        dispatch(&ipp_req(op::CUPS_CREATE_LOCAL_PRINTER), &admin).code,
        status::ERROR_BAD_REQUEST
    );
    let bad_local_name = with_op_attr(
        ipp_req(op::CUPS_CREATE_LOCAL_PRINTER),
        "printer-name",
        tags::NAME,
        Value::Name("../evil".into()),
    );
    assert_eq!(
        dispatch(&bad_local_name, &admin).code,
        status::ERROR_BAD_REQUEST
    );
    let bad_local_uri = with_op_attr(
        with_op_attr(
            ipp_req(op::CUPS_CREATE_LOCAL_PRINTER),
            "printer-name",
            tags::NAME,
            Value::Name("loc1".into()),
        ),
        "device-uri",
        tags::URI,
        Value::Uri("file:///tmp/out".into()),
    );
    assert_eq!(
        dispatch(&bad_local_uri, &admin).code,
        status::ERROR_NOT_POSSIBLE
    );
    let bad_local_ppd = with_op_attr(
        with_op_attr(
            ipp_req(op::CUPS_CREATE_LOCAL_PRINTER),
            "printer-name",
            tags::NAME,
            Value::Name("loc1".into()),
        ),
        "ppd-name",
        tags::NAME,
        Value::Name("../bad".into()),
    );
    assert_eq!(
        dispatch(&bad_local_ppd, &admin).code,
        status::ERROR_BAD_REQUEST
    );
    let good_local = with_op_attr(
        with_op_attr(
            with_op_attr(
                with_op_attr(
                    ipp_req(op::CUPS_CREATE_LOCAL_PRINTER),
                    "printer-name",
                    tags::NAME,
                    Value::Name("loc_ok".into()),
                ),
                "device-uri",
                tags::URI,
                Value::Uri("ipp://loc.local/ipp".into()),
            ),
            "ppd-name",
            tags::NAME,
            Value::Name("good.ppd".into()),
        ),
        "ppd-make",
        tags::TEXT,
        Value::Text("Generic".into()),
    );
    assert_eq!(dispatch(&good_local, &admin).code, status::OK);

    // 4. Nonexistent destination error paths across all admin ops + Set-Printer-Attributes bad device-uri/state:
    for code in [
        op::CUPS_DELETE_PRINTER,
        op::CUPS_SET_DEFAULT,
        op::PAUSE_PRINTER,
        op::CUPS_ACCEPT_JOBS,
        op::HOLD_NEW_JOBS,
        op::RELEASE_HELD_NEW_JOBS,
        op::SET_PRINTER_ATTRIBUTES,
        op::IDENTIFY_PRINTER,
    ] {
        let req = with_printer_uri(ipp_req(code), "ipp://localhost:631/printers/no_such_q");
        assert_eq!(
            dispatch(&req, &admin).code,
            status::ERROR_NOT_FOUND,
            "op {code:#x} should return NOT_FOUND"
        );
    }

    let spa_bad_dev = with_printer_attr(
        with_printer_uri(
            ipp_req(op::SET_PRINTER_ATTRIBUTES),
            "ipp://localhost:631/printers/laser1",
        ),
        "device-uri",
        tags::URI,
        Value::Uri("file:///etc/passwd".into()),
    );
    assert_eq!(
        dispatch(&spa_bad_dev, &admin).code,
        status::ERROR_NOT_POSSIBLE
    );
    let spa_bad_state = with_printer_attr(
        with_printer_uri(
            ipp_req(op::SET_PRINTER_ATTRIBUTES),
            "ipp://localhost:631/printers/laser1",
        ),
        "printer-state",
        tags::ENUM,
        Value::Enum(77),
    );
    assert_eq!(
        dispatch(&spa_bad_state, &admin).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );

    // `Identify-Printer` with explicit `identify-actions`:
    let id_req = with_op_attr(
        with_printer_uri(
            ipp_req(op::IDENTIFY_PRINTER),
            "ipp://localhost:631/printers/laser1",
        ),
        "identify-actions",
        tags::KEYWORD,
        Value::Keyword("flash".into()),
    );
    assert_eq!(dispatch(&id_req, &admin).code, status::OK);

    // 5. `CUPS-Get-PPDs` (mock with ignored lines + empty name) and `CUPS-Get-PPD` (async file:, printer-uri fallback, missing):
    let ppds_resp = dispatch(&ipp_req(op::CUPS_GET_PPDS), &admin);
    assert_eq!(ppds_resp.code, status::OK);
    assert_eq!(
        ppds_resp
            .groups
            .iter()
            .filter(|g| g.tag == tags::PRINTER)
            .count(),
        1
    );

    // Async `CUPS-Get-PPD` via `file:laser1` and via `printer-uri` without local file (falls back to `ppd-name` option):
    let get_file_ppd = with_op_attr(
        ipp_req(op::CUPS_GET_PPD),
        "ppd-name",
        tags::NAME,
        Value::Name("file:laser1".into()),
    );
    let async_file = block_on(dispatch_async(&get_file_ppd, &admin)).response;
    assert_eq!(async_file.code, status::OK);
    assert_ne!(async_file.document, Vec::<u8>::new());

    std::fs::remove_file(h.server_root.join("ppd/laser1.ppd")).unwrap();
    let get_by_uri = with_printer_uri(
        ipp_req(op::CUPS_GET_PPD),
        "ipp://localhost:631/printers/laser1",
    );
    assert_eq!(dispatch(&get_by_uri, &admin).code, status::OK);

    // Missing PPD via `file:missing` and async missing driverd model:
    let miss_file = with_op_attr(
        ipp_req(op::CUPS_GET_PPD),
        "ppd-name",
        tags::NAME,
        Value::Name("file:does_not_exist".into()),
    );
    assert_eq!(dispatch(&miss_file, &admin).code, status::ERROR_NOT_FOUND);
    let miss_drv = with_op_attr(
        ipp_req(op::CUPS_GET_PPD),
        "ppd-name",
        tags::NAME,
        Value::Name("no_such_model.ppd".into()),
    );
    assert_eq!(
        block_on(dispatch_async(&miss_drv, &admin)).response.code,
        status::ERROR_NOT_FOUND
    );

    // Missing `cups-driverd` binary -> ERROR_INTERNAL:
    std::fs::remove_file(h.server_bin.join("daemon/cups-driverd")).unwrap();
    assert_eq!(
        dispatch(&ipp_req(op::CUPS_GET_PPDS), &admin).code,
        status::ERROR_INTERNAL
    );
    // Unauthorized async `CUPS-Get-Devices` -> need_auth:
    assert!(block_on(dispatch_async(&ipp_req(op::CUPS_GET_DEVICES), &h.ctx())).need_auth);
}

#[test]
fn jobs_ops_error_paths_oracles_and_edge_cases() {
    let h = Harness::new("jobs-edges");
    h.add_printer("laser2", "ipp://printer2.local/ipp");
    let alice = h.user_ctx("alice");
    let bob = h.user_ctx("bob");
    let admin = h.admin_ctx();
    let anon = h.ctx();

    // 1. AuthZ-before-404 oracle checks for anonymous caller on nonexistent printer/job!
    for req in [
        with_op_attr(
            with_printer_uri(
                ipp_req(op::CANCEL_JOB),
                "ipp://localhost:631/printers/secret_q",
            ),
            "job-id",
            tags::INTEGER,
            Value::Integer(0),
        ),
        with_printer_uri(
            ipp_req(op::CANCEL_CURRENT_JOB),
            "ipp://localhost:631/printers/secret_q",
        ),
        with_printer_uri(
            ipp_req(op::SUSPEND_CURRENT_JOB),
            "ipp://localhost:631/printers/secret_q",
        ),
        with_printer_uri(
            ipp_req(op::CANCEL_MY_JOBS),
            "ipp://localhost:631/printers/secret_q",
        ),
        with_printer_uri(
            ipp_req(op::CANCEL_JOBS),
            "ipp://localhost:631/printers/secret_q",
        ),
        with_printer_uri(
            ipp_req(op::PURGE_JOBS),
            "ipp://localhost:631/printers/secret_q",
        ),
        with_op_attr(
            with_printer_uri(
                ipp_req(op::CUPS_MOVE_JOB),
                "ipp://localhost:631/printers/secret_q",
            ),
            "job-printer-uri",
            tags::URI,
            Value::Uri("ipp://localhost:631/printers/laser2".into()),
        ),
        with_op_attr(
            with_op_attr(
                with_printer_uri(
                    ipp_req(op::SEND_DOCUMENT),
                    "ipp://localhost:631/printers/laser1",
                ),
                "job-id",
                tags::INTEGER,
                Value::Integer(9999),
            ),
            "last-document",
            tags::BOOLEAN,
            Value::Boolean(true),
        ),
        with_op_attr(
            with_op_attr(
                with_printer_uri(ipp_req(op::SEND_URI), "ipp://localhost:631/printers/laser1"),
                "job-id",
                tags::INTEGER,
                Value::Integer(9999),
            ),
            "last-document",
            tags::BOOLEAN,
            Value::Boolean(true),
        ),
    ] {
        let out = dispatch_outcome(&req, &anon);
        assert!(
            out.need_auth,
            "op {:#x} must challenge anonymous before returning 404 (got {:#x})",
            req.code, out.response.code
        );
    }

    // 2. Nonexistent printer & rejecting printer & AllowUser denied on Validate-Job / Print-Job / Create-Job:
    for code in [op::VALIDATE_JOB, op::PRINT_JOB, op::CREATE_JOB] {
        let miss = with_printer_uri(ipp_req(code), "ipp://localhost:631/printers/no_q");
        assert_eq!(dispatch(&miss, &alice).code, status::ERROR_NOT_FOUND);
    }

    // Rejecting printer + AllowUser denial:
    h.registry
        .write()
        .unwrap()
        .printers
        .get_mut("laser2")
        .unwrap()
        .accepting = false;
    for code in [op::VALIDATE_JOB, op::PRINT_JOB, op::CREATE_JOB] {
        let rej = with_printer_uri(ipp_req(code), "ipp://localhost:631/printers/laser2");
        assert_eq!(
            dispatch(&rej, &alice).code,
            status::ERROR_NOT_ACCEPTING_JOBS
        );
    }
    {
        let mut reg = h.registry.write().unwrap();
        let p2 = reg.printers.get_mut("laser2").unwrap();
        p2.accepting = true;
        p2.users = vec!["bob".into()];
        p2.deny_users = false;
    }
    for code in [op::VALIDATE_JOB, op::PRINT_JOB, op::CREATE_JOB] {
        let denied = with_printer_uri(ipp_req(code), "ipp://localhost:631/printers/laser2");
        assert_eq!(dispatch(&denied, &alice).code, status::ERROR_NOT_AUTHORIZED);
    }

    // 3. `Print-Job` / `Create-Job` / `Validate-Job` attribute edge cases:
    // Bad copies in OPERATION group, bad orientation, unknown attr -> OK_IGNORED_OR_SUBSTITUTED,
    // unsupported format, unsupported compression, `job-hold-until`.
    let bad_op_copies = with_op_attr(
        with_printer_uri(
            ipp_req(op::VALIDATE_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        "copies",
        tags::INTEGER,
        Value::Integer(0),
    );
    assert_eq!(
        dispatch(&bad_op_copies, &alice).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );

    let bad_orient = with_job_attr(
        with_printer_uri(
            ipp_req(op::CREATE_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        "orientation-requested",
        tags::ENUM,
        Value::Enum(99),
    );
    assert_eq!(
        dispatch(&bad_orient, &alice).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );

    let bad_fmt = with_op_attr(
        with_printer_uri(
            ipp_req(op::PRINT_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        "document-format",
        tags::MIMETYPE,
        Value::MimeMediaType("application/x-unknown-evil".into()),
    );
    assert_eq!(
        dispatch(&bad_fmt, &alice).code,
        status::ERROR_DOCUMENT_FORMAT_NOT_SUPPORTED
    );

    let bad_comp = with_op_attr(
        with_printer_uri(
            ipp_req(op::VALIDATE_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        "compression",
        tags::KEYWORD,
        Value::Keyword("lzma".into()),
    );
    assert_eq!(
        dispatch(&bad_comp, &alice).code,
        status::ERROR_COMPRESSION_NOT_SUPPORTED
    );

    // Unknown attr (fidelity=false) -> OK_IGNORED_OR_SUBSTITUTED on both Print-Job and Create-Job!
    let mut alice_doc = h.user_ctx("alice");
    alice_doc.document = b"hello world";
    let pj_held_ign = with_job_attr(
        with_job_attr(
            with_printer_uri(
                ipp_req(op::PRINT_JOB),
                "ipp://localhost:631/printers/laser1",
            ),
            "job-hold-until",
            tags::KEYWORD,
            Value::Keyword("indefinite".into()),
        ),
        "x-unknown-vendor-attr",
        tags::KEYWORD,
        Value::Keyword("foo".into()),
    );
    let pj_resp = dispatch(&pj_held_ign, &alice_doc);
    assert_eq!(pj_resp.code, status::OK_IGNORED_OR_SUBSTITUTED);
    let jid1 = find_attr_int(&pj_resp, tags::JOB, "job-id").unwrap();

    let cj_ign = with_job_attr(
        with_job_attr(
            with_printer_uri(
                ipp_req(op::CREATE_JOB),
                "ipp://localhost:631/printers/laser1",
            ),
            "job-hold-until",
            tags::KEYWORD,
            Value::Keyword("evening".into()),
        ),
        "x-unknown-cj",
        tags::KEYWORD,
        Value::Keyword("bar".into()),
    );
    let cj_resp = dispatch(&cj_ign, &alice);
    assert_eq!(cj_resp.code, status::OK_IGNORED_OR_SUBSTITUTED);
    let jid2 = find_attr_int(&cj_resp, tags::JOB, "job-id").unwrap();

    // `Send-Document` error paths (missing job, bad format, bad compression, quota) & hold-until on last=true:
    let sd_miss = with_op_attr(
        with_op_attr(
            with_printer_uri(
                ipp_req(op::SEND_DOCUMENT),
                "ipp://localhost:631/printers/laser1",
            ),
            "job-id",
            tags::INTEGER,
            Value::Integer(8888),
        ),
        "last-document",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    assert_eq!(dispatch(&sd_miss, &admin).code, status::ERROR_NOT_FOUND);

    let sd_bad_fmt = with_op_attr(
        with_op_attr(
            with_op_attr(
                with_printer_uri(
                    ipp_req(op::SEND_DOCUMENT),
                    "ipp://localhost:631/printers/laser1",
                ),
                "job-id",
                tags::INTEGER,
                Value::Integer(jid2),
            ),
            "last-document",
            tags::BOOLEAN,
            Value::Boolean(false),
        ),
        "document-format",
        tags::MIMETYPE,
        Value::MimeMediaType("application/x-nope".into()),
    );
    assert_eq!(
        dispatch(&sd_bad_fmt, &alice_doc).code,
        status::ERROR_DOCUMENT_FORMAT_NOT_SUPPORTED
    );

    let sd_bad_comp = with_op_attr(
        with_op_attr(
            with_op_attr(
                with_printer_uri(
                    ipp_req(op::SEND_DOCUMENT),
                    "ipp://localhost:631/printers/laser1",
                ),
                "job-id",
                tags::INTEGER,
                Value::Integer(jid2),
            ),
            "last-document",
            tags::BOOLEAN,
            Value::Boolean(false),
        ),
        "compression",
        tags::KEYWORD,
        Value::Keyword("bzip2".into()),
    );
    assert_eq!(
        dispatch(&sd_bad_comp, &alice_doc).code,
        status::ERROR_COMPRESSION_NOT_SUPPORTED
    );

    // Send-Document with last-document=true on job with `job-hold-until=evening` keeps PendingHeld!
    let sd_ok = with_op_attr(
        with_op_attr(
            with_printer_uri(
                ipp_req(op::SEND_DOCUMENT),
                "ipp://localhost:631/printers/laser1",
            ),
            "job-id",
            tags::INTEGER,
            Value::Integer(jid2),
        ),
        "last-document",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    let sd_resp = dispatch(&sd_ok, &alice_doc);
    assert_eq!(sd_resp.code, status::OK);
    assert_eq!(
        find_attr_int(&sd_resp, tags::JOB, "job-state"),
        Some(JobState::PendingHeld as i32)
    );

    // `Send-URI` missing `last-document` and nonexistent job as admin:
    let su_no_last = with_op_attr(
        with_printer_uri(ipp_req(op::SEND_URI), "ipp://localhost:631/printers/laser1"),
        "job-id",
        tags::INTEGER,
        Value::Integer(jid2),
    );
    assert_eq!(
        dispatch(&su_no_last, &alice).code,
        status::ERROR_BAD_REQUEST
    );
    let su_miss = with_op_attr(
        with_op_attr(
            with_printer_uri(ipp_req(op::SEND_URI), "ipp://localhost:631/printers/laser1"),
            "job-id",
            tags::INTEGER,
            Value::Integer(7777),
        ),
        "last-document",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    assert_eq!(dispatch(&su_miss, &admin).code, status::ERROR_NOT_FOUND);

    // `Print-URI` with bad gzip payload from fetcher:
    let mut fetch_ctx = h.user_ctx("alice");
    fetch_ctx.on_fetch_uri = Some(Arc::new(|_| Ok(b"not valid gzip".to_vec())));
    let pu_bad_gz = with_op_attr(
        with_op_attr(
            with_printer_uri(
                ipp_req(op::PRINT_URI),
                "ipp://localhost:631/printers/laser1",
            ),
            "document-uri",
            tags::URI,
            Value::Uri("https://example.com/bad.gz".into()),
        ),
        "compression",
        tags::KEYWORD,
        Value::Keyword("gzip".into()),
    );
    assert_eq!(
        dispatch(&pu_bad_gz, &fetch_ctx).code,
        status::ERROR_COMPRESSION_ERROR
    );

    // 4. `CUPS-Move-Job`: missing target, nonexistent target, rejecting target,
    // AllowUser bypass BLOCKED when alice tries to move her job to `laser2` (only allows bob)!
    let mv_no_target = with_job_uri(
        ipp_req(op::CUPS_MOVE_JOB),
        &format!("ipp://localhost:631/jobs/{jid1}"),
    );
    assert_eq!(
        dispatch(&mv_no_target, &alice).code,
        status::ERROR_BAD_REQUEST
    );
    let mv_miss = with_op_attr(
        with_job_uri(
            ipp_req(op::CUPS_MOVE_JOB),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        "job-printer-uri",
        tags::URI,
        Value::Uri("ipp://localhost:631/printers/no_target".into()),
    );
    assert_eq!(dispatch(&mv_miss, &alice).code, status::ERROR_NOT_FOUND);

    let mv_denied_acl = with_op_attr(
        with_job_uri(
            ipp_req(op::CUPS_MOVE_JOB),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        "job-printer-uri",
        tags::URI,
        Value::Uri("ipp://localhost:631/printers/laser2".into()),
    );
    assert_eq!(
        dispatch(&mv_denied_acl, &alice).code,
        status::ERROR_NOT_AUTHORIZED
    );

    // Move-All-Jobs from nonexistent source as admin -> ERROR_NOT_FOUND:
    let mv_all_miss = with_op_attr(
        with_printer_uri(
            ipp_req(op::CUPS_MOVE_JOB),
            "ipp://localhost:631/printers/no_src",
        ),
        "job-printer-uri",
        tags::URI,
        Value::Uri("ipp://localhost:631/printers/laser2".into()),
    );
    assert_eq!(dispatch(&mv_all_miss, &admin).code, status::ERROR_NOT_FOUND);

    // Rejecting destination on CUPS-Move-Job:
    h.registry
        .write()
        .unwrap()
        .printers
        .get_mut("laser2")
        .unwrap()
        .accepting = false;
    assert_eq!(
        dispatch(&mv_denied_acl, &admin).code,
        status::ERROR_NOT_ACCEPTING_JOBS
    );
    h.registry
        .write()
        .unwrap()
        .printers
        .get_mut("laser2")
        .unwrap()
        .accepting = true;

    // 5. `Hold-Job` invalid `job-hold-until`, `Set-Job-Attributes` bad value & hold toggling,
    // `Schedule-Job-After` with `job-uri-next`, nonexistent ref job, different-printer ref job:
    let bad_hold = with_op_attr(
        with_job_uri(
            ipp_req(op::HOLD_JOB),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        "job-hold-until",
        tags::KEYWORD,
        Value::Keyword("next-century".into()),
    );
    assert_eq!(
        dispatch(&bad_hold, &alice).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );

    let sja_bad_val = with_job_attr(
        with_job_uri(
            ipp_req(op::SET_JOB_ATTRIBUTES),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        "copies",
        tags::INTEGER,
        Value::Integer(0),
    );
    assert_eq!(
        dispatch(&sja_bad_val, &alice).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );

    // Release jid1 via Set-Job-Attributes `job-hold-until=no-hold`, then re-hold via `indefinite`:
    let sja_nohold = with_job_attr(
        with_job_uri(
            ipp_req(op::SET_JOB_ATTRIBUTES),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        "job-hold-until",
        tags::KEYWORD,
        Value::Keyword("no-hold".into()),
    );
    assert_eq!(
        find_attr_int(&dispatch(&sja_nohold, &alice), tags::JOB, "job-state"),
        Some(JobState::Pending as i32)
    );
    let sja_hold = with_job_attr(
        with_job_attr(
            with_job_uri(
                ipp_req(op::SET_JOB_ATTRIBUTES),
                &format!("ipp://localhost:631/jobs/{jid1}"),
            ),
            "job-hold-until",
            tags::KEYWORD,
            Value::Keyword("indefinite".into()),
        ),
        "copies",
        tags::INTEGER,
        Value::Integer(2),
    );
    assert_eq!(
        find_attr_int(&dispatch(&sja_hold, &alice), tags::JOB, "job-state"),
        Some(JobState::PendingHeld as i32)
    );

    // `Schedule-Job-After` with `job-uri-next`, nonexistent ref, omitted ref, and cross-printer ref:
    let sja_uri_next = with_op_attr(
        with_job_uri(
            ipp_req(op::SCHEDULE_JOB_AFTER),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        "job-uri-next",
        tags::URI,
        Value::Uri(format!("ipp://localhost:631/jobs/{jid2}").into()),
    );
    assert_eq!(dispatch(&sja_uri_next, &admin).code, status::OK);

    let sja_no_ref = with_job_uri(
        ipp_req(op::SCHEDULE_JOB_AFTER),
        &format!("ipp://localhost:631/jobs/{jid1}"),
    );
    assert_eq!(dispatch(&sja_no_ref, &admin).code, status::OK);

    let sja_miss_ref = with_op_attr(
        with_job_uri(
            ipp_req(op::SCHEDULE_JOB_AFTER),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        "job-id-next",
        tags::INTEGER,
        Value::Integer(9999),
    );
    assert_eq!(
        dispatch(&sja_miss_ref, &admin).code,
        status::ERROR_NOT_FOUND
    );

    // Create a bob job on laser2 to test cross-printer `Schedule-Job-After`:
    let mut bob_doc = h.user_ctx("bob");
    bob_doc.document = b"bobdoc";
    let bob_jid = find_attr_int(
        &dispatch(
            &with_printer_uri(
                ipp_req(op::PRINT_JOB),
                "ipp://localhost:631/printers/laser2",
            ),
            &bob_doc,
        ),
        tags::JOB,
        "job-id",
    )
    .unwrap();
    let sja_cross = with_op_attr(
        with_job_uri(
            ipp_req(op::SCHEDULE_JOB_AFTER),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        "job-id-next",
        tags::INTEGER,
        Value::Integer(bob_jid),
    );
    assert_eq!(
        dispatch(&sja_cross, &admin).code,
        status::ERROR_NOT_POSSIBLE
    );

    // 6. `Get-Documents` privacy redaction (bob cannot see alice's `document-name`) & missing doc errors:
    let gd_req = with_job_uri(
        ipp_req(op::GET_DOCUMENTS),
        &format!("ipp://localhost:631/jobs/{jid1}"),
    );
    let gd_alice = dispatch(&gd_req, &alice);
    assert_eq!(gd_alice.code, status::OK);
    assert!(gd_alice.find(tags::DOCUMENT, "document-name").is_some());
    let gd_bob = dispatch(&gd_req, &bob);
    assert_eq!(gd_bob.code, status::OK);
    assert!(gd_bob.find(tags::DOCUMENT, "document-name").is_none());

    let gd_miss = with_op_attr(
        with_job_uri(
            ipp_req(op::GET_DOCUMENT_ATTRIBUTES),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        "document-number",
        tags::INTEGER,
        Value::Integer(99),
    );
    assert_eq!(dispatch(&gd_miss, &alice).code, status::ERROR_NOT_FOUND);

    // `CUPS-Get-Document` missing document number -> ERROR_NOT_FOUND:
    let cgd_miss = with_op_attr(
        with_job_uri(
            ipp_req(op::CUPS_GET_DOCUMENT),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        "document-number",
        tags::INTEGER,
        Value::Integer(99),
    );
    assert_eq!(dispatch(&cgd_miss, &alice).code, status::ERROR_NOT_FOUND);

    // `Cancel-Document` / `Set-Document-Attributes` missing doc number & nonexistent doc:
    for code in [op::CANCEL_DOCUMENT, op::SET_DOCUMENT_ATTRIBUTES] {
        let no_dn = with_job_uri(ipp_req(code), &format!("ipp://localhost:631/jobs/{jid1}"));
        assert_eq!(dispatch(&no_dn, &alice).code, status::ERROR_BAD_REQUEST);
        let miss_dn = with_op_attr(
            with_job_uri(ipp_req(code), &format!("ipp://localhost:631/jobs/{jid1}")),
            "document-number",
            tags::INTEGER,
            Value::Integer(77),
        );
        assert_eq!(dispatch(&miss_dn, &alice).code, status::ERROR_NOT_FOUND);
    }

    // `Set-Document-Attributes` setting `copies` & `media` on doc 1:
    let mut sda_more = with_op_attr(
        with_job_uri(
            ipp_req(op::SET_DOCUMENT_ATTRIBUTES),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        "document-number",
        tags::INTEGER,
        Value::Integer(1),
    );
    sda_more.push(
        tags::DOCUMENT,
        Attribute::new("copies", tags::INTEGER, vec![Value::Integer(3)]),
    );
    sda_more.push(
        tags::DOCUMENT,
        Attribute::new(
            "media",
            tags::KEYWORD,
            vec![Value::Keyword("iso_a4_210x297mm".into())],
        ),
    );
    assert_eq!(dispatch(&sda_more, &alice).code, status::OK);

    // 7. Cancel `jid1`, then verify EVERY completed-job guard returns ERROR_NOT_POSSIBLE!
    let cancel1 = with_job_uri(
        ipp_req(op::CANCEL_JOB),
        &format!("ipp://localhost:631/jobs/{jid1}"),
    );
    assert_eq!(dispatch(&cancel1, &alice).code, status::OK);
    // Canceling again -> ERROR_NOT_POSSIBLE:
    assert_eq!(dispatch(&cancel1, &alice).code, status::ERROR_NOT_POSSIBLE);

    for req in [
        with_op_attr(
            with_job_uri(
                ipp_req(op::SEND_DOCUMENT),
                &format!("ipp://localhost:631/jobs/{jid1}"),
            ),
            "last-document",
            tags::BOOLEAN,
            Value::Boolean(true),
        ),
        with_job_uri(
            ipp_req(op::HOLD_JOB),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        with_job_uri(
            ipp_req(op::RELEASE_JOB),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        with_job_uri(
            ipp_req(op::PROMOTE_JOB),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        with_job_uri(
            ipp_req(op::SCHEDULE_JOB_AFTER),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        with_job_uri(
            ipp_req(op::SET_JOB_ATTRIBUTES),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        with_job_uri(
            ipp_req(op::CUPS_AUTHENTICATE_JOB),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        with_op_attr(
            with_job_uri(
                ipp_req(op::CUPS_MOVE_JOB),
                &format!("ipp://localhost:631/jobs/{jid1}"),
            ),
            "job-printer-uri",
            tags::URI,
            Value::Uri("ipp://localhost:631/printers/laser2".into()),
        ),
        with_op_attr(
            with_job_uri(
                ipp_req(op::CANCEL_DOCUMENT),
                &format!("ipp://localhost:631/jobs/{jid1}"),
            ),
            "document-number",
            tags::INTEGER,
            Value::Integer(1),
        ),
        with_op_attr(
            with_job_uri(
                ipp_req(op::SET_DOCUMENT_ATTRIBUTES),
                &format!("ipp://localhost:631/jobs/{jid1}"),
            ),
            "document-number",
            tags::INTEGER,
            Value::Integer(1),
        ),
    ] {
        assert_eq!(
            dispatch(&req, &admin).code,
            status::ERROR_NOT_POSSIBLE,
            "completed job op {:#x} should return NOT_POSSIBLE",
            req.code
        );
    }

    // 8. `Restart-Job` with `job-hold-until`, and missing spool file on `Restart-Job` / `Resubmit-Job` / `CUPS-Get-Document`:
    let restart_held = with_op_attr(
        with_job_uri(
            ipp_req(op::RESTART_JOB),
            &format!("ipp://localhost:631/jobs/{jid1}"),
        ),
        "job-hold-until",
        tags::KEYWORD,
        Value::Keyword("weekend".into()),
    );
    let rh_resp = dispatch(&restart_held, &alice);
    assert_eq!(rh_resp.code, status::OK);
    assert_eq!(
        find_attr_int(&rh_resp, tags::JOB, "job-state"),
        Some(JobState::PendingHeld as i32)
    );

    // Delete spool file for jid1 and verify Restart-Job, Resubmit-Job, CUPS-Get-Document fail cleanly:
    std::fs::remove_file(Job::data_path(&h.request_root, jid1, 1)).unwrap();
    assert_eq!(
        dispatch(
            &with_job_uri(
                ipp_req(op::RESTART_JOB),
                &format!("ipp://localhost:631/jobs/{jid1}")
            ),
            &alice
        )
        .code,
        status::ERROR_NOT_POSSIBLE
    );
    assert_eq!(
        dispatch(
            &with_job_uri(
                ipp_req(op::RESUBMIT_JOB),
                &format!("ipp://localhost:631/jobs/{jid1}")
            ),
            &alice
        )
        .code,
        status::ERROR_NOT_POSSIBLE
    );
    assert_eq!(
        dispatch(
            &with_job_uri(
                ipp_req(op::CUPS_GET_DOCUMENT),
                &format!("ipp://localhost:631/jobs/{jid1}")
            ),
            &alice
        )
        .code,
        status::ERROR_NOT_FOUND
    );

    // `Resubmit-Job` with bad override attr, hold-until, and rejecting printer:
    let resub_bad = with_job_attr(
        with_job_uri(
            ipp_req(op::RESUBMIT_JOB),
            &format!("ipp://localhost:631/jobs/{jid2}"),
        ),
        "copies",
        tags::INTEGER,
        Value::Integer(0),
    );
    assert_eq!(
        dispatch(&resub_bad, &alice).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );
    let resub_held = with_job_attr(
        with_job_uri(
            ipp_req(op::RESUBMIT_JOB),
            &format!("ipp://localhost:631/jobs/{jid2}"),
        ),
        "job-hold-until",
        tags::KEYWORD,
        Value::Keyword("night".into()),
    );
    assert_eq!(dispatch(&resub_held, &alice).code, status::OK);

    // 9. `Cancel-Current-Job`, `Suspend-Current-Job`, `Cancel-Job(id=0)`, `Cancel-Jobs`, `Purge-Jobs`, `Cancel-My-Jobs` edge cases:
    for code in [op::CANCEL_CURRENT_JOB, op::SUSPEND_CURRENT_JOB] {
        assert_eq!(
            dispatch(
                &with_printer_uri(ipp_req(code), "ipp://localhost:631/printers/no_q"),
                &admin
            )
            .code,
            status::ERROR_NOT_FOUND
        );
        // No processing job on laser1 -> ERROR_NOT_FOUND:
        assert_eq!(
            dispatch(
                &with_printer_uri(ipp_req(code), "ipp://localhost:631/printers/laser1"),
                &admin
            )
            .code,
            status::ERROR_NOT_FOUND
        );
    }

    // `Cancel-Jobs` with `my-jobs=true` on all printers URI, and nonexistent printer:
    assert_eq!(
        dispatch(
            &with_printer_uri(
                ipp_req(op::CANCEL_JOBS),
                "ipp://localhost:631/printers/no_q"
            ),
            &admin
        )
        .code,
        status::ERROR_NOT_FOUND
    );
    let cj_all = with_op_attr(
        with_printer_uri(ipp_req(op::CANCEL_JOBS), "ipp://localhost:631/"),
        "my-jobs",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    assert_eq!(dispatch(&cj_all, &admin).code, status::OK);

    // `Cancel-My-Jobs` on all-printers URI & nonexistent printer:
    assert_eq!(
        dispatch(
            &with_printer_uri(
                ipp_req(op::CANCEL_MY_JOBS),
                "ipp://localhost:631/printers/no_q"
            ),
            &admin
        )
        .code,
        status::ERROR_NOT_FOUND
    );
    assert_eq!(
        dispatch(
            &with_printer_uri(ipp_req(op::CANCEL_MY_JOBS), "ipp://localhost:631/"),
            &alice
        )
        .code,
        status::OK
    );

    // `Cancel-Job` with `job-id=0` on laser1 (now has no active jobs!) -> ERROR_NOT_POSSIBLE,
    // and nonexistent printer -> ERROR_NOT_FOUND, and missing job-id -> ERROR_NOT_FOUND:
    let cj0_empty = with_op_attr(
        with_printer_uri(
            ipp_req(op::CANCEL_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        "job-id",
        tags::INTEGER,
        Value::Integer(0),
    );
    assert_eq!(
        dispatch(&cj0_empty, &admin).code,
        status::ERROR_NOT_POSSIBLE
    );
    let cj0_miss_p = with_op_attr(
        with_printer_uri(ipp_req(op::CANCEL_JOB), "ipp://localhost:631/printers/no_q"),
        "job-id",
        tags::INTEGER,
        Value::Integer(0),
    );
    assert_eq!(dispatch(&cj0_miss_p, &admin).code, status::ERROR_NOT_FOUND);
    let cj_no_id = with_printer_uri(
        ipp_req(op::CANCEL_JOB),
        "ipp://localhost:631/printers/laser1",
    );
    assert_eq!(dispatch(&cj_no_id, &admin).code, status::ERROR_NOT_FOUND);

    // `Purge-Jobs` with `purge-jobs=false` on all printers, and nonexistent printer:
    assert_eq!(
        dispatch(
            &with_printer_uri(ipp_req(op::PURGE_JOBS), "ipp://localhost:631/printers/no_q"),
            &admin
        )
        .code,
        status::ERROR_NOT_FOUND
    );
    let pj_no_hist = with_op_attr(
        with_printer_uri(ipp_req(op::PURGE_JOBS), "ipp://localhost:631/"),
        "purge-jobs",
        tags::BOOLEAN,
        Value::Boolean(false),
    );
    assert_eq!(dispatch(&pj_no_hist, &admin).code, status::OK);
    // Jobs still exist (history not purged) even though bob_jid was canceled!
    assert!(h.jobs.read().unwrap().get(bob_jid).is_some());
}

#[test]
fn jobs_ops_class_get_jobs_resubmit_guards_and_send_document_hold() {
    let h = Harness::new("jobs-extra");
    let alice = h.user_ctx("alice");
    let bob = h.user_ctx("bob");
    let admin = h.admin_ctx();

    // Create a class containing laser1, submit jobs for alice and bob, test Get-Jobs on class & nonexistent printer.
    let mk_class = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_CLASS),
            "ipp://localhost:631/classes/pool",
        ),
        "member-uris",
        tags::URI,
        Value::Uri("ipp://localhost:631/printers/laser1".into()),
    );
    assert_eq!(dispatch(&mk_class, &admin).code, status::OK);

    let mut alice_doc = h.user_ctx("alice");
    alice_doc.document = b"alice payload";
    let ajid = find_attr_int(
        &dispatch(
            &with_printer_uri(
                ipp_req(op::PRINT_JOB),
                "ipp://localhost:631/printers/laser1",
            ),
            &alice_doc,
        ),
        tags::JOB,
        "job-id",
    )
    .unwrap();
    // Set processing_at on ajid so `time-at-processing` emission is exercised!
    h.jobs.write().unwrap().get_mut(ajid).unwrap().processing_at = Some(1_700_000_000);

    let mut bob_doc = h.user_ctx("bob");
    bob_doc.document = b"bob payload";
    let _bjid = find_attr_int(
        &dispatch(
            &with_printer_uri(
                ipp_req(op::PRINT_JOB),
                "ipp://localhost:631/printers/laser1",
            ),
            &bob_doc,
        ),
        tags::JOB,
        "job-id",
    )
    .unwrap();

    // `Get-Jobs` on class with `my-jobs=true` filters to alice's job only & emits `time-at-processing`!
    let gj_class = with_op_attr(
        with_op_attr(
            with_printer_uri(ipp_req(op::GET_JOBS), "ipp://localhost:631/classes/pool"),
            "my-jobs",
            tags::BOOLEAN,
            Value::Boolean(true),
        ),
        "requested-attributes",
        tags::KEYWORD,
        Value::Keyword("all".into()),
    );
    let gj_resp = dispatch(&gj_class, &alice);
    assert_eq!(gj_resp.code, status::OK);
    assert_eq!(
        gj_resp.groups.iter().filter(|g| g.tag == tags::JOB).count(),
        1
    );
    assert!(gj_resp.find(tags::JOB, "time-at-processing").is_some());

    // `Get-Jobs` on nonexistent printer -> ERROR_NOT_FOUND; `Get-Job-Attributes` & `Cancel-Job` nonexistent job -> ERROR_NOT_FOUND.
    assert_eq!(
        dispatch(
            &with_printer_uri(ipp_req(op::GET_JOBS), "ipp://localhost:631/printers/no_q"),
            &alice
        )
        .code,
        status::ERROR_NOT_FOUND
    );
    assert_eq!(
        dispatch(
            &with_job_uri(
                ipp_req(op::GET_JOB_ATTRIBUTES),
                "ipp://localhost:631/jobs/9999"
            ),
            &admin
        )
        .code,
        status::ERROR_NOT_FOUND
    );
    assert_eq!(
        dispatch(
            &with_job_uri(ipp_req(op::CANCEL_JOB), "ipp://localhost:631/jobs/9999"),
            &admin
        )
        .code,
        status::ERROR_NOT_FOUND
    );

    // `Print-Job` bad job attr & `Create-Job` quota limit exceeded:
    let bad_pj = with_job_attr(
        with_printer_uri(
            ipp_req(op::PRINT_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        "sides",
        tags::KEYWORD,
        Value::Keyword("three-sided".into()),
    );
    assert_eq!(
        dispatch(&bad_pj, &alice_doc).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );
    let mut quota_ctx = h.user_ctx("alice");
    quota_ctx.max_jobs_per_printer = 1;
    assert_eq!(
        dispatch(
            &with_printer_uri(
                ipp_req(op::CREATE_JOB),
                "ipp://localhost:631/printers/laser1",
            ),
            &quota_ctx
        )
        .code,
        status::ERROR_TOO_MANY_JOBS
    );

    // `Send-Document` on a printer with `hold-new-jobs` sets PendingHeld, and quota breach fails cleanly!
    let cj_id = find_attr_int(
        &dispatch(
            &with_printer_uri(
                ipp_req(op::CREATE_JOB),
                "ipp://localhost:631/printers/laser1",
            ),
            &alice,
        ),
        tags::JOB,
        "job-id",
    )
    .unwrap();
    // Test Resubmit-Job on empty-files job `cj_id` -> ERROR_NOT_POSSIBLE!
    assert_eq!(
        dispatch(
            &with_job_uri(
                ipp_req(op::RESUBMIT_JOB),
                &format!("ipp://localhost:631/jobs/{cj_id}"),
            ),
            &alice
        )
        .code,
        status::ERROR_NOT_POSSIBLE
    );

    // Quota breach on Send-Document (`job-k-limit = 1` with 2048-byte doc):
    h.registry
        .write()
        .unwrap()
        .printers
        .get_mut("laser1")
        .unwrap()
        .k_limit = 1;
    let big_payload = vec![b'P'; 2048];
    let mut big_ctx = h.user_ctx("alice");
    big_ctx.document = &big_payload;
    let sd_big = with_op_attr(
        with_op_attr(
            with_printer_uri(
                ipp_req(op::SEND_DOCUMENT),
                "ipp://localhost:631/printers/laser1",
            ),
            "job-id",
            tags::INTEGER,
            Value::Integer(cj_id),
        ),
        "last-document",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    assert_eq!(dispatch(&sd_big, &big_ctx).code, status::ERROR_NOT_POSSIBLE);

    // Clear k_limit, enable `hold-new-jobs`, then Send-Document last=true -> PendingHeld with `hold-new-jobs`!
    h.registry
        .write()
        .unwrap()
        .printers
        .get_mut("laser1")
        .unwrap()
        .k_limit = 0;
    assert_eq!(
        dispatch(
            &with_printer_uri(
                ipp_req(op::HOLD_NEW_JOBS),
                "ipp://localhost:631/printers/laser1",
            ),
            &admin
        )
        .code,
        status::OK
    );
    let sd_hold = dispatch(&sd_big, &alice_doc);
    assert_eq!(sd_hold.code, status::OK);
    assert_eq!(
        find_attr_int(&sd_hold, tags::JOB, "job-state"),
        Some(JobState::PendingHeld as i32)
    );

    // `Resubmit-Job` while `hold-new-jobs` is active creates held clone; also test rejecting, AllowUser denied,
    // quota exceeded, and missing destination printer!
    let resub_hold = dispatch(
        &with_job_uri(
            ipp_req(op::RESUBMIT_JOB),
            &format!("ipp://localhost:631/jobs/{ajid}"),
        ),
        &alice,
    );
    assert_eq!(resub_hold.code, status::OK);
    assert_eq!(
        find_attr_int(&resub_hold, tags::JOB, "job-state"),
        Some(JobState::PendingHeld as i32)
    );

    // Quota exceeded on Resubmit-Job:
    assert_eq!(
        dispatch(
            &with_job_uri(
                ipp_req(op::RESUBMIT_JOB),
                &format!("ipp://localhost:631/jobs/{ajid}"),
            ),
            &quota_ctx
        )
        .code,
        status::ERROR_TOO_MANY_JOBS
    );

    // AllowUser denied on Resubmit-Job:
    {
        let mut reg = h.registry.write().unwrap();
        let p = reg.printers.get_mut("laser1").unwrap();
        p.users = vec!["bob".into()];
        p.deny_users = false;
    }
    assert_eq!(
        dispatch(
            &with_job_uri(
                ipp_req(op::RESUBMIT_JOB),
                &format!("ipp://localhost:631/jobs/{ajid}"),
            ),
            &alice
        )
        .code,
        status::ERROR_NOT_AUTHORIZED
    );

    // Rejecting printer on Resubmit-Job:
    {
        let mut reg = h.registry.write().unwrap();
        let p = reg.printers.get_mut("laser1").unwrap();
        p.users.clear();
        p.accepting = false;
    }
    assert_eq!(
        dispatch(
            &with_job_uri(
                ipp_req(op::RESUBMIT_JOB),
                &format!("ipp://localhost:631/jobs/{ajid}"),
            ),
            &alice
        )
        .code,
        status::ERROR_NOT_ACCEPTING_JOBS
    );

    // Deleted printer on Resubmit-Job -> ERROR_NOT_FOUND:
    h.registry.write().unwrap().remove("laser1");
    assert_eq!(
        dispatch(
            &with_job_uri(
                ipp_req(op::RESUBMIT_JOB),
                &format!("ipp://localhost:631/jobs/{ajid}"),
            ),
            &alice
        )
        .code,
        status::ERROR_NOT_FOUND
    );
    let _ = bob;
}

#[test]
fn concurrency_no_deadlock_with_writer_contending_on_registry_and_jobs() {
    let h = Harness::new("conc-lock");
    let mk_class = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_CLASS),
            "ipp://localhost:631/classes/pool",
        ),
        "member-uris",
        tags::URI,
        Value::Uri("ipp://localhost:631/printers/laser1".into()),
    );
    assert_eq!(dispatch(&mk_class, &h.admin_ctx()).code, status::OK);

    // Contend writers (`reg_write` + `jobs_write`) against readers hitting all
    // previously nested/re-entrant paths (missing dests, class Get-Jobs, Cancel-Job id=0).
    std::thread::scope(|s| {
        s.spawn(|| {
            let admin = h.admin_ctx();
            for i in 0..40 {
                let req = with_printer_attr(
                    with_printer_uri(
                        ipp_req(op::SET_PRINTER_ATTRIBUTES),
                        "ipp://localhost:631/printers/laser1",
                    ),
                    "printer-info",
                    tags::TEXT,
                    Value::Text(format!("Info {i}").into()),
                );
                assert_eq!(dispatch(&req, &admin).code, status::OK);
            }
        });
        s.spawn(|| {
            let alice = h.user_ctx("alice");
            let admin = h.admin_ctx();
            for _ in 0..40 {
                assert_eq!(
                    dispatch(
                        &with_printer_uri(
                            ipp_req(op::GET_PRINTER_ATTRIBUTES),
                            "ipp://localhost:631/printers/missing_q",
                        ),
                        &alice,
                    )
                    .code,
                    status::ERROR_NOT_FOUND
                );
                assert_eq!(
                    dispatch(
                        &with_printer_uri(
                            ipp_req(op::VALIDATE_JOB),
                            "ipp://localhost:631/printers/missing_q",
                        ),
                        &alice,
                    )
                    .code,
                    status::ERROR_NOT_FOUND
                );
                assert_eq!(
                    dispatch(
                        &with_printer_uri(
                            ipp_req(op::GET_JOBS),
                            "ipp://localhost:631/printers/missing_q",
                        ),
                        &alice,
                    )
                    .code,
                    status::ERROR_NOT_FOUND
                );
                assert_eq!(
                    dispatch(
                        &with_printer_uri(
                            ipp_req(op::GET_JOBS),
                            "ipp://localhost:631/classes/pool",
                        ),
                        &alice,
                    )
                    .code,
                    status::OK
                );
                let c0 = with_op_attr(
                    with_printer_uri(
                        ipp_req(op::CANCEL_JOB),
                        "ipp://localhost:631/printers/laser1",
                    ),
                    "job-id",
                    tags::INTEGER,
                    Value::Integer(0),
                );
                assert_eq!(dispatch(&c0, &admin).code, status::ERROR_NOT_POSSIBLE);
            }
        });
    });
}

#[test]
fn allow_deny_user_blocks_anonymous_spoofing_and_supports_all_none_clear() {
    let h = Harness::new("acl-spoof");
    let admin = h.admin_ctx();

    // 1. Configure `AllowUser alice`:
    {
        let mut reg = h.registry.write().unwrap();
        let p = reg.printers.get_mut("laser1").unwrap();
        p.users = vec!["alice".into()];
        p.deny_users = false;
    }

    // Anonymous caller spoofing `requesting-user-name = alice` MUST be challenged
    // with `need_auth = true` (`ERROR_NOT_AUTHENTICATED`) across Validate/Print/Create!
    let mut anon = h.ctx();
    anon.document = b"spoofed";
    for code in [op::VALIDATE_JOB, op::PRINT_JOB, op::CREATE_JOB] {
        let req = with_op_attr(
            with_printer_uri(ipp_req(code), "ipp://localhost:631/printers/laser1"),
            "requesting-user-name",
            tags::NAME,
            Value::Name("alice".into()),
        );
        let out = dispatch_outcome(&req, &anon);
        assert!(out.need_auth, "op {code:#x} must require auth on AllowUser");
        assert_eq!(out.auth_type, Some(cups_config::AuthType::Default));
        assert_eq!(out.response.code, status::ERROR_NOT_AUTHENTICATED);
    }

    // `CUPS-Get-Printers` MUST hide the `AllowUser alice` queue from anonymous spoofers!
    let gp_spoof = with_op_attr(
        ipp_req(op::CUPS_GET_PRINTERS),
        "requesting-user-name",
        tags::NAME,
        Value::Name("alice".into()),
    );
    let gp_resp = dispatch(&gp_spoof, &anon);
    assert_eq!(
        gp_resp
            .groups
            .iter()
            .filter(|g| g.tag == tags::PRINTER)
            .count(),
        0
    );

    // Authenticated `alice` succeeds; authenticated `bob` gets ERROR_NOT_AUTHORIZED (not need_auth).
    let val_req = with_printer_uri(
        ipp_req(op::VALIDATE_JOB),
        "ipp://localhost:631/printers/laser1",
    );
    assert_eq!(dispatch(&val_req, &h.user_ctx("alice")).code, status::OK);
    let bob_out = dispatch_outcome(&val_req, &h.user_ctx("bob"));
    assert!(!bob_out.need_auth);
    assert_eq!(bob_out.response.code, status::ERROR_NOT_AUTHORIZED);

    // 2. `AllowUser @ALL` permits anonymous caller cleanly:
    h.registry
        .write()
        .unwrap()
        .printers
        .get_mut("laser1")
        .unwrap()
        .users = vec!["@ALL".into()];
    assert_eq!(dispatch(&val_req, &anon).code, status::OK);

    // 3. `DenyUser mallory`: anonymous caller spoofing `alice` MUST fail closed with `need_auth`!
    {
        let mut reg = h.registry.write().unwrap();
        let p = reg.printers.get_mut("laser1").unwrap();
        p.users = vec!["mallory".into()];
        p.deny_users = true;
    }
    let spoof_val = with_op_attr(
        with_printer_uri(
            ipp_req(op::VALIDATE_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        "requesting-user-name",
        tags::NAME,
        Value::Name("alice".into()),
    );
    let deny_anon = dispatch_outcome(&spoof_val, &anon);
    assert!(deny_anon.need_auth);
    assert_eq!(deny_anon.response.code, status::ERROR_NOT_AUTHENTICATED);
    assert_eq!(dispatch(&val_req, &h.user_ctx("alice")).code, status::OK);
    assert_eq!(
        dispatch(&val_req, &h.user_ctx("mallory")).code,
        status::ERROR_NOT_AUTHORIZED
    );

    // 4. `requesting-user-name-allowed = ["all"]` and `requesting-user-name-denied = ["none"]`
    // clear `p.users` (matching CUPS)!
    let clear_allow = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
            "ipp://localhost:631/printers/laser1",
        ),
        "requesting-user-name-allowed",
        tags::NAME,
        Value::Name("all".into()),
    );
    assert_eq!(dispatch(&clear_allow, &admin).code, status::OK);
    assert_eq!(
        h.registry.read().unwrap().find("laser1").unwrap().users,
        Vec::<String>::new()
    );

    h.registry
        .write()
        .unwrap()
        .printers
        .get_mut("laser1")
        .unwrap()
        .users = vec!["mallory".into()];
    h.registry
        .write()
        .unwrap()
        .printers
        .get_mut("laser1")
        .unwrap()
        .deny_users = true;
    let clear_deny = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
            "ipp://localhost:631/printers/laser1",
        ),
        "requesting-user-name-denied",
        tags::NAME,
        Value::Name("none".into()),
    );
    assert_eq!(dispatch(&clear_deny, &admin).code, status::OK);
    {
        let reg = h.registry.read().unwrap();
        let p = reg.find("laser1").unwrap();
        assert_eq!(p.users, Vec::<String>::new());
        assert!(!p.deny_users);
    }
}

#[test]
fn ppd_cr_lines_whitespace_qualifiers_foomatic_variants_and_drv_abs_blocked() {
    // Classic bare-CR PPD line separator smuggling blocked:
    assert!(validate_ppd_bytes(b"*PPD-Adobe: \"4.3\"\r*cupsFilter: \"*/* 0 /bin/sh\"\n").is_err());
    assert!(validate_ppd_bytes(b"*PPD-Adobe: \"4.3\"\r*FoomaticRIPCommandLine: \"id\"\n").is_err());

    // Whitespace-qualified directives & Foomatic variants blocked:
    assert!(
        validate_ppd_bytes(b"*PPD-Adobe: \"4.3\"\n*cupsFilter foo: \"*/* 0 /bin/sh\"\n").is_err()
    );
    assert!(
        validate_ppd_bytes(b"*PPD-Adobe: \"4.3\"\n*FoomaticRIPCommandLine foo: \"id\"\n").is_err()
    );
    assert!(
        validate_ppd_bytes(b"*PPD-Adobe: \"4.3\"\n*FoomaticRIPCommandLinePDF: \"id\"\n").is_err()
    );
    assert!(validate_ppd_bytes(
        b"*PPD-Adobe: \"4.3\"\n*FoomaticRIPOptionSetting foo=bar: \"id\"\n"
    )
    .is_err());

    // `drv:////...` absolute-path escape & empty `drv:///` rejected; valid relative accepted:
    assert!(validate_driverd_ppd_name("drv:////etc/foo.drv/model").is_err());
    assert!(validate_driverd_ppd_name("DRV:////etc/passwd").is_err());
    assert!(validate_driverd_ppd_name("drv:///").is_err());
    assert!(validate_driverd_ppd_name("drv:///sample.drv/generic.ppd").is_ok());
}

#[test]
fn uri_resource_colon_in_path_does_not_trigger_all_printers_ops() {
    let h = Harness::new("colon-uri");
    let admin = h.admin_ctx();
    let mut alice_doc = h.user_ctx("alice");
    alice_doc.document = b"keep me safe";

    let jid = find_attr_int(
        &dispatch(
            &with_printer_uri(
                ipp_req(op::PRINT_JOB),
                "ipp://localhost:631/printers/laser1",
            ),
            &alice_doc,
        ),
        tags::JOB,
        "job-id",
    )
    .unwrap();

    // URIs with `:123/` in the path MUST NOT be misclassified as all-printers URIs!
    for tricky_uri in [
        "ipp://localhost:631/printers/hp:123/",
        "ipp://localhost:631/printers/hp:123/printers",
        "IPP://localhost:631/printers/hp:999/",
    ] {
        for code in [
            op::CANCEL_JOBS,
            op::PURGE_JOBS,
            op::CANCEL_MY_JOBS,
            op::GET_JOBS,
        ] {
            let resp = dispatch(&with_printer_uri(ipp_req(code), tricky_uri), &admin);
            assert_eq!(
                resp.code,
                status::ERROR_NOT_FOUND,
                "op {code:#x} on {tricky_uri} must NOT match all_printers"
            );
        }
    }
    // Alice's job on `laser1` must still be Pending and untouched!
    assert_eq!(
        h.jobs.read().unwrap().get(jid).unwrap().state,
        JobState::Pending
    );

    // IPv6 server root URI `ipp://[::1]:631/` DOES match all_printers:
    let gj_v6 = dispatch(
        &with_printer_uri(ipp_req(op::GET_JOBS), "ipp://[::1]:631/"),
        &admin,
    );
    assert_eq!(gj_v6.code, status::OK);
    assert_eq!(
        gj_v6.groups.iter().filter(|g| g.tag == tags::JOB).count(),
        1
    );
}

#[test]
fn review_finding5_collisions_quotas_hold_job_uri_subs_policies_and_states() {
    let mut h = Harness::new("finding5");

    // Add a TLS-only policy and a second queue `secure_q` using it.
    let mut tls_pol = Policy {
        name: "strict-tls".into(),
        ops: Vec::new(),
        job_access: vec!["@OWNER".into(), "@SYSTEM".into()],
        job_values: vec!["default".into()],
        sub_access: vec!["@OWNER".into(), "@SYSTEM".into()],
        sub_values: vec!["default".into()],
    };
    let mut tls_loc = Location::new("<policy>");
    tls_loc.order = OrderType::Allow;
    tls_loc.encryption = cups_config::Encryption::Required;
    tls_pol.ops.push(PolicyOp {
        op: ipp_codec::ops::op::ANY_OPERATION,
        loc: tls_loc,
    });
    h.cfg.cupsd.policies.push(tls_pol);
    {
        let mut p = Printer::new("secure_q", "ipp://secure.local/ipp");
        p.op_policy = Some("strict-tls".into());
        p.shared = true;
        h.registry.write().unwrap().add(p);
    }

    let admin = h.admin_ctx();
    let alice = h.user_ctx("alice");

    // 5a-1: `CUPS-Create-Local-Printer` MUST NOT overwrite existing class or printer or write PPD.
    let mk_class = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_CLASS),
            "ipp://localhost:631/classes/pool",
        ),
        "member-uris",
        tags::URI,
        Value::Uri("ipp://localhost:631/printers/laser1".into()),
    );
    assert_eq!(dispatch(&mk_class, &admin).code, status::OK);

    let mut admin_ppd = h.admin_ctx();
    let sample_ppd = valid_sample_ppd();
    admin_ppd.document = sample_ppd.as_bytes();
    for existing_name in ["pool", "laser1"] {
        let collide = with_op_attr(
            ipp_req(op::CUPS_CREATE_LOCAL_PRINTER),
            "printer-name",
            tags::NAME,
            Value::Name(existing_name.into()),
        );
        assert_eq!(
            dispatch(&collide, &admin_ppd).code,
            status::ERROR_NOT_POSSIBLE
        );
    }
    assert!(h.registry.read().unwrap().find("pool").unwrap().is_class());
    assert!(!h.server_root.join("ppd/pool.ppd").exists());

    // 5a-2: `CUPS-Add-Modify-Printer` with invalid `printer-state = 99` fails BEFORE writing PPD!
    let bad_state_ppd = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
            "ipp://localhost:631/printers/fresh_bad",
        ),
        "printer-state",
        tags::ENUM,
        Value::Enum(99),
    );
    assert_eq!(
        dispatch(&bad_state_ppd, &admin_ppd).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );
    assert!(!h.server_root.join("ppd/fresh_bad.ppd").exists());

    // 5b: `Create-Job` + `Send-Document` at `job-page-limit = 1` succeeds (no double-count!),
    // sets reason `"none"` (not `"job-incoming"`), and rejects extra Send-Document once closed/processing!
    h.registry
        .write()
        .unwrap()
        .printers
        .get_mut("laser1")
        .unwrap()
        .page_limit = 1;
    let cj_id = find_attr_int(
        &dispatch(
            &with_printer_uri(
                ipp_req(op::CREATE_JOB),
                "ipp://localhost:631/printers/laser1",
            ),
            &alice,
        ),
        tags::JOB,
        "job-id",
    )
    .unwrap();

    // 5e-0: `Close-Job` / `Release-Job` on 0-file Create-Job MUST return ERROR_NOT_POSSIBLE!
    for code in [op::CLOSE_JOB, op::RELEASE_JOB] {
        assert_eq!(
            dispatch(
                &with_job_uri(ipp_req(code), &format!("ipp://localhost:631/jobs/{cj_id}")),
                &alice
            )
            .code,
            status::ERROR_NOT_POSSIBLE
        );
    }

    let mut alice_doc = h.user_ctx("alice");
    alice_doc.document = b"doc body";
    let sd_last = with_op_attr(
        with_op_attr(
            with_job_uri(
                ipp_req(op::SEND_DOCUMENT),
                &format!("ipp://localhost:631/jobs/{cj_id}"),
            ),
            "last-document",
            tags::BOOLEAN,
            Value::Boolean(true),
        ),
        "requested-attributes",
        tags::KEYWORD,
        Value::Keyword("all".into()),
    );
    let sd_resp = dispatch(&sd_last, &alice_doc);
    assert_eq!(sd_resp.code, status::OK);
    assert_eq!(
        find_attr_text(&sd_resp, tags::JOB, "job-state-reasons").as_deref(),
        Some("none")
    );
    // Sending another document to the already-closed job MUST return ERROR_NOT_POSSIBLE!
    assert_eq!(
        dispatch(&sd_last, &alice_doc).code,
        status::ERROR_NOT_POSSIBLE
    );
    h.registry
        .write()
        .unwrap()
        .printers
        .get_mut("laser1")
        .unwrap()
        .page_limit = 0;

    // 5c: `Release-Held-New-Jobs` releases ONLY `hold-new-jobs`, NOT user-held `job-hold-until`!
    assert_eq!(
        dispatch(
            &with_printer_uri(
                ipp_req(op::HOLD_NEW_JOBS),
                "ipp://localhost:631/printers/laser1",
            ),
            &admin,
        )
        .code,
        status::OK
    );
    let held_by_queue = find_attr_int(
        &dispatch(
            &with_printer_uri(
                ipp_req(op::PRINT_JOB),
                "ipp://localhost:631/printers/laser1",
            ),
            &alice_doc,
        ),
        tags::JOB,
        "job-id",
    )
    .unwrap();
    let held_by_user = find_attr_int(
        &dispatch(
            &with_job_attr(
                with_printer_uri(
                    ipp_req(op::PRINT_JOB),
                    "ipp://localhost:631/printers/laser1",
                ),
                "job-hold-until",
                tags::KEYWORD,
                Value::Keyword("indefinite".into()),
            ),
            &alice_doc,
        ),
        tags::JOB,
        "job-id",
    )
    .unwrap();
    assert_eq!(
        dispatch(
            &with_printer_uri(
                ipp_req(op::RELEASE_HELD_NEW_JOBS),
                "ipp://localhost:631/printers/laser1",
            ),
            &admin,
        )
        .code,
        status::OK
    );
    assert_eq!(
        h.jobs.read().unwrap().get(held_by_queue).unwrap().state,
        JobState::Pending
    );
    assert_eq!(
        h.jobs.read().unwrap().get(held_by_user).unwrap().state,
        JobState::PendingHeld
    );

    // 5d: `Create-Job-Subscriptions` using `job-uri` (no `job-id` attr) resolves job accurately!
    let jsub_uri = with_sub_group(
        with_job_uri(
            ipp_req(op::CREATE_JOB_SUBSCRIPTIONS),
            &format!("ipp://localhost:631/jobs/{cj_id}"),
        ),
        vec![Attribute::new(
            "notify-pull-method",
            tags::KEYWORD,
            vec![Value::Keyword("ippget".into())],
        )],
    );
    let jsub_resp = dispatch(&jsub_uri, &alice);
    assert_eq!(jsub_resp.code, status::OK);
    let sid = find_attr_int(&jsub_resp, tags::SUBSCRIPTION, "notify-subscription-id").unwrap();
    let sub_attr_resp = dispatch(
        &with_op_attr(
            ipp_req(op::GET_SUBSCRIPTION_ATTRIBUTES),
            "notify-subscription-id",
            tags::INTEGER,
            Value::Integer(sid),
        ),
        &alice,
    );
    assert_eq!(
        find_attr_int(&sub_attr_resp, tags::SUBSCRIPTION, "notify-job-id"),
        Some(cj_id)
    );
    assert!(
        find_attr_text(&sub_attr_resp, tags::SUBSCRIPTION, "notify-printer-uri")
            .unwrap()
            .ends_with("/printers/laser1")
    );
    // Omitting both `job-id` and `job-uri` on `Create-Job-Subscriptions` -> ERROR_BAD_REQUEST!
    let jsub_missing = with_sub_group(
        with_printer_uri(
            ipp_req(op::CREATE_JOB_SUBSCRIPTIONS),
            "ipp://localhost:631/printers/laser1",
        ),
        vec![Attribute::new(
            "notify-pull-method",
            tags::KEYWORD,
            vec![Value::Keyword("ippget".into())],
        )],
    );
    assert_eq!(
        dispatch(&jsub_missing, &admin).code,
        status::ERROR_BAD_REQUEST
    );

    // 5e-1: `Get-Jobs /` (`all_printers`) enforces per-printer `op_policy` (`strict-tls`)!
    let mut alice_tls_doc = h.user_ctx("alice");
    alice_tls_doc.is_encrypted = true;
    alice_tls_doc.document = b"secret tls job";
    let sec_jid = find_attr_int(
        &dispatch(
            &with_printer_uri(
                ipp_req(op::PRINT_JOB),
                "ipps://localhost:631/printers/secure_q",
            ),
            &alice_tls_doc,
        ),
        tags::JOB,
        "job-id",
    )
    .unwrap();

    let gj_all_plain = dispatch(
        &with_printer_uri(ipp_req(op::GET_JOBS), "ipp://localhost:631/"),
        &alice,
    );
    let plain_ids: Vec<i32> = gj_all_plain
        .groups
        .iter()
        .filter(|g| g.tag == tags::JOB)
        .filter_map(|g| g.find("job-id").and_then(Attribute::int))
        .collect();
    assert!(!plain_ids.contains(&sec_jid));

    let gj_all_tls = dispatch(
        &with_printer_uri(ipp_req(op::GET_JOBS), "ipps://localhost:631/"),
        &alice_tls_doc,
    );
    let tls_ids: Vec<i32> = gj_all_tls
        .groups
        .iter()
        .filter(|g| g.tag == tags::JOB)
        .filter_map(|g| g.find("job-id").and_then(Attribute::int))
        .collect();
    assert!(tls_ids.contains(&sec_jid));

    // 5e-2: `CUPS-Move-Job` enforces target `op_policy` (blocks unencrypted move into `secure_q`)
    // AND refuses to move actively `Processing` jobs (both single and Move-All-Jobs)!
    let mv_to_tls = with_op_attr(
        with_job_uri(
            ipp_req(op::CUPS_MOVE_JOB),
            &format!("ipp://localhost:631/jobs/{cj_id}"),
        ),
        "job-printer-uri",
        tags::URI,
        Value::Uri("ipp://localhost:631/printers/secure_q".into()),
    );
    let mv_out = dispatch_outcome(&mv_to_tls, &alice);
    assert!(mv_out.upgrade_required);
    assert_eq!(mv_out.response.code, status::ERROR_CUPS_UPGRADE_REQUIRED);

    // Mark `cj_id` as `Processing`: single move & Release-Job / Close-Job MUST fail with ERROR_NOT_POSSIBLE!
    h.jobs.write().unwrap().get_mut(cj_id).unwrap().state = JobState::Processing;
    let mut admin_tls = h.admin_ctx();
    admin_tls.is_encrypted = true;
    assert_eq!(
        dispatch(&mv_to_tls, &admin_tls).code,
        status::ERROR_NOT_POSSIBLE
    );
    for code in [op::RELEASE_JOB, op::RESUME_JOB, op::CLOSE_JOB] {
        assert_eq!(
            dispatch(
                &with_job_uri(ipp_req(code), &format!("ipp://localhost:631/jobs/{cj_id}")),
                &alice
            )
            .code,
            status::ERROR_NOT_POSSIBLE
        );
    }

    // `Close-Job` on an open `Create-Job` with 1 doc and explicit `job-hold-until=indefinite`
    // MUST preserve `PendingHeld`!
    let cj_held_id = find_attr_int(
        &dispatch(
            &with_job_attr(
                with_printer_uri(
                    ipp_req(op::CREATE_JOB),
                    "ipp://localhost:631/printers/laser1",
                ),
                "job-hold-until",
                tags::KEYWORD,
                Value::Keyword("indefinite".into()),
            ),
            &alice,
        ),
        tags::JOB,
        "job-id",
    )
    .unwrap();
    let sd_part = with_op_attr(
        with_job_uri(
            ipp_req(op::SEND_DOCUMENT),
            &format!("ipp://localhost:631/jobs/{cj_held_id}"),
        ),
        "last-document",
        tags::BOOLEAN,
        Value::Boolean(false),
    );
    assert_eq!(dispatch(&sd_part, &alice_doc).code, status::OK);
    let close_resp = dispatch(
        &with_job_uri(
            ipp_req(op::CLOSE_JOB),
            &format!("ipp://localhost:631/jobs/{cj_held_id}"),
        ),
        &alice,
    );
    assert_eq!(close_resp.code, status::OK);
    assert_eq!(
        find_attr_int(&close_resp, tags::JOB, "job-state"),
        Some(JobState::PendingHeld as i32)
    );

    // Move-All-Jobs from `laser1` to `secure_q` (over TLS): moves pending/held jobs, leaves Processing `cj_id` on `laser1`!
    let mv_all = with_op_attr(
        with_printer_uri(
            ipp_req(op::CUPS_MOVE_JOB),
            "ipps://localhost:631/printers/laser1",
        ),
        "job-printer-uri",
        tags::URI,
        Value::Uri("ipps://localhost:631/printers/secure_q".into()),
    );
    assert_eq!(dispatch(&mv_all, &admin_tls).code, status::OK);
    assert_eq!(h.jobs.read().unwrap().get(cj_id).unwrap().dest, "laser1");
    assert_eq!(
        h.jobs.read().unwrap().get(held_by_queue).unwrap().dest,
        "secure_q"
    );
}
