#![allow(clippy::too_many_lines)]

mod common;

use common::{
    crc32_test, find_attr_int, gzip_stored, ipp_req, valid_sample_ppd, with_job_uri, with_op_attr,
    with_printer_attr, with_printer_uri, write_file, Harness, HookRecorder,
};
use ipp_codec::{ops::op, ops::status, tags, Value};
use ops::{
    atomic_write_ppd, decompress_gzip, decompress_gzip_with_limits, dispatch,
    parse_ppd_capabilities, patch_ppd_cups_attrs, resolve_safe_file_ppd, validate_driverd_ppd_name,
    validate_ppd_bytes, GzipError, PpdLookupError,
};
use std::sync::Arc;

#[test]
fn printer_name_device_uri_and_file_device_validation() {
    let mut h = Harness::new("name-uri-filedev");
    assert!(h.cfg.files.file_device.is_none());

    // 1. Invalid printer names rejected.
    for bad in ["../evil", "a/b", "bad name", "bad?q", "bad#f", "."] {
        let req = with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
            &format!("ipp://localhost:631/printers/{bad}"),
        );
        assert_eq!(
            dispatch(&req, &h.admin_ctx()).code,
            status::ERROR_BAD_REQUEST,
            "name {bad:?} must be rejected"
        );
    }

    // 2. FileDevice No rejects file:///etc/passwd AND file:///dev/null!
    for file_uri in ["file:///etc/passwd", "file:///dev/null", "file:/tmp/x"] {
        let req = with_printer_attr(
            with_printer_uri(
                ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
                "ipp://localhost:631/printers/pfile",
            ),
            "device-uri",
            tags::URI,
            Value::Uri(file_uri.into()),
        );
        assert_eq!(
            dispatch(&req, &h.admin_ctx()).code,
            status::ERROR_NOT_POSSIBLE,
            "file URI {file_uri} must fail when FileDevice No"
        );
    }

    // 3. Invalid non-file device-uri rejected with BAD_REQUEST.
    for bad_uri in [
        "no-scheme",
        "ipp://",
        "ipp://host/../../etc/passwd",
        "ipp://h t/p",
    ] {
        let req = with_printer_attr(
            with_printer_uri(
                ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
                "ipp://localhost:631/printers/pbad",
            ),
            "device-uri",
            tags::URI,
            Value::Uri(bad_uri.into()),
        );
        assert_eq!(
            dispatch(&req, &h.admin_ctx()).code,
            status::ERROR_BAD_REQUEST,
            "bad device-uri {bad_uri:?} must be rejected"
        );
    }

    // 4. Enable FileDevice -> valid file:///tmp/out succeeds!
    h.cfg.files.file_device = Some("^/tmp/".into());
    let ok_req = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
            "ipp://localhost:631/printers/pfile",
        ),
        "device-uri",
        tags::URI,
        Value::Uri("file:///tmp/out".into()),
    );
    assert_eq!(dispatch(&ok_req, &h.admin_ctx()).code, status::OK);

    // Set-Printer-Attributes also enforces device-uri validation!
    h.cfg.files.file_device = None;
    let set_bad = with_printer_attr(
        with_printer_uri(
            ipp_req(op::SET_PRINTER_ATTRIBUTES),
            "ipp://localhost:631/printers/pfile",
        ),
        "device-uri",
        tags::URI,
        Value::Uri("file:///etc/shadow".into()),
    );
    assert_eq!(
        dispatch(&set_bad, &h.admin_ctx()).code,
        status::ERROR_NOT_POSSIBLE
    );
}

#[test]
fn ppd_upload_validation_and_cups_attr_injection_blocked() {
    let h = Harness::new("ppd-hardening");

    // Reject empty, NUL, missing header, FoomaticRIPCommandLine, traversal & shell filters.
    assert!(validate_ppd_bytes(b"").is_err());
    assert!(validate_ppd_bytes(b"*PPD-Adobe: \"4.3\"\0").is_err());
    assert!(validate_ppd_bytes(b"not a ppd file\n").is_err());
    assert!(
        validate_ppd_bytes(b"*PPD-Adobe: \"4.3\"\n*FoomaticRIPCommandLine: \"cat; id\"\n").is_err()
    );
    assert!(validate_ppd_bytes(
        b"*PPD-Adobe: \"4.3\"\n*cupsFilter: \"application/pdf 0 ../../../bin/sh\"\n"
    )
    .is_err());
    assert!(validate_ppd_bytes(
        b"*PPD-Adobe: \"4.3\"\n*cupsFilter2: \"application/pdf application/pdf 0 /bin/sh\"\n"
    )
    .is_err());
    assert!(validate_ppd_bytes(
        b"*PPD-Adobe: \"4.3\"\n*cupsFilter: \"application/pdf 0 filt;id\"\n"
    )
    .is_err());
    assert!(validate_ppd_bytes(b"*PPD-Adobe: \"4.3\"\n*cupsFilter: \"bad\"\n").is_err());
    assert!(validate_ppd_bytes(
        b"*PPD-Adobe: \"4.3\"\n*cupsPreFilter: \"application/pdf 0 bad/path\"\n"
    )
    .is_err());

    // Valid PPD upload succeeds via CUPS-Add-Modify-Printer.
    let ppd = valid_sample_ppd();
    assert!(validate_ppd_bytes(ppd.as_bytes()).is_ok());

    let req = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
            "ipp://localhost:631/printers/ppdq",
        ),
        "device-uri",
        tags::URI,
        Value::Uri("ipp://192.0.2.10:631/ipp/print".into()),
    );
    let mut admin = h.admin_ctx();
    admin.document = ppd.as_bytes();
    assert_eq!(dispatch(&req, &admin).code, status::OK);

    // Reject malicious PPD upload through IPP.
    admin.document = b"*PPD-Adobe: \"4.3\"\n*cupsFilter: \"*/* 0 /bin/sh\"\n";
    assert_eq!(dispatch(&req, &admin).code, status::ERROR_BAD_REQUEST);

    // Reject patching cupsFilter or injecting newlines via cups* attributes.
    let admin_no_doc = h.admin_ctx();
    let bad_patch_filter = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
            "ipp://localhost:631/printers/ppdq",
        ),
        "cupsFilter",
        tags::TEXT,
        Value::Text("application/pdf 0 /bin/sh".into()),
    );
    assert_eq!(
        dispatch(&bad_patch_filter, &admin_no_doc).code,
        status::ERROR_BAD_REQUEST
    );

    let bad_patch_nl = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
            "ipp://localhost:631/printers/ppdq",
        ),
        "cupsManualCopies",
        tags::TEXT,
        Value::Text("True\n*cupsFilter: \"*/* 0 /bin/sh\"".into()),
    );
    assert_eq!(
        dispatch(&bad_patch_nl, &admin_no_doc).code,
        status::ERROR_BAD_REQUEST
    );

    // Valid cups* patch succeeds and atomically updates the PPD file!
    let good_patch = with_printer_attr(
        with_printer_attr(
            with_printer_uri(
                ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
                "ipp://localhost:631/printers/ppdq",
            ),
            "cupsManualCopies",
            tags::BOOLEAN,
            Value::Boolean(true),
        ),
        "cupsModelNumber",
        tags::INTEGER,
        Value::Integer(7),
    );
    assert_eq!(dispatch(&good_patch, &admin_no_doc).code, status::OK);
    let saved = std::fs::read_to_string(h.server_root.join("ppd/ppdq.ppd")).unwrap();
    assert!(saved.contains("*cupsManualCopies: True"));
    assert!(saved.contains("*cupsModelNumber: 7"));

    // Test patch_ppd_cups_attrs directly for append without trailing newline & invalid key.
    let patched =
        patch_ppd_cups_attrs("*PPD-Adobe: \"4.3\"", &[("cupsFoo".into(), "false".into())]).unwrap();
    assert!(patched.contains("*cupsFoo: False\n"));
    assert!(
        patch_ppd_cups_attrs("*PPD-Adobe: \"4.3\"\n", &[("bad:key".into(), "1".into())]).is_err()
    );

    // Symlink target refused by atomic_write_ppd!
    #[cfg(unix)]
    {
        let victim = h.tmp.path.join("victim.txt");
        write_file(&victim, b"untouched");
        let link = h.server_root.join("ppd/symq.ppd");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(atomic_write_ppd(&h.server_root, "symq", ppd.as_bytes()).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
    }

    // Parse capabilities checks.
    let caps = parse_ppd_capabilities(&ppd);
    assert_eq!(caps.color_device, Some(true));
    assert_eq!(caps.default_media.as_deref(), Some("iso_a4_210x297mm"));
    assert_eq!(caps.duplex_supported, Some(true));
    assert_eq!(caps.default_duplex.as_deref(), Some("two-sided-long-edge"));
    assert_eq!(caps.default_resolution, Some((1200, 1200)));
    assert!(caps.resolutions.contains(&(600, 600)));
    assert!(caps
        .filter_formats
        .iter()
        .any(|f| f == "application/vnd.yindle-test"));
}

#[test]
fn cups_get_ppd_containment_blocks_arbitrary_file_read() {
    let h = Harness::new("get-ppd-safe");
    let ppd = valid_sample_ppd();
    write_file(&h.server_root.join("ppd/laser1.ppd"), ppd.as_bytes());
    write_file(&h.data_dir.join("ppd/shared-model.ppd"), ppd.as_bytes());
    let secret = h.tmp.path.join("secret.txt");
    write_file(&secret, b"SUPER_SECRET");

    let mut ctx = h.ctx();
    let hooks = HookRecorder::attach(&mut ctx);

    // 1. Absolute path outside allowed PPD roots -> FORBIDDEN!
    for evil in [
        format!("file:{}", secret.display()),
        format!("file://{}", secret.display()),
        "file:/etc/passwd".into(),
        "file:../../secret.txt".into(),
        "file:..\\secret.txt".into(),
        "../../etc/passwd".into(),
        "/etc/passwd".into(),
    ] {
        let req = with_op_attr(
            ipp_req(op::CUPS_GET_PPD),
            "ppd-name",
            tags::NAME,
            Value::Name(evil.as_str().into()),
        );
        let resp = dispatch(&req, &ctx);
        assert_eq!(
            resp.code,
            status::ERROR_FORBIDDEN,
            "ppd-name {evil:?} MUST be FORBIDDEN"
        );
        assert!(
            resp.document.is_empty(),
            "forbidden PPD lookup must not leak document bytes"
        );
    }
    assert!(!hooks.audits.lock().unwrap().is_empty());

    // 2. Symlink inside ppd/ pointing outside allowed root -> FORBIDDEN!
    #[cfg(unix)]
    {
        let escape_link = h.server_root.join("ppd/escape.ppd");
        std::os::unix::fs::symlink(&secret, &escape_link).unwrap();
        let req = with_op_attr(
            ipp_req(op::CUPS_GET_PPD),
            "ppd-name",
            tags::NAME,
            Value::Name("file:escape".into()),
        );
        assert_eq!(dispatch(&req, &ctx).code, status::ERROR_FORBIDDEN);
    }

    // 3. Legitimate contained `file:laser1` and `file:shared-model.ppd` succeed!
    let ok1 = with_op_attr(
        ipp_req(op::CUPS_GET_PPD),
        "ppd-name",
        tags::NAME,
        Value::Name("file:laser1".into()),
    );
    let r1 = dispatch(&ok1, &ctx);
    assert_eq!(r1.code, status::OK);
    assert_eq!(r1.document, ppd.as_bytes());

    let ok2 = with_op_attr(
        ipp_req(op::CUPS_GET_PPD),
        "ppd-name",
        tags::NAME,
        Value::Name("file:shared-model.ppd".into()),
    );
    let r2 = dispatch(&ok2, &ctx);
    assert_eq!(r2.code, status::OK);
    assert_eq!(r2.document, ppd.as_bytes());

    // 4. Absolute path *inside* allowed root succeeds; nonexistent inside root -> NotFound.
    let abs_ok = format!("file:{}", h.server_root.join("ppd/laser1.ppd").display());
    assert!(resolve_safe_file_ppd(&abs_ok, &ctx.ppd_roots()).is_ok());
    let abs_missing = format!("file:{}", h.server_root.join("ppd/nope.ppd").display());
    assert_eq!(
        resolve_safe_file_ppd(&abs_missing, &ctx.ppd_roots()),
        Err(PpdLookupError::NotFound)
    );

    // 5. Via printer-uri resolves queue PPD cleanly.
    let by_uri = with_printer_uri(
        ipp_req(op::CUPS_GET_PPD),
        "ipp://localhost:631/printers/laser1",
    );
    let r3 = dispatch(&by_uri, &ctx);
    assert_eq!(r3.code, status::OK);
    assert_eq!(r3.document, ppd.as_bytes());

    // 6. Missing ppd-name & printer-uri -> NOT_FOUND.
    assert_eq!(
        dispatch(&ipp_req(op::CUPS_GET_PPD), &ctx).code,
        status::ERROR_NOT_FOUND
    );

    // Validate driverd ppd names directly.
    assert!(validate_driverd_ppd_name("everywhere").is_ok());
    assert!(validate_driverd_ppd_name("drv:///sample.drv/generic.ppd").is_ok());
    assert!(validate_driverd_ppd_name("drv:///../etc/passwd").is_err());
    assert!(validate_driverd_ppd_name("").is_err());
}

#[test]
fn print_uri_and_send_uri_reject_file_scheme_and_support_safe_fetcher() {
    let h = Harness::new("uri-hardening");
    let secret = h.tmp.path.join("secret.doc");
    write_file(&secret, b"TOP_SECRET");

    let mut ctx = h.user_ctx("alice");
    let hooks = HookRecorder::attach(&mut ctx);

    // 1. Print-URI with file:// -> FORBIDDEN (never reads local file!).
    for uri in [
        format!("file://{}", secret.display()),
        format!("file://localhost{}", secret.display()),
        "FILE:///etc/passwd".into(),
    ] {
        let req = with_op_attr(
            with_printer_uri(
                ipp_req(op::PRINT_URI),
                "ipp://localhost:631/printers/laser1",
            ),
            "document-uri",
            tags::URI,
            Value::Uri(uri.as_str().into()),
        );
        assert_eq!(dispatch(&req, &ctx).code, status::ERROR_FORBIDDEN);
    }
    assert!(!hooks.audits.lock().unwrap().is_empty());

    // 2. Print-URI without fetcher hook -> ERROR_URI_SCHEME; missing attr -> BAD_REQUEST; malformed -> BAD_REQUEST.
    let http_req = with_op_attr(
        with_printer_uri(
            ipp_req(op::PRINT_URI),
            "ipp://localhost:631/printers/laser1",
        ),
        "document-uri",
        tags::URI,
        Value::Uri("https://files.example/report.pdf".into()),
    );
    assert_eq!(dispatch(&http_req, &ctx).code, status::ERROR_URI_SCHEME);

    let gopher_req = with_op_attr(
        with_printer_uri(
            ipp_req(op::PRINT_URI),
            "ipp://localhost:631/printers/laser1",
        ),
        "document-uri",
        tags::URI,
        Value::Uri("gopher://files.example/1".into()),
    );
    assert_eq!(dispatch(&gopher_req, &ctx).code, status::ERROR_URI_SCHEME);

    let bad_req = with_op_attr(
        with_printer_uri(
            ipp_req(op::PRINT_URI),
            "ipp://localhost:631/printers/laser1",
        ),
        "document-uri",
        tags::URI,
        Value::Uri("not-a-uri".into()),
    );
    assert_eq!(dispatch(&bad_req, &ctx).code, status::ERROR_BAD_REQUEST);
    assert_eq!(
        dispatch(
            &with_printer_uri(
                ipp_req(op::PRINT_URI),
                "ipp://localhost:631/printers/laser1"
            ),
            &ctx
        )
        .code,
        status::ERROR_BAD_REQUEST
    );

    // 3. With a safe on_fetch_uri hook, Print-URI + Send-URI succeed!
    ctx.on_fetch_uri = Some(Arc::new(|uri| {
        if uri.contains("fail") {
            Err("upstream 404".into())
        } else {
            Ok(b"%PDF-1.7 fetched".to_vec())
        }
    }));
    let ok_resp = dispatch(&http_req, &ctx);
    assert_eq!(ok_resp.code, status::OK);
    let jid = find_attr_int(&ok_resp, tags::JOB, "job-id").unwrap();
    let spooled = std::fs::read(job::Job::data_path(&h.request_root, jid, 1)).unwrap();
    assert_eq!(spooled, b"%PDF-1.7 fetched");

    // Fetch error -> ERROR_DOCUMENT_ACCESS.
    let fail_req = with_op_attr(
        with_printer_uri(
            ipp_req(op::PRINT_URI),
            "ipp://localhost:631/printers/laser1",
        ),
        "document-uri",
        tags::URI,
        Value::Uri("https://files.example/fail.pdf".into()),
    );
    assert_eq!(
        dispatch(&fail_req, &ctx).code,
        status::ERROR_DOCUMENT_ACCESS
    );

    // 4. Create-Job + Send-URI: file:// still FORBIDDEN even with fetcher configured!
    let cj = dispatch(
        &with_printer_uri(
            ipp_req(op::CREATE_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        &ctx,
    );
    let cjid = find_attr_int(&cj, tags::JOB, "job-id").unwrap();

    let send_file = with_op_attr(
        with_op_attr(
            with_job_uri(
                ipp_req(op::SEND_URI),
                &format!("ipp://localhost:631/jobs/{cjid}"),
            ),
            "document-uri",
            tags::URI,
            Value::Uri(format!("file://{}", secret.display()).into()),
        ),
        "last-document",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    assert_eq!(dispatch(&send_file, &ctx).code, status::ERROR_FORBIDDEN);

    let send_http = with_op_attr(
        with_op_attr(
            with_job_uri(
                ipp_req(op::SEND_URI),
                &format!("ipp://localhost:631/jobs/{cjid}"),
            ),
            "document-uri",
            tags::URI,
            Value::Uri("https://files.example/part2.pdf".into()),
        ),
        "last-document",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    let su_resp = dispatch(&send_http, &ctx);
    assert_eq!(su_resp.code, status::OK);
    assert_eq!(find_attr_int(&su_resp, tags::JOB, "job-state"), Some(3)); // Pending
}

#[test]
fn gzip_decompression_huffman_headers_and_zip_bomb_guards() {
    // 1. Stored block round-trip.
    let payload = b"Yindle IPP compression=gzip stored block test!";
    let gz = gzip_stored(payload);
    assert_eq!(decompress_gzip(&gz, 1024).unwrap(), payload);

    // 2. Fixed Huffman + back-reference stream (generated via standard RFC 1951):
    // Compress repetitive text with system `gzip` if available, plus test hand-crafted
    // fixed-Huffman and dynamic-Huffman streams with FEXTRA/FNAME/FCOMMENT/FHCRC.
    let repeated = b"ABCDABCDABCDABCDABCDABCDABCDABCDhello world repeated 0123456789\n".repeat(40);
    if let Ok(mut child) = std::process::Command::new("gzip")
        .arg("-c")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(&repeated).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        assert_eq!(
            decompress_gzip(&out.stdout, repeated.len() + 16).unwrap(),
            repeated
        );

        // Zip-bomb max_bytes limit rejects oversized output!
        assert!(matches!(
            decompress_gzip(&out.stdout, 100),
            Err(GzipError::LimitExceeded(_))
        ));
        // Zip-bomb ratio guard rejects extreme expansion ratio!
        assert!(matches!(
            decompress_gzip_with_limits(&out.stdout, 10_000_000, 2, 16),
            Err(GzipError::LimitExceeded(_))
        ));
    }

    // 3. Gzip with FEXTRA | FNAME | FCOMMENT | FHCRC optional header fields.
    let mut fancy = vec![0x1f, 0x8b, 8, 0x04 | 0x08 | 0x10 | 0x02, 0, 0, 0, 0, 0, 3];
    fancy.extend_from_slice(&2u16.to_le_bytes()); // XLEN=2
    fancy.extend_from_slice(b"EX"); // FEXTRA
    fancy.extend_from_slice(b"doc.txt\0"); // FNAME
    fancy.extend_from_slice(b"comment\0"); // FCOMMENT
    fancy.extend_from_slice(&0u16.to_le_bytes()); // FHCRC
                                                  // Single fixed-Huffman block encoding "hi" (literals 'h'=104, 'i'=105, EOB=256):
                                                  // BFINAL=1 (1b), BTYPE=01 (2b) -> bits: 1, 1, 0
                                                  // Fixed 8-bit code for sym s in 0..=143 is 0b0011_0000 + s reversed MSB-first.
    let mut bits: Vec<u8> = vec![1, 1, 0];
    let push_huff = |bits: &mut Vec<u8>, code: u16, len: u8| {
        for i in (0..len).rev() {
            bits.push(((code >> i) & 1) as u8);
        }
    };
    push_huff(&mut bits, 0x30 + u16::from(b'h'), 8);
    push_huff(&mut bits, 0x30 + u16::from(b'i'), 8);
    push_huff(&mut bits, 0, 7); // sym 256 (EOB) = 7-bit 0000000
    let mut deflated = Vec::new();
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &b) in chunk.iter().enumerate() {
            byte |= b << i;
        }
        deflated.push(byte);
    }
    fancy.extend_from_slice(&deflated);
    fancy.extend_from_slice(&crc32_test(b"hi").to_le_bytes());
    fancy.extend_from_slice(&2u32.to_le_bytes());
    assert_eq!(decompress_gzip(&fancy, 64).unwrap(), b"hi");

    // 4. Error branches: truncated, bad magic, wrong method, reserved flags, bad LEN/NLEN, bad CRC, btype=3.
    assert!(matches!(
        decompress_gzip(b"short", 64),
        Err(GzipError::Corrupt(_))
    ));
    let mut bad_magic = gz.clone();
    bad_magic[0] = 0x00;
    assert!(matches!(
        decompress_gzip(&bad_magic, 64),
        Err(GzipError::Corrupt(_))
    ));
    let mut bad_cm = gz.clone();
    bad_cm[2] = 9;
    assert!(matches!(
        decompress_gzip(&bad_cm, 64),
        Err(GzipError::Corrupt(_))
    ));
    let mut bad_flg = gz.clone();
    bad_flg[3] = 0x80;
    assert!(matches!(
        decompress_gzip(&bad_flg, 64),
        Err(GzipError::Corrupt(_))
    ));
    let mut bad_crc = gz.clone();
    let last = bad_crc.len() - 5;
    bad_crc[last] ^= 0xff;
    assert_eq!(
        decompress_gzip(&bad_crc, 1024),
        Err(GzipError::ChecksumMismatch)
    );
    let mut bad_nlen = gz.clone();
    bad_nlen[13] ^= 0xff;
    assert!(matches!(
        decompress_gzip(&bad_nlen, 1024),
        Err(GzipError::Corrupt(_))
    ));
    let mut btype3 = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 0b0000_0111];
    btype3.extend_from_slice(&[0u8; 8]);
    assert!(matches!(
        decompress_gzip(&btype3, 64),
        Err(GzipError::Corrupt(_))
    ));
    assert!(GzipError::ChecksumMismatch.to_string().contains("checksum"));
    assert!(GzipError::Corrupt("x").to_string().contains("corrupt"));
    assert!(GzipError::LimitExceeded("x").to_string().contains("limit"));

    // 5. End-to-end IPP Print-Job with compression=gzip & unsupported compression!
    let h = Harness::new("ipp-gzip");
    let req = with_op_attr(
        with_printer_uri(
            ipp_req(op::PRINT_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        "compression",
        tags::KEYWORD,
        Value::Keyword("gzip".into()),
    );
    let mut ctx = h.user_ctx("alice");
    ctx.document = &gz;
    let resp = dispatch(&req, &ctx);
    assert_eq!(resp.code, status::OK);
    let jid = find_attr_int(&resp, tags::JOB, "job-id").unwrap();
    let spooled = std::fs::read(job::Job::data_path(&h.request_root, jid, 1)).unwrap();
    assert_eq!(spooled, payload);

    // Corrupt gzip -> ERROR_COMPRESSION_ERROR.
    ctx.document = &bad_crc;
    assert_eq!(dispatch(&req, &ctx).code, status::ERROR_COMPRESSION_ERROR);

    // Unsupported compression -> ERROR_COMPRESSION_NOT_SUPPORTED.
    let bad_comp = with_op_attr(
        with_printer_uri(
            ipp_req(op::PRINT_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        "compression",
        tags::KEYWORD,
        Value::Keyword("bzip2".into()),
    );
    assert_eq!(
        dispatch(&bad_comp, &ctx).code,
        status::ERROR_COMPRESSION_NOT_SUPPORTED
    );
}
