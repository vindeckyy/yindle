#![allow(clippy::too_many_lines, clippy::similar_names)]

mod common;

use common::{
    block_on, find_attr_int, find_attr_text, ipp_req, valid_sample_ppd, with_job_attr,
    with_job_uri, with_op_attr, with_printer_attr, with_printer_uri, with_sub_group, write_file,
    Harness, HookRecorder,
};
use ipp_codec::{ops::op, ops::status, tags, Attribute, Group, IppMessage, Value};
use job::JobState;
use ops::{dispatch, dispatch_async, dispatch_outcome};
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn print_one(h: &Harness, user: &str, printer: &str, title: &str, body: &[u8]) -> i32 {
    let req = with_op_attr(
        with_printer_uri(
            ipp_req(op::PRINT_JOB),
            &format!("ipp://localhost:631/printers/{printer}"),
        ),
        "job-name",
        tags::NAME,
        Value::Name(title.into()),
    );
    let mut ctx = h.user_ctx(user);
    ctx.document = body;
    let resp = dispatch(&req, &ctx);
    assert_eq!(resp.code, status::OK);
    find_attr_int(&resp, tags::JOB, "job-id").expect("job-id")
}

#[test]
fn multi_job_and_multi_subscription_ipp_responses_preserve_all_objects() {
    let h = Harness::new("multi-object");

    let j1 = print_one(&h, "alice", "laser1", "Job One", b"one");
    let j2 = print_one(&h, "alice", "laser1", "Job Two", b"two");
    let j3 = print_one(&h, "alice", "laser1", "Job Three", b"three");

    // Get-Jobs MUST emit 3 distinct JOB groups (not drop jobs 2..N!).
    let gj = with_printer_uri(ipp_req(op::GET_JOBS), "ipp://localhost:631/printers/laser1");
    let resp = dispatch(&gj, &h.user_ctx("alice"));
    assert_eq!(resp.code, status::OK);
    let resp_job_groups: Vec<&Group> = resp.groups.iter().filter(|g| g.tag == tags::JOB).collect();
    assert_eq!(resp_job_groups.len(), 3, "each job must have its own Group");

    // Wire round-trip through ipp-codec: repeated group delimiters decode with
    // `Attribute::separator()` markers and preserve ALL 3 job-id attributes!
    let encoded = ipp_codec::encode(&resp).unwrap();
    let (decoded, _) = ipp_codec::decode(&encoded).unwrap();
    let ids: Vec<i32> = decoded
        .find_all("job-id")
        .filter_map(Attribute::int)
        .collect();
    assert_eq!(
        ids,
        vec![j1, j2, j3],
        "all 3 jobs must survive wire round-trip"
    );
    let seps = decoded
        .group(tags::JOB)
        .unwrap()
        .attributes
        .iter()
        .filter(|a| a.is_separator())
        .count();
    assert_eq!(
        seps, 2,
        "3 jobs must emit 2 group-delimiter separators on wire"
    );

    // Check valid RFC 4122 UUID v4 format on job-uuid (NOT fake `urn:uuid:job-1`).
    let full = with_op_attr(
        gj,
        "requested-attributes",
        tags::KEYWORD,
        Value::Keyword("all".into()),
    );
    let full_resp = dispatch(&full, &h.user_ctx("alice"));
    for g in full_resp.groups.iter().filter(|g| g.tag == tags::JOB) {
        let uuid = g.find("job-uuid").and_then(Attribute::text).unwrap();
        assert!(
            uuid.starts_with("urn:uuid:") && uuid.len() == "urn:uuid:".len() + 36,
            "job-uuid must be RFC 4122, got {uuid}"
        );
        assert!(!uuid.contains("job-"));
    }

    // Create 3 subscriptions and verify Get-Subscriptions emits 3 distinct SUBSCRIPTION groups!
    let mut sids = Vec::new();
    for ev in ["job-created", "job-completed", "printer-modified"] {
        let sreq = with_sub_group(
            with_printer_uri(
                ipp_req(op::CREATE_PRINTER_SUBSCRIPTIONS),
                "ipp://localhost:631/printers/laser1",
            ),
            vec![
                Attribute::new(
                    "notify-pull-method",
                    tags::KEYWORD,
                    vec![Value::Keyword("ippget".into())],
                ),
                Attribute::new(
                    "notify-events",
                    tags::KEYWORD,
                    vec![Value::Keyword(ev.into())],
                ),
            ],
        );
        let sr = dispatch(&sreq, &h.user_ctx("alice"));
        assert_eq!(sr.code, status::OK);
        sids.push(find_attr_int(&sr, tags::SUBSCRIPTION, "notify-subscription-id").unwrap());
    }

    let gs = with_printer_uri(
        ipp_req(op::GET_SUBSCRIPTIONS),
        "ipp://localhost:631/printers/laser1",
    );
    let gs_resp = dispatch(&gs, &h.user_ctx("alice"));
    assert_eq!(gs_resp.code, status::OK);
    let sub_groups: Vec<&Group> = gs_resp
        .groups
        .iter()
        .filter(|g| g.tag == tags::SUBSCRIPTION)
        .collect();
    assert_eq!(
        sub_groups.len(),
        3,
        "each subscription must have its own Group"
    );
    let gs_wire = ipp_codec::encode(&gs_resp).unwrap();
    let (gs_dec, _) = ipp_codec::decode(&gs_wire).unwrap();
    let got_sids: Vec<i32> = gs_dec
        .find_all("notify-subscription-id")
        .filter_map(Attribute::int)
        .collect();
    assert_eq!(
        got_sids, sids,
        "all 3 subscriptions must survive wire round-trip"
    );
}

#[test]
fn preamble_validation_rejects_malformed_requests_without_panicking() {
    let h = Harness::new("preamble");
    let ctx = h.ctx();

    // Bad version
    let mut bad_ver = ipp_req(op::CUPS_GET_PRINTERS);
    bad_ver.version = (3, 0);
    assert_eq!(
        dispatch(&bad_ver, &ctx).code,
        status::ERROR_VERSION_NOT_SUPPORTED
    );

    // Bad request_id
    let mut bad_id = ipp_req(op::CUPS_GET_PRINTERS);
    bad_id.request_id = 0;
    assert_eq!(dispatch(&bad_id, &ctx).code, status::ERROR_BAD_REQUEST);

    // Empty groups
    let empty = IppMessage::new(op::CUPS_GET_PRINTERS);
    assert_eq!(dispatch(&empty, &ctx).code, status::ERROR_BAD_REQUEST);

    // Out-of-order groups (JOB=2 before OPERATION=1)
    let mut ooo = IppMessage::new(op::GET_JOBS);
    ooo.groups.push(Group {
        tag: tags::JOB,
        attributes: vec![Attribute::new(
            "copies",
            tags::INTEGER,
            vec![Value::Integer(1)],
        )],
    });
    ooo.groups.push(Group {
        tag: tags::OPERATION,
        attributes: vec![Attribute::new(
            "attributes-charset",
            tags::CHARSET,
            vec![Value::Charset("utf-8".into())],
        )],
    });
    assert_eq!(dispatch(&ooo, &ctx).code, status::ERROR_BAD_REQUEST);

    // Missing operation group (only PRINTER group)
    let mut no_op = IppMessage::new(op::CUPS_GET_PRINTERS);
    no_op.push(
        tags::PRINTER,
        Attribute::new("x", tags::KEYWORD, vec![Value::Keyword("y".into())]),
    );
    assert_eq!(dispatch(&no_op, &ctx).code, status::ERROR_BAD_REQUEST);

    // Missing charset
    let mut no_cs = IppMessage::new(op::CUPS_GET_PRINTERS);
    no_cs.push(
        tags::OPERATION,
        Attribute::new(
            "attributes-natural-language",
            tags::LANGUAGE,
            vec![Value::NaturalLanguage("en".into())],
        ),
    );
    assert_eq!(dispatch(&no_cs, &ctx).code, status::ERROR_BAD_REQUEST);

    // Unsupported charset
    let mut bad_cs = IppMessage::new(op::CUPS_GET_PRINTERS);
    bad_cs.push(
        tags::OPERATION,
        Attribute::new(
            "attributes-charset",
            tags::CHARSET,
            vec![Value::Charset("iso-8859-1".into())],
        ),
    );
    bad_cs.push(
        tags::OPERATION,
        Attribute::new(
            "attributes-natural-language",
            tags::LANGUAGE,
            vec![Value::NaturalLanguage("en".into())],
        ),
    );
    assert_eq!(dispatch(&bad_cs, &ctx).code, status::ERROR_CHARSET);

    // Bad language
    let mut bad_lang = IppMessage::new(op::CUPS_GET_PRINTERS);
    bad_lang.push(
        tags::OPERATION,
        Attribute::new(
            "attributes-charset",
            tags::CHARSET,
            vec![Value::Charset("utf-8".into())],
        ),
    );
    bad_lang.push(
        tags::OPERATION,
        Attribute::new(
            "attributes-natural-language",
            tags::LANGUAGE,
            vec![Value::NaturalLanguage("en_US!".into())],
        ),
    );
    assert_eq!(dispatch(&bad_lang, &ctx).code, status::ERROR_BAD_REQUEST);

    // Missing required printer-uri
    let no_uri = ipp_req(op::GET_PRINTER_ATTRIBUTES);
    assert_eq!(dispatch(&no_uri, &ctx).code, status::ERROR_BAD_REQUEST);

    // Unsupported operation code
    let unsup = with_printer_uri(ipp_req(0x00ff), "ipp://localhost:631/printers/laser1");
    assert_eq!(
        dispatch(&unsup, &ctx).code,
        status::ERROR_OPERATION_NOT_SUPPORTED
    );
}

#[test]
fn validate_job_allow_deny_user_limits_and_quotas() {
    let mut h = Harness::new("validate-quotas");
    h.cfg.cupsd.max_copies = 5;
    h.cfg.cupsd.max_jobs_per_user = 2;
    h.cfg.cupsd.max_jobs_per_printer = 3;
    h.cfg.cupsd.max_jobs = 10;

    let base_validate = || {
        with_printer_uri(
            ipp_req(op::VALIDATE_JOB),
            "ipp://localhost:631/printers/laser1",
        )
    };

    // Valid request passes.
    assert_eq!(
        dispatch(&base_validate(), &h.user_ctx("alice")).code,
        status::OK
    );

    // Unsupported format -> ERROR_DOCUMENT_FORMAT_NOT_SUPPORTED.
    let bad_fmt = with_op_attr(
        base_validate(),
        "document-format",
        tags::MIMETYPE,
        Value::MimeMediaType("application/x-unknown-pdl".into()),
    );
    assert_eq!(
        dispatch(&bad_fmt, &h.user_ctx("alice")).code,
        status::ERROR_DOCUMENT_FORMAT_NOT_SUPPORTED
    );

    // Unsupported compression -> ERROR_COMPRESSION_NOT_SUPPORTED.
    let bad_comp = with_op_attr(
        base_validate(),
        "compression",
        tags::KEYWORD,
        Value::Keyword("lzma".into()),
    );
    assert_eq!(
        dispatch(&bad_comp, &h.user_ctx("alice")).code,
        status::ERROR_COMPRESSION_NOT_SUPPORTED
    );

    // Copies > MaxCopies -> ERROR_ATTRIBUTES_OR_VALUES.
    let too_many_copies =
        with_job_attr(base_validate(), "copies", tags::INTEGER, Value::Integer(9));
    assert_eq!(
        dispatch(&too_many_copies, &h.user_ctx("alice")).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );

    // Bad priority, orientation, sides, hold-until -> ERROR_ATTRIBUTES_OR_VALUES.
    assert_eq!(
        dispatch(
            &with_job_attr(
                base_validate(),
                "job-priority",
                tags::INTEGER,
                Value::Integer(150)
            ),
            &h.user_ctx("alice")
        )
        .code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );
    assert_eq!(
        dispatch(
            &with_job_attr(
                base_validate(),
                "orientation-requested",
                tags::ENUM,
                Value::Enum(99)
            ),
            &h.user_ctx("alice")
        )
        .code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );
    assert_eq!(
        dispatch(
            &with_job_attr(
                base_validate(),
                "sides",
                tags::KEYWORD,
                Value::Keyword("three-sided".into())
            ),
            &h.user_ctx("alice")
        )
        .code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );
    assert_eq!(
        dispatch(
            &with_job_attr(
                base_validate(),
                "job-hold-until",
                tags::KEYWORD,
                Value::Keyword("never-ever".into())
            ),
            &h.user_ctx("alice")
        )
        .code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );

    // Unknown job attribute: fidelity=false -> OK_IGNORED_OR_SUBSTITUTED; fidelity=true -> ERROR_ATTRIBUTES_OR_VALUES.
    let unknown_loose = with_job_attr(
        base_validate(),
        "vendor-magic",
        tags::KEYWORD,
        Value::Keyword("sparkles".into()),
    );
    assert_eq!(
        dispatch(&unknown_loose, &h.user_ctx("alice")).code,
        status::OK_IGNORED_OR_SUBSTITUTED
    );
    let unknown_strict = with_op_attr(
        unknown_loose,
        "ipp-attribute-fidelity",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    assert_eq!(
        dispatch(&unknown_strict, &h.user_ctx("alice")).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );

    // AllowUser / DenyUser enforcement (with @SYSTEM bypass!).
    {
        let mut reg = h.registry.write().unwrap();
        let p = reg.find_mut("laser1").unwrap();
        p.users = vec!["alice".into(), "@vip".into()];
        p.deny_users = false;
    }
    assert_eq!(
        dispatch(&base_validate(), &h.user_ctx("bob")).code,
        status::ERROR_NOT_AUTHORIZED
    );
    assert_eq!(
        dispatch(&base_validate(), &h.user_ctx("alice")).code,
        status::OK
    );
    let mut vip = h.user_ctx("charlie");
    vip.user_groups = vec!["vip".into()];
    assert_eq!(dispatch(&base_validate(), &vip).code, status::OK);
    // Admin bypasses AllowUser.
    assert_eq!(dispatch(&base_validate(), &h.admin_ctx()).code, status::OK);

    // DenyUser list blocks bob, allows alice.
    {
        let mut reg = h.registry.write().unwrap();
        let p = reg.find_mut("laser1").unwrap();
        p.users = vec!["bob".into()];
        p.deny_users = true;
    }
    assert_eq!(
        dispatch(&base_validate(), &h.user_ctx("bob")).code,
        status::ERROR_NOT_AUTHORIZED
    );
    assert_eq!(
        dispatch(&base_validate(), &h.user_ctx("alice")).code,
        status::OK
    );

    // MaxJobsPerUser (2) enforcement.
    let _ = print_one(&h, "alice", "laser1", "j1", b"data1");
    let _ = print_one(&h, "alice", "laser1", "j2", b"data2");
    assert_eq!(
        dispatch(&base_validate(), &h.user_ctx("alice")).code,
        status::ERROR_TOO_MANY_JOBS
    );

    // MaxJobsPerPrinter (3) enforcement (charlie submits 3rd job, 4th fails).
    let _ = print_one(&h, "charlie", "laser1", "j3", b"data3");
    assert_eq!(
        dispatch(&base_validate(), &h.user_ctx("dave")).code,
        status::ERROR_TOO_MANY_JOBS
    );

    // Quota enforcement (job-k-limit & job-page-limit & job-quota-period).
    h.cfg.cupsd.max_jobs_per_printer = 0;
    h.cfg.cupsd.max_jobs_per_user = 0;
    {
        let mut reg = h.registry.write().unwrap();
        let p = reg.find_mut("laser1").unwrap();
        p.users.clear();
        p.quota_period = 3600;
        p.k_limit = 2; // 2 KiB
        p.page_limit = 10;
    }
    let big_req = with_printer_uri(
        ipp_req(op::PRINT_JOB),
        "ipp://localhost:631/printers/laser1",
    );
    let mut dave = h.user_ctx("dave");
    dave.document = &[b'x'; 4096]; // 4 KiB > 2 KiB quota!
    assert_eq!(dispatch(&big_req, &dave).code, status::ERROR_NOT_POSSIBLE);

    // Page limit check.
    {
        let mut reg = h.registry.write().unwrap();
        let p = reg.find_mut("laser1").unwrap();
        p.k_limit = 0;
        p.page_limit = 2;
    }
    let three_copies = with_job_attr(
        with_printer_uri(
            ipp_req(op::PRINT_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        "copies",
        tags::INTEGER,
        Value::Integer(3),
    );
    dave.document = b"small";
    assert_eq!(
        dispatch(&three_copies, &dave).code,
        status::ERROR_NOT_POSSIBLE
    );
}

#[test]
fn which_jobs_all_eleven_keywords_and_queued_job_count() {
    let h = Harness::new("which-jobs");

    // Seed jobs covering every single JobState + proof-print.
    let j_pend = print_one(&h, "alice", "laser1", "pending", b"a");
    let j_held = print_one(&h, "alice", "laser1", "held", b"b");
    let j_proc = print_one(&h, "alice", "laser1", "proc", b"c");
    let j_stop = print_one(&h, "alice", "laser1", "stop", b"d");
    let j_canc = print_one(&h, "alice", "laser1", "canc", b"e");
    let j_abrt = print_one(&h, "alice", "laser1", "abrt", b"f");
    let j_comp = print_one(&h, "alice", "laser1", "comp", b"g");

    {
        let mut jobs = h.jobs.write().unwrap();
        jobs.get_mut(j_held).unwrap().state = JobState::PendingHeld;
        jobs.get_mut(j_proc).unwrap().state = JobState::Processing;
        jobs.get_mut(j_stop).unwrap().state = JobState::ProcessingStopped;
        jobs.get_mut(j_canc).unwrap().state = JobState::Canceled;
        jobs.get_mut(j_abrt).unwrap().state = JobState::Aborted;
        jobs.get_mut(j_comp).unwrap().state = JobState::Completed;
        jobs.get_mut(j_pend)
            .unwrap()
            .options
            .insert("proof-print".into(), "true".into());
    }

    // Live queued-job-count MUST be 4 (pending + held + processing + stopped), NOT 0!
    let gpa = with_printer_uri(
        ipp_req(op::GET_PRINTER_ATTRIBUTES),
        "ipp://localhost:631/printers/laser1",
    );
    let pa_resp = dispatch(&gpa, &h.ctx());
    assert_eq!(
        find_attr_int(&pa_resp, tags::PRINTER, "queued-job-count"),
        Some(4)
    );

    let query = |which: &str| -> Vec<i32> {
        let req = with_op_attr(
            with_printer_uri(ipp_req(op::GET_JOBS), "ipp://localhost:631/printers/laser1"),
            "which-jobs",
            tags::KEYWORD,
            Value::Keyword(which.into()),
        );
        let resp = dispatch(&req, &h.user_ctx("alice"));
        assert_eq!(resp.code, status::OK, "which-jobs={which} failed");
        resp.groups
            .iter()
            .filter(|g| g.tag == tags::JOB)
            .filter_map(|g| g.find("job-id").and_then(Attribute::int))
            .collect()
    };

    assert_eq!(query("not-completed"), vec![j_pend, j_held, j_proc, j_stop]);
    assert_eq!(query("completed"), vec![j_canc, j_abrt, j_comp]);
    assert_eq!(query("all").len(), 7);
    assert_eq!(query("pending"), vec![j_pend]);
    assert_eq!(query("pending-held"), vec![j_held]);
    assert_eq!(query("processing"), vec![j_proc]);
    assert_eq!(query("processing-stopped"), vec![j_stop]);
    assert_eq!(query("canceled"), vec![j_canc]);
    assert_eq!(query("aborted"), vec![j_abrt]);
    assert_eq!(query("fetchable"), vec![j_pend, j_held, j_proc, j_stop]);
    assert_eq!(query("proof-print"), vec![j_pend]);

    // Unknown which-jobs rejected!
    let bad_which = with_op_attr(
        with_printer_uri(ipp_req(op::GET_JOBS), "ipp://localhost:631/printers/laser1"),
        "which-jobs",
        tags::KEYWORD,
        Value::Keyword("bogus-filter".into()),
    );
    assert_eq!(
        dispatch(&bad_which, &h.ctx()).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );

    // Get-Jobs with all-printers URI + my-jobs + limit + job-uri.
    let all_req = with_op_attr(
        with_op_attr(
            with_printer_uri(ipp_req(op::GET_JOBS), "ipp://localhost:631/"),
            "my-jobs",
            tags::BOOLEAN,
            Value::Boolean(true),
        ),
        "limit",
        tags::INTEGER,
        Value::Integer(2),
    );
    let r = dispatch(&all_req, &h.user_ctx("alice"));
    assert_eq!(r.groups.iter().filter(|g| g.tag == tags::JOB).count(), 2);

    let one_job_uri = with_job_uri(
        ipp_req(op::GET_JOBS),
        &format!("ipp://localhost:631/jobs/{j_pend}"),
    );
    assert_eq!(
        dispatch(&one_job_uri, &h.user_ctx("alice"))
            .groups
            .iter()
            .filter(|g| g.tag == tags::JOB)
            .count(),
        1
    );
    let bad_job_uri = with_job_uri(ipp_req(op::GET_JOBS), "ipp://localhost:631/jobs/notanumber");
    assert_eq!(
        dispatch(&bad_job_uri, &h.ctx()).code,
        status::ERROR_BAD_REQUEST
    );
}

#[test]
fn full_job_and_document_lifecycle_hooks_and_new_ops() {
    let h = Harness::new("job-lifecycle");
    h.add_printer("laser2", "ipp://printer2.local:631/ipp/print");

    let mut alice = h.user_ctx("alice");
    let mut admin = h.admin_ctx();
    let hooks = HookRecorder::attach(&mut alice);
    let admin_hooks = HookRecorder::attach(&mut admin);

    // 1. Create-Job + 2x Send-Document + Get-Documents + Get-Document-Attributes + Set-Document-Attributes + Cancel-Document.
    let cj = dispatch(
        &with_op_attr(
            with_printer_uri(
                ipp_req(op::CREATE_JOB),
                "ipp://localhost:631/printers/laser1",
            ),
            "job-name",
            tags::NAME,
            Value::Name("MultiDoc".into()),
        ),
        &alice,
    );
    assert_eq!(cj.code, status::OK);
    let jid = find_attr_int(&cj, tags::JOB, "job-id").unwrap();
    let juri = format!("ipp://localhost:631/jobs/{jid}");

    // Send-Document missing last-document -> BAD_REQUEST.
    assert_eq!(
        dispatch(&with_job_uri(ipp_req(op::SEND_DOCUMENT), &juri), &alice).code,
        status::ERROR_BAD_REQUEST
    );

    alice.document = b"doc-one";
    alice.document_name = "first.txt".into();
    let sd1 = with_op_attr(
        with_op_attr(
            with_job_uri(ipp_req(op::SEND_DOCUMENT), &juri),
            "last-document",
            tags::BOOLEAN,
            Value::Boolean(false),
        ),
        "document-format",
        tags::MIMETYPE,
        Value::MimeMediaType("text/plain".into()),
    );
    assert_eq!(dispatch(&sd1, &alice).code, status::OK);

    alice.document = b"doc-two";
    alice.document_name = "second.txt".into();
    let sd2 = with_op_attr(
        with_op_attr(
            with_job_uri(ipp_req(op::SEND_DOCUMENT), &juri),
            "last-document",
            tags::BOOLEAN,
            Value::Boolean(true),
        ),
        "document-format",
        tags::MIMETYPE,
        Value::MimeMediaType("text/plain".into()),
    );
    let sd2_resp = dispatch(&sd2, &alice);
    assert_eq!(sd2_resp.code, status::OK);
    assert_eq!(
        find_attr_int(&sd2_resp, tags::JOB, "number-of-documents"),
        Some(2)
    );
    assert_eq!(find_attr_int(&sd2_resp, tags::JOB, "job-state"), Some(3)); // Pending

    // Get-Documents returns 2 distinct DOCUMENT groups!
    let gd = dispatch(&with_job_uri(ipp_req(op::GET_DOCUMENTS), &juri), &alice);
    assert_eq!(gd.code, status::OK);
    assert_eq!(
        gd.groups.iter().filter(|g| g.tag == tags::DOCUMENT).count(),
        2
    );

    // Get-Document-Attributes for doc 2 (and missing document-number -> 400).
    assert_eq!(
        dispatch(
            &with_job_uri(ipp_req(op::GET_DOCUMENT_ATTRIBUTES), &juri),
            &alice
        )
        .code,
        status::ERROR_BAD_REQUEST
    );
    let gda = with_op_attr(
        with_job_uri(ipp_req(op::GET_DOCUMENT_ATTRIBUTES), &juri),
        "document-number",
        tags::INTEGER,
        Value::Integer(2),
    );
    let gda_resp = dispatch(&gda, &alice);
    assert_eq!(gda_resp.code, status::OK);
    assert_eq!(
        find_attr_int(&gda_resp, tags::DOCUMENT, "document-number"),
        Some(2)
    );

    // Set-Document-Attributes updates doc 2's name & rejects non-settable attr!
    let mut sda = with_op_attr(
        with_job_uri(ipp_req(op::SET_DOCUMENT_ATTRIBUTES), &juri),
        "document-number",
        tags::INTEGER,
        Value::Integer(2),
    );
    sda.push(
        tags::DOCUMENT,
        Attribute::new(
            "document-name",
            tags::NAME,
            vec![Value::Name("renamed.pdf".into())],
        ),
    );
    sda.push(
        tags::DOCUMENT,
        Attribute::new(
            "document-format",
            tags::MIMETYPE,
            vec![Value::MimeMediaType("application/pdf".into())],
        ),
    );
    assert_eq!(dispatch(&sda, &alice).code, status::OK);
    assert_eq!(
        h.jobs.read().unwrap().get(jid).unwrap().files[1].name,
        "renamed.pdf"
    );

    let mut sda_bad = with_op_attr(
        with_job_uri(ipp_req(op::SET_DOCUMENT_ATTRIBUTES), &juri),
        "document-number",
        tags::INTEGER,
        Value::Integer(2),
    );
    sda_bad.push(
        tags::DOCUMENT,
        Attribute::new("document-number", tags::INTEGER, vec![Value::Integer(99)]),
    );
    assert_eq!(
        dispatch(&sda_bad, &alice).code,
        status::ERROR_ATTRIBUTES_NOT_SETTABLE
    );

    // Cancel-Document actually removes doc 2 and deletes its spool file!
    let cd = with_op_attr(
        with_job_uri(ipp_req(op::CANCEL_DOCUMENT), &juri),
        "document-number",
        tags::INTEGER,
        Value::Integer(2),
    );
    assert_eq!(dispatch(&cd, &alice).code, status::OK);
    assert_eq!(h.jobs.read().unwrap().get(jid).unwrap().files.len(), 1);
    assert!(!job::Job::data_path(&h.request_root, jid, 2).exists());
    // Canceling doc 2 again -> NOT_FOUND.
    assert_eq!(dispatch(&cd, &alice).code, status::ERROR_NOT_FOUND);

    // 2. Set-Job-Attributes: updates title/priority/copies/hold-until & rejects non-settable!
    let sja = with_job_attr(
        with_job_attr(
            with_job_attr(
                with_job_attr(
                    with_job_uri(ipp_req(op::SET_JOB_ATTRIBUTES), &juri),
                    "job-name",
                    tags::NAME,
                    Value::Name("Renamed Job".into()),
                ),
                "job-priority",
                tags::INTEGER,
                Value::Integer(75),
            ),
            "copies",
            tags::INTEGER,
            Value::Integer(3),
        ),
        "job-hold-until",
        tags::KEYWORD,
        Value::Keyword("indefinite".into()),
    );
    let sja_resp = dispatch(&sja, &alice);
    assert_eq!(sja_resp.code, status::OK);
    assert_eq!(find_attr_int(&sja_resp, tags::JOB, "job-state"), Some(4)); // PendingHeld
    assert_eq!(
        find_attr_int(&sja_resp, tags::JOB, "job-priority"),
        Some(75)
    );
    assert_eq!(find_attr_int(&sja_resp, tags::JOB, "copies"), Some(3));

    // Release via Set-Job-Attributes job-hold-until=no-hold.
    let sja_rel = with_job_attr(
        with_job_uri(ipp_req(op::SET_JOB_ATTRIBUTES), &juri),
        "job-hold-until",
        tags::KEYWORD,
        Value::Keyword("no-hold".into()),
    );
    assert_eq!(
        find_attr_int(&dispatch(&sja_rel, &alice), tags::JOB, "job-state"),
        Some(3) // Pending
    );

    // Non-settable attribute -> ERROR_ATTRIBUTES_NOT_SETTABLE.
    let sja_bad = with_job_attr(
        with_job_uri(ipp_req(op::SET_JOB_ATTRIBUTES), &juri),
        "job-state",
        tags::ENUM,
        Value::Enum(9),
    );
    assert_eq!(
        dispatch(&sja_bad, &alice).code,
        status::ERROR_ATTRIBUTES_NOT_SETTABLE
    );

    // 3. Hold-Job, Release-Job, Close-Job, Resume-Job, Promote-Job, Schedule-Job-After.
    assert_eq!(
        dispatch(&with_job_uri(ipp_req(op::HOLD_JOB), &juri), &alice).code,
        status::OK
    );
    assert_eq!(
        dispatch(&with_job_uri(ipp_req(op::RELEASE_JOB), &juri), &alice).code,
        status::OK
    );
    assert_eq!(
        dispatch(&with_job_uri(ipp_req(op::CLOSE_JOB), &juri), &alice).code,
        status::OK
    );
    assert_eq!(
        dispatch(&with_job_uri(ipp_req(op::PROMOTE_JOB), &juri), &admin).code,
        status::OK
    );
    assert_eq!(h.jobs.read().unwrap().get(jid).unwrap().priority, 100);

    let jid2 = print_one(&h, "alice", "laser1", "Second", b"second-body");
    let sched = with_op_attr(
        with_job_uri(
            ipp_req(op::SCHEDULE_JOB_AFTER),
            &format!("ipp://localhost:631/jobs/{jid2}"),
        ),
        "job-id-next",
        tags::INTEGER,
        Value::Integer(jid),
    );
    let sched_resp = dispatch(&sched, &admin);
    assert_eq!(sched_resp.code, status::OK);
    assert_eq!(
        find_attr_int(&sched_resp, tags::JOB, "job-priority"),
        Some(99)
    );

    // Schedule-Job-After without ref puts at priority 1; missing ref -> NOT_FOUND.
    assert_eq!(
        dispatch(
            &with_job_uri(
                ipp_req(op::SCHEDULE_JOB_AFTER),
                &format!("ipp://localhost:631/jobs/{jid2}"),
            ),
            &admin
        )
        .code,
        status::OK
    );
    assert_eq!(h.jobs.read().unwrap().get(jid2).unwrap().priority, 1);

    // 4. Suspend-Current-Job + Cancel-Current-Job!
    h.jobs.write().unwrap().get_mut(jid).unwrap().state = JobState::Processing;
    let susp = dispatch(
        &with_printer_uri(
            ipp_req(op::SUSPEND_CURRENT_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        &alice,
    );
    assert_eq!(susp.code, status::OK);
    assert_eq!(find_attr_int(&susp, tags::JOB, "job-state"), Some(6)); // ProcessingStopped

    // Resume-Job back to Pending, then mark Processing and Cancel-Current-Job.
    assert_eq!(
        dispatch(&with_job_uri(ipp_req(op::RESUME_JOB), &juri), &alice).code,
        status::OK
    );
    h.jobs.write().unwrap().get_mut(jid).unwrap().state = JobState::Processing;
    let ccj = dispatch(
        &with_printer_uri(
            ipp_req(op::CANCEL_CURRENT_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        &alice,
    );
    assert_eq!(ccj.code, status::OK);
    assert_eq!(find_attr_int(&ccj, tags::JOB, "job-state"), Some(7)); // Canceled
    assert!(hooks
        .canceled
        .lock()
        .unwrap()
        .contains(&jid.cast_unsigned()));

    // 5. Restart-Job, Reprocess-Job, Resubmit-Job!
    let rst = dispatch(&with_job_uri(ipp_req(op::RESTART_JOB), &juri), &alice);
    assert_eq!(rst.code, status::OK);
    assert_eq!(find_attr_int(&rst, tags::JOB, "job-state"), Some(3)); // Pending

    let reproc = dispatch(&with_job_uri(ipp_req(op::REPROCESS_JOB), &juri), &alice);
    assert_eq!(reproc.code, status::OK);
    let reproc_id = find_attr_int(&reproc, tags::JOB, "job-id").unwrap();
    assert_ne!(reproc_id, jid);
    assert!(job::Job::data_path(&h.request_root, reproc_id, 1).is_file());

    let resub = with_job_attr(
        with_job_uri(ipp_req(op::RESUBMIT_JOB), &juri),
        "copies",
        tags::INTEGER,
        Value::Integer(4),
    );
    let resub_resp = dispatch(&resub, &alice);
    assert_eq!(resub_resp.code, status::OK);
    let resub_id = find_attr_int(&resub_resp, tags::JOB, "job-id").unwrap();
    assert_ne!(resub_id, jid);
    assert_eq!(find_attr_int(&resub_resp, tags::JOB, "copies"), Some(4));

    // 6. CUPS-Authenticate-Job releases a job held for authentication!
    {
        let mut jobs = h.jobs.write().unwrap();
        let j = jobs.get_mut(jid2).unwrap();
        j.state = JobState::PendingHeld;
        j.reasons = vec!["cups-held-for-authentication".into()];
    }
    let auth_job = with_op_attr(
        with_job_uri(
            ipp_req(op::CUPS_AUTHENTICATE_JOB),
            &format!("ipp://localhost:631/jobs/{jid2}"),
        ),
        "auth-info",
        tags::TEXT,
        Value::Text("alice".into()),
    );
    let auth_resp = dispatch(&auth_job, &alice);
    assert_eq!(auth_resp.code, status::OK);
    assert_eq!(find_attr_int(&auth_resp, tags::JOB, "job-state"), Some(3)); // Pending

    // 7. CUPS-Move-Job (single job AND Move-All-Jobs)!
    let mv_one = with_op_attr(
        with_job_uri(
            ipp_req(op::CUPS_MOVE_JOB),
            &format!("ipp://localhost:631/jobs/{jid2}"),
        ),
        "job-printer-uri",
        tags::URI,
        Value::Uri("ipp://localhost:631/printers/laser2".into()),
    );
    assert_eq!(dispatch(&mv_one, &alice).code, status::OK);
    assert_eq!(h.jobs.read().unwrap().get(jid2).unwrap().dest, "laser2");

    // Move-All-Jobs from laser1 -> laser2!
    let mv_all = with_op_attr(
        with_printer_uri(
            ipp_req(op::CUPS_MOVE_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        "job-printer-uri",
        tags::URI,
        Value::Uri("ipp://localhost:631/printers/laser2".into()),
    );
    assert_eq!(dispatch(&mv_all, &admin).code, status::OK);
    assert_eq!(h.jobs.read().unwrap().get(jid).unwrap().dest, "laser2");

    // 8. Cancel-Job (job-id=0 current), Cancel-My-Jobs, Cancel-Jobs, Purge-Jobs + cancel hook!
    let cancel_zero = with_op_attr(
        with_printer_uri(
            ipp_req(op::CANCEL_JOB),
            "ipp://localhost:631/printers/laser2",
        ),
        "job-id",
        tags::INTEGER,
        Value::Integer(0),
    );
    assert_eq!(dispatch(&cancel_zero, &admin).code, status::OK);
    assert!(!admin_hooks.canceled.lock().unwrap().is_empty());

    // Cancel-My-Jobs cancels alice's remaining jobs on laser2!
    let cmj = with_printer_uri(
        ipp_req(op::CANCEL_MY_JOBS),
        "ipp://localhost:631/printers/laser2",
    );
    assert_eq!(dispatch(&cmj, &alice).code, status::OK);

    // Submit a bob job, cancel with Cancel-Jobs, then Purge-Jobs!
    let bjid = print_one(&h, "bob", "laser2", "BobDoc", b"bob");
    let cj_all = with_printer_uri(
        ipp_req(op::CANCEL_JOBS),
        "ipp://localhost:631/printers/laser2",
    );
    assert_eq!(dispatch(&cj_all, &admin).code, status::OK);
    assert!(admin_hooks
        .canceled
        .lock()
        .unwrap()
        .contains(&bjid.cast_unsigned()));

    let pj = with_printer_uri(
        ipp_req(op::PURGE_JOBS),
        "ipp://localhost:631/printers/laser2",
    );
    assert_eq!(dispatch(&pj, &admin).code, status::OK);
    assert!(h.jobs.read().unwrap().by_id.is_empty());
    assert!(!hooks.events.lock().unwrap().is_empty());
}

#[test]
fn admin_printers_classes_hold_new_jobs_and_common_attr_uniqueness() {
    let h = Harness::new("admin-classes-common");
    let mut admin = h.admin_ctx();
    let hooks = HookRecorder::attach(&mut admin);

    // 1. CUPS-Create-Local-Printer + CUPS-Set-Default + Set-Printer-Attributes + Identify-Printer.
    let clp = with_printer_attr(
        with_printer_attr(
            with_printer_attr(
                with_printer_attr(
                    ipp_req(op::CUPS_CREATE_LOCAL_PRINTER),
                    "printer-name",
                    tags::NAME,
                    Value::Name("color1".into()),
                ),
                "device-uri",
                tags::URI,
                Value::Uri("ipp://color1.local:631/ipp/print".into()),
            ),
            "printer-info",
            tags::TEXT,
            Value::Text("Color Printer".into()),
        ),
        "printer-device-id",
        tags::TEXT,
        Value::Text("MFG:Acme;MDL:Color1;".into()),
    );
    let clp_resp = dispatch(&clp, &admin);
    assert_eq!(clp_resp.code, status::OK);
    assert!(h.server_root.join("printers.conf").is_file());

    // Upload sample PPD to color1 so common.rs reflects real PPD capabilities!
    let ppd = valid_sample_ppd();
    admin.document = ppd.as_bytes();
    let add_ppd = with_printer_attr(
        with_printer_attr(
            with_printer_uri(
                ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
                "ipp://localhost:631/printers/color1",
            ),
            "printer-organization",
            tags::TEXT,
            Value::Text("Acme Corp".into()),
        ),
        "printer-geo-location",
        tags::URI,
        Value::Uri("geo:37.7749,-122.4194".into()),
    );
    assert_eq!(dispatch(&add_ppd, &admin).code, status::OK);
    admin.document = &[];

    // Inspect Get-Printer-Attributes for:
    //  a) ZERO duplicate attribute names!
    //  b) printer-supply attributes present (IPP Everywhere: one
    //     explicitly-unknown entry when the queue reports no markers,
    //     with a matching description and info URI)!
    //  c) IPP 2.2 in ipp-versions-supported!
    //  d) NO duplicate 600dpi in printer-resolution-supported!
    //  e) PPD capabilities honored (color-supported=true, A4 default, 1200dpi, custom MIME)!
    let gpa = with_printer_uri(
        ipp_req(op::GET_PRINTER_ATTRIBUTES),
        "ipp://localhost:631/printers/color1",
    );
    let pa = dispatch(&gpa, &h.ctx());
    assert_eq!(pa.code, status::OK);

    let pg = pa.group(tags::PRINTER).expect("printer group");
    let mut seen = HashSet::new();
    for a in &pg.attributes {
        let name = a.name.as_str().into_owned();
        assert!(
            seen.insert(name.clone()),
            "duplicate attribute emitted in Get-Printer-Attributes: {name}"
        );
    }
    assert!(pg.find("printer-supply-info-uri").is_some());
    // No markers on this queue: exactly one explicitly-unknown supply
    // entry, with a matching description.
    let supply = pg.find("printer-supply").expect("printer-supply");
    assert_eq!(supply.values.len(), 1);
    assert_eq!(
        pg.find("printer-supply-description")
            .expect("printer-supply-description")
            .values
            .len(),
        1
    );
    let versions: Vec<String> = pg
        .find("ipp-versions-supported")
        .unwrap()
        .values
        .iter()
        .filter_map(|v| match v {
            Value::Keyword(k) => Some(k.as_str().into_owned()),
            _ => None,
        })
        .collect();
    assert!(versions.iter().any(|v| v == "2.2"));
    assert_eq!(pg.find("color-supported").and_then(Attribute::int), Some(1));
    assert_eq!(
        find_attr_text(&pa, tags::PRINTER, "media-default").as_deref(),
        Some("iso_a4_210x297mm")
    );
    let res_vals = &pg.find("printer-resolution-supported").unwrap().values;
    let res_uniq: HashSet<String> = res_vals.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(res_vals.len(), res_uniq.len());
    assert!(pg
        .find("document-format-supported")
        .unwrap()
        .values
        .iter()
        .any(
            |v| matches!(v, Value::MimeMediaType(t) if t.as_str() == "application/vnd.yindle-test")
        ));

    // 2. Hold-New-Jobs + submit job (automatically PendingHeld!) + Release-Held-New-Jobs (released to Pending!).
    let hnj = with_printer_uri(
        ipp_req(op::HOLD_NEW_JOBS),
        "ipp://localhost:631/printers/color1",
    );
    assert_eq!(dispatch(&hnj, &admin).code, status::OK);

    let held_jid = print_one(&h, "alice", "color1", "HeldByQueue", b"hold me");
    assert_eq!(
        h.jobs.read().unwrap().get(held_jid).unwrap().state,
        JobState::PendingHeld
    );

    let rhnj = with_printer_uri(
        ipp_req(op::RELEASE_HELD_NEW_JOBS),
        "ipp://localhost:631/printers/color1",
    );
    assert_eq!(dispatch(&rhnj, &admin).code, status::OK);
    assert_eq!(
        h.jobs.read().unwrap().get(held_jid).unwrap().state,
        JobState::Pending
    );

    // 3. CUPS-Add-Modify-Class + classes.conf persistence + CUPS-Get-Classes + CUPS-Delete-Class!
    let mut add_cls = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_CLASS),
            "ipp://localhost:631/classes/pool1",
        ),
        "printer-info",
        tags::TEXT,
        Value::Text("Main Pool".into()),
    );
    add_cls.push(
        tags::PRINTER,
        Attribute::new(
            "member-uris",
            tags::URI,
            vec![
                Value::Uri("ipp://localhost:631/printers/laser1".into()),
                Value::Uri("ipp://localhost:631/printers/color1".into()),
            ],
        ),
    );
    assert_eq!(dispatch(&add_cls, &admin).code, status::OK);
    let classes_conf = h.server_root.join("classes.conf");
    assert!(classes_conf.is_file());
    let classes_txt = std::fs::read_to_string(&classes_conf).unwrap();
    assert!(classes_txt.contains("<Class pool1>"));
    assert!(classes_txt.contains("Printer laser1"));
    assert!(classes_txt.contains("Printer color1"));

    // Reject self-membership, missing member, and printer/class name collision!
    let self_cls = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_CLASS),
            "ipp://localhost:631/classes/pool1",
        ),
        "member-uris",
        tags::URI,
        Value::Uri("ipp://localhost:631/classes/pool1".into()),
    );
    assert_eq!(dispatch(&self_cls, &admin).code, status::ERROR_NOT_POSSIBLE);

    let missing_mem = with_printer_attr(
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_CLASS),
            "ipp://localhost:631/classes/pool1",
        ),
        "member-uris",
        tags::URI,
        Value::Uri("ipp://localhost:631/printers/ghost".into()),
    );
    assert_eq!(dispatch(&missing_mem, &admin).code, status::ERROR_NOT_FOUND);

    let collide_cls = with_printer_uri(
        ipp_req(op::CUPS_ADD_MODIFY_CLASS),
        "ipp://localhost:631/classes/laser1",
    );
    assert_eq!(
        dispatch(&collide_cls, &admin).code,
        status::ERROR_NOT_POSSIBLE
    );

    // CUPS-Get-Classes returns pool1 with member-uris and live queued-job-count (includes member color1's job!).
    let gc = dispatch(&ipp_req(op::CUPS_GET_CLASSES), &h.ctx());
    assert_eq!(gc.code, status::OK);
    assert_eq!(
        find_attr_text(&gc, tags::PRINTER, "printer-name").as_deref(),
        Some("pool1")
    );
    assert_eq!(
        find_attr_int(&gc, tags::PRINTER, "queued-job-count"),
        Some(1)
    );

    // CUPS-Set-Default, CUPS-Get-Default, Get-Printer-Supported-Values, Pause/Resume/Accept/Reject/Identify.
    assert_eq!(
        dispatch(
            &with_printer_uri(
                ipp_req(op::CUPS_SET_DEFAULT),
                "ipp://localhost:631/classes/pool1"
            ),
            &admin
        )
        .code,
        status::OK
    );
    assert_eq!(
        find_attr_text(
            &dispatch(&ipp_req(op::CUPS_GET_DEFAULT), &h.ctx()),
            tags::PRINTER,
            "printer-name"
        )
        .as_deref(),
        Some("pool1")
    );
    assert_eq!(
        dispatch(
            &with_printer_uri(
                ipp_req(op::GET_PRINTER_SUPPORTED_VALUES),
                "ipp://localhost:631/printers/color1"
            ),
            &h.ctx()
        )
        .code,
        status::OK
    );
    for code in [
        op::PAUSE_PRINTER,
        op::RESUME_PRINTER,
        op::SHUTDOWN_PRINTER,
        op::STARTUP_PRINTER,
        op::CUPS_REJECT_JOBS,
        op::CUPS_ACCEPT_JOBS,
        op::DISABLE_PRINTER,
        op::ENABLE_PRINTER,
        op::IDENTIFY_PRINTER,
    ] {
        assert_eq!(
            dispatch(
                &with_printer_uri(ipp_req(code), "ipp://localhost:631/printers/color1"),
                &admin
            )
            .code,
            status::OK,
            "op {} failed",
            op::name(code)
        );
    }

    // Set-Printer-Attributes updates info/location/quotas/state.
    let spa = with_printer_attr(
        with_printer_attr(
            with_printer_uri(
                ipp_req(op::SET_PRINTER_ATTRIBUTES),
                "ipp://localhost:631/printers/color1",
            ),
            "printer-location",
            tags::TEXT,
            Value::Text("Floor 3".into()),
        ),
        "printer-is-shared",
        tags::BOOLEAN,
        Value::Boolean(false),
    );
    assert_eq!(dispatch(&spa, &admin).code, status::OK);

    // CUPS-Get-Printers filters: !is_local hides unshared color1; printer-location filter; bad printer-id.
    let mut remote = h.ctx();
    remote.is_local = false;
    let gp_remote = dispatch(&ipp_req(op::CUPS_GET_PRINTERS), &remote);
    assert_eq!(gp_remote.code, status::OK);
    let names: Vec<String> = gp_remote
        .find_all("printer-name")
        .filter_map(|a| a.text().map(std::borrow::Cow::into_owned))
        .collect();
    assert!(names.contains(&"laser1".to_string()));
    assert!(!names.contains(&"color1".to_string()));

    let bad_pid = with_op_attr(
        ipp_req(op::CUPS_GET_PRINTERS),
        "printer-id",
        tags::INTEGER,
        Value::Integer(0),
    );
    assert_eq!(
        dispatch(&bad_pid, &h.ctx()).code,
        status::ERROR_ATTRIBUTES_OR_VALUES
    );

    // CUPS-Delete-Class & CUPS-Delete-Printer.
    assert_eq!(
        dispatch(
            &with_printer_uri(
                ipp_req(op::CUPS_DELETE_CLASS),
                "ipp://localhost:631/classes/pool1"
            ),
            &admin
        )
        .code,
        status::OK
    );
    assert_eq!(
        dispatch(
            &with_printer_uri(
                ipp_req(op::CUPS_DELETE_CLASS),
                "ipp://localhost:631/classes/pool1"
            ),
            &admin
        )
        .code,
        status::ERROR_NOT_FOUND
    );
    assert_eq!(
        dispatch(
            &with_printer_uri(
                ipp_req(op::CUPS_DELETE_PRINTER),
                "ipp://localhost:631/printers/color1"
            ),
            &admin
        )
        .code,
        status::OK
    );
    assert!(!hooks.events.lock().unwrap().is_empty());
}

#[test]
fn subscriptions_persistence_non_destructive_ippget_and_async_notify_wait() {
    let mut h = Harness::new("subs-ippget-wait");
    h.cfg.cupsd.max_subscriptions_per_user = 3;

    let mut alice = h.user_ctx("alice");
    alice.notify_wait_timeout = Duration::from_millis(250);

    // 1. Create-Printer-Subscriptions persists subscriptions.conf!
    let csub = with_sub_group(
        with_printer_uri(
            ipp_req(op::CREATE_PRINTER_SUBSCRIPTIONS),
            "ipp://localhost:631/printers/laser1",
        ),
        vec![
            Attribute::new(
                "notify-pull-method",
                tags::KEYWORD,
                vec![Value::Keyword("ippget".into())],
            ),
            Attribute::new(
                "notify-events",
                tags::KEYWORD,
                vec![Value::Keyword("job-created".into())],
            ),
            Attribute::new(
                "notify-lease-duration",
                tags::INTEGER,
                vec![Value::Integer(3600)],
            ),
        ],
    );
    let sr = dispatch(&csub, &alice);
    assert_eq!(sr.code, status::OK);
    let sid = find_attr_int(&sr, tags::SUBSCRIPTION, "notify-subscription-id").unwrap();
    let subs_conf = h.server_root.join("subscriptions.conf");
    assert!(subs_conf.is_file());
    let mut reloaded = events::Subscriptions::new();
    let errs = reloaded.load_file(&subs_conf).unwrap();
    assert_eq!(errs, Vec::<String>::new());
    assert!(reloaded.find(sid).is_some());

    // 2. Verify literal "Subscription #{id} not found." formatting bug is FIXED!
    for code in [
        op::GET_SUBSCRIPTION_ATTRIBUTES,
        op::RENEW_SUBSCRIPTION,
        op::CANCEL_SUBSCRIPTION,
    ] {
        let req = with_op_attr(
            ipp_req(code),
            "notify-subscription-id",
            tags::INTEGER,
            Value::Integer(999),
        );
        let resp = dispatch(&req, &h.admin_ctx());
        assert_eq!(resp.code, status::ERROR_NOT_FOUND);
        let msg = find_attr_text(&resp, tags::OPERATION, "status-message").unwrap();
        assert_eq!(msg, "Subscription #999 not found.");
    }

    // 3. Emit 2 job events and verify NON-DESTRUCTIVE multi-client ippget with notify-sequence-numbers!
    let _ = print_one(&h, "alice", "laser1", "E1", b"1");
    let _ = print_one(&h, "alice", "laser1", "E2", b"2");

    let poll = |first_seq: i32| {
        with_op_attr(
            with_op_attr(
                ipp_req(op::GET_NOTIFICATIONS),
                "notify-subscription-ids",
                tags::INTEGER,
                Value::Integer(sid),
            ),
            "notify-sequence-numbers",
            tags::INTEGER,
            Value::Integer(first_seq),
        )
    };
    let c1 = dispatch(&poll(1), &alice);
    assert_eq!(c1.code, status::OK);
    assert_eq!(
        c1.groups
            .iter()
            .filter(|g| g.tag == tags::EVENT_NOTIFICATION)
            .count(),
        2
    );
    // Second client reading from seq 1 STILL gets BOTH events (non-destructive)!
    let c2 = dispatch(&poll(1), &alice);
    assert_eq!(
        c2.groups
            .iter()
            .filter(|g| g.tag == tags::EVENT_NOTIFICATION)
            .count(),
        2
    );
    // Reading from seq 2 gets only event #2!
    let c3 = dispatch(&poll(2), &alice);
    assert_eq!(
        c3.groups
            .iter()
            .filter(|g| g.tag == tags::EVENT_NOTIFICATION)
            .count(),
        1
    );

    // 4. Sync notify-wait=true: wakes when background thread pushes event #3!
    let wait_req = with_op_attr(poll(3), "notify-wait", tags::BOOLEAN, Value::Boolean(true));
    let subs_arc = Arc::new(h.subs.read().unwrap().notifier());
    let _ = subs_arc;
    let resp_sync_wait = thread::scope(|s| {
        let h_ref = &h;
        s.spawn(move || {
            thread::sleep(Duration::from_millis(25));
            h_ref.subs.write().unwrap().push(
                events::Event::JobCreated,
                Some("laser1"),
                Some(42),
                Some(3),
                "async wake event 3",
            );
        });
        dispatch(&wait_req, &alice)
    });
    assert_eq!(resp_sync_wait.code, status::OK);
    assert_eq!(
        resp_sync_wait
            .groups
            .iter()
            .filter(|g| g.tag == tags::EVENT_NOTIFICATION)
            .count(),
        1
    );

    // 5. Async dispatch_async with notify-wait=true: wakes cleanly on event #4!
    let wait_req4 = with_op_attr(poll(4), "notify-wait", tags::BOOLEAN, Value::Boolean(true));
    let resp_async_wait = thread::scope(|s| {
        let h_ref = &h;
        s.spawn(move || {
            thread::sleep(Duration::from_millis(25));
            h_ref.subs.write().unwrap().push(
                events::Event::JobCreated,
                Some("laser1"),
                Some(43),
                Some(3),
                "async wake event 4",
            );
        });
        block_on(dispatch_async(&wait_req4, &alice))
    });
    assert_eq!(resp_async_wait.response.code, status::OK);
    assert_eq!(
        resp_async_wait
            .response
            .groups
            .iter()
            .filter(|g| g.tag == tags::EVENT_NOTIFICATION)
            .count(),
        1
    );

    // 6. Async notify-wait timeout returns OK with 0 events without hanging.
    let mut short_alice = h.user_ctx("alice");
    short_alice.notify_wait_timeout = Duration::from_millis(30);
    let wait_req5 = with_op_attr(poll(5), "notify-wait", tags::BOOLEAN, Value::Boolean(true));
    let timed = block_on(dispatch_async(&wait_req5, &short_alice));
    assert_eq!(timed.response.code, status::OK);
    assert_eq!(
        timed
            .response
            .groups
            .iter()
            .filter(|g| g.tag == tags::EVENT_NOTIFICATION)
            .count(),
        0
    );

    // 7. Renew-Subscription + Cancel-Subscription update subscriptions.conf!
    let ren = with_op_attr(
        with_op_attr(
            ipp_req(op::RENEW_SUBSCRIPTION),
            "notify-subscription-id",
            tags::INTEGER,
            Value::Integer(sid),
        ),
        "notify-lease-duration",
        tags::INTEGER,
        Value::Integer(7200),
    );
    assert_eq!(dispatch(&ren, &alice).code, status::OK);

    let can = with_op_attr(
        ipp_req(op::CANCEL_SUBSCRIPTION),
        "notify-subscription-id",
        tags::INTEGER,
        Value::Integer(sid),
    );
    assert_eq!(dispatch(&can, &alice).code, status::OK);
    let mut reloaded2 = events::Subscriptions::new();
    reloaded2.load_file(&subs_conf).unwrap();
    assert!(reloaded2.find(sid).is_none());
}

#[test]
fn sync_and_async_deviced_and_driverd_helpers_with_correct_ppddir_drvroot() {
    let h = Harness::new("helpers-async");

    // Mock cups-deviced outputting two discovered devices.
    h.install_mock_script(
        "daemon/cups-deviced",
        "#!/bin/sh\necho 'network ipp://192.0.2.50:631/ipp/print \"Acme M1\" \"Acme Printer\" \"MFG:Acme;MDL:M1;\"'\necho 'direct usb://Acme/M2 \"Acme M2\" \"USB Printer\" \"\"'\n",
    );

    // Mock cups-driverd asserting PPDDIR and DRVROOT point under DataDir (NOT server_bin.parent()!).
    let env_log = h.tmp.path.join("driverd-env.log");
    let driverd_script = format!(
        "#!/bin/sh\nprintf 'PPDDIR=%s\\nDRVROOT=%s\\nCUPS_DATADIR=%s\\n' \"$PPDDIR\" \"$DRVROOT\" \"$CUPS_DATADIR\" > '{}'\nif [ \"$1\" = \"list\" ]; then\n  echo 'ppd \"everywhere\" \"IPP Everywhere\" \"CMD:PDF;\" \"(Everywhere)\" \"(3010)\" \"drv\"'\n  echo 'ppd \"sample.ppd\" \"Sample Printer\" \"\" \"(Sample)\" \"\" \"ppd\"'\nelif [ \"$1\" = \"cat\" ] && [ \"$2\" = \"everywhere\" ]; then\n  printf '*PPD-Adobe: \"4.3\"\\n*ModelName: \"Everywhere\"\\n'\nelse\n  exit 1\nfi\n",
        env_log.display()
    );
    h.install_mock_script("daemon/cups-driverd", &driverd_script);

    let admin = h.admin_ctx();

    // 1. Sync & Async CUPS-Get-Devices.
    let dev_sync = dispatch_outcome(&ipp_req(op::CUPS_GET_DEVICES), &admin);
    assert_eq!(dev_sync.response.code, status::OK);
    assert_eq!(dev_sync.response.find_all("device-uri").count(), 2);

    let dev_async = block_on(dispatch_async(&ipp_req(op::CUPS_GET_DEVICES), &admin));
    assert_eq!(dev_async.response.code, status::OK);
    assert_eq!(dev_async.response.find_all("device-uri").count(), 2);

    // 2. Sync & Async CUPS-Get-PPDs + verify PPDDIR/DRVROOT/CUPS_DATADIR env!
    let ppds_req = with_op_attr(
        with_op_attr(
            ipp_req(op::CUPS_GET_PPDS),
            "ppd-make",
            tags::TEXT,
            Value::Text("Generic".into()),
        ),
        "limit",
        tags::INTEGER,
        Value::Integer(10),
    );
    let ppds_sync = dispatch_outcome(&ppds_req, &admin);
    assert_eq!(ppds_sync.response.code, status::OK);
    assert_eq!(
        ppds_sync
            .response
            .groups
            .iter()
            .filter(|g| g.tag == tags::PRINTER)
            .count(),
        2
    );

    let logged = std::fs::read_to_string(&env_log).unwrap();
    assert!(
        logged.contains(&format!("PPDDIR={}/ppd", h.data_dir.display())),
        "PPDDIR must use DataDir/ppd, got: {logged}"
    );
    assert!(
        logged.contains(&format!("DRVROOT={}/drv", h.data_dir.display())),
        "DRVROOT must use DataDir/drv, got: {logged}"
    );

    let ppds_async = block_on(dispatch_async(&ppds_req, &admin));
    assert_eq!(ppds_async.response.code, status::OK);

    // 3. Sync & Async CUPS-Get-PPD (everywhere + missing model).
    let get_ew = with_op_attr(
        ipp_req(op::CUPS_GET_PPD),
        "ppd-name",
        tags::NAME,
        Value::Name("everywhere".into()),
    );
    let r_sync = dispatch(&get_ew, &admin);
    assert_eq!(r_sync.code, status::OK);
    assert!(r_sync.document.starts_with(b"*PPD-Adobe:"));

    let r_async = block_on(dispatch_async(&get_ew, &admin));
    assert_eq!(r_async.response.code, status::OK);
    assert!(r_async.response.document.starts_with(b"*PPD-Adobe:"));

    let get_missing = with_op_attr(
        ipp_req(op::CUPS_GET_PPD),
        "ppd-name",
        tags::NAME,
        Value::Name("no-such-model.ppd".into()),
    );
    assert_eq!(
        block_on(dispatch_async(&get_missing, &admin)).response.code,
        status::ERROR_NOT_FOUND
    );

    // 4. Slow helper killed cleanly on helper_timeout!
    h.install_mock_script("daemon/cups-driverd", "#!/bin/sh\nsleep 5\n");
    let mut fast_timeout = h.admin_ctx();
    fast_timeout.helper_timeout = Duration::from_millis(60);
    let timed_out = dispatch(&get_ew, &fast_timeout);
    assert_eq!(timed_out.code, status::ERROR_NOT_FOUND);

    // 5. Also verify embedded job subscription on Print-Job + missing helper binary error!
    let emb_req = with_sub_group(
        with_printer_uri(
            ipp_req(op::PRINT_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        vec![
            Attribute::new(
                "notify-pull-method",
                tags::KEYWORD,
                vec![Value::Keyword("ippget".into())],
            ),
            Attribute::new(
                "notify-events",
                tags::KEYWORD,
                vec![Value::Keyword("job-completed".into())],
            ),
        ],
    );
    let mut u = h.user_ctx("alice");
    u.document = b"sub-doc";
    let emb_resp = dispatch(&emb_req, &u);
    assert_eq!(emb_resp.code, status::OK);
    assert!(find_attr_int(&emb_resp, tags::SUBSCRIPTION, "notify-subscription-id").is_some());

    // Embedded job subscription with forbidden notify-lease-duration -> BAD_REQUEST.
    let bad_emb = with_sub_group(
        with_printer_uri(
            ipp_req(op::PRINT_JOB),
            "ipp://localhost:631/printers/laser1",
        ),
        vec![
            Attribute::new(
                "notify-pull-method",
                tags::KEYWORD,
                vec![Value::Keyword("ippget".into())],
            ),
            Attribute::new(
                "notify-lease-duration",
                tags::INTEGER,
                vec![Value::Integer(60)],
            ),
        ],
    );
    assert_eq!(dispatch(&bad_emb, &u).code, status::ERROR_BAD_REQUEST);

    // Also cover Create-Job-Subscriptions!
    let jid = find_attr_int(&emb_resp, tags::JOB, "job-id").unwrap();
    let cjs = with_sub_group(
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
    assert_eq!(dispatch(&cjs, &u).code, status::OK);

    // Cover write_file helper usage & missing binary error handling.
    write_file(&h.tmp.path.join("marker.txt"), b"ok");
    std::fs::remove_file(h.server_bin.join("daemon/cups-deviced")).unwrap();
    assert_eq!(
        dispatch(&ipp_req(op::CUPS_GET_DEVICES), &admin).code,
        status::ERROR_INTERNAL
    );
}
