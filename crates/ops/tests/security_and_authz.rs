#![allow(clippy::too_many_lines)]

mod common;

use common::{
    find_attr_int, ipp_req, with_job_uri, with_op_attr, with_printer_attr, with_printer_uri,
    with_sub_group, Harness, HookRecorder,
};
use cups_config::{
    AuthLevel, AuthType, Encryption, Location, OrderType, Policy, PolicyOp, Satisfy,
};
use ipp_codec::{ops::op, ops::status, tags, Attribute, Value};
use ops::{dispatch, dispatch_outcome};
use std::net::{IpAddr, Ipv4Addr};

fn submit_job(h: &Harness, user: &str, title: &str) -> i32 {
    let req = with_op_attr(
        with_op_attr(
            with_printer_uri(
                ipp_req(op::PRINT_JOB),
                "ipp://localhost:631/printers/laser1",
            ),
            "job-name",
            tags::NAME,
            Value::Name(title.into()),
        ),
        "requesting-user-name",
        tags::NAME,
        Value::Name(user.into()),
    );
    let mut ctx = h.user_ctx(user);
    ctx.document = b"hello world";
    let resp = dispatch(&req, &ctx);
    assert_eq!(resp.code, status::OK);
    find_attr_int(&resp, tags::JOB, "job-id").expect("job-id")
}

#[test]
fn anonymous_caller_denied_with_need_auth_across_admin_and_owner_ops() {
    let h = Harness::new("anon-authz");
    let jid = submit_job(&h, "alice", "Secret Payroll");

    // Create a subscription owned by alice too.
    let sub_req = with_sub_group(
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
                vec![Value::Keyword("all".into())],
            ),
        ],
    );
    let sub_resp = dispatch(&sub_req, &h.user_ctx("alice"));
    assert_eq!(sub_resp.code, status::OK);
    let sid = find_attr_int(&sub_resp, tags::SUBSCRIPTION, "notify-subscription-id").unwrap();

    // Anonymous caller attempting spoofing via `requesting-user-name = alice`
    // and `ctx.requesting_user = Some("admin")` MUST STILL BE DENIED!
    let mut anon = h.ctx();
    anon.username = None;
    anon.requesting_user = Some("admin".into());
    let hooks = HookRecorder::attach(&mut anon);

    let admin_and_owner_reqs = vec![
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_PRINTER),
            "ipp://localhost:631/printers/newp",
        ),
        with_printer_uri(
            ipp_req(op::CUPS_DELETE_PRINTER),
            "ipp://localhost:631/printers/laser1",
        ),
        with_printer_uri(
            ipp_req(op::CUPS_ADD_MODIFY_CLASS),
            "ipp://localhost:631/classes/cls1",
        ),
        with_printer_uri(
            ipp_req(op::CUPS_DELETE_CLASS),
            "ipp://localhost:631/classes/cls1",
        ),
        with_printer_uri(
            ipp_req(op::CUPS_SET_DEFAULT),
            "ipp://localhost:631/printers/laser1",
        ),
        with_printer_attr(
            ipp_req(op::CUPS_CREATE_LOCAL_PRINTER),
            "printer-name",
            tags::NAME,
            Value::Name("loc1".into()),
        ),
        ipp_req(op::CUPS_GET_DEVICES),
        with_printer_uri(
            ipp_req(op::PAUSE_PRINTER),
            "ipp://localhost:631/printers/laser1",
        ),
        with_printer_uri(
            ipp_req(op::RESUME_PRINTER),
            "ipp://localhost:631/printers/laser1",
        ),
        with_printer_uri(
            ipp_req(op::HOLD_NEW_JOBS),
            "ipp://localhost:631/printers/laser1",
        ),
        with_printer_uri(
            ipp_req(op::RELEASE_HELD_NEW_JOBS),
            "ipp://localhost:631/printers/laser1",
        ),
        with_printer_uri(
            ipp_req(op::SET_PRINTER_ATTRIBUTES),
            "ipp://localhost:631/printers/laser1",
        ),
        with_printer_uri(
            ipp_req(op::CUPS_ACCEPT_JOBS),
            "ipp://localhost:631/printers/laser1",
        ),
        with_printer_uri(
            ipp_req(op::CUPS_REJECT_JOBS),
            "ipp://localhost:631/printers/laser1",
        ),
        with_printer_uri(
            ipp_req(op::CANCEL_JOBS),
            "ipp://localhost:631/printers/laser1",
        ),
        with_op_attr(
            ipp_req(op::CANCEL_MY_JOBS),
            "requesting-user-name",
            tags::NAME,
            Value::Name("alice".into()),
        ),
        ipp_req(op::PURGE_JOBS),
        with_job_uri(
            ipp_req(op::CUPS_GET_DOCUMENT),
            &format!("ipp://localhost:631/jobs/{jid}"),
        ),
        with_job_uri(
            ipp_req(op::CANCEL_JOB),
            &format!("ipp://localhost:631/jobs/{jid}"),
        ),
        with_job_uri(
            ipp_req(op::HOLD_JOB),
            &format!("ipp://localhost:631/jobs/{jid}"),
        ),
        with_job_uri(
            ipp_req(op::RELEASE_JOB),
            &format!("ipp://localhost:631/jobs/{jid}"),
        ),
        with_job_uri(
            ipp_req(op::RESTART_JOB),
            &format!("ipp://localhost:631/jobs/{jid}"),
        ),
        with_job_uri(
            ipp_req(op::REPROCESS_JOB),
            &format!("ipp://localhost:631/jobs/{jid}"),
        ),
        with_job_uri(
            ipp_req(op::RESUBMIT_JOB),
            &format!("ipp://localhost:631/jobs/{jid}"),
        ),
        with_job_uri(
            ipp_req(op::PROMOTE_JOB),
            &format!("ipp://localhost:631/jobs/{jid}"),
        ),
        with_job_uri(
            ipp_req(op::SCHEDULE_JOB_AFTER),
            &format!("ipp://localhost:631/jobs/{jid}"),
        ),
        with_job_uri(
            ipp_req(op::SET_JOB_ATTRIBUTES),
            &format!("ipp://localhost:631/jobs/{jid}"),
        ),
        with_job_uri(
            ipp_req(op::CUPS_AUTHENTICATE_JOB),
            &format!("ipp://localhost:631/jobs/{jid}"),
        ),
        with_op_attr(
            with_job_uri(
                ipp_req(op::SEND_DOCUMENT),
                &format!("ipp://localhost:631/jobs/{jid}"),
            ),
            "last-document",
            tags::BOOLEAN,
            Value::Boolean(true),
        ),
        with_op_attr(
            with_op_attr(
                with_job_uri(
                    ipp_req(op::SEND_URI),
                    &format!("ipp://localhost:631/jobs/{jid}"),
                ),
                "document-uri",
                tags::URI,
                Value::Uri("http://example.com/a.pdf".into()),
            ),
            "last-document",
            tags::BOOLEAN,
            Value::Boolean(true),
        ),
        with_op_attr(
            with_job_uri(
                ipp_req(op::CUPS_MOVE_JOB),
                &format!("ipp://localhost:631/jobs/{jid}"),
            ),
            "job-printer-uri",
            tags::URI,
            Value::Uri("ipp://localhost:631/printers/laser1".into()),
        ),
        with_op_attr(
            with_job_uri(
                ipp_req(op::CANCEL_DOCUMENT),
                &format!("ipp://localhost:631/jobs/{jid}"),
            ),
            "document-number",
            tags::INTEGER,
            Value::Integer(1),
        ),
        with_op_attr(
            with_job_uri(
                ipp_req(op::SET_DOCUMENT_ATTRIBUTES),
                &format!("ipp://localhost:631/jobs/{jid}"),
            ),
            "document-number",
            tags::INTEGER,
            Value::Integer(1),
        ),
        with_op_attr(
            ipp_req(op::RENEW_SUBSCRIPTION),
            "notify-subscription-id",
            tags::INTEGER,
            Value::Integer(sid),
        ),
        with_op_attr(
            ipp_req(op::CANCEL_SUBSCRIPTION),
            "notify-subscription-id",
            tags::INTEGER,
            Value::Integer(sid),
        ),
        with_op_attr(
            ipp_req(op::GET_NOTIFICATIONS),
            "notify-subscription-ids",
            tags::INTEGER,
            Value::Integer(sid),
        ),
    ];

    for mut req in admin_and_owner_reqs {
        // Inject spoofed requesting-user-name="alice" on every single op!
        if req.find(tags::OPERATION, "requesting-user-name").is_none() {
            req = with_op_attr(
                req,
                "requesting-user-name",
                tags::NAME,
                Value::Name("alice".into()),
            );
        }
        let out = dispatch_outcome(&req, &anon);
        assert_eq!(
            out.response.code,
            status::ERROR_NOT_AUTHENTICATED,
            "op {} must reject anonymous caller with NOT_AUTHENTICATED",
            op::name(req.code)
        );
        assert!(
            out.need_auth,
            "op {} must set need_auth=true",
            op::name(req.code)
        );
        assert!(out.auth_type.is_some());
    }
    assert!(
        !hooks.audits.lock().unwrap().is_empty(),
        "auth denials must emit audit records"
    );

    // Now test an authenticated NON-owner ("bob") trying to access alice's job/sub
    // -> must get FORBIDDEN (need_auth=false), NOT allowed!
    let bob = h.user_ctx("bob");
    for code in [
        op::CUPS_GET_DOCUMENT,
        op::CANCEL_JOB,
        op::HOLD_JOB,
        op::SET_JOB_ATTRIBUTES,
        op::CUPS_AUTHENTICATE_JOB,
        op::CANCEL_DOCUMENT,
        op::SET_DOCUMENT_ATTRIBUTES,
        op::RESUBMIT_JOB,
    ] {
        let mut req = with_job_uri(ipp_req(code), &format!("ipp://localhost:631/jobs/{jid}"));
        if code == op::CANCEL_DOCUMENT || code == op::SET_DOCUMENT_ATTRIBUTES {
            req = with_op_attr(req, "document-number", tags::INTEGER, Value::Integer(1));
        }
        let out = dispatch_outcome(&req, &bob);
        assert_eq!(
            out.response.code,
            status::ERROR_FORBIDDEN,
            "bob must be FORBIDDEN on alice's job for {}",
            op::name(code)
        );
        assert!(!out.need_auth);
    }

    // Bob trying to spoof Cancel-My-Jobs for alice -> FORBIDDEN!
    let spoof_cancel = with_op_attr(
        ipp_req(op::CANCEL_MY_JOBS),
        "requesting-user-name",
        tags::NAME,
        Value::Name("alice".into()),
    );
    assert_eq!(
        dispatch_outcome(&spoof_cancel, &bob).response.code,
        status::ERROR_FORBIDDEN
    );

    // Owner alice CAN read her own document via CUPS-Get-Document!
    let get_doc = with_job_uri(
        ipp_req(op::CUPS_GET_DOCUMENT),
        &format!("ipp://localhost:631/jobs/{jid}"),
    );
    let doc_resp = dispatch(&get_doc, &h.user_ctx("alice"));
    assert_eq!(doc_resp.code, status::OK);
    assert_eq!(doc_resp.document, b"hello world");
}

#[test]
fn host_header_cannot_bypass_hostname_acl_and_encryption_upgrade_signaled() {
    let mut h = Harness::new("host-acl-tls");

    // Policy requiring hostname `trusted.corp` + TLS encryption on Get-Printer-Attributes.
    let mut loc = Location::new("<policy>");
    loc.order = OrderType::Deny; // Order allow,deny
    loc.allow
        .push(cups_config::HostMask::parse_one("trusted.corp").unwrap());
    loc.encryption = Encryption::Required;
    loc.satisfy = Satisfy::All;
    loc.auth_level = AuthLevel::Anon;

    let pol = Policy {
        name: "strict-tls".into(),
        ops: vec![PolicyOp {
            op: op::ANY_OPERATION,
            loc,
        }],
        job_access: vec!["@OWNER".into(), "@SYSTEM".into()],
        job_values: vec!["default".into()],
        sub_access: vec!["@OWNER".into(), "@SYSTEM".into()],
        sub_values: vec!["default".into()],
    };
    h.cfg.cupsd.policies.push(pol);
    h.registry
        .write()
        .unwrap()
        .find_mut("laser1")
        .unwrap()
        .op_policy = Some("strict-tls".into());

    let req = with_printer_uri(
        ipp_req(op::GET_PRINTER_ATTRIBUTES),
        "ipp://trusted.corp:631/printers/laser1",
    );

    // 1. Unencrypted -> UpgradeRequired!
    let mut ctx = h.ctx();
    ctx.client_addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    ctx.hostname = "trusted.corp".into(); // attacker HTTP Host header!
    ctx.peer_host = None;
    ctx.is_encrypted = false;
    let out = dispatch_outcome(&req, &ctx);
    assert_eq!(out.response.code, status::ERROR_CUPS_UPGRADE_REQUIRED);
    assert!(out.upgrade_required);

    // 2. Encrypted, attacker sets HTTP Host: trusted.corp, peer_host is None -> STILL FORBIDDEN!
    ctx.is_encrypted = true;
    let out = dispatch_outcome(&req, &ctx);
    assert_eq!(out.response.code, status::ERROR_FORBIDDEN);
    assert!(!out.upgrade_required);

    // 3. Verified peer_host = "trusted.corp" + encrypted -> ALLOWED!
    ctx.peer_host = Some("trusted.corp".into());
    let out = dispatch_outcome(&req, &ctx);
    assert_eq!(out.response.code, status::OK);
}

#[test]
fn policy_resolution_order_and_fail_closed_when_missing() {
    let mut h = Harness::new("policy-order");

    // Add a custom policy "corp-default" that requires @SYSTEM for Print-Job.
    let mut admin_only = Location::new("<policy>");
    admin_only.order = OrderType::Allow;
    admin_only.auth_level = AuthLevel::User;
    admin_only.auth_type = AuthType::Basic;
    admin_only.names = vec!["@SYSTEM".into()];

    let mut pol = cups_config::default_policy();
    pol.name = "corp-default".into();
    pol.ops.insert(
        0,
        PolicyOp {
            op: u32::from(op::PRINT_JOB),
            loc: admin_only,
        },
    );
    h.cfg.cupsd.policies.push(pol);
    h.cfg.cupsd.default_policy = Some("corp-default".into());

    let req = with_printer_uri(
        ipp_req(op::PRINT_JOB),
        "ipp://localhost:631/printers/laser1",
    );
    // Anonymous fails under DefaultPolicy = "corp-default" (not hardcoded "default"!).
    let mut anon = h.ctx();
    anon.document = b"test";
    let out = dispatch_outcome(&req, &anon);
    assert_eq!(out.response.code, status::ERROR_NOT_AUTHENTICATED);
    assert!(out.need_auth);

    // Admin succeeds under "corp-default".
    let mut admin = h.admin_ctx();
    admin.document = b"test";
    assert_eq!(dispatch(&req, &admin).code, status::OK);

    // Per-printer op_policy overrides DefaultPolicy back to "default" (allowing anonymous Print-Job).
    h.registry
        .write()
        .unwrap()
        .find_mut("laser1")
        .unwrap()
        .op_policy = Some("default".into());
    assert_eq!(dispatch(&req, &anon).code, status::OK);

    // Missing/unknown policy fails CLOSED (Forbidden).
    h.registry
        .write()
        .unwrap()
        .find_mut("laser1")
        .unwrap()
        .op_policy = Some("nonexistent-policy".into());
    assert_eq!(dispatch(&req, &admin).code, status::ERROR_FORBIDDEN);
}

#[test]
fn job_and_subscription_private_values_enforcement() {
    let mut h = Harness::new("privacy-redaction");
    let jid = submit_job(&h, "alice", "Top Secret Merger");

    // Create a subscription owned by alice with user_data.
    let sub_req = with_sub_group(
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
                "notify-user-data",
                tags::STRING,
                vec![Value::OctetString(b"secret-cookie".to_vec())],
            ),
        ],
    );
    let sub_resp = dispatch(&sub_req, &h.user_ctx("alice"));
    let sid = find_attr_int(&sub_resp, tags::SUBSCRIPTION, "notify-subscription-id").unwrap();

    // 1. Bob (non-owner, non-@SYSTEM) calls Get-Job-Attributes: private attrs redacted!
    let job_req = with_job_uri(
        ipp_req(op::GET_JOB_ATTRIBUTES),
        &format!("ipp://localhost:631/jobs/{jid}"),
    );
    let bob_resp = dispatch(&job_req, &h.user_ctx("bob"));
    assert_eq!(bob_resp.code, status::OK);
    assert!(bob_resp.find(tags::JOB, "job-id").is_some());
    assert!(bob_resp.find(tags::JOB, "job-name").is_none());
    assert!(bob_resp
        .find(tags::JOB, "job-originating-user-name")
        .is_none());
    assert!(bob_resp
        .find(tags::JOB, "job-originating-host-name")
        .is_none());

    // 2. Owner alice sees private attributes.
    let alice_resp = dispatch(&job_req, &h.user_ctx("alice"));
    assert!(alice_resp.find(tags::JOB, "job-name").is_some());
    assert!(alice_resp
        .find(tags::JOB, "job-originating-user-name")
        .is_some());

    // 3. @SYSTEM admin sees private attributes.
    let admin_resp = dispatch(&job_req, &h.admin_ctx());
    assert!(admin_resp.find(tags::JOB, "job-name").is_some());

    // 4. Bob calls Get-Subscription-Attributes: private sub attrs redacted!
    let sreq = with_op_attr(
        ipp_req(op::GET_SUBSCRIPTION_ATTRIBUTES),
        "notify-subscription-id",
        tags::INTEGER,
        Value::Integer(sid),
    );
    let bob_sub = dispatch(&sreq, &h.user_ctx("bob"));
    assert_eq!(bob_sub.code, status::OK);
    assert!(bob_sub
        .find(tags::SUBSCRIPTION, "notify-subscription-id")
        .is_some());
    assert!(bob_sub
        .find(tags::SUBSCRIPTION, "notify-user-data")
        .is_none());
    assert!(bob_sub
        .find(tags::SUBSCRIPTION, "notify-subscriber-user-name")
        .is_none());
    assert!(bob_sub.find(tags::SUBSCRIPTION, "notify-events").is_none());

    // Owner sees subscription private attrs.
    let alice_sub = dispatch(&sreq, &h.user_ctx("alice"));
    assert!(alice_sub
        .find(tags::SUBSCRIPTION, "notify-user-data")
        .is_some());

    // 5. Test `JobPrivateValues all` + `JobPrivateAccess @auditors` / `charlie` / `none` / `all` / `default`.
    let pol = &mut h.cfg.cupsd.policies[0];
    pol.job_values = vec!["all".into()];
    pol.job_access = vec!["@auditors".into(), "charlie".into()];
    let mut auditor = h.user_ctx("dave");
    auditor.user_groups = vec!["auditors".into()];
    assert!(dispatch(&job_req, &auditor)
        .find(tags::JOB, "copies")
        .is_some());
    assert!(dispatch(&job_req, &h.user_ctx("charlie"))
        .find(tags::JOB, "copies")
        .is_some());
    let bob_all = dispatch(&job_req, &h.user_ctx("bob"));
    assert!(bob_all.find(tags::JOB, "job-id").is_some()); // core kept
    assert!(bob_all.find(tags::JOB, "copies").is_none()); // redacted under `all`

    // Test `JobPrivateValues none` & `JobPrivateAccess all` & `default` & `none`.
    h.cfg.cupsd.policies[0].job_values = vec!["none".into()];
    assert!(dispatch(&job_req, &h.user_ctx("bob"))
        .find(tags::JOB, "job-name")
        .is_some());

    h.cfg.cupsd.policies[0].job_values = vec!["default".into()];
    h.cfg.cupsd.policies[0].job_access = vec!["none".into(), "default".into()];
    assert!(dispatch(&job_req, &h.user_ctx("alice"))
        .find(tags::JOB, "job-name")
        .is_some());
    assert!(dispatch(&job_req, &h.user_ctx("bob"))
        .find(tags::JOB, "job-name")
        .is_none());

    h.cfg.cupsd.policies[0].job_access = vec!["all".into()];
    assert!(dispatch(&job_req, &h.user_ctx("bob"))
        .find(tags::JOB, "job-name")
        .is_some());

    // Empty access list defaults to @OWNER @SYSTEM; empty values redacts nothing.
    h.cfg.cupsd.policies[0].job_access = Vec::new();
    h.cfg.cupsd.policies[0].job_values = Vec::new();
    assert!(dispatch(&job_req, &h.user_ctx("bob"))
        .find(tags::JOB, "job-name")
        .is_some());
}
