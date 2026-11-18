//! `cupsdProcessIPPRequest()` — validation preamble + sync/async op dispatch.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines
)]

use ipp_codec::{ops::op, ops::status, tags, Attribute, IppMessage, Value};
use printer::{pstate, ptype, Printer};

use crate::admin_ops;
use crate::common::{copy_printer_attrs, new_response, requested_attrs, send_status};
use crate::ctx::{Ctx, DispatchOutcome};
use crate::jobs_ops;
use crate::security::{authorize_op, check_printer_user_allowed};
use crate::sub_ops;

/// `cupsdProcessIPPRequest()` — validate, authorize, and execute one IPP
/// request synchronously, returning only the [`IppMessage`] for backward
/// compatibility with existing `cupsd` call sites.
#[must_use]
pub fn dispatch(req: &IppMessage, ctx: &Ctx) -> IppMessage {
    dispatch_outcome(req, ctx).response
}

/// `cupsdProcessIPPRequest()` — synchronous dispatch returning a structured
/// [`DispatchOutcome`] with `need_auth`, `auth_type`, and `upgrade_required`
/// signals so `cupsd` can emit HTTP `401 WWW-Authenticate` or `426 Upgrade`.
#[must_use]
pub fn dispatch_outcome(req: &IppMessage, ctx: &Ctx) -> DispatchOutcome {
    let mut outcome = DispatchOutcome::new(new_response(req, &ctx.default_language));
    let Ok(uri_attr) = validate_preamble(req, &mut outcome.response) else {
        return outcome;
    };
    match req.code {
        op::CUPS_GET_DEVICES => admin_ops::get_devices_sync(req, &mut outcome, ctx),
        op::CUPS_GET_PPDS => admin_ops::get_ppds_sync(req, &mut outcome, ctx),
        op::CUPS_GET_PPD => admin_ops::get_ppd_sync(req, &mut outcome, ctx),
        op::GET_NOTIFICATIONS => sub_ops::get_notifications_sync(req, &mut outcome, ctx),
        _ => run_core_op(req, &mut outcome, ctx, uri_attr),
    }
    outcome
}

/// Asynchronous IPP request dispatcher — identical semantics to
/// [`dispatch_outcome`], but runs `cups-deviced`, `cups-driverd`, and
/// `Get-Notifications` (`notify-wait=true`) without blocking Tokio worker
/// threads.
pub async fn dispatch_async(req: &IppMessage, ctx: &Ctx<'_>) -> DispatchOutcome {
    let mut outcome = DispatchOutcome::new(new_response(req, &ctx.default_language));
    let Ok(uri_attr) = validate_preamble(req, &mut outcome.response) else {
        return outcome;
    };
    match req.code {
        op::CUPS_GET_DEVICES => admin_ops::get_devices_async(req, &mut outcome, ctx).await,
        op::CUPS_GET_PPDS => admin_ops::get_ppds_async(req, &mut outcome, ctx).await,
        op::CUPS_GET_PPD => admin_ops::get_ppd_async(req, &mut outcome, ctx).await,
        op::GET_NOTIFICATIONS => sub_ops::get_notifications_async(req, &mut outcome, ctx).await,
        _ => run_core_op(req, &mut outcome, ctx, uri_attr),
    }
    outcome
}

/// RFC 8011 request validation preamble (version, request-id, group order,
/// required `attributes-charset` + `attributes-natural-language`, URI check).
/// Returns `Ok(optional_uri_attr)` on success, or `Err(())` after setting an
/// error status on `resp`.
fn validate_preamble<'a>(
    req: &'a IppMessage,
    resp: &mut IppMessage,
) -> Result<Option<&'a Attribute>, ()> {
    if req.version.0 != 1 && req.version.0 != 2 {
        send_status(
            resp,
            status::ERROR_VERSION_NOT_SUPPORTED,
            format!(
                "Bad request version number {}.{}.",
                req.version.0, req.version.1
            ),
        );
        return Err(());
    }
    if req.request_id < 1 {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            format!("Bad request ID {}.", req.request_id),
        );
        return Err(());
    }
    if req.groups.is_empty() || req.groups[0].attributes.is_empty() {
        send_status(resp, status::ERROR_BAD_REQUEST, "No attributes in request.");
        return Err(());
    }

    // Groups must be non-decreasing (tag order).
    let mut prev = 0u8;
    for g in &req.groups {
        if g.tag < prev && g.tag != tags::ZERO {
            send_status(
                resp,
                status::ERROR_BAD_REQUEST,
                format!(
                    "Attribute groups are out of order ({:#x} < {:#x}).",
                    g.tag, prev
                ),
            );
            return Err(());
        }
        prev = g.tag;
    }

    let Some(op_group) = req.group(tags::OPERATION) else {
        send_status(resp, status::ERROR_BAD_REQUEST, "No attributes in request.");
        return Err(());
    };

    let Some(charset_attr) = op_group
        .attributes
        .first()
        .filter(|a| a.name == "attributes-charset" && a.values.len() == 1)
    else {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            "Missing \"attributes-charset\" attribute.",
        );
        return Err(());
    };
    let charset_supported = matches!(charset_attr.first(), Some(Value::Charset(t)) if {
        let s = t.as_str();
        s.eq_ignore_ascii_case("us-ascii") || s.eq_ignore_ascii_case("utf-8")
    });
    if !charset_supported {
        send_status(
            resp,
            status::ERROR_CHARSET,
            "Unsupported \"attributes-charset\" value.",
        );
        return Err(());
    }

    let language_ok = op_group.attributes.get(1).is_some_and(|a| {
        a.name == "attributes-natural-language"
            && a.values.len() == 1
            && matches!(a.first(), Some(Value::NaturalLanguage(t)) if valid_lang(&t.as_str()))
    });
    if !language_ok {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            "Bad \"attributes-natural-language\" value.",
        );
        return Err(());
    }

    let needs_uri = !matches!(
        req.code,
        op::CUPS_GET_DEFAULT
            | op::CUPS_GET_PRINTERS
            | op::CUPS_GET_CLASSES
            | op::CUPS_GET_DEVICES
            | op::CUPS_GET_PPDS
            | op::CUPS_GET_PPD
            | op::CUPS_CREATE_LOCAL_PRINTER
            | op::GET_NOTIFICATIONS
            | op::GET_SUBSCRIPTIONS
            | op::GET_SUBSCRIPTION_ATTRIBUTES
            | op::RENEW_SUBSCRIPTION
            | op::CANCEL_SUBSCRIPTION
            | op::CANCEL_MY_JOBS
            | op::PURGE_JOBS
    );
    let uri_attr = req
        .find(tags::OPERATION, "printer-uri")
        .or_else(|| req.find(tags::OPERATION, "job-uri"));
    if needs_uri && uri_attr.is_none() {
        send_status(
            resp,
            status::ERROR_BAD_REQUEST,
            "Missing required attributes.",
        );
        return Err(());
    }
    Ok(uri_attr)
}

fn run_core_op(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    match req.code {
        // Read-only printer queries
        op::GET_PRINTER_ATTRIBUTES => get_printer_attrs(req, outcome, ctx, uri_attr),
        op::GET_PRINTER_SUPPORTED_VALUES => get_printer_supported(outcome, ctx, uri_attr),
        op::CUPS_GET_DEFAULT => get_default(req, outcome, ctx),
        op::CUPS_GET_PRINTERS => get_printers(req, outcome, ctx, 0),
        op::CUPS_GET_CLASSES => get_printers(req, outcome, ctx, ptype::CLASS),

        // Job submission, validation, queries & lifecycle
        op::VALIDATE_JOB => jobs_ops::validate_job(req, outcome, ctx, uri_attr),
        op::GET_JOBS => jobs_ops::get_jobs(req, outcome, ctx, uri_attr),
        op::PRINT_JOB => jobs_ops::print_job(req, outcome, ctx, uri_attr),
        op::PRINT_URI => jobs_ops::print_uri(req, outcome, ctx, uri_attr),
        op::CREATE_JOB => jobs_ops::create_job(req, outcome, ctx, uri_attr),
        op::SEND_DOCUMENT => jobs_ops::send_document(req, outcome, ctx, uri_attr),
        op::SEND_URI => jobs_ops::send_uri(req, outcome, ctx, uri_attr),
        op::CANCEL_JOB => jobs_ops::cancel_job(req, outcome, ctx, uri_attr),
        op::CANCEL_CURRENT_JOB => jobs_ops::cancel_current_job(req, outcome, ctx, uri_attr),
        op::CANCEL_JOBS => jobs_ops::cancel_jobs(req, outcome, ctx, uri_attr),
        op::CANCEL_MY_JOBS => jobs_ops::cancel_my_jobs(req, outcome, ctx, uri_attr),
        op::PURGE_JOBS => jobs_ops::purge_jobs(req, outcome, ctx, uri_attr),
        op::HOLD_JOB => jobs_ops::hold_job(req, outcome, ctx, uri_attr),
        op::RELEASE_JOB | op::RESUME_JOB | op::CLOSE_JOB => {
            jobs_ops::release_or_resume_job(req, outcome, ctx, uri_attr);
        }
        op::RESTART_JOB => jobs_ops::restart_job(req, outcome, ctx, uri_attr),
        op::REPROCESS_JOB | op::RESUBMIT_JOB => {
            jobs_ops::resubmit_or_reprocess_job(req, outcome, ctx, uri_attr);
        }
        op::SUSPEND_CURRENT_JOB => jobs_ops::suspend_current_job(req, outcome, ctx, uri_attr),
        op::PROMOTE_JOB => jobs_ops::promote_job(req, outcome, ctx, uri_attr),
        op::SCHEDULE_JOB_AFTER => jobs_ops::schedule_job_after(req, outcome, ctx, uri_attr),
        op::SET_JOB_ATTRIBUTES => jobs_ops::set_job_attributes(req, outcome, ctx, uri_attr),
        op::CUPS_MOVE_JOB => jobs_ops::cups_move_job(req, outcome, ctx, uri_attr),
        op::CUPS_AUTHENTICATE_JOB => jobs_ops::cups_authenticate_job(req, outcome, ctx, uri_attr),
        op::GET_JOB_ATTRIBUTES => jobs_ops::get_job_attributes(req, outcome, ctx, uri_attr),
        op::CUPS_GET_DOCUMENT => jobs_ops::get_document(req, outcome, ctx, uri_attr),
        op::GET_DOCUMENTS | op::GET_DOCUMENT_ATTRIBUTES => {
            jobs_ops::get_documents(req, outcome, ctx, uri_attr);
        }
        op::CANCEL_DOCUMENT => jobs_ops::cancel_document(req, outcome, ctx, uri_attr),
        op::SET_DOCUMENT_ATTRIBUTES => {
            jobs_ops::set_document_attributes(req, outcome, ctx, uri_attr);
        }

        // Printer & class administration
        op::CUPS_ADD_MODIFY_PRINTER => admin_ops::add_modify_printer(req, outcome, ctx, uri_attr),
        op::CUPS_CREATE_LOCAL_PRINTER => admin_ops::create_local_printer(req, outcome, ctx),
        op::CUPS_DELETE_PRINTER => admin_ops::delete_printer(req, outcome, ctx, uri_attr),
        op::CUPS_ADD_MODIFY_CLASS => admin_ops::add_modify_class(req, outcome, ctx, uri_attr),
        op::CUPS_DELETE_CLASS => admin_ops::delete_class(req, outcome, ctx, uri_attr),
        op::CUPS_SET_DEFAULT => admin_ops::set_default(req, outcome, ctx, uri_attr),
        op::PAUSE_PRINTER
        | op::PAUSE_PRINTER_AFTER_CURRENT_JOB
        | op::SHUTDOWN_PRINTER
        | op::DEACTIVATE_PRINTER => {
            admin_ops::set_printer_state(req, outcome, ctx, uri_attr, pstate::STOPPED);
        }
        op::RESUME_PRINTER | op::RESTART_PRINTER | op::STARTUP_PRINTER | op::ACTIVATE_PRINTER => {
            admin_ops::set_printer_state(req, outcome, ctx, uri_attr, pstate::IDLE);
        }
        op::CUPS_ACCEPT_JOBS | op::ENABLE_PRINTER => {
            admin_ops::set_accepting(req, outcome, ctx, uri_attr, true);
        }
        op::CUPS_REJECT_JOBS | op::DISABLE_PRINTER => {
            admin_ops::set_accepting(req, outcome, ctx, uri_attr, false);
        }
        op::HOLD_NEW_JOBS => admin_ops::hold_new_jobs(req, outcome, ctx, uri_attr),
        op::RELEASE_HELD_NEW_JOBS => admin_ops::release_held_new_jobs(req, outcome, ctx, uri_attr),
        op::SET_PRINTER_ATTRIBUTES => {
            admin_ops::set_printer_attributes(req, outcome, ctx, uri_attr);
        }
        op::IDENTIFY_PRINTER => admin_ops::identify_printer(req, outcome, ctx, uri_attr),

        // Subscriptions
        op::CREATE_PRINTER_SUBSCRIPTIONS | op::CREATE_JOB_SUBSCRIPTIONS => {
            sub_ops::create_subscription(req, outcome, ctx, uri_attr);
        }
        op::GET_SUBSCRIPTIONS => sub_ops::get_subscriptions(req, outcome, ctx, uri_attr),
        op::GET_SUBSCRIPTION_ATTRIBUTES => sub_ops::get_subscription_attrs(req, outcome, ctx),
        op::RENEW_SUBSCRIPTION => sub_ops::renew_subscription(req, outcome, ctx),
        op::CANCEL_SUBSCRIPTION => sub_ops::cancel_subscription(req, outcome, ctx),

        code => {
            send_status(
                &mut outcome.response,
                status::ERROR_OPERATION_NOT_SUPPORTED,
                format!("{} not supported.", op::name(code)),
            );
        }
    }
}

/// Resolve and authorize a destination URI for read-only printer queries.
fn resolve_printer_for_read(
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
    op_code: u16,
) -> Option<Printer> {
    let Some(uri) = uri_attr.and_then(attr_text) else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing \"printer-uri\" attribute.",
        );
        return None;
    };
    let printer = {
        let reg = ctx.reg();
        let Some((p, _)) = reg.validate_dest(&uri) else {
            drop(reg);
            let policy = ctx.effective_policy_for_dest(None);
            if !authorize_op(ctx, outcome, &policy, op_code, None, Some(&uri)) {
                return None;
            }
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_FOUND,
                "The printer or class does not exist.",
            );
            return None;
        };
        p.clone()
    };
    let policy = ctx.effective_policy_name(Some(&printer)).to_string();
    if !authorize_op(ctx, outcome, &policy, op_code, None, Some(&printer.name)) {
        return None;
    }
    Some(printer)
}

/// `Get-Printer-Attributes` (0x000b).
fn get_printer_attrs(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(printer) =
        resolve_printer_for_read(outcome, ctx, uri_attr, op::GET_PRINTER_ATTRIBUTES)
    else {
        return;
    };
    let ra = requested_attrs(req);
    let qcount = ctx.queued_job_count_for(&printer);
    copy_printer_attrs(&mut outcome.response, &printer, ctx, &ra, qcount);
    outcome.response.code = status::OK;
}

/// `Get-Printer-Supported-Values` (0x0015).
fn get_printer_supported(
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    if resolve_printer_for_read(outcome, ctx, uri_attr, op::GET_PRINTER_SUPPORTED_VALUES).is_none()
    {
        return;
    }
    for name in [
        "printer-geo-location",
        "printer-info",
        "printer-location",
        "printer-organization",
        "printer-organizational-unit",
    ] {
        outcome.response.push(
            tags::PRINTER,
            Attribute::new(name, tags::ADMINDEFINE, vec![Value::AdminDefine]),
        );
    }
    outcome.response.code = status::OK;
}

/// `CUPS-Get-Default` (0x4001).
fn get_default(req: &IppMessage, outcome: &mut DispatchOutcome, ctx: &Ctx<'_>) {
    let printer = ctx.reg().default_printer().cloned();
    let policy = ctx.effective_policy_name(printer.as_ref()).to_string();
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        op::CUPS_GET_DEFAULT,
        None,
        printer.as_ref().map(|p| p.name.as_str()),
    ) {
        return;
    }
    let Some(p) = printer else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "No default printer.",
        );
        return;
    };
    let ra = requested_attrs(req);
    let qcount = ctx.queued_job_count_for(&p);
    copy_printer_attrs(&mut outcome.response, &p, ctx, &ra, qcount);
    outcome.response.code = status::OK;
}

/// `CUPS-Get-Printers` (0x4002) / `CUPS-Get-Classes` (0x4005).
fn get_printers(req: &IppMessage, outcome: &mut DispatchOutcome, ctx: &Ctx<'_>, want_class: i32) {
    let op_code = if want_class != 0 {
        op::CUPS_GET_CLASSES
    } else {
        op::CUPS_GET_PRINTERS
    };
    let policy = ctx.effective_policy_for_dest(None);
    if !authorize_op(ctx, outcome, &policy, op_code, None, None) {
        return;
    }

    let limit = int_attr(req, "limit").unwrap_or(10_000_000);
    let first = req
        .find(tags::OPERATION, "first-printer-name")
        .and_then(attr_text);
    let printer_id = int_attr(req, "printer-id");
    if let Some(id) = printer_id {
        if id <= 0 {
            send_status(
                &mut outcome.response,
                status::ERROR_ATTRIBUTES_OR_VALUES,
                format!("Bad \"printer-id\" value {id}."),
            );
            return;
        }
    }
    let pt_filter = int_attr(req, "printer-type").unwrap_or(0);
    let pt_mask = int_attr(req, "printer-type-mask").unwrap_or(0);
    let loc_filter = req
        .find(tags::OPERATION, "printer-location")
        .and_then(attr_text);
    let ra = requested_attrs(req);

    let matching: Vec<Printer> = {
        let reg = ctx.reg();
        if reg.printers.is_empty() {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_FOUND,
                "No destinations added.",
            );
            return;
        }
        let mut iter: Vec<&Printer> = reg.printers.values().collect();
        if let Some(first_name) = first {
            if let Some(pos) = iter.iter().position(|p| p.name == first_name) {
                iter = iter.split_off(pos);
            }
        }
        let mut out = Vec::new();
        for p in iter {
            if (out.len() as i64) >= limit {
                break;
            }
            if !ctx.is_local && !p.shared {
                continue;
            }
            if let Some(id) = printer_id {
                if i64::from(p.printer_id) != id {
                    continue;
                }
            }
            if want_class != 0 && !p.is_class() {
                continue;
            }
            if want_class == 0 && p.is_class() {
                continue;
            }
            if i64::from(p.effective_ptype(reg.default.as_deref() == Some(p.name.as_str())))
                & pt_mask
                != pt_filter
            {
                continue;
            }
            if let Some(loc) = &loc_filter {
                match &p.location {
                    Some(l) if l.eq_ignore_ascii_case(loc) => {}
                    _ => continue,
                }
            }
            if !check_printer_user_allowed(ctx, p) {
                continue;
            }
            out.push(p.clone());
        }
        out
    };

    for p in &matching {
        let qcount = ctx.queued_job_count_for(p);
        copy_printer_attrs(&mut outcome.response, p, ctx, &ra, qcount);
    }
    outcome.response.code = status::OK;
}

// ---------- Shared IPP attribute & URI helpers ----------

/// String payload of an attribute's first value.
pub fn attr_text(a: &Attribute) -> Option<String> {
    match a.first()? {
        Value::Text(t)
        | Value::Name(t)
        | Value::Uri(t)
        | Value::Keyword(t)
        | Value::UriScheme(t)
        | Value::MimeMediaType(t) => Some(t.as_str().into_owned()),
        _ => None,
    }
}

/// Integer/enum attribute first value.
pub fn attr_int(a: &Attribute) -> Option<i64> {
    match a.first()? {
        Value::Integer(i) | Value::Enum(i) => Some(i64::from(*i)),
        _ => None,
    }
}

/// Integer payload of an operation-group attribute.
pub fn int_attr(req: &IppMessage, name: &str) -> Option<i64> {
    req.find(tags::OPERATION, name).and_then(attr_int)
}

/// Basic `attributes-natural-language` sanity — RFC 3066 token shape.
fn valid_lang(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 35
        && s.split('-')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Resource path inside an `ipp[s]://` or `http[s]://` URI — after authority.
///
/// Authority cannot contain `'/'`, so splitting at the first `'/'` after the
/// scheme accurately handles IPv4, IPv6 (`[::1]:631`), bare paths, and colons
/// inside path segments (e.g. `/printers/hp:123/`).
pub fn uri_resource(uri: &str) -> &str {
    let no_query = uri.split('?').next().unwrap_or(uri);
    let after_scheme = ["ipps://", "ipp://", "https://", "http://"]
        .into_iter()
        .find_map(|scheme| {
            let n = scheme.len();
            no_query
                .get(..n)
                .filter(|head| head.eq_ignore_ascii_case(scheme))
                .and_then(|_| no_query.get(n..))
        });
    match after_scheme {
        Some(rest) => match rest.find('/') {
            Some(i) => &rest[i..],
            None => "/",
        },
        None => no_query,
    }
}

/// True when a `printer-uri` names the server root (`ipp://host/`) or a
/// `/printers` / `/classes` collection ("all destinations").
pub fn is_all_printers_uri(uri: &str) -> bool {
    let path = uri_resource(uri).trim_end_matches('/');
    path.is_empty() || path == "/printers" || path == "/classes"
}

/// Printer/class name from a `printer-uri` — last `/printers/` or `/classes/` segment.
pub fn dest_name(uri: &str) -> Option<String> {
    for seg in ["/printers/", "/classes/"] {
        if let Some(i) = uri.rfind(seg) {
            return uri[i + seg.len()..]
                .split('?')
                .next()
                .filter(|n| !n.is_empty())
                .map(str::to_string);
        }
    }
    uri.rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .map(str::to_string)
}
