//! Administrative printer/class operations, device discovery, and PPD
//! catalog/fetch operations.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines
)]

use ipp_codec::{ops::op, ops::status, tags, Attribute, IppMessage, Value};
use job::JobState;
use printer::{pstate, Printer};
use std::fmt::Write as _;

use crate::async_exec::{run_helper_async, run_helper_sync, HelperOutput, HelperSpec};
use crate::common::send_status;
use crate::ctx::{Ctx, DispatchOutcome};
use crate::dispatch::{attr_int, attr_text, dest_name, int_attr};
use crate::ppd::{
    atomic_write_ppd, patch_ppd_cups_attrs, read_file_nofollow_bounded, resolve_safe_file_ppd,
    validate_driverd_ppd_name, validate_ppd_bytes, PpdLookupError, MAX_PPD_BYTES,
};
use crate::security::{authorize_op, validate_device_uri_for_ctx};

/// Maximum stdout accepted from `cups-deviced` / `cups-driverd` (16 MiB).
const MAX_HELPER_STDOUT: usize = 16 * 1024 * 1024;

/// Extract, validate, and authorize a queue name from `printer-uri`.
fn prepare_admin_dest(
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
    expect_class: Option<bool>,
    op_code: u16,
) -> Option<String> {
    let Some(uri) = uri_attr.and_then(attr_text) else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing \"printer-uri\" attribute.",
        );
        return None;
    };
    let name = match expect_class {
        Some(true) => uri
            .rsplit_once("/classes/")
            .or_else(|| uri.rsplit_once("/printers/"))
            .map(|(_, tail)| tail),
        Some(false) => uri.rsplit_once("/printers/").map(|(_, tail)| tail),
        None => uri
            .rsplit_once("/printers/")
            .or_else(|| uri.rsplit_once("/classes/"))
            .map(|(_, tail)| tail),
    };
    let Some(name) = name else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Bad printer-uri.",
        );
        return None;
    };
    if printer::validate_printer_name(name).is_err() {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Bad printer-name.",
        );
        return None;
    }
    let policy = ctx.effective_policy_for_dest(Some(name));
    if !authorize_op(ctx, outcome, &policy, op_code, None, Some(name)) {
        return None;
    }
    Some(name.to_string())
}

/// Collect `cups*` attribute patches from PRINTER and OPERATION groups.
fn collect_cups_patches(req: &IppMessage) -> Vec<(String, String)> {
    let mut patches = Vec::new();
    for g in &req.groups {
        if g.tag != tags::PRINTER && g.tag != tags::OPERATION {
            continue;
        }
        for a in &g.attributes {
            let name = a.name.as_str();
            if !name.starts_with("cups") {
                continue;
            }
            let val = match a.values.first() {
                Some(Value::Boolean(b)) => b.to_string(),
                Some(Value::Keyword(s) | Value::Text(s) | Value::Name(s)) => {
                    s.as_str().into_owned()
                }
                Some(Value::Integer(i) | Value::Enum(i)) => i.to_string(),
                _ => continue,
            };
            patches.push((name.into_owned(), val));
        }
    }
    patches
}

/// Apply common printer/class metadata attributes (`info`, `location`, quotas,
/// `AllowUser`/`DenyUser`, policies, banners, shared/accepting/state).
fn apply_common_dest_attrs(p: &mut Printer, req: &IppMessage) -> Result<(), (u16, String)> {
    for g in &req.groups {
        if g.tag != tags::PRINTER && g.tag != tags::OPERATION {
            continue;
        }
        for a in &g.attributes {
            match a.name.as_str().as_ref() {
                "printer-info" => {
                    if let Some(v) = attr_text(a) {
                        p.info = Some(v);
                    }
                }
                "printer-location" => {
                    if let Some(v) = attr_text(a) {
                        p.location = Some(v);
                    }
                }
                "printer-geo-location" => {
                    if let Some(v) = attr_text(a) {
                        p.geo_location = Some(v);
                    }
                }
                "printer-make-and-model" => {
                    if let Some(v) = attr_text(a) {
                        p.make_model = Some(v);
                    }
                }
                "printer-organization" => {
                    if let Some(v) = attr_text(a) {
                        p.organization = Some(v);
                    }
                }
                "printer-organizational-unit" => {
                    if let Some(v) = attr_text(a) {
                        p.organizational_unit = Some(v);
                    }
                }
                "printer-is-accepting-jobs" => {
                    if let Some(Value::Boolean(b)) = a.values.first() {
                        p.accepting = *b;
                    }
                }
                "printer-is-shared" => {
                    if let Some(Value::Boolean(b)) = a.values.first() {
                        p.shared = *b;
                    }
                }
                "printer-is-temporary" => {
                    if let Some(Value::Boolean(b)) = a.values.first() {
                        p.temporary = *b;
                    }
                }
                "printer-state" => {
                    if let Some(v) = attr_int(a) {
                        if matches!(v, 3..=5) {
                            p.state = v as i32;
                            p.state_time = printer::now();
                        } else {
                            return Err((
                                status::ERROR_ATTRIBUTES_OR_VALUES,
                                format!("Bad printer-state value {v}."),
                            ));
                        }
                    }
                }
                "printer-op-policy" => {
                    if let Some(v) = attr_text(a) {
                        p.op_policy = Some(v);
                    }
                }
                "printer-error-policy" => {
                    if let Some(v) = attr_text(a) {
                        p.error_policy = Some(v);
                    }
                }
                "job-quota-period" => {
                    if let Some(v) = attr_int(a) {
                        p.quota_period = v.max(0) as i32;
                    }
                }
                "job-k-limit" => {
                    if let Some(v) = attr_int(a) {
                        p.k_limit = v.max(0) as i32;
                    }
                }
                "job-page-limit" => {
                    if let Some(v) = attr_int(a) {
                        p.page_limit = v.max(0) as i32;
                    }
                }
                "requesting-user-name-allowed" => {
                    let users: Vec<String> = a
                        .values
                        .iter()
                        .filter_map(|v| match v {
                            Value::Name(t) | Value::Text(t) | Value::Keyword(t) => {
                                Some(t.as_str().into_owned())
                            }
                            _ => None,
                        })
                        .collect();
                    if users.is_empty()
                        || (users.len() == 1
                            && (users[0].eq_ignore_ascii_case("all")
                                || users[0].eq_ignore_ascii_case("@all")))
                    {
                        p.users.clear();
                        p.deny_users = false;
                    } else {
                        p.users = users;
                        p.deny_users = false;
                    }
                }
                "requesting-user-name-denied" => {
                    let users: Vec<String> = a
                        .values
                        .iter()
                        .filter_map(|v| match v {
                            Value::Name(t) | Value::Text(t) | Value::Keyword(t) => {
                                Some(t.as_str().into_owned())
                            }
                            _ => None,
                        })
                        .collect();
                    if users.is_empty()
                        || (users.len() == 1 && users[0].eq_ignore_ascii_case("none"))
                    {
                        p.users.clear();
                        p.deny_users = false;
                    } else {
                        p.users = users;
                        p.deny_users = true;
                    }
                }
                "job-sheets-default" => {
                    let sheets: Vec<String> = a
                        .values
                        .iter()
                        .filter_map(|v| match v {
                            Value::Name(t) | Value::Keyword(t) => Some(t.as_str().into_owned()),
                            _ => None,
                        })
                        .collect();
                    if let Some(first) = sheets.first() {
                        let second = sheets.get(1).unwrap_or(first);
                        p.job_sheets = (first.clone(), second.clone());
                    }
                }
                "auth-info-required" => {
                    p.auth_info_required = a
                        .values
                        .iter()
                        .filter_map(|v| match v {
                            Value::Keyword(t) | Value::Name(t) => Some(t.as_str().into_owned()),
                            _ => None,
                        })
                        .collect();
                }
                _ => {}
            }
        }
    }
    p.config_time = printer::now();
    Ok(())
}

/// Apply uploaded PPD bytes or `ppd-name` fetch + validated `cups*` patches
/// atomically to `{ServerRoot}/ppd/{name}.ppd`.
fn install_and_patch_ppd(
    req: &IppMessage,
    ctx: &Ctx<'_>,
    name: &str,
    ppd_name_opt: Option<&str>,
) -> Result<(), (u16, String)> {
    // 1. Uploaded PPD in request document body or resolved `ppd-name`.
    let raw_ppd: Option<Vec<u8>> = if !ctx.document.is_empty() {
        Some(ctx.document.to_vec())
    } else if let Some(ppd_name) = ppd_name_opt {
        fetch_ppd_sync(ctx, ppd_name)
    } else {
        None
    };
    if let Some(bytes) = raw_ppd {
        validate_ppd_bytes(&bytes)
            .map_err(|e| (status::ERROR_BAD_REQUEST, format!("Invalid PPD: {e}")))?;
        atomic_write_ppd(&ctx.server_root, name, &bytes)
            .map_err(|e| (status::ERROR_INTERNAL, format!("Failed to save PPD: {e}")))?;
    }

    // 2. Patch validated `cups*` IPP attributes into the queue PPD (rejecting
    // `cupsFilter*` and CR/LF/NUL injection!).
    let patches = collect_cups_patches(req);
    if !patches.is_empty() {
        // Validate patches even if no PPD file exists yet so injection attempts
        // are ALWAYS rejected loudly!
        for (k, v) in &patches {
            crate::ppd::validate_cups_patch_attr(k, v)
                .map_err(|e| (status::ERROR_BAD_REQUEST, e))?;
        }
        let ppd_path = ctx.server_root.join("ppd").join(format!("{name}.ppd"));
        if let Ok(raw) = read_file_nofollow_bounded(&ppd_path, MAX_PPD_BYTES) {
            let text = String::from_utf8_lossy(&raw);
            let updated_ppd = patch_ppd_cups_attrs(&text, &patches)
                .map_err(|e| (status::ERROR_BAD_REQUEST, e))?;
            atomic_write_ppd(&ctx.server_root, name, updated_ppd.as_bytes())
                .map_err(|e| (status::ERROR_INTERNAL, format!("Failed to update PPD: {e}")))?;
        }
    }
    Ok(())
}

/// `CUPS-Add-Modify-Printer` (0x4003).
pub fn add_modify_printer(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(name) = prepare_admin_dest(
        outcome,
        ctx,
        uri_attr,
        Some(false),
        op::CUPS_ADD_MODIFY_PRINTER,
    ) else {
        return;
    };

    let pg = req.groups.iter().find(|g| g.tag == tags::PRINTER);
    let attr = |n: &str| -> Option<&Attribute> {
        pg.and_then(|g| g.find(n))
            .or_else(|| req.find(tags::OPERATION, n))
    };

    // Validate device-uri if supplied.
    let explicit_device_uri = attr("device-uri").and_then(attr_text);
    if let Some(ref uri) = explicit_device_uri {
        if let Err((code, msg)) = validate_device_uri_for_ctx(uri, ctx) {
            send_status(&mut outcome.response, code, msg);
            return;
        }
    }

    // Validate ppd-name if supplied.
    let ppd_name = attr("ppd-name").and_then(attr_text);
    if let Some(ref pn) = ppd_name {
        if let Err(e) = validate_driverd_ppd_name(pn) {
            send_status(&mut outcome.response, status::ERROR_BAD_REQUEST, e);
            return;
        }
    }

    // Reject class name collisions and validate common attributes BEFORE
    // writing any PPD file to disk.
    if ctx.reg().printers.get(&name).is_some_and(Printer::is_class) {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_POSSIBLE,
            "A class with that name already exists.",
        );
        return;
    }
    {
        let mut scratch = Printer::new(name.clone(), String::new());
        if let Err((code, msg)) = apply_common_dest_attrs(&mut scratch, req) {
            send_status(&mut outcome.response, code, msg);
            return;
        }
    }

    // Validate/install PPD before mutating the registry so invalid uploads fail cleanly.
    if let Err((code, msg)) = install_and_patch_ppd(req, ctx, &name, ppd_name.as_deref()) {
        send_status(&mut outcome.response, code, msg);
        return;
    }

    let mut registry = ctx.reg_write();
    if let Some(existing) = registry.printers.get(&name) {
        if existing.is_class() {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "A class with that name already exists.",
            );
            return;
        }
    }
    let exists = registry.printers.contains_key(&name);
    let mut p = if let Some(existing) = registry.printers.get(&name) {
        existing.clone()
    } else {
        let initial_uri = explicit_device_uri.clone().unwrap_or_default();
        let mut created = Printer::new(name.clone(), initial_uri);
        created.shared = ctx.default_shared;
        created.state = pstate::IDLE;
        created.accepting = true;
        created
    };

    if let Some(uri) = explicit_device_uri {
        p.device_uri = uri;
    }
    if let Err((code, msg)) = apply_common_dest_attrs(&mut p, req) {
        send_status(&mut outcome.response, code, msg);
        return;
    }
    if let Some(ppd) = ppd_name {
        p.options
            .retain(|(n, _)| !n.eq_ignore_ascii_case("ppd-name"));
        p.options.push(("ppd-name".into(), ppd));
    }

    let shared = p.shared;
    registry.add(p.clone());
    drop(registry);

    ctx.save_printers();
    ctx.event(
        if exists {
            events::Event::PrinterModified
        } else {
            events::Event::PrinterAdded
        },
        Some(&name),
        None,
        format!(
            "Printer {name} {}.",
            if exists { "modified" } else { "added" }
        ),
    );
    ctx.audit(
        "CUPS-Add-Modify-Printer",
        Some(&name),
        "allowed",
        if exists { "modified" } else { "added" },
    );
    if shared {
        ctx.dnssd_publish(&p);
    } else {
        ctx.dnssd_unpublish(&name);
    }
    outcome.response.code = status::OK;
}

/// `CUPS-Create-Local-Printer` (0x4028).
pub fn create_local_printer(req: &IppMessage, outcome: &mut DispatchOutcome, ctx: &Ctx<'_>) {
    let pg = req.groups.iter().find(|g| g.tag == tags::PRINTER);
    let attr = |n: &str| -> Option<&Attribute> {
        pg.and_then(|g| g.find(n))
            .or_else(|| req.find(tags::OPERATION, n))
    };
    let Some(name) = attr("printer-name").and_then(attr_text) else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing printer-name.",
        );
        return;
    };
    if let Err(e) = printer::validate_printer_name(&name) {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            format!("Bad printer-name: {e}"),
        );
        return;
    }

    let policy = ctx.effective_policy_for_dest(Some(&name));
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        op::CUPS_CREATE_LOCAL_PRINTER,
        None,
        Some(&name),
    ) {
        return;
    }

    let explicit_device_uri = attr("device-uri").and_then(attr_text);
    if let Some(ref uri) = explicit_device_uri {
        if let Err((code, msg)) = validate_device_uri_for_ctx(uri, ctx) {
            send_status(&mut outcome.response, code, msg);
            return;
        }
    }

    let ppd_name = attr("ppd-name").and_then(attr_text);
    if let Some(ref pn) = ppd_name {
        if let Err(e) = validate_driverd_ppd_name(pn) {
            send_status(&mut outcome.response, status::ERROR_BAD_REQUEST, e);
            return;
        }
    }

    // Reject colliding existing printer or class BEFORE writing any PPD file.
    if ctx.reg().printers.contains_key(&name) {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_POSSIBLE,
            "A printer or class with that name already exists.",
        );
        return;
    }

    let mut p = Printer::new(name.clone(), explicit_device_uri.unwrap_or_default());
    p.shared = ctx.default_shared;
    p.accepting = true;
    p.state = pstate::IDLE;

    if let Some(ref ppd) = ppd_name {
        p.options.push(("ppd-name".into(), ppd.clone()));
    }
    if let Some(devid) = attr("printer-device-id")
        .and_then(attr_text)
        .or_else(|| attr("device-id").and_then(attr_text))
    {
        p.options.push(("printer-device-id".into(), devid));
    }
    if let Some(mk) = attr("ppd-make").and_then(attr_text) {
        if p.make_model.is_none() {
            p.make_model = Some(mk);
        }
    }
    if let Err((code, msg)) = apply_common_dest_attrs(&mut p, req) {
        send_status(&mut outcome.response, code, msg);
        return;
    }

    if let Err((code, msg)) = install_and_patch_ppd(req, ctx, &name, ppd_name.as_deref()) {
        send_status(&mut outcome.response, code, msg);
        return;
    }

    let saved_p = p.clone();
    {
        let mut registry = ctx.reg_write();
        if registry.printers.contains_key(&name) {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "A printer or class with that name already exists.",
            );
            return;
        }
        registry.add(p);
    }
    ctx.save_printers();
    ctx.event(
        events::Event::PrinterAdded,
        Some(&name),
        None,
        format!("Printer {name} added."),
    );
    ctx.audit("CUPS-Create-Local-Printer", Some(&name), "allowed", "added");
    if saved_p.shared {
        ctx.dnssd_publish(&saved_p);
    }

    outcome.response.code = status::OK;
    let g = outcome.response.group_mut(tags::PRINTER);
    let mut add = |n: &str, tag: u8, v: Value| {
        g.attributes.push(Attribute::new(n, tag, vec![v]));
    };
    add(
        "printer-is-accepting-jobs",
        tags::BOOLEAN,
        Value::Boolean(saved_p.accepting),
    );
    add("printer-state", tags::ENUM, Value::Enum(saved_p.state));
    add(
        "printer-state-reasons",
        tags::KEYWORD,
        Value::Keyword("none".into()),
    );
    let scheme = if ctx.is_encrypted { "ipps" } else { "ipp" };
    add(
        "printer-uri-supported",
        tags::URI,
        Value::Uri(
            format!(
                "{scheme}://{}:{}/printers/{}",
                ctx.hostname, ctx.port, saved_p.name
            )
            .into(),
        ),
    );
}

/// `CUPS-Delete-Printer` (0x4004).
pub fn delete_printer(
    _req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(name) =
        prepare_admin_dest(outcome, ctx, uri_attr, Some(false), op::CUPS_DELETE_PRINTER)
    else {
        return;
    };
    let mut registry = ctx.reg_write();
    if registry.printers.get(&name).is_none_or(Printer::is_class) {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "The printer does not exist.",
        );
        return;
    }
    registry.remove(&name);
    drop(registry);

    let _ = std::fs::remove_file(ctx.server_root.join("ppd").join(format!("{name}.ppd")));
    ctx.save_all_destinations();
    ctx.dnssd_unpublish(&name);
    ctx.event(
        events::Event::PrinterDeleted,
        Some(&name),
        None,
        format!("Printer {name} deleted."),
    );
    ctx.audit("CUPS-Delete-Printer", Some(&name), "allowed", "deleted");
    outcome.response.code = status::OK;
}

/// `CUPS-Add-Modify-Class` (0x4006).
pub fn add_modify_class(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(name) = prepare_admin_dest(
        outcome,
        ctx,
        uri_attr,
        Some(true),
        op::CUPS_ADD_MODIFY_CLASS,
    ) else {
        return;
    };

    let pg = req.groups.iter().find(|g| g.tag == tags::PRINTER);
    let member_attr = pg
        .and_then(|g| g.find("member-uris"))
        .or_else(|| req.find(tags::OPERATION, "member-uris"));

    let mut registry = ctx.reg_write();
    if let Some(existing) = registry.printers.get(&name) {
        if !existing.is_class() {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "A printer with that name already exists.",
            );
            return;
        }
    }

    let exists = registry.printers.contains_key(&name);
    let mut class = if let Some(existing) = registry.printers.get(&name) {
        existing.clone()
    } else {
        let mut c = Printer::new_class(name.clone());
        c.shared = ctx.default_shared;
        c.accepting = true;
        c.state = pstate::IDLE;
        c
    };

    if let Some(ma) = member_attr {
        let mut new_members = Vec::new();
        for val in &ma.values {
            let uri = match val {
                Value::Uri(t) | Value::Name(t) | Value::Text(t) => t.as_str().into_owned(),
                _ => continue,
            };
            let Some(m_name) = dest_name(&uri) else {
                send_status(
                    &mut outcome.response,
                    status::ERROR_BAD_REQUEST,
                    format!("Bad member URI \"{uri}\"."),
                );
                return;
            };
            if m_name == name {
                send_status(
                    &mut outcome.response,
                    status::ERROR_NOT_POSSIBLE,
                    "A class cannot contain itself.",
                );
                return;
            }
            if !registry.printers.contains_key(&m_name) {
                send_status(
                    &mut outcome.response,
                    status::ERROR_NOT_FOUND,
                    format!("Member printer \"{m_name}\" does not exist."),
                );
                return;
            }
            if !new_members.iter().any(|x| x == &m_name) {
                new_members.push(m_name);
            }
        }
        class.members = new_members;
    }

    if let Err((code, msg)) = apply_common_dest_attrs(&mut class, req) {
        send_status(&mut outcome.response, code, msg);
        return;
    }

    let shared = class.shared;
    registry.add(class.clone());
    drop(registry);

    ctx.save_classes();
    ctx.event(
        if exists {
            events::Event::PrinterModified
        } else {
            events::Event::PrinterAdded
        },
        Some(&name),
        None,
        format!(
            "Class {name} {}.",
            if exists { "modified" } else { "added" }
        ),
    );
    ctx.audit(
        "CUPS-Add-Modify-Class",
        Some(&name),
        "allowed",
        if exists { "modified" } else { "added" },
    );
    if shared {
        ctx.dnssd_publish(&class);
    } else {
        ctx.dnssd_unpublish(&name);
    }
    outcome.response.code = status::OK;
}

/// `CUPS-Delete-Class` (0x4007).
pub fn delete_class(
    _req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(name) = prepare_admin_dest(outcome, ctx, uri_attr, Some(true), op::CUPS_DELETE_CLASS)
    else {
        return;
    };
    let mut registry = ctx.reg_write();
    if !registry.printers.get(&name).is_some_and(Printer::is_class) {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "The class does not exist.",
        );
        return;
    }
    registry.remove(&name);
    drop(registry);

    ctx.save_all_destinations();
    ctx.dnssd_unpublish(&name);
    ctx.event(
        events::Event::PrinterDeleted,
        Some(&name),
        None,
        format!("Class {name} deleted."),
    );
    ctx.audit("CUPS-Delete-Class", Some(&name), "allowed", "deleted");
    outcome.response.code = status::OK;
}

/// `CUPS-Set-Default` (0x400a).
pub fn set_default(
    _req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(name) = prepare_admin_dest(outcome, ctx, uri_attr, None, op::CUPS_SET_DEFAULT) else {
        return;
    };
    let mut registry = ctx.reg_write();
    if !registry.printers.contains_key(&name) {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "The printer or class does not exist.",
        );
        return;
    }
    registry.default = Some(name.clone());
    drop(registry);

    ctx.save_all_destinations();
    ctx.audit("CUPS-Set-Default", Some(&name), "allowed", "set default");
    outcome.response.code = status::OK;
}

/// `Pause-Printer`, `Pause-Printer-After-Current-Job`, `Shutdown-Printer`,
/// `Deactivate-Printer`, `Resume-Printer`, `Restart-Printer`,
/// `Startup-Printer`, `Activate-Printer`.
pub fn set_printer_state(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
    state: i32,
) {
    let Some(name) = prepare_admin_dest(outcome, ctx, uri_attr, None, req.code) else {
        return;
    };
    let mut registry = ctx.reg_write();
    let Some(p) = registry.printers.get_mut(&name) else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "The printer or class does not exist.",
        );
        return;
    };
    p.state = state;
    p.state_time = printer::now();
    if let Some(msg) = req
        .find(tags::OPERATION, "printer-state-message")
        .and_then(attr_text)
    {
        p.state_message = msg;
    }
    if req.code == op::DEACTIVATE_PRINTER || req.code == op::SHUTDOWN_PRINTER {
        p.accepting = false;
    } else if req.code == op::ACTIVATE_PRINTER || req.code == op::STARTUP_PRINTER {
        p.accepting = true;
    }
    let is_class = p.is_class();
    let shared = p.shared;
    let saved_p = p.clone();
    drop(registry);

    if is_class {
        ctx.save_classes();
    } else {
        ctx.save_printers();
    }
    let ev = if state == pstate::STOPPED {
        events::Event::PrinterStopped
    } else {
        events::Event::PrinterStateChanged
    };
    ctx.event(
        ev,
        Some(&name),
        None,
        format!("Printer {name} state changed to {state}."),
    );
    ctx.audit(
        op::name(req.code),
        Some(&name),
        "allowed",
        format!("state={state}"),
    );
    if shared {
        ctx.dnssd_publish(&saved_p);
    }
    outcome.response.code = status::OK;
}

/// `CUPS-Accept-Jobs`/`Enable-Printer` and `CUPS-Reject-Jobs`/`Disable-Printer`.
pub fn set_accepting(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
    accepting: bool,
) {
    let Some(name) = prepare_admin_dest(outcome, ctx, uri_attr, None, req.code) else {
        return;
    };
    let mut registry = ctx.reg_write();
    let Some(p) = registry.printers.get_mut(&name) else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "The printer or class does not exist.",
        );
        return;
    };
    p.accepting = accepting;
    if accepting {
        p.reasons.clear();
    } else {
        if let Some(r) = req
            .find(tags::OPERATION, "printer-state-message")
            .and_then(attr_text)
        {
            p.state_message = r;
        }
        if let Some(reasons) = req.find(tags::OPERATION, "printer-state-reasons") {
            p.reasons = reasons
                .values
                .iter()
                .filter_map(|v| match v {
                    Value::Keyword(t) | Value::Text(t) => Some(t.to_string()),
                    _ => None,
                })
                .collect();
        }
    }
    let is_class = p.is_class();
    drop(registry);

    if is_class {
        ctx.save_classes();
    } else {
        ctx.save_printers();
    }
    ctx.event(
        events::Event::PrinterStateChanged,
        Some(&name),
        None,
        format!("Printer {name} accepting={accepting}."),
    );
    ctx.audit(
        op::name(req.code),
        Some(&name),
        "allowed",
        format!("accepting={accepting}"),
    );
    outcome.response.code = status::OK;
}

/// `Hold-New-Jobs` (0x0025) — place new jobs submitted to this destination into
/// `pending-held` state until `Release-Held-New-Jobs` is called.
pub fn hold_new_jobs(
    _req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(name) = prepare_admin_dest(outcome, ctx, uri_attr, None, op::HOLD_NEW_JOBS) else {
        return;
    };
    let mut registry = ctx.reg_write();
    let Some(p) = registry.printers.get_mut(&name) else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "The printer or class does not exist.",
        );
        return;
    };
    if !p.options.iter().any(|(k, _)| k == "hold-new-jobs") {
        p.options.push(("hold-new-jobs".into(), "true".into()));
    }
    if !p.reasons.iter().any(|r| r == "hold-new-jobs") {
        p.reasons.push("hold-new-jobs".into());
    }
    p.state_time = printer::now();
    let is_class = p.is_class();
    drop(registry);

    if is_class {
        ctx.save_classes();
    } else {
        ctx.save_printers();
    }
    ctx.event(
        events::Event::PrinterStateChanged,
        Some(&name),
        None,
        format!("Printer {name} is now holding new jobs."),
    );
    ctx.audit("Hold-New-Jobs", Some(&name), "allowed", "holding new jobs");
    outcome.response.code = status::OK;
}

/// `Release-Held-New-Jobs` (0x0026) — clear the hold-new-jobs flag and release
/// held jobs on this destination back to `Pending`.
pub fn release_held_new_jobs(
    _req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(name) = prepare_admin_dest(outcome, ctx, uri_attr, None, op::RELEASE_HELD_NEW_JOBS)
    else {
        return;
    };
    let mut registry = ctx.reg_write();
    let Some(p) = registry.printers.get_mut(&name) else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "The printer or class does not exist.",
        );
        return;
    };
    p.options.retain(|(k, _)| k != "hold-new-jobs");
    p.reasons.retain(|r| r != "hold-new-jobs");
    p.state_time = printer::now();
    let is_class = p.is_class();
    drop(registry);

    // Release ONLY jobs held due to `hold-new-jobs` (never jobs explicitly held
    // by users via `Hold-Job` or `job-hold-until`).
    let mut released_ids = Vec::new();
    {
        let mut jobs = ctx.jobs_write();
        for j in jobs.by_id.values_mut() {
            if j.dest == name
                && j.state == JobState::PendingHeld
                && !j.files.is_empty()
                && j.reasons.iter().any(|r| r == "hold-new-jobs")
            {
                j.state = JobState::Pending;
                j.hold_until = None;
                j.reasons = vec!["none".into()];
                let _ = j.save(&ctx.request_root);
                released_ids.push(j.id);
            }
        }
    }
    for jid in &released_ids {
        ctx.event_with_state(
            events::Event::JobStateChanged,
            Some(&name),
            Some(*jid),
            Some(JobState::Pending as i32),
            None,
            format!("Job {jid} released."),
        );
    }

    if is_class {
        ctx.save_classes();
    } else {
        ctx.save_printers();
    }
    ctx.event(
        events::Event::PrinterStateChanged,
        Some(&name),
        None,
        format!(
            "Printer {name} released {} held job(s).",
            released_ids.len()
        ),
    );
    ctx.audit(
        "Release-Held-New-Jobs",
        Some(&name),
        "allowed",
        format!("released={}", released_ids.len()),
    );
    outcome.response.code = status::OK;
}

/// `Set-Printer-Attributes` (0x0013).
pub fn set_printer_attributes(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(name) = prepare_admin_dest(outcome, ctx, uri_attr, None, op::SET_PRINTER_ATTRIBUTES)
    else {
        return;
    };

    let pg = req.groups.iter().find(|g| g.tag == tags::PRINTER);
    let explicit_device_uri = pg
        .and_then(|g| g.find("device-uri"))
        .or_else(|| req.find(tags::OPERATION, "device-uri"))
        .and_then(attr_text);
    if let Some(ref uri) = explicit_device_uri {
        if let Err((code, msg)) = validate_device_uri_for_ctx(uri, ctx) {
            send_status(&mut outcome.response, code, msg);
            return;
        }
    }

    let mut registry = ctx.reg_write();
    let Some(p) = registry.printers.get_mut(&name) else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "The printer or class does not exist.",
        );
        return;
    };
    if let Some(uri) = explicit_device_uri {
        p.device_uri = uri;
    }
    if let Err((code, msg)) = apply_common_dest_attrs(p, req) {
        send_status(&mut outcome.response, code, msg);
        return;
    }
    let is_class = p.is_class();
    let shared = p.shared;
    let saved_p = p.clone();
    drop(registry);

    if is_class {
        ctx.save_classes();
    } else {
        ctx.save_printers();
    }
    ctx.event(
        events::Event::PrinterConfigChanged,
        Some(&name),
        None,
        format!("Printer {name} attributes updated."),
    );
    ctx.audit("Set-Printer-Attributes", Some(&name), "allowed", "updated");
    if shared {
        ctx.dnssd_publish(&saved_p);
    } else {
        ctx.dnssd_unpublish(&name);
    }
    outcome.response.code = status::OK;
}

/// `Identify-Printer` (0x003c).
pub fn identify_printer(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(name) = prepare_admin_dest(outcome, ctx, uri_attr, None, op::IDENTIFY_PRINTER) else {
        return;
    };
    if ctx.reg().find(&name).is_none() {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "The printer does not exist.",
        );
        return;
    }
    let actions = req.find(tags::OPERATION, "identify-actions").map_or_else(
        || "display".into(),
        |a| {
            a.values
                .iter()
                .filter_map(|v| match v {
                    Value::Keyword(k) => Some(k.as_str().as_ref().to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(",")
        },
    );
    ctx.event(
        events::Event::PrinterStateChanged,
        Some(&name),
        None,
        format!("Identify-Printer: actions={actions}"),
    );
    outcome.response.code = status::OK;
}

// ==================== Helpers: cups-deviced & cups-driverd ====================

fn deviced_spec(ctx: &Ctx<'_>) -> HelperSpec {
    let timeout_secs = ctx.helper_timeout.as_secs().clamp(1, 60);
    HelperSpec {
        program: ctx.server_bin.join("daemon").join("cups-deviced"),
        args: vec![
            "0".into(),
            "0".into(),
            timeout_secs.to_string(),
            ctx.server_bin
                .join("backend")
                .to_string_lossy()
                .into_owned(),
        ],
        env: Vec::new(),
        timeout: ctx.helper_timeout,
        max_stdout: MAX_HELPER_STDOUT,
    }
}

fn emit_devices_output(outcome: &mut DispatchOutcome, out: Option<HelperOutput>) {
    let Some(out) = out else {
        send_status(
            &mut outcome.response,
            status::ERROR_INTERNAL,
            "cannot run cups-deviced",
        );
        return;
    };
    outcome.response.code = status::OK;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut it = line.splitn(3, ' ');
        let (Some(class_), Some(uri), body) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let q = quoted_fields(body.unwrap_or(""));
        let (mm, info, devid) = (
            q.first().cloned().unwrap_or_default(),
            q.get(1).cloned().unwrap_or_default(),
            q.get(2).cloned().unwrap_or_default(),
        );
        let g = outcome.response.new_group_mut(tags::PRINTER);
        g.attributes.push(Attribute::new(
            "device-class",
            tags::KEYWORD,
            vec![Value::Keyword(class_.into())],
        ));
        g.attributes.push(Attribute::new(
            "device-uri",
            tags::URI,
            vec![Value::Uri(uri.into())],
        ));
        g.attributes.push(Attribute::new(
            "device-make-and-model",
            tags::TEXT,
            vec![Value::Text(mm.into())],
        ));
        g.attributes.push(Attribute::new(
            "device-info",
            tags::TEXT,
            vec![Value::Text(info.into())],
        ));
        g.attributes.push(Attribute::new(
            "device-id",
            tags::TEXT,
            vec![Value::Text(devid.into())],
        ));
    }
}

/// Sync `CUPS-Get-Devices` (0x400b) with authorization enforcement.
pub fn get_devices_sync(_req: &IppMessage, outcome: &mut DispatchOutcome, ctx: &Ctx<'_>) {
    let policy = ctx.effective_policy_for_dest(None);
    if !authorize_op(ctx, outcome, &policy, op::CUPS_GET_DEVICES, None, None) {
        return;
    }
    let out = run_helper_sync(&deviced_spec(ctx));
    emit_devices_output(outcome, out);
}

/// Async `CUPS-Get-Devices` (0x400b) — never blocks Tokio workers.
pub async fn get_devices_async(_req: &IppMessage, outcome: &mut DispatchOutcome, ctx: &Ctx<'_>) {
    let policy = ctx.effective_policy_for_dest(None);
    if !authorize_op(ctx, outcome, &policy, op::CUPS_GET_DEVICES, None, None) {
        return;
    }
    let out = run_helper_async(deviced_spec(ctx)).await;
    emit_devices_output(outcome, out);
}

fn driverd_list_spec(req: &IppMessage, ctx: &Ctx<'_>) -> HelperSpec {
    let mut opts = String::new();
    for name in [
        "ppd-device-id",
        "ppd-natural-language",
        "ppd-make",
        "ppd-make-and-model",
        "ppd-product",
        "ppd-psversion",
        "ppd-type",
        "include-schemes",
        "exclude-schemes",
    ] {
        if let Some(v) = req.find(tags::OPERATION, name).and_then(attr_text) {
            if !v.bytes().any(|b| b < 0x20 || b == 0x7f) {
                let _ = write!(opts, "{name}={v} ");
            }
        }
    }
    let limit = int_attr(req, "limit").unwrap_or(0).max(0).to_string();
    HelperSpec {
        program: ctx.server_bin.join("daemon").join("cups-driverd"),
        args: vec!["list".into(), "0".into(), limit, opts.trim().into()],
        env: ctx.driverd_env(),
        timeout: ctx.helper_timeout,
        max_stdout: MAX_HELPER_STDOUT,
    }
}

fn emit_ppds_output(outcome: &mut DispatchOutcome, out: Option<HelperOutput>) {
    let Some(out) = out else {
        send_status(
            &mut outcome.response,
            status::ERROR_INTERNAL,
            "cannot run cups-driverd",
        );
        return;
    };
    outcome.response.code = status::OK;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some(body) = line.strip_prefix("ppd ") else {
            continue;
        };
        let q = quoted_fields(body);
        let name = q.first().cloned().unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let g = outcome.response.new_group_mut(tags::PRINTER);
        let attrs = [
            ("ppd-name", tags::NAME, name),
            (
                "ppd-make-and-model",
                tags::TEXT,
                q.get(1).cloned().unwrap_or_default(),
            ),
            (
                "ppd-device-id",
                tags::TEXT,
                q.get(2).cloned().unwrap_or_default(),
            ),
            (
                "ppd-product",
                tags::TEXT,
                q.get(3).cloned().unwrap_or_default(),
            ),
            (
                "ppd-psversion",
                tags::TEXT,
                q.get(4).cloned().unwrap_or_default(),
            ),
            (
                "ppd-type",
                tags::KEYWORD,
                q.get(5).cloned().unwrap_or_default(),
            ),
            ("ppd-natural-language", tags::LANGUAGE, "en".to_string()),
        ];
        for (an, tag, av) in attrs {
            if av.is_empty() {
                continue;
            }
            g.attributes
                .push(Attribute::new(an, tag, vec![scalar_value(tag, av)]));
        }
    }
}

/// Sync `CUPS-Get-PPDs` (0x400c).
pub fn get_ppds_sync(req: &IppMessage, outcome: &mut DispatchOutcome, ctx: &Ctx<'_>) {
    let policy = ctx.effective_policy_for_dest(None);
    if !authorize_op(ctx, outcome, &policy, op::CUPS_GET_PPDS, None, None) {
        return;
    }
    let out = run_helper_sync(&driverd_list_spec(req, ctx));
    emit_ppds_output(outcome, out);
}

/// Async `CUPS-Get-PPDs` (0x400c).
pub async fn get_ppds_async(req: &IppMessage, outcome: &mut DispatchOutcome, ctx: &Ctx<'_>) {
    let policy = ctx.effective_policy_for_dest(None);
    if !authorize_op(ctx, outcome, &policy, op::CUPS_GET_PPDS, None, None) {
        return;
    }
    let out = run_helper_async(driverd_list_spec(req, ctx)).await;
    emit_ppds_output(outcome, out);
}

enum PpdResolution {
    Ready(Vec<u8>),
    Driverd(String),
}

/// Validate, authorize, and resolve `CUPS-Get-PPD` target (`file:` safely
/// contained under allowed PPD roots, or validated `cups-driverd` model name).
fn resolve_get_ppd(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
) -> Option<PpdResolution> {
    let mut target_printer: Option<String> = None;
    let name = req
        .find(tags::OPERATION, "ppd-name")
        .and_then(attr_text)
        .or_else(|| {
            req.find(tags::OPERATION, "printer-uri")
                .and_then(attr_text)
                .and_then(|u| {
                    let registry = ctx.reg();
                    registry.validate_dest(&u).map(|(p, _)| {
                        target_printer = Some(p.name.clone());
                        if ctx
                            .server_root
                            .join("ppd")
                            .join(format!("{}.ppd", p.name))
                            .is_file()
                        {
                            return format!("file:{}", p.name);
                        }
                        p.options
                            .iter()
                            .find(|(n, _)| n.eq_ignore_ascii_case("ppd-name"))
                            .map_or_else(|| "everywhere".to_string(), |(_, v)| v.clone())
                    })
                })
        });

    let policy = ctx.effective_policy_for_dest(target_printer.as_deref());
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        op::CUPS_GET_PPD,
        None,
        target_printer.as_deref(),
    ) {
        return None;
    }

    let Some(name) = name else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "No PPD name or printer PPD.",
        );
        return None;
    };

    if name.to_ascii_lowercase().starts_with("file:") {
        match resolve_safe_file_ppd(&name, &ctx.ppd_roots()) {
            Ok(bytes) => return Some(PpdResolution::Ready(bytes)),
            Err(PpdLookupError::Forbidden) => {
                send_status(
                    &mut outcome.response,
                    status::ERROR_FORBIDDEN,
                    "PPD path outside allowed directories.",
                );
                ctx.audit(
                    "CUPS-Get-PPD",
                    Some(&name),
                    "denied",
                    "PPD path traversal blocked",
                );
                return None;
            }
            Err(PpdLookupError::NotFound) => {
                send_status(
                    &mut outcome.response,
                    status::ERROR_NOT_FOUND,
                    "PPD not found.",
                );
                return None;
            }
        }
    }

    if let Err(e) = validate_driverd_ppd_name(&name) {
        send_status(&mut outcome.response, status::ERROR_FORBIDDEN, e);
        ctx.audit("CUPS-Get-PPD", Some(&name), "denied", "invalid ppd-name");
        return None;
    }
    Some(PpdResolution::Driverd(name))
}

fn driverd_cat_spec(ctx: &Ctx<'_>, name: &str) -> HelperSpec {
    HelperSpec {
        program: ctx.server_bin.join("daemon").join("cups-driverd"),
        args: vec!["cat".into(), name.into()],
        env: ctx.driverd_env(),
        timeout: ctx.helper_timeout,
        max_stdout: MAX_PPD_BYTES,
    }
}

fn fetch_ppd_sync(ctx: &Ctx<'_>, name: &str) -> Option<Vec<u8>> {
    validate_driverd_ppd_name(name).ok()?;
    let out = run_helper_sync(&driverd_cat_spec(ctx, name))?;
    out.success.then_some(out.stdout)
}

/// Sync `CUPS-Get-PPD` (0x400f).
pub fn get_ppd_sync(req: &IppMessage, outcome: &mut DispatchOutcome, ctx: &Ctx<'_>) {
    match resolve_get_ppd(req, outcome, ctx) {
        None => {}
        Some(PpdResolution::Ready(bytes)) => {
            outcome.response.code = status::OK;
            outcome.response.document = bytes;
        }
        Some(PpdResolution::Driverd(name)) => match fetch_ppd_sync(ctx, &name) {
            Some(bytes) => {
                outcome.response.code = status::OK;
                outcome.response.document = bytes;
            }
            None => send_status(
                &mut outcome.response,
                status::ERROR_NOT_FOUND,
                format!("PPD \"{name}\" not found."),
            ),
        },
    }
}

/// Async `CUPS-Get-PPD` (0x400f) — never blocks Tokio workers.
pub async fn get_ppd_async(req: &IppMessage, outcome: &mut DispatchOutcome, ctx: &Ctx<'_>) {
    match resolve_get_ppd(req, outcome, ctx) {
        None => {}
        Some(PpdResolution::Ready(bytes)) => {
            outcome.response.code = status::OK;
            outcome.response.document = bytes;
        }
        Some(PpdResolution::Driverd(name)) => {
            let fetched = run_helper_async(driverd_cat_spec(ctx, &name))
                .await
                .and_then(|o| o.success.then_some(o.stdout));
            match fetched {
                Some(bytes) => {
                    outcome.response.code = status::OK;
                    outcome.response.document = bytes;
                }
                None => send_status(
                    &mut outcome.response,
                    status::ERROR_NOT_FOUND,
                    format!("PPD \"{name}\" not found."),
                ),
            }
        }
    }
}

/// Split `"a" "b" "c"` quoted fields (handles embedded spaces).
fn quoted_fields(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inq = false;
    for c in s.chars() {
        match c {
            '"' => {
                if inq {
                    out.push(std::mem::take(&mut cur));
                }
                inq = !inq;
            }
            c if inq => cur.push(c),
            _ => {}
        }
    }
    out
}

fn scalar_value(tag: u8, s: String) -> Value {
    if tag == tags::URI {
        Value::Uri(s.into())
    } else if tag == tags::NAME {
        Value::Name(s.into())
    } else if tag == tags::KEYWORD {
        Value::Keyword(s.into())
    } else if tag == tags::LANGUAGE {
        Value::NaturalLanguage(s.into())
    } else if tag == tags::CHARSET {
        Value::Charset(s.into())
    } else {
        Value::Text(s.into())
    }
}
