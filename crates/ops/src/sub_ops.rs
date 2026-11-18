//! IPP event subscription & notification operations (RFC 3995 / RFC 3996):
//! `Create-Printer-Subscriptions`, `Create-Job-Subscriptions`,
//! `Get-Subscriptions`, `Get-Subscription-Attributes`, `Renew-Subscription`,
//! `Cancel-Subscription`, and `Get-Notifications` (non-destructive `ippget`
//! with `notify-sequence-numbers` and sync/async `notify-wait=true`).

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines
)]

use ipp_codec::{ops::op, ops::status, tags, Attribute, IppMessage, Value};
use std::time::{Duration, Instant};

use crate::async_exec::wait_notifier_async;
use crate::common::send_status;
use crate::ctx::{Ctx, DispatchOutcome};
use crate::dispatch::{attr_text, dest_name, int_attr, is_all_printers_uri};
use crate::security::{authorize_op, originating_user, should_redact_sub_attr};

/// Subscription-attribute segments inside a request, split on `IPP_TAG_ZERO`
/// separators (or separate `SUBSCRIPTION` groups).
pub fn sub_segments(req: &IppMessage) -> Vec<Vec<&Attribute>> {
    let mut segs: Vec<Vec<&Attribute>> = Vec::new();
    for g in &req.groups {
        if g.tag != tags::SUBSCRIPTION {
            continue;
        }
        let mut cur: Vec<&Attribute> = Vec::new();
        for a in &g.attributes {
            if a.is_separator() {
                if !cur.is_empty() {
                    segs.push(std::mem::take(&mut cur));
                }
            } else {
                cur.push(a);
            }
        }
        if !cur.is_empty() {
            segs.push(cur);
        }
    }
    segs
}

fn seg_find<'a>(seg: &[&'a Attribute], name: &str) -> Option<&'a Attribute> {
    seg.iter().find(|a| a.name.as_str() == name).copied()
}

fn seg_events(seg: &[&Attribute]) -> Option<Vec<events::Event>> {
    let a = seg_find(seg, "notify-events")?;
    let mut out = Vec::new();
    for v in &a.values {
        if let Value::Keyword(k) = v {
            out.push(events::Event::from_name(k.as_str().as_ref())?);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn seg_int(seg: &[&Attribute], name: &str) -> Option<i32> {
    match seg_find(seg, name).and_then(|a| a.values.first()) {
        Some(Value::Integer(i)) => Some(*i),
        _ => None,
    }
}

fn seg_subscribed(seg: &[&Attribute]) -> bool {
    seg_find(seg, "notify-recipient-uri").is_some() || seg_find(seg, "notify-pull-method").is_some()
}

fn seg_recipient_uri(seg: &[&Attribute]) -> Option<String> {
    seg_find(seg, "notify-recipient-uri").and_then(attr_text)
}

fn seg_user_data(seg: &[&Attribute]) -> Option<Vec<u8>> {
    match seg_find(seg, "notify-user-data").and_then(|a| a.first()) {
        Some(Value::OctetString(b)) => Some(b.clone()),
        _ => None,
    }
}

/// Emit `notify-subscription-id` (+ effective lease) as a fresh subscription group.
fn emit_sub_id(resp: &mut IppMessage, id: i32, lease_out: i32) {
    let g = resp.new_group_mut(tags::SUBSCRIPTION);
    g.attributes.push(Attribute::new(
        "notify-subscription-id",
        tags::INTEGER,
        vec![Value::Integer(id)],
    ));
    g.attributes.push(Attribute::new(
        "notify-lease-duration",
        tags::INTEGER,
        vec![Value::Integer(lease_out)],
    ));
}

/// Enforce `MaxSubscriptions`, `MaxSubscriptionsPerJob`,
/// `MaxSubscriptionsPerPrinter`, and `MaxSubscriptionsPerUser`.
fn check_sub_limits(
    ctx: &Ctx<'_>,
    printer: Option<&str>,
    job_id: Option<i32>,
    owner: &str,
) -> bool {
    let subs = ctx.subs();
    if ctx.max_subscriptions > 0 && subs.count() >= ctx.max_subscriptions as usize {
        return false;
    }
    let live = subs.list(None, None);
    if ctx.max_subscriptions_per_user > 0 {
        let n = live
            .iter()
            .filter(|s| s.owner.eq_ignore_ascii_case(owner))
            .count();
        if n >= ctx.max_subscriptions_per_user as usize {
            return false;
        }
    }
    if let Some(p) = printer {
        if ctx.max_subscriptions_per_printer > 0 {
            let n = live
                .iter()
                .filter(|s| s.printer.as_deref() == Some(p))
                .count();
            if n >= ctx.max_subscriptions_per_printer as usize {
                return false;
            }
        }
    }
    if let Some(jid) = job_id {
        if ctx.max_subscriptions_per_job > 0 {
            let n = live.iter().filter(|s| s.job_id == Some(jid)).count();
            if n >= ctx.max_subscriptions_per_job as usize {
                return false;
            }
        }
    }
    true
}

/// Embedded job subscription attached to `Print-Job`/`Create-Job`/`Print-URI`
/// (RFC 3995 §5.1.2).
pub fn maybe_add_job_subscription(
    req: &IppMessage,
    resp: &mut IppMessage,
    ctx: &Ctx<'_>,
    job_id: i32,
    dest: &str,
) {
    let segs = sub_segments(req);
    if segs.is_empty() {
        return;
    }
    let owner = originating_user(req, ctx);
    let mut created_any = false;
    for seg in segs {
        if !seg_subscribed(&seg) {
            continue;
        }
        if seg_find(&seg, "notify-lease-duration").is_some() {
            send_status(
                resp,
                status::ERROR_BAD_REQUEST,
                "notify-lease-duration cannot be used with job subscriptions.",
            );
            return;
        }
        let ev = seg_events(&seg).unwrap_or_else(|| vec![events::Event::JobCompleted]);
        if !check_sub_limits(ctx, Some(dest), Some(job_id), &owner) {
            break;
        }
        let recipient = seg_recipient_uri(&seg);
        let mut subs = ctx.subs_write();
        subs.set_lease_limits(ctx.default_lease_duration, ctx.max_lease_duration);
        let id = subs.add_with_recipient(
            Some(dest.to_string()),
            Some(job_id),
            ev,
            owner.clone(),
            events::NEVER_EXPIRE,
            seg_user_data(&seg),
            recipient,
        );
        drop(subs);
        emit_sub_id(resp, id, 0);
        created_any = true;
    }
    if created_any {
        ctx.save_subscriptions();
    }
}

/// `Create-Printer-Subscriptions` / `Create-Job-Subscriptions`.
pub fn create_subscription(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let job_sub = req.code == op::CREATE_JOB_SUBSCRIPTIONS;
    let uri_opt = uri_attr.and_then(attr_text);
    let printer = if job_sub {
        None
    } else {
        uri_opt
            .as_deref()
            .filter(|u| !is_all_printers_uri(u))
            .and_then(dest_name)
    };

    let (job_id, job_owner, policy_dest) = if job_sub {
        let Some(id) = crate::jobs_ops::job_id(req, uri_attr) else {
            let policy = ctx.effective_policy_for_dest(None);
            if !authorize_op(ctx, outcome, &policy, req.code, None, None) {
                return;
            }
            send_status(
                &mut outcome.response,
                status::ERROR_BAD_REQUEST,
                "Missing job-id or job-uri.",
            );
            return;
        };
        let job_meta = ctx
            .jobs_read()
            .get(id)
            .map(|j| (j.username.clone(), j.dest.clone()));
        let Some((owner, dest)) = job_meta else {
            let policy = ctx.effective_policy_for_dest(None);
            if !authorize_op(ctx, outcome, &policy, req.code, None, None) {
                return;
            }
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_FOUND,
                "Job not found.",
            );
            return;
        };
        (Some(id), Some(owner), Some(dest))
    } else {
        (None, None, printer.clone())
    };

    let policy = ctx.effective_policy_for_dest(policy_dest.as_deref());
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        req.code,
        job_owner.as_deref(),
        policy_dest.as_deref(),
    ) {
        return;
    }

    let segs = sub_segments(req);
    if segs.is_empty() {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "No subscription attributes in request.",
        );
        return;
    }

    let owner = originating_user(req, ctx);
    outcome.response.code = status::ERROR_BAD_REQUEST;
    let mut created_any = false;

    for seg in segs {
        if !seg_subscribed(&seg) {
            break;
        }
        let ev = match seg_events(&seg) {
            Some(e) => e,
            None if job_id.is_some() => vec![events::Event::JobCompleted],
            None if printer.is_some() => vec![events::Event::PrinterStateChanged],
            None => {
                send_status(
                    &mut outcome.response,
                    status::ERROR_BAD_REQUEST,
                    "notify-events not specified.",
                );
                return;
            }
        };
        let requested_lease = if job_sub {
            events::NEVER_EXPIRE
        } else {
            seg_int(&seg, "notify-lease-duration").unwrap_or(ctx.default_lease_duration)
        };
        if !check_sub_limits(ctx, policy_dest.as_deref(), job_id, &owner) {
            send_status(
                &mut outcome.response,
                status::ERROR_TOO_MANY_SUBSCRIPTIONS,
                "Too many subscriptions.",
            );
            return;
        }
        let recipient = seg_recipient_uri(&seg);
        let (id, effective_lease) = {
            let mut subs = ctx.subs_write();
            subs.set_lease_limits(ctx.default_lease_duration, ctx.max_lease_duration);
            let effective = subs.clamp_lease_duration(requested_lease);
            let id = subs.add_with_recipient(
                policy_dest.clone(),
                job_id,
                ev,
                owner.clone(),
                requested_lease,
                seg_user_data(&seg),
                recipient,
            );
            (id, effective)
        };
        emit_sub_id(&mut outcome.response, id, effective_lease);
        outcome.response.code = status::OK;
        created_any = true;
    }
    if created_any {
        ctx.save_subscriptions();
        ctx.audit(
            op::name(req.code),
            policy_dest.as_deref(),
            "allowed",
            format!("subscription(s) created by {owner}"),
        );
    }
}

/// Emit a FRESH `tags::SUBSCRIPTION` group per subscription (`cupsdCopySubscription`),
/// enforcing `SubscriptionPrivateValues` / `SubscriptionPrivateAccess`.
pub fn add_sub_group(resp: &mut IppMessage, s: &events::Subscription, ctx: &Ctx<'_>, policy: &str) {
    let g = resp.new_group_mut(tags::SUBSCRIPTION);
    let mut add = |name: &str, tag: u8, vals: Vec<Value>| {
        if !should_redact_sub_attr(ctx, policy, &s.owner, name) {
            g.attributes.push(Attribute::new(name, tag, vals));
        }
    };

    let evs: Vec<Value> = s
        .event_names()
        .iter()
        .map(|e| Value::Keyword(e.clone().into()))
        .collect();
    add("notify-events", tags::KEYWORD, evs);
    add(
        "notify-subscription-id",
        tags::INTEGER,
        vec![Value::Integer(s.id)],
    );
    add(
        "notify-subscriber-user-name",
        tags::NAME,
        vec![Value::Name(s.owner.clone().into())],
    );
    add(
        "notify-lease-duration",
        tags::INTEGER,
        vec![Value::Integer(s.lease_remaining())],
    );
    if let Some(ref r) = s.recipient_uri {
        add(
            "notify-recipient-uri",
            tags::URI,
            vec![Value::Uri(r.clone().into())],
        );
    } else {
        add(
            "notify-pull-method",
            tags::KEYWORD,
            vec![Value::Keyword("ippget".into())],
        );
    }
    if let Some(p) = &s.printer {
        let scheme = if ctx.is_encrypted { "ipps" } else { "ipp" };
        add(
            "notify-printer-uri",
            tags::URI,
            vec![Value::Uri(
                format!("{scheme}://{}:{}/printers/{p}", ctx.hostname, ctx.port).into(),
            )],
        );
    }
    if let Some(j) = s.job_id {
        add("notify-job-id", tags::INTEGER, vec![Value::Integer(j)]);
    }
    if let Some(d) = &s.user_data {
        add(
            "notify-user-data",
            tags::STRING,
            vec![Value::OctetString(d.clone())],
        );
    }
}

/// `Get-Subscriptions`.
pub fn get_subscriptions(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let uri_opt = uri_attr.and_then(attr_text);
    let printer = uri_opt
        .as_deref()
        .filter(|u| !is_all_printers_uri(u))
        .and_then(dest_name);
    let policy = ctx.effective_policy_for_dest(printer.as_deref());
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        op::GET_SUBSCRIPTIONS,
        None,
        printer.as_deref(),
    ) {
        return;
    }

    ctx.subs_write().expire();

    let my_subs = req
        .find(tags::OPERATION, "my-subscriptions")
        .is_some_and(|a| matches!(a.first(), Some(Value::Boolean(true))));
    let owner_filter = if my_subs {
        Some(originating_user(req, ctx))
    } else {
        None
    };
    let limit = int_attr(req, "limit")
        .filter(|&l| l > 0)
        .map_or(usize::MAX, |l| l as usize);

    let list: Vec<events::Subscription> = {
        let guard = ctx.subs();
        guard
            .list(printer.as_deref(), owner_filter.as_deref())
            .into_iter()
            .take(limit)
            .cloned()
            .collect()
    };

    outcome.response.code = status::OK;
    for s in &list {
        let sub_policy = ctx.effective_policy_for_dest(s.printer.as_deref());
        add_sub_group(&mut outcome.response, s, ctx, &sub_policy);
    }
}

/// `Get-Subscription-Attributes`.
pub fn get_subscription_attrs(req: &IppMessage, outcome: &mut DispatchOutcome, ctx: &Ctx<'_>) {
    let Some(id) = int_attr(req, "notify-subscription-id").map(|i| i as i32) else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing notify-subscription-id.",
        );
        return;
    };
    ctx.subs_write().expire();
    let sub = ctx.subs().find(id).cloned();
    let Some(s) = sub else {
        let policy = ctx.effective_policy_for_dest(None);
        if !authorize_op(
            ctx,
            outcome,
            &policy,
            op::GET_SUBSCRIPTION_ATTRIBUTES,
            None,
            None,
        ) {
            return;
        }
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            format!("Subscription #{id} not found."),
        );
        return;
    };
    let policy = ctx.effective_policy_for_dest(s.printer.as_deref());
    let target = format!("subscription/{id}");
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        op::GET_SUBSCRIPTION_ATTRIBUTES,
        Some(&s.owner),
        Some(&target),
    ) {
        return;
    }
    outcome.response.code = status::OK;
    add_sub_group(&mut outcome.response, &s, ctx, &policy);
}

/// `Renew-Subscription`.
pub fn renew_subscription(req: &IppMessage, outcome: &mut DispatchOutcome, ctx: &Ctx<'_>) {
    let Some(id) = int_attr(req, "notify-subscription-id").map(|i| i as i32) else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing notify-subscription-id.",
        );
        return;
    };
    ctx.subs_write().expire();
    let sub = ctx.subs().find(id).cloned();
    let Some(s) = sub else {
        let policy = ctx.effective_policy_for_dest(None);
        if !authorize_op(ctx, outcome, &policy, op::RENEW_SUBSCRIPTION, None, None) {
            return;
        }
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            format!("Subscription #{id} not found."),
        );
        return;
    };
    let policy = ctx.effective_policy_for_dest(s.printer.as_deref());
    let target = format!("subscription/{id}");
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        op::RENEW_SUBSCRIPTION,
        Some(&s.owner),
        Some(&target),
    ) {
        return;
    }
    let req_lease = int_attr(req, "notify-lease-duration").map(|v| v as i32);
    let renewed = {
        let mut subs = ctx.subs_write();
        subs.set_lease_limits(ctx.default_lease_duration, ctx.max_lease_duration);
        subs.renew_with_duration(id, req_lease)
    };
    if let Some(new_lease) = renewed {
        ctx.save_subscriptions();
        ctx.audit(
            "Renew-Subscription",
            Some(&target),
            "allowed",
            format!("lease={new_lease}"),
        );
        outcome.response.code = status::OK;
        emit_sub_id(&mut outcome.response, id, new_lease);
    } else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            format!("Subscription #{id} not found."),
        );
    }
}

/// `Cancel-Subscription`.
pub fn cancel_subscription(req: &IppMessage, outcome: &mut DispatchOutcome, ctx: &Ctx<'_>) {
    let Some(id) = int_attr(req, "notify-subscription-id").map(|i| i as i32) else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing notify-subscription-id.",
        );
        return;
    };
    ctx.subs_write().expire();
    let sub = ctx.subs().find(id).cloned();
    let Some(s) = sub else {
        let policy = ctx.effective_policy_for_dest(None);
        if !authorize_op(ctx, outcome, &policy, op::CANCEL_SUBSCRIPTION, None, None) {
            return;
        }
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            format!("Subscription #{id} not found."),
        );
        return;
    };
    let policy = ctx.effective_policy_for_dest(s.printer.as_deref());
    let target = format!("subscription/{id}");
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        op::CANCEL_SUBSCRIPTION,
        Some(&s.owner),
        Some(&target),
    ) {
        return;
    }
    if ctx.subs_write().remove(id).is_some() {
        ctx.save_subscriptions();
        ctx.audit("Cancel-Subscription", Some(&target), "allowed", "canceled");
        outcome.response.code = status::OK;
    } else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            format!("Subscription #{id} not found."),
        );
    }
}

struct ParsedNotifyReq {
    pairs: Vec<(i32, i32)>,
    notify_wait: bool,
}

/// Parse and authorize a `Get-Notifications` request.
fn prepare_get_notifications(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
) -> Option<ParsedNotifyReq> {
    let ids: Vec<i32> = req
        .find(tags::OPERATION, "notify-subscription-ids")
        .map(|a| {
            a.values
                .iter()
                .filter_map(|v| match v {
                    Value::Integer(i) | Value::Enum(i) => Some(*i),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    if ids.is_empty() {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing notify-subscription-ids.",
        );
        return None;
    }
    let seqs: Vec<i32> = req
        .find(tags::OPERATION, "notify-sequence-numbers")
        .map(|a| {
            a.values
                .iter()
                .filter_map(|v| match v {
                    Value::Integer(i) | Value::Enum(i) => Some(*i),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let notify_wait = req
        .find(tags::OPERATION, "notify-wait")
        .is_some_and(|a| matches!(a.first(), Some(Value::Boolean(true))));

    ctx.subs_write().expire();

    // Check existence and authorize each live subscription.
    let mut found_live = false;
    let mut pairs = Vec::with_capacity(ids.len());
    for (idx, &id) in ids.iter().enumerate() {
        let sub = ctx.subs().find(id).cloned();
        if let Some(s) = sub {
            found_live = true;
            let policy = ctx.effective_policy_for_dest(s.printer.as_deref());
            let target = format!("subscription/{id}");
            if !authorize_op(
                ctx,
                outcome,
                &policy,
                op::GET_NOTIFICATIONS,
                Some(&s.owner),
                Some(&target),
            ) {
                return None;
            }
            let first_seq = seqs.get(idx).copied().unwrap_or(1).max(1);
            pairs.push((id, first_seq));
        }
    }
    if !found_live {
        let policy = ctx.effective_policy_for_dest(None);
        if !authorize_op(ctx, outcome, &policy, op::GET_NOTIFICATIONS, None, None) {
            return None;
        }
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "No matching subscriptions found.",
        );
        return None;
    }
    Some(ParsedNotifyReq { pairs, notify_wait })
}

/// Snapshot non-destructive notifications across `pairs` along with the
/// notifier handle & generation version for race-free waiting.
fn collect_notifications(
    ctx: &Ctx<'_>,
    pairs: &[(i32, i32)],
) -> (Vec<(i32, events::Notification)>, u64, events::EventNotifier) {
    let subs = ctx.subs();
    let notifier = subs.notifier();
    let ver = notifier.version();
    let mut out = Vec::new();
    for &(id, first_seq) in pairs {
        for n in subs.get_notifications_from(id, first_seq) {
            out.push((id, n));
        }
    }
    (out, ver, notifier)
}

fn emit_notifications_response(
    resp: &mut IppMessage,
    ctx: &Ctx<'_>,
    notes: Vec<(i32, events::Notification)>,
) {
    resp.code = status::OK;
    let op_g = resp.group_mut(tags::OPERATION);
    op_g.attributes.push(Attribute::new(
        "notify-get-interval",
        tags::INTEGER,
        vec![Value::Integer(15)],
    ));
    let scheme = if ctx.is_encrypted { "ipps" } else { "ipp" };
    for (id, n) in notes {
        let g = resp.new_group_mut(tags::EVENT_NOTIFICATION);
        let mut add = |name: &str, tag: u8, v: Value| {
            g.attributes.push(Attribute::new(name, tag, vec![v]));
        };
        add("notify-subscription-id", tags::INTEGER, Value::Integer(id));
        add(
            "notify-sequence-number",
            tags::INTEGER,
            Value::Integer(n.seq),
        );
        add(
            "notify-subscribed-event",
            tags::KEYWORD,
            Value::Keyword(n.event.name().into()),
        );
        add(
            "notify-event",
            tags::KEYWORD,
            Value::Keyword(n.event.name().into()),
        );
        add(
            "printer-up-time",
            tags::INTEGER,
            Value::Integer(n.time as i32),
        );
        if let Some(p) = &n.printer {
            add(
                "notify-printer-uri",
                tags::URI,
                Value::Uri(format!("{scheme}://{}:{}/printers/{p}", ctx.hostname, ctx.port).into()),
            );
            add("printer-name", tags::NAME, Value::Name(p.clone().into()));
        }
        if let Some(j) = n.job_id {
            add("notify-job-id", tags::INTEGER, Value::Integer(j));
        }
        if let Some(js) = n.job_state {
            add("job-state", tags::ENUM, Value::Enum(js));
        }
        add(
            "notify-text",
            tags::TEXT,
            Value::Text(n.text.clone().into()),
        );
    }
}

/// Synchronous `Get-Notifications` — non-destructive `ippget` pull with
/// bounded `notify-wait=true` using `EventNotifier::wait_timeout`.
pub fn get_notifications_sync(req: &IppMessage, outcome: &mut DispatchOutcome, ctx: &Ctx<'_>) {
    let Some(parsed) = prepare_get_notifications(req, outcome, ctx) else {
        return;
    };
    let max_wait = ctx.notify_wait_timeout.min(Duration::from_secs(60));
    let deadline = Instant::now() + max_wait;

    loop {
        let (notes, ver, notifier) = collect_notifications(ctx, &parsed.pairs);
        if !notes.is_empty() || !parsed.notify_wait {
            emit_notifications_response(&mut outcome.response, ctx, notes);
            return;
        }
        let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
            emit_notifications_response(&mut outcome.response, ctx, Vec::new());
            return;
        };
        if notifier.wait_timeout(ver, rem).is_none() {
            let (final_notes, _, _) = collect_notifications(ctx, &parsed.pairs);
            emit_notifications_response(&mut outcome.response, ctx, final_notes);
            return;
        }
    }
}

/// Asynchronous `Get-Notifications` — non-destructive `ippget` pull with
/// non-blocking `notify-wait=true` awaiting `EventNotifier::notified`.
pub async fn get_notifications_async(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
) {
    let Some(parsed) = prepare_get_notifications(req, outcome, ctx) else {
        return;
    };
    let max_wait = ctx.notify_wait_timeout.min(Duration::from_secs(60));
    let deadline = Instant::now() + max_wait;

    loop {
        let (notes, ver, notifier) = collect_notifications(ctx, &parsed.pairs);
        if !notes.is_empty() || !parsed.notify_wait {
            emit_notifications_response(&mut outcome.response, ctx, notes);
            return;
        }
        let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
            emit_notifications_response(&mut outcome.response, ctx, Vec::new());
            return;
        };
        if wait_notifier_async(&notifier, ver, rem).await.is_none() {
            let (final_notes, _, _) = collect_notifications(ctx, &parsed.pairs);
            emit_notifications_response(&mut outcome.response, ctx, final_notes);
            return;
        }
    }
}
