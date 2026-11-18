//! Authorization, privacy redaction (`JobPrivate*` / `SubscriptionPrivate*`),
//! user ACL (`AllowUser` / `DenyUser`), and job quota/limit enforcement.

use authz::{AccessDecision, Subject};
use cups_config::Policy;
use ipp_codec::{ops::op, ops::status, tags, IppMessage};
use printer::{Printer, ValidationError};

use crate::common::send_status;
use crate::ctx::{Ctx, DispatchOutcome};

/// Default `JobPrivateValues` list when a policy specifies `default`.
const DEFAULT_JOB_PRIVATE_VALUES: &[&str] = &[
    "job-name",
    "job-originating-host-name",
    "job-originating-user-name",
    "phone",
];

/// Core identifying job attributes retained even under `JobPrivateValues all`.
const CORE_PUBLIC_JOB_ATTRS: &[&str] = &[
    "job-id",
    "job-uri",
    "job-printer-uri",
    "job-state",
    "job-state-reasons",
    "job-printer-up-time",
];

/// Default `SubscriptionPrivateValues` list when a policy specifies `default`.
const DEFAULT_SUB_PRIVATE_VALUES: &[&str] = &[
    "notify-events",
    "notify-pull-method",
    "notify-recipient-uri",
    "notify-subscriber-user-name",
    "notify-user-data",
];

/// Core identifying subscription attributes retained even under
/// `SubscriptionPrivateValues all`.
const CORE_PUBLIC_SUB_ATTRS: &[&str] = &[
    "notify-subscription-id",
    "notify-lease-duration",
    "notify-printer-uri",
    "notify-job-id",
];

/// Canonical fallback policy op for operations omitted from synthesized default
/// policies, ensuring they never silently fall through to anonymous `<Limit All>`.
fn fallback_policy_op(op_code: u16) -> Option<u32> {
    match op_code {
        op::CANCEL_DOCUMENT => Some(u32::from(op::CANCEL_JOB)),
        op::SET_DOCUMENT_ATTRIBUTES => Some(u32::from(op::SET_JOB_ATTRIBUTES)),
        op::RESUBMIT_JOB => Some(u32::from(op::RESTART_JOB)),
        op::CUPS_CREATE_LOCAL_PRINTER => Some(u32::from(op::CUPS_ADD_MODIFY_PRINTER)),
        _ => None,
    }
}

/// Build an `authz::Subject` strictly from verified session state:
/// - `user` is ONLY `ctx.username` (NEVER untrusted IPP `requesting-user-name`!)
/// - `host` is ONLY `ctx.peer_host` (NEVER attacker-controlled HTTP `Host:`!)
#[must_use]
pub fn authz_subject<'a>(ctx: &'a Ctx<'_>) -> Subject<'a> {
    Subject {
        user: ctx.username.as_deref(),
        groups: &ctx.user_groups,
        system_groups: &ctx.system_groups,
        addr: ctx.client_addr,
        host: ctx.peer_host_for_authz(),
        encrypted: ctx.is_encrypted,
    }
}

/// Evaluate an IPP operation against the resolved `<Policy>` using fail-closed
/// `authz::check_op`.
#[must_use]
pub fn evaluate_op_decision(
    ctx: &Ctx<'_>,
    policy_name: &str,
    op_code: u16,
    owner: Option<&str>,
) -> AccessDecision {
    let subj = authz_subject(ctx);
    let op_u32 = u32::from(op_code);

    // If the resolved policy has no explicit `<Limit>` for this op, check
    // whether a canonical fallback op applies (e.g. Cancel-Document -> Cancel-Job)
    // before falling through to `<Limit All>`.
    if let Some(fallback) = fallback_policy_op(op_code) {
        if let Some(pol) = ctx.policy_defs.iter().find(|p| p.name == policy_name) {
            let has_explicit = pol.ops.iter().any(|p| p.op == op_u32);
            if !has_explicit {
                return authz::check_op(ctx.policy_defs, Some(policy_name), fallback, &subj, owner);
            }
        }
    }

    authz::check_op(ctx.policy_defs, Some(policy_name), op_u32, &subj, owner)
}

/// Authorize `op_code` against `policy_name` (and optional resource `owner`).
///
/// On denial, writes the appropriate IPP error status (`ERROR_NOT_AUTHENTICATED`,
/// `ERROR_CUPS_UPGRADE_REQUIRED`, or `ERROR_FORBIDDEN`), updates `outcome`
/// (`need_auth`, `auth_type`, `upgrade_required`), emits an audit record, and
/// returns `false`.
pub fn authorize_op(
    ctx: &Ctx<'_>,
    outcome: &mut DispatchOutcome,
    policy_name: &str,
    op_code: u16,
    owner: Option<&str>,
    target: Option<&str>,
) -> bool {
    let op_name = op::name(op_code);
    match evaluate_op_decision(ctx, policy_name, op_code, owner) {
        AccessDecision::Allowed => true,
        AccessDecision::AuthRequired(at) => {
            outcome.need_auth = true;
            outcome.auth_type = Some(at);
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_AUTHENTICATED,
                "Authentication required.",
            );
            ctx.audit(
                op_name,
                target,
                "auth-required",
                format!("policy={policy_name} auth_type={at:?}"),
            );
            false
        }
        AccessDecision::UpgradeRequired => {
            outcome.upgrade_required = true;
            send_status(
                &mut outcome.response,
                status::ERROR_CUPS_UPGRADE_REQUIRED,
                "Encryption required.",
            );
            ctx.audit(
                op_name,
                target,
                "upgrade-required",
                format!("policy={policy_name} TLS required"),
            );
            false
        }
        AccessDecision::Forbidden => {
            send_status(
                &mut outcome.response,
                status::ERROR_FORBIDDEN,
                "You do not have permission to access this resource.",
            );
            ctx.audit(
                op_name,
                target,
                "denied",
                format!("policy={policy_name} forbidden"),
            );
            false
        }
    }
}

/// Find the `<Policy>` definition by name (falling back to `"default"`).
fn find_policy<'a>(ctx: &'a Ctx<'_>, policy_name: &str) -> Option<&'a Policy> {
    ctx.policy_defs
        .iter()
        .find(|p| p.name == policy_name)
        .or_else(|| ctx.policy_defs.iter().find(|p| p.name == "default"))
}

/// Evaluate a `JobPrivateAccess` or `SubscriptionPrivateAccess` token list.
fn has_private_access(ctx: &Ctx<'_>, access_list: &[String], owner: &str) -> bool {
    let tokens: Vec<&str> = if access_list.is_empty() {
        vec!["@OWNER", "@SYSTEM"]
    } else {
        access_list.iter().map(String::as_str).collect()
    };

    for tok in tokens {
        if tok.eq_ignore_ascii_case("all") {
            return true;
        }
        if tok.eq_ignore_ascii_case("none") {
            continue;
        }
        if tok.eq_ignore_ascii_case("default") {
            if ctx.username.as_deref() == Some(owner) || ctx.is_system_admin() {
                return true;
            }
            continue;
        }
        if tok == "@OWNER" {
            if ctx.username.as_deref() == Some(owner) {
                return true;
            }
            continue;
        }
        if tok == "@SYSTEM" {
            if ctx.is_system_admin() {
                return true;
            }
            continue;
        }
        if let Some(group) = tok.strip_prefix('@') {
            if ctx.username.is_some()
                && !group.is_empty()
                && ctx.user_groups.iter().any(|g| g == group)
            {
                return true;
            }
            continue;
        }
        if ctx.username.as_deref() == Some(tok) {
            return true;
        }
    }
    false
}

/// True if `attr_name` should be redacted from a job response for this caller.
#[must_use]
pub fn should_redact_job_attr(
    ctx: &Ctx<'_>,
    policy_name: &str,
    job_owner: &str,
    attr_name: &str,
) -> bool {
    let Some(pol) = find_policy(ctx, policy_name) else {
        // Fail closed on private attributes if policy missing.
        if ctx.username.as_deref() == Some(job_owner) || ctx.is_system_admin() {
            return false;
        }
        return DEFAULT_JOB_PRIVATE_VALUES
            .iter()
            .any(|v| v.eq_ignore_ascii_case(attr_name));
    };
    if has_private_access(ctx, &pol.job_access, job_owner) {
        return false;
    }
    matches_private_value_list(
        &pol.job_values,
        attr_name,
        DEFAULT_JOB_PRIVATE_VALUES,
        CORE_PUBLIC_JOB_ATTRS,
    )
}

/// True if `attr_name` should be redacted from a subscription response for this caller.
#[must_use]
pub fn should_redact_sub_attr(
    ctx: &Ctx<'_>,
    policy_name: &str,
    sub_owner: &str,
    attr_name: &str,
) -> bool {
    let Some(pol) = find_policy(ctx, policy_name) else {
        if ctx.username.as_deref() == Some(sub_owner) || ctx.is_system_admin() {
            return false;
        }
        return DEFAULT_SUB_PRIVATE_VALUES
            .iter()
            .any(|v| v.eq_ignore_ascii_case(attr_name));
    };
    if has_private_access(ctx, &pol.sub_access, sub_owner) {
        return false;
    }
    matches_private_value_list(
        &pol.sub_values,
        attr_name,
        DEFAULT_SUB_PRIVATE_VALUES,
        CORE_PUBLIC_SUB_ATTRS,
    )
}

fn matches_private_value_list(
    values: &[String],
    attr_name: &str,
    defaults: &[&str],
    core_public: &[&str],
) -> bool {
    if values.is_empty() {
        return false;
    }
    for v in values {
        if v.eq_ignore_ascii_case("none") {
            return false;
        }
        if v.eq_ignore_ascii_case("all") {
            return !core_public
                .iter()
                .any(|c| c.eq_ignore_ascii_case(attr_name));
        }
        if v.eq_ignore_ascii_case("default") {
            if defaults.iter().any(|d| d.eq_ignore_ascii_case(attr_name)) {
                return true;
            }
            continue;
        }
        if v.eq_ignore_ascii_case(attr_name) {
            return true;
        }
    }
    false
}

/// Check per-printer `AllowUser` / `DenyUser` ACL.
/// `@SYSTEM` administrators bypass per-queue user restrictions (matching CUPS).
/// Supports `@group` entries against `ctx.user_groups` when authenticated.
#[must_use]
pub fn check_printer_user_allowed(ctx: &Ctx<'_>, printer: &Printer, user: &str) -> bool {
    if printer.users.is_empty() || ctx.is_system_admin() {
        return true;
    }
    let matches_entry = |entry: &str| -> bool {
        if entry == "@ALL" {
            return true;
        }
        if let Some(group) = entry.strip_prefix('@') {
            return ctx.username.is_some()
                && !group.is_empty()
                && ctx.user_groups.iter().any(|g| g == group);
        }
        entry.eq_ignore_ascii_case(user)
    };
    let listed = printer.users.iter().any(|u| matches_entry(u));
    if printer.deny_users {
        !listed
    } else {
        listed
    }
}

/// Determine job/subscription originating user metadata (NOT for authorization!).
/// Uses verified `ctx.username` whenever authenticated, falling back to IPP
/// `requesting-user-name` only when policy permitted an unauthenticated request.
#[must_use]
pub fn originating_user(req: &IppMessage, ctx: &Ctx<'_>) -> String {
    ctx.username
        .clone()
        .or_else(|| {
            req.find(tags::OPERATION, "requesting-user-name")
                .and_then(|a| a.text().map(std::borrow::Cow::into_owned))
        })
        .or_else(|| ctx.requesting_user.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "anonymous".into())
}

/// Validate a `device-uri` against `printer::validate_device_uri` and `FileDevice`.
pub fn validate_device_uri_for_ctx(uri: &str, ctx: &Ctx<'_>) -> Result<(), (u16, String)> {
    let allow_file = ctx.file_device.is_some();
    printer::validate_device_uri(uri, allow_file).map_err(|e| match e {
        ValidationError::FileDeviceDisallowed => (
            status::ERROR_NOT_POSSIBLE,
            "File device URIs have been disabled by FileDevice policy.".into(),
        ),
        other => (
            status::ERROR_BAD_REQUEST,
            format!("Bad device-uri: {other}"),
        ),
    })
}

/// Enforce `MaxJobs`, `MaxJobsPerPrinter`, `MaxJobsPerUser`, `MaxCopies`, and
/// per-printer `job-quota-period` / `job-k-limit` / `job-page-limit`.
pub fn check_job_limits_and_quotas(
    ctx: &Ctx<'_>,
    printer: &Printer,
    user: &str,
    incoming_bytes: u64,
    copies: i32,
) -> Result<(), (u16, String)> {
    if copies < 1 || (ctx.max_copies > 0 && copies > ctx.max_copies) {
        return Err((
            status::ERROR_ATTRIBUTES_OR_VALUES,
            format!("Bad copies value {copies} (max {}).", ctx.max_copies),
        ));
    }

    let jobs = ctx.jobs_read();
    let mut total_active = 0i32;
    let mut printer_active = 0i32;
    let mut user_active = 0i32;

    let now_s = printer::now();
    let window_start = if printer.quota_period > 0 {
        now_s.saturating_sub(i64::from(printer.quota_period))
    } else {
        i64::MIN
    };
    let mut user_k_used: u64 = 0;
    let mut user_pages_used: u64 = 0;

    for j in jobs.by_id.values() {
        if !j.state.is_final() {
            total_active = total_active.saturating_add(1);
            if j.dest == printer.name {
                printer_active = printer_active.saturating_add(1);
            }
            if j.username.eq_ignore_ascii_case(user) {
                user_active = user_active.saturating_add(1);
            }
        }
        if j.dest == printer.name
            && j.username.eq_ignore_ascii_case(user)
            && j.created_at >= window_start
        {
            let bytes: u64 = j.files.iter().map(|f| f.size).sum();
            user_k_used = user_k_used.saturating_add(bytes.div_ceil(1024));
            let pages = u64::try_from(j.copies.max(1)).unwrap_or(1);
            user_pages_used = user_pages_used.saturating_add(pages);
        }
    }

    if ctx.max_jobs > 0 && total_active >= ctx.max_jobs {
        return Err((
            status::ERROR_TOO_MANY_JOBS,
            "Too many jobs on server.".into(),
        ));
    }
    if ctx.max_jobs_per_printer > 0 && printer_active >= ctx.max_jobs_per_printer {
        return Err((
            status::ERROR_TOO_MANY_JOBS,
            format!("Too many jobs on printer \"{}\".", printer.name),
        ));
    }
    if ctx.max_jobs_per_user > 0 && user_active >= ctx.max_jobs_per_user {
        return Err((
            status::ERROR_TOO_MANY_JOBS,
            format!("Too many jobs for user \"{user}\"."),
        ));
    }

    if printer.k_limit > 0 {
        let limit = u64::try_from(printer.k_limit).unwrap_or(u64::MAX);
        let inc_k = incoming_bytes.div_ceil(1024);
        if user_k_used.saturating_add(inc_k) > limit {
            return Err((
                status::ERROR_NOT_POSSIBLE,
                "Quota limit reached (job-k-limit exceeded).".into(),
            ));
        }
    }
    if printer.page_limit > 0 {
        let limit = u64::try_from(printer.page_limit).unwrap_or(u64::MAX);
        let inc_pages = u64::try_from(copies.max(1)).unwrap_or(1);
        if user_pages_used.saturating_add(inc_pages) > limit {
            return Err((
                status::ERROR_NOT_POSSIBLE,
                "Quota limit reached (job-page-limit exceeded).".into(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cups_config::{Config, CupsFilesConfig, CupsdConfig};
    use events::Subscriptions;
    use job::Jobs;
    use mime_db::MimeDb;
    use printer::Registry;
    use std::sync::RwLock;

    #[test]
    fn missing_policy_redacts_private_attrs_fail_closed_and_bad_copies_rejected() {
        let cfg = Config {
            cupsd: CupsdConfig::defaults(),
            files: CupsFilesConfig::defaults(),
        };
        let reg = RwLock::new(Registry::default());
        let jobs = RwLock::new(Jobs::default());
        let mime = MimeDb::default();
        let subs = RwLock::new(Subscriptions::new());
        let dnssd = RwLock::new(None);
        let mut ctx = Ctx::new(&reg, &cfg, 631, &jobs, &mime, &subs, &dnssd);

        // Outsider: default private attrs redacted fail-closed when policy missing.
        ctx.username = Some("bob".into());
        assert!(should_redact_job_attr(&ctx, "missing", "alice", "job-name"));
        assert!(!should_redact_job_attr(&ctx, "missing", "alice", "job-id"));
        assert!(should_redact_sub_attr(
            &ctx,
            "missing",
            "alice",
            "notify-user-data"
        ));
        assert!(!should_redact_sub_attr(
            &ctx,
            "missing",
            "alice",
            "notify-subscription-id"
        ));

        // Owner sees own private attrs even when policy missing.
        ctx.username = Some("alice".into());
        assert!(!should_redact_job_attr(
            &ctx, "missing", "alice", "job-name"
        ));
        assert!(!should_redact_sub_attr(
            &ctx,
            "missing",
            "alice",
            "notify-user-data"
        ));

        // Direct `check_job_limits_and_quotas` copies bounds check.
        let p = Printer::new("p", "ipp://p/ipp");
        assert!(check_job_limits_and_quotas(&ctx, &p, "alice", 0, 0).is_err());
        ctx.max_copies = 5;
        assert!(check_job_limits_and_quotas(&ctx, &p, "alice", 0, 6).is_err());
    }
}
