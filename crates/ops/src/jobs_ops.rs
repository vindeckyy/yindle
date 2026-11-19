//! IPP job and document operations:
//! `Validate-Job`, `Print-Job`, `Print-URI`, `Create-Job`, `Send-Document`,
//! `Send-URI`, `Get-Jobs`, `Get-Job-Attributes`, `Cancel-Job`,
//! `Cancel-Current-Job`, `Cancel-Jobs`, `Cancel-My-Jobs`, `Purge-Jobs`,
//! `Hold-Job`, `Release-Job`, `Restart-Job`, `Reprocess-Job`, `Resubmit-Job`,
//! `Suspend-Current-Job`, `Resume-Job`, `Promote-Job`, `Schedule-Job-After`,
//! `Close-Job`, `Set-Job-Attributes`, `CUPS-Move-Job` (single + all),
//! `CUPS-Authenticate-Job`, `CUPS-Get-Document`, `Get-Documents`,
//! `Get-Document-Attributes`, `Cancel-Document`, `Set-Document-Attributes`.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::ref_option
)]

use ipp_codec::{ops::op, ops::status, tags, Attribute, IppMessage, Value};
use job::{Job, JobFile, JobState};
use printer::Printer;

use crate::common::{printer_supported_formats, requested_attrs, send_status, wants};
use crate::ctx::{Ctx, DispatchOutcome};
use crate::dispatch::{attr_int, attr_text, is_all_printers_uri};
use crate::gzip::decompress_gzip;
use crate::ppd::read_file_nofollow_bounded;
use crate::security::{
    authorize_op, check_document_k_quota, check_job_limits_and_quotas,
    enforce_printer_user_allowed, evaluate_op_decision, originating_user, should_redact_job_attr,
};
use crate::sub_ops::maybe_add_job_subscription;

/// Settable job attributes accepted by `Set-Job-Attributes` and job creation.
const SETTABLE_JOB_ATTRS: &[&str] = &[
    "copies",
    "finishings",
    "ipp-attribute-fidelity",
    "job-hold-until",
    "job-name",
    "job-priority",
    "job-sheets",
    "media",
    "media-col",
    "multiple-document-handling",
    "number-up",
    "orientation-requested",
    "output-bin",
    "page-ranges",
    "print-color-mode",
    "print-quality",
    "print-scaling",
    "printer-resolution",
    "proof-print",
    "sides",
];

/// Supported `sides` keywords.
const SUPPORTED_SIDES: &[&str] = &["one-sided", "two-sided-long-edge", "two-sided-short-edge"];

/// Supported `job-hold-until` keywords.
const SUPPORTED_HOLD_UNTIL: &[&str] = &[
    "no-hold",
    "indefinite",
    "day-time",
    "evening",
    "night",
    "second-shift",
    "third-shift",
    "weekend",
];

/// Current Unix epoch seconds.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Resolve a job-id from `job-id` operation attribute or trailing `job-uri` segment.
pub fn job_id(req: &IppMessage, uri_attr: Option<&Attribute>) -> Option<i32> {
    if let Some(a) = req.find(tags::OPERATION, "job-id") {
        if let Some(Value::Integer(i) | Value::Enum(i)) = a.values.first() {
            return Some(*i);
        }
    }
    uri_attr
        .and_then(attr_text)
        .filter(|u| u.contains("/jobs/"))
        .and_then(|u| u.rsplit('/').next().and_then(|s| s.parse().ok()))
}

fn hold_requested(attrs: &[Attribute]) -> Option<String> {
    attrs
        .iter()
        .find(|a| a.name.as_str() == "job-hold-until")
        .and_then(|a| a.text().map(std::borrow::Cow::into_owned))
        .filter(|v| v != "no-hold")
}

fn printer_holds_new_jobs(p: &Printer) -> bool {
    p.options
        .iter()
        .any(|(k, v)| k == "hold-new-jobs" && v == "true")
}

fn format_supported(p: &Printer, ctx: &Ctx<'_>, fmt: &str) -> bool {
    if fmt.eq_ignore_ascii_case("application/octet-stream") {
        return true;
    }
    if printer_supported_formats(p, ctx)
        .iter()
        .any(|f| f.eq_ignore_ascii_case(fmt))
    {
        return true;
    }
    if ctx.mime.get(fmt).is_some() {
        return true;
    }
    false
}

/// Decompress `raw` when `compression=gzip` is set; reject unsupported
/// compression algorithms and zip-bomb / corrupt payloads.
fn decompress_if_needed(
    req: &IppMessage,
    raw: &[u8],
    ctx: &Ctx<'_>,
) -> Result<Vec<u8>, (u16, String)> {
    let comp = req
        .find(tags::OPERATION, "compression")
        .and_then(attr_text)
        .unwrap_or_else(|| "none".into());
    if comp.eq_ignore_ascii_case("none") {
        return Ok(raw.to_vec());
    }
    if comp.eq_ignore_ascii_case("gzip") {
        return decompress_gzip(raw, ctx.max_decompressed_size).map_err(|e| {
            (
                status::ERROR_COMPRESSION_ERROR,
                format!("gzip decompression failed: {e}"),
            )
        });
    }
    Err((
        status::ERROR_COMPRESSION_NOT_SUPPORTED,
        format!("Unsupported compression \"{comp}\"."),
    ))
}

/// Securely resolve `document-uri` for `Print-URI` and `Send-URI`.
///
/// Strictly forbids `file://` local reads (never invokes `std::fs::read`!).
/// Delegates non-`file:` network URIs to `ctx.on_fetch_uri` if configured,
/// otherwise returns `ERROR_URI_SCHEME`.
fn fetch_document_uri(req: &IppMessage, ctx: &Ctx<'_>) -> Result<(Vec<u8>, String), (u16, String)> {
    let Some(doc_uri) = req
        .find(tags::OPERATION, "document-uri")
        .and_then(attr_text)
    else {
        return Err((
            status::ERROR_BAD_REQUEST,
            "Missing \"document-uri\".".into(),
        ));
    };
    let lower = doc_uri.to_ascii_lowercase();
    if lower.starts_with("file:") {
        ctx.audit(
            op::name(req.code),
            Some(&doc_uri),
            "denied",
            "local file:// document-uri blocked",
        );
        return Err((
            status::ERROR_FORBIDDEN,
            "Local file:// document-uri is not permitted.".into(),
        ));
    }
    let Some((scheme, _)) = doc_uri.split_once("://") else {
        return Err((
            status::ERROR_BAD_REQUEST,
            format!("Malformed document-uri \"{doc_uri}\"."),
        ));
    };
    if !matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "ipp" | "ipps" | "ftp"
    ) {
        return Err((
            status::ERROR_URI_SCHEME,
            format!("document-uri scheme \"{scheme}\" not supported."),
        ));
    }
    let Some(fetcher) = &ctx.on_fetch_uri else {
        return Err((
            status::ERROR_URI_SCHEME,
            "document-uri scheme not supported.".into(),
        ));
    };
    let bytes = fetcher(&doc_uri)
        .map_err(|e| (status::ERROR_DOCUMENT_ACCESS, format!("document-uri: {e}")))?;
    let name = doc_uri
        .split('?')
        .next()
        .unwrap_or(&doc_uri)
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("document")
        .to_string();
    Ok((bytes, name))
}

/// Sniff MIME type from spooled data when client declared `application/octet-stream`.
fn sniff(mime: &mime_db::MimeDb, path: &std::path::Path, declared: &str) -> String {
    if declared != "application/octet-stream" {
        return declared.into();
    }
    let head = read_file_nofollow_bounded(path, 8192).unwrap_or_default();
    mime.detect(path.to_str().unwrap_or(""), &head)
        .map_or_else(|| declared.into(), mime_db::Type::name)
}

/// Extract job-template options into `BTreeMap<String, String>` for persistence
/// and filter `argv[5]` forwarding.
fn extract_job_options(attrs: &[Attribute]) -> std::collections::BTreeMap<String, String> {
    let mut opts = std::collections::BTreeMap::new();
    for a in attrs {
        let name = a.name.as_str();
        if let Some(t) = a.text() {
            opts.insert(name.into_owned(), t.into_owned());
        } else if let Some(i) = a.int() {
            opts.insert(name.into_owned(), i.to_string());
        }
    }
    opts
}

/// Validate job attributes (copies, priority, sides, orientation, hold-until,
/// unknown attributes with `ipp-attribute-fidelity`).
/// Returns `Ok(had_unsupported_ignored)` or `Err((status, msg, unsupported_attrs))`.
fn validate_job_attrs(
    req: &IppMessage,
    ctx: &Ctx<'_>,
) -> Result<Vec<Attribute>, (u16, String, Vec<Attribute>)> {
    let fidelity = req
        .find(tags::OPERATION, "ipp-attribute-fidelity")
        .is_some_and(|a| matches!(a.first(), Some(Value::Boolean(true))));

    let mut unsupported = Vec::new();

    for g in &req.groups {
        if g.tag != tags::JOB {
            continue;
        }
        for a in &g.attributes {
            let name = a.name.as_str();
            match name.as_ref() {
                "copies" => {
                    let c = attr_int(a).unwrap_or(0);
                    if c < 1 || (ctx.max_copies > 0 && c > i64::from(ctx.max_copies)) {
                        unsupported.push(a.clone());
                        return Err((
                            status::ERROR_ATTRIBUTES_OR_VALUES,
                            format!("Bad copies value {c}."),
                            unsupported,
                        ));
                    }
                }
                "job-priority" => {
                    let pr = attr_int(a).unwrap_or(0);
                    if !(1..=100).contains(&pr) {
                        unsupported.push(a.clone());
                        return Err((
                            status::ERROR_ATTRIBUTES_OR_VALUES,
                            format!("Bad job-priority value {pr}."),
                            unsupported,
                        ));
                    }
                }
                "orientation-requested" => {
                    let o = attr_int(a).unwrap_or(0);
                    if !(3..=6).contains(&o) {
                        unsupported.push(a.clone());
                        return Err((
                            status::ERROR_ATTRIBUTES_OR_VALUES,
                            format!("Bad orientation-requested value {o}."),
                            unsupported,
                        ));
                    }
                }
                "sides" => {
                    let s = attr_text(a).unwrap_or_default();
                    if !SUPPORTED_SIDES.contains(&s.as_str()) {
                        unsupported.push(a.clone());
                        return Err((
                            status::ERROR_ATTRIBUTES_OR_VALUES,
                            format!("Unsupported sides value \"{s}\"."),
                            unsupported,
                        ));
                    }
                }
                "job-hold-until" => {
                    let h = attr_text(a).unwrap_or_default();
                    if !SUPPORTED_HOLD_UNTIL.contains(&h.as_str()) {
                        unsupported.push(a.clone());
                        return Err((
                            status::ERROR_ATTRIBUTES_OR_VALUES,
                            format!("Unsupported job-hold-until value \"{h}\"."),
                            unsupported,
                        ));
                    }
                }
                other if !SETTABLE_JOB_ATTRS.contains(&other) => {
                    unsupported.push(Attribute::new(
                        other,
                        tags::UNSUPPORTED,
                        vec![Value::Unsupported],
                    ));
                }
                _ => {}
            }
        }
    }

    // Also validate `copies` if passed in OPERATION group.
    if let Some(a) = req.find(tags::OPERATION, "copies") {
        let c = attr_int(a).unwrap_or(0);
        if c < 1 || (ctx.max_copies > 0 && c > i64::from(ctx.max_copies)) {
            unsupported.push(a.clone());
            return Err((
                status::ERROR_ATTRIBUTES_OR_VALUES,
                format!("Bad copies value {c}."),
                unsupported,
            ));
        }
    }

    if fidelity && !unsupported.is_empty() {
        return Err((
            status::ERROR_ATTRIBUTES_OR_VALUES,
            "Unsupported job attributes with ipp-attribute-fidelity=true.".into(),
            unsupported,
        ));
    }
    Ok(unsupported)
}

/// Emit a FRESH `tags::JOB` group per job (`cupsdCopyJob`), enforcing
/// `JobPrivateValues` / `JobPrivateAccess` and emitting real RFC 4122 `job-uuid`.
pub fn add_job_group(
    resp: &mut IppMessage,
    job: &Job,
    ctx: &Ctx<'_>,
    ra: &Option<Vec<String>>,
    policy: &str,
) {
    let g = resp.new_group_mut(tags::JOB);
    let mut add_vals = |name: &str, tag: u8, vals: Vec<Value>| {
        if wants(ra, name) && !should_redact_job_attr(ctx, policy, &job.username, name) {
            g.attributes.push(Attribute::new(name, tag, vals));
        }
    };

    let scheme = if ctx.is_encrypted { "ipps" } else { "ipp" };
    let web_scheme = if ctx.is_encrypted { "https" } else { "http" };

    add_vals("job-id", tags::INTEGER, vec![Value::Integer(job.id)]);
    add_vals(
        "job-uri",
        tags::URI,
        vec![Value::Uri(
            format!("{scheme}://{}:{}/jobs/{}", ctx.hostname, ctx.port, job.id).into(),
        )],
    );
    add_vals(
        "job-printer-uri",
        tags::URI,
        vec![Value::Uri(
            format!(
                "{scheme}://{}:{}/printers/{}",
                ctx.hostname, ctx.port, job.dest
            )
            .into(),
        )],
    );
    add_vals("job-state", tags::ENUM, vec![Value::Enum(job.state as i32)]);
    let reason_vals: Vec<Value> = if job.reasons.is_empty() {
        vec![Value::Keyword("none".into())]
    } else {
        job.reasons
            .iter()
            .map(|r| Value::Keyword(r.as_str().into()))
            .collect()
    };
    add_vals("job-state-reasons", tags::KEYWORD, reason_vals);
    add_vals(
        "job-originating-user-name",
        tags::NAME,
        vec![Value::Name(job.username.clone().into())],
    );
    add_vals(
        "job-originating-host-name",
        tags::NAME,
        vec![Value::Name(ctx.client_addr.to_string().into())],
    );
    add_vals(
        "job-name",
        tags::NAME,
        vec![Value::Name(job.title.clone().into())],
    );
    add_vals(
        "job-state-message",
        tags::TEXT,
        vec![Value::Text("".into())],
    );
    add_vals(
        "job-priority",
        tags::INTEGER,
        vec![Value::Integer(job.priority)],
    );
    add_vals("copies", tags::INTEGER, vec![Value::Integer(job.copies)]);
    add_vals(
        "document-format",
        tags::MIMETYPE,
        vec![Value::MimeMediaType(job.format.clone().into())],
    );
    add_vals(
        "number-of-documents",
        tags::INTEGER,
        vec![Value::Integer(job.files.len() as i32)],
    );
    let k_octets: u64 = job.files.iter().map(|f| f.size).sum();
    add_vals(
        "job-k-octets",
        tags::INTEGER,
        vec![Value::Integer(k_octets.div_ceil(1024) as i32)],
    );
    add_vals(
        "job-more-info",
        tags::URI,
        vec![Value::Uri(
            format!(
                "{web_scheme}://{}:{}/jobs/{}",
                ctx.hostname, ctx.port, job.id
            )
            .into(),
        )],
    );
    add_vals(
        "job-printer-up-time",
        tags::INTEGER,
        vec![Value::Integer(now_secs() as i32)],
    );
    if job.state.is_final() {
        add_vals(
            "job-preserved",
            tags::BOOLEAN,
            vec![Value::Boolean(!job.files.is_empty())],
        );
    }
    if let Some(ref hold) = job.hold_until {
        add_vals(
            "job-hold-until",
            tags::KEYWORD,
            vec![Value::Keyword(hold.as_str().into())],
        );
    }
    add_vals(
        "time-at-creation",
        tags::INTEGER,
        vec![Value::Integer(job.created_at as i32)],
    );
    if let Some(t) = job.processing_at {
        add_vals(
            "time-at-processing",
            tags::INTEGER,
            vec![Value::Integer(t as i32)],
        );
    }
    if let Some(t) = job.completed_at {
        add_vals(
            "time-at-completed",
            tags::INTEGER,
            vec![Value::Integer(t as i32)],
        );
    }
    add_vals(
        "job-uuid",
        tags::URI,
        vec![Value::Uri(job.job_uuid.as_str().into())],
    );
}

/// Resolve and authorize a destination for job submission/validation.
fn resolve_and_authorize_dest(
    ctx: &Ctx<'_>,
    outcome: &mut DispatchOutcome,
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
        let registry = ctx.reg();
        let Some((p, _)) = registry.validate_dest(&uri) else {
            drop(registry);
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

/// `Validate-Job` (0x0004) — full validation: authorization, accepting queue,
/// `AllowUser`/`DenyUser`, format, compression, copies/priority/options,
/// `MaxJobs*`, quotas, and `ipp-attribute-fidelity`.
pub fn validate_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(p) = resolve_and_authorize_dest(ctx, outcome, uri_attr, op::VALIDATE_JOB) else {
        return;
    };
    if !p.accepting {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_ACCEPTING_JOBS,
            "Destination is not accepting jobs.",
        );
        return;
    }
    if !enforce_printer_user_allowed(ctx, outcome, &p, op::VALIDATE_JOB) {
        return;
    }
    let user = originating_user(req, ctx);
    if let Some(fmt) = req
        .find(tags::OPERATION, "document-format")
        .and_then(attr_text)
    {
        if !format_supported(&p, ctx, &fmt) {
            send_status(
                &mut outcome.response,
                status::ERROR_DOCUMENT_FORMAT_NOT_SUPPORTED,
                format!("Unsupported document-format \"{fmt}\"."),
            );
            return;
        }
    }
    if let Some(comp) = req.find(tags::OPERATION, "compression").and_then(attr_text) {
        if !comp.eq_ignore_ascii_case("none") && !comp.eq_ignore_ascii_case("gzip") {
            send_status(
                &mut outcome.response,
                status::ERROR_COMPRESSION_NOT_SUPPORTED,
                format!("Unsupported compression \"{comp}\"."),
            );
            return;
        }
    }
    let ignored = match validate_job_attrs(req, ctx) {
        Ok(u) => u,
        Err((code, msg, unsup)) => {
            for a in unsup {
                outcome.response.push(tags::UNSUPPORTED, a);
            }
            send_status(&mut outcome.response, code, msg);
            return;
        }
    };
    let copies = req
        .groups
        .iter()
        .find(|g| g.tag == tags::JOB)
        .and_then(|g| g.find("copies"))
        .or_else(|| req.find(tags::OPERATION, "copies"))
        .and_then(attr_int)
        .unwrap_or(1) as i32;
    if let Err((code, msg)) = check_job_limits_and_quotas(ctx, &p, &user, 0, copies) {
        send_status(&mut outcome.response, code, msg);
        return;
    }
    if ignored.is_empty() {
        outcome.response.code = status::OK;
    } else {
        for a in ignored {
            outcome.response.push(tags::UNSUPPORTED, a);
        }
        outcome.response.code = status::OK_IGNORED_OR_SUBSTITUTED;
    }
}

/// `Get-Jobs` (0x000a) — supports all 11 `which-jobs` keywords, emits a fresh
/// `tags::JOB` group per job, and enforces `JobPrivateValues`.
pub fn get_jobs(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(uri) = uri_attr.and_then(attr_text) else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing \"printer-uri\" attribute.",
        );
        return;
    };
    let is_job_uri = uri_attr.is_some_and(|a| a.name.as_str().eq_ignore_ascii_case("job-uri"));
    let only_job: Option<i32> = if is_job_uri {
        let Some(id) = uri
            .rsplit('/')
            .next()
            .filter(|_| uri.contains("/jobs/"))
            .and_then(|s| s.parse::<i32>().ok())
        else {
            send_status(
                &mut outcome.response,
                status::ERROR_BAD_REQUEST,
                "Bad \"job-uri\" attribute.",
            );
            return;
        };
        Some(id)
    } else {
        None
    };

    let all_printers = !is_job_uri && is_all_printers_uri(&uri);
    let only_job_dest = only_job.and_then(|id| ctx.jobs_read().get(id).map(|j| j.dest.clone()));

    let p_name = if all_printers {
        let policy = ctx.effective_policy_for_dest(None);
        if !authorize_op(ctx, outcome, &policy, op::GET_JOBS, None, None) {
            return;
        }
        None
    } else {
        let registry = ctx.reg();
        let resolved = if let Some(ref jdest) = only_job_dest {
            registry.find(jdest)
        } else {
            registry.validate_dest(&uri).map(|(p, _)| p)
        };
        let Some(p) = resolved else {
            drop(registry);
            let policy = ctx.effective_policy_for_dest(None);
            if !authorize_op(ctx, outcome, &policy, op::GET_JOBS, None, Some(&uri)) {
                return;
            }
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_FOUND,
                "The printer or class does not exist.",
            );
            return;
        };
        let pname = p.name.clone();
        let policy = ctx.effective_policy_name(Some(p)).to_string();
        drop(registry);
        if !authorize_op(ctx, outcome, &policy, op::GET_JOBS, None, Some(&pname)) {
            return;
        }
        Some(pname)
    };

    let which = req
        .find(tags::OPERATION, "which-jobs")
        .and_then(attr_text)
        .unwrap_or_else(|| "not-completed".into());
    if !matches!(
        which.as_str(),
        "not-completed"
            | "completed"
            | "all"
            | "aborted"
            | "canceled"
            | "pending"
            | "pending-held"
            | "processing"
            | "processing-stopped"
            | "fetchable"
            | "proof-print"
    ) {
        outcome.response.push(
            tags::UNSUPPORTED,
            Attribute::new(
                "which-jobs",
                tags::KEYWORD,
                vec![Value::Keyword(which.into())],
            ),
        );
        send_status(
            &mut outcome.response,
            status::ERROR_ATTRIBUTES_OR_VALUES,
            "Unsupported \"which-jobs\" value.",
        );
        return;
    }

    let limit = req
        .find(tags::OPERATION, "limit")
        .and_then(attr_int)
        .filter(|l| *l > 0)
        .map_or(usize::MAX, |l| l as usize);
    let my_jobs = req
        .find(tags::OPERATION, "my-jobs")
        .is_some_and(|a| matches!(a.first(), Some(Value::Boolean(true))));
    let my_user = if my_jobs {
        Some(originating_user(req, ctx))
    } else {
        None
    };

    let ra = requested_attrs(req).or_else(|| Some(vec!["job-id".into(), "job-uri".into()]));

    // Resolve class members BEFORE locking `jobs` to prevent nested locks.
    let class_members: Vec<String> = if all_printers {
        Vec::new()
    } else {
        let target = p_name.as_deref().unwrap_or("");
        let registry = ctx.reg();
        registry
            .find(target)
            .filter(|p| p.is_class())
            .map(|p| p.members.clone())
            .unwrap_or_default()
    };

    let candidates: Vec<Job> = {
        let jobs = ctx.jobs_read();
        let iter: Vec<&Job> = if all_printers {
            jobs.by_id.values().collect()
        } else {
            let target = p_name.as_deref().unwrap_or("");
            jobs.by_id
                .values()
                .filter(|j| j.dest == target || class_members.iter().any(|m| m == &j.dest))
                .collect()
        };
        iter.into_iter()
            .filter(|j| {
                if only_job.is_some_and(|id| j.id != id) {
                    return false;
                }
                if let Some(ref u) = my_user {
                    if !j.username.eq_ignore_ascii_case(u) {
                        return false;
                    }
                }
                matches_which_jobs(j, &which)
            })
            .cloned()
            .collect()
    };

    // In `all_printers` mode, enforce each job's destination `op_policy` so
    // per-printer policies (e.g. TLS-only / restricted queues) cannot be
    // bypassed via `Get-Jobs /`.
    let matched: Vec<Job> = if all_printers {
        candidates
            .into_iter()
            .filter(|j| {
                let policy = ctx.effective_policy_for_dest(Some(&j.dest));
                evaluate_op_decision(ctx, &policy, op::GET_JOBS, Some(&j.username))
                    == authz::AccessDecision::Allowed
            })
            .take(limit)
            .collect()
    } else {
        candidates.into_iter().take(limit).collect()
    };

    outcome.response.code = status::OK;
    for j in &matched {
        let policy = ctx.effective_policy_for_dest(Some(&j.dest));
        add_job_group(&mut outcome.response, j, ctx, &ra, &policy);
    }
}

fn matches_which_jobs(j: &Job, which: &str) -> bool {
    match which {
        "completed" => j.state.is_final(),
        "all" => true,
        "aborted" => j.state == JobState::Aborted,
        "canceled" => j.state == JobState::Canceled,
        "pending" => j.state == JobState::Pending,
        "pending-held" => j.state == JobState::PendingHeld,
        "processing" => j.state == JobState::Processing,
        "processing-stopped" => j.state == JobState::ProcessingStopped,
        "fetchable" => {
            !j.state.is_final()
                && (!j.files.is_empty() || j.reasons.iter().any(|r| r == "job-fetchable"))
        }
        "proof-print" => {
            j.options.contains_key("proof-print") || j.attrs.iter().any(|a| a.name == "proof-print")
        }
        _ => !j.state.is_final(), // "not-completed"
    }
}

/// `Print-Job` (0x0002).
pub fn print_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(p) = resolve_and_authorize_dest(ctx, outcome, uri_attr, op::PRINT_JOB) else {
        return;
    };
    let doc = match decompress_if_needed(req, ctx.document, ctx) {
        Ok(d) => d,
        Err((code, msg)) => {
            send_status(&mut outcome.response, code, msg);
            return;
        }
    };
    let name = ctx.document_name.clone();
    submit_document(req, outcome, ctx, &p, &doc, name);
}

/// `Print-URI` (0x0003) — forbids `file://` arbitrary reads.
pub fn print_uri(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(p) = resolve_and_authorize_dest(ctx, outcome, uri_attr, op::PRINT_URI) else {
        return;
    };
    let (raw, name) = match fetch_document_uri(req, ctx) {
        Ok(v) => v,
        Err((code, msg)) => {
            send_status(&mut outcome.response, code, msg);
            return;
        }
    };
    let doc = match decompress_if_needed(req, &raw, ctx) {
        Ok(d) => d,
        Err((code, msg)) => {
            send_status(&mut outcome.response, code, msg);
            return;
        }
    };
    submit_document(req, outcome, ctx, &p, &doc, name);
}

fn submit_document(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    p: &Printer,
    document: &[u8],
    document_name: String,
) {
    if !p.accepting {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_ACCEPTING_JOBS,
            "Destination is not accepting jobs.",
        );
        return;
    }
    if !enforce_printer_user_allowed(ctx, outcome, p, req.code) {
        return;
    }
    let user = originating_user(req, ctx);
    let format = req
        .find(tags::OPERATION, "document-format")
        .and_then(attr_text)
        .unwrap_or_else(|| "application/octet-stream".into());
    if !format_supported(p, ctx, &format) {
        send_status(
            &mut outcome.response,
            status::ERROR_DOCUMENT_FORMAT_NOT_SUPPORTED,
            format!("Unsupported document-format \"{format}\"."),
        );
        return;
    }
    let ignored = match validate_job_attrs(req, ctx) {
        Ok(u) => u,
        Err((code, msg, unsup)) => {
            for a in unsup {
                outcome.response.push(tags::UNSUPPORTED, a);
            }
            send_status(&mut outcome.response, code, msg);
            return;
        }
    };

    let job_group_attrs: Vec<Attribute> = req
        .groups
        .iter()
        .find(|g| g.tag == tags::JOB)
        .map(|g| g.attributes.clone())
        .unwrap_or_default();

    let copies = job_group_attrs
        .iter()
        .find(|a| a.name == "copies")
        .or_else(|| req.find(tags::OPERATION, "copies"))
        .and_then(attr_int)
        .unwrap_or(1) as i32;
    let priority = job_group_attrs
        .iter()
        .find(|a| a.name == "job-priority")
        .and_then(attr_int)
        .unwrap_or(50)
        .clamp(1, 100) as i32;

    if let Err((code, msg)) =
        check_job_limits_and_quotas(ctx, p, &user, document.len() as u64, copies)
    {
        send_status(&mut outcome.response, code, msg);
        return;
    }

    let title = req
        .find(tags::OPERATION, "job-name")
        .and_then(attr_text)
        .or_else(|| {
            job_group_attrs
                .iter()
                .find(|a| a.name == "job-name")
                .and_then(attr_text)
        })
        .or_else(|| {
            req.find(tags::OPERATION, "document-name")
                .and_then(attr_text)
        })
        .unwrap_or_else(|| document_name.clone());

    let doc_name = req
        .find(tags::OPERATION, "document-name")
        .and_then(attr_text)
        .unwrap_or(document_name);

    let mut jobs = ctx.jobs_write();
    let id = jobs.alloc_id();
    let mut job = Job::new(id, p.name.clone(), user.clone());
    job.title = title;
    job.copies = copies;
    job.priority = priority;
    job.format.clone_from(&format);
    job.options = extract_job_options(&job_group_attrs);
    job.attrs = job_group_attrs;

    if let Some(hold) = hold_requested(&job.attrs) {
        job.state = JobState::PendingHeld;
        job.hold_until = Some(hold);
        job.reasons = vec!["job-hold-until-specified".into()];
    } else if printer_holds_new_jobs(p) {
        job.state = JobState::PendingHeld;
        job.hold_until = Some("indefinite".into());
        job.reasons = vec!["hold-new-jobs".into()];
    }

    // Write spool data atomically with 0600 + O_EXCL|O_NOFOLLOW.
    let data_path = match Job::write_data_file(&ctx.request_root, id, 1, document) {
        Ok(path) => path,
        Err(e) => {
            send_status(
                &mut outcome.response,
                status::ERROR_INTERNAL,
                format!("spool write: {e}"),
            );
            return;
        }
    };
    let filetype = sniff(ctx.mime, &data_path, &format);
    job.files.push(JobFile {
        num: 1,
        filetype,
        size: document.len() as u64,
        name: doc_name,
        format,
    });
    let saved_job = job.clone();
    if let Err(e) = jobs.add(&ctx.request_root, job) {
        let _ = std::fs::remove_file(&data_path);
        send_status(
            &mut outcome.response,
            status::ERROR_INTERNAL,
            format!("cannot save job: {e}"),
        );
        return;
    }
    drop(jobs);

    ctx.event_with_state(
        events::Event::JobCreated,
        Some(&p.name),
        Some(id),
        Some(saved_job.state as i32),
        Some(saved_job.title.clone()),
        format!("Job {id} created."),
    );
    ctx.audit(
        op::name(req.code),
        Some(&format!("job/{id}")),
        "allowed",
        format!("printer={} user={user} bytes={}", p.name, document.len()),
    );

    if ignored.is_empty() {
        outcome.response.code = status::OK;
    } else {
        for a in ignored {
            outcome.response.push(tags::UNSUPPORTED, a);
        }
        outcome.response.code = status::OK_IGNORED_OR_SUBSTITUTED;
    }
    let policy = ctx.effective_policy_name(Some(p)).to_string();
    add_job_group(
        &mut outcome.response,
        &saved_job,
        ctx,
        &requested_attrs(req),
        &policy,
    );
    maybe_add_job_subscription(req, &mut outcome.response, ctx, id, &p.name);
}

/// `Create-Job` (0x0005).
pub fn create_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(p) = resolve_and_authorize_dest(ctx, outcome, uri_attr, op::CREATE_JOB) else {
        return;
    };
    if !p.accepting {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_ACCEPTING_JOBS,
            "Destination is not accepting jobs.",
        );
        return;
    }
    if !enforce_printer_user_allowed(ctx, outcome, &p, op::CREATE_JOB) {
        return;
    }
    let user = originating_user(req, ctx);
    let ignored = match validate_job_attrs(req, ctx) {
        Ok(u) => u,
        Err((code, msg, unsup)) => {
            for a in unsup {
                outcome.response.push(tags::UNSUPPORTED, a);
            }
            send_status(&mut outcome.response, code, msg);
            return;
        }
    };

    let job_group_attrs: Vec<Attribute> = req
        .groups
        .iter()
        .find(|g| g.tag == tags::JOB)
        .map(|g| g.attributes.clone())
        .unwrap_or_default();

    let copies = job_group_attrs
        .iter()
        .find(|a| a.name == "copies")
        .or_else(|| req.find(tags::OPERATION, "copies"))
        .and_then(attr_int)
        .unwrap_or(1) as i32;
    let priority = job_group_attrs
        .iter()
        .find(|a| a.name == "job-priority")
        .and_then(attr_int)
        .unwrap_or(50)
        .clamp(1, 100) as i32;

    if let Err((code, msg)) = check_job_limits_and_quotas(ctx, &p, &user, 0, copies) {
        send_status(&mut outcome.response, code, msg);
        return;
    }

    let mut jobs = ctx.jobs_write();
    let id = jobs.alloc_id();
    let mut job = Job::new(id, p.name.clone(), user.clone());
    job.state = JobState::PendingHeld;
    job.reasons = vec!["job-data-insufficient".into()];
    job.copies = copies;
    job.priority = priority;
    job.title = req
        .find(tags::OPERATION, "job-name")
        .and_then(attr_text)
        .unwrap_or_default();
    job.hold_until = hold_requested(&job_group_attrs);
    job.options = extract_job_options(&job_group_attrs);
    job.attrs = job_group_attrs;

    let saved_job = job.clone();
    if let Err(e) = jobs.add(&ctx.request_root, job) {
        send_status(
            &mut outcome.response,
            status::ERROR_INTERNAL,
            format!("cannot save job: {e}"),
        );
        return;
    }
    drop(jobs);

    ctx.event_with_state(
        events::Event::JobCreated,
        Some(&p.name),
        Some(id),
        Some(saved_job.state as i32),
        Some(saved_job.title.clone()),
        format!("Job {id} created."),
    );
    ctx.audit(
        "Create-Job",
        Some(&format!("job/{id}")),
        "allowed",
        format!("printer={} user={user}", p.name),
    );
    outcome.response.code = if ignored.is_empty() {
        status::OK
    } else {
        for a in ignored {
            outcome.response.push(tags::UNSUPPORTED, a);
        }
        status::OK_IGNORED_OR_SUBSTITUTED
    };
    let policy = ctx.effective_policy_name(Some(&p)).to_string();
    add_job_group(
        &mut outcome.response,
        &saved_job,
        ctx,
        &requested_attrs(req),
        &policy,
    );
    maybe_add_job_subscription(req, &mut outcome.response, ctx, id, &p.name);
}

/// Shared body for `Send-Document` (0x0006) and `Send-URI` (0x0007).
fn attach_document_to_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
    raw_bytes: &[u8],
    fallback_name: String,
    op_code: u16,
) {
    let Some(id) = job_id(req, uri_attr) else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "Job not found.",
        );
        return;
    };
    let Some(last_attr) = req.find(tags::OPERATION, "last-document") else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing \"last-document\" attribute.",
        );
        return;
    };
    let job_meta = ctx.jobs_read().get(id).map(|j| {
        let open_for_docs = j.state == JobState::PendingHeld
            && j.reasons.iter().any(|r| r == "job-data-insufficient");
        (j.username.clone(), j.dest.clone(), j.state, open_for_docs)
    });
    let Some((owner, dest, state, open_for_docs)) = job_meta else {
        let policy = ctx.effective_policy_for_dest(None);
        if !authorize_op(ctx, outcome, &policy, op_code, None, None) {
            return;
        }
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "Job not found.",
        );
        return;
    };
    let policy = ctx.effective_policy_for_dest(Some(&dest));
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        op_code,
        Some(&owner),
        Some(&format!("job/{id}")),
    ) {
        return;
    }
    if state.is_final() || !open_for_docs {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_POSSIBLE,
            "Job is not accepting additional documents.",
        );
        return;
    }

    let document = match decompress_if_needed(req, raw_bytes, ctx) {
        Ok(d) => d,
        Err((code, msg)) => {
            send_status(&mut outcome.response, code, msg);
            return;
        }
    };

    let printer_opt = ctx.reg().find(&dest).cloned();
    if let Some(ref p) = printer_opt {
        if let Some(fmt) = req
            .find(tags::OPERATION, "document-format")
            .and_then(attr_text)
        {
            if !format_supported(p, ctx, &fmt) {
                send_status(
                    &mut outcome.response,
                    status::ERROR_DOCUMENT_FORMAT_NOT_SUPPORTED,
                    format!("Unsupported document-format \"{fmt}\"."),
                );
                return;
            }
        }
        if let Err((code, msg)) = check_document_k_quota(ctx, p, &owner, document.len() as u64) {
            send_status(&mut outcome.response, code, msg);
            return;
        }
    }

    let mut jobs = ctx.jobs_write();
    let Some(job) = jobs.get_mut(id) else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "Job not found.",
        );
        return;
    };
    if job.state != JobState::PendingHeld
        || !job.reasons.iter().any(|r| r == "job-data-insufficient")
    {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_POSSIBLE,
            "Job is not accepting additional documents.",
        );
        return;
    }
    let num = job.files.iter().map(|f| f.num).max().unwrap_or(0) + 1;
    let data_path = match Job::write_data_file(&ctx.request_root, id, num, &document) {
        Ok(path) => path,
        Err(e) => {
            send_status(
                &mut outcome.response,
                status::ERROR_INTERNAL,
                format!("spool write: {e}"),
            );
            return;
        }
    };
    let format = req
        .find(tags::OPERATION, "document-format")
        .and_then(attr_text)
        .unwrap_or_else(|| job.format.clone());
    let doc_name = req
        .find(tags::OPERATION, "document-name")
        .and_then(attr_text)
        .unwrap_or(fallback_name);
    let filetype = sniff(ctx.mime, &data_path, &format);
    if job.files.is_empty() {
        job.format.clone_from(&format);
    }
    job.files.push(JobFile {
        num,
        filetype,
        size: document.len() as u64,
        name: doc_name,
        format,
    });
    let last = matches!(last_attr.first(), Some(Value::Boolean(true)));
    if last {
        if let Some(hold) = hold_requested(&job.attrs) {
            job.state = JobState::PendingHeld;
            job.hold_until = Some(hold);
            job.reasons = vec!["job-hold-until-specified".into()];
        } else if printer_opt.as_ref().is_some_and(printer_holds_new_jobs) {
            job.state = JobState::PendingHeld;
            job.hold_until = Some("indefinite".into());
            job.reasons = vec!["hold-new-jobs".into()];
        } else {
            job.state = JobState::Pending;
            job.reasons = vec!["none".into()];
        }
    }
    let _ = job.save(&ctx.request_root);
    let saved_job = job.clone();
    drop(jobs);

    ctx.event_with_state(
        events::Event::JobStateChanged,
        Some(&dest),
        Some(id),
        Some(saved_job.state as i32),
        Some(saved_job.title.clone()),
        format!("Document {num} added to job {id}."),
    );
    outcome.response.code = status::OK;
    add_job_group(
        &mut outcome.response,
        &saved_job,
        ctx,
        &requested_attrs(req),
        &policy,
    );
}

/// `Send-Document` (0x0006).
pub fn send_document(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    attach_document_to_job(
        req,
        outcome,
        ctx,
        uri_attr,
        ctx.document,
        ctx.document_name.clone(),
        op::SEND_DOCUMENT,
    );
}

/// `Send-URI` (0x0007) — forbids `file://` local reads.
pub fn send_uri(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    // Check job + authz BEFORE fetching any URI!
    let Some(id) = job_id(req, uri_attr) else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "Job not found.",
        );
        return;
    };
    let job_meta = ctx
        .jobs_read()
        .get(id)
        .map(|j| (j.username.clone(), j.dest.clone()));
    if let Some((owner, dest)) = job_meta {
        let policy = ctx.effective_policy_for_dest(Some(&dest));
        if !authorize_op(
            ctx,
            outcome,
            &policy,
            op::SEND_URI,
            Some(&owner),
            Some(&format!("job/{id}")),
        ) {
            return;
        }
    } else {
        let policy = ctx.effective_policy_for_dest(None);
        if !authorize_op(ctx, outcome, &policy, op::SEND_URI, None, None) {
            return;
        }
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "Job not found.",
        );
        return;
    }

    if req.find(tags::OPERATION, "last-document").is_none() {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing \"last-document\" attribute.",
        );
        return;
    }

    let (raw, name) = match fetch_document_uri(req, ctx) {
        Ok(v) => v,
        Err((code, msg)) => {
            send_status(&mut outcome.response, code, msg);
            return;
        }
    };
    attach_document_to_job(req, outcome, ctx, uri_attr, &raw, name, op::SEND_URI);
}

/// `Cancel-Job` (0x0008).
pub fn cancel_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(mut id) = job_id(req, uri_attr) else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "Job not found.",
        );
        return;
    };
    if id == 0 {
        let Some(uri) = uri_attr.and_then(attr_text) else {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_FOUND,
                "Job not found.",
            );
            return;
        };
        let dest = {
            let registry = ctx.reg();
            let Some((p, _)) = registry.validate_dest(&uri) else {
                drop(registry);
                let policy = ctx.effective_policy_for_dest(None);
                if !authorize_op(ctx, outcome, &policy, op::CANCEL_JOB, None, Some(&uri)) {
                    return;
                }
                send_status(
                    &mut outcome.response,
                    status::ERROR_NOT_FOUND,
                    "The printer or class does not exist.",
                );
                return;
            };
            p.name.clone()
        };
        let jr = ctx.jobs_read();
        let active = jr.for_printer(&dest).find(|j| {
            matches!(
                j.state,
                JobState::Pending | JobState::PendingHeld | JobState::Processing
            )
        });
        let stopped = jr
            .for_printer(&dest)
            .find(|j| j.state == JobState::ProcessingStopped);
        if let Some(j) = active.or(stopped) {
            id = j.id;
        } else {
            drop(jr);
            let policy = ctx.effective_policy_for_dest(Some(&dest));
            if !authorize_op(ctx, outcome, &policy, op::CANCEL_JOB, None, Some(&dest)) {
                return;
            }
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                format!("No active jobs on {dest}."),
            );
            return;
        }
    }

    let job_meta = ctx
        .jobs_read()
        .get(id)
        .map(|j| (j.username.clone(), j.dest.clone()));
    let Some((owner, dest)) = job_meta else {
        let policy = ctx.effective_policy_for_dest(None);
        if !authorize_op(ctx, outcome, &policy, op::CANCEL_JOB, None, None) {
            return;
        }
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "Job not found.",
        );
        return;
    };
    let policy = ctx.effective_policy_for_dest(Some(&dest));
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        op::CANCEL_JOB,
        Some(&owner),
        Some(&format!("job/{id}")),
    ) {
        return;
    }

    let mut jobs = ctx.jobs_write();
    let Some(j) = jobs.get_mut(id) else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "Job not found.",
        );
        return;
    };
    if j.state.is_final() {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_POSSIBLE,
            "Job already completed.",
        );
        return;
    }
    j.state = JobState::Canceled;
    j.reasons = vec!["job-canceled-by-user".into()];
    j.completed_at = Some(now_secs());
    let _ = j.save(&ctx.request_root);
    let saved_job = j.clone();
    drop(jobs);

    ctx.notify_cancel_job(id);
    ctx.event_with_state(
        events::Event::JobCompleted,
        Some(&dest),
        Some(id),
        Some(JobState::Canceled as i32),
        Some(saved_job.title.clone()),
        format!("Job {id} canceled."),
    );
    ctx.audit(
        "Cancel-Job",
        Some(&format!("job/{id}")),
        "allowed",
        "canceled",
    );
    outcome.response.code = status::OK;
    add_job_group(
        &mut outcome.response,
        &saved_job,
        ctx,
        &requested_attrs(req),
        &policy,
    );
}

/// Shared body for `Cancel-Current-Job` (0x002d) and `Suspend-Current-Job` (0x002e).
fn transition_current_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
    op_code: u16,
    to_state: JobState,
) {
    let Some(uri) = uri_attr.and_then(attr_text) else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing \"printer-uri\" attribute.",
        );
        return;
    };
    let dest = {
        let registry = ctx.reg();
        let Some((p, _)) = registry.validate_dest(&uri) else {
            drop(registry);
            let policy = ctx.effective_policy_for_dest(None);
            if !authorize_op(ctx, outcome, &policy, op_code, None, Some(&uri)) {
                return;
            }
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_FOUND,
                "The printer does not exist.",
            );
            return;
        };
        p.name.clone()
    };
    let policy = ctx.effective_policy_for_dest(Some(&dest));
    let cur = ctx
        .jobs_read()
        .for_printer(&dest)
        .find(|j| j.state == JobState::Processing)
        .map(|j| (j.id, j.username.clone()));

    let Some((id, owner)) = cur else {
        if !authorize_op(ctx, outcome, &policy, op_code, None, Some(&dest)) {
            return;
        }
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "No active job on printer.",
        );
        return;
    };
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        op_code,
        Some(&owner),
        Some(&format!("job/{id}")),
    ) {
        return;
    }

    let Some(saved_job) = mutate_job_entry(ctx, id, outcome, |j, _| {
        j.state = to_state;
        if to_state == JobState::Canceled {
            j.reasons = vec!["job-canceled-by-user".into()];
            j.completed_at = Some(now_secs());
        } else {
            j.reasons = vec!["job-suspended".into()];
        }
        true
    }) else {
        return;
    };

    if to_state == JobState::Canceled {
        ctx.notify_cancel_job(id);
    }
    let (ev, verb) = if to_state == JobState::Canceled {
        (events::Event::JobCompleted, "canceled")
    } else {
        (events::Event::JobStopped, "suspended")
    };
    ctx.event_with_state(
        ev,
        Some(&dest),
        Some(id),
        Some(to_state as i32),
        Some(saved_job.title.clone()),
        format!("Job {id} {verb}."),
    );
    ctx.audit(
        op::name(op_code),
        Some(&format!("job/{id}")),
        "allowed",
        verb,
    );
    outcome.response.code = status::OK;
    add_job_group(
        &mut outcome.response,
        &saved_job,
        ctx,
        &requested_attrs(req),
        &policy,
    );
}

/// `Cancel-Current-Job` (0x002d).
pub fn cancel_current_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    transition_current_job(
        req,
        outcome,
        ctx,
        uri_attr,
        op::CANCEL_CURRENT_JOB,
        JobState::Canceled,
    );
}

/// `Cancel-My-Jobs` (0x0039) — cancels all non-final jobs owned by the target user.
pub fn cancel_my_jobs(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    // Determine whose jobs are being targeted: if a non-admin supplies a
    // different `requesting-user-name`, `@OWNER` fails closed!
    let target_user = req
        .find(tags::OPERATION, "requesting-user-name")
        .and_then(attr_text)
        .or_else(|| ctx.username.clone())
        .or_else(|| ctx.requesting_user.clone());

    let uri_opt = uri_attr.and_then(attr_text);
    let dest = if let Some(ref uri) = uri_opt {
        if is_all_printers_uri(uri) {
            None
        } else {
            let registry = ctx.reg();
            let Some((p, _)) = registry.validate_dest(uri) else {
                drop(registry);
                let policy = ctx.effective_policy_for_dest(None);
                if !authorize_op(
                    ctx,
                    outcome,
                    &policy,
                    op::CANCEL_MY_JOBS,
                    target_user.as_deref(),
                    Some(uri),
                ) {
                    return;
                }
                send_status(
                    &mut outcome.response,
                    status::ERROR_NOT_FOUND,
                    "The printer or class does not exist.",
                );
                return;
            };
            Some(p.name.clone())
        }
    } else {
        None
    };

    let policy = ctx.effective_policy_for_dest(dest.as_deref());
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        op::CANCEL_MY_JOBS,
        target_user.as_deref(),
        dest.as_deref(),
    ) {
        return;
    }

    let Some(user) = target_user.filter(|s| !s.is_empty()) else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing user identity for Cancel-My-Jobs.",
        );
        return;
    };

    let now = now_secs();
    let mut canceled: Vec<(i32, String, String)> = Vec::new();
    {
        let mut jobs = ctx.jobs_write();
        for j in jobs.by_id.values_mut() {
            if j.state.is_final() {
                continue;
            }
            if let Some(ref d) = dest {
                if &j.dest != d {
                    continue;
                }
            }
            if j.username.eq_ignore_ascii_case(&user) {
                j.state = JobState::Canceled;
                j.reasons = vec!["job-canceled-by-user".into()];
                j.completed_at = Some(now);
                let _ = j.save(&ctx.request_root);
                canceled.push((j.id, j.dest.clone(), j.title.clone()));
            }
        }
    }
    for (id, jdest, title) in &canceled {
        ctx.notify_cancel_job(*id);
        ctx.event_with_state(
            events::Event::JobCompleted,
            Some(jdest),
            Some(*id),
            Some(JobState::Canceled as i32),
            Some(title.clone()),
            format!("Job {id} canceled."),
        );
    }
    ctx.audit(
        "Cancel-My-Jobs",
        dest.as_deref(),
        "allowed",
        format!("user={user} canceled={}", canceled.len()),
    );
    outcome.response.code = status::OK;
}

/// `Cancel-Jobs` (0x0038).
pub fn cancel_jobs(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some(uri) = uri_attr.and_then(attr_text) else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing \"printer-uri\" attribute.",
        );
        return;
    };
    let all = is_all_printers_uri(&uri);
    let dest = if all {
        None
    } else {
        let registry = ctx.reg();
        let Some((p, _)) = registry.validate_dest(&uri) else {
            drop(registry);
            let policy = ctx.effective_policy_for_dest(None);
            if !authorize_op(ctx, outcome, &policy, op::CANCEL_JOBS, None, Some(&uri)) {
                return;
            }
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_FOUND,
                "The printer or class does not exist.",
            );
            return;
        };
        Some(p.name.clone())
    };
    let policy = ctx.effective_policy_for_dest(dest.as_deref());
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        op::CANCEL_JOBS,
        None,
        dest.as_deref(),
    ) {
        return;
    }

    let my_jobs = req
        .find(tags::OPERATION, "my-jobs")
        .is_some_and(|a| matches!(a.first(), Some(Value::Boolean(true))));
    let user = originating_user(req, ctx);
    let now = now_secs();
    let mut canceled: Vec<(i32, String, String)> = Vec::new();
    {
        let mut jobs = ctx.jobs_write();
        for j in jobs.by_id.values_mut() {
            if j.state.is_final() {
                continue;
            }
            if let Some(ref d) = dest {
                if &j.dest != d {
                    continue;
                }
            }
            if my_jobs && !j.username.eq_ignore_ascii_case(&user) {
                continue;
            }
            j.state = JobState::Canceled;
            j.reasons = vec!["job-canceled-by-operator".into()];
            j.completed_at = Some(now);
            let _ = j.save(&ctx.request_root);
            canceled.push((j.id, j.dest.clone(), j.title.clone()));
        }
    }
    for (id, jdest, title) in &canceled {
        ctx.notify_cancel_job(*id);
        ctx.event_with_state(
            events::Event::JobCompleted,
            Some(jdest),
            Some(*id),
            Some(JobState::Canceled as i32),
            Some(title.clone()),
            format!("Job {id} canceled."),
        );
    }
    ctx.audit(
        "Cancel-Jobs",
        dest.as_deref(),
        "allowed",
        format!("canceled={}", canceled.len()),
    );
    outcome.response.code = status::OK;
}

/// `Purge-Jobs` (0x0012).
pub fn purge_jobs(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let dest = if let Some(uri) = uri_attr.and_then(attr_text) {
        if is_all_printers_uri(&uri) {
            None
        } else {
            let registry = ctx.reg();
            let Some((p, _)) = registry.validate_dest(&uri) else {
                drop(registry);
                let policy = ctx.effective_policy_for_dest(None);
                if !authorize_op(ctx, outcome, &policy, op::PURGE_JOBS, None, Some(&uri)) {
                    return;
                }
                send_status(
                    &mut outcome.response,
                    status::ERROR_NOT_FOUND,
                    "The printer or class does not exist.",
                );
                return;
            };
            Some(p.name.clone())
        }
    } else {
        None
    };

    let policy = ctx.effective_policy_for_dest(dest.as_deref());
    // Purge-Jobs requires @SYSTEM (owner = None).
    if !authorize_op(ctx, outcome, &policy, op::PURGE_JOBS, None, dest.as_deref()) {
        return;
    }

    let purge_history = req
        .find(tags::OPERATION, "purge-jobs")
        .is_none_or(|a| matches!(a.first(), Some(Value::Boolean(true))));
    let now = now_secs();
    let mut ids_to_cancel = Vec::new();
    let mut ids_to_remove = Vec::new();
    {
        let mut jobs = ctx.jobs_write();
        for j in jobs.by_id.values_mut() {
            if let Some(ref d) = dest {
                if &j.dest != d {
                    continue;
                }
            }
            if !j.state.is_final() {
                j.state = JobState::Canceled;
                j.reasons = vec!["job-canceled-by-operator".into()];
                j.completed_at = Some(now);
                let _ = j.save(&ctx.request_root);
                ids_to_cancel.push((j.id, j.dest.clone(), j.title.clone()));
            }
            if purge_history {
                ids_to_remove.push(j.id);
            }
        }
        for id in &ids_to_remove {
            let _ = jobs.remove(&ctx.request_root, *id);
        }
    }
    for (id, jdest, title) in &ids_to_cancel {
        ctx.notify_cancel_job(*id);
        ctx.event_with_state(
            events::Event::JobCompleted,
            Some(jdest),
            Some(*id),
            Some(JobState::Canceled as i32),
            Some(title.clone()),
            format!("Job {id} purged."),
        );
    }
    ctx.audit(
        "Purge-Jobs",
        dest.as_deref(),
        "allowed",
        format!(
            "canceled={} purged={}",
            ids_to_cancel.len(),
            ids_to_remove.len()
        ),
    );
    outcome.response.code = status::OK;
}

/// `Suspend-Current-Job` (0x002e).
pub fn suspend_current_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    transition_current_job(
        req,
        outcome,
        ctx,
        uri_attr,
        op::SUSPEND_CURRENT_JOB,
        JobState::ProcessingStopped,
    );
}

/// Shared authorized single-job lookup returning `(job_clone, policy_name)`.
fn read_authorized_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
    op_code: u16,
) -> Option<(Job, String)> {
    let Some(id) = job_id(req, uri_attr) else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "Job not found.",
        );
        return None;
    };
    let job = ctx.jobs_read().get(id).cloned();
    let Some(job) = job else {
        let policy = ctx.effective_policy_for_dest(None);
        if !authorize_op(ctx, outcome, &policy, op_code, None, None) {
            return None;
        }
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "Job not found.",
        );
        return None;
    };
    let policy = ctx.effective_policy_for_dest(Some(&job.dest));
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        op_code,
        Some(&job.username),
        Some(&format!("job/{id}")),
    ) {
        return None;
    }
    Some((job, policy))
}

/// Mutate job `id` under the write lock, persist to disk, and return a snapshot.
/// Returns `None` if the job disappeared concurrently or `f` set an error.
fn mutate_job_entry<F>(ctx: &Ctx<'_>, id: i32, outcome: &mut DispatchOutcome, f: F) -> Option<Job>
where
    F: FnOnce(&mut Job, &mut DispatchOutcome) -> bool,
{
    let mut jobs = ctx.jobs_write();
    let Some(j) = jobs.get_mut(id) else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "Job not found.",
        );
        return None;
    };
    if !f(j, outcome) {
        return None;
    }
    let _ = j.save(&ctx.request_root);
    Some(j.clone())
}

/// Shared authorized single-job lookup helper.
fn lookup_and_authorize_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
    op_code: u16,
) -> Option<(i32, String, String)> {
    let (job, policy) = read_authorized_job(req, outcome, ctx, uri_attr, op_code)?;
    Some((job.id, job.dest, policy))
}

/// `Hold-Job` (0x000c).
pub fn hold_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some((id, dest, policy)) =
        lookup_and_authorize_job(req, outcome, ctx, uri_attr, op::HOLD_JOB)
    else {
        return;
    };
    let hold_until = req
        .find(tags::OPERATION, "job-hold-until")
        .and_then(attr_text)
        .unwrap_or_else(|| "indefinite".into());
    if !SUPPORTED_HOLD_UNTIL.contains(&hold_until.as_str()) {
        send_status(
            &mut outcome.response,
            status::ERROR_ATTRIBUTES_OR_VALUES,
            format!("Unsupported job-hold-until \"{hold_until}\"."),
        );
        return;
    }
    let Some(saved_job) = mutate_job_entry(ctx, id, outcome, |j, outcome| {
        if j.state.is_final() {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "Cannot hold a completed job.",
            );
            return false;
        }
        j.state = JobState::PendingHeld;
        j.hold_until = Some(hold_until);
        j.reasons = vec!["job-hold-until-specified".into()];
        true
    }) else {
        return;
    };

    ctx.event_with_state(
        events::Event::JobStateChanged,
        Some(&dest),
        Some(id),
        Some(JobState::PendingHeld as i32),
        Some(saved_job.title.clone()),
        format!("Job {id} held."),
    );
    ctx.audit("Hold-Job", Some(&format!("job/{id}")), "allowed", "held");
    outcome.response.code = status::OK;
    add_job_group(
        &mut outcome.response,
        &saved_job,
        ctx,
        &requested_attrs(req),
        &policy,
    );
}

/// `Release-Job` (0x000d) / `Resume-Job` (0x002f) / `Close-Job` (0x003b).
pub fn release_or_resume_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some((id, dest, policy)) = lookup_and_authorize_job(req, outcome, ctx, uri_attr, req.code)
    else {
        return;
    };
    let dest_holds_new = ctx.reg().find(&dest).is_some_and(printer_holds_new_jobs);
    let is_close = req.code == op::CLOSE_JOB;
    let Some(saved_job) = mutate_job_entry(ctx, id, outcome, |j, outcome| {
        if j.state.is_final() {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "Job is already completed.",
            );
            return false;
        }
        if j.state == JobState::Processing {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "Job is already processing.",
            );
            return false;
        }
        if j.files.is_empty() {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "Job has no documents.",
            );
            return false;
        }
        if is_close {
            if j.hold_until.is_some() {
                j.state = JobState::PendingHeld;
                j.reasons = vec!["job-hold-until-specified".into()];
            } else if dest_holds_new {
                j.state = JobState::PendingHeld;
                j.hold_until = Some("indefinite".into());
                j.reasons = vec!["hold-new-jobs".into()];
            } else {
                j.state = JobState::Pending;
                j.reasons = vec!["none".into()];
            }
        } else {
            j.state = JobState::Pending;
            j.hold_until = None;
            j.completed_at = None;
            j.reasons = vec!["none".into()];
        }
        true
    }) else {
        return;
    };

    ctx.event_with_state(
        events::Event::JobStateChanged,
        Some(&dest),
        Some(id),
        Some(saved_job.state as i32),
        Some(saved_job.title.clone()),
        format!("Job {id} state updated."),
    );
    ctx.audit(
        op::name(req.code),
        Some(&format!("job/{id}")),
        "allowed",
        "pending",
    );
    outcome.response.code = status::OK;
    add_job_group(
        &mut outcome.response,
        &saved_job,
        ctx,
        &requested_attrs(req),
        &policy,
    );
}

/// `Restart-Job` (0x000e) — restarts a completed/canceled/held job if spool
/// files are still preserved.
pub fn restart_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some((id, dest, policy)) =
        lookup_and_authorize_job(req, outcome, ctx, uri_attr, op::RESTART_JOB)
    else {
        return;
    };
    let hold_until = req
        .find(tags::OPERATION, "job-hold-until")
        .and_then(attr_text)
        .filter(|h| h != "no-hold");
    let Some(saved_job) = mutate_job_entry(ctx, id, outcome, |j, outcome| {
        if j.files.is_empty()
            || !j
                .files
                .iter()
                .all(|f| Job::data_path(&ctx.request_root, id, f.num).is_file())
        {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "Job document files are no longer available for restart.",
            );
            return false;
        }
        j.completed_at = None;
        j.processing_at = None;
        if let Some(h) = hold_until {
            j.state = JobState::PendingHeld;
            j.hold_until = Some(h);
            j.reasons = vec!["job-hold-until-specified".into()];
        } else {
            j.state = JobState::Pending;
            j.hold_until = None;
            j.reasons = vec!["job-restarted".into()];
        }
        true
    }) else {
        return;
    };

    ctx.event_with_state(
        events::Event::JobStateChanged,
        Some(&dest),
        Some(id),
        Some(saved_job.state as i32),
        Some(saved_job.title.clone()),
        format!("Job {id} restarted."),
    );
    ctx.audit(
        "Restart-Job",
        Some(&format!("job/{id}")),
        "allowed",
        "restarted",
    );
    outcome.response.code = status::OK;
    add_job_group(
        &mut outcome.response,
        &saved_job,
        ctx,
        &requested_attrs(req),
        &policy,
    );
}

/// `Resubmit-Job` (0x003a) and `Reprocess-Job` (0x002c) — clone an existing
/// job's preserved spool files into a brand-new job with a fresh job-id,
/// applying optional attribute overrides (for `Resubmit-Job`).
pub fn resubmit_or_reprocess_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some((src, policy)) = read_authorized_job(req, outcome, ctx, uri_attr, req.code) else {
        return;
    };
    let src_id = src.id;
    let dest = src.dest.clone();
    let Some(p) = ctx.reg().find(&dest).cloned() else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "The printer or class does not exist.",
        );
        return;
    };
    if !p.accepting {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_ACCEPTING_JOBS,
            "Destination is not accepting jobs.",
        );
        return;
    }
    if src.files.is_empty() {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_POSSIBLE,
            "Source job has no preserved documents.",
        );
        return;
    }

    // Read all preserved source files safely (`O_NOFOLLOW`) before allocating the new job.
    let mut doc_payloads = Vec::with_capacity(src.files.len());
    let mut total_bytes: u64 = 0;
    for f in &src.files {
        let path = Job::data_path(&ctx.request_root, src_id, f.num);
        let Ok(bytes) = read_file_nofollow_bounded(&path, ctx.max_decompressed_size) else {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "Source job document files are no longer available.",
            );
            return;
        };
        total_bytes = total_bytes.saturating_add(bytes.len() as u64);
        doc_payloads.push((f.clone(), bytes));
    }

    if !enforce_printer_user_allowed(ctx, outcome, &p, req.code) {
        return;
    }
    let user = originating_user(req, ctx);
    if req.code == op::RESUBMIT_JOB {
        if let Err((code, msg, unsup)) = validate_job_attrs(req, ctx) {
            for a in unsup {
                outcome.response.push(tags::UNSUPPORTED, a);
            }
            send_status(&mut outcome.response, code, msg);
            return;
        }
    }

    let override_attrs: Vec<Attribute> = if req.code == op::RESUBMIT_JOB {
        req.groups
            .iter()
            .find(|g| g.tag == tags::JOB)
            .map(|g| g.attributes.clone())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let copies = override_attrs
        .iter()
        .find(|a| a.name == "copies")
        .and_then(attr_int)
        .map_or(src.copies, |v| v as i32);

    if let Err((code, msg)) = check_job_limits_and_quotas(ctx, &p, &user, total_bytes, copies) {
        send_status(&mut outcome.response, code, msg);
        return;
    }

    let mut jobs = ctx.jobs_write();
    let new_id = jobs.alloc_id();
    let mut new_job = Job::new(new_id, dest.clone(), user.clone());
    new_job.title = req
        .find(tags::OPERATION, "job-name")
        .and_then(attr_text)
        .unwrap_or_else(|| src.title.clone());
    new_job.copies = copies;
    new_job.priority = override_attrs
        .iter()
        .find(|a| a.name == "job-priority")
        .and_then(attr_int)
        .map_or(src.priority, |v| v.clamp(1, 100) as i32);
    new_job.format.clone_from(&src.format);
    new_job.attrs.clone_from(&src.attrs);
    new_job.options.clone_from(&src.options);
    for a in &override_attrs {
        new_job.attrs.retain(|e| e.name != a.name);
        new_job.attrs.push(a.clone());
    }
    for (k, v) in extract_job_options(&override_attrs) {
        new_job.options.insert(k, v);
    }

    if let Some(hold) = hold_requested(&new_job.attrs) {
        new_job.state = JobState::PendingHeld;
        new_job.hold_until = Some(hold);
        new_job.reasons = vec!["job-hold-until-specified".into()];
    } else if printer_holds_new_jobs(&p) {
        new_job.state = JobState::PendingHeld;
        new_job.hold_until = Some("indefinite".into());
        new_job.reasons = vec!["hold-new-jobs".into()];
    }

    for (idx, (f, bytes)) in doc_payloads.into_iter().enumerate() {
        let num = idx as u32 + 1;
        if let Err(e) = Job::write_data_file(&ctx.request_root, new_id, num, &bytes) {
            send_status(
                &mut outcome.response,
                status::ERROR_INTERNAL,
                format!("spool copy failed: {e}"),
            );
            return;
        }
        new_job.files.push(JobFile {
            num,
            filetype: f.filetype,
            size: bytes.len() as u64,
            name: f.name,
            format: f.format,
        });
    }

    let saved_job = new_job.clone();
    if let Err(e) = jobs.add(&ctx.request_root, new_job) {
        send_status(
            &mut outcome.response,
            status::ERROR_INTERNAL,
            format!("cannot save job: {e}"),
        );
        return;
    }
    drop(jobs);

    ctx.event_with_state(
        events::Event::JobCreated,
        Some(&dest),
        Some(new_id),
        Some(saved_job.state as i32),
        Some(saved_job.title.clone()),
        format!("Job {new_id} created from job {src_id}."),
    );
    ctx.audit(
        op::name(req.code),
        Some(&format!("job/{new_id}")),
        "allowed",
        format!("source=job/{src_id} dest={dest}"),
    );
    outcome.response.code = status::OK;
    add_job_group(
        &mut outcome.response,
        &saved_job,
        ctx,
        &requested_attrs(req),
        &policy,
    );
}

/// `Promote-Job` (0x0030) — raise a non-final job to top priority (100).
pub fn promote_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some((id, dest, policy)) =
        lookup_and_authorize_job(req, outcome, ctx, uri_attr, op::PROMOTE_JOB)
    else {
        return;
    };
    let Some(saved_job) = mutate_job_entry(ctx, id, outcome, |j, outcome| {
        if j.state.is_final() {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "Cannot promote a completed job.",
            );
            return false;
        }
        j.priority = 100;
        true
    }) else {
        return;
    };

    ctx.event_with_state(
        events::Event::JobConfigChanged,
        Some(&dest),
        Some(id),
        Some(saved_job.state as i32),
        Some(saved_job.title.clone()),
        format!("Job {id} promoted."),
    );
    ctx.audit(
        "Promote-Job",
        Some(&format!("job/{id}")),
        "allowed",
        "priority=100",
    );
    outcome.response.code = status::OK;
    add_job_group(
        &mut outcome.response,
        &saved_job,
        ctx,
        &requested_attrs(req),
        &policy,
    );
}

/// `Schedule-Job-After` (0x0031) — schedule `job` immediately after `job-id-next`
/// (or at the back of the queue if omitted), adjusting priority cleanly.
pub fn schedule_job_after(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some((id, dest, policy)) =
        lookup_and_authorize_job(req, outcome, ctx, uri_attr, op::SCHEDULE_JOB_AFTER)
    else {
        return;
    };
    let after_id = req
        .find(tags::OPERATION, "job-id-next")
        .and_then(attr_int)
        .map(|v| v as i32)
        .or_else(|| {
            req.find(tags::OPERATION, "job-uri-next")
                .and_then(attr_text)
                .filter(|u| u.contains("/jobs/"))
                .and_then(|u| u.rsplit('/').next().and_then(|s| s.parse::<i32>().ok()))
        });

    let mut jobs = ctx.jobs_write();
    let new_priority = if let Some(aid) = after_id {
        let Some(ref_job) = jobs.get(aid) else {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_FOUND,
                format!("Reference job {aid} not found."),
            );
            return;
        };
        if ref_job.dest != dest {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "Reference job belongs to a different printer.",
            );
            return;
        }
        (ref_job.priority - 1).clamp(1, 100)
    } else {
        1
    };

    let Some(j) = jobs.get_mut(id) else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "Job not found.",
        );
        return;
    };
    if j.state.is_final() {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_POSSIBLE,
            "Cannot reschedule a completed job.",
        );
        return;
    }
    j.priority = new_priority;
    if let Some(aid) = after_id {
        j.options
            .insert("job-scheduled-after".into(), aid.to_string());
    }
    let _ = j.save(&ctx.request_root);
    let saved_job = j.clone();
    drop(jobs);

    ctx.event_with_state(
        events::Event::JobConfigChanged,
        Some(&dest),
        Some(id),
        Some(saved_job.state as i32),
        Some(saved_job.title.clone()),
        format!("Job {id} rescheduled (priority={new_priority})."),
    );
    ctx.audit(
        "Schedule-Job-After",
        Some(&format!("job/{id}")),
        "allowed",
        format!("priority={new_priority} after={after_id:?}"),
    );
    outcome.response.code = status::OK;
    add_job_group(
        &mut outcome.response,
        &saved_job,
        ctx,
        &requested_attrs(req),
        &policy,
    );
}

/// `Set-Job-Attributes` (0x0014) — update settable attributes on an active job.
pub fn set_job_attributes(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some((id, dest, policy)) =
        lookup_and_authorize_job(req, outcome, ctx, uri_attr, op::SET_JOB_ATTRIBUTES)
    else {
        return;
    };

    let job_group_attrs: Vec<Attribute> = req
        .groups
        .iter()
        .find(|g| g.tag == tags::JOB)
        .map(|g| g.attributes.clone())
        .unwrap_or_default();

    // Reject non-settable attributes cleanly.
    let mut not_settable = Vec::new();
    for a in &job_group_attrs {
        let name = a.name.as_str();
        if !SETTABLE_JOB_ATTRS.contains(&name.as_ref()) {
            not_settable.push(Attribute::new(
                name.as_ref(),
                tags::NOTSETTABLE,
                vec![Value::NotSettable],
            ));
        }
    }
    if !not_settable.is_empty() {
        for a in not_settable {
            outcome.response.push(tags::UNSUPPORTED, a);
        }
        send_status(
            &mut outcome.response,
            status::ERROR_ATTRIBUTES_NOT_SETTABLE,
            "One or more attributes are not settable.",
        );
        return;
    }

    if let Err((code, msg, unsup)) = validate_job_attrs(req, ctx) {
        for a in unsup {
            outcome.response.push(tags::UNSUPPORTED, a);
        }
        send_status(&mut outcome.response, code, msg);
        return;
    }

    let Some(saved_job) = mutate_job_entry(ctx, id, outcome, |j, outcome| {
        if j.state.is_final() {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "Cannot modify attributes of a completed job.",
            );
            return false;
        }
        for a in &job_group_attrs {
            match a.name.as_str().as_ref() {
                "job-name" => {
                    if let Some(t) = attr_text(a) {
                        j.title = t;
                    }
                }
                "job-priority" => {
                    if let Some(p) = attr_int(a) {
                        j.priority = p.clamp(1, 100) as i32;
                    }
                }
                "copies" => {
                    if let Some(c) = attr_int(a) {
                        j.copies = c as i32;
                    }
                }
                "job-hold-until" => {
                    if let Some(h) = attr_text(a) {
                        if h == "no-hold" {
                            j.hold_until = None;
                            if j.state == JobState::PendingHeld && !j.files.is_empty() {
                                j.state = JobState::Pending;
                                j.reasons = vec!["none".into()];
                            }
                        } else {
                            j.hold_until = Some(h);
                            if j.state == JobState::Pending {
                                j.state = JobState::PendingHeld;
                                j.reasons = vec!["job-hold-until-specified".into()];
                            }
                        }
                    }
                }
                _ => {}
            }
            j.attrs.retain(|e| e.name != a.name);
            j.attrs.push(a.clone());
        }
        for (k, v) in extract_job_options(&job_group_attrs) {
            j.options.insert(k, v);
        }
        true
    }) else {
        return;
    };

    ctx.event_with_state(
        events::Event::JobConfigChanged,
        Some(&dest),
        Some(id),
        Some(saved_job.state as i32),
        Some(saved_job.title.clone()),
        format!("Job {id} attributes modified."),
    );
    ctx.audit(
        "Set-Job-Attributes",
        Some(&format!("job/{id}")),
        "allowed",
        "attributes updated",
    );
    outcome.response.code = status::OK;
    add_job_group(
        &mut outcome.response,
        &saved_job,
        ctx,
        &requested_attrs(req),
        &policy,
    );
}

/// `CUPS-Authenticate-Job` (0x400e) — authenticate & release held job.
pub fn cups_authenticate_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some((id, dest, policy)) =
        lookup_and_authorize_job(req, outcome, ctx, uri_attr, op::CUPS_AUTHENTICATE_JOB)
    else {
        return;
    };

    let Some(saved_job) = mutate_job_entry(ctx, id, outcome, |j, outcome| {
        if j.state.is_final() {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "Cannot authenticate a completed job.",
            );
            return false;
        }
        if let Some(auth_info) = req.find(tags::OPERATION, "auth-info") {
            let count = auth_info.values.len();
            j.options
                .insert("auth-info-provided".into(), count.to_string());
        }
        j.reasons.retain(|r| r != "cups-held-for-authentication");
        if j.state == JobState::PendingHeld && !j.files.is_empty() && j.hold_until.is_none() {
            j.state = JobState::Pending;
            if j.reasons.is_empty() {
                j.reasons.push("none".into());
            }
        }
        true
    }) else {
        return;
    };

    ctx.event_with_state(
        events::Event::JobStateChanged,
        Some(&dest),
        Some(id),
        Some(saved_job.state as i32),
        Some(saved_job.title.clone()),
        format!("Job {id} authenticated."),
    );
    ctx.audit(
        "CUPS-Authenticate-Job",
        Some(&format!("job/{id}")),
        "allowed",
        "authenticated",
    );
    outcome.response.code = status::OK;
    add_job_group(
        &mut outcome.response,
        &saved_job,
        ctx,
        &requested_attrs(req),
        &policy,
    );
}

/// Validate `job-printer-uri` destination for `CUPS-Move-Job` (existence,
/// destination `op_policy`, accepting state, and per-printer `AllowUser`/`DenyUser`).
fn resolve_move_target(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    owner: Option<&str>,
) -> Option<String> {
    let target_uri = req
        .groups
        .iter()
        .find(|g| g.tag == tags::JOB)
        .and_then(|g| g.find("job-printer-uri"))
        .or_else(|| req.find(tags::OPERATION, "job-printer-uri"))
        .and_then(attr_text);
    let Some(target_uri) = target_uri else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing job-printer-uri.",
        );
        return None;
    };
    let target_printer = {
        let registry = ctx.reg();
        let Some((p, _)) = registry.validate_dest(&target_uri) else {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_FOUND,
                "Destination printer does not exist.",
            );
            return None;
        };
        p.clone()
    };
    let target_policy = ctx.effective_policy_name(Some(&target_printer)).to_string();
    if !authorize_op(
        ctx,
        outcome,
        &target_policy,
        op::CUPS_MOVE_JOB,
        owner,
        Some(&target_printer.name),
    ) {
        return None;
    }
    if !target_printer.accepting {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_ACCEPTING_JOBS,
            "Destination printer is not accepting jobs.",
        );
        return None;
    }
    if !enforce_printer_user_allowed(ctx, outcome, &target_printer, op::CUPS_MOVE_JOB) {
        return None;
    }
    Some(target_printer.name)
}

/// `CUPS-Move-Job` (0x400d) — moves either a single job (`job-id` / `job-uri`)
/// or ALL active non-processing jobs from a source printer (`printer-uri`
/// without `job-id`, CUPS `Move-All-Jobs` semantics) to `job-printer-uri`.
pub fn cups_move_job(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    // Authorize BEFORE validating destination existence/accepting state so
    // anonymous callers cannot probe destination queues.
    if job_id(req, uri_attr).is_some() {
        let Some((src_job, policy)) =
            read_authorized_job(req, outcome, ctx, uri_attr, op::CUPS_MOVE_JOB)
        else {
            return;
        };
        let id = src_job.id;
        let old_dest = src_job.dest;
        let Some(target_dest) = resolve_move_target(req, outcome, ctx, Some(&src_job.username))
        else {
            return;
        };
        let Some(saved_job) = mutate_job_entry(ctx, id, outcome, |j, outcome| {
            if j.state.is_final() || j.state == JobState::Processing {
                send_status(
                    &mut outcome.response,
                    status::ERROR_NOT_POSSIBLE,
                    "Cannot move a completed or processing job.",
                );
                return false;
            }
            j.dest.clone_from(&target_dest);
            true
        }) else {
            return;
        };

        ctx.event_with_state(
            events::Event::JobConfigChanged,
            Some(&target_dest),
            Some(id),
            Some(saved_job.state as i32),
            Some(saved_job.title.clone()),
            format!("Job {id} moved from {old_dest} to {target_dest}."),
        );
        ctx.audit(
            "CUPS-Move-Job",
            Some(&format!("job/{id}")),
            "allowed",
            format!("{old_dest} -> {target_dest}"),
        );
        outcome.response.code = status::OK;
        add_job_group(
            &mut outcome.response,
            &saved_job,
            ctx,
            &requested_attrs(req),
            &policy,
        );
        return;
    }

    // Move-All-Jobs: move all movable jobs from source `printer-uri` to `target_dest`.
    let Some(src_uri) = uri_attr.and_then(attr_text) else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing \"printer-uri\" attribute.",
        );
        return;
    };
    let src_dest = {
        let registry = ctx.reg();
        let Some((p, _)) = registry.validate_dest(&src_uri) else {
            drop(registry);
            let policy = ctx.effective_policy_for_dest(None);
            if !authorize_op(
                ctx,
                outcome,
                &policy,
                op::CUPS_MOVE_JOB,
                None,
                Some(&src_uri),
            ) {
                return;
            }
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_FOUND,
                "Source printer does not exist.",
            );
            return;
        };
        p.name.clone()
    };
    let policy = ctx.effective_policy_for_dest(Some(&src_dest));
    if !authorize_op(
        ctx,
        outcome,
        &policy,
        op::CUPS_MOVE_JOB,
        None,
        Some(&src_dest),
    ) {
        return;
    }
    let Some(target_dest) = resolve_move_target(req, outcome, ctx, None) else {
        return;
    };

    let mut moved_ids = Vec::new();
    {
        let mut jobs = ctx.jobs_write();
        for j in jobs.by_id.values_mut() {
            if j.dest == src_dest && !j.state.is_final() && j.state != JobState::Processing {
                j.dest.clone_from(&target_dest);
                let _ = j.save(&ctx.request_root);
                moved_ids.push(j.id);
            }
        }
    }
    for jid in &moved_ids {
        ctx.event_with_state(
            events::Event::JobConfigChanged,
            Some(&target_dest),
            Some(*jid),
            None,
            None,
            format!("Job {jid} moved from {src_dest} to {target_dest}."),
        );
    }
    ctx.audit(
        "CUPS-Move-Job",
        Some(&src_dest),
        "allowed",
        format!("moved {} job(s) to {target_dest}", moved_ids.len()),
    );
    outcome.response.code = status::OK;
}

/// `Get-Job-Attributes` (0x0009).
pub fn get_job_attributes(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some((job, policy)) =
        read_authorized_job(req, outcome, ctx, uri_attr, op::GET_JOB_ATTRIBUTES)
    else {
        return;
    };
    outcome.response.code = status::OK;
    add_job_group(
        &mut outcome.response,
        &job,
        ctx,
        &requested_attrs(req),
        &policy,
    );
}

/// `CUPS-Get-Document` (0x4027) — strictly authorized (`@OWNER`/`@SYSTEM`),
/// reads spool file with `O_NOFOLLOW`.
pub fn get_document(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some((job, policy)) =
        read_authorized_job(req, outcome, ctx, uri_attr, op::CUPS_GET_DOCUMENT)
    else {
        return;
    };
    let id = job.id;
    let num = req
        .find(tags::OPERATION, "document-number")
        .and_then(attr_int)
        .unwrap_or(1)
        .max(1) as u32;

    let Some(file) = job.files.iter().find(|f| f.num == num) else {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "Document number does not exist.",
        );
        return;
    };
    let path = Job::data_path(&ctx.request_root, id, num);
    match read_file_nofollow_bounded(&path, ctx.max_decompressed_size) {
        Ok(bytes) => {
            outcome.response.document = bytes;
            outcome.response.code = status::OK;
            let g = outcome.response.group_mut(tags::OPERATION);
            g.attributes.push(Attribute::new(
                "document-format",
                tags::MIMETYPE,
                vec![Value::MimeMediaType(file.format.as_str().into())],
            ));
            add_job_group(
                &mut outcome.response,
                &job,
                ctx,
                &requested_attrs(req),
                &policy,
            );
        }
        Err(e) => {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_FOUND,
                format!("Cannot open document: {e}"),
            );
        }
    }
}

/// `Get-Documents` (0x0035) and `Get-Document-Attributes` (0x0034).
pub fn get_documents(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some((job, policy)) = read_authorized_job(req, outcome, ctx, uri_attr, req.code) else {
        return;
    };
    let id = job.id;
    let only = req
        .find(tags::OPERATION, "document-number")
        .and_then(attr_int)
        .map(|n| n as u32);
    if req.code == op::GET_DOCUMENT_ATTRIBUTES && only.is_none() {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing \"document-number\" attribute.",
        );
        return;
    }
    let mut found = false;
    let scheme = if ctx.is_encrypted { "ipps" } else { "ipp" };
    for f in &job.files {
        if let Some(n) = only {
            if f.num != n {
                continue;
            }
        }
        found = true;
        let g = outcome.response.new_group_mut(tags::DOCUMENT);
        let mut push = |name: &str, tag: u8, v: Value| {
            g.attributes.push(Attribute::new(name, tag, vec![v]));
        };
        push(
            "document-number",
            tags::INTEGER,
            Value::Integer(f.num as i32),
        );
        push(
            "document-format",
            tags::MIMETYPE,
            Value::MimeMediaType(f.format.as_str().into()),
        );
        if !should_redact_job_attr(ctx, &policy, &job.username, "document-name")
            && !should_redact_job_attr(ctx, &policy, &job.username, "job-name")
        {
            push(
                "document-name",
                tags::NAME,
                Value::Name(f.name.as_str().into()),
            );
        }
        push(
            "document-uri",
            tags::URI,
            Value::Uri(
                format!(
                    "{scheme}://{}:{}/jobs/{}/documents/{}",
                    ctx.hostname, ctx.port, id, f.num
                )
                .into(),
            ),
        );
        push("document-job-id", tags::INTEGER, Value::Integer(id));
        push("copies", tags::INTEGER, Value::Integer(job.copies));
        push(
            "document-k-octets",
            tags::INTEGER,
            Value::Integer(f.size.div_ceil(1024) as i32),
        );
    }
    if !found {
        send_status(
            &mut outcome.response,
            status::ERROR_NOT_FOUND,
            "Document not found.",
        );
        return;
    }
    outcome.response.code = status::OK;
}

/// `Cancel-Document` (0x0033) — real document cancellation & spool cleanup.
pub fn cancel_document(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some((id, dest, _)) =
        lookup_and_authorize_job(req, outcome, ctx, uri_attr, op::CANCEL_DOCUMENT)
    else {
        return;
    };
    let Some(doc_num) = req
        .find(tags::OPERATION, "document-number")
        .and_then(attr_int)
        .filter(|&n| n >= 1)
        .map(|n| n as u32)
    else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing or invalid \"document-number\" attribute.",
        );
        return;
    };

    if mutate_job_entry(ctx, id, outcome, |j, outcome| {
        if j.state.is_final() {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "Cannot cancel document of a completed job.",
            );
            return false;
        }
        let before = j.files.len();
        j.files.retain(|f| f.num != doc_num);
        if j.files.len() == before {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_FOUND,
                "Document not found.",
            );
            return false;
        }
        let _ = std::fs::remove_file(Job::data_path(&ctx.request_root, id, doc_num));
        if let Some(first) = j.files.first() {
            j.format.clone_from(&first.format);
        }
        true
    })
    .is_none()
    {
        return;
    }

    ctx.event_with_state(
        events::Event::JobConfigChanged,
        Some(&dest),
        Some(id),
        None,
        None,
        format!("Document {doc_num} of job {id} canceled."),
    );
    ctx.audit(
        "Cancel-Document",
        Some(&format!("job/{id}/doc/{doc_num}")),
        "allowed",
        "canceled",
    );
    outcome.response.code = status::OK;
}

/// `Set-Document-Attributes` (0x0037) — real per-document attribute mutation.
pub fn set_document_attributes(
    req: &IppMessage,
    outcome: &mut DispatchOutcome,
    ctx: &Ctx<'_>,
    uri_attr: Option<&Attribute>,
) {
    let Some((id, dest, _)) =
        lookup_and_authorize_job(req, outcome, ctx, uri_attr, op::SET_DOCUMENT_ATTRIBUTES)
    else {
        return;
    };
    let Some(doc_num) = req
        .find(tags::OPERATION, "document-number")
        .and_then(attr_int)
        .filter(|&n| n >= 1)
        .map(|n| n as u32)
    else {
        send_status(
            &mut outcome.response,
            status::ERROR_BAD_REQUEST,
            "Missing or invalid \"document-number\" attribute.",
        );
        return;
    };

    let doc_attrs: Vec<Attribute> = req
        .groups
        .iter()
        .filter(|g| g.tag == tags::DOCUMENT)
        .flat_map(|g| g.attributes.iter().cloned())
        .collect();

    let mut not_settable = Vec::new();
    for a in &doc_attrs {
        let name = a.name.as_str();
        if !matches!(
            name.as_ref(),
            "document-name" | "document-format" | "copies" | "media" | "sides"
        ) {
            not_settable.push(Attribute::new(
                name.as_ref(),
                tags::NOTSETTABLE,
                vec![Value::NotSettable],
            ));
        }
    }
    if !not_settable.is_empty() {
        for a in not_settable {
            outcome.response.push(tags::UNSUPPORTED, a);
        }
        send_status(
            &mut outcome.response,
            status::ERROR_ATTRIBUTES_NOT_SETTABLE,
            "One or more document attributes are not settable.",
        );
        return;
    }

    if mutate_job_entry(ctx, id, outcome, |j, outcome| {
        if j.state.is_final() {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_POSSIBLE,
                "Cannot modify document of a completed job.",
            );
            return false;
        }
        let Some(file) = j.files.iter_mut().find(|f| f.num == doc_num) else {
            send_status(
                &mut outcome.response,
                status::ERROR_NOT_FOUND,
                "Document not found.",
            );
            return false;
        };
        for a in &doc_attrs {
            match a.name.as_str().as_ref() {
                "document-name" => {
                    if let Some(v) = attr_text(a) {
                        file.name = v;
                    }
                }
                "document-format" => {
                    if let Some(v) = attr_text(a) {
                        file.format.clone_from(&v);
                        file.filetype = v;
                    }
                }
                _ => {}
            }
        }
        if let Some(first) = j.files.first() {
            j.format.clone_from(&first.format);
        }
        true
    })
    .is_none()
    {
        return;
    }

    ctx.event_with_state(
        events::Event::JobConfigChanged,
        Some(&dest),
        Some(id),
        None,
        None,
        format!("Document {doc_num} of job {id} updated."),
    );
    ctx.audit(
        "Set-Document-Attributes",
        Some(&format!("job/{id}/doc/{doc_num}")),
        "allowed",
        "updated",
    );
    outcome.response.code = status::OK;
}
