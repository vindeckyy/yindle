//! Shared response-construction helpers — ports of `ippNewResponse`,
//! `send_ipp_status`, `copy_printer_attrs`, `create_requested_array`,
//! and the `CommonData` attribute block from `cupsdCreateCommonData`.
//!
//! Same rationale as `dispatch`: intentional `i64`/`usize`→`i32` IPP-int
//! downcasts (bounded by the model), `&Option` helper params kept for the
//! shared call sites, and table-sized fns — allowed module-wide.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::ref_option
)]

use ipp_codec::{tags, Attribute, IppMessage, Value};
use printer::{ipp_datetime, now, ptype, state_reasons_attr, Printer};
use std::collections::HashSet;

use crate::ctx::Ctx;
use crate::ppd::{load_queue_ppd_capabilities, PpdCapabilities};

/// `ippNewResponse()` — response message seeded from the request:
/// same version + request-id, `attributes-charset` echoed from the
/// request's first op attr when valid (else `utf-8`), same for
/// `attributes-natural-language` (else `DefaultLanguage`).
pub fn new_response(req: &IppMessage, default_language: &str) -> IppMessage {
    let mut resp = IppMessage::new(0);
    resp.version = req.version;
    resp.request_id = req.request_id;

    let op = req.group(tags::OPERATION);
    let charset = op
        .and_then(|g| g.attributes.first())
        .filter(|a| a.name == "attributes-charset" && a.values.len() == 1)
        .and_then(|a| a.first())
        .and_then(|v| match v {
            Value::Charset(t) => Some(t.clone()),
            _ => None,
        });
    let language = op
        .and_then(|g| g.attributes.get(1))
        .filter(|a| a.name == "attributes-natural-language" && a.values.len() == 1)
        .and_then(|a| a.first())
        .and_then(|v| match v {
            Value::NaturalLanguage(t) => Some(t.clone()),
            _ => None,
        });

    resp.push(
        tags::OPERATION,
        Attribute::new(
            "attributes-charset",
            tags::CHARSET,
            vec![Value::Charset(charset.unwrap_or_else(|| "utf-8".into()))],
        ),
    );
    resp.push(
        tags::OPERATION,
        Attribute::new(
            "attributes-natural-language",
            tags::LANGUAGE,
            vec![Value::NaturalLanguage(
                language.unwrap_or_else(|| default_language.into()),
            )],
        ),
    );
    resp
}

/// `send_ipp_status()` — set the response status code and append a
/// `status-message` text attr to the operation group.
pub fn send_status(resp: &mut IppMessage, code: u16, message: impl Into<String>) {
    resp.code = code;
    resp.push(
        tags::OPERATION,
        Attribute::new(
            "status-message",
            tags::TEXT,
            vec![Value::Text(message.into().into())],
        ),
    );
}

/// `ippCreateRequestedArray()` — names from the request's
/// `requested-attributes` keyword attr; `None` = all attrs.
#[must_use]
pub fn requested_attrs(req: &IppMessage) -> Option<Vec<String>> {
    let attr = req.find(tags::OPERATION, "requested-attributes")?;
    let names: Vec<String> = attr
        .values
        .iter()
        .filter_map(|v| match v {
            Value::Keyword(t) | Value::Name(t) => Some(t.as_str().to_string()),
            _ => None,
        })
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

/// IPP job-attribute names — the bases for `xxx-default`/`xxx-supported`
/// job-template attributes (RFC 8011 §5.2 + media-col).
const JOB_ATTRS: &[&str] = &[
    "copies",
    "finishings",
    "job-hold-until",
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
    "sides",
    "jpeg-k-octets",
    "jpeg-x-dimension",
    "jpeg-y-dimension",
    "pdf-k-octets",
    "pdf-versions",
    "print-as-raster",
];

/// Is `name` a job-template attribute (`xxx-default`, `xxx-supported`
/// whose base is a job attribute, or a media-col database/ready entry)?
fn is_job_template(name: &str) -> bool {
    if matches!(
        name,
        "media-col-database" | "media-col-ready" | "media-ready"
    ) {
        return true;
    }
    let base = name
        .strip_suffix("-default")
        .or_else(|| name.strip_suffix("-supported"))
        .or_else(|| name.strip_suffix("-ready"));
    match base {
        Some(b) => JOB_ATTRS.contains(&b) || b.starts_with("media-"),
        None => JOB_ATTRS.contains(&name),
    }
}

/// `cupsArrayFind(ra, name)` — `requested-attributes` filter predicate.
pub fn wants(ra: &Option<Vec<String>>, name: &str) -> bool {
    let opt_in_only = matches!(name, "media-col-database" | "media-size-database");
    match ra {
        None => !opt_in_only,
        Some(ra) => ra.iter().any(|n| {
            n == name
                || (!opt_in_only
                    && (n == "all"
                        || (n == "job-template" && is_job_template(name))
                        || (n == "printer-description" && !is_job_template(name))
                        || (n == "printer-defaults" && name.ends_with("-default"))
                        || (n == "document-format" && name.starts_with("document-format"))))
        }),
    }
}

/// URI assembly mirroring `httpAssembleURIf` for queue URIs:
/// `ipp://host[:port]/{printers|classes}/{name}` (ipps when encrypted).
pub fn queue_uri(ctx: &Ctx, is_class: bool, name: &str) -> String {
    let scheme = if ctx.is_encrypted { "ipps" } else { "ipp" };
    let sub = if is_class { "classes" } else { "printers" };
    format!("{scheme}://{}:{}/{}/{}", ctx.hostname, ctx.port, sub, name)
}

/// Web-URI assembly (`/icons/`, `/printers/`, strings) — http(s).
fn web_uri(ctx: &Ctx, path: &str) -> String {
    let scheme = if ctx.is_encrypted { "https" } else { "http" };
    format!("{scheme}://{}:{}{}", ctx.hostname, ctx.port, path)
}

/// Push attributes filtered by `requested-attributes`, deduplicating names
/// within the current printer's emission so no duplicate attribute can ever be
/// produced on the wire.
fn copy_attrs_dedup(
    group: &mut ipp_codec::Group,
    attrs: &[Attribute],
    ra: &Option<Vec<String>>,
    seen: &mut HashSet<String>,
) {
    for a in attrs {
        if a.is_separator() {
            continue;
        }
        let key = a.name.as_str().into_owned();
        if wants(ra, &key) && seen.insert(key) {
            group.attributes.push(a.clone());
        }
    }
}

/// Compute the supported `document-format` list for a printer (honoring queue
/// PPD `*cupsFilter`/`*cupsFilter2` declarations plus standard driverless types).
#[must_use]
pub fn printer_supported_formats(p: &Printer, ctx: &Ctx) -> Vec<String> {
    let mut formats = vec![
        "application/octet-stream".to_string(),
        "application/pdf".to_string(),
        "application/postscript".to_string(),
        "image/jpeg".to_string(),
        "image/png".to_string(),
        "image/pwg-raster".to_string(),
        "image/urf".to_string(),
        "text/plain".to_string(),
    ];
    if let Some(caps) = load_queue_ppd_capabilities(&ctx.server_root, &p.name) {
        for f in caps.filter_formats {
            if !formats.iter().any(|x| x.eq_ignore_ascii_case(&f)) {
                formats.push(f);
            }
        }
    }
    formats
}

/// `copy_printer_attrs()` — dynamic per-request attrs, stored printer attrs
/// (honoring queue PPD capabilities where present), and `CommonData`, with
/// strict per-printer attribute uniqueness (zero duplicates).
pub fn copy_printer_attrs(
    resp: &mut IppMessage,
    p: &Printer,
    ctx: &Ctx,
    ra: &Option<Vec<String>>,
    queued_job_count: i32,
) {
    let curtime = now();
    let is_default = ctx.reg().default.as_deref() == Some(p.name.as_str());
    let ppd_caps = load_queue_ppd_capabilities(&ctx.server_root, &p.name);
    let mut seen: HashSet<String> = HashSet::with_capacity(128);
    let _ = resp.new_group_mut(tags::PRINTER);

    let mut push_attr = |resp: &mut IppMessage, attr: Attribute| {
        let name = attr.name.as_str().into_owned();
        if wants(ra, &name) && seen.insert(name) {
            if let Some(g) = resp.groups.last_mut().filter(|g| g.tag == tags::PRINTER) {
                g.attributes.push(attr);
            }
        }
    };

    if p.marker_time != 0 {
        push_attr(
            resp,
            Attribute::new(
                "marker-change-time",
                tags::INTEGER,
                vec![Value::Integer(p.marker_time as i32)],
            ),
        );
    }

    // member-uris & member-names for classes.
    if !p.members.is_empty() {
        let reg = ctx.reg();
        let uri_vals: Vec<Value> = p
            .members
            .iter()
            .map(|m| {
                let member_is_class = reg.printers.get(m.as_str()).is_some_and(Printer::is_class);
                Value::Uri(queue_uri(ctx, member_is_class, m).into())
            })
            .collect();
        drop(reg);
        push_attr(resp, Attribute::new("member-uris", tags::URI, uri_vals));
        let name_vals: Vec<Value> = p
            .members
            .iter()
            .map(|m| Value::Name(m.as_str().into()))
            .collect();
        push_attr(resp, Attribute::new("member-names", tags::NAME, name_vals));
    }

    // printer-alert / printer-alert-description emitted ONCE (printer value or default).
    if let Some(a) = &p.alert {
        push_attr(
            resp,
            Attribute::new(
                "printer-alert",
                tags::STRING,
                vec![Value::OctetString(a.clone().into_bytes())],
            ),
        );
    } else {
        push_attr(
            resp,
            Attribute::new(
                "printer-alert",
                tags::STRING,
                vec![Value::OctetString(vec![
                    0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ])],
            ),
        );
    }
    if let Some(a) = &p.alert_description {
        push_attr(
            resp,
            Attribute::new(
                "printer-alert-description",
                tags::TEXT,
                vec![Value::Text(a.as_str().into())],
            ),
        );
    } else {
        push_attr(
            resp,
            Attribute::new(
                "printer-alert-description",
                tags::TEXT,
                vec![Value::Text("ready".into())],
            ),
        );
    }

    push_attr(
        resp,
        Attribute::new(
            "printer-config-change-date-time",
            tags::DATE,
            vec![ipp_datetime(p.config_time)],
        ),
    );
    push_attr(
        resp,
        Attribute::new(
            "printer-config-change-time",
            tags::INTEGER,
            vec![Value::Integer(p.config_time as i32)],
        ),
    );
    push_attr(
        resp,
        Attribute::new(
            "printer-current-time",
            tags::DATE,
            vec![ipp_datetime(curtime)],
        ),
    );

    match &p.reg_name {
        Some(r) => push_attr(
            resp,
            Attribute::new(
                "printer-dns-sd-name",
                tags::NAME,
                vec![Value::Name(r.as_str().into())],
            ),
        ),
        None => push_attr(
            resp,
            Attribute::new("printer-dns-sd-name", tags::NOVALUE, vec![Value::NoValue]),
        ),
    }

    if let Some(ep) = &p.error_policy {
        push_attr(
            resp,
            Attribute::new(
                "printer-error-policy",
                tags::NAME,
                vec![Value::Name(ep.as_str().into())],
            ),
        );
    }
    if p.is_class() {
        push_attr(
            resp,
            Attribute::new(
                "printer-error-policy-supported",
                tags::NAME,
                vec![Value::Name("retry-current-job".into())],
            ),
        );
    } else {
        let errs = [
            "abort-job",
            "retry-current-job",
            "retry-job",
            "stop-printer",
        ];
        push_attr(
            resp,
            Attribute::new(
                "printer-error-policy-supported",
                tags::NAME,
                errs.iter().map(|e| Value::Name((*e).into())).collect(),
            ),
        );
    }

    push_attr(
        resp,
        Attribute::new(
            "printer-icons",
            tags::URI,
            vec![Value::Uri(
                web_uri(ctx, &format!("/icons/{}.png", p.name)).into(),
            )],
        ),
    );
    push_attr(
        resp,
        Attribute::new(
            "printer-is-accepting-jobs",
            tags::BOOLEAN,
            vec![Value::Boolean(p.accepting)],
        ),
    );
    push_attr(
        resp,
        Attribute::new(
            "printer-is-shared",
            tags::BOOLEAN,
            vec![Value::Boolean(p.shared)],
        ),
    );
    push_attr(
        resp,
        Attribute::new(
            "printer-is-temporary",
            tags::BOOLEAN,
            vec![Value::Boolean(p.temporary)],
        ),
    );
    push_attr(
        resp,
        Attribute::new(
            "printer-more-info",
            tags::URI,
            vec![Value::Uri(
                web_uri(
                    ctx,
                    &format!(
                        "/{}/{}",
                        if p.is_class() { "classes" } else { "printers" },
                        p.name
                    ),
                )
                .into(),
            )],
        ),
    );

    let effective_policy = ctx.effective_policy_name(Some(p));
    push_attr(
        resp,
        Attribute::new(
            "printer-op-policy",
            tags::NAME,
            vec![Value::Name(effective_policy.into())],
        ),
    );

    push_attr(
        resp,
        Attribute::new("printer-state", tags::ENUM, vec![Value::Enum(p.state)]),
    );
    push_attr(
        resp,
        Attribute::new(
            "printer-state-change-date-time",
            tags::DATE,
            vec![ipp_datetime(p.state_time)],
        ),
    );
    push_attr(
        resp,
        Attribute::new(
            "printer-state-change-time",
            tags::INTEGER,
            vec![Value::Integer(p.state_time as i32)],
        ),
    );
    push_attr(
        resp,
        Attribute::new(
            "printer-state-message",
            tags::TEXT,
            vec![Value::Text(p.state_message.as_str().into())],
        ),
    );
    push_attr(resp, state_reasons_attr(p));
    push_attr(
        resp,
        Attribute::new(
            "printer-strings-uri",
            tags::URI,
            vec![Value::Uri(
                web_uri(ctx, &format!("/strings/{}.strings", ctx.language)).into(),
            )],
        ),
    );
    push_attr(
        resp,
        Attribute::new(
            "printer-type",
            tags::ENUM,
            vec![Value::Enum(p.effective_ptype(is_default))],
        ),
    );
    push_attr(
        resp,
        Attribute::new(
            "printer-up-time",
            tags::INTEGER,
            vec![Value::Integer(curtime as i32)],
        ),
    );
    push_attr(
        resp,
        Attribute::new(
            "printer-uri-supported",
            tags::URI,
            vec![Value::Uri(queue_uri(ctx, p.is_class(), &p.name).into())],
        ),
    );
    push_attr(
        resp,
        Attribute::new(
            "queued-job-count",
            tags::INTEGER,
            vec![Value::Integer(queued_job_count)],
        ),
    );
    push_attr(
        resp,
        Attribute::new(
            "uri-security-supported",
            tags::KEYWORD,
            vec![Value::Keyword(
                if ctx.is_encrypted { "tls" } else { "none" }.into(),
            )],
        ),
    );
    push_attr(
        resp,
        Attribute::new(
            "uri-authentication-supported",
            tags::KEYWORD,
            vec![Value::Keyword(ctx.uri_authentication.as_str().into())],
        ),
    );

    // Stored printer attrs (incorporating PPD capabilities where present) and
    // CommonData — shared server capabilities, deduplicated against printer attrs.
    let stored = stored_attrs(p, ctx, ppd_caps.as_ref());
    let cd = common_data(ctx);
    if let Some(g) = resp.groups.last_mut().filter(|g| g.tag == tags::PRINTER) {
        copy_attrs_dedup(g, &stored, ra, &mut seen);
        copy_attrs_dedup(g, &cd, ra, &mut seen);
    }
}

fn add1(v: &mut Vec<Attribute>, name: &str, tag: u8, val: Value) {
    v.push(Attribute::new(name, tag, vec![val]));
}
fn addn(v: &mut Vec<Attribute>, name: &str, tag: u8, vals: Vec<Value>) {
    v.push(Attribute::new(name, tag, vals));
}

/// Per-queue stored attributes, incorporating PPD capabilities where present.
fn stored_attrs(p: &Printer, ctx: &Ctx, ppd_caps: Option<&PpdCapabilities>) -> Vec<Attribute> {
    let mut v: Vec<Attribute> = Vec::with_capacity(64);
    let kw = |s: &str| Value::Keyword(s.into());

    let color_supported = ppd_caps
        .and_then(|c| c.color_device)
        .unwrap_or(p.ptype & ptype::COLOR != 0);
    add1(
        &mut v,
        "color-supported",
        tags::BOOLEAN,
        Value::Boolean(color_supported),
    );
    if color_supported {
        addn(
            &mut v,
            "print-color-mode-supported",
            tags::KEYWORD,
            ["auto", "color", "monochrome"]
                .iter()
                .map(|s| kw(s))
                .collect(),
        );
    } else {
        addn(
            &mut v,
            "print-color-mode-supported",
            tags::KEYWORD,
            ["auto", "monochrome"].iter().map(|s| kw(s)).collect(),
        );
    }

    if !p.uuid.is_empty() {
        add1(
            &mut v,
            "printer-uuid",
            tags::URI,
            Value::Uri(p.uuid.as_str().into()),
        );
    }

    let doc_formats = printer_supported_formats(p, ctx);
    addn(
        &mut v,
        "document-format-supported",
        tags::MIMETYPE,
        doc_formats
            .into_iter()
            .map(|f| Value::MimeMediaType(f.into()))
            .collect(),
    );
    add1(
        &mut v,
        "document-format-default",
        tags::MIMETYPE,
        Value::MimeMediaType("application/octet-stream".into()),
    );
    // An empty device-uri is not a URI: emitting `Value::Uri("")` fails
    // response encoding (RFC 8011 §5.1.6) and turns the whole
    // Get-Printer-Attributes into client-error-bad-request. A printer
    // added without a device-uri (CUPS-Add-Modify-Printer validates it
    // only when supplied) simply omits the attribute.
    if !p.device_uri.is_empty() {
        add1(
            &mut v,
            "device-uri",
            tags::URI,
            Value::Uri(p.device_uri.as_str().into()),
        );
    }

    let devid = p
        .options
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("printer-device-id"))
        .map_or_else(
            || "MFG:yindle;MDL:ipp-everywhere;CMD:PWG-Raster;".into(),
            |(_, v)| v.clone(),
        );
    add1(
        &mut v,
        "printer-device-id",
        tags::TEXT,
        Value::Text(devid.into()),
    );
    add1(&mut v, "finishings-supported", tags::ENUM, Value::Enum(3));
    add1(&mut v, "finishings-default", tags::ENUM, Value::Enum(3));
    add1(
        &mut v,
        "printer-info",
        tags::TEXT,
        Value::Text(p.info.as_deref().unwrap_or(&p.name).into()),
    );
    add1(
        &mut v,
        "printer-location",
        tags::TEXT,
        Value::Text(p.location.as_deref().unwrap_or("").into()),
    );
    if let Some(g) = &p.geo_location {
        add1(
            &mut v,
            "printer-geo-location",
            tags::URI,
            Value::Uri(g.as_str().into()),
        );
    } else {
        add1(
            &mut v,
            "printer-geo-location",
            tags::UNKNOWN,
            Value::Unknown,
        );
    }
    add1(
        &mut v,
        "printer-make-and-model",
        tags::TEXT,
        Value::Text(
            p.make_model
                .as_deref()
                .unwrap_or_else(|| {
                    p.device_uri
                        .split("://")
                        .next()
                        .filter(|s| !s.is_empty())
                        .unwrap_or("Unknown")
                })
                .into(),
        ),
    );
    add1(
        &mut v,
        "printer-organization",
        tags::TEXT,
        Value::Text(p.organization.as_deref().unwrap_or("").into()),
    );
    add1(
        &mut v,
        "printer-organizational-unit",
        tags::TEXT,
        Value::Text(p.organizational_unit.as_deref().unwrap_or("").into()),
    );
    if !p.auth_info_required.is_empty() {
        addn(
            &mut v,
            "auth-info-required",
            tags::KEYWORD,
            p.auth_info_required.iter().map(|s| kw(s)).collect(),
        );
    }
    add1(
        &mut v,
        "printer-name",
        tags::NAME,
        Value::Name(p.name.as_str().into()),
    );
    add1(
        &mut v,
        "printer-id",
        tags::INTEGER,
        Value::Integer(p.printer_id),
    );

    // Per-queue quotas & banners.
    add1(
        &mut v,
        "job-quota-period",
        tags::INTEGER,
        Value::Integer(p.quota_period),
    );
    add1(
        &mut v,
        "job-k-limit",
        tags::INTEGER,
        Value::Integer(p.k_limit),
    );
    add1(
        &mut v,
        "job-page-limit",
        tags::INTEGER,
        Value::Integer(p.page_limit),
    );
    if ctx.classification.is_empty() {
        addn(
            &mut v,
            "job-sheets-default",
            tags::NAME,
            vec![
                Value::Name(p.job_sheets.0.as_str().into()),
                Value::Name(p.job_sheets.1.as_str().into()),
            ],
        );
    } else {
        add1(
            &mut v,
            "job-sheets-default",
            tags::NAME,
            Value::Name(ctx.classification.as_str().into()),
        );
    }

    // Honor PPD media/sides/resolutions when present on the queue.
    if let Some(caps) = ppd_caps {
        if let Some(ref dm) = caps.default_media {
            add1(&mut v, "media-default", tags::KEYWORD, kw(dm));
        }
        if !caps.media_supported.is_empty() {
            addn(
                &mut v,
                "media-supported",
                tags::KEYWORD,
                caps.media_supported.iter().map(|m| kw(m)).collect(),
            );
        }
        if let Some(ref ds) = caps.default_duplex {
            add1(&mut v, "sides-default", tags::KEYWORD, kw(ds));
        }
        if let Some(duplex) = caps.duplex_supported {
            let sides: &[&str] = if duplex {
                &["one-sided", "two-sided-long-edge", "two-sided-short-edge"]
            } else {
                &["one-sided"]
            };
            addn(
                &mut v,
                "sides-supported",
                tags::KEYWORD,
                sides.iter().map(|s| kw(s)).collect(),
            );
        }
        if let Some((x, y)) = caps.default_resolution {
            add1(
                &mut v,
                "printer-resolution-default",
                tags::RESOLUTION,
                Value::Resolution { x, y, units: 3 },
            );
        }
        if !caps.resolutions.is_empty() {
            addn(
                &mut v,
                "printer-resolution-supported",
                tags::RESOLUTION,
                caps.resolutions
                    .iter()
                    .map(|&(x, y)| Value::Resolution { x, y, units: 3 })
                    .collect(),
            );
        }
    }

    addn(
        &mut v,
        "job-creation-attributes-supported",
        tags::KEYWORD,
        vec![
            kw("copies"),
            kw("finishings"),
            kw("ipp-attribute-fidelity"),
            kw("job-hold-until"),
            kw("job-name"),
            kw("job-priority"),
            kw("job-sheets"),
            kw("media"),
            kw("media-col"),
            kw("multiple-document-handling"),
            kw("number-up"),
            kw("output-bin"),
            kw("orientation-requested"),
            kw("page-ranges"),
            kw("print-color-mode"),
            kw("print-quality"),
            kw("printer-resolution"),
            kw("sides"),
        ],
    );

    if !p.marker_names.is_empty() {
        addn(
            &mut v,
            "marker-names",
            tags::NAME,
            p.marker_names
                .iter()
                .map(|s| Value::Name(s.as_str().into()))
                .collect(),
        );
    }
    if !p.marker_levels.is_empty() {
        addn(
            &mut v,
            "marker-levels",
            tags::INTEGER,
            p.marker_levels.iter().map(|i| Value::Integer(*i)).collect(),
        );
    }
    if !p.marker_low_levels.is_empty() {
        addn(
            &mut v,
            "marker-low-levels",
            tags::INTEGER,
            p.marker_low_levels
                .iter()
                .map(|i| Value::Integer(*i))
                .collect(),
        );
    }
    if !p.marker_high_levels.is_empty() {
        addn(
            &mut v,
            "marker-high-levels",
            tags::INTEGER,
            p.marker_high_levels
                .iter()
                .map(|i| Value::Integer(*i))
                .collect(),
        );
    }
    if !p.marker_types.is_empty() {
        addn(
            &mut v,
            "marker-types",
            tags::KEYWORD,
            p.marker_types.iter().map(|s| kw(s)).collect(),
        );
    }
    if !p.marker_colors.is_empty() {
        addn(
            &mut v,
            "marker-colors",
            tags::NAME,
            p.marker_colors
                .iter()
                .map(|s| Value::Name(s.as_str().into()))
                .collect(),
        );
    }
    if !p.marker_message.is_empty() {
        add1(
            &mut v,
            "marker-message",
            tags::TEXT,
            Value::Text(p.marker_message.as_str().into()),
        );
    }

    // printer-supply / printer-supply-description / printer-supply-info-uri
    // (IPP Everywhere; the PWG supply octet-string format stock cupsd
    // derives from marker-* and `ippeveprinter` always emits). One entry
    // per marker when the queue reports markers; otherwise a single
    // explicitly-unknown entry (level -2, type unknown) so clients can
    // tell supply state is unknown rather than absent. The info URI
    // mirrors ippeveprinter's `/supplies` path on this server.
    let supply_names: Vec<String> = if p.marker_names.is_empty() {
        vec!["Unknown Supply".to_string()]
    } else {
        p.marker_names.clone()
    };
    let supplies: Vec<Value> = supply_names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let supply_type = p
                .marker_types
                .get(i)
                .map_or("unknown", String::as_str);
            let class = if supply_type.starts_with("waste") {
                "receptacleThatIsFilled"
            } else {
                "supplyThatIsConsumed"
            };
            let level = p.marker_levels.get(i).copied().unwrap_or(-2);
            let colorant = p
                .marker_colors
                .get(i)
                .map_or_else(
                    || {
                        if p.marker_names.is_empty() {
                            "unknown"
                        } else {
                            name.as_str()
                        }
                    },
                    String::as_str,
                );
            Value::OctetString(
                format!(
                    "index={};class={class};type={supply_type};unit=percent;maxcapacity=100;level={level};colorantname={colorant};",
                    i + 1
                )
                .into_bytes(),
            )
        })
        .collect();
    addn(&mut v, "printer-supply", tags::STRING, supplies);
    addn(
        &mut v,
        "printer-supply-description",
        tags::TEXT,
        supply_names
            .iter()
            .map(|s| Value::Text(s.as_str().into()))
            .collect(),
    );
    add1(
        &mut v,
        "printer-supply-info-uri",
        tags::URI,
        Value::Uri(web_uri(ctx, "/supplies").into()),
    );
    v
}

/// `CommonData` — `cupsdCreateCommonData()`. Config-dependent values
/// come from `ctx`. Never duplicates per-printer attributes (`printer-alert*`,
/// `printer-geo-location`, `printer-organization*`) or resolutions, and never
/// fabricates bogus `https://localhost/supplies` URIs.
#[must_use]
pub fn common_data(ctx: &Ctx) -> Vec<Attribute> {
    const K_SUPPORTED: i32 = i32::MAX;
    let mut v: Vec<Attribute> = Vec::with_capacity(64);
    let kw = |s: &str| Value::Keyword(s.into());
    let nm = |s: &str| Value::Name(s.into());

    add1(
        &mut v,
        "charset-configured",
        tags::CHARSET,
        Value::Charset("utf-8".into()),
    );
    addn(
        &mut v,
        "charset-supported",
        tags::CHARSET,
        vec![
            Value::Charset("us-ascii".into()),
            Value::Charset("utf-8".into()),
        ],
    );
    addn(
        &mut v,
        "compression-supported",
        tags::KEYWORD,
        vec![kw("none"), kw("gzip")],
    );
    add1(
        &mut v,
        "cups-version",
        tags::TEXT,
        Value::Text(ctx.cups_version.as_str().into()),
    );
    add1(
        &mut v,
        "generated-natural-language-supported",
        tags::LANGUAGE,
        Value::NaturalLanguage(ctx.default_language.as_str().into()),
    );
    addn(
        &mut v,
        "ipp-versions-supported",
        tags::KEYWORD,
        ["1.0", "1.1", "2.0", "2.1", "2.2"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    add1(
        &mut v,
        "ippget-event-life",
        tags::INTEGER,
        Value::Integer(15),
    );
    add1(
        &mut v,
        "job-cancel-after-supported",
        tags::RANGE,
        Value::Range {
            low: 0,
            high: i32::MAX,
        },
    );
    addn(
        &mut v,
        "job-hold-until-supported",
        tags::KEYWORD,
        [
            "no-hold",
            "indefinite",
            "day-time",
            "evening",
            "night",
            "second-shift",
            "third-shift",
            "weekend",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    add1(
        &mut v,
        "job-ids-supported",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    add1(
        &mut v,
        "job-k-octets-supported",
        tags::RANGE,
        Value::Range {
            low: 0,
            high: K_SUPPORTED,
        },
    );
    add1(
        &mut v,
        "job-priority-supported",
        tags::INTEGER,
        Value::Integer(100),
    );
    addn(
        &mut v,
        "job-settable-attributes-supported",
        tags::KEYWORD,
        [
            "copies",
            "finishings",
            "job-hold-until",
            "job-name",
            "job-priority",
            "media",
            "media-col",
            "multiple-document-handling",
            "number-up",
            "output-bin",
            "orientation-requested",
            "page-ranges",
            "print-color-mode",
            "print-quality",
            "printer-resolution",
            "sides",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    addn(
        &mut v,
        "job-sheets-col-supported",
        tags::KEYWORD,
        ["job-sheets", "media", "media-col"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    if ctx.classification.is_empty() {
        addn(
            &mut v,
            "job-sheets-supported",
            tags::NAME,
            std::iter::once(nm("none"))
                .chain(ctx.banners.iter().map(|b| nm(b)))
                .collect(),
        );
    } else {
        add1(
            &mut v,
            "job-sheets-supported",
            tags::NAME,
            Value::Name(ctx.classification.as_str().into()),
        );
    }
    add1(
        &mut v,
        "jpeg-k-octets-supported",
        tags::RANGE,
        Value::Range {
            low: 0,
            high: K_SUPPORTED,
        },
    );
    add1(
        &mut v,
        "jpeg-x-dimension-supported",
        tags::RANGE,
        Value::Range {
            low: 0,
            high: 65535,
        },
    );
    add1(
        &mut v,
        "jpeg-y-dimension-supported",
        tags::RANGE,
        Value::Range {
            low: 1,
            high: 65535,
        },
    );
    addn(
        &mut v,
        "media-col-supported",
        tags::KEYWORD,
        [
            "media-bottom-margin",
            "media-left-margin",
            "media-right-margin",
            "media-size",
            "media-source",
            "media-top-margin",
            "media-type",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    let mut media_col = Vec::new();
    media_col.push(Attribute::new(
        "media-size",
        tags::BEGIN_COLLECTION,
        vec![Value::Collection(vec![
            Attribute::new("x-dimension", tags::INTEGER, vec![Value::Integer(21590)]),
            Attribute::new("y-dimension", tags::INTEGER, vec![Value::Integer(27940)]),
        ])],
    ));
    for m in [
        "media-top-margin",
        "media-bottom-margin",
        "media-left-margin",
        "media-right-margin",
    ] {
        media_col.push(Attribute::new(m, tags::INTEGER, vec![Value::Integer(300)]));
    }
    media_col.push(Attribute::new(
        "media-source",
        tags::KEYWORD,
        vec![kw("auto")],
    ));
    media_col.push(Attribute::new(
        "media-type",
        tags::KEYWORD,
        vec![kw("stationery")],
    ));
    add1(
        &mut v,
        "media-col-default",
        tags::BEGIN_COLLECTION,
        Value::Collection(media_col),
    );
    addn(
        &mut v,
        "multiple-document-handling-supported",
        tags::KEYWORD,
        [
            "separate-documents-uncollated-copies",
            "separate-documents-collated-copies",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    add1(
        &mut v,
        "multiple-document-jobs-supported",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    add1(
        &mut v,
        "multiple-operation-time-out",
        tags::INTEGER,
        Value::Integer(ctx.multiple_operation_timeout),
    );
    add1(
        &mut v,
        "multiple-operation-time-out-action",
        tags::KEYWORD,
        kw("process-job"),
    );
    add1(&mut v, "copies-default", tags::INTEGER, Value::Integer(1));
    add1(
        &mut v,
        "copies-supported",
        tags::RANGE,
        Value::Range {
            low: 1,
            high: ctx.max_copies.max(1),
        },
    );
    add1(
        &mut v,
        "media-default",
        tags::KEYWORD,
        kw("na_letter_8.5x11in"),
    );
    addn(
        &mut v,
        "media-supported",
        tags::KEYWORD,
        [
            "na_letter_8.5x11in",
            "na_legal_8.5x14in",
            "iso_a4_210x297mm",
            "na_number-10_4.125x9.5in",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    let media_col_db = |x: i32, y: i32| {
        Value::Collection(vec![
            Attribute::new(
                "media-size",
                tags::BEGIN_COLLECTION,
                vec![Value::Collection(vec![
                    Attribute::new("x-dimension", tags::INTEGER, vec![Value::Integer(x)]),
                    Attribute::new("y-dimension", tags::INTEGER, vec![Value::Integer(y)]),
                ])],
            ),
            Attribute::new("media-type", tags::KEYWORD, vec![kw("stationery")]),
            Attribute::new("media-source", tags::KEYWORD, vec![kw("auto")]),
        ])
    };
    addn(
        &mut v,
        "media-col-database",
        tags::BEGIN_COLLECTION,
        vec![
            media_col_db(21590, 27940),
            media_col_db(21590, 35560),
            media_col_db(21000, 29700),
        ],
    );
    add1(
        &mut v,
        "number-up-default",
        tags::INTEGER,
        Value::Integer(1),
    );
    add1(
        &mut v,
        "orientation-requested-default",
        tags::ENUM,
        Value::Enum(3),
    );
    add1(&mut v, "print-quality-default", tags::ENUM, Value::Enum(4));
    add1(
        &mut v,
        "print-color-mode-default",
        tags::KEYWORD,
        kw("auto"),
    );
    add1(&mut v, "sides-default", tags::KEYWORD, kw("one-sided"));
    addn(
        &mut v,
        "sides-supported",
        tags::KEYWORD,
        ["one-sided", "two-sided-long-edge", "two-sided-short-edge"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    add1(&mut v, "output-bin-default", tags::KEYWORD, kw("face-down"));
    add1(
        &mut v,
        "output-bin-supported",
        tags::KEYWORD,
        kw("face-down"),
    );
    addn(
        &mut v,
        "print-quality-supported",
        tags::ENUM,
        vec![Value::Enum(3), Value::Enum(4), Value::Enum(5)],
    );
    let res300 = Value::Resolution {
        x: 300,
        y: 300,
        units: 3,
    };
    let res600 = Value::Resolution {
        x: 600,
        y: 600,
        units: 3,
    };
    add1(
        &mut v,
        "printer-resolution-default",
        tags::RESOLUTION,
        res600.clone(),
    );
    addn(
        &mut v,
        "printer-resolution-supported",
        tags::RESOLUTION,
        vec![res300, res600],
    );
    addn(
        &mut v,
        "media-size-supported",
        tags::BEGIN_COLLECTION,
        [
            (21590, 27940),
            (21590, 35560),
            (21000, 29700),
            (10477, 24130),
        ]
        .iter()
        .map(|&(x, y)| {
            Value::Collection(vec![
                Attribute::new("x-dimension", tags::INTEGER, vec![Value::Integer(x)]),
                Attribute::new("y-dimension", tags::INTEGER, vec![Value::Integer(y)]),
            ])
        })
        .collect(),
    );
    addn(
        &mut v,
        "media-type-supported",
        tags::KEYWORD,
        [
            "stationery",
            "stationery-letterhead",
            "cardstock",
            "envelope",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    add1(
        &mut v,
        "pages-per-minute",
        tags::INTEGER,
        Value::Integer(30),
    );
    add1(
        &mut v,
        "job-hold-until-default",
        tags::KEYWORD,
        kw("no-hold"),
    );
    add1(
        &mut v,
        "job-priority-default",
        tags::INTEGER,
        Value::Integer(50),
    );
    addn(
        &mut v,
        "media-col-ready",
        tags::BEGIN_COLLECTION,
        vec![media_col_db(21590, 27940)],
    );
    addn(
        &mut v,
        "media-ready",
        tags::KEYWORD,
        ["na_letter_8.5x11in"].iter().map(|s| kw(s)).collect(),
    );
    addn(
        &mut v,
        "media-source-supported",
        tags::KEYWORD,
        ["auto", "main", "manual", "by-pass-tray"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    for (name, mm) in [
        ("media-bottom-margin-supported", 635),
        ("media-top-margin-supported", 635),
        ("media-left-margin-supported", 635),
        ("media-right-margin-supported", 635),
    ] {
        add1(&mut v, name, tags::INTEGER, Value::Integer(mm));
    }
    addn(
        &mut v,
        "overrides-supported",
        tags::KEYWORD,
        [
            "document-number",
            "document-numbers",
            "output-pages",
            "pages",
            "orientation-requested",
            "media",
            "media-col",
            "sides",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    for (base, kwv) in [
        ("print-content-optimize", "auto"),
        ("print-rendering-intent", "auto"),
    ] {
        add1(&mut v, &format!("{base}-default"), tags::KEYWORD, kw(kwv));
        addn(
            &mut v,
            &format!("{base}-supported"),
            tags::KEYWORD,
            ["auto"].iter().map(|s| kw(s)).collect(),
        );
    }
    addn(
        &mut v,
        "pwg-raster-document-resolution-supported",
        tags::RESOLUTION,
        vec![
            Value::Resolution {
                x: 600,
                y: 600,
                units: 3,
            },
            Value::Resolution {
                x: 1200,
                y: 1200,
                units: 3,
            },
        ],
    );
    add1(
        &mut v,
        "pwg-raster-document-sheet-back",
        tags::KEYWORD,
        kw("normal"),
    );
    addn(
        &mut v,
        "pwg-raster-document-type-supported",
        tags::KEYWORD,
        ["black_1", "sgray_8", "srgb_8", "srgb_16"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    addn(
        &mut v,
        "notify-events-default",
        tags::KEYWORD,
        ["none"].iter().map(|s| kw(s)).collect(),
    );
    add1(
        &mut v,
        "notify-lease-duration-default",
        tags::INTEGER,
        Value::Integer(ctx.default_lease_duration),
    );
    addn(
        &mut v,
        "identify-actions-default",
        tags::KEYWORD,
        ["display"].iter().map(|s| kw(s)).collect(),
    );
    addn(
        &mut v,
        "identify-actions-supported",
        tags::KEYWORD,
        ["display", "sound"].iter().map(|s| kw(s)).collect(),
    );
    addn(
        &mut v,
        "ipp-features-supported",
        tags::KEYWORD,
        ["ipp-everywhere", "subscription-object", "document-object"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    add1(
        &mut v,
        "preferred-attributes-supported",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    add1(
        &mut v,
        "printer-message-from-operator",
        tags::TEXT,
        Value::Text("".into()),
    );
    addn(
        &mut v,
        "reference-uri-schemes-supported",
        tags::URISCHEME,
        ["ftp", "http", "https", "ipp", "ipps"]
            .iter()
            .map(|s| Value::UriScheme((*s).into()))
            .collect(),
    );
    add1(
        &mut v,
        "natural-language-configured",
        tags::LANGUAGE,
        Value::NaturalLanguage(ctx.default_language.as_str().into()),
    );
    addn(
        &mut v,
        "notify-attributes-supported",
        tags::KEYWORD,
        [
            "printer-state-change-time",
            "notify-lease-expiration-time",
            "notify-subscriber-user-name",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    add1(
        &mut v,
        "notify-lease-duration-supported",
        tags::RANGE,
        Value::Range {
            low: 0,
            high: if ctx.max_lease_duration == 0 {
                i32::MAX
            } else {
                ctx.max_lease_duration
            },
        },
    );
    add1(
        &mut v,
        "notify-max-events-supported",
        tags::INTEGER,
        Value::Integer(ctx.max_events),
    );
    addn(
        &mut v,
        "notify-events-supported",
        tags::KEYWORD,
        [
            "job-completed",
            "job-config-changed",
            "job-created",
            "job-progress",
            "job-state-changed",
            "job-stopped",
            "printer-added",
            "printer-changed",
            "printer-config-changed",
            "printer-deleted",
            "printer-finishings-changed",
            "printer-media-changed",
            "printer-modified",
            "printer-restarted",
            "printer-shutdown",
            "printer-state-changed",
            "printer-stopped",
            "server-audit",
            "server-restarted",
            "server-started",
            "server-stopped",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    add1(
        &mut v,
        "notify-pull-method-supported",
        tags::KEYWORD,
        kw("ippget"),
    );
    if !ctx.notifiers.is_empty() {
        addn(
            &mut v,
            "notify-schemes-supported",
            tags::KEYWORD,
            ctx.notifiers.iter().map(|n| kw(n)).collect(),
        );
    }
    addn(
        &mut v,
        "number-up-supported",
        tags::INTEGER,
        [1, 2, 4, 6, 9, 16]
            .iter()
            .map(|i| Value::Integer(*i))
            .collect(),
    );
    addn(
        &mut v,
        "number-up-layout-supported",
        tags::KEYWORD,
        [
            "btlr", "btrl", "lrbt", "lrtb", "rlbt", "rltb", "tblr", "tbrl",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    addn(
        &mut v,
        "operations-supported",
        tags::ENUM,
        ctx.operations_supported
            .iter()
            .map(|o| Value::Enum(*o))
            .collect(),
    );
    addn(
        &mut v,
        "orientation-requested-supported",
        tags::ENUM,
        [3, 4, 5, 6].iter().map(|i| Value::Enum(*i)).collect(),
    );
    addn(
        &mut v,
        "page-delivery-supported",
        tags::KEYWORD,
        ["reverse-order", "same-order"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    add1(
        &mut v,
        "page-ranges-supported",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    add1(
        &mut v,
        "pdf-k-octets-supported",
        tags::RANGE,
        Value::Range {
            low: 0,
            high: K_SUPPORTED,
        },
    );
    addn(
        &mut v,
        "pdf-versions-supported",
        tags::KEYWORD,
        [
            "adobe-1.2",
            "adobe-1.3",
            "adobe-1.4",
            "adobe-1.5",
            "adobe-1.6",
            "adobe-1.7",
            "iso-19005-1_2005",
            "iso-32000-1_2008",
            "pwg-5102.3",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    add1(
        &mut v,
        "pdl-override-supported",
        tags::KEYWORD,
        kw("attempted"),
    );
    add1(
        &mut v,
        "print-as-raster-supported",
        tags::BOOLEAN,
        Value::Boolean(true),
    );
    addn(
        &mut v,
        "print-scaling-supported",
        tags::KEYWORD,
        ["auto", "auto-fit", "fill", "fit", "none"]
            .iter()
            .map(|s| kw(s))
            .collect(),
    );
    add1(
        &mut v,
        "printer-get-attributes-supported",
        tags::KEYWORD,
        kw("document-format"),
    );
    if !ctx.policies.is_empty() {
        addn(
            &mut v,
            "printer-op-policy-supported",
            tags::NAME,
            ctx.policies
                .iter()
                .map(|p| Value::Name(p.as_str().into()))
                .collect(),
        );
    }
    addn(
        &mut v,
        "printer-settable-attributes-supported",
        tags::KEYWORD,
        [
            "printer-geo-location",
            "printer-info",
            "printer-location",
            "printer-organization",
            "printer-organizational-unit",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    add1(
        &mut v,
        "printer-strings-languages-supported",
        tags::LANGUAGE,
        Value::NaturalLanguage(ctx.default_language.as_str().into()),
    );
    add1(
        &mut v,
        "server-is-sharing-printers",
        tags::BOOLEAN,
        Value::Boolean(ctx.sharing),
    );
    addn(
        &mut v,
        "which-jobs-supported",
        tags::KEYWORD,
        [
            "completed",
            "not-completed",
            "aborted",
            "all",
            "canceled",
            "pending",
            "pending-held",
            "processing",
            "processing-stopped",
            "proof-print",
            "fetchable",
        ]
        .iter()
        .map(|s| kw(s))
        .collect(),
    );
    v
}
