//! `ops` — hardened IPP 1.0–2.2 / CUPS operation dispatcher, ported from
//! `scheduler/ipp.c` (`cupsdProcessIPPRequest` + per-op handlers).
//!
//! Features:
//! - Full fail-closed `<Policy>` authorization (`authz::check_op`) on every
//!   IPP operation with per-printer `printer-op-policy` → `DefaultPolicy` →
//!   `"default"` resolution and `JobPrivate*`/`SubscriptionPrivate*` redaction
//! - Structured [`DispatchOutcome`] signaling `need_auth` (HTTP 401) and
//!   `upgrade_required` (HTTP 426) alongside the IPP response
//! - Sync ([`dispatch`], [`dispatch_outcome`]) and non-blocking async
//!   ([`dispatch_async`]) execution for `cups-deviced`, `cups-driverd`, and
//!   `Get-Notifications` (`notify-wait=true`)
//! - Hardened PPD validation/patching, canonical path containment, `FileDevice`
//!   enforcement, atomic `0600` job spooling, and bounded RFC 1952 gzip
//!   decompression
//! - Wave-2b daemon hooks on [`Ctx`]: `on_cancel_job`, `on_audit`, `on_event`,
//!   and `on_fetch_uri`

#![forbid(unsafe_code)]

mod admin_ops;
mod async_exec;
mod common;
mod ctx;
mod dispatch;
mod gzip;
mod jobs_ops;
mod ppd;
mod security;
mod sub_ops;

pub use ctx::{
    AuditHook, AuditRecord, CancelJobHook, Ctx, DispatchOutcome, EventHook, EventSignal,
    FetchUriHook,
};
pub use dispatch::{dispatch, dispatch_async, dispatch_outcome};
pub use gzip::{decompress_gzip, decompress_gzip_with_limits, GzipError};
pub use ppd::{
    atomic_write_ppd, parse_ppd_capabilities, patch_ppd_cups_attrs, resolve_safe_file_ppd,
    validate_driverd_ppd_name, validate_ppd_bytes, PpdCapabilities, PpdLookupError,
};
