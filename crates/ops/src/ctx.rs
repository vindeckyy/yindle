//! Request context (`Ctx`), dispatch outcome (`DispatchOutcome`), and Wave-2b
//! daemon integration hooks (`on_cancel_job`, `on_audit`, `on_event`,
//! `on_fetch_uri`).

use ipp_codec::{ops::op, IppMessage};
use job::Jobs;
use printer::{ptype, Printer, Registry};
use std::path::PathBuf;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

/// Structured outcome returned by [`crate::dispatch_outcome`] and
/// [`crate::dispatch_async`].
///
/// Allows `cupsd` to emit HTTP `401 Unauthorized` + `WWW-Authenticate` when
/// `need_auth` is `true`, or HTTP `426 Upgrade Required` when `upgrade_required`
/// is `true`, in addition to returning the IPP response payload.
#[derive(Debug, Clone)]
pub struct DispatchOutcome {
    /// The encoded-ready IPP response message.
    pub response: IppMessage,
    /// `true` when authorization failed with `AccessDecision::AuthRequired`.
    pub need_auth: bool,
    /// Required authentication scheme when `need_auth` is `true`.
    pub auth_type: Option<cups_config::AuthType>,
    /// `true` when authorization failed with `AccessDecision::UpgradeRequired`.
    pub upgrade_required: bool,
}

impl DispatchOutcome {
    #[must_use]
    pub fn new(response: IppMessage) -> Self {
        Self {
            response,
            need_auth: false,
            auth_type: None,
            upgrade_required: false,
        }
    }
}

/// Enterprise audit event emitted on admin mutations, job lifecycle actions,
/// and authorization denials. `cupsd` Wave 2b bridges this into
/// `cups_log::AuditEvent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Authenticated actor username (`None` for anonymous requests).
    pub actor: Option<String>,
    /// Client IP address (formatted).
    pub client: String,
    /// IPP operation name (e.g. `"CUPS-Add-Modify-Printer"`, `"Cancel-Job"`).
    pub operation: String,
    /// Affected queue, job, or subscription target (if any).
    pub target: Option<String>,
    /// Outcome keyword (`"allowed"`, `"denied"`, `"auth-required"`, `"upgrade-required"`, `"error"`).
    pub outcome: String,
    /// Human-readable detail message.
    pub detail: String,
}

/// Event notification payload emitted alongside [`events::Subscriptions::push`]
/// so `cupsd` Wave 2b can forward signals to `cups_dbus::Notifier`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSignal {
    pub event: events::Event,
    pub printer: Option<String>,
    pub printer_uri: Option<String>,
    pub printer_state: Option<i32>,
    pub printer_state_reasons: Option<String>,
    pub printer_accepting: Option<bool>,
    pub job_id: Option<i32>,
    pub job_state: Option<i32>,
    pub job_name: Option<String>,
    pub text: String,
}

/// Callback invoked when a job is canceled or purged so the daemon can kill
/// running filter/backend child PIDs.
pub type CancelJobHook = Arc<dyn Fn(u32) + Send + Sync>;

/// Callback invoked for enterprise audit trail records.
pub type AuditHook = Arc<dyn Fn(&AuditRecord) + Send + Sync>;

/// Callback invoked for printer/job/server events (e.g. D-Bus `Notifier`).
pub type EventHook = Arc<dyn Fn(&EventSignal) + Send + Sync>;

/// Optional network URI fetcher for `Print-URI`/`Send-URI` (never invoked for
/// `file:` URIs).
pub type FetchUriHook = Arc<dyn Fn(&str) -> Result<Vec<u8>, String> + Send + Sync>;

/// Per-request context — the pieces of global server state handlers
/// consult (the `con`/`cupsd` globals in the C scheduler).
#[allow(clippy::struct_excessive_bools)]
pub struct Ctx<'a> {
    /// Destination registry (shared; admin ops take the write lock).
    pub registry: &'a RwLock<Registry>,
    /// Server hostname for generated response URIs (`httpGetHostname`).
    /// NEVER used for authorization host ACL matching!
    pub hostname: String,
    /// Peer reverse-DNS hostname for authorization host masks (NEVER HTTP `Host:`).
    pub peer_host: Option<String>,
    /// Listen port for generated URIs.
    pub port: u16,
    /// Whether the connection is TLS (`ipps`/`https` in URIs).
    pub is_encrypted: bool,
    /// Whether the client is on localhost (`!shared` hidden otherwise).
    pub is_local: bool,
    /// Authenticated username if any (strictly used for authorization).
    pub username: Option<String>,
    /// Unauthenticated `requesting-user-name` fallback (display/metadata ONLY;
    /// NEVER used for authorization!).
    pub requesting_user: Option<String>,
    /// Negotiated response language (`attributes-natural-language`).
    pub language: String,
    /// `DefaultLanguage` config.
    pub default_language: String,
    /// `DefaultPolicy` name from `cupsd.conf` (defaults to `"default"`).
    pub default_policy: Option<String>,
    /// `uri-authentication-supported` for this listener/location.
    pub uri_authentication: String,
    /// `cups-version` string (`CUPS_SVERSION` tail).
    pub cups_version: String,
    /// `Classification` (banner override; empty = per-queue banners).
    pub classification: String,
    /// Banner names present in `Banners` dir.
    pub banners: Vec<String>,
    /// `MultipleOperationTimeout`.
    pub multiple_operation_timeout: i32,
    /// `DefaultLeaseDuration`.
    pub default_lease_duration: i32,
    /// `MaxLeaseDuration`.
    pub max_lease_duration: i32,
    /// `MaxEvents`.
    pub max_events: i32,
    /// `MaxSubscriptions` — cap on live subscriptions.
    pub max_subscriptions: i32,
    /// `MaxSubscriptionsPerJob` (0 = unlimited).
    pub max_subscriptions_per_job: i32,
    /// `MaxSubscriptionsPerPrinter` (0 = unlimited).
    pub max_subscriptions_per_printer: i32,
    /// `MaxSubscriptionsPerUser` (0 = unlimited).
    pub max_subscriptions_per_user: i32,
    /// `MaxJobs` (0 = unlimited).
    pub max_jobs: i32,
    /// `MaxJobsPerPrinter` (0 = unlimited).
    pub max_jobs_per_printer: i32,
    /// `MaxJobsPerUser` (0 = unlimited).
    pub max_jobs_per_user: i32,
    /// `MaxCopies` (defaults to 9999).
    pub max_copies: i32,
    /// `DefaultShared` for newly created queues.
    pub default_shared: bool,
    /// Notifier scheme names present in `ServerBin/notifier`.
    pub notifiers: Vec<String>,
    /// `printer-op-policy-supported` (policy names).
    pub policies: Vec<String>,
    /// `server-is-sharing-printers` (`Browsing && BrowseLocalProtocols`).
    pub sharing: bool,
    /// `operations-supported` — the op list the daemon advertises.
    pub operations_supported: Vec<i32>,
    /// `StrictConformance` mode.
    pub strict: bool,
    /// Legacy field kept for API backward compatibility; live `queued-job-count`
    /// is computed dynamically from `jobs`.
    pub queued_job_count: i32,
    /// The job table — mutated by print/cancel ops.
    pub jobs: &'a RwLock<Jobs>,
    /// MIME database for filter-chain resolution.
    pub mime: &'a mime_db::MimeDb,
    /// `RequestRoot` spool dir.
    pub request_root: PathBuf,
    /// `ServerBin` dir (filters/backends live under it).
    pub server_bin: PathBuf,
    /// `DataDir` dir (`{data_dir}/ppd`, `{data_dir}/drv`).
    pub data_dir: PathBuf,
    /// Raw document bytes that followed the IPP attrs in the request
    /// (Print-Job / Send-Document payload). Empty for ops without a body.
    pub document: &'a [u8],
    /// Filename for the document (`document-name`/`job-name` fallback).
    pub document_name: String,
    /// `CUPS_SERVERROOT` — `printers.conf`, `classes.conf`, `subscriptions.conf`, `ppd/`.
    pub server_root: PathBuf,
    /// `ConfigFilePerm` (default `0640`).
    pub config_file_perm: u32,
    /// `FileDevice` pattern (`None` = `FileDevice No`, rejecting `file:` URIs).
    pub file_device: Option<String>,
    /// Client IP for authz host masks.
    pub client_addr: std::net::IpAddr,
    /// Groups the authenticated user belongs to (`@SYSTEM` expansion).
    pub user_groups: Vec<String>,
    /// Configured policies for `authz::check_op`.
    pub policy_defs: &'a [cups_config::Policy],
    /// `SystemGroup` names (`@SYSTEM` maps here).
    pub system_groups: Vec<String>,
    /// IPP event subscriptions (`Subscriptions` global).
    pub subscriptions: &'a RwLock<events::Subscriptions>,
    /// DNS-SD advertiser (`DNSSDContext`), `None` when `Browsing`/`dnssd` off.
    pub dnssd: &'a RwLock<Option<dnssd::Advertiser>>,
    /// Maximum wait duration for `Get-Notifications` with `notify-wait=true`.
    pub notify_wait_timeout: Duration,
    /// Maximum execution timeout for `cups-deviced` / `cups-driverd` helpers.
    pub helper_timeout: Duration,
    /// Maximum decompressed payload size for `compression=gzip`.
    pub max_decompressed_size: usize,
    /// Optional callback invoked on job cancellation/purge so `cupsd` can kill
    /// active filter/backend child PIDs.
    pub on_cancel_job: Option<CancelJobHook>,
    /// Optional enterprise audit trail callback.
    pub on_audit: Option<AuditHook>,
    /// Optional event signal callback (e.g. `cups_dbus::Notifier`).
    pub on_event: Option<EventHook>,
    /// Optional network URI fetcher for `Print-URI`/`Send-URI` (never called for `file:`).
    pub on_fetch_uri: Option<FetchUriHook>,
}

impl Ctx<'_> {
    /// Short-lived read guard on the registry.
    pub fn reg(&self) -> RwLockReadGuard<'_, Registry> {
        self.registry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Write guard on the registry (admin ops only).
    pub fn reg_write(&self) -> RwLockWriteGuard<'_, Registry> {
        self.registry
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Read guard on the job table.
    pub fn jobs_read(&self) -> RwLockReadGuard<'_, Jobs> {
        self.jobs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Write guard on the job table.
    pub fn jobs_write(&self) -> RwLockWriteGuard<'_, Jobs> {
        self.jobs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Read guard on the subscription table.
    pub fn subs(&self) -> RwLockReadGuard<'_, events::Subscriptions> {
        self.subscriptions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Write guard on the subscription table.
    pub fn subs_write(&self) -> RwLockWriteGuard<'_, events::Subscriptions> {
        self.subscriptions
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Peer hostname for authorization host masks — NEVER falls back to HTTP
    /// `Host:` (`self.hostname`).
    #[must_use]
    pub fn peer_host_for_authz(&self) -> &str {
        self.peer_host.as_deref().unwrap_or("")
    }

    /// Resolve effective policy name: per-printer `op_policy` ->
    /// `cfg.cupsd.default_policy` -> `"default"`.
    #[must_use]
    pub fn effective_policy_name<'b>(&'b self, printer: Option<&'b Printer>) -> &'b str {
        printer
            .and_then(|p| p.op_policy.as_deref())
            .filter(|s| !s.is_empty())
            .or_else(|| self.default_policy.as_deref().filter(|s| !s.is_empty()))
            .unwrap_or("default")
    }

    /// Resolve effective policy name for a named destination via registry lookup.
    /// Short-circuits without locking `registry` when `dest` is `None`.
    #[must_use]
    pub fn effective_policy_for_dest(&self, dest: Option<&str>) -> String {
        let Some(d) = dest else {
            return self.effective_policy_name(None).to_string();
        };
        let reg = self.reg();
        self.effective_policy_name(reg.find(d)).to_string()
    }

    /// True if the authenticated caller belongs to any configured `SystemGroup`.
    #[must_use]
    pub fn is_system_admin(&self) -> bool {
        self.username.is_some()
            && self
                .user_groups
                .iter()
                .any(|g| self.system_groups.contains(g))
    }

    /// Compute real live `queued-job-count` (non-final jobs) for `p`.
    /// For a class, includes jobs targeting the class itself or its direct members.
    #[must_use]
    pub fn queued_job_count_for(&self, p: &Printer) -> i32 {
        let jobs = self.jobs_read();
        let count = jobs
            .by_id
            .values()
            .filter(|j| {
                !j.state.is_final()
                    && (j.dest == p.name
                        || (p.is_class() && p.members.iter().any(|m| m == &j.dest)))
            })
            .count();
        i32::try_from(count).unwrap_or(i32::MAX)
    }

    /// Emit an event to all covering subscriptions and optional D-Bus hook.
    pub fn event(&self, ev: events::Event, printer: Option<&str>, job: Option<i32>, text: String) {
        self.event_with_state(ev, printer, job, None, None, text);
    }

    /// Emit an event with optional job state & job name metadata.
    pub fn event_with_state(
        &self,
        ev: events::Event,
        printer: Option<&str>,
        job_id: Option<i32>,
        job_state: Option<i32>,
        job_name: Option<String>,
        text: String,
    ) {
        self.subs_write()
            .push(ev, printer, job_id, job_state, &text);
        if let Some(hook) = &self.on_event {
            let (printer_uri, printer_state, printer_state_reasons, printer_accepting) =
                if let Some(pname) = printer {
                    let reg = self.reg();
                    if let Some(p) = reg.find(pname) {
                        let reasons = if p.reasons.is_empty() {
                            "none".to_string()
                        } else {
                            p.reasons.join(",")
                        };
                        (
                            Some(crate::common::queue_uri(self, p.is_class(), &p.name)),
                            Some(p.state),
                            Some(reasons),
                            Some(p.accepting),
                        )
                    } else {
                        (None, None, None, None)
                    }
                } else {
                    (None, None, None, None)
                };
            hook(&EventSignal {
                event: ev,
                printer: printer.map(str::to_string),
                printer_uri,
                printer_state,
                printer_state_reasons,
                printer_accepting,
                job_id,
                job_state,
                job_name,
                text,
            });
        }
    }

    /// Emit an enterprise audit record via `on_audit` (if configured) and tracing.
    pub fn audit(
        &self,
        operation: &str,
        target: Option<&str>,
        outcome: &str,
        detail: impl Into<String>,
    ) {
        let detail = detail.into();
        tracing::info!(
            actor = self.username.as_deref().unwrap_or("anonymous"),
            client = %self.client_addr,
            operation,
            target = target.unwrap_or("-"),
            outcome,
            detail = %detail,
            "ipp audit"
        );
        if let Some(hook) = &self.on_audit {
            hook(&AuditRecord {
                actor: self.username.clone(),
                client: self.client_addr.to_string(),
                operation: operation.to_string(),
                target: target.map(str::to_string),
                outcome: outcome.to_string(),
                detail,
            });
        }
    }

    /// Notify the daemon that job `job_id` was canceled/purged so active
    /// filter/backend PIDs can be terminated.
    pub fn notify_cancel_job(&self, job_id: i32) {
        if let (Some(hook), Ok(id)) = (&self.on_cancel_job, u32::try_from(job_id)) {
            hook(id);
        }
    }

    /// Allowed canonical PPD roots for `CUPS-Get-PPD` `file:` containment.
    #[must_use]
    pub fn ppd_roots(&self) -> Vec<PathBuf> {
        vec![
            self.server_root.join("ppd"),
            self.data_dir.join("ppd"),
            PathBuf::from("/usr/share/ppd"),
        ]
    }

    /// Environment variables for `cups-driverd` (`PPDDIR`, `DRVROOT`, `CUPS_DATADIR`).
    #[must_use]
    pub fn driverd_env(&self) -> Vec<(String, String)> {
        let data_ppd = self.data_dir.join("ppd");
        let ppd_dir = if data_ppd.is_dir() {
            data_ppd
        } else {
            let sys_ppd = PathBuf::from("/usr/share/ppd");
            if sys_ppd.is_dir() {
                sys_ppd
            } else {
                data_ppd
            }
        };
        let drv_dir = self.data_dir.join("drv");
        vec![
            ("PPDDIR".into(), ppd_dir.to_string_lossy().into_owned()),
            ("DRVROOT".into(), drv_dir.to_string_lossy().into_owned()),
            (
                "CUPS_DATADIR".into(),
                self.data_dir.to_string_lossy().into_owned(),
            ),
        ]
    }

    /// Persist `printers.conf` atomically using Wave-1 `Registry` API.
    pub fn save_printers(&self) {
        let reg = self.reg();
        let _ = reg.save_printers_file_with_mode(
            &self.server_root.join("printers.conf"),
            self.config_file_perm,
        );
    }

    /// Persist `classes.conf` atomically using Wave-1 `Registry` API.
    pub fn save_classes(&self) {
        let reg = self.reg();
        let _ = reg.save_classes_file_with_mode(
            &self.server_root.join("classes.conf"),
            self.config_file_perm,
        );
    }

    /// Persist both `printers.conf` and `classes.conf` atomically.
    pub fn save_all_destinations(&self) {
        let reg = self.reg();
        let _ = reg.save_all(&self.server_root, self.config_file_perm);
    }

    /// Persist `subscriptions.conf` atomically using Wave-1 `Subscriptions` API.
    pub fn save_subscriptions(&self) {
        let subs = self.subs();
        let _ = subs.save_file_with_mode(
            &self.server_root.join("subscriptions.conf"),
            self.config_file_perm,
        );
    }

    /// Build the DNS-SD [`dnssd::SharedPrinter`] descriptor for `p`, resolving
    /// actual PDL formats from its queue PPD when present.
    #[must_use]
    pub fn build_shared_printer(&self, p: &Printer) -> dnssd::SharedPrinter {
        let pdl = crate::ppd::load_queue_ppd_capabilities(&self.server_root, &p.name)
            .filter(|c| !c.filter_formats.is_empty())
            .map_or_else(
                || dnssd::DEFAULT_PDL.to_string(),
                |c| c.filter_formats.join(","),
            );
        #[allow(clippy::cast_sign_loss)]
        dnssd::SharedPrinter {
            name: p.name.clone(),
            info: p.info.clone().unwrap_or_default(),
            make_model: p.make_model.clone().unwrap_or_default(),
            location: p.location.clone().unwrap_or_default(),
            pdl,
            printer_type: p.ptype as u32,
            printer_state: p.state,
            uuid: p.uuid.clone(),
            is_class: p.ptype & ptype::CLASS != 0,
            is_fax: p.ptype & ptype::FAX != 0,
        }
    }

    /// `cupsdRegisterPrinter` — advertise a shared printer via DNS-SD.
    pub fn dnssd_publish(&self, p: &Printer) {
        let shared = self.build_shared_printer(p);
        if let Some(adv) = self
            .dnssd
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            let _ = adv.publish(&shared);
        }
    }

    /// `cupsdDeregisterPrinter` — stop advertising a printer.
    pub fn dnssd_unpublish(&self, name: &str) {
        if let Some(adv) = self
            .dnssd
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            adv.unpublish(name);
        }
    }
}

impl<'a> Ctx<'a> {
    /// Build a context with config-derived defaults.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn new(
        registry: &'a RwLock<Registry>,
        cfg: &'a cups_config::Config,
        port: u16,
        jobs: &'a RwLock<Jobs>,
        mime: &'a mime_db::MimeDb,
        subscriptions: &'a RwLock<events::Subscriptions>,
        dnssd: &'a RwLock<Option<dnssd::Advertiser>>,
    ) -> Self {
        let mut ops: Vec<i32> = vec![
            i32::from(op::PRINT_JOB),
            i32::from(op::PRINT_URI),
            i32::from(op::VALIDATE_JOB),
            i32::from(op::CREATE_JOB),
            i32::from(op::SEND_DOCUMENT),
            i32::from(op::SEND_URI),
            i32::from(op::CANCEL_JOB),
            i32::from(op::CANCEL_CURRENT_JOB),
            i32::from(op::IDENTIFY_PRINTER),
            i32::from(op::GET_JOB_ATTRIBUTES),
            i32::from(op::GET_JOBS),
            i32::from(op::GET_PRINTER_ATTRIBUTES),
            i32::from(op::HOLD_JOB),
            i32::from(op::RELEASE_JOB),
            i32::from(op::PAUSE_PRINTER),
            i32::from(op::PAUSE_PRINTER_AFTER_CURRENT_JOB),
            i32::from(op::RESUME_PRINTER),
            i32::from(op::RESTART_PRINTER),
            i32::from(op::SHUTDOWN_PRINTER),
            i32::from(op::STARTUP_PRINTER),
            i32::from(op::PURGE_JOBS),
            i32::from(op::SET_PRINTER_ATTRIBUTES),
            i32::from(op::SET_JOB_ATTRIBUTES),
            i32::from(op::GET_PRINTER_SUPPORTED_VALUES),
            i32::from(op::CREATE_PRINTER_SUBSCRIPTIONS),
            i32::from(op::CREATE_JOB_SUBSCRIPTIONS),
            i32::from(op::GET_SUBSCRIPTION_ATTRIBUTES),
            i32::from(op::GET_SUBSCRIPTIONS),
            i32::from(op::RENEW_SUBSCRIPTION),
            i32::from(op::CANCEL_SUBSCRIPTION),
            i32::from(op::GET_NOTIFICATIONS),
            i32::from(op::ENABLE_PRINTER),
            i32::from(op::DISABLE_PRINTER),
            i32::from(op::HOLD_NEW_JOBS),
            i32::from(op::RELEASE_HELD_NEW_JOBS),
            i32::from(op::CANCEL_JOBS),
            i32::from(op::CANCEL_MY_JOBS),
            i32::from(op::CLOSE_JOB),
            i32::from(op::CUPS_GET_DEFAULT),
            i32::from(op::CUPS_GET_PRINTERS),
            i32::from(op::CUPS_ADD_MODIFY_PRINTER),
            i32::from(op::CUPS_CREATE_LOCAL_PRINTER),
            i32::from(op::CUPS_DELETE_PRINTER),
            i32::from(op::CUPS_GET_CLASSES),
            i32::from(op::CUPS_ADD_MODIFY_CLASS),
            i32::from(op::CUPS_DELETE_CLASS),
            i32::from(op::CUPS_ACCEPT_JOBS),
            i32::from(op::CUPS_REJECT_JOBS),
            i32::from(op::CUPS_SET_DEFAULT),
            i32::from(op::CUPS_GET_DEVICES),
            i32::from(op::CUPS_GET_PPDS),
            i32::from(op::CUPS_MOVE_JOB),
            i32::from(op::CUPS_AUTHENTICATE_JOB),
            i32::from(op::CUPS_GET_PPD),
            i32::from(op::CUPS_GET_DOCUMENT),
            i32::from(op::RESTART_JOB),
            i32::from(op::REPROCESS_JOB),
            i32::from(op::SUSPEND_CURRENT_JOB),
            i32::from(op::RESUME_JOB),
            i32::from(op::PROMOTE_JOB),
            i32::from(op::SCHEDULE_JOB_AFTER),
            i32::from(op::CANCEL_DOCUMENT),
            i32::from(op::GET_DOCUMENT_ATTRIBUTES),
            i32::from(op::GET_DOCUMENTS),
            i32::from(op::SET_DOCUMENT_ATTRIBUTES),
            i32::from(op::RESUBMIT_JOB),
        ];
        ops.sort_unstable();
        Self {
            registry,
            hostname: "localhost".into(),
            peer_host: None,
            port,
            is_encrypted: false,
            is_local: true,
            username: None,
            requesting_user: None,
            language: cfg
                .cupsd
                .default_language
                .clone()
                .unwrap_or_else(|| "en".into()),
            default_language: cfg
                .cupsd
                .default_language
                .clone()
                .unwrap_or_else(|| "en".into()),
            default_policy: cfg.cupsd.default_policy.clone(),
            uri_authentication: "none".into(),
            cups_version: format!("{}.{}", 2, 5),
            classification: cfg.cupsd.classification.clone().unwrap_or_default(),
            banners: Vec::new(),
            multiple_operation_timeout: cfg.cupsd.multiple_operation_timeout,
            default_lease_duration: cfg.cupsd.default_lease_duration,
            max_lease_duration: cfg.cupsd.max_lease_duration,
            max_events: cfg.cupsd.max_events,
            max_subscriptions: cfg.cupsd.max_subscriptions,
            max_subscriptions_per_job: cfg.cupsd.max_subscriptions_per_job,
            max_subscriptions_per_printer: cfg.cupsd.max_subscriptions_per_printer,
            max_subscriptions_per_user: cfg.cupsd.max_subscriptions_per_user,
            max_jobs: cfg.cupsd.max_jobs,
            max_jobs_per_printer: cfg.cupsd.max_jobs_per_printer,
            max_jobs_per_user: cfg.cupsd.max_jobs_per_user,
            max_copies: cfg.cupsd.max_copies.max(1),
            default_shared: cfg.cupsd.default_shared,
            notifiers: Vec::new(),
            policies: cfg.cupsd.policies.iter().map(|p| p.name.clone()).collect(),
            policy_defs: &cfg.cupsd.policies,
            sharing: cfg.cupsd.browsing && cfg.cupsd.browse_local_protocols.0 != 0,
            operations_supported: ops,
            strict: cfg.cupsd.strict_conformance,
            queued_job_count: 0,
            jobs,
            mime,
            request_root: cfg
                .files
                .request_root
                .clone()
                .unwrap_or_else(|| "/var/spool/cups".into())
                .into(),
            server_bin: cfg
                .files
                .server_bin
                .clone()
                .unwrap_or_else(|| "/usr/lib/cups".into())
                .into(),
            data_dir: cfg
                .files
                .data_dir
                .clone()
                .unwrap_or_else(|| "/usr/share/cups".into())
                .into(),
            document: &[],
            document_name: String::new(),
            server_root: cfg
                .files
                .server_root
                .clone()
                .unwrap_or_else(|| "/etc/cups".into())
                .into(),
            config_file_perm: cfg.files.config_file_perm,
            file_device: cfg.files.file_device.clone(),
            client_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            user_groups: Vec::new(),
            system_groups: cfg.files.system_group_names.clone(),
            subscriptions,
            dnssd,
            notify_wait_timeout: Duration::from_secs(15),
            helper_timeout: Duration::from_secs(15),
            max_decompressed_size: crate::gzip::DEFAULT_MAX_DECOMPRESSED,
            on_cancel_job: None,
            on_audit: None,
            on_event: None,
            on_fetch_uri: None,
        }
    }
}
