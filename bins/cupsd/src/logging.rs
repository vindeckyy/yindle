//! Structured logging (`cups_log::Logger` + `tracing`) and D-Bus event
//! notification bridge (`cups_dbus::Notifier`).

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

use cups_config::{
    AccessLogLevel as CfgAccessLevel, Config, LogLevel as CfgLogLevel, LogTimeFormat,
};
use cups_dbus::{
    JobEventKind, JobSignalPayload, Notifier, PrinterEventKind, PrinterSignalPayload,
    ServerEventKind,
};
use cups_log::{
    AccessCategory, AccessLogLevel, AuditEvent, AuditOutcome, Level, LogFormat, LogLevelFilter,
    Logger, Sink, TimeFormat,
};
use ipp_codec::ops::op;
use ops::{AuditRecord, EventSignal};
use pipeline::LogSeverity;

static TRACING_INIT: OnceLock<()> = OnceLock::new();

/// Initialize the process-wide `tracing` subscriber once (respecting `RUST_LOG`
/// or the configured `LogLevel`).
pub fn init_tracing(cfg_level: CfgLogLevel, format: LogFormat) {
    TRACING_INIT.get_or_init(|| {
        let lvl = match cfg_level {
            CfgLogLevel::None => "off",
            CfgLogLevel::Emerg | CfgLogLevel::Alert | CfgLogLevel::Crit | CfgLogLevel::Error => {
                "error"
            }
            CfgLogLevel::Warn => "warn",
            CfgLogLevel::Notice | CfgLogLevel::Info => "info",
            CfgLogLevel::Debug => "debug",
            CfgLogLevel::Debug2 => "trace",
        };
        let default_filter = format!("cupsd={lvl},ops={lvl},httpd={lvl},pipeline={lvl},warn");
        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter));
        let builder = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(std::io::stderr);
        let _ = match format {
            LogFormat::Text | LogFormat::Json => builder.try_init(),
        };
    });
}

/// Convert `cups_config::LogLevel` -> `cups_log::LogLevelFilter`.
#[must_use]
pub const fn map_log_level(level: CfgLogLevel) -> LogLevelFilter {
    match level {
        CfgLogLevel::None => LogLevelFilter::None,
        CfgLogLevel::Emerg => LogLevelFilter::Emergency,
        CfgLogLevel::Alert => LogLevelFilter::Alert,
        CfgLogLevel::Crit => LogLevelFilter::Crit,
        CfgLogLevel::Error => LogLevelFilter::Error,
        CfgLogLevel::Warn => LogLevelFilter::Warn,
        CfgLogLevel::Notice => LogLevelFilter::Notice,
        CfgLogLevel::Info => LogLevelFilter::Info,
        CfgLogLevel::Debug => LogLevelFilter::Debug,
        CfgLogLevel::Debug2 => LogLevelFilter::Debug2,
    }
}

/// Convert `cups_config::AccessLogLevel` -> `cups_log::AccessLogLevel`.
#[must_use]
pub const fn map_access_level(level: CfgAccessLevel) -> AccessLogLevel {
    match level {
        CfgAccessLevel::None => AccessLogLevel::None,
        CfgAccessLevel::Config => AccessLogLevel::Config,
        CfgAccessLevel::Actions => AccessLogLevel::Actions,
        CfgAccessLevel::All => AccessLogLevel::All,
    }
}

/// Convert `pipeline::LogSeverity` -> `cups_log::Level`.
#[must_use]
pub const fn map_pipeline_severity(sev: LogSeverity) -> Level {
    match sev {
        LogSeverity::Emerg => Level::Emergency,
        LogSeverity::Alert => Level::Alert,
        LogSeverity::Crit => Level::Crit,
        LogSeverity::Error => Level::Error,
        LogSeverity::Warning => Level::Warn,
        LogSeverity::Notice => Level::Notice,
        LogSeverity::Info => Level::Info,
        LogSeverity::Debug => Level::Debug,
        LogSeverity::Debug2 => Level::Debug2,
    }
}

/// Build a file or stderr [`Sink`] honoring `LogFilePerm` and `MaxLogSize`.
fn build_sink(path: Option<&str>, perm: u32, max_size: u64, default_stderr: bool) -> Option<Sink> {
    match path {
        // `syslog` maps to stderr (captured by journald) — never a literal `./syslog` file.
        Some(p) if p.eq_ignore_ascii_case("stderr") || p.eq_ignore_ascii_case("syslog") => {
            Some(Sink::stderr())
        }
        Some(p) if p.eq_ignore_ascii_case("none") || p.is_empty() => None,
        Some(p) => {
            if let Some(parent) = Path::new(p).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            Some(Sink::file_with_options(p, perm, max_size))
        }
        None if default_stderr => Some(Sink::stderr()),
        None => None,
    }
}

/// Derive a sibling `audit_log` path alongside `error_log` when file-backed.
fn derive_audit_path(error_log: Option<&str>) -> Option<PathBuf> {
    let raw = error_log?;
    if raw.is_empty()
        || raw.eq_ignore_ascii_case("stderr")
        || raw.eq_ignore_ascii_case("syslog")
        || raw.eq_ignore_ascii_case("none")
    {
        return None;
    }
    let p = Path::new(raw);
    let parent = p.parent()?;
    Some(parent.join("audit_log"))
}

/// Construct a fully configured [`cups_log::Logger`] from [`Config`].
#[must_use]
pub fn build_logger(cfg: &Config, format: LogFormat) -> Logger {
    let perm = cfg.files.log_file_perm;
    let max_size = cfg.cupsd.max_log_size;
    let time_format = match cfg.cupsd.log_time_format {
        LogTimeFormat::Standard => TimeFormat::Standard,
        LogTimeFormat::Usecs => TimeFormat::Usecs,
    };

    let error = build_sink(cfg.files.error_log.as_deref(), perm, max_size, true)
        .unwrap_or_else(Sink::stderr);
    let access = build_sink(cfg.files.access_log.as_deref(), perm, max_size, true)
        .unwrap_or_else(Sink::stderr);
    let page = build_sink(cfg.files.page_log.as_deref(), perm, max_size, false);
    let audit = derive_audit_path(cfg.files.error_log.as_deref())
        .map(|p| Sink::file_with_options(p, perm, max_size));

    // `ErrorLog none` / `AccessLog none` disable that log entirely.
    let is_none = |v: Option<&str>| v.is_some_and(|p| p.eq_ignore_ascii_case("none"));
    let error_level = if is_none(cfg.files.error_log.as_deref()) {
        LogLevelFilter::None
    } else {
        map_log_level(cfg.cupsd.log_level)
    };
    let access_level = if is_none(cfg.files.access_log.as_deref()) {
        AccessLogLevel::None
    } else {
        map_access_level(cfg.cupsd.access_log_level)
    };

    Logger {
        error,
        access,
        page,
        audit,
        error_level,
        access_level,
        time_format,
        format,
    }
}

/// Hot-reloadable wrapper around [`cups_log::Logger`] shared across all tasks.
pub struct LogManager {
    inner: RwLock<Arc<Logger>>,
    format: LogFormat,
    echo_stderr: bool,
}

impl LogManager {
    /// Create a new [`LogManager`] from `cfg`.
    #[must_use]
    pub fn new(cfg: &Config, format: LogFormat, echo_stderr: bool) -> Self {
        Self {
            inner: RwLock::new(Arc::new(build_logger(cfg, format))),
            format,
            echo_stderr,
        }
    }

    /// Snapshot the current [`Arc<Logger>`].
    #[must_use]
    pub fn current(&self) -> Arc<Logger> {
        Arc::clone(
            &self
                .inner
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Reopen all log sinks and rebuild logger settings on `SIGHUP`.
    pub fn reload(&self, cfg: &Config) -> std::io::Result<()> {
        let new_logger = Arc::new(build_logger(cfg, self.format));
        let res = new_logger.reopen_all();
        *self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = new_logger;
        res
    }

    /// Emit an error log entry + corresponding `tracing` event.
    pub fn err(&self, level: Level, msg: impl AsRef<str>) {
        let text = msg.as_ref();
        let logger = self.current();
        let wrote = logger.log_error(level, text);
        if self.echo_stderr && logger.error_level.allows(level) {
            if wrote {
                match level {
                    Level::Emergency | Level::Alert | Level::Crit | Level::Error => {
                        tracing::error!("{text}");
                    }
                    Level::Warn => tracing::warn!("{text}"),
                    Level::Notice | Level::Info => tracing::info!("{text}"),
                    Level::Debug | Level::Debug2 => tracing::debug!("{text}"),
                }
            } else {
                eprintln!("cupsd: {text}");
            }
        }
    }

    /// Emit an `access_log` entry carrying the real authenticated username.
    #[allow(clippy::too_many_arguments)]
    pub fn access(
        &self,
        category: AccessCategory,
        host: &str,
        user: Option<&str>,
        method: &str,
        uri: &str,
        version: (u8, u8),
        code: u16,
        bytes: u64,
        op_name: &str,
        status_name: &str,
    ) {
        self.current().log_access(
            category,
            host,
            user,
            method,
            uri,
            version,
            code,
            bytes,
            op_name,
            status_name,
            None,
        );
    }

    /// Emit a `page_log` entry on `PAGE:` status events.
    pub fn page(
        &self,
        page_format: &str,
        printer: &str,
        user: Option<&str>,
        job_id: i32,
        page_tail: &str,
        job_attrs: &[ipp_codec::Attribute],
    ) {
        self.current()
            .log_page(page_format, printer, user, job_id, page_tail, job_attrs);
    }

    /// Emit an enterprise audit record directly.
    pub fn audit(&self, event: &AuditEvent<'_>) {
        self.current().log_audit(event);
    }

    /// Bridge an [`ops::AuditRecord`] into [`cups_log::Logger::log_audit`].
    pub fn audit_from_ops(&self, rec: &AuditRecord, auth_method: &str) {
        let outcome = match rec.outcome.as_str() {
            "allowed" | "success" => AuditOutcome::Success,
            "denied" | "auth-required" | "upgrade-required" => AuditOutcome::Denied,
            "error" => AuditOutcome::Error,
            _ => AuditOutcome::Failure,
        };
        let ev = AuditEvent {
            timestamp: None,
            actor: rec.actor.as_deref().unwrap_or("anonymous"),
            peer_ip: &rec.client,
            auth_method,
            operation: &rec.operation,
            target: rec.target.as_deref().unwrap_or("-"),
            outcome,
            detail: &rec.detail,
        };
        self.audit(&ev);
    }
}

/// Classify an IPP operation code into [`AccessCategory`] for `AccessLogLevel`.
#[must_use]
pub const fn classify_ipp_op(code: u16) -> AccessCategory {
    match code {
        op::CUPS_ADD_MODIFY_PRINTER
        | op::CUPS_DELETE_PRINTER
        | op::CUPS_ADD_MODIFY_CLASS
        | op::CUPS_DELETE_CLASS
        | op::CUPS_SET_DEFAULT
        | op::CUPS_CREATE_LOCAL_PRINTER
        | op::SET_PRINTER_ATTRIBUTES
        | op::PAUSE_PRINTER
        | op::PAUSE_PRINTER_AFTER_CURRENT_JOB
        | op::RESUME_PRINTER
        | op::ENABLE_PRINTER
        | op::DISABLE_PRINTER
        | op::HOLD_NEW_JOBS
        | op::RELEASE_HELD_NEW_JOBS
        | op::DEACTIVATE_PRINTER
        | op::ACTIVATE_PRINTER
        | op::RESTART_PRINTER
        | op::SHUTDOWN_PRINTER
        | op::STARTUP_PRINTER
        | op::CUPS_ACCEPT_JOBS
        | op::CUPS_REJECT_JOBS => AccessCategory::Config,
        op::PRINT_JOB
        | op::PRINT_URI
        | op::CREATE_JOB
        | op::SEND_DOCUMENT
        | op::SEND_URI
        | op::CANCEL_JOB
        | op::CANCEL_CURRENT_JOB
        | op::CANCEL_JOBS
        | op::CANCEL_MY_JOBS
        | op::CANCEL_DOCUMENT
        | op::PURGE_JOBS
        | op::HOLD_JOB
        | op::RELEASE_JOB
        | op::RESTART_JOB
        | op::REPROCESS_JOB
        | op::RESUBMIT_JOB
        | op::PROMOTE_JOB
        | op::SCHEDULE_JOB_AFTER
        | op::SUSPEND_CURRENT_JOB
        | op::RESUME_JOB
        | op::CLOSE_JOB
        | op::SET_JOB_ATTRIBUTES
        | op::SET_DOCUMENT_ATTRIBUTES
        | op::CUPS_MOVE_JOB
        | op::CUPS_AUTHENTICATE_JOB
        | op::CREATE_PRINTER_SUBSCRIPTIONS
        | op::CREATE_JOB_SUBSCRIPTIONS
        | op::RENEW_SUBSCRIPTION
        | op::CANCEL_SUBSCRIPTION
        | op::IDENTIFY_PRINTER => AccessCategory::Action,
        _ => AccessCategory::Query,
    }
}

/// Forward an [`ops::EventSignal`] to `cups_dbus::Notifier`.
pub fn emit_dbus_event(notifier: &Notifier, sig: &EventSignal) {
    use events::Event;

    let printer_payload = || PrinterSignalPayload {
        text: sig.text.clone(),
        printer_uri: sig.printer_uri.clone().unwrap_or_default(),
        printer_name: sig.printer.clone().unwrap_or_default(),
        printer_state: u32::try_from(sig.printer_state.unwrap_or(3)).unwrap_or(3),
        printer_state_reasons: sig
            .printer_state_reasons
            .clone()
            .unwrap_or_else(|| "none".into()),
        printer_is_accepting_jobs: sig.printer_accepting.unwrap_or(true),
    };

    let job_payload = || JobSignalPayload {
        printer: printer_payload(),
        job_id: u32::try_from(sig.job_id.unwrap_or(0)).unwrap_or(0),
        job_state: u32::try_from(sig.job_state.unwrap_or(3)).unwrap_or(3),
        job_state_reasons: "none".into(),
        job_name: sig.job_name.clone().unwrap_or_default(),
        job_impressions_completed: 0,
    };

    let _ = match sig.event {
        Event::ServerStarted => notifier.emit_server(ServerEventKind::Started, sig.text.clone()),
        Event::ServerStopped => notifier.emit_server(ServerEventKind::Stopped, sig.text.clone()),
        Event::ServerRestarted => {
            notifier.emit_server(ServerEventKind::Restarted, sig.text.clone())
        }
        Event::ServerAudit => notifier.emit_server(ServerEventKind::Audit, sig.text.clone()),
        Event::PrinterAdded => notifier.emit_printer(PrinterEventKind::Added, printer_payload()),
        Event::PrinterDeleted => {
            notifier.emit_printer(PrinterEventKind::Deleted, printer_payload())
        }
        Event::PrinterModified
        | Event::PrinterConfigChanged
        | Event::PrinterChanged
        | Event::PrinterFinishingsChanged
        | Event::PrinterMediaChanged => {
            notifier.emit_printer(PrinterEventKind::Modified, printer_payload())
        }
        Event::PrinterRestarted => {
            notifier.emit_printer(PrinterEventKind::Restarted, printer_payload())
        }
        Event::PrinterShutdown => {
            notifier.emit_printer(PrinterEventKind::Shutdown, printer_payload())
        }
        Event::PrinterStopped => {
            notifier.emit_printer(PrinterEventKind::Stopped, printer_payload())
        }
        Event::PrinterState | Event::PrinterStateChanged => {
            notifier.emit_printer(PrinterEventKind::StateChanged, printer_payload())
        }
        Event::JobCreated => notifier.emit_job(JobEventKind::Created, job_payload()),
        Event::JobCompleted => notifier.emit_job(JobEventKind::Completed, job_payload()),
        Event::JobStopped | Event::JobStateChanged => {
            notifier.emit_job(JobEventKind::State, job_payload())
        }
        Event::JobConfigChanged => notifier.emit_job(JobEventKind::ConfigChanged, job_payload()),
        Event::JobProgress => notifier.emit_job(JobEventKind::Progress, job_payload()),
        Event::All => Ok(false),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_dir(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "presswork-cupsd-log-{}-{tag}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn log_manager_writes_error_access_page_audit_and_reloads() {
        let dir = tmp_dir("files");
        let mut cfg = Config {
            cupsd: cups_config::CupsdConfig::defaults(),
            files: cups_config::CupsFilesConfig::defaults(),
        };
        cfg.cupsd.log_level = CfgLogLevel::Debug2;
        cfg.cupsd.access_log_level = CfgAccessLevel::All;
        cfg.cupsd.log_time_format = LogTimeFormat::Usecs;
        cfg.files.error_log = Some(dir.join("error_log").to_string_lossy().into_owned());
        cfg.files.access_log = Some(dir.join("access_log").to_string_lossy().into_owned());
        cfg.files.page_log = Some(dir.join("page_log").to_string_lossy().into_owned());

        init_tracing(cfg.cupsd.log_level, LogFormat::Text);
        let mgr = LogManager::new(&cfg, LogFormat::Text, true);
        mgr.err(Level::Error, "err line");
        mgr.err(Level::Warn, "warn line");
        mgr.err(Level::Info, "info line");
        mgr.err(Level::Debug, "debug line");
        mgr.access(
            AccessCategory::Action,
            "127.0.0.1",
            Some("alice"),
            "POST",
            "/printers/p1",
            (1, 1),
            200,
            128,
            "Print-Job",
            "successful-ok",
        );
        mgr.page("%p %u %j %P %C", "p1", Some("alice"), 42, "1 2", &[]);
        mgr.audit_from_ops(
            &AuditRecord {
                actor: Some("alice".into()),
                client: "127.0.0.1".into(),
                operation: "Print-Job".into(),
                target: Some("p1".into()),
                outcome: "allowed".into(),
                detail: "submitted".into(),
            },
            "basic",
        );
        mgr.audit_from_ops(
            &AuditRecord {
                actor: None,
                client: "10.0.0.5".into(),
                operation: "CUPS-Delete-Printer".into(),
                target: Some("p1".into()),
                outcome: "denied".into(),
                detail: "forbidden".into(),
            },
            "none",
        );
        mgr.audit_from_ops(
            &AuditRecord {
                actor: None,
                client: "10.0.0.5".into(),
                operation: "X".into(),
                target: None,
                outcome: "error".into(),
                detail: "boom".into(),
            },
            "none",
        );
        mgr.audit_from_ops(
            &AuditRecord {
                actor: None,
                client: "10.0.0.5".into(),
                operation: "Y".into(),
                target: None,
                outcome: "other".into(),
                detail: "fail".into(),
            },
            "none",
        );

        assert!(std::fs::read_to_string(dir.join("error_log"))
            .unwrap()
            .contains("info line"));
        assert!(std::fs::read_to_string(dir.join("access_log"))
            .unwrap()
            .contains("alice"));
        assert!(std::fs::read_to_string(dir.join("page_log"))
            .unwrap()
            .contains("p1 alice 42 1 2"));
        assert!(std::fs::read_to_string(dir.join("audit_log"))
            .unwrap()
            .contains("actor=alice"));

        mgr.reload(&cfg).unwrap();

        // Test JSON + stderr + none sinks
        cfg.files.error_log = Some("stderr".into());
        cfg.files.access_log = Some("none".into());
        cfg.files.page_log = None;
        let mgr_json = LogManager::new(&cfg, LogFormat::Json, false);
        mgr_json.err(Level::Info, "json stderr");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mappings_and_dbus_event_bridge() {
        assert_eq!(map_log_level(CfgLogLevel::None), LogLevelFilter::None);
        assert_eq!(map_log_level(CfgLogLevel::Emerg), LogLevelFilter::Emergency);
        assert_eq!(map_log_level(CfgLogLevel::Alert), LogLevelFilter::Alert);
        assert_eq!(map_log_level(CfgLogLevel::Crit), LogLevelFilter::Crit);
        assert_eq!(map_log_level(CfgLogLevel::Error), LogLevelFilter::Error);
        assert_eq!(map_log_level(CfgLogLevel::Warn), LogLevelFilter::Warn);
        assert_eq!(map_log_level(CfgLogLevel::Notice), LogLevelFilter::Notice);
        assert_eq!(map_log_level(CfgLogLevel::Info), LogLevelFilter::Info);
        assert_eq!(map_log_level(CfgLogLevel::Debug), LogLevelFilter::Debug);
        assert_eq!(map_log_level(CfgLogLevel::Debug2), LogLevelFilter::Debug2);

        assert_eq!(map_access_level(CfgAccessLevel::None), AccessLogLevel::None);
        assert_eq!(
            map_access_level(CfgAccessLevel::Config),
            AccessLogLevel::Config
        );
        assert_eq!(
            map_access_level(CfgAccessLevel::Actions),
            AccessLogLevel::Actions
        );
        assert_eq!(map_access_level(CfgAccessLevel::All), AccessLogLevel::All);

        assert_eq!(map_pipeline_severity(LogSeverity::Emerg), Level::Emergency);
        assert_eq!(map_pipeline_severity(LogSeverity::Alert), Level::Alert);
        assert_eq!(map_pipeline_severity(LogSeverity::Crit), Level::Crit);
        assert_eq!(map_pipeline_severity(LogSeverity::Error), Level::Error);
        assert_eq!(map_pipeline_severity(LogSeverity::Warning), Level::Warn);
        assert_eq!(map_pipeline_severity(LogSeverity::Notice), Level::Notice);
        assert_eq!(map_pipeline_severity(LogSeverity::Info), Level::Info);
        assert_eq!(map_pipeline_severity(LogSeverity::Debug), Level::Debug);
        assert_eq!(map_pipeline_severity(LogSeverity::Debug2), Level::Debug2);

        assert_eq!(
            classify_ipp_op(op::CUPS_ADD_MODIFY_PRINTER),
            AccessCategory::Config
        );
        assert_eq!(classify_ipp_op(op::PRINT_JOB), AccessCategory::Action);
        assert_eq!(
            classify_ipp_op(op::GET_PRINTER_ATTRIBUTES),
            AccessCategory::Query
        );

        let notifier = Notifier::noop();
        for ev in events::Event::ALL {
            emit_dbus_event(
                &notifier,
                &EventSignal {
                    event: *ev,
                    printer: Some("p1".into()),
                    printer_uri: Some("ipp://localhost:631/printers/p1".into()),
                    printer_state: Some(3),
                    printer_state_reasons: Some("none".into()),
                    printer_accepting: Some(true),
                    job_id: Some(1),
                    job_state: Some(9),
                    job_name: Some("doc".into()),
                    text: "event".into(),
                },
            );
        }
    }

    #[test]
    fn syslog_maps_to_stderr_and_none_disables_logs() {
        let dir = tmp_dir("syslog");
        let prev = std::env::current_dir().unwrap();
        let mut cfg = Config {
            cupsd: cups_config::CupsdConfig::defaults(),
            files: cups_config::CupsFilesConfig::defaults(),
        };
        cfg.files.error_log = Some("syslog".into());
        cfg.files.access_log = Some("SysLog".into());
        cfg.files.page_log = Some("syslog".into());
        let logger = build_logger(&cfg, LogFormat::Text);
        assert!(logger.page.is_some());
        assert!(logger.audit.is_none());
        assert_ne!(logger.error_level, LogLevelFilter::None);
        // No literal `syslog` file is ever created relative to the CWD.
        assert!(!prev.join("syslog").exists());
        assert!(!dir.join("syslog").exists());

        cfg.files.error_log = Some("none".into());
        cfg.files.access_log = Some("None".into());
        cfg.files.page_log = Some("none".into());
        let off = build_logger(&cfg, LogFormat::Text);
        assert_eq!(off.error_level, LogLevelFilter::None);
        assert_eq!(off.access_level, AccessLogLevel::None);
        assert!(off.page.is_none());
        assert!(off.audit.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
