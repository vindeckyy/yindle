//! Enterprise daemon lifecycle: startup bootstrap, crash recovery, DNS-SD
//! management, `sd_notify` + `WATCHDOG_USEC` heartbeat, `SIGHUP` zero-downtime
//! hot-reload, and graceful `SIGTERM`/`SIGINT`/`IdleExitTimeout` draining & flush.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use cups_config::{BrowseProtocols, Config, ListenAddr, Paths};
use cups_dbus::{Notifier, ServerEventKind};
use cups_log::Level;
use dnssd::{Advertiser, AdvertiserConfig, SharedPrinter};
use events::Subscriptions;
use job::{CrashRecoveryPolicy, Jobs};
use mime_db::MimeDb;
use printer::{ptype, Printer, Registry};
use tokio::sync::{watch, Notify};
use tokio::task::JoinSet;

use crate::cli::{effective_server_root, CliArgs, VERSION};
use crate::logging::{init_tracing, LogManager};
use crate::metrics::Metrics;
use crate::scheduler::{Scheduler, SchedulerOptions};
use crate::server::{
    accept_tcp_loop, accept_unix_loop, bind_listeners_with_activated, build_clients_semaphore,
    build_server_config, build_tls_config, default_authenticator, init_tls, local_hostname,
    BoundListener, DaemonState,
};

/// Options customizing daemon startup (allows tests to use fast housekeeping/drain intervals).
#[derive(Debug, Clone)]
pub struct DaemonRuntimeOptions {
    /// Housekeeping interval for the event-driven scheduler.
    pub housekeeping_interval: Duration,
    /// Maximum wait to drain in-flight HTTP/IPP clients during shutdown.
    pub drain_timeout: Duration,
    /// Echo error logs to stderr (foreground mode).
    pub echo_stderr: bool,
    /// Enable on-demand `IdleExitTimeout` mode (`-l`).
    pub on_demand: bool,
    /// Optional `WATCHDOG_USEC` override (reads `std::env::var("WATCHDOG_USEC")` when `None`).
    pub watchdog_usec: Option<u64>,
}

impl Default for DaemonRuntimeOptions {
    fn default() -> Self {
        Self {
            housekeeping_interval: Duration::from_secs(1),
            drain_timeout: Duration::from_secs(10),
            echo_stderr: true,
            on_demand: false,
            watchdog_usec: None,
        }
    }
}

/// Live handle to a running `cupsd` instance (used both by the CLI entrypoint
/// and by live loopback integration tests).
pub struct RunningDaemon {
    pub state: Arc<DaemonState>,
    paths: Paths,
    bound_tcp: Vec<SocketAddr>,
    bound_unix: Vec<PathBuf>,
    shutdown_tx: watch::Sender<bool>,
    idle_exit_rx: watch::Receiver<bool>,
    tasks: JoinSet<()>,
    drain_timeout: Duration,
}

impl RunningDaemon {
    /// Bound TCP listener addresses (useful when binding ephemeral port `0`).
    #[must_use]
    pub fn bound_tcp_addrs(&self) -> &[SocketAddr] {
        &self.bound_tcp
    }

    /// Bound Unix domain socket paths.
    #[must_use]
    pub fn bound_unix_paths(&self) -> &[PathBuf] {
        &self.bound_unix
    }

    /// Subscribe to on-demand `IdleExitTimeout` exit signal.
    #[must_use]
    pub fn idle_exit_receiver(&self) -> watch::Receiver<bool> {
        self.idle_exit_rx.clone()
    }

    /// Perform zero-downtime `SIGHUP` hot-reload:
    /// - Emits `sd_notify("RELOADING=1")`
    /// - Reloads `cupsd.conf` / `cups-files.conf` (keeping old config on parse error!)
    /// - Reloads `MimeDb::load_standard`
    /// - Reloads `ReloadableTls` atomically
    /// - Reopens all log sinks and updates `Logger`
    /// - Refreshes `httpd::ServerConfig`, `FilterLimit`, `MaxClients`, and DNS-SD
    /// - Emits `ServerRestarted` on D-Bus and `sd_notify("READY=1")`
    #[allow(clippy::too_many_lines)]
    pub fn reload(&self) -> io::Result<()> {
        let _ = sys::sd_notify("RELOADING=1");
        self.state
            .log
            .err(Level::Info, "Reloading configuration (SIGHUP).");

        let outcome = cups_config::load(&self.paths);
        if !outcome.ok {
            self.state.log.err(
                Level::Error,
                "Configuration reload failed; keeping previous active configuration.",
            );
            let _ = sys::sd_notify("READY=1");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid configuration on SIGHUP reload",
            ));
        }
        let new_cfg = Arc::new(outcome.config);
        let new_server_root = effective_server_root(&new_cfg, &self.paths);
        let data_dir = PathBuf::from(
            new_cfg
                .files
                .data_dir
                .as_deref()
                .unwrap_or("/usr/share/cups"),
        );

        // Reload MIME DB.
        match MimeDb::load_standard(&data_dir, &new_server_root) {
            Ok(db) => {
                *self
                    .state
                    .mime
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(db);
            }
            Err(e) => {
                self.state.log.err(
                    Level::Warn,
                    format!("MIME DB reload warning ({e}); retaining previous MIME table"),
                );
            }
        }

        // Reload TLS certificates & SSLOptions atomically (rollback on error); if TLS was
        // disabled at startup, attempt initialization so newly deployed certs take effect.
        let ssl_dir = crate::server::effective_ssl_dir(&new_cfg, &new_server_root);
        if let Some(tls_handle) = self.state.current_tls() {
            match build_tls_config(&new_cfg.cupsd.tls_options, &ssl_dir)
                .and_then(|tc| tls_handle.reload_with_config(tc))
            {
                Ok(()) => {
                    self.state
                        .log
                        .err(Level::Info, "TLS certificates reloaded cleanly.");
                }
                Err(e) => {
                    self.state.log.err(
                        Level::Error,
                        format!("TLS reload failed ({e}); keeping previous active certificates"),
                    );
                }
            }
        } else if let Ok(Some(handle)) = init_tls(&new_cfg, &new_server_root, &self.state.log) {
            *self
                .state
                .tls
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
        }

        // Reopen log files & update Logger thresholds.
        if let Err(e) = self.state.log.reload(&new_cfg) {
            self.state
                .log
                .err(Level::Warn, format!("Log reopen warning: {e}"));
        }

        // Swap runtime config, httpd ServerConfig, FilterLimit, MaxClients, ServerRoot.
        let new_httpd = Arc::new(build_server_config(&new_cfg));
        let new_sem = build_clients_semaphore(&new_cfg);
        let new_filter_limit = u64::try_from(new_cfg.cupsd.filter_limit.max(0)).unwrap_or(0);
        self.state
            .cfg
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone_from(&new_cfg);
        self.state
            .server_root
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone_from(&new_server_root);
        *self
            .state
            .httpd_cfg
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = new_httpd;
        *self
            .state
            .clients_sem
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = new_sem;
        self.state.metrics.set_filter_limit(new_filter_limit);

        // Refresh DNS-SD advertiser with updated AdvertiserConfig.
        refresh_dnssd(
            &new_cfg,
            &new_server_root,
            self.state.current_tls().is_some(),
            &self.state.registry,
            &self.state.dnssd,
            &self.state.log,
        );

        let _ = self.state.dbus.emit_server(
            ServerEventKind::Restarted,
            "Scheduler reloaded configuration.",
        );
        self.state.scheduler.notify();
        let _ = sys::sd_notify("READY=1");
        self.state
            .log
            .err(Level::Info, "Configuration reload complete.");
        Ok(())
    }

    /// Perform graceful zero-data-loss shutdown:
    /// - Marks `/readyz` unhealthy (`503 Service Unavailable`)
    /// - Emits `sd_notify("STOPPING=1")`
    /// - Stops accepting new connections
    /// - Deregisters DNS-SD
    /// - Drains in-flight client connections (up to `drain_timeout`)
    /// - Cancels/cleans up active jobs
    /// - Atomically flushes `printers.conf`, `classes.conf`, `subscriptions.conf`, `job.cache`, `printcap`
    /// - Emits `ServerStopped` on D-Bus
    pub async fn shutdown(mut self) {
        self.state.metrics.set_shutting_down(true);
        let _ = sys::sd_notify("STOPPING=1");
        self.state
            .log
            .err(Level::Info, "Scheduler initiating graceful shutdown.");

        // 1. Stop accept loops, scheduler loop, and watchdog.
        let _ = self.shutdown_tx.send(true);

        // 2. Deregister DNS-SD immediately so clients stop discovering this instance.
        if let Some(adv) = self
            .state
            .dnssd
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            adv.shutdown();
        }

        // 3. Gracefully drain in-flight HTTP/IPP connections within bounded drain timeout.
        let drain_deadline = Instant::now() + self.drain_timeout;
        while self.state.metrics.active_clients() > 0 {
            let Some(rem) = drain_deadline.checked_duration_since(Instant::now()) else {
                self.state.log.err(
                    Level::Warn,
                    format!(
                        "Drain timeout reached with {} active client(s) remaining.",
                        self.state.metrics.active_clients()
                    ),
                );
                break;
            };
            let notified = self.state.clients_drained.notified();
            if self.state.metrics.active_clients() == 0 {
                break;
            }
            let _ = tokio::time::timeout(rem.min(Duration::from_millis(100)), notified).await;
        }

        // 4. Gracefully stop active running jobs.
        self.state
            .scheduler
            .shutdown_active_jobs(self.drain_timeout.min(Duration::from_secs(5)))
            .await;

        // 5. Await accept/scheduler/watchdog task termination cleanly.
        let join_deadline = Instant::now() + Duration::from_secs(2);
        while !self.tasks.is_empty() {
            let Some(rem) = join_deadline.checked_duration_since(Instant::now()) else {
                self.tasks.abort_all();
                break;
            };
            if tokio::time::timeout(rem, self.tasks.join_next())
                .await
                .is_err()
            {
                self.tasks.abort_all();
                break;
            }
        }

        // 6. Flush all persistent state atomically.
        self.state.scheduler.flush_state();
        let _ = self
            .state
            .dbus
            .emit_server(ServerEventKind::Stopped, "Scheduler stopped.");
        self.state
            .log
            .err(Level::Info, "Scheduler shut down cleanly.");
    }
}

/// Start all `cupsd` subsystems and return a [`RunningDaemon`] handle.
pub async fn start_daemon(
    cfg: Config,
    args: &CliArgs,
    paths: Paths,
    rt_opts: DaemonRuntimeOptions,
) -> io::Result<RunningDaemon> {
    start_daemon_with_activated(cfg, args, paths, rt_opts, Vec::new()).await
}

/// Like [`start_daemon`], additionally adopting systemd socket-activated
/// listener fds (obtained via `sys::sd_listen_fds()` before the runtime started).
#[allow(clippy::too_many_lines)]
pub async fn start_daemon_with_activated(
    cfg: Config,
    args: &CliArgs,
    paths: Paths,
    rt_opts: DaemonRuntimeOptions,
    activated: Vec<OwnedFd>,
) -> io::Result<RunningDaemon> {
    let log_format = args.log_format.to_cups_log_format();
    init_tracing(cfg.cupsd.log_level, log_format);

    let server_root = effective_server_root(&cfg, &paths);
    let request_root = PathBuf::from(
        cfg.files
            .request_root
            .as_deref()
            .unwrap_or("/var/spool/cups"),
    );
    let cache_dir = PathBuf::from(cfg.files.cache_dir.as_deref().unwrap_or("/var/cache/cups"));
    let data_dir = PathBuf::from(cfg.files.data_dir.as_deref().unwrap_or("/usr/share/cups"));

    let _ = std::fs::create_dir_all(&request_root);
    let _ = std::fs::create_dir_all(&cache_dir);

    let log = Arc::new(LogManager::new(&cfg, log_format, rt_opts.echo_stderr));
    let filter_limit = u64::try_from(cfg.cupsd.filter_limit.max(0)).unwrap_or(0);
    let metrics = Arc::new(Metrics::new(filter_limit));

    // Load destination registry (`printers.conf` + `classes.conf`).
    let mut reg = Registry {
        next_printer_id: 1,
        next_job_id: 1,
        ..Registry::default()
    };
    for (fname, is_classes) in [("printers.conf", false), ("classes.conf", true)] {
        let p = server_root.join(fname);
        let res = if is_classes {
            reg.load_classes_file(&p)
        } else {
            reg.load_printers_file(&p)
        };
        match res {
            Ok(errs) => {
                for e in errs {
                    log.err(Level::Warn, format!("{fname}: {e}"));
                }
            }
            Err(e) => log.err(Level::Warn, format!("Unable to read {}: {e}", p.display())),
        }
    }
    let registry = Arc::new(RwLock::new(reg));

    // Load subscriptions (`subscriptions.conf`).
    let mut subs_tbl = Subscriptions::new();
    match subs_tbl.load_file(&server_root.join("subscriptions.conf")) {
        Ok(errs) => {
            for e in errs {
                log.err(Level::Warn, format!("subscriptions.conf: {e}"));
            }
        }
        Err(e) => log.err(
            Level::Warn,
            format!("Unable to load subscriptions.conf: {e}"),
        ),
    }
    let subs = Arc::new(RwLock::new(subs_tbl));

    // Load jobs with startup crash recovery (`CrashRecoveryPolicy::Requeue`).
    let loaded_jobs = Jobs::load_with_cache(
        &request_root,
        &cache_dir.join("job.cache"),
        CrashRecoveryPolicy::Requeue,
    );
    let jobs = Arc::new(RwLock::new(loaded_jobs));

    // Load MIME database using standard CUPS FHS precedence (`DataDir/mime`, `DataDir`, `ServerRoot`).
    let mime_db = match MimeDb::load_standard(&data_dir, &server_root) {
        Ok(db) => {
            log.err(
                Level::Info,
                format!(
                    "Loaded MIME database: {} type(s), {} conversion(s).",
                    db.types.len(),
                    db.convs.len()
                ),
            );
            db
        }
        Err(e) => {
            log.err(
                Level::Warn,
                format!("Unable to load MIME database ({e}); continuing with empty MIME DB"),
            );
            MimeDb::default()
        }
    };
    let mime = Arc::new(RwLock::new(Arc::new(mime_db)));

    // Initialize TLS (fail-closed when explicit SSLListen/SSLPort cannot start TLS!).
    let tls_handle = init_tls(&cfg, &server_root, &log)?;
    let has_tls = tls_handle.is_some();
    let tls = Arc::new(RwLock::new(tls_handle));

    // Connect system D-Bus notifier (degrades gracefully to no-op when bus absent).
    let dbus = Arc::new(Notifier::connect_system());

    // Start DNS-SD advertiser when Browsing + BrowseLocalProtocols dnssd enabled.
    let dnssd = Arc::new(RwLock::new(None));
    refresh_dnssd(&cfg, &server_root, has_tls, &registry, &dnssd, &log);

    // Bind systemd activated fds + configured listeners.
    let bound = bind_listeners_with_activated(&cfg, has_tls, &log, activated).await?;

    let httpd_cfg = Arc::new(RwLock::new(Arc::new(build_server_config(&cfg))));
    let clients_sem = Arc::new(RwLock::new(build_clients_semaphore(&cfg)));
    let cfg_lock = Arc::new(RwLock::new(Arc::new(cfg)));
    let root_lock = Arc::new(RwLock::new(server_root));

    let scheduler = Scheduler::new(
        Arc::clone(&cfg_lock),
        Arc::clone(&registry),
        Arc::clone(&jobs),
        Arc::clone(&mime),
        Arc::clone(&subs),
        Arc::clone(&log),
        Arc::clone(&metrics),
        Arc::clone(&dbus),
        Arc::clone(&root_lock),
        SchedulerOptions {
            housekeeping_interval: rt_opts.housekeeping_interval,
            on_demand: rt_opts.on_demand || args.on_demand,
        },
    );

    let state = Arc::new(DaemonState {
        cfg: cfg_lock,
        httpd_cfg,
        registry,
        jobs,
        mime,
        subs,
        dnssd,
        tls,
        authenticator: default_authenticator(),
        log: Arc::clone(&log),
        metrics,
        dbus: Arc::clone(&dbus),
        scheduler: Arc::clone(&scheduler),
        server_root: root_lock,
        clients_sem,
        host_clients: Arc::new(Mutex::new(HashMap::new())),
        clients_drained: Arc::new(Notify::new()),
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (idle_exit_tx, idle_exit_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    let mut bound_tcp = Vec::new();
    let mut bound_unix = Vec::new();

    for ln in bound {
        match ln {
            BoundListener::Tcp {
                listener,
                addr,
                ssl,
            } => {
                bound_tcp.push(addr);
                tasks.spawn(accept_tcp_loop(
                    listener,
                    ssl,
                    Arc::clone(&state),
                    shutdown_rx.clone(),
                ));
            }
            BoundListener::Unix { listener, path } => {
                if let Some(p) = path {
                    bound_unix.push(p);
                }
                tasks.spawn(accept_unix_loop(
                    listener,
                    Arc::clone(&state),
                    shutdown_rx.clone(),
                ));
            }
        }
    }

    // Spawn event-driven async job scheduler loop.
    tasks.spawn(Arc::clone(&scheduler).run(shutdown_rx.clone(), Some(idle_exit_tx)));

    // Spawn systemd watchdog heartbeat task if `WATCHDOG_USEC` is set.
    let watchdog_usec = rt_opts.watchdog_usec.or_else(parse_watchdog_usec_env);
    if let Some(usec) = watchdog_usec.filter(|&u| u > 0) {
        let interval = Duration::from_micros((usec / 2).max(1_000));
        tasks.spawn(watchdog_loop(interval, shutdown_rx));
    }

    let listener_count = bound_tcp.len() + bound_unix.len();
    log.err(
        Level::Info,
        format!("cupsd {VERSION} ready on {listener_count} listener(s)"),
    );
    let _ = dbus.emit_server(ServerEventKind::Started, format!("cupsd {VERSION} started"));
    let _ = sys::sd_notify("READY=1");

    Ok(RunningDaemon {
        state,
        paths,
        bound_tcp,
        bound_unix,
        shutdown_tx,
        idle_exit_rx,
        tasks,
        drain_timeout: rt_opts.drain_timeout,
    })
}

/// Run the full daemon with OS signal handlers (`SIGHUP`, `SIGTERM`, `SIGINT`)
/// plus on-demand `IdleExitTimeout` exit.
pub async fn run_daemon_with_signals(
    cfg: Config,
    args: CliArgs,
    paths: Paths,
    activated: Vec<OwnedFd>,
) -> std::process::ExitCode {
    let drain_secs = u64::try_from(cfg.cupsd.reload_timeout.clamp(1, 30)).unwrap_or(10);
    let rt_opts = DaemonRuntimeOptions {
        housekeeping_interval: Duration::from_secs(1),
        drain_timeout: Duration::from_secs(drain_secs),
        echo_stderr: true,
        on_demand: args.on_demand,
        watchdog_usec: None,
    };

    let daemon = match start_daemon_with_activated(cfg, &args, paths, rt_opts, activated).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cupsd: startup failed: {e}");
            return std::process::ExitCode::from(1);
        }
    };

    let Ok(mut sigint) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    else {
        eprintln!("cupsd: unable to register SIGINT handler");
        daemon.shutdown().await;
        return std::process::ExitCode::from(1);
    };
    let Ok(mut sigterm) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        eprintln!("cupsd: unable to register SIGTERM handler");
        daemon.shutdown().await;
        return std::process::ExitCode::from(1);
    };
    let Ok(mut sighup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
    else {
        eprintln!("cupsd: unable to register SIGHUP handler");
        daemon.shutdown().await;
        return std::process::ExitCode::from(1);
    };

    let mut idle_rx = daemon.idle_exit_receiver();

    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            _ = sighup.recv() => {
                let _ = daemon.reload();
            }
            res = idle_rx.changed() => {
                if res.is_ok() && *idle_rx.borrow() {
                    break;
                }
            }
        }
    }

    daemon.shutdown().await;
    std::process::ExitCode::SUCCESS
}

/// Start, reload, or stop the DNS-SD [`Advertiser`] honoring `Browsing`,
/// `BrowseLocalProtocols`, `BrowseWebIF`, `BrowseIPPSOnly`, `BrowseDNSSDSubTypes`,
/// and real PPD PDL formats.
pub fn refresh_dnssd(
    cfg: &Config,
    server_root: &Path,
    has_tls: bool,
    registry: &RwLock<Registry>,
    dnssd_slot: &RwLock<Option<Advertiser>>,
    log: &LogManager,
) {
    // Shut down any prior advertiser before applying updated config.
    if let Some(old) = dnssd_slot
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        old.shutdown();
    }

    let enabled =
        cfg.cupsd.browsing && (cfg.cupsd.browse_local_protocols.0 & BrowseProtocols::DNSSD.0) != 0;
    if !enabled {
        return;
    }

    let port = cfg
        .cupsd
        .listeners
        .iter()
        .find_map(|l| match &l.addr {
            ListenAddr::Tcp(a) => Some(a.port()),
            ListenAddr::Unix(_) => None,
        })
        .unwrap_or(631);
    let host = cfg
        .cupsd
        .dnssd_host_name
        .clone()
        .unwrap_or_else(local_hostname);
    let computer = cfg
        .cupsd
        .dnssd_computer_name
        .clone()
        .unwrap_or_else(local_hostname);
    let subtypes = dnssd::parse_subtypes(cfg.cupsd.dnssd_subtypes.as_deref());

    let adv_cfg = AdvertiserConfig {
        host: host.clone(),
        computer,
        port,
        tls: has_tls,
        browse_web_if: cfg.cupsd.browse_web_if,
        browse_ipps_only: cfg.cupsd.browse_ipps_only,
        subtypes,
    };

    match Advertiser::start_with_config(adv_cfg) {
        Ok(mut adv) => {
            let shared_printers: Vec<SharedPrinter> = {
                let reg = registry
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                reg.printers
                    .values()
                    .filter(|p| p.shared)
                    .map(|p| build_shared_printer(p, server_root))
                    .collect()
            };
            let count = shared_printers.len();
            for sp in &shared_printers {
                let _ = adv.publish(sp);
            }
            log.err(
                Level::Info,
                format!("DNS-SD advertising {count} shared printer(s) on {host}"),
            );
            *dnssd_slot
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(adv);
        }
        Err(e) => {
            log.err(
                Level::Warn,
                format!("DNS-SD unavailable ({e}); sharing disabled"),
            );
        }
    }
}

/// Build a [`SharedPrinter`] descriptor resolving real PPD PDL formats when present.
#[must_use]
pub fn build_shared_printer(p: &Printer, server_root: &Path) -> SharedPrinter {
    let ppd_path = server_root.join("ppd").join(format!("{}.ppd", p.name));
    let pdl = std::fs::read_to_string(&ppd_path)
        .ok()
        .map(|text| ops::parse_ppd_capabilities(&text))
        .filter(|caps| !caps.filter_formats.is_empty())
        .map_or_else(
            || dnssd::DEFAULT_PDL.to_string(),
            |caps| caps.filter_formats.join(","),
        );
    #[allow(clippy::cast_sign_loss)]
    SharedPrinter {
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

fn parse_watchdog_usec_env() -> Option<u64> {
    std::env::var("WATCHDOG_USEC")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&u| u > 0)
}

async fn watchdog_loop(interval: Duration, mut shutdown_rx: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                let _ = sys::sd_notify("WATCHDOG=1");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn tmp_dir(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "presswork-cupsd-life-{}-{tag}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write_test_tree(base: &Path, extra_cupsd: &str) -> Paths {
        let etc = base.join("etc");
        let spool = base.join("spool");
        let cache = base.join("cache");
        let logs = base.join("logs");
        let run = base.join("run");
        let data = base.join("data");
        let doc = base.join("doc-root");
        for d in [&etc, &spool, &cache, &logs, &run, &data.join("mime"), &doc] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(
            data.join("mime").join("mime.types"),
            "text/plain txt\napplication/octet-stream\n",
        )
        .unwrap();
        std::fs::write(
            data.join("mime").join("mime.convs"),
            "application/octet-stream application/vnd.cups-raw 0 -\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("cups-files.conf"),
            format!(
                "ServerRoot {}\nRequestRoot {}\nCacheDir {}\nStateDir {}\nDataDir {}\nDocumentRoot {}\nErrorLog {}\nAccessLog {}\nPageLog {}\nFileDevice Yes\nPrintcap {}\n",
                etc.display(),
                spool.display(),
                cache.display(),
                run.display(),
                data.display(),
                doc.display(),
                logs.join("error_log").display(),
                logs.join("access_log").display(),
                logs.join("page_log").display(),
                run.join("printcap").display(),
            ),
        )
        .unwrap();
        std::fs::write(
            etc.join("cupsd.conf"),
            format!(
                "LogLevel info\nListen 127.0.0.1:0\nListen {}\nBrowsing No\nWebInterface Yes\n{extra_cupsd}\n<Location />\n  Order allow,deny\n  Allow from 127.0.0.1\n  Allow from ::1\n</Location>\n",
                run.join("cups.sock").display(),
            ),
        )
        .unwrap();
        Paths {
            server_root: etc.clone(),
            cupsd_conf: etc.join("cupsd.conf"),
            cups_files_conf: etc.join("cups-files.conf"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_daemon_startup_reload_dns_rebinding_block_and_graceful_shutdown() {
        let base = tmp_dir("live");
        let paths = write_test_tree(&base, "FilterLimit 100");
        let loaded = cups_config::load(&paths);
        assert!(loaded.ok);

        // Seed a crashed Processing job so startup crash recovery requeues it!
        let mut crashed = job::Job::new(1, "q1", "alice");
        crashed.state = job::JobState::Processing;
        crashed.save(&base.join("spool")).unwrap();

        let daemon = start_daemon(
            loaded.config,
            &CliArgs::default(),
            paths.clone(),
            DaemonRuntimeOptions {
                housekeeping_interval: Duration::from_millis(50),
                drain_timeout: Duration::from_millis(500),
                echo_stderr: false,
                on_demand: false,
                watchdog_usec: Some(40_000),
            },
        )
        .await
        .unwrap();

        assert_eq!(daemon.bound_tcp_addrs().len(), 1);
        assert_eq!(daemon.bound_unix_paths().len(), 1);
        let addr = daemon.bound_tcp_addrs()[0];

        // Verify crash recovery requeued job #1 to Pending!
        assert_eq!(
            daemon.state.jobs.read().unwrap().get(1).unwrap().state,
            job::JobState::Pending
        );

        // 1. Live HTTP GET /healthz & /metrics
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(
            format!(
                "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                addr.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("\"status\":\"ok\""));

        // 2. DNS rebinding blocked (`Host: evil.attacker.example` -> 400 Bad Request!)
        let mut s2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        s2.write_all(
            b"GET /healthz HTTP/1.1\r\nHost: evil.attacker.example\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut resp2 = String::new();
        s2.read_to_string(&mut resp2).await.unwrap();
        assert!(resp2.starts_with("HTTP/1.1 400 Bad Request"));

        // 3. Live Unix socket GET /readyz
        let mut us = tokio::net::UnixStream::connect(&daemon.bound_unix_paths()[0])
            .await
            .unwrap();
        us.write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut uresp = String::new();
        us.read_to_string(&mut uresp).await.unwrap();
        assert!(uresp.starts_with("HTTP/1.1 200 OK"));
        assert!(uresp.contains("\"status\":\"ready\""));

        // 4. Hot-reload (`SIGHUP`) updates FilterLimit live without dropping listener!
        std::fs::write(
            &paths.cupsd_conf,
            "LogLevel info\nListen 127.0.0.1:0\nBrowsing No\nFilterLimit 420\n<Location />\n  Order allow,deny\n  Allow from 127.0.0.1\n</Location>\n",
        )
        .unwrap();
        daemon.reload().unwrap();
        assert_eq!(daemon.state.metrics.filter_limit(), 420);

        // Invalid config on SIGHUP fails cleanly while keeping old config intact!
        let _ = std::fs::remove_file(&paths.cupsd_conf);
        assert!(daemon.reload().is_err());
        assert_eq!(daemon.state.metrics.filter_limit(), 420);

        // 5. Graceful shutdown flushes state cleanly
        daemon.shutdown().await;
        assert!(base.join("etc").join("printers.conf").is_file());
        assert!(base.join("etc").join("classes.conf").is_file());
        assert!(base.join("etc").join("subscriptions.conf").is_file());
        assert!(base.join("cache").join("job.cache").is_file());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn on_demand_idle_exit_timeout_triggers_clean_exit() {
        let base = tmp_dir("idle");
        let paths = write_test_tree(&base, "IdleExitTimeout 1");
        let loaded = cups_config::load(&paths);
        assert!(loaded.ok);

        let daemon = start_daemon(
            loaded.config,
            &CliArgs {
                on_demand: true,
                ..CliArgs::default()
            },
            paths,
            DaemonRuntimeOptions {
                housekeeping_interval: Duration::from_millis(100),
                drain_timeout: Duration::from_millis(300),
                echo_stderr: false,
                on_demand: true,
                watchdog_usec: None,
            },
        )
        .await
        .unwrap();

        let mut idle_rx = daemon.idle_exit_receiver();
        let fired = tokio::time::timeout(Duration::from_secs(3), idle_rx.changed()).await;
        assert!(fired.is_ok());
        assert!(*idle_rx.borrow());

        daemon.shutdown().await;
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_degraded_paths_drain_timeout_and_corrupt_state_files() {
        let base = tmp_dir("degraded");
        let paths = write_test_tree(&base, "");
        // Corrupt persisted state: startup must log & continue.
        std::fs::write(
            base.join("etc").join("printers.conf"),
            "<Printer good>\nDeviceURI socket://192.0.2.1\nBogusDirective 1\n</Printer>\nGarbage line\n",
        )
        .unwrap();
        std::fs::create_dir_all(base.join("etc").join("classes.conf")).unwrap();
        std::fs::write(
            base.join("etc").join("subscriptions.conf"),
            "<Subscription 1>\nNotAThing x\n</Subscription>\njunk\n",
        )
        .unwrap();
        // Remove all MIME sources: startup continues with an empty MIME DB.
        let _ = std::fs::remove_dir_all(base.join("data"));

        let loaded = cups_config::load(&paths);
        assert!(loaded.ok);
        let daemon = start_daemon(
            loaded.config,
            &CliArgs::default(),
            paths.clone(),
            DaemonRuntimeOptions {
                housekeeping_interval: Duration::from_millis(50),
                drain_timeout: Duration::from_millis(200),
                echo_stderr: false,
                on_demand: false,
                watchdog_usec: Some(0),
            },
        )
        .await
        .unwrap();
        let tls = daemon.state.current_tls();
        assert!(tls.is_some());

        // Corrupt the TLS identity + break the error log path: reload keeps old TLS
        // and degrades gracefully while still applying the new config.
        let ssl_dir = base.join("etc").join("ssl");
        for f in ["server.crt", "server.key"] {
            std::fs::write(ssl_dir.join(f), b"not a pem").unwrap();
        }
        let files_conf = std::fs::read_to_string(&paths.cups_files_conf).unwrap();
        let blocker = base.join("blocker");
        std::fs::write(&blocker, b"file").unwrap();
        std::fs::write(
            &paths.cups_files_conf,
            files_conf.replace(
                &format!("ErrorLog {}", base.join("logs").join("error_log").display()),
                &format!("ErrorLog {}", blocker.join("error_log").display()),
            ) + "CreateSelfSignedCerts No\n",
        )
        .unwrap();
        let conf = std::fs::read_to_string(&paths.cupsd_conf).unwrap();
        std::fs::write(
            &paths.cupsd_conf,
            conf.replace("LogLevel info", "LogLevel debug\nFilterLimit 77"),
        )
        .unwrap();
        daemon.reload().unwrap();
        assert_eq!(daemon.state.metrics.filter_limit(), 77);
        assert!(daemon.state.current_tls().is_some());

        // Hold an idle client open so shutdown hits the bounded drain timeout.
        let addr = daemon.bound_tcp_addrs()[0];
        let idle = tokio::net::TcpStream::connect(addr).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while daemon.state.metrics.active_clients() == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(daemon.state.metrics.active_clients() > 0);
        let started = Instant::now();
        daemon.shutdown().await;
        assert!(started.elapsed() < Duration::from_secs(10));
        drop(idle);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dnssd_refresh_shared_printer_pdl_and_shutdown() {
        let base = tmp_dir("dnssd");
        let paths = write_test_tree(&base, "");
        let mut cfg = cups_config::load(&paths).config;
        let log = LogManager::new(&cfg, cups_log::LogFormat::Text, false);
        let server_root = base.join("etc");

        let mut reg = Registry::default();
        let mut p = Printer::new("shared1", "socket://192.0.2.1:9100");
        p.shared = true;
        p.info = Some("Front desk".into());
        reg.printers.insert("shared1".into(), p.clone());
        let registry = RwLock::new(reg);
        let slot: RwLock<Option<Advertiser>> = RwLock::new(None);

        // Disabled browsing never starts an advertiser.
        cfg.cupsd.browsing = false;
        refresh_dnssd(&cfg, &server_root, false, &registry, &slot, &log);
        assert!(slot.read().unwrap().is_none());

        // Enabled browsing (dnssd protocol) starts (or degrades cleanly if mDNS unavailable).
        cfg.cupsd.browsing = true;
        cfg.cupsd.browse_local_protocols = BrowseProtocols::DNSSD;
        cfg.cupsd.dnssd_host_name = Some("pw-test".into());
        refresh_dnssd(&cfg, &server_root, true, &registry, &slot, &log);
        // Refresh again replaces (shuts down) any previous advertiser.
        refresh_dnssd(&cfg, &server_root, true, &registry, &slot, &log);
        if let Some(adv) = slot.write().unwrap().take() {
            adv.shutdown();
        }

        // Real PPD PDLs are advertised when a queue PPD exists.
        let generic = build_shared_printer(&p, &server_root);
        assert_eq!(generic.pdl, dnssd::DEFAULT_PDL);
        std::fs::create_dir_all(server_root.join("ppd")).unwrap();
        std::fs::write(
            server_root.join("ppd").join("shared1.ppd"),
            "*PPD-Adobe: \"4.3\"\n*cupsFilter2: \"application/pdf application/vnd.cups-pdf 0 -\"\n*cupsFilter2: \"image/urf application/vnd.cups-raster 0 -\"\n",
        )
        .unwrap();
        let rich = build_shared_printer(&p, &server_root);
        assert_eq!(rich.name, "shared1");
        assert_eq!(rich.info, "Front desk");
        assert!(!rich.is_class);

        // A live daemon with browsing enabled deregisters DNS-SD on shutdown.
        let conf = std::fs::read_to_string(&paths.cupsd_conf).unwrap();
        std::fs::write(
            &paths.cupsd_conf,
            conf.replace("Browsing No", "Browsing Yes\nBrowseLocalProtocols dnssd"),
        )
        .unwrap();
        let loaded = cups_config::load(&paths);
        let daemon = start_daemon(
            loaded.config,
            &CliArgs::default(),
            paths,
            DaemonRuntimeOptions {
                echo_stderr: false,
                drain_timeout: Duration::from_millis(200),
                ..DaemonRuntimeOptions::default()
            },
        )
        .await
        .unwrap();
        daemon.shutdown().await;
        assert!(parse_watchdog_usec_env().is_none() || std::env::var("WATCHDOG_USEC").is_ok());
        let _ = std::fs::remove_dir_all(&base);
    }
}
