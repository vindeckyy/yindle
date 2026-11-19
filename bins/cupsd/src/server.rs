//! Hardened HTTP/TLS/AuthN/AuthZ/IPP connection server and listener management.
//!
//! Integrates all hardened Wave-1 and Wave-2a crates:
//! - `httpd::ServerConfig` (`max_body`, timeouts, `keep_alive`, temp spool dir,
//!   `HostValidator` blocking DNS rebinding, `PrefixedStream` RFC 2817 handoff)
//! - `cups_tls::ReloadableTls` (`TlsConfig::from_ssl_options_str`, `ServerKeychain`,
//!   `CreateSelfSignedCerts`, optional mTLS, fail-closed `SSLListen`/`SSLPort`,
//!   bounded TLS handshake timeout)
//! - `authn::Authenticator` offloaded via `tokio::task::spawn_blocking` (strict
//!   `401` on invalid `Authorization` header — NEVER falls back to `SO_PEERCRED`)
//! - `authz::check_location` enforced on EVERY request (`426`/`401`/`403`)
//! - `ops::dispatch_async` with verified `peer_host`, `on_cancel_job`, `on_audit`,
//!   and `on_event` -> `cups_dbus::Notifier` + DNS-SD refresh + scheduler wakeup
//! - `MaxClients` and `MaxClientsPerHost` concurrency limits
//! - Atomic `0666` `bind_unix` + systemd `sd_listen_fds` alongside config listeners

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use authn::{AuthBackend, Authenticator};
use authz::{AccessDecision, Subject};
use cups_config::{
    AuthType, Config, ListenAddr, Location, OrderType, PeerCred, Satisfy, TlsOptions,
    TlsVersion as CfgTlsVersion,
};
use cups_dbus::Notifier;
use cups_log::{AccessCategory, AuditEvent, AuditOutcome, Level};
use cups_tls::{ClientAuth, ReloadableTls, TlsConfig};
use dnssd::Advertiser;
use events::Subscriptions;
use httpd::{
    ConnectionOutcome, HostValidator, HttpVersion, Method, PrefixedStream, Request, Response,
    ServerConfig, StatusCode,
};
use ipp_codec::{ops::op, ops::status, DecodeLimits};
use job::Jobs;
use mime_db::MimeDb;
use printer::Registry;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{watch, Notify, OwnedSemaphorePermit, Semaphore};

use crate::cgi::{self, CgiContext, DEFAULT_CGI_TIMEOUT};
use crate::logging::{classify_ipp_op, emit_dbus_event, LogManager};
use crate::metrics::Metrics;
use crate::scheduler::Scheduler;
use crate::web;

/// Timeout applied to every TLS handshake (`SSLListen` and RFC 2817 upgrade).
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

static UNIX_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// All shared runtime state held by the daemon and passed to listeners & handlers.
pub struct DaemonState {
    pub cfg: Arc<RwLock<Arc<Config>>>,
    pub httpd_cfg: Arc<RwLock<Arc<ServerConfig>>>,
    pub registry: Arc<RwLock<Registry>>,
    pub jobs: Arc<RwLock<Jobs>>,
    pub mime: Arc<RwLock<Arc<MimeDb>>>,
    pub subs: Arc<RwLock<Subscriptions>>,
    pub dnssd: Arc<RwLock<Option<Advertiser>>>,
    pub tls: Arc<RwLock<Option<ReloadableTls>>>,
    pub authenticator: Arc<Authenticator>,
    pub log: Arc<LogManager>,
    pub metrics: Arc<Metrics>,
    pub dbus: Arc<Notifier>,
    pub scheduler: Arc<Scheduler>,
    pub server_root: Arc<RwLock<PathBuf>>,
    pub clients_sem: Arc<RwLock<Option<Arc<Semaphore>>>>,
    pub host_clients: Arc<Mutex<HashMap<IpAddr, usize>>>,
    pub clients_drained: Arc<Notify>,
}

impl DaemonState {
    /// Snapshot the current [`Config`].
    #[must_use]
    pub fn current_cfg(&self) -> Arc<Config> {
        Arc::clone(
            &self
                .cfg
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Snapshot the current [`httpd::ServerConfig`].
    #[must_use]
    pub fn current_httpd_cfg(&self) -> Arc<ServerConfig> {
        Arc::clone(
            &self
                .httpd_cfg
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Snapshot the current [`MimeDb`].
    #[must_use]
    pub fn current_mime(&self) -> Arc<MimeDb> {
        Arc::clone(
            &self
                .mime
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Snapshot the current [`ReloadableTls`], if enabled.
    #[must_use]
    pub fn current_tls(&self) -> Option<ReloadableTls> {
        self.tls
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Snapshot effective `ServerRoot`.
    #[must_use]
    pub fn current_server_root(&self) -> PathBuf {
        self.server_root
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Snapshot the current `MaxClients` semaphore (if bounded).
    #[must_use]
    pub fn current_clients_sem(&self) -> Option<Arc<Semaphore>> {
        self.clients_sem
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Real local hostname via `yindle_sys::gethostname()` (falling back to
/// `$HOSTNAME`, then `"localhost"`).
#[must_use]
pub fn local_hostname() -> String {
    if let Some(h) = sys::gethostname() {
        let trimmed = h.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .unwrap_or_else(|| "localhost".into())
}

/// Build a [`HostValidator`] from `ServerName`, `ServerAlias`, local hostname,
/// and local interface IPs to block DNS rebinding attacks.
#[must_use]
pub fn build_host_validator(cfg: &Config) -> HostValidator {
    let server_name = cfg
        .cupsd
        .server_name
        .clone()
        .or_else(|| Some(local_hostname()));
    let mut aliases = cfg.cupsd.server_aliases.clone();
    // Allow connections addressing the host by any of its own local interface IPs
    // (e.g. Kubernetes kubelet/Prometheus pod IP probes) while still blocking
    // arbitrary external DNS names used in DNS rebinding attacks.
    for iface in sys::local_interfaces() {
        let ip_s = iface.addr.to_string();
        if !aliases.iter().any(|a| a.eq_ignore_ascii_case(&ip_s)) {
            aliases.push(ip_s);
        }
    }
    HostValidator::new(server_name, aliases)
}

/// Build a hardened [`httpd::ServerConfig`] from `cfg`.
#[must_use]
pub fn build_server_config(cfg: &Config) -> ServerConfig {
    let max_body = if cfg.cupsd.max_request_size == 0 {
        Some(httpd::DEFAULT_MAX_BODY)
    } else {
        usize::try_from(cfg.cupsd.max_request_size).ok()
    };
    let request_root = PathBuf::from(
        cfg.files
            .request_root
            .as_deref()
            .unwrap_or("/var/spool/cups"),
    );
    let temp_dir = cfg
        .files
        .temp_dir
        .as_deref()
        .map_or_else(|| request_root.join("tmp"), PathBuf::from);
    let _ = std::fs::create_dir_all(&temp_dir);

    let idle_secs = u64::try_from(cfg.cupsd.timeout.clamp(5, 3600)).unwrap_or(300);
    let idle_timeout = Duration::from_secs(idle_secs);
    let ka_secs = u64::try_from(cfg.cupsd.keep_alive_timeout.clamp(1, 300)).unwrap_or(30);
    let keep_alive_timeout = Duration::from_secs(ka_secs);
    let header_timeout = Duration::from_secs(30).min(idle_timeout);

    ServerConfig {
        server_tokens: cfg.cupsd.server_header.clone(),
        max_body,
        spool_threshold: Some(httpd::DEFAULT_SPOOL_THRESHOLD),
        spool_dir: Some(temp_dir),
        idle_timeout,
        keep_alive: cfg.cupsd.keep_alive,
        keep_alive_timeout,
        header_timeout,
        body_timeout: idle_timeout,
        write_timeout: Duration::from_secs(30),
        host_validator: Some(build_host_validator(cfg)),
    }
}

/// Convert `cups_config::TlsOptions` + optional mTLS CA path into [`cups_tls::TlsConfig`],
/// validating through [`TlsConfig::from_ssl_options_str`].
pub fn build_tls_config(opts: &TlsOptions, ssl_dir: &Path) -> io::Result<TlsConfig> {
    let mut tokens: Vec<&'static str> = Vec::new();
    match opts.min_version {
        CfgTlsVersion::V1_3 | CfgTlsVersion::Max => tokens.push("MinTLS1.3"),
        _ => tokens.push("MinTLS1.2"),
    }
    match opts.max_version {
        CfgTlsVersion::V1_2 => tokens.push("MaxTLS1.2"),
        CfgTlsVersion::V1_3 => tokens.push("MaxTLS1.3"),
        CfgTlsVersion::V1_0 => tokens.push("MaxTLS1.0"),
        CfgTlsVersion::V1_1 => tokens.push("MaxTLS1.1"),
        CfgTlsVersion::Ssl3 | CfgTlsVersion::Max => {}
    }
    if opts.deny_cbc {
        tokens.push("DenyCBC");
    }
    let mut tls_cfg = TlsConfig::from_ssl_options_str(&tokens.join(" "))?;

    // Optional mTLS client certificate verification when configured via env or `{ssl_dir}/client-ca.pem`.
    if let Ok(ca_path) =
        std::env::var("YINDLE_MTLS_CA").or_else(|_| std::env::var("PRESSWORK_MTLS_CA"))
    {
        if !ca_path.trim().is_empty() {
            let require = std::env::var("YINDLE_MTLS_REQUIRE")
                .or_else(|_| std::env::var("PRESSWORK_MTLS_REQUIRE"))
                .is_ok_and(|v| {
                    v.eq_ignore_ascii_case("true") || v == "1" || v.eq_ignore_ascii_case("yes")
                });
            tls_cfg.client_auth = if require {
                ClientAuth::RequiredCaFile(PathBuf::from(ca_path))
            } else {
                ClientAuth::OptionalCaFile(PathBuf::from(ca_path))
            };
        }
    } else {
        let default_ca = ssl_dir.join("client-ca.pem");
        if default_ca.is_file() {
            tls_cfg.client_auth = ClientAuth::OptionalCaFile(default_ca);
        }
    }
    Ok(tls_cfg)
}

/// Resolve the effective TLS keychain directory: uses explicit `ServerKeychain`
/// when overridden (or when `ServerRoot` is `/etc/cups`), otherwise `{ServerRoot}/ssl`.
#[must_use]
pub fn effective_ssl_dir(cfg: &Config, server_root: &Path) -> PathBuf {
    match cfg.files.server_keychain.as_deref() {
        Some(kc)
            if !kc.is_empty()
                && (kc != "/etc/cups/ssl" || server_root == Path::new("/etc/cups")) =>
        {
            PathBuf::from(kc)
        }
        _ => cups_tls::ssl_dir(server_root),
    }
}

/// Initialize [`ReloadableTls`] from `cfg` and `server_root`.
///
/// **Fail-closed invariant**: returns `Err` whenever an explicit `SSLListen` or
/// `SSLPort` listener is configured and TLS initialization fails.
pub fn init_tls(
    cfg: &Config,
    server_root: &Path,
    log: &LogManager,
) -> io::Result<Option<ReloadableTls>> {
    let ssl_dir = effective_ssl_dir(cfg, server_root);
    let cn = cfg.cupsd.server_name.clone().unwrap_or_else(local_hostname);
    let has_ssl_listener = cfg.cupsd.listeners.iter().any(|l| l.ssl);

    let tls_cfg = match build_tls_config(&cfg.cupsd.tls_options, &ssl_dir) {
        Ok(c) => c,
        Err(e) => {
            if has_ssl_listener {
                return Err(e);
            }
            log.err(
                Level::Warn,
                format!("Invalid TLS options ({e}); encryption disabled"),
            );
            return Ok(None);
        }
    };

    match ReloadableTls::load_or_create(&ssl_dir, &cn, cfg.files.create_self_signed_certs, tls_cfg)
    {
        Ok(handle) => {
            log.err(
                Level::Info,
                format!("TLS initialized from {}", ssl_dir.display()),
            );
            Ok(Some(handle))
        }
        Err(e) => {
            if has_ssl_listener {
                log.err(
                    Level::Error,
                    format!("TLS required by SSLListen/SSLPort but failed to initialize: {e}"),
                );
                return Err(e);
            }
            log.err(
                Level::Warn,
                format!("Unable to set up TLS ({e}); encryption disabled"),
            );
            Ok(None)
        }
    }
}

/// Build the global `MaxClients` semaphore (`None` when `max_clients <= 0`).
#[must_use]
pub fn build_clients_semaphore(cfg: &Config) -> Option<Arc<Semaphore>> {
    usize::try_from(cfg.cupsd.max_clients)
        .ok()
        .filter(|&n| n > 0)
        .map(|n| Arc::new(Semaphore::new(n)))
}

/// Safely bind a Unix domain socket with mode `0666` (NEVER `0777`!) without
/// unlinking arbitrary non-socket files or exposing a chmod race window.
pub fn bind_unix(path: &Path) -> io::Result<UnixListener> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("refusing to replace non-socket path {}", path.display()),
            ));
        }
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        std::fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid unix socket path"))?;
    let seq = UNIX_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!(".{file_name}.{}.{seq}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp_path);

    let listener = UnixListener::bind(&tmp_path)?;
    if let Err(e) = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o666)) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    Ok(listener)
}

/// Bound listener handle ready to spawn accept tasks.
pub enum BoundListener {
    /// TCP listener with its bound address and `SSLListen` flag.
    Tcp {
        listener: TcpListener,
        addr: SocketAddr,
        ssl: bool,
    },
    /// Unix domain socket listener with optional filesystem path.
    Unix {
        listener: UnixListener,
        path: Option<PathBuf>,
    },
}

/// Adopt the given systemd socket-activated file descriptors (from
/// `sys::sd_listen_fds()`), then bind every configured listener not already
/// covered by one of them.
pub async fn bind_listeners_with_activated(
    cfg: &Config,
    has_tls: bool,
    log: &LogManager,
    activated: Vec<OwnedFd>,
) -> io::Result<Vec<BoundListener>> {
    let mut out = Vec::new();
    let mut covered_tcp: HashSet<SocketAddr> = HashSet::new();
    let mut covered_unix: HashSet<PathBuf> = HashSet::new();

    for fd in activated {
        if let Some(bl) = adopt_activated_fd(fd, cfg, has_tls, log)? {
            match &bl {
                BoundListener::Tcp { addr, .. } => {
                    covered_tcp.insert(*addr);
                }
                BoundListener::Unix { path: Some(p), .. } => {
                    covered_unix.insert(std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()));
                }
                BoundListener::Unix { path: None, .. } => {}
            }
            out.push(bl);
        }
    }

    // 2. Bind any configured listener not already covered by an activated fd.
    for ln in &cfg.cupsd.listeners {
        match &ln.addr {
            ListenAddr::Tcp(addr) => {
                if tcp_already_covered(*addr, &covered_tcp) {
                    continue;
                }
                if ln.ssl && !has_tls {
                    return Err(io::Error::other(format!(
                        "SSLListen {addr} requires TLS but TLS is unavailable"
                    )));
                }
                match TcpListener::bind(addr).await {
                    Ok(listener) => {
                        let bound_addr = listener.local_addr().unwrap_or(*addr);
                        covered_tcp.insert(bound_addr);
                        log.err(
                            Level::Info,
                            format!(
                                "Listening for client connections on {bound_addr}{}",
                                if ln.ssl { " (TLS)" } else { "" }
                            ),
                        );
                        out.push(BoundListener::Tcp {
                            listener,
                            addr: bound_addr,
                            ssl: ln.ssl,
                        });
                    }
                    Err(e) => log.err(
                        Level::Error,
                        format!("Unable to open listen socket for address {addr} - {e}"),
                    ),
                }
            }
            ListenAddr::Unix(path) => {
                let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                if covered_unix.contains(&canon) {
                    continue;
                }
                match bind_unix(path) {
                    Ok(listener) => {
                        let bound_canon =
                            std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                        covered_unix.insert(bound_canon);
                        log.err(
                            Level::Info,
                            format!("Listening for client connections on {}.", path.display()),
                        );
                        out.push(BoundListener::Unix {
                            listener,
                            path: Some(path.clone()),
                        });
                    }
                    Err(e) => log.err(
                        Level::Error,
                        format!(
                            "Unable to open listen socket for address {} - {e}",
                            path.display()
                        ),
                    ),
                }
            }
        }
    }

    if out.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no listeners could be bound",
        ));
    }
    Ok(out)
}

/// Adopt one systemd socket-activated file descriptor as a [`BoundListener`].
///
/// Returns `Ok(None)` for unsupported socket families (the fd is closed), and
/// `Err` (fail-closed) when an activated listener is configured as `SSLListen`
/// but TLS is unavailable.
pub fn adopt_activated_fd(
    fd: OwnedFd,
    cfg: &Config,
    has_tls: bool,
    log: &LogManager,
) -> io::Result<Option<BoundListener>> {
    let family = sys::socket_family(fd.as_raw_fd());
    if family == libc::AF_UNIX {
        let std_l = std::os::unix::net::UnixListener::from(fd);
        let path = std_l
            .local_addr()
            .ok()
            .and_then(|a| a.as_pathname().map(Path::to_path_buf));
        std_l.set_nonblocking(true)?;
        let listener = UnixListener::from_std(std_l)?;
        log.err(Level::Info, "Listening on activated unix socket.");
        return Ok(Some(BoundListener::Unix { listener, path }));
    }
    if family == libc::AF_INET || family == libc::AF_INET6 {
        let std_l = std::net::TcpListener::from(fd);
        std_l.set_nonblocking(true)?;
        let addr = std_l.local_addr()?;
        let listener = TcpListener::from_std(std_l)?;
        // Determine if configured as SSLListen/SSLPort for this addr/port.
        let ssl = cfg.cupsd.listeners.iter().any(|l| {
            l.ssl && matches!(l.addr, ListenAddr::Tcp(ca) if ca == addr || ca.port() == addr.port())
        });
        if ssl && !has_tls {
            return Err(io::Error::other(format!(
                "activated SSL listener {addr} requires TLS but TLS is disabled"
            )));
        }
        let tls_note = if ssl { " (TLS)" } else { "" };
        log.err(
            Level::Info,
            format!("Listening on activated TCP socket {addr}{tls_note}."),
        );
        return Ok(Some(BoundListener::Tcp {
            listener,
            addr,
            ssl,
        }));
    }
    log.err(
        Level::Warn,
        format!("Ignoring activated fd with unsupported socket family {family}."),
    );
    Ok(None)
}

fn tcp_already_covered(want: SocketAddr, covered: &HashSet<SocketAddr>) -> bool {
    if covered.contains(&want) {
        return true;
    }
    covered.iter().any(|c| {
        c.port() == want.port()
            && ((c.ip().is_unspecified() && c.is_ipv4() == want.is_ipv4())
                || (c.ip().is_unspecified() && c.is_ipv6()))
    })
}

/// RAII concurrency guard enforcing `MaxClients`, `MaxClientsPerHost`, and
/// live `yindle_active_clients` / graceful-drain wakeup.
pub struct ClientGuard {
    state: Arc<DaemonState>,
    addr: IpAddr,
    _permit: Option<OwnedSemaphorePermit>,
}

impl ClientGuard {
    /// Attempt to admit a new client connection from `addr`.
    /// Returns `None` when `MaxClients` or `MaxClientsPerHost` is saturated.
    #[must_use]
    pub fn try_acquire(state: Arc<DaemonState>, addr: IpAddr) -> Option<Self> {
        let permit = match state.current_clients_sem() {
            Some(sem) => Some(sem.try_acquire_owned().ok()?),
            None => None,
        };
        let cfg = state.current_cfg();
        let per_host_limit = usize::try_from(cfg.cupsd.max_clients_per_host.max(0)).unwrap_or(0);
        {
            let mut map = state
                .host_clients
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = map.entry(addr).or_insert(0);
            if per_host_limit > 0 && *entry >= per_host_limit {
                return None;
            }
            *entry += 1;
        }
        state.metrics.inc_active_clients();
        state.scheduler.touch_activity();
        Some(Self {
            state,
            addr,
            _permit: permit,
        })
    }
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        {
            let mut map = self
                .state
                .host_clients
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(cnt) = map.get_mut(&self.addr) {
                if *cnt <= 1 {
                    map.remove(&self.addr);
                } else {
                    *cnt -= 1;
                }
            }
        }
        if self.state.metrics.dec_active_clients() == 0 {
            self.state.clients_drained.notify_waiters();
        }
    }
}

/// Connection-level peer context (never attacker-controlled).
#[derive(Debug, Clone)]
pub struct ConnContext {
    pub local: bool,
    pub port: u16,
    pub client_addr: IpAddr,
    /// Verified peer host (NEVER HTTP `Host:` header!).
    pub peer_host: Option<String>,
    /// Peer UID from `SO_PEERCRED` on Unix domain sockets only.
    pub peer_uid: Option<u32>,
    /// Whether this connection is currently TLS-encrypted.
    pub encrypted: bool,
}

/// Accept loop for a TCP listener; exits cleanly when `shutdown_rx` becomes `true`.
pub async fn accept_tcp_loop(
    listener: TcpListener,
    ssl_first_byte: bool,
    state: Arc<DaemonState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            res = listener.accept() => {
                match res {
                    Ok((mut stream, peer)) => {
                        let Some(guard) = ClientGuard::try_acquire(Arc::clone(&state), peer.ip()) else {
                            let _ = reject_overloaded(&mut stream).await;
                            continue;
                        };
                        let port = stream.local_addr().map_or(631, |a| a.port());
                        let local = is_loopback_ip(peer.ip());
                        let conn = ConnContext {
                            local,
                            port,
                            client_addr: peer.ip(),
                            peer_host: local.then(|| "localhost".to_string()),
                            peer_uid: None,
                            encrypted: ssl_first_byte,
                        };
                        let st = Arc::clone(&state);
                        tokio::spawn(async move {
                            let _guard = guard;
                            serve_stream(stream, st, conn, ssl_first_byte).await;
                        });
                    }
                    Err(e) => {
                        state.log.err(Level::Warn, format!("TCP accept error: {e}"));
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
}

/// Accept loop for a Unix domain socket listener; exits cleanly on `shutdown_rx`.
pub async fn accept_unix_loop(
    listener: UnixListener,
    state: Arc<DaemonState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            res = listener.accept() => {
                match res {
                    Ok((mut stream, _)) => {
                        let Some(guard) = ClientGuard::try_acquire(Arc::clone(&state), lo) else {
                            let _ = reject_overloaded(&mut stream).await;
                            continue;
                        };
                        let peer_uid = sys::peer_cred(stream.as_raw_fd()).map(|(_, uid, _)| uid);
                        let conn = ConnContext {
                            local: true,
                            port: 631,
                            client_addr: lo,
                            peer_host: Some("localhost".to_string()),
                            peer_uid,
                            encrypted: false,
                        };
                        let st = Arc::clone(&state);
                        tokio::spawn(async move {
                            let _guard = guard;
                            serve_stream(stream, st, conn, false).await;
                        });
                    }
                    Err(e) => {
                        state.log.err(Level::Warn, format!("Unix accept error: {e}"));
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
}

async fn reject_overloaded<S: AsyncWrite + Unpin>(stream: &mut S) -> io::Result<()> {
    let body = b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.write_all(body)).await;
    let _ = stream.shutdown().await;
    Ok(())
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Serve one client stream, handling first-byte TLS (`SSLListen`), bounded
/// TLS handshake timeout, and RFC 2817 `Upgrade: TLS/1.2` with [`PrefixedStream`].
pub async fn serve_stream<S>(
    mut stream: S,
    state: Arc<DaemonState>,
    mut conn: ConnContext,
    ssl_first_byte: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let httpd_cfg = state.current_httpd_cfg();

    if ssl_first_byte {
        let Some(tls) = state.current_tls() else {
            return;
        };
        let acc = tls.acceptor();
        let Ok(Ok(mut tls_stream)) =
            tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acc.accept(stream)).await
        else {
            return;
        };
        conn.encrypted = true;
        let _ = serve_http_loop(&mut tls_stream, &httpd_cfg, &state, &conn).await;
        return;
    }

    match serve_http_loop(&mut stream, &httpd_cfg, &state, &conn).await {
        Ok(ConnectionOutcome::UpgradeTls { leftover }) => {
            let Some(tls) = state.current_tls() else {
                return;
            };
            let prefixed = PrefixedStream::new(leftover, stream);
            let acc = tls.acceptor();
            let Ok(Ok(mut tls_stream)) =
                tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acc.accept(prefixed)).await
            else {
                return;
            };
            conn.encrypted = true;
            let upgraded_cfg = state.current_httpd_cfg();
            let _ = serve_http_loop(&mut tls_stream, &upgraded_cfg, &state, &conn).await;
        }
        Ok(ConnectionOutcome::Closed) | Err(_) => {}
    }
}

async fn serve_http_loop<S>(
    stream: &mut S,
    httpd_cfg: &ServerConfig,
    state: &Arc<DaemonState>,
    conn: &ConnContext,
) -> Result<ConnectionOutcome, httpd::ServeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let handle = tokio::runtime::Handle::current();
    httpd::serve_connection_with_config(stream, httpd_cfg, |req| {
        tokio::task::block_in_place(|| {
            handle.block_on(dispatch_http_request(Arc::clone(state), conn.clone(), req))
        })
    })
    .await
}

/// Result of per-request authentication.
enum AuthResult {
    /// No credentials supplied (anonymous).
    Anonymous,
    /// Successfully authenticated.
    Authenticated {
        user: String,
        groups: Vec<String>,
        method: &'static str,
    },
    /// Invalid or rejected `Authorization` header — MUST return `401` immediately
    /// without falling back to `SO_PEERCRED`!
    InvalidAuthHeader {
        reason: &'static str,
        detail: &'static str,
    },
}

/// Authenticate a request using `Authorization` header (offloaded via
/// `spawn_blocking`) OR `SO_PEERCRED` (only when NO `Authorization` header was sent).
async fn authenticate_request(
    req: &Request,
    conn: &ConnContext,
    cfg: &Config,
    authenticator: &Arc<Authenticator>,
) -> AuthResult {
    if let Some(raw_header) = req.headers.get("authorization") {
        let Some(creds) = authn::parse(raw_header) else {
            return AuthResult::InvalidAuthHeader {
                reason: "invalid_header",
                detail: "Malformed Authorization header",
            };
        };
        let method = if creds.scheme.eq_ignore_ascii_case("bearer") {
            "bearer"
        } else {
            "basic"
        };
        let auth = Arc::clone(authenticator);
        let verified = tokio::task::spawn_blocking(move || auth.authenticate(&creds))
            .await
            .ok()
            .flatten();
        return match verified {
            Some((user, groups)) => AuthResult::Authenticated {
                user,
                groups,
                method,
            },
            None => AuthResult::InvalidAuthHeader {
                reason: "invalid_credentials",
                detail: "Invalid credentials supplied in Authorization header",
            },
        };
    }

    // `SO_PEERCRED` applies ONLY on Unix domain sockets when no Authorization header was sent.
    if let Some(uid) = conn.peer_uid {
        let allowed = match cfg.files.peer_cred {
            PeerCred::Off => false,
            PeerCred::RootOnly => uid == 0,
            PeerCred::On => true,
        };
        if allowed {
            let resolved = tokio::task::spawn_blocking(move || {
                sys::name_of_uid(uid).map(|u| {
                    let groups = sys::groups_of(&u);
                    (u, groups)
                })
            })
            .await
            .ok()
            .flatten();
            if let Some((user, groups)) = resolved {
                return AuthResult::Authenticated {
                    user,
                    groups,
                    method: "peercred",
                };
            }
        }
    }

    AuthResult::Anonymous
}

/// Build the `WWW-Authenticate` header value honoring `AuthType` and `DefaultAuthType`.
#[must_use]
pub fn www_authenticate_header(required: AuthType, default_auth: AuthType) -> String {
    let effective = if required == AuthType::Default {
        default_auth
    } else {
        required
    };
    match effective {
        AuthType::Bearer => authn::bearer_challenge("CUPS", None),
        _ => authn::basic_challenge("CUPS"),
    }
}

/// Return effective `<Location>` list (synthesizing a loopback-only `<Location />`
/// ONLY when `cupsd.conf` declared zero `<Location>` blocks).
fn effective_locations(cfg: &Config) -> Cow<'_, [Location]> {
    if !cfg.cupsd.locations.is_empty() {
        return Cow::Borrowed(&cfg.cupsd.locations);
    }
    let mut loc = Location::new("/");
    loc.order = OrderType::Deny; // `Order allow,deny` with empty masks -> loopback only!
    loc.encryption = cfg.cupsd.default_encryption;
    loc.satisfy = Satisfy::All;
    Cow::Owned(vec![loc])
}

/// Full async HTTP/IPP request dispatcher (testable directly without sockets!).
#[allow(clippy::too_many_lines)]
pub async fn dispatch_http_request(
    state: Arc<DaemonState>,
    conn: ConnContext,
    req: Request,
) -> Response {
    state.scheduler.touch_activity();
    let cfg = state.current_cfg();
    let host_log = conn.client_addr.to_string();
    let http_ver = match req.version {
        HttpVersion::V09 => (0, 9),
        HttpVersion::V10 => (1, 0),
        _ => (1, 1),
    };

    // 1. Authenticate (strict 401 on invalid Authorization header — NEVER fall back to SO_PEERCRED!).
    let (auth_user, auth_groups, auth_method) =
        match authenticate_request(&req, &conn, &cfg, &state.authenticator).await {
            AuthResult::Anonymous => (None, Vec::new(), "none"),
            AuthResult::Authenticated {
                user,
                groups,
                method,
            } => (Some(user), groups, method),
            AuthResult::InvalidAuthHeader { reason, detail } => {
                state.metrics.record_auth_failure(reason);
                state.metrics.record_http_request(req.method.as_str(), 401);
                state.log.audit(&AuditEvent {
                    timestamp: None,
                    actor: "anonymous",
                    peer_ip: &host_log,
                    auth_method: "invalid",
                    operation: req.method.as_str(),
                    target: &req.uri,
                    outcome: AuditOutcome::Denied,
                    detail,
                });
                state.log.access(
                    AccessCategory::Action,
                    &host_log,
                    None,
                    req.method.as_str(),
                    &req.uri,
                    http_ver,
                    401,
                    0,
                    "-",
                    "-",
                );
                let mut resp = Response::status(StatusCode::UNAUTHORIZED).with_security_headers();
                resp.headers.set(
                    "WWW-Authenticate",
                    www_authenticate_header(AuthType::Default, cfg.cupsd.default_auth_type),
                );
                return resp;
            }
        };

    // 2. RFC 2817 `OPTIONS *` + `Upgrade: TLS/1.x` pre-TLS handshake seam.
    if req.method == Method::Options && req.wants_tls_upgrade {
        let locs = effective_locations(&cfg);
        let mut upgrade_subj = Subject {
            user: auth_user.as_deref(),
            groups: &auth_groups,
            system_groups: &cfg.files.system_group_names,
            addr: conn.client_addr,
            host: conn.peer_host.as_deref().unwrap_or(""),
            encrypted: true, // evaluate host ACL without blocking on pre-upgrade encryption
        };
        let dec = authz::check_location(&locs, "/", "OPTIONS", &upgrade_subj, None);
        if dec == AccessDecision::Forbidden {
            upgrade_subj.encrypted = conn.encrypted;
            let _ = upgrade_subj;
            state.metrics.record_auth_failure("forbidden");
            state.metrics.record_http_request("OPTIONS", 403);
            return Response::status(StatusCode::FORBIDDEN).with_security_headers();
        }
        if state.current_tls().is_some() {
            let mut resp = Response::status(StatusCode::SWITCHING_PROTOCOLS);
            resp.headers.set("Connection", "Upgrade");
            resp.headers.set("Upgrade", "TLS/1.2");
            state.metrics.record_http_request("OPTIONS", 101);
            return resp;
        }
        state.metrics.record_http_request("OPTIONS", 501);
        return Response::status(StatusCode::NOT_IMPLEMENTED).with_security_headers();
    }

    // 3. Enforce `<Location>` ACLs via `authz::check_location` on EVERY request!
    let loc_path = if req.method == Method::Options && req.uri == "*" {
        "/"
    } else {
        req.uri.as_str()
    };
    let subject = Subject {
        user: auth_user.as_deref(),
        groups: &auth_groups,
        system_groups: &cfg.files.system_group_names,
        addr: conn.client_addr,
        host: conn.peer_host.as_deref().unwrap_or(""),
        encrypted: conn.encrypted,
    };
    let locs = effective_locations(&cfg);
    match authz::check_location(&locs, loc_path, req.method.as_str(), &subject, None) {
        AccessDecision::Allowed => {}
        AccessDecision::UpgradeRequired => {
            state.metrics.record_auth_failure("upgrade_required");
            state.metrics.record_http_request(req.method.as_str(), 426);
            state.log.audit(&AuditEvent {
                timestamp: None,
                actor: auth_user.as_deref().unwrap_or("anonymous"),
                peer_ip: &host_log,
                auth_method,
                operation: req.method.as_str(),
                target: &req.uri,
                outcome: AuditOutcome::Denied,
                detail: "TLS encryption required by <Location>",
            });
            state.log.access(
                AccessCategory::Action,
                &host_log,
                auth_user.as_deref(),
                req.method.as_str(),
                &req.uri,
                http_ver,
                426,
                0,
                "-",
                "-",
            );
            let mut resp = Response::status(StatusCode::UPGRADE_REQUIRED).with_security_headers();
            resp.headers.set("Connection", "Upgrade");
            resp.headers.set("Upgrade", "TLS/1.2");
            return resp;
        }
        AccessDecision::AuthRequired(required_auth) => {
            state.metrics.record_auth_failure("unauthorized");
            state.metrics.record_http_request(req.method.as_str(), 401);
            state.log.audit(&AuditEvent {
                timestamp: None,
                actor: "anonymous",
                peer_ip: &host_log,
                auth_method,
                operation: req.method.as_str(),
                target: &req.uri,
                outcome: AuditOutcome::Denied,
                detail: "Authentication required by <Location>",
            });
            state.log.access(
                AccessCategory::Action,
                &host_log,
                None,
                req.method.as_str(),
                &req.uri,
                http_ver,
                401,
                0,
                "-",
                "-",
            );
            let mut resp = Response::status(StatusCode::UNAUTHORIZED).with_security_headers();
            resp.headers.set(
                "WWW-Authenticate",
                www_authenticate_header(required_auth, cfg.cupsd.default_auth_type),
            );
            return resp;
        }
        AccessDecision::Forbidden => {
            state.metrics.record_auth_failure("forbidden");
            state.metrics.record_http_request(req.method.as_str(), 403);
            state.log.audit(&AuditEvent {
                timestamp: None,
                actor: auth_user.as_deref().unwrap_or("anonymous"),
                peer_ip: &host_log,
                auth_method,
                operation: req.method.as_str(),
                target: &req.uri,
                outcome: AuditOutcome::Denied,
                detail: "Denied by <Location> ACL",
            });
            state.log.access(
                AccessCategory::Action,
                &host_log,
                auth_user.as_deref(),
                req.method.as_str(),
                &req.uri,
                http_ver,
                403,
                0,
                "-",
                "-",
            );
            return Response::status(StatusCode::FORBIDDEN).with_security_headers();
        }
    }

    // 4. Built-in observability probes (`/healthz`, `/readyz`, `/metrics`).
    let clean_path = req.uri.split(['?', '#']).next().unwrap_or(&req.uri);
    if matches!(req.method, Method::Get | Method::Head) {
        let probe_resp = match clean_path {
            "/healthz" => Some(state.metrics.healthz_response()),
            "/readyz" => {
                let req_root = PathBuf::from(
                    cfg.files
                        .request_root
                        .as_deref()
                        .unwrap_or("/var/spool/cups"),
                );
                Some(
                    state
                        .metrics
                        .readyz_response(&state.registry, &state.jobs, &req_root),
                )
            }
            "/metrics" => Some(state.metrics.metrics_response(&state.registry, &state.jobs)),
            _ => None,
        };
        if let Some(resp) = probe_resp {
            let code = resp.status.0;
            let len = resp.body.len() as u64;
            state.metrics.record_http_request(req.method.as_str(), code);
            state.log.access(
                AccessCategory::Query,
                &host_log,
                auth_user.as_deref(),
                req.method.as_str(),
                &req.uri,
                http_ver,
                code,
                len,
                "-",
                "-",
            );
            return resp;
        }
    }

    // 5. IPP POST dispatch (`Content-Type: application/ipp`).
    if req.method == Method::Post && is_ipp_content_type(req.content_type()) {
        return dispatch_ipp_async(
            &state,
            &cfg,
            &conn,
            &req,
            auth_user,
            auth_groups,
            auth_method,
            &host_log,
            http_ver,
        )
        .await;
    }

    // 6. Plain OPTIONS.
    if req.method == Method::Options {
        state.metrics.record_http_request("OPTIONS", 200);
        state.log.access(
            AccessCategory::Query,
            &host_log,
            auth_user.as_deref(),
            "OPTIONS",
            &req.uri,
            http_ver,
            200,
            0,
            "-",
            "-",
        );
        return Response::status(StatusCode::OK).with_security_headers();
    }

    // 7. Web UI / CGI / Static routes (enforce `WebInterface No`!).
    if matches!(req.method, Method::Get | Method::Head | Method::Post) {
        if !cfg.cupsd.web_interface {
            state.metrics.record_http_request(req.method.as_str(), 403);
            state.log.access(
                AccessCategory::Query,
                &host_log,
                auth_user.as_deref(),
                req.method.as_str(),
                &req.uri,
                http_ver,
                403,
                0,
                "-",
                "-",
            );
            return Response::with_body(
                StatusCode::FORBIDDEN,
                "text/plain; charset=utf-8",
                b"Web interface is disabled.\n".to_vec(),
            )
            .with_security_headers();
        }

        let server_bin = PathBuf::from(cfg.files.server_bin.as_deref().unwrap_or("/usr/lib/cups"));
        let server_root = state.current_server_root();
        let doc_root = PathBuf::from(
            cfg.files
                .document_root
                .as_deref()
                .unwrap_or("/usr/share/cups/doc-root"),
        );
        let server_name = cfg.cupsd.server_name.clone().unwrap_or_else(local_hostname);

        let body_bytes = read_request_body_async(&req).await.unwrap_or_default();
        let cgi_ctx = CgiContext {
            server_bin: &server_bin,
            server_root: &server_root,
            cfg: &cfg,
            client_addr: conn.client_addr,
            server_name: &server_name,
            port: conn.port,
            encrypted: conn.encrypted,
            remote_user: auth_user.as_deref(),
            auth_type: (auth_method != "none").then_some(auth_method),
            timeout: DEFAULT_CGI_TIMEOUT,
        };

        let resp = if let Some(cgi_resp) = cgi::dispatch_async(&req, &body_bytes, &cgi_ctx).await {
            cgi_resp
        } else if matches!(req.method, Method::Get | Method::Head) {
            let static_resp = web::static_get_async(&req.uri, &doc_root).await;
            if static_resp.status == StatusCode::NOT_FOUND {
                web::render_builtin_ui(
                    &req.uri,
                    &cfg,
                    &state.registry,
                    &state.jobs,
                    &state.metrics,
                    &server_name,
                    auth_user.as_deref(),
                    &auth_groups,
                )
                .unwrap_or(static_resp)
            } else {
                static_resp
            }
        } else {
            Response::status(StatusCode::NOT_IMPLEMENTED).with_security_headers()
        };

        let code = resp.status.0;
        let len = resp.body.len() as u64;
        state.metrics.record_http_request(req.method.as_str(), code);
        state.log.access(
            AccessCategory::Query,
            &host_log,
            auth_user.as_deref(),
            req.method.as_str(),
            &req.uri,
            http_ver,
            code,
            len,
            "-",
            "-",
        );
        return resp;
    }

    state.metrics.record_http_request(req.method.as_str(), 501);
    state.log.access(
        AccessCategory::Query,
        &host_log,
        auth_user.as_deref(),
        req.method.as_str(),
        &req.uri,
        http_ver,
        501,
        0,
        "-",
        "-",
    );
    Response::status(StatusCode::NOT_IMPLEMENTED).with_security_headers()
}

fn is_ipp_content_type(ct: Option<&str>) -> bool {
    ct.is_some_and(|c| {
        c.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/ipp")
    })
}

async fn read_request_body_async(req: &Request) -> io::Result<Cow<'_, [u8]>> {
    if let Some(path) = req.body.spooled_path() {
        let bytes = tokio::fs::read(path).await?;
        Ok(Cow::Owned(bytes))
    } else {
        Ok(Cow::Borrowed(req.body.as_bytes()))
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn dispatch_ipp_async(
    state: &Arc<DaemonState>,
    cfg: &Config,
    conn: &ConnContext,
    req: &Request,
    auth_user: Option<String>,
    auth_groups: Vec<String>,
    auth_method: &'static str,
    host_log: &str,
    http_ver: (u8, u8),
) -> Response {
    let Ok(raw_body) = read_request_body_async(req).await else {
        state.metrics.record_http_request("POST", 500);
        return Response::status(StatusCode::INTERNAL);
    };

    let Ok((msg, consumed)) = ipp_codec::decode_with_limits(&raw_body, &DecodeLimits::default())
    else {
        state.metrics.record_http_request("POST", 400);
        state.log.access(
            AccessCategory::Action,
            host_log,
            auth_user.as_deref(),
            "POST",
            &req.uri,
            http_ver,
            400,
            0,
            "-",
            "-",
        );
        return Response::status(StatusCode::BAD_REQUEST);
    };

    let document = &raw_body[consumed..];
    let mime = state.current_mime();
    let server_root = state.current_server_root();

    let mut ctx = ops::Ctx::new(
        state.registry.as_ref(),
        cfg,
        conn.port,
        state.jobs.as_ref(),
        mime.as_ref(),
        state.subs.as_ref(),
        state.dnssd.as_ref(),
    );
    ctx.is_local = conn.local;
    ctx.is_encrypted = conn.encrypted;
    // Validated HTTP `Host:` is used ONLY for response URIs, NEVER for authz ACLs!
    ctx.hostname = req
        .headers
        .get("host")
        .map_or_else(local_hostname, extract_host_only);
    // Verified peer host for authz host masks (NEVER HTTP `Host:`).
    ctx.peer_host.clone_from(&conn.peer_host);
    ctx.document = document;
    ctx.server_root = server_root;
    ctx.client_addr = conn.client_addr;
    ctx.username.clone_from(&auth_user);
    ctx.user_groups = auth_groups;

    // Wire Wave-2b daemon hooks: cancel_job, audit, event (D-Bus + DNS-SD + scheduler wakeup).
    ctx.on_cancel_job = Some(state.scheduler.cancel_hook());

    let log_for_audit = Arc::clone(&state.log);
    ctx.on_audit = Some(Arc::new(move |rec| {
        log_for_audit.audit_from_ops(rec, auth_method);
    }));

    let dbus_for_event = Arc::clone(&state.dbus);
    let sched_for_event = Arc::clone(&state.scheduler);
    ctx.on_event = Some(Arc::new(move |sig| {
        emit_dbus_event(&dbus_for_event, sig);
        sched_for_event.mark_dirty();
        sched_for_event.notify();
    }));

    let outcome = ops::dispatch_async(&msg, &ctx).await;

    let op_name = op::name(msg.code);
    let status_name = status::name(outcome.response.code);
    state.metrics.record_ipp_request(op_name, status_name);

    if is_scheduler_waking_op(msg.code) {
        state.scheduler.mark_dirty();
        state.scheduler.notify();
    }

    let Ok(encoded) = ipp_codec::encode(&outcome.response) else {
        state.metrics.record_http_request("POST", 500);
        return Response::status(StatusCode::INTERNAL);
    };

    let (http_code, mut resp) = if outcome.upgrade_required {
        state.metrics.record_auth_failure("upgrade_required");
        let mut r = Response::ipp(StatusCode::UPGRADE_REQUIRED, encoded);
        r.headers.set("Connection", "Upgrade");
        r.headers.set("Upgrade", "TLS/1.2");
        (426u16, r)
    } else if outcome.need_auth {
        state.metrics.record_auth_failure("unauthorized");
        let mut r = Response::ipp(StatusCode::UNAUTHORIZED, encoded);
        r.headers.set(
            "WWW-Authenticate",
            www_authenticate_header(
                outcome.auth_type.unwrap_or(AuthType::Default),
                cfg.cupsd.default_auth_type,
            ),
        );
        (401u16, r)
    } else {
        if matches!(
            outcome.response.code,
            status::ERROR_FORBIDDEN | status::ERROR_NOT_AUTHORIZED
        ) {
            state.metrics.record_auth_failure("forbidden");
        }
        (200u16, Response::ipp(StatusCode::OK, encoded))
    };

    resp.headers.set("X-Content-Type-Options", "nosniff");
    state.metrics.record_http_request("POST", http_code);
    state.log.access(
        classify_ipp_op(msg.code),
        host_log,
        auth_user.as_deref(),
        "POST",
        &req.uri,
        http_ver,
        http_code,
        resp.body.len() as u64,
        op_name,
        status_name,
    );
    resp
}

fn extract_host_only(raw_host: &str) -> String {
    let trimmed = raw_host.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((v6, _)) = rest.split_once(']') {
            return format!("[{v6}]");
        }
    }
    trimmed
        .rsplit_once(':')
        .map_or(trimmed, |(h, _)| h)
        .to_string()
}

const fn is_scheduler_waking_op(code: u16) -> bool {
    matches!(
        code,
        op::PRINT_JOB
            | op::PRINT_URI
            | op::SEND_DOCUMENT
            | op::SEND_URI
            | op::CLOSE_JOB
            | op::RELEASE_JOB
            | op::RESTART_JOB
            | op::REPROCESS_JOB
            | op::RESUBMIT_JOB
            | op::RESUME_JOB
            | op::PROMOTE_JOB
            | op::SCHEDULE_JOB_AFTER
            | op::CUPS_MOVE_JOB
            | op::CUPS_AUTHENTICATE_JOB
            | op::RESUME_PRINTER
            | op::ENABLE_PRINTER
            | op::CUPS_ACCEPT_JOBS
            | op::CUPS_ADD_MODIFY_PRINTER
            | op::CUPS_ADD_MODIFY_CLASS
            | op::RELEASE_HELD_NEW_JOBS
            | op::CANCEL_JOB
            | op::CANCEL_CURRENT_JOB
            | op::CANCEL_JOBS
            | op::CANCEL_MY_JOBS
            | op::PURGE_JOBS
    )
}

/// Build the default PAM-first [`Authenticator`] (with shadow fallback when PAM absent).
#[must_use]
pub fn default_authenticator() -> Arc<Authenticator> {
    Arc::new(Authenticator::new(AuthBackend::default()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpd::{Body, Headers};
    use ipp_codec::{tags, Attribute, IppMessage, Text, Value};
    use std::sync::atomic::AtomicU64;

    fn tmp_dir(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "yindle-cupsd-srv-{}-{tag}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    struct StaticBearer;
    impl authn::TokenVerifier for StaticBearer {
        fn verify_bearer(&self, token: &str) -> Option<authn::VerifiedIdentity> {
            if token == "good-token" {
                Some(authn::VerifiedIdentity {
                    user: "admin-user".into(),
                    groups: vec!["lpadmin".into()],
                })
            } else {
                None
            }
        }
    }

    fn test_state(dir: &Path, cupsd_conf: &str) -> Arc<DaemonState> {
        let spool = dir.join("spool");
        let cache = dir.join("cache");
        let logs = dir.join("logs");
        let doc_root = dir.join("doc-root");
        for d in [&spool, &cache, &logs, &doc_root] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (mut cupsd, diags) = cups_config::parse_cupsd_conf(cupsd_conf.as_bytes(), "cupsd.conf");
        assert!(!diags.has_errors(), "diags: {:?}", diags.entries);
        if !cupsd.policies.iter().any(|p| p.name == "default") {
            cupsd.policies.push(cups_config::default_policy());
        }
        let mut files = cups_config::CupsFilesConfig::defaults();
        files.server_root = Some(dir.to_string_lossy().into_owned());
        files.request_root = Some(spool.to_string_lossy().into_owned());
        files.cache_dir = Some(cache.to_string_lossy().into_owned());
        files.document_root = Some(doc_root.to_string_lossy().into_owned());
        files.error_log = Some(logs.join("error_log").to_string_lossy().into_owned());
        files.access_log = Some(logs.join("access_log").to_string_lossy().into_owned());
        files.page_log = Some(logs.join("page_log").to_string_lossy().into_owned());
        files.system_group_names = vec!["lpadmin".into()];

        let cfg = Config { cupsd, files };
        let httpd_cfg = Arc::new(build_server_config(&cfg));
        let log = Arc::new(LogManager::new(&cfg, cups_log::LogFormat::Text, false));
        let metrics = Arc::new(Metrics::new(0));
        let registry = Arc::new(RwLock::new(Registry::default()));
        let jobs = Arc::new(RwLock::new(Jobs::default()));
        let mime = Arc::new(RwLock::new(Arc::new(MimeDb::default())));
        let subs = Arc::new(RwLock::new(Subscriptions::new()));
        let dnssd = Arc::new(RwLock::new(None));
        let dbus = Arc::new(Notifier::noop());
        let cfg_lock = Arc::new(RwLock::new(Arc::new(cfg.clone())));
        let root_lock = Arc::new(RwLock::new(dir.to_path_buf()));
        let tls = init_tls(&cfg, dir, &log).unwrap();
        let clients_sem = build_clients_semaphore(&cfg);
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
            crate::scheduler::SchedulerOptions::default(),
        );
        let authenticator = Arc::new(
            Authenticator::new(AuthBackend::ShadowOnly).with_token_verifier(Arc::new(StaticBearer)),
        );

        Arc::new(DaemonState {
            cfg: cfg_lock,
            httpd_cfg: Arc::new(RwLock::new(httpd_cfg)),
            registry,
            jobs,
            mime,
            subs,
            dnssd,
            tls: Arc::new(RwLock::new(tls)),
            authenticator,
            log,
            metrics,
            dbus,
            scheduler,
            server_root: root_lock,
            clients_sem: Arc::new(RwLock::new(clients_sem)),
            host_clients: Arc::new(Mutex::new(HashMap::new())),
            clients_drained: Arc::new(Notify::new()),
        })
    }

    fn make_req(method: Method, uri: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Request {
        let mut h = Headers::new();
        h.set("Host", "localhost:631");
        for (k, v) in headers {
            h.set(k, *v);
        }
        Request {
            method,
            method_token: method.as_str().into(),
            uri: uri.into(),
            version: HttpVersion::V11,
            headers: h,
            body: if body.is_empty() {
                Body::Empty
            } else {
                Body::Bytes(body)
            },
            keep_alive: true,
            wants_tls_upgrade: false,
        }
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn location_acl_invalid_auth_no_peercred_fallback_and_web_interface() {
        let dir = tmp_dir("acl");
        let conf = "\
LogLevel info
AccessLogLevel all
WebInterface Yes
DefaultAuthType Basic
<Location />
  Order allow,deny
  Allow from 127.0.0.1
</Location>
<Location /admin>
  AuthType Bearer
  Require user @SYSTEM
  Encryption Required
  Order allow,deny
  Allow from 127.0.0.1
</Location>
";
        let state = test_state(&dir, conf);
        let local_conn = ConnContext {
            local: true,
            port: 631,
            client_addr: "127.0.0.1".parse().unwrap(),
            peer_host: Some("localhost".into()),
            peer_uid: Some(0), // Simulate Unix socket peercred for root!
            encrypted: false,
        };

        // 1. Invalid Authorization header MUST return 401 and MUST NOT fall back to SO_PEERCRED!
        let bad_hdr = make_req(
            Method::Get,
            "/",
            &[("Authorization", "BadSchemeOnly")],
            vec![],
        );
        let r1 = dispatch_http_request(Arc::clone(&state), local_conn.clone(), bad_hdr).await;
        assert_eq!(r1.status, StatusCode::UNAUTHORIZED);
        assert!(r1.headers.get("www-authenticate").is_some());

        let bad_creds = make_req(
            Method::Get,
            "/",
            &[("Authorization", "Bearer wrong-token")],
            vec![],
        );
        let r2 = dispatch_http_request(Arc::clone(&state), local_conn.clone(), bad_creds).await;
        assert_eq!(r2.status, StatusCode::UNAUTHORIZED);

        // 2. `/admin` requires TLS -> 426 Upgrade Required on plaintext
        let admin_plain = make_req(Method::Get, "/admin", &[], vec![]);
        let r3 = dispatch_http_request(Arc::clone(&state), local_conn.clone(), admin_plain).await;
        assert_eq!(r3.status, StatusCode::UPGRADE_REQUIRED);
        assert_eq!(r3.headers.get("upgrade"), Some("TLS/1.2"));

        // 3. `/admin` over TLS without auth (and no peercred) -> 401 with Bearer challenge
        let tls_anon = ConnContext {
            encrypted: true,
            peer_uid: None,
            ..local_conn.clone()
        };
        let r4 = dispatch_http_request(
            Arc::clone(&state),
            tls_anon.clone(),
            make_req(Method::Get, "/admin", &[], vec![]),
        )
        .await;
        assert_eq!(r4.status, StatusCode::UNAUTHORIZED);
        assert!(r4
            .headers
            .get("www-authenticate")
            .unwrap()
            .starts_with("Bearer "));

        // 4. Remote IP denied by `<Location />` -> 403 Forbidden
        let remote_conn = ConnContext {
            local: false,
            client_addr: "203.0.113.5".parse().unwrap(),
            peer_host: None,
            peer_uid: None,
            ..local_conn.clone()
        };
        let r5 = dispatch_http_request(
            Arc::clone(&state),
            remote_conn,
            make_req(Method::Get, "/healthz", &[], vec![]),
        )
        .await;
        assert_eq!(r5.status, StatusCode::FORBIDDEN);

        // 5. Local `/healthz`, `/readyz`, `/metrics`, and built-in Web UI `/`
        let hz = dispatch_http_request(
            Arc::clone(&state),
            tls_anon.clone(),
            make_req(Method::Get, "/healthz", &[], vec![]),
        )
        .await;
        assert_eq!(hz.status, StatusCode::OK);
        let rz = dispatch_http_request(
            Arc::clone(&state),
            tls_anon.clone(),
            make_req(Method::Get, "/readyz", &[], vec![]),
        )
        .await;
        assert_eq!(rz.status, StatusCode::OK);
        let met = dispatch_http_request(
            Arc::clone(&state),
            tls_anon.clone(),
            make_req(Method::Get, "/metrics", &[], vec![]),
        )
        .await;
        assert_eq!(met.status, StatusCode::OK);
        let ui = dispatch_http_request(
            Arc::clone(&state),
            tls_anon.clone(),
            make_req(Method::Get, "/", &[], vec![]),
        )
        .await;
        assert_eq!(ui.status, StatusCode::OK);
        assert!(String::from_utf8(ui.body)
            .unwrap()
            .contains("Yindle Print Scheduler"));

        // 6. Authenticated IPP request logs real username (`admin-user`) in access_log!
        let mut ipp = IppMessage::new(op::CUPS_GET_PRINTERS);
        ipp.request_id = 1;
        let g = ipp.group_mut(tags::OPERATION);
        g.attributes.push(Attribute::new(
            "attributes-charset",
            tags::CHARSET,
            vec![Value::Charset(Text::from("utf-8"))],
        ));
        g.attributes.push(Attribute::new(
            "attributes-natural-language",
            tags::LANGUAGE,
            vec![Value::NaturalLanguage(Text::from("en"))],
        ));
        let ipp_bytes = ipp_codec::encode(&ipp).unwrap();
        let ipp_req = make_req(
            Method::Post,
            "/",
            &[
                ("Content-Type", "application/ipp"),
                ("Authorization", "Bearer good-token"),
            ],
            ipp_bytes,
        );
        let r_ipp = dispatch_http_request(Arc::clone(&state), tls_anon.clone(), ipp_req).await;
        assert_eq!(r_ipp.status, StatusCode::OK);
        let access_log = std::fs::read_to_string(dir.join("logs").join("access_log")).unwrap();
        assert!(access_log.contains("admin-user"));

        // 7. `OPTIONS *` + `Upgrade: TLS/1.2` returns 101 Switching Protocols
        let mut opt_up = make_req(Method::Options, "*", &[], vec![]);
        opt_up.wants_tls_upgrade = true;
        let r_up = dispatch_http_request(Arc::clone(&state), local_conn.clone(), opt_up).await;
        assert_eq!(r_up.status, StatusCode::SWITCHING_PROTOCOLS);

        // Plain OPTIONS returns 200
        let r_opt = dispatch_http_request(
            Arc::clone(&state),
            local_conn.clone(),
            make_req(Method::Options, "*", &[], vec![]),
        )
        .await;
        assert_eq!(r_opt.status, StatusCode::OK);

        // 8. `WebInterface No` blocks UI/static/CGI with 403
        {
            let mut next = (*state.current_cfg()).clone();
            next.cupsd.web_interface = false;
            *state.cfg.write().unwrap() = Arc::new(next);
        }
        let r_noweb = dispatch_http_request(
            Arc::clone(&state),
            tls_anon,
            make_req(Method::Get, "/printers", &[], vec![]),
        )
        .await;
        assert_eq!(r_noweb.status, StatusCode::FORBIDDEN);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fail_closed_tls_and_safe_unix_socket_and_client_limits() {
        let dir = tmp_dir("tls_unix");
        let mut cfg = Config {
            cupsd: cups_config::CupsdConfig::defaults(),
            files: cups_config::CupsFilesConfig::defaults(),
        };
        cfg.files.create_self_signed_certs = false;
        cfg.files.server_keychain = Some(dir.join("empty_ssl").to_string_lossy().into_owned());
        cfg.cupsd.listeners.push(cups_config::Listener {
            addr: ListenAddr::Tcp("127.0.0.1:0".parse().unwrap()),
            ssl: true,
        });
        let log = LogManager::new(&cfg, cups_log::LogFormat::Text, false);
        // Explicit SSLListen MUST fail closed when cert is missing and CreateSelfSignedCerts=No!
        assert!(init_tls(&cfg, &dir, &log).is_err());

        // Safe bind_unix refuses to overwrite regular file and sets 0666 mode (never 0777!)
        let regular = dir.join("not_a_socket");
        std::fs::write(&regular, b"keep").unwrap();
        assert!(bind_unix(&regular).is_err());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let sock = dir.join("cups.sock");
            let l1 = bind_unix(&sock).unwrap();
            let mode = std::fs::symlink_metadata(&sock)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o666);
            drop(l1);
            // Atomic replacement of existing socket succeeds
            let _l2 = bind_unix(&sock).unwrap();
        });

        // Client limits (MaxClients & MaxClientsPerHost)
        let state = test_state(
            &dir,
            "MaxClients 2\nMaxClientsPerHost 1\n<Location />\n  Order allow,deny\n</Location>\n",
        );
        let ip1: IpAddr = "127.0.0.1".parse().unwrap();
        let ip2: IpAddr = "127.0.0.2".parse().unwrap();
        let ip3: IpAddr = "127.0.0.3".parse().unwrap();
        let g1 = ClientGuard::try_acquire(Arc::clone(&state), ip1).unwrap();
        // Per-host cap blocks second from ip1
        assert!(ClientGuard::try_acquire(Arc::clone(&state), ip1).is_none());
        let g2 = ClientGuard::try_acquire(Arc::clone(&state), ip2).unwrap();
        // Global MaxClients=2 blocks ip3
        assert!(ClientGuard::try_acquire(Arc::clone(&state), ip3).is_none());
        drop(g1);
        drop(g2);
        assert_eq!(state.metrics.active_clients(), 0);

        assert_eq!(extract_host_only("[::1]:631"), "[::1]");
        assert_eq!(extract_host_only("print.local:8631"), "print.local");
        assert_ne!(local_hostname(), "");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------------------
    // Live loopback TLS / RFC 2817 / overload / IPP outcome tests
    // ---------------------------------------------------------------------

    use tokio::io::AsyncReadExt;
    use tokio_rustls::rustls;

    /// Test-only verifier accepting the daemon's freshly generated self-signed cert.
    #[derive(Debug)]
    struct AcceptAnyCert(Arc<rustls::crypto::CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    pub(crate) fn tls_connector(tls12_only: bool) -> tokio_rustls::TlsConnector {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let versions: &[&rustls::SupportedProtocolVersion] = if tls12_only {
            &[&rustls::version::TLS12]
        } else {
            rustls::DEFAULT_VERSIONS
        };
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(cfg))
    }

    async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            let n = s.read(&mut byte).await.unwrap();
            if n == 0 {
                break;
            }
            buf.push(byte[0]);
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    async fn http_roundtrip<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, raw: &[u8]) -> String {
        s.write_all(raw).await.unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    fn ipp_request(code: u16, printer: Option<&str>) -> IppMessage {
        let mut ipp = IppMessage::new(code);
        ipp.request_id = 7;
        let g = ipp.group_mut(tags::OPERATION);
        g.attributes.push(Attribute::new(
            "attributes-charset",
            tags::CHARSET,
            vec![Value::Charset(Text::from("utf-8"))],
        ));
        g.attributes.push(Attribute::new(
            "attributes-natural-language",
            tags::LANGUAGE,
            vec![Value::NaturalLanguage(Text::from("en"))],
        ));
        if let Some(p) = printer {
            g.attributes.push(Attribute::new(
                "printer-uri",
                tags::URI,
                vec![Value::Uri(Text::from(format!(
                    "ipp://localhost/printers/{p}"
                )))],
            ));
        }
        ipp
    }

    const LIVE_CONF: &str = "\
LogLevel debug
ServerName localhost
WebInterface Yes
DefaultAuthType Basic
<Location />
  Order allow,deny
  Allow from 127.0.0.1
</Location>
<Policy default>
  <Limit CUPS-Add-Modify-Printer>
    AuthType Basic
    Require user @SYSTEM
    Order deny,allow
  </Limit>
  <Limit CUPS-Add-Modify-Class>
    Encryption Required
    Order deny,allow
  </Limit>
  <Limit CUPS-Delete-Class>
    Order allow,deny
    Deny from all
  </Limit>
  <Limit All>
    Order deny,allow
  </Limit>
</Policy>
";

    #[allow(clippy::too_many_lines)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_tls_first_byte_rfc2817_upgrade_unix_and_overload() {
        let dir = tmp_dir("live_tls");
        let state = test_state(&dir, LIVE_CONF);
        assert!(state.current_tls().is_some());
        let (tx, rx) = watch::channel(false);

        let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let plain_addr = plain.local_addr().unwrap();
        let ssl = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssl_addr = ssl.local_addr().unwrap();
        let sock = dir.join("live.sock");
        let unix = bind_unix(&sock).unwrap();
        let t1 = tokio::spawn(accept_tcp_loop(
            plain,
            false,
            Arc::clone(&state),
            rx.clone(),
        ));
        let t2 = tokio::spawn(accept_tcp_loop(ssl, true, Arc::clone(&state), rx.clone()));
        let t3 = tokio::spawn(accept_unix_loop(unix, Arc::clone(&state), rx.clone()));

        let connector = tls_connector(false);
        let sni = rustls::pki_types::ServerName::try_from("localhost").unwrap();

        // 1. First-byte TLS (`SSLListen`) GET /healthz (TLS 1.2 client).
        let tcp = tokio::net::TcpStream::connect(ssl_addr).await.unwrap();
        let mut tls = tls_connector(true).connect(sni.clone(), tcp).await.unwrap();
        let resp = http_roundtrip(
            &mut tls,
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");

        // 2. Plaintext on the SSL listener fails the handshake and is dropped.
        let mut bogus = tokio::net::TcpStream::connect(ssl_addr).await.unwrap();
        let junk = http_roundtrip(&mut bogus, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(!junk.starts_with("HTTP/1.1 200"));

        // 3. RFC 2817 `OPTIONS *` + `Upgrade: TLS/1.2` -> 101 -> TLS on same socket.
        let mut up = tokio::net::TcpStream::connect(plain_addr).await.unwrap();
        up.write_all(
            b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: TLS/1.2\r\n\r\n",
        )
        .await
        .unwrap();
        let head = read_head(&mut up).await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        assert!(head.to_ascii_lowercase().contains("upgrade: tls/1.2"));
        let mut up_tls = connector.connect(sni.clone(), up).await.unwrap();
        let resp = http_roundtrip(
            &mut up_tls,
            b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains("yindle_active_clients"));

        // 4. Unix domain socket with SO_PEERCRED.
        let mut us = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let resp = http_roundtrip(
            &mut us,
            b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");

        // 5. Large (> spool threshold) IPP body is spooled to disk and still decoded.
        let mut big = ipp_codec::encode(&ipp_request(op::CUPS_GET_PRINTERS, None)).unwrap();
        big.extend(std::iter::repeat_n(
            b'x',
            httpd::DEFAULT_SPOOL_THRESHOLD + 4096,
        ));
        let mut raw = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/ipp\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            big.len()
        )
        .into_bytes();
        raw.extend_from_slice(&big);
        let mut bs = tokio::net::TcpStream::connect(plain_addr).await.unwrap();
        let resp = http_roundtrip(&mut bs, &raw).await;
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "{}",
            &resp[..resp.len().min(200)]
        );

        // 6. MaxClients saturation -> 503 Service Unavailable (TCP and Unix).
        *state.clients_sem.write().unwrap() = Some(Arc::new(Semaphore::new(0)));
        let mut over = tokio::net::TcpStream::connect(plain_addr).await.unwrap();
        let resp = http_roundtrip(&mut over, b"").await;
        assert!(resp.starts_with("HTTP/1.1 503"), "{resp}");
        let mut over_u = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let resp = http_roundtrip(&mut over_u, b"").await;
        assert!(resp.starts_with("HTTP/1.1 503"), "{resp}");
        *state.clients_sem.write().unwrap() = None;

        // 7. TLS disabled at runtime: SSL listener drops, upgrade answers 501.
        *state.tls.write().unwrap() = None;
        let mut no_tls = tokio::net::TcpStream::connect(ssl_addr).await.unwrap();
        assert_eq!(http_roundtrip(&mut no_tls, b"x").await, "");
        let mut up2 = tokio::net::TcpStream::connect(plain_addr).await.unwrap();
        up2.write_all(
            b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: TLS/1.2\r\n\r\n",
        )
        .await
        .unwrap();
        let resp = read_head(&mut up2).await;
        assert!(resp.starts_with("HTTP/1.1 501"), "{resp}");

        tx.send(true).unwrap();
        for t in [t1, t2, t3] {
            tokio::time::timeout(Duration::from_secs(5), t)
                .await
                .unwrap()
                .unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ipp_policy_outcomes_events_bad_bodies_and_methods() {
        let dir = tmp_dir("ipp_outcomes");
        let state = test_state(&dir, LIVE_CONF);
        let conn = ConnContext {
            local: true,
            port: 631,
            client_addr: "127.0.0.1".parse().unwrap(),
            peer_host: Some("localhost".into()),
            peer_uid: None,
            encrypted: false,
        };
        let post = |body: Vec<u8>, auth: Option<&str>| {
            let mut hdrs = vec![("Content-Type", "application/ipp")];
            if let Some(a) = auth {
                hdrs.push(("Authorization", a));
            }
            make_req(Method::Post, "/admin/", &hdrs, body)
        };

        // Malformed IPP -> 400.
        let r = dispatch_http_request(Arc::clone(&state), conn.clone(), post(vec![1, 2, 3], None))
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);

        // Anonymous CUPS-Add-Modify-Printer -> IPP need_auth -> HTTP 401 + Basic challenge.
        let mut add = ipp_request(op::CUPS_ADD_MODIFY_PRINTER, Some("q1"));
        add.group_mut(tags::PRINTER).attributes.push(Attribute::new(
            "device-uri",
            tags::URI,
            vec![Value::Uri(Text::from("socket://192.0.2.10:9100"))],
        ));
        let add_bytes = ipp_codec::encode(&add).unwrap();
        let r = dispatch_http_request(
            Arc::clone(&state),
            conn.clone(),
            post(add_bytes.clone(), None),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert!(r
            .headers
            .get("www-authenticate")
            .unwrap()
            .starts_with("Basic"));

        // Authenticated (Bearer -> admin-user in @SYSTEM) succeeds and fires events.
        let r = dispatch_http_request(
            Arc::clone(&state),
            conn.clone(),
            post(add_bytes, Some("Bearer good-token")),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        let (decoded, _) = ipp_codec::decode(&r.body).unwrap();
        assert!(
            state.registry.read().unwrap().find("q1").is_some(),
            "status=0x{:04x} {:?}",
            decoded.code,
            decoded.find(tags::OPERATION, "status-message")
        );

        // CUPS-Add-Modify-Class over plaintext -> 426 Upgrade Required.
        let mut cls = ipp_request(op::CUPS_ADD_MODIFY_CLASS, None);
        cls.group_mut(tags::OPERATION)
            .attributes
            .push(Attribute::new(
                "printer-uri",
                tags::URI,
                vec![Value::Uri(Text::from("ipp://localhost/classes/c1"))],
            ));
        let r = dispatch_http_request(
            Arc::clone(&state),
            conn.clone(),
            post(ipp_codec::encode(&cls).unwrap(), Some("Bearer good-token")),
        )
        .await;
        assert_eq!(r.status, StatusCode::UPGRADE_REQUIRED);
        assert_eq!(r.headers.get("upgrade"), Some("TLS/1.2"));

        // CUPS-Delete-Class denied by policy -> HTTP 200 carrying IPP forbidden status.
        let mut del = ipp_request(op::CUPS_DELETE_CLASS, None);
        del.group_mut(tags::OPERATION)
            .attributes
            .push(Attribute::new(
                "printer-uri",
                tags::URI,
                vec![Value::Uri(Text::from("ipp://localhost/classes/c1"))],
            ));
        let before = state
            .metrics
            .render_prometheus(&state.registry, &state.jobs);
        let r = dispatch_http_request(
            Arc::clone(&state),
            conn.clone(),
            post(ipp_codec::encode(&del).unwrap(), Some("Bearer good-token")),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        let after = state
            .metrics
            .render_prometheus(&state.registry, &state.jobs);
        assert_ne!(before, after);

        // Non-IPP POST with no CGI program -> 501; unsupported method -> 501.
        let r = dispatch_http_request(
            Arc::clone(&state),
            conn.clone(),
            make_req(
                Method::Post,
                "/nothing-here",
                &[("Content-Type", "text/plain")],
                b"x".to_vec(),
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::NOT_IMPLEMENTED);
        let r = dispatch_http_request(
            Arc::clone(&state),
            conn.clone(),
            make_req(Method::Delete, "/whatever", &[], vec![]),
        )
        .await;
        assert_eq!(r.status, StatusCode::NOT_IMPLEMENTED);

        // Static file present in DocumentRoot is served instead of the built-in UI.
        std::fs::write(dir.join("doc-root").join("index.html"), b"<p>static</p>").unwrap();
        let r = dispatch_http_request(
            Arc::clone(&state),
            conn.clone(),
            make_req(Method::Get, "/index.html", &[], vec![]),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body, b"<p>static</p>");

        // HTTP/1.0 + remote OPTIONS upgrade attempt denied by <Location /> -> 403.
        let mut opt = make_req(Method::Options, "*", &[], vec![]);
        opt.wants_tls_upgrade = true;
        opt.version = HttpVersion::V10;
        let remote = ConnContext {
            local: false,
            client_addr: "198.51.100.7".parse().unwrap(),
            peer_host: None,
            ..conn.clone()
        };
        let r = dispatch_http_request(Arc::clone(&state), remote, opt).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);

        // Basic credentials that fail shadow auth -> 401 (never peercred fallback).
        let r = dispatch_http_request(
            Arc::clone(&state),
            ConnContext {
                peer_uid: Some(0),
                ..conn.clone()
            },
            make_req(
                Method::Get,
                "/",
                &[("Authorization", "Basic bm9ib2R5LXB3Ondyb25n")],
                vec![],
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);

        // Peercred (no Authorization header) maps uid -> user for local socket.
        let me = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
        let r = dispatch_http_request(
            Arc::clone(&state),
            ConnContext {
                peer_uid: Some(me),
                ..conn.clone()
            },
            make_req(Method::Get, "/healthz", &[], vec![]),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);

        assert_eq!(
            www_authenticate_header(AuthType::Default, AuthType::Bearer)
                .split(' ')
                .next(),
            Some("Bearer")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn activated_fds_are_adopted_and_ssl_fails_closed_without_tls() {
        let dir = tmp_dir("activated");
        let mut cfg = Config {
            cupsd: cups_config::CupsdConfig::defaults(),
            files: cups_config::CupsFilesConfig::defaults(),
        };
        let log = LogManager::new(&cfg, cups_log::LogFormat::Text, false);

        let std_tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_addr = std_tcp.local_addr().unwrap();
        let unix_path = dir.join("act.sock");
        let std_unix = std::os::unix::net::UnixListener::bind(&unix_path).unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();

        // Configured listeners: the activated TCP addr (covered) + the activated unix path (covered)
        // + a fresh ephemeral TCP listener (bound in addition).
        cfg.cupsd.listeners = vec![
            cups_config::Listener {
                addr: ListenAddr::Tcp(tcp_addr),
                ssl: false,
            },
            cups_config::Listener {
                addr: ListenAddr::Unix(unix_path.clone()),
                ssl: false,
            },
            cups_config::Listener {
                addr: ListenAddr::Tcp("127.0.0.1:0".parse().unwrap()),
                ssl: false,
            },
        ];
        let fds: Vec<OwnedFd> = vec![
            OwnedFd::from(std_tcp),
            OwnedFd::from(std_unix),
            OwnedFd::from(udp),
            OwnedFd::from(file),
        ];
        let bound = bind_listeners_with_activated(&cfg, false, &log, fds)
            .await
            .unwrap();
        // 1 activated TCP + 1 activated unix + 1 freshly-bound TCP (UDP is a socket of
        // family AF_INET and is adopted as TCP only if listen works; /dev/null ignored).
        let tcp_count = bound
            .iter()
            .filter(|b| matches!(b, BoundListener::Tcp { .. }))
            .count();
        let unix_count = bound
            .iter()
            .filter(|b| matches!(b, BoundListener::Unix { .. }))
            .count();
        assert!(tcp_count >= 2, "tcp_count={tcp_count}");
        assert_eq!(unix_count, 1);
        drop(bound);

        // Activated listener configured as SSLListen without TLS -> fail closed.
        let std_tcp2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr2 = std_tcp2.local_addr().unwrap();
        cfg.cupsd.listeners = vec![cups_config::Listener {
            addr: ListenAddr::Tcp(addr2),
            ssl: true,
        }];
        assert!(adopt_activated_fd(OwnedFd::from(std_tcp2), &cfg, false, &log).is_err());
        // Configured SSLListen (not activated) without TLS also fails closed.
        assert!(bind_listeners_with_activated(&cfg, false, &log, Vec::new())
            .await
            .is_err());

        // Unbindable listeners only -> AddrNotAvailable.
        cfg.cupsd.listeners = vec![
            cups_config::Listener {
                addr: ListenAddr::Tcp("192.0.2.1:9".parse().unwrap()),
                ssl: false,
            },
            cups_config::Listener {
                addr: ListenAddr::Unix(dir.join("missing-parent-file").join("x.sock")),
                ssl: false,
            },
        ];
        std::fs::write(dir.join("missing-parent-file"), b"file").unwrap();
        let err = bind_listeners_with_activated(&cfg, false, &log, Vec::new())
            .await
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);

        // tcp_already_covered wildcard semantics.
        let mut covered = HashSet::new();
        covered.insert("0.0.0.0:631".parse::<SocketAddr>().unwrap());
        assert!(tcp_already_covered(
            "127.0.0.1:631".parse().unwrap(),
            &covered
        ));
        assert!(!tcp_already_covered(
            "127.0.0.1:632".parse().unwrap(),
            &covered
        ));

        // TLS option variants and mTLS CA discovery.
        let ssl_dir = dir.join("ssl");
        std::fs::create_dir_all(&ssl_dir).unwrap();
        std::fs::write(ssl_dir.join("client-ca.pem"), b"pem").unwrap();
        let mut opts = cfg.cupsd.tls_options.clone();
        opts.min_version = CfgTlsVersion::V1_3;
        opts.max_version = CfgTlsVersion::V1_3;
        opts.deny_cbc = true;
        let tc = build_tls_config(&opts, &ssl_dir).unwrap();
        assert!(matches!(tc.client_auth, ClientAuth::OptionalCaFile(_)));
        opts.min_version = CfgTlsVersion::V1_2;
        opts.max_version = CfgTlsVersion::V1_2;
        assert!(build_tls_config(&opts, &ssl_dir).is_ok());
        opts.max_version = CfgTlsVersion::V1_1;
        assert!(build_tls_config(&opts, &ssl_dir).is_err());
        opts.max_version = CfgTlsVersion::V1_0;
        assert!(build_tls_config(&opts, &ssl_dir).is_err());

        // Invalid TLS options: warn & disable when no SSL listener; fail when SSLListen.
        let mut bad = cfg.clone();
        bad.cupsd.tls_options.max_version = CfgTlsVersion::V1_0;
        bad.cupsd.listeners.clear();
        assert!(init_tls(&bad, &dir, &log).unwrap().is_none());
        bad.cupsd.listeners.push(cups_config::Listener {
            addr: ListenAddr::Tcp("127.0.0.1:0".parse().unwrap()),
            ssl: true,
        });
        assert!(init_tls(&bad, &dir, &log).is_err());
        // Missing cert without self-signed creation and no SSL listener -> disabled.
        let mut nocert = cfg.clone();
        nocert.cupsd.listeners.clear();
        nocert.files.create_self_signed_certs = false;
        nocert.files.server_keychain = Some(dir.join("nocert").to_string_lossy().into_owned());
        assert!(init_tls(&nocert, &dir, &log).unwrap().is_none());

        // MaxRequestSize explicit value is honored.
        let mut sized = cfg.clone();
        sized.cupsd.max_request_size = 4096;
        assert_eq!(build_server_config(&sized).max_body, Some(4096));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
