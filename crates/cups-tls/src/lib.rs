//! TLS for `cupsd` — a port of `cups/tls.c` + `scheduler/client.c`'s
//! `HTTP_STATE_TLS_*` / `cupsdCreateCert` behavior.
//!
//! Two entry modes:
//!  * `SSLListen`/`SSLPort` — TLS from the first byte (`Encryption Always`).
//!  * RFC 2817 `OPTIONS *` + `Upgrade: TLS/1.x` — `101 Switching Protocols`,
//!    then TLS on the same connection (`Encryption IfRequested/Required`).
//!
//! Security hardening:
//!  * Never panics on mismatched/invalid certs or keys (all errors return `io::Result`).
//!  * Never overwrites existing admin-deployed certificates or keys on parse/match error.
//!  * Enforces `0700` on the `ssl/` directory and `0600` (`O_NOFOLLOW`) on private keys.
//!  * Honors `SSLOptions` (`MinTLS1.2`/`MinTLS1.3`/`MaxTLS1.2`/`MaxTLS1.3`, AEAD-only).
//!  * Supports optional and required mTLS client certificate verification from a CA bundle.
//!  * Provides [`ReloadableTls`] for atomic, zero-downtime `SIGHUP` certificate rotation.

#![forbid(unsafe_code)]

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, SupportedProtocolVersion};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tokio_rustls::TlsAcceptor;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "m68k",
        target_arch = "powerpc",
        target_arch = "powerpc64",
    )
))]
const O_NOFOLLOW: i32 = 0x8000;

#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "m68k",
        target_arch = "powerpc",
        target_arch = "powerpc64",
    ))
))]
const O_NOFOLLOW: i32 = 0x20000;

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const O_NOFOLLOW: i32 = 0x0100;

/// TLS protocol version selector mirroring CUPS `SSLOptions` (`MinTLS*` / `MaxTLS*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum TlsVersion {
    /// `SSLv3` (insecure; unsupported by rustls).
    Ssl3,
    /// TLS 1.0 (insecure; unsupported by rustls).
    V1_0,
    /// TLS 1.1 (insecure; unsupported by rustls).
    V1_1,
    /// TLS 1.2 (minimum supported secure default).
    #[default]
    V1_2,
    /// TLS 1.3.
    V1_3,
    /// Highest protocol version supported by the TLS stack.
    Max,
}

/// Mutual TLS (client certificate) verification policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ClientAuth {
    /// Do not request or verify client certificates (CUPS default).
    #[default]
    None,
    /// Offer client auth using CA certificates from a PEM file; allow unauthenticated clients.
    OptionalCaFile(PathBuf),
    /// Require a valid client certificate chaining to a CA in this PEM file.
    RequiredCaFile(PathBuf),
    /// Offer client auth using inline PEM CA bytes; allow unauthenticated clients.
    OptionalCaPem(Vec<u8>),
    /// Require a valid client certificate chaining to inline PEM CA bytes.
    RequiredCaPem(Vec<u8>),
}

/// TLS server configuration options (protocol versions + mTLS policy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    /// Minimum allowed TLS version (`MinTLS*`).
    pub min_version: TlsVersion,
    /// Maximum allowed TLS version (`MaxTLS*`).
    pub max_version: TlsVersion,
    /// Deny CBC cipher suites (`DenyCBC` — rustls always uses AEAD suites only).
    pub deny_cbc: bool,
    /// Client certificate verification mode (mTLS).
    pub client_auth: ClientAuth,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            min_version: TlsVersion::V1_2,
            max_version: TlsVersion::Max,
            deny_cbc: true,
            client_auth: ClientAuth::None,
        }
    }
}

impl TlsConfig {
    /// Parse a CUPS `SSLOptions` directive value into a [`TlsConfig`].
    pub fn from_ssl_options_str(directive: &str) -> io::Result<Self> {
        let mut cfg = Self::default();
        for tok in directive.split_whitespace() {
            match tok.to_ascii_lowercase().as_str() {
                "none" => cfg = Self::default(),
                "allowssl3" => cfg.min_version = TlsVersion::Ssl3,
                "mintls1.0" => cfg.min_version = TlsVersion::V1_0,
                "mintls1.1" | "denytls1.0" => cfg.min_version = TlsVersion::V1_1,
                "mintls1.2" => cfg.min_version = TlsVersion::V1_2,
                "mintls1.3" => cfg.min_version = TlsVersion::V1_3,
                "maxtls1.0" => cfg.max_version = TlsVersion::V1_0,
                "maxtls1.1" => cfg.max_version = TlsVersion::V1_1,
                "maxtls1.2" => cfg.max_version = TlsVersion::V1_2,
                "maxtls1.3" => cfg.max_version = TlsVersion::V1_3,
                "denycbc" => cfg.deny_cbc = true,
                "allowrc4" | "allowdh" | "nosystem" | "noemptyfragments" => {}
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unknown SSLOptions token: {other}"),
                    ));
                }
            }
        }
        // Validate version bounds eagerly.
        let _ = select_protocol_versions(cfg.min_version, cfg.max_version)?;
        Ok(cfg)
    }
}

/// Validated certificate + private key material for the TLS listener.
///
/// The certificate chain and private key are verified to match during
/// construction, so [`Self::server_config`] and [`Self::acceptor`] never panic.
pub struct ServerIdentity {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    default_config: Arc<ServerConfig>,
}

impl ServerIdentity {
    /// Validate a DER certificate chain + private key and construct a [`ServerIdentity`].
    pub fn from_der(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> io::Result<Self> {
        if certs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "certificate chain is empty",
            ));
        }
        let default_config = build_server_config_inner(&certs, &key, &TlsConfig::default())?;
        Ok(Self {
            certs,
            key,
            default_config,
        })
    }

    /// Parse PEM certificate chain + private key bytes into a validated [`ServerIdentity`].
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> io::Result<Self> {
        let certs = CertificateDer::pem_slice_iter(cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid cert PEM: {e}"))
            })?;
        let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("invalid key PEM: {e}"))
        })?;
        Self::from_der(certs, key)
    }

    /// Return the pre-validated default `rustls::ServerConfig` (TLS 1.2+, no client auth).
    ///
    /// Guaranteed not to panic because the cert/key pair was validated at load time.
    #[must_use]
    pub fn server_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.default_config)
    }

    /// Build a `rustls::ServerConfig` honoring custom [`TlsConfig`] (`SSLOptions` + mTLS).
    pub fn build_server_config(&self, opts: &TlsConfig) -> io::Result<Arc<ServerConfig>> {
        build_server_config_inner(&self.certs, &self.key, opts)
    }

    /// A `tokio-rustls` acceptor using the default validated config.
    #[must_use]
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.server_config())
    }

    /// Build a `tokio-rustls` acceptor honoring custom [`TlsConfig`].
    pub fn build_acceptor(&self, opts: &TlsConfig) -> io::Result<TlsAcceptor> {
        Ok(TlsAcceptor::from(self.build_server_config(opts)?))
    }

    /// Access the loaded certificate chain.
    #[must_use]
    pub fn certs(&self) -> &[CertificateDer<'static>] {
        &self.certs
    }
}

struct ReloadSource {
    dir: PathBuf,
    cn: String,
    create_self_signed: bool,
}

struct ReloadableInner {
    current: RwLock<Arc<ServerConfig>>,
    tls_config: RwLock<TlsConfig>,
    source: Option<ReloadSource>,
}

/// Hot-reloadable TLS configuration handle for `SIGHUP` certificate rotation.
///
/// Cloning is cheap (`Arc` clone) so all listeners and accepted connection
/// handlers can share a single handle.
#[derive(Clone)]
pub struct ReloadableTls {
    inner: Arc<ReloadableInner>,
}

impl ReloadableTls {
    /// Load (or generate when absent and permitted) a TLS identity and wrap it
    /// in a hot-reloadable handle configured with `tls_config`.
    pub fn load_or_create(
        dir: &Path,
        cn: &str,
        create_self_signed: bool,
        tls_config: TlsConfig,
    ) -> io::Result<Self> {
        let id = load_or_create_with_options(dir, cn, create_self_signed)?;
        let cfg = id.build_server_config(&tls_config)?;
        Ok(Self {
            inner: Arc::new(ReloadableInner {
                current: RwLock::new(cfg),
                tls_config: RwLock::new(tls_config),
                source: Some(ReloadSource {
                    dir: dir.to_path_buf(),
                    cn: cn.to_string(),
                    create_self_signed,
                }),
            }),
        })
    }

    /// Wrap an already-built `Arc<ServerConfig>` (without a disk reload source).
    #[must_use]
    pub fn from_config(config: Arc<ServerConfig>) -> Self {
        Self {
            inner: Arc::new(ReloadableInner {
                current: RwLock::new(config),
                tls_config: RwLock::new(TlsConfig::default()),
                source: None,
            }),
        }
    }

    /// Current active `Arc<ServerConfig>`.
    #[must_use]
    pub fn server_config(&self) -> Arc<ServerConfig> {
        Arc::clone(
            &self
                .inner
                .current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Build a `TlsAcceptor` backed by the current active `ServerConfig`.
    #[must_use]
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.server_config())
    }

    /// Atomically replace the active `ServerConfig`.
    pub fn swap(&self, new_config: Arc<ServerConfig>) {
        *self
            .inner
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = new_config;
    }

    /// Reload certificates and keys from disk using the existing [`TlsConfig`].
    ///
    /// Atomic: if loading or validation fails, the previous active config
    /// remains untouched and the error is returned.
    pub fn reload(&self) -> io::Result<()> {
        let opts = self
            .inner
            .tls_config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        self.reload_with_config(opts)
    }

    /// Reload certificates from disk AND update [`TlsConfig`] atomically.
    pub fn reload_with_config(&self, tls_config: TlsConfig) -> io::Result<()> {
        let Some(src) = &self.inner.source else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TLS handle has no disk source to reload",
            ));
        };
        let id = load_or_create_with_options(&src.dir, &src.cn, src.create_self_signed)?;
        let new_cfg = id.build_server_config(&tls_config)?;
        *self
            .inner
            .tls_config
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = tls_config;
        self.swap(new_cfg);
        Ok(())
    }
}

/// Load `{dir}/server.crt|key`, generating a self-signed pair ONLY when both
/// files are genuinely absent (`cupsdCreateCert`).
///
/// Never overwrites existing admin-deployed files on parse/mismatch errors.
pub fn load_or_create(dir: &Path, cn: &str) -> io::Result<ServerIdentity> {
    load_or_create_with_options(dir, cn, true)
}

/// Load `{dir}/server.crt|key`, optionally generating a self-signed pair when
/// BOTH files are absent and `create_self_signed` (`CreateSelfSignedCerts`) is `true`.
pub fn load_or_create_with_options(
    dir: &Path,
    cn: &str,
    create_self_signed: bool,
) -> io::Result<ServerIdentity> {
    let crt = dir.join("server.crt");
    let key = dir.join("server.key");
    let crt_present = path_exists_nofollow(&crt)?;
    let key_present = path_exists_nofollow(&key)?;

    if crt_present || key_present {
        // Never overwrite existing admin-deployed certificate or key material.
        return load(dir);
    }
    if !create_self_signed {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "TLS certificate/key absent in {} and CreateSelfSignedCerts is disabled",
                dir.display()
            ),
        ));
    }
    create(dir, cn)
}

/// Load and validate `{dir}/server.crt` and `{dir}/server.key` without
/// following symlinks, tightening loose key permissions to `0600`.
pub fn load(dir: &Path) -> io::Result<ServerIdentity> {
    load_files(&dir.join("server.crt"), &dir.join("server.key"))
}

/// Load and validate explicit certificate and private key paths without
/// following symlinks, tightening loose private key permissions to `0600`.
pub fn load_files(cert_path: &Path, key_path: &Path) -> io::Result<ServerIdentity> {
    let crt_pem = read_regular_nofollow(cert_path, false)?;
    let key_pem = read_regular_nofollow(key_path, true)?;
    ServerIdentity::from_pem(&crt_pem, &key_pem)
}

/// `ssl_dir` — `{ServerRoot}/ssl`.
#[must_use]
pub fn ssl_dir(server_root: &Path) -> PathBuf {
    server_root.join("ssl")
}

fn path_exists_nofollow(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Generate a self-signed cert + write it (dir `0700`, key `0600` `O_NOFOLLOW`) to `dir`.
fn create(dir: &Path, cn: &str) -> io::Result<ServerIdentity> {
    ensure_ssl_dir(dir)?;
    let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).map_err(to_io)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn.to_string());
    let pair = rcgen::KeyPair::generate().map_err(to_io)?;
    let cert = params.self_signed(&pair).map_err(to_io)?;
    let crt_pem = cert.pem();
    let key_pem = pair.serialize_pem();
    let crt_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    write_new_file(&key_path, key_pem.as_bytes(), 0o600)?;
    write_new_file(&crt_path, crt_pem.as_bytes(), 0o644)?;
    load(dir)
}

fn ensure_ssl_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        if !path_exists_nofollow(dir)? {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        let meta = std::fs::symlink_metadata(dir)?;
        if !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("ssl path {} is not a real directory", dir.display()),
            ));
        }
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

fn read_regular_nofollow(path: &Path, enforce_0600: bool) -> io::Result<Vec<u8>> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    opts.custom_flags(O_NOFOLLOW);
    let mut file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    #[cfg(unix)]
    if enforce_0600 && (meta.permissions().mode() & 0o077 != 0) {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        opts.mode(mode).custom_flags(O_NOFOLLOW);
    }
    let mut file: File = opts.open(path)?;
    file.write_all(bytes)?;
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    Ok(())
}

fn crypto_provider() -> Arc<CryptoProvider> {
    if let Some(p) = CryptoProvider::get_default() {
        Arc::clone(p)
    } else {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }
}

static ONLY_TLS13: [&SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
static ONLY_TLS12: [&SupportedProtocolVersion; 1] = [&rustls::version::TLS12];
static TLS13_AND_12: [&SupportedProtocolVersion; 2] =
    [&rustls::version::TLS13, &rustls::version::TLS12];

fn select_protocol_versions(
    min: TlsVersion,
    max: TlsVersion,
) -> io::Result<&'static [&'static SupportedProtocolVersion]> {
    if min > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TLS version bounds: min {min:?} > max {max:?}"),
        ));
    }
    if max < TlsVersion::V1_2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TLS max version {max:?} is below minimum supported TLS 1.2"),
        ));
    }
    if min >= TlsVersion::V1_3 {
        Ok(&ONLY_TLS13)
    } else if max == TlsVersion::V1_2 {
        Ok(&ONLY_TLS12)
    } else {
        Ok(&TLS13_AND_12)
    }
}

fn build_server_config_inner(
    certs: &[CertificateDer<'static>],
    key: &PrivateKeyDer<'static>,
    opts: &TlsConfig,
) -> io::Result<Arc<ServerConfig>> {
    let provider = crypto_provider();
    let versions = select_protocol_versions(opts.min_version, opts.max_version)?;

    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("TLS versions: {e}")))?;

    let builder = match &opts.client_auth {
        ClientAuth::None => builder.with_no_client_auth(),
        ClientAuth::OptionalCaFile(path) => {
            let pem = read_regular_nofollow(path, false)?;
            builder.with_client_cert_verifier(build_client_verifier(&pem, true, &provider)?)
        }
        ClientAuth::RequiredCaFile(path) => {
            let pem = read_regular_nofollow(path, false)?;
            builder.with_client_cert_verifier(build_client_verifier(&pem, false, &provider)?)
        }
        ClientAuth::OptionalCaPem(pem) => {
            builder.with_client_cert_verifier(build_client_verifier(pem, true, &provider)?)
        }
        ClientAuth::RequiredCaPem(pem) => {
            builder.with_client_cert_verifier(build_client_verifier(pem, false, &provider)?)
        }
    };

    let cfg = builder
        .with_single_cert(certs.to_vec(), key.clone_key())
        .map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("cert/key invalid: {e}"))
        })?;
    Ok(Arc::new(cfg))
}

fn build_client_verifier(
    ca_pem: &[u8],
    allow_unauthenticated: bool,
    provider: &Arc<CryptoProvider>,
) -> io::Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let certs = CertificateDer::pem_slice_iter(ca_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid CA PEM: {e}")))?;
    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client auth CA bundle contains no valid certificates",
        ));
    }
    let mut vb = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(provider));
    if allow_unauthenticated {
        vb = vb.allow_unauthenticated();
    }
    vb.build()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("mTLS verifier: {e}")))
}

fn to_io(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, ServerConnection};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_dir(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "presswork-tls-test-{}-{label}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn gen_self_signed(cn: &str) -> (String, String) {
        let params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
        let kp = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&kp).unwrap();
        (cert.pem(), kp.serialize_pem())
    }

    fn gen_ca_and_leaf(leaf_cn: &str) -> (String, String, String) {
        let mut ca_params = rcgen::CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_kp = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_kp);

        let leaf_params = rcgen::CertificateParams::new(vec![leaf_cn.to_string()]).unwrap();
        let leaf_kp = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();
        (ca_cert.pem(), leaf_cert.pem(), leaf_kp.serialize_pem())
    }

    fn run_handshake(
        server_cfg: Arc<ServerConfig>,
        client_cfg: Arc<ClientConfig>,
        server_name: &str,
    ) -> Result<rustls::ProtocolVersion, rustls::Error> {
        let mut srv = ServerConnection::new(server_cfg)?;
        let mut cli = ClientConnection::new(
            client_cfg,
            ServerName::try_from(server_name.to_string()).unwrap(),
        )?;
        let mut buf = Vec::new();
        for _ in 0..16 {
            buf.clear();
            let _ = cli.write_tls(&mut buf);
            if !buf.is_empty() {
                srv.read_tls(&mut &buf[..]).unwrap();
                srv.process_new_packets()?;
            }
            buf.clear();
            let _ = srv.write_tls(&mut buf);
            if !buf.is_empty() {
                cli.read_tls(&mut &buf[..]).unwrap();
                cli.process_new_packets()?;
            }
            if !cli.is_handshaking() && !srv.is_handshaking() {
                break;
            }
        }
        Ok(srv.protocol_version().unwrap())
    }

    #[test]
    fn load_or_create_sets_strict_permissions_and_builds_acceptor() {
        let dir = temp_dir("create");
        assert_eq!(ssl_dir(&dir), dir.join("ssl"));
        let ssl = ssl_dir(&dir);

        let id = load_or_create(&ssl, "localhost").unwrap();
        assert_eq!(id.certs().len(), 1);
        let _acc = id.acceptor();
        let _cfg = id.server_config();

        #[cfg(unix)]
        {
            let dir_mode = std::fs::symlink_metadata(&ssl)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            let key_mode = std::fs::symlink_metadata(ssl.join("server.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(key_mode, 0o600);
        }

        // Subsequent load reuses the existing cert without regenerating.
        let orig_crt = std::fs::read(ssl.join("server.crt")).unwrap();
        let _id2 = load_or_create(&ssl, "localhost").unwrap();
        assert_eq!(std::fs::read(ssl.join("server.crt")).unwrap(), orig_crt);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mismatched_or_corrupt_admin_certs_return_err_and_are_never_overwritten() {
        let dir = temp_dir("mismatch");
        std::fs::create_dir_all(&dir).unwrap();

        // 1. Mismatched cert and key -> Err (NO panic!) and files untouched.
        let (crt1, _key1) = gen_self_signed("host1.local");
        let (_crt2, key2) = gen_self_signed("host2.local");
        std::fs::write(dir.join("server.crt"), &crt1).unwrap();
        std::fs::write(dir.join("server.key"), &key2).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(
            dir.join("server.key"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let err = load_or_create(&dir, "host1.local").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // Existing files must NOT be overwritten!
        assert_eq!(
            std::fs::read_to_string(dir.join("server.crt")).unwrap(),
            crt1
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("server.key")).unwrap(),
            key2
        );
        // Key perms must STILL have been tightened to 0600 on read!
        #[cfg(unix)]
        {
            let mode = std::fs::symlink_metadata(dir.join("server.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        // 2. Corrupt PEM -> Err and never overwritten.
        std::fs::write(dir.join("server.crt"), "NOT A CERT").unwrap();
        assert!(load_or_create(&dir, "host1.local").is_err());
        assert_eq!(
            std::fs::read_to_string(dir.join("server.crt")).unwrap(),
            "NOT A CERT"
        );

        // 3. CreateSelfSignedCerts = false on empty dir -> NotFound.
        let empty = temp_dir("nocreate");
        let err = load_or_create_with_options(&empty, "localhost", false)
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        // 4. Empty cert chain rejected cleanly.
        let (_, key) = gen_self_signed("localhost");
        let parsed_key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
        assert!(ServerIdentity::from_der(Vec::new(), parsed_key).is_err());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&empty);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_key_and_dir_rejected_via_nofollow() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("symlink");
        std::fs::create_dir_all(&dir).unwrap();
        let (crt, key) = gen_self_signed("localhost");
        let real_key = dir.join("real.key");
        std::fs::write(&real_key, &key).unwrap();
        std::fs::write(dir.join("server.crt"), &crt).unwrap();
        symlink(&real_key, dir.join("server.key")).unwrap();

        assert!(load(&dir).is_err());

        // Non-directory path rejected by ensure_ssl_dir.
        let file_as_dir = dir.join("notadir");
        std::fs::write(&file_as_dir, "x").unwrap();
        assert!(ensure_ssl_dir(&file_as_dir).is_err());

        // Directory passed as cert file rejected.
        assert!(read_regular_nofollow(&dir, false).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ssl_options_parsing_and_protocol_version_enforcement() {
        let c13 = TlsConfig::from_ssl_options_str("MinTLS1.3 DenyCBC NoEmptyFragments").unwrap();
        assert_eq!(c13.min_version, TlsVersion::V1_3);
        assert!(c13.deny_cbc);

        let c12 = TlsConfig::from_ssl_options_str("MinTLS1.2 MaxTLS1.2").unwrap();
        assert_eq!(c12.min_version, TlsVersion::V1_2);
        assert_eq!(c12.max_version, TlsVersion::V1_2);

        let c_reset =
            TlsConfig::from_ssl_options_str("MinTLS1.3 None AllowDH AllowRC4 NoSystem").unwrap();
        assert_eq!(c_reset.min_version, TlsVersion::V1_2);

        let c_legacy_min =
            TlsConfig::from_ssl_options_str("AllowSSL3 MinTLS1.0 DenyTLS1.0 MaxTLS1.3").unwrap();
        assert_eq!(c_legacy_min.max_version, TlsVersion::V1_3);

        // Invalid / conflicting options rejected cleanly.
        assert!(TlsConfig::from_ssl_options_str("MinTLS1.3 MaxTLS1.2").is_err());
        assert!(TlsConfig::from_ssl_options_str("MaxTLS1.1").is_err());
        assert!(TlsConfig::from_ssl_options_str("MaxTLS1.0").is_err());
        assert!(TlsConfig::from_ssl_options_str("BogusOption").is_err());

        // Verify live TLS handshake honors MinTLS1.3 vs MaxTLS1.2.
        let (ca_pem, srv_crt, srv_key) = gen_ca_and_leaf("localhost");
        let id = ServerIdentity::from_pem(srv_crt.as_bytes(), srv_key.as_bytes()).unwrap();

        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let provider = crypto_provider();

        // Server pinned to TLS 1.3 only -> TLS 1.3 client succeeds, TLS 1.2-only client fails.
        let srv13 = id.build_server_config(&c13).unwrap();
        let cli13 = Arc::new(
            ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots.clone())
                .with_no_client_auth(),
        );
        assert_eq!(
            run_handshake(Arc::clone(&srv13), cli13, "localhost").unwrap(),
            rustls::ProtocolVersion::TLSv1_3
        );
        let cli12 = Arc::new(
            ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_protocol_versions(&[&rustls::version::TLS12])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        assert!(run_handshake(srv13, Arc::clone(&cli12), "localhost").is_err());

        // Server pinned to MaxTLS1.2 -> TLS 1.2 client succeeds.
        let srv12 = id.build_server_config(&c12).unwrap();
        assert_eq!(
            run_handshake(srv12, Arc::clone(&cli12), "localhost").unwrap(),
            rustls::ProtocolVersion::TLSv1_2
        );

        // min_version = Max, max_version = Max -> enforces TLS 1.3 only (rejects TLS 1.2).
        let c_max = TlsConfig {
            min_version: TlsVersion::Max,
            max_version: TlsVersion::Max,
            ..Default::default()
        };
        let srv_max = id.build_server_config(&c_max).unwrap();
        assert!(run_handshake(srv_max, cli12, "localhost").is_err());
    }

    #[test]
    fn mtls_optional_and_required_client_auth() {
        let dir = temp_dir("mtls");
        std::fs::create_dir_all(&dir).unwrap();

        let (srv_ca, srv_crt, srv_key) = gen_ca_and_leaf("localhost");
        let (cli_ca, cli_crt, cli_key) = gen_ca_and_leaf("client.local");
        let ca_path = dir.join("client-ca.pem");
        std::fs::write(&ca_path, &cli_ca).unwrap();

        let id = ServerIdentity::from_pem(srv_crt.as_bytes(), srv_key.as_bytes()).unwrap();
        let mut srv_roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(srv_ca.as_bytes()) {
            srv_roots.add(cert.unwrap()).unwrap();
        }
        let provider = crypto_provider();

        let anon_client = Arc::new(
            ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(srv_roots.clone())
                .with_no_client_auth(),
        );
        let client_certs: Vec<_> = CertificateDer::pem_slice_iter(cli_crt.as_bytes())
            .map(Result::unwrap)
            .collect();
        let client_key = PrivateKeyDer::from_pem_slice(cli_key.as_bytes()).unwrap();
        let authed_client = Arc::new(
            ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(srv_roots)
                .with_client_auth_cert(client_certs, client_key)
                .unwrap(),
        );

        // Required mTLS via CA file: rejects anonymous client, accepts valid client cert.
        let req_cfg = TlsConfig {
            client_auth: ClientAuth::RequiredCaFile(ca_path.clone()),
            ..Default::default()
        };
        let srv_req = id.build_server_config(&req_cfg).unwrap();
        assert!(
            run_handshake(Arc::clone(&srv_req), Arc::clone(&anon_client), "localhost").is_err()
        );
        assert!(run_handshake(srv_req, Arc::clone(&authed_client), "localhost").is_ok());

        // Optional mTLS via CA file: accepts BOTH anonymous and valid client cert.
        let opt_cfg = TlsConfig {
            client_auth: ClientAuth::OptionalCaFile(ca_path),
            ..Default::default()
        };
        let srv_opt = id.build_server_config(&opt_cfg).unwrap();
        assert!(run_handshake(Arc::clone(&srv_opt), Arc::clone(&anon_client), "localhost").is_ok());
        assert!(run_handshake(srv_opt, Arc::clone(&authed_client), "localhost").is_ok());

        // Inline PEM variants + empty CA bundle rejection.
        let req_pem_cfg = TlsConfig {
            client_auth: ClientAuth::RequiredCaPem(cli_ca.as_bytes().to_vec()),
            ..Default::default()
        };
        assert!(id.build_acceptor(&req_pem_cfg).is_ok());
        let opt_pem_cfg = TlsConfig {
            client_auth: ClientAuth::OptionalCaPem(cli_ca.as_bytes().to_vec()),
            ..Default::default()
        };
        assert!(id.build_server_config(&opt_pem_cfg).is_ok());
        let empty_ca_cfg = TlsConfig {
            client_auth: ClientAuth::RequiredCaPem(Vec::new()),
            ..Default::default()
        };
        assert!(id.build_server_config(&empty_ca_cfg).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reloadable_tls_rotates_and_rolls_back_safely() {
        let dir = temp_dir("reload");
        let handle =
            ReloadableTls::load_or_create(&dir, "localhost", true, TlsConfig::default()).unwrap();
        let before = handle.server_config();
        let _acc = handle.acceptor();

        // Rotate cert + key on disk, then reload().
        let (new_crt, new_key) = gen_self_signed("rotated.local");
        std::fs::write(dir.join("server.crt"), &new_crt).unwrap();
        std::fs::write(dir.join("server.key"), &new_key).unwrap();
        handle.reload().unwrap();
        let after = handle.server_config();
        assert!(!Arc::ptr_eq(&before, &after));

        // Corrupt cert on disk -> reload() fails cleanly AND previous valid config stays active!
        std::fs::write(dir.join("server.crt"), "BROKEN").unwrap();
        assert!(handle.reload().is_err());
        assert!(Arc::ptr_eq(&after, &handle.server_config()));

        // ReloadableTls::from_config cannot reload from disk.
        let static_handle = ReloadableTls::from_config(Arc::clone(&after));
        assert!(Arc::ptr_eq(&static_handle.server_config(), &after));
        assert!(static_handle.reload().is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
