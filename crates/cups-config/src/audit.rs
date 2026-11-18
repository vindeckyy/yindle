//! Configuration audit & migration linter (`cupsd --check-config`).
//!
//! Classifies every directive parsed from `cupsd.conf` and `cups-files.conf`
//! (supported, deprecated, moved, or unknown/ignored) and flags security
//! misconfigurations such as `FileDevice Yes`, `Satisfy Any` bypassing auth,
//! wildcard listeners, weak TLS settings, or missing admin restrictions.

use std::fmt::Write as _;
use std::io::BufRead;

use crate::acl::Severity;
use crate::config::{
    default_listeners, default_policy, read_cups_files_conf, read_cupsd_conf, CupsFilesConfig,
    CupsdConfig, Diagnostic, Diagnostics,
};
use crate::lexer::ConfLines;
use crate::types::{AuthLevel, AuthType, Encryption, ListenAddr, Sandboxing, Satisfy, TlsVersion};
use crate::{Config, Paths};

/// Classification of one directive encountered in `cupsd.conf` or `cups-files.conf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectiveStatus {
    /// Recognized and active in Presswork.
    Supported,
    /// Recognized for compatibility, but deprecated upstream.
    Deprecated,
    /// Valid `cups-files.conf` directive misplaced in `cupsd.conf`.
    Moved,
    /// Unknown or ignored directive.
    Unknown,
}

/// One audited directive line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditedDirective {
    /// Source file label.
    pub file: String,
    /// 1-based line number.
    pub line: usize,
    /// Directive name as written.
    pub name: String,
    /// Classification status.
    pub status: DirectiveStatus,
    /// Optional human-readable hint or replacement.
    pub note: Option<String>,
}

/// Severity level for a configuration security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditSeverity {
    /// Informational hardening suggestion.
    Info,
    /// Operational or security warning.
    Warning,
    /// High-risk misconfiguration that weakens authentication or isolation.
    High,
}

/// One security or operational finding emitted by [`audit_config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityFinding {
    /// Finding severity.
    pub severity: AuditSeverity,
    /// Stable machine-readable finding code (e.g. `"FILE_DEVICE_ENABLED"`).
    pub code: &'static str,
    /// Human-readable description of the risk.
    pub message: String,
    /// Suggested remediation.
    pub remediation: String,
}

/// Full report returned by [`audit_config`], [`audit_readers`], and [`audit_paths`].
#[derive(Debug, Clone)]
pub struct ConfigAuditReport {
    /// Classified directives from raw source files (empty for [`audit_config`] on a pre-parsed [`Config`]).
    pub directives: Vec<AuditedDirective>,
    /// Security and hardening findings detected in the effective configuration.
    pub findings: Vec<SecurityFinding>,
    /// Parser diagnostics emitted while loading configuration files.
    pub diagnostics: Vec<Diagnostic>,
    /// `true` if configuration parsed without fatal errors.
    pub ok: bool,
}

impl ConfigAuditReport {
    /// True if any parser error occurred or `ok` is `false`.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        !self.ok
            || self
                .diagnostics
                .iter()
                .any(|d| d.severity == Severity::Error)
    }

    /// True if any finding of severity `Warning` or higher, or any parser warning, exists.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity >= AuditSeverity::Warning)
            || self
                .diagnostics
                .iter()
                .any(|d| d.severity == Severity::Warn)
    }

    /// True if any `High`-severity security finding was reported.
    #[must_use]
    pub fn has_high_findings(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == AuditSeverity::High)
    }

    /// Number of directives classified with `status`.
    #[must_use]
    pub fn directive_count(&self, status: DirectiveStatus) -> usize {
        self.directives
            .iter()
            .filter(|d| d.status == status)
            .count()
    }

    /// Render a concise, human-readable audit report suitable for `cupsd --check-config`.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "Config check: {} (directives: {} supported, {} deprecated, {} moved, {} unknown; findings: {}, diagnostics: {})",
            if self.has_errors() { "FAILED" } else { "OK" },
            self.directive_count(DirectiveStatus::Supported),
            self.directive_count(DirectiveStatus::Deprecated),
            self.directive_count(DirectiveStatus::Moved),
            self.directive_count(DirectiveStatus::Unknown),
            self.findings.len(),
            self.diagnostics.len(),
        );
        for d in &self.directives {
            if d.status != DirectiveStatus::Supported {
                let _ = writeln!(
                    out,
                    "  [{:?}] {}:{} {} {}",
                    d.status,
                    d.file,
                    d.line,
                    d.name,
                    d.note.as_deref().unwrap_or("")
                );
            }
        }
        for f in &self.findings {
            let _ = writeln!(
                out,
                "  [{:?}] {}: {} (remediation: {})",
                f.severity, f.code, f.message, f.remediation
            );
        }
        for diag in &self.diagnostics {
            let _ = writeln!(
                out,
                "  [{:?}] {}:{} {}",
                diag.severity, diag.file, diag.line, diag.message
            );
        }
        out
    }
}

/// Known `cupsd.conf` top-level and block directives.
const CUPSD_SUPPORTED: &[&str] = &[
    "<Location",
    "</Location>",
    "<Limit",
    "</Limit>",
    "<LimitExcept",
    "</LimitExcept>",
    "<Policy",
    "</Policy>",
    "AccessLogLevel",
    "Allow",
    "AuthType",
    "AutoPurgeJobs",
    "BrowseDNSSDSubTypes",
    "BrowseIPPSOnly",
    "BrowseLocalProtocols",
    "BrowseWebIF",
    "Browsing",
    "Classification",
    "ClassifyOverride",
    "DefaultAuthType",
    "DefaultEncryption",
    "DefaultLanguage",
    "DefaultLeaseDuration",
    "DefaultPaperSize",
    "DefaultPolicy",
    "DefaultShared",
    "Deny",
    "DirtyCleanInterval",
    "DNSSDComputerName",
    "DNSSDHostName",
    "Encryption",
    "ErrorPolicy",
    "FilterLimit",
    "FilterNice",
    "GSSServiceName",
    "HostNameLookups",
    "IdleExitTimeout",
    "JobKillDelay",
    "JobPrivateAccess",
    "JobPrivateValues",
    "JobRetryInterval",
    "JobRetryLimit",
    "KeepAlive",
    "LimitRequestBody",
    "Listen",
    "LogDebugHistory",
    "LogLevel",
    "LogTimeFormat",
    "MaxActiveJobs",
    "MaxClients",
    "MaxClientsPerHost",
    "MaxCopies",
    "MaxEvents",
    "MaxHoldTime",
    "MaxJobs",
    "MaxJobsPerPrinter",
    "MaxJobsPerUser",
    "MaxJobTime",
    "MaxLeaseDuration",
    "MaxLogSize",
    "MaxRequestSize",
    "MaxSubscriptions",
    "MaxSubscriptionsPerJob",
    "MaxSubscriptionsPerPrinter",
    "MaxSubscriptionsPerUser",
    "MultipleOperationTimeout",
    "Order",
    "PageLogFormat",
    "Port",
    "PreserveJobFiles",
    "PreserveJobHistory",
    "ReadyPaperSizes",
    "ReloadTimeout",
    "Require",
    "RootCertDuration",
    "SSLListen",
    "SSLOptions",
    "SSLPort",
    "Satisfy",
    "ServerAdmin",
    "ServerAlias",
    "ServerName",
    "ServerTokens",
    "StrictConformance",
    "SubscriptionPrivateAccess",
    "SubscriptionPrivateValues",
    "Timeout",
    "WebInterface",
];

/// Deprecated `cupsd.conf` directives (parsed with a warning).
const CUPSD_DEPRECATED: &[(&str, &str)] = &[
    (
        "AuthClass",
        "Use `Require valid-user` or `Require user @SYSTEM`.",
    ),
    ("AuthGroupName", "Use `Require user @<group>`."),
    ("BrowseProtocols", "Use `BrowseLocalProtocols`."),
    ("FaxRetryInterval", "Use `JobRetryInterval`."),
    ("FaxRetryLimit", "Use `JobRetryLimit`."),
    ("LaunchdTimeout", "Use `IdleExitTimeout`."),
];

/// Directives that moved from `cupsd.conf` to `cups-files.conf`.
const CUPSD_MOVED: &[&str] = &[
    "AccessLog",
    "CacheDir",
    "ConfigFilePerm",
    "DataDir",
    "DocumentRoot",
    "ErrorLog",
    "FatalErrors",
    "FileDevice",
    "Group",
    "LogFilePerm",
    "PageLog",
    "PassEnv",
    "Printcap",
    "PrintcapFormat",
    "RemoteRoot",
    "RequestRoot",
    "ServerBin",
    "ServerCertificate",
    "ServerKey",
    "ServerKeychain",
    "ServerRoot",
    "SetEnv",
    "StateDir",
    "SystemGroup",
    "SystemGroupAuthKey",
    "TempDir",
    "User",
];

/// Known `cups-files.conf` directives.
const CUPSFILES_SUPPORTED: &[&str] = &[
    "AccessLog",
    "CacheDir",
    "ConfigFilePerm",
    "CreateSelfSignedCerts",
    "DataDir",
    "DocumentRoot",
    "ErrorLog",
    "FatalErrors",
    "FileDevice",
    "Group",
    "LogFileGroup",
    "LogFilePerm",
    "OAuthGroup",
    "OAuthScopes",
    "OAuthServer",
    "PageLog",
    "PassEnv",
    "PeerCred",
    "Printcap",
    "PrintcapFormat",
    "RemoteRoot",
    "RequestRoot",
    "Sandboxing",
    "ServerBin",
    "ServerKeychain",
    "ServerRoot",
    "SetEnv",
    "StateDir",
    "StripUserDomain",
    "SyncOnClose",
    "SystemGroup",
    "SystemGroupAuthKey",
    "TempDir",
    "User",
];

const CUPSFILES_DEPRECATED: &[(&str, &str)] = &[
    ("ServerCertificate", "Use `ServerKeychain` instead."),
    ("ServerKey", "Use `ServerKeychain` instead."),
];

/// Classify all directives in a `cupsd.conf` byte slice.
fn classify_cupsd_directives(bytes: &[u8], filename: &str) -> Vec<AuditedDirective> {
    let mut out = Vec::new();
    for line in ConfLines::new(bytes).flatten() {
        let name = line.name;
        let (status, note) = if let Some((_, hint)) = CUPSD_DEPRECATED
            .iter()
            .find(|(d, _)| d.eq_ignore_ascii_case(&name))
        {
            (DirectiveStatus::Deprecated, Some((*hint).to_string()))
        } else if CUPSD_MOVED.iter().any(|d| d.eq_ignore_ascii_case(&name)) {
            (
                DirectiveStatus::Moved,
                Some("Move this directive to cups-files.conf.".to_string()),
            )
        } else if CUPSD_SUPPORTED
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&name))
        {
            (DirectiveStatus::Supported, None)
        } else {
            (
                DirectiveStatus::Unknown,
                Some("Directive is unknown and ignored.".to_string()),
            )
        };
        out.push(AuditedDirective {
            file: filename.to_string(),
            line: line.linenum,
            name,
            status,
            note,
        });
    }
    out
}

/// Classify all directives in a `cups-files.conf` byte slice.
fn classify_files_directives(bytes: &[u8], filename: &str) -> Vec<AuditedDirective> {
    let mut out = Vec::new();
    for line in ConfLines::new(bytes).flatten() {
        let name = line.name;
        let (status, note) = if let Some((_, hint)) = CUPSFILES_DEPRECATED
            .iter()
            .find(|(d, _)| d.eq_ignore_ascii_case(&name))
        {
            (DirectiveStatus::Deprecated, Some((*hint).to_string()))
        } else if CUPSFILES_SUPPORTED
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&name))
        {
            (DirectiveStatus::Supported, None)
        } else {
            (
                DirectiveStatus::Unknown,
                Some("Directive is unknown and ignored.".to_string()),
            )
        };
        out.push(AuditedDirective {
            file: filename.to_string(),
            line: line.linenum,
            name,
            status,
            note,
        });
    }
    out
}

/// Audit a parsed [`Config`] for security misconfigurations and operational risks.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn audit_config(cfg: &Config) -> ConfigAuditReport {
    let mut findings = Vec::new();

    // 1. FileDevice enabled
    if let Some(pat) = &cfg.files.file_device {
        findings.push(SecurityFinding {
            severity: AuditSeverity::High,
            code: "FILE_DEVICE_ENABLED",
            message: format!(
                "FileDevice is enabled (pattern \"{pat}\"), allowing file:// device writes."
            ),
            remediation: "Set `FileDevice No` in cups-files.conf unless strictly required.".into(),
        });
    }

    // 2. Empty SystemGroup
    if cfg.files.system_group_names.is_empty() {
        findings.push(SecurityFinding {
            severity: AuditSeverity::High,
            code: "EMPTY_SYSTEM_GROUP",
            message: "No SystemGroup names are configured; @SYSTEM authorization checks cannot match any admin group.".into(),
            remediation: "Set `SystemGroup lpadmin` (or `sys root wheel`) in cups-files.conf.".into(),
        });
    }

    // 3. Running as root UID
    if cfg.files.user == 0 {
        findings.push(SecurityFinding {
            severity: AuditSeverity::High,
            code: "ROOT_WORKER_USER",
            message: "Configured worker `User` resolves to UID 0 (root).".into(),
            remediation: "Set `User lp` (non-privileged account) in cups-files.conf.".into(),
        });
    }

    // 4. Sandboxing disabled
    if cfg.files.sandboxing == Sandboxing::Off {
        findings.push(SecurityFinding {
            severity: AuditSeverity::Warning,
            code: "SANDBOXING_OFF",
            message: "Filter/backend sandboxing is disabled (`Sandboxing Off`).".into(),
            remediation: "Set `Sandboxing Strict` or `Sandboxing Relaxed` in cups-files.conf."
                .into(),
        });
    }

    // 5. Wildcard / non-loopback listeners
    let mut has_non_loopback = false;
    for l in &cfg.cupsd.listeners {
        if let ListenAddr::Tcp(sa) = l.addr {
            if sa.ip().is_unspecified() {
                has_non_loopback = true;
                findings.push(SecurityFinding {
                    severity: if l.ssl {
                        AuditSeverity::Warning
                    } else {
                        AuditSeverity::High
                    },
                    code: "WILDCARD_LISTEN",
                    message: format!(
                        "Listener binds unspecified wildcard address {sa} (ssl={}).",
                        l.ssl
                    ),
                    remediation: "Bind `Listen localhost:631` or an explicit interface IP, and use TLS (`SSLListen` / `Encryption Required`).".into(),
                });
            } else if !sa.ip().is_loopback() {
                has_non_loopback = true;
            }
        }
    }

    // 6. WebInterface exposed remotely
    if cfg.cupsd.web_interface && has_non_loopback {
        findings.push(SecurityFinding {
            severity: AuditSeverity::Warning,
            code: "REMOTE_WEB_INTERFACE",
            message: "WebInterface is enabled while listening on a non-loopback TCP address.".into(),
            remediation: "Restrict `/admin` with `Encryption Required` and explicit `Allow` rules, or set `WebInterface No`.".into(),
        });
    }

    // 7. `Satisfy Any` on Locations or Policy Limits that also require auth
    for loc in &cfg.cupsd.locations {
        if loc.satisfy == Satisfy::Any && loc.auth_level != AuthLevel::Anon {
            findings.push(SecurityFinding {
                severity: AuditSeverity::High,
                code: "LOCATION_SATISFY_ANY",
                message: format!(
                    "<Location {}> uses `Satisfy Any` with authentication required, allowing host ACL matches to bypass auth.",
                    loc.path
                ),
                remediation: "Use `Satisfy All` (the secure default) on authenticated locations.".into(),
            });
        }
    }
    for pol in &cfg.cupsd.policies {
        for op in &pol.ops {
            if op.loc.satisfy == Satisfy::Any && op.loc.auth_level != AuthLevel::Anon {
                findings.push(SecurityFinding {
                    severity: AuditSeverity::High,
                    code: "POLICY_SATISFY_ANY",
                    message: format!(
                        "<Policy {}> op 0x{:04x} uses `Satisfy Any` with authentication required, allowing host ACL matches to bypass auth.",
                        pol.name, op.op
                    ),
                    remediation: "Use `Satisfy All` inside `<Policy>` `<Limit>` blocks.".into(),
                });
                break; // report once per policy
            }
        }
    }

    // 8. Missing `/admin` restriction
    let has_admin_loc = cfg
        .cupsd
        .locations
        .iter()
        .any(|l| l.path == "/admin" && l.auth_level != AuthLevel::Anon);
    if !has_admin_loc {
        findings.push(SecurityFinding {
            severity: AuditSeverity::Warning,
            code: "MISSING_ADMIN_LOCATION_AUTH",
            message: "No authenticated `<Location /admin>` block is configured.".into(),
            remediation: "Add `<Location /admin>` with `AuthType Default` and `Require user @SYSTEM`.".into(),
        });
    }

    // 9. Remote listener without TLS on /admin
    if has_non_loopback {
        if let Some(admin) = cfg.cupsd.locations.iter().find(|l| l.path == "/admin") {
            if !matches!(admin.encryption, Encryption::Required | Encryption::Always) {
                findings.push(SecurityFinding {
                    severity: AuditSeverity::Warning,
                    code: "ADMIN_PLAINTEXT_REMOTE",
                    message: "`<Location /admin>` does not require TLS while listening on a non-loopback address.".into(),
                    remediation: "Add `Encryption Required` inside `<Location /admin>`.".into(),
                });
            }
        }
    }

    // 10. DefaultAuthType None
    if cfg.cupsd.default_auth_type == AuthType::None {
        findings.push(SecurityFinding {
            severity: AuditSeverity::High,
            code: "DEFAULT_AUTH_NONE",
            message: "`DefaultAuthType None` disables authentication for all `AuthType Default` locations.".into(),
            remediation: "Set `DefaultAuthType Basic` (or `Auto`).".into(),
        });
    }

    // 11. ServerAlias * (DNS rebinding)
    if cfg.cupsd.server_aliases.iter().any(|a| a == "*") {
        findings.push(SecurityFinding {
            severity: AuditSeverity::High,
            code: "WILDCARD_SERVER_ALIAS",
            message:
                "`ServerAlias *` disables Host header validation and permits DNS rebinding attacks."
                    .into(),
            remediation: "List explicit hostnames in `ServerAlias` instead of `*`.".into(),
        });
    }

    // 12. Weak TLS options
    if cfg.cupsd.tls_options.allow_rc4
        || cfg.cupsd.tls_options.allow_dh
        || cfg.cupsd.tls_options.min_version < TlsVersion::V1_2
    {
        findings.push(SecurityFinding {
            severity: AuditSeverity::Warning,
            code: "WEAK_TLS_OPTIONS",
            message: format!(
                "TLS options permit legacy protocol/ciphers (min_version={:?}, allow_rc4={}, allow_dh={}).",
                cfg.cupsd.tls_options.min_version,
                cfg.cupsd.tls_options.allow_rc4,
                cfg.cupsd.tls_options.allow_dh
            ),
            remediation: "Set `SSLOptions MinTLS1.2 DenyCBC` in cupsd.conf.".into(),
        });
    }

    // 13. Unlimited request size / MaxClients
    if cfg.cupsd.max_request_size == 0 {
        findings.push(SecurityFinding {
            severity: AuditSeverity::Info,
            code: "UNLIMITED_REQUEST_SIZE",
            message: "`MaxRequestSize 0` imposes no explicit configuration cap on request bodies.".into(),
            remediation: "Consider setting an explicit `MaxRequestSize` (e.g. `100m`) for multi-tenant deployments.".into(),
        });
    }
    if cfg.cupsd.max_clients == 0 {
        findings.push(SecurityFinding {
            severity: AuditSeverity::Warning,
            code: "UNLIMITED_CLIENTS",
            message: "`MaxClients 0` allows unbounded concurrent connections.".into(),
            remediation: "Set a bounded `MaxClients` (e.g. `100`) in cupsd.conf.".into(),
        });
    }

    ConfigAuditReport {
        directives: Vec::new(),
        findings,
        diagnostics: Vec::new(),
        ok: true,
    }
}

/// Parse and audit `cupsd.conf` (and optional `cups-files.conf`) from readers,
/// classifying every directive and collecting all diagnostics and security findings.
#[must_use]
pub fn audit_readers<R1: BufRead, R2: BufRead>(
    mut cupsd_reader: R1,
    cupsd_name: &str,
    files_reader: Option<(R2, &str)>,
    server_root: &str,
) -> (Config, ConfigAuditReport) {
    let mut files_cfg = CupsFilesConfig::defaults();
    let mut cupsd_cfg = CupsdConfig::defaults();
    let mut diags = Diagnostics::default();
    let mut directives = Vec::new();
    let mut ok = true;

    if let Some((mut fr, fname)) = files_reader {
        let mut raw_files = Vec::new();
        if fr.read_to_end(&mut raw_files).is_ok() {
            directives.extend(classify_files_directives(&raw_files, fname));
            let mut fatal = cupsd_cfg.fatal_errors;
            if !read_cups_files_conf(
                &raw_files[..],
                fname,
                &mut files_cfg,
                server_root,
                &mut fatal,
                &mut diags,
                &|name| {
                    #[cfg(unix)]
                    {
                        sys::gid_of(name)
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = name;
                        None
                    }
                },
                &|name| {
                    #[cfg(unix)]
                    {
                        sys::uid_of(name)
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = name;
                        None
                    }
                },
            ) {
                ok = false;
            }
            cupsd_cfg.fatal_errors = fatal;
            diags.fatal = fatal;
        } else {
            ok = false;
        }
    }

    let mut raw_cupsd = Vec::new();
    if cupsd_reader.read_to_end(&mut raw_cupsd).is_ok() {
        directives.extend(classify_cupsd_directives(&raw_cupsd, cupsd_name));
        if !read_cupsd_conf(&raw_cupsd[..], cupsd_name, &mut cupsd_cfg, &mut diags) {
            ok = false;
        }
    } else {
        ok = false;
    }

    if !cupsd_cfg.policies.iter().any(|p| p.name == "default") {
        cupsd_cfg.policies.push(default_policy());
    }
    if cupsd_cfg.default_policy.is_none() {
        cupsd_cfg.default_policy = Some("default".to_string());
    }
    default_listeners(&mut cupsd_cfg);

    let cfg = Config {
        cupsd: cupsd_cfg,
        files: files_cfg,
    };
    let mut report = audit_config(&cfg);
    report.directives = directives;
    report.diagnostics = diags.entries;
    report.ok = ok
        && !report
            .diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error);
    (cfg, report)
}

/// Load and audit `cups-files.conf` + `cupsd.conf` from filesystem `paths`
/// (intended directly for `cupsd --check-config`).
#[must_use]
pub fn audit_paths(paths: &Paths) -> (Config, ConfigAuditReport) {
    let server_root = paths.server_root.to_string_lossy().to_string();
    let files_name = paths.cups_files_conf.to_string_lossy().to_string();
    let cupsd_name = paths.cupsd_conf.to_string_lossy().to_string();

    let files_bytes = std::fs::read(&paths.cups_files_conf).ok();
    let Ok(cupsd_bytes) = std::fs::read(&paths.cupsd_conf) else {
        let cfg = Config {
            cupsd: CupsdConfig::defaults(),
            files: CupsFilesConfig::defaults(),
        };
        let mut report = audit_config(&cfg);
        report.ok = false;
        report.diagnostics.push(Diagnostic {
            severity: Severity::Error,
            file: cupsd_name,
            line: 0,
            message: format!("Unable to open \"{}\".", paths.cupsd_conf.display()),
        });
        return (cfg, report);
    };

    let files_arg = files_bytes
        .as_deref()
        .map(|b| (std::io::Cursor::new(b), files_name.as_str()));
    audit_readers(
        std::io::Cursor::new(cupsd_bytes.as_slice()),
        &cupsd_name,
        files_arg,
        &server_root,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_clean_hardened_config_has_no_high_findings() {
        let cupsd = br"
LogLevel warn
Listen localhost:631
DefaultAuthType Basic
SSLOptions MinTLS1.2 DenyCBC
MaxRequestSize 64m
MaxClients 100
WebInterface Yes
<Location />
  Order allow,deny
</Location>
<Location /admin>
  AuthType Default
  Require user @SYSTEM
  Encryption Required
  Order allow,deny
</Location>
";
        let files = br"
SystemGroup root
FileDevice No
Sandboxing Strict
";
        let (_cfg, report) = audit_readers(
            &cupsd[..],
            "cupsd.conf",
            Some((&files[..], "cups-files.conf")),
            "/etc/cups",
        );
        assert!(report.ok);
        assert!(!report.has_errors());
        assert!(!report.has_high_findings());
        assert!(!report.has_warnings());
        assert_eq!(report.directive_count(DirectiveStatus::Unknown), 0);
        assert_eq!(report.directive_count(DirectiveStatus::Deprecated), 0);
        assert_eq!(report.directive_count(DirectiveStatus::Moved), 0);
        assert!(report.directive_count(DirectiveStatus::Supported) > 10);
        let text = report.summary();
        assert!(text.contains("Config check: OK"));
    }

    #[test]
    fn audit_detects_all_security_findings_and_directive_classifications() {
        let cupsd = br"
Port 631
SSLListen *:8631
DefaultAuthType None
ServerAlias *
MaxClients 0
MaxRequestSize 0
WebInterface Yes
SSLOptions AllowRC4 AllowDH
FaxRetryInterval 60
FileDevice No
UnknownFancyDirective yes
<Location /admin>
  AuthType Default
  Require user @SYSTEM
  Satisfy Any
  Order allow,deny
</Location>
<Policy default>
  <Limit CUPS-Add-Modify-Printer>
    AuthType Default
    Require user @SYSTEM
    Satisfy Any
    Order deny,allow
  </Limit>
</Policy>
";
        let files = br"
FileDevice Yes
Sandboxing Off
ServerCertificate /etc/cups/ssl/server.crt
BogusFilesDirective 1
";
        let (mut cfg, mut report) = audit_readers(
            &cupsd[..],
            "cupsd.conf",
            Some((&files[..], "cups-files.conf")),
            "/etc/cups",
        );
        assert!(report.has_errors());
        assert!(report.has_warnings());
        assert!(report.has_high_findings());
        assert!(report.directive_count(DirectiveStatus::Deprecated) >= 2);
        assert!(report.directive_count(DirectiveStatus::Moved) >= 1);
        assert!(report.directive_count(DirectiveStatus::Unknown) >= 2);

        let codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
        for expected in [
            "FILE_DEVICE_ENABLED",
            "SANDBOXING_OFF",
            "WILDCARD_LISTEN",
            "REMOTE_WEB_INTERFACE",
            "LOCATION_SATISFY_ANY",
            "POLICY_SATISFY_ANY",
            "ADMIN_PLAINTEXT_REMOTE",
            "DEFAULT_AUTH_NONE",
            "WILDCARD_SERVER_ALIAS",
            "WEAK_TLS_OPTIONS",
            "UNLIMITED_REQUEST_SIZE",
            "UNLIMITED_CLIENTS",
        ] {
            assert!(
                codes.contains(&expected),
                "expected finding {expected}, got {codes:?}"
            );
        }

        let summary = report.summary();
        assert!(summary.contains("Config check: FAILED"));
        assert!(summary.contains("FILE_DEVICE_ENABLED"));
        assert!(summary.contains("[Deprecated]"));
        assert!(summary.contains("[Moved]"));
        assert!(summary.contains("[Unknown]"));

        // Also trigger EMPTY_SYSTEM_GROUP, ROOT_WORKER_USER, MISSING_ADMIN_LOCATION_AUTH, non-loopback non-wildcard IP.
        cfg.files.system_group_names.clear();
        cfg.files.user = 0;
        cfg.cupsd.locations.clear();
        cfg.cupsd.listeners = vec![crate::types::Listener {
            addr: ListenAddr::Tcp("192.0.2.5:631".parse().unwrap()),
            ssl: false,
        }];
        report = audit_config(&cfg);
        let codes2: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
        assert!(codes2.contains(&"EMPTY_SYSTEM_GROUP"));
        assert!(codes2.contains(&"ROOT_WORKER_USER"));
        assert!(codes2.contains(&"MISSING_ADMIN_LOCATION_AUTH"));
        assert!(codes2.contains(&"REMOTE_WEB_INTERFACE"));
    }

    #[test]
    fn audit_paths_existing_and_missing() {
        let dir = std::env::temp_dir().join(format!("pw-cfg-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let paths = Paths::resolve(Some(&dir));
        let (_cfg, missing) = audit_paths(&paths);
        assert!(!missing.ok);
        assert!(missing.has_errors());

        std::fs::write(
            &paths.cupsd_conf,
            b"LogLevel info\nListen localhost:631\n<Location /admin>\nAuthType Default\nRequire user @SYSTEM\n</Location>\n",
        )
        .unwrap();
        std::fs::write(&paths.cups_files_conf, b"FileDevice No\n").unwrap();

        let (_cfg, ok_rep) = audit_paths(&paths);
        assert!(ok_rep.ok);
        assert!(!ok_rep.has_errors());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
