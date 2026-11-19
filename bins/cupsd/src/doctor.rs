//! Enterprise `cupsd doctor` diagnostics subcommand.
//!
//! Validates configuration syntax & security posture, runtime directories and
//! permissions, MIME database loading, helper/backend/filter/`cups-exec` binary
//! presence & permissions, TLS certificate/key health, PAM/NSS availability,
//! and host conflicts (such as stock CUPS `AppArmor` profiles).

use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use cups_config::{Config, ListenAddr, Paths};

use crate::cli::{effective_server_root, push_json_str, resolve_paths, CliArgs};

/// Diagnostic status for a single doctor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// Check passed cleanly.
    Pass,
    /// Non-fatal operational or security warning.
    Warn,
    /// Blocking error that prevents safe production startup.
    Fail,
}

impl CheckStatus {
    /// Short fixed-width badge for table output.
    #[must_use]
    pub const fn badge(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }

    /// Lowercase string for JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// One diagnostic check row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    /// Check category / name.
    pub name: String,
    /// Pass / Warn / Fail verdict.
    pub status: CheckStatus,
    /// Summary of what was observed.
    pub message: String,
    /// Optional actionable remediation hint.
    pub hint: Option<String>,
}

/// Complete result of running `cupsd doctor`.
#[derive(Debug, Clone)]
pub struct DoctorReport {
    /// Ordered list of diagnostic checks.
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    /// Count checks matching `status`.
    #[must_use]
    pub fn count(&self, status: CheckStatus) -> usize {
        self.checks.iter().filter(|c| c.status == status).count()
    }

    /// `true` iff zero checks ended with [`CheckStatus::Fail`].
    #[must_use]
    pub fn ok(&self) -> bool {
        self.count(CheckStatus::Fail) == 0
    }

    /// Render a crisp human-readable pass/warn/fail diagnostic table.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::from("Yindle cupsd doctor\n");
        out.push_str("------------------------------------------------------------------------\n");
        for c in &self.checks {
            let _ = writeln!(out, "[{:4}] {:<24} {}", c.status.badge(), c.name, c.message);
            if let Some(ref hint) = c.hint {
                let _ = writeln!(out, "       hint: {hint}");
            }
        }
        out.push_str("------------------------------------------------------------------------\n");
        let _ = writeln!(
            out,
            "Summary: {} passed, {} warnings, {} failed",
            self.count(CheckStatus::Pass),
            self.count(CheckStatus::Warn),
            self.count(CheckStatus::Fail)
        );
        out
    }

    /// Render the report as structured JSON (`cupsd doctor --json`).
    #[must_use]
    pub fn render_json(&self) -> String {
        let mut out = String::with_capacity(512);
        let _ = write!(
            out,
            "{{\"ok\":{},\"summary\":{{\"pass\":{},\"warn\":{},\"fail\":{}}},\"checks\":[",
            self.ok(),
            self.count(CheckStatus::Pass),
            self.count(CheckStatus::Warn),
            self.count(CheckStatus::Fail),
        );
        for (i, c) in self.checks.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"name\":");
            push_json_str(&mut out, &c.name);
            out.push_str(",\"status\":");
            push_json_str(&mut out, c.status.as_str());
            out.push_str(",\"message\":");
            push_json_str(&mut out, &c.message);
            out.push_str(",\"hint\":");
            match &c.hint {
                Some(h) => push_json_str(&mut out, h),
                None => out.push_str("null"),
            }
            out.push('}');
        }
        out.push_str("]}\n");
        out
    }
}

/// Injectable host environment paths so unit tests can exercise host conflict
/// checks without reading system `/etc` files.
#[derive(Debug, Clone)]
pub struct DoctorEnv {
    /// Path to stock CUPS `AppArmor` profile (default `/etc/apparmor.d/usr.sbin.cupsd`).
    pub apparmor_profile: PathBuf,
    /// Path to PAM service config (default `/etc/pam.d/cups`).
    pub pam_service_file: PathBuf,
}

impl Default for DoctorEnv {
    fn default() -> Self {
        Self {
            apparmor_profile: PathBuf::from("/etc/apparmor.d/usr.sbin.cupsd"),
            pam_service_file: PathBuf::from("/etc/pam.d/cups"),
        }
    }
}

/// Run `cupsd doctor` for the CLI arguments and return `(ok, rendered_output)`.
#[must_use]
pub fn run_doctor_cli(args: &CliArgs) -> (bool, String) {
    let paths = resolve_paths(args);
    let report = run_doctor(&paths, &DoctorEnv::default());
    let out = if args.json {
        report.render_json()
    } else {
        report.render_text()
    };
    (report.ok(), out)
}

/// Run all diagnostic checks for `paths` and `env`.
#[must_use]
pub fn run_doctor(paths: &Paths, env: &DoctorEnv) -> DoctorReport {
    let mut checks = Vec::new();
    let (cfg, audit) = cups_config::audit_paths(paths);

    // 1. Config syntax & security audit.
    if audit.has_errors() {
        checks.push(DoctorCheck {
            name: "config.syntax".into(),
            status: CheckStatus::Fail,
            message: format!(
                "Configuration errors detected in {}",
                paths.cupsd_conf.display()
            ),
            hint: Some("Run `cupsd --check-config` for line-by-line diagnostics.".into()),
        });
    } else if audit.has_high_findings() || audit.has_warnings() {
        checks.push(DoctorCheck {
            name: "config.audit".into(),
            status: CheckStatus::Warn,
            message: format!(
                "Configuration valid with {} security/migration finding(s)",
                audit.findings.len()
            ),
            hint: Some("Run `cupsd --check-config` to review and remediate warnings.".into()),
        });
    } else {
        checks.push(DoctorCheck {
            name: "config.audit".into(),
            status: CheckStatus::Pass,
            message: format!(
                "Configuration syntax and security audit clean ({})",
                paths.cupsd_conf.display()
            ),
            hint: None,
        });
    }

    let server_root = effective_server_root(&cfg, paths);
    let request_root = PathBuf::from(
        cfg.files
            .request_root
            .as_deref()
            .unwrap_or("/var/spool/cups"),
    );
    let cache_dir = PathBuf::from(cfg.files.cache_dir.as_deref().unwrap_or("/var/cache/cups"));
    let temp_dir = cfg
        .files
        .temp_dir
        .as_deref()
        .map_or_else(|| request_root.join("tmp"), PathBuf::from);
    let state_dir = PathBuf::from(cfg.files.state_dir.as_deref().unwrap_or("/run/cups"));
    let log_dir = cfg
        .files
        .error_log
        .as_deref()
        .and_then(|p| Path::new(p).parent().map(Path::to_path_buf))
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("/var/log/cups"));
    let data_dir = PathBuf::from(cfg.files.data_dir.as_deref().unwrap_or("/usr/share/cups"));
    let server_bin = PathBuf::from(cfg.files.server_bin.as_deref().unwrap_or("/usr/lib/cups"));

    // 2. Runtime directories & permissions.
    checks.push(check_directory(
        "dir.server_root",
        &server_root,
        true,
        false,
    ));
    checks.push(check_directory(
        "dir.request_root",
        &request_root,
        true,
        true,
    ));
    checks.push(check_directory("dir.cache_dir", &cache_dir, false, false));
    checks.push(check_directory("dir.temp_dir", &temp_dir, false, false));
    checks.push(check_directory("dir.log_dir", &log_dir, false, false));
    checks.push(check_directory("dir.run_dir", &state_dir, false, false));

    // 3. MIME database.
    checks.push(check_mime_db(&data_dir, &server_root));

    // 4. Backends, filters, and cups-exec binaries.
    checks.push(check_binaries(&server_bin));

    // 5. TLS certificate / private key health.
    checks.push(check_tls(&cfg, &server_root));

    // 6. PAM / NSS availability.
    checks.push(check_pam_nss(&cfg, env));

    // 7. Host conflicts (AppArmor / listener sockets).
    checks.push(check_host_conflicts(&cfg, env));

    DoctorReport { checks }
}

fn check_directory(name: &str, path: &Path, required: bool, check_private: bool) -> DoctorCheck {
    let Ok(meta) = std::fs::metadata(path) else {
        return DoctorCheck {
            name: name.into(),
            status: if required {
                CheckStatus::Fail
            } else {
                CheckStatus::Warn
            },
            message: format!("{} does not exist", path.display()),
            hint: Some(format!("Create directory: mkdir -p {}", path.display())),
        };
    };
    if !meta.is_dir() {
        return DoctorCheck {
            name: name.into(),
            status: CheckStatus::Fail,
            message: format!("{} is not a directory", path.display()),
            hint: Some(format!("Replace {} with a directory.", path.display())),
        };
    }
    let mode = meta.permissions().mode() & 0o777;
    if (mode & 0o002) != 0 && (meta.permissions().mode() & 0o1000) == 0 {
        return DoctorCheck {
            name: name.into(),
            status: CheckStatus::Warn,
            message: format!("{} is world-writable (mode {:04o})", path.display(), mode),
            hint: Some(format!(
                "Tighten permissions: chmod 0750 {}",
                path.display()
            )),
        };
    }
    if check_private && (mode & 0o007) != 0 {
        return DoctorCheck {
            name: name.into(),
            status: CheckStatus::Warn,
            message: format!(
                "{} is world-accessible (mode {:04o}); spool files should be private",
                path.display(),
                mode
            ),
            hint: Some(format!(
                "Tighten permissions: chmod 0710 {}",
                path.display()
            )),
        };
    }
    DoctorCheck {
        name: name.into(),
        status: CheckStatus::Pass,
        message: format!("{} (mode {:04o})", path.display(), mode),
        hint: None,
    }
}

fn check_mime_db(data_dir: &Path, server_root: &Path) -> DoctorCheck {
    match mime_db::MimeDb::load_standard(data_dir, server_root) {
        Ok(db) if !db.types.is_empty() && !db.convs.is_empty() => DoctorCheck {
            name: "mime.database".into(),
            status: CheckStatus::Pass,
            message: format!(
                "Loaded {} MIME type(s) and {} conversion rule(s)",
                db.types.len(),
                db.convs.len()
            ),
            hint: None,
        },
        Ok(db) => DoctorCheck {
            name: "mime.database".into(),
            status: CheckStatus::Warn,
            message: format!(
                "MIME DB incomplete ({} types, {} convs) under {} / {}",
                db.types.len(),
                db.convs.len(),
                data_dir.display(),
                server_root.display()
            ),
            hint: Some(format!(
                "Install mime.types and mime.convs in {}/mime.",
                data_dir.display()
            )),
        },
        Err(e) => DoctorCheck {
            name: "mime.database".into(),
            status: CheckStatus::Fail,
            message: format!("Failed to load MIME DB: {e}"),
            hint: Some("Check permissions on DataDir/mime and ServerRoot.".into()),
        },
    }
}

fn check_binaries(server_bin: &Path) -> DoctorCheck {
    let backend_dir = server_bin.join("backend");
    let filter_dir = server_bin.join("filter");
    let cups_exec = server_bin.join("daemon").join("cups-exec");

    let mut backends = 0usize;
    let mut insecure = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&backend_dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if let Ok(m) = std::fs::metadata(&p) {
                let mode = m.permissions().mode();
                if m.is_file() && (mode & 0o111) != 0 {
                    backends += 1;
                    if (mode & 0o002) != 0 {
                        insecure.push(p.display().to_string());
                    }
                }
            }
        }
    }

    let filters = std::fs::read_dir(&filter_dir).ok().map_or(0, |rd| {
        rd.flatten()
            .filter(|e| {
                std::fs::metadata(e.path())
                    .is_ok_and(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
            })
            .count()
    });

    let has_cups_exec = std::fs::metadata(&cups_exec)
        .is_ok_and(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0);

    if !insecure.is_empty() {
        return DoctorCheck {
            name: "bin.executables".into(),
            status: CheckStatus::Fail,
            message: format!("World-writable backend binary: {}", insecure.join(", ")),
            hint: Some("Remove world-write permission (`chmod o-w`).".into()),
        };
    }

    if backends == 0 || !has_cups_exec {
        return DoctorCheck {
            name: "bin.executables".into(),
            status: CheckStatus::Warn,
            message: format!(
                "{backends} backend(s), {filters} filter(s), cups-exec={}",
                if has_cups_exec { "present" } else { "missing" }
            ),
            hint: Some(format!(
                "Ensure backends and daemon/cups-exec are installed under {}.",
                server_bin.display()
            )),
        };
    }

    DoctorCheck {
        name: "bin.executables".into(),
        status: CheckStatus::Pass,
        message: format!("{backends} backend(s), {filters} filter(s), cups-exec present"),
        hint: None,
    }
}

fn check_tls(cfg: &Config, server_root: &Path) -> DoctorCheck {
    let ssl_dir = crate::server::effective_ssl_dir(cfg, server_root);
    let crt = ssl_dir.join("server.crt");
    let key = ssl_dir.join("server.key");
    let has_ssl_listener = cfg.cupsd.listeners.iter().any(|l| l.ssl);

    if !crt.exists() && !key.exists() {
        if cfg.files.create_self_signed_certs {
            return DoctorCheck {
                name: "tls.identity".into(),
                status: CheckStatus::Warn,
                message: format!(
                    "No certificate in {}; self-signed pair will be generated on first start",
                    ssl_dir.display()
                ),
                hint: Some("Deploy a CA-signed server.crt/server.key for production.".into()),
            };
        }
        return DoctorCheck {
            name: "tls.identity".into(),
            status: if has_ssl_listener {
                CheckStatus::Fail
            } else {
                CheckStatus::Warn
            },
            message: format!(
                "No certificate in {} and CreateSelfSignedCerts is disabled",
                ssl_dir.display()
            ),
            hint: Some(
                "Install server.crt and server.key (0600) or enable CreateSelfSignedCerts.".into(),
            ),
        };
    }

    match cups_tls::load(&ssl_dir) {
        Ok(id) => {
            let key_mode =
                std::fs::symlink_metadata(&key).map_or(0, |m| m.permissions().mode() & 0o777);
            DoctorCheck {
                name: "tls.identity".into(),
                status: CheckStatus::Pass,
                message: format!(
                    "Valid certificate chain ({} cert(s)) in {} (key mode {:04o})",
                    id.certs().len(),
                    ssl_dir.display(),
                    key_mode
                ),
                hint: None,
            }
        }
        Err(e) => DoctorCheck {
            name: "tls.identity".into(),
            status: CheckStatus::Fail,
            message: format!("Invalid TLS certificate/key in {}: {e}", ssl_dir.display()),
            hint: Some(
                "Verify server.crt and server.key match and are regular files (not symlinks)."
                    .into(),
            ),
        },
    }
}

fn check_pam_nss(cfg: &Config, env: &DoctorEnv) -> DoctorCheck {
    let pam_lib = sys::pam_available();
    let pam_conf = env.pam_service_file.is_file();
    let user_ok = sys::name_of_uid(cfg.files.user).is_some();
    let group_ok = sys::group_name_of_gid(cfg.files.group).is_some();
    let resolved_sys_groups = cfg
        .files
        .system_group_names
        .iter()
        .filter(|g| sys::gid_of(g).is_some())
        .count();

    if !user_ok || !group_ok {
        return DoctorCheck {
            name: "auth.pam_nss".into(),
            status: CheckStatus::Warn,
            message: format!(
                "PAM lib={}, pam.d={}, User uid {} resolved={}, Group gid {} resolved={}",
                pam_lib, pam_conf, cfg.files.user, user_ok, cfg.files.group, group_ok
            ),
            hint: Some("Verify User/Group directives in cups-files.conf exist in NSS.".into()),
        };
    }
    if !pam_lib || !pam_conf || resolved_sys_groups == 0 {
        return DoctorCheck {
            name: "auth.pam_nss".into(),
            status: CheckStatus::Warn,
            message: format!(
                "PAM lib={}, {}={}, SystemGroup resolved {}/{}",
                pam_lib,
                env.pam_service_file.display(),
                pam_conf,
                resolved_sys_groups,
                cfg.files.system_group_names.len()
            ),
            hint: Some(
                "Install /etc/pam.d/cups and ensure at least one SystemGroup exists on this host."
                    .into(),
            ),
        };
    }
    DoctorCheck {
        name: "auth.pam_nss".into(),
        status: CheckStatus::Pass,
        message: format!(
            "PAM available, {} present, {resolved_sys_groups}/{} SystemGroup(s) resolved",
            env.pam_service_file.display(),
            cfg.files.system_group_names.len()
        ),
        hint: None,
    }
}

fn check_host_conflicts(cfg: &Config, env: &DoctorEnv) -> DoctorCheck {
    let mut warnings = Vec::new();
    if env.apparmor_profile.exists() {
        warnings.push(format!(
            "AppArmor profile {} exists and may restrict Yindle paths",
            env.apparmor_profile.display()
        ));
    }
    for ln in &cfg.cupsd.listeners {
        if let ListenAddr::Unix(ref sock) = ln.addr {
            if sock.exists() {
                warnings.push(format!(
                    "Unix socket {} already exists (another cupsd may be running)",
                    sock.display()
                ));
            }
        }
    }
    if warnings.is_empty() {
        DoctorCheck {
            name: "host.conflicts".into(),
            status: CheckStatus::Pass,
            message: "No AppArmor profile or stale Unix socket conflicts detected".into(),
            hint: None,
        }
    } else {
        DoctorCheck {
            name: "host.conflicts".into(),
            status: CheckStatus::Warn,
            message: warnings.join("; "),
            hint: Some(
                "Review AppArmor/SELinux profiles or stop conflicting CUPS daemon before starting."
                    .into(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_dir(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "yindle-cupsd-doc-{}-{tag}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn doctor_reports_healthy_warn_and_fail_states() {
        let base = tmp_dir("healthy");
        let etc = base.join("etc");
        let spool = base.join("spool");
        let cache = base.join("cache");
        let tmp = base.join("tmp");
        let logs = base.join("logs");
        let run = base.join("run");
        let mime = base.join("data").join("mime");
        let bin = base.join("bin");
        let ssl = etc.join("ssl");
        for d in [
            &etc,
            &spool,
            &cache,
            &tmp,
            &logs,
            &run,
            &mime,
            &bin.join("backend"),
            &bin.join("filter"),
            &bin.join("daemon"),
            &ssl,
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o710)).unwrap();
        std::fs::write(mime.join("mime.types"), "text/plain txt\n").unwrap();
        std::fs::write(
            mime.join("mime.convs"),
            "text/plain application/vnd.cups-raw 0 -\n",
        )
        .unwrap();
        std::fs::write(bin.join("backend").join("file"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            bin.join("backend").join("file"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::write(bin.join("daemon").join("cups-exec"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            bin.join("daemon").join("cups-exec"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let _ = cups_tls::load_or_create(&ssl, "localhost").unwrap();

        let pam_file = base.join("pam_cups");
        std::fs::write(&pam_file, "auth required pam_unix.so\n").unwrap();

        let (user_id, group_id) = pipeline::current_euid_egid();
        let cur_user = sys::name_of_uid(user_id).unwrap_or_else(|| "nobody".into());
        let cur_group = sys::group_name_of_gid(group_id).unwrap_or_else(|| "nogroup".into());
        std::fs::write(
            etc.join("cups-files.conf"),
            format!(
                "User {cur_user}\nGroup {cur_group}\nSystemGroup {cur_group}\nServerRoot {}\nRequestRoot {}\nCacheDir {}\nTempDir {}\nStateDir {}\nDataDir {}\nServerBin {}\nServerKeychain {}\nErrorLog {}\nFileDevice No\n",
                etc.display(),
                spool.display(),
                cache.display(),
                tmp.display(),
                run.display(),
                base.join("data").display(),
                bin.display(),
                ssl.display(),
                logs.join("error_log").display(),
            ),
        )
        .unwrap();
        std::fs::write(
            etc.join("cupsd.conf"),
            "LogLevel warn\nListen localhost:8631\nDefaultAuthType Basic\nSSLOptions MinTLS1.2 DenyCBC\nMaxRequestSize 64m\nMaxClients 100\n<Location />\n  Order allow,deny\n</Location>\n<Location /admin>\n  AuthType Default\n  Require user @SYSTEM\n  Encryption Required\n  Order allow,deny\n</Location>\n",
        )
        .unwrap();

        let paths = Paths {
            server_root: etc.clone(),
            cupsd_conf: etc.join("cupsd.conf"),
            cups_files_conf: etc.join("cups-files.conf"),
        };
        let env = DoctorEnv {
            apparmor_profile: base.join("no-apparmor"),
            pam_service_file: pam_file,
        };
        let rep = run_doctor(&paths, &env);
        assert!(rep.ok(), "unexpected failures: {}", rep.render_text());
        assert!(rep.render_text().contains("[PASS]"));
        assert!(rep.render_json().contains("\"ok\":true"));

        // Now trigger warnings and failures: AppArmor profile, existing sock,
        // world-writable backend, corrupt cert, missing config
        let aa = base.join("apparmor");
        std::fs::write(&aa, "# profile").unwrap();
        let sock = run.join("cups.sock");
        std::fs::write(&sock, "").unwrap();
        std::fs::write(
            etc.join("cupsd.conf"),
            format!("Listen {}\nListen localhost:8631\n", sock.display()),
        )
        .unwrap();
        std::fs::set_permissions(
            bin.join("backend").join("file"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        std::fs::write(ssl.join("server.crt"), "CORRUPT").unwrap();
        std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o777)).unwrap();
        let not_a_dir = base.join("notadir");
        std::fs::write(&not_a_dir, "x").unwrap();

        let bad_env = DoctorEnv {
            apparmor_profile: aa,
            pam_service_file: base.join("missing-pam"),
        };
        let rep2 = run_doctor(&paths, &bad_env);
        assert!(!rep2.ok());
        let txt2 = rep2.render_text();
        assert!(txt2.contains("[FAIL]"));
        assert!(txt2.contains("[WARN]"));
        assert!(txt2.contains("AppArmor"));
        assert!(rep2.render_json().contains("\"ok\":false"));

        // Missing config + missing TLS with CreateSelfSignedCerts No + empty MIME
        let bad_paths = Paths {
            server_root: base.join("missing_root"),
            cupsd_conf: base.join("missing_root").join("cupsd.conf"),
            cups_files_conf: base.join("missing_root").join("cups-files.conf"),
        };
        let rep3 = run_doctor(&bad_paths, &bad_env);
        assert!(!rep3.ok());

        // Exercise CLI wrapper
        let (ok_cli, out_cli) = run_doctor_cli(&CliArgs {
            cupsd_conf: Some(bad_paths.cupsd_conf),
            json: true,
            ..CliArgs::default()
        });
        assert!(!ok_cli);
        assert!(out_cli.contains("\"checks\""));

        // Direct directory helper edge cases
        assert_eq!(
            check_directory("t", &not_a_dir, true, false).status,
            CheckStatus::Fail
        );
        assert_eq!(
            check_directory("t", &base.join("absent"), false, false).status,
            CheckStatus::Warn
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn doctor_component_checks_cover_warn_and_fail_branches() {
        let base =
            std::env::temp_dir().join(format!("yindle-cupsd-doctor-parts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        // MIME: types without convs -> Warn; no sources at all -> Warn/Fail (never Pass).
        let data = base.join("data");
        std::fs::create_dir_all(data.join("mime")).unwrap();
        std::fs::write(data.join("mime").join("mime.types"), "text/plain txt\n").unwrap();
        assert_eq!(check_mime_db(&data, &base).status, CheckStatus::Warn);
        assert_ne!(
            check_mime_db(&base.join("nope"), &base.join("nope2")).status,
            CheckStatus::Pass
        );

        // Binaries: world-writable backend -> Fail; backend without cups-exec -> Warn; full -> Pass.
        let sb = base.join("serverbin");
        for d in ["backend", "filter", "daemon"] {
            std::fs::create_dir_all(sb.join(d)).unwrap();
        }
        let be = sb.join("backend").join("socket");
        std::fs::write(&be, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&be, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(sb.join("backend").join("README"), "doc").unwrap();
        let flt = sb.join("filter").join("pdftopdf");
        std::fs::write(&flt, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&flt, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(check_binaries(&sb).status, CheckStatus::Warn);
        let ce = sb.join("daemon").join("cups-exec");
        std::fs::write(&ce, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&ce, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(check_binaries(&sb).status, CheckStatus::Pass);
        std::fs::set_permissions(&be, std::fs::Permissions::from_mode(0o757)).unwrap();
        assert_eq!(check_binaries(&sb).status, CheckStatus::Fail);

        // TLS: missing + CreateSelfSignedCerts No -> Warn (no SSL listener) / Fail (SSLListen).
        let mut cfg = Config {
            cupsd: cups_config::CupsdConfig::defaults(),
            files: cups_config::CupsFilesConfig::defaults(),
        };
        cfg.files.create_self_signed_certs = false;
        cfg.files.server_keychain = Some(base.join("ssl").to_string_lossy().into_owned());
        assert_eq!(check_tls(&cfg, &base).status, CheckStatus::Warn);
        cfg.cupsd.listeners.push(cups_config::Listener {
            addr: cups_config::ListenAddr::Tcp("127.0.0.1:0".parse().unwrap()),
            ssl: true,
        });
        assert_eq!(check_tls(&cfg, &base).status, CheckStatus::Fail);

        // PAM/NSS: unresolvable User/Group -> Warn.
        let env = DoctorEnv {
            apparmor_profile: base.join("no-apparmor"),
            pam_service_file: base.join("no-pam"),
        };
        cfg.files.user = 4_294_000_000;
        cfg.files.group = 4_294_000_000;
        assert_eq!(check_pam_nss(&cfg, &env).status, CheckStatus::Warn);

        let _ = std::fs::remove_dir_all(&base);
    }
}
