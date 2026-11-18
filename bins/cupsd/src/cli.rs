//! Enterprise CLI parsing, configuration path resolution, `-t` syntax testing,
//! and `--check-config` migration auditing (`cups_config::audit_paths`).

use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use cups_config::{AuditSeverity, ConfigAuditReport, Diagnostic, DirectiveStatus, Paths, Severity};

/// Crate version reported by `-v` / `-V` / `--version` and `/healthz`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Log serialization format selected via `--log-format` or `PRESSWORK_LOG_FORMAT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CliLogFormat {
    /// Classic CUPS / CLF plain text format.
    #[default]
    Text,
    /// Structured single-line JSON (NDJSON).
    Json,
}

impl CliLogFormat {
    /// Parse `"text"` or `"json"` (case-insensitive).
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "text" | "plain" => Some(Self::Text),
            "json" | "ndjson" => Some(Self::Json),
            _ => None,
        }
    }

    /// Convert to [`cups_log::LogFormat`].
    #[must_use]
    pub const fn to_cups_log_format(self) -> cups_log::LogFormat {
        match self {
            Self::Text => cups_log::LogFormat::Text,
            Self::Json => cups_log::LogFormat::Json,
        }
    }
}

/// Top-level command selected from CLI arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Show usage help and exit 0.
    Help,
    /// Show version string and exit 0.
    Version,
    /// `-t` / `-C`: parse and validate configuration files and exit.
    TestConfig(CliArgs),
    /// `--check-config`: run the migration linter & security audit and exit.
    CheckConfig(CliArgs),
    /// `doctor`: run comprehensive host, permission, TLS, MIME, and binary diagnostics.
    Doctor(CliArgs),
    /// Normal daemon execution.
    Run(CliArgs),
}

/// Parsed CLI options shared across daemon, `-t`, `--check-config`, and `doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct CliArgs {
    /// Explicit `-c <cupsd.conf>` path.
    pub cupsd_conf: Option<PathBuf>,
    /// Explicit `-s <cups-files.conf>` path (honored even when `-c` is also given).
    pub cups_files_conf: Option<PathBuf>,
    /// `-f` foreground mode (stay attached to terminal/supervisor).
    pub foreground: bool,
    /// `-F` foreground without detaching stdio/process group.
    pub foreground_no_detach: bool,
    /// `-l` on-demand / socket-activation mode (enables `IdleExitTimeout`).
    pub on_demand: bool,
    /// `--log-format text|json` (falls back to `PRESSWORK_LOG_FORMAT`).
    pub log_format: CliLogFormat,
    /// `--json` structured JSON output for `--check-config` and `doctor`.
    pub json: bool,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            cupsd_conf: None,
            cups_files_conf: None,
            foreground: false,
            foreground_no_detach: false,
            on_demand: false,
            log_format: CliLogFormat::Text,
            json: false,
        }
    }
}

/// Return full CLI usage text.
#[must_use]
pub fn usage() -> &'static str {
    "Usage: cupsd [options]\n\
     \x20      cupsd doctor [options]\n\
     \n\
     Options:\n\
     \x20 -c <config-file>         Load the specified cupsd.conf configuration file.\n\
     \x20 -s <files-config>        Load the specified cups-files.conf file.\n\
     \x20 -f                       Run in the foreground.\n\
     \x20 -F                       Run in the foreground without detaching.\n\
     \x20 -l                       On-demand mode (socket activation / IdleExitTimeout).\n\
     \x20 -t                       Test configuration syntax and exit.\n\
     \x20 --check-config           Run migration & security configuration audit and exit.\n\
     \x20 --log-format <text|json> Select log output format (env: PRESSWORK_LOG_FORMAT).\n\
     \x20 --json                   Emit JSON output for --check-config or doctor.\n\
     \x20 -v, -V, --version        Show version and exit.\n\
     \x20 -h, --help               Show this help message and exit.\n\
     \n\
     Subcommands:\n\
     \x20 doctor                   Run runtime environment, TLS, MIME, and security checks.\n"
}

/// Format the version banner printed for `-v` / `-V` / `--version`.
#[must_use]
pub fn version_line() -> String {
    format!("cupsd {VERSION} (presswork)")
}

/// Parse CLI arguments (excluding `argv[0]`), consulting `env_log_format`
/// (from `PRESSWORK_LOG_FORMAT`) as the default before explicit `--log-format`.
pub fn parse_args<I>(args: I, env_log_format: Option<&str>) -> Result<Command, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut parsed = CliArgs::default();
    if let Some(raw) = env_log_format {
        if !raw.trim().is_empty() {
            parsed.log_format = CliLogFormat::parse(raw).ok_or_else(|| {
                format!("cupsd: invalid PRESSWORK_LOG_FORMAT '{raw}' (expected 'text' or 'json')")
            })?;
        }
    }

    let mut is_doctor = false;
    let mut test_config = false;
    let mut check_config = false;
    let mut it = args.into_iter().peekable();

    if let Some(first) = it.peek() {
        if first.to_string_lossy() == "doctor" {
            is_doctor = true;
            let _ = it.next();
        }
    }

    while let Some(arg) = it.next() {
        let s = arg.to_string_lossy();
        match s.as_ref() {
            "-c" => {
                let val = it
                    .next()
                    .ok_or_else(|| "cupsd: option '-c' requires a config file path".to_string())?;
                parsed.cupsd_conf = Some(PathBuf::from(val));
            }
            "-s" => {
                let val = it.next().ok_or_else(|| {
                    "cupsd: option '-s' requires a cups-files.conf path".to_string()
                })?;
                parsed.cups_files_conf = Some(PathBuf::from(val));
            }
            "-t" | "-C" => test_config = true,
            "--check-config" => check_config = true,
            "-f" => parsed.foreground = true,
            "-F" => {
                parsed.foreground = true;
                parsed.foreground_no_detach = true;
            }
            "-l" => parsed.on_demand = true,
            "--json" => parsed.json = true,
            "--log-format" => {
                let val = it.next().ok_or_else(|| {
                    "cupsd: option '--log-format' requires 'text' or 'json'".to_string()
                })?;
                let vs = val.to_string_lossy();
                parsed.log_format = CliLogFormat::parse(&vs).ok_or_else(|| {
                    format!("cupsd: invalid --log-format '{vs}' (expected 'text' or 'json')")
                })?;
            }
            raw if raw.starts_with("--log-format=") => {
                let vs = &raw["--log-format=".len()..];
                parsed.log_format = CliLogFormat::parse(vs).ok_or_else(|| {
                    format!("cupsd: invalid --log-format '{vs}' (expected 'text' or 'json')")
                })?;
            }
            "-h" | "--help" => return Ok(Command::Help),
            "-v" | "-V" | "--version" => return Ok(Command::Version),
            "doctor" => is_doctor = true,
            other => return Err(format!("cupsd: bad option/argument '{other}'")),
        }
    }

    if is_doctor {
        Ok(Command::Doctor(parsed))
    } else if check_config {
        Ok(Command::CheckConfig(parsed))
    } else if test_config {
        Ok(Command::TestConfig(parsed))
    } else {
        Ok(Command::Run(parsed))
    }
}

/// Resolve [`Paths`] from CLI arguments, properly honoring `-s <cups-files.conf>`
/// even when `-c <cupsd.conf>` is also provided.
#[must_use]
pub fn resolve_paths(args: &CliArgs) -> Paths {
    let parent_non_empty = |p: &Path| -> Option<PathBuf> {
        let par = p.parent()?;
        if par.as_os_str().is_empty() {
            Some(PathBuf::from("."))
        } else {
            Some(par.to_path_buf())
        }
    };

    let inferred_root = args
        .cupsd_conf
        .as_deref()
        .and_then(parent_non_empty)
        .or_else(|| args.cups_files_conf.as_deref().and_then(parent_non_empty));

    let mut paths = Paths::resolve(inferred_root.as_deref());
    if let Some(ref cupsd_conf) = args.cupsd_conf {
        paths.cupsd_conf.clone_from(cupsd_conf);
    }
    if let Some(ref files_conf) = args.cups_files_conf {
        paths.cups_files_conf.clone_from(files_conf);
    }
    paths
}

/// Determine effective runtime `ServerRoot`: prefers explicit `ServerRoot` from
/// `cups-files.conf` when loaded, otherwise falls back to `paths.server_root`.
#[must_use]
pub fn effective_server_root(cfg: &cups_config::Config, paths: &Paths) -> PathBuf {
    if paths.cups_files_conf.is_file() {
        if let Some(ref configured) = cfg.files.server_root {
            if configured != "/etc/cups" || paths.server_root == Path::new("/etc/cups") {
                return PathBuf::from(configured);
            }
        }
    }
    paths.server_root.clone()
}

/// Format parser diagnostics in standard CUPS `L [file:line] msg` style.
#[must_use]
pub fn format_diagnostics(ds: &[Diagnostic]) -> String {
    let mut out = String::new();
    for e in ds {
        let lvl = match e.severity {
            Severity::Info => "I",
            Severity::Warn => "W",
            Severity::Error => "E",
        };
        let _ = writeln!(out, "{lvl} [{:>16}:{}] {}", e.file, e.line, e.message);
    }
    out
}

/// Render a [`ConfigAuditReport`] for `--check-config` in human-readable text format.
#[must_use]
pub fn render_audit_text(report: &ConfigAuditReport) -> String {
    let mut out = report.summary();
    if report.findings.is_empty()
        && report.directive_count(DirectiveStatus::Deprecated) == 0
        && report.directive_count(DirectiveStatus::Moved) == 0
        && report.directive_count(DirectiveStatus::Unknown) == 0
        && !report.has_errors()
    {
        out.push_str("  No migration issues or security warnings detected.\n");
    }
    out
}

/// Render a [`ConfigAuditReport`] for `--check-config --json`.
#[must_use]
pub fn render_audit_json(report: &ConfigAuditReport) -> String {
    let mut out = String::with_capacity(512);
    out.push_str("{\"ok\":");
    out.push_str(if report.has_errors() { "false" } else { "true" });
    let _ = write!(
        out,
        ",\"counts\":{{\"supported\":{},\"deprecated\":{},\"moved\":{},\"unknown\":{},\"findings\":{},\"diagnostics\":{}}}",
        report.directive_count(DirectiveStatus::Supported),
        report.directive_count(DirectiveStatus::Deprecated),
        report.directive_count(DirectiveStatus::Moved),
        report.directive_count(DirectiveStatus::Unknown),
        report.findings.len(),
        report.diagnostics.len(),
    );

    out.push_str(",\"directives\":[");
    for (i, d) in report.directives.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"file\":");
        push_json_str(&mut out, &d.file);
        let _ = write!(out, ",\"line\":{},\"name\":", d.line);
        push_json_str(&mut out, &d.name);
        out.push_str(",\"status\":");
        push_json_str(&mut out, directive_status_str(d.status));
        out.push_str(",\"note\":");
        match &d.note {
            Some(note) => push_json_str(&mut out, note),
            None => out.push_str("null"),
        }
        out.push('}');
    }
    out.push_str("],\"findings\":[");
    for (i, f) in report.findings.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"severity\":");
        push_json_str(&mut out, audit_severity_str(f.severity));
        out.push_str(",\"code\":");
        push_json_str(&mut out, f.code);
        out.push_str(",\"message\":");
        push_json_str(&mut out, &f.message);
        out.push_str(",\"remediation\":");
        push_json_str(&mut out, &f.remediation);
        out.push('}');
    }
    out.push_str("],\"diagnostics\":[");
    for (i, diag) in report.diagnostics.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"severity\":");
        push_json_str(&mut out, diag_severity_str(diag.severity));
        out.push_str(",\"file\":");
        push_json_str(&mut out, &diag.file);
        let _ = write!(out, ",\"line\":{},\"message\":", diag.line);
        push_json_str(&mut out, &diag.message);
        out.push('}');
    }
    out.push_str("]}\n");
    out
}

const fn directive_status_str(status: DirectiveStatus) -> &'static str {
    match status {
        DirectiveStatus::Supported => "supported",
        DirectiveStatus::Deprecated => "deprecated",
        DirectiveStatus::Moved => "moved",
        DirectiveStatus::Unknown => "unknown",
    }
}

const fn audit_severity_str(sev: AuditSeverity) -> &'static str {
    match sev {
        AuditSeverity::Info => "info",
        AuditSeverity::Warning => "warning",
        AuditSeverity::High => "high",
    }
}

const fn diag_severity_str(sev: Severity) -> &'static str {
    match sev {
        Severity::Info => "info",
        Severity::Warn => "warn",
        Severity::Error => "error",
    }
}

/// JSON string escaper shared across CLI, doctor, and health/readiness endpoints.
pub fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\x7f' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            _ => out.push(c),
        }
    }
    out.push('"');
}

/// Execute `-t` syntax validation and return `(ok, stdout, stderr)`.
#[must_use]
pub fn run_test_config(args: &CliArgs) -> (bool, String, String) {
    let paths = resolve_paths(args);
    let outcome = cups_config::load(&paths);
    let stderr_diags = format_diagnostics(&outcome.diagnostics);
    if outcome.ok {
        (
            true,
            format!("{} is OK\n", paths.cupsd_conf.display()),
            stderr_diags,
        )
    } else {
        let mut err = stderr_diags;
        let _ = writeln!(err, "{} contains errors", paths.cupsd_conf.display());
        (false, String::new(), err)
    }
}

/// Execute `--check-config` migration linter & security audit and return `(ok, output)`.
#[must_use]
pub fn run_check_config(args: &CliArgs) -> (bool, String) {
    let paths = resolve_paths(args);
    let (_cfg, report) = cups_config::audit_paths(&paths);
    let rendered = if args.json {
        render_audit_json(&report)
    } else {
        render_audit_text(&report)
    };
    (!report.has_errors(), rendered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn os_args(xs: &[&str]) -> Vec<OsString> {
        xs.iter().map(OsString::from).collect()
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "presswork-cupsd-cli-{}-{tag}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn parse_all_flags_and_subcommands() {
        assert_eq!(parse_args(os_args(&["-h"]), None).unwrap(), Command::Help);
        assert_eq!(
            parse_args(os_args(&["--help"]), None).unwrap(),
            Command::Help
        );
        assert_eq!(
            parse_args(os_args(&["-v"]), None).unwrap(),
            Command::Version
        );
        assert_eq!(
            parse_args(os_args(&["-V"]), None).unwrap(),
            Command::Version
        );
        assert_eq!(
            parse_args(os_args(&["--version"]), None).unwrap(),
            Command::Version
        );
        assert!(version_line().contains(VERSION));
        assert!(usage().contains("--check-config"));
        assert!(usage().contains("doctor"));

        let cmd = parse_args(
            os_args(&[
                "-c",
                "/a/cupsd.conf",
                "-s",
                "/b/cups-files.conf",
                "-F",
                "-l",
                "--log-format",
                "json",
            ]),
            None,
        )
        .unwrap();
        match cmd {
            Command::Run(a) => {
                assert_eq!(a.cupsd_conf, Some(PathBuf::from("/a/cupsd.conf")));
                assert_eq!(a.cups_files_conf, Some(PathBuf::from("/b/cups-files.conf")));
                assert!(a.foreground);
                assert!(a.foreground_no_detach);
                assert!(a.on_demand);
                assert_eq!(a.log_format, CliLogFormat::Json);
                assert_eq!(a.log_format.to_cups_log_format(), cups_log::LogFormat::Json);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        // `-f` and `--log-format=text` + env fallback
        let cmd2 = parse_args(os_args(&["-f", "--log-format=text"]), Some("json")).unwrap();
        match cmd2 {
            Command::Run(a) => {
                assert!(a.foreground);
                assert!(!a.foreground_no_detach);
                assert_eq!(a.log_format, CliLogFormat::Text);
                assert_eq!(a.log_format.to_cups_log_format(), cups_log::LogFormat::Text);
            }
            other => panic!("unexpected: {other:?}"),
        }

        // Env log format honored when flag omitted
        let cmd3 = parse_args(os_args(&["-t"]), Some("json")).unwrap();
        assert!(matches!(
            cmd3,
            Command::TestConfig(a) if a.log_format == CliLogFormat::Json
        ));

        // --check-config --json
        let cmd4 = parse_args(os_args(&["--check-config", "--json"]), None).unwrap();
        assert!(matches!(cmd4, Command::CheckConfig(a) if a.json));

        // doctor subcommand (leading or trailing)
        let cmd5 = parse_args(
            os_args(&["doctor", "-c", "/etc/cups/cupsd.conf", "--json"]),
            None,
        )
        .unwrap();
        assert!(matches!(cmd5, Command::Doctor(a) if a.json && a.cupsd_conf.is_some()));

        let cmd6 = parse_args(os_args(&["-c", "/etc/cups/cupsd.conf", "doctor"]), None).unwrap();
        assert!(matches!(cmd6, Command::Doctor(_)));

        // Error cases
        assert!(parse_args(os_args(&["-c"]), None).is_err());
        assert!(parse_args(os_args(&["-s"]), None).is_err());
        assert!(parse_args(os_args(&["--log-format"]), None).is_err());
        assert!(parse_args(os_args(&["--log-format", "yaml"]), None).is_err());
        assert!(parse_args(os_args(&["--log-format=xml"]), None).is_err());
        assert!(parse_args(os_args(&["--bogus"]), None).is_err());
        assert!(parse_args(os_args(&[]), Some("invalid")).is_err());
        assert_eq!(CliLogFormat::parse("plain"), Some(CliLogFormat::Text));
        assert_eq!(CliLogFormat::parse("ndjson"), Some(CliLogFormat::Json));
    }

    #[test]
    fn resolve_paths_honors_both_c_and_s() {
        let args = CliArgs {
            cupsd_conf: Some(PathBuf::from("/custom/a/cupsd.conf")),
            cups_files_conf: Some(PathBuf::from("/other/b/my-files.conf")),
            ..CliArgs::default()
        };
        let p = resolve_paths(&args);
        assert_eq!(p.cupsd_conf, PathBuf::from("/custom/a/cupsd.conf"));
        assert_eq!(p.cups_files_conf, PathBuf::from("/other/b/my-files.conf"));
        assert_eq!(p.server_root, PathBuf::from("/custom/a"));

        // Relative filename with empty parent maps to `.`
        let rel = CliArgs {
            cupsd_conf: Some(PathBuf::from("cupsd.conf")),
            ..CliArgs::default()
        };
        assert_eq!(resolve_paths(&rel).server_root, PathBuf::from("."));

        // `-s` alone infers server_root from `-s`
        let s_only = CliArgs {
            cups_files_conf: Some(PathBuf::from("/alt/cups-files.conf")),
            ..CliArgs::default()
        };
        let ps = resolve_paths(&s_only);
        assert_eq!(ps.server_root, PathBuf::from("/alt"));
        assert_eq!(ps.cups_files_conf, PathBuf::from("/alt/cups-files.conf"));
    }

    #[test]
    fn test_config_and_check_config_end_to_end() {
        let dir = tmp_dir("audit");
        let cupsd_p = dir.join("cupsd.conf");
        let files_p = dir.join("custom-files.conf");
        std::fs::write(
            &files_p,
            format!(
                "ServerRoot {}\nFileDevice Yes\nUnknownFilesDir 1\nServerCertificate /tmp/c\n",
                dir.display()
            ),
        )
        .unwrap();
        std::fs::write(
            &cupsd_p,
            "LogLevel info\nListen 127.0.0.1:8631\nAuthClass System\nFileDevice Yes\nBogusDirective 1\n<Location />\n  Order allow,deny\n</Location>\n",
        )
        .unwrap();

        let args = CliArgs {
            cupsd_conf: Some(cupsd_p.clone()),
            cups_files_conf: Some(files_p.clone()),
            ..CliArgs::default()
        };
        let (ok_t, out_t, _err_t) = run_test_config(&args);
        assert!(ok_t);
        assert!(out_t.contains("is OK"));

        let (ok_c, txt) = run_check_config(&args);
        // Misplaced/unknown directives produce parser errors so --check-config exits non-zero.
        assert!(!ok_c);
        assert!(txt.contains("FILE_DEVICE_ENABLED"));
        assert!(txt.contains("Deprecated"));
        assert!(txt.contains("Moved"));
        assert!(txt.contains("Unknown"));

        let json_args = CliArgs {
            json: true,
            ..args.clone()
        };
        let (ok_j, js) = run_check_config(&json_args);
        assert!(!ok_j);
        assert!(js.starts_with("{\"ok\":false"));
        assert!(js.contains("\"FILE_DEVICE_ENABLED\""));
        assert!(js.contains("\"deprecated\":"));

        // Clean hardened config reports no warnings
        let clean_dir = tmp_dir("clean");
        let clean_c = clean_dir.join("cupsd.conf");
        let clean_f = clean_dir.join("cups-files.conf");
        std::fs::write(&clean_f, "SystemGroup lpadmin\nFileDevice No\n").unwrap();
        std::fs::write(
            &clean_c,
            "LogLevel warn\nListen localhost:631\nDefaultAuthType Basic\nSSLOptions MinTLS1.2 DenyCBC\nMaxRequestSize 64m\nMaxClients 100\n<Location />\n  Order allow,deny\n</Location>\n<Location /admin>\n  AuthType Default\n  Require user @SYSTEM\n  Encryption Required\n  Order allow,deny\n</Location>\n",
        )
        .unwrap();
        let clean_args = CliArgs {
            cupsd_conf: Some(clean_c),
            cups_files_conf: Some(clean_f),
            ..CliArgs::default()
        };
        let (ok_clean, clean_txt) = run_check_config(&clean_args);
        assert!(ok_clean);
        assert!(clean_txt.contains("No migration issues or security warnings detected"));

        // Missing config file fails both -t and --check-config
        let missing = CliArgs {
            cupsd_conf: Some(dir.join("does-not-exist.conf")),
            ..CliArgs::default()
        };
        let (ok_m, _, err_m) = run_test_config(&missing);
        assert!(!ok_m);
        assert!(err_m.contains("contains errors"));
        let (check_ok, check_out) = run_check_config(&CliArgs {
            json: true,
            ..missing
        });
        assert!(!check_ok);
        assert!(check_out.contains("\"ok\":false"));

        // effective_server_root picks explicit ServerRoot from cups-files.conf
        let paths = resolve_paths(&args);
        let loaded = cups_config::load(&paths);
        assert_eq!(effective_server_root(&loaded.config, &paths), dir);

        // JSON string escaping edge cases
        let mut s = String::new();
        push_json_str(&mut s, "a\"b\\c\n\r\t\x08\x0c\x01");
        assert_eq!(s, "\"a\\\"b\\\\c\\n\\r\\t\\b\\f\\u0001\"");

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&clean_dir);
    }
}
