//! `cupsd` — Presswork enterprise CUPS-compatible print scheduler daemon.
//!
//! Integrates all hardened Wave-1 and Wave-2a workspace crates:
//! - Event-driven async job scheduler (`scheduler`)
//! - Hardened HTTP/1.1, TLS (`ReloadableTls` + RFC 2817), `AuthN` (`spawn_blocking`
//!   PAM/shadow/Bearer), `AuthZ` (`<Location>` + `<Policy>`), and async IPP dispatch (`server`)
//! - Hardened async CGI/1.1 (`cgi`) and static + read-only Web UI (`web`)
//! - Enterprise observability `/healthz`, `/readyz`, Prometheus `/metrics` (`metrics`)
//! - Structured `cups_log::Logger` + `tracing` + `cups_dbus::Notifier` (`logging`)
//! - Zero-downtime `SIGHUP` hot-reload, graceful `SIGTERM`/`SIGINT` drain,
//!   `sd_notify` + watchdog (`lifecycle`)
//! - Full CLI (`-c`, `-s`, `-f`, `-F`, `-l`, `-t`, `-v`/`-V`, `--log-format`,
//!   `--check-config`, `doctor`) (`cli`, `doctor`)

#![forbid(unsafe_code)]

pub mod cgi;
pub mod cli;
pub mod doctor;
pub mod lifecycle;
pub mod logging;
pub mod metrics;
pub mod scheduler;
pub mod server;
pub mod web;

use std::ffi::OsString;
use std::process::ExitCode;

use cli::{
    format_diagnostics, parse_args, resolve_paths, run_check_config, run_test_config, usage,
    version_line, Command,
};

/// Execute `cupsd` from an iterator of CLI arguments (excluding `argv[0]`).
#[must_use]
pub fn run_cli<I>(args: I) -> ExitCode
where
    I: IntoIterator<Item = OsString>,
{
    let env_log_fmt = std::env::var("PRESSWORK_LOG_FORMAT").ok();
    let cmd = match parse_args(args, env_log_fmt.as_deref()) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(1);
        }
    };

    match cmd {
        Command::Help => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!("{}", version_line());
            ExitCode::SUCCESS
        }
        Command::TestConfig(a) => {
            let (ok, stdout, stderr) = run_test_config(&a);
            if !stderr.is_empty() {
                eprint!("{stderr}");
            }
            if !stdout.is_empty() {
                print!("{stdout}");
            }
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Command::CheckConfig(a) => {
            let (ok, output) = run_check_config(&a);
            print!("{output}");
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Command::Doctor(a) => {
            let (ok, output) = doctor::run_doctor_cli(&a);
            print!("{output}");
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Command::Run(a) => {
            let paths = resolve_paths(&a);
            let outcome = cups_config::load(&paths);
            let diags = format_diagnostics(&outcome.diagnostics);
            if !diags.is_empty() {
                eprint!("{diags}");
            }
            if !outcome.ok {
                eprintln!("cupsd: unable to read configuration, exiting");
                return ExitCode::from(1);
            }

            // Adopt systemd socket-activated fds while still single-threaded
            // (`sd_listen_fds` clears `LISTEN_*` from the environment).
            let activated = sys::sd_listen_fds();
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("cupsd: unable to initialize async runtime: {e}");
                    return ExitCode::from(1);
                }
            };
            rt.block_on(lifecycle::run_daemon_with_signals(
                outcome.config,
                a,
                paths,
                activated,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(xs: &[&str]) -> Vec<OsString> {
        xs.iter().map(OsString::from).collect()
    }

    #[test]
    fn run_cli_dispatches_help_version_errors_and_missing_config() {
        assert_eq!(run_cli(os(&["-h"])), ExitCode::SUCCESS);
        assert_eq!(run_cli(os(&["-V"])), ExitCode::SUCCESS);
        assert_eq!(run_cli(os(&["--bad-flag"])), ExitCode::from(1));
        assert_eq!(
            run_cli(os(&["-t", "-c", "/nonexistent/pw-cupsd.conf"])),
            ExitCode::from(1)
        );
        assert_eq!(
            run_cli(os(&["--check-config", "-c", "/nonexistent/pw-cupsd.conf"])),
            ExitCode::from(1)
        );
        assert_eq!(
            run_cli(os(&["doctor", "-c", "/nonexistent/pw-cupsd.conf"])),
            ExitCode::from(1)
        );
        assert_eq!(
            run_cli(os(&["-c", "/nonexistent/pw-cupsd.conf"])),
            ExitCode::from(1)
        );
    }
}
