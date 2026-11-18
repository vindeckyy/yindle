//! Hardened CUPS filter+backend pipeline — a port of `scheduler/job.c`'s
//! `start_job` / `cupsdStartProcess` machinery.
//!
//! For each job file, CUPS resolves a MIME filter chain (`mime_db::MimeDb::filter_chain`)
//! from the document type to the printer's accept type, then spawns:
//!   `[filter0] -> [filter1] -> ... -> [backend]`
//!
//! Security and protocol invariants enforced by this crate:
//! - **Multi-filter argv contract**: `data_file` (`argv[6]`) is passed ONLY to the
//!   first stage when reading from a file; filters 2..N and any backend preceded by
//!   filters receive 5 arguments and read piped stdin from the preceding stage.
//! - **Executable containment & safety**: strict RFC 3986 URI scheme validation,
//!   `..` / symlink / relative-path rejection, trusted directory canonicalization,
//!   regular executable non-group/world-writable non-setuid/setgid & UID ownership checks.
//! - **Environment sanitization & credential stripping**: `env_clear()`, explicit
//!   safe allowlist, `cups_config::is_prohibited_env` filtering, and `DEVICE_URI`
//!   passed ONLY to the backend (never to untrusted filters).
//! - **Status parsing (`statbuf`) & channels**: every filter and backend stderr is
//!   piped into bounded `StatBuf` threads emitting structured [`StatusEvent`]s;
//!   CUPS backchannel (fd 3) and sidechannel (fd 4) primitives are provided.
//! - **Sandboxing & cancellation**: `SandboxConfig` (`Sandboxing::{Strict,Relaxed,Off}`,
//!   `User`/`Group` privilege drop, `umask 077`, `FilterNice`, `Rlimits`, `PR_SET_NO_NEW_PRIVS`,
//!   Linux Landlock, `cups-exec` launcher integration) plus process-group `SIGTERM` ->
//!   `SIGKILL` cancellation via [`Pipeline::kill_job`].

pub mod channels;
pub mod exit;
pub mod sandbox;
pub mod security;
pub mod status;

use std::collections::HashMap;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

pub use channels::{
    BackChannel, SideChannel, SideChannelCommand, SideChannelEnd, SideChannelMessage,
    SideChannelStatus, CUPS_BC_FD, CUPS_SC_FD, CUPS_SC_MAX_DATA,
};
pub use exit::{
    kill_pid, kill_process_group, BackendExit, FilterExit, KillSignal, OsSignalSender,
    PipelineExit, SignalSender,
};
pub use sandbox::{
    apply_current_process_sandbox, apply_sandbox_with_ops, build_cups_exec_args,
    build_landlock_rules, sandbox_profile_name, LandlockContext, OsSandboxOps, SandboxConfig,
    SandboxOps, SandboxReport, DEFAULT_FILTER_UMASK,
};
pub use security::{
    current_euid_egid, parse_proc_status_ids, resolve_trusted_executable, sanitize_env_value,
    sanitize_extra_env, try_backend_for_uri, validate_program_name, validate_uri_scheme,
    verify_executable_metadata, verify_executable_path, SecurityPolicy,
};
pub use status::{
    parse_kv_pairs, parse_page_event, parse_state_changes, parse_status_line, spawn_stderr_reader,
    LogSeverity, PageEvent, StatBuf, StateChange, StatusEvent, StatusMessage, MAX_STATBUF_LINE,
};

/// Safe default `PATH` injected into filter and backend subprocesses.
const SAFE_STAGE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/bin:/bin";

/// One resolved pipeline stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    /// Filter program resolved under `filter_dir`.
    pub program: PathBuf,
    /// `CONTENT_TYPE` for this stage's input.
    pub src_type: String,
    /// `FINAL_CONTENT_TYPE` target.
    pub dst_type: String,
}

/// One parsed PPD `*cupsFilter` or `*cupsFilter2` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PpdFilter {
    /// Source MIME type accepted by the driver filter.
    pub src: String,
    /// Destination MIME type produced (`application/vnd.cups-raw` for `*cupsFilter`).
    pub dst: String,
    /// Relative conversion cost.
    pub cost: u32,
    /// Filter program name (or `"-"` for passthrough).
    pub program: String,
}

/// Parse `*cupsFilter` and `*cupsFilter2` lines from PPD text safely.
///
/// Rejects entries with path traversal (`..`), control chars, or invalid names
/// (other than the `"-"` passthrough sentinel).
#[must_use]
pub fn parse_ppd_filters(ppd: &str) -> Vec<PpdFilter> {
    let mut out = Vec::new();
    for raw_line in ppd.lines() {
        let line = raw_line.trim();
        let (is_v2, rest) = if let Some(r) = line.strip_prefix("*cupsFilter2") {
            (true, r)
        } else if let Some(r) = line.strip_prefix("*cupsFilter") {
            (false, r)
        } else {
            continue;
        };
        let Some((_, val)) = rest.split_once(':') else {
            continue;
        };
        let val = val.trim().trim_matches('"');
        let parts: Vec<&str> = val.split_whitespace().collect();
        let (src, dst, cost_str, prog) = if is_v2 {
            if parts.len() < 4 {
                continue;
            }
            (parts[0], parts[1], parts[2], parts[3])
        } else {
            if parts.len() < 3 {
                continue;
            }
            (parts[0], "application/vnd.cups-raw", parts[1], parts[2])
        };
        let Ok(cost) = cost_str.parse::<u32>() else {
            continue;
        };
        if !src.contains('/') || !dst.contains('/') {
            continue;
        }
        if prog != "-" && validate_program_name(prog).is_err() {
            continue;
        }
        out.push(PpdFilter {
            src: src.to_ascii_lowercase(),
            dst: dst.to_ascii_lowercase(),
            cost,
            program: prog.to_string(),
        });
    }
    out
}

/// Format CUPS job options `(key, value)` pairs into a properly quoted `argv[5]`
/// option string (`cupsParseOptions`-compatible).
#[must_use]
pub fn format_job_options(options: &[(String, String)]) -> String {
    let mut out = String::new();
    for (k, v) in options {
        let key: String = k
            .chars()
            .filter(|c| !c.is_control() && !c.is_whitespace() && *c != '=')
            .collect();
        if key.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&key);
        if !v.is_empty() {
            out.push('=');
            let clean_val: String = v.chars().filter(|c| !c.is_control()).collect();
            if clean_val.contains([' ', '\t', '"', '\'', '\\']) {
                out.push('"');
                for ch in clean_val.chars() {
                    if ch == '"' || ch == '\\' {
                        out.push('\\');
                    }
                    out.push(ch);
                }
                out.push('"');
            } else {
                out.push_str(&clean_val);
            }
        }
    }
    out
}

/// Optional security, sandbox, status, channel, and environment overrides for
/// spawning a pipeline ([`JobSpec::spawn_with_options`]).
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct SpawnOptions {
    /// Executable path, ownership, and permission verification policy.
    pub security: SecurityPolicy,
    /// Sandboxing, privilege-drop, rlimit, nice, and `cups-exec` settings.
    pub sandbox: SandboxConfig,
    /// Optional external channel to receive structured filter/backend stderr
    /// [`StatusMessage`] events. When `None`, `Pipeline` creates an internal
    /// channel accessible via [`Pipeline::take_status_receiver`] / [`Pipeline::drain_status_events`].
    pub status_tx: Option<mpsc::Sender<StatusMessage>>,
    /// Allocate a [`BackChannel`] OS pipe (`CUPS_BC_FD = 3`).
    pub enable_backchannel: bool,
    /// Allocate a [`SideChannel`] `AF_UNIX` `SOCK_DGRAM` socketpair (`CUPS_SC_FD = 4`).
    pub enable_sidechannel: bool,
    /// Place all filter+backend stages in a dedicated process group so
    /// [`Pipeline::kill_job`] signals the entire job tree cleanly.
    pub process_group: bool,
    /// `PPD` file path exposed to filters and backend.
    pub ppd: Option<PathBuf>,
    /// `PRINTER_INFO` environment value (defaults to `printer`).
    pub printer_info: Option<String>,
    /// `PRINTER_LOCATION` environment value (defaults to `""`).
    pub printer_location: Option<String>,
    /// `CUPS_SERVERROOT` directory.
    pub server_root: Option<PathBuf>,
    /// `CUPS_SERVERBIN` directory.
    pub server_bin: Option<PathBuf>,
    /// `CUPS_DATADIR` directory.
    pub data_dir: Option<PathBuf>,
    /// `CUPS_CACHEDIR` directory.
    pub cache_dir: Option<PathBuf>,
    /// `CUPS_REQUESTROOT` directory.
    pub request_root: Option<PathBuf>,
    /// `CUPS_STATEDIR` directory.
    pub state_dir: Option<PathBuf>,
    /// `TMPDIR` directory.
    pub temp_dir: Option<PathBuf>,
    /// `RIP_MAX_CACHE` value (defaults to `"128m"`).
    pub rip_max_cache: Option<String>,
    /// 1-based document number in a multi-document job.
    pub document_number: Option<u32>,
    /// Optional document name for multi-document jobs.
    pub document_name: Option<String>,
    /// Whether the first stage receives `data_file` as `argv[6]` (`true` for
    /// file-backed jobs, `false` when streaming solely via stdin).
    pub input_is_file: bool,
}

impl Default for SpawnOptions {
    fn default() -> Self {
        Self {
            security: SecurityPolicy::for_current_process(),
            sandbox: SandboxConfig::default(),
            status_tx: None,
            enable_backchannel: true,
            enable_sidechannel: false,
            process_group: true,
            ppd: None,
            printer_info: None,
            printer_location: None,
            server_root: None,
            server_bin: None,
            data_dir: None,
            cache_dir: None,
            request_root: None,
            state_dir: None,
            temp_dir: None,
            rip_max_cache: None,
            document_number: None,
            document_name: None,
            input_is_file: true,
        }
    }
}

impl SpawnOptions {
    /// Construct [`SpawnOptions`] wired from a loaded [`cups_config::Config`].
    #[must_use]
    pub fn from_cups_config(cfg: &cups_config::Config) -> Self {
        Self {
            sandbox: SandboxConfig::from_cups_config(cfg),
            server_root: cfg.files.server_root.as_deref().map(PathBuf::from),
            server_bin: cfg.files.server_bin.as_deref().map(PathBuf::from),
            data_dir: cfg.files.data_dir.as_deref().map(PathBuf::from),
            cache_dir: cfg.files.cache_dir.as_deref().map(PathBuf::from),
            request_root: cfg.files.request_root.as_deref().map(PathBuf::from),
            state_dir: cfg.files.state_dir.as_deref().map(PathBuf::from),
            temp_dir: cfg.files.temp_dir.as_deref().map(PathBuf::from),
            ..Self::default()
        }
    }
}

/// A running filter+backend pipeline — child handles in spawn order plus
/// process-group metadata, stderr status event stream, and back/side channels.
pub struct Pipeline {
    /// Filter stages (everything before the backend).
    pub filters: Vec<Child>,
    /// The backend child (writes to `device_uri`).
    pub backend: Child,
    pgid: Option<i32>,
    status_rx: Option<mpsc::Receiver<StatusMessage>>,
    status_threads: Vec<JoinHandle<()>>,
    backchannel: Option<BackChannel>,
    sidechannel: Option<SideChannel>,
    backend_stdout: Option<ChildStdout>,
}

impl Pipeline {
    /// Process group ID shared by all stages, if `process_group` was enabled.
    #[must_use]
    pub const fn pgid(&self) -> Option<i32> {
        self.pgid
    }

    /// Return PIDs of all stages (filters first, backend last).
    #[must_use]
    pub fn pids(&self) -> Vec<u32> {
        let mut out: Vec<u32> = self.filters.iter().map(Child::id).collect();
        out.push(self.backend.id());
        out
    }

    /// Take ownership of the structured stderr [`StatusMessage`] receiver (if an
    /// external `status_tx` was not supplied in [`SpawnOptions`]).
    pub fn take_status_receiver(&mut self) -> Option<mpsc::Receiver<StatusMessage>> {
        self.status_rx.take()
    }

    /// Drain all currently buffered status messages from the internal receiver.
    #[must_use]
    pub fn drain_status_events(&self) -> Vec<StatusMessage> {
        let Some(ref rx) = self.status_rx else {
            return Vec::new();
        };
        let mut out = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            out.push(msg);
        }
        out
    }

    /// Borrow the allocated [`BackChannel`] pipe, if enabled.
    #[must_use]
    pub const fn backchannel(&self) -> Option<&BackChannel> {
        self.backchannel.as_ref()
    }

    /// Take ownership of the [`BackChannel`] pipe.
    pub fn take_backchannel(&mut self) -> Option<BackChannel> {
        self.backchannel.take()
    }

    /// Borrow the allocated [`SideChannel`] socketpair, if enabled.
    #[must_use]
    pub const fn sidechannel(&self) -> Option<&SideChannel> {
        self.sidechannel.as_ref()
    }

    /// Take ownership of the [`SideChannel`] socketpair.
    pub fn take_sidechannel(&mut self) -> Option<SideChannel> {
        self.sidechannel.take()
    }

    /// Take ownership of the backend's piped stdout, if captured.
    pub fn take_backend_stdout(&mut self) -> Option<ChildStdout> {
        self.backend_stdout.take()
    }

    /// Wait for the backend and all filter stages to finish, join all stderr
    /// status reader threads, and return the classified [`PipelineExit`].
    pub fn wait_all(mut self) -> io::Result<PipelineExit> {
        let bstatus = self.backend.wait()?;
        let mut filter_exits = Vec::with_capacity(self.filters.len());
        for (i, f) in self.filters.iter_mut().enumerate() {
            let st = f.wait()?;
            filter_exits.push(FilterExit::from_status(i, f.id(), st));
        }
        self.join_status_threads();
        Ok(PipelineExit {
            backend: BackendExit::from_exit_status(bstatus),
            filters: filter_exits,
        })
    }

    /// Gracefully cancel the entire filter+backend job process group (`SIGTERM`,
    /// waiting up to `kill_delay` / `JobKillDelay`, then escalating to `SIGKILL`),
    /// reap all children, and join stderr status threads.
    pub fn kill_job(&mut self, kill_delay: Duration) -> io::Result<PipelineExit> {
        let mut sender = OsSignalSender;
        self.kill_job_with_sender(kill_delay, &mut sender)
    }

    /// Testable variant of [`Self::kill_job`] accepting a custom [`SignalSender`].
    pub fn kill_job_with_sender<S: SignalSender>(
        &mut self,
        kill_delay: Duration,
        sender: &mut S,
    ) -> io::Result<PipelineExit> {
        let res = exit::kill_children_gracefully(
            self.pgid,
            &mut self.filters,
            &mut self.backend,
            kill_delay,
            sender,
        )?;
        self.join_status_threads();
        Ok(res)
    }

    fn join_status_threads(&mut self) {
        for handle in self.status_threads.drain(..) {
            let _ = handle.join();
        }
    }
}

/// Running filter-only chain (used by `cupsfilter` and filter-only tests).
pub struct FilterRun {
    /// Running filter children in chain order.
    pub filters: Vec<Child>,
    /// Piped stdout of the last filter (when `Stdio::piped()` was requested).
    pub stdout: Option<ChildStdout>,
    pgid: Option<i32>,
    status_rx: Option<mpsc::Receiver<StatusMessage>>,
    status_threads: Vec<JoinHandle<()>>,
}

impl FilterRun {
    /// Process group ID of the filter chain, if `process_group` was enabled.
    #[must_use]
    pub const fn pgid(&self) -> Option<i32> {
        self.pgid
    }

    /// Take the internal status event receiver.
    pub fn take_status_receiver(&mut self) -> Option<mpsc::Receiver<StatusMessage>> {
        self.status_rx.take()
    }

    /// Wait for every filter in the chain to finish and join status threads.
    pub fn wait_all(mut self) -> io::Result<Vec<FilterExit>> {
        let mut exits = Vec::with_capacity(self.filters.len());
        for (i, f) in self.filters.iter_mut().enumerate() {
            let st = f.wait()?;
            exits.push(FilterExit::from_status(i, f.id(), st));
        }
        for handle in self.status_threads.drain(..) {
            let _ = handle.join();
        }
        Ok(exits)
    }
}

/// One document inside a multi-document print job (Wave-2b helper for `cupsd`).
#[derive(Debug, Clone)]
pub struct JobDocument {
    /// 1-based document number.
    pub number: u32,
    /// Optional document name.
    pub name: Option<String>,
    /// Spool data file path.
    pub data_file: PathBuf,
    /// Document MIME type (`document-format`).
    pub src_type: String,
    /// Resolved conversion chain for this document.
    pub chain: Vec<mime_db::Conv>,
}

/// Spawn spec for a print job.
#[derive(Debug, Clone)]
pub struct JobSpec {
    /// Queue name.
    pub printer: String,
    /// Job ID (`argv[1]`).
    pub job_id: i32,
    /// Submitting username (`argv[2]`).
    pub username: String,
    /// Job title (`argv[3]`).
    pub title: String,
    /// Requested copies (`argv[4]`).
    pub copies: i32,
    /// `argv[5]` — the `name=value name2=value2 ...` option string.
    pub options: String,
    /// Spool data file fed to the first filter (`argv[6]`/stdin).
    pub data_file: PathBuf,
    /// `document-format` of the spool file.
    pub src_type: String,
    /// Printer's `document-format-supported` target (the backend's input).
    pub dst_type: String,
    /// `DEVICE_URI` — resolved printer device (passed ONLY to the backend!).
    pub device_uri: String,
    /// `CUPS_SERVERBIN/filter` dir.
    pub filter_dir: PathBuf,
    /// `CUPS_SERVERBIN/backend` dir.
    pub backend_dir: PathBuf,
    /// Backend program name derived from device-uri scheme (`ipp`, `socket`...).
    pub backend: String,
    /// Extra env merged into every stage (`PassEnv`/`SetEnv` results; filtered
    /// against `cups_config::is_prohibited_env`).
    pub env: HashMap<String, String>,
}

impl JobSpec {
    /// Build the sanitized environment for a stage (`cupsdStartProcess` envp).
    ///
    /// Security invariants:
    /// - Starts from an empty environment (`Command::env_clear()`).
    /// - Filters `self.env` through `cups_config::is_prohibited_env` so dynamic
    ///   linker (`LD_*`), shell/interpreter, proxy, and scheduler vars cannot be injected.
    /// - **NEVER** passes `DEVICE_URI` (which may contain credentials) to filters
    ///   (`is_backend == false`); passes `DEVICE_URI` **ONLY** to the backend.
    #[must_use]
    pub fn build_stage_env(
        &self,
        stage_src_type: &str,
        final_dst_type: &str,
        is_backend: bool,
        opts: &SpawnOptions,
    ) -> HashMap<String, String> {
        let mut e = sanitize_extra_env(&self.env);

        // Scheduler-authoritative CUPS baseline variables (always overwrite extra env).
        e.insert("CHARSET".into(), "utf-8".into());
        e.insert("CONTENT_TYPE".into(), sanitize_env_value(stage_src_type));
        e.insert("CUPS_FILETYPE".into(), "document".into());
        e.insert(
            "FINAL_CONTENT_TYPE".into(),
            sanitize_env_value(final_dst_type),
        );
        e.insert("LANG".into(), "en_US.UTF-8".into());
        e.insert("PATH".into(), SAFE_STAGE_PATH.into());
        e.insert("PRINTER".into(), sanitize_env_value(&self.printer));
        e.insert(
            "PRINTER_INFO".into(),
            sanitize_env_value(opts.printer_info.as_deref().unwrap_or(&self.printer)),
        );
        e.insert(
            "PRINTER_LOCATION".into(),
            sanitize_env_value(opts.printer_location.as_deref().unwrap_or("")),
        );
        e.insert(
            "RIP_MAX_CACHE".into(),
            sanitize_env_value(opts.rip_max_cache.as_deref().unwrap_or("128m")),
        );
        e.insert("USER".into(), sanitize_env_value(&self.username));

        if let Some(ref p) = opts.ppd {
            e.insert("PPD".into(), sanitize_env_value(&p.to_string_lossy()));
        }
        if let Some(ref p) = opts.server_root {
            e.insert(
                "CUPS_SERVERROOT".into(),
                sanitize_env_value(&p.to_string_lossy()),
            );
        }
        if let Some(ref p) = opts.server_bin {
            e.insert(
                "CUPS_SERVERBIN".into(),
                sanitize_env_value(&p.to_string_lossy()),
            );
        }
        if let Some(ref p) = opts.data_dir {
            e.insert(
                "CUPS_DATADIR".into(),
                sanitize_env_value(&p.to_string_lossy()),
            );
        }
        if let Some(ref p) = opts.cache_dir {
            e.insert(
                "CUPS_CACHEDIR".into(),
                sanitize_env_value(&p.to_string_lossy()),
            );
        }
        if let Some(ref p) = opts.request_root {
            e.insert(
                "CUPS_REQUESTROOT".into(),
                sanitize_env_value(&p.to_string_lossy()),
            );
        }
        if let Some(ref p) = opts.state_dir {
            e.insert(
                "CUPS_STATEDIR".into(),
                sanitize_env_value(&p.to_string_lossy()),
            );
        }
        if let Some(ref p) = opts.temp_dir {
            e.insert("TMPDIR".into(), sanitize_env_value(&p.to_string_lossy()));
        }
        if let Some(num) = opts.document_number {
            e.insert("CUPS_DOCUMENT_NUMBER".into(), num.to_string());
        }
        if let Some(ref name) = opts.document_name {
            e.insert("CUPS_DOCUMENT_NAME".into(), sanitize_env_value(name));
        }

        // Security invariant: DEVICE_URI (potentially carrying credentials) goes
        // ONLY to the backend process and NEVER to untrusted filter stages.
        if is_backend {
            e.insert("DEVICE_URI".into(), sanitize_env_value(&self.device_uri));
        } else {
            e.remove("DEVICE_URI");
        }
        e
    }

    /// Build the CUPS filter/backend argument vector:
    /// `[job-id, user, title, copies, options]` plus optional `[data_file]`
    /// ONLY when `with_file == true`.
    #[must_use]
    pub fn argv(&self, with_file: bool) -> Vec<String> {
        let mut a = vec![
            self.job_id.to_string(),
            self.username.clone(),
            self.title.clone(),
            self.copies.to_string(),
            self.options.clone(),
        ];
        if with_file {
            a.push(self.data_file.to_string_lossy().into_owned());
        }
        a
    }

    /// Create a clone of this [`JobSpec`] targeting one document in a
    /// multi-document print job (with matching [`SpawnOptions`] metadata).
    #[must_use]
    pub fn for_document(
        &self,
        doc: &JobDocument,
        base_opts: &SpawnOptions,
    ) -> (Self, SpawnOptions) {
        let mut spec = self.clone();
        spec.data_file.clone_from(&doc.data_file);
        spec.src_type.clone_from(&doc.src_type);
        let mut opts = base_opts.clone();
        opts.document_number = Some(doc.number);
        opts.document_name.clone_from(&doc.name);
        (spec, opts)
    }

    /// Resolve the filter chain + spawn all stages (`start_job`) using default
    /// hardened [`SpawnOptions`].
    ///
    /// Preserves full backward compatibility with Wave-1 callers while enforcing
    /// all P0 security fixes (multi-filter `argv[6]`, executable containment &
    /// safety, `DEVICE_URI` stripping from filters, `statbuf` stderr parsing,
    /// and process-group isolation).
    pub fn spawn(&self, chain: &[mime_db::Conv]) -> io::Result<Pipeline> {
        self.spawn_with_options(chain, &SpawnOptions::default())
    }

    /// Resolve and spawn the full filter+backend pipeline with explicit [`SpawnOptions`].
    pub fn spawn_with_options(
        &self,
        chain: &[mime_db::Conv],
        opts: &SpawnOptions,
    ) -> io::Result<Pipeline> {
        // Validate backend URI scheme & executable BEFORE spawning any filters so
        // invalid URIs/backends fail fast without side effects.
        let expected_backend = try_backend_for_uri(&self.device_uri)?;
        let backend_name = if self.backend.is_empty() {
            expected_backend.as_str()
        } else {
            validate_program_name(&self.backend)?;
            self.backend.as_str()
        };
        let bprog = resolve_trusted_executable(&self.backend_dir, backend_name, &opts.security)?;
        let active_filters = self.resolve_active_filters(chain, &opts.security)?;
        let cups_exec = resolve_cups_exec(opts)?;

        let (tx, internal_rx) = make_status_channel(opts);
        let backchannel = opts.enable_backchannel.then(BackChannel::new).transpose()?;
        let sidechannel = opts.enable_sidechannel.then(SideChannel::new).transpose()?;

        let data = sys::open_readonly_nofollow(&self.data_file)?;
        let mut spawned = self.spawn_filter_stages(
            &active_filters,
            data.into(),
            opts,
            cups_exec.as_deref(),
            &tx,
            None,
        )?;

        // Backend: receives `argv(true)` ONLY when no filters ran (`input_is_file == true`).
        let backend_args = self.argv(spawned.input_is_file);
        let backend_env = self.build_stage_env(&self.src_type, &self.dst_type, true, opts);
        let mut bc = build_stage_command(
            &bprog,
            &self.printer,
            &backend_args,
            &backend_env,
            true,
            opts,
            cups_exec.as_deref(),
        );
        apply_process_group(&mut bc, opts.process_group, spawned.pgid);
        bc.stdin(spawned.next_stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut backend = match bc.spawn() {
            Ok(c) => c,
            Err(e) => {
                cleanup_partial_children(&mut spawned.filters);
                return Err(io::Error::new(
                    e.kind(),
                    format!("{}: {e}", bprog.display()),
                ));
            }
        };
        if opts.process_group && spawned.pgid.is_none() {
            spawned.pgid = i32::try_from(backend.id()).ok();
        }
        let backend_stdout = backend.stdout.take();
        if let Some(stderr) = backend.stderr.take() {
            spawned.status_threads.push(spawn_stderr_reader(
                stderr,
                format!("backend:{backend_name}"),
                true,
                tx,
            ));
        }

        Ok(Pipeline {
            filters: spawned.filters,
            backend,
            pgid: spawned.pgid,
            status_rx: internal_rx,
            status_threads: spawned.status_threads,
            backchannel,
            sidechannel,
            backend_stdout,
        })
    }

    /// Spawn ONLY the filter stages (no backend), directing the last filter's
    /// stdout to `final_stdout`. Used by `cupsfilter` and filter chain testing.
    pub fn spawn_filters_only(
        &self,
        chain: &[mime_db::Conv],
        opts: &SpawnOptions,
        final_stdout: Stdio,
    ) -> io::Result<FilterRun> {
        let active_filters = self.resolve_active_filters(chain, &opts.security)?;
        if active_filters.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "filter chain contains no executable filters",
            ));
        }

        let cups_exec = resolve_cups_exec(opts)?;
        let data = sys::open_readonly_nofollow(&self.data_file)?;
        let (tx, internal_rx) = make_status_channel(opts);
        let mut spawned = self.spawn_filter_stages(
            &active_filters,
            data.into(),
            opts,
            cups_exec.as_deref(),
            &tx,
            Some(final_stdout),
        )?;

        let stdout = spawned.filters.last_mut().and_then(|c| c.stdout.take());
        Ok(FilterRun {
            filters: spawned.filters,
            stdout,
            pgid: spawned.pgid,
            status_rx: internal_rx,
            status_threads: spawned.status_threads,
        })
    }

    fn spawn_filter_stages(
        &self,
        active_filters: &[Stage],
        initial_stdin: Stdio,
        opts: &SpawnOptions,
        cups_exec: Option<&Path>,
        tx: &mpsc::Sender<StatusMessage>,
        mut final_stdout: Option<Stdio>,
    ) -> io::Result<SpawnedFilters> {
        let mut filters: Vec<Child> = Vec::with_capacity(active_filters.len());
        let mut status_threads: Vec<JoinHandle<()>> = Vec::with_capacity(active_filters.len());
        let mut next_stdin = initial_stdin;
        let mut input_is_file = opts.input_is_file;
        let mut pgid: Option<i32> = None;
        let last_idx = active_filters.len().saturating_sub(1);
        let pipe_last_to_backend = final_stdout.is_none();

        for (idx, stage) in active_filters.iter().enumerate() {
            // P0 FIX: pass `data_file` as `argv[6]` ONLY to the first stage when
            // reading from a file; subsequent stages receive 5 args and read stdin!
            let stage_args = self.argv(input_is_file);
            let env = self.build_stage_env(&stage.src_type, &self.dst_type, false, opts);
            let mut cmd = build_stage_command(
                &stage.program,
                &self.printer,
                &stage_args,
                &env,
                false,
                opts,
                cups_exec,
            );
            apply_process_group(&mut cmd, opts.process_group, pgid);
            let stage_stdout = if idx == last_idx && !pipe_last_to_backend {
                final_stdout.take().unwrap_or_else(Stdio::inherit)
            } else {
                Stdio::piped()
            };
            cmd.stdin(next_stdin)
                .stdout(stage_stdout)
                .stderr(Stdio::piped());

            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    cleanup_partial_children(&mut filters);
                    return Err(io::Error::new(
                        e.kind(),
                        format!("{}: {e}", stage.program.display()),
                    ));
                }
            };
            if opts.process_group && pgid.is_none() {
                pgid = i32::try_from(child.id()).ok();
            }
            if let Some(stderr) = child.stderr.take() {
                let name = stage
                    .program
                    .file_name()
                    .map_or_else(|| "filter".into(), |n| n.to_string_lossy().into_owned());
                status_threads.push(spawn_stderr_reader(
                    stderr,
                    format!("filter[{idx}]:{name}"),
                    false,
                    tx.clone(),
                ));
            }
            next_stdin = if idx < last_idx || pipe_last_to_backend {
                child.stdout.take().map_or_else(Stdio::null, Into::into)
            } else {
                Stdio::null()
            };
            input_is_file = false;
            filters.push(child);
        }

        Ok(SpawnedFilters {
            filters,
            next_stdin,
            input_is_file,
            pgid,
            status_threads,
        })
    }

    /// Resolve and security-verify every non-passthrough (`!= "-"`) filter in `chain`.
    pub fn resolve_active_filters(
        &self,
        chain: &[mime_db::Conv],
        policy: &SecurityPolicy,
    ) -> io::Result<Vec<Stage>> {
        let mut stages = Vec::new();
        let mut current_type = self.src_type.clone();
        for conv in chain {
            if conv.program == "-" {
                if !conv.dst.contains('*') {
                    current_type.clone_from(&conv.dst);
                }
                continue;
            }
            let prog = resolve_trusted_executable(&self.filter_dir, &conv.program, policy)?;
            let src_type = if conv.src.contains('*') {
                current_type.clone()
            } else {
                conv.src.clone()
            };
            let dst_type = if conv.dst.contains('*') {
                self.dst_type.clone()
            } else {
                conv.dst.clone()
            };
            stages.push(Stage {
                program: prog,
                src_type,
                dst_type: dst_type.clone(),
            });
            current_type = dst_type;
        }
        Ok(stages)
    }
}

struct SpawnedFilters {
    filters: Vec<Child>,
    next_stdin: Stdio,
    input_is_file: bool,
    pgid: Option<i32>,
    status_threads: Vec<JoinHandle<()>>,
}

fn make_status_channel(
    opts: &SpawnOptions,
) -> (
    mpsc::Sender<StatusMessage>,
    Option<mpsc::Receiver<StatusMessage>>,
) {
    if let Some(ext) = &opts.status_tx {
        (ext.clone(), None)
    } else {
        let (tx, rx) = mpsc::channel();
        (tx, Some(rx))
    }
}

fn resolve_cups_exec(opts: &SpawnOptions) -> io::Result<Option<PathBuf>> {
    if opts.sandbox.mode == cups_config::Sandboxing::Off {
        return Ok(None);
    }
    let Some(ref exec_path) = opts.sandbox.cups_exec_path else {
        return Ok(None);
    };
    let parent = exec_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "cups-exec path has no parent directory",
        )
    })?;
    let name = exec_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid cups-exec filename"))?;
    let verified = resolve_trusted_executable(parent, name, &opts.security)?;
    Ok(Some(verified))
}

fn build_stage_command(
    program: &Path,
    argv0: &str,
    stage_args: &[String],
    env: &HashMap<String, String>,
    is_backend: bool,
    opts: &SpawnOptions,
    cups_exec: Option<&Path>,
) -> Command {
    let (eff_user, eff_group) = current_euid_egid();
    let (run_user, run_group) = if eff_user == 0 {
        (
            opts.sandbox.uid.unwrap_or(eff_user),
            opts.sandbox.gid.unwrap_or(eff_group),
        )
    } else {
        (eff_user, eff_group)
    };

    if let Some(exec_bin) = cups_exec {
        let profile = sandbox_profile_name(opts.sandbox.mode, is_backend);
        let exec_args = build_cups_exec_args(
            profile,
            run_user,
            run_group,
            opts.sandbox.nice,
            program,
            argv0,
            stage_args,
        );
        let mut cmd = Command::new(exec_bin);
        cmd.args(exec_args).env_clear().envs(env);
        return cmd;
    }

    let mut cmd = Command::new(program);
    cmd.arg0(argv0).args(stage_args).env_clear().envs(env);
    // When running as root without `cups-exec`, still honor User/Group privilege drop.
    if eff_user == 0 {
        if let Some(gid) = opts.sandbox.gid {
            cmd.gid(gid);
        }
        if let Some(uid) = opts.sandbox.uid {
            if uid != 0 {
                cmd.uid(uid);
            }
        }
    }
    cmd
}

fn apply_process_group(cmd: &mut Command, enabled: bool, existing_pgid: Option<i32>) {
    if enabled {
        cmd.process_group(existing_pgid.unwrap_or(0));
    }
}

fn cleanup_partial_children(children: &mut Vec<Child>) {
    for c in children.iter_mut() {
        let _ = c.kill();
        let _ = c.wait();
    }
    children.clear();
}

/// The backend name for a device URI: strictly validated RFC 3986 scheme part,
/// with CUPS's historical aliases (`http`/`https`/`ipps` -> `ipp`).
///
/// Returns an empty string for malformed or malicious URIs (which fails closed
/// during executable resolution). Use [`try_backend_for_uri`] for detailed errors.
#[must_use]
pub fn backend_for_uri(device_uri: &str) -> String {
    try_backend_for_uri(device_uri).unwrap_or_default()
}
