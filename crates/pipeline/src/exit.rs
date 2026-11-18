//! Backend/filter exit-code classification (`CUPS_BACKEND_*`) and graceful
//! `SIGTERM` -> `SIGKILL` process-group job cancellation (`JobKillDelay`).

use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Classification of a CUPS backend exit status (`cups/backend.h` `CUPS_BACKEND_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendExit {
    /// `CUPS_BACKEND_OK` (0) — job completed successfully.
    Ok,
    /// `CUPS_BACKEND_FAILED` (1) — generic failure; apply queue `ErrorPolicy`.
    Failed,
    /// `CUPS_BACKEND_AUTH_REQUIRED` (2) — hold job for authentication.
    AuthRequired,
    /// `CUPS_BACKEND_HOLD` (3) — hold the job.
    Hold,
    /// `CUPS_BACKEND_STOP` (4) — stop the printer queue.
    Stop,
    /// `CUPS_BACKEND_CANCEL` (5) — cancel the job.
    Cancel,
    /// `CUPS_BACKEND_RETRY` (6) — retry the job after `JobRetryInterval`.
    Retry,
    /// `CUPS_BACKEND_RETRY_CURRENT` (7) — retry the current job immediately.
    RetryCurrent,
    /// Any other non-zero exit code (treated like `Failed`).
    Unknown(i32),
    /// Process was terminated by a UNIX signal.
    Signal(i32),
}

impl BackendExit {
    /// Classify a raw backend exit code (`0..=7` or unknown).
    #[must_use]
    pub const fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::Failed,
            2 => Self::AuthRequired,
            3 => Self::Hold,
            4 => Self::Stop,
            5 => Self::Cancel,
            6 => Self::Retry,
            7 => Self::RetryCurrent,
            other => Self::Unknown(other),
        }
    }

    /// Classify a process [`ExitStatus`].
    #[must_use]
    pub fn from_exit_status(status: ExitStatus) -> Self {
        if let Some(code) = status.code() {
            Self::from_code(code)
        } else if let Some(sig) = status.signal() {
            Self::Signal(sig)
        } else {
            Self::Failed
        }
    }

    /// Returns `true` only when the backend exited with `CUPS_BACKEND_OK` (0).
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Returns `true` for `Retry` or `RetryCurrent`.
    #[must_use]
    pub const fn should_retry(self) -> bool {
        matches!(self, Self::Retry | Self::RetryCurrent)
    }

    /// Returns `true` for `Stop`.
    #[must_use]
    pub const fn should_stop_printer(self) -> bool {
        matches!(self, Self::Stop)
    }

    /// Returns `true` for `Hold` or `AuthRequired`.
    #[must_use]
    pub const fn should_hold_job(self) -> bool {
        matches!(self, Self::Hold | Self::AuthRequired)
    }

    /// Returns `true` for `Cancel`.
    #[must_use]
    pub const fn should_cancel_job(self) -> bool {
        matches!(self, Self::Cancel)
    }

    /// Standard IPP `job-state-reasons` keyword corresponding to this exit.
    #[must_use]
    pub const fn ipp_job_state_reason(self) -> &'static str {
        match self {
            Self::Ok => "job-completed-successfully",
            Self::AuthRequired => "cups-held-for-authentication",
            Self::Hold => "job-hold-until-specified",
            Self::Cancel => "job-canceled-at-device",
            Self::Retry | Self::RetryCurrent => "job-restartable",
            Self::Stop | Self::Failed | Self::Unknown(_) | Self::Signal(_) => {
                "job-aborted-by-system"
            }
        }
    }
}

/// Exit outcome of a single filter stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterExit {
    /// 0-based filter index in the chain.
    pub index: usize,
    /// OS process ID of the filter.
    pub pid: u32,
    /// Exit code, if exited normally.
    pub code: Option<i32>,
    /// Terminating signal, if killed by a signal.
    pub signal: Option<i32>,
}

impl FilterExit {
    /// Construct from a filter's index, PID, and [`ExitStatus`].
    #[must_use]
    pub fn from_status(index: usize, pid: u32, status: ExitStatus) -> Self {
        Self {
            index,
            pid,
            code: status.code(),
            signal: status.signal(),
        }
    }

    /// Returns `true` iff the filter exited normally with code 0.
    #[must_use]
    pub const fn success(self) -> bool {
        matches!(self.code, Some(0))
    }
}

/// Combined exit outcome of a completed or killed pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineExit {
    /// Classified backend exit status.
    pub backend: BackendExit,
    /// Exit status of every filter stage in chain order.
    pub filters: Vec<FilterExit>,
}

impl PipelineExit {
    /// Returns `true` iff the backend and every filter succeeded.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.backend.is_ok() && self.filters.iter().all(|f| f.success())
    }
}

/// POSIX signal sent during job cancellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillSignal {
    /// Graceful termination request (`SIGTERM`).
    Term,
    /// Unconditional termination (`SIGKILL`).
    Kill,
}

impl KillSignal {
    #[must_use]
    const fn flag(self) -> &'static str {
        match self {
            Self::Term => "-TERM",
            Self::Kill => "-KILL",
        }
    }
}

/// Signal delivery abstraction for safe process-group cancellation & unit tests.
pub trait SignalSender {
    /// Deliver `sig` to process group `-pgid` (`pgid > 1`).
    fn signal_group(&mut self, pgid: i32, sig: KillSignal) -> io::Result<()>;
    /// Deliver `sig` to a single `pid` (`pid > 1`).
    fn signal_pid(&mut self, pid: u32, sig: KillSignal) -> io::Result<()>;
}

/// Safe OS signal sender invoking `/bin/kill` (or `/usr/bin/kill`) with a clean
/// environment, avoiding `unsafe` `libc::killpg` while still signaling the full
/// job process group.
pub struct OsSignalSender;

fn find_kill_binary() -> &'static Path {
    for p in ["/bin/kill", "/usr/bin/kill"] {
        let path = Path::new(p);
        if path.is_file() {
            return path;
        }
    }
    Path::new("kill")
}

fn invoke_kill(target: &str, sig: KillSignal) -> io::Result<()> {
    let status = Command::new(find_kill_binary())
        .env_clear()
        .args([sig.flag(), "--", target])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "kill {} {target} exited with {status}",
            sig.flag()
        )))
    }
}

/// Send `sig` to process group `pgid` (`pgid` must be `> 1`).
pub fn kill_process_group(pgid: i32, sig: KillSignal) -> io::Result<()> {
    if pgid <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to signal unsafe process group {pgid}"),
        ));
    }
    invoke_kill(&format!("-{pgid}"), sig)
}

/// Send `sig` to a single process `pid` (`pid` must be `> 1`).
pub fn kill_pid(pid: u32, sig: KillSignal) -> io::Result<()> {
    if pid <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to signal unsafe pid {pid}"),
        ));
    }
    invoke_kill(&pid.to_string(), sig)
}

impl SignalSender for OsSignalSender {
    fn signal_group(&mut self, pgid: i32, sig: KillSignal) -> io::Result<()> {
        kill_process_group(pgid, sig)
    }

    fn signal_pid(&mut self, pid: u32, sig: KillSignal) -> io::Result<()> {
        kill_pid(pid, sig)
    }
}

/// Gracefully terminate `filters` and `backend` using `SIGTERM`, wait up to
/// `kill_delay` (CUPS `JobKillDelay`), then escalate to `SIGKILL` (plus
/// `Child::kill` fallback) and reap every child process.
pub fn kill_children_gracefully<S: SignalSender>(
    pgid: Option<i32>,
    filters: &mut [Child],
    backend: &mut Child,
    kill_delay: Duration,
    sender: &mut S,
) -> io::Result<PipelineExit> {
    let mut filter_statuses: Vec<Option<ExitStatus>> = vec![None; filters.len()];
    let mut backend_status: Option<ExitStatus> = None;

    // 1. Send SIGTERM to the whole process group (or individual PIDs).
    if let Some(g) = pgid {
        let _ = sender.signal_group(g, KillSignal::Term);
    } else {
        for f in filters.iter() {
            let _ = sender.signal_pid(f.id(), KillSignal::Term);
        }
        let _ = sender.signal_pid(backend.id(), KillSignal::Term);
    }

    // 2. Poll until all children exit or `kill_delay` expires.
    let deadline = Instant::now() + kill_delay;
    loop {
        poll_children(filters, &mut filter_statuses, backend, &mut backend_status);
        if backend_status.is_some() && filter_statuses.iter().all(Option::is_some) {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
    }

    // 3. Escalate to SIGKILL for any surviving children / grandchildren.
    if backend_status.is_none() || filter_statuses.iter().any(Option::is_none) {
        if let Some(g) = pgid {
            let _ = sender.signal_group(g, KillSignal::Kill);
        }
        for (i, f) in filters.iter_mut().enumerate() {
            if filter_statuses[i].is_none() {
                let _ = f.kill();
            }
        }
        if backend_status.is_none() {
            let _ = backend.kill();
        }
    }

    // 4. Reap every child so no zombies remain.
    let mut filter_exits = Vec::with_capacity(filters.len());
    for (i, f) in filters.iter_mut().enumerate() {
        let status = match filter_statuses[i] {
            Some(s) => s,
            None => f.wait()?,
        };
        filter_exits.push(FilterExit::from_status(i, f.id(), status));
    }
    let bstatus = match backend_status {
        Some(s) => s,
        None => backend.wait()?,
    };

    Ok(PipelineExit {
        backend: BackendExit::from_exit_status(bstatus),
        filters: filter_exits,
    })
}

fn poll_children(
    filters: &mut [Child],
    filter_statuses: &mut [Option<ExitStatus>],
    backend: &mut Child,
    backend_status: &mut Option<ExitStatus>,
) {
    for (i, f) in filters.iter_mut().enumerate() {
        if filter_statuses[i].is_none() {
            if let Ok(Some(st)) = f.try_wait() {
                filter_statuses[i] = Some(st);
            }
        }
    }
    if backend_status.is_none() {
        if let Ok(Some(st)) = backend.try_wait() {
            *backend_status = Some(st);
        }
    }
}
