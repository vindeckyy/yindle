//! Real event-driven async job scheduler (`scheduler/job.c`).
//!
//! Features:
//! - Event-driven wakeup (`tokio::sync::Notify`) triggered on job submission,
//!   completion, cancellation, printer resume/modify, and job release/move.
//! - Periodic housekeeping timer: `hold-until` release, `MaxHoldTime`,
//!   delayed retries (`JobRetryInterval`), `MaxJobTime`, `PreserveJobFiles`,
//!   `PreserveJobHistory`, `AutoPurgeJobs`, `MaxJobs`, `DirtyCleanInterval`,
//!   and on-demand `IdleExitTimeout`.
//! - Concurrent multi-printer dispatch per tick with `FilterLimit` budget
//!   enforcement and `MaxActiveJobs` cap.
//! - Strict paused/stopped check (`p.state == STOPPED || !p.accepting`).
//! - Class routing via `Registry::resolve_class_member` + round-robin selection.
//! - Atomic TOCTOU-free `Pending -> Processing` transition under write lock.
//! - Multi-document execution (`JobSpec::for_document`), real job options
//!   (`format_job_options`), sanitized `PassEnv`/`SetEnv` (`is_prohibited_env`),
//!   `SpawnOptions::from_cups_config`, and `DataDir`-based PPD/DRV resolution.
//! - Live cancellation via `ops::Ctx::on_cancel_job` -> `Pipeline::kill_job(JobKillDelay)`
//!   without ever overwriting a `Canceled` job back to `Completed`.
//! - Full `BackendExit` + `ErrorPolicy` (`retry-job`, `retry-current-job`,
//!   `abort-job`, `stop-printer`) and live `StatusEvent` consumption
//!   (`STATE:`, `INFO:`, `PAGE:`, `ATTR:`, `PPD:`).

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use cups_config::{Config, PrintcapFormat, Sandboxing};
use cups_dbus::Notifier;
use cups_log::Level;
use events::{Event, Subscriptions};
use ipp_codec::{tags, Attribute, Value};
use job::{Job, JobState, Jobs};
use mime_db::MimeDb;
use ops::{CancelJobHook, EventSignal};
use pipeline::{
    format_job_options, parse_ppd_filters, try_backend_for_uri, BackendExit, JobDocument, JobSpec,
    LogSeverity, PageEvent, Pipeline, PipelineExit, SpawnOptions, StateChange, StatusEvent,
    StatusMessage,
};
use printer::{pstate, Printer, Registry};
use tokio::sync::{watch, Notify};

use crate::logging::{emit_dbus_event, map_pipeline_severity, LogManager};
use crate::metrics::{FilterCostGuard, Metrics};

/// Default `PageLogFormat` when unspecified in `cupsd.conf`.
const DEFAULT_PAGE_LOG_FORMAT: &str =
    "%p %u %j %T %P %C %{job-billing} %{job-originating-host-name} %{job-name} %{media} %{sides}";

/// Control handle for one currently executing job pipeline.
struct ActiveJobHandle {
    printer: String,
    started_at: Instant,
    cancel_flag: Arc<AtomicBool>,
    timeout_flag: Arc<AtomicBool>,
}

/// Per-job retry bookkeeping for `JobRetryLimit` / `JobRetryInterval`.
#[derive(Debug, Clone, Copy, Default)]
struct RetryInfo {
    attempts: u32,
    next_retry_at: i64,
}

/// Runtime knobs for the scheduler loop (configurable for fast unit/integration tests).
#[derive(Debug, Clone, Copy)]
pub struct SchedulerOptions {
    /// Housekeeping poll interval (default 1s).
    pub housekeeping_interval: Duration,
    /// On-demand `-l` mode (enables `IdleExitTimeout`).
    pub on_demand: bool,
}

impl Default for SchedulerOptions {
    fn default() -> Self {
        Self {
            housekeeping_interval: Duration::from_secs(1),
            on_demand: false,
        }
    }
}

/// Shared event-driven job scheduler.
pub struct Scheduler {
    cfg: Arc<RwLock<Arc<Config>>>,
    registry: Arc<RwLock<Registry>>,
    jobs: Arc<RwLock<Jobs>>,
    mime: Arc<RwLock<Arc<MimeDb>>>,
    subs: Arc<RwLock<Subscriptions>>,
    log: Arc<LogManager>,
    metrics: Arc<Metrics>,
    dbus: Arc<Notifier>,
    server_root: Arc<RwLock<PathBuf>>,
    wakeup: Arc<Notify>,
    active_jobs: Arc<Mutex<HashMap<i32, ActiveJobHandle>>>,
    retries: Arc<Mutex<HashMap<i32, RetryInfo>>>,
    class_rr: Arc<Mutex<HashMap<String, usize>>>,
    dirty: Arc<AtomicBool>,
    last_activity: Arc<Mutex<Instant>>,
    options: SchedulerOptions,
}

impl Scheduler {
    /// Construct a new [`Scheduler`] attached to daemon state.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: Arc<RwLock<Arc<Config>>>,
        registry: Arc<RwLock<Registry>>,
        jobs: Arc<RwLock<Jobs>>,
        mime: Arc<RwLock<Arc<MimeDb>>>,
        subs: Arc<RwLock<Subscriptions>>,
        log: Arc<LogManager>,
        metrics: Arc<Metrics>,
        dbus: Arc<Notifier>,
        server_root: Arc<RwLock<PathBuf>>,
        options: SchedulerOptions,
    ) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            registry,
            jobs,
            mime,
            subs,
            log,
            metrics,
            dbus,
            server_root,
            wakeup: Arc::new(Notify::new()),
            active_jobs: Arc::new(Mutex::new(HashMap::new())),
            retries: Arc::new(Mutex::new(HashMap::new())),
            class_rr: Arc::new(Mutex::new(HashMap::new())),
            dirty: Arc::new(AtomicBool::new(false)),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            options,
        })
    }

    /// Wake the scheduler loop immediately (job submitted/released/completed, printer resumed).
    pub fn notify(&self) {
        self.touch_activity();
        self.wakeup.notify_one();
    }

    /// Record daemon activity (resets `IdleExitTimeout` clock).
    pub fn touch_activity(&self) {
        *self
            .last_activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
    }

    /// Mark persistent config/cache state dirty so `DirtyCleanInterval` flushes it.
    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
    }

    /// Return an [`ops::CancelJobHook`] wired to [`Self::cancel_job`].
    #[must_use]
    pub fn cancel_hook(self: &Arc<Self>) -> CancelJobHook {
        let sched = Arc::clone(self);
        Arc::new(move |job_id: u32| {
            if let Ok(id) = i32::try_from(job_id) {
                sched.cancel_job(id);
            }
        })
    }

    /// Signal an active running job to cancel via `Pipeline::kill_job(JobKillDelay)`.
    pub fn cancel_job(&self, job_id: i32) {
        self.touch_activity();
        let active = self
            .active_jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(handle) = active.get(&job_id) {
            handle.cancel_flag.store(true, Ordering::SeqCst);
            self.log.err(
                Level::Info,
                format!("[Job {job_id}] Cancellation requested for active pipeline."),
            );
        }
        drop(active);
        self.retries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&job_id);
        self.wakeup.notify_one();
    }

    /// Number of currently executing job pipelines.
    #[must_use]
    pub fn active_job_count(&self) -> usize {
        self.active_jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Snapshot current config.
    fn current_cfg(&self) -> Arc<Config> {
        Arc::clone(
            &self
                .cfg
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Snapshot current MIME database.
    fn current_mime(&self) -> Arc<MimeDb> {
        Arc::clone(
            &self
                .mime
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Snapshot current `ServerRoot`.
    fn current_server_root(&self) -> PathBuf {
        self.server_root
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Run the event-driven scheduler loop until `shutdown_rx` signals `true`
    /// (or `IdleExitTimeout` fires in on-demand mode, sending `true` on `idle_exit_tx`).
    pub async fn run(
        self: Arc<Self>,
        mut shutdown_rx: watch::Receiver<bool>,
        idle_exit_tx: Option<watch::Sender<bool>>,
    ) {
        let mut interval = tokio::time::interval(self.options.housekeeping_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_dirty_flush = Instant::now();

        // Immediate boot tick to dispatch recovered/pending jobs right away.
        self.dispatch_pending();

        loop {
            if *shutdown_rx.borrow() {
                break;
            }
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                () = self.wakeup.notified() => {
                    self.dispatch_pending();
                }
                _ = interval.tick() => {
                    self.run_housekeeping(&mut last_dirty_flush);
                    self.dispatch_pending();
                    if self.should_idle_exit() {
                        self.log.err(Level::Info, "IdleExitTimeout reached; initiating graceful exit.");
                        if let Some(ref tx) = idle_exit_tx {
                            let _ = tx.send(true);
                        }
                        break;
                    }
                }
            }
        }
    }

    /// Gracefully cancel and wait for all active jobs during daemon shutdown.
    pub async fn shutdown_active_jobs(&self, max_wait: Duration) {
        {
            let active = self
                .active_jobs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (job_id, handle) in active.iter() {
                handle.cancel_flag.store(true, Ordering::SeqCst);
                self.log.err(
                    Level::Info,
                    format!("[Job {job_id}] Stopping active job for scheduler shutdown."),
                );
            }
        }
        let deadline = Instant::now() + max_wait;
        while self.active_job_count() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Flush `printers.conf`, `classes.conf`, `subscriptions.conf`, `job.cache`,
    /// and optional `Printcap` atomically to disk.
    pub fn flush_state(&self) {
        let cfg = self.current_cfg();
        let server_root = self.current_server_root();
        let perm = cfg.files.config_file_perm;

        {
            let reg = self
                .registry
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Err(e) = reg.save_all(&server_root, perm) {
                self.log.err(
                    Level::Warn,
                    format!("Unable to save printers/classes state: {e}"),
                );
            }
            if let Some(ref printcap) = cfg.files.printcap {
                if !printcap.is_empty() && !printcap.eq_ignore_ascii_case("none") {
                    write_printcap(Path::new(printcap), cfg.files.printcap_format, &reg);
                }
            }
        }

        {
            let subs = self
                .subs
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Err(e) = subs.save_file_with_mode(&server_root.join("subscriptions.conf"), perm)
            {
                self.log.err(
                    Level::Warn,
                    format!("Unable to save subscriptions.conf: {e}"),
                );
            }
        }

        if let Some(ref cache_dir) = cfg.files.cache_dir {
            let cdir = PathBuf::from(cache_dir);
            if std::fs::create_dir_all(&cdir).is_ok() {
                let jobs = self
                    .jobs
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Err(e) = jobs.save_cache(&cdir.join("job.cache")) {
                    self.log
                        .err(Level::Warn, format!("Unable to save job.cache: {e}"));
                }
            }
        }

        self.dirty.store(false, Ordering::Release);
    }

    /// Execute one housekeeping pass (subscription expiry, hold-until release,
    /// `MaxJobTime`, `PreserveJobFiles`/`PreserveJobHistory`/`AutoPurgeJobs`, `DirtyCleanInterval`).
    pub fn run_housekeeping(&self, last_dirty_flush: &mut Instant) {
        let cfg = self.current_cfg();
        let now_ts = job::now();
        let request_root = request_root_from(&cfg);

        // 1. Expire subscriptions.
        self.subs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expire();

        // 2. Enforce `MaxJobTime` on running jobs.
        if cfg.cupsd.max_job_time > 0 {
            let max_dur = Duration::from_secs(u64::try_from(cfg.cupsd.max_job_time).unwrap_or(0));
            let active = self
                .active_jobs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (job_id, handle) in active.iter() {
                if handle.started_at.elapsed() >= max_dur
                    && !handle.timeout_flag.swap(true, Ordering::SeqCst)
                {
                    self.log.err(
                        Level::Error,
                        format!(
                            "[Job {job_id}] Exceeded MaxJobTime ({}s); aborting.",
                            cfg.cupsd.max_job_time
                        ),
                    );
                }
            }
        }

        // 3. Release due `hold-until` jobs & enforce `MaxHoldTime`.
        self.housekeep_held_jobs(&cfg, &request_root, now_ts);

        // 4. Enforce `PreserveJobFiles`, `PreserveJobHistory`, `AutoPurgeJobs`, `MaxJobs`.
        self.housekeep_job_retention(&cfg, &request_root, now_ts);

        // 5. Periodic `DirtyCleanInterval` state flush.
        let clean_interval =
            Duration::from_secs(u64::try_from(cfg.cupsd.dirty_clean_interval.max(1)).unwrap_or(30));
        if self.dirty.load(Ordering::Acquire) && last_dirty_flush.elapsed() >= clean_interval {
            self.flush_state();
            *last_dirty_flush = Instant::now();
        }
    }

    fn housekeep_held_jobs(&self, cfg: &Config, request_root: &Path, now_ts: i64) {
        let max_hold = i64::from(cfg.cupsd.max_hold_time);
        let mut released_any = false;
        let mut jg = self
            .jobs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for j in jg.values_mut() {
            if j.state != JobState::PendingHeld {
                continue;
            }
            if let Some(ref hold) = j.hold_until {
                if is_hold_until_due(hold, now_ts) {
                    j.state = JobState::Pending;
                    j.hold_until = None;
                    j.reasons.retain(|r| r != "job-hold-until-specified");
                    if j.reasons.is_empty() {
                        j.reasons.push("none".into());
                    }
                    let _ = j.save(request_root);
                    released_any = true;
                    continue;
                }
            }
            if max_hold > 0 && now_ts.saturating_sub(j.created_at) >= max_hold {
                j.state = JobState::Canceled;
                j.completed_at = Some(now_ts);
                j.reasons = vec!["job-canceled-by-system".into()];
                let _ = j.save(request_root);
                self.metrics.record_job_terminal("canceled", None);
            }
        }
        drop(jg);
        if released_any {
            self.mark_dirty();
        }
    }

    fn housekeep_job_retention(&self, cfg: &Config, request_root: &Path, now_ts: i64) {
        let preserve_files = i64::from(cfg.cupsd.preserve_job_files);
        let preserve_history = i64::from(cfg.cupsd.preserve_job_history);
        let auto_purge = cfg.cupsd.job_auto_purge;
        let max_jobs = usize::try_from(cfg.cupsd.max_jobs.max(0)).unwrap_or(0);

        let mut purge_ids: Vec<i32> = Vec::new();
        let mut jg = self
            .jobs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        for j in jg.values_mut() {
            if !j.state.is_final() {
                continue;
            }
            let done_ts = j.completed_at.unwrap_or(j.created_at);
            let age = now_ts.saturating_sub(done_ts);

            // Clean spool data files (`PreserveJobFiles`).
            if cfg.cupsd.preserve_job_files < i32::MAX
                && age >= preserve_files
                && !j.files.is_empty()
            {
                for f in &j.files {
                    let _ = std::fs::remove_file(Job::data_path(request_root, j.id, f.num));
                }
                j.files.clear();
                let _ = j.save(request_root);
            }

            // Purge entire job history (`PreserveJobHistory` / `AutoPurgeJobs`).
            let history_expired = cfg.cupsd.preserve_job_history == 0
                || (cfg.cupsd.preserve_job_history < i32::MAX && age >= preserve_history);
            if history_expired || (auto_purge && cfg.cupsd.preserve_job_history == 0) {
                purge_ids.push(j.id);
            }
        }

        for id in &purge_ids {
            let _ = jg.remove(request_root, *id);
        }

        // Enforce `MaxJobs` cap by purging oldest terminal jobs first.
        if max_jobs > 0 && jg.by_id.len() > max_jobs {
            let excess = jg.by_id.len() - max_jobs;
            let mut terminal: Vec<(i64, i32)> = jg
                .by_id
                .values()
                .filter(|j| j.state.is_final())
                .map(|j| (j.completed_at.unwrap_or(j.created_at), j.id))
                .collect();
            terminal.sort_unstable();
            for (_, id) in terminal.into_iter().take(excess) {
                let _ = jg.remove(request_root, id);
                purge_ids.push(id);
            }
        }
        drop(jg);

        if !purge_ids.is_empty() {
            self.mark_dirty();
        }
    }

    fn should_idle_exit(&self) -> bool {
        if !self.options.on_demand {
            return false;
        }
        let cfg = self.current_cfg();
        if cfg.cupsd.idle_exit_timeout <= 0 {
            return false;
        }
        if self.metrics.active_clients() > 0 || self.active_job_count() > 0 {
            return false;
        }
        let has_non_final = self
            .jobs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active()
            .next()
            .is_some();
        if has_non_final {
            return false;
        }
        let idle_for = self
            .last_activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .elapsed();
        idle_for >= Duration::from_secs(u64::try_from(cfg.cupsd.idle_exit_timeout).unwrap_or(60))
    }

    /// Dispatch ALL eligible pending jobs across all idle/accepting printers concurrently!
    #[allow(clippy::too_many_lines)]
    pub fn dispatch_pending(self: &Arc<Self>) -> usize {
        let cfg = self.current_cfg();
        let mime = self.current_mime();
        let server_root = self.current_server_root();
        let request_root = request_root_from(&cfg);
        let server_bin = server_bin_from(&cfg);
        let data_dir = data_dir_from(&cfg);
        let now_ts = job::now();
        let max_active = usize::try_from(cfg.cupsd.max_active_jobs.max(0)).unwrap_or(0);

        // Step 1: Collect candidate pending jobs sorted by (priority DESC, id ASC).
        let candidates: Vec<(i32, i32, String)> = {
            let jg = self
                .jobs
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let retries = self
                .retries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut list: Vec<(i32, i32, String)> = jg
                .active()
                .filter(|j| {
                    j.state == JobState::Pending
                        && j.backend_pid.is_none()
                        && !j.files.is_empty()
                        && retries.get(&j.id).is_none_or(|r| r.next_retry_at <= now_ts)
                })
                .map(|j| (j.priority, j.id, j.dest.clone()))
                .collect();
            list.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            list
        };

        if candidates.is_empty() {
            return 0;
        }

        // Track concrete printers already busy with a Processing job.
        let mut busy_printers: HashSet<String> = {
            let active = self
                .active_jobs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            active.values().map(|h| h.printer.clone()).collect()
        };
        {
            let jg = self
                .jobs
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for j in jg.active() {
                if j.state == JobState::Processing {
                    busy_printers.insert(j.dest.clone());
                }
            }
        }

        let mut dispatched = 0usize;

        for (_prio, job_id, dest_name) in candidates {
            if max_active > 0 && self.active_job_count() >= max_active {
                break;
            }

            // Step 2: Resolve concrete printer (direct or class member via Registry::resolve_class_member).
            let Some(concrete_printer) = self.resolve_target_printer(&dest_name, &busy_printers)
            else {
                continue;
            };

            // Step 3: Resolve PPD, filter chains across ALL job files, and total filter cost.
            let job_snapshot = {
                let jg = self
                    .jobs
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                jg.get(job_id)
                    .filter(|j| j.state == JobState::Pending && !j.files.is_empty())
                    .cloned()
            };
            let Some(job_snap) = job_snapshot else {
                continue;
            };

            let ppd_path = server_root
                .join("ppd")
                .join(format!("{}.ppd", concrete_printer.name));
            let ppd_text =
                load_printer_ppd(&concrete_printer, &server_root, &server_bin, &data_dir);
            let (dst_type, ppd_driver_filter) = resolve_ppd_target(ppd_text.as_deref());

            let mut docs = Vec::with_capacity(job_snap.files.len());
            let mut total_cost = 0u64;
            for f in &job_snap.files {
                let data_path = Job::data_path(&request_root, job_id, f.num);
                let mut chain: Vec<mime_db::Conv> = mime
                    .filter_chain(&f.filetype, &dst_type, 0)
                    .unwrap_or_default()
                    .into_iter()
                    .cloned()
                    .collect();
                if let Some(ref drv) = ppd_driver_filter {
                    chain.push(drv.clone());
                }
                for conv in &chain {
                    if conv.program != "-" {
                        total_cost = total_cost.saturating_add(u64::from(conv.cost));
                    }
                }
                docs.push(JobDocument {
                    number: f.num,
                    name: (!f.name.is_empty()).then(|| f.name.clone()),
                    data_file: data_path,
                    src_type: f.filetype.clone(),
                    chain,
                });
            }

            // Step 4: Enforce `FilterLimit` budget BEFORE transitioning job state.
            let Some(cost_guard) =
                FilterCostGuard::try_acquire(Arc::clone(&self.metrics), total_cost)
            else {
                self.log.err(
                    Level::Debug,
                    format!(
                        "[Job {job_id}] Deferred: FilterLimit {} reached (current={}, needed={total_cost}).",
                        self.metrics.filter_limit(),
                        self.metrics.filter_cost_current()
                    ),
                );
                continue;
            };

            // Step 5: Atomically claim job (`Pending -> Processing`) under write lock (eliminates TOCTOU!).
            let claimed = {
                let mut jg = self
                    .jobs
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match jg.get_mut(job_id) {
                    Some(j) if j.state == JobState::Pending && j.backend_pid.is_none() => {
                        j.state = JobState::Processing;
                        j.processing_at = Some(now_ts);
                        j.reasons = vec!["job-printing".into()];
                        let _ = j.save(&request_root);
                        true
                    }
                    _ => false,
                }
            };
            if !claimed {
                continue; // `cost_guard` is released on drop.
            }

            busy_printers.insert(concrete_printer.name.clone());

            // Mark concrete printer as Processing.
            {
                let mut reg = self
                    .registry
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(p) = reg.find_mut(&concrete_printer.name) {
                    if p.state != pstate::STOPPED {
                        p.state = pstate::PROCESSING;
                        p.state_time = now_ts;
                    }
                }
            }

            let cancel_flag = Arc::new(AtomicBool::new(false));
            let timeout_flag = Arc::new(AtomicBool::new(false));
            {
                let mut active = self
                    .active_jobs
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                active.insert(
                    job_id,
                    ActiveJobHandle {
                        printer: concrete_printer.name.clone(),
                        started_at: Instant::now(),
                        cancel_flag: Arc::clone(&cancel_flag),
                        timeout_flag: Arc::clone(&timeout_flag),
                    },
                );
            }

            let base_spec = build_job_spec(
                &job_snap,
                &concrete_printer,
                &docs[0].data_file,
                &docs[0].src_type,
                &dst_type,
                &server_bin,
                &cfg,
            );
            let base_opts = build_spawn_options(
                &cfg,
                &concrete_printer,
                &server_root,
                ppd_path.is_file().then_some(ppd_path),
            );

            let sched = Arc::clone(self);
            let target_printer_name = concrete_printer.name.clone();
            let job_username = job_snap.username.clone();
            let job_title = job_snap.title.clone();
            let job_attrs = job_snap.attrs.clone();
            let kill_delay = Duration::from_secs(
                u64::try_from(cfg.cupsd.job_kill_delay.clamp(1, 300)).unwrap_or(30),
            );
            let page_log_fmt = cfg
                .cupsd
                .page_log_format
                .clone()
                .unwrap_or_else(|| DEFAULT_PAGE_LOG_FORMAT.to_string());
            let file_device_allowed = cfg.files.file_device.is_some();

            let job_request_root = request_root.clone();
            tokio::spawn(async move {
                sched
                    .execute_job_task(JobRunParams {
                        job_id,
                        printer_name: target_printer_name,
                        username: job_username,
                        title: job_title,
                        job_attrs,
                        base_spec,
                        base_opts,
                        docs,
                        request_root: job_request_root,
                        kill_delay,
                        page_log_fmt,
                        file_device_allowed,
                        cancel_flag,
                        timeout_flag,
                        _cost_guard: cost_guard,
                    })
                    .await;
            });

            dispatched += 1;
        }

        dispatched
    }

    /// Resolve a destination name to a concrete, accepting, non-stopped,
    /// non-busy [`Printer`], routing classes via `Registry::resolve_class_member`
    /// plus round-robin member selection.
    fn resolve_target_printer(
        &self,
        dest_name: &str,
        busy_printers: &HashSet<String>,
    ) -> Option<Printer> {
        let reg = self
            .registry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dest = reg.find(dest_name)?;
        // NEVER print to paused/stopped or non-accepting queues!
        if dest.state == pstate::STOPPED || !dest.accepting {
            return None;
        }

        if !dest.is_class() {
            if busy_printers.contains(&dest.name) {
                return None;
            }
            return Some(dest.clone());
        }

        // Class routing: honor Registry::resolve_class_member and round-robin across idle members.
        if !dest.members.is_empty() {
            let mut rr = self
                .class_rr
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let start = rr.get(&dest.name).copied().unwrap_or(0) % dest.members.len();
            for offset in 0..dest.members.len() {
                let idx = (start + offset) % dest.members.len();
                let member_name = &dest.members[idx];
                if let Some(m) = reg.find(member_name) {
                    if !m.is_class()
                        && m.accepting
                        && m.state != pstate::STOPPED
                        && !busy_printers.contains(&m.name)
                    {
                        rr.insert(dest.name.clone(), (idx + 1) % dest.members.len());
                        return Some(m.clone());
                    }
                }
            }
        }

        // Fallback to Registry::resolve_class_member (handles nested classes with cycle protection).
        let resolved = reg.resolve_class_member(&dest.name)?;
        if resolved.state != pstate::STOPPED
            && resolved.accepting
            && !busy_printers.contains(&resolved.name)
        {
            Some(resolved.clone())
        } else {
            None
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_job_task(self: Arc<Self>, params: JobRunParams) {
        let started = Instant::now();
        let job_id = params.job_id;
        let printer_name = params.printer_name.clone();
        let username = params.username.clone();
        let title = params.title.clone();
        let request_root = params.request_root.clone();
        let cancel_flag = Arc::clone(&params.cancel_flag);
        let timeout_flag = Arc::clone(&params.timeout_flag);

        let sched_for_blocking = Arc::clone(&self);
        let run_result =
            tokio::task::spawn_blocking(move || sched_for_blocking.run_documents_blocking(&params))
                .await;

        let outcome = match run_result {
            Ok(res) => res,
            Err(e) => JobExecResult::SpawnError(format!("job runner join error: {e}")),
        };

        // Clean up active handle before state finalization so next tick can immediately reuse printer.
        {
            let mut active = self
                .active_jobs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            active.remove(&job_id);
        }

        let elapsed = started.elapsed().as_secs_f64();
        let was_canceled = cancel_flag.load(Ordering::Acquire);
        let was_timed_out = timeout_flag.load(Ordering::Acquire);

        self.finalize_job_outcome(
            job_id,
            &printer_name,
            &username,
            &title,
            &request_root,
            outcome,
            was_canceled,
            was_timed_out,
            elapsed,
        );

        // Immediately wake scheduler so the next queued job on this printer starts!
        self.notify();
    }

    fn run_documents_blocking(&self, params: &JobRunParams) -> JobExecResult {
        // Defense in depth: verify FileDevice policy before spawning `file` backend.
        if params.base_spec.backend.eq_ignore_ascii_case("file") && !params.file_device_allowed {
            return JobExecResult::SpawnError(
                "file: device URIs are disabled by FileDevice No".into(),
            );
        }

        for doc in &params.docs {
            if params.cancel_flag.load(Ordering::Acquire) {
                return JobExecResult::Canceled;
            }
            if params.timeout_flag.load(Ordering::Acquire) {
                return JobExecResult::TimedOut;
            }

            let (mut doc_spec, mut doc_opts) =
                params.base_spec.for_document(doc, &params.base_opts);
            let (tx, rx) = std::sync::mpsc::channel::<StatusMessage>();
            doc_opts.status_tx = Some(tx);

            apply_unprivileged_exec_adjustments(
                &mut doc_spec,
                &mut doc_opts,
                &doc.chain,
                params.file_device_allowed,
            );

            let mut pipe: Pipeline = match doc_spec.spawn_with_options(&doc.chain, &doc_opts) {
                Ok(p) => p,
                Err(e) => return JobExecResult::SpawnError(e.to_string()),
            };
            // Drop our local sender clone immediately so `rx` observes
            // `Disconnected` as soon as the pipeline's stderr reader threads finish.
            doc_opts.status_tx = None;

            let backend_pid = i32::try_from(pipe.backend.id()).ok();
            {
                let mut jg = self
                    .jobs
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(j) = jg.get_mut(params.job_id) {
                    j.backend_pid = backend_pid;
                }
            }
            self.log.err(
                Level::Info,
                format!(
                    "[Job {}] Started backend '{}' (PID {}, doc #{})",
                    params.job_id,
                    doc_spec.backend,
                    pipe.backend.id(),
                    doc.number
                ),
            );

            // Live loop: consume stderr StatusEvents, honor cancellation & MaxJobTime, wait for backend.
            let exit = self.monitor_pipeline(
                &mut pipe,
                &rx,
                params.job_id,
                &params.printer_name,
                &params.username,
                &params.job_attrs,
                &params.page_log_fmt,
                &params.cancel_flag,
                &params.timeout_flag,
                params.kill_delay,
            );

            match exit {
                MonitorOutcome::Canceled => return JobExecResult::Canceled,
                MonitorOutcome::TimedOut => return JobExecResult::TimedOut,
                MonitorOutcome::Finished(pe) => {
                    if !pe.is_ok() {
                        return JobExecResult::Exited(pe);
                    }
                }
                MonitorOutcome::WaitError(e) => {
                    return JobExecResult::SpawnError(format!("pipeline wait failed: {e}"));
                }
            }
        }

        JobExecResult::Exited(PipelineExit {
            backend: BackendExit::Ok,
            filters: Vec::new(),
        })
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn monitor_pipeline(
        &self,
        pipe: &mut Pipeline,
        rx: &std::sync::mpsc::Receiver<StatusMessage>,
        job_id: i32,
        printer_name: &str,
        username: &str,
        job_attrs: &[Attribute],
        page_log_fmt: &str,
        cancel_flag: &AtomicBool,
        timeout_flag: &AtomicBool,
        kill_delay: Duration,
    ) -> MonitorOutcome {
        loop {
            self.drain_status(rx, job_id, printer_name, username, job_attrs, page_log_fmt);

            if cancel_flag.load(Ordering::Acquire) {
                let _ = pipe.kill_job(kill_delay);
                self.drain_status_until_closed(
                    rx,
                    job_id,
                    printer_name,
                    username,
                    job_attrs,
                    page_log_fmt,
                    Duration::from_millis(500),
                );
                return MonitorOutcome::Canceled;
            }

            if timeout_flag.load(Ordering::Acquire) {
                let _ = pipe.kill_job(kill_delay);
                self.drain_status_until_closed(
                    rx,
                    job_id,
                    printer_name,
                    username,
                    job_attrs,
                    page_log_fmt,
                    Duration::from_millis(500),
                );
                return MonitorOutcome::TimedOut;
            }

            match pipe.backend.try_wait() {
                Ok(Some(bstatus)) => {
                    let mut filter_exits: Vec<Option<pipeline::FilterExit>> =
                        vec![None; pipe.filters.len()];
                    let grace =
                        kill_delay.clamp(Duration::from_millis(100), Duration::from_secs(2));
                    let grace_deadline = Instant::now() + grace;

                    while filter_exits.iter().any(Option::is_none) {
                        self.drain_status(
                            rx,
                            job_id,
                            printer_name,
                            username,
                            job_attrs,
                            page_log_fmt,
                        );
                        if cancel_flag.load(Ordering::Acquire) {
                            let _ = pipe.kill_job(kill_delay);
                            self.drain_status_until_closed(
                                rx,
                                job_id,
                                printer_name,
                                username,
                                job_attrs,
                                page_log_fmt,
                                Duration::from_millis(500),
                            );
                            return MonitorOutcome::Canceled;
                        }
                        if timeout_flag.load(Ordering::Acquire) {
                            let _ = pipe.kill_job(kill_delay);
                            self.drain_status_until_closed(
                                rx,
                                job_id,
                                printer_name,
                                username,
                                job_attrs,
                                page_log_fmt,
                                Duration::from_millis(500),
                            );
                            return MonitorOutcome::TimedOut;
                        }
                        for (i, f) in pipe.filters.iter_mut().enumerate() {
                            if filter_exits[i].is_none() {
                                if let Ok(Some(st)) = f.try_wait() {
                                    filter_exits[i] =
                                        Some(pipeline::FilterExit::from_status(i, f.id(), st));
                                }
                            }
                        }
                        if filter_exits.iter().all(Option::is_some) {
                            break;
                        }
                        if Instant::now() >= grace_deadline {
                            self.log.err(
                                Level::Warn,
                                format!(
                                    "[Job {job_id}] Backend exited while filter(s) remained running; terminating filter group."
                                ),
                            );
                            if let Ok(killed) = pipe.kill_job(kill_delay) {
                                for fe in killed.filters {
                                    if let Some(slot) = filter_exits.get_mut(fe.index) {
                                        if slot.is_none() {
                                            *slot = Some(fe);
                                        }
                                    }
                                }
                            }
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }

                    // Drain all remaining stderr StatusMessages until the reader threads
                    // close the channel (bounded by a short safety deadline).
                    self.drain_status_until_closed(
                        rx,
                        job_id,
                        printer_name,
                        username,
                        job_attrs,
                        page_log_fmt,
                        Duration::from_millis(500),
                    );
                    return MonitorOutcome::Finished(PipelineExit {
                        backend: BackendExit::from_exit_status(bstatus),
                        filters: filter_exits.into_iter().flatten().collect(),
                    });
                }
                Ok(None) => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return MonitorOutcome::WaitError(e.to_string()),
            }
        }
    }

    /// Apply every currently queued [`StatusMessage`] without blocking.
    fn drain_status(
        &self,
        rx: &std::sync::mpsc::Receiver<StatusMessage>,
        job_id: i32,
        printer_name: &str,
        username: &str,
        job_attrs: &[Attribute],
        page_log_fmt: &str,
    ) {
        while let Ok(msg) = rx.try_recv() {
            self.apply_status_message(job_id, printer_name, username, job_attrs, page_log_fmt, msg);
        }
    }

    /// Drain [`StatusMessage`]s until all stderr reader threads close the channel
    /// (or `max_wait` elapses).
    #[allow(clippy::too_many_arguments)]
    fn drain_status_until_closed(
        &self,
        rx: &std::sync::mpsc::Receiver<StatusMessage>,
        job_id: i32,
        printer_name: &str,
        username: &str,
        job_attrs: &[Attribute],
        page_log_fmt: &str,
        max_wait: Duration,
    ) {
        let deadline = Instant::now() + max_wait;
        while let Some(rem) = deadline.checked_duration_since(Instant::now()) {
            match rx.recv_timeout(rem) {
                Ok(msg) => self.apply_status_message(
                    job_id,
                    printer_name,
                    username,
                    job_attrs,
                    page_log_fmt,
                    msg,
                ),
                Err(
                    std::sync::mpsc::RecvTimeoutError::Disconnected
                    | std::sync::mpsc::RecvTimeoutError::Timeout,
                ) => break,
            }
        }
    }

    /// Consume a live filter/backend `StatusMessage` (`STATE:`, `INFO:`, `PAGE:`, `ATTR:`, `PPD:`).
    #[allow(clippy::too_many_lines)]
    pub fn apply_status_message(
        &self,
        job_id: i32,
        printer_name: &str,
        username: &str,
        job_attrs: &[Attribute],
        page_log_fmt: &str,
        msg: StatusMessage,
    ) {
        match msg.event {
            StatusEvent::Log { severity, message } => {
                let lvl = map_pipeline_severity(severity);
                self.log
                    .err(lvl, format!("[Job {job_id}] ({}) {message}", msg.stage));
                if matches!(
                    severity,
                    LogSeverity::Info
                        | LogSeverity::Warning
                        | LogSeverity::Error
                        | LogSeverity::Crit
                        | LogSeverity::Alert
                        | LogSeverity::Emerg
                ) {
                    let mut reg = self
                        .registry
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Some(p) = reg.find_mut(printer_name) {
                        p.state_message = message;
                        p.state_time = job::now();
                    }
                }
            }
            StatusEvent::State(changes) => {
                let mut reg = self
                    .registry
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(p) = reg.find_mut(printer_name) {
                    apply_state_changes(&mut p.reasons, &changes);
                    p.state_time = job::now();
                }
                drop(reg);
                self.emit_event(
                    Event::PrinterStateChanged,
                    Some(printer_name),
                    Some(job_id),
                    None,
                    None,
                    format!("Printer {printer_name} state reasons updated."),
                );
            }
            StatusEvent::Page(page_ev) => match page_ev {
                PageEvent::Sheet {
                    page,
                    copies,
                    extra: _,
                } => {
                    let delta = i32::try_from(copies.max(1)).unwrap_or(1);
                    {
                        let mut jg = self
                            .jobs
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Some(j) = jg.get_mut(job_id) {
                            increment_job_impressions(&mut j.attrs, delta);
                        }
                    }
                    self.metrics
                        .record_pages_printed(printer_name, u64::from(copies.max(1)));
                    self.log.page(
                        page_log_fmt,
                        printer_name,
                        Some(username),
                        job_id,
                        &format!("{page} {copies}"),
                        job_attrs,
                    );
                    self.emit_event(
                        Event::JobProgress,
                        Some(printer_name),
                        Some(job_id),
                        Some(JobState::Processing as i32),
                        None,
                        format!("Printed page {page}, {copies} copy(ies)."),
                    );
                }
                PageEvent::Total(total) => {
                    let total_i32 = i32::try_from(total).unwrap_or(i32::MAX);
                    {
                        let mut jg = self
                            .jobs
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Some(j) = jg.get_mut(job_id) {
                            set_job_impressions_min(&mut j.attrs, total_i32);
                        }
                    }
                    self.log.page(
                        page_log_fmt,
                        printer_name,
                        Some(username),
                        job_id,
                        &format!("total {total}"),
                        job_attrs,
                    );
                }
            },
            StatusEvent::Attr(pairs) => {
                let mut reg = self
                    .registry
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(p) = reg.find_mut(printer_name) {
                    apply_printer_attrs(p, &pairs);
                }
                drop(reg);
                self.mark_dirty();
            }
            StatusEvent::Ppd(pairs) => {
                self.log.err(
                    Level::Debug,
                    format!("[Job {job_id}] PPD update: {} pair(s)", pairs.len()),
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn finalize_job_outcome(
        &self,
        job_id: i32,
        printer_name: &str,
        _username: &str,
        job_title: &str,
        request_root: &Path,
        outcome: JobExecResult,
        was_canceled: bool,
        was_timed_out: bool,
        elapsed_secs: f64,
    ) {
        let cfg = self.current_cfg();
        let now_ts = job::now();
        let retry_limit = u32::try_from(cfg.cupsd.job_retry_limit.max(0)).unwrap_or(5);
        let retry_interval = i64::from(cfg.cupsd.job_retry_interval.max(1));

        // Resolve effective ErrorPolicy (per-printer -> cupsd.conf -> "stop-printer").
        let error_policy = {
            let reg = self
                .registry
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            reg.find(printer_name)
                .and_then(|p| p.error_policy.clone())
                .or_else(|| cfg.cupsd.error_policy.clone())
                .unwrap_or_else(|| "stop-printer".to_string())
                .to_ascii_lowercase()
        };

        // Check if job was already canceled externally while running — NEVER overwrite `Canceled`!
        let already_canceled = {
            let jg = self
                .jobs
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            jg.get(job_id)
                .is_some_and(|j| j.state == JobState::Canceled)
        };

        if already_canceled || was_canceled || matches!(outcome, JobExecResult::Canceled) {
            self.set_printer_idle_if_processing(printer_name, now_ts);
            let mut jg = self
                .jobs
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(j) = jg.get_mut(job_id) {
                j.state = JobState::Canceled;
                j.backend_pid = None;
                j.completed_at.get_or_insert(now_ts);
                if j.reasons.is_empty() || j.reasons == ["job-printing"] {
                    j.reasons = vec!["job-canceled-by-user".into()];
                }
                let _ = j.save(request_root);
            }
            drop(jg);
            self.retries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&job_id);
            self.metrics
                .record_job_terminal("canceled", Some(elapsed_secs));
            self.emit_event(
                Event::JobCompleted,
                Some(printer_name),
                Some(job_id),
                Some(JobState::Canceled as i32),
                Some(job_title.to_string()),
                format!("Job {job_id} canceled."),
            );
            self.subs
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .expire_job(job_id);
            self.mark_dirty();
            return;
        }

        if was_timed_out || matches!(outcome, JobExecResult::TimedOut) {
            self.abort_job(
                job_id,
                printer_name,
                job_title,
                request_root,
                "job-aborted-by-system",
                "Job exceeded MaxJobTime and was aborted.",
                elapsed_secs,
                now_ts,
            );
            return;
        }

        match outcome {
            JobExecResult::Exited(pe) if pe.is_ok() => {
                self.set_printer_idle_if_processing(printer_name, now_ts);
                {
                    let mut jg = self
                        .jobs
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Some(j) = jg.get_mut(job_id) {
                        j.state = JobState::Completed;
                        j.backend_pid = None;
                        j.completed_at = Some(now_ts);
                        j.reasons = vec!["job-completed-successfully".into()];
                        let _ = j.save(request_root);
                    }
                }
                self.retries
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&job_id);
                self.metrics
                    .record_job_terminal("completed", Some(elapsed_secs));
                self.emit_event(
                    Event::JobCompleted,
                    Some(printer_name),
                    Some(job_id),
                    Some(JobState::Completed as i32),
                    Some(job_title.to_string()),
                    format!("Job {job_id} completed."),
                );
                self.subs
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .expire_job(job_id);
                self.log
                    .err(Level::Info, format!("[Job {job_id}] Job completed."));
                self.mark_dirty();
            }
            JobExecResult::Exited(pe) => {
                self.handle_backend_failure(
                    job_id,
                    printer_name,
                    job_title,
                    request_root,
                    pe.backend,
                    &error_policy,
                    retry_limit,
                    retry_interval,
                    elapsed_secs,
                    now_ts,
                );
            }
            JobExecResult::SpawnError(err_msg) => {
                self.log.err(
                    Level::Error,
                    format!("[Job {job_id}] Unable to start pipeline: {err_msg}"),
                );
                self.handle_backend_failure(
                    job_id,
                    printer_name,
                    job_title,
                    request_root,
                    BackendExit::Failed,
                    &error_policy,
                    retry_limit,
                    retry_interval,
                    elapsed_secs,
                    now_ts,
                );
            }
            JobExecResult::Canceled | JobExecResult::TimedOut => {}
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn handle_backend_failure(
        &self,
        job_id: i32,
        printer_name: &str,
        job_title: &str,
        request_root: &Path,
        backend_exit: BackendExit,
        error_policy: &str,
        retry_limit: u32,
        retry_interval: i64,
        elapsed_secs: f64,
        now_ts: i64,
    ) {
        match backend_exit {
            BackendExit::Cancel => {
                self.set_printer_idle_if_processing(printer_name, now_ts);
                {
                    let mut jg = self
                        .jobs
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Some(j) = jg.get_mut(job_id) {
                        j.state = JobState::Canceled;
                        j.backend_pid = None;
                        j.completed_at = Some(now_ts);
                        j.reasons = vec!["job-canceled-at-device".into()];
                        let _ = j.save(request_root);
                    }
                }
                self.retries
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&job_id);
                self.metrics
                    .record_job_terminal("canceled-at-device", Some(elapsed_secs));
                self.emit_event(
                    Event::JobCompleted,
                    Some(printer_name),
                    Some(job_id),
                    Some(JobState::Canceled as i32),
                    Some(job_title.to_string()),
                    format!("Job {job_id} canceled at device."),
                );
                self.subs
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .expire_job(job_id);
                self.mark_dirty();
            }
            BackendExit::Hold | BackendExit::AuthRequired => {
                self.set_printer_idle_if_processing(printer_name, now_ts);
                let reason = backend_exit.ipp_job_state_reason().to_string();
                {
                    let mut jg = self
                        .jobs
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Some(j) = jg.get_mut(job_id) {
                        j.state = JobState::PendingHeld;
                        j.backend_pid = None;
                        j.reasons = vec![reason];
                        let _ = j.save(request_root);
                    }
                }
                self.emit_event(
                    Event::JobStateChanged,
                    Some(printer_name),
                    Some(job_id),
                    Some(JobState::PendingHeld as i32),
                    Some(job_title.to_string()),
                    format!("Job {job_id} held ({backend_exit:?})."),
                );
                self.mark_dirty();
            }
            BackendExit::Stop => {
                self.stop_printer_and_requeue(job_id, printer_name, request_root, now_ts);
            }
            BackendExit::RetryCurrent => {
                self.requeue_or_abort(
                    job_id,
                    printer_name,
                    job_title,
                    request_root,
                    retry_limit,
                    0,
                    elapsed_secs,
                    now_ts,
                );
            }
            BackendExit::Retry => {
                self.requeue_or_abort(
                    job_id,
                    printer_name,
                    job_title,
                    request_root,
                    retry_limit,
                    retry_interval,
                    elapsed_secs,
                    now_ts,
                );
            }
            BackendExit::Failed
            | BackendExit::Unknown(_)
            | BackendExit::Signal(_)
            | BackendExit::Ok => {
                // Apply configured ErrorPolicy (retry-current-job | retry-job | abort-job | stop-printer).
                match error_policy {
                    "retry-current-job" => {
                        self.requeue_or_abort(
                            job_id,
                            printer_name,
                            job_title,
                            request_root,
                            retry_limit,
                            0,
                            elapsed_secs,
                            now_ts,
                        );
                    }
                    "retry-job" => {
                        self.requeue_or_abort(
                            job_id,
                            printer_name,
                            job_title,
                            request_root,
                            retry_limit,
                            retry_interval,
                            elapsed_secs,
                            now_ts,
                        );
                    }
                    "abort-job" => {
                        self.abort_job(
                            job_id,
                            printer_name,
                            job_title,
                            request_root,
                            "job-aborted-by-system",
                            "Backend failed; job aborted per ErrorPolicy.",
                            elapsed_secs,
                            now_ts,
                        );
                    }
                    _ => {
                        // Default CUPS ErrorPolicy: `stop-printer`.
                        self.stop_printer_and_requeue(job_id, printer_name, request_root, now_ts);
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn requeue_or_abort(
        &self,
        job_id: i32,
        printer_name: &str,
        job_title: &str,
        request_root: &Path,
        retry_limit: u32,
        delay_secs: i64,
        elapsed_secs: f64,
        now_ts: i64,
    ) {
        let attempts = {
            let mut r = self
                .retries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = r.entry(job_id).or_default();
            entry.attempts = entry.attempts.saturating_add(1);
            entry.next_retry_at = now_ts.saturating_add(delay_secs);
            entry.attempts
        };
        if retry_limit > 0 && attempts <= retry_limit {
            self.set_printer_idle_if_processing(printer_name, now_ts);
            {
                let mut jg = self
                    .jobs
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(j) = jg.get_mut(job_id) {
                    j.state = JobState::Pending;
                    j.backend_pid = None;
                    j.reasons = vec!["job-restartable".into()];
                    let _ = j.save(request_root);
                }
            }
            self.log.err(
                Level::Warn,
                format!(
                    "[Job {job_id}] Retry {attempts}/{retry_limit} scheduled in {delay_secs}s."
                ),
            );
            self.emit_event(
                Event::JobStateChanged,
                Some(printer_name),
                Some(job_id),
                Some(JobState::Pending as i32),
                Some(job_title.to_string()),
                format!("Job {job_id} scheduled for retry {attempts}/{retry_limit}."),
            );
            self.mark_dirty();
        } else {
            self.abort_job(
                job_id,
                printer_name,
                job_title,
                request_root,
                "job-aborted-by-system",
                "Job retry limit exceeded; aborting job.",
                elapsed_secs,
                now_ts,
            );
        }
    }

    fn stop_printer_and_requeue(
        &self,
        job_id: i32,
        printer_name: &str,
        request_root: &Path,
        now_ts: i64,
    ) {
        {
            let mut reg = self
                .registry
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(p) = reg.find_mut(printer_name) {
                p.state = pstate::STOPPED;
                p.state_time = now_ts;
                if !p.reasons.iter().any(|r| r == "paused") {
                    p.reasons.push("paused".into());
                }
            }
        }
        {
            let mut jg = self
                .jobs
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(j) = jg.get_mut(job_id) {
                j.state = JobState::Pending;
                j.backend_pid = None;
                j.reasons = vec!["printer-stopped".into()];
                let _ = j.save(request_root);
            }
        }
        self.log.err(
            Level::Error,
            format!("[Job {job_id}] Stopping printer '{printer_name}' per ErrorPolicy."),
        );
        self.emit_event(
            Event::PrinterStopped,
            Some(printer_name),
            Some(job_id),
            Some(JobState::Pending as i32),
            None,
            format!("Printer {printer_name} stopped due to backend error."),
        );
        self.mark_dirty();
    }

    #[allow(clippy::too_many_arguments)]
    fn abort_job(
        &self,
        job_id: i32,
        printer_name: &str,
        job_title: &str,
        request_root: &Path,
        reason: &str,
        log_msg: &str,
        elapsed_secs: f64,
        now_ts: i64,
    ) {
        self.set_printer_idle_if_processing(printer_name, now_ts);
        {
            let mut jg = self
                .jobs
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(j) = jg.get_mut(job_id) {
                j.state = JobState::Aborted;
                j.backend_pid = None;
                j.completed_at = Some(now_ts);
                j.reasons = vec![reason.to_string()];
                let _ = j.save(request_root);
            }
        }
        self.retries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&job_id);
        self.metrics
            .record_job_terminal("aborted", Some(elapsed_secs));
        // P0 FIX: Aborted is IPP enum `8` (`JobState::Aborted as i32`), NEVER `7`!
        self.emit_event(
            Event::JobStopped,
            Some(printer_name),
            Some(job_id),
            Some(JobState::Aborted as i32),
            Some(job_title.to_string()),
            format!("Job {job_id} aborted."),
        );
        self.subs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expire_job(job_id);
        self.log
            .err(Level::Error, format!("[Job {job_id}] {log_msg}"));
        self.mark_dirty();
    }

    fn set_printer_idle_if_processing(&self, printer_name: &str, now_ts: i64) {
        let mut reg = self
            .registry
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(p) = reg.find_mut(printer_name) {
            if p.state == pstate::PROCESSING {
                p.state = pstate::IDLE;
                p.state_time = now_ts;
            }
        }
    }

    fn emit_event(
        &self,
        ev: Event,
        printer: Option<&str>,
        job_id: Option<i32>,
        job_state: Option<i32>,
        job_name: Option<String>,
        text: String,
    ) {
        self.subs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ev, printer, job_id, job_state, &text);
        let (printer_state, printer_reasons, printer_accepting) = if let Some(pname) = printer {
            let reg = self
                .registry
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(p) = reg.find(pname) {
                let reasons = if p.reasons.is_empty() {
                    "none".into()
                } else {
                    p.reasons.join(",")
                };
                (Some(p.state), Some(reasons), Some(p.accepting))
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };
        emit_dbus_event(
            &self.dbus,
            &EventSignal {
                event: ev,
                printer: printer.map(str::to_string),
                printer_uri: printer.map(|p| format!("ipp://localhost/printers/{p}")),
                printer_state,
                printer_state_reasons: printer_reasons,
                printer_accepting,
                job_id,
                job_state,
                job_name,
                text,
            },
        );
    }
}

struct JobRunParams {
    job_id: i32,
    printer_name: String,
    username: String,
    title: String,
    job_attrs: Vec<Attribute>,
    base_spec: JobSpec,
    base_opts: SpawnOptions,
    docs: Vec<JobDocument>,
    request_root: PathBuf,
    kill_delay: Duration,
    page_log_fmt: String,
    file_device_allowed: bool,
    cancel_flag: Arc<AtomicBool>,
    timeout_flag: Arc<AtomicBool>,
    _cost_guard: FilterCostGuard,
}

enum JobExecResult {
    Exited(PipelineExit),
    Canceled,
    TimedOut,
    SpawnError(String),
}

enum MonitorOutcome {
    Finished(PipelineExit),
    Canceled,
    TimedOut,
    WaitError(String),
}

/// Build [`JobSpec`] with real job options (`format_job_options`) and sanitized
/// `PassEnv` / `SetEnv` (`!cups_config::is_prohibited_env`).
#[must_use]
pub fn build_job_spec(
    j: &Job,
    p: &Printer,
    data_file: &Path,
    src_type: &str,
    dst_type: &str,
    server_bin: &Path,
    cfg: &Config,
) -> JobSpec {
    let mut opt_pairs: Vec<(String, String)> = p.options.clone();
    for (k, v) in &j.options {
        opt_pairs.push((k.clone(), v.clone()));
    }
    for attr in &j.attrs {
        let name = attr.name.as_str();
        if matches!(
            name.as_ref(),
            "media"
                | "sides"
                | "number-up"
                | "orientation-requested"
                | "print-quality"
                | "print-color-mode"
                | "page-ranges"
                | "finishings"
                | "job-billing"
                | "job-sheets"
        ) {
            if let Some(val) = attr.values.first().and_then(ipp_value_to_option_str) {
                opt_pairs.push((name.into_owned(), val));
            }
        }
    }

    let mut env = collect_configured_env(cfg);
    if cfg.files.file_device.is_some() {
        env.insert("CUPS_FILE_DEVICE".into(), "yes".into());
    }

    let backend = try_backend_for_uri(&p.device_uri).unwrap_or_default();

    JobSpec {
        printer: p.name.clone(),
        job_id: j.id,
        username: j.username.clone(),
        title: j.title.clone(),
        copies: j.copies.max(1),
        options: format_job_options(&opt_pairs),
        data_file: data_file.to_path_buf(),
        src_type: src_type.to_string(),
        dst_type: dst_type.to_string(),
        device_uri: p.device_uri.clone(),
        filter_dir: server_bin.join("filter"),
        backend_dir: server_bin.join("backend"),
        backend,
        env,
    }
}

/// Collect `PassEnv` and `SetEnv` from `cups-files.conf`, strictly filtering out
/// every variable blocked by `cups_config::is_prohibited_env`.
#[must_use]
pub fn collect_configured_env(cfg: &Config) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for key in &cfg.files.pass_env {
        if !key.is_empty() && !cups_config::is_prohibited_env(key) {
            if let Ok(val) = std::env::var(key) {
                out.insert(key.clone(), val);
            }
        }
    }
    for (k, v) in &cfg.files.set_env {
        if !k.is_empty() && !cups_config::is_prohibited_env(k) {
            out.insert(k.clone(), v.clone());
        }
    }
    out
}

/// Build [`SpawnOptions`] from [`Config`] and target [`Printer`].
#[must_use]
pub fn build_spawn_options(
    cfg: &Config,
    p: &Printer,
    server_root: &Path,
    ppd: Option<PathBuf>,
) -> SpawnOptions {
    let mut opts = SpawnOptions::from_cups_config(cfg);
    opts.server_root = Some(server_root.to_path_buf());
    opts.ppd = ppd;
    opts.printer_info = p.info.clone().or_else(|| Some(p.name.clone()));
    opts.printer_location.clone_from(&p.location);
    opts
}

/// Safe adjustments for unprivileged execution (`euid != 0`) and `FileDevice`
/// targets:
/// - Root (`euid == 0`) NEVER relaxes `SecurityPolicy::strict()`; for `file://`
///   with explicit `FileDevice Yes`, `Sandboxing::Off` still runs through
///   `cups-exec none` to drop root privileges cleanly while allowing writes to
///   the admin-approved `file://` destination.
/// - Non-root (`euid != 0`) tolerates User Private Group `0775` (`uid == euid &&
///   gid == egid && mode & 0o002 == 0`) on developer builds (Ubuntu/Debian/Fedora
///   `umask 0002`), while STILL rejecting world-writable (`0o002`), setuid/setgid,
///   symlinks, and foreign-group-writable binaries.
fn apply_unprivileged_exec_adjustments(
    spec: &mut JobSpec,
    opts: &mut SpawnOptions,
    chain: &[mime_db::Conv],
    file_device_allowed: bool,
) {
    let (user_id, group_id) = pipeline::current_euid_egid();

    // Admin explicitly enabled FileDevice Yes for `file://` output target:
    // Landlock's static named profile cannot know arbitrary `file:///...` output dirs.
    if file_device_allowed && spec.backend.eq_ignore_ascii_case("file") {
        opts.sandbox.mode = Sandboxing::Off;
        if user_id != 0 {
            opts.sandbox.cups_exec_path = None;
        }
    }

    if user_id == 0 {
        return;
    }

    // Check if backend or any active filter is a UPG-owned 0775 binary (never world-writable!).
    let mut needs_upg_relax =
        is_upg_group_writable(&spec.backend_dir.join(&spec.backend), user_id, group_id);
    for conv in chain {
        if conv.program != "-"
            && is_upg_group_writable(&spec.filter_dir.join(&conv.program), user_id, group_id)
        {
            needs_upg_relax = true;
        }
    }
    if needs_upg_relax {
        // Verify none of the targets are world-writable (0o002) before relaxing group-write.
        let world_writable = is_world_writable(&spec.backend_dir.join(&spec.backend))
            || chain
                .iter()
                .any(|c| c.program != "-" && is_world_writable(&spec.filter_dir.join(&c.program)));
        if !world_writable {
            opts.security.reject_group_or_world_writable = false;
            opts.sandbox.cups_exec_path = None;
        }
    }
}

fn is_upg_group_writable(path: &Path, user_id: u32, group_id: u32) -> bool {
    let Ok(m) = std::fs::symlink_metadata(path) else {
        return false;
    };
    let mode = m.mode();
    m.is_file()
        && m.uid() == user_id
        && m.gid() == group_id
        && (mode & 0o020) != 0
        && (mode & 0o002) == 0
}

fn is_world_writable(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| (m.mode() & 0o002) != 0)
}

/// Load a queue's PPD text: prefers installed `{ServerRoot}/ppd/{name}.ppd`,
/// falling back to `cups-driverd cat <ppd-name>` using `DataDir`-based `PPDDIR`/`DRVROOT`
/// (NEVER `server_bin.parent()`!).
#[must_use]
pub fn load_printer_ppd(
    p: &Printer,
    server_root: &Path,
    server_bin: &Path,
    data_dir: &Path,
) -> Option<String> {
    let queue_ppd = server_root.join("ppd").join(format!("{}.ppd", p.name));
    if let Ok(mut file) = sys::open_readonly_nofollow(&queue_ppd) {
        let mut text = String::new();
        if std::io::Read::read_to_string(&mut file, &mut text).is_ok() && !text.is_empty() {
            return Some(text);
        }
    }

    let ppd_name = p
        .options
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("ppd-name"))
        .map(|(_, v)| v.as_str())?;
    let driverd = server_bin.join("daemon").join("cups-driverd");
    if !driverd.is_file() {
        return None;
    }

    let data_ppd = data_dir.join("ppd");
    let ppd_dir = if data_ppd.is_dir() {
        data_ppd
    } else {
        let sys_ppd = PathBuf::from("/usr/share/ppd");
        if sys_ppd.is_dir() {
            sys_ppd
        } else {
            data_ppd
        }
    };
    let drv_dir = data_dir.join("drv");

    let out = std::process::Command::new(driverd)
        .args(["cat", ppd_name])
        .env("PPDDIR", &ppd_dir)
        .env("DRVROOT", &drv_dir)
        .env("CUPS_DATADIR", data_dir)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Select the cheapest PPD target MIME type and optional final driver filter
/// using `pipeline::parse_ppd_filters`.
#[must_use]
pub fn resolve_ppd_target(ppd: Option<&str>) -> (String, Option<mime_db::Conv>) {
    let Some(text) = ppd else {
        return ("application/vnd.cups-raw".into(), None);
    };
    let mut filters = parse_ppd_filters(text);
    if filters.is_empty() {
        return ("application/vnd.cups-raw".into(), None);
    }
    filters.sort_by_key(|f| f.cost);
    let best = &filters[0];
    let driver_conv = (best.program != "-").then(|| mime_db::Conv {
        src: best.src.clone(),
        dst: best.dst.clone(),
        cost: best.cost,
        program: best.program.clone(),
    });
    (best.src.clone(), driver_conv)
}

/// Apply `STATE:` reason mutations (`+reason`, `-reason`, `reason`, `none`).
pub fn apply_state_changes(reasons: &mut Vec<String>, changes: &[StateChange]) {
    for ch in changes {
        match ch {
            StateChange::Clear => reasons.clear(),
            StateChange::Set(r) => {
                reasons.clear();
                reasons.push(r.clone());
            }
            StateChange::Add(r) => {
                if !reasons.iter().any(|x| x == r) {
                    reasons.push(r.clone());
                }
            }
            StateChange::Remove(r) => {
                reasons.retain(|x| x != r);
            }
        }
    }
}

/// Apply `ATTR:` supply/marker/alert updates onto a [`Printer`].
pub fn apply_printer_attrs(p: &mut Printer, pairs: &[(String, String)]) {
    let mut updated_markers = false;
    for (k, v) in pairs {
        match k.as_str() {
            "marker-colors" => {
                p.marker_colors = split_csv(v);
                updated_markers = true;
            }
            "marker-names" => {
                p.marker_names = split_csv(v);
                updated_markers = true;
            }
            "marker-types" => {
                p.marker_types = split_csv(v);
                updated_markers = true;
            }
            "marker-levels" => {
                p.marker_levels = split_csv_i32(v);
                updated_markers = true;
            }
            "marker-low-levels" => {
                p.marker_low_levels = split_csv_i32(v);
                updated_markers = true;
            }
            "marker-high-levels" => {
                p.marker_high_levels = split_csv_i32(v);
                updated_markers = true;
            }
            "marker-message" => {
                p.marker_message.clone_from(v);
                updated_markers = true;
            }
            "printer-alert" => p.alert = Some(v.clone()),
            "printer-alert-description" => p.alert_description = Some(v.clone()),
            "auth-info-required" => p.auth_info_required = split_csv(v),
            _ => {}
        }
    }
    if updated_markers {
        p.marker_time = job::now();
    }
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|part| part.trim().trim_matches('"').to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

fn split_csv_i32(s: &str) -> Vec<i32> {
    s.split(',')
        .filter_map(|part| part.trim().parse::<i32>().ok())
        .collect()
}

fn increment_job_impressions(attrs: &mut Vec<Attribute>, delta: i32) {
    if let Some(a) = attrs
        .iter_mut()
        .find(|a| a.name == "job-impressions-completed")
    {
        let cur = a
            .values
            .first()
            .and_then(|v| match v {
                Value::Integer(n) => Some(*n),
                _ => None,
            })
            .unwrap_or(0);
        a.values = vec![Value::Integer(cur.saturating_add(delta))];
    } else {
        attrs.push(Attribute {
            tag: tags::INTEGER,
            name: "job-impressions-completed".into(),
            values: vec![Value::Integer(delta)],
        });
    }
}

fn set_job_impressions_min(attrs: &mut Vec<Attribute>, total: i32) {
    if let Some(a) = attrs
        .iter_mut()
        .find(|a| a.name == "job-impressions-completed")
    {
        let cur = a
            .values
            .first()
            .and_then(|v| match v {
                Value::Integer(n) => Some(*n),
                _ => None,
            })
            .unwrap_or(0);
        a.values = vec![Value::Integer(cur.max(total))];
    } else {
        attrs.push(Attribute {
            tag: tags::INTEGER,
            name: "job-impressions-completed".into(),
            values: vec![Value::Integer(total)],
        });
    }
}

fn ipp_value_to_option_str(v: &Value) -> Option<String> {
    match v {
        Value::Integer(n) | Value::Enum(n) => Some(n.to_string()),
        Value::Boolean(b) => Some(if *b { "true" } else { "false" }.into()),
        Value::Keyword(t)
        | Value::Name(t)
        | Value::Text(t)
        | Value::MimeMediaType(t)
        | Value::Uri(t) => Some(t.as_str().into_owned()),
        Value::Range { low, high } => Some(format!("{low}-{high}")),
        _ => None,
    }
}

/// Evaluate whether a CUPS `job-hold-until` keyword/timestamp is due for release.
#[must_use]
pub fn is_hold_until_due(hold_until: &str, now_ts: i64) -> bool {
    let trimmed = hold_until.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("no-hold") {
        return true;
    }
    if trimmed.eq_ignore_ascii_case("indefinite") {
        return false;
    }
    if let Ok(ts) = trimmed.parse::<i64>() {
        return now_ts >= ts;
    }
    let local = cups_log::local_now();
    let hour = local.hour();
    let weekday_num = local.weekday().number_from_monday();
    match trimmed.to_ascii_lowercase().as_str() {
        "day-time" => (6..18).contains(&hour),
        "evening" | "night" => !(6..18).contains(&hour),
        "second-shift" => (16..24).contains(&hour),
        "third-shift" => hour < 8,
        "weekend" => weekday_num >= 6,
        other => {
            // `HH:MM` or `HH:MM:SS` (UTC per RFC 8011)
            let mut parts = other.split(':');
            let (Some(hs), Some(ms)) = (parts.next(), parts.next()) else {
                return false;
            };
            let (Ok(h), Ok(m)) = (hs.parse::<u8>(), ms.parse::<u8>()) else {
                return false;
            };
            let s: u8 = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
            if h >= 24 || m >= 60 || s >= 60 {
                return false;
            }
            let target_secs = i64::from(h) * 3600 + i64::from(m) * 60 + i64::from(s);
            let now_secs = now_ts.rem_euclid(86_400);
            now_secs >= target_secs
        }
    }
}

/// Best-effort `/etc/printcap` writer (BSD / Solaris / Plist formats).
pub fn write_printcap(path: &Path, fmt: PrintcapFormat, reg: &Registry) {
    let mut out = String::from("# This file was automatically generated by cupsd (yindle)\n");
    match fmt {
        PrintcapFormat::Bsd => {
            for p in reg.printers.values() {
                let info = p.info.as_deref().unwrap_or(&p.name);
                let _ = std::fmt::Write::write_fmt(
                    &mut out,
                    format_args!("{}|{}:rm=localhost:rp={}:\n", p.name, info, p.name),
                );
            }
        }
        PrintcapFormat::Solaris => {
            for p in reg.printers.values() {
                let _ = std::fmt::Write::write_fmt(
                    &mut out,
                    format_args!("{}:bsdaddr=localhost,{},Solaris:\n", p.name, p.name),
                );
            }
        }
        PrintcapFormat::Plist => {
            out.push_str("<plist version=\"1.0\"><array>\n");
            for p in reg.printers.values() {
                let _ = std::fmt::Write::write_fmt(
                    &mut out,
                    format_args!("<string>{}</string>\n", p.name),
                );
            }
            out.push_str("</array></plist>\n");
        }
    }
    let _ = sys::atomic_write_secure(path, out.as_bytes(), 0o644, false);
}

fn request_root_from(cfg: &Config) -> PathBuf {
    PathBuf::from(
        cfg.files
            .request_root
            .as_deref()
            .unwrap_or("/var/spool/cups"),
    )
}

fn server_bin_from(cfg: &Config) -> PathBuf {
    PathBuf::from(cfg.files.server_bin.as_deref().unwrap_or("/usr/lib/cups"))
}

fn data_dir_from(cfg: &Config) -> PathBuf {
    PathBuf::from(cfg.files.data_dir.as_deref().unwrap_or("/usr/share/cups"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use job::JobFile;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicU64;

    fn tmp_dir(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "yindle-cupsd-sched-{}-{tag}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn make_script(path: &Path, body: &str) {
        if let Some(par) = path.parent() {
            std::fs::create_dir_all(par).unwrap();
        }
        // Write via a `cp` child so this (multi-threaded, process-spawning) test
        // binary never holds a writable fd to the script: otherwise a concurrent
        // fork could inherit it and make the later exec fail with ETXTBSY.
        let staged = path.with_extension("staged");
        std::fs::write(&staged, body).unwrap();
        let _ = std::fs::remove_file(path);
        let st = std::process::Command::new("cp")
            .arg(&staged)
            .arg(path)
            .status()
            .unwrap();
        assert!(st.success());
        let _ = std::fs::remove_file(&staged);
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    struct TestHarness {
        base: PathBuf,
        spool: PathBuf,
        etc: PathBuf,
        bin: PathBuf,
        sched: Arc<Scheduler>,
        registry: Arc<RwLock<Registry>>,
        jobs: Arc<RwLock<Jobs>>,
        metrics: Arc<Metrics>,
    }

    fn setup_harness(tag: &str, filter_limit: i32, error_policy: &str) -> TestHarness {
        setup_harness_opts(tag, filter_limit, error_policy, false)
    }

    fn setup_harness_opts(
        tag: &str,
        filter_limit: i32,
        error_policy: &str,
        on_demand: bool,
    ) -> TestHarness {
        let base = tmp_dir(tag);
        let etc = base.join("etc");
        let spool = base.join("spool");
        let cache = base.join("cache");
        let bin = base.join("bin");
        let data = base.join("data");
        let logs = base.join("logs");
        for d in [
            &etc,
            &spool,
            &cache,
            &bin.join("backend"),
            &bin.join("filter"),
            &bin.join("daemon"),
            &data.join("mime"),
            &logs,
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(
            data.join("mime").join("mime.types"),
            "text/plain txt\napplication/octet-stream\n",
        )
        .unwrap();
        std::fs::write(
            data.join("mime").join("mime.convs"),
            "text/plain application/vnd.cups-raw 50 passthru\napplication/octet-stream application/vnd.cups-raw 0 -\n",
        )
        .unwrap();

        let mut cfg = Config {
            cupsd: cups_config::CupsdConfig::defaults(),
            files: cups_config::CupsFilesConfig::defaults(),
        };
        cfg.cupsd.filter_limit = filter_limit;
        cfg.cupsd.error_policy = Some(error_policy.into());
        cfg.cupsd.job_retry_limit = 1;
        cfg.cupsd.job_retry_interval = 1;
        cfg.cupsd.job_kill_delay = 1;
        cfg.cupsd.log_level = cups_config::LogLevel::Debug;
        cfg.files.server_root = Some(etc.to_string_lossy().into_owned());
        cfg.files.request_root = Some(spool.to_string_lossy().into_owned());
        cfg.files.cache_dir = Some(cache.to_string_lossy().into_owned());
        cfg.files.server_bin = Some(bin.to_string_lossy().into_owned());
        cfg.files.data_dir = Some(data.to_string_lossy().into_owned());
        cfg.files.error_log = Some(logs.join("error_log").to_string_lossy().into_owned());
        cfg.files.access_log = Some(logs.join("access_log").to_string_lossy().into_owned());
        cfg.files.page_log = Some(logs.join("page_log").to_string_lossy().into_owned());
        cfg.files.printcap = Some(base.join("printcap").to_string_lossy().into_owned());
        cfg.files.file_device = Some(".*".into());
        cfg.files.sandboxing = Sandboxing::Off;
        cfg.files.set_env = vec![
            ("CUSTOM_OK".into(), "yes".into()),
            ("LD_PRELOAD".into(), "/evil.so".into()),
        ];

        let mime = Arc::new(MimeDb::load_standard(&data, &etc).unwrap());
        let log = Arc::new(LogManager::new(&cfg, cups_log::LogFormat::Text, false));
        let metrics = Arc::new(Metrics::new(
            u64::try_from(filter_limit.max(0)).unwrap_or(0),
        ));
        let registry = Arc::new(RwLock::new(Registry::default()));
        let jobs = Arc::new(RwLock::new(Jobs::default()));
        let subs = Arc::new(RwLock::new(Subscriptions::new()));
        let dbus = Arc::new(Notifier::noop());

        let sched = Scheduler::new(
            Arc::new(RwLock::new(Arc::new(cfg))),
            Arc::clone(&registry),
            Arc::clone(&jobs),
            Arc::new(RwLock::new(mime)),
            subs,
            log,
            Arc::clone(&metrics),
            dbus,
            Arc::new(RwLock::new(etc.clone())),
            SchedulerOptions {
                housekeeping_interval: Duration::from_millis(40),
                on_demand,
            },
        );
        TestHarness {
            base,
            spool,
            etc,
            bin,
            sched,
            registry,
            jobs,
            metrics,
        }
    }

    fn add_job(h: &TestHarness, dest: &str, docs: &[(&str, &[u8])]) -> i32 {
        let mut jg = h.jobs.write().unwrap();
        let id = jg.alloc_id();
        let mut j = Job::new(id, dest, "alice");
        j.title = format!("job-{id}");
        j.options
            .insert("sides".into(), "two-sided-long-edge".into());
        j.attrs.push(Attribute {
            tag: tags::KEYWORD,
            name: "media".into(),
            values: vec![Value::Keyword(ipp_codec::Text::from("iso_a4_210x297mm"))],
        });
        for (idx, (mime, data)) in docs.iter().enumerate() {
            let num = u32::try_from(idx + 1).unwrap();
            Job::write_data_file(&h.spool, id, num, data).unwrap();
            j.files.push(JobFile {
                num,
                filetype: (*mime).into(),
                size: data.len() as u64,
                name: format!("doc-{num}"),
                format: (*mime).into(),
            });
        }
        jg.add(&h.spool, j).unwrap();
        id
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_multi_printer_multi_doc_status_events_and_paused_guard() {
        let h = setup_harness("multi", 0, "abort-job");
        let out_dir = h.base.join("out");
        std::fs::create_dir_all(&out_dir).unwrap();

        // Mock backend that appends each doc, emits STATE/INFO/PAGE/ATTR events!
        make_script(
            &h.bin.join("backend").join("mock"),
                "#!/bin/sh\n\
                 echo 'STATE: +toner-low-warning' >&2\n\
                 echo 'INFO: Printing sheet' >&2\n\
                 echo 'PAGE: 1 2' >&2\n\
                 echo 'ATTR: marker-levels=75,40 marker-names=\"Black,Cyan\" marker-colors=\"#000000,#00ffff\"' >&2\n\
                 target=\"${DEVICE_URI#mock://}\"\n\
                 if [ -n \"$6\" ]; then cat \"$6\" >> \"$target\"; else cat >> \"$target\"; fi\n\
                 exit 0\n",
        );
        make_script(
            &h.bin.join("filter").join("passthru"),
            "#!/bin/sh\nif [ -n \"$6\" ]; then cat \"$6\"; else cat; fi\n",
        );

        let f1 = out_dir.join("p1.out");
        let f2 = out_dir.join("p2.out");
        let f3 = out_dir.join("paused.out");
        {
            let mut reg = h.registry.write().unwrap();
            reg.add(Printer::new("p1", format!("mock://{}", f1.display())));
            reg.add(Printer::new("p2", format!("mock://{}", f2.display())));
            let mut paused = Printer::new("paused", format!("mock://{}", f3.display()));
            paused.state = pstate::STOPPED;
            reg.add(paused);

            let mut cls = Printer::new_class("pool");
            cls.add_member("p1");
            cls.add_member("p2");
            reg.add(cls);
        }

        // Submit multi-doc job to p1, single job to p2, and job to paused printer!
        let j1 = add_job(
            &h,
            "p1",
            &[
                ("text/plain", b"doc1-"),
                ("application/octet-stream", b"doc2"),
            ],
        );
        let j2 = add_job(&h, "p2", &[("application/octet-stream", b"hello-p2")]);
        let j_paused = add_job(&h, "paused", &[("application/octet-stream", b"never")]);

        // Single tick MUST dispatch BOTH p1 and p2 concurrently (fixes break-after-1 bug!),
        // and MUST NOT dispatch `paused`!
        let started = h.sched.dispatch_pending();
        assert_eq!(started, 2);

        for _ in 0..80 {
            let done = {
                let jg = h.jobs.read().unwrap();
                jg.get(j1).unwrap().state == JobState::Completed
                    && jg.get(j2).unwrap().state == JobState::Completed
            };
            if done {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        assert_eq!(std::fs::read(&f1).unwrap(), b"doc1-doc2");
        assert_eq!(std::fs::read(&f2).unwrap(), b"hello-p2");
        assert!(!f3.exists());
        assert_eq!(
            h.jobs.read().unwrap().get(j_paused).unwrap().state,
            JobState::Pending
        );

        // Verify live StatusEvents updated printer reasons, message, markers, and page_log!
        {
            let reg = h.registry.read().unwrap();
            let p1 = reg.find("p1").unwrap();
            assert!(p1.reasons.contains(&"toner-low-warning".to_string()));
            assert_eq!(p1.state_message, "Printing sheet");
            assert_eq!(p1.marker_levels, vec![75, 40]);
            assert_eq!(p1.marker_names, vec!["Black", "Cyan"]);
        }
        let page_log = std::fs::read_to_string(h.base.join("logs").join("page_log")).unwrap();
        assert!(page_log.contains("p1 alice"));

        // Class routing dispatches job to an idle member (p1 or p2)
        let j_cls = add_job(&h, "pool", &[("application/octet-stream", b"-from-class")]);
        assert_eq!(h.sched.dispatch_pending(), 1);
        for _ in 0..80 {
            if h.jobs.read().unwrap().get(j_cls).unwrap().state == JobState::Completed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(
            h.jobs.read().unwrap().get(j_cls).unwrap().state,
            JobState::Completed
        );

        h.sched.flush_state();
        assert!(h.etc.join("printers.conf").is_file());
        assert!(h.etc.join("classes.conf").is_file());
        assert!(h.etc.join("subscriptions.conf").is_file());
        assert!(h.base.join("cache").join("job.cache").is_file());
        assert!(h.base.join("printcap").is_file());
        assert_eq!(h.metrics.filter_cost_current(), 0);

        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_kills_pipeline_and_never_overwrites_canceled() {
        let h = setup_harness("cancel", 0, "abort-job");
        make_script(
            &h.bin.join("backend").join("slow"),
            "#!/bin/sh\nsleep 10\nexit 0\n",
        );
        h.registry
            .write()
            .unwrap()
            .add(Printer::new("slowq", "slow://localhost"));

        let jid = add_job(&h, "slowq", &[("application/octet-stream", b"data")]);
        assert_eq!(h.sched.dispatch_pending(), 1);
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Simulate IPP Cancel-Job marking state Canceled + invoking cancel_hook
        {
            let mut jg = h.jobs.write().unwrap();
            let j = jg.get_mut(jid).unwrap();
            j.state = JobState::Canceled;
        }
        let hook = h.sched.cancel_hook();
        hook(u32::try_from(jid).unwrap());

        for _ in 0..80 {
            if h.sched.active_job_count() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(h.sched.active_job_count(), 0);
        // MUST stay Canceled (never overwritten to Completed or Aborted!)
        assert_eq!(
            h.jobs.read().unwrap().get(jid).unwrap().state,
            JobState::Canceled
        );

        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn backend_exit_codes_error_policies_and_housekeeping() {
        let h = setup_harness("exits", 0, "abort-job");
        // Backend exits with code specified after `exitcode://`
        make_script(
            &h.bin.join("backend").join("exitcode"),
            "#!/bin/sh\ncode=\"${DEVICE_URI#exitcode://}\"\nexit \"$code\"\n",
        );
        {
            let mut reg = h.registry.write().unwrap();
            let mut p_abort = Printer::new("p_abort", "exitcode://1");
            p_abort.error_policy = Some("abort-job".into());
            reg.add(p_abort);

            let mut p_cancel = Printer::new("p_cancel", "exitcode://5");
            p_cancel.error_policy = Some("abort-job".into());
            reg.add(p_cancel);

            let p_hold = Printer::new("p_hold", "exitcode://3");
            reg.add(p_hold);

            let p_auth = Printer::new("p_auth", "exitcode://2");
            reg.add(p_auth);

            let p_stop = Printer::new("p_stop", "exitcode://4");
            reg.add(p_stop);

            let mut p_retry = Printer::new("p_retry", "exitcode://7");
            p_retry.error_policy = Some("retry-current-job".into());
            reg.add(p_retry);
        }

        let ja = add_job(&h, "p_abort", &[("application/octet-stream", b"x")]);
        let jc = add_job(&h, "p_cancel", &[("application/octet-stream", b"x")]);
        let jh = add_job(&h, "p_hold", &[("application/octet-stream", b"x")]);
        let jauth = add_job(&h, "p_auth", &[("application/octet-stream", b"x")]);
        let jstop = add_job(&h, "p_stop", &[("application/octet-stream", b"x")]);
        let jretry = add_job(&h, "p_retry", &[("application/octet-stream", b"x")]);

        assert_eq!(h.sched.dispatch_pending(), 6);
        for _ in 0..80 {
            if h.sched.active_job_count() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        {
            let jg = h.jobs.read().unwrap();
            assert_eq!(jg.get(ja).unwrap().state, JobState::Aborted);
            assert_eq!(JobState::Aborted as i32, 8);
            assert_eq!(jg.get(jc).unwrap().state, JobState::Canceled);
            assert_eq!(jg.get(jh).unwrap().state, JobState::PendingHeld);
            assert_eq!(jg.get(jauth).unwrap().state, JobState::PendingHeld);
            assert_eq!(
                jg.get(jauth).unwrap().reasons,
                vec!["cups-held-for-authentication"]
            );
            assert_eq!(jg.get(jstop).unwrap().state, JobState::Pending);
            assert_eq!(jg.get(jretry).unwrap().state, JobState::Pending);
        }
        assert_eq!(
            h.registry.read().unwrap().find("p_stop").unwrap().state,
            pstate::STOPPED
        );

        // Second retry exceeds JobRetryLimit=1 -> Aborted
        assert_eq!(h.sched.dispatch_pending(), 1);
        for _ in 0..80 {
            if h.sched.active_job_count() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(
            h.jobs.read().unwrap().get(jretry).unwrap().state,
            JobState::Aborted
        );

        // Hold-until release & retention housekeeping
        let mut j_held = Job::new(999, "p_abort", "alice");
        j_held.state = JobState::PendingHeld;
        j_held.hold_until = Some("no-hold".into());
        h.jobs.write().unwrap().add(&h.spool, j_held).unwrap();
        let mut last = backdate(Duration::from_secs(120));
        h.sched.mark_dirty();
        h.sched.run_housekeeping(&mut last);
        assert_eq!(
            h.jobs.read().unwrap().get(999).unwrap().state,
            JobState::Pending
        );

        // Helper unit tests
        assert!(is_hold_until_due("no-hold", 100));
        assert!(!is_hold_until_due("indefinite", 100));
        assert!(is_hold_until_due("50", 100));
        assert!(!is_hold_until_due("200", 100));
        assert!(is_hold_until_due("00:00:00", 100));
        assert!(!is_hold_until_due("bad-val", 100));
        let _ = is_hold_until_due("day-time", 100);
        let _ = is_hold_until_due("evening", 100);
        let _ = is_hold_until_due("second-shift", 100);
        let _ = is_hold_until_due("third-shift", 100);
        let _ = is_hold_until_due("weekend", 100);

        let mut rs = vec!["a".into()];
        apply_state_changes(
            &mut rs,
            &[
                StateChange::Add("b".into()),
                StateChange::Remove("a".into()),
                StateChange::Set("c".into()),
                StateChange::Clear,
            ],
        );
        assert_eq!(rs, Vec::<String>::new());

        let (dst, drv) = resolve_ppd_target(Some(
            "*cupsFilter: \"application/vnd.cups-raster 50 rastertofoo\"\n",
        ));
        assert_eq!(dst, "application/vnd.cups-raster");
        assert_eq!(drv.unwrap().program, "rastertofoo");

        write_printcap(
            &h.base.join("pc_solaris"),
            PrintcapFormat::Solaris,
            &h.registry.read().unwrap(),
        );
        write_printcap(
            &h.base.join("pc_plist"),
            PrintcapFormat::Plist,
            &h.registry.read().unwrap(),
        );

        let _ = std::fs::remove_dir_all(&h.base);
    }

    // ---------------------------------------------------------------------
    // Additional coverage: run loop, shutdown, housekeeping, policies, helpers.
    // ---------------------------------------------------------------------

    const OCTET: &str = "application/octet-stream";

    fn set_cfg(h: &TestHarness, f: impl FnOnce(&mut Config)) {
        let mut c = (*h.sched.current_cfg()).clone();
        f(&mut c);
        *h.sched.cfg.write().unwrap() = Arc::new(c);
    }

    fn state_of(h: &TestHarness, id: i32) -> JobState {
        h.jobs.read().unwrap().get(id).unwrap().state
    }

    async fn wait_for(mut cond: impl FnMut() -> bool) -> bool {
        for _ in 0..160 {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        cond()
    }

    fn status_msg(event: StatusEvent) -> StatusMessage {
        StatusMessage {
            stage: "backend:mock".into(),
            is_backend: true,
            event,
            raw: String::new(),
        }
    }

    fn insert_job(h: &TestHarness, dest: &str, state: JobState, f: impl FnOnce(&mut Job)) -> i32 {
        let mut jg = h.jobs.write().unwrap();
        let id = jg.alloc_id();
        let mut j = Job::new(id, dest, "bob");
        j.state = state;
        f(&mut j);
        jg.add(&h.spool, j).unwrap();
        id
    }

    fn add_slow_backend(h: &TestHarness) {
        make_script(
            &h.bin.join("backend").join("slow"),
            "#!/bin/sh\necho 'INFO: warming up' >&2\nsleep 10\nexit 0\n",
        );
    }

    fn backdate(i: Duration) -> Instant {
        Instant::now().checked_sub(i).unwrap()
    }

    fn run_params(h: &TestHarness, job_id: i32, printer: &str, file_ok: bool) -> JobRunParams {
        let cfg = h.sched.current_cfg();
        let p = h.registry.read().unwrap().find(printer).unwrap().clone();
        let j = h.jobs.read().unwrap().get(job_id).unwrap().clone();
        let data = Job::data_path(&h.spool, job_id, 1);
        let raw = "application/vnd.cups-raw";
        JobRunParams {
            job_id,
            printer_name: printer.into(),
            username: j.username.clone(),
            title: j.title.clone(),
            job_attrs: j.attrs.clone(),
            base_spec: build_job_spec(&j, &p, &data, OCTET, raw, &h.bin, &cfg),
            base_opts: build_spawn_options(&cfg, &p, &h.etc, None),
            docs: vec![JobDocument {
                number: 1,
                name: None,
                data_file: data,
                src_type: OCTET.into(),
                chain: Vec::new(),
            }],
            request_root: h.spool.clone(),
            kill_delay: Duration::from_secs(1),
            page_log_fmt: DEFAULT_PAGE_LOG_FORMAT.into(),
            file_device_allowed: file_ok,
            cancel_flag: Arc::new(AtomicBool::new(false)),
            timeout_flag: Arc::new(AtomicBool::new(false)),
            _cost_guard: FilterCostGuard::try_acquire(Arc::clone(&h.metrics), 0).unwrap(),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_loop_shutdown_signals_and_idle_exit() {
        // Already-shut-down receiver: loop exits on the first check.
        let h = setup_harness("runloop", 0, "abort-job");
        let (_tx0, rx0) = watch::channel(true);
        tokio::time::timeout(Duration::from_secs(2), Arc::clone(&h.sched).run(rx0, None))
            .await
            .unwrap();

        // A `false` change keeps looping; a later `true` stops it.
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(Arc::clone(&h.sched).run(rx, None));
        tokio::time::sleep(Duration::from_millis(60)).await;
        h.sched.notify();
        tx.send(false).unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(!handle.is_finished());
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(!h.sched.should_idle_exit());
        let _ = std::fs::remove_dir_all(&h.base);

        // On-demand mode: IdleExitTimeout guard conditions, then a real idle exit.
        let h = setup_harness_opts("idle", 0, "abort-job", true);
        set_cfg(&h, |c| c.cupsd.idle_exit_timeout = 0);
        assert!(!h.sched.should_idle_exit());
        set_cfg(&h, |c| c.cupsd.idle_exit_timeout = 1);
        *h.sched.last_activity.lock().unwrap() = backdate(Duration::from_secs(5));
        h.metrics.inc_active_clients();
        assert!(!h.sched.should_idle_exit());
        h.metrics.dec_active_clients();
        let held = insert_job(&h, "nowhere", JobState::PendingHeld, |j| {
            j.hold_until = Some("indefinite".into());
        });
        assert!(!h.sched.should_idle_exit());
        h.jobs.write().unwrap().get_mut(held).unwrap().state = JobState::Completed;
        assert!(h.sched.should_idle_exit());
        *h.sched.last_activity.lock().unwrap() = Instant::now();
        assert!(!h.sched.should_idle_exit());
        *h.sched.last_activity.lock().unwrap() = backdate(Duration::from_secs(5));

        let (_stx, srx) = watch::channel(false);
        let (itx, irx) = watch::channel(false);
        tokio::time::timeout(
            Duration::from_secs(3),
            Arc::clone(&h.sched).run(srx, Some(itx)),
        )
        .await
        .unwrap();
        assert!(*irx.borrow());
        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_active_jobs_cancels_running_pipelines() {
        let h = setup_harness("shutdown", 0, "abort-job");
        add_slow_backend(&h);
        h.registry
            .write()
            .unwrap()
            .add(Printer::new("slowq", "slow://localhost"));
        let jid = add_job(&h, "slowq", &[(OCTET, b"data")]);
        assert_eq!(h.sched.dispatch_pending(), 1);
        assert!(
            wait_for(|| h
                .jobs
                .read()
                .unwrap()
                .get(jid)
                .unwrap()
                .backend_pid
                .is_some())
            .await
        );

        h.sched.shutdown_active_jobs(Duration::from_secs(5)).await;
        assert_eq!(h.sched.active_job_count(), 0);
        assert!(wait_for(|| state_of(&h, jid) == JobState::Canceled).await);
        assert_eq!(
            h.jobs.read().unwrap().get(jid).unwrap().reasons,
            vec!["job-canceled-by-user"]
        );
        // No active jobs: returns immediately.
        h.sched
            .shutdown_active_jobs(Duration::from_millis(10))
            .await;
        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn max_job_time_times_out_and_aborts_running_job() {
        let h = setup_harness("maxjobtime", 0, "abort-job");
        add_slow_backend(&h);
        h.registry
            .write()
            .unwrap()
            .add(Printer::new("slowq", "slow://localhost"));
        set_cfg(&h, |c| c.cupsd.max_job_time = 1);
        let jid = add_job(&h, "slowq", &[(OCTET, b"data")]);
        assert_eq!(h.sched.dispatch_pending(), 1);
        assert!(
            wait_for(|| h
                .jobs
                .read()
                .unwrap()
                .get(jid)
                .unwrap()
                .backend_pid
                .is_some())
            .await
        );

        let mut last = Instant::now();
        // Not yet exceeded.
        h.sched.run_housekeeping(&mut last);
        assert_eq!(state_of(&h, jid), JobState::Processing);
        if let Some(handle) = h.sched.active_jobs.lock().unwrap().get_mut(&jid) {
            handle.started_at = backdate(Duration::from_secs(10));
        }
        h.sched.run_housekeeping(&mut last);
        h.sched.run_housekeeping(&mut last);
        assert!(wait_for(|| state_of(&h, jid) == JobState::Aborted).await);
        assert_eq!(
            h.jobs.read().unwrap().get(jid).unwrap().reasons,
            vec!["job-aborted-by-system"]
        );
        assert!(wait_for(|| h.sched.active_job_count() == 0).await);
        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn filter_limit_defers_and_max_active_jobs_caps_dispatch() {
        let h = setup_harness("filterlimit", 60, "abort-job");
        add_slow_backend(&h);
        make_script(
            &h.bin.join("filter").join("passthru"),
            "#!/bin/sh\nif [ -n \"$6\" ]; then cat \"$6\"; else cat; fi\n",
        );
        {
            let mut reg = h.registry.write().unwrap();
            reg.add(Printer::new("q1", "slow://one"));
            reg.add(Printer::new("q2", "slow://two"));
            reg.add(Printer::new("q3", "slow://three"));
        }
        let j1 = add_job(&h, "q1", &[("text/plain", b"one")]);
        let j2 = add_job(&h, "q2", &[("text/plain", b"two")]);
        // Second text/plain job (cost 50 + 50 > FilterLimit 60) is deferred.
        assert_eq!(h.sched.dispatch_pending(), 1);
        assert_eq!(state_of(&h, j1), JobState::Processing);
        assert_eq!(state_of(&h, j2), JobState::Pending);

        // MaxActiveJobs=1 stops dispatch even for zero-cost jobs on idle queues.
        set_cfg(&h, |c| c.cupsd.max_active_jobs = 1);
        let j3 = add_job(&h, "q3", &[(OCTET, b"three")]);
        assert_eq!(h.sched.dispatch_pending(), 0);
        assert_eq!(state_of(&h, j3), JobState::Pending);

        // Lift the cap: a non-active Processing job still marks its queue busy.
        set_cfg(&h, |c| c.cupsd.max_active_jobs = 0);
        let stale = insert_job(&h, "q3", JobState::Processing, |_| {});
        assert_eq!(h.sched.dispatch_pending(), 0);
        h.jobs.write().unwrap().get_mut(stale).unwrap().state = JobState::Completed;

        h.sched.shutdown_active_jobs(Duration::from_secs(5)).await;
        assert_eq!(h.sched.active_job_count(), 0);
        assert!(wait_for(|| state_of(&h, j1) == JobState::Canceled).await);
        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ppd_driver_filter_spawn_error_and_retry_policies_via_dispatch() {
        let h = setup_harness("ppddrv", 0, "abort-job");
        let out = h.base.join("drv.out");
        make_script(
            &h.bin.join("backend").join("mock"),
            "#!/bin/sh\ntarget=\"${DEVICE_URI#mock://}\"\n\
             echo 'PAGE: total 3' >&2\n\
             if [ -n \"$6\" ]; then cat \"$6\" >> \"$target\"; else cat >> \"$target\"; fi\nexit 0\n",
        );
        make_script(
            &h.bin.join("filter").join("drvfilter"),
            "#!/bin/sh\nprintf 'DRV:'\nif [ -n \"$6\" ]; then cat \"$6\"; else cat; fi\n",
        );
        make_script(
            &h.bin.join("backend").join("exitcode"),
            "#!/bin/sh\ncode=\"${DEVICE_URI#exitcode://}\"\nexit \"$code\"\n",
        );
        std::fs::create_dir_all(h.etc.join("ppd")).unwrap();
        std::fs::write(
            h.etc.join("ppd").join("drvq.ppd"),
            "*PPD-Adobe: \"4.3\"\n*cupsFilter: \"application/vnd.cups-raw 10 drvfilter\"\n",
        )
        .unwrap();
        {
            let mut reg = h.registry.write().unwrap();
            reg.add(Printer::new("drvq", format!("mock://{}", out.display())));
            // Backend binary does not exist -> SpawnError -> ErrorPolicy abort-job.
            reg.add(Printer::new("nobackend", "nosuchbackend://x"));
            let mut p_retry = Printer::new("p_retry", "exitcode://6");
            p_retry.error_policy = Some("retry-job".into());
            reg.add(p_retry);
        }
        set_cfg(&h, |c| c.cupsd.job_retry_interval = 600);
        let jd = add_job(&h, "drvq", &[(OCTET, b"payload")]);
        let jn = add_job(&h, "nobackend", &[(OCTET, b"x")]);
        let jr = add_job(&h, "p_retry", &[(OCTET, b"x")]);
        assert_eq!(h.sched.dispatch_pending(), 3);
        assert!(wait_for(|| h.sched.active_job_count() == 0).await);
        assert_eq!(state_of(&h, jd), JobState::Completed);
        assert_eq!(std::fs::read(&out).unwrap(), b"DRV:payload");
        assert_eq!(state_of(&h, jn), JobState::Aborted);
        // BackendExit::Retry -> requeued with JobRetryInterval delay (not immediately redispatched).
        assert_eq!(state_of(&h, jr), JobState::Pending);
        assert_eq!(
            h.jobs.read().unwrap().get(jr).unwrap().reasons,
            vec!["job-restartable"]
        );
        assert!(
            h.sched
                .retries
                .lock()
                .unwrap()
                .get(&jr)
                .unwrap()
                .next_retry_at
                > 0
        );
        assert_eq!(h.sched.dispatch_pending(), 0);
        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[test]
    fn run_documents_blocking_guard_paths() {
        let h = setup_harness("rundocs", 0, "abort-job");
        make_script(&h.bin.join("backend").join("ok"), "#!/bin/sh\nexit 0\n");
        {
            let mut reg = h.registry.write().unwrap();
            reg.add(Printer::new(
                "fileq",
                format!("file://{}", h.base.join("f.out").display()),
            ));
            reg.add(Printer::new("okq", "ok://x"));
            reg.add(Printer::new("missing", "missing://x"));
        }
        let jf = add_job(&h, "fileq", &[(OCTET, b"x")]);
        let jo = add_job(&h, "okq", &[(OCTET, b"x")]);
        let jm = add_job(&h, "missing", &[(OCTET, b"x")]);

        let r = h
            .sched
            .run_documents_blocking(&run_params(&h, jf, "fileq", false));
        assert!(matches!(r, JobExecResult::SpawnError(ref m) if m.contains("FileDevice")));

        let p = run_params(&h, jo, "okq", true);
        p.cancel_flag.store(true, Ordering::SeqCst);
        assert!(matches!(
            h.sched.run_documents_blocking(&p),
            JobExecResult::Canceled
        ));

        let p = run_params(&h, jo, "okq", true);
        p.timeout_flag.store(true, Ordering::SeqCst);
        assert!(matches!(
            h.sched.run_documents_blocking(&p),
            JobExecResult::TimedOut
        ));

        let r = h
            .sched
            .run_documents_blocking(&run_params(&h, jm, "missing", true));
        assert!(matches!(r, JobExecResult::SpawnError(_)));

        let r = h
            .sched
            .run_documents_blocking(&run_params(&h, jo, "okq", true));
        assert!(matches!(r, JobExecResult::Exited(ref pe) if pe.is_ok()));
        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn finalize_outcomes_and_error_policies_direct() {
        let h = setup_harness("policies", 0, "stop-printer");
        {
            let mut reg = h.registry.write().unwrap();
            for name in ["pa", "pb", "pc", "pd", "pe"] {
                let mut p = Printer::new(name, "mock://x");
                p.state = pstate::PROCESSING;
                reg.add(p);
            }
        }
        let rr = h.spool.clone();
        let processing = |h: &TestHarness, dest: &str| {
            insert_job(h, dest, JobState::Processing, |j| {
                j.reasons = vec!["job-printing".into()];
            })
        };
        let now = job::now();

        // Canceled outcome for an unknown job id is harmless.
        h.sched.finalize_job_outcome(
            424_242,
            "pa",
            "u",
            "t",
            &rr,
            JobExecResult::Canceled,
            false,
            false,
            0.1,
        );

        // Outcome-reported timeout (flag unset) still aborts.
        let jt = processing(&h, "pa");
        h.sched.finalize_job_outcome(
            jt,
            "pa",
            "u",
            "t",
            &rr,
            JobExecResult::TimedOut,
            false,
            false,
            0.1,
        );
        assert_eq!(state_of(&h, jt), JobState::Aborted);

        // SpawnError with per-printer retry-current-job policy.
        h.registry
            .write()
            .unwrap()
            .find_mut("pb")
            .unwrap()
            .error_policy = Some("Retry-Current-Job".into());
        let js = processing(&h, "pb");
        h.sched.finalize_job_outcome(
            js,
            "pb",
            "u",
            "t",
            &rr,
            JobExecResult::SpawnError("boom".into()),
            false,
            false,
            0.1,
        );
        assert_eq!(state_of(&h, js), JobState::Pending);
        assert_eq!(
            h.sched.retries.lock().unwrap().get(&js).unwrap().attempts,
            1
        );

        // retry-job policy on an unknown exit code; then retry limit exhausted -> abort.
        let jr = processing(&h, "pc");
        h.sched.handle_backend_failure(
            jr,
            "pc",
            "t",
            &rr,
            BackendExit::Unknown(42),
            "retry-job",
            1,
            30,
            0.1,
            now,
        );
        assert_eq!(state_of(&h, jr), JobState::Pending);
        assert_eq!(
            h.sched
                .retries
                .lock()
                .unwrap()
                .get(&jr)
                .unwrap()
                .next_retry_at,
            now + 30
        );
        h.sched.handle_backend_failure(
            jr,
            "pc",
            "t",
            &rr,
            BackendExit::Failed,
            "retry-current-job",
            1,
            30,
            0.1,
            now,
        );
        assert_eq!(state_of(&h, jr), JobState::Aborted);
        assert!(h.sched.retries.lock().unwrap().get(&jr).is_none());

        // RetryLimit 0 disables retries entirely.
        let j0 = processing(&h, "pc");
        h.sched.requeue_or_abort(j0, "pc", "t", &rr, 0, 0, 0.1, now);
        assert_eq!(state_of(&h, j0), JobState::Aborted);

        // BackendExit::Retry / RetryCurrent honor the retry limit too.
        let jx = processing(&h, "pd");
        h.sched.handle_backend_failure(
            jx,
            "pd",
            "t",
            &rr,
            BackendExit::Retry,
            "abort-job",
            3,
            5,
            0.1,
            now,
        );
        assert_eq!(state_of(&h, jx), JobState::Pending);
        h.sched.handle_backend_failure(
            jx,
            "pd",
            "t",
            &rr,
            BackendExit::RetryCurrent,
            "abort-job",
            3,
            5,
            0.1,
            now,
        );
        assert_eq!(state_of(&h, jx), JobState::Pending);
        assert_eq!(
            h.sched.retries.lock().unwrap().get(&jx).unwrap().attempts,
            2
        );

        // Default stop-printer policy on a signal; second stop keeps a single "paused".
        let jp = processing(&h, "pe");
        h.sched.handle_backend_failure(
            jp,
            "pe",
            "t",
            &rr,
            BackendExit::Signal(9),
            "stop-printer",
            3,
            5,
            0.1,
            now,
        );
        h.sched.stop_printer_and_requeue(jp, "pe", &rr, now);
        {
            let reg = h.registry.read().unwrap();
            let pe = reg.find("pe").unwrap();
            assert_eq!(pe.state, pstate::STOPPED);
            assert_eq!(pe.reasons.iter().filter(|r| *r == "paused").count(), 1);
        }
        assert_eq!(state_of(&h, jp), JobState::Pending);
        // Stopped printer is not reset to idle.
        h.sched.set_printer_idle_if_processing("pe", now);
        assert_eq!(
            h.registry.read().unwrap().find("pe").unwrap().state,
            pstate::STOPPED
        );
        // Unknown printer / job ids are tolerated everywhere.
        h.sched.stop_printer_and_requeue(777_777, "ghost", &rr, now);
        h.sched.set_printer_idle_if_processing("ghost", now);
        h.sched.emit_event(
            Event::ServerRestarted,
            None,
            None,
            None,
            None,
            "no printer".into(),
        );
        h.sched.emit_event(
            Event::PrinterStateChanged,
            Some("ghost"),
            None,
            None,
            None,
            "unknown printer".into(),
        );
        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn apply_status_message_all_event_kinds() {
        let h = setup_harness("status", 0, "abort-job");
        h.registry
            .write()
            .unwrap()
            .add(Printer::new("sp", "mock://x"));
        let jid = insert_job(&h, "sp", JobState::Processing, |j| {
            j.attrs.push(Attribute {
                tag: tags::KEYWORD,
                name: "job-impressions-completed".into(),
                values: vec![Value::Keyword(ipp_codec::Text::from("bogus"))],
            });
        });
        let fmt = DEFAULT_PAGE_LOG_FORMAT;
        let apply = |printer: &str, job: i32, ev: StatusEvent| {
            h.sched
                .apply_status_message(job, printer, "bob", &[], fmt, status_msg(ev));
        };
        let impressions = || {
            let jg = h.jobs.read().unwrap();
            let j = jg.get(jid).unwrap();
            let a = j
                .attrs
                .iter()
                .find(|a| a.name == "job-impressions-completed")
                .unwrap();
            match a.values[0] {
                Value::Integer(n) => n,
                _ => -1,
            }
        };

        apply(
            "sp",
            jid,
            StatusEvent::Log {
                severity: LogSeverity::Debug,
                message: "debug only".into(),
            },
        );
        apply(
            "ghost",
            jid,
            StatusEvent::Log {
                severity: LogSeverity::Warning,
                message: "no printer".into(),
            },
        );
        apply("ghost", jid, StatusEvent::State(vec![StateChange::Clear]));

        // Non-integer impressions value is treated as 0.
        apply(
            "sp",
            jid,
            StatusEvent::Page(PageEvent::Sheet {
                page: 1,
                copies: 0,
                extra: None,
            }),
        );
        assert_eq!(impressions(), 1);
        apply("sp", jid, StatusEvent::Page(PageEvent::Total(5)));
        assert_eq!(impressions(), 5);
        apply("sp", jid, StatusEvent::Page(PageEvent::Total(2)));
        assert_eq!(impressions(), 5);

        // Total on a job without the attribute creates it.
        let j2 = insert_job(&h, "sp", JobState::Processing, |_| {});
        apply("sp", j2, StatusEvent::Page(PageEvent::Total(7)));
        assert!(h
            .jobs
            .read()
            .unwrap()
            .get(j2)
            .unwrap()
            .attrs
            .iter()
            .any(|a| a.name == "job-impressions-completed" && a.values == [Value::Integer(7)]));
        let mut attrs = vec![Attribute {
            tag: tags::INTEGER,
            name: "job-impressions-completed".into(),
            values: vec![Value::NoValue],
        }];
        set_job_impressions_min(&mut attrs, 3);
        assert_eq!(attrs[0].values, vec![Value::Integer(3)]);

        apply(
            "sp",
            jid,
            StatusEvent::Attr(vec![
                ("marker-types".into(), "toner,ink".into()),
                ("marker-low-levels".into(), "5,x,10".into()),
                ("marker-high-levels".into(), "100".into()),
                ("marker-message".into(), "Low".into()),
                ("printer-alert".into(), "code=1".into()),
                ("printer-alert-description".into(), "jam".into()),
                ("auth-info-required".into(), "username,password".into()),
                ("unknown-key".into(), "ignored".into()),
            ]),
        );
        apply("ghost", jid, StatusEvent::Attr(vec![]));
        {
            let reg = h.registry.read().unwrap();
            let p = reg.find("sp").unwrap();
            assert_eq!(p.marker_types, vec!["toner", "ink"]);
            assert_eq!(p.marker_low_levels, vec![5, 10]);
            assert_eq!(p.marker_high_levels, vec![100]);
            assert_eq!(p.marker_message, "Low");
            assert_eq!(p.alert.as_deref(), Some("code=1"));
            assert_eq!(p.alert_description.as_deref(), Some("jam"));
            assert_eq!(p.auth_info_required, vec!["username", "password"]);
        }
        assert!(h.sched.dirty.load(Ordering::Acquire));
        apply(
            "sp",
            jid,
            StatusEvent::Ppd(vec![("PageSize".into(), "A4".into())]),
        );

        // Attr pairs with no marker keys leave marker_time untouched.
        let mut p = Printer::new("x", "mock://x");
        let before = p.marker_time;
        apply_printer_attrs(&mut p, &[("printer-alert".into(), "a".into())]);
        assert_eq!(p.marker_time, before);
        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[test]
    fn housekeeping_hold_release_max_hold_and_retention() {
        let h = setup_harness("housekeep", 0, "abort-job");
        let now = job::now();
        set_cfg(&h, |c| c.cupsd.max_hold_time = 60);
        let expired = insert_job(&h, "q", JobState::PendingHeld, |j| {
            j.hold_until = Some("indefinite".into());
            j.created_at = now - 3600;
        });
        let released = insert_job(&h, "q", JobState::PendingHeld, |j| {
            j.hold_until = Some("no-hold".into());
            j.reasons = vec!["job-hold-until-specified".into()];
        });
        let still_held = insert_job(&h, "q", JobState::PendingHeld, |j| {
            j.hold_until = Some("indefinite".into());
        });
        let no_hold_attr = insert_job(&h, "q", JobState::PendingHeld, |_| {});
        let mut last = Instant::now();
        h.sched.run_housekeeping(&mut last);
        assert_eq!(state_of(&h, expired), JobState::Canceled);
        assert_eq!(
            h.jobs.read().unwrap().get(expired).unwrap().reasons,
            vec!["job-canceled-by-system"]
        );
        assert_eq!(state_of(&h, released), JobState::Pending);
        assert_eq!(
            h.jobs.read().unwrap().get(released).unwrap().reasons,
            vec!["none"]
        );
        assert_eq!(state_of(&h, still_held), JobState::PendingHeld);
        assert_eq!(state_of(&h, no_hold_attr), JobState::PendingHeld);

        // PreserveJobFiles=0 removes spool data of finished jobs but keeps history.
        set_cfg(&h, |c| {
            c.cupsd.max_hold_time = 0;
            c.cupsd.preserve_job_files = 0;
        });
        let done = add_job(&h, "q", &[(OCTET, b"spooled")]);
        {
            let mut jg = h.jobs.write().unwrap();
            let j = jg.get_mut(done).unwrap();
            j.state = JobState::Completed;
            j.completed_at = Some(now - 10);
        }
        let data = Job::data_path(&h.spool, done, 1);
        assert!(data.is_file());
        h.sched.run_housekeeping(&mut last);
        assert!(!data.exists());
        assert_eq!(h.jobs.read().unwrap().get(done).unwrap().files.len(), 0);

        // PreserveJobHistory=0 purges finished jobs entirely.
        h.sched.dirty.store(false, Ordering::Release);
        set_cfg(&h, |c| c.cupsd.preserve_job_history = 0);
        h.sched.run_housekeeping(&mut last);
        assert!(h.jobs.read().unwrap().get(done).is_none());
        assert!(h.jobs.read().unwrap().get(expired).is_none());
        assert!(h.sched.dirty.load(Ordering::Acquire));

        // MaxJobs purges the oldest terminal jobs first.
        set_cfg(&h, |c| {
            c.cupsd.preserve_job_history = i32::MAX;
            c.cupsd.preserve_job_files = i32::MAX;
            c.cupsd.max_jobs = 4;
        });
        let mut olds = Vec::new();
        for age in [400, 300, 200, 100] {
            olds.push(insert_job(&h, "q", JobState::Completed, |j| {
                j.completed_at = Some(now - age);
            }));
        }
        let total_before = h.jobs.read().unwrap().by_id.len();
        assert!(total_before > 4);
        h.sched.run_housekeeping(&mut last);
        let jg = h.jobs.read().unwrap();
        assert_eq!(jg.by_id.len(), 4);
        assert!(jg.get(olds[0]).is_none());
        assert!(jg.get(released).is_some());
        drop(jg);
        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[test]
    fn flush_state_reports_write_failures() {
        let h = setup_harness("flusherr", 0, "abort-job");
        let not_a_dir = h.base.join("not-a-dir");
        std::fs::write(&not_a_dir, b"file").unwrap();
        *h.sched.server_root.write().unwrap() = not_a_dir.clone();
        set_cfg(&h, |c| {
            c.files.printcap = Some("none".into());
            c.files.cache_dir = Some(not_a_dir.join("cache").to_string_lossy().into_owned());
        });
        h.sched.mark_dirty();
        h.sched.flush_state();
        assert!(!h.sched.dirty.load(Ordering::Acquire));

        // job.cache path occupied by a directory -> save_cache error is logged.
        let cache = h.base.join("cache2");
        std::fs::create_dir_all(cache.join("job.cache")).unwrap();
        set_cfg(&h, |c| {
            c.files.printcap = Some(String::new());
            c.files.cache_dir = Some(cache.to_string_lossy().into_owned());
        });
        h.sched.flush_state();
        set_cfg(&h, |c| {
            c.files.printcap = None;
            c.files.cache_dir = None;
        });
        h.sched.flush_state();
        let log =
            std::fs::read_to_string(h.base.join("logs").join("error_log")).unwrap_or_default();
        assert!(log.is_empty() || log.contains("Unable to save"));
        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[test]
    fn resolve_target_printer_class_routing_paths() {
        let h = setup_harness("classes", 0, "abort-job");
        {
            let mut reg = h.registry.write().unwrap();
            reg.add(Printer::new("m1", "mock://1"));
            reg.add(Printer::new("m2", "mock://2"));
            reg.add(Printer::new("m3", "mock://3"));
            let mut pool = Printer::new_class("pool");
            pool.add_member("m1");
            pool.add_member("ghost");
            pool.add_member("m2");
            reg.add(pool);
            let mut inner = Printer::new_class("inner");
            inner.add_member("m3");
            reg.add(inner);
            let mut outer = Printer::new_class("outer");
            outer.add_member("inner");
            reg.add(outer);
            reg.add(Printer::new_class("empty"));
            let mut rejecting = Printer::new("rej", "mock://r");
            rejecting.accepting = false;
            reg.add(rejecting);
        }
        let none: HashSet<String> = HashSet::new();
        let busy = |names: &[&str]| {
            names
                .iter()
                .map(|s| (*s).to_string())
                .collect::<HashSet<_>>()
        };

        assert!(h.sched.resolve_target_printer("nope", &none).is_none());
        assert!(h.sched.resolve_target_printer("rej", &none).is_none());
        assert!(h
            .sched
            .resolve_target_printer("m1", &busy(&["m1"]))
            .is_none());
        // Round-robin across idle members.
        let a = h.sched.resolve_target_printer("pool", &none).unwrap().name;
        let b = h.sched.resolve_target_printer("pool", &none).unwrap().name;
        assert_ne!(a, b);
        // Skips busy member.
        assert_eq!(
            h.sched
                .resolve_target_printer("pool", &busy(&["m1"]))
                .unwrap()
                .name,
            "m2"
        );
        // All members busy -> fallback resolver also busy -> None.
        assert!(h
            .sched
            .resolve_target_printer("pool", &busy(&["m1", "m2"]))
            .is_none());
        // Nested class: direct members are classes, fallback resolves m3.
        assert_eq!(
            h.sched.resolve_target_printer("outer", &none).unwrap().name,
            "m3"
        );
        // Empty class has nothing to resolve.
        assert!(h.sched.resolve_target_printer("empty", &none).is_none());
        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn job_spec_env_ppd_and_value_helpers() {
        let h = setup_harness("helpers", 0, "abort-job");
        let cfg = h.sched.current_cfg();
        let p = Printer::new("hp", "mock://x");
        let mut j = Job::new(1, "hp", "carol");
        let kw = |s: &str| ipp_codec::Text::from(s);
        let attr = |name: &str, v: Value| Attribute {
            tag: tags::KEYWORD,
            name: name.into(),
            values: vec![v],
        };
        j.attrs = vec![
            attr("sides", Value::Keyword(kw("one-sided"))),
            attr("number-up", Value::Integer(2)),
            attr("orientation-requested", Value::Enum(4)),
            attr("print-quality", Value::Enum(5)),
            attr("print-color-mode", Value::Keyword(kw("monochrome"))),
            attr("page-ranges", Value::Range { low: 1, high: 3 }),
            attr("finishings", Value::Enum(3)),
            attr("job-billing", Value::Name(kw("acct"))),
            attr("job-sheets", Value::Collection(Vec::new())),
            attr("job-name", Value::Name(kw("ignored"))),
        ];
        let spec = build_job_spec(&j, &p, Path::new("/tmp/d"), OCTET, OCTET, &h.bin, &cfg);
        for needle in [
            "number-up=2",
            "page-ranges=1-3",
            "job-billing=acct",
            "print-color-mode=monochrome",
        ] {
            assert!(
                spec.options.contains(needle),
                "{needle} in {}",
                spec.options
            );
        }
        assert!(!spec.options.contains("job-sheets"));

        assert_eq!(
            ipp_value_to_option_str(&Value::Boolean(true)).as_deref(),
            Some("true")
        );
        assert_eq!(
            ipp_value_to_option_str(&Value::Boolean(false)).as_deref(),
            Some("false")
        );
        assert_eq!(
            ipp_value_to_option_str(&Value::Text(kw("a"))).as_deref(),
            Some("a")
        );
        assert_eq!(
            ipp_value_to_option_str(&Value::MimeMediaType(kw("b"))).as_deref(),
            Some("b")
        );
        assert_eq!(
            ipp_value_to_option_str(&Value::Uri(kw("c"))).as_deref(),
            Some("c")
        );
        assert!(ipp_value_to_option_str(&Value::NoValue).is_none());

        // PassEnv: only existing, non-prohibited variables are forwarded.
        let existing = std::env::vars()
            .map(|(k, _)| k)
            .find(|k| !k.is_empty() && !cups_config::is_prohibited_env(k));
        let mut c2 = (*cfg).clone();
        c2.files.pass_env = vec![
            String::new(),
            "LD_PRELOAD".into(),
            "YINDLE_SURELY_UNSET_VARIABLE_XYZ".into(),
        ];
        if let Some(ref k) = existing {
            c2.files.pass_env.push(k.clone());
        }
        c2.files.set_env.push((String::new(), "x".into()));
        let env = collect_configured_env(&c2);
        assert!(!env.contains_key("LD_PRELOAD"));
        assert!(!env.contains_key("YINDLE_SURELY_UNSET_VARIABLE_XYZ"));
        assert_eq!(env.get("CUSTOM_OK").map(String::as_str), Some("yes"));
        if let Some(k) = existing {
            assert!(env.contains_key(&k));
        }

        // PPD target selection without filters, and PPD loading via cups-driverd.
        assert_eq!(
            resolve_ppd_target(Some("*PPD-Adobe: \"4.3\"\n")).0,
            "application/vnd.cups-raw"
        );
        assert_eq!(resolve_ppd_target(None).0, "application/vnd.cups-raw");
        let data = h.base.join("data");
        let mut pp = Printer::new("drvp", "mock://x");
        assert!(load_printer_ppd(&pp, &h.etc, &h.bin, &data).is_none());
        std::fs::create_dir_all(h.etc.join("ppd")).unwrap();
        std::fs::write(h.etc.join("ppd").join("drvp.ppd"), b"").unwrap();
        pp.options
            .push(("PPD-Name".into(), "drv:///foo.ppd".into()));
        assert!(load_printer_ppd(&pp, &h.etc, &h.bin, &data).is_none());
        make_script(
            &h.bin.join("daemon").join("cups-driverd"),
            "#!/bin/sh\n[ \"$1\" = cat ] || exit 1\n[ \"$2\" = fail ] && exit 2\n\
             echo \"*PPD-Adobe: \\\"4.3\\\"\"\necho \"*% $PPDDIR\"\n",
        );
        // Retry briefly: a concurrently forked test process may transiently hold the
        // freshly written script open (ETXTBSY).
        let load_retry = |pp: &Printer| {
            (0..100)
                .find_map(|_| {
                    let res = load_printer_ppd(pp, &h.etc, &h.bin, &data);
                    if res.is_none() {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    res
                })
                .unwrap()
        };
        let text = load_retry(&pp);
        assert!(text.contains("PPD-Adobe"));
        std::fs::create_dir_all(data.join("ppd")).unwrap();
        let text = load_retry(&pp);
        assert!(text.contains(&data.join("ppd").display().to_string()));
        pp.options = vec![("ppd-name".into(), "fail".into())];
        assert!(load_printer_ppd(&pp, &h.etc, &h.bin, &data).is_none());

        // job-hold-until HH:MM parsing edge cases.
        assert!(!is_hold_until_due("aa:bb", 100));
        assert!(!is_hold_until_due("25:00", 100));
        assert!(!is_hold_until_due("12:61", 100));
        assert!(is_hold_until_due("", 100));

        let mut attrs = Vec::new();
        increment_job_impressions(&mut attrs, 2);
        increment_job_impressions(&mut attrs, 3);
        assert_eq!(attrs[0].values, vec![Value::Integer(5)]);
        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[test]
    fn unprivileged_exec_adjustments_upg_and_file_device() {
        let h = setup_harness("upg", 0, "abort-job");
        let cfg = h.sched.current_cfg();
        let (uid, gid) = pipeline::current_euid_egid();
        let conv = |prog: &str| mime_db::Conv {
            src: OCTET.into(),
            dst: "application/vnd.cups-raw".into(),
            cost: 1,
            program: prog.into(),
        };
        let mk = |uri: &str| {
            let p = Printer::new("u", uri);
            let j = Job::new(1, "u", "dave");
            let spec = build_job_spec(&j, &p, Path::new("/tmp/d"), OCTET, OCTET, &h.bin, &cfg);
            let opts = build_spawn_options(&cfg, &p, &h.etc, None);
            (spec, opts)
        };

        // FileDevice Yes + file:// backend disables sandboxing.
        let (mut spec, mut opts) = mk("file:///tmp/out");
        apply_unprivileged_exec_adjustments(&mut spec, &mut opts, &[], true);
        assert_eq!(opts.sandbox.mode, Sandboxing::Off);
        if uid != 0 {
            assert!(opts.sandbox.cups_exec_path.is_none());
        }

        // UPG 0775 backend + filter owned by us -> group-writable relaxation.
        let upg = h.bin.join("backend").join("upg");
        make_script(&upg, "#!/bin/sh\nexit 0\n");
        std::fs::set_permissions(&upg, std::fs::Permissions::from_mode(0o775)).unwrap();
        let upg_filter = h.bin.join("filter").join("upgf");
        make_script(&upg_filter, "#!/bin/sh\ncat\n");
        std::fs::set_permissions(&upg_filter, std::fs::Permissions::from_mode(0o775)).unwrap();
        let ww_filter = h.bin.join("filter").join("wwf");
        make_script(&ww_filter, "#!/bin/sh\ncat\n");
        std::fs::set_permissions(&ww_filter, std::fs::Permissions::from_mode(0o777)).unwrap();
        let upg_ok = is_upg_group_writable(&upg, uid, gid);

        let (mut spec, mut opts) = mk("upg://x");
        opts.security.reject_group_or_world_writable = true;
        apply_unprivileged_exec_adjustments(
            &mut spec,
            &mut opts,
            &[conv("-"), conv("upgf")],
            false,
        );
        if uid != 0 && upg_ok {
            assert!(!opts.security.reject_group_or_world_writable);
        }

        // A world-writable filter in the chain blocks the relaxation.
        let (mut spec, mut opts) = mk("missing://x");
        opts.security.reject_group_or_world_writable = true;
        apply_unprivileged_exec_adjustments(
            &mut spec,
            &mut opts,
            &[conv("upgf"), conv("wwf")],
            false,
        );
        assert!(opts.security.reject_group_or_world_writable);

        assert!(!is_upg_group_writable(&h.bin.join("nope"), uid, gid));
        assert!(!is_upg_group_writable(&ww_filter, uid, gid));
        assert!(is_world_writable(&ww_filter));
        assert!(!is_world_writable(&h.bin.join("nope")));
        let _ = std::fs::remove_dir_all(&h.base);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn early_exiting_backend_terminates_stuck_filter_and_drains_final_status() {
        let h = setup_harness("stuck_flt", 200, "abort-job");

        // Filter ignores SIGPIPE and sleeps 60s so a blocking `f.wait()` would hang forever!
        let stuck_filter = h.bin.join("filter").join("passthru");
        make_script(
            &stuck_filter,
            "#!/bin/sh\ntrap '' PIPE\necho 'INFO: filter running' >&2\nsleep 60\n",
        );

        // Backend emits final PAGE/INFO lines and exits immediately with CUPS_BACKEND_CANCEL (5).
        let fast_be = h.bin.join("backend").join("fastfail");
        make_script(
            &fast_be,
            "#!/bin/sh\necho 'PAGE: 1 2' >&2\necho 'INFO: backend exited early' >&2\nexit 5\n",
        );

        {
            let mut reg = h.registry.write().unwrap();
            let mut p = Printer::new("qstuck", "fastfail://dev");
            p.state = pstate::IDLE;
            p.accepting = true;
            reg.add(p);
        }
        let jid = add_job(&h, "qstuck", &[("text/plain", b"hello\n")]);

        let started = Instant::now();
        h.sched.dispatch_pending();
        let deadline = Instant::now() + Duration::from_secs(6);
        while Instant::now() < deadline {
            if h.jobs
                .read()
                .unwrap()
                .get(jid)
                .is_some_and(|j| j.state == JobState::Canceled)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(
            h.jobs.read().unwrap().get(jid).unwrap().state,
            JobState::Canceled
        );
        // Must complete rapidly without hanging on the 60s sleeping filter!
        assert!(started.elapsed() < Duration::from_secs(5));
        // FilterCostGuard must be released and printer returned to Idle!
        assert_eq!(h.metrics.filter_cost_current(), 0);
        assert_eq!(
            h.registry.read().unwrap().find("qstuck").unwrap().state,
            pstate::IDLE
        );
        // Trailing stderr PAGE/INFO lines written just before backend exit were not dropped!
        let sheets = h
            .jobs
            .read()
            .unwrap()
            .get(jid)
            .unwrap()
            .attrs
            .iter()
            .find(|a| a.name.as_str() == "job-impressions-completed")
            .and_then(|a| a.values.first())
            .and_then(|v| match v {
                Value::Integer(n) => Some(*n),
                _ => None,
            });
        assert_eq!(sheets, Some(2));

        let _ = std::fs::remove_dir_all(&h.base);
    }
}
