//! Enterprise observability: Prometheus `/metrics` exposition, `/healthz`,
//! and `/readyz` probe handlers.
//!
//! All metric names and label keys match `deploy/monitoring/prometheus-alerts.yaml`
//! and `deploy/monitoring/grafana-dashboard.json` 100% verbatim:
//! - `yindle_jobs_active{printer}`
//! - `yindle_jobs_pending{printer}`
//! - `yindle_jobs_total{state}`
//! - `yindle_job_duration_seconds_bucket{le}` / `_sum` / `_count`
//! - `yindle_ipp_requests_total{operation,status}`
//! - `yindle_auth_failures_total{reason}`
//! - `yindle_active_clients`
//! - `yindle_filter_cost_current`
//! - `yindle_filter_limit`

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use httpd::{Response, StatusCode};
use job::{JobState, Jobs};
use printer::{pstate, Registry};

use crate::cli::{push_json_str, VERSION};

/// Prometheus text exposition content type (version 0.0.4).
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Histogram bucket upper bounds (seconds) for `yindle_job_duration_seconds`.
pub const JOB_DURATION_BUCKETS: &[f64] = &[
    0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
];

/// Thread-safe Prometheus histogram for job completion durations.
#[derive(Debug)]
struct DurationHistogram {
    /// Per-bucket counters matching [`JOB_DURATION_BUCKETS`].
    buckets: Vec<AtomicU64>,
    /// Total observed samples (`+Inf` bucket and `_count`).
    count: AtomicU64,
    /// Cumulative duration in microseconds (avoids float atomics).
    sum_micros: AtomicU64,
}

impl Default for DurationHistogram {
    fn default() -> Self {
        Self {
            buckets: JOB_DURATION_BUCKETS
                .iter()
                .map(|_| AtomicU64::new(0))
                .collect(),
            count: AtomicU64::new(0),
            sum_micros: AtomicU64::new(0),
        }
    }
}

impl DurationHistogram {
    fn observe(&self, seconds: f64) {
        let clamped = if seconds.is_finite() && seconds >= 0.0 {
            seconds
        } else {
            0.0
        };
        for (i, &bound) in JOB_DURATION_BUCKETS.iter().enumerate() {
            if clamped <= bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let micros = (clamped * 1_000_000.0).round() as u64;
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
    }

    fn render(&self, out: &mut String) {
        out.push_str(
            "# HELP yindle_job_duration_seconds Print job processing duration in seconds.\n\
             # TYPE yindle_job_duration_seconds histogram\n",
        );
        for (i, &bound) in JOB_DURATION_BUCKETS.iter().enumerate() {
            let v = self.buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "yindle_job_duration_seconds_bucket{{le=\"{bound}\"}} {v}"
            );
        }
        let total = self.count.load(Ordering::Relaxed);
        #[allow(clippy::cast_precision_loss)]
        let sum_secs = self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let _ = writeln!(
            out,
            "yindle_job_duration_seconds_bucket{{le=\"+Inf\"}} {total}"
        );
        let _ = writeln!(out, "yindle_job_duration_seconds_sum {sum_secs:.6}");
        let _ = writeln!(out, "yindle_job_duration_seconds_count {total}");
    }
}

/// Shared runtime metrics store for `cupsd`.
#[derive(Debug)]
pub struct Metrics {
    started_at: Instant,
    shutting_down: AtomicBool,
    active_clients: AtomicI64,
    filter_cost_current: AtomicU64,
    filter_limit: AtomicU64,
    /// `yindle_jobs_total{state}`
    jobs_total: RwLock<BTreeMap<String, u64>>,
    /// `yindle_ipp_requests_total{operation,status}`
    ipp_requests: RwLock<BTreeMap<(String, String), u64>>,
    /// `yindle_auth_failures_total{reason}`
    auth_failures: RwLock<BTreeMap<String, u64>>,
    /// `yindle_pages_printed_total{printer}`
    pages_printed: RwLock<BTreeMap<String, u64>>,
    /// `yindle_http_requests_total{method,status}`
    http_requests: RwLock<BTreeMap<(String, u16), u64>>,
    /// `yindle_job_duration_seconds`
    job_duration: DurationHistogram,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Metrics {
    /// Create a fresh metrics registry initialized with `filter_limit`.
    #[must_use]
    pub fn new(filter_limit: u64) -> Self {
        let mut jobs_total = BTreeMap::new();
        for state in ["completed", "aborted", "canceled", "canceled-at-device"] {
            jobs_total.insert(state.to_string(), 0);
        }
        Self {
            started_at: Instant::now(),
            shutting_down: AtomicBool::new(false),
            active_clients: AtomicI64::new(0),
            filter_cost_current: AtomicU64::new(0),
            filter_limit: AtomicU64::new(filter_limit),
            jobs_total: RwLock::new(jobs_total),
            ipp_requests: RwLock::new(BTreeMap::new()),
            auth_failures: RwLock::new(BTreeMap::new()),
            pages_printed: RwLock::new(BTreeMap::new()),
            http_requests: RwLock::new(BTreeMap::new()),
            job_duration: DurationHistogram::default(),
        }
    }

    /// Daemon uptime in whole seconds.
    #[must_use]
    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Mark daemon shutting down (flips `/readyz` to `503 Service Unavailable`).
    pub fn set_shutting_down(&self, value: bool) {
        self.shutting_down.store(value, Ordering::SeqCst);
    }

    /// Whether daemon shutdown has begun.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    /// Update configured `FilterLimit` gauge (e.g. on boot and `SIGHUP` reload).
    pub fn set_filter_limit(&self, limit: u64) {
        self.filter_limit.store(limit, Ordering::Relaxed);
    }

    /// Current configured `FilterLimit`.
    #[must_use]
    pub fn filter_limit(&self) -> u64 {
        self.filter_limit.load(Ordering::Relaxed)
    }

    /// Current active filter cost budget usage.
    #[must_use]
    pub fn filter_cost_current(&self) -> u64 {
        self.filter_cost_current.load(Ordering::Acquire)
    }

    /// Atomically try to reserve `cost` against `filter_limit` (0 = unlimited).
    /// Always permits a single job when `current == 0` so an expensive job cannot starve.
    pub fn try_reserve_filter_cost(&self, cost: u64) -> bool {
        let limit = self.filter_limit.load(Ordering::Relaxed);
        if cost == 0 || limit == 0 {
            self.filter_cost_current.fetch_add(cost, Ordering::AcqRel);
            return true;
        }
        let mut cur = self.filter_cost_current.load(Ordering::Acquire);
        loop {
            if cur > 0 && cur.saturating_add(cost) > limit {
                return false;
            }
            let next = cur.saturating_add(cost);
            match self.filter_cost_current.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Release previously reserved filter cost.
    pub fn release_filter_cost(&self, cost: u64) {
        if cost == 0 {
            return;
        }
        let mut cur = self.filter_cost_current.load(Ordering::Acquire);
        loop {
            let next = cur.saturating_sub(cost);
            match self.filter_cost_current.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Increment active client count.
    pub fn inc_active_clients(&self) -> i64 {
        self.active_clients.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Decrement active client count (clamped at 0).
    pub fn dec_active_clients(&self) -> i64 {
        let prev = self.active_clients.fetch_sub(1, Ordering::AcqRel);
        if prev <= 1 {
            self.active_clients.store(0, Ordering::Release);
            0
        } else {
            prev - 1
        }
    }

    /// Current active connected clients.
    #[must_use]
    pub fn active_clients(&self) -> i64 {
        self.active_clients.load(Ordering::Acquire).max(0)
    }

    /// Record a terminal job outcome (`completed`, `aborted`, `canceled`, `canceled-at-device`).
    pub fn record_job_terminal(&self, state: &str, duration_secs: Option<f64>) {
        let mut map = self
            .jobs_total
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *map.entry(state.to_string()).or_insert(0) += 1;
        drop(map);
        if let Some(d) = duration_secs {
            self.job_duration.observe(d);
        }
    }

    /// Record an IPP request outcome (`operation`, `status`).
    pub fn record_ipp_request(&self, operation: &str, status: &str) {
        let mut map = self
            .ipp_requests
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *map.entry((operation.to_string(), status.to_string()))
            .or_insert(0) += 1;
    }

    /// Record an authentication/authorization failure (`reason`).
    pub fn record_auth_failure(&self, reason: &str) {
        let mut map = self
            .auth_failures
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *map.entry(reason.to_string()).or_insert(0) += 1;
    }

    /// Record printed pages for `printer`.
    pub fn record_pages_printed(&self, printer: &str, pages: u64) {
        if pages == 0 {
            return;
        }
        let mut map = self
            .pages_printed
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *map.entry(printer.to_string()).or_insert(0) += pages;
    }

    /// Record an HTTP request (`method`, `status`).
    pub fn record_http_request(&self, method: &str, status: u16) {
        let mut map = self
            .http_requests
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *map.entry((method.to_string(), status)).or_insert(0) += 1;
    }

    /// Render the full Prometheus text exposition payload.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn render_prometheus(&self, registry: &RwLock<Registry>, jobs: &RwLock<Jobs>) -> String {
        let mut out = String::with_capacity(2048);

        // Snapshot queue names and printer state counts.
        let (printer_names, idle_n, proc_n, stop_n) = {
            let reg = registry
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut names = Vec::with_capacity(reg.printers.len());
            let (mut idle, mut proc_, mut stop) = (0u64, 0u64, 0u64);
            for p in reg.printers.values() {
                names.push(p.name.clone());
                match p.state {
                    pstate::IDLE => idle += 1,
                    pstate::PROCESSING => proc_ += 1,
                    pstate::STOPPED => stop += 1,
                    _ => {}
                }
            }
            (names, idle, proc_, stop)
        };

        // Snapshot active and pending job counts per printer.
        let mut active_by_printer: BTreeMap<String, u64> = BTreeMap::new();
        let mut pending_by_printer: BTreeMap<String, u64> = BTreeMap::new();
        for name in &printer_names {
            active_by_printer.insert(name.clone(), 0);
            pending_by_printer.insert(name.clone(), 0);
        }
        {
            let jg = jobs
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for j in jg.by_id.values() {
                match j.state {
                    JobState::Processing | JobState::ProcessingStopped => {
                        *active_by_printer.entry(j.dest.clone()).or_insert(0) += 1;
                    }
                    JobState::Pending | JobState::PendingHeld => {
                        *pending_by_printer.entry(j.dest.clone()).or_insert(0) += 1;
                    }
                    _ => {}
                }
            }
        }

        // 1. yindle_jobs_active{printer}
        out.push_str(
            "# HELP yindle_jobs_active Number of actively processing print jobs per printer.\n\
             # TYPE yindle_jobs_active gauge\n",
        );
        for (printer, count) in &active_by_printer {
            let _ = writeln!(
                out,
                "yindle_jobs_active{{printer=\"{}\"}} {count}",
                escape_prom_label(printer)
            );
        }

        // 2. yindle_jobs_pending{printer}
        out.push_str(
            "# HELP yindle_jobs_pending Number of pending or held print jobs per printer.\n\
             # TYPE yindle_jobs_pending gauge\n",
        );
        for (printer, count) in &pending_by_printer {
            let _ = writeln!(
                out,
                "yindle_jobs_pending{{printer=\"{}\"}} {count}",
                escape_prom_label(printer)
            );
        }

        // 3. yindle_jobs_total{state}
        out.push_str(
            "# HELP yindle_jobs_total Total print jobs reaching a terminal state.\n\
             # TYPE yindle_jobs_total counter\n",
        );
        {
            let jt = self
                .jobs_total
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (state, count) in jt.iter() {
                let _ = writeln!(
                    out,
                    "yindle_jobs_total{{state=\"{}\"}} {count}",
                    escape_prom_label(state)
                );
            }
        }

        // 4. yindle_job_duration_seconds (histogram)
        self.job_duration.render(&mut out);

        // 5. yindle_ipp_requests_total{operation,status}
        out.push_str(
            "# HELP yindle_ipp_requests_total Total IPP requests handled by operation and status.\n\
             # TYPE yindle_ipp_requests_total counter\n",
        );
        {
            let ipp = self
                .ipp_requests
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for ((op, st), count) in ipp.iter() {
                let _ = writeln!(
                    out,
                    "yindle_ipp_requests_total{{operation=\"{}\",status=\"{}\"}} {count}",
                    escape_prom_label(op),
                    escape_prom_label(st)
                );
            }
        }

        // 6. yindle_auth_failures_total{reason}
        out.push_str(
            "# HELP yindle_auth_failures_total Total authentication and authorization failures.\n\
             # TYPE yindle_auth_failures_total counter\n",
        );
        {
            let af = self
                .auth_failures
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (reason, count) in af.iter() {
                let _ = writeln!(
                    out,
                    "yindle_auth_failures_total{{reason=\"{}\"}} {count}",
                    escape_prom_label(reason)
                );
            }
        }

        // 7. yindle_active_clients
        out.push_str(
            "# HELP yindle_active_clients Current number of active HTTP/IPP client connections.\n\
             # TYPE yindle_active_clients gauge\n",
        );
        let _ = writeln!(out, "yindle_active_clients {}", self.active_clients());

        // 8. yindle_filter_cost_current & yindle_filter_limit
        out.push_str(
            "# HELP yindle_filter_cost_current Current filter pipeline cost in use.\n\
             # TYPE yindle_filter_cost_current gauge\n",
        );
        let _ = writeln!(
            out,
            "yindle_filter_cost_current {}",
            self.filter_cost_current()
        );
        out.push_str(
            "# HELP yindle_filter_limit Configured FilterLimit budget (0 means unlimited).\n\
             # TYPE yindle_filter_limit gauge\n",
        );
        let _ = writeln!(out, "yindle_filter_limit {}", self.filter_limit());

        // 9. Supplementary SRE gauges/counters
        out.push_str(
            "# HELP yindle_printers_total Registered destinations by state.\n\
             # TYPE yindle_printers_total gauge\n",
        );
        let _ = writeln!(out, "yindle_printers_total{{state=\"idle\"}} {idle_n}");
        let _ = writeln!(
            out,
            "yindle_printers_total{{state=\"processing\"}} {proc_n}"
        );
        let _ = writeln!(out, "yindle_printers_total{{state=\"stopped\"}} {stop_n}");

        out.push_str(
            "# HELP yindle_pages_printed_total Total pages reported via PAGE: status events.\n\
             # TYPE yindle_pages_printed_total counter\n",
        );
        {
            let pp = self
                .pages_printed
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (printer, count) in pp.iter() {
                let _ = writeln!(
                    out,
                    "yindle_pages_printed_total{{printer=\"{}\"}} {count}",
                    escape_prom_label(printer)
                );
            }
        }

        out.push_str(
            "# HELP yindle_http_requests_total Total HTTP requests handled by method and status code.\n\
             # TYPE yindle_http_requests_total counter\n",
        );
        {
            let hr = self
                .http_requests
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for ((method, status), count) in hr.iter() {
                let _ = writeln!(
                    out,
                    "yindle_http_requests_total{{method=\"{}\",status=\"{status}\"}} {count}",
                    escape_prom_label(method)
                );
            }
        }

        out.push_str(
            "# HELP yindle_uptime_seconds Scheduler uptime in seconds.\n\
             # TYPE yindle_uptime_seconds gauge\n",
        );
        let _ = writeln!(out, "yindle_uptime_seconds {}", self.uptime_seconds());

        out.push_str(
            "# HELP yindle_info Yindle daemon build info.\n\
             # TYPE yindle_info gauge\n",
        );
        let _ = writeln!(
            out,
            "yindle_info{{version=\"{}\"}} 1",
            escape_prom_label(VERSION)
        );

        out
    }

    /// Build `GET /healthz` response (`200 OK` JSON).
    #[must_use]
    pub fn healthz_response(&self) -> Response {
        let mut body = String::with_capacity(96);
        body.push_str("{\"status\":\"ok\",\"version\":");
        push_json_str(&mut body, VERSION);
        let _ = write!(body, ",\"uptime_seconds\":{}}}", self.uptime_seconds());
        Response::with_body(StatusCode::OK, "application/json", body.into_bytes())
            .with_security_headers()
    }

    /// Build `GET /readyz` response (`200 OK` or `503 Service Unavailable` JSON).
    #[must_use]
    pub fn readyz_response(
        &self,
        registry: &RwLock<Registry>,
        jobs: &RwLock<Jobs>,
        request_root: &Path,
    ) -> Response {
        let shutting_down = self.is_shutting_down();
        let spool_ok = request_root.is_dir();
        let ready = !shutting_down && spool_ok;

        let printers = registry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .printers
            .len();
        let (active_jobs, pending_jobs) = {
            let jg = jobs
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut active = 0usize;
            let mut pending = 0usize;
            for j in jg.by_id.values() {
                match j.state {
                    JobState::Processing | JobState::ProcessingStopped => active += 1,
                    JobState::Pending | JobState::PendingHeld => pending += 1,
                    _ => {}
                }
            }
            (active, pending)
        };

        let status_word = if ready { "ready" } else { "not_ready" };
        let body = format!(
            "{{\"status\":\"{status_word}\",\"shutting_down\":{shutting_down},\"spool_ok\":{spool_ok},\"printers\":{printers},\"active_jobs\":{active_jobs},\"pending_jobs\":{pending_jobs},\"active_clients\":{},\"uptime_seconds\":{}}}",
            self.active_clients(),
            self.uptime_seconds()
        );
        let code = if ready {
            StatusCode::OK
        } else {
            StatusCode(503)
        };
        Response::with_body(code, "application/json", body.into_bytes()).with_security_headers()
    }

    /// Build `GET /metrics` Prometheus text response.
    #[must_use]
    pub fn metrics_response(&self, registry: &RwLock<Registry>, jobs: &RwLock<Jobs>) -> Response {
        let text = self.render_prometheus(registry, jobs);
        Response::with_body(StatusCode::OK, PROMETHEUS_CONTENT_TYPE, text.into_bytes())
            .with_security_headers()
    }
}

/// RAII guard that releases filter cost budget on drop (even on spawn failure).
pub struct FilterCostGuard {
    metrics: Arc<Metrics>,
    cost: u64,
}

impl FilterCostGuard {
    /// Attempt to reserve `cost` against `FilterLimit`; returns `None` if budget exceeded.
    #[must_use]
    pub fn try_acquire(metrics: Arc<Metrics>, cost: u64) -> Option<Self> {
        if metrics.try_reserve_filter_cost(cost) {
            Some(Self { metrics, cost })
        } else {
            None
        }
    }
}

impl Drop for FilterCostGuard {
    fn drop(&mut self) {
        self.metrics.release_filter_cost(self.cost);
    }
}

/// Escape Prometheus label values per Prometheus text exposition format 0.0.4.
#[must_use]
pub fn escape_prom_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use job::Job;
    use printer::Printer;

    #[test]
    fn metrics_exports_exact_alert_and_dashboard_series() {
        let m = Arc::new(Metrics::new(200));
        assert_eq!(m.filter_limit(), 200);
        m.set_filter_limit(300);
        assert_eq!(m.filter_limit(), 300);

        // Filter cost reservation & budget cap
        let g1 = FilterCostGuard::try_acquire(Arc::clone(&m), 250).unwrap();
        assert_eq!(m.filter_cost_current(), 250);
        assert!(FilterCostGuard::try_acquire(Arc::clone(&m), 100).is_none());
        // Zero-cost job always allowed
        let g0 = FilterCostGuard::try_acquire(Arc::clone(&m), 0).unwrap();
        drop(g0);
        drop(g1);
        assert_eq!(m.filter_cost_current(), 0);
        // Single job larger than limit still allowed when current == 0
        let g_big = FilterCostGuard::try_acquire(Arc::clone(&m), 500).unwrap();
        assert_eq!(m.filter_cost_current(), 500);
        drop(g_big);
        assert_eq!(m.filter_cost_current(), 0);

        // Active clients clamping
        assert_eq!(m.inc_active_clients(), 1);
        assert_eq!(m.inc_active_clients(), 2);
        assert_eq!(m.dec_active_clients(), 1);
        assert_eq!(m.dec_active_clients(), 0);
        assert_eq!(m.dec_active_clients(), 0);

        // Counters & histogram
        m.record_job_terminal("completed", Some(0.42));
        m.record_job_terminal("aborted", Some(f64::NAN));
        m.record_job_terminal("canceled-at-device", None);
        m.record_ipp_request("Print-Job", "successful-ok");
        m.record_ipp_request("Cancel-Job", "client-error-not-authorized");
        m.record_auth_failure("invalid_credentials");
        m.record_pages_printed("laser1", 3);
        m.record_pages_printed("laser1", 0);
        m.record_http_request("GET", 200);

        let mut reg = Registry::default();
        let mut p1 = Printer::new("laser1", "socket://10.0.0.1");
        p1.state = pstate::PROCESSING;
        let mut p2 = Printer::new("paused1", "socket://10.0.0.2");
        p2.state = pstate::STOPPED;
        let p3 = Printer::new("idle1", "socket://10.0.0.3");
        reg.add(p1);
        reg.add(p2);
        reg.add(p3);
        let reg = RwLock::new(reg);

        let mut jobs = Jobs::default();
        let mut j1 = Job::new(1, "laser1", "alice");
        j1.state = JobState::Processing;
        let j2 = Job::new(2, "laser1", "bob");
        jobs.by_id.insert(1, j1);
        jobs.by_id.insert(2, j2);
        let jobs = RwLock::new(jobs);

        let resp = m.metrics_response(&reg, &jobs);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type"),
            Some(PROMETHEUS_CONTENT_TYPE)
        );
        let text = String::from_utf8(resp.body).unwrap();
        assert!(text.contains("yindle_jobs_active{printer=\"laser1\"} 1"));
        assert!(text.contains("yindle_jobs_pending{printer=\"laser1\"} 1"));
        assert!(text.contains("yindle_jobs_pending{printer=\"idle1\"} 0"));
        assert!(text.contains("yindle_jobs_total{state=\"completed\"} 1"));
        assert!(text.contains("yindle_jobs_total{state=\"aborted\"} 1"));
        assert!(text.contains("yindle_jobs_total{state=\"canceled-at-device\"} 1"));
        assert!(text.contains("yindle_job_duration_seconds_bucket{le=\"0.5\"} 2"));
        assert!(text.contains("yindle_job_duration_seconds_bucket{le=\"+Inf\"} 2"));
        assert!(text.contains("yindle_job_duration_seconds_count 2"));
        assert!(text.contains(
            "yindle_ipp_requests_total{operation=\"Print-Job\",status=\"successful-ok\"} 1"
        ));
        assert!(text.contains("yindle_auth_failures_total{reason=\"invalid_credentials\"} 1"));
        assert!(text.contains("yindle_active_clients 0"));
        assert!(text.contains("yindle_filter_cost_current 0"));
        assert!(text.contains("yindle_filter_limit 300"));
        assert!(text.contains("yindle_pages_printed_total{printer=\"laser1\"} 3"));
        assert!(text.contains("yindle_http_requests_total{method=\"GET\",status=\"200\"} 1"));

        // Healthz & readyz
        let hz = m.healthz_response();
        assert_eq!(hz.status, StatusCode::OK);
        let hz_str = String::from_utf8(hz.body).unwrap();
        assert!(hz_str.contains("\"status\":\"ok\""));
        assert!(hz_str.contains(VERSION));

        let rz_ok = m.readyz_response(&reg, &jobs, &std::env::temp_dir());
        assert_eq!(rz_ok.status, StatusCode::OK);
        let rz_str = String::from_utf8(rz_ok.body).unwrap();
        assert!(rz_str.contains("\"status\":\"ready\""));
        assert!(rz_str.contains("\"active_jobs\":1"));
        assert!(rz_str.contains("\"pending_jobs\":1"));

        // Missing spool dir -> 503
        let rz_bad_spool = m.readyz_response(&reg, &jobs, Path::new("/nonexistent/pw-spool-xyz"));
        assert_eq!(rz_bad_spool.status, StatusCode(503));

        // Shutting down -> 503
        m.set_shutting_down(true);
        assert!(m.is_shutting_down());
        let rz_down = m.readyz_response(&reg, &jobs, &std::env::temp_dir());
        assert_eq!(rz_down.status, StatusCode(503));
        assert!(String::from_utf8(rz_down.body)
            .unwrap()
            .contains("\"shutting_down\":true"));

        // Prometheus label escaping
        assert_eq!(escape_prom_label("a\"b\\c\n\rd"), "a\\\"b\\\\c\\nd");
        let def = Metrics::default();
        assert_eq!(def.filter_limit(), 0);
    }
}
