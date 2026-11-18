//! IPP event subscriptions + notifications — a port of
//! `scheduler/subscriptions.c` + `scheduler/event.c`.
//!
//! A [`Subscriptions`] table holds `Create-{Printer,Job}-Subscriptions`
//! objects. State changes call [`Subscriptions::push`], which appends a
//! [`Notification`] with a monotonic sequence number to every covering
//! subscription's bounded ring buffer and wakes any async (`notify-wait=true`)
//! or blocking waiters via [`EventNotifier`].
//!
//! Multi-client `ippget` consumers should read non-destructively with
//! [`Subscriptions::get_notifications`] (or [`Subscriptions::get_notifications_from`])
//! rather than the legacy destructive [`Subscriptions::drain`].
//! Subscriptions can be persisted atomically to `subscriptions.conf` with
//! [`Subscriptions::save_file`] / [`Subscriptions::load_file`].

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Default permissions for `subscriptions.conf` (`0640`).
pub const CONFIG_FILE_MODE: u32 = 0o640;

/// Default `notify-lease-duration` (seconds) — upstream `DefaultLeaseDuration`.
pub const DEFAULT_LEASE_DURATION: i32 = 86_400;

/// `notify-lease-duration` meaning "never expire".
pub const NEVER_EXPIRE: i32 = 0;

/// Default maximum buffered notifications per subscription (`MaxEvents`).
pub const DEFAULT_MAX_EVENTS: usize = 100;

/// Platform `O_NOFOLLOW` flag for `OpenOptionsExt::custom_flags`.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    )
))]
const O_NOFOLLOW: i32 = 0o100_000;

#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    ))
))]
const O_NOFOLLOW: i32 = 0o400_000;

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const O_NOFOLLOW: i32 = 0x0100;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static WAITER_COUNTER: AtomicU64 = AtomicU64::new(1);

/// IPP `notify-events` keywords (`cupsdEventName`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    PrinterAdded,
    PrinterDeleted,
    PrinterModified,
    PrinterState,
    PrinterStateChanged,
    PrinterConfigChanged,
    PrinterChanged,
    PrinterFinishingsChanged,
    PrinterMediaChanged,
    PrinterRestarted,
    PrinterShutdown,
    PrinterStopped,
    JobCreated,
    JobCompleted,
    JobStopped,
    JobStateChanged,
    JobConfigChanged,
    JobProgress,
    ServerRestarted,
    ServerStarted,
    ServerStopped,
    ServerAudit,
    /// `all` — matches every event.
    All,
}

impl Event {
    /// RFC 3995 / CUPS `notify-events` keyword.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::PrinterAdded => "printer-added",
            Self::PrinterDeleted => "printer-deleted",
            Self::PrinterModified => "printer-modified",
            Self::PrinterState => "printer-state",
            Self::PrinterStateChanged => "printer-state-changed",
            Self::PrinterConfigChanged => "printer-config-changed",
            Self::PrinterChanged => "printer-changed",
            Self::PrinterFinishingsChanged => "printer-finishings-changed",
            Self::PrinterMediaChanged => "printer-media-changed",
            Self::PrinterRestarted => "printer-restarted",
            Self::PrinterShutdown => "printer-shutdown",
            Self::PrinterStopped => "printer-stopped",
            Self::JobCreated => "job-created",
            Self::JobCompleted => "job-completed",
            Self::JobStopped => "job-stopped",
            Self::JobStateChanged => "job-state-changed",
            Self::JobConfigChanged => "job-config-changed",
            Self::JobProgress => "job-progress",
            Self::ServerRestarted => "server-restarted",
            Self::ServerStarted => "server-started",
            Self::ServerStopped => "server-stopped",
            Self::ServerAudit => "server-audit",
            Self::All => "all",
        }
    }

    /// Parse a `notify-events` keyword. `None` if unknown.
    #[must_use]
    pub fn from_name(n: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|e| e.name() == n)
    }

    /// Every recognized `Event` variant.
    pub const ALL: &'static [Self] = &[
        Self::PrinterAdded,
        Self::PrinterDeleted,
        Self::PrinterModified,
        Self::PrinterState,
        Self::PrinterStateChanged,
        Self::PrinterConfigChanged,
        Self::PrinterChanged,
        Self::PrinterFinishingsChanged,
        Self::PrinterMediaChanged,
        Self::PrinterRestarted,
        Self::PrinterShutdown,
        Self::PrinterStopped,
        Self::JobCreated,
        Self::JobCompleted,
        Self::JobStopped,
        Self::JobStateChanged,
        Self::JobConfigChanged,
        Self::JobProgress,
        Self::ServerRestarted,
        Self::ServerStarted,
        Self::ServerStopped,
        Self::ServerAudit,
        Self::All,
    ];

    /// Does `sub`'s event mask cover `ev` (including RFC 3995 categories & `All`)?
    #[must_use]
    pub fn covered(mask: &[Self], ev: Self) -> bool {
        mask.iter().any(|&m| m.matches(ev))
    }

    fn matches(self, ev: Self) -> bool {
        if self == ev || self == Self::All {
            return true;
        }
        match self {
            Self::PrinterState => matches!(
                ev,
                Self::PrinterStateChanged
                    | Self::PrinterStopped
                    | Self::PrinterRestarted
                    | Self::PrinterShutdown
            ),
            Self::PrinterStateChanged => matches!(
                ev,
                Self::PrinterStopped | Self::PrinterRestarted | Self::PrinterShutdown
            ),
            Self::PrinterConfigChanged => {
                matches!(
                    ev,
                    Self::PrinterFinishingsChanged | Self::PrinterMediaChanged
                )
            }
            Self::PrinterChanged => matches!(
                ev,
                Self::PrinterAdded
                    | Self::PrinterDeleted
                    | Self::PrinterModified
                    | Self::PrinterState
                    | Self::PrinterStateChanged
                    | Self::PrinterConfigChanged
                    | Self::PrinterFinishingsChanged
                    | Self::PrinterMediaChanged
                    | Self::PrinterRestarted
                    | Self::PrinterShutdown
                    | Self::PrinterStopped
            ),
            Self::JobStateChanged => {
                matches!(ev, Self::JobCreated | Self::JobCompleted | Self::JobStopped)
            }
            _ => false,
        }
    }
}

/// A queued event notification for the `ippget` pull.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    pub seq: i32,
    pub event: Event,
    pub time: i64,
    pub printer: Option<String>,
    pub job_id: Option<i32>,
    pub job_state: Option<i32>,
    pub text: String,
}

/// One subscription (`cupsd_subscription_t`).
#[derive(Clone, Debug)]
pub struct Subscription {
    pub id: i32,
    /// Printer scope — `None` = all printers.
    pub printer: Option<String>,
    /// Job scope — `None` = printer/system subscription.
    pub job_id: Option<i32>,
    pub events: Vec<Event>,
    pub owner: String,
    /// Absolute lease expiry (epoch secs); `i64::MAX` = never.
    pub lease: i64,
    /// Effective `notify-lease-duration` (clamped), for `Renew`.
    pub lease_duration: i32,
    pub user_data: Option<Vec<u8>>,
    /// Push recipient URI (e.g. `mailto:`, `rss:`, `dbus:`), if push subscription.
    pub recipient_uri: Option<String>,
    next_seq: i32,
    queue: VecDeque<Notification>,
}

// ---------- async + sync notification wakeup ----------

#[derive(Default)]
struct WaitState {
    version: u64,
    wakers: Vec<(u64, Waker)>,
}

/// Cloneable wakeup handle for `Get-Notifications` with `notify-wait=true`.
///
/// Works with any async runtime (`tokio`, `tokio::time::timeout`, etc.) via
/// [`EventNotifier::notified`] and also supports blocking threads via
/// [`EventNotifier::wait_timeout`]. Uses a monotonic generation counter so
/// events pushed between checking [`Subscriptions`] and awaiting never suffer
/// lost wakeups.
#[derive(Clone)]
pub struct EventNotifier {
    inner: Arc<(Mutex<WaitState>, Condvar)>,
}

impl std::fmt::Debug for EventNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventNotifier")
            .field("version", &self.version())
            .finish()
    }
}

impl EventNotifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new((Mutex::new(WaitState::default()), Condvar::new())),
        }
    }

    /// Current monotonic change version. Snapshot this before dropping a read
    /// lock on [`Subscriptions`], then pass it to [`Self::notified`].
    #[must_use]
    pub fn version(&self) -> u64 {
        let state = self
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.version
    }

    /// Bump the generation version and wake every waiting async task and thread.
    pub fn notify_all(&self) {
        let wakers = {
            let mut state = self
                .inner
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.version = state.version.wrapping_add(1);
            std::mem::take(&mut state.wakers)
        };
        self.inner.1.notify_all();
        for (_, w) in wakers {
            w.wake();
        }
    }

    /// Return a [`Future`] that resolves to the new generation version once
    /// `version != seen_version`. Resolves immediately if an update already
    /// occurred since `seen_version`.
    #[must_use]
    pub fn notified(&self, seen_version: u64) -> Notified {
        Notified {
            inner: Arc::clone(&self.inner),
            seen_version,
            waiter_id: WAITER_COUNTER.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Block the current thread until `version != seen_version` or `timeout`
    /// elapses. Returns `Some(new_version)` if woken, or `None` on timeout.
    #[must_use]
    pub fn wait_timeout(&self, seen_version: u64, timeout: Duration) -> Option<u64> {
        let deadline = Instant::now() + timeout;
        let mut state = self
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while state.version == seen_version {
            let rem = deadline.checked_duration_since(Instant::now())?;
            let (guard, res) = self
                .inner
                .1
                .wait_timeout(state, rem)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = guard;
            if res.timed_out() && state.version == seen_version {
                return None;
            }
        }
        Some(state.version)
    }
}

impl Default for EventNotifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Future returned by [`EventNotifier::notified`]. Cleans up its registered
/// waker automatically on drop (e.g. when cancelled by a lease/request timeout).
pub struct Notified {
    inner: Arc<(Mutex<WaitState>, Condvar)>,
    seen_version: u64,
    waiter_id: u64,
}

impl Future for Notified {
    type Output = u64;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.version != self.seen_version {
            state.wakers.retain(|(id, _)| *id != self.waiter_id);
            return Poll::Ready(state.version);
        }
        if let Some((_, existing)) = state
            .wakers
            .iter_mut()
            .find(|(id, _)| *id == self.waiter_id)
        {
            existing.clone_from(cx.waker());
        } else {
            state.wakers.push((self.waiter_id, cx.waker().clone()));
        }
        Poll::Pending
    }
}

impl Drop for Notified {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.wakers.retain(|(id, _)| *id != self.waiter_id);
    }
}

/// The subscription table (`Subscriptions` global).
pub struct Subscriptions {
    subs: BTreeMap<i32, Subscription>,
    next_id: i32,
    default_lease_duration: i32,
    max_lease_duration: i32,
    max_events: usize,
    notifier: EventNotifier,
}

impl Default for Subscriptions {
    fn default() -> Self {
        Self::new()
    }
}

impl Subscriptions {
    #[must_use]
    pub fn new() -> Self {
        Self {
            subs: BTreeMap::new(),
            next_id: 1,
            default_lease_duration: DEFAULT_LEASE_DURATION,
            max_lease_duration: DEFAULT_LEASE_DURATION,
            max_events: DEFAULT_MAX_EVENTS,
            notifier: EventNotifier::new(),
        }
    }

    /// Configure `DefaultLeaseDuration` and `MaxLeaseDuration` (`0` = unlimited).
    pub fn set_lease_limits(&mut self, default_lease: i32, max_lease: i32) {
        self.default_lease_duration = default_lease.max(1);
        self.max_lease_duration = max_lease.max(0);
    }

    /// Configure maximum retained notifications per subscription ring buffer.
    pub fn set_max_events(&mut self, max_events: usize) {
        self.max_events = max_events.max(1);
    }

    /// Return a cloneable [`EventNotifier`] woken on every pushed event or
    /// subscription cancellation/expiry.
    #[must_use]
    pub fn notifier(&self) -> EventNotifier {
        self.notifier.clone()
    }

    /// Clamp a requested lease duration against `DefaultLeaseDuration` and
    /// `MaxLeaseDuration`.
    #[must_use]
    pub fn clamp_lease_duration(&self, requested: i32) -> i32 {
        if requested == NEVER_EXPIRE {
            return NEVER_EXPIRE;
        }
        let base = if requested < 0 {
            self.default_lease_duration.max(1)
        } else {
            requested
        };
        if self.max_lease_duration > 0 {
            base.min(self.max_lease_duration).max(1)
        } else {
            base.max(1)
        }
    }

    /// `cupsdAddSubscription` — returns the new subscription id.
    pub fn add(
        &mut self,
        printer: Option<String>,
        job_id: Option<i32>,
        events: Vec<Event>,
        owner: String,
        lease_duration: i32,
        user_data: Option<Vec<u8>>,
    ) -> i32 {
        self.add_with_recipient(
            printer,
            job_id,
            events,
            owner,
            lease_duration,
            user_data,
            None,
        )
    }

    /// Create a subscription with an optional push `recipient_uri`.
    #[allow(clippy::too_many_arguments)]
    pub fn add_with_recipient(
        &mut self,
        printer: Option<String>,
        job_id: Option<i32>,
        events: Vec<Event>,
        owner: String,
        lease_duration: i32,
        user_data: Option<Vec<u8>>,
        recipient_uri: Option<String>,
    ) -> i32 {
        let id = self.next_id.max(1);
        self.next_id = id.saturating_add(1);
        let clamped = self.clamp_lease_duration(lease_duration);
        let lease = if clamped == NEVER_EXPIRE {
            i64::MAX
        } else {
            now().saturating_add(i64::from(clamped))
        };
        self.subs.insert(
            id,
            Subscription {
                id,
                printer,
                job_id,
                events,
                owner,
                lease,
                lease_duration: clamped,
                user_data,
                recipient_uri,
                next_seq: 1,
                queue: VecDeque::new(),
            },
        );
        id
    }

    /// `cupsdExpireSubscriptions` — drop expired subs; call on each op.
    pub fn expire(&mut self) {
        let t = now();
        let before = self.subs.len();
        self.subs.retain(|_, s| s.lease > t);
        if self.subs.len() != before {
            self.notifier.notify_all();
        }
    }

    /// `cupsdExpireSubscriptions(NULL, job)` — drop every subscription tied
    /// to a job; upstream calls this when the job leaves the active list
    /// (completes/aborts), so job subs don't outlive their job.
    pub fn expire_job(&mut self, job_id: i32) {
        let before = self.subs.len();
        self.subs.retain(|_, s| s.job_id != Some(job_id));
        if self.subs.len() != before {
            self.notifier.notify_all();
        }
    }

    /// Push an event — appends a [`Notification`] with a monotonic sequence
    /// number to every covering subscription's ring buffer and wakes waiters.
    pub fn push(
        &mut self,
        event: Event,
        printer: Option<&str>,
        job_id: Option<i32>,
        job_state: Option<i32>,
        text: &str,
    ) {
        self.expire();
        let mut pushed_any = false;
        let ts = now();
        let cap = self.max_events.max(1);
        for s in self.subs.values_mut() {
            if !Event::covered(&s.events, event) {
                continue;
            }
            if s.printer.as_deref().is_some_and(|p| Some(p) != printer) {
                continue;
            }
            if s.job_id.is_some() && s.job_id != job_id {
                continue;
            }
            let seq = s.next_seq;
            s.next_seq = s.next_seq.saturating_add(1);
            s.queue.push_back(Notification {
                seq,
                event,
                time: ts,
                printer: printer.map(str::to_string),
                job_id,
                job_state,
                text: text.to_string(),
            });
            while s.queue.len() > cap {
                s.queue.pop_front();
            }
            pushed_any = true;
        }
        if pushed_any {
            self.notifier.notify_all();
        }
    }

    /// A live subscription reads `None` once its lease lapses.
    #[must_use]
    pub fn find(&self, id: i32) -> Option<&Subscription> {
        self.subs.get(&id).filter(|s| !s.expired())
    }

    pub fn find_mut(&mut self, id: i32) -> Option<&mut Subscription> {
        self.subs.get_mut(&id).filter(|s| !s.expired())
    }

    pub fn remove(&mut self, id: i32) -> Option<Subscription> {
        let removed = self.subs.remove(&id);
        if removed.is_some() {
            self.notifier.notify_all();
        }
        removed
    }

    /// Renew a subscription's lease (`Renew-Subscription`).
    pub fn renew(&mut self, id: i32) -> bool {
        self.renew_with_duration(id, None).is_some()
    }

    /// Renew a subscription's lease, optionally updating `notify-lease-duration`
    /// (clamped to configured lease limits). Returns the effective duration.
    pub fn renew_with_duration(&mut self, id: i32, requested: Option<i32>) -> Option<i32> {
        let clamped = requested.map(|r| self.clamp_lease_duration(r));
        let s = self.subs.get_mut(&id)?;
        if let Some(d) = clamped {
            s.lease_duration = d;
        }
        s.lease = if s.lease_duration == NEVER_EXPIRE {
            i64::MAX
        } else {
            now().saturating_add(i64::from(s.lease_duration))
        };
        Some(s.lease_duration)
    }

    /// All *live* subscriptions, optionally filtered to a printer/owner.
    #[must_use]
    pub fn list(&self, printer: Option<&str>, owner: Option<&str>) -> Vec<&Subscription> {
        self.subs
            .values()
            .filter(|s| {
                !s.expired()
                    && (printer.is_none() || s.printer.as_deref() == printer)
                    && (owner.is_none() || s.owner == owner.unwrap_or(""))
            })
            .collect()
    }

    /// Raw entry count including lapsed leases.
    #[must_use]
    pub fn count(&self) -> usize {
        self.subs.len()
    }

    /// Non-destructive `ippget` read: returns all retained notifications for
    /// live subscription `sub_id` with `n.seq > since_seq`.
    ///
    /// Pass `since_seq = 0` to read from the oldest retained event; pass the
    /// highest `n.seq` already seen on subsequent polls so multiple `ippget`
    /// clients can track independent cursors without losing events.
    #[must_use]
    pub fn get_notifications(&self, sub_id: i32, since_seq: i32) -> Vec<Notification> {
        self.try_get_notifications(sub_id, since_seq)
            .unwrap_or_default()
    }

    /// RFC 3996 inclusive `notify-sequence-numbers` read (`n.seq >= first_seq`).
    #[must_use]
    pub fn get_notifications_from(&self, sub_id: i32, first_seq: i32) -> Vec<Notification> {
        self.get_notifications(sub_id, first_seq.saturating_sub(1))
    }

    /// Non-destructive read distinguishing a missing/expired subscription
    /// (`None`) from a live subscription with zero unseen events (`Some([])`).
    #[must_use]
    pub fn try_get_notifications(&self, sub_id: i32, since_seq: i32) -> Option<Vec<Notification>> {
        self.find(sub_id).map(|s| s.notifications_since(since_seq))
    }

    /// Highest sequence number assigned so far on `sub_id` (`0` if none yet).
    #[must_use]
    pub fn latest_seq(&self, sub_id: i32) -> Option<i32> {
        self.find(sub_id).map(Subscription::latest_seq)
    }

    /// Atomic snapshot for `Get-Notifications` with `notify-wait=true`: returns
    /// `(notifications, current_version, notifier)` under the caller's read lock
    /// so awaiting `notifier.notified(version)` after dropping the lock cannot
    /// miss concurrent pushes.
    #[must_use]
    pub fn snapshot_wait(
        &self,
        sub_id: i32,
        since_seq: i32,
    ) -> (Option<Vec<Notification>>, u64, EventNotifier) {
        let ver = self.notifier.version();
        let notes = self.try_get_notifications(sub_id, since_seq);
        (notes, ver, self.notifier.clone())
    }

    /// Legacy destructive drain kept for backward compatibility.
    /// Prefer [`Self::get_notifications`] for RFC 3996 multi-client `ippget`.
    pub fn drain(&mut self, id: i32) -> Vec<Notification> {
        self.subs
            .get_mut(&id)
            .map(|s| s.queue.drain(..).collect())
            .unwrap_or_default()
    }

    /// Serialize live subscriptions in CUPS `subscriptions.conf` format.
    #[must_use]
    pub fn save_conf(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("# Subscription configuration file for CUPS v2.5-rust\n");
        out.push_str("# Written by cupsd\n");
        out.push_str("# DO NOT EDIT THIS FILE WHEN CUPSD IS RUNNING\n\n");
        let _ = writeln!(out, "NextSubscriptionId {}", self.next_id.max(1));

        for s in self.subs.values() {
            if s.expired() {
                continue;
            }
            let _ = writeln!(out, "<Subscription {}>", s.id);
            let ev_list = s.event_names().join(" ");
            let _ = writeln!(out, "Events {ev_list}");
            let _ = writeln!(out, "Owner {}", esc(&s.owner));
            if let Some(ref p) = s.printer {
                let _ = writeln!(out, "PrinterName {}", esc(p));
            }
            if let Some(j) = s.job_id {
                let _ = writeln!(out, "JobId {j}");
            }
            if let Some(ref r) = s.recipient_uri {
                let _ = writeln!(out, "Recipient {}", esc(r));
            }
            let _ = writeln!(out, "LeaseDuration {}", s.lease_duration);
            if s.lease != i64::MAX {
                let _ = writeln!(out, "ExpirationTime {}", s.lease);
            }
            let _ = writeln!(out, "NextEventId {}", s.next_seq);
            if let Some(ref ud) = s.user_data {
                let _ = writeln!(out, "UserData {}", hex_encode(ud));
            }
            out.push_str("</Subscription>\n\n");
        }
        out.into_bytes()
    }

    /// Parse `subscriptions.conf` from a buffered reader, skipping expired
    /// entries while preserving sequence numbers and `NextSubscriptionId`.
    pub fn load_conf<R: BufRead>(&mut self, r: R) -> Vec<String> {
        let mut errors = Vec::new();
        let mut cur: Option<Subscription> = None;

        for (idx, line_res) in r.lines().enumerate() {
            let linenum = idx + 1;
            let Ok(raw) = line_res else { break };
            let stripped = strip_comment_and_unescape(&raw);
            let line = stripped.trim();
            if line.is_empty() {
                continue;
            }

            let (name, val) = split_directive(line);
            if name.eq_ignore_ascii_case("NextSubscriptionId") {
                if let Ok(n) = val.parse::<i32>() {
                    self.next_id = self.next_id.max(n.max(1));
                }
            } else if name.eq_ignore_ascii_case("<Subscription") {
                let id_str = val.strip_suffix('>').map(str::trim);
                if let (None, Some(Ok(id))) = (&cur, id_str.map(str::parse::<i32>)) {
                    if id > 0 {
                        cur = Some(Subscription {
                            id,
                            printer: None,
                            job_id: None,
                            events: Vec::new(),
                            owner: String::new(),
                            lease: i64::MAX,
                            lease_duration: NEVER_EXPIRE,
                            user_data: None,
                            recipient_uri: None,
                            next_seq: 1,
                            queue: VecDeque::new(),
                        });
                    } else {
                        errors.push(format!("Invalid subscription id on line {linenum}."));
                    }
                } else {
                    errors.push(format!(
                        "Syntax error on line {linenum} of subscriptions.conf."
                    ));
                }
            } else if name.eq_ignore_ascii_case("</Subscription>") {
                if let Some(s) = cur.take() {
                    if s.id >= self.next_id {
                        self.next_id = s.id.saturating_add(1);
                    }
                    if !s.expired() {
                        self.subs.insert(s.id, s);
                    }
                } else {
                    errors.push(format!(
                        "Unexpected </Subscription> on line {linenum} of subscriptions.conf."
                    ));
                }
            } else if let Some(s) = cur.as_mut() {
                apply_sub_directive(s, name, val);
            }
        }
        if cur.is_some() {
            errors.push("Unterminated <Subscription> block in subscriptions.conf.".into());
        }
        errors
    }

    /// Atomically write `subscriptions.conf` with default mode `0640`.
    pub fn save_file(&self, path: &Path) -> io::Result<()> {
        self.save_file_with_mode(path, CONFIG_FILE_MODE)
    }

    /// Atomically write `subscriptions.conf` with an explicit permission mode.
    pub fn save_file_with_mode(&self, path: &Path, mode: u32) -> io::Result<()> {
        write_atomic(path, &self.save_conf(), mode)
    }

    /// Load `subscriptions.conf` from disk (opening with `O_NOFOLLOW`).
    /// Missing file returns `Ok(Vec::new())`.
    pub fn load_file(&mut self, path: &Path) -> io::Result<Vec<String>> {
        match open_read_nofollow(path) {
            Ok(f) => Ok(self.load_conf(BufReader::new(f))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }
}

/// `Subscription` helpers for building IPP attrs.
impl Subscription {
    /// Lease lapsed (always false for a `NEVER_EXPIRE` lease).
    #[must_use]
    pub fn expired(&self) -> bool {
        self.lease != i64::MAX && self.lease <= now()
    }

    /// `notify-lease-duration` remaining (0 = expired/never).
    #[must_use]
    pub fn lease_remaining(&self) -> i32 {
        if self.lease == i64::MAX {
            0
        } else {
            i32::try_from((self.lease - now()).max(0)).unwrap_or(i32::MAX)
        }
    }

    /// Queued notification count currently retained in the ring buffer.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.queue.len()
    }

    /// Next sequence number to be assigned on the next event.
    #[must_use]
    pub fn next_seq(&self) -> i32 {
        self.next_seq
    }

    /// Highest sequence number assigned so far (`0` before the first event).
    #[must_use]
    pub fn latest_seq(&self) -> i32 {
        self.next_seq.saturating_sub(1)
    }

    /// Non-destructive slice of buffered notifications with `n.seq > since_seq`.
    #[must_use]
    pub fn notifications_since(&self, since_seq: i32) -> Vec<Notification> {
        self.queue
            .iter()
            .filter(|n| n.seq > since_seq)
            .cloned()
            .collect()
    }

    /// Event keyword names for IPP `notify-events`.
    #[must_use]
    pub fn event_names(&self) -> Vec<String> {
        self.events.iter().map(|e| e.name().to_string()).collect()
    }
}

// ---------- subscriptions.conf parsing & formatting ----------

fn split_directive(line: &str) -> (&str, &str) {
    match line.find(char::is_whitespace) {
        Some(i) => (&line[..i], line[i..].trim()),
        None => (line, ""),
    }
}

fn apply_sub_directive(s: &mut Subscription, name: &str, val: &str) {
    if name.eq_ignore_ascii_case("Events") {
        s.events = val
            .split_whitespace()
            .filter_map(Event::from_name)
            .collect();
    } else if name.eq_ignore_ascii_case("Owner") {
        s.owner = val.to_string();
    } else if name.eq_ignore_ascii_case("PrinterName") {
        s.printer = Some(val.to_string());
    } else if name.eq_ignore_ascii_case("JobId") {
        s.job_id = val.parse().ok();
    } else if name.eq_ignore_ascii_case("Recipient") {
        s.recipient_uri = Some(val.to_string());
    } else if name.eq_ignore_ascii_case("LeaseDuration") {
        if let Ok(d) = val.parse::<i32>() {
            s.lease_duration = d.max(0);
        }
    } else if name.eq_ignore_ascii_case("ExpirationTime") {
        if let Ok(t) = val.parse::<i64>() {
            s.lease = if t <= 0 { i64::MAX } else { t };
        }
    } else if name.eq_ignore_ascii_case("NextEventId") {
        if let Ok(seq) = val.parse::<i32>() {
            s.next_seq = seq.max(1);
        }
    } else if name.eq_ignore_ascii_case("UserData") {
        s.user_data = hex_decode(val);
    }
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '#' => o.push_str("\\#"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            c => o.push(c),
        }
    }
    o
}

fn strip_comment_and_unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match c {
            '#' => break,
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('\\') | None => out.push('\\'),
                Some('#') => out.push('#'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
            },
            c => out.push(c),
        }
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < s.len() {
        let byte = u8::from_str_radix(s.get(i..i + 2)?, 16).ok()?;
        out.push(byte);
        i += 2;
    }
    Some(out)
}

// ---------- hardened atomic file I/O ----------

fn open_read_nofollow(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    opts.custom_flags(O_NOFOLLOW);
    opts.open(path)
}

/// Atomically write `data` to `path` via a unique temp file in the same
/// directory created with `O_CREAT | O_EXCL | O_NOFOLLOW` and `mode`,
/// then `fchmod`, `fsync`, `rename`, and best-effort parent-dir `fsync`.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let base = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("subscriptions");
    let pid = std::process::id();

    let mut tmp_path = PathBuf::new();
    let mut file = None;
    for _ in 0..64 {
        let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{base}.tmp.{pid}.{seq}"));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(mode).custom_flags(O_NOFOLLOW);
        match opts.open(&candidate) {
            Ok(f) => {
                tmp_path = candidate;
                file = Some(f);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    let mut f =
        file.ok_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "tmp collision"))?;

    let write_res = (|| -> io::Result<()> {
        #[cfg(unix)]
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_res {
        drop(f);
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(f);

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::task::Wake;

    fn temp_dir(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "presswork-events-test-{}-{}-{id}",
            std::process::id(),
            tag
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct FlagWaker(AtomicBool);
    impl Wake for FlagWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn add_scope_and_drain() {
        let mut t = Subscriptions::new();
        let a = t.add(
            Some("p1".into()),
            None,
            vec![Event::PrinterStateChanged],
            "u".into(),
            0,
            None,
        );
        let _b = t.add(
            Some("p2".into()),
            None,
            vec![Event::All],
            "u".into(),
            0,
            None,
        );
        t.push(Event::PrinterStateChanged, Some("p1"), None, None, "x");
        assert_eq!(t.find(a).unwrap().pending(), 1);
        assert_eq!(t.drain(a).len(), 1);
        assert_eq!(t.drain(a).len(), 0);
    }

    #[test]
    fn all_advertised_events_round_trip_and_categories() {
        let advertised = [
            "job-completed",
            "job-config-changed",
            "job-created",
            "job-progress",
            "job-state-changed",
            "job-stopped",
            "printer-added",
            "printer-changed",
            "printer-config-changed",
            "printer-deleted",
            "printer-finishings-changed",
            "printer-media-changed",
            "printer-modified",
            "printer-restarted",
            "printer-shutdown",
            "printer-state",
            "printer-state-changed",
            "printer-stopped",
            "server-audit",
            "server-restarted",
            "server-started",
            "server-stopped",
            "all",
        ];
        for name in advertised {
            let ev = Event::from_name(name).unwrap_or_else(|| panic!("missing event {name}"));
            assert_eq!(ev.name(), name);
        }
        assert_eq!(Event::from_name("not-a-real-event"), None);
        for e in Event::ALL {
            assert_eq!(Event::from_name(e.name()), Some(*e));
        }

        // Category coverage checks.
        assert!(Event::covered(&[Event::All], Event::JobProgress));
        assert!(!Event::covered(&[Event::JobCreated], Event::JobCompleted));
        assert!(Event::covered(
            &[Event::PrinterState],
            Event::PrinterStopped
        ));
        assert!(Event::covered(
            &[Event::PrinterStateChanged],
            Event::PrinterRestarted
        ));
        assert!(Event::covered(
            &[Event::PrinterConfigChanged],
            Event::PrinterMediaChanged
        ));
        assert!(Event::covered(
            &[Event::PrinterConfigChanged],
            Event::PrinterFinishingsChanged
        ));
        assert!(Event::covered(
            &[Event::PrinterChanged],
            Event::PrinterShutdown
        ));
        assert!(Event::covered(
            &[Event::JobStateChanged],
            Event::JobCompleted
        ));
        assert!(!Event::covered(
            &[Event::PrinterStateChanged],
            Event::PrinterMediaChanged
        ));
    }

    #[test]
    fn job_scope_and_expire_job() {
        let mut t = Subscriptions::default();
        let a = t.add(
            None,
            Some(7),
            vec![Event::JobStateChanged],
            "u".into(),
            0,
            None,
        );
        t.push(Event::JobStateChanged, None, Some(8), None, "wrong job");
        t.push(Event::JobStateChanged, None, Some(7), Some(5), "right");
        assert_eq!(t.find(a).unwrap().pending(), 1);
        assert_eq!(t.count(), 1);
        assert_eq!(t.list(None, Some("u")).len(), 1);

        t.expire_job(7);
        assert!(t.find(a).is_none());
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn non_destructive_ring_buffer_and_multi_client_ippget() {
        let mut t = Subscriptions::new();
        t.set_max_events(3);
        let id = t.add(
            Some("laser".into()),
            None,
            vec![Event::PrinterChanged],
            "alice".into(),
            NEVER_EXPIRE,
            None,
        );
        assert_eq!(t.latest_seq(id), Some(0));
        assert_eq!(t.find(id).unwrap().next_seq(), 1);
        assert_eq!(t.find(id).unwrap().lease_remaining(), 0);

        for i in 1..=5 {
            t.push(
                Event::PrinterStopped,
                Some("laser"),
                None,
                None,
                &format!("ev-{i}"),
            );
        }

        // Ring buffer keeps the latest 3 events: seq 3, 4, 5.
        assert_eq!(t.latest_seq(id), Some(5));
        let client_a = t.get_notifications(id, 0);
        assert_eq!(
            client_a.iter().map(|n| n.seq).collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        // Second client reads the exact same events non-destructively!
        let client_b = t.get_notifications_from(id, 1);
        assert_eq!(client_b, client_a);
        // Client A advances cursor to 4 -> sees only 5.
        let client_a_next = t.get_notifications(id, 4);
        assert_eq!(
            client_a_next.iter().map(|n| n.seq).collect::<Vec<_>>(),
            vec![5]
        );
        // RFC 3996 inclusive `first_seq = 5` also returns [5].
        assert_eq!(t.get_notifications_from(id, 5), client_a_next);
        // Missing sub returns None on try_get_notifications and empty on get_notifications.
        assert!(t.try_get_notifications(999, 0).is_none());
        assert_eq!(t.get_notifications(999, 0), Vec::<Notification>::new());
    }

    #[test]
    fn lease_duration_clamping_and_renewal() {
        let mut t = Subscriptions::new();
        // Negative lease clamps to default (86400).
        let s_neg = t.add(None, None, vec![Event::All], "u".into(), -50, None);
        assert_eq!(
            t.find(s_neg).unwrap().lease_duration,
            DEFAULT_LEASE_DURATION
        );
        assert!(t.find(s_neg).unwrap().lease_remaining() > 86_000);

        // Oversized lease clamps to max_lease_duration (default 86400).
        let s_big = t.add(None, None, vec![Event::All], "u".into(), 999_999, None);
        assert_eq!(
            t.find(s_big).unwrap().lease_duration,
            DEFAULT_LEASE_DURATION
        );

        // Normal lease kept verbatim.
        let s_ok = t.add(None, None, vec![Event::All], "u".into(), 120, None);
        assert_eq!(t.find(s_ok).unwrap().lease_duration, 120);

        // Custom limits + unlimited max (0).
        t.set_lease_limits(600, 300);
        assert_eq!(t.clamp_lease_duration(-1), 300);
        assert_eq!(t.clamp_lease_duration(1000), 300);
        t.set_lease_limits(600, 0);
        assert_eq!(t.clamp_lease_duration(1000), 1000);

        // Renew existing and missing subscriptions.
        assert!(t.renew(s_ok));
        assert_eq!(t.renew_with_duration(s_ok, Some(500)), Some(500));
        assert_eq!(t.renew_with_duration(s_ok, Some(NEVER_EXPIRE)), Some(0));
        assert_eq!(t.find(s_ok).unwrap().lease, i64::MAX);
        assert!(!t.renew(9999));

        // Expired subscription filtered on find and reaped on expire.
        t.find_mut(s_big).unwrap().lease = now() - 10;
        assert!(t.find(s_big).is_none());
        t.expire();
        assert_eq!(t.count(), 2);
        assert!(t.remove(s_neg).is_some());
        assert!(t.remove(s_neg).is_none());
    }

    #[test]
    fn async_and_blocking_notifier_wakeups() {
        let mut t = Subscriptions::new();
        let id = t.add(
            Some("p1".into()),
            None,
            vec![Event::PrinterAdded],
            "alice".into(),
            NEVER_EXPIRE,
            None,
        );

        let (notes, ver, notifier) = t.snapshot_wait(id, 0);
        assert_eq!(notes, Some(Vec::new()));
        assert!(format!("{notifier:?}").contains("EventNotifier"));

        // Poll Notified before push -> Pending, registers waker.
        let flag = Arc::new(FlagWaker(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&flag));
        let mut cx = Context::from_waker(&waker);
        let mut fut = notifier.notified(ver);
        assert_eq!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending);
        // Repoll with same waker updates in place cleanly.
        assert_eq!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending);
        assert!(!flag.0.load(Ordering::SeqCst));

        // Dropping a cancelled future cleans up its waker slot.
        let mut cancelled = notifier.notified(ver);
        assert_eq!(Pin::new(&mut cancelled).poll(&mut cx), Poll::Pending);
        drop(cancelled);

        // Push event -> wakes the registered async waker!
        t.push(Event::PrinterAdded, Some("p1"), None, None, "added");
        assert!(flag.0.load(Ordering::SeqCst));
        let new_ver = match Pin::new(&mut fut).poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("expected Ready after push"),
        };
        assert_ne!(new_ver, ver);

        // Late poll with stale `ver` resolves immediately (zero lost wakeup!).
        let mut immediate = notifier.notified(ver);
        assert_eq!(Pin::new(&mut immediate).poll(&mut cx), Poll::Ready(new_ver));

        // Blocking wait_timeout: returns None on timeout, Some on cross-thread notify.
        let notifier_default = EventNotifier::default();
        let v0 = notifier_default.version();
        assert_eq!(
            notifier_default.wait_timeout(v0, Duration::from_millis(15)),
            None
        );
        let n2 = notifier_default.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(15));
            n2.notify_all();
        });
        let woken = notifier_default.wait_timeout(v0, Duration::from_secs(2));
        handle.join().unwrap();
        assert_eq!(woken, Some(v0 + 1));
    }

    #[test]
    fn subscriptions_conf_roundtrip_and_atomic_save() {
        let dir = temp_dir("conf");
        let path = dir.join("subscriptions.conf");

        let mut t = Subscriptions::new();
        let id1 = t.add_with_recipient(
            Some("laser#1\\a\nb\rc".into()),
            Some(42),
            vec![
                Event::PrinterFinishingsChanged,
                Event::PrinterMediaChanged,
                Event::JobCompleted,
            ],
            "alice#1".into(),
            3600,
            Some(vec![0xde, 0xad, 0xbe, 0xef]),
            Some("mailto:ops@example.com".into()),
        );
        t.push(
            Event::JobCompleted,
            Some("laser#1\\a\nb\rc"),
            Some(42),
            Some(9),
            "done",
        );

        let id2 = t.add(
            None,
            None,
            vec![Event::ServerAudit],
            "root".into(),
            NEVER_EXPIRE,
            None,
        );
        // Add an already-expired subscription that should NOT be persisted.
        let id3 = t.add(None, None, vec![Event::All], "old".into(), 60, None);
        t.find_mut(id3).unwrap().lease = now() - 5;

        t.save_file(&path).unwrap();
        #[cfg(unix)]
        {
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o640);
        }

        let mut t2 = Subscriptions::new();
        assert_eq!(t2.load_file(&path).unwrap(), Vec::<String>::new());
        // Missing file returns Ok(empty).
        assert_eq!(
            t2.load_file(&dir.join("missing.conf")).unwrap(),
            Vec::<String>::new()
        );

        let s1 = t2.find(id1).unwrap();
        assert_eq!(s1.printer.as_deref(), Some("laser#1\\a\nb\rc"));
        assert_eq!(s1.job_id, Some(42));
        assert_eq!(s1.owner, "alice#1");
        assert_eq!(s1.lease_duration, 3600);
        assert_eq!(s1.next_seq(), 2); // monotonic seq survived restart!
        assert_eq!(s1.user_data.as_deref(), Some(&[0xde, 0xad, 0xbe, 0xef][..]));
        assert_eq!(s1.recipient_uri.as_deref(), Some("mailto:ops@example.com"));
        assert_eq!(
            s1.events,
            vec![
                Event::PrinterFinishingsChanged,
                Event::PrinterMediaChanged,
                Event::JobCompleted,
            ]
        );

        let s2 = t2.find(id2).unwrap();
        assert_eq!(s2.lease, i64::MAX);
        assert!(t2.find(id3).is_none());

        // Exercise parser error branches & escaping edge cases.
        let bad_conf = "\
# comment
NextSubscriptionId 10
</Subscription>
<Subscription 0>
<Subscription bad>
<Subscription 5>
Owner bob\\x\\
ExpirationTime 0
UserData abc
<Subscription 6>
";
        let mut t3 = Subscriptions::new();
        let errs = t3.load_conf(io::Cursor::new(bad_conf.as_bytes()));
        assert!(errs.len() >= 4, "expected syntax errors, got {errs:?}");

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn nofollow_rejects_symlink_on_subscriptions_load() {
        use std::os::unix::fs::symlink;
        let dir = temp_dir("symlink");
        let real = dir.join("real.conf");
        fs::write(&real, b"NextSubscriptionId 1\n").unwrap();
        let link = dir.join("subscriptions.conf");
        symlink(&real, &link).unwrap();
        let mut t = Subscriptions::new();
        let err = t.load_file(&link).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(40)); // ELOOP
        let _ = fs::remove_dir_all(&dir);
    }
}
