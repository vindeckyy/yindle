//! Zero-dependency non-blocking subprocess runner and async timer primitives.
//!
//! Ensures `cups-deviced`, `cups-driverd`, and `Get-Notifications`
//! (`notify-wait=true`) never block Tokio worker threads when invoked via
//! [`crate::dispatch_async`], while keeping `crates/ops` free of extra Cargo
//! dependencies.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::future::Future;
use std::io::Read;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

/// Output returned by bounded helper execution (`cups-deviced` / `cups-driverd`).
#[derive(Debug, Clone)]
pub struct HelperOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
}

/// Parameters for launching an external CUPS daemon helper.
#[derive(Debug, Clone)]
pub struct HelperSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
    pub max_stdout: usize,
}

/// Run a helper synchronously with a hard timeout and stdout byte cap.
/// Kills and reaps the child if it exceeds `spec.timeout`.
#[must_use]
pub fn run_helper_sync(spec: &HelperSpec) -> Option<HelperOutput> {
    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().ok()?;
    let stdout_pipe = child.stdout.take();
    let max_bytes = spec.max_stdout;

    // Drain stdout on a short-lived reader thread so large output never
    // deadlocks the child while we poll for completion/timeout.
    let reader = thread::spawn(move || -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(pipe) = stdout_pipe {
            let cap = u64::try_from(max_bytes).unwrap_or(u64::MAX);
            let _ = pipe.take(cap).read_to_end(&mut buf);
        }
        buf
    });

    let deadline = Instant::now() + spec.timeout;
    let mut timed_out = false;
    let success = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) => {
                let now = Instant::now();
                if now >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break false;
                }
                let step = (deadline - now).min(Duration::from_millis(10));
                thread::sleep(step);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                timed_out = true;
                break false;
            }
        }
    };
    // On timeout, detach the reader thread so a grandchild holding stdout open
    // cannot block the daemon past `spec.timeout`.
    let stdout = if timed_out {
        Vec::new()
    } else {
        reader.join().unwrap_or_default()
    };
    Some(HelperOutput { success, stdout })
}

/// Run a helper asynchronously on a background OS thread without blocking the
/// calling async runtime worker thread.
pub async fn run_helper_async(spec: HelperSpec) -> Option<HelperOutput> {
    enum SlotState {
        Pending,
        Ready(Option<HelperOutput>),
    }

    struct Slot {
        state: SlotState,
        waker: Option<Waker>,
    }

    struct HelperFuture {
        slot: Arc<Mutex<Slot>>,
    }

    impl Future for HelperFuture {
        type Output = Option<HelperOutput>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let mut guard = self
                .slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match std::mem::replace(&mut guard.state, SlotState::Pending) {
                SlotState::Ready(res) => Poll::Ready(res),
                SlotState::Pending => {
                    guard.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        }
    }

    let slot = Arc::new(Mutex::new(Slot {
        state: SlotState::Pending,
        waker: None,
    }));
    let worker_slot = Arc::clone(&slot);
    thread::spawn(move || {
        let out = run_helper_sync(&spec);
        let waker = {
            let mut guard = worker_slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.state = SlotState::Ready(out);
            guard.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    });

    HelperFuture { slot }.await
}

// ---------- Lightweight shared async deadline timer ----------

struct TimerEntry {
    deadline: Instant,
    id: u64,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl PartialEq for TimerEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline && self.id == other.id
    }
}
impl Eq for TimerEntry {}
impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deadline
            .cmp(&other.deadline)
            .then_with(|| self.id.cmp(&other.id))
    }
}

struct TimerDriver {
    queue: Mutex<BinaryHeap<Reverse<TimerEntry>>>,
    cv: Condvar,
}

static TIMER_DRIVER: OnceLock<Arc<TimerDriver>> = OnceLock::new();
static TIMER_ID: AtomicU64 = AtomicU64::new(1);

fn timer_driver() -> &'static Arc<TimerDriver> {
    TIMER_DRIVER.get_or_init(|| {
        let driver = Arc::new(TimerDriver {
            queue: Mutex::new(BinaryHeap::new()),
            cv: Condvar::new(),
        });
        let bg = Arc::clone(&driver);
        let _ = thread::Builder::new()
            .name("ops-timer".into())
            .spawn(move || {
                let mut q = bg
                    .queue
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                loop {
                    let now = Instant::now();
                    while let Some(top) = q.peek() {
                        if top.0.deadline <= now {
                            if let Some(Reverse(entry)) = q.pop() {
                                let waker = entry
                                    .waker
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .take();
                                if let Some(w) = waker {
                                    w.wake();
                                }
                            }
                        } else {
                            break;
                        }
                    }
                    if let Some(top) = q.peek() {
                        let wait = top.0.deadline.saturating_duration_since(Instant::now());
                        let (guard, _) = bg
                            .cv
                            .wait_timeout(q, wait)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        q = guard;
                    } else {
                        q = bg
                            .cv
                            .wait(q)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                    }
                }
            });
        driver
    })
}

/// Await `notifier.notified(seen_version)` up to `timeout` without blocking
/// the async worker thread. Returns `Some(new_version)` if notified before the
/// deadline, or `None` on timeout.
pub async fn wait_notifier_async(
    notifier: &events::EventNotifier,
    seen_version: u64,
    timeout: Duration,
) -> Option<u64> {
    struct NotifiedTimeout {
        notified: events::Notified,
        deadline: Instant,
        timer_id: u64,
        waker_slot: Arc<Mutex<Option<Waker>>>,
        armed: bool,
    }

    impl Drop for NotifiedTimeout {
        fn drop(&mut self) {
            let _ = self
                .waker_slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }
    }

    impl Future for NotifiedTimeout {
        type Output = Option<u64>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            // Check notifier first so events ready at the exact deadline win.
            if let Poll::Ready(ver) = Pin::new(&mut self.notified).poll(cx) {
                return Poll::Ready(Some(ver));
            }
            if Instant::now() >= self.deadline {
                return Poll::Ready(None);
            }
            {
                let mut slot = self
                    .waker_slot
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *slot = Some(cx.waker().clone());
            }
            if !self.armed {
                let driver = timer_driver();
                let mut q = driver
                    .queue
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                q.push(Reverse(TimerEntry {
                    deadline: self.deadline,
                    id: self.timer_id,
                    waker: Arc::clone(&self.waker_slot),
                }));
                self.armed = true;
                driver.cv.notify_one();
            }
            Poll::Pending
        }
    }

    NotifiedTimeout {
        notified: notifier.notified(seen_version),
        deadline: Instant::now() + timeout,
        timer_id: TIMER_ID.fetch_add(1, Ordering::Relaxed),
        waker_slot: Arc::new(Mutex::new(None)),
        armed: false,
    }
    .await
}
