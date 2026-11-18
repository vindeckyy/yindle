#![allow(dead_code)]

use cups_config::{Config, CupsFilesConfig, CupsdConfig};
use events::Subscriptions;
use ipp_codec::{tags, Attribute, Group, IppMessage, Value};
use job::Jobs;
use mime_db::MimeDb;
use ops::{AuditRecord, Ctx, EventSignal};
use printer::{Printer, Registry};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;

static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

/// Auto-cleaned temporary directory for isolated spool/config/PPD tests.
pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new(label: &str) -> Self {
        let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("presswork-ops-test-{label}-{pid}-{seq}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp test dir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Reusable test harness owning `Registry`, `Jobs`, `MimeDb`, `Subscriptions`, `Config`,
/// and isolated temp directories (`server_root`, `request_root`, `data_dir`, `server_bin`).
pub struct Harness {
    pub tmp: TempDir,
    pub server_root: PathBuf,
    pub request_root: PathBuf,
    pub data_dir: PathBuf,
    pub server_bin: PathBuf,
    pub cfg: Config,
    pub registry: RwLock<Registry>,
    pub jobs: RwLock<Jobs>,
    pub mime: MimeDb,
    pub subs: RwLock<Subscriptions>,
    pub dnssd: RwLock<Option<dnssd::Advertiser>>,
}

impl Harness {
    pub fn new(label: &str) -> Self {
        let tmp = TempDir::new(label);
        let server_root = tmp.path.join("etc");
        let request_root = tmp.path.join("spool");
        let data_dir = tmp.path.join("share");
        let server_bin = tmp.path.join("lib");
        for d in [
            &server_root,
            &request_root,
            &data_dir,
            &server_bin,
            &server_root.join("ppd"),
            &data_dir.join("ppd"),
            &data_dir.join("drv"),
            &server_bin.join("daemon"),
            &server_bin.join("backend"),
        ] {
            std::fs::create_dir_all(d).expect("create subdir");
        }

        let mut cupsd = CupsdConfig::defaults();
        cupsd.policies.push(cups_config::default_policy());
        let mut files = CupsFilesConfig::defaults();
        files.server_root = Some(server_root.to_string_lossy().into_owned());
        files.request_root = Some(request_root.to_string_lossy().into_owned());
        files.data_dir = Some(data_dir.to_string_lossy().into_owned());
        files.server_bin = Some(server_bin.to_string_lossy().into_owned());

        let mut registry = Registry::default();
        let mut p = Printer::new("laser1", "ipp://printer1.local:631/ipp/print");
        p.info = Some("Office Laser".into());
        p.location = Some("Room 101".into());
        p.shared = true;
        registry.add(p);
        registry.default = Some("laser1".into());

        Self {
            tmp,
            server_root,
            request_root,
            data_dir,
            server_bin,
            cfg: Config { cupsd, files },
            registry: RwLock::new(registry),
            jobs: RwLock::new(Jobs::default()),
            mime: MimeDb::default(),
            subs: RwLock::new(Subscriptions::new()),
            dnssd: RwLock::new(None),
        }
    }

    pub fn ctx(&self) -> Ctx<'_> {
        let mut ctx = Ctx::new(
            &self.registry,
            &self.cfg,
            631,
            &self.jobs,
            &self.mime,
            &self.subs,
            &self.dnssd,
        );
        ctx.client_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        ctx
    }

    pub fn admin_ctx(&self) -> Ctx<'_> {
        let mut ctx = self.ctx();
        ctx.username = Some("admin".into());
        ctx.user_groups = vec!["lpadmin".into()];
        ctx
    }

    pub fn user_ctx(&self, user: &str) -> Ctx<'_> {
        let mut ctx = self.ctx();
        ctx.username = Some(user.into());
        ctx.user_groups = vec!["users".into()];
        ctx
    }

    pub fn add_printer(&self, name: &str, device_uri: &str) {
        let mut p = Printer::new(name, device_uri);
        p.shared = true;
        self.registry.write().unwrap().add(p);
    }

    pub fn install_mock_script(&self, rel: &str, body: &str) -> PathBuf {
        let path = self.server_bin.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }
}

/// Build a valid IPP 2.0 request pre-populated with required charset + language.
pub fn ipp_req(op_code: u16) -> IppMessage {
    let mut m = IppMessage::new(op_code);
    m.version = (2, 0);
    m.request_id = 1;
    m.push(
        tags::OPERATION,
        Attribute::new(
            "attributes-charset",
            tags::CHARSET,
            vec![Value::Charset("utf-8".into())],
        ),
    );
    m.push(
        tags::OPERATION,
        Attribute::new(
            "attributes-natural-language",
            tags::LANGUAGE,
            vec![Value::NaturalLanguage("en".into())],
        ),
    );
    m
}

pub fn with_printer_uri(mut m: IppMessage, uri: &str) -> IppMessage {
    m.push(
        tags::OPERATION,
        Attribute::new("printer-uri", tags::URI, vec![Value::Uri(uri.into())]),
    );
    m
}

pub fn with_job_uri(mut m: IppMessage, uri: &str) -> IppMessage {
    m.push(
        tags::OPERATION,
        Attribute::new("job-uri", tags::URI, vec![Value::Uri(uri.into())]),
    );
    m
}

pub fn with_op_attr(mut m: IppMessage, name: &str, tag: u8, val: Value) -> IppMessage {
    m.push(tags::OPERATION, Attribute::new(name, tag, vec![val]));
    m
}

pub fn with_job_attr(mut m: IppMessage, name: &str, tag: u8, val: Value) -> IppMessage {
    m.push(tags::JOB, Attribute::new(name, tag, vec![val]));
    m
}

pub fn with_printer_attr(mut m: IppMessage, name: &str, tag: u8, val: Value) -> IppMessage {
    m.push(tags::PRINTER, Attribute::new(name, tag, vec![val]));
    m
}

pub fn with_sub_group(mut m: IppMessage, attrs: Vec<Attribute>) -> IppMessage {
    let mut g = Group::new(tags::SUBSCRIPTION);
    g.attributes = attrs;
    m.groups.push(g);
    m
}

pub fn find_attr_int(msg: &IppMessage, group_tag: u8, name: &str) -> Option<i32> {
    msg.find(group_tag, name).and_then(Attribute::int)
}

pub fn find_attr_text(msg: &IppMessage, group_tag: u8, name: &str) -> Option<String> {
    msg.find(group_tag, name)
        .and_then(|a| a.text().map(std::borrow::Cow::into_owned))
}

/// Attach recording hooks for cancel/audit/event assertions.
pub struct HookRecorder {
    pub canceled: Arc<Mutex<Vec<u32>>>,
    pub audits: Arc<Mutex<Vec<AuditRecord>>>,
    pub events: Arc<Mutex<Vec<EventSignal>>>,
}

impl HookRecorder {
    pub fn attach(ctx: &mut Ctx<'_>) -> Self {
        let canceled = Arc::new(Mutex::new(Vec::new()));
        let audits = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));

        let c2 = Arc::clone(&canceled);
        ctx.on_cancel_job = Some(Arc::new(move |id| c2.lock().unwrap().push(id)));

        let a2 = Arc::clone(&audits);
        ctx.on_audit = Some(Arc::new(move |rec| a2.lock().unwrap().push(rec.clone())));

        let e2 = Arc::clone(&events);
        ctx.on_event = Some(Arc::new(move |sig| e2.lock().unwrap().push(sig.clone())));

        Self {
            canceled,
            audits,
            events,
        }
    }
}

/// Minimal pure-stdlib `block_on` executor for testing `dispatch_async`.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    struct ThreadWaker(thread::Thread);
    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    let waker = Waker::from(Arc::new(ThreadWaker(thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => return out,
            Poll::Pending => thread::park(),
        }
    }
}

/// Build a valid RFC 1952 gzip stream using stored DEFLATE blocks (no external deps).
pub fn gzip_stored(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    let mut pos = 0usize;
    loop {
        let chunk_len = (payload.len() - pos).min(65535);
        let is_final = pos + chunk_len >= payload.len();
        out.push(u8::from(is_final));
        let len = u16::try_from(chunk_len).unwrap();
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(&payload[pos..pos + chunk_len]);
        pos += chunk_len;
        if is_final {
            break;
        }
    }
    let crc = crc32_test(payload);
    out.extend_from_slice(&crc.to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out
}

pub fn crc32_test(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

pub fn valid_sample_ppd() -> String {
    concat!(
        "*PPD-Adobe: \"4.3\"\n",
        "*FormatVersion: \"4.3\"\n",
        "*FileVersion: \"1.0\"\n",
        "*LanguageVersion: English\n",
        "*LanguageEncoding: ISOLatin1\n",
        "*PCFileName: \"SAMPLE.PPD\"\n",
        "*Manufacturer: \"Presswork\"\n",
        "*ModelName: \"Presswork Color 1200\"\n",
        "*NickName: \"Presswork Color 1200\"\n",
        "*ColorDevice: True\n",
        "*DefaultPageSize: A4\n",
        "*PageSize A4/A4: \"\"\n",
        "*PageSize Letter/US Letter: \"\"\n",
        "*PageSize Legal/US Legal: \"\"\n",
        "*DefaultDuplex: DuplexNoTumble\n",
        "*Duplex None/Off: \"\"\n",
        "*Duplex DuplexNoTumble/Long Edge: \"\"\n",
        "*Duplex DuplexTumble/Short Edge: \"\"\n",
        "*DefaultResolution: 1200dpi\n",
        "*Resolution 600dpi/600 DPI: \"\"\n",
        "*Resolution 1200dpi/1200 DPI: \"\"\n",
        "*cupsFilter: \"application/vnd.presswork-test 10 pdftopdf\"\n",
        "*cupsFilter2: \"application/pdf application/pdf 0 -\"\n",
        "*cupsManualCopies: False\n",
    )
    .to_string()
}

pub fn write_file(path: &Path, data: &[u8]) {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::write(path, data).unwrap();
}
