//! Print job model + spool persistence — a port of `scheduler/job.c`.
//!
//! Jobs live under `RequestRoot` (default `/var/spool/cups`):
//! - `d%05d-%03d`: document data files (e.g. `d00012-001`, `d100000-001`)
//! - `c%05d`: IPP-serialized job-attribute control file (variable-width
//!   numeric suffix `c<id>`, supporting IDs >= 100,000)
//! - `job.cache`: optional fast-boot index in `CacheDir`
//!
//! Spool files are written atomically in the target directory with
//! `O_CREAT | O_EXCL | O_NOFOLLOW`, mode `0600`, `fsync`, and `rename`.

use ipp_codec::model::{Attribute, IppMessage, Text, Value};
use ipp_codec::tags;
use std::collections::hash_map::RandomState;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Default permissions for spool control (`c*`) and data (`d*`) files (`0600`).
pub const SPOOL_FILE_MODE: u32 = 0o600;

/// Default permissions for `job.cache` (`0600`).
pub const CACHE_FILE_MODE: u32 = 0o600;

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
static UUID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// IPP `job-state` enum values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum JobState {
    Pending = 3,
    PendingHeld = 4,
    Processing = 5,
    ProcessingStopped = 6,
    Canceled = 7,
    Aborted = 8,
    Completed = 9,
}

impl JobState {
    #[must_use]
    pub fn from_i32(v: i32) -> Option<Self> {
        Some(match v {
            3 => Self::Pending,
            4 => Self::PendingHeld,
            5 => Self::Processing,
            6 => Self::ProcessingStopped,
            7 => Self::Canceled,
            8 => Self::Aborted,
            9 => Self::Completed,
            _ => return None,
        })
    }

    /// Whether the job is finished.
    #[must_use]
    pub fn is_final(self) -> bool {
        matches!(self, Self::Canceled | Self::Aborted | Self::Completed)
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::PendingHeld => "pending-held",
            Self::Processing => "processing",
            Self::ProcessingStopped => "processing-stopped",
            Self::Canceled => "canceled",
            Self::Aborted => "aborted",
            Self::Completed => "completed",
        }
    }
}

/// How startup crash recovery handles jobs persisted in `Processing` state
/// (whose `backend_pid` is `None` after an unclean daemon restart).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CrashRecoveryPolicy {
    /// Transition interrupted `Processing` jobs back to `Pending` so the
    /// scheduler cleanly re-runs them instead of permanently wedging the queue.
    #[default]
    Requeue,
    /// Transition interrupted `Processing` jobs to `Aborted`.
    Abort,
}

/// One document in a job (`job->files[i]` analogue).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobFile {
    /// File number (1-based; `d%05d-%03d`).
    pub num: u32,
    /// Detected/declared MIME type.
    pub filetype: String,
    /// Byte size on disk.
    pub size: u64,
    /// Filename the client supplied (`document-name`).
    pub name: String,
    /// `document-format` as submitted.
    pub format: String,
}

/// A queued print job (`cupsd_job_t` analogue).
#[derive(Debug, Clone)]
pub struct Job {
    pub id: i32,
    pub state: JobState,
    /// `job-state-reasons`.
    pub reasons: Vec<String>,
    pub priority: i32,
    /// Owning user.
    pub username: String,
    /// Target printer queue name.
    pub dest: String,
    /// Original IPP job-attributes (client-submitted + synthesized).
    pub attrs: Vec<Attribute>,
    pub files: Vec<JobFile>,
    pub created_at: i64,
    /// When the job entered `Processing` (`time-at-processing`).
    pub processing_at: Option<i64>,
    pub completed_at: Option<i64>,
    /// Running filter-pipeline backend pid, if any.
    pub backend_pid: Option<i32>,
    pub copies: i32,
    pub title: String,
    /// `document-format` of the primary file.
    pub format: String,
    /// RFC 4122 UUID v4 URI (`urn:uuid:...`).
    pub job_uuid: String,
    /// `job-hold-until` keyword/specification, if held.
    pub hold_until: Option<String>,
    /// Key-value print options (`cupsParseOptions` / filter argv[5]).
    pub options: BTreeMap<String, String>,
}

impl Job {
    pub fn new(id: i32, dest: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            id,
            state: JobState::Pending,
            reasons: vec!["job-incoming".into()],
            priority: 50,
            username: username.into(),
            dest: dest.into(),
            attrs: Vec::new(),
            files: Vec::new(),
            created_at: now(),
            processing_at: None,
            completed_at: None,
            backend_pid: None,
            copies: 1,
            title: String::new(),
            format: "application/octet-stream".into(),
            job_uuid: format!("urn:uuid:{}", uuid_v4()),
            hold_until: None,
            options: BTreeMap::new(),
        }
    }

    /// Control-file path: `RequestRoot/c%05d` (variable width for IDs >= 100,000).
    #[must_use]
    pub fn control_path(root: &Path, id: i32) -> PathBuf {
        root.join(format!("c{id:05}"))
    }

    /// Data-file path: `RequestRoot/d%05d-%03d`.
    #[must_use]
    pub fn data_path(root: &Path, id: i32, num: u32) -> PathBuf {
        root.join(format!("d{id:05}-{num:03}"))
    }

    /// Atomically write a spool document data file (`d%05d-%03d`) with
    /// `O_CREAT | O_EXCL | O_NOFOLLOW`, mode `0600`, `fsync`, and `rename`.
    pub fn write_data_file(root: &Path, id: i32, num: u32, data: &[u8]) -> io::Result<PathBuf> {
        let path = Self::data_path(root, id, num);
        write_atomic(&path, data, SPOOL_FILE_MODE)?;
        Ok(path)
    }

    /// Serialize `job-attributes` to the control file (`cupsdSaveJob`).
    pub fn save(&self, root: &Path) -> io::Result<()> {
        let mut msg = IppMessage::new(ipp_codec::ops::op::PRINT_JOB);
        msg.request_id = self.id;
        let g = msg.group_mut(tags::JOB);
        g.attributes.clone_from(&self.attrs);

        // Bookkeeping attrs live in the same set so a restart rebuilds the
        // job verbatim.
        upsert(&mut msg, "job-id", tags::INTEGER, Value::Integer(self.id));
        upsert(
            &mut msg,
            "job-state",
            tags::ENUM,
            Value::Enum(self.state as i32),
        );
        upsert(
            &mut msg,
            "job-priority",
            tags::INTEGER,
            Value::Integer(self.priority),
        );
        upsert(
            &mut msg,
            "copies",
            tags::INTEGER,
            Value::Integer(self.copies),
        );
        upsert(
            &mut msg,
            "job-printer-uri",
            tags::URI,
            Value::Uri(Text::from(format!(
                "ipp://localhost/printers/{}",
                self.dest
            ))),
        );
        upsert(
            &mut msg,
            "job-originating-user-name",
            tags::NAME,
            Value::Name(Text::from(self.username.as_str())),
        );
        upsert(
            &mut msg,
            "job-name",
            tags::NAME,
            Value::Name(Text::from(self.title.as_str())),
        );
        upsert(
            &mut msg,
            "document-format",
            tags::MIMETYPE,
            Value::MimeMediaType(Text::from(self.format.as_str())),
        );
        upsert(
            &mut msg,
            "job-uuid",
            tags::URI,
            Value::Uri(Text::from(self.job_uuid.as_str())),
        );
        upsert(
            &mut msg,
            "time-at-creation",
            tags::INTEGER,
            Value::Integer(i32::try_from(self.created_at).unwrap_or(i32::MAX)),
        );
        save_optional_attrs(&mut msg, self);
        save_files_attrs(&mut msg, &self.files);

        let bytes = ipp_codec::encode(&msg).map_err(|e| io::Error::other(e.to_string()))?;
        write_atomic(&Self::control_path(root, self.id), &bytes, SPOOL_FILE_MODE)
    }

    /// Load a job from its control file (`cupsdLoadAllJobs` per file).
    /// Opens the control file with `O_NOFOLLOW` to avoid symlink traversal.
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut buf = Vec::new();
        open_read_nofollow(path)?.read_to_end(&mut buf)?;
        let (msg, _) = ipp_codec::decode(&buf)
            .map_err(|e| io::Error::other(format!("bad control file: {e}")))?;
        let get_i = |name: &str| -> Option<i32> {
            find(&msg, name).and_then(|v| match v {
                Value::Integer(i) | Value::Enum(i) => Some(*i),
                _ => None,
            })
        };
        let get_t = |name: &str| -> Option<String> { find(&msg, name).and_then(value_to_string) };

        let id = get_i("job-id").unwrap_or_else(|| {
            path.file_name()
                .and_then(|s| s.to_str())
                .and_then(parse_control_filename)
                .unwrap_or(0)
        });
        let state =
            JobState::from_i32(get_i("job-state").unwrap_or(3)).unwrap_or(JobState::Pending);
        let dest_uri = get_t("job-printer-uri").unwrap_or_default();
        let dest = dest_uri.rsplit('/').next().unwrap_or("").to_string();
        let files = load_files_attrs(&msg, path, id);
        let reasons: Vec<String> = find_all(&msg, "job-state-reasons")
            .into_iter()
            .filter_map(value_to_string)
            .filter(|r| !r.is_empty())
            .collect();
        let job_uuid = get_t("job-uuid")
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| format!("urn:uuid:{}", uuid_v4()));
        let hold_until = get_t("job-hold-until").filter(|h| !h.is_empty());
        let mut options = BTreeMap::new();
        for v in find_all(&msg, "job-options") {
            if let Some(s) = value_to_string(v) {
                if let Some((k, val)) = decode_option_pair(&s) {
                    options.insert(k, val);
                }
            }
        }

        Ok(Self {
            id,
            state,
            reasons,
            priority: get_i("job-priority").unwrap_or(50),
            username: get_t("job-originating-user-name").unwrap_or_else(|| "anonymous".into()),
            dest,
            attrs: msg
                .groups
                .first()
                .map(|g| g.attributes.clone())
                .unwrap_or_default(),
            files,
            created_at: get_i("time-at-creation").map_or_else(now, i64::from),
            processing_at: get_i("time-at-processing").map(i64::from),
            completed_at: get_i("time-at-completed").map(i64::from),
            backend_pid: None,
            copies: get_i("copies").unwrap_or(1),
            title: get_t("job-name").unwrap_or_default(),
            format: get_t("document-format").unwrap_or_else(|| "application/octet-stream".into()),
            job_uuid,
            hold_until,
            options,
        })
    }
}

fn save_optional_attrs(msg: &mut IppMessage, job: &Job) {
    if let Some(t) = job.processing_at {
        upsert(
            msg,
            "time-at-processing",
            tags::INTEGER,
            Value::Integer(i32::try_from(t).unwrap_or(i32::MAX)),
        );
    } else {
        remove_attr(msg, "time-at-processing");
    }
    if let Some(t) = job.completed_at {
        upsert(
            msg,
            "time-at-completed",
            tags::INTEGER,
            Value::Integer(i32::try_from(t).unwrap_or(i32::MAX)),
        );
    } else {
        remove_attr(msg, "time-at-completed");
    }
    if job.reasons.is_empty() {
        remove_attr(msg, "job-state-reasons");
    } else {
        upsert_n(
            msg,
            "job-state-reasons",
            tags::KEYWORD,
            job.reasons
                .iter()
                .map(|r| Value::Keyword(Text::from(r.as_str())))
                .collect(),
        );
    }
    if let Some(ref hold) = job.hold_until {
        upsert(
            msg,
            "job-hold-until",
            tags::KEYWORD,
            Value::Keyword(Text::from(hold.as_str())),
        );
    } else {
        remove_attr(msg, "job-hold-until");
    }
    if job.options.is_empty() {
        remove_attr(msg, "job-options");
    } else {
        upsert_n(
            msg,
            "job-options",
            tags::TEXT,
            job.options
                .iter()
                .map(|(k, v)| Value::Text(Text::from(encode_option_pair(k, v))))
                .collect(),
        );
    }
}

fn save_files_attrs(msg: &mut IppMessage, files: &[JobFile]) {
    if files.is_empty() {
        remove_attr(msg, "job-document-files");
        remove_attr(msg, "job-document-numbers");
        remove_attr(msg, "job-document-sizes");
        remove_attr(msg, "job-document-names");
        remove_attr(msg, "job-document-formats");
        return;
    }
    upsert_n(
        msg,
        "job-document-files",
        tags::MIMETYPE,
        files
            .iter()
            .map(|f| Value::MimeMediaType(Text::from(f.filetype.as_str())))
            .collect(),
    );
    upsert_n(
        msg,
        "job-document-numbers",
        tags::INTEGER,
        files
            .iter()
            .map(|f| Value::Integer(i32::try_from(f.num).unwrap_or(i32::MAX)))
            .collect(),
    );
    upsert_n(
        msg,
        "job-document-sizes",
        tags::TEXT,
        files
            .iter()
            .map(|f| Value::Text(Text::from(f.size.to_string())))
            .collect(),
    );
    upsert_n(
        msg,
        "job-document-names",
        tags::NAME,
        files
            .iter()
            .map(|f| Value::Name(Text::from(f.name.as_str())))
            .collect(),
    );
    upsert_n(
        msg,
        "job-document-formats",
        tags::MIMETYPE,
        files
            .iter()
            .map(|f| Value::MimeMediaType(Text::from(f.format.as_str())))
            .collect(),
    );
}

fn load_files_attrs(msg: &IppMessage, path: &Path, id: i32) -> Vec<JobFile> {
    let filetypes = find_all(msg, "job-document-files");
    let numbers = find_all(msg, "job-document-numbers");
    let sizes = find_all(msg, "job-document-sizes");
    let names = find_all(msg, "job-document-names");
    let formats = find_all(msg, "job-document-formats");

    filetypes
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let num = numbers
                .get(i)
                .and_then(|nv| match nv {
                    Value::Integer(n) | Value::Enum(n) => u32::try_from(*n).ok(),
                    _ => None,
                })
                .unwrap_or_else(|| u32::try_from(i).unwrap_or(0) + 1);
            let filetype = value_to_string(v).unwrap_or_else(|| "application/octet-stream".into());
            let size = sizes
                .get(i)
                .and_then(|sv| match sv {
                    Value::Integer(n) => u64::try_from(*n).ok(),
                    other => value_to_string(other).and_then(|s| s.parse::<u64>().ok()),
                })
                .unwrap_or_else(|| {
                    path.parent()
                        .and_then(|root| fs::metadata(Job::data_path(root, id, num)).ok())
                        .map_or(0, |m| m.len())
                });
            let name = names
                .get(i)
                .and_then(|nv| value_to_string(nv))
                .unwrap_or_default();
            let format = formats
                .get(i)
                .and_then(|fv| value_to_string(fv))
                .unwrap_or_else(|| filetype.clone());
            JobFile {
                num,
                filetype,
                size,
                name,
                format,
            }
        })
        .collect()
}

/// In-memory job table keyed by id (`cupsd_jobs` analogue).
#[derive(Debug, Default)]
pub struct Jobs {
    pub by_id: BTreeMap<i32, Job>,
    next_id: i32,
}

impl Jobs {
    /// Scan `RequestRoot` for `c<id>` control files and rebuild the table.
    ///
    /// Supports variable-length numeric `c<id>` filenames (including IDs
    /// at or above 100,000 such as `c100000`) and recovers interrupted
    /// `Processing` jobs back to `Pending` using [`CrashRecoveryPolicy::Requeue`].
    #[must_use]
    pub fn load_all(root: &Path) -> Self {
        Self::load_all_with_policy(root, CrashRecoveryPolicy::Requeue)
    }

    /// Scan `RequestRoot` for `c<id>` control files with an explicit
    /// [`CrashRecoveryPolicy`].
    #[must_use]
    pub fn load_all_with_policy(root: &Path, policy: CrashRecoveryPolicy) -> Self {
        let mut j = Jobs::default();
        let Ok(rd) = fs::read_dir(root) else {
            j.next_id = 1;
            return j;
        };
        let mut max = 0i32;
        for e in rd.flatten() {
            let p = e.path();
            let n = e.file_name();
            let Some(name_str) = n.to_str() else {
                continue;
            };
            if parse_control_filename(name_str).is_none() {
                continue;
            }
            if let Ok(mut job) = Job::load(&p) {
                if job.state == JobState::Processing && job.backend_pid.is_none() {
                    recover_job(&mut job, policy);
                    let _ = job.save(root);
                }
                max = max.max(job.id);
                j.by_id.insert(job.id, job);
            }
        }
        j.next_id = max.saturating_add(1).max(1);
        j
    }

    /// Recover any in-memory jobs currently in `Processing` state with no
    /// running `backend_pid`. Returns the recovered job IDs.
    pub fn recover_crashed(
        &mut self,
        root: Option<&Path>,
        policy: CrashRecoveryPolicy,
    ) -> Vec<i32> {
        let mut recovered = Vec::new();
        for job in self.by_id.values_mut() {
            if job.state == JobState::Processing && job.backend_pid.is_none() {
                recover_job(job, policy);
                if let Some(dir) = root {
                    let _ = job.save(dir);
                }
                recovered.push(job.id);
            }
        }
        recovered
    }

    /// Next job-id that will be allocated (at least 1).
    #[must_use]
    pub fn next_id(&self) -> i32 {
        self.next_id.max(1)
    }

    /// Allocate the next job-id (`cupsdNextJobId`).
    pub fn alloc_id(&mut self) -> i32 {
        let id = self.next_id.max(1);
        self.next_id = id.saturating_add(1);
        id
    }

    /// Insert and persist a job.
    pub fn add(&mut self, root: &Path, job: Job) -> io::Result<i32> {
        let id = job.id;
        job.save(root)?;
        if id >= self.next_id {
            self.next_id = id.saturating_add(1);
        }
        self.by_id.insert(id, job);
        Ok(id)
    }

    /// Persist an existing job's current state.
    pub fn save(&self, root: &Path, id: i32) -> io::Result<()> {
        if let Some(j) = self.by_id.get(&id) {
            j.save(root)
        } else {
            Ok(())
        }
    }

    /// Remove a job + its spool files (`cupsdDeleteJob`).
    pub fn remove(&mut self, root: &Path, id: i32) -> io::Result<()> {
        if let Some(j) = self.by_id.remove(&id) {
            for f in &j.files {
                let _ = fs::remove_file(Job::data_path(root, id, f.num));
            }
            let _ = fs::remove_file(Job::control_path(root, id));
        }
        Ok(())
    }

    #[must_use]
    pub fn get(&self, id: i32) -> Option<&Job> {
        self.by_id.get(&id)
    }

    pub fn get_mut(&mut self, id: i32) -> Option<&mut Job> {
        self.by_id.get_mut(&id)
    }

    /// Jobs targeting a printer.
    pub fn for_printer<'a>(&'a self, dest: &'a str) -> impl Iterator<Item = &'a Job> + 'a {
        self.by_id.values().filter(move |j| j.dest == dest)
    }

    /// Active (non-final) jobs in submission order.
    pub fn active(&self) -> impl Iterator<Item = &Job> {
        self.by_id.values().filter(|j| !j.state.is_final())
    }

    /// All jobs, mutable (bulk ops like Cancel-My-Jobs / Purge-Jobs).
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut Job> {
        self.by_id.values_mut()
    }

    /// Every job id currently tracked.
    #[must_use]
    pub fn ids(&self) -> Vec<i32> {
        self.by_id.keys().copied().collect()
    }

    /// Serialize a fast-boot `job.cache` index (CUPS `cupsdSaveJobCache` analogue).
    #[must_use]
    pub fn encode_cache(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("# Job cache file for CUPS v2.5-rust\n");
        out.push_str("# Written by cupsd\n");
        let _ = writeln!(out, "NextJobId {}", self.next_id());
        for job in self.by_id.values() {
            let _ = writeln!(out, "<Job {}>", job.id);
            let _ = writeln!(out, "State {}", job.state as i32);
            let _ = writeln!(out, "Priority {}", job.priority);
            let _ = writeln!(out, "Username {}", esc_cache(&job.username));
            let _ = writeln!(out, "Destination {}", esc_cache(&job.dest));
            let _ = writeln!(out, "Title {}", esc_cache(&job.title));
            let _ = writeln!(out, "Format {}", esc_cache(&job.format));
            let _ = writeln!(out, "Copies {}", job.copies);
            let _ = writeln!(out, "Created {}", job.created_at);
            if let Some(t) = job.processing_at {
                let _ = writeln!(out, "Processing {t}");
            }
            if let Some(t) = job.completed_at {
                let _ = writeln!(out, "Completed {t}");
            }
            let _ = writeln!(out, "UUID {}", esc_cache(&job.job_uuid));
            if let Some(ref hold) = job.hold_until {
                let _ = writeln!(out, "HoldUntil {}", esc_cache(hold));
            }
            for r in &job.reasons {
                let _ = writeln!(out, "Reason {}", esc_cache(r));
            }
            for (k, v) in &job.options {
                let _ = writeln!(out, "Option {}", esc_cache(&encode_option_pair(k, v)));
            }
            for f in &job.files {
                let _ = writeln!(
                    out,
                    "File {}\t{}\t{}\t{}\t{}",
                    f.num,
                    f.size,
                    esc_cache(&f.filetype),
                    esc_cache(&f.format),
                    esc_cache(&f.name),
                );
            }
            out.push_str("</Job>\n");
        }
        out.into_bytes()
    }

    /// Atomically write `job.cache` with mode `0600`.
    pub fn save_cache(&self, cache_path: &Path) -> io::Result<()> {
        self.save_cache_with_mode(cache_path, CACHE_FILE_MODE)
    }

    /// Atomically write `job.cache` with an explicit permission mode.
    pub fn save_cache_with_mode(&self, cache_path: &Path, mode: u32) -> io::Result<()> {
        write_atomic(cache_path, &self.encode_cache(), mode)
    }

    /// Load jobs from a `job.cache` file (applying crash recovery).
    pub fn load_cache(cache_path: &Path, policy: CrashRecoveryPolicy) -> io::Result<Self> {
        let f = open_read_nofollow(cache_path)?;
        Self::decode_cache(BufReader::new(f), policy)
    }

    /// Parse `job.cache` from any buffered reader.
    pub fn decode_cache<R: BufRead>(r: R, policy: CrashRecoveryPolicy) -> io::Result<Self> {
        let mut jobs = Self::default();
        let mut cur: Option<Job> = None;
        let mut saw_next_id = false;
        let mut max_id = 0i32;

        for line_res in r.lines() {
            let line = line_res?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("NextJobId ") {
                let parsed: i32 = rest
                    .trim()
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad NextJobId"))?;
                if parsed < 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "NextJobId must be >= 1",
                    ));
                }
                jobs.next_id = parsed;
                saw_next_id = true;
            } else if let Some(rest) = trimmed.strip_prefix("<Job ") {
                if cur.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "nested <Job> block",
                    ));
                }
                let id_str = rest
                    .strip_suffix('>')
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unclosed <Job"))?;
                let id: i32 = id_str
                    .trim()
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad job id"))?;
                let mut job = Job::new(id, "", "anonymous");
                job.reasons.clear();
                cur = Some(job);
            } else if trimmed == "</Job>" {
                let mut job = cur.take().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "stray </Job> tag")
                })?;
                if job.state == JobState::Processing && job.backend_pid.is_none() {
                    recover_job(&mut job, policy);
                }
                max_id = max_id.max(job.id);
                jobs.by_id.insert(job.id, job);
            } else if let Some(job) = cur.as_mut() {
                apply_cache_directive(job, trimmed)?;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected directive outside <Job>",
                ));
            }
        }

        if cur.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unterminated <Job> block",
            ));
        }
        if !saw_next_id && jobs.by_id.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty job.cache",
            ));
        }
        jobs.next_id = jobs.next_id.max(max_id.saturating_add(1)).max(1);
        Ok(jobs)
    }

    /// Fast-boot loader: loads `cache_path` when it exists, is valid, and is at
    /// least as fresh as `root`; otherwise falls back cleanly to scanning `c*`
    /// control files in `root`.
    #[must_use]
    pub fn load_with_cache(root: &Path, cache_path: &Path, policy: CrashRecoveryPolicy) -> Self {
        if cache_is_fresh(root, cache_path) {
            if let Ok(cached) = Self::load_cache(cache_path, policy) {
                // Persist recovered jobs if crash recovery changed state.
                for job in cached.by_id.values() {
                    if job.reasons.iter().any(|r| r == "job-restartable")
                        || job.state == JobState::Aborted
                    {
                        let _ = job.save(root);
                    }
                }
                return cached;
            }
        }
        Self::load_all_with_policy(root, policy)
    }
}

fn cache_is_fresh(root: &Path, cache_path: &Path) -> bool {
    let Ok(cache_meta) = fs::symlink_metadata(cache_path) else {
        return false;
    };
    if !cache_meta.file_type().is_file() {
        return false;
    }
    let Ok(cache_mtime) = cache_meta.modified() else {
        return false;
    };
    let Ok(root_mtime) = fs::metadata(root).and_then(|m| m.modified()) else {
        return true;
    };
    cache_mtime >= root_mtime
}

fn apply_cache_directive(job: &mut Job, line: &str) -> io::Result<()> {
    let (key, val) = line.split_once(' ').unwrap_or((line, ""));
    match key {
        "State" => {
            let s: i32 = val
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad State"))?;
            job.state = JobState::from_i32(s)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unknown JobState"))?;
        }
        "Priority" => {
            job.priority = val
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad Priority"))?;
        }
        "Username" => job.username = unesc_cache(val),
        "Destination" => job.dest = unesc_cache(val),
        "Title" => job.title = unesc_cache(val),
        "Format" => job.format = unesc_cache(val),
        "Copies" => {
            job.copies = val
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad Copies"))?;
        }
        "Created" => {
            job.created_at = val
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad Created"))?;
        }
        "Processing" => {
            job.processing_at = Some(
                val.parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad Processing"))?,
            );
        }
        "Completed" => {
            job.completed_at = Some(
                val.parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad Completed"))?,
            );
        }
        "UUID" => job.job_uuid = unesc_cache(val),
        "HoldUntil" => job.hold_until = Some(unesc_cache(val)),
        "Reason" => job.reasons.push(unesc_cache(val)),
        "Option" => {
            let decoded = unesc_cache(val);
            if let Some((k, v)) = decode_option_pair(&decoded) {
                job.options.insert(k, v);
            }
        }
        "File" => {
            let mut parts = val.splitn(5, '\t');
            let (Some(num_s), Some(size_s), Some(ft), Some(fmt), Some(name)) = (
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
            ) else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad File entry"));
            };
            let num = num_s
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad File num"))?;
            let size = size_s
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad File size"))?;
            job.files.push(JobFile {
                num,
                size,
                filetype: unesc_cache(ft),
                format: unesc_cache(fmt),
                name: unesc_cache(name),
            });
        }
        _ => {}
    }
    Ok(())
}

fn recover_job(job: &mut Job, policy: CrashRecoveryPolicy) {
    job.backend_pid = None;
    job.reasons
        .retain(|r| r != "job-printing" && r != "processing-to-stop-point");
    match policy {
        CrashRecoveryPolicy::Requeue => {
            job.state = JobState::Pending;
            job.processing_at = None;
            if !job.reasons.iter().any(|r| r == "job-restartable") {
                job.reasons.push("job-restartable".into());
            }
        }
        CrashRecoveryPolicy::Abort => {
            job.state = JobState::Aborted;
            job.completed_at = Some(now());
            if !job.reasons.iter().any(|r| r == "aborted-by-system") {
                job.reasons.push("aborted-by-system".into());
            }
        }
    }
}

/// Parse a spool control filename `c<digits>` (any positive digit width,
/// e.g. `c00001`, `c99999`, `c100000`, `c1234567`).
fn parse_control_filename(name: &str) -> Option<i32> {
    let digits = name.strip_prefix('c')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let id = digits.parse::<i32>().ok()?;
    (id > 0).then_some(id)
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
/// directory created with `O_CREAT | O_EXCL | O_NOFOLLOW` and `mode`, then
/// `fchmod`, `fsync`, `rename`, and best-effort parent-directory `fsync`.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let base = path.file_name().and_then(|n| n.to_str()).unwrap_or("spool");
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

// ---------- RFC 4122 UUID v4 ----------

/// Generate a valid RFC 4122 version 4 UUID using OS randomness (`/dev/urandom`).
#[must_use]
pub fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    let mut src = File::open("/dev/urandom").ok();
    fill_random_bytes(src.as_mut(), &mut bytes);
    format_uuid_v4(bytes)
}

fn fill_random_bytes<R: Read>(src: Option<&mut R>, out: &mut [u8; 16]) {
    if let Some(r) = src {
        if r.read_exact(out).is_ok() {
            return;
        }
    }
    // Fallback when /dev/urandom is unavailable: mix RandomState (OS-seeded),
    // high-res timestamp, PID, and a monotonic atomic counter.
    let c = UUID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let pid = u64::from(std::process::id());
    let mut h1 = RandomState::new().build_hasher();
    h1.write_u64(c);
    h1.write_u128(nanos);
    h1.write_u64(pid);
    let a = h1.finish();
    let mut h2 = RandomState::new().build_hasher();
    h2.write_u64(a ^ 0x9e37_79b9_7f4a_7c15);
    h2.write_u64(c.wrapping_add(1));
    let b = h2.finish();
    out[..8].copy_from_slice(&a.to_le_bytes());
    out[8..].copy_from_slice(&b.to_le_bytes());
}

fn format_uuid_v4(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant 1
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

// ---------- escaping & option helpers ----------

fn encode_option_pair(k: &str, v: &str) -> String {
    let mut out = String::with_capacity(k.len() + v.len() + 1);
    for c in k.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            c => out.push(c),
        }
    }
    out.push('=');
    out.push_str(v);
    out
}

fn decode_option_pair(s: &str) -> Option<(String, String)> {
    let mut key = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let next = chars.next()?;
                key.push(next);
            }
            '=' => {
                return Some((key, chars.as_str().to_string()));
            }
            c => key.push(c),
        }
    }
    None
}

fn esc_cache(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

fn unesc_cache(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ---------- attribute helpers ----------

fn value_to_string(v: &Value) -> Option<String> {
    match v {
        Value::Text(t)
        | Value::Name(t)
        | Value::Keyword(t)
        | Value::Uri(t)
        | Value::UriScheme(t)
        | Value::MimeMediaType(t)
        | Value::Charset(t)
        | Value::NaturalLanguage(t) => Some(t.to_string()),
        _ => None,
    }
}

fn find<'a>(msg: &'a IppMessage, name: &str) -> Option<&'a Value> {
    msg.groups
        .iter()
        .flat_map(|g| &g.attributes)
        .find(|a| a.name == name)
        .and_then(|a| a.values.first())
}

fn find_all<'a>(msg: &'a IppMessage, name: &str) -> Vec<&'a Value> {
    msg.groups
        .iter()
        .flat_map(|g| &g.attributes)
        .find(|a| a.name == name)
        .map(|a| a.values.iter().collect())
        .unwrap_or_default()
}

fn remove_attr(msg: &mut IppMessage, name: &str) {
    let g = msg.group_mut(tags::JOB);
    g.attributes.retain(|a| a.name != name);
}

fn upsert(msg: &mut IppMessage, name: &str, tag: u8, v: Value) {
    let g = msg.group_mut(tags::JOB);
    if let Some(a) = g.attributes.iter_mut().find(|a| a.name == name) {
        a.tag = tag;
        a.values = vec![v];
    } else {
        g.attributes.push(Attribute::new(name, tag, vec![v]));
    }
}

fn upsert_n(msg: &mut IppMessage, name: &str, tag: u8, vs: Vec<Value>) {
    let g = msg.group_mut(tags::JOB);
    if let Some(a) = g.attributes.iter_mut().find(|a| a.name == name) {
        a.tag = tag;
        a.values = vs;
    } else {
        g.attributes.push(Attribute::new(name, tag, vs));
    }
}

#[must_use]
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn temp_dir(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "presswork-job-test-{}-{}-{id}",
            std::process::id(),
            tag
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn job_state_conversions_and_names() {
        let cases = [
            (3, JobState::Pending, "pending", false),
            (4, JobState::PendingHeld, "pending-held", false),
            (5, JobState::Processing, "processing", false),
            (6, JobState::ProcessingStopped, "processing-stopped", false),
            (7, JobState::Canceled, "canceled", true),
            (8, JobState::Aborted, "aborted", true),
            (9, JobState::Completed, "completed", true),
        ];
        for (code, st, name, is_final) in cases {
            assert_eq!(JobState::from_i32(code), Some(st));
            assert_eq!(st.name(), name);
            assert_eq!(st.is_final(), is_final);
        }
        assert_eq!(JobState::from_i32(0), None);
        assert_eq!(JobState::from_i32(2), None);
        assert_eq!(JobState::from_i32(10), None);
    }

    #[test]
    fn uuid_v4_valid_and_unique() {
        let mut seen = HashSet::new();
        for _ in 0..256 {
            let u = uuid_v4();
            assert_eq!(u.len(), 36, "bad len: {u}");
            let b = u.as_bytes();
            assert_eq!(b[8], b'-');
            assert_eq!(b[13], b'-');
            assert_eq!(b[14], b'4', "must be v4: {u}");
            assert_eq!(b[18], b'-');
            assert!(
                matches!(b[19], b'8' | b'9' | b'a' | b'b'),
                "must be RFC 4122 variant: {u}"
            );
            assert_eq!(b[23], b'-');
            assert!(seen.insert(u), "duplicate UUID generated");
        }

        // Also test the fallback generator when reader is None or fails.
        let mut out1 = [0u8; 16];
        let mut out2 = [0u8; 16];
        fill_random_bytes::<io::Empty>(None, &mut out1);
        let mut empty = io::empty();
        fill_random_bytes(Some(&mut empty), &mut out2);
        assert_ne!(out1, out2);
        let u_fb = format_uuid_v4(out1);
        assert_eq!(u_fb.as_bytes()[14], b'4');
    }

    #[test]
    fn save_load_roundtrip_full_metadata_and_integer_job_id() {
        let dir = temp_dir("roundtrip");
        let mut job = Job::new(42, "office-laser", "alice");
        job.state = JobState::PendingHeld;
        job.priority = 75;
        job.copies = 3;
        job.title = "Quarterly Report".into();
        job.format = "application/pdf".into();
        job.reasons = vec!["job-hold-until-specified".into(), "job-incoming".into()];
        job.hold_until = Some("indefinite".into());
        job.processing_at = Some(1_700_000_100);
        job.completed_at = Some(1_700_000_200);
        job.options
            .insert("sides".into(), "two-sided-long-edge".into());
        job.options
            .insert("media".into(), "na_letter_8.5x11in".into());
        job.options.insert("k=with\\eq".into(), "val=1".into());
        job.files.push(JobFile {
            num: 1,
            filetype: "application/pdf".into(),
            size: 123_456_789_012,
            name: "report.pdf".into(),
            format: "application/pdf".into(),
        });
        job.files.push(JobFile {
            num: 2,
            filetype: "text/plain".into(),
            size: 512,
            name: "cover sheet.txt".into(),
            format: "application/octet-stream".into(),
        });

        job.save(&dir).unwrap();

        // Verify control file mode is 0600 and job-id is encoded as tags::INTEGER.
        let cpath = Job::control_path(&dir, 42);
        #[cfg(unix)]
        {
            let mode = fs::metadata(&cpath).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let raw = fs::read(&cpath).unwrap();
        let (msg, _) = ipp_codec::decode(&raw).unwrap();
        let job_id_attr = msg
            .groups
            .iter()
            .flat_map(|g| &g.attributes)
            .find(|a| a.name == "job-id")
            .unwrap();
        assert_eq!(job_id_attr.tag, tags::INTEGER);
        assert_eq!(job_id_attr.values, vec![Value::Integer(42)]);

        // Reload and verify every field survived verbatim.
        let loaded = Job::load(&cpath).unwrap();
        assert_eq!(loaded.id, 42);
        assert_eq!(loaded.state, JobState::PendingHeld);
        assert_eq!(loaded.priority, 75);
        assert_eq!(loaded.copies, 3);
        assert_eq!(loaded.username, "alice");
        assert_eq!(loaded.dest, "office-laser");
        assert_eq!(loaded.title, "Quarterly Report");
        assert_eq!(loaded.format, "application/pdf");
        assert_eq!(loaded.job_uuid, job.job_uuid);
        assert!(loaded.job_uuid.starts_with("urn:uuid:"));
        assert_eq!(loaded.hold_until.as_deref(), Some("indefinite"));
        assert_eq!(loaded.reasons, job.reasons);
        assert_eq!(loaded.processing_at, Some(1_700_000_100));
        assert_eq!(loaded.completed_at, Some(1_700_000_200));
        assert_eq!(loaded.options, job.options);
        assert_eq!(loaded.files, job.files);

        // Save again after clearing optional fields — stale attributes must be removed.
        let mut cleared = loaded;
        cleared.reasons.clear();
        cleared.hold_until = None;
        cleared.processing_at = None;
        cleared.completed_at = None;
        cleared.options.clear();
        cleared.files.clear();
        cleared.save(&dir).unwrap();

        let reloaded = Job::load(&cpath).unwrap();
        assert_eq!(reloaded.reasons, Vec::<String>::new());
        assert_eq!(reloaded.hold_until, None);
        assert_eq!(reloaded.processing_at, None);
        assert_eq!(reloaded.completed_at, None);
        assert!(reloaded.options.is_empty());
        assert_eq!(reloaded.files, Vec::<JobFile>::new());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_legacy_control_file_with_enum_job_id_and_missing_file_metadata() {
        let dir = temp_dir("legacy");
        let data_path = Job::write_data_file(&dir, 7, 1, b"hello spool").unwrap();
        #[cfg(unix)]
        {
            let mode = fs::metadata(&data_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let mut msg = IppMessage::new(ipp_codec::ops::op::PRINT_JOB);
        let g = msg.group_mut(tags::JOB);
        g.attributes
            .push(Attribute::new("job-id", tags::ENUM, vec![Value::Enum(7)]));
        g.attributes.push(Attribute::new(
            "job-state",
            tags::ENUM,
            vec![Value::Enum(JobState::Pending as i32)],
        ));
        g.attributes.push(Attribute::new(
            "job-printer-uri",
            tags::URI,
            vec![Value::Uri(Text::from("ipp://localhost/printers/lp0"))],
        ));
        g.attributes.push(Attribute::new(
            "job-document-files",
            tags::MIMETYPE,
            vec![Value::MimeMediaType(Text::from("text/plain"))],
        ));
        let bytes = ipp_codec::encode(&msg).unwrap();
        let cpath = Job::control_path(&dir, 7);
        fs::write(&cpath, bytes).unwrap();

        let loaded = Job::load(&cpath).unwrap();
        assert_eq!(loaded.id, 7);
        assert_eq!(loaded.dest, "lp0");
        assert_eq!(loaded.files.len(), 1);
        assert_eq!(loaded.files[0].num, 1);
        assert_eq!(loaded.files[0].filetype, "text/plain");
        assert_eq!(loaded.files[0].format, "text/plain");
        assert_eq!(loaded.files[0].size, 11); // stat'd from d00007-001!
        assert!(loaded.job_uuid.starts_with("urn:uuid:"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_all_supports_job_ids_above_99999() {
        let dir = temp_dir("high-ids");
        for id in [1, 99_999, 100_000, 1_234_567] {
            let job = Job::new(id, "p1", "bob");
            job.save(&dir).unwrap();
        }
        // Stray non-control files must be ignored.
        fs::write(dir.join("d00001-001"), b"payload").unwrap();
        fs::write(dir.join("c00001.tmp"), b"garbage").unwrap();
        fs::write(dir.join("cnotdigits"), b"garbage").unwrap();
        fs::write(dir.join("c0"), b"garbage").unwrap();

        let mut jobs = Jobs::load_all(&dir);
        assert_eq!(jobs.ids(), vec![1, 99_999, 100_000, 1_234_567]);
        assert_eq!(jobs.next_id(), 1_234_568);
        assert_eq!(jobs.alloc_id(), 1_234_568);
        assert_eq!(jobs.alloc_id(), 1_234_569);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn crash_recovery_transitions_processing_jobs_without_pid() {
        let dir = temp_dir("crash-recovery");
        let mut j1 = Job::new(1, "p1", "alice");
        j1.state = JobState::Processing;
        j1.processing_at = Some(1_700_000_000);
        j1.reasons = vec!["job-printing".into()];
        j1.save(&dir).unwrap();

        let mut j2 = Job::new(2, "p1", "bob");
        j2.state = JobState::Completed;
        j2.save(&dir).unwrap();

        // Default load_all uses CrashRecoveryPolicy::Requeue.
        let jobs = Jobs::load_all(&dir);
        let r1 = jobs.get(1).unwrap();
        assert_eq!(r1.state, JobState::Pending);
        assert_eq!(r1.processing_at, None);
        assert!(!r1.reasons.iter().any(|r| r == "job-printing"));
        assert!(r1.reasons.iter().any(|r| r == "job-restartable"));
        // Completed job untouched.
        assert_eq!(jobs.get(2).unwrap().state, JobState::Completed);

        // Also test CrashRecoveryPolicy::Abort.
        let mut j3 = Job::new(3, "p1", "carol");
        j3.state = JobState::Processing;
        j3.reasons = vec!["job-printing".into()];
        j3.save(&dir).unwrap();

        let jobs_abort = Jobs::load_all_with_policy(&dir, CrashRecoveryPolicy::Abort);
        let r3 = jobs_abort.get(3).unwrap();
        assert_eq!(r3.state, JobState::Aborted);
        assert!(r3.completed_at.is_some());
        assert!(r3.reasons.iter().any(|r| r == "aborted-by-system"));

        // Also test explicit recover_crashed on in-memory table (skips jobs with live PID).
        let mut table = Jobs::default();
        let mut live = Job::new(10, "p1", "u");
        live.state = JobState::Processing;
        live.backend_pid = Some(9999);
        let mut orphaned = Job::new(11, "p1", "u");
        orphaned.state = JobState::Processing;
        table.add(&dir, live).unwrap();
        table.add(&dir, orphaned).unwrap();
        let rec = table.recover_crashed(Some(&dir), CrashRecoveryPolicy::Requeue);
        assert_eq!(rec, vec![11]);
        assert_eq!(table.get(10).unwrap().state, JobState::Processing);
        assert_eq!(table.get(11).unwrap().state, JobState::Pending);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn jobs_table_crud_and_iterators() {
        let dir = temp_dir("crud");
        let mut jobs = Jobs::load_all(&dir.join("nonexistent"));
        assert_eq!(jobs.next_id(), 1);

        let id1 = jobs.alloc_id();
        let mut j1 = Job::new(id1, "p1", "alice");
        Job::write_data_file(&dir, id1, 1, b"doc1").unwrap();
        j1.files.push(JobFile {
            num: 1,
            filetype: "text/plain".into(),
            size: 4,
            name: "a.txt".into(),
            format: "text/plain".into(),
        });
        jobs.add(&dir, j1).unwrap();

        let id2 = jobs.alloc_id();
        let mut j2 = Job::new(id2, "p2", "bob");
        j2.state = JobState::Completed;
        jobs.add(&dir, j2).unwrap();

        assert_eq!(jobs.for_printer("p1").count(), 1);
        assert_eq!(jobs.active().count(), 1);
        for j in jobs.values_mut() {
            j.priority = 60;
        }
        assert_eq!(jobs.get_mut(id1).unwrap().priority, 60);
        jobs.save(&dir, id1).unwrap();
        jobs.save(&dir, 9999).unwrap(); // missing id is a no-op

        jobs.remove(&dir, id1).unwrap();
        assert!(jobs.get(id1).is_none());
        assert!(!Job::control_path(&dir, id1).exists());
        assert!(!Job::data_path(&dir, id1, 1).exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn job_cache_roundtrip_and_fallback() {
        let dir = temp_dir("cache");
        let cache_dir = temp_dir("cache-meta");
        let cache_path = cache_dir.join("job.cache");

        let mut jobs = Jobs::default();
        let mut j1 = Job::new(100_005, "p1", "alice\\bob");
        j1.title = "line1\nline2\ttab\rcr".into();
        j1.state = JobState::Processing;
        j1.processing_at = Some(1_700_000_050);
        j1.completed_at = Some(1_700_000_099);
        j1.hold_until = Some("night".into());
        j1.options.insert("copies".into(), "2".into());
        j1.files.push(JobFile {
            num: 1,
            filetype: "application/pdf".into(),
            size: 2048,
            name: "my\tfile.pdf".into(),
            format: "application/pdf".into(),
        });
        jobs.add(&dir, j1).unwrap();
        jobs.save_cache(&cache_path).unwrap();

        #[cfg(unix)]
        {
            let mode = fs::metadata(&cache_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        // Fast-boot via cache recovers Processing -> Pending and preserves all metadata.
        let loaded = Jobs::load_with_cache(&dir, &cache_path, CrashRecoveryPolicy::Requeue);
        assert_eq!(loaded.next_id(), 100_006);
        let lj = loaded.get(100_005).unwrap();
        assert_eq!(lj.state, JobState::Pending);
        assert_eq!(lj.username, "alice\\bob");
        assert_eq!(lj.title, "line1\nline2\ttab\rcr");
        assert_eq!(lj.hold_until.as_deref(), Some("night"));
        assert_eq!(lj.options.get("copies").map(String::as_str), Some("2"));
        assert_eq!(lj.files.len(), 1);
        assert_eq!(lj.files[0].name, "my\tfile.pdf");
        assert_eq!(lj.files[0].size, 2048);

        // Corrupt cache falls back cleanly to scanning c* files.
        fs::write(&cache_path, b"not valid cache\n").unwrap();
        let fallback = Jobs::load_with_cache(&dir, &cache_path, CrashRecoveryPolicy::Requeue);
        assert!(fallback.get(100_005).is_some());

        // Missing cache also falls back cleanly.
        let _ = fs::remove_file(&cache_path);
        let fallback2 = Jobs::load_with_cache(&dir, &cache_path, CrashRecoveryPolicy::Requeue);
        assert!(fallback2.get(100_005).is_some());

        // Exercise invalid cache parse branches.
        for bad in [
            "NextJobId 0\n",
            "NextJobId nope\n",
            "<Job 1>\n<Job 2>\n</Job>\n",
            "<Job 1\n</Job>\n",
            "<Job abc>\n</Job>\n",
            "</Job>\n",
            "StrayDirective foo\n",
            "<Job 1>\n",
            "# empty\n",
            "<Job 1>\nState 99\n</Job>\n",
            "<Job 1>\nState bad\n</Job>\n",
            "<Job 1>\nPriority bad\n</Job>\n",
            "<Job 1>\nCopies bad\n</Job>\n",
            "<Job 1>\nCreated bad\n</Job>\n",
            "<Job 1>\nProcessing bad\n</Job>\n",
            "<Job 1>\nCompleted bad\n</Job>\n",
            "<Job 1>\nFile 1\t2\n</Job>\n",
            "<Job 1>\nFile bad\t2\ta\tb\tc\n</Job>\n",
            "<Job 1>\nFile 1\tbad\ta\tb\tc\n</Job>\n",
        ] {
            assert!(
                Jobs::decode_cache(
                    io::Cursor::new(bad.as_bytes()),
                    CrashRecoveryPolicy::Requeue
                )
                .is_err(),
                "expected error for cache input: {bad:?}"
            );
        }

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&cache_dir);
    }

    #[cfg(unix)]
    #[test]
    fn nofollow_rejects_symlinks_on_load() {
        use std::os::unix::fs::symlink;
        let dir = temp_dir("symlink");
        let real = dir.join("real");
        let job = Job::new(1, "p1", "u");
        job.save(&dir).unwrap();
        fs::rename(Job::control_path(&dir, 1), &real).unwrap();
        let link = Job::control_path(&dir, 1);
        symlink(&real, &link).unwrap();

        let err = Job::load(&link).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(40)); // ELOOP on Linux

        // Symlinked cache is also rejected and falls back.
        let cache_link = dir.join("cache_link");
        symlink(&real, &cache_link).unwrap();
        assert!(!cache_is_fresh(&dir, &cache_link));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decode_option_and_cache_escape_edge_cases() {
        assert_eq!(decode_option_pair("no_equals"), None);
        assert_eq!(decode_option_pair("trailing_slash\\"), None);
        assert_eq!(unesc_cache("abc\\"), "abc\\");
        assert_eq!(unesc_cache("a\\xb"), "axb");
        assert!(parse_control_filename("c").is_none());
        assert!(parse_control_filename("c0").is_none());
        assert!(parse_control_filename("d00001").is_none());
        assert_eq!(parse_control_filename("c00001"), Some(1));
        assert_eq!(parse_control_filename("c100000"), Some(100_000));
    }
}
