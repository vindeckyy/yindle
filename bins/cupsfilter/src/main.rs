//! `cupsfilter` — Presswork CUPS-compatible filter pipeline CLI (`cupsfilter(8)`).
//!
//! Resolves MIME types via `mime-db::MimeDb::load_standard`, loads CUPS
//! configuration via `cups-config`, optionally incorporates PPD `*cupsFilter` /
//! `*cupsFilter2` rules, and executes the computed filter chain via `pipeline`,
//! streaming the converted output to stdout.

mod cli;

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use cli::{parse_cli, usage_text, CliAction, CliArgs};
use cups_config::{Config, CupsFilesConfig, CupsdConfig, Paths};
use mime_db::{Conv, MimeDb};
use pipeline::{
    format_job_options, parse_ppd_filters, JobSpec, LogSeverity, SpawnOptions, StatusEvent,
    StatusMessage,
};

static STDIN_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Maximum bytes peeked from input for MIME magic detection (`mimeFileType`).
const MIME_SNIFF_BYTES: usize = 4096;

/// Maximum bytes read from a PPD file (2 MiB safety bound).
const MAX_PPD_BYTES: u64 = 2 * 1024 * 1024;

/// Maximum bytes spooled from stdin when reading a stream (256 MiB safety bound).
const MAX_STDIN_BYTES: u64 = 256 * 1024 * 1024;

/// Effective directory paths resolved from config + environment overrides.
#[derive(Debug, Clone)]
struct RuntimeDirs {
    server_root: PathBuf,
    server_bin: PathBuf,
    data_dir: PathBuf,
    request_root: PathBuf,
    temp_dir: PathBuf,
}

/// RAII cleanup guard for temporary spooled stdin files.
struct TempFileGuard(Option<PathBuf>);

impl TempFileGuard {
    fn path(&self) -> Option<&Path> {
        self.0.as_deref()
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Load effective `cups-config` settings from `-c <cupsd.conf>` (plus sibling
/// `cups-files.conf`) or defaults, applying `CUPS_*` environment overrides.
fn load_effective_config<S: std::hash::BuildHasher>(
    cupsd_conf: Option<&Path>,
    env: &HashMap<String, String, S>,
) -> io::Result<(Config, RuntimeDirs)> {
    let mut cfg = Config {
        cupsd: CupsdConfig::defaults(),
        files: CupsFilesConfig::defaults(),
    };

    let mut server_root = env
        .get("CUPS_SERVERROOT")
        .filter(|s| !s.is_empty())
        .map_or_else(|| PathBuf::from("/etc/cups"), PathBuf::from);

    if let Some(conf_path) = cupsd_conf {
        let f = File::open(conf_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("unable to open config '{}': {e}", conf_path.display()),
            )
        })?;
        let parent = conf_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        server_root = parent.to_path_buf();

        let sibling_files = parent.join("cups-files.conf");
        if sibling_files.is_file() {
            let ff = File::open(&sibling_files)?;
            let (files_cfg, _fatal, _diags) = cups_config::parse_cups_files_conf(
                BufReader::new(ff),
                &sibling_files.to_string_lossy(),
                &server_root.to_string_lossy(),
            );
            cfg.files = files_cfg;
        }

        let (cupsd_cfg, diags) =
            cups_config::parse_cupsd_conf(BufReader::new(f), &conf_path.to_string_lossy());
        if diags.has_errors() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("syntax errors in '{}'", conf_path.display()),
            ));
        }
        cfg.cupsd = cupsd_cfg;
    } else {
        let paths = Paths::resolve(Some(&server_root));
        if paths.cupsd_conf.is_file() || paths.cups_files_conf.is_file() {
            let outcome = cups_config::load(&paths);
            cfg = outcome.config;
        }
    }

    if let Some(sr) = cfg.files.server_root.as_deref().filter(|s| !s.is_empty()) {
        if cupsd_conf.is_none() && !env.contains_key("CUPS_SERVERROOT") {
            server_root = PathBuf::from(sr);
        }
    }

    let data_dir = env
        .get("CUPS_DATADIR")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| cfg.files.data_dir.as_deref().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/usr/share/cups"));

    let server_bin = env
        .get("CUPS_SERVERBIN")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| cfg.files.server_bin.as_deref().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/usr/lib/cups"));

    let request_root = env
        .get("CUPS_REQUESTROOT")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| cfg.files.request_root.as_deref().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/var/spool/cups"));

    let temp_dir = env
        .get("TMPDIR")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| cfg.files.temp_dir.as_deref().map(PathBuf::from))
        .unwrap_or_else(std::env::temp_dir);

    Ok((
        cfg,
        RuntimeDirs {
            server_root,
            server_bin,
            data_dir,
            request_root,
            temp_dir,
        },
    ))
}

/// Stream stdin directly into an exclusive `0600` temporary file under `temp_dir`
/// in fixed 16 KiB chunks (zero unbounded RAM buffering, overflow-safe size cap).
fn spool_stdin_to_temp_with_limit<R: Read>(
    stdin: &mut R,
    temp_dir: &Path,
    max_bytes: u64,
) -> io::Result<TempFileGuard> {
    std::fs::create_dir_all(temp_dir)?;
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());

    let (mut file, guard) = create_exclusive_temp_file(temp_dir, pid, nanos)?;

    let mut buf = [0u8; 16 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = stdin.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk_len = n as u64;
        if chunk_len > max_bytes.saturating_sub(total) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stdin input exceeds maximum allowed size",
            ));
        }
        file.write_all(&buf[..n])?;
        total += chunk_len;
    }
    file.flush()?;
    Ok(guard)
}

fn create_exclusive_temp_file(
    temp_dir: &Path,
    pid: u32,
    nanos: u32,
) -> io::Result<(File, TempFileGuard)> {
    for _ in 0..32 {
        let seq = STDIN_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_path = temp_dir.join(format!(".cupsfilter-stdin-{pid}-{nanos}-{seq}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
        {
            Ok(f) => {
                // Guard immediately so partial files are always removed on error.
                let guard = TempFileGuard(Some(tmp_path));
                let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
                return Ok((f, guard));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to create unique stdin spool file",
    ))
}

fn spool_stdin_to_temp<R: Read>(stdin: &mut R, temp_dir: &Path) -> io::Result<TempFileGuard> {
    spool_stdin_to_temp_with_limit(stdin, temp_dir, MAX_STDIN_BYTES)
}

/// Detect input MIME type from explicit `-i` override or `mime-db` magic/name rules.
fn detect_input_mime(db: &MimeDb, input_path: &Path, explicit: Option<&str>) -> io::Result<String> {
    if let Some(m) = explicit {
        return Ok(m.to_string());
    }
    let mut file = File::open(input_path)?;
    let mut head = vec![0u8; MIME_SNIFF_BYTES];
    let n = file.read(&mut head)?;
    head.truncate(n);

    let name = input_path
        .file_name()
        .map_or("", |s| s.to_str().unwrap_or(""));
    Ok(db.detect(name, &head).map_or_else(
        || "application/octet-stream".to_string(),
        mime_db::Type::name,
    ))
}

/// Resolve the minimum-cost filter chain from `src_mime` to `dst_mime`,
/// optionally applying PPD `*cupsFilter`/`*cupsFilter2` rules.
///
/// Returns `(chain, effective_dst_mime)`.
fn resolve_filter_chain(
    db: &MimeDb,
    src_mime: &str,
    dst_mime: &str,
    ppd_text: Option<&str>,
    use_every_ppd_filter: bool,
) -> io::Result<(Vec<Conv>, String)> {
    let target_printer_ppd = use_every_ppd_filter || dst_mime.starts_with("printer/");

    if target_printer_ppd {
        if let Some(ppd) = ppd_text {
            let ppd_filters = parse_ppd_filters(ppd);
            if !ppd_filters.is_empty() {
                let mut best: Option<(u32, Vec<Conv>, String)> = None;
                for pf in ppd_filters {
                    let Some(prefix) = db.filter_chain(src_mime, &pf.src, 0) else {
                        continue;
                    };
                    let prefix_cost: u32 = prefix.iter().map(|c| c.cost).sum();
                    let total_cost = prefix_cost.saturating_add(pf.cost);
                    let mut chain: Vec<Conv> = prefix.into_iter().cloned().collect();
                    if pf.program != "-" {
                        chain.push(Conv {
                            src: pf.src.clone(),
                            dst: pf.dst.clone(),
                            cost: pf.cost,
                            program: pf.program.clone(),
                        });
                    }
                    let replace = best
                        .as_ref()
                        .is_none_or(|(best_cost, _, _)| total_cost < *best_cost);
                    if replace {
                        best = Some((total_cost, chain, pf.dst));
                    }
                }
                if let Some((_, chain, final_dst)) = best {
                    return Ok((chain, final_dst));
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unable to convert {src_mime} using PPD filters"),
                ));
            }
        }
    }

    // Standard MIME conversion (including any PPD-declared intermediate rules).
    if let Some(ppd) = ppd_text {
        let ppd_filters = parse_ppd_filters(ppd);
        if !ppd_filters.is_empty() {
            let mut augmented = MimeDb::default();
            augmented.convs.clone_from(&db.convs);
            for pf in ppd_filters {
                augmented.convs.push(Conv {
                    src: pf.src,
                    dst: pf.dst,
                    cost: pf.cost,
                    program: pf.program,
                });
            }
            if let Some(chain) = augmented.filter_chain(src_mime, dst_mime, 0) {
                return Ok((chain.into_iter().cloned().collect(), dst_mime.to_string()));
            }
        }
    }

    let chain = db.filter_chain(src_mime, dst_mime, 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("no filter chain from {src_mime} to {dst_mime}"),
        )
    })?;
    Ok((chain.into_iter().cloned().collect(), dst_mime.to_string()))
}

/// Resolve the PPD file path from explicit `-p`/`-P` or `{ServerRoot}/ppd/{printer}.ppd`.
fn resolve_ppd_path(args: &CliArgs, server_root: &Path) -> Option<PathBuf> {
    if let Some(ref explicit) = args.ppd {
        return Some(explicit.clone());
    }
    if let Some(ref printer) = args.printer {
        let candidate = server_root.join("ppd").join(format!("{printer}.ppd"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn read_ppd_text(path: &Path) -> io::Result<String> {
    let f = sys::open_readonly_nofollow(path)?;
    let mut text = String::new();
    f.take(MAX_PPD_BYTES).read_to_string(&mut text)?;
    Ok(text)
}

fn format_status_message(msg: &StatusMessage) -> String {
    match &msg.event {
        StatusEvent::Log { severity, message } => {
            let level = match severity {
                LogSeverity::Emerg => "EMERG",
                LogSeverity::Alert => "ALERT",
                LogSeverity::Crit => "CRIT",
                LogSeverity::Error => "ERROR",
                LogSeverity::Warning => "WARNING",
                LogSeverity::Notice => "NOTICE",
                LogSeverity::Info => "INFO",
                LogSeverity::Debug => "DEBUG",
                LogSeverity::Debug2 => "DEBUG2",
            };
            format!("{level}: [{}] {message}", msg.stage)
        }
        StatusEvent::State(_)
        | StatusEvent::Page(_)
        | StatusEvent::Attr(_)
        | StatusEvent::Ppd(_) => {
            format!("INFO: [{}] {}", msg.stage, msg.raw)
        }
    }
}

/// Resolve input file path (explicit file, `-j` spool file, or spooled stdin).
fn resolve_input_file<R: Read>(
    args: &CliArgs,
    dirs: &RuntimeDirs,
    stdin: &mut R,
) -> io::Result<(PathBuf, Option<TempFileGuard>, bool)> {
    if let Some(ref path) = args.input_file {
        return Ok((path.clone(), None, true));
    }
    if let Some((job_id, doc_num)) = args.job {
        let spool = dirs.request_root.join(format!("d{job_id:05}-{doc_num:03}"));
        return Ok((spool, None, false));
    }
    let guard = spool_stdin_to_temp(stdin, &dirs.temp_dir)?;
    let path = guard
        .path()
        .ok_or_else(|| io::Error::other("spooled stdin temp path missing"))?
        .to_path_buf();
    Ok((path, Some(guard), false))
}

/// Main testable implementation of `cupsfilter`.
#[allow(clippy::too_many_lines)]
fn run_cupsfilter<R: Read, W: Write, E: Write, S: std::hash::BuildHasher>(
    argv: &[String],
    env: &HashMap<String, String, S>,
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let cli = match parse_cli(argv) {
        Ok(CliAction::Help) => {
            let _ = write!(stdout, "{}", usage_text());
            return 0;
        }
        Ok(CliAction::Version) => {
            let _ = writeln!(
                stdout,
                "cupsfilter (Presswork {})",
                env!("CARGO_PKG_VERSION")
            );
            return 0;
        }
        Ok(CliAction::Run(a)) => *a,
        Err(msg) => {
            let _ = writeln!(stderr, "cupsfilter: {msg}");
            let _ = write!(stderr, "{}", usage_text());
            return 1;
        }
    };

    let (cfg, dirs) = match load_effective_config(cli.cupsd_conf.as_deref(), env) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "cupsfilter: {e}");
            return 1;
        }
    };

    let db = match MimeDb::load_standard(&dirs.data_dir, &dirs.server_root) {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(stderr, "cupsfilter: unable to load MIME database: {e}");
            return 1;
        }
    };

    let ppd_path = resolve_ppd_path(&cli, &dirs.server_root);
    let ppd_text = match ppd_path.as_deref() {
        Some(p) => match read_ppd_text(p) {
            Ok(t) => Some(t),
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "cupsfilter: unable to read PPD '{}': {e}",
                    p.display()
                );
                return 1;
            }
        },
        None => None,
    };

    // Fast path for `--list-filters` when `-i` is explicit and no file/job was passed:
    // avoid blocking on stdin just to compute and display the filter chain.
    if cli.list_filters && cli.input_file.is_none() && cli.job.is_none() && cli.input_mime.is_some()
    {
        let src_mime = cli
            .input_mime
            .as_deref()
            .unwrap_or("application/octet-stream");
        return match resolve_filter_chain(
            &db,
            src_mime,
            &cli.output_mime,
            ppd_text.as_deref(),
            cli.use_every_filter,
        ) {
            Ok((chain, _)) => {
                for conv in &chain {
                    if conv.program != "-" {
                        let _ = writeln!(stdout, "{}", conv.program);
                    }
                }
                0
            }
            Err(e) => {
                let _ = writeln!(stderr, "cupsfilter: {e}");
                1
            }
        };
    }

    let (input_path, _stdin_guard, is_explicit_file) = match resolve_input_file(&cli, &dirs, stdin)
    {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "cupsfilter: unable to prepare input: {e}");
            return 1;
        }
    };

    let src_mime = match detect_input_mime(&db, &input_path, cli.input_mime.as_deref()) {
        Ok(m) => m,
        Err(e) => {
            let _ = writeln!(
                stderr,
                "cupsfilter: unable to determine MIME type for '{}': {e}",
                input_path.display()
            );
            return 1;
        }
    };

    let (chain, final_dst) = match resolve_filter_chain(
        &db,
        &src_mime,
        &cli.output_mime,
        ppd_text.as_deref(),
        cli.use_every_filter,
    ) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "cupsfilter: {e}");
            return 1;
        }
    };

    let exit_code = if cli.list_filters {
        for conv in &chain {
            if conv.program != "-" {
                let _ = writeln!(stdout, "{}", conv.program);
            }
        }
        0
    } else if chain.iter().all(|c| c.program == "-") {
        // Direct passthrough: stream input file straight to stdout.
        match File::open(&input_path).and_then(|mut f| io::copy(&mut f, stdout)) {
            Ok(_) => 0,
            Err(e) => {
                let _ = writeln!(stderr, "cupsfilter: passthrough failed: {e}");
                1
            }
        }
    } else {
        execute_filter_chain(
            &cli,
            &cfg,
            &dirs,
            &input_path,
            &src_mime,
            &final_dst,
            ppd_path.as_deref(),
            &chain,
            env,
            stdout,
            stderr,
        )
    };

    // Post-conversion cleanup flags (`-D`, `-u`): NEVER delete files during
    // read-only `--list-filters` dry-run mode!
    if !cli.list_filters {
        if cli.delete_input && is_explicit_file {
            let _ = std::fs::remove_file(&input_path);
        }
        if cli.remove_ppd {
            if let Some(ref p) = cli.ppd {
                let _ = std::fs::remove_file(p);
            }
        }
    }

    exit_code
}

#[allow(clippy::too_many_arguments)]
fn execute_filter_chain<W: Write, E: Write, S: std::hash::BuildHasher>(
    args: &CliArgs,
    cfg: &Config,
    dirs: &RuntimeDirs,
    input_path: &Path,
    src_mime: &str,
    final_dst: &str,
    ppd_path: Option<&Path>,
    chain: &[Conv],
    env: &HashMap<String, String, S>,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let printer = args
        .printer
        .clone()
        .unwrap_or_else(|| "cupsfilter".to_string());
    let job_id = args.job.map_or(0, |(id, _)| id);
    let username = args
        .user
        .clone()
        .or_else(|| env.get("USER").cloned())
        .unwrap_or_else(|| "anonymous".to_string());
    let title = args.title.clone().unwrap_or_else(|| {
        input_path.file_name().map_or_else(
            || "Untitled".to_string(),
            |n| n.to_string_lossy().into_owned(),
        )
    });

    let spec = JobSpec {
        printer,
        job_id,
        username,
        title,
        copies: args.copies,
        options: format_job_options(&args.options),
        data_file: input_path.to_path_buf(),
        src_type: src_mime.to_string(),
        dst_type: final_dst.to_string(),
        device_uri: "file:///dev/null".to_string(),
        filter_dir: dirs.server_bin.join("filter"),
        backend_dir: dirs.server_bin.join("backend"),
        backend: "file".to_string(),
        env: HashMap::new(),
    };

    let mut opts = SpawnOptions::from_cups_config(cfg);
    let exec_candidate = dirs.server_bin.join("daemon").join("cups-exec");
    opts.sandbox.cups_exec_path = exec_candidate.is_file().then_some(exec_candidate);
    let (eff_user, _) = pipeline::current_euid_egid();
    if eff_user != 0 {
        opts.sandbox.uid = None;
        opts.sandbox.gid = None;
        opts.sandbox.username = None;
    }
    opts.ppd = ppd_path.map(Path::to_path_buf);
    opts.server_root = Some(dirs.server_root.clone());
    opts.server_bin = Some(dirs.server_bin.clone());
    opts.data_dir = Some(dirs.data_dir.clone());
    opts.request_root = Some(dirs.request_root.clone());
    opts.temp_dir = Some(dirs.temp_dir.clone());
    opts.document_number = args.job.map(|(_, n)| n);

    let mut run = match spec.spawn_filters_only(chain, &opts, Stdio::piped()) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stderr, "cupsfilter: unable to run filters: {e}");
            return 1;
        }
    };

    let status_rx = run.take_status_receiver();
    let copy_res = if let Some(mut out_pipe) = run.stdout.take() {
        io::copy(&mut out_pipe, stdout).map(|_| ())
    } else {
        Ok(())
    };

    let exits = match run.wait_all() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "cupsfilter: error waiting for filters: {e}");
            return 1;
        }
    };

    if let Some(rx) = status_rx {
        while let Ok(msg) = rx.try_recv() {
            let _ = writeln!(stderr, "{}", format_status_message(&msg));
        }
    }

    if let Err(e) = copy_res {
        let _ = writeln!(stderr, "cupsfilter: output stream error: {e}");
        return 1;
    }

    if let Some(failed) = exits.iter().find(|ex| !ex.success()) {
        let _ = writeln!(
            stderr,
            "cupsfilter: filter {} (PID {}) exited with code {:?} / signal {:?}",
            failed.index, failed.pid, failed.code, failed.signal
        );
        return 1;
    }

    0
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let env: HashMap<String, String> = std::env::vars().collect();
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    ExitCode::from(run_cupsfilter(
        &argv,
        &env,
        &mut stdin,
        &mut stdout,
        &mut stderr,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cli::{parse_job_spec, parse_option_pair, validate_mime_type, validate_printer_name};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TestEnv {
        root: PathBuf,
        server_root: PathBuf,
        data_dir: PathBuf,
        server_bin: PathBuf,
        request_root: PathBuf,
        temp_dir: PathBuf,
    }

    impl TestEnv {
        fn new(tag: &str) -> Self {
            let id = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("pw-cfilter-{tag}-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            let server_root = root.join("etc");
            let data_dir = root.join("share");
            let server_bin = root.join("lib");
            let request_root = root.join("spool");
            let temp_dir = root.join("tmp");
            for d in [
                &server_root,
                &server_root.join("ppd"),
                &data_dir.join("mime"),
                &server_bin.join("filter"),
                &server_bin.join("backend"),
                &request_root,
                &temp_dir,
            ] {
                fs::create_dir_all(d).expect("mkdir");
            }

            fs::write(
                data_dir.join("mime").join("mime.types"),
                r#"
application/pdf         pdf string(0,%PDF)
text/plain              txt printable(0,1024)
image/pwg-raster        string(0,"RaS2")
application/octet-stream
"#,
            )
            .expect("write mime.types");

            fs::write(
                data_dir.join("mime").join("mime.convs"),
                r"
text/plain          application/pdf       30 texttopdf
application/pdf     image/pwg-raster      40 pdftoraster
application/octet-stream application/vnd.cups-raw 0 -
",
            )
            .expect("write mime.convs");

            Self {
                root,
                server_root,
                data_dir,
                server_bin,
                request_root,
                temp_dir,
            }
        }

        fn env_map(&self) -> HashMap<String, String> {
            HashMap::from([
                (
                    "CUPS_SERVERROOT".into(),
                    self.server_root.to_string_lossy().into_owned(),
                ),
                (
                    "CUPS_DATADIR".into(),
                    self.data_dir.to_string_lossy().into_owned(),
                ),
                (
                    "CUPS_SERVERBIN".into(),
                    self.server_bin.to_string_lossy().into_owned(),
                ),
                (
                    "CUPS_REQUESTROOT".into(),
                    self.request_root.to_string_lossy().into_owned(),
                ),
                (
                    "TMPDIR".into(),
                    self.temp_dir.to_string_lossy().into_owned(),
                ),
                ("USER".into(), "bob".into()),
            ])
        }

        fn write_filter(&self, name: &str, script: &str) -> PathBuf {
            let p = self.server_bin.join("filter").join(name);
            fs::write(&p, script).expect("write filter");
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).expect("chmod");
            p
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn argv(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn cli_parsing_all_flags_and_errors() {
        assert_eq!(parse_cli(&argv(&["cupsfilter", "-h"])), Ok(CliAction::Help));
        assert_eq!(
            parse_cli(&argv(&["cupsfilter", "--help"])),
            Ok(CliAction::Help)
        );
        assert_eq!(
            parse_cli(&argv(&["cupsfilter", "-V"])),
            Ok(CliAction::Version)
        );
        assert_eq!(
            parse_cli(&argv(&["cupsfilter", "--version"])),
            Ok(CliAction::Version)
        );

        let parsed = match parse_cli(&argv(&[
            "cupsfilter",
            "-c",
            "/etc/cups/cupsd.conf",
            "-d",
            "laser1",
            "-Deu",
            "-i",
            "text/plain",
            "-j",
            "42,3",
            "-mimage/pwg-raster",
            "-n2",
            "-o",
            "media=letter",
            "-o",
            "landscape",
            "-P",
            "/tmp/test.ppd",
            "-t",
            "My Doc",
            "-U",
            "alice",
            "--list-filters",
            "--",
            "input.txt",
        ]))
        .expect("parse full")
        {
            CliAction::Run(a) => *a,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(
            parsed.cupsd_conf.as_deref(),
            Some(Path::new("/etc/cups/cupsd.conf"))
        );
        assert_eq!(parsed.printer.as_deref(), Some("laser1"));
        assert!(parsed.delete_input);
        assert!(parsed.use_every_filter);
        assert!(parsed.remove_ppd);
        assert_eq!(parsed.input_mime.as_deref(), Some("text/plain"));
        assert_eq!(parsed.job, Some((42, 3)));
        assert_eq!(parsed.output_mime, "image/pwg-raster");
        assert_eq!(parsed.copies, 2);
        assert_eq!(
            parsed.options,
            vec![
                ("media".into(), "letter".into()),
                ("landscape".into(), "true".into())
            ]
        );
        assert_eq!(parsed.ppd.as_deref(), Some(Path::new("/tmp/test.ppd")));
        assert_eq!(parsed.title.as_deref(), Some("My Doc"));
        assert_eq!(parsed.user.as_deref(), Some("alice"));
        assert!(parsed.list_filters);
        assert_eq!(parsed.input_file.as_deref(), Some(Path::new("input.txt")));

        // `-p` and stdin `-`
        let parsed2 = match parse_cli(&argv(&["cupsfilter", "-p", "/a.ppd", "-"])).expect("ok") {
            CliAction::Run(a) => *a,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(parsed2.ppd.as_deref(), Some(Path::new("/a.ppd")));
        assert_eq!(parsed2.input_file, None);

        // Validation helpers & error cases
        assert_eq!(parse_job_spec("5"), Ok((5, 1)));
        assert!(parse_job_spec("0").is_err());
        assert!(parse_job_spec("abc").is_err());
        assert!(parse_job_spec("5,0").is_err());
        assert!(parse_job_spec("5,x").is_err());

        assert!(validate_mime_type("text/plain").is_ok());
        assert!(validate_mime_type("notslash").is_err());
        assert!(validate_mime_type("/sub").is_err());
        assert!(validate_mime_type("sup/").is_err());
        assert!(validate_mime_type("a/b/c").is_err());
        assert!(validate_mime_type("a/b c").is_err());

        assert!(validate_printer_name("ok_queue-1").is_ok());
        assert!(validate_printer_name("").is_err());
        assert!(validate_printer_name("../bad").is_err());
        assert!(validate_printer_name("a/b").is_err());

        assert!(parse_option_pair("=val").is_err());

        for bad in [
            vec!["cupsfilter", "--unknown"],
            vec!["cupsfilter", "-Z"],
            vec!["cupsfilter", "-m"],
            vec!["cupsfilter", "-m", "badmime"],
            vec!["cupsfilter", "-n", "0"],
            vec!["cupsfilter", "-n", "abc"],
            vec!["cupsfilter", "-c", ""],
            vec!["cupsfilter", "-p", ""],
            vec!["cupsfilter", "-U", ""],
            vec!["cupsfilter", "f1", "f2"],
        ] {
            assert!(parse_cli(&argv(&bad)).is_err(), "expected err for {bad:?}");
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn list_filters_passthrough_multistage_stdin_spool_ppd_and_cleanup() {
        let te = TestEnv::new("e2e");
        let env = te.env_map();

        te.write_filter(
            "texttopdf",
            r#"#!/bin/sh
set -eu
echo "INFO: texttopdf job=$1 user=$2 title=$3 copies=$4 opts=$5" >&2
printf '%%PDF-1.4\n%s\n' "$(cat "$6")"
"#,
        );
        te.write_filter(
            "pdftoraster",
            r#"#!/bin/sh
set -eu
if [ "$#" -ne 5 ]; then echo "ERROR: expected 5 args got $#" >&2; exit 9; fi
echo "PAGE: 1 1" >&2
printf 'RaS2:%s' "$(cat)"
"#,
        );
        te.write_filter(
            "rastertofoo",
            r#"#!/bin/sh
set -eu
echo "STATE: +cups-foo" >&2
printf 'FOO(%s)' "$(cat)"
"#,
        );

        let mut empty_in: &[u8] = b"";
        let mut out = Vec::new();
        let mut err = Vec::new();

        // 1. Help & version
        assert_eq!(
            run_cupsfilter(
                &argv(&["cupsfilter", "--help"]),
                &env,
                &mut empty_in,
                &mut out,
                &mut err
            ),
            0
        );
        assert!(String::from_utf8_lossy(&out).contains("Usage: cupsfilter"));
        out.clear();
        assert_eq!(
            run_cupsfilter(
                &argv(&["cupsfilter", "-V"]),
                &env,
                &mut empty_in,
                &mut out,
                &mut err
            ),
            0
        );
        assert!(String::from_utf8_lossy(&out).contains("Presswork"));

        // 2. `--list-filters` fast path with `-i` and no stdin
        out.clear();
        assert_eq!(
            run_cupsfilter(
                &argv(&[
                    "cupsfilter",
                    "--list-filters",
                    "-i",
                    "text/plain",
                    "-m",
                    "image/pwg-raster"
                ]),
                &env,
                &mut empty_in,
                &mut out,
                &mut err
            ),
            0
        );
        assert_eq!(String::from_utf8_lossy(&out), "texttopdf\npdftoraster\n");

        // 3. Multi-stage execution from explicit file with auto-MIME + `-D` deletion
        let input_txt = te.root.join("note.txt");
        fs::write(&input_txt, b"hello presswork").expect("write");
        out.clear();
        err.clear();
        assert_eq!(
            run_cupsfilter(
                &argv(&[
                    "cupsfilter",
                    "-D",
                    "-m",
                    "image/pwg-raster",
                    "-o",
                    "media=a4",
                    "-n",
                    "2",
                    "-t",
                    "TestTitle",
                    input_txt.to_str().expect("str"),
                ]),
                &env,
                &mut empty_in,
                &mut out,
                &mut err
            ),
            0,
            "stderr={}",
            String::from_utf8_lossy(&err)
        );
        assert_eq!(
            String::from_utf8_lossy(&out),
            "RaS2:%PDF-1.4\nhello presswork"
        );
        assert!(!input_txt.exists(), "-D should delete explicit input file");
        let err_str = String::from_utf8_lossy(&err);
        assert!(err_str.contains("texttopdf"));
        assert!(err_str.contains("PAGE: 1 1"));

        // 4. Stdin execution + PPD `-p` + `-e` + `-u` deletion
        let ppd_file = te.root.join("custom.ppd");
        fs::write(
            &ppd_file,
            "*PPD-Adobe: \"4.3\"\n*cupsFilter: \"image/pwg-raster 20 rastertofoo\"\n",
        )
        .expect("write ppd");
        let mut stdin_bytes: &[u8] = b"from stdin";
        out.clear();
        err.clear();
        assert_eq!(
            run_cupsfilter(
                &argv(&[
                    "cupsfilter",
                    "-e",
                    "-u",
                    "-p",
                    ppd_file.to_str().expect("str"),
                ]),
                &env,
                &mut stdin_bytes,
                &mut out,
                &mut err
            ),
            0,
            "stderr={}",
            String::from_utf8_lossy(&err)
        );
        assert_eq!(
            String::from_utf8_lossy(&out),
            "FOO(RaS2:%PDF-1.4\nfrom stdin)"
        );
        assert!(!ppd_file.exists(), "-u should delete PPD file");

        // 5. `-j 7,2` spool file resolution + direct passthrough (`application/pdf` -> `application/pdf`)
        let spool_doc = te.request_root.join("d00007-002");
        fs::write(&spool_doc, b"%PDF-1.4\nDIRECT\n").expect("write spool");
        out.clear();
        err.clear();
        assert_eq!(
            run_cupsfilter(
                &argv(&["cupsfilter", "-j", "7,2", "-m", "application/pdf"]),
                &env,
                &mut empty_in,
                &mut out,
                &mut err
            ),
            0
        );
        assert_eq!(out, b"%PDF-1.4\nDIRECT\n");

        // 6. `-d <printer>` auto-loads `{ServerRoot}/ppd/{printer}.ppd` + `-m printer/q1`
        let auto_ppd = te.server_root.join("ppd").join("q1.ppd");
        fs::write(
            &auto_ppd,
            "*cupsFilter2: \"application/pdf application/vnd.cups-raw 5 -\"\n",
        )
        .expect("write q1 ppd");
        out.clear();
        assert_eq!(
            run_cupsfilter(
                &argv(&[
                    "cupsfilter",
                    "--list-filters",
                    "-d",
                    "q1",
                    "-i",
                    "text/plain",
                    "-m",
                    "printer/q1"
                ]),
                &env,
                &mut empty_in,
                &mut out,
                &mut err
            ),
            0
        );
        assert_eq!(String::from_utf8_lossy(&out), "texttopdf\n");

        // 7. PPD intermediate filter with standard `-m` target
        let inter_ppd = te.root.join("inter.ppd");
        fs::write(
            &inter_ppd,
            "*cupsFilter2: \"image/pwg-raster application/x-custom 5 rastertofoo\"\n",
        )
        .expect("write inter ppd");
        out.clear();
        assert_eq!(
            run_cupsfilter(
                &argv(&[
                    "cupsfilter",
                    "--list-filters",
                    "-p",
                    inter_ppd.to_str().expect("str"),
                    "-i",
                    "application/pdf",
                    "-m",
                    "application/x-custom",
                ]),
                &env,
                &mut empty_in,
                &mut out,
                &mut err
            ),
            0
        );
        assert_eq!(String::from_utf8_lossy(&out), "pdftoraster\nrastertofoo\n");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn config_loading_error_paths_and_status_formatting() {
        let te = TestEnv::new("errs");
        let env = te.env_map();

        // `-c cupsd.conf` with sibling `cups-files.conf`
        let cupsd_conf = te.server_root.join("cupsd.conf");
        let files_conf = te.server_root.join("cups-files.conf");
        fs::write(&cupsd_conf, "LogLevel info\nFilterNice 5\n").expect("write cupsd.conf");
        fs::write(
            &files_conf,
            format!(
                "DataDir {}\nServerBin {}\nSandboxing relaxed\n",
                te.data_dir.display(),
                te.server_bin.display()
            ),
        )
        .expect("write cups-files.conf");

        let (cfg, dirs) = load_effective_config(Some(&cupsd_conf), &HashMap::new()).expect("load");
        assert_eq!(cfg.cupsd.filter_nice, 5);
        assert_eq!(dirs.data_dir, te.data_dir);

        // Default load path via CUPS_SERVERROOT when cupsd.conf exists
        let (cfg2, _) = load_effective_config(None, &env).expect("load default");
        assert_eq!(cfg2.cupsd.filter_nice, 5);

        // Syntax error in cupsd.conf fails cleanly
        let bad_conf = te.root.join("bad.conf");
        fs::write(&bad_conf, "<Limit\n").expect("write bad");
        assert!(load_effective_config(Some(&bad_conf), &env).is_err());
        assert!(load_effective_config(Some(&te.root.join("missing.conf")), &env).is_err());

        // Stdin spool size limit (cleans up partial temp file, handles u64::MAX without overflow)
        let spool_dir = te.temp_dir.join("stream-test");
        let mut big: &[u8] = b"0123456789abcdef";
        assert!(spool_stdin_to_temp_with_limit(&mut big, &spool_dir, 8).is_err());
        assert_eq!(fs::read_dir(&spool_dir).expect("readdir").count(), 0);
        let mut small: &[u8] = b"tiny";
        let ok_guard =
            spool_stdin_to_temp_with_limit(&mut small, &spool_dir, u64::MAX).expect("u64::MAX");
        let p = ok_guard.path().expect("path").to_path_buf();
        assert_eq!(fs::read(&p).expect("read"), b"tiny");
        assert_eq!(
            fs::metadata(&p).expect("meta").permissions().mode() & 0o777,
            0o600
        );
        drop(ok_guard);
        assert!(!p.exists());

        // Regression test: `--list-filters` with explicit filename (no `-i`) + `-D` + `-u`
        // MUST NOT delete the input file or PPD file!
        let keep_input = te.root.join("keep_me.txt");
        let keep_ppd = te.root.join("keep_me.ppd");
        fs::write(&keep_input, b"do not delete").expect("write keep_input");
        fs::write(&keep_ppd, "*cupsFilter: \"application/pdf 10 -\"\n").expect("write keep_ppd");
        let mut empty_in_keep: &[u8] = b"";
        let mut out_keep = Vec::new();
        let mut err_keep = Vec::new();
        assert_eq!(
            run_cupsfilter(
                &argv(&[
                    "cupsfilter",
                    "--list-filters",
                    "-D",
                    "-u",
                    "-p",
                    keep_ppd.to_str().expect("str"),
                    "-m",
                    "application/pdf",
                    keep_input.to_str().expect("str"),
                ]),
                &env,
                &mut empty_in_keep,
                &mut out_keep,
                &mut err_keep,
            ),
            0
        );
        assert_eq!(String::from_utf8_lossy(&out_keep), "texttopdf\n");
        assert!(
            keep_input.exists(),
            "--list-filters must NOT delete input (-D)"
        );
        assert!(keep_ppd.exists(), "--list-filters must NOT delete PPD (-u)");

        // Standalone cups-files.conf (without cupsd.conf) is also loaded.
        let standalone_root = te.root.join("standalone-etc");
        fs::create_dir_all(&standalone_root).expect("mkdir standalone");
        fs::write(
            standalone_root.join("cups-files.conf"),
            "Sandboxing relaxed\n",
        )
        .expect("write standalone files conf");
        let standalone_env = HashMap::from([(
            "CUPS_SERVERROOT".to_string(),
            standalone_root.to_string_lossy().into_owned(),
        )]);
        let (standalone_cfg, _) =
            load_effective_config(None, &standalone_env).expect("load standalone");
        assert_eq!(
            standalone_cfg.files.sandboxing,
            cups_config::Sandboxing::Relaxed
        );

        // Filter exiting non-zero -> exit 1
        te.write_filter("texttopdf", "#!/bin/sh\necho 'ERROR: boom' >&2\nexit 7\n");
        let mut stdin_txt: &[u8] = b"hello";
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            run_cupsfilter(
                &argv(&["cupsfilter", "-i", "text/plain", "-m", "application/pdf"]),
                &env,
                &mut stdin_txt,
                &mut out,
                &mut err
            ),
            1
        );
        assert!(String::from_utf8_lossy(&err).contains("exited with code Some(7)"));

        // CLI error, missing PPD, missing input file, unconvertible MIME, failing PPD chain
        let mut empty_in: &[u8] = b"";
        assert_eq!(
            run_cupsfilter(
                &argv(&["cupsfilter", "--bad"]),
                &env,
                &mut empty_in,
                &mut out,
                &mut err
            ),
            1
        );
        assert_eq!(
            run_cupsfilter(
                &argv(&["cupsfilter", "-c", "/nonexistent/cupsd.conf"]),
                &env,
                &mut empty_in,
                &mut out,
                &mut err
            ),
            1
        );
        assert_eq!(
            run_cupsfilter(
                &argv(&["cupsfilter", "-p", "/nonexistent/x.ppd"]),
                &env,
                &mut empty_in,
                &mut out,
                &mut err
            ),
            1
        );
        assert_eq!(
            run_cupsfilter(
                &argv(&["cupsfilter", "/nonexistent/input.txt"]),
                &env,
                &mut empty_in,
                &mut out,
                &mut err
            ),
            1
        );
        assert_eq!(
            run_cupsfilter(
                &argv(&[
                    "cupsfilter",
                    "--list-filters",
                    "-i",
                    "application/x-unknown",
                    "-m",
                    "image/pwg-raster"
                ]),
                &env,
                &mut empty_in,
                &mut out,
                &mut err
            ),
            1
        );

        let unreachable_ppd = te.root.join("unreach.ppd");
        fs::write(&unreachable_ppd, "*cupsFilter: \"image/x-never 10 f\"\n").expect("write");
        assert_eq!(
            run_cupsfilter(
                &argv(&[
                    "cupsfilter",
                    "-e",
                    "-p",
                    unreachable_ppd.to_str().expect("str"),
                    "-i",
                    "application/x-unknown"
                ]),
                &env,
                &mut empty_in,
                &mut out,
                &mut err
            ),
            1
        );

        // Status message formatting across all severities
        for sev in [
            LogSeverity::Emerg,
            LogSeverity::Alert,
            LogSeverity::Crit,
            LogSeverity::Error,
            LogSeverity::Warning,
            LogSeverity::Notice,
            LogSeverity::Info,
            LogSeverity::Debug,
            LogSeverity::Debug2,
        ] {
            let formatted = format_status_message(&StatusMessage {
                stage: "f0".into(),
                is_backend: false,
                event: StatusEvent::Log {
                    severity: sev,
                    message: "m".into(),
                },
                raw: "m".into(),
            });
            assert!(formatted.contains("[f0] m"));
        }
    }
}
