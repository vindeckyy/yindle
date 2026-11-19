//! Command-line argument parser for `cupsfilter`.
//!
//! Supports all standard CUPS `cupsfilter(8)` flags:
//! `-c <cupsd.conf>`, `-d <printer>`, `-D`, `-e`, `-i <mime/type>`,
//! `-j <job-id[,N]>`, `-m <mime/type>`, `-n <copies>`, `-o <name=value>`,
//! `-p <ppd>`, `-P <ppd>`, `-t <title>`, `-u`, `-U <user>`, `--list-filters`,
//! `-h`/`--help`, `-V`/`--version`, and optional input filename (or stdin).

use std::path::PathBuf;

/// Default destination MIME type when `-m` is omitted (`cupsfilter(8)`).
pub const DEFAULT_OUTPUT_MIME: &str = "application/pdf";

/// Parsed `cupsfilter` options.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct CliArgs {
    /// `-c <cupsd.conf>`
    pub cupsd_conf: Option<PathBuf>,
    /// `-d <printer>`
    pub printer: Option<String>,
    /// `-D` — delete input file after conversion.
    pub delete_input: bool,
    /// `-e` — use every filter from PPD.
    pub use_every_filter: bool,
    /// `-i <mime/type>` — explicit input MIME type.
    pub input_mime: Option<String>,
    /// `-j <job-id[,N]>` — `(job_id, doc_num)`.
    pub job: Option<(i32, u32)>,
    /// `-m <mime/type>` — destination MIME type (default `application/pdf`).
    pub output_mime: String,
    /// `-n <copies>` — number of copies (default `1`).
    pub copies: i32,
    /// `-o <name=value>` — repeatable job options.
    pub options: Vec<(String, String)>,
    /// `-p <ppd>` / `-P <ppd>` — PPD file path.
    pub ppd: Option<PathBuf>,
    /// `-t <title>` — job title.
    pub title: Option<String>,
    /// `-u` — remove PPD file after conversion.
    pub remove_ppd: bool,
    /// `-U <user>` — username.
    pub user: Option<String>,
    /// `--list-filters` — print filter chain and exit without running.
    pub list_filters: bool,
    /// Positional input filename (`None` or `Some("-")` reads stdin).
    pub input_file: Option<PathBuf>,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            cupsd_conf: None,
            printer: None,
            delete_input: false,
            use_every_filter: false,
            input_mime: None,
            job: None,
            output_mime: DEFAULT_OUTPUT_MIME.to_string(),
            copies: 1,
            options: Vec::new(),
            ppd: None,
            title: None,
            remove_ppd: false,
            user: None,
            list_filters: false,
            input_file: None,
        }
    }
}

/// Top-level parsed CLI action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliAction {
    /// Execute conversion (or `--list-filters`).
    Run(Box<CliArgs>),
    /// Print help text and exit 0.
    Help,
    /// Print version string and exit 0.
    Version,
}

/// Usage message for `cupsfilter`.
#[must_use]
pub const fn usage_text() -> &'static str {
    "Usage: cupsfilter [options] [filename]\n\
Options:\n\
  --list-filters          List filters that would be run without executing them\n\
  -c cupsd.conf           Use alternate cupsd.conf file\n\
  -d printer              Use the named printer/queue\n\
  -D                      Remove input file after conversion\n\
  -e                      Use every filter from the PPD file\n\
  -i mime/type            Set input MIME media type (skip auto-detection)\n\
  -j job-id[,N]           Filter document N (default 1) of spool job job-id\n\
  -m mime/type            Set output MIME media type (default application/pdf)\n\
  -n copies               Set number of copies (default 1)\n\
  -o name=value           Set job option (repeatable)\n\
  -p filename.ppd         Set PPD file\n\
  -P filename.ppd         Set PPD file (alias for -p)\n\
  -t title                Set job title\n\
  -u                      Remove PPD file after conversion\n\
  -U username             Set username\n\
  -h, --help              Show this help message\n\
  -V, --version           Show version information\n"
}

/// Parse `-j job-id[,N]` into `(job_id, doc_num)`.
pub fn parse_job_spec(raw: &str) -> Result<(i32, u32), String> {
    let (id_part, doc_part) = match raw.split_once(',') {
        Some((a, b)) => (a, Some(b)),
        None => (raw, None),
    };
    let job_id: i32 = id_part
        .parse()
        .map_err(|_| format!("invalid job id '{raw}'"))?;
    if job_id <= 0 {
        return Err(format!("job id must be positive: '{raw}'"));
    }
    let doc_num = match doc_part {
        Some(d) => {
            let n: u32 = d
                .parse()
                .map_err(|_| format!("invalid document number in '{raw}'"))?;
            if n == 0 {
                return Err(format!("document number must be >= 1 in '{raw}'"));
            }
            n
        }
        None => 1,
    };
    Ok((job_id, doc_num))
}

/// Validate a `super/type` MIME type token.
pub fn validate_mime_type(raw: &str) -> Result<String, String> {
    let Some((main, sub)) = raw.split_once('/') else {
        return Err(format!("invalid MIME type '{raw}' (expected type/subtype)"));
    };
    if main.is_empty()
        || sub.is_empty()
        || sub.contains('/')
        || raw
            .bytes()
            .any(|b| b <= 0x20 || b == 0x7f || b == b'\\' || b == b'"')
    {
        return Err(format!("invalid MIME type '{raw}'"));
    }
    Ok(raw.to_ascii_lowercase())
}

/// Validate a printer queue name passed to `-d`.
pub fn validate_printer_name(name: &str) -> Result<String, String> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return Err(format!("invalid printer name '{name}'"));
    }
    Ok(name.to_string())
}

/// Parse one `-o name=value` (or bare boolean `-o landscape`) option.
pub fn parse_option_pair(raw: &str) -> Result<(String, String), String> {
    let (k, v) = match raw.split_once('=') {
        Some((a, b)) => (a.trim(), b.trim()),
        None => (raw.trim(), "true"),
    };
    if k.is_empty() || k.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!("invalid option '{raw}'"));
    }
    Ok((k.to_string(), v.to_string()))
}

/// Parse full `cupsfilter` CLI arguments (`argv[0]` is the program name).
#[allow(clippy::too_many_lines)]
pub fn parse_cli(argv: &[String]) -> Result<CliAction, String> {
    let mut out = CliArgs::default();
    let mut idx = 1usize;
    let mut positional_only = false;

    while idx < argv.len() {
        let arg = &argv[idx];
        if !positional_only && arg == "--" {
            positional_only = true;
            idx += 1;
            continue;
        }
        if !positional_only && arg.starts_with("--") {
            match arg.as_str() {
                "--list-filters" => out.list_filters = true,
                "--help" => return Ok(CliAction::Help),
                "--version" => return Ok(CliAction::Version),
                _ => return Err(format!("unknown option '{arg}'")),
            }
            idx += 1;
            continue;
        }
        if !positional_only && arg.starts_with('-') && arg.len() > 1 {
            let mut chars = arg[1..].chars();
            while let Some(flag) = chars.next() {
                let rest: &str = chars.as_str();
                match flag {
                    'h' => return Ok(CliAction::Help),
                    'V' => return Ok(CliAction::Version),
                    'D' => out.delete_input = true,
                    'e' => out.use_every_filter = true,
                    'u' => out.remove_ppd = true,
                    'c' | 'd' | 'i' | 'j' | 'm' | 'n' | 'o' | 'p' | 'P' | 't' | 'U' => {
                        let val = if rest.is_empty() {
                            idx += 1;
                            argv.get(idx)
                                .ok_or_else(|| format!("option '-{flag}' requires an argument"))?
                                .as_str()
                        } else {
                            rest
                        };
                        apply_value_flag(&mut out, flag, val)?;
                        break;
                    }
                    _ => return Err(format!("unknown option '-{flag}'")),
                }
            }
            idx += 1;
            continue;
        }

        if out.input_file.is_some() {
            return Err(format!("unexpected extra argument '{arg}'"));
        }
        if arg != "-" {
            out.input_file = Some(PathBuf::from(arg));
        }
        idx += 1;
    }

    Ok(CliAction::Run(Box::new(out)))
}

fn apply_value_flag(out: &mut CliArgs, flag: char, val: &str) -> Result<(), String> {
    match flag {
        'c' => {
            if val.is_empty() {
                return Err("option '-c' requires a non-empty path".into());
            }
            out.cupsd_conf = Some(PathBuf::from(val));
        }
        'd' => out.printer = Some(validate_printer_name(val)?),
        'i' => out.input_mime = Some(validate_mime_type(val)?),
        'j' => out.job = Some(parse_job_spec(val)?),
        'm' => out.output_mime = validate_mime_type(val)?,
        'n' => {
            let n: i32 = val
                .parse()
                .map_err(|_| format!("invalid copy count '{val}'"))?;
            if n <= 0 {
                return Err(format!("copy count must be positive: '{val}'"));
            }
            out.copies = n;
        }
        'o' => out.options.push(parse_option_pair(val)?),
        'p' | 'P' => {
            if val.is_empty() {
                return Err(format!("option '-{flag}' requires a non-empty PPD path"));
            }
            out.ppd = Some(PathBuf::from(val));
        }
        't' => out.title = Some(val.to_string()),
        'U' => {
            if val.is_empty() {
                return Err("option '-U' requires a non-empty username".into());
            }
            out.user = Some(val.to_string());
        }
        _ => return Err(format!("unknown option '-{flag}'")),
    }
    Ok(())
}
