//! MIME type database for the filter pipeline — a port of CUPS `mime/*.c`.
//!
//! `mime.types` maps `super/type` names to file-recognition rules
//! (`mime_readfile.c`/`mime_type_t`); `mime.convs` maps source→destination
//! type pairs to a cost + filter program (`mime_filter_t`). `filter_chain`
//! resolves a minimum-cost path through the conversion graph, mirroring
//! `mimeFilter2` semantics (including `*/*` and `super/*` wildcards).

mod regex;

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

/// Maximum nesting depth for parenthesized and negated rule expressions.
const MAX_RULE_DEPTH: usize = 64;

/// Maximum logical line byte length (caps `\` continuation growth).
const MAX_LOGICAL_LINE: usize = 64 * 1024;

/// A single primitive test in a rule (`mime_type_check_t` analogue).
#[derive(Debug, Clone)]
pub enum Rule {
    /// `string(offset, "lit")` — bytes identical to literal.
    Str { offset: i64, lit: Vec<u8> },
    /// `istring(...)` — case-insensitive `string`.
    IStr { offset: i64, lit: Vec<u8> },
    /// `char(offset, v)` — single byte equal.
    Char { offset: i64, v: u8 },
    /// `short(offset, v)` — big-endian 16-bit equal.
    Short { offset: i64, v: u16 },
    /// `int(offset, v)` — big-endian 32-bit equal.
    Int { offset: i64, v: u32 },
    /// `ascii(off,len)` — bytes are CR/NL/TAB/BS or 32..=126.
    Ascii { offset: i64, len: usize },
    /// `printable(off,len)` — ascii plus 128..=254.
    Printable { offset: i64, len: usize },
    /// `contains(off,range,"lit")` — literal found within range.
    Contains {
        offset: i64,
        range: usize,
        lit: Vec<u8>,
    },
    /// `regex(off,"pat")` — ERE match over bytes starting at `off`.
    Regex { offset: i64, pat: String },
    /// `match("pat")` / bare `ext` — filename match (`*.ext`, glob, substring).
    Match { pat: String },
    /// `locale("s")` — match the system locale (checked once at eval).
    Locale { s: String },
    /// `priority(n)` — not a test; sets `Type::priority`.
    Priority { n: i32 },
    /// `( expr )` — sub-expression.
    Group { expr: Expr },
    /// `! rule` — logical negation.
    Not { rule: Box<Rule> },
}

/// How a rule joins the running (left-associative) result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Join {
    /// `,`/whitespace — `result || eval(rule)`.
    Or,
    /// `+` — `result && eval(rule)`.
    And,
}

/// A parenthesized sub-expression evaluated as one operand.
#[derive(Debug, Clone)]
pub struct Group(pub Vec<(Join, Rule)>);

/// A full recognition expression: operands + joiners, evaluated
/// left-to-right (`a b + c` = `(a || b) && c`, matching `mime_checkrules`).
pub type Expr = Vec<(Join, Rule)>;

/// One recognized MIME type (`mime_type_t`).
#[derive(Debug)]
pub struct Type {
    /// `super` component (e.g. `application`).
    pub sup: String,
    /// `type` component (e.g. `pdf`).
    pub typ: String,
    /// The parsed rule expression (appended on repeated defs).
    pub expr: Expr,
    /// `priority(n)` — higher wins ties (default 100).
    pub priority: i32,
}

impl Type {
    /// `application/pdf`-style display name.
    #[must_use]
    pub fn name(&self) -> String {
        format!("{}/{}", self.sup, self.typ)
    }
}

/// One `mime.convs` line (`mime_filter_t`).
#[derive(Debug, Clone)]
pub struct Conv {
    /// Source type (`super/type`, `super/*`, or `*/*`).
    pub src: String,
    /// Destination type.
    pub dst: String,
    /// Relative cost (lower preferred).
    pub cost: u32,
    /// Filter program (basename under `CUPS_SERVERBIN/filter`), or `-`.
    pub program: String,
}

/// The loaded database.
#[derive(Debug, Default)]
pub struct MimeDb {
    /// Types, sorted by (priority desc, name asc) at load.
    pub types: Vec<Type>,
    /// Conversion table.
    pub convs: Vec<Conv>,
}

impl MimeDb {
    /// Load all `*.types` + `*.convs` under `dir` (`mimeLoad`).
    ///
    /// Also checks `dir/mime` first when present so passing FHS `DataDir`
    /// (`/usr/share/cups`) automatically loads `/usr/share/cups/mime/*.{types,convs}`
    /// alongside any files directly in `dir`.
    pub fn load(dir: &Path) -> std::io::Result<Self> {
        // Preserve error semantics when `dir` itself cannot be read.
        let _ = std::fs::read_dir(dir)?;
        let mime_sub = dir.join("mime");
        let mut dirs = Vec::with_capacity(2);
        if mime_sub.is_dir() {
            dirs.push(mime_sub);
        }
        dirs.push(dir.to_path_buf());
        Self::load_dirs(&dirs)
    }

    /// Load `*.types` and `*.convs` from multiple directories in order.
    ///
    /// Missing directories (`NotFound`) are skipped cleanly; files are
    /// deduplicated by canonical path so overlapping directories never
    /// double-load the same file.
    pub fn load_dirs<P: AsRef<Path>>(dirs: &[P]) -> std::io::Result<Self> {
        let mut db = MimeDb::default();
        let mut seen_types = HashSet::new();
        let mut seen_convs = HashSet::new();

        for d in dirs {
            let dir = d.as_ref();
            let types_files = match sorted_ext(dir, "types") {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            for f in types_files {
                let key = std::fs::canonicalize(&f).unwrap_or_else(|_| f.clone());
                if seen_types.insert(key) {
                    db.load_types(&f)?;
                }
            }
            for f in sorted_ext(dir, "convs")? {
                let key = std::fs::canonicalize(&f).unwrap_or_else(|_| f.clone());
                if seen_convs.insert(key) {
                    db.load_convs(&f)?;
                }
            }
        }
        db.sort_types();
        Ok(db)
    }

    /// Load MIME definitions in standard CUPS FHS precedence order:
    /// `data_dir/mime`, `data_dir`, then `server_root` (for `local.types` /
    /// `local.convs`).
    pub fn load_standard(data_dir: &Path, server_root: &Path) -> std::io::Result<Self> {
        Self::load_dirs(&[
            data_dir.join("mime"),
            data_dir.to_path_buf(),
            server_root.to_path_buf(),
        ])
    }

    /// Sort loaded MIME types by `(priority desc, name asc)`.
    pub fn sort_types(&mut self) {
        self.types
            .sort_by(|a, b| b.priority.cmp(&a.priority).then(a.name().cmp(&b.name())));
    }

    /// Parse one `mime.types`-format file.
    pub fn load_types(&mut self, path: &Path) -> std::io::Result<()> {
        self.load_types_reader(BufReader::new(File::open(path)?))
    }

    /// Parse one `mime.types`-format stream (`mimeFileType` rules).
    pub fn load_types_reader<R: BufRead>(&mut self, r: R) -> std::io::Result<()> {
        for line in logical_lines(r) {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.splitn(2, char::is_whitespace);
            let Some(tname) = it.next() else { continue };
            let Some((sup, typ)) = tname.split_once('/') else {
                continue;
            };
            if sup.is_empty() || typ.is_empty() {
                continue;
            }
            let rest = it.next().unwrap_or("").trim();
            let (expr, prio) = parse_rules(rest, 0);
            // Merge into existing type (upstream: repeated defs append).
            match self
                .types
                .iter_mut()
                .find(|t| t.sup.eq_ignore_ascii_case(sup) && t.typ.eq_ignore_ascii_case(typ))
            {
                Some(t) => {
                    if let Some(p) = prio {
                        t.priority = p;
                    }
                    if !t.expr.is_empty() && !expr.is_empty() {
                        let mut e = expr;
                        e[0].0 = Join::Or;
                        t.expr.extend(e);
                    } else if !expr.is_empty() {
                        t.expr = expr;
                    }
                }
                None => self.types.push(Type {
                    sup: sup.to_lowercase(),
                    typ: typ.to_lowercase(),
                    expr,
                    priority: prio.unwrap_or(100),
                }),
            }
        }
        Ok(())
    }

    /// Parse one `mime.convs`-format file.
    pub fn load_convs(&mut self, path: &Path) -> std::io::Result<()> {
        self.load_convs_reader(BufReader::new(File::open(path)?))
    }

    /// Parse one `mime.convs`-format stream (`mimeFilter` rules).
    pub fn load_convs_reader<R: BufRead>(&mut self, r: R) -> std::io::Result<()> {
        for line in logical_lines(r) {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.split_whitespace();
            let (Some(src), Some(dst), Some(cost), Some(program)) =
                (it.next(), it.next(), it.next(), it.next())
            else {
                continue;
            };
            let Ok(cost) = cost.parse::<u32>() else {
                continue;
            };
            self.convs.push(Conv {
                src: src.to_lowercase(),
                dst: dst.to_lowercase(),
                cost,
                program: program.to_string(),
            });
        }
        Ok(())
    }

    /// Detect a file's MIME type from its name + first `head` bytes
    /// (`mimeFileType`). Returns `None` for unrecognized.
    #[must_use]
    pub fn detect(&self, filename: &str, head: &[u8]) -> Option<&Type> {
        self.types
            .iter()
            .find(|t| !t.expr.is_empty() && eval_expr(&t.expr, filename, head))
    }

    /// Look up a type by `super/type` name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Type> {
        let (s, t) = name.split_once('/')?;
        self.types
            .iter()
            .find(|x| x.sup.eq_ignore_ascii_case(s) && x.typ.eq_ignore_ascii_case(t))
    }

    /// Minimum-cost filter chain src→dst (`mimeFilter2` — Dijkstra over the
    /// conv graph). Supports `*/*` and `super/*` wildcards and `-` zero-filter
    /// passthrough edges. Returns the ordered filter conv steps; empty = direct.
    #[must_use]
    pub fn filter_chain(&self, src: &str, dst: &str, max_cost: u32) -> Option<Vec<&Conv>> {
        let src = src.to_lowercase();
        let dst = dst.to_lowercase();
        if mime_matches(&dst, &src) {
            return Some(vec![]);
        }
        // best[type] = (cost, wildcard_penalty, filter_path)
        let mut best: HashMap<String, (u32, u32, Vec<&Conv>)> = HashMap::new();
        let mut heap = BinaryHeap::new();
        best.insert(src.clone(), (0, 0, vec![]));
        heap.push(Reverse(((0u32, 0u32), src)));

        while let Some(Reverse(((cost, wpen), cur))) = heap.pop() {
            if mime_matches(&dst, &cur) {
                return Some(best[&cur].2.clone());
            }
            if best
                .get(&cur)
                .is_some_and(|(d, dw, _)| (cost, wpen) > (*d, *dw))
            {
                continue;
            }
            for c in self.convs.iter().filter(|c| mime_matches(&c.src, &cur)) {
                let ncost = cost.saturating_add(c.cost);
                if max_cost != 0 && ncost > max_cost {
                    continue;
                }
                let nwpen = wpen.saturating_add(wildcard_penalty(&c.src));
                let better = best
                    .get(&c.dst)
                    .is_none_or(|(d, dw, _)| (ncost, nwpen) < (*d, *dw));
                if better {
                    let mut path = best[&cur].2.clone();
                    if c.program != "-" {
                        path.push(c);
                    }
                    best.insert(c.dst.clone(), (ncost, nwpen, path));
                    heap.push(Reverse(((ncost, nwpen), c.dst.clone())));
                }
            }
        }
        None
    }

    /// Does `dst` accept `src` directly or via convs (for `file_ready` checks)?
    #[must_use]
    pub fn can_convert(&self, src: &str, dst: &str) -> bool {
        self.filter_chain(src, dst, 0).is_some()
    }
}

/// Does MIME `pattern` (which may contain `*/*` or `super/*`) match `concrete`?
fn mime_matches(pattern: &str, concrete: &str) -> bool {
    if pattern == "*/*" || pattern == concrete {
        return true;
    }
    let (Some((ps, pt)), Some((cs, ct))) = (pattern.split_once('/'), concrete.split_once('/'))
    else {
        return false;
    };
    (ps == "*" || ps == cs) && (pt == "*" || pt == ct)
}

fn wildcard_penalty(pattern: &str) -> u32 {
    if pattern == "*/*" {
        2
    } else {
        u32::from(pattern.contains('*'))
    }
}

fn sorted_ext(dir: &Path, ext: &str) -> std::io::Result<Vec<PathBuf>> {
    let mut v: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == ext))
        .collect();
    v.sort();
    Ok(v)
}

/// Join `\`-continuation lines while tolerating non-UTF-8 bytes in comments.
fn logical_lines<R: BufRead>(mut r: R) -> impl Iterator<Item = String> {
    let mut buf = String::new();
    let mut out = Vec::new();
    let mut raw = Vec::new();
    loop {
        raw.clear();
        match r.read_until(b'\n', &mut raw) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let lossy = String::from_utf8_lossy(&raw);
        let line = lossy.trim_end();
        if let Some(stripped) = line.strip_suffix('\\') {
            if buf.len() < MAX_LOGICAL_LINE {
                buf.push_str(stripped);
                buf.push(' ');
            }
        } else {
            if buf.len() < MAX_LOGICAL_LINE {
                buf.push_str(line);
            }
            out.push(std::mem::take(&mut buf));
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out.into_iter()
}

// ---------- rule parsing ----------

fn skip_ascii_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && b[*i].is_ascii_whitespace() {
        *i += 1;
    }
}

fn next_char_len(s: &str, pos: usize) -> usize {
    s.get(pos..)
        .and_then(|rest| rest.chars().next())
        .map_or(1, char::len_utf8)
}

fn parse_rules(s: &str, depth: usize) -> (Expr, Option<i32>) {
    if depth > MAX_RULE_DEPTH {
        return (Vec::new(), None);
    }

    // Recursive-descent fold: expr := operand (join operand)* where the
    // joiner is `+` (And) or `,`/whitespace (Or). Whitespace around `+` is
    // part of the And join — matching mime_checkrules' left-associative
    // evaluation (`a b + c` = `(a || b) && c`).
    let buf = s.as_bytes();
    let mut pos = 0usize;
    let mut expr: Expr = Vec::new();
    let mut pending_and = false;
    let mut priority: Option<i32> = None;

    skip_ascii_ws(buf, &mut pos);
    while pos < buf.len() {
        let before = pos;
        let Some(rule) = parse_operand(s, &mut pos, depth) else {
            if pos == before {
                pos += next_char_len(s, pos);
            }
            skip_ascii_ws(buf, &mut pos);
            continue;
        };

        if let Rule::Priority { n } = rule {
            priority = Some(n);
            skip_ascii_ws(buf, &mut pos);
            pending_and = false;
            if pos < buf.len() && (buf[pos] == b'+' || buf[pos] == b',') {
                pos += 1;
            }
            skip_ascii_ws(buf, &mut pos);
            continue;
        }
        let join = if pending_and { Join::And } else { Join::Or };
        expr.push((join, rule));

        // Consume the joiner: whitespace, then optional `+` (And) or `,` (Or).
        skip_ascii_ws(buf, &mut pos);
        pending_and = false;
        if pos < buf.len() && buf[pos] == b'+' {
            pending_and = true;
            pos += 1;
        } else if pos < buf.len() && buf[pos] == b',' {
            pos += 1;
        }
        skip_ascii_ws(buf, &mut pos);
    }
    (expr, priority)
}

fn parse_operand(s: &str, pos: &mut usize, depth: usize) -> Option<Rule> {
    if depth > MAX_RULE_DEPTH {
        *pos = s.len();
        return None;
    }
    let buf = s.as_bytes();
    skip_ascii_ws(buf, pos);
    if *pos >= buf.len() {
        return None;
    }
    if buf[*pos] == b'!' {
        *pos += 1;
        skip_ascii_ws(buf, pos);
        let inner = parse_operand(s, pos, depth + 1)?;
        return Some(Rule::Not {
            rule: Box::new(inner),
        });
    }
    if buf[*pos] == b'(' {
        let mut pdepth = 1usize;
        let mut k = *pos + 1;
        let mut quote: Option<u8> = None;
        while k < buf.len() && pdepth > 0 {
            let b = buf[k];
            if let Some(q) = quote {
                if b == q {
                    quote = None;
                }
            } else {
                match b {
                    b'"' | b'\'' => quote = Some(b),
                    b'(' => pdepth += 1,
                    b')' => pdepth -= 1,
                    _ => {}
                }
            }
            k += 1;
        }
        let inner_end = if pdepth == 0 && k > *pos + 1 && buf[k - 1] == b')' {
            k - 1
        } else {
            k
        };
        let inner_str = s.get(*pos + 1..inner_end).unwrap_or("");
        *pos = k;
        let (inner, _) = parse_rules(inner_str, depth + 1);
        return Some(Rule::Group { expr: inner });
    }

    let start = *pos;
    let mut k = start;
    let mut pdepth = 0usize;
    let mut quote: Option<u8> = None;
    while k < buf.len() {
        let b = buf[k];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
        } else {
            match b {
                b'"' | b'\'' => quote = Some(b),
                b'(' => pdepth += 1,
                b')' => {
                    if pdepth == 0 {
                        break;
                    }
                    pdepth -= 1;
                }
                b'+' | b',' if pdepth == 0 => break,
                _ if b.is_ascii_whitespace() && pdepth == 0 => break,
                _ => {}
            }
        }
        k += 1;
    }
    if k == start {
        *pos += next_char_len(s, start);
        return None;
    }
    *pos = k;
    s.get(start..k).and_then(parse_rule)
}

fn parse_rule(t: &str) -> Option<Rule> {
    if t.is_empty() {
        return None;
    }
    if let Some(open) = t.find('(') {
        let name = &t[..open];
        let argstr = t[open + 1..].trim_end_matches(')');
        let mut parts = argstr.splitn(2, ',');
        let arg1 = parts.next().unwrap_or("").trim();
        let arg2 = parts.next().unwrap_or("").trim();
        return match name {
            "string" => Some(Rule::Str {
                offset: num(arg1),
                lit: lit(arg2),
            }),
            "istring" => Some(Rule::IStr {
                offset: num(arg1),
                lit: lit(arg2),
            }),
            "char" => Some(Rule::Char {
                offset: num(arg1),
                v: u8::try_from(num(arg2)).unwrap_or_default(),
            }),
            "short" => Some(Rule::Short {
                offset: num(arg1),
                v: u16::try_from(num(arg2)).unwrap_or_default(),
            }),
            "int" => Some(Rule::Int {
                offset: num(arg1),
                v: u32::try_from(num(arg2)).unwrap_or_default(),
            }),
            "ascii" => Some(Rule::Ascii {
                offset: num(arg1),
                len: usize::try_from(num(arg2)).unwrap_or_default(),
            }),
            "printable" => Some(Rule::Printable {
                offset: num(arg1),
                len: usize::try_from(num(arg2)).unwrap_or_default(),
            }),
            "contains" => {
                let mut a2 = arg2.splitn(2, ',');
                Some(Rule::Contains {
                    offset: num(arg1),
                    range: usize::try_from(num(a2.next().unwrap_or("0"))).unwrap_or_default(),
                    lit: lit(a2.next().unwrap_or("")),
                })
            }
            "regex" => Some(Rule::Regex {
                offset: num(arg1),
                pat: unquote(arg2).into_owned(),
            }),
            "match" => Some(Rule::Match {
                pat: unquote(arg1).into_owned(),
            }),
            "locale" => Some(Rule::Locale {
                s: unquote(arg1).into_owned(),
            }),
            "priority" => Some(Rule::Priority {
                n: i32::try_from(num(arg1)).unwrap_or_default(),
            }),
            _ => None,
        };
    }
    // Bare token = filename extension match (`*.tok` semantics).
    if t.eq_ignore_ascii_case("true") {
        Some(Rule::Match { pat: String::new() })
    } else {
        Some(Rule::Match {
            pat: format!("*.{t}"),
        })
    }
}

fn num(s: &str) -> i64 {
    let s = s.trim().trim_matches('"').trim_matches('\'');
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

fn lit(s: &str) -> Vec<u8> {
    let unq = unquote(s.trim());
    // `<hex>` escapes inside the literal — supports single- and multi-byte hex
    // sequences (e.g. `<89>`, `<FFD8FF>`, `<59a66a95>`), while leaving non-hex
    // angle-bracket text like `<HTML>` or `<!DOCTYPE` literal.
    let b = unq.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'<' {
            if let Some(end) = b[i + 1..].iter().position(|&c| c == b'>') {
                let hex = &unq[i + 1..i + 1 + end];
                if !hex.is_empty()
                    && hex.len().is_multiple_of(2)
                    && hex.bytes().all(|c| c.is_ascii_hexdigit())
                {
                    let mut j = 0;
                    while j < hex.len() {
                        if let Ok(v) = u8::from_str_radix(&hex[j..j + 2], 16) {
                            out.push(v);
                        }
                        j += 2;
                    }
                    i += end + 2;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn unquote(s: &str) -> std::borrow::Cow<'_, str> {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].into()
    } else {
        s.into()
    }
}

// ---------- rule evaluation ----------

fn eval_expr(expr: &Expr, filename: &str, head: &[u8]) -> bool {
    // Left-associative fold, mirroring mime_checkrules.
    let mut result = false;
    for (idx, (join, r)) in expr.iter().enumerate() {
        let v = eval_rule(r, filename, head);
        result = if idx == 0 {
            v
        } else {
            match join {
                Join::And => result && v,
                Join::Or => result || v,
            }
        };
    }
    result
}

fn eval_rule(r: &Rule, filename: &str, head: &[u8]) -> bool {
    match r {
        Rule::Str { offset, lit } => {
            !lit.is_empty() && get_exact(head, *offset, lit.len()) == Some(lit.as_slice())
        }
        Rule::IStr { offset, lit } => {
            !lit.is_empty()
                && get_exact(head, *offset, lit.len()).is_some_and(|s| s.eq_ignore_ascii_case(lit))
        }
        Rule::Char { offset, v } => get_exact(head, *offset, 1).is_some_and(|s| s[0] == *v),
        Rule::Short { offset, v } => get_exact(head, *offset, 2)
            .and_then(|s| s.try_into().ok())
            .is_some_and(|b| u16::from_be_bytes(b) == *v),
        Rule::Int { offset, v } => get_exact(head, *offset, 4)
            .and_then(|s| s.try_into().ok())
            .is_some_and(|b| u32::from_be_bytes(b) == *v),
        Rule::Ascii { offset, len } => {
            let s = get_clamped(head, *offset, *len);
            !s.is_empty()
                && s.iter()
                    .all(|c| matches!(c, b'\r' | b'\n' | b'\t' | 8 | 32..=126))
        }
        Rule::Printable { offset, len } => {
            let s = get_clamped(head, *offset, *len);
            !s.is_empty()
                && s.iter()
                    .all(|c| matches!(c, b'\r' | b'\n' | b'\t' | 8 | 32..=126 | 128..=254))
        }
        Rule::Contains { offset, range, lit } => {
            if lit.is_empty() {
                false
            } else {
                let win = get_clamped(head, *offset, *range);
                win.windows(lit.len()).any(|w| w == lit.as_slice())
            }
        }
        Rule::Regex { offset, pat } => {
            let slice = get_clamped(head, *offset, 2048);
            let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
            if end == 0 {
                return false;
            }
            let text = String::from_utf8_lossy(&slice[..end]);
            regex::regex_match(pat, &text)
        }
        Rule::Match { pat } => {
            if pat.is_empty() {
                return true;
            }
            let pat = pat.to_lowercase();
            let name = Path::new(filename)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(filename)
                .to_lowercase();
            if pat.contains('*') || pat.contains('?') {
                glob_match(&pat, &name)
            } else {
                name.contains(&pat)
            }
        }
        Rule::Locale { s } => std::env::var("LANG")
            .unwrap_or_else(|_| "C".into())
            .to_lowercase()
            .contains(&s.to_lowercase()),
        Rule::Priority { .. } => true,
        Rule::Group { expr } => eval_expr(expr, filename, head),
        Rule::Not { rule } => !eval_rule(rule, filename, head),
    }
}

/// Exact slice of length `len` at `offset`; returns `None` on OOB or overflow.
fn get_exact(head: &[u8], offset: i64, len: usize) -> Option<&[u8]> {
    let start = if offset < 0 {
        let neg = usize::try_from(offset.unsigned_abs()).ok()?;
        head.len().checked_sub(neg)?
    } else {
        usize::try_from(offset).ok()?
    };
    let end = start.checked_add(len)?;
    head.get(start..end)
}

/// Clamped slice of up to `max_len` bytes starting at `offset` (capped at `head.len()`).
/// Returns `&[]` if `offset` is past the end of `head` or `max_len == 0`.
fn get_clamped(head: &[u8], offset: i64, max_len: usize) -> &[u8] {
    if max_len == 0 || head.is_empty() {
        return &[];
    }
    let start = if offset < 0 {
        let neg = usize::try_from(offset.unsigned_abs()).unwrap_or(usize::MAX);
        head.len().saturating_sub(neg)
    } else {
        let Ok(off) = usize::try_from(offset) else {
            return &[];
        };
        if off >= head.len() {
            return &[];
        }
        off
    };
    let end = start.saturating_add(max_len).min(head.len());
    head.get(start..end).unwrap_or(&[])
}

/// Linear-time wildcard glob matching (`*` and `?`).
fn glob_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pat_idx, mut txt_idx) = (0usize, 0usize);
    let mut star_pat: Option<usize> = None;
    let mut star_txt = 0usize;

    while txt_idx < t.len() {
        if pat_idx < p.len() && (p[pat_idx] == '?' || p[pat_idx] == t[txt_idx]) {
            pat_idx += 1;
            txt_idx += 1;
        } else if pat_idx < p.len() && p[pat_idx] == '*' {
            star_pat = Some(pat_idx);
            star_txt = txt_idx;
            pat_idx += 1;
        } else if let Some(sp) = star_pat {
            pat_idx = sp + 1;
            star_txt += 1;
            txt_idx = star_txt;
        } else {
            return false;
        }
    }
    while pat_idx < p.len() && p[pat_idx] == '*' {
        pat_idx += 1;
    }
    pat_idx == p.len()
}

impl std::fmt::Display for MimeDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        write!(s, "{} types, {} convs", self.types.len(), self.convs.len())?;
        f.write_str(&s)
    }
}
