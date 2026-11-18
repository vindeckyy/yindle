//! `cups-driverd` — hardened PPD/driver database helper (`scheduler/cups-driverd.cxx`).
//!
//! Commands:
//!  * `list <req-id> <limit> <options>` — emit sanitized `ppd` records matching
//!    all requested filters (`include-schemes`, `exclude-schemes`, `ppd-make`,
//!    `ppd-make-and-model`, `ppd-device-id`, `ppd-product`, `ppd-psversion`,
//!    `ppd-natural-language`, `ppd-type`).
//!  * `cat <ppd-name>` — emit PPD bytes for `everywhere`, `drv://...`, or a
//!    `.ppd` / `.ppd.gz` strictly contained inside `PPDDIR`.
//!
//! Security & functional hardening:
//!  * Canonical root containment check (`safe_resolve_under`) on `cat`,
//!    `drv_ppd`, and `.drv` `#include` directives (eliminates arbitrary file read).
//!  * Symlink-loop and recursion-depth guards (`MAX_SCAN_DEPTH`) during
//!    directory scanning, preserving subdirectory relative paths.
//!  * Real `.ppd` and `.ppd.gz` (pure-Rust RFC 1952/1951 gunzip with anti-bomb
//!    size cap) metadata parsing (`*Manufacturer`, `*ModelName`, `*NickName`,
//!    `*1284DeviceID`, `*LanguageVersion`, `*Product`, `*PSVersion`).

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

const MAX_SCAN_DEPTH: usize = 16;
const MAX_INCLUDE_DEPTH: usize = 16;
const MAX_PPD_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// One driver/PPD database entry for `list` output.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ppd {
    name: String,
    make: String,
    make_and_model: String,
    device_id: String,
    product: String,
    psversion: String,
    natural_language: String,
    kind: String,
    scheme: String, // "drv" or "ppd"
}

/// A parsed `.drv` model block.
#[derive(Default)]
struct DrvModel {
    model_name: String,
    pc_file_name: String,
    manufacturer: String,
    device_id: String,
    filters: Vec<String>,
    media_sizes: Vec<String>,
    hw_margins: Option<[f64; 4]>,
    resolutions: Vec<String>,
    color_models: Vec<String>,
    duplex: bool,
    version: String,
    drv_rel: String,
}

fn sanitize_record_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => {}
            '\r' | '\n' | '\t' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.trim().to_string()
}

fn everywhere_entry() -> Ppd {
    Ppd {
        name: "everywhere".into(),
        make: "Generic".into(),
        make_and_model: "IPP Everywhere".into(),
        device_id: "MFG:;MDL:IPP Everywhere;DES:IPP Everywhere;CMD:PWGRaster,AppleRaster,JPEG,PDF;"
            .into(),
        product: "(IPP Everywhere)".into(),
        psversion: "(3010.00) 0".into(),
        natural_language: "en".into(),
        kind: "drv".into(),
        scheme: "drv".into(),
    }
}

fn generic_entry() -> Ppd {
    Ppd {
        name: "lsb/usr/cupsfilters/Generic-IPP-Everywhere-Printer.ppd".into(),
        make: "Generic".into(),
        make_and_model: "Generic IPP Everywhere Printer".into(),
        device_id: "MFG:Generic;MDL:IPP Everywhere Printer;DES:Generic IPP Everywhere Printer;CMD:PWGRaster,AppleRaster,JPEG,PDF;".into(),
        product: "(Generic IPP Everywhere Printer)".into(),
        psversion: "(3010.00) 0".into(),
        natural_language: "en".into(),
        kind: "drv".into(),
        scheme: "drv".into(),
    }
}

/// Strictly resolve a relative path under `root` via canonical containment:
/// rejects empty paths, NUL bytes, absolute paths, `..` traversal, symlinks
/// escaping `root`, and non-regular files.
fn safe_resolve_under(root: &Path, rel: &str) -> Option<PathBuf> {
    if rel.is_empty() || rel.contains('\0') || rel.contains('\\') {
        return None;
    }
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() {
        return None;
    }
    for c in rel_path.components() {
        match c {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    let canon_root = std::fs::canonicalize(root).ok()?;
    let candidate = canon_root.join(rel_path);
    let canon_target = std::fs::canonicalize(&candidate).ok()?;
    if !canon_target.starts_with(&canon_root) || canon_target == canon_root {
        return None;
    }
    canon_target.is_file().then_some(canon_target)
}

fn read_file_bounded(path: &Path, limit: usize) -> Option<Vec<u8>> {
    let f = std::fs::File::open(path).ok()?;
    let mut out = Vec::new();
    let mut limited = f.take((limit as u64).saturating_add(1));
    limited.read_to_end(&mut out).ok()?;
    (out.len() <= limit).then_some(out)
}

// ---------- Pure-Rust bounded RFC 1952 gzip + RFC 1951 DEFLATE decoder ----------

struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_buf: u32,
    bit_count: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_buf: 0,
            bit_count: 0,
        }
    }

    fn read_bits(&mut self, n: u8) -> Result<u32, &'static str> {
        while self.bit_count < n {
            let b = *self.data.get(self.byte_pos).ok_or("unexpected EOF")?;
            self.byte_pos += 1;
            self.bit_buf |= u32::from(b) << self.bit_count;
            self.bit_count += 8;
        }
        let mask = if n == 32 { u32::MAX } else { (1u32 << n) - 1 };
        let val = self.bit_buf & mask;
        self.bit_buf >>= n;
        self.bit_count -= n;
        Ok(val)
    }

    fn align_byte(&mut self) {
        let rem = self.bit_count % 8;
        if rem != 0 {
            self.bit_buf >>= rem;
            self.bit_count -= rem;
        }
    }

    fn read_u8_aligned(&mut self) -> Result<u8, &'static str> {
        u8::try_from(self.read_bits(8)?).map_err(|_| "byte overflow")
    }

    fn read_u16_le_aligned(&mut self) -> Result<u16, &'static str> {
        let lo = u16::from(self.read_u8_aligned()?);
        let hi = u16::from(self.read_u8_aligned()?);
        Ok(lo | (hi << 8))
    }

    fn remaining_aligned_bytes(&self) -> &'a [u8] {
        let back = usize::from(self.bit_count / 8);
        let pos = self.byte_pos.saturating_sub(back);
        &self.data[pos..]
    }
}

struct HuffmanTree {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl HuffmanTree {
    fn from_lengths(lengths: &[u8]) -> Result<Self, &'static str> {
        let mut counts = [0u16; 16];
        for &len in lengths {
            if usize::from(len) >= counts.len() {
                return Err("invalid Huffman code length");
            }
            if len > 0 {
                counts[usize::from(len)] += 1;
            }
        }
        let mut offsets = [0usize; 16];
        let mut total = 0usize;
        for bits in 1..16 {
            offsets[bits] = total;
            total += usize::from(counts[bits]);
        }
        let mut symbols = vec![0u16; total];
        for (sym, &len) in lengths.iter().enumerate() {
            if len > 0 {
                let idx = offsets[usize::from(len)];
                symbols[idx] = u16::try_from(sym).map_err(|_| "symbol overflow")?;
                offsets[usize::from(len)] += 1;
            }
        }
        Ok(Self { counts, symbols })
    }

    fn decode(&self, br: &mut BitReader<'_>) -> Result<u16, &'static str> {
        let mut code = 0i32;
        let mut first = 0i32;
        let mut index = 0usize;
        for len in 1..16 {
            code |= i32::try_from(br.read_bits(1)?).unwrap_or(0);
            let count = i32::from(self.counts[len]);
            if code - count < first {
                let sym_idx = index + usize::try_from(code - first).map_err(|_| "bad code")?;
                return self
                    .symbols
                    .get(sym_idx)
                    .copied()
                    .ok_or("bad Huffman symbol");
            }
            index += usize::try_from(count).unwrap_or(0);
            first = (first + count) << 1;
            code <<= 1;
        }
        Err("invalid Huffman code")
    }
}

fn fixed_trees() -> Result<(HuffmanTree, HuffmanTree), &'static str> {
    let mut lit = [0u8; 288];
    lit[0..=143].fill(8);
    lit[144..=255].fill(9);
    lit[256..=279].fill(7);
    lit[280..=287].fill(8);
    let dist = [5u8; 32];
    Ok((
        HuffmanTree::from_lengths(&lit)?,
        HuffmanTree::from_lengths(&dist)?,
    ))
}

fn read_dynamic_trees(br: &mut BitReader<'_>) -> Result<(HuffmanTree, HuffmanTree), &'static str> {
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let hlit = usize::try_from(br.read_bits(5)?).unwrap_or(0) + 257;
    let hdist = usize::try_from(br.read_bits(5)?).unwrap_or(0) + 1;
    let hclen = usize::try_from(br.read_bits(4)?).unwrap_or(0) + 4;
    if hlit > 286 || hdist > 30 {
        return Err("invalid dynamic Huffman header");
    }
    let mut cl_lens = [0u8; 19];
    for &idx in ORDER.iter().take(hclen) {
        cl_lens[idx] = u8::try_from(br.read_bits(3)?).map_err(|_| "cl overflow")?;
    }
    let cl_tree = HuffmanTree::from_lengths(&cl_lens)?;
    let total = hlit + hdist;
    let mut lens = Vec::with_capacity(total);
    while lens.len() < total {
        let sym = cl_tree.decode(br)?;
        match sym {
            0..=15 => lens.push(u8::try_from(sym).map_err(|_| "len overflow")?),
            16 => {
                let prev = *lens.last().ok_or("repeat without previous length")?;
                let rep = usize::try_from(br.read_bits(2)?).unwrap_or(0) + 3;
                for _ in 0..rep {
                    lens.push(prev);
                }
            }
            17 => {
                let rep = usize::try_from(br.read_bits(3)?).unwrap_or(0) + 3;
                lens.resize(lens.len() + rep, 0);
            }
            18 => {
                let rep = usize::try_from(br.read_bits(7)?).unwrap_or(0) + 11;
                lens.resize(lens.len() + rep, 0);
            }
            _ => return Err("invalid code-length symbol"),
        }
    }
    if lens.len() != total {
        return Err("dynamic length table overrun");
    }
    Ok((
        HuffmanTree::from_lengths(&lens[..hlit])?,
        HuffmanTree::from_lengths(&lens[hlit..])?,
    ))
}

fn inflate_huffman_block(
    br: &mut BitReader<'_>,
    lit_tree: &HuffmanTree,
    dist_tree: &HuffmanTree,
    out: &mut Vec<u8>,
    max_out: usize,
) -> Result<(), &'static str> {
    const LEN_BASE: [usize; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    const LEN_EXTRA: [u8; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    const DIST_BASE: [usize; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    const DIST_EXTRA: [u8; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13,
    ];

    loop {
        let sym = lit_tree.decode(br)?;
        match sym {
            0..=255 => {
                if out.len() >= max_out {
                    return Err("decompressed output exceeds limit");
                }
                out.push(u8::try_from(sym).map_err(|_| "lit overflow")?);
            }
            256 => return Ok(()),
            _ => {
                let lidx = usize::from(sym - 257);
                if lidx >= LEN_BASE.len() {
                    return Err("invalid length symbol");
                }
                let extra_l = usize::try_from(br.read_bits(LEN_EXTRA[lidx])?).unwrap_or(0);
                let length = LEN_BASE[lidx] + extra_l;
                let dsym = usize::from(dist_tree.decode(br)?);
                if dsym >= DIST_BASE.len() {
                    return Err("invalid distance symbol");
                }
                let extra_d = usize::try_from(br.read_bits(DIST_EXTRA[dsym])?).unwrap_or(0);
                let dist = DIST_BASE[dsym] + extra_d;
                if dist == 0 || dist > out.len() {
                    return Err("invalid back-reference distance");
                }
                if out.len().saturating_add(length) > max_out {
                    return Err("decompressed output exceeds limit");
                }
                for _ in 0..length {
                    let b = out[out.len() - dist];
                    out.push(b);
                }
            }
        }
    }
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Decompress an RFC 1952 `.gz` payload with a strict output cap and CRC32 check.
fn gunzip_bounded(input: &[u8], max_out: usize) -> Result<Vec<u8>, &'static str> {
    if input.len() < 18 || input[0] != 0x1f || input[1] != 0x8b || input[2] != 8 {
        return Err("invalid gzip header");
    }
    let flg = input[3];
    let mut pos = 10usize;
    if flg & 0x04 != 0 {
        // FEXTRA
        if pos + 2 > input.len() {
            return Err("truncated gzip FEXTRA");
        }
        let xlen = usize::from(u16::from_le_bytes([input[pos], input[pos + 1]]));
        pos = pos.checked_add(2 + xlen).ok_or("gzip FEXTRA overflow")?;
    }
    if flg & 0x08 != 0 {
        // FNAME (NUL-terminated)
        let nul = input
            .get(pos..)
            .ok_or("truncated FNAME")?
            .iter()
            .position(|&b| b == 0)
            .ok_or("unterminated FNAME")?;
        pos += nul + 1;
    }
    if flg & 0x10 != 0 {
        // FCOMMENT (NUL-terminated)
        let nul = input
            .get(pos..)
            .ok_or("truncated FCOMMENT")?
            .iter()
            .position(|&b| b == 0)
            .ok_or("unterminated FCOMMENT")?;
        pos += nul + 1;
    }
    if flg & 0x02 != 0 {
        // FHCRC
        pos += 2;
    }
    if pos >= input.len() {
        return Err("truncated gzip stream");
    }

    let mut br = BitReader::new(&input[pos..]);
    let mut out = Vec::new();
    loop {
        let bfinal = br.read_bits(1)?;
        let btype = br.read_bits(2)?;
        match btype {
            0 => {
                br.align_byte();
                let len = br.read_u16_le_aligned()?;
                let nlen = br.read_u16_le_aligned()?;
                if len != !nlen {
                    return Err("corrupt stored DEFLATE block");
                }
                let count = usize::from(len);
                if out.len().saturating_add(count) > max_out {
                    return Err("decompressed output exceeds limit");
                }
                for _ in 0..count {
                    out.push(br.read_u8_aligned()?);
                }
            }
            1 => {
                let (lt, dt) = fixed_trees()?;
                inflate_huffman_block(&mut br, &lt, &dt, &mut out, max_out)?;
            }
            2 => {
                let (lt, dt) = read_dynamic_trees(&mut br)?;
                inflate_huffman_block(&mut br, &lt, &dt, &mut out, max_out)?;
            }
            _ => return Err("invalid DEFLATE block type"),
        }
        if bfinal != 0 {
            break;
        }
    }

    br.align_byte();
    let trailer = br.remaining_aligned_bytes();
    if trailer.len() < 8 {
        return Err("truncated gzip trailer");
    }
    let want_crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let want_size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    let actual_size = u32::try_from(out.len() & 0xffff_ffff).unwrap_or(0);
    if crc32_ieee(&out) != want_crc || actual_size != want_size {
        return Err("gzip CRC/size mismatch");
    }
    Ok(out)
}

// ---------- PPD metadata parser ----------

fn ppd_language_code(lang_ver: &str) -> String {
    let tok = lang_ver.trim().trim_matches('"');
    match tok.to_ascii_lowercase().as_str() {
        "english" | "" => "en".to_string(),
        "french" => "fr".to_string(),
        "german" => "de".to_string(),
        "spanish" => "es".to_string(),
        "italian" => "it".to_string(),
        "japanese" => "ja".to_string(),
        "chinese" => "zh".to_string(),
        "korean" => "ko".to_string(),
        "portuguese" => "pt".to_string(),
        "russian" => "ru".to_string(),
        "dutch" => "nl".to_string(),
        "swedish" => "sv".to_string(),
        "danish" => "da".to_string(),
        "norwegian" => "no".to_string(),
        "finnish" => "fi".to_string(),
        "polish" => "pl".to_string(),
        other => other.to_string(),
    }
}

fn ppd_value(line: &str) -> String {
    let v = line.trim();
    if let Some(rest) = v.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").trim().to_string()
    } else {
        v.to_string()
    }
}

/// Parse real PPD metadata from `.ppd` or decompressed `.ppd.gz` text.
fn parse_ppd_metadata(content: &str, name: &str) -> Ppd {
    let mut manufacturer = String::new();
    let mut model_name = String::new();
    let mut nick_name = String::new();
    let mut short_nick = String::new();
    let mut device_id = String::new();
    let mut product = String::new();
    let mut psversion = String::new();
    let mut lang_ver = String::new();
    let mut ppd_type = "postscript".to_string();

    for raw in content.lines() {
        let line = raw.trim();
        if !line.starts_with('*') || line.starts_with("*%") {
            continue;
        }
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        match key {
            "*Manufacturer" if manufacturer.is_empty() => manufacturer = ppd_value(val),
            "*ModelName" if model_name.is_empty() => model_name = ppd_value(val),
            "*NickName" if nick_name.is_empty() => nick_name = ppd_value(val),
            "*ShortNickName" if short_nick.is_empty() => short_nick = ppd_value(val),
            "*1284DeviceID" if device_id.is_empty() => device_id = ppd_value(val),
            "*Product" if product.is_empty() => product = ppd_value(val),
            "*PSVersion" if psversion.is_empty() => psversion = ppd_value(val),
            "*LanguageVersion" if lang_ver.is_empty() => lang_ver = ppd_value(val),
            "*cupsFilter" | "*cupsFilter2" => {
                let v = ppd_value(val).to_ascii_lowercase();
                if v.contains("raster") {
                    ppd_type = "raster".to_string();
                } else if v.contains("pdf") && ppd_type == "postscript" {
                    ppd_type = "pdf".to_string();
                }
            }
            "*cupsFax" if ppd_value(val).eq_ignore_ascii_case("true") => {
                ppd_type = "fax".to_string();
            }
            _ => {}
        }
    }

    let make_and_model = if !nick_name.is_empty() {
        nick_name
    } else if !short_nick.is_empty() {
        short_nick
    } else if !model_name.is_empty() {
        model_name
    } else {
        name.to_string()
    };
    let make = if manufacturer.is_empty() {
        make_and_model
            .split_whitespace()
            .next()
            .unwrap_or("Generic")
            .to_string()
    } else {
        manufacturer
    };
    if product.is_empty() {
        product = format!("({make_and_model})");
    }
    if psversion.is_empty() {
        psversion = "(3010.00) 0".to_string();
    }

    Ppd {
        name: sanitize_record_field(name),
        make: sanitize_record_field(&make),
        make_and_model: sanitize_record_field(&make_and_model),
        device_id: sanitize_record_field(&device_id),
        product: sanitize_record_field(&product),
        psversion: sanitize_record_field(&psversion),
        natural_language: sanitize_record_field(&ppd_language_code(&lang_ver)),
        kind: ppd_type,
        scheme: "ppd".into(),
    }
}

// ---------- .drv parser with safe #include expansion ----------

/// The first quoted `"…"` or bare token after the directive keyword.
fn arg1(rest: &str) -> String {
    let rest = rest.trim();
    if let Some(inner) = rest.strip_prefix('"').and_then(|r| r.split('"').next()) {
        return inner.to_string();
    }
    rest.split_whitespace().next().unwrap_or("").to_string()
}

/// Extract `#include <file>` or `#include "file"` target.
fn parse_include_directive(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("#include")?.trim();
    if let Some(inner) = rest.strip_prefix('<').and_then(|r| r.strip_suffix('>')) {
        return (!inner.is_empty()).then_some(inner.trim());
    }
    if let Some(inner) = rest.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        return (!inner.is_empty()).then_some(inner.trim());
    }
    None
}

/// Load a `.drv` file expanding bounded, root-contained `#include` directives.
fn load_drv_expanded(
    path: &Path,
    drv_root: &Path,
    depth: usize,
    active_includes: &mut HashSet<PathBuf>,
    out_lines: &mut Vec<String>,
) {
    if depth > MAX_INCLUDE_DEPTH {
        return;
    }
    let Ok(canon) = std::fs::canonicalize(path) else {
        return;
    };
    if !active_includes.insert(canon.clone()) {
        return; // cycle guard
    }
    if let Some(bytes) = read_file_bounded(&canon, MAX_PPD_BYTES) {
        let text = String::from_utf8_lossy(&bytes);
        let cur_dir = canon.parent().unwrap_or(drv_root);
        let canon_root = std::fs::canonicalize(drv_root).unwrap_or_else(|_| drv_root.to_path_buf());
        for raw in text.lines() {
            let trimmed = raw.trim();
            if let Some(inc) = parse_include_directive(trimmed) {
                // Resolve relative to current subdir (within drv_root), else drv_root.
                let sub_rel = cur_dir
                    .strip_prefix(&canon_root)
                    .ok()
                    .filter(|p| !p.as_os_str().is_empty())
                    .map(|p| format!("{}/{inc}", p.to_string_lossy().replace('\\', "/")));
                let resolved = sub_rel
                    .as_deref()
                    .and_then(|r| safe_resolve_under(&canon_root, r))
                    .or_else(|| safe_resolve_under(&canon_root, inc));
                if let Some(inc_path) = resolved {
                    load_drv_expanded(
                        &inc_path,
                        &canon_root,
                        depth + 1,
                        active_includes,
                        out_lines,
                    );
                }
            } else {
                out_lines.push(raw.to_string());
            }
        }
    }
    active_includes.remove(&canon);
}

/// Parse a `.drv` file (with `#include` support) into its model blocks.
#[allow(clippy::too_many_lines)]
fn parse_drv(path: &Path, drv_root: &Path) -> Vec<DrvModel> {
    let mut lines = Vec::new();
    let mut active = HashSet::new();
    load_drv_expanded(path, drv_root, 0, &mut active, &mut lines);
    if lines.is_empty() {
        return Vec::new();
    }
    let canon_root = std::fs::canonicalize(drv_root).unwrap_or_else(|_| drv_root.to_path_buf());
    let canon_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let rel = canon_path
        .strip_prefix(&canon_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    let mut shared = DrvModel {
        drv_rel: rel,
        ..Default::default()
    };
    let mut models: Vec<DrvModel> = Vec::new();
    let mut cur: Option<DrvModel> = None;
    let mut pending_media: Vec<String> = Vec::new();
    let mut pending_res: Vec<String> = Vec::new();
    let mut pending_color: Vec<String> = Vec::new();
    let mut pending_filters: Vec<String> = Vec::new();
    let mut pending_duplex = false;

    for raw in &lines {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        let (kw, rest) = line
            .split_once(|c: char| c.is_whitespace())
            .map_or((line, ""), |(k, r)| (k, r.trim()));
        match kw.trim_start_matches('*') {
            "Manufacturer" => shared.manufacturer = arg1(rest),
            "Version" => shared.version = arg1(rest),
            "Attribute" => {
                // `Attribute "1284DeviceID" "" "MFG:...;"`
                let quoted: Vec<&str> = rest.split('"').collect();
                if quoted.len() >= 6 && quoted[1].eq_ignore_ascii_case("1284DeviceID") {
                    let val = quoted[5].to_string();
                    if let Some(m) = cur.as_mut() {
                        m.device_id = val;
                    } else {
                        shared.device_id = val;
                    }
                }
            }
            "ModelName" => {
                if let Some(mut m) = cur.take() {
                    m.media_sizes.append(&mut pending_media);
                    m.resolutions.append(&mut pending_res);
                    m.color_models.append(&mut pending_color);
                    m.filters.append(&mut pending_filters);
                    m.duplex = pending_duplex;
                    models.push(m);
                }
                let mut m = shared.clone_shallow();
                m.model_name = arg1(rest);
                cur = Some(m);
                pending_media.clone_from(&shared.media_sizes);
                pending_res.clone_from(&shared.resolutions);
                pending_color.clone_from(&shared.color_models);
                pending_filters.clone_from(&shared.filters);
                pending_duplex = shared.duplex;
            }
            "PCFileName" => {
                if let Some(m) = cur.as_mut() {
                    m.pc_file_name = arg1(rest);
                }
            }
            "MediaSize" => {
                let v = line.split_whitespace().nth(1).unwrap_or("").to_string();
                if cur.is_none() {
                    shared.media_sizes.push(v.clone());
                }
                pending_media.push(v);
            }
            "Resolution" => {
                if cur.is_none() {
                    shared.resolutions.push(line.to_string());
                }
                pending_res.push(line.to_string());
            }
            "ColorModel" => {
                if cur.is_none() {
                    shared.color_models.push(line.to_string());
                }
                pending_color.push(line.to_string());
            }
            "Filter" => {
                if cur.is_none() {
                    shared.filters.push(rest.to_string());
                }
                pending_filters.push(rest.to_string());
            }
            "HWMargins" => {
                let nums: Vec<f64> = rest
                    .split_whitespace()
                    .filter_map(|t| t.parse().ok())
                    .collect();
                if nums.len() >= 4 {
                    let m = [nums[0], nums[1], nums[2], nums[3]];
                    if let Some(cm) = cur.as_mut() {
                        cm.hw_margins = Some(m);
                    } else {
                        shared.hw_margins = Some(m);
                    }
                }
            }
            "Duplex" => {
                shared.duplex = true;
                pending_duplex = true;
            }
            _ => {}
        }
    }
    if let Some(mut m) = cur.take() {
        m.media_sizes.append(&mut pending_media);
        m.resolutions.append(&mut pending_res);
        m.color_models.append(&mut pending_color);
        m.filters.append(&mut pending_filters);
        m.duplex = pending_duplex;
        models.push(m);
    }
    models
}

impl DrvModel {
    fn clone_shallow(&self) -> Self {
        Self {
            manufacturer: self.manufacturer.clone(),
            device_id: self.device_id.clone(),
            version: self.version.clone(),
            drv_rel: self.drv_rel.clone(),
            hw_margins: self.hw_margins,
            ..Default::default()
        }
    }
}

/// Scan `cur` recursively under `root` for `.drv` files with symlink-loop,
/// root-containment, and depth guards.
fn scan_drv_dir(
    root: &Path,
    cur: &Path,
    depth: usize,
    visited: &mut HashSet<PathBuf>,
    out: &mut Vec<Ppd>,
) {
    if depth > MAX_SCAN_DEPTH {
        return;
    }
    let Ok(canon_root) = std::fs::canonicalize(root) else {
        return;
    };
    let Ok(canon_cur) = std::fs::canonicalize(cur) else {
        return;
    };
    if !canon_cur.starts_with(&canon_root) || !visited.insert(canon_cur.clone()) {
        return;
    }
    let Ok(rd) = std::fs::read_dir(&canon_cur) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let p = e.path();
        let Ok(canon_p) = std::fs::canonicalize(&p) else {
            continue;
        };
        if !canon_p.starts_with(&canon_root) {
            continue;
        }
        if canon_p.is_dir() {
            scan_drv_dir(&canon_root, &canon_p, depth + 1, visited, out);
        } else if canon_p.is_file() && canon_p.extension().is_some_and(|x| x == "drv") {
            for m in parse_drv(&canon_p, &canon_root) {
                if m.pc_file_name.is_empty() {
                    continue;
                }
                let dev_id = if m.device_id.is_empty() {
                    format!(
                        "MFG:{};MDL:{};DES:{};",
                        m.manufacturer, m.model_name, m.model_name
                    )
                } else {
                    m.device_id.clone()
                };
                out.push(Ppd {
                    name: sanitize_record_field(&format!(
                        "drv:///{}/{}",
                        m.drv_rel, m.pc_file_name
                    )),
                    make: sanitize_record_field(&m.manufacturer),
                    make_and_model: sanitize_record_field(&m.model_name),
                    device_id: sanitize_record_field(&dev_id),
                    product: sanitize_record_field(&format!("({})", m.model_name)),
                    psversion: "(3010.00) 0".into(),
                    natural_language: "en".into(),
                    kind: "drv".into(),
                    scheme: "drv".into(),
                });
            }
        }
    }
}

/// Scan `cur` recursively under `root` for `.ppd` and `.ppd.gz` files with
/// symlink-loop, root-containment, and depth guards, parsing real metadata.
fn scan_ppd_dir(
    root: &Path,
    cur: &Path,
    depth: usize,
    visited: &mut HashSet<PathBuf>,
    out: &mut Vec<Ppd>,
) {
    if depth > MAX_SCAN_DEPTH {
        return;
    }
    let Ok(canon_root) = std::fs::canonicalize(root) else {
        return;
    };
    let Ok(canon_cur) = std::fs::canonicalize(cur) else {
        return;
    };
    if !canon_cur.starts_with(&canon_root) || !visited.insert(canon_cur.clone()) {
        return;
    }
    let Ok(rd) = std::fs::read_dir(&canon_cur) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let p = e.path();
        let Ok(canon_p) = std::fs::canonicalize(&p) else {
            continue;
        };
        if !canon_p.starts_with(&canon_root) {
            continue;
        }
        if canon_p.is_dir() {
            scan_ppd_dir(&canon_root, &canon_p, depth + 1, visited, out);
        } else if canon_p.is_file() {
            let fname = canon_p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let is_ppd = Path::new(fname)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("ppd"));
            let is_ppd_gz = fname.to_ascii_lowercase().ends_with(".ppd.gz");
            if !is_ppd && !is_ppd_gz {
                continue;
            }
            let rel = canon_p
                .strip_prefix(&canon_root)
                .unwrap_or(&canon_p)
                .to_string_lossy()
                .replace('\\', "/");
            let Some(raw_bytes) = read_file_bounded(&canon_p, MAX_PPD_BYTES) else {
                continue;
            };
            let decoded = if is_ppd_gz {
                let Ok(plain) = gunzip_bounded(&raw_bytes, MAX_PPD_BYTES) else {
                    continue;
                };
                plain
            } else {
                raw_bytes
            };
            let content = String::from_utf8_lossy(&decoded);
            out.push(parse_ppd_metadata(&content, &rel));
        }
    }
}

fn drv_roots_from(drv_env: Option<&str>, ppd_env: Option<&str>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(d) = drv_env.filter(|s| !s.is_empty()) {
        v.push(PathBuf::from(d));
    }
    if let Some(d) = ppd_env.filter(|s| !s.is_empty()) {
        let p = PathBuf::from(d);
        v.push(p.join("drv"));
        v.push(p);
    }
    v
}

/// Compile a PPD from `drv:///<rel>.drv/<pcfile>` after strict root-containment check.
fn drv_ppd_in(name: &str, roots: &[PathBuf]) -> Option<String> {
    let rest = name.strip_prefix("drv:///")?;
    let (rel_drv, pcfile) = rest.rsplit_once('/')?;
    let is_drv = Path::new(rel_drv)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("drv"));
    if !is_drv || pcfile.is_empty() || pcfile.contains("..") || pcfile.contains('/') {
        return None;
    }
    for root in roots {
        let Some(drv) = safe_resolve_under(root, rel_drv) else {
            continue;
        };
        for m in parse_drv(&drv, root) {
            if m.pc_file_name == pcfile {
                return Some(compile_ppd(&m));
            }
        }
    }
    None
}

/// Read a `.ppd` or `.ppd.gz` file strictly inside `ppd_dirs`, decompressing `.ppd.gz`.
fn read_ppd_cat(name: &str, ppd_dirs: &[PathBuf]) -> Option<Vec<u8>> {
    let is_ppd = Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("ppd"));
    let is_ppd_gz = name.to_ascii_lowercase().ends_with(".ppd.gz");
    if !is_ppd && !is_ppd_gz {
        return None;
    }
    for dir in ppd_dirs {
        let Some(resolved) = safe_resolve_under(dir, name) else {
            continue;
        };
        let raw = read_file_bounded(&resolved, MAX_PPD_BYTES)?;
        if is_ppd_gz {
            return gunzip_bounded(&raw, MAX_PPD_BYTES).ok();
        }
        return Some(raw);
    }
    None
}

fn media_size_points(name: &str) -> Option<(f64, f64)> {
    let named: &[(&str, f64, f64)] = &[
        ("Letter", 612.0, 792.0),
        ("Legal", 612.0, 1008.0),
        ("Executive", 522.0, 756.0),
        ("Tabloid", 792.0, 1224.0),
        ("Ledger", 1224.0, 792.0),
        ("A3", 842.0, 1191.0),
        ("A4", 595.0, 842.0),
        ("A5", 420.0, 595.0),
        ("A6", 298.0, 420.0),
        ("B4", 729.0, 1032.0),
        ("B5", 516.0, 729.0),
        ("Env10", 297.0, 684.0),
        ("EnvC5", 459.0, 649.0),
        ("EnvDL", 312.0, 624.0),
        ("EnvMonarch", 279.0, 540.0),
        ("4x6", 288.0, 432.0),
        ("5x7", 360.0, 504.0),
    ];
    for (n, w, h) in named {
        if name.eq_ignore_ascii_case(n) {
            return Some((*w, *h));
        }
    }
    if let Some(rest) = name.strip_prefix('w') {
        if let Some((w, h)) = rest.split_once('h') {
            if let (Ok(w), Ok(h)) = (w.parse::<f64>(), h.parse::<f64>()) {
                return Some((w, h));
            }
        }
    }
    None
}

#[allow(clippy::too_many_lines)]
fn compile_ppd(m: &DrvModel) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let mm = if m.model_name.is_empty() {
        "Unknown"
    } else {
        &m.model_name
    };
    s.push_str("*PPD-Adobe: \"4.3\"\n*FormatVersion: \"4.3\"\n*FileVersion: \"1.0\"\n");
    s.push_str("*LanguageVersion: English\n*LanguageEncoding: ISOLatin1\n");
    let _ = writeln!(s, "*PCFileName: \"{}\"", m.pc_file_name);
    let _ = writeln!(s, "*Manufacturer: \"{}\"", m.manufacturer);
    if !m.device_id.is_empty() {
        let _ = writeln!(s, "*1284DeviceID: \"{}\"", m.device_id);
    }
    let _ = writeln!(
        s,
        "*Product: \"({mm})\"\n*ModelName: \"{mm}\"\n*NickName: \"{mm}\"\n*ShortNickName: \"{mm}\""
    );
    let _ = writeln!(
        s,
        "*DriverVersion: \"{}\"",
        if m.version.is_empty() {
            "1.0"
        } else {
            &m.version
        }
    );
    s.push_str("*PSVersion: \"(3010.00) 0\"\n*LanguageLevel: \"3\"\n*ColorDevice: True\n*DefaultColorSpace: RGB\n");
    let mar = m.hw_margins.unwrap_or([0.0, 0.0, 0.0, 0.0]);
    let _ = writeln!(s, "*HWMargins: {} {} {} {}", mar[0], mar[1], mar[2], mar[3]);
    for f in &m.filters {
        let mut it = f.split_whitespace();
        if let (Some(mime), Some(cost), Some(cmd)) = (it.next(), it.next(), it.next()) {
            let _ = writeln!(s, "*cupsFilter: \"{mime} {cost} {cmd}\"");
        }
    }
    if !m.media_sizes.is_empty() {
        s.push_str(
            "*OpenUI *PageSize/Media Size: PickOne\n*OrderDependency: 10 AnySetup *PageSize\n",
        );
        for (i, sz) in m.media_sizes.iter().enumerate() {
            if i == 0 {
                let _ = writeln!(s, "*DefaultPageSize: {sz}");
            }
            let (w, h) = media_size_points(sz).unwrap_or((612.0, 792.0));
            let _ = writeln!(
                s,
                "*PageSize {sz}/{sz}: \"<</PageSize[{w:.0} {h:.0}]>>setpagedevice\""
            );
        }
        s.push_str("*CloseUI: *PageSize\n*OpenUI *PageRegion/Media Size: PickOne\n*OrderDependency: 10 AnySetup *PageRegion\n");
        let _ = writeln!(s, "*DefaultPageRegion: {}", m.media_sizes[0]);
        for sz in &m.media_sizes {
            let (w, h) = media_size_points(sz).unwrap_or((612.0, 792.0));
            let _ = writeln!(
                s,
                "*PageRegion {sz}/{sz}: \"<</PageSize[{w:.0} {h:.0}]>>setpagedevice\""
            );
        }
        s.push_str("*CloseUI: *PageRegion\n*OpenGroup: ImageableArea/Imageable Area\n");
        let _ = writeln!(s, "*DefaultImageableArea: {}", m.media_sizes[0]);
        for sz in &m.media_sizes {
            let (w, h) = media_size_points(sz).unwrap_or((612.0, 792.0));
            let _ = writeln!(
                s,
                "*ImageableArea {sz}/{sz}: \"{} {} {:.2} {:.2}\"",
                mar[0],
                mar[1],
                w - mar[2],
                h - mar[3]
            );
        }
        s.push_str("*CloseGroup: ImageableArea\n*OpenGroup: PaperDimension/Paper Dimension\n");
        let _ = writeln!(s, "*DefaultPaperDimension: {}", m.media_sizes[0]);
        for sz in &m.media_sizes {
            let (w, h) = media_size_points(sz).unwrap_or((612.0, 792.0));
            let _ = writeln!(s, "*PaperDimension {sz}/{sz}: \"{w:.0} {h:.0}\"");
        }
        s.push_str("*CloseGroup: PaperDimension\n");
    }
    if !m.resolutions.is_empty() {
        s.push_str(
            "*OpenUI *Resolution/Resolution: PickOne\n*OrderDependency: 20 AnySetup *Resolution\n",
        );
        for (i, r) in m.resolutions.iter().enumerate() {
            let label = r
                .split('"')
                .nth(1)
                .map_or_else(|| r.split_whitespace().last().unwrap_or(""), |q| q)
                .split('/')
                .next()
                .unwrap_or("600dpi");
            let (xdpi, ydpi) = label.trim_end_matches("dpi").split_once('x').map_or_else(
                || (label.trim_end_matches("dpi"), label.trim_end_matches("dpi")),
                |(x, y)| (x, y),
            );
            if i == 0 {
                let _ = writeln!(s, "*DefaultResolution: {label}");
            }
            let _ = writeln!(
                s,
                "*Resolution {label}: \"<</HWResolution[{xdpi} {ydpi}]>>setpagedevice\""
            );
        }
        s.push_str("*CloseUI: *Resolution\n");
    }
    if !m.color_models.is_empty() {
        s.push_str(
            "*OpenUI *ColorModel/Color Mode: PickOne\n*OrderDependency: 30 AnySetup *ColorModel\n",
        );
        for (i, c) in m.color_models.iter().enumerate() {
            let nm = c
                .split_whitespace()
                .nth(1)
                .unwrap_or("RGB")
                .split('/')
                .next()
                .unwrap_or("RGB");
            if i == 0 {
                let _ = writeln!(s, "*DefaultColorModel: {nm}");
            }
            let _ = writeln!(
                s,
                "*ColorModel {nm}: \"<</cupsColorSpace 0>>setpagedevice\""
            );
        }
        s.push_str("*CloseUI: *ColorModel\n");
    }
    if m.duplex {
        s.push_str("*OpenUI *Duplex/2-Sided Printing: PickOne\n*OrderDependency: 40 AnySetup *Duplex\n*DefaultDuplex: None\n");
        s.push_str("*Duplex None/Off: \"<</Duplex false>>setpagedevice\"\n*Duplex DuplexNoTumble/Long-Edge: \"<</Duplex true/Tumble false>>setpagedevice\"\n*CloseUI: *Duplex\n");
    }
    s
}

fn driverless_ppd() -> &'static str {
    "*PPD-Adobe: \"4.3\"\n\
     *FormatVersion: \"4.3\"\n\
     *FileVersion: \"1.0\"\n\
     *LanguageVersion: English\n\
     *LanguageEncoding: ISOLatin1\n\
     *PCFileName: \"ippeve.ppd\"\n\
     *Manufacturer: \"Generic\"\n\
     *Product: \"(IPP Everywhere)\"\n\
     *ModelName: \"IPP Everywhere\"\n\
     *NickName: \"IPP Everywhere\"\n\
     *ShortNickName: \"IPP Everywhere\"\n\
     *DefaultColorSpace: Gray\n\
     *ColorDevice: True\n\
     *cupsFilter2: \"application/vnd.cups-pdf application/pdf 0 -\"\n\
     *cupsFilter2: \"image/jpeg image/jpeg 0 -\"\n\
     *cupsFilter2: \"image/pwg-raster image/pwg-raster 0 -\"\n\
     *cupsFilter2: \"image/urf image/urf 0 -\"\n\
     *OpenUI *PageSize/Media Size: PickOne\n\
     *OrderDependency: 10 AnySetup *PageSize\n\
     *DefaultPageSize: Letter\n\
     *PageSize Letter/US Letter: \"<</PageSize[612 792]>>setpagedevice\"\n\
     *PageSize Legal/US Legal: \"<</PageSize[612 1008]>>setpagedevice\"\n\
     *PageSize A4/A4: \"<</PageSize[595 842]>>setpagedevice\"\n\
     *CloseUI: *PageSize\n\
     *OpenUI *Duplex/2-Sided Printing: PickOne\n\
     *OrderDependency: 20 AnySetup *Duplex\n\
     *DefaultDuplex: None\n\
     *Duplex None/Off: \"<</Duplex false>>setpagedevice\"\n\
     *Duplex DuplexNoTumble/Long-Edge (Portrait): \"<</Duplex true/Tumble false>>setpagedevice\"\n\
     *Duplex DuplexTumble/Short-Edge (Landscape): \"<</Duplex true/Tumble true>>setpagedevice\"\n\
     *CloseUI: *Duplex\n"
}

// ---------- `list` filter parsing & matching ----------

const KNOWN_FILTERS: &[&str] = &[
    "ppd-device-id",
    "ppd-natural-language",
    "ppd-make",
    "ppd-make-and-model",
    "ppd-product",
    "ppd-psversion",
    "ppd-type",
    "include-schemes",
    "exclude-schemes",
];

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                if let Ok(val) = u8::try_from((h << 4) | l) {
                    out.push(val);
                }
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `list` filter options (handles both percent-encoded tokens and
/// space-separated `key=multi word value` options passed by `cupsd`).
fn parse_list_filters(opts: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut cur_key: Option<String> = None;
    let mut cur_val = String::new();

    for tok in opts.split_whitespace() {
        if let Some((k, v)) = tok.split_once('=') {
            let k_lower = k.to_ascii_lowercase();
            if KNOWN_FILTERS.contains(&k_lower.as_str()) {
                if let Some(prev_k) = cur_key.take() {
                    map.insert(prev_k, pct_decode(cur_val.trim()));
                }
                cur_key = Some(k_lower);
                cur_val = v.to_string();
                continue;
            }
        }
        if cur_key.is_some() {
            if !cur_val.is_empty() {
                cur_val.push(' ');
            }
            cur_val.push_str(tok);
        }
    }
    if let Some(prev_k) = cur_key {
        map.insert(prev_k, pct_decode(cur_val.trim()));
    }
    map
}

fn strip_parens(s: &str) -> &str {
    s.trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim()
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn matches_filters(p: &Ppd, filters: &HashMap<String, String>) -> bool {
    if let Some(inc) = filters.get("include-schemes") {
        let ok = inc
            .split(',')
            .any(|s| s.trim().eq_ignore_ascii_case(&p.scheme));
        if !ok {
            return false;
        }
    }
    if let Some(exc) = filters.get("exclude-schemes") {
        if exc
            .split(',')
            .any(|s| s.trim().eq_ignore_ascii_case(&p.scheme))
        {
            return false;
        }
    }
    if let Some(make) = filters.get("ppd-make") {
        if !p.make.eq_ignore_ascii_case(make) && !contains_ci(&p.make_and_model, make) {
            return false;
        }
    }
    if let Some(mm) = filters.get("ppd-make-and-model") {
        if !contains_ci(&p.make_and_model, mm) {
            return false;
        }
    }
    if let Some(prod) = filters.get("ppd-product") {
        let want = strip_parens(prod);
        let have = strip_parens(&p.product);
        if !have.eq_ignore_ascii_case(want) && !contains_ci(have, want) {
            return false;
        }
    }
    if let Some(psv) = filters.get("ppd-psversion") {
        if !contains_ci(&p.psversion, strip_parens(psv)) {
            return false;
        }
    }
    if let Some(lang) = filters.get("ppd-natural-language") {
        let want = lang.split(['-', '_']).next().unwrap_or(lang);
        let have = p
            .natural_language
            .split(['-', '_'])
            .next()
            .unwrap_or(&p.natural_language);
        if !have.eq_ignore_ascii_case(want) {
            return false;
        }
    }
    if let Some(devid) = filters.get("ppd-device-id") {
        if p.device_id.is_empty() {
            return false;
        }
        // Match either full substring or MFG/MDL pair overlap.
        let direct = contains_ci(&p.device_id, devid);
        let kv_match = devid
            .split(';')
            .filter_map(|part| part.split_once(':'))
            .filter(|(k, v)| {
                !v.trim().is_empty()
                    && (k.trim().eq_ignore_ascii_case("MFG")
                        || k.trim().eq_ignore_ascii_case("MDL"))
            })
            .all(|(k, v)| contains_ci(&p.device_id, &format!("{}:{}", k.trim(), v.trim())));
        if !direct && !kv_match {
            return false;
        }
    }
    if let Some(ty) = filters.get("ppd-type") {
        if !p.kind.eq_ignore_ascii_case(ty) && !p.scheme.eq_ignore_ascii_case(ty) {
            return false;
        }
    }
    true
}

fn collect(drv_dirs: &[PathBuf], ppd_dirs: &[PathBuf]) -> Vec<Ppd> {
    let mut v = vec![everywhere_entry(), generic_entry()];
    let mut seen_drv = HashSet::new();
    for d in drv_dirs {
        scan_drv_dir(d, d, 0, &mut seen_drv, &mut v);
    }
    let mut seen_ppd = HashSet::new();
    for d in ppd_dirs {
        scan_ppd_dir(d, d, 0, &mut seen_ppd, &mut v);
    }
    v
}

fn run_cli(
    args: &[String],
    drv_env: Option<&str>,
    ppd_env: Option<&str>,
    out: &mut impl Write,
) -> i32 {
    let mode = args.get(1).map_or("", String::as_str);
    let drv_dirs = drv_roots_from(drv_env, ppd_env);
    let ppd_dirs: Vec<PathBuf> = ppd_env
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .into_iter()
        .collect();

    match mode {
        "list" => {
            let limit: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
            let opts = args.get(4..).map(|o| o.join(" ")).unwrap_or_default();
            let filters = parse_list_filters(&opts);
            let mut n = 0usize;
            for p in collect(&drv_dirs, &ppd_dirs) {
                if limit != 0 && n >= limit {
                    break;
                }
                if !matches_filters(&p, &filters) {
                    continue;
                }
                let _ = writeln!(
                    out,
                    "ppd \"{}\" \"{}\" \"{}\" \"{}\" \"{}\" \"{}\"",
                    p.name, p.make_and_model, p.device_id, p.product, p.psversion, p.scheme
                );
                n += 1;
            }
            0
        }
        "cat" => {
            let name = args.get(2).map_or("", String::as_str);
            match name {
                "everywhere" => {
                    let _ = out.write_all(driverless_ppd().as_bytes());
                    0
                }
                _ if name.starts_with("drv:///") => {
                    if let Some(p) = drv_ppd_in(name, &drv_dirs) {
                        let _ = out.write_all(p.as_bytes());
                        0
                    } else {
                        eprintln!("ERROR: PPD \"{name}\" not found.");
                        1
                    }
                }
                _ => {
                    if let Some(bytes) = read_ppd_cat(name, &ppd_dirs) {
                        let _ = out.write_all(&bytes);
                        0
                    } else {
                        eprintln!("ERROR: PPD \"{name}\" not found.");
                        1
                    }
                }
            }
        }
        _ => {
            eprintln!("Usage: cups-driverd cat ppd-name");
            eprintln!("Usage: cups-driverd list request_id limit options");
            1
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let drv_env = std::env::var("DRVROOT").ok();
    let ppd_env = std::env::var("PPDDIR").ok();
    let code = run_cli(
        &args,
        drv_env.as_deref(),
        ppd_env.as_deref(),
        &mut io::stdout().lock(),
    );
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid RFC 1952 gzip archive using a stored (uncompressed) DEFLATE
    /// block, plus test dynamic/fixed Huffman streams via real gzip fixtures.
    fn make_stored_gzip(payload: &[u8]) -> Vec<u8> {
        let mut gz = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0xff];
        let len = u16::try_from(payload.len()).unwrap();
        let nlen = !len;
        gz.push(0x01); // BFINAL=1, BTYPE=00 (stored)
        gz.extend_from_slice(&len.to_le_bytes());
        gz.extend_from_slice(&nlen.to_le_bytes());
        gz.extend_from_slice(payload);
        gz.extend_from_slice(&crc32_ieee(payload).to_le_bytes());
        let payload_len = u32::try_from(payload.len()).unwrap();
        gz.extend_from_slice(&payload_len.to_le_bytes());
        gz
    }

    #[test]
    fn gunzip_handles_stored_fixed_dynamic_and_rejects_corrupt() {
        let sample =
            b"*PPD-Adobe: \"4.3\"\n*Manufacturer: \"Acme\"\n*NickName: \"Acme Laser 5000\"\n";
        let gz_stored = make_stored_gzip(sample);
        assert_eq!(gunzip_bounded(&gz_stored, MAX_PPD_BYTES).unwrap(), sample);

        // Enforce anti-bomb size limit.
        assert!(gunzip_bounded(&gz_stored, 10).is_err());

        // Real gzip (dynamic/fixed Huffman with FNAME flag) generated by standard gzip:
        // Exercise `gzip -c` if installed OR a real pre-encoded dynamic-Huffman gzip fixture.
        // Real RFC 1952 gzip of b"hello hello hello hello hello\n" (fixed Huffman):
        let fixed_gz: &[u8] = &[
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcb, 0x48, 0xcd, 0xc9,
            0xc9, 0x57, 0xc8, 0xc0, 0x4e, 0x72, 0x01, 0x00, 0x68, 0x02, 0x31, 0x66, 0x1e, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(
            gunzip_bounded(fixed_gz, 1024).unwrap(),
            b"hello hello hello hello hello\n"
        );

        // Test FEXTRA + FNAME + FCOMMENT + FHCRC header flags with stored block.
        let mut fancy = vec![0x1f, 0x8b, 0x08, 0x1e, 0, 0, 0, 0, 0, 3];
        fancy.extend_from_slice(&[2, 0, b'X', b'Y']); // FEXTRA
        fancy.extend_from_slice(b"test.ppd\0"); // FNAME
        fancy.extend_from_slice(b"comment\0"); // FCOMMENT
        fancy.extend_from_slice(&[0, 0]); // FHCRC
        let body = b"abc";
        fancy.push(0x01);
        fancy.extend_from_slice(&3u16.to_le_bytes());
        fancy.extend_from_slice(&(!3u16).to_le_bytes());
        fancy.extend_from_slice(body);
        fancy.extend_from_slice(&crc32_ieee(body).to_le_bytes());
        fancy.extend_from_slice(&3u32.to_le_bytes());
        assert_eq!(gunzip_bounded(&fancy, 1024).unwrap(), b"abc");

        // Dynamic Huffman block (BTYPE=2 with repeat codes 16/17/18) via system `gzip`.
        if let Ok(mut child) = std::process::Command::new("gzip")
            .arg("-9")
            .arg("-c")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
        {
            use std::fmt::Write as _;
            let mut big_ppd = String::from(
                "*PPD-Adobe: \"4.3\"\n*Manufacturer: \"Canon\"\n*ModelName: \"PIXMA Pro\"\n",
            );
            for i in 0..60 {
                let _ = writeln!(
                    big_ppd,
                    "*Option{i:03} Val{i:03}/Label {i} XYZ!@#$%^&*()_+: \"<< /Param{i} {} >> setpagedevice\"",
                    i * 7
                );
            }
            child
                .stdin
                .take()
                .unwrap()
                .write_all(big_ppd.as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success());
            // Verify gzip actually used BTYPE=2 (dynamic Huffman).
            assert_eq!((out.stdout[10] >> 1) & 3, 2);
            let plain = gunzip_bounded(&out.stdout, MAX_PPD_BYTES).unwrap();
            assert_eq!(plain, big_ppd.as_bytes());
        }

        // Corrupt headers/stored-block/btype/CRC/length rejected.
        assert!(gunzip_bounded(b"not gzip", 1024).is_err());
        let mut bad_crc = gz_stored.clone();
        *bad_crc.last_mut().unwrap() ^= 0xff;
        assert!(gunzip_bounded(&bad_crc, 1024).is_err());
        let mut bad_btype = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 3, 0x07];
        bad_btype.extend_from_slice(&[0u8; 8]);
        assert!(gunzip_bounded(&bad_btype, 1024).is_err());
        let mut bad_nlen = vec![
            0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 3, 0x01, 1, 0, 0, 0, 0,
        ];
        bad_nlen.extend_from_slice(&[0u8; 8]);
        assert!(gunzip_bounded(&bad_nlen, 1024).is_err());
    }

    #[test]
    fn path_traversal_and_symlink_escape_rejected_in_cat_and_drv() {
        let base = std::env::temp_dir().join(format!("pw-driverd-sec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let ppd_dir = base.join("ppd");
        let drv_dir = base.join("drv");
        let secret = base.join("secret.ppd");
        std::fs::create_dir_all(ppd_dir.join("sub")).unwrap();
        std::fs::create_dir_all(drv_dir.join("sub")).unwrap();
        std::fs::write(&secret, b"TOP_SECRET_SHADOW_DATA").unwrap();

        let good_ppd = ppd_dir.join("sub/good.ppd");
        std::fs::write(
            &good_ppd,
            "*PPD-Adobe: \"4.3\"\n*Manufacturer: \"HP\"\n*NickName: \"HP Office\"\n*1284DeviceID: \"MFG:HP;MDL:Office;\"\n*LanguageVersion: French\n*Product: \"(HP Office)\"\n*PSVersion: \"(3010.00) 0\"\n",
        )
        .unwrap();

        // Symlink inside ppd_dir pointing OUTSIDE ppd_dir!
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&secret, ppd_dir.join("escape.ppd")).unwrap();
            // Symlink loop directory inside ppd_dir!
            std::os::unix::fs::symlink(&ppd_dir, ppd_dir.join("sub/loop")).unwrap();
            std::os::unix::fs::symlink(&drv_dir, drv_dir.join("sub/loop")).unwrap();
        }

        let ppd_str = ppd_dir.to_string_lossy().into_owned();
        let drv_str = drv_dir.to_string_lossy().into_owned();

        // Traversal, absolute path, symlink escape, and non-ppd files MUST all fail!
        for evil in [
            "/etc/passwd",
            "../secret.ppd",
            "sub/../../secret.ppd",
            "escape.ppd",
            "sub/good.txt",
            "drv:///../secret.drv/x.ppd",
            "drv:////etc/passwd/x.ppd",
            "drv:///sub/a.drv/../evil",
        ] {
            let mut out = Vec::new();
            let rc = run_cli(
                &["cups-driverd".into(), "cat".into(), evil.into()],
                Some(&drv_str),
                Some(&ppd_str),
                &mut out,
            );
            assert_eq!(rc, 1, "must reject evil cat target: {evil}");
            assert_eq!(out, [] as [u8; 0]);
        }

        // Valid relative PPD inside PPDDIR succeeds.
        let mut ok_out = Vec::new();
        assert_eq!(
            run_cli(
                &["cups-driverd".into(), "cat".into(), "sub/good.ppd".into()],
                Some(&drv_str),
                Some(&ppd_str),
                &mut ok_out,
            ),
            0
        );
        assert!(String::from_utf8(ok_out).unwrap().contains("HP Office"));

        // Directory scan does not hang on symlink loops and skips escape.ppd!
        let entries = collect(
            std::slice::from_ref(&drv_dir),
            std::slice::from_ref(&ppd_dir),
        );
        assert!(entries
            .iter()
            .any(|p| p.name == "sub/good.ppd" && p.natural_language == "fr"));
        assert!(!entries.iter().any(|p| p.name.contains("escape")));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn drv_include_subdir_ppd_gz_and_all_list_filters() {
        let base = std::env::temp_dir().join(format!("pw-driverd-full-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let ppd_dir = base.join("ppd/vendor");
        let drv_dir = base.join("drv/brand");
        std::fs::create_dir_all(&ppd_dir).unwrap();
        std::fs::create_dir_all(&drv_dir).unwrap();

        // Shared include file + subdir .drv file + blocked escape include.
        std::fs::write(
            base.join("drv/common.defs"),
            "Manufacturer \"Epson\"\nVersion \"2.1\"\nMediaSize Letter\nMediaSize A4\nMediaSize w288h432\nHWMargins 9 9 9 9\nDuplex normal\n",
        )
        .unwrap();
        std::fs::write(
            drv_dir.join("inkjet.drv"),
            "#include <common.defs>\n#include \"../../etc/passwd\"\nAttribute \"1284DeviceID\" \"\" \"MFG:Epson;MDL:EcoTank;\"\nFilter application/vnd.cups-raster 50 rastertoepson\nResolution - 8 90 0 0 \"600dpi/600 DPI\"\nColorModel RGB rgb chunked\nModelName \"EcoTank ET-2850\"\nPCFileName \"et2850.ppd\"\n",
        )
        .unwrap();

        // Real gzipped PPD file under subdir.
        let gz_ppd = "*PPD-Adobe: \"4.3\"\n*Manufacturer: \"Brother\"\n*ModelName: \"HL-L2350DW\"\n*NickName: \"Brother HL-L2350DW\"\n*1284DeviceID: \"MFG:Brother;MDL:HL-L2350DW;\"\n*Product: \"(HL-L2350DW)\"\n*PSVersion: \"(3010.00) 0\"\n*LanguageVersion: German\n*cupsFilter: \"application/vnd.cups-raster 50 rastertobr\"\n";
        std::fs::write(
            ppd_dir.join("brother.ppd.gz"),
            make_stored_gzip(gz_ppd.as_bytes()),
        )
        .unwrap();

        let drv_root = base.join("drv").to_string_lossy().into_owned();
        let ppd_root = base.join("ppd").to_string_lossy().into_owned();

        // cat compiled drv:///brand/inkjet.drv/et2850.ppd (subdir preserved + #include applied!)
        let mut drv_out = Vec::new();
        assert_eq!(
            run_cli(
                &[
                    "cups-driverd".into(),
                    "cat".into(),
                    "drv:///brand/inkjet.drv/et2850.ppd".into(),
                ],
                Some(&drv_root),
                Some(&ppd_root),
                &mut drv_out,
            ),
            0
        );
        let compiled = String::from_utf8(drv_out).unwrap();
        assert!(compiled.contains("*Manufacturer: \"Epson\""));
        assert!(compiled.contains("*ModelName: \"EcoTank ET-2850\""));
        assert!(compiled.contains("*DefaultPageSize: Letter"));
        assert!(compiled.contains("*PageSize w288h432/w288h432"));
        assert!(compiled.contains("*cupsFilter: \"application/vnd.cups-raster 50 rastertoepson\""));
        assert!(compiled.contains("*DefaultResolution: 600dpi"));
        assert!(compiled.contains("*DefaultColorModel: RGB"));
        assert!(compiled.contains("*DefaultDuplex: None"));

        // cat decompressed .ppd.gz
        let mut gz_out = Vec::new();
        assert_eq!(
            run_cli(
                &[
                    "cups-driverd".into(),
                    "cat".into(),
                    "vendor/brother.ppd.gz".into()
                ],
                Some(&drv_root),
                Some(&ppd_root),
                &mut gz_out,
            ),
            0
        );
        assert!(String::from_utf8(gz_out).unwrap().contains("HL-L2350DW"));

        // cat everywhere
        let mut eve_out = Vec::new();
        assert_eq!(
            run_cli(
                &["cups-driverd".into(), "cat".into(), "everywhere".into()],
                None,
                None,
                &mut eve_out,
            ),
            0
        );
        assert!(String::from_utf8(eve_out).unwrap().contains("ippeve.ppd"));

        // Test all list filters!
        let run_list = |opts: &str, limit: &str| -> String {
            let mut buf = Vec::new();
            assert_eq!(
                run_cli(
                    &[
                        "cups-driverd".into(),
                        "list".into(),
                        "1".into(),
                        limit.into(),
                        opts.into(),
                    ],
                    Some(&drv_root),
                    Some(&ppd_root),
                    &mut buf,
                ),
                0
            );
            String::from_utf8(buf).unwrap()
        };

        assert!(run_list("include-schemes=drv ppd-make=Epson", "0").contains("et2850.ppd"));
        assert!(!run_list("exclude-schemes=drv", "0").contains("everywhere"));
        assert!(run_list("ppd-natural-language=de", "0").contains("brother.ppd.gz"));
        assert!(run_list("ppd-make-and-model=Brother%20HL-L2350DW", "0").contains("brother.ppd.gz"));
        assert!(run_list(
            "ppd-product=(HL-L2350DW) ppd-psversion=3010.00 ppd-type=raster",
            "0"
        )
        .contains("brother.ppd.gz"));
        assert!(run_list("ppd-device-id=MFG:Epson;MDL:EcoTank;", "0").contains("et2850.ppd"));
        assert_eq!(run_list("", "1").lines().count(), 1);

        // Invalid mode prints usage & returns 1.
        let mut bad_out = Vec::new();
        assert_eq!(
            run_cli(
                &["cups-driverd".into(), "bad".into()],
                None,
                None,
                &mut bad_out
            ),
            1
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn metadata_languages_multimodel_drv_cycles_and_negative_filters() {
        // Language code table coverage.
        for (input, want) in [
            ("English", "en"),
            ("French", "fr"),
            ("German", "de"),
            ("Spanish", "es"),
            ("Italian", "it"),
            ("Japanese", "ja"),
            ("Chinese", "zh"),
            ("Korean", "ko"),
            ("Portuguese", "pt"),
            ("Russian", "ru"),
            ("Dutch", "nl"),
            ("Swedish", "sv"),
            ("Danish", "da"),
            ("Norwegian", "no"),
            ("Finnish", "fi"),
            ("Polish", "pl"),
            ("CustomLang", "customlang"),
        ] {
            assert_eq!(ppd_language_code(input), want);
        }

        // Metadata fallbacks: ShortNickName, ModelName-only, PDF filter, Fax, empty fallback.
        let p_short = parse_ppd_metadata(
            "*ShortNickName: \"Mini Print\"\n*cupsFilter2: \"application/pdf application/pdf 0 -\"\n",
            "mini.ppd",
        );
        assert_eq!(p_short.make_and_model, "Mini Print");
        assert_eq!(p_short.make, "Mini");
        assert_eq!(p_short.kind, "pdf");

        let p_fax = parse_ppd_metadata("*ModelName: \"FaxBox\"\n*cupsFax: True\n", "fax.ppd");
        assert_eq!(p_fax.make_and_model, "FaxBox");
        assert_eq!(p_fax.kind, "fax");

        let p_empty = parse_ppd_metadata("*% comment only\nplain line\n", "bare.ppd");
        assert_eq!(p_empty.make_and_model, "bare.ppd");

        // Negative filter assertions on every filter field.
        let p = everywhere_entry();
        for (k, v) in [
            ("include-schemes", "ppd"),
            ("exclude-schemes", "drv"),
            ("ppd-make", "Canon"),
            ("ppd-make-and-model", "Nonexistent"),
            ("ppd-product", "OtherProduct"),
            ("ppd-psversion", "9999.00"),
            ("ppd-natural-language", "ja"),
            ("ppd-device-id", "MFG:Nonexistent;MDL:Nope;"),
            ("ppd-type", "fax"),
        ] {
            let f = parse_list_filters(&format!("{k}={v}"));
            assert!(!matches_filters(&p, &f), "expected reject for {k}={v}");
        }
        // Empty device-id rejected when ppd-device-id filter is requested.
        let f_dev = parse_list_filters("ppd-device-id=MFG:HP;");
        assert!(!matches_filters(&p_empty, &f_dev));

        // Multi-model .drv with #include cycle guard and per-model HWMargins/DeviceID.
        let base = std::env::temp_dir().join(format!("pw-driverd-cyc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(
            base.join("a.defs"),
            "#include \"b.defs\"\nManufacturer \"Ricoh\"\n",
        )
        .unwrap();
        std::fs::write(base.join("b.defs"), "#include \"a.defs\"\n").unwrap();
        std::fs::write(
            base.join("multi.drv"),
            "#include \"a.defs\"\nModelName \"Model One\"\nPCFileName \"m1.ppd\"\nHWMargins 12 12 12 12\nAttribute \"1284DeviceID\" \"\" \"MFG:Ricoh;MDL:M1;\"\nModelName \"Model Two\"\nPCFileName \"m2.ppd\"\nMediaSize UnknownCustom\n",
        )
        .unwrap();

        let models = parse_drv(&base.join("multi.drv"), &base);
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].model_name, "Model One");
        assert_eq!(models[1].model_name, "Model Two");
        let compiled = compile_ppd(&models[0]);
        assert!(compiled.contains("*1284DeviceID: \"MFG:Ricoh;MDL:M1;\""));
        assert!(media_size_points("UnknownSize").is_none());
        assert_eq!(media_size_points("A4"), Some((595.0, 842.0)));

        // Sanitize embedded quotes/newlines.
        assert_eq!(sanitize_record_field("A \"B\"\r\nC\x07"), "A B  C");
        let _ = std::fs::remove_dir_all(&base);
    }
}
