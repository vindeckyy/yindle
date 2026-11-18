//! Bounded pure-Rust RFC 1952 (gzip) + RFC 1951 (DEFLATE) decompressor.
//!
//! Enforces strict maximum output size and expansion-ratio limits to defend
//! against zip-bomb payloads when clients submit IPP requests with
//! `compression=gzip`, with zero external dependencies and `#![forbid(unsafe_code)]`.

use std::fmt;

/// Default maximum decompressed document size (64 MiB).
pub const DEFAULT_MAX_DECOMPRESSED: usize = 64 * 1024 * 1024;
/// Default maximum decompression ratio once output passes the ratio floor.
pub const DEFAULT_MAX_RATIO: usize = 100;
/// Minimum decompressed output size before ratio checks kick in (1 MiB) so
/// small highly-compressible documents (e.g. blank pages) are never rejected.
const RATIO_CHECK_FLOOR: usize = 1024 * 1024;

/// Errors returned during gzip / DEFLATE decompression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GzipError {
    /// Truncated or malformed gzip header/trailer or DEFLATE bitstream.
    Corrupt(&'static str),
    /// Decompressed size or compression ratio exceeded safety limits.
    LimitExceeded(&'static str),
    /// CRC-32 or ISIZE trailer mismatch.
    ChecksumMismatch,
}

impl fmt::Display for GzipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt(m) => write!(f, "corrupt gzip stream: {m}"),
            Self::LimitExceeded(m) => write!(f, "gzip limit exceeded: {m}"),
            Self::ChecksumMismatch => write!(f, "gzip checksum or length mismatch"),
        }
    }
}

impl std::error::Error for GzipError {}

/// Decompress a gzip stream with default ratio guard and explicit `max_bytes`.
///
/// # Errors
/// Returns [`GzipError`] on invalid gzip/DEFLATE data, checksum mismatch, or
/// if output exceeds `max_bytes` or the zip-bomb ratio limit.
pub fn decompress_gzip(input: &[u8], max_bytes: usize) -> Result<Vec<u8>, GzipError> {
    decompress_gzip_with_limits(input, max_bytes, DEFAULT_MAX_RATIO, RATIO_CHECK_FLOOR)
}

/// Decompress a gzip stream with explicit `(max_bytes, max_ratio, ratio_floor)`.
///
/// # Errors
/// Returns [`GzipError`] on corrupt input, checksum mismatch, or limit breach.
pub fn decompress_gzip_with_limits(
    input: &[u8],
    max_bytes: usize,
    max_ratio: usize,
    ratio_floor: usize,
) -> Result<Vec<u8>, GzipError> {
    // RFC 1952 header: 10-byte fixed header + 8-byte trailer minimum.
    if input.len() < 18 {
        return Err(GzipError::Corrupt("stream shorter than gzip framing"));
    }
    if input[0] != 0x1f || input[1] != 0x8b {
        return Err(GzipError::Corrupt("bad gzip magic"));
    }
    if input[2] != 8 {
        return Err(GzipError::Corrupt("unsupported compression method"));
    }
    let flg = input[3];
    if flg & 0xe0 != 0 {
        return Err(GzipError::Corrupt("reserved header flags set"));
    }
    let mut pos = 10usize;
    let body_end = input.len() - 8;

    // FEXTRA
    if flg & 0x04 != 0 {
        if pos + 2 > body_end {
            return Err(GzipError::Corrupt("truncated FEXTRA length"));
        }
        let xlen = usize::from(u16::from_le_bytes([input[pos], input[pos + 1]]));
        pos += 2;
        if pos + xlen > body_end {
            return Err(GzipError::Corrupt("truncated FEXTRA data"));
        }
        pos += xlen;
    }
    // FNAME (NUL-terminated)
    if flg & 0x08 != 0 {
        pos = skip_cstr(input, pos, body_end)?;
    }
    // FCOMMENT (NUL-terminated)
    if flg & 0x10 != 0 {
        pos = skip_cstr(input, pos, body_end)?;
    }
    // FHCRC
    if flg & 0x02 != 0 {
        if pos + 2 > body_end {
            return Err(GzipError::Corrupt("truncated FHCRC"));
        }
        pos += 2;
    }

    let ratio_cap = input
        .len()
        .max(1)
        .saturating_mul(max_ratio.max(1))
        .max(ratio_floor);
    let effective_limit = max_bytes.min(ratio_cap);

    let mut br = BitReader::new(&input[pos..body_end]);
    let mut out = Vec::with_capacity(input.len().min(effective_limit));

    loop {
        let bfinal = br.read_bits(1)?;
        let btype = br.read_bits(2)?;
        match btype {
            0 => decode_stored(&mut br, &mut out, effective_limit)?,
            1 => {
                let (litlen, dist) = fixed_tables();
                decode_huffman(&mut br, &litlen, &dist, &mut out, effective_limit)?;
            }
            2 => {
                let (litlen, dist) = read_dynamic_tables(&mut br)?;
                decode_huffman(&mut br, &litlen, &dist, &mut out, effective_limit)?;
            }
            _ => return Err(GzipError::Corrupt("invalid DEFLATE block type 3")),
        }
        if bfinal != 0 {
            break;
        }
    }

    let trailer = &input[body_end..];
    let expected_crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let expected_isize = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    let actual_crc = crc32(&out);
    #[allow(clippy::cast_possible_truncation)]
    let actual_isize = out.len() as u32;
    if actual_crc != expected_crc || actual_isize != expected_isize {
        return Err(GzipError::ChecksumMismatch);
    }
    Ok(out)
}

fn skip_cstr(data: &[u8], start: usize, end: usize) -> Result<usize, GzipError> {
    let mut p = start;
    while p < end {
        if data[p] == 0 {
            return Ok(p + 1);
        }
        p += 1;
    }
    Err(GzipError::Corrupt("unterminated header string"))
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bitbuf: u32,
    bitcnt: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bitbuf: 0,
            bitcnt: 0,
        }
    }

    fn read_bits(&mut self, n: u8) -> Result<u32, GzipError> {
        while self.bitcnt < n {
            if self.pos >= self.data.len() {
                return Err(GzipError::Corrupt("unexpected EOF in bitstream"));
            }
            self.bitbuf |= u32::from(self.data[self.pos]) << self.bitcnt;
            self.pos += 1;
            self.bitcnt += 8;
        }
        let mask = if n == 32 { u32::MAX } else { (1u32 << n) - 1 };
        let val = self.bitbuf & mask;
        self.bitbuf >>= n;
        self.bitcnt -= n;
        Ok(val)
    }

    fn align_byte(&mut self) {
        let drop_bits = self.bitcnt % 8;
        self.bitbuf >>= drop_bits;
        self.bitcnt -= drop_bits;
    }

    fn read_aligned_u16(&mut self) -> Result<u16, GzipError> {
        let lo = self.read_bits(8)?;
        let hi = self.read_bits(8)?;
        #[allow(clippy::cast_possible_truncation)]
        Ok(((hi << 8) | lo) as u16)
    }

    fn read_aligned_bytes(&mut self, len: usize, out: &mut Vec<u8>) -> Result<(), GzipError> {
        // Drain any whole bytes already in bitbuf first.
        let mut remaining = len;
        while remaining > 0 && self.bitcnt >= 8 {
            #[allow(clippy::cast_possible_truncation)]
            out.push((self.bitbuf & 0xff) as u8);
            self.bitbuf >>= 8;
            self.bitcnt -= 8;
            remaining -= 1;
        }
        if self.pos + remaining > self.data.len() {
            return Err(GzipError::Corrupt("truncated stored block"));
        }
        out.extend_from_slice(&self.data[self.pos..self.pos + remaining]);
        self.pos += remaining;
        Ok(())
    }
}

fn decode_stored(br: &mut BitReader<'_>, out: &mut Vec<u8>, limit: usize) -> Result<(), GzipError> {
    br.align_byte();
    let len = br.read_aligned_u16()?;
    let nlen = br.read_aligned_u16()?;
    if len != !nlen {
        return Err(GzipError::Corrupt("stored block LEN/NLEN mismatch"));
    }
    let len = usize::from(len);
    if out.len().saturating_add(len) > limit {
        return Err(GzipError::LimitExceeded(
            "decompressed output exceeds limit",
        ));
    }
    br.read_aligned_bytes(len, out)
}

/// Canonical Huffman table up to 15-bit codes (RFC 1951 §3.2.2).
struct HuffTable {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl HuffTable {
    fn from_lengths(lengths: &[u8]) -> Result<Self, GzipError> {
        let mut counts = [0u16; 16];
        for &len in lengths {
            if len > 15 {
                return Err(GzipError::Corrupt("huffman code length > 15"));
            }
            if len > 0 {
                counts[usize::from(len)] = counts[usize::from(len)]
                    .checked_add(1)
                    .ok_or(GzipError::Corrupt("huffman count overflow"))?;
            }
        }
        // Check oversubscribed code space.
        let mut left: i32 = 1;
        for &c in &counts[1..] {
            left = (left << 1) - i32::from(c);
            if left < 0 {
                return Err(GzipError::Corrupt("oversubscribed huffman tree"));
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
                #[allow(clippy::cast_possible_truncation)]
                {
                    symbols[idx] = sym as u16;
                }
                offsets[usize::from(len)] = idx + 1;
            }
        }
        Ok(Self { counts, symbols })
    }

    fn decode(&self, br: &mut BitReader<'_>) -> Result<u16, GzipError> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for bits in 1..16 {
            #[allow(clippy::cast_possible_wrap)]
            let bit = br.read_bits(1)? as i32;
            code |= bit;
            let count = i32::from(self.counts[bits]);
            if code - count < first {
                #[allow(clippy::cast_sign_loss)]
                let pos = (index + (code - first)) as usize;
                return self
                    .symbols
                    .get(pos)
                    .copied()
                    .ok_or(GzipError::Corrupt("huffman symbol index OOB"));
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(GzipError::Corrupt("invalid huffman code"))
    }
}

fn fixed_tables() -> (HuffTable, HuffTable) {
    let mut litlen = [0u8; 288];
    litlen[..=143].fill(8);
    litlen[144..=255].fill(9);
    litlen[256..=279].fill(7);
    litlen[280..=287].fill(8);
    let dist = [5u8; 32];
    // Fixed tables are RFC 1951 constants and always valid.
    let lt = HuffTable::from_lengths(&litlen).unwrap_or(HuffTable {
        counts: [0; 16],
        symbols: Vec::new(),
    });
    let dt = HuffTable::from_lengths(&dist).unwrap_or(HuffTable {
        counts: [0; 16],
        symbols: Vec::new(),
    });
    (lt, dt)
}

fn read_dynamic_tables(br: &mut BitReader<'_>) -> Result<(HuffTable, HuffTable), GzipError> {
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let hlit = br.read_bits(5)? as usize + 257;
    let hdist = br.read_bits(5)? as usize + 1;
    let hclen = br.read_bits(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        return Err(GzipError::Corrupt("dynamic huffman counts out of range"));
    }

    let mut cl_lens = [0u8; 19];
    for &idx in ORDER.iter().take(hclen) {
        #[allow(clippy::cast_possible_truncation)]
        {
            cl_lens[idx] = br.read_bits(3)? as u8;
        }
    }
    let cl_table = HuffTable::from_lengths(&cl_lens)?;

    let total = hlit + hdist;
    let mut lens = Vec::with_capacity(total);
    while lens.len() < total {
        let sym = cl_table.decode(br)?;
        match sym {
            0..=15 => {
                #[allow(clippy::cast_possible_truncation)]
                lens.push(sym as u8);
            }
            16 => {
                let prev = *lens
                    .last()
                    .ok_or(GzipError::Corrupt("repeat with no prior length"))?;
                let rep = br.read_bits(2)? as usize + 3;
                if lens.len() + rep > total {
                    return Err(GzipError::Corrupt("code length repeat overflow"));
                }
                lens.resize(lens.len() + rep, prev);
            }
            17 => {
                let rep = br.read_bits(3)? as usize + 3;
                if lens.len() + rep > total {
                    return Err(GzipError::Corrupt("zero length repeat overflow"));
                }
                lens.resize(lens.len() + rep, 0);
            }
            18 => {
                let rep = br.read_bits(7)? as usize + 11;
                if lens.len() + rep > total {
                    return Err(GzipError::Corrupt("long zero repeat overflow"));
                }
                lens.resize(lens.len() + rep, 0);
            }
            _ => return Err(GzipError::Corrupt("invalid code-length symbol")),
        }
    }

    let litlen = HuffTable::from_lengths(&lens[..hlit])?;
    let dist = HuffTable::from_lengths(&lens[hlit..])?;
    Ok((litlen, dist))
}

fn decode_huffman(
    br: &mut BitReader<'_>,
    litlen: &HuffTable,
    dist: &HuffTable,
    out: &mut Vec<u8>,
    limit: usize,
) -> Result<(), GzipError> {
    const LEN_BASE: [u16; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    const LEN_EXTRA: [u8; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    const DIST_BASE: [u16; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    const DIST_EXTRA: [u8; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13,
    ];

    loop {
        let sym = litlen.decode(br)?;
        match sym.cmp(&256) {
            std::cmp::Ordering::Less => {
                if out.len() >= limit {
                    return Err(GzipError::LimitExceeded(
                        "decompressed output exceeds limit",
                    ));
                }
                #[allow(clippy::cast_possible_truncation)]
                out.push(sym as u8);
            }
            std::cmp::Ordering::Equal => return Ok(()),
            std::cmp::Ordering::Greater => {
                let li = usize::from(sym - 257);
                if li >= LEN_BASE.len() {
                    return Err(GzipError::Corrupt("invalid length symbol"));
                }
                let length = usize::from(LEN_BASE[li]) + br.read_bits(LEN_EXTRA[li])? as usize;
                let di = usize::from(dist.decode(br)?);
                if di >= DIST_BASE.len() {
                    return Err(GzipError::Corrupt("invalid distance symbol"));
                }
                let distance = usize::from(DIST_BASE[di]) + br.read_bits(DIST_EXTRA[di])? as usize;
                if distance == 0 || distance > out.len() {
                    return Err(GzipError::Corrupt("back-reference beyond output start"));
                }
                if out.len().saturating_add(length) > limit {
                    return Err(GzipError::LimitExceeded(
                        "decompressed output exceeds limit",
                    ));
                }
                for _ in 0..length {
                    let b = out[out.len() - distance];
                    out.push(b);
                }
            }
        }
    }
}

/// Standard IEEE 802.3 CRC-32 (RFC 1952 §8).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
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
