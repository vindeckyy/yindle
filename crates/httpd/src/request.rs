//! Parsed HTTP request line + headers + body framing (in-memory or disk-spooled).

use std::io;
use std::path::{Path, PathBuf};

use crate::Headers;

/// HTTP version on the request line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    /// `HTTP/0.9` — no version token (upstream still tolerates this).
    V09,
    /// `HTTP/1.0` — close-by-default.
    V10,
    /// `HTTP/1.1` — keep-alive by default, `Host` required.
    V11,
    /// Anything else — `cupsd` answers `505 Not Supported`.
    Other,
}

/// Request method. Unknown methods parse as `Unknown` and the handler
/// decides (upstream maps unknown -> `HTTP_STATUS_ERROR` -> 400/501).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `OPTIONS` — used by RFC 2817 TLS upgrade (`OPTIONS *`).
    Options,
    /// `GET` — static files, CGIs, IPP-over-GET isn't a thing upstream.
    Get,
    /// `HEAD` — like GET, headers only.
    Head,
    /// `POST` — all IPP traffic.
    Post,
    /// `PUT` — document uploads (`Send-Document` uses POST upstream;
    /// PUT is used by `cupsPutFile`-style admin).
    Put,
    /// `DELETE` — admin file ops.
    Delete,
    /// `TRACE` — upstream rejects.
    Trace,
    /// `CONNECT` — upstream rejects.
    Connect,
    /// Anything else.
    Unknown,
}

impl Method {
    /// Parse a method token (case-sensitive, uppercase per RFC 9110;
    /// upstream `httpUpdate()` compares exactly).
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "OPTIONS" => Self::Options,
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "TRACE" => Self::Trace,
            "CONNECT" => Self::Connect,
            _ => Self::Unknown,
        }
    }

    /// Token used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Options => "OPTIONS",
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
            Self::Unknown => "",
        }
    }
}

/// A large request body streamed directly to a private (`0600`) temporary file
/// on disk so large print jobs never OOM RAM.
///
/// Automatically removes its temp file on [`Drop`] unless moved via [`Self::persist`].
#[derive(Debug)]
pub struct SpooledBody {
    path: Option<PathBuf>,
    len: u64,
}

impl SpooledBody {
    pub(crate) const fn new(path: PathBuf, len: u64) -> Self {
        Self {
            path: Some(path),
            len,
        }
    }

    /// Path to the temporary spool file on disk.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.path.as_deref().unwrap_or_else(|| Path::new(""))
    }

    /// Total length of the spooled payload in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Returns `true` if the spooled payload is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Open the spooled file for reading.
    pub fn open(&self) -> io::Result<std::fs::File> {
        std::fs::File::open(self.path())
    }

    /// Read the entire spooled file into memory.
    pub fn read_all(&self) -> io::Result<Vec<u8>> {
        std::fs::read(self.path())
    }

    /// Persist (rename) the temporary spool file to `dest`, disarming automatic cleanup.
    pub fn persist(mut self, dest: &Path) -> io::Result<()> {
        let Some(src) = self.path.take() else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "spooled body already moved",
            ));
        };
        if let Err(err) = std::fs::rename(&src, dest) {
            // Put path back so Drop still cleans up on rename failure.
            self.path = Some(src);
            return Err(err);
        }
        Ok(())
    }
}

impl Drop for SpooledBody {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Request body — either buffered in RAM or streamed to a temporary spool file.
#[derive(Debug)]
pub enum Body {
    /// No body.
    Empty,
    /// Buffered body (`Content-Length` or chunked-decoded).
    Bytes(Vec<u8>),
    /// Body extends to EOF — `Connection: close` semantics.
    UntilEof(Vec<u8>),
    /// Large body streamed to a `0600` temp file on disk (avoids OOM on large print jobs).
    Spooled(SpooledBody),
}

impl Body {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.byte_len() == 0
    }

    /// Exact payload length in bytes (works for both in-memory and spooled bodies).
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        match self {
            Self::Empty => 0,
            Self::Bytes(b) | Self::UntilEof(b) => b.len() as u64,
            Self::Spooled(s) => s.len(),
        }
    }

    /// In-memory byte slice (empty for [`Self::Empty`] and [`Self::Spooled`]).
    ///
    /// Callers accepting spooled bodies should check [`Self::spooled_path`] or
    /// call [`Self::read_all`].
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Empty | Self::Spooled(_) => &[],
            Self::Bytes(b) | Self::UntilEof(b) => b,
        }
    }

    /// `true` if this body was spooled to disk.
    #[must_use]
    pub const fn is_spooled(&self) -> bool {
        matches!(self, Self::Spooled(_))
    }

    /// Temporary file path if the body was spooled to disk.
    #[must_use]
    pub fn spooled_path(&self) -> Option<&Path> {
        match self {
            Self::Spooled(s) => Some(s.path()),
            _ => None,
        }
    }

    /// Extract ownership of the [`SpooledBody`] handle if spooled.
    #[must_use]
    pub fn into_spooled(self) -> Option<SpooledBody> {
        match self {
            Self::Spooled(s) => Some(s),
            _ => None,
        }
    }

    /// Return the full body bytes, reading from disk if spooled.
    pub fn read_all(&self) -> io::Result<Vec<u8>> {
        match self {
            Self::Empty => Ok(Vec::new()),
            Self::Bytes(b) | Self::UntilEof(b) => Ok(b.clone()),
            Self::Spooled(s) => s.read_all(),
        }
    }
}

/// A fully-parsed request (headers + body).
#[derive(Debug)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Raw method token as received (for `Unknown`).
    pub method_token: String,
    /// Request URI — absolute path or absolute URI; also `*` for
    /// `OPTIONS *` (TLS upgrade request).
    pub uri: String,
    /// HTTP version from the request line.
    pub version: HttpVersion,
    /// Header collection.
    pub headers: Headers,
    /// Request body (in-memory or spooled).
    pub body: Body,
    /// Whether the client asked for the connection to stay open,
    /// resolved against version + `Connection:` (upstream
    /// `HTTP_KEEPALIVE_*` state).
    pub keep_alive: bool,
    /// Whether the request demands a TLS upgrade (`OPTIONS *` +
    /// `Upgrade: TLS/1.x`, or a resource whose `<Location>` requires
    /// encryption — resolved by the daemon, not the server core).
    pub wants_tls_upgrade: bool,
}

impl Request {
    /// Content type, trimmed (for `application/ipp` dispatch).
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type")
    }

    /// `Content-Length` if present as a single valid non-negative ASCII integer.
    #[must_use]
    pub fn content_length(&self) -> Option<usize> {
        if self.headers.count("content-length") != 1 {
            return None;
        }
        let v = self.headers.get("content-length")?;
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        v.parse().ok()
    }
}
