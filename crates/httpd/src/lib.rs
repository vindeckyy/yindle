//! `httpd` — the HTTP/1.1 server core shared by `cupsd`.
//!
//! Mirrors the client-connection semantics of upstream
//! `scheduler/client.c`: request-line + header parsing,
//! `Transfer-Encoding: chunked` and `Content-Length` request bodies,
//! `Expect: 100-continue`, persistent connections (HTTP/1.1 default,
//! HTTP/1.0 with `Connection: keep-alive`), `Host` enforcement on 1.1,
//! and an RFC 2817 `Upgrade: TLS/1.x` seam with read-ahead buffer
//! preservation.
//!
//! Hardened against HTTP request smuggling, Slowloris header/body `DoS`,
//! response splitting (CRLF injection), DNS rebinding (`Host` validation),
//! and large-body OOM (configurable `max_body` + streaming disk spooling).

#![forbid(unsafe_code)]

mod headers;
mod request;
mod response;
mod server;

pub use headers::{is_valid_header_name, is_valid_header_value, HeaderError, Headers};
pub use request::{Body, HttpVersion, Method, Request, SpooledBody};
pub use response::{reason_phrase, Response, StatusCode};
pub use server::{
    read_body, serve_connection, serve_connection_with_config, validate_host, ConnectionOutcome,
    HostValidator, PrefixedStream, ServeError, ServerConfig, ServerOptions,
};

/// Maximum request line + header block size (32 KiB).
pub const MAX_HEADER_BLOCK: usize = 32 * 1024;

/// Default maximum request body size (64 MiB) when unspecified.
pub const DEFAULT_MAX_BODY: usize = 64 * 1024 * 1024;

/// Default threshold (1 MiB) above which [`ServerConfig`] spools request bodies
/// to a `0600` temporary file instead of keeping them in RAM.
pub const DEFAULT_SPOOL_THRESHOLD: usize = 1024 * 1024;

/// Maximum trailer lines accepted after a chunked request body.
pub const MAX_TRAILER_LINES: usize = 64;

/// Maximum cumulative bytes across all chunked trailer lines (8 KiB).
pub const MAX_TRAILER_BYTES: usize = 8 * 1024;
