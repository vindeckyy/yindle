#![no_main]
//! Fuzz `httpd`: HTTP/1.1 request framing, anti-smuggling header validation,
//! `Transfer-Encoding: chunked` decoding (with trailers), RFC 2817 upgrade
//! leftover-buffer handoff, `HostValidator` DNS-rebinding defense, and response
//! header CRLF-injection defense.

use std::io;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Duration;

use httpd::{
    is_valid_header_name, is_valid_header_value, read_body, reason_phrase,
    serve_connection_with_config, validate_host, Body, ConnectionOutcome, Headers, HostValidator,
    HttpVersion, Method, PrefixedStream, Request, Response, ServerConfig, StatusCode,
};
use libfuzzer_sys::fuzz_target;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::runtime::{Builder, Runtime};

const MAX_FUZZ_BODY: usize = 16 * 1024;
const MAX_REQUESTS_PER_CONN: u32 = 16;

fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("failed to build tokio current_thread runtime")
    })
}

/// Zero-overhead in-memory `AsyncRead + AsyncWrite` stream for fuzzing `httpd`.
struct MemStream<'a> {
    input: &'a [u8],
    pos: usize,
    chunk_size: usize,
    written: usize,
}

impl<'a> MemStream<'a> {
    const fn new(input: &'a [u8], chunk_size: usize) -> Self {
        Self {
            input,
            pos: 0,
            chunk_size,
            written: 0,
        }
    }
}

impl AsyncRead for MemStream<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos >= self.input.len() {
            return Poll::Ready(Ok(()));
        }
        let rem = &self.input[self.pos..];
        let take = rem.len().min(buf.remaining()).min(self.chunk_size);
        buf.put_slice(&rem[..take]);
        self.pos += take;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MemStream<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written = self.written.saturating_add(buf.len());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fuzz_target!(|data: &[u8]| {
    // 1. Direct synchronous fuzzing of HostValidator, Headers, Method, and Response encoding.
    let text = String::from_utf8_lossy(data);
    let aliases = vec!["*.corp.example".to_string(), "alias.local".to_string()];
    let validator_allow = HostValidator::new(Some("print.example.com".into()), aliases.clone());
    let mut validator_no_lb = validator_allow.clone();
    validator_no_lb.allow_loopback = false;

    let allowed = validator_allow.is_allowed(&text);
    let _ = validator_no_lb.is_allowed(&text);
    let _ = validate_host(&text, Some("print.example.com"), &aliases);

    // Trimmed Host values with CTLs or URI authority/path delimiters must never be allowed.
    let trimmed = text.trim();
    if trimmed
        .bytes()
        .any(|b| b <= 0x20 || b == 0x7f || matches!(b, b'@' | b'/' | b'\\' | b'?' | b'#'))
    {
        assert!(!allowed);
    }

    let (hname, hval) = match text.split_once(':') {
        Some((k, v)) => (k, v),
        None => (text.as_ref(), text.as_ref()),
    };
    let mut hdrs = Headers::new();
    let set_res = hdrs.try_set(hname, hval);
    if hval.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        assert!(set_res.is_err());
    }
    if set_res.is_ok() {
        assert!(is_valid_header_name(hname));
        assert!(is_valid_header_value(hval));
    }
    let _ = hdrs.try_push(hname, hval);
    hdrs.set(hname, hval);
    hdrs.push(hname, hval);
    hdrs.apply_security_headers();

    let mut resp = Response::status(StatusCode::OK);
    resp.headers = hdrs;
    let wire = resp.encode(false, true);
    if let Some(end) = wire.windows(4).position(|w| w == b"\r\n\r\n") {
        assert!(!wire[..end].contains(&0));
    }
    let _ = Method::parse(hname);
    let code = u16::from_be_bytes([
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
    ]);
    let _ = reason_phrase(code);

    // 2. Full HTTP/1.1 connection framing + chunked decoding over MemStream.
    // Exercise 1-byte and small partial reads only on short inputs to avoid O(N^2) fuzzing slowdowns.
    let chunk_size = if data.len() <= 512 {
        match data.last().copied().unwrap_or(0) % 4 {
            0 => 4096,
            1 => 1,
            2 => 7,
            _ => 64,
        }
    } else {
        4096
    };
    let use_host_validator = data.len() % 2 == 1;

    runtime().block_on(async {
        let cfg = ServerConfig {
            server_tokens: "CUPS/2.5 (fuzz)".into(),
            max_body: Some(MAX_FUZZ_BODY),
            spool_threshold: None,
            spool_dir: None,
            idle_timeout: Duration::from_secs(5),
            keep_alive: true,
            keep_alive_timeout: Duration::from_secs(5),
            header_timeout: Duration::from_secs(5),
            body_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            host_validator: if use_host_validator {
                Some(validator_allow)
            } else {
                None
            },
        };

        let mut stream = MemStream::new(data, chunk_size);
        let mut handled = 0u32;
        let outcome = serve_connection_with_config(&mut stream, &cfg, |req| {
            handled += 1;
            assert!(req.body.byte_len() <= MAX_FUZZ_BODY as u64);
            assert!(req.headers.count("content-length") <= 1);
            assert!(
                !(req.headers.count("transfer-encoding") > 0
                    && req.headers.count("content-length") > 0)
            );
            if req.version == HttpVersion::V11 {
                assert_eq!(req.headers.count("host"), 1);
            }
            let _ = req.content_type();
            let _ = req.content_length();
            let _ = req.body.as_bytes();
            let _ = req.body.is_empty();

            if req.wants_tls_upgrade {
                return Response::status(StatusCode::SWITCHING_PROTOCOLS);
            }
            let mut r = Response::with_body(StatusCode::OK, "text/plain", Vec::new())
                .with_security_headers();
            if handled >= MAX_REQUESTS_PER_CONN {
                r.headers.set("Connection", "close");
            }
            r
        })
        .await;

        if let Ok(ConnectionOutcome::UpgradeTls { leftover }) = outcome {
            let mut prefixed = PrefixedStream::new(leftover, MemStream::new(&[], 64));
            let _ = prefixed.remaining_prefix();
            let mut drained = Vec::new();
            let _ = prefixed.read_to_end(&mut drained).await;
            let _ = prefixed.into_inner();
        }

        // 3. Direct chunked body decoder fuzzing on raw bytes.
        let mut chunk_headers = Headers::new();
        chunk_headers.set("Host", "localhost");
        chunk_headers.set("Transfer-Encoding", "chunked");
        let mut chunk_req = Request {
            method: Method::Post,
            method_token: "POST".into(),
            uri: "/printers/fuzz".into(),
            version: HttpVersion::V11,
            headers: chunk_headers,
            body: Body::Empty,
            keep_alive: true,
            wants_tls_upgrade: false,
        };
        let mut prebuf = Vec::new();
        let mut chunk_stream = MemStream::new(data, chunk_size);
        if read_body(&mut chunk_stream, &mut prebuf, &mut chunk_req, 8 * 1024)
            .await
            .is_ok()
        {
            assert!(chunk_req.body.byte_len() <= 8 * 1024);
        }
    });
});
