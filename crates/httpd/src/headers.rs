//! Case-insensitive ordered header collection with CRLF injection protection.
//!
//! Upstream keeps headers in `http_t` fields (`httpFields()`); we keep
//! an ordered vec — ordered because `Connection: Upgrade` +
//! `Upgrade:` pairing is order-relevant in some clients, and IPP
//! responses sometimes carry repeated headers.

/// Error returned when a header name or value violates HTTP/1.1 framing rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    /// Header name is empty or contains non-token bytes (whitespace, `:`, CTLs, etc.).
    #[error("invalid HTTP header name")]
    InvalidName,
    /// Header value contains `\r`, `\n`, or `\0` (response-splitting risk).
    #[error("invalid HTTP header value")]
    InvalidValue,
}

/// Returns `true` if `name` is a non-empty RFC 9110 HTTP token (`tchar+`).
///
/// Rejects whitespace (including space before `:`), `:`, `\r`, `\n`, and all CTLs.
#[must_use]
pub fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Returns `true` if `value` contains no `\r`, `\n`, or `\0` bytes.
#[must_use]
pub fn is_valid_header_value(value: &str) -> bool {
    !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// An ordered, case-insensitive header list.
#[derive(Debug, Clone, Default)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validated insert-or-replace (returns `Err` on invalid name or CR/LF/NUL in value).
    pub fn try_set(&mut self, name: &str, value: impl Into<String>) -> Result<(), HeaderError> {
        if !is_valid_header_name(name) {
            return Err(HeaderError::InvalidName);
        }
        let v = value.into();
        if !is_valid_header_value(&v) {
            return Err(HeaderError::InvalidValue);
        }
        for e in &mut self.entries {
            if e.0.eq_ignore_ascii_case(name) {
                e.1 = v;
                return Ok(());
            }
        }
        self.entries.push((name.to_string(), v));
        Ok(())
    }

    /// Validated append without replacing (returns `Err` on invalid name or CR/LF/NUL in value).
    pub fn try_push(&mut self, name: &str, value: impl Into<String>) -> Result<(), HeaderError> {
        if !is_valid_header_name(name) {
            return Err(HeaderError::InvalidName);
        }
        let v = value.into();
        if !is_valid_header_value(&v) {
            return Err(HeaderError::InvalidValue);
        }
        self.entries.push((name.to_string(), v));
        Ok(())
    }

    /// Insert or replace the first occurrence (case-insensitive).
    ///
    /// Silently refuses invalid names or values containing `\r`, `\n`, or `\0`
    /// to prevent HTTP response splitting / header injection.
    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        if let Err(err) = self.try_set(name, value) {
            tracing::warn!(header = name, error = %err, "blocked unsafe HTTP header in set()");
        }
    }

    /// Append without replacing (for multi-instance headers).
    ///
    /// Silently refuses invalid names or values containing `\r`, `\n`, or `\0`.
    pub fn push(&mut self, name: &str, value: impl Into<String>) {
        if let Err(err) = self.try_push(name, value) {
            tracing::warn!(header = name, error = %err, "blocked unsafe HTTP header in push()");
        }
    }

    /// Remove all occurrences matching `name` (case-insensitive).
    pub fn remove(&mut self, name: &str) {
        self.entries.retain(|e| !e.0.eq_ignore_ascii_case(name));
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.0.eq_ignore_ascii_case(name))
            .map(|e| e.1.as_str())
    }

    /// Iterate all values matching `name` (case-insensitive), in wire order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.entries
            .iter()
            .filter(move |e| e.0.eq_ignore_ascii_case(name))
            .map(|e| e.1.as_str())
    }

    /// Count how many occurrences of `name` exist (case-insensitive).
    #[must_use]
    pub fn count(&self, name: &str) -> usize {
        self.get_all(name).count()
    }

    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Iterate `(name, value)` in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|e| (e.0.as_str(), e.1.as_str()))
    }

    /// `Connection` token check across ALL `Connection` headers — handles
    /// `keep-alive`, `close`, `Upgrade`, and comma-separated lists.
    #[must_use]
    pub fn connection_has(&self, token: &str) -> bool {
        self.get_all("connection")
            .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }

    /// Apply baseline defense-in-depth HTTP security headers (preserving any
    /// caller-supplied `Content-Security-Policy`).
    pub fn apply_security_headers(&mut self) {
        self.set("X-Content-Type-Options", "nosniff");
        self.set("X-Frame-Options", "DENY");
        self.set("Referrer-Policy", "no-referrer");
        if !self.contains("content-security-policy") {
            self.set(
                "Content-Security-Policy",
                "default-src 'self'; frame-ancestors 'none'",
            );
        }
    }
}
