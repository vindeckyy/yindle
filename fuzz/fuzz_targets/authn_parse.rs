#![no_main]
//! Fuzz `authn`: HTTP `Authorization` header parsing (`Basic` / `Bearer` /
//! arbitrary schemes), `Credentials` `Debug` secret redaction, `Bearer`
//! token-verifier dispatch, and `basic_challenge` / `bearer_challenge` escaping
//! against HTTP header and quote injection.

use std::sync::Arc;

use authn::{
    basic_challenge, bearer_challenge, parse, AuthBackend, Authenticator, Credentials,
    TokenVerifier, VerifiedIdentity,
};
use libfuzzer_sys::fuzz_target;

struct FuzzTokenVerifier;

impl TokenVerifier for FuzzTokenVerifier {
    fn verify_bearer(&self, token: &str) -> Option<VerifiedIdentity> {
        if token.len().is_multiple_of(2) {
            Some(VerifiedIdentity {
                user: "svc-fuzz".into(),
                groups: vec!["lpadmin".into()],
            })
        } else {
            None
        }
    }
}

/// Verify an escaped RFC 7230/7617 quoted-string inner payload has no unescaped
/// quotes, no trailing lone backslash, and no ASCII control bytes.
fn assert_valid_quoted_inner(inner: &str) {
    assert!(!inner.bytes().any(|b| b < 0x20 || b == 0x7f));
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let escaped = chars.next().expect("dangling backslash in quoted-string");
            assert!(escaped == '\\' || escaped == '"');
        } else {
            assert_ne!(c, '"', "unescaped quote in challenge parameter");
        }
    }
}

fn check_parsed(creds: &Credentials, auth: &Authenticator) {
    if creds.scheme.eq_ignore_ascii_case("basic") {
        assert!(!creds.user.contains('\0'));
        assert!(!creds.secret.contains('\0'));
    } else {
        // Pure in-memory Bearer/other scheme dispatch (never touches PAM or /etc/shadow).
        let _ = auth.authenticate(creds);
    }

    // Secret must always be redacted in Debug output.
    let dbg = format!("{creds:?}");
    assert!(dbg.contains("[REDACTED]"));
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let auth = Authenticator::new(AuthBackend::ShadowOnly)
        .with_token_verifier(Arc::new(FuzzTokenVerifier));

    // 1. Raw Authorization header parsing + synthesized Basic/Bearer headers.
    if let Some(creds) = parse(&text) {
        check_parsed(&creds, &auth);
    }
    let basic_hdr = format!("Basic {text}");
    if let Some(creds) = parse(&basic_hdr) {
        check_parsed(&creds, &auth);
    }
    let bearer_hdr = format!("Bearer {text}");
    if let Some(creds) = parse(&bearer_hdr) {
        check_parsed(&creds, &auth);
    }

    // Verify Debug redaction against a unique sentinel secret.
    const SENTINEL: &str = "PW_FUZZ_SECRET_SENTINEL_9f8e7d6c";
    if !text.contains(SENTINEL) {
        let synthetic = Credentials {
            scheme: text.to_string(),
            user: text.to_string(),
            secret: SENTINEL.to_string(),
        };
        let dbg = format!("{synthetic:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(SENTINEL));
    }

    // 2. basic_challenge escaping (no CR/LF/NUL/CTL or quote breakout).
    let basic_chal = basic_challenge(&text);
    assert!(basic_chal.starts_with("Basic realm=\"") && basic_chal.ends_with('"'));
    assert_valid_quoted_inner(&basic_chal["Basic realm=\"".len()..basic_chal.len() - 1]);

    // 3. bearer_challenge escaping (realm only + realm with scope).
    let bearer_only = bearer_challenge(&text, None);
    assert!(bearer_only.starts_with("Bearer realm=\"") && bearer_only.ends_with('"'));
    assert_valid_quoted_inner(&bearer_only["Bearer realm=\"".len()..bearer_only.len() - 1]);

    let (realm, scope) = match text.split_once('\0') {
        Some((r, s)) => (r, s),
        None => (text.as_ref(), text.as_ref()),
    };
    let bearer_scoped = bearer_challenge(realm, Some(scope));
    assert!(bearer_scoped.starts_with("Bearer realm=\""));
    assert!(!bearer_scoped.bytes().any(|b| b < 0x20 || b == 0x7f));
});
