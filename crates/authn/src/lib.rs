//! Authentication — HTTP `Authorization` parsing, PAM-first credential
//! verification with hardened shadow fallback, and extensible Bearer/OAuth
//! token verification (`scheduler/auth.c`).
//!
//! - `Basic` credentials decode `Authorization: Basic base64(user:pass)` and
//!   verify via PAM (`libpam.so.0`, default service `"cups"`) when available,
//!   falling back to reentrant shadow verification (`sys::check_password`)
//!   only when PAM is unavailable on the host.
//! - `Bearer` tokens delegate to a caller-supplied [`TokenVerifier`] (for
//!   enterprise `OAuth2`/OIDC integration).
//! - [`Credentials`] redacts its `secret` field in `Debug` output.

use base64::Engine;
use std::fmt;
use std::sync::Arc;

/// Decoded HTTP `Authorization` credentials.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    /// Auth scheme: `Basic`, `Bearer`, `Negotiate`, …
    pub scheme: String,
    /// Username (`Basic`) or empty (`Bearer`/`Negotiate`).
    pub user: String,
    /// Password (`Basic`) or raw token (`Bearer`/`Negotiate`) — always redacted
    /// in `Debug` output.
    pub secret: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("scheme", &self.scheme)
            .field("user", &self.user)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Configured backend strategy for verifying `Basic` username/password pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthBackend {
    /// Try PAM (`service`, e.g. `"cups"`) first; fall back to local shadow
    /// verification ONLY when `libpam.so.0` is unavailable (`PamOutcome::Unavailable`).
    /// An explicit PAM denial (`PamOutcome::Denied`) never falls back to shadow.
    PamOrShadow {
        /// PAM service name (usually `"cups"`).
        service: String,
    },
    /// Require PAM authentication; never fall back to shadow.
    PamOnly {
        /// PAM service name (usually `"cups"`).
        service: String,
    },
    /// Verify directly against `/etc/shadow` via `sys::check_password`.
    ShadowOnly,
}

impl Default for AuthBackend {
    fn default() -> Self {
        Self::PamOrShadow {
            service: "cups".to_string(),
        }
    }
}

/// Verified user identity returned by a [`TokenVerifier`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// Authenticated username / subject.
    pub user: String,
    /// Group memberships associated with the token/user.
    pub groups: Vec<String>,
}

/// Enterprise extensibility hook for validating `Authorization: Bearer <token>`
/// credentials (e.g., `OAuth2` token introspection or OIDC JWT verification).
pub trait TokenVerifier: Send + Sync {
    /// Validate a Bearer token and return the authenticated identity if valid.
    fn verify_bearer(&self, token: &str) -> Option<VerifiedIdentity>;
}

/// Configurable authentication engine combining local `Basic` auth (PAM/shadow)
/// with an optional enterprise [`TokenVerifier`] for `Bearer` tokens.
#[derive(Clone)]
pub struct Authenticator {
    backend: AuthBackend,
    token_verifier: Option<Arc<dyn TokenVerifier>>,
}

impl fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authenticator")
            .field("backend", &self.backend)
            .field("has_token_verifier", &self.token_verifier.is_some())
            .finish()
    }
}

impl Default for Authenticator {
    fn default() -> Self {
        Self::new(AuthBackend::default())
    }
}

impl Authenticator {
    /// Create a new `Authenticator` using `backend` for Basic authentication.
    #[must_use]
    pub fn new(backend: AuthBackend) -> Self {
        Self {
            backend,
            token_verifier: None,
        }
    }

    /// Attach a [`TokenVerifier`] for `Authorization: Bearer` tokens.
    #[must_use]
    pub fn with_token_verifier(mut self, verifier: Arc<dyn TokenVerifier>) -> Self {
        self.token_verifier = Some(verifier);
        self
    }

    /// Currently configured `Basic` auth backend.
    #[must_use]
    pub fn backend(&self) -> &AuthBackend {
        &self.backend
    }

    /// Verify `creds` and return `(username, groups)` on success.
    #[must_use]
    pub fn authenticate(&self, creds: &Credentials) -> Option<(String, Vec<String>)> {
        authenticate_with(creds, &self.backend, self.token_verifier.as_deref())
    }
}

/// Parse an HTTP `Authorization` header value.
#[must_use]
pub fn parse(header: &str) -> Option<Credentials> {
    let trimmed = header.trim();
    let (scheme, rest) = trimmed.split_once(|c: char| c.is_ascii_whitespace())?;
    let param = rest.trim();
    if scheme.is_empty() || param.is_empty() {
        return None;
    }
    if scheme.eq_ignore_ascii_case("basic") {
        let dec = base64::engine::general_purpose::STANDARD
            .decode(param)
            .ok()?;
        let s = String::from_utf8(dec).ok()?;
        let (u, p) = s.split_once(':')?;
        if u.contains('\0') || p.contains('\0') {
            return None;
        }
        Some(Credentials {
            scheme: "Basic".into(),
            user: u.to_string(),
            secret: p.to_string(),
        })
    } else {
        // Bearer/Negotiate: token only, no local password.
        Some(Credentials {
            scheme: scheme.to_string(),
            user: String::new(),
            secret: param.to_string(),
        })
    }
}

/// Verify `Basic` `(user, password)` against `backend`, returning
/// `(username, unix_groups)` on success.
#[must_use]
pub fn authenticate_basic(
    user: &str,
    password: &str,
    backend: &AuthBackend,
) -> Option<(String, Vec<String>)> {
    authenticate_basic_with_ops(
        user,
        password,
        backend,
        sys::pam_authenticate,
        sys::check_password,
        sys::groups_of,
    )
}

fn authenticate_basic_with_ops<FPam, FShadow, FGroups>(
    user: &str,
    password: &str,
    backend: &AuthBackend,
    pam_fn: FPam,
    shadow_fn: FShadow,
    groups_fn: FGroups,
) -> Option<(String, Vec<String>)>
where
    FPam: Fn(&str, &str, &str) -> sys::PamOutcome,
    FShadow: Fn(&str, &str) -> bool,
    FGroups: Fn(&str) -> Vec<String>,
{
    if user.is_empty() || password.is_empty() || user.contains('\0') || password.contains('\0') {
        return None;
    }
    let ok = match backend {
        AuthBackend::PamOrShadow { service } => match pam_fn(service, user, password) {
            sys::PamOutcome::Authenticated => true,
            sys::PamOutcome::Denied(_) => false,
            sys::PamOutcome::Unavailable => shadow_fn(user, password),
        },
        AuthBackend::PamOnly { service } => {
            matches!(
                pam_fn(service, user, password),
                sys::PamOutcome::Authenticated
            )
        }
        AuthBackend::ShadowOnly => shadow_fn(user, password),
    };
    if !ok {
        return None;
    }
    Some((user.to_string(), groups_fn(user)))
}

/// Verify `creds` using `backend` (for `Basic`) and optional `token_verifier`
/// (for `Bearer`), returning `(username, groups)` on success.
#[must_use]
pub fn authenticate_with(
    creds: &Credentials,
    backend: &AuthBackend,
    token_verifier: Option<&dyn TokenVerifier>,
) -> Option<(String, Vec<String>)> {
    if creds.scheme.eq_ignore_ascii_case("basic") {
        authenticate_basic(&creds.user, &creds.secret, backend)
    } else if creds.scheme.eq_ignore_ascii_case("bearer") {
        if creds.secret.is_empty() {
            return None;
        }
        let id = token_verifier?.verify_bearer(&creds.secret)?;
        if id.user.is_empty() {
            return None;
        }
        Some((id.user, id.groups))
    } else {
        None
    }
}

/// Verify credentials using the default backend (`PAM` `"cups"` with safe
/// shadow fallback when PAM is unavailable) and return `(username, groups)`.
#[must_use]
pub fn authenticate(creds: &Credentials) -> Option<(String, Vec<String>)> {
    authenticate_with(creds, &AuthBackend::default(), None)
}

/// Escape an RFC 7230 / RFC 7617 quoted-string parameter value, stripping CR/LF
/// and ASCII control characters to prevent HTTP response header injection.
fn escape_quoted_param(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_control() {
            continue;
        }
        if ch == '\\' || ch == '"' {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// `Basic realm="…"` challenge for a `401 Unauthorized` `WWW-Authenticate` header.
///
/// Escapes `\` and `"` and strips CR/LF and control characters from `realm`.
#[must_use]
pub fn basic_challenge(realm: &str) -> String {
    let escaped = escape_quoted_param(realm);
    format!("Basic realm=\"{escaped}\"")
}

/// `Bearer realm="…"` (with optional `scope="…"`) challenge for a `401` header.
///
/// Escapes `\` and `"` and strips CR/LF and control characters from `realm` and `scope`.
#[must_use]
pub fn bearer_challenge(realm: &str, scope: Option<&str>) -> String {
    let escaped_realm = escape_quoted_param(realm);
    match scope.filter(|s| !s.is_empty()) {
        Some(sc) => {
            let escaped_scope = escape_quoted_param(sc);
            format!("Bearer realm=\"{escaped_realm}\", scope=\"{escaped_scope}\"")
        }
        None => format!("Bearer realm=\"{escaped_realm}\""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticBearerVerifier {
        expected_token: String,
        identity: VerifiedIdentity,
    }

    impl TokenVerifier for StaticBearerVerifier {
        fn verify_bearer(&self, token: &str) -> Option<VerifiedIdentity> {
            if token == self.expected_token {
                Some(self.identity.clone())
            } else {
                None
            }
        }
    }

    #[test]
    fn credentials_debug_redacts_secret() {
        let creds = Credentials {
            scheme: "Basic".into(),
            user: "alice".into(),
            secret: "super-secret-password-999".into(),
        };
        let dbg = format!("{creds:?}");
        assert!(dbg.contains("alice"));
        assert!(dbg.contains("Basic"));
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("super-secret-password-999"));
    }

    #[test]
    fn parse_basic_bearer_and_malformed_headers() {
        // Basic alice:s3cr3t -> base64 "YWxpY2U6czNjcjN0"
        let b64 = base64::engine::general_purpose::STANDARD.encode("alice:s3cr3t");
        let creds = parse(&format!("Basic {b64}")).unwrap();
        assert_eq!(creds.scheme, "Basic");
        assert_eq!(creds.user, "alice");
        assert_eq!(creds.secret, "s3cr3t");

        // Case-insensitive scheme + colon inside password
        let b64_colon = base64::engine::general_purpose::STANDARD.encode("bob:p@ss:w0rd");
        let creds2 = parse(&format!("  bAsIc   {b64_colon}  ")).unwrap();
        assert_eq!(creds2.user, "bob");
        assert_eq!(creds2.secret, "p@ss:w0rd");

        // Bearer and Negotiate
        let bearer = parse("Bearer eyJhbGciOiJIUzI1NiJ9.tok").unwrap();
        assert_eq!(bearer.scheme, "Bearer");
        assert_eq!(bearer.user, "");
        assert_eq!(bearer.secret, "eyJhbGciOiJIUzI1NiJ9.tok");

        let neg = parse("Negotiate YIIF...").unwrap();
        assert_eq!(neg.scheme, "Negotiate");
        assert_eq!(neg.secret, "YIIF...");

        // Malformed inputs
        assert!(parse("").is_none());
        assert!(parse("Basic").is_none());
        assert!(parse("Basic   ").is_none());
        assert!(parse("Basic !!!not-base64!!!").is_none());
        let no_colon = base64::engine::general_purpose::STANDARD.encode("nocolon");
        assert!(parse(&format!("Basic {no_colon}")).is_none());
        let with_nul = base64::engine::general_purpose::STANDARD.encode("alice:bad\0pass");
        assert!(parse(&format!("Basic {with_nul}")).is_none());
        let bad_utf8 = base64::engine::general_purpose::STANDARD.encode([0xff, 0xfe, b':', b'a']);
        assert!(parse(&format!("Basic {bad_utf8}")).is_none());
    }

    #[test]
    fn challenge_escaping_blocks_header_and_quote_injection() {
        assert_eq!(basic_challenge("CUPS"), "Basic realm=\"CUPS\"");
        assert_eq!(
            basic_challenge("Corp \"Print\" \\ Lab\r\nX-Injected: evil\x00"),
            "Basic realm=\"Corp \\\"Print\\\" \\\\ LabX-Injected: evil\""
        );
        assert_eq!(bearer_challenge("CUPS", None), "Bearer realm=\"CUPS\"");
        assert_eq!(
            bearer_challenge("CUPS \"Prod\"\r\n", Some("print:admin \"all\"\n")),
            "Bearer realm=\"CUPS \\\"Prod\\\"\", scope=\"print:admin \\\"all\\\"\""
        );
    }

    #[test]
    fn basic_auth_backend_dispatch_and_no_shadow_fallback_on_pam_deny() {
        let groups_ok = |u: &str| vec![u.to_string(), "lpadmin".to_string()];

        // 1. PamOrShadow: PAM Authenticated -> succeeds without calling shadow
        let res = authenticate_basic_with_ops(
            "alice",
            "pw",
            &AuthBackend::default(),
            |svc, u, p| {
                assert_eq!(svc, "cups");
                assert_eq!(u, "alice");
                assert_eq!(p, "pw");
                sys::PamOutcome::Authenticated
            },
            |_, _| panic!("shadow must not run when PAM succeeds"),
            groups_ok,
        );
        assert_eq!(
            res,
            Some(("alice".into(), vec!["alice".into(), "lpadmin".into()]))
        );

        // 2. PamOrShadow: PAM Denied -> MUST NOT fall back to shadow
        let res = authenticate_basic_with_ops(
            "alice",
            "wrong",
            &AuthBackend::default(),
            |_, _, _| sys::PamOutcome::Denied(7),
            |_, _| panic!("shadow must NOT run after explicit PAM denial"),
            groups_ok,
        );
        assert!(res.is_none());

        // 3. PamOrShadow: PAM Unavailable -> falls back to shadow
        let res = authenticate_basic_with_ops(
            "alice",
            "pw",
            &AuthBackend::default(),
            |_, _, _| sys::PamOutcome::Unavailable,
            |u, p| u == "alice" && p == "pw",
            groups_ok,
        );
        assert_eq!(
            res,
            Some(("alice".into(), vec!["alice".into(), "lpadmin".into()]))
        );
        let res_bad = authenticate_basic_with_ops(
            "alice",
            "bad",
            &AuthBackend::default(),
            |_, _, _| sys::PamOutcome::Unavailable,
            |_, _| false,
            groups_ok,
        );
        assert!(res_bad.is_none());

        // 4. PamOnly: never falls back even when Unavailable
        let res_pam_only = authenticate_basic_with_ops(
            "alice",
            "pw",
            &AuthBackend::PamOnly {
                service: "cups-enterprise".into(),
            },
            |svc, _, _| {
                assert_eq!(svc, "cups-enterprise");
                sys::PamOutcome::Unavailable
            },
            |_, _| panic!("shadow must not run in PamOnly mode"),
            groups_ok,
        );
        assert!(res_pam_only.is_none());

        // 5. ShadowOnly: bypasses PAM
        let res_shadow = authenticate_basic_with_ops(
            "bob",
            "pw",
            &AuthBackend::ShadowOnly,
            |_, _, _| panic!("PAM must not run in ShadowOnly mode"),
            |u, p| u == "bob" && p == "pw",
            groups_ok,
        );
        assert_eq!(
            res_shadow,
            Some(("bob".into(), vec!["bob".into(), "lpadmin".into()]))
        );

        // 6. Empty / NUL inputs rejected
        assert!(authenticate_basic_with_ops(
            "",
            "pw",
            &AuthBackend::ShadowOnly,
            |_, _, _| sys::PamOutcome::Authenticated,
            |_, _| true,
            groups_ok,
        )
        .is_none());
        assert!(authenticate_basic_with_ops(
            "alice",
            "",
            &AuthBackend::ShadowOnly,
            |_, _, _| sys::PamOutcome::Authenticated,
            |_, _| true,
            groups_ok,
        )
        .is_none());
    }

    #[test]
    fn authenticator_and_bearer_token_verifier() {
        let verifier = Arc::new(StaticBearerVerifier {
            expected_token: "valid-jwt-123".into(),
            identity: VerifiedIdentity {
                user: "svc-printer".into(),
                groups: vec!["lpadmin".into()],
            },
        });

        let auth = Authenticator::default().with_token_verifier(verifier);
        assert_eq!(auth.backend(), &AuthBackend::default());
        assert!(format!("{auth:?}").contains("has_token_verifier: true"));

        let good_bearer = parse("Bearer valid-jwt-123").unwrap();
        assert_eq!(
            auth.authenticate(&good_bearer),
            Some(("svc-printer".into(), vec!["lpadmin".into()]))
        );

        let bad_bearer = parse("Bearer wrong-token").unwrap();
        assert!(auth.authenticate(&bad_bearer).is_none());

        let empty_bearer = Credentials {
            scheme: "Bearer".into(),
            user: String::new(),
            secret: String::new(),
        };
        assert!(auth.authenticate(&empty_bearer).is_none());

        // Empty user returned by verifier is rejected
        let empty_user_verifier = Arc::new(StaticBearerVerifier {
            expected_token: "tok".into(),
            identity: VerifiedIdentity {
                user: String::new(),
                groups: vec![],
            },
        });
        let auth_empty =
            Authenticator::new(AuthBackend::ShadowOnly).with_token_verifier(empty_user_verifier);
        assert!(auth_empty
            .authenticate(&parse("Bearer tok").unwrap())
            .is_none());

        // Unsupported scheme returns None
        let neg = parse("Negotiate abc").unwrap();
        assert!(auth.authenticate(&neg).is_none());

        // Top-level `authenticate` on nonexistent local user fails cleanly
        let bad_basic = Credentials {
            scheme: "Basic".into(),
            user: "definitely-not-a-user-xyz".into(),
            secret: "wrong".into(),
        };
        assert!(authenticate(&bad_basic).is_none());
        assert!(authenticate(&good_bearer).is_none());
    }
}
