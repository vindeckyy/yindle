//! Authorization — `<Location>`/`<Limit>`/`<Policy>` evaluation, a hardened
//! port of `scheduler/auth.c`'s `cupsdFindBest`/`cupsdCheckAccess`/`cupsdIsAuthorized`.
//!
//! Layers:
//!  * [`check_access`] / [`permitted`] / [`permitted_with_owner`] — evaluate one
//!    ACL block (`Encryption`, host `Allow`/`Deny` + `Order`, `Require`, `Satisfy`).
//!  * [`find_best_location`] / [`check_location`] — match an HTTP `(path, method)`
//!    against configured `<Location>` blocks and return an [`AccessDecision`].
//!  * [`policy_op`] / [`check_op`] / [`op_allowed`] / [`op_allowed_with_owner`] —
//!    fail-closed IPP `<Policy>` operation evaluation with `@OWNER` and `@SYSTEM`.

use cups_config::{limit, AuthLevel, AuthType, Encryption, Location, OrderType, Policy, Satisfy};
use std::net::IpAddr;

/// Who/what is making the request.
#[derive(Debug, Clone, Copy)]
pub struct Subject<'a> {
    /// Authenticated username (`None` = anonymous).
    pub user: Option<&'a str>,
    /// Unix group names the user belongs to.
    pub groups: &'a [String],
    /// Configured `SystemGroup` names — the `@SYSTEM` expansion.
    pub system_groups: &'a [String],
    /// Client address.
    pub addr: IpAddr,
    /// Client hostname (for name-based masks).
    pub host: &'a str,
    /// Is this connection over TLS?
    pub encrypted: bool,
}

/// Detailed authorization decision for HTTP `<Location>` and IPP `<Policy>` checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    /// Access granted.
    Allowed,
    /// TLS encryption is required (`426 Upgrade Required` / `IPP_STATUS_ERROR_UPGRADE_REQUIRED`).
    UpgradeRequired,
    /// Authentication is required (`401 Unauthorized` + `WWW-Authenticate` challenge).
    AuthRequired(AuthType),
    /// Denied by host ACL, missing policy/limit, or insufficient user/group privilege (`403 Forbidden`).
    Forbidden,
}

impl AccessDecision {
    /// Returns `true` iff this decision is [`AccessDecision::Allowed`].
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Map an HTTP method name (case-insensitive) to its `cups_config::limit::*` bit.
/// Returns `0` for unknown methods.
#[must_use]
pub fn http_method_bit(method: &str) -> u32 {
    if method.eq_ignore_ascii_case("GET") {
        limit::GET
    } else if method.eq_ignore_ascii_case("HEAD") {
        limit::HEAD
    } else if method.eq_ignore_ascii_case("POST") {
        limit::POST
    } else if method.eq_ignore_ascii_case("PUT") {
        limit::PUT
    } else if method.eq_ignore_ascii_case("DELETE") {
        limit::DELETE
    } else if method.eq_ignore_ascii_case("OPTIONS") {
        limit::OPTIONS
    } else if method.eq_ignore_ascii_case("TRACE") {
        limit::TRACE
    } else {
        0
    }
}

/// Normalize a request URI path (strip query/fragment and trailing slash except `"/"`).
fn normalize_path(path: &str) -> &str {
    let without_query = path.split_once(['?', '#']).map_or(path, |(p, _)| p);
    if without_query.len() > 1 {
        without_query.trim_end_matches('/')
    } else {
        without_query
    }
}

/// True if `req_path` (normalized) matches `loc_path` on a path-segment boundary.
/// Returns the matched prefix length for longest-prefix selection.
fn location_path_match_len(loc_path: &str, req_path: &str) -> Option<usize> {
    if !req_path.starts_with('/') {
        return None;
    }
    let lp = normalize_path(loc_path);
    if lp == "/" {
        return Some(1);
    }
    if req_path == lp {
        return Some(lp.len());
    }
    if req_path.starts_with(lp) && req_path.as_bytes().get(lp.len()) == Some(&b'/') {
        return Some(lp.len());
    }
    None
}

/// Find the most specific `<Location>` matching `(path, method_bit)` (port of `cupsdFindBest`).
///
/// Selects the longest matching path prefix whose `limit` bitmask includes `method_bit`.
/// Ties on path length prefer the narrower method mask (`count_ones()`).
#[must_use]
pub fn find_best_location<'a>(
    locations: &'a [Location],
    path: &str,
    method_bit: u32,
) -> Option<&'a Location> {
    if method_bit == 0 {
        return None;
    }
    let req_path = normalize_path(path);
    let mut best: Option<(&Location, usize, u32)> = None;

    for loc in locations {
        if (loc.limit & method_bit) == 0 {
            continue;
        }
        let Some(match_len) = location_path_match_len(&loc.path, req_path) else {
            continue;
        };
        let specificity = loc.limit.count_ones();
        let replace = match best {
            None => true,
            Some((_, best_len, best_spec)) => {
                match_len > best_len || (match_len == best_len && specificity <= best_spec)
            }
        };
        if replace {
            best = Some((loc, match_len, specificity));
        }
    }
    best.map(|(loc, _, _)| loc)
}

/// True for IPv4 loopback, IPv6 loopback, or IPv4-mapped IPv6 loopback (`::ffff:127.x.x.x`).
fn is_loopback_addr(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Evaluate a single [`Location`] ACL against `s` and optional resource `owner`
/// (job/subscription owner for `@OWNER` checks), returning a structured [`AccessDecision`].
#[must_use]
pub fn check_access(loc: &Location, s: &Subject, owner: Option<&str>) -> AccessDecision {
    // 1. Encryption requirement.
    if matches!(loc.encryption, Encryption::Required | Encryption::Always) && !s.encrypted {
        return AccessDecision::UpgradeRequired;
    }

    // 2. Host allow/deny + Order evaluation.
    let allowed = loc
        .allow
        .iter()
        .any(|m| m.matches(&s.addr) || m.matches_name(s.host));
    let denied = loc
        .deny
        .iter()
        .any(|m| m.matches(&s.addr) || m.matches_name(s.host));
    let host_ok = match loc.order {
        // `Order deny,allow` — allow evaluated last, wins ties; empty allows all.
        OrderType::Allow => allowed || !denied,
        // `Order allow,deny` — deny evaluated last, wins ties.
        // Matching upstream CUPS `cupsdIsAuthorized`: when neither `Allow` nor
        // `Deny` masks are configured, loopback is permitted and remote hosts are denied.
        OrderType::Deny => {
            if loc.allow.is_empty() && loc.deny.is_empty() {
                is_loopback_addr(s.addr)
            } else {
                !denied && allowed
            }
        }
    };

    // 3. Authentication & Require user/group/valid-user/@OWNER/@SYSTEM evaluation.
    let auth_ok = satisfies_auth(loc, s, owner);

    // 4. Combine host & auth under `Satisfy` (default `Satisfy::All`).
    match loc.satisfy {
        Satisfy::All => {
            if !host_ok {
                return AccessDecision::Forbidden;
            }
            if !auth_ok {
                return if s.user.is_none() {
                    AccessDecision::AuthRequired(loc.auth_type)
                } else {
                    AccessDecision::Forbidden
                };
            }
            AccessDecision::Allowed
        }
        Satisfy::Any => {
            if host_ok || auth_ok {
                return AccessDecision::Allowed;
            }
            if s.user.is_none() && loc.auth_level != AuthLevel::Anon {
                AccessDecision::AuthRequired(loc.auth_type)
            } else {
                AccessDecision::Forbidden
            }
        }
    }
}

/// Evaluate `<Location>` ACLs for an HTTP request `(path, method)`.
///
/// Fails closed (`AccessDecision::Forbidden`) when no matching `<Location>` exists
/// or `method` is unrecognized.
#[must_use]
pub fn check_location(
    locations: &[Location],
    path: &str,
    method: &str,
    s: &Subject,
    owner: Option<&str>,
) -> AccessDecision {
    let bit = http_method_bit(method);
    match find_best_location(locations, path, bit) {
        Some(loc) => check_access(loc, s, owner),
        None => AccessDecision::Forbidden,
    }
}

/// `cupsdCheckAccess` on one `Location` without a resource owner.
#[must_use]
pub fn permitted(loc: &Location, s: &Subject) -> bool {
    check_access(loc, s, None).is_allowed()
}

/// `cupsdCheckAccess` on one `Location` with an optional resource `owner`
/// (used for `@OWNER` matching on jobs and subscriptions).
#[must_use]
pub fn permitted_with_owner(loc: &Location, s: &Subject, owner: Option<&str>) -> bool {
    check_access(loc, s, owner).is_allowed()
}

/// Whether `Require`/`AuthLevel` user & group constraints pass.
fn satisfies_auth(loc: &Location, s: &Subject, owner: Option<&str>) -> bool {
    match loc.auth_level {
        AuthLevel::Anon => {
            if loc.names.is_empty() {
                true
            } else {
                check_user_names(&loc.names, s, owner)
            }
        }
        AuthLevel::ValidUser => {
            let Some(_) = s.user else {
                return false;
            };
            if loc.names.is_empty() {
                true
            } else {
                check_user_names(&loc.names, s, owner)
            }
        }
        AuthLevel::Group => check_group_names(&loc.names, s, owner),
        AuthLevel::User => check_user_names(&loc.names, s, owner),
    }
}

/// Match `Require group ...` entries strictly against the subject's groups
/// (plus `@SYSTEM` / `@OWNER` special tokens), NEVER against `s.user`.
fn check_group_names(names: &[String], s: &Subject, owner: Option<&str>) -> bool {
    let Some(user) = s.user else {
        return false;
    };
    if names.is_empty() {
        return false;
    }
    for n in names {
        match n.as_str() {
            "@SYSTEM" => {
                if s.groups.iter().any(|g| s.system_groups.contains(g)) {
                    return true;
                }
            }
            "@OWNER" => {
                if owner.is_some_and(|o| o == user) {
                    return true;
                }
            }
            g => {
                let target = g.strip_prefix('@').unwrap_or(g);
                if !target.is_empty() && s.groups.iter().any(|x| x == target) {
                    return true;
                }
            }
        }
    }
    false
}

/// Match `Require user ...` entries (`valid-user`, `@SYSTEM`, `@OWNER`, `@group`, or exact username).
fn check_user_names(names: &[String], s: &Subject, owner: Option<&str>) -> bool {
    let Some(user) = s.user else {
        return false;
    };
    if names.is_empty() {
        return false;
    }
    for n in names {
        match n.as_str() {
            "valid-user" => return true,
            "@SYSTEM" => {
                if s.groups.iter().any(|g| s.system_groups.contains(g)) {
                    return true;
                }
            }
            "@OWNER" => {
                if owner.is_some_and(|o| o == user) {
                    return true;
                }
            }
            g if g.starts_with('@') => {
                let target = &g[1..];
                if !target.is_empty() && s.groups.iter().any(|x| x == target) {
                    return true;
                }
            }
            u if u == user => return true,
            _ => {}
        }
    }
    false
}

/// Find the policy op limit for `op` in `policy`, falling back to `All` (`u32::MAX`).
#[must_use]
pub fn policy_op(policy: &Policy, op: u32) -> Option<&Location> {
    policy
        .ops
        .iter()
        .find(|p| p.op == op)
        .or_else(|| policy.ops.iter().find(|p| p.op == u32::MAX))
        .map(|p| &p.loc)
}

/// Evaluate an IPP `op` against a named policy in `policies` with optional
/// resource `owner`, returning a structured [`AccessDecision`].
///
/// Fails CLOSED (`AccessDecision::Forbidden`) when:
/// - `policy_name` (or `"default"` when `None`) is missing from `policies`, OR
/// - neither an explicit `<Limit op>` nor `<Limit All>` matches `op`.
#[must_use]
pub fn check_op(
    policies: &[Policy],
    policy_name: Option<&str>,
    op: u32,
    s: &Subject,
    owner: Option<&str>,
) -> AccessDecision {
    let name = policy_name.unwrap_or("default");
    let Some(pol) = policies.iter().find(|p| p.name == name) else {
        return AccessDecision::Forbidden;
    };
    match policy_op(pol, op) {
        Some(loc) => check_access(loc, s, owner),
        None => AccessDecision::Forbidden,
    }
}

/// Evaluate an IPP op against a named policy in `policies` (without resource owner).
/// `None` policy name → `"default"`. Missing policy or missing `<Limit>` → fail closed (`false`).
#[must_use]
pub fn op_allowed(policies: &[Policy], policy_name: Option<&str>, op: u32, s: &Subject) -> bool {
    check_op(policies, policy_name, op, s, None).is_allowed()
}

/// Evaluate an IPP op against a named policy in `policies` with optional resource `owner`
/// (enforcing `@OWNER` for job and subscription operations).
#[must_use]
pub fn op_allowed_with_owner(
    policies: &[Policy],
    policy_name: Option<&str>,
    op: u32,
    s: &Subject,
    owner: Option<&str>,
) -> bool {
    check_op(policies, policy_name, op, s, owner).is_allowed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cups_config::{default_policy, parse_cupsd_conf, HostMask, PolicyOp};

    fn local_anon() -> Subject<'static> {
        Subject {
            user: None,
            groups: &[],
            system_groups: &[],
            addr: "127.0.0.1".parse().unwrap(),
            host: "localhost",
            encrypted: false,
        }
    }

    #[test]
    fn satisfy_default_is_all_blocking_anon_admin_bypass() {
        assert_eq!(Satisfy::default(), Satisfy::All);

        let policies = vec![default_policy()];
        let sys_groups = vec!["lpadmin".to_string()];
        let anon = Subject {
            user: None,
            groups: &[],
            system_groups: &sys_groups,
            addr: "127.0.0.1".parse().unwrap(),
            host: "localhost",
            encrypted: false,
        };
        // Admin op (CUPS-Add-Modify-Printer = 0x4003) MUST reject anonymous caller!
        let add_printer_op = 0x4003;
        assert!(!op_allowed(&policies, None, add_printer_op, &anon));
        assert_eq!(
            check_op(&policies, None, add_printer_op, &anon, None),
            AccessDecision::AuthRequired(AuthType::Default)
        );

        // Non-admin authenticated user must be Forbidden.
        let user_groups = vec!["users".to_string()];
        let regular = Subject {
            user: Some("alice"),
            groups: &user_groups,
            system_groups: &sys_groups,
            addr: "127.0.0.1".parse().unwrap(),
            host: "localhost",
            encrypted: false,
        };
        assert!(!op_allowed(&policies, None, add_printer_op, &regular));
        assert_eq!(
            check_op(&policies, None, add_printer_op, &regular, None),
            AccessDecision::Forbidden
        );

        // @SYSTEM member is Allowed.
        let admin_groups = vec!["lpadmin".to_string()];
        let admin = Subject {
            user: Some("root"),
            groups: &admin_groups,
            system_groups: &sys_groups,
            addr: "127.0.0.1".parse().unwrap(),
            host: "localhost",
            encrypted: false,
        };
        assert!(op_allowed(&policies, None, add_printer_op, &admin));
        // CUPS-Get-Devices (0x400B) is also protected in default_policy.
        assert!(!op_allowed(&policies, None, 0x400B, &anon));
        assert!(op_allowed(&policies, None, 0x400B, &admin));
    }

    #[test]
    fn op_allowed_fails_closed_when_policy_or_limit_missing() {
        let s = local_anon();
        // Missing policy
        assert!(!op_allowed(&[], Some("default"), 0x0002, &s));
        assert_eq!(
            check_op(&[], Some("default"), 0x0002, &s, None),
            AccessDecision::Forbidden
        );

        // Policy with only op 0x0002 and NO `<Limit All>` -> op 0x0008 must fail closed!
        let pol = Policy {
            name: "strict".into(),
            ops: vec![PolicyOp {
                op: 0x0002,
                loc: Location::new("strict"),
            }],
            job_access: vec![],
            job_values: vec![],
            sub_access: vec![],
            sub_values: vec![],
        };
        assert!(op_allowed(
            std::slice::from_ref(&pol),
            Some("strict"),
            0x0002,
            &s
        ));
        assert!(!op_allowed(
            std::slice::from_ref(&pol),
            Some("strict"),
            0x0008,
            &s
        ));
        assert_eq!(
            check_op(&[pol], Some("strict"), 0x0008, &s, None),
            AccessDecision::Forbidden
        );
    }

    #[test]
    fn require_valid_user_accepts_any_authenticated_user_with_empty_names() {
        let conf = b"<Location /jobs>\n  AuthType Basic\n  Require valid-user\n  Order deny,allow\n</Location>\n";
        let (cfg, diags) = parse_cupsd_conf(&conf[..], "cupsd.conf");
        assert!(!diags.has_errors());
        let loc = &cfg.locations[0];
        assert_eq!(loc.auth_level, AuthLevel::ValidUser);
        assert_eq!(loc.names, Vec::<String>::new());

        let anon = local_anon();
        assert!(!permitted(loc, &anon));
        assert_eq!(
            check_access(loc, &anon, None),
            AccessDecision::AuthRequired(AuthType::Basic)
        );

        let authed = Subject {
            user: Some("anyone"),
            ..anon
        };
        assert!(permitted(loc, &authed));
        assert_eq!(check_access(loc, &authed, None), AccessDecision::Allowed);
    }

    #[test]
    fn require_group_matches_groups_and_never_username() {
        let conf = b"<Location /ops>\n  AuthType Basic\n  Require group printops\n  Order deny,allow\n</Location>\n";
        let (cfg, diags) = parse_cupsd_conf(&conf[..], "cupsd.conf");
        assert!(!diags.has_errors());
        let loc = &cfg.locations[0];
        assert_eq!(loc.auth_level, AuthLevel::Group);
        assert_eq!(loc.names, vec!["printops"]);

        // User literally named "printops" who is NOT in group "printops" MUST BE REJECTED!
        let wrong_groups = vec!["users".to_string()];
        let imposter = Subject {
            user: Some("printops"),
            groups: &wrong_groups,
            system_groups: &[],
            addr: "127.0.0.1".parse().unwrap(),
            host: "localhost",
            encrypted: false,
        };
        assert!(!permitted(loc, &imposter));
        assert_eq!(
            check_access(loc, &imposter, None),
            AccessDecision::Forbidden
        );

        // User "alice" in group "printops" MUST BE ALLOWED!
        let ok_groups = vec!["users".to_string(), "printops".to_string()];
        let member = Subject {
            user: Some("alice"),
            groups: &ok_groups,
            system_groups: &[],
            addr: "127.0.0.1".parse().unwrap(),
            host: "localhost",
            encrypted: false,
        };
        assert!(permitted(loc, &member));

        // Anonymous rejected with AuthRequired
        assert_eq!(
            check_access(loc, &local_anon(), None),
            AccessDecision::AuthRequired(AuthType::Basic)
        );

        // Group level with empty names fails closed
        let mut empty_grp = Location::new("/empty");
        empty_grp.auth_level = AuthLevel::Group;
        assert!(!permitted(&empty_grp, &member));

        // Group level with @SYSTEM and @OWNER and @prefix
        let mut special_grp = Location::new("/special");
        special_grp.auth_level = AuthLevel::Group;
        special_grp.names = vec!["@SYSTEM".into(), "@OWNER".into(), "@netops".into()];
        let sys_g = vec!["wheel".to_string()];
        let owner_s = Subject {
            user: Some("bob"),
            groups: &[],
            system_groups: &sys_g,
            addr: "127.0.0.1".parse().unwrap(),
            host: "localhost",
            encrypted: false,
        };
        assert!(!permitted_with_owner(&special_grp, &owner_s, Some("alice")));
        assert!(permitted_with_owner(&special_grp, &owner_s, Some("bob")));
        let sys_member_groups = vec!["wheel".to_string()];
        let sys_member = Subject {
            user: Some("carol"),
            groups: &sys_member_groups,
            system_groups: &sys_g,
            addr: "127.0.0.1".parse().unwrap(),
            host: "localhost",
            encrypted: false,
        };
        assert!(permitted_with_owner(
            &special_grp,
            &sys_member,
            Some("alice")
        ));
        let net_groups = vec!["netops".to_string()];
        let net_member = Subject {
            user: Some("dave"),
            groups: &net_groups,
            system_groups: &sys_g,
            addr: "127.0.0.1".parse().unwrap(),
            host: "localhost",
            encrypted: false,
        };
        assert!(permitted_with_owner(
            &special_grp,
            &net_member,
            Some("alice")
        ));
    }

    #[test]
    fn owner_enforcement_and_special_username_spoof_protection() {
        let policies = vec![default_policy()];
        let sys_groups = vec!["lpadmin".to_string()];
        let cancel_job_op = 0x0008; // Cancel-Job: Require user @OWNER @SYSTEM

        let alice = Subject {
            user: Some("alice"),
            groups: &[],
            system_groups: &sys_groups,
            addr: "127.0.0.1".parse().unwrap(),
            host: "localhost",
            encrypted: false,
        };
        // Owner matches -> allowed
        assert!(op_allowed_with_owner(
            &policies,
            None,
            cancel_job_op,
            &alice,
            Some("alice")
        ));
        // Different owner -> denied
        assert!(!op_allowed_with_owner(
            &policies,
            None,
            cancel_job_op,
            &alice,
            Some("bob")
        ));
        // No owner provided -> fails closed for non-@SYSTEM
        assert!(!op_allowed(&policies, None, cancel_job_op, &alice));

        // Literal username "@SYSTEM" or "@OWNER" must NEVER bypass group/owner checks!
        let spoof_sys = Subject {
            user: Some("@SYSTEM"),
            ..alice
        };
        assert!(!op_allowed(&policies, None, cancel_job_op, &spoof_sys));
        let spoof_owner = Subject {
            user: Some("@OWNER"),
            ..alice
        };
        assert!(!op_allowed_with_owner(
            &policies,
            None,
            cancel_job_op,
            &spoof_owner,
            Some("alice")
        ));

        // @SYSTEM can cancel any user's job
        let admin_groups = vec!["lpadmin".to_string()];
        let admin = Subject {
            user: Some("admin"),
            groups: &admin_groups,
            system_groups: &sys_groups,
            addr: "127.0.0.1".parse().unwrap(),
            host: "localhost",
            encrypted: false,
        };
        assert!(op_allowed_with_owner(
            &policies,
            None,
            cancel_job_op,
            &admin,
            Some("alice")
        ));
    }

    #[test]
    fn location_matching_encryption_order_and_satisfy_any() {
        let conf = br"
<Location />
  Order allow,deny
</Location>

<Location /admin>
  AuthType Default
  Require user @SYSTEM
  Encryption Required
  Order allow,deny
</Location>

<Location /admin/conf>
  AuthType Basic
  Require user alice @netops
  Order deny,allow
  Deny from all
  Allow from 10.0.0.0/8
  Satisfy Any
</Location>

<Location /printers>
  <Limit POST>
    AuthType Basic
    Require valid-user
    Order deny,allow
  </Limit>
  Order deny,allow
</Location>
";
        let (cfg, diags) = parse_cupsd_conf(&conf[..], "cupsd.conf");
        assert!(!diags.has_errors());

        let sys_groups = vec!["lpadmin".to_string()];
        let admin_groups = vec!["lpadmin".to_string()];

        // 1. `<Location /> Order allow,deny` allows loopback (v4, v6, v4-mapped) and blocks remote.
        let lo_v4 = local_anon();
        assert_eq!(
            check_location(&cfg.locations, "/", "GET", &lo_v4, None),
            AccessDecision::Allowed
        );
        let lo_v6_mapped = Subject {
            addr: "::ffff:127.0.0.1".parse().unwrap(),
            ..lo_v4
        };
        assert_eq!(
            check_location(
                &cfg.locations,
                "/index.html?foo=1",
                "GET",
                &lo_v6_mapped,
                None
            ),
            AccessDecision::Allowed
        );
        let remote = Subject {
            addr: "198.51.100.9".parse().unwrap(),
            host: "evil.example",
            ..lo_v4
        };
        assert_eq!(
            check_location(&cfg.locations, "/", "GET", &remote, None),
            AccessDecision::Forbidden
        );

        // 2. `/admin` requires TLS -> UpgradeRequired when plaintext, AuthRequired when TLS+anon,
        //    Allowed when TLS+@SYSTEM+loopback, Forbidden when remote.
        assert_eq!(
            check_location(&cfg.locations, "/admin", "GET", &lo_v4, None),
            AccessDecision::UpgradeRequired
        );
        let lo_tls_anon = Subject {
            encrypted: true,
            system_groups: &sys_groups,
            ..lo_v4
        };
        assert_eq!(
            check_location(&cfg.locations, "/admin/", "POST", &lo_tls_anon, None),
            AccessDecision::AuthRequired(AuthType::Default)
        );
        let lo_tls_admin = Subject {
            user: Some("root"),
            groups: &admin_groups,
            ..lo_tls_anon
        };
        assert_eq!(
            check_location(&cfg.locations, "/admin/jobs", "GET", &lo_tls_admin, None),
            AccessDecision::Allowed
        );
        // Path boundary: `/admin2` matches `/`, NOT `/admin`!
        assert_eq!(
            check_location(&cfg.locations, "/admin2", "GET", &lo_v4, None),
            AccessDecision::Allowed
        );
    }

    #[test]
    fn location_satisfy_any_limits_and_methods() {
        let conf = br"
<Location /admin/conf>
  AuthType Basic
  Require user alice @netops
  Order deny,allow
  Deny from all
  Allow from 10.0.0.0/8
  Satisfy Any
</Location>

<Location /printers>
  <Limit POST>
    AuthType Basic
    Require valid-user
    Order deny,allow
  </Limit>
  Order deny,allow
</Location>
";
        let (cfg, diags) = parse_cupsd_conf(&conf[..], "cupsd.conf");
        assert!(!diags.has_errors());
        let lo_v4 = local_anon();

        // 3. `/admin/conf` has `Satisfy Any` + `Deny from all` + `Allow from 10.0.0.0/8`:
        //    - 10.1.2.3 anonymous -> Allowed via host_ok
        //    - 2001:db8::1 anonymous -> AuthRequired (IPv6 denied by `Deny from all`!)
        //    - 2001:db8::1 authenticated as alice -> Allowed via auth_ok
        //    - 2001:db8::1 authenticated as bob -> Forbidden
        let lan_anon = Subject {
            addr: "10.1.2.3".parse().unwrap(),
            ..lo_v4
        };
        assert_eq!(
            check_location(&cfg.locations, "/admin/conf", "GET", &lan_anon, None),
            AccessDecision::Allowed
        );
        let v6_anon = Subject {
            addr: "2001:db8::1".parse().unwrap(),
            ..lo_v4
        };
        assert_eq!(
            check_location(&cfg.locations, "/admin/conf", "GET", &v6_anon, None),
            AccessDecision::AuthRequired(AuthType::Basic)
        );
        let v6_alice = Subject {
            user: Some("alice"),
            ..v6_anon
        };
        assert_eq!(
            check_location(&cfg.locations, "/admin/conf", "GET", &v6_alice, None),
            AccessDecision::Allowed
        );
        let netops = vec!["netops".to_string()];
        let v6_netops = Subject {
            user: Some("charlie"),
            groups: &netops,
            ..v6_anon
        };
        assert_eq!(
            check_location(&cfg.locations, "/admin/conf", "GET", &v6_netops, None),
            AccessDecision::Allowed
        );
        let v6_bob = Subject {
            user: Some("bob"),
            ..v6_anon
        };
        assert_eq!(
            check_location(&cfg.locations, "/admin/conf", "GET", &v6_bob, None),
            AccessDecision::Forbidden
        );

        // 4. `<Location /printers>` with `<Limit POST>`: GET allowed anon, POST requires auth.
        assert_eq!(
            check_location(&cfg.locations, "/printers/hp", "GET", &lo_v4, None),
            AccessDecision::Allowed
        );
        assert_eq!(
            check_location(&cfg.locations, "/printers/hp", "POST", &lo_v4, None),
            AccessDecision::AuthRequired(AuthType::Basic)
        );
        assert_eq!(
            check_location(
                &cfg.locations,
                "/printers/hp",
                "POST",
                &Subject {
                    user: Some("alice"),
                    ..lo_v4
                },
                None
            ),
            AccessDecision::Allowed
        );

        // 5. Unknown HTTP method & relative path fail closed.
        assert_eq!(
            check_location(&cfg.locations, "/", "BREW", &lo_v4, None),
            AccessDecision::Forbidden
        );
        assert_eq!(
            check_location(&cfg.locations, "relative", "GET", &lo_v4, None),
            AccessDecision::Forbidden
        );
        assert_eq!(http_method_bit("HEAD"), limit::HEAD);
        assert_eq!(http_method_bit("PUT"), limit::PUT);
        assert_eq!(http_method_bit("DELETE"), limit::DELETE);
        assert_eq!(http_method_bit("OPTIONS"), limit::OPTIONS);
        assert_eq!(http_method_bit("TRACE"), limit::TRACE);
    }

    #[test]
    fn explicit_allow_deny_rules_and_user_edge_cases() {
        // Explicit `Order allow,deny` with `Allow from 10.0.0.0/8` does NOT implicitly allow loopback.
        let mut loc = Location::new("/lan");
        loc.order = OrderType::Deny;
        loc.allow.push(HostMask::parse_one("10.0.0.0/8").unwrap());
        assert!(!permitted(&loc, &local_anon()));
        assert!(permitted(
            &loc,
            &Subject {
                addr: "10.9.8.7".parse().unwrap(),
                ..local_anon()
            }
        ));

        // AuthLevel::User with empty names fails closed; valid-user token inside names works.
        let mut u_empty = Location::new("/u");
        u_empty.auth_level = AuthLevel::User;
        let authed = Subject {
            user: Some("alice"),
            ..local_anon()
        };
        assert!(!permitted(&u_empty, &authed));
        u_empty.names.push("valid-user".into());
        assert!(permitted(&u_empty, &authed));

        // AuthLevel::ValidUser with non-empty names checks names.
        let mut vu_named = Location::new("/vu");
        vu_named.auth_level = AuthLevel::ValidUser;
        vu_named.names.push("alice".into());
        assert!(permitted(&vu_named, &authed));
        assert!(!permitted(
            &vu_named,
            &Subject {
                user: Some("bob"),
                ..local_anon()
            }
        ));

        // AuthLevel::Anon with explicit names still enforces names.
        let mut anon_named = Location::new("/an");
        anon_named.auth_level = AuthLevel::Anon;
        anon_named.names.push("alice".into());
        assert!(!permitted(&anon_named, &local_anon()));
        assert!(permitted(&anon_named, &authed));
    }
}
