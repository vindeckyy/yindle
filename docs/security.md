# Security Architecture & Threat Model

Presswork is a network-facing print spooler and IPP scheduler that parses untrusted network packets, HTTP headers, configuration files, PPDs, and print documents while coordinating device backends. This document details the threat model, structural defenses, and verification controls shipped in Presswork.

For vulnerability reporting, Coordinated Vulnerability Disclosure (CVD) SLAs, and FIPS 140-3 guidance, see [SECURITY.md](../SECURITY.md).

---

## 1. Why the September 2024 CUPS RCE Chain Cannot Recur

CVE-2024-47176 / CVE-2024-47076 / CVE-2024-47175 / CVE-2024-47177 demonstrated unauthenticated remote command execution in the C printing stack when attacker-controlled IPP attributes flowed unsanitized into generated PPDs and shell-evaluated filter command lines. Every link in that vulnerability class is structurally eliminated in Presswork:

| Stage in the C RCE Chain | Presswork Defense | Enforcement Location |
|---|---|---|
| Untrusted IPP attributes parsed in C | Strictly typed, bounded pure-Rust wire codec (`#![forbid(unsafe_code)]`, `DecodeLimits`) fuzzed with `libFuzzer` | `crates/ipp-codec`, `fuzz/fuzz_targets/ipp_decode.rs` |
| Unsanitized PPD/attribute injection (`*cupsFilter`, Foomatic, newlines) | Strict PPD validation rejects CR/LF, whitespace qualifiers, Foomatic command-injection patterns, `*cupsFilter` path traversal, and `cups*` injection; atomic `O_NOFOLLOW` writes | `crates/ops/src/ppd.rs` |
| Shell command templating (`system()` / `popen()`) | Zero shell execution; filters and backends spawn via direct `execv`-style `Vec<OsString>` with validated root-owned executable metadata | `crates/pipeline`, `bins/cups-exec` |
| Untrusted discovery/network redirection | Discovery tokens/fields sanitized against quote/newline injection; outbound network backends enforce `SsrfPolicy` against metadata, link-local, and loopback targets | `crates/backend-common` |
| Child process runs with daemon privileges | `cups-exec` drops supplementary groups and drops to non-root `User`/`Group` (`lp`), sets `umask 077`, `rlimits`, `PR_SET_NO_NEW_PRIVS`, and Linux Landlock rulesets | `bins/cups-exec`, `crates/sys/src/sandbox.rs` |

---

## 2. Memory Safety & `unsafe` Confinement

- **Workspace-wide `#![forbid(unsafe_code)]`**: enforced across all 16 safe library crates and all 15 binary crates via `[workspace.lints.rust] unsafe_code = "forbid"` and verified in CI (`forbid-unsafe` job).
- **Single audited FFI boundary (`crates/sys`)**: isolates POSIX syscalls using **reentrant, thread-safe APIs only** (`getpwnam_r`, `getpwuid_r`, `getgrnam_r`, `getgrgid_r`, `getspnam_r` with bounded `ERANGE` growth, `getgrouplist`, dynamically resolved `crypt_r`, dynamically loaded `libpam.so.0` with zeroized response cleanup, `SO_PEERCRED`, `FD_CLOEXEC` + env-unsetting `sd_listen_fds`, `sd_notify`, `O_NOFOLLOW`, `O_NOCTTY`, privilege drop, `setrlimit`, and Linux Landlock UAPI).
- **Zero panics on untrusted input**: daemon, HTTP, IPP, config, MIME, and backend paths avoid `.unwrap()`, `.expect()`, and unchecked slice indexing, returning typed errors instead.
- **8 continuous `cargo-fuzz` targets (`fuzz/`)**: `ipp_decode`, `config_lexer`, `mime_db`, `printers_conf`, `httpd_parse`, `authn_parse`, `backend_uri`, and `dnssd_uri`—exercised on every PR with curated seeds and regression tests.

---

## 3. Privilege Separation, Sandboxing & Process Hardening

### Filter & Backend Isolation (`crates/pipeline` + `bins/cups-exec`)

- **No shell interpolation**: argv is passed directly as `[program, job-id, user, title, copies, options, [file]]`, with the spool file path (`argv[6]`) passed **only** to the first filter stage.
- **Executable & path verification**: filter and backend paths must resolve cleanly inside trusted directories (`ServerBin/filter`, `ServerBin/backend`) with strict RFC 3986 scheme validation, no `..` traversal, and non-group/world-writable ownership checks.
- **Clean environment**: `env_clear()` followed by a strict allowlist. `is_prohibited_env` blocks all `LD_*` dynamic-linker variables plus `PATH`, `IFS`, `BASH_ENV`, `ENV`, `GCONV_PATH`, `PYTHONPATH`, `PERL5LIB`, `RUBYLIB`, `NODE_OPTIONS`, `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, and CUPS internal vars from `PassEnv`/`SetEnv`. **`DEVICE_URI` (which may contain backend credentials) is stripped from filter processes** and passed only to the final backend.
- **Linux Landlock & privilege drop**: `cups-exec` applies `set_nice`, `umask 077`, `setrlimit` (`Rlimits::filter_default()`), fail-closed `drop_privileges` (clearing supplementary groups, setting GID/UID—refusing UID `0` for filters), `PR_SET_NO_NEW_PRIVS`, and Linux Landlock filesystem rulesets (`strict`/`relaxed` profiles for filters and backends).
- **No `lp` -> `lpadmin` escalation**: neither `install.sh`, `.deb`, RPM, nor `sysusers.d` adds `lp` to `lpadmin`, preventing compromised filter/backend processes from gaining `@SYSTEM` admin rights over `/run/cups/cups.sock`.

### Systemd & Container Hardening

- **Loopback-only default sockets**: `data/systemd/cups.socket` binds `127.0.0.1:631`, `[::1]:631`, and `/run/cups/cups.sock`; `data/systemd/cups-lpd.socket` binds `127.0.0.1:515` and `[::1]:515` with `MaxConnections=64` and `MaxConnectionsPerSource=16`.
- **`cups.service` confinement**: `RuntimeDirectory=cups`, `ProtectSystem=strict` (writable only on `/var/spool/cups`, `/var/cache/cups`, `/var/log/cups`, `/etc/cups`), `ProtectHome=true`, `PrivateTmp=true`, `NoNewPrivileges=true`, `RestrictNamespaces=true`, `RestrictSUIDSGID=true`, `LockPersonality=true`, `RestrictRealtime=true`, minimal `CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH CAP_SETUID CAP_SETGID CAP_CHOWN CAP_FOWNER`, `SystemCallFilter=@system-service`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `UMask=0027`, `MemoryMax=512M`, `TasksMax=256`.
- **`cups-lpd@.service` confinement**: runs unprivileged as `User=lp` / `Group=lp` with empty `CapabilityBoundingSet=`, `PrivateDevices=true`, `UMask=0077`, `MemoryMax=64M`, `TasksMax=16`.
- **Containers & Kubernetes**: non-root UID/GID `631:631`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `cap_drop: [ALL]` + `NET_BIND_SERVICE`, `RuntimeDefault` seccomp, and least-privilege Kubernetes `NetworkPolicy`.

---

## 4. Network, HTTP, TLS & Backend Defenses

### HTTP/1.1 & CGI Hardening (`crates/httpd`, `bins/cupsd`)

- **Anti-smuggling**: rejects `Transfer-Encoding` + `Content-Length` combinations, duplicate or malformed `Content-Length`, whitespace before `:`, `obs-fold`, bare `\n\n`, and invalid chunk CRLFs; closes connections immediately on `400`/`408`/`413`/`431`/`505`; returns `413 Payload Too Large` before `100 Continue`.
- **Anti-DoS & Slowloris**: enforces `header_timeout`, `body_timeout`, `write_timeout`, `keep_alive_timeout`, `MaxClients`, per-host `MaxClientsPerHost`, TLS handshake timeout, and streams large request bodies to `0600` `O_NOFOLLOW` temp files (`Body::Spooled`) with automatic cleanup on drop/cancel instead of unbounded RAM buffering.
- **DNS rebinding protection**: validates HTTP `Host:` headers via `HostValidator` against configured `ServerName`, `ServerAlias`, and loopback addresses (`cupsd --check-config` flags `ServerAlias *` as High severity).
- **CGI & static file safety**: CGI runs asynchronously with `env_clear()`, strips `HTTP_PROXY` (HTTPoxy) and `HTTP_AUTHORIZATION`, removes URL argv splitting, and avoids >64 KiB pipe deadlocks. Static file serving enforces canonical `DocumentRoot` containment, rejects symlinks escaping root and non-regular files, and attaches `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Content-Security-Policy` headers.

### TLS & Mutual TLS (`crates/cups-tls`)

- Powered by `rustls` (TLS 1.2 and TLS 1.3 with AEAD cipher suites only; honors `SSLOptions` `MinTLS1.2`/`MinTLS1.3`/`MaxTLS1.2`/`MaxTLS1.3`/`DenyCBC`).
- Supports optional and required mutual TLS (mTLS) client certificate verification (`WebPkiClientVerifier`).
- Enforces `0700` on `/etc/cups/ssl` and `0600` (`O_NOFOLLOW`) on private keys, never overwrites existing admin-deployed certs/keys on parse errors, fails closed when explicit `SSLListen`/`SSLPort` initialization fails, and supports atomic `SIGHUP` certificate rotation via `ReloadableTls`.
- **Cryptographic modules & FIPS 140-3**: `rustls` uses `aws-lc-rs`/`aws-lc-sys` (and `rcgen` uses `ring`). Prebuilt binaries are not FIPS 140-3 validated out of the box—see [SECURITY.md](../SECURITY.md#5-cryptographic-modules--fips-140-3-note-aws-lc-sys--ring) for FIPS build or reverse-proxy termination guidance.

### Outbound Backend SSRF & Local Device Protection

- **SSRF policy (`crates/backend-common::SsrfPolicy`)**: `ipp`, `lpd`, `socket`, `snmp`, and `dnssd` backends resolve hostnames once and verify **every** returned IP before connecting, blocking port `0`, unspecified addresses (`0.0.0.0`, `::`), cloud metadata and link-local ranges (`169.254.0.0/16`, `100.100.100.200`, `fe80::/10`, `fd00:ec2::254`, and IPv4-mapped IPv6 forms), broadcast/multicast, and loopback (`127.0.0.0/8`, `::1`, opt-in via `CUPS_ALLOW_LOOPBACK_BACKENDS=yes`).
- **Device & file backends**: `usb`, `serial`, and `parallel` enforce canonical `/dev/` prefix checks, `O_NOFOLLOW` (+ `O_NOCTTY` on serial), and pre-/post-open `fstat` `S_ISCHR` verification. `file` enforces `FileDevice` fail-closed and writes regular files only (`0600`, `O_NOFOLLOW`, rejecting symlinks/FIFOs).
- **Credential redaction**: backend logs redact `user:pass@` from URIs (`redact_uri`), and `authn::Credentials` redacts `secret` in `Debug` output.

---

## 5. Authentication, Authorization & Auditability

- **PAM-first Basic auth (`crates/authn`)**: dynamically loads `libpam.so.0` (service `cups`) via `dlopen` so LDAP, SSSD, Active Directory, and `pam_faillock` work out of the box. Explicit PAM denials never fall back to `/etc/shadow`. Shadow verification (used only when `libpam` is absent) uses reentrant `getspnam_r` + dynamic `crypt_r`, rejects locked/expired/empty accounts, equalizes timing with a dummy SHA-512 crypt hash, and compares hashes in constant time.
- **Peer credentials (`SO_PEERCRED`)**: Unix domain socket clients are authenticated by kernel peer UID/GID (`PeerCred On|Off|RootOnly`), never by client-claimed headers. Invalid `Authorization` headers always return `401 Unauthorized` without falling back to `SO_PEERCRED`.
- **Bearer / OAuth extensibility**: `crates/authn` defines the `TokenVerifier` trait for `Authorization: Bearer` tokens. Native Kerberos/GSSAPI (`Negotiate`) and built-in OIDC provider adapters are planned roadmap items (not shipped via hidden Cargo features; see [docs/deviations.md](deviations.md#3-transparent-roadmap-not-yet-implemented)).
- **Fail-closed authorization (`crates/authz`)**: defaults to `Satisfy all` (both host ACL and authentication/group checks must succeed), denies unmatched IPP operations in `<Policy>`, enforces canonical `<Location>` path matching (blocking `..`/`\`/`\0`), real `@LOCAL` and `@IF(name)` network interface checks, IPv6-safe `HostMask` CIDR normalization, `@OWNER`, `@SYSTEM` (configured `SystemGroup`), and `JobPrivate*`/`SubscriptionPrivate*` redaction.
- **Audit & log integrity (`crates/cups-log`)**: enforces `LogFilePerm` (`0640`), `O_NOFOLLOW`, `MaxLogSize` `.O` rotation, CRLF log-forging sanitization, authenticated usernames in `access_log`, structured JSON output (`--log-format json`), and enterprise audit events.
- **Spool & config file permissions**: spool files (`c*`, `d*`) are written atomically with `0600` (`O_EXCL | O_NOFOLLOW`); `printers.conf`, `classes.conf`, and `subscriptions.conf` are written atomically with `ConfigFilePerm` (`0640`, `O_NOFOLLOW`).

---

## 6. Supply Chain, Testing & Continuous Assurance

- **Per-crate `>= 95%` line coverage gate**: CI and pre-release checks run `./scripts/coverage-gate.sh` (`cargo-llvm-cov --fail-under-lines 95`) on **every** workspace crate individually.
- **Dependency & license enforcement**: `cargo audit` (RustSec) and `cargo deny check` (advisories, yanked/unmaintained crates, license allowlist, wildcard guard, source pinning) gate every PR and release.
- **Pinned CI/CD**: all GitHub Actions workflows declare top-level `permissions: {}` with least-privilege per-job permissions and commit-SHA-pinned actions; OpenSSF Scorecard runs weekly and on pushes to `main`.
- **CycloneDX SBOM & SLSA provenance**: every tagged release generates `presswork-<version>.cdx.json` via `anchore/sbom-action`, publishes unified `SHA256SUMS`, and signs SLSA build provenance (`actions/attest-build-provenance`) and SBOM attestations (`actions/attest-sbom`) for tarballs, `.deb` packages, and multi-arch GHCR images. Verify with `gh attestation verify` (see [SECURITY.md](../SECURITY.md#verifying-release-artifacts)).
- **License scoping**: original code and documentation are dual-licensed `Apache-2.0 OR MIT`; upstream-derived MIME database files (`data/mime/mime.{types,convs}`) are scoped strictly under `Apache-2.0` as documented in [NOTICE](../NOTICE).
