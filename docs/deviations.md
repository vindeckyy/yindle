# Documented Deviations from OpenPrinting CUPS

Presswork targets drop-in wire, configuration, spool, and filter/backend compatibility with OpenPrinting CUPS 2.x on Linux. Where Presswork intentionally differs from upstream CUPS—chiefly to eliminate classes of security vulnerabilities by default—or where an upstream capability is on the roadmap rather than yet shipped, it is recorded here.

Any behavioral difference **not** listed on this page should be treated as a compatibility bug and reported via the [Compatibility Report](https://github.com/vindeckyy/presswork/issues/new?template=compat_report.md) template.

---

## 1. Intentional Security-First Defaults

Presswork flips several permissive upstream defaults to fail-closed settings so a fresh installation or migration cannot silently expose administrative controls or arbitrary file/network primitives.

| Area | OpenPrinting CUPS 2.x | Presswork | Rationale & Escape Hatch |
|---|---|---|---|
| **Default `Satisfy` mode** | `Satisfy any` inside `<Location>` / `<Limit>` unless `Satisfy all` is explicit | **`Satisfy all`** (`crates/cups-config/src/types.rs`, `crates/authz`) | Prevents an `Order deny,allow` block with empty `Allow`/`Deny` rules from bypassing `Require user @SYSTEM` or `Require user @OWNER`. Legacy configs that rely on `Satisfy any` can declare it explicitly; `cupsd --check-config` flags authenticated `Satisfy any` blocks (`LOCATION_SATISFY_ANY` / `POLICY_SATISFY_ANY`). |
| **Systemd socket binding** | `cups.socket` ships `ListenStream=631` (binds `0.0.0.0:631` and `[::]:631` globally) | **Loopback-only** (`127.0.0.1:631`, `[::1]:631`, `/run/cups/cups.sock`) in `data/systemd/cups.socket` | Installing a print spooler must never expose TCP/631 to untrusted LANs by accident. Operators opt into network listeners explicitly via `systemctl edit cups.socket` alongside TLS (`SSLListen` / `Encryption Required`). See [docs/operations.md](operations.md#systemd-bare-metal--vm). |
| **LPD socket & service** | Often runs as root or binds wildcard port 515 | **Loopback-only** (`127.0.0.1:515`, `[::1]:515`), `User=lp`, `MaxConnections=64`, `MaxConnectionsPerSource=16`, bounded temp spool (`100 MiB` default) | RFC 1179 LPD is an unauthenticated legacy protocol. Override via `systemctl edit cups-lpd.socket` and firewall rules if LAN LPD clients are required. |
| **Unmatched `<Policy>` operations** | Permissive fallback in edge configurations | **Fail-closed** (`authz::check_op` denies when no `<Limit>` matches) | Every one of the 68 dispatched IPP operations requires an explicit `<Limit>` or `<Limit All>` match under the effective policy (`printer-op-policy` -> `DefaultPolicy` -> `default`). |
| **Identity & host trust** | Some legacy code paths consult client-supplied attributes | **Verified identity & peer IP only** | Authorization never falls back to untrusted IPP `requesting-user-name` or HTTP `Host:` headers; invalid `Authorization` headers return `401 Unauthorized` without falling back to `SO_PEERCRED`. `Host:` headers are validated against `ServerName` and `ServerAlias` to block DNS rebinding. |
| **`FileDevice` enforcement** | `FileDevice No` in default config | **Strict fail-closed enforcement** in both `ops` and `cups-backend-file` | `file://` device URIs are rejected unless explicitly allowed by `FileDevice` in `cups-files.conf`. When enabled, `cups-backend-file` truncates targets with `0600` + `O_NOFOLLOW`, rejecting symlinks and FIFOs. |
| **`Print-URI` / `Send-URI`** | May fetch local `file://` URIs depending on build/policy | **`file://` scheme forbidden** | Prevents unauthenticated or cross-user arbitrary local file disclosure via `Print-URI` + `CUPS-Get-Document`. |
| **PPD & filter validation** | Permissive string parsing in legacy `libppd`/`cupsd` | **Strict validation & containment** | Uploaded/patched PPDs reject CR/LF injection, whitespace qualifiers, Foomatic command-injection patterns, `*cupsFilter`/`*cupsFilter2` absolute paths or `..` traversal, and untrusted executable permissions. `CUPS-Get-PPD` enforces canonical root containment and rejects `drv:////...` absolute-path escapes. |
| **Spool, config & TLS permissions** | Historically `0644` on some spool/config artifacts | **Atomic `0600` spool files, `0640` configs, `0700`/`0600` TLS** | Job files (`c*`, `d*`) are written atomically (`O_EXCL \| O_NOFOLLOW`, `0600`). `printers.conf`, `classes.conf`, and `subscriptions.conf` use atomic `O_NOFOLLOW` writes honoring `ConfigFilePerm` (`0640`). `/etc/cups/ssl` is `0700`, private keys are `0600`, and existing admin certs/keys are **never** overwritten on parse errors. |
| **Filter/backend sandboxing** | Platform-specific (macOS Seatbelt; relaxed on Linux) | **Privilege drop + `umask 077` + `rlimits` + `PR_SET_NO_NEW_PRIVS` + Linux Landlock** via `cups-exec` | Filters and backends run via direct `execv` (no shell), `env_clear()`, expanded prohibited env blocklist (`LD_*`, `PATH`, `IFS`, `HTTP_PROXY`, `PYTHONPATH`, etc.), and `DEVICE_URI` stripped from filters. `lp` is **never** added to `lpadmin`. Landlock activates automatically on Linux kernels >= 5.13 and gracefully degrades to privdrop + `NO_NEW_PRIVS` + `rlimits` + systemd hardening on older kernels. |
| **Outbound backend SSRF guard** | Network backends connect to any IP/hostname | **Built-in `SsrfPolicy` in `backend-common`** | Network backends (`ipp`, `lpd`, `socket`, `snmp`, `dnssd`) validate every DNS resolution result and block unspecified (`0.0.0.0`, `::`), link-local/cloud metadata (`169.254.0.0/16`, `100.100.100.200`, `fe80::/10`, `fd00:ec2::254`, and IPv4-mapped IPv6 forms), broadcast/multicast, and loopback (`127.0.0.0/8`, `::1`). Set `CUPS_ALLOW_LOOPBACK_BACKENDS=yes` to explicitly allow loopback backend targets (for example, local print gateways or test harnesses). |
| **HTTP/1.1 parser strictness** | Tolerates certain non-RFC HTTP quirks | **Strict anti-smuggling parser (`crates/httpd`)** | Rejects simultaneous `Transfer-Encoding` + `Content-Length`, duplicate `Content-Length`, whitespace before `:`, `obs-fold`, bare `\n\n`, and malformed chunk CRLFs; closes connections immediately on `400`/`408`/`413`/`431`/`505`; returns `413 Payload Too Large` before `100 Continue`; enforces Slowloris header/body/write/keep-alive timeouts and disk-spooled large bodies. |
| **TLS protocol & cipher floor** | OpenSSL/GnuTLS with optional legacy TLS 1.0/1.1/CBC | **`rustls` TLS 1.2+ with AEAD cipher suites only** | `SSLOptions` `MinTLS1.2`/`MinTLS1.3`/`MaxTLS1.2`/`MaxTLS1.3` and `DenyCBC` are enforced. Legacy `SSLv3`, `TLS 1.0`, `TLS 1.1`, `RC4`, and CBC suites are not supported (and are flagged by `cupsd --check-config`). See [SECURITY.md](../SECURITY.md) for FIPS 140-3 guidance regarding `aws-lc-rs`/`ring`. |

---

## 2. Runtime, Packaging, and Operational Differences

### External `cups-filters` Runtime Dependency

Presswork ships the scheduler (`cupsd`), helper daemons (`cups-deviced`, `cups-driverd`, `cups-exec`, `cups-lpd`), `cupsfilter`, and all 9 standard backends (`socket`, `file`, `ipp`, `lpd`, `snmp`, `usb`, `dnssd`, `serial`, `parallel`). It does **not** reimplement OpenPrinting's document conversion filters (`pstops`, `pdftopdf`, `pdftoraster`, `rastertopwg`, `foomatic-rip`, etc.).

- **Driverless IPP Everywhere / AirPrint queues** send PDF, PWG Raster, or URF directly to modern printers and require no external filters.
- **Legacy PPD queues** or workflows requiring server-side PostScript/PDF/raster conversion require installing your distribution's `cups-filters` package (declared as `Recommends: cups-filters` in Debian/RPM and `optdepends` in Arch; optional via `--build-arg INSTALL_CUPS_FILTERS=true` in the `Dockerfile`).
- In `data/mime/mime.convs`, raw passthrough (`application/octet-stream -> application/vnd.cups-raw`) is enabled by default so pre-formatted jobs work without `-o raw`. Override via `/etc/cups/local.convs` if you want to reject unrecognized binary streams.

### Dynamic PAM and `libcrypt` Resolution (`dlopen`)

Instead of linking against a distribution-specific `libpam` or `libcrypt.so.1` soname at compile time, `crates/sys` resolves authentication libraries dynamically at runtime:

- **PAM**: loads `libpam.so.0` (falling back to `libpam.so`) via `dlopen` for service `cups` (`/etc/pam.d/cups`). When PAM is present, PAM is authoritative—an explicit PAM denial **never** falls back to `/etc/shadow`. Shadow fallback runs only when `libpam` is absent on the host.
- **Shadow password hashing**: resolves reentrant `crypt_r(3)` in order `libcrypt.so.2` -> `libcrypt.so.1` -> `libcrypt.so` -> `RTLD_DEFAULT` (covering glibc, libxcrypt on Fedora/RHEL/Arch, and musl on Alpine without requiring `libxcrypt-compat`), with constant-time comparison and dummy-hash equalization for unknown/locked/expired accounts.

### Pure-Rust D-Bus Wire Notifier

`crates/cups-dbus` publishes standard `org.cups.cupsd.Notifier` signals (`/org/cups/cupsd/Notifier`) directly over the D-Bus v1 Unix socket wire protocol (`/run/dbus/system_bus_socket`, SASL `EXTERNAL`) with zero external C library dependencies. When no system D-Bus daemon is present (such as inside minimal containers), the notifier degrades gracefully to a no-op without blocking startup.

### Built-In Observability, Diagnostics, and Web UI Fallback

Presswork extends the stock `cupsd` surface with enterprise-native endpoints and CLI tools while staying 100% compatible with existing IPP clients:

- **HTTP endpoints**: `GET /healthz`, `GET /readyz`, and `GET /metrics` (Prometheus exposition format matching `deploy/monitoring/prometheus-alerts.yaml` and `deploy/monitoring/grafana-dashboard.json`).
- **Built-in status Web UI fallback**: when `WebInterface Yes` is set and no static files or stock CGIs exist in `DocumentRoot` (unified to `/usr/share/cups/doc-root`), Presswork serves a clean, read-only, XSS-escaped HTML status UI on `/`, `/printers`, `/classes`, and `/jobs` with `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Content-Security-Policy` headers instead of returning a bare `404`.
- **CLI diagnostics & structured logging**: `cupsd --check-config [--json]` audits configs for deprecated/moved/unknown directives and security risks; `cupsd doctor [-c ...] [-s ...] [--json]` checks host permissions, MIME DB, binaries, TLS certs, PAM/NSS, and AppArmor conflicts; `--log-format json` (or `PRESSWORK_LOG_FORMAT=json`) emits structured JSON logs alongside enterprise audit events.

### Spool Compatibility Enhancements

- **Job IDs above 99,999**: spool control files (`c<id>`) support variable-width numeric IDs (`c00001` through `c100000+`) instead of failing or resetting `next_id` after job `#99,999`.
- **Crash recovery**: on startup, jobs left in `Processing` state from a prior hard crash are cleanly recovered (requeued or aborted per policy) rather than permanently wedging queues.
- **Zero-downtime `SIGHUP` reload**: reloads `cupsd.conf`, `cups-files.conf`, MIME database, TLS certificates (atomically retaining the previous valid cert on error), and log file descriptors while reporting `RELOADING=1` / `READY=1` via `sd_notify`.

### Local Hardware Backend Notes

- **`usb` backend**: currently operates on Linux `usblp` kernel character devices (`/dev/usb/lp*`, `/dev/usblp*`) with canonical `/dev/` and `S_ISCHR` verification. User-space `libusb` transport and vendor-specific USB quirk tables are not yet implemented.
- **`DocumentRoot` path**: unified to `/usr/share/cups/doc-root` across code defaults, `data/cups-files.conf.default`, and `Makefile`. Override explicitly in `cups-files.conf` if serving custom static assets from another directory.

---

## 3. Transparent Roadmap (Not Yet Implemented)

The following upstream or enterprise capabilities are **not** yet shipped in Presswork and are tracked on the roadmap:

| Capability | Current Status | Planned Direction |
|---|---|---|
| **HTTP/2 transport (`h2`)** | HTTP/1.1 with keep-alive, chunked transfer, `Expect: 100-continue`, and RFC 2817 TLS upgrade are shipped. | Add optional HTTP/2 (`h2`) listener support alongside HTTP/1.1. |
| **OpenTelemetry (OTLP) export** | Prometheus `/metrics` and structured JSON logs are shipped. | Add optional OTLP trace and metric export for distributed tracing across IPP requests and filter pipelines. |
| **Native Kerberos/GSSAPI (`Negotiate`) & OAuth2/OIDC providers** | `crates/authn` provides the extensible `TokenVerifier` trait for `Bearer` tokens, and `cups-config` parses `GSSServiceName`, `OAuthServer`, `OAuthScopes`, and `OAuthGroup`; runtime authentication currently executes PAM, `/etc/shadow`, `SO_PEERCRED`, and mTLS. | Ship built-in SPNEGO/GSSAPI (`Negotiate`) and OIDC JWT/introspection `TokenVerifier` adapters. |
| **Push notification schemes (`mailto:`, `rss:`)** | Pull notifications (`ippget` with `notify-sequence-numbers` and `notify-wait`), persistent `subscriptions.conf`, and D-Bus `org.cups.cupsd.Notifier` signals are shipped. | Add optional outbound `mailto:` and `rss:` notifiers. |
| **IPP System Service (PWG 5100.22)** | Core CUPS 2.x / IPP 1.0–2.2 and IPP Everywhere (68 operations) are shipped. | Implement `Get-System-Attributes`, `Create-Printer`, and system-level IPP System Service operations. |
| **`colord` ICC color profile registration** | `org.cups.cupsd.Notifier` D-Bus signals are shipped; `colord` D-Bus calls are not yet implemented. | Add optional `colord` device/profile registration over D-Bus. |
| **Live `/etc/printcap` generation** | `Printcap` and `PrintcapFormat` directives are parsed by `cups-config`. | Emit live BSD/Solaris/plist `printcap` updates on queue mutations. |
| **`libusb` USB backend & hardware quirk table** | Kernel `usblp` (`/dev/usb/lp*`) backend is shipped. | Add optional `libusb` user-space backend with upstream printer quirk handling. |
| **macOS Tier-2 support** | Linux is the primary supported platform. | Add `launchd` socket activation, macOS `local-cert` auth, and IOKit USB support. |
