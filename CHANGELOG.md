# Changelog

All notable changes to Presswork are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Enterprise readiness, security hardening, observability, packaging, and
documentation overhaul across the full workspace.

### Security

- **Fail-closed authorization (`crates/authz`, `crates/cups-config`, `crates/ops`)**:
  - Switched default `Satisfy` mode to **`Satisfy all`** and made `op_allowed` / `check_op` fail closed across all 68 dispatched IPP operations (`printer-op-policy` -> `DefaultPolicy` -> `"default"`).
  - Eliminated untrusted `requesting-user-name` and HTTP `Host:` header ACL spoofing; enforced canonical `<Location>` path checks, real `@LOCAL` and `@IF(name)` interface matching, IPv6/IPv4-mapped CIDR normalization, `@OWNER`/`@SYSTEM`, `JobPrivate*`/`SubscriptionPrivate*` redaction, and `401`/`426` responses without silent `SO_PEERCRED` fallback on bad `Authorization` headers.
- **Thread-safe POSIX FFI & PAM (`crates/sys`, `crates/authn`)**:
  - Replaced all non-reentrant libc calls with `*_r` variants (`getpwnam_r`, `getpwuid_r`, `getgrnam_r`, `getgrgid_r`, `getspnam_r` with bounded `ERANGE` growth).
  - Added dynamic `dlopen("libpam.so.0")` PAM-first authentication (supporting LDAP/SSSD/AD with zeroized response cleanup and no shadow fallback on PAM deny) and dynamic `crypt_r` resolution (`libcrypt.so.2` -> `libcrypt.so.1` -> `libcrypt.so` -> `RTLD_DEFAULT`) with constant-time comparison and dummy-hash equalization.
  - Redacted `authn::Credentials::secret` in `Debug` output and added extensible `TokenVerifier` trait for `Bearer` tokens.
- **Privilege separation & Linux Landlock sandboxing (`crates/pipeline`, `bins/cups-exec`)**:
  - Implemented real `cups-exec` sandbox launcher with `set_nice`, `umask 077`, `setrlimit`, fail-closed `drop_privileges`, `PR_SET_NO_NEW_PRIVS`, and Linux Landlock rulesets.
  - Hardened filter/backend execution with strict RFC 3986 URI scheme and trusted-dir executable checks, `env_clear()`, expanded prohibited environment blocklist (`LD_*`, `PATH`, `IFS`, `HTTP_PROXY`, interpreter vars), and stripping `DEVICE_URI` credentials from filters.
  - Removed `lp` -> `lpadmin` group membership from installers and packaging.
- **HTTP/1.1 anti-smuggling, TLS/mTLS & CGI hardening (`crates/httpd`, `crates/cups-tls`, `bins/cupsd`)**:
  - Blocked `TE`+`CL`, duplicate `Content-Length`, whitespace before `:`, `obs-fold`, bare `\n\n`, and invalid chunk CRLFs; enforced `413` before `100 Continue`, Slowloris timeouts, `HostValidator` DNS-rebinding defense, and `0600` `O_NOFOLLOW` disk-spooled large bodies.
  - Hardened `cups-tls` with zero `.expect()` panics, `SSLOptions` enforcement (TLS 1.2+ AEAD-only), optional/required mTLS (`WebPkiClientVerifier`), `0700`/`0600` `O_NOFOLLOW` cert/key protection (never overwriting admin certs on error), and atomic `SIGHUP` `ReloadableTls`.
  - Fixed CGI OOB panic, pipe deadlock, HTTPoxy (`HTTP_PROXY`/`HTTP_AUTHORIZATION` stripped), and URL argv injection; enforced canonical `DocumentRoot` containment and security headers on static/HTML responses.
- **PPD, spool & backend SSRF hardening (`crates/ops`, `crates/job`, `crates/printer`, `crates/backend-common`, `bins/backends/*`, `bins/cups-driverd`, `bins/cups-deviced`, `bins/cups-lpd`)**:
  - Hardened PPD validation against CR/LF, Foomatic, and `cups*` injection; enforced canonical containment in `cups-driverd` (`cat`, `drv_ppd`, `#include`), `CUPS-Get-PPD`, and `FileDevice No` fail-closed; blocked `file://` in `Print-URI`/`Send-URI`.
  - Enforced atomic `0600` `O_EXCL|O_NOFOLLOW` spool files and `0640` `O_NOFOLLOW` `printers.conf`/`classes.conf`/`subscriptions.conf`.
  - Added `SsrfPolicy` single-resolution validation across all network backends (`ipp`, `lpd`, `socket`, `snmp`, `dnssd`) blocking metadata, link-local, unspecified, multicast, and loopback targets (loopback opt-in via `CUPS_ALLOW_LOOPBACK_BACKENDS=yes`), plus canonical `/dev/` + `S_ISCHR` + `O_NOFOLLOW|O_NOCTTY` checks in hardware backends.
- **Systemd, container & supply-chain hardening**:
  - Switched `cups.socket` and `cups-lpd.socket` to loopback-only defaults; hardened `cups.service` (`RuntimeDirectory=cups`, `ProtectSystem=strict`, minimal `CapabilityBoundingSet`, `SystemCallFilter=@system-service`, `UMask=0027`, `MemoryMax`/`TasksMax`) and `cups-lpd@.service` (`User=lp`).
  - Hardened `Dockerfile` and `docker-compose.yml` to non-root UID/GID `631:631`, `read_only: true`, `127.0.0.1:8631:631`, `ca-certificates`, `HEALTHCHECK`, and optional `INSTALL_CUPS_FILTERS=true`.
  - Populated canonical `LICENSE-APACHE`, `LICENSE-MIT`, `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, tightened `deny.toml` and `dependabot.yml`, SHA-pinned all GitHub Actions with least-privilege permissions, and added CycloneDX SBOM + SLSA build provenance & SBOM attestations to releases and GHCR images.

### Added

- **Real `cupsfilter(8)` and `cups-exec` binaries** replacing placeholder stubs.
- **Complete IPP 1.0–2.2 operation coverage (68 dispatched ops)** including `Set-Job-Attributes`, `Hold-New-Jobs`, `Release-Held-New-Jobs`, `CUPS-Add-Modify-Class`, `CUPS-Delete-Class`, `CUPS-Authenticate-Job`, `Send-URI`, `Cancel-My-Jobs`, `Cancel-Document`, `Set-Document-Attributes`, `Resubmit-Job`, `Reprocess-Job`, `Schedule-Job-After`, `CUPS-Move-Job` (single & all), real `Validate-Job`, all 11 `which-jobs`, bounded pure-Rust RFC 1952 gzip decompression, and live `queued-job-count`.
- **Event-driven async scheduler & zero-downtime lifecycle (`bins/cupsd`)**: `tokio::sync::Notify` + housekeeping timer, multi-printer concurrent dispatch, `FilterLimit`, class routing, multi-document jobs, active PGID cancellation, full `BackendExit` + `ErrorPolicy` handling, stderr `StatBuf` (`STATE:`/`INFO:`/`PAGE:`/`ATTR:`) consumption, `SIGHUP` hot-reload, graceful `SIGTERM`/`SIGINT` drain, and `sd_notify` (`READY=1`, `RELOADING=1`, `STOPPING=1`, `WATCHDOG=1`).
- **Enterprise observability & CLI diagnostics**: `GET /healthz`, `GET /readyz`, `GET /metrics` (Prometheus), built-in read-only HTML status Web UI fallback (`/`, `/printers`, `/classes`, `/jobs`), `--log-format json` / `PRESSWORK_LOG_FORMAT=json`, enterprise audit log, `page_log`, `cupsd -V`, `cupsd --check-config [--json]`, and `cupsd doctor [--json]`.
- **Pure-Rust D-Bus notifier (`crates/cups-dbus`)**: implements `org.cups.cupsd.Notifier` over D-Bus wire protocol v1 with graceful no-op fallback when no bus is present.
- **Kubernetes & monitoring deployment assets**: Helm v2 chart (`deploy/helm/presswork/`), 6 Prometheus alert rules (`deploy/monitoring/prometheus-alerts.yaml`), and 11-panel Grafana dashboard (`deploy/monitoring/grafana-dashboard.json`).
- **Operational tooling & testing**: `./scripts/dev-local.sh` isolated quickstart, `./scripts/coverage-gate.sh` (`>= 95%` per-crate line coverage gate wired into CI and releases), `make install-files` (`CHOWN=0`) / `make coverage` / `make test-gate`, `tmpfiles.d`, `sysusers.d`, and `logrotate.d` configs.
- **Expanded fuzzing (`fuzz/`)**: 4 new targets (`httpd_parse`, `authn_parse`, `backend_uri`, `dnssd_uri`) for 8 total `libFuzzer` targets with curated seed corpora.
- **Documentation & Unix man pages**: comprehensive `docs/deviations.md`, enterprise SRE manual `docs/operations.md`, rewritten conflict-free `docs/migration.md`, updated `README.md`/`docs/*`/`RELEASING.md`, and groff man pages (`man/cupsd.8`, `man/cupsd.conf.5`, `man/cups-files.conf.5`, `man/cups-lpd.8`, `man/cupsfilter.8`).

### Fixed

- Fixed multi-stage filter pipeline `argv[6]` corruption so filters 2..N read piped stdin instead of re-reading the raw spool file.
- Fixed `Jobs::load_all` rollover limit above job `#99,999`, startup crash recovery for orphaned `Processing` jobs, `classes.conf` `<Class>` persistence, and `subscriptions.conf` persistence + non-destructive `ippget`.
- Fixed FHS `MimeDb::load_standard` loading `DataDir/mime` + `ServerRoot`, `DataDir`-based `PPDDIR`/`DRVROOT`, unified `DocumentRoot` (`/usr/share/cups/doc-root`), `mime-db` Thompson NFA ERE regex & wildcard/empty-slice/UTF-8 bugs.
- Fixed `ipp` (`http`/`https`, chunked responses, streaming, IPv6, job polling), `lpd` (`cfA`/`dfA`), `snmp` (ASN.1 BER + `snmp.conf` + port probing), `socket` (IPv6, `waiteof`), `serial` (`+` options, `dtrdsr`), `parallel` (short `/dev/parport/` panic), `dnssd`, and `cups-lpd` (`03`/`04` queue state, `05` cancel, both transfer orders).
- Fixed `dnssd` `printer-type` bitmasks, AirPrint `URF=`/`_universal`, real `pdl=`, and UTF-8 percent-decoding in `resolve_uri`.
- Fixed `cups-log` multi-threaded Linux localtime via pure-Rust RFC 8536 `TZif` parsing.
- Fixed `install.sh` (non-destructive config preservation, fail-closed `SHA256SUMS`, `--uninstall`), `scripts/dist.sh` (clean `.deb` staging with zero `/` pollution, `0755` dir normalization, `DEBIAN/conffiles`, reachable `postinst` systemd activation), all distro packages (`debian`, `rpm`, `alpine`, `arch`, `aur-bin`, `nix`), and `.github/workflows/release.yml` + `publish.yml` (`workflow_call` chaining, 4-target Linux build matrix).

---

## [0.1.0] - 2026-11-12

First public release: a memory-safe Rust reimplementation of the CUPS 2.x
print spooler and IPP scheduler, built for drop-in compatibility.

### Highlights

- **cupsd** scheduler: Tokio-based, reads `/etc/cups/cupsd.conf`,
  `cups-files.conf`, and `printers.conf` in place with the upstream FHS layout,
  socket activation, and `SO_PEERCRED` local auth.
- **IPP surface**: operations, status codes, attribute groups, and wire
  encoding verified against the upstream `ipptool` corpus — 34 passed / 0
  failed / 1 skipped (documented in `docs/conformance.md`).
- **Stock client compatibility**: upstream `lp`, `lpq`, `lpr`, `cancel`,
  `lpstat`, `lpadmin`, `lpinfo`, `lpoptions`, `cupsenable`, `cupsaccept`, and
  `cups-lpd` (RFC 1179) verified end to end — the upstream `test/5.x` client
  suite passes 34/34.
- **Driverless first**: IPP Everywhere and `driverless` PPD generation via
  `cups-driverd`, plus PPD/legacy-driver persistence under `ServerRoot/ppd`.
- **Backends**: `socket`, `file`, `ipp`/`ipps`, `lpd`, `dnssd`, `snmp`, `usb`,
  `parallel`, and `serial`.
- **Safety boundary**: `#![forbid(unsafe_code)]` workspace-wide outside the
  audited `crates/sys` FFI shim, enforced in CI.

### Validation

- `cargo audit` and `cargo deny`: clean.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean on stable and
  MSRV 1.88; `cargo fmt --check`: clean.
- Initial `cargo-fuzz` targets exercised (`ipp_decode`, `config_lexer`,
  `printers_conf`, `mime_db`).
- Differential runner (`scripts/differential.sh`) verified parity against stock
  `cupsd`.

### Known limitations (as of 0.1.0)

- Physical-printer hardware matrix (real USB/serial/network devices) is not yet
  covered by CI.
- Native Kerberos/GSSAPI and OIDC provider adapters are on the roadmap (see
  `docs/deviations.md`).
- Stock CUPS CGIs remain optional alongside the built-in read-only HTML status
  fallback.
