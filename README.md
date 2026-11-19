# yindle

[![CI](https://github.com/vindeckyy/yindle/actions/workflows/ci.yml/badge.svg)](https://github.com/vindeckyy/yindle/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](LICENSE-APACHE)
[![MSRV](https://img.shields.io/badge/rust-1.88%2B-orange)](Cargo.toml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/vindeckyy/yindle/badge)](https://scorecard.dev/viewer/?uri=github.com/vindeckyy/yindle)
[![Conformance](https://img.shields.io/badge/upstream%20conformance-34%2F0%2F1-brightgreen)](docs/conformance.md)

A memory-safe, enterprise-hardened **CUPS replacement in Rust**: a drop-in
`cupsd` print server and IPP 1.0–2.2 scheduler for Linux that keeps the Common
UNIX Printing System's wire protocol, `/etc/cups` configuration files,
`/var/spool/cups` layout, and filter/backend process contracts so existing
applications, desktop print dialogs, scripts, driverless IPP Everywhere
printers, and AirPrint clients work unmodified.

**Conformance & Quality:** upstream `ipptool` (`test/4.x` + `examples/`)
passes **34 passed / 0 failed / 1 skipped**; upstream `test/5.x` stock-client
suite passes **34/34** ([`docs/conformance.md`](docs/conformance.md)); every
workspace crate enforces a **`>= 95%` per-crate line coverage gate**
([`scripts/coverage-gate.sh`](scripts/coverage-gate.sh)) and `#![forbid(unsafe_code)]`
outside one audited FFI crate (`crates/sys`).

**Contents**:
[60-Second Quickstart](#60-second-quickstart) ·
[Enterprise Features](#enterprise-features) ·
[Architecture & Workspace Layout](#architecture--workspace-layout) ·
[Building & Testing](#building--testing) ·
[Documentation](#documentation) ·
[FAQ](#faq) ·
[License](#license)

---

## 60-Second Quickstart

Choose the path that fits your environment—none of the evaluation paths collide
with an existing host CUPS daemon on port `631`.

### Path 1: One-Command Local Dev (Zero Root, Zero Host Conflict)

Clone the repository and run the automated isolated smoke test on
`127.0.0.1:8631` (builds, starts an unprivileged daemon, probes `/healthz`,
creates a queue, prints a test job, verifies output, and cleans up):

```sh
./scripts/dev-local.sh
# Keep the isolated daemon running for interactive testing (Ctrl-C to stop):
./scripts/dev-local.sh --keep
```

### Path 2: Docker Compose (Zero Host Install, Port `8631`)

Runs as non-root `lp` (`631:631`) with `read_only: true`, `cap_drop: [ALL]`,
persistent volumes, and a built-in `/healthz` `HEALTHCHECK`, bound safely to
host loopback `127.0.0.1:8631`:

```sh
docker compose up --build -d
# Optional: bundle OpenPrinting cups-filters for legacy PPD/PostScript queues:
# INSTALL_CUPS_FILTERS=true docker compose up --build -d

curl -fsS http://127.0.0.1:8631/healthz
curl -fsS http://127.0.0.1:8631/readyz
lpstat -h 127.0.0.1:8631 -t
```

Multi-arch images (`linux/amd64`, `linux/arm64`) are published to
`ghcr.io/vindeckyy/yindle` with OCI SBOM and SLSA provenance attestations.

### Path 3: Production Native Linux, Package, or Kubernetes

- **Native Linux installer (`x86_64` & `aarch64`, fail-closed `SHA256SUMS`, preserves `/etc/cups`)**:
  ```sh
  curl -fsSL https://raw.githubusercontent.com/vindeckyy/yindle/main/install.sh | sh
  ```
- **Debian / Ubuntu `.deb`** (from [GitHub Releases](https://github.com/vindeckyy/yindle/releases), declares `Provides: cups, cups-daemon`, `Recommends: cups-client, cups-filters`, and `DEBIAN/conffiles`):
  ```sh
  sudo apt-get install -y ./yindle_0.1.1-1_amd64.deb
  ```
- **Kubernetes / Helm** ([`deploy/helm/yindle/`](deploy/helm/yindle/Chart.yaml)):
  ```sh
  helm upgrade --install yindle ./deploy/helm/yindle \
    --namespace printing --create-namespace \
    --set serviceMonitor.enabled=true
  ```

After a native install, verify config, host readiness, and queues:

```sh
cupsd -V
sudo cupsd --check-config
sudo cupsd doctor
sudo usermod -aG lpadmin "$USER"   # grant @SYSTEM admin access (re-login)
lpstat -t
```

See [`docs/install.md`](docs/install.md) for RPM, Arch/AUR, Alpine (OpenRC),
Nix, Homebrew, and SLSA/SBOM verification instructions, and
[`docs/migration.md`](docs/migration.md) for conflict-free side-by-side shadow
testing and zero-downtime migration from OpenPrinting CUPS.

---

## Enterprise Features

- **Memory safety & fuzzing**: `#![forbid(unsafe_code)]` across all 31 crates
  and binaries outside `crates/sys` (which uses reentrant `*_r` POSIX APIs),
  **8 `libFuzzer` targets** under [`fuzz/`](fuzz/Cargo.toml) (`ipp_decode`,
  `config_lexer`, `mime_db`, `printers_conf`, `httpd_parse`, `authn_parse`,
  `backend_uri`, `dnssd_uri`), `cargo audit` + `cargo deny`, and OpenSSF
  Scorecard. Eliminates the September 2024 CUPS RCE class (CVE-2024-47176 et
  al.) structurally—see [`docs/security.md`](docs/security.md).
- **Security-first defaults & Linux Landlock sandboxing**: fail-closed
  `Satisfy all` authorization across all 68 IPP operations, loopback-only
  default `cups.socket` & `cups-lpd.socket`, real `cups-exec` privilege drop
  (`User`/`Group`, `umask 077`, `setrlimit`, `PR_SET_NO_NEW_PRIVS`, Linux
  Landlock rulesets), `0600` atomic `O_NOFOLLOW` spool files, hardened systemd
  units (`ProtectSystem=strict`, minimal `CapabilityBoundingSet`,
  `SystemCallFilter=@system-service`), and outbound backend SSRF blocking
  (`SsrfPolicy`).
- **Enterprise AuthN & TLS/mTLS**: dynamic PAM-first HTTP Basic auth
  (`dlopen("libpam.so.0")` for LDAP/SSSD/AD, with reentrant dynamic `crypt_r`
  shadow fallback only when PAM is absent), kernel-verified `SO_PEERCRED`,
  extensible `TokenVerifier` trait for Bearer/OAuth2 tokens, `rustls` TLS 1.2+
  (AEAD-only) with optional/required **mTLS** client certificate verification,
  and atomic `SIGHUP` certificate hot-reload.
- **Full CUPS 2.x spooler & driverless printing**: event-driven async job
  scheduler with crash recovery, multi-document jobs, printer classes
  (`classes.conf`), persistent subscriptions (`subscriptions.conf`) with
  non-destructive `ippget`, IPP Everywhere / AirPrint DNS-SD (`URF=` +
  `_universal`), `.drv`/PPD legacy driver support, pure-Rust D-Bus
  `org.cups.cupsd.Notifier`, and full compatibility with unmodified
  `cups-client` tools and OpenPrinting `cups-filters`.
- **SRE Observability & Zero-Downtime Lifecycle**: built-in `GET /healthz`,
  `GET /readyz`, `GET /metrics` (Prometheus), ready-to-import Prometheus alert
  rules ([`deploy/monitoring/prometheus-alerts.yaml`](deploy/monitoring/prometheus-alerts.yaml))
  and 11-panel Grafana dashboard
  ([`deploy/monitoring/grafana-dashboard.json`](deploy/monitoring/grafana-dashboard.json)),
  built-in read-only HTML status Web UI fallback (`/`, `/printers`, `/classes`,
  `/jobs`), structured JSON logging (`--log-format json`), enterprise audit
  logging, `page_log` accounting, `SIGHUP` zero-downtime reload, `sd_notify`
  lifecycle/watchdog, `cupsd --check-config [--json]`, and
  `cupsd doctor [--json]`.
- **Supply-chain provenance**: multi-arch release artifacts (`x86_64`/`aarch64`
  `glibc` & `musl` tarballs + `.deb` + GHCR images) with `SHA256SUMS`,
  CycloneDX SBOMs (`*.cdx.json`), and signed GitHub SLSA provenance + SBOM
  attestations.

---

## Architecture & Workspace Layout

`yindle` is the project name; installed executables keep the upstream CUPS
names and FHS layout for drop-in compatibility.

### Library Crates (`crates/` — 17 Crates)

| Crate | Purpose |
|---|---|
| `ipp-codec` | Pure-Rust IPP 1.0–2.2 wire codec + model with bounded `DecodeLimits` |
| `httpd` | Anti-smuggling HTTP/1.1 server, Slowloris timeouts, `HostValidator`, disk-spooled bodies, RFC 2817 TLS upgrade |
| `cups-config` | `cupsd.conf` / `cups-files.conf` parsers, IPv4/IPv6/`@LOCAL`/`@IF` ACLs, `--check-config` migration/security auditor |
| `mime-db` | `mime.types` / `mime.convs` loader (`DataDir/mime` + `ServerRoot`), linear-time NFA regex engine, Dijkstra filter graph |
| `authz` | Fail-closed `Satisfy all` `<Location>` and `<Policy>` authorization engine (`@OWNER`, `@SYSTEM`, `Require`) |
| `authn` | PAM-first Basic auth + constant-time shadow fallback, redacted `Credentials`, extensible `TokenVerifier` trait |
| `job` | Job state machine, atomic `0600` spool persistence (`>99,999` IDs), startup crash recovery, `job.cache` |
| `printer` | Printer & class registry (`printers.conf`, `classes.conf`), class member routing, CSPRNG UUID v4 |
| `pipeline` | Multi-stage filter/backend supervisor (`argv[0..6]`, stderr `StatBuf`, fd 3/4 channels, Landlock/privdrop, PGID kill) |
| `ops` | 68-operation IPP 1.0–2.2 dispatcher (`dispatch_async`), PPD/URI hardening, quotas, bounded RFC 1952 gzip |
| `events` | RFC 3995 subscriptions, `subscriptions.conf` persistence, non-destructive `ippget` ring buffer & `notify-wait` |
| `dnssd` | AirPrint/mDNS registration & browsing (`URF=`, `_universal`, official `printer-type` bitmasks, `pdl=`) |
| `cups-tls` | `rustls` TLS 1.2+ config (`SSLOptions`), optional/required mTLS, `0700`/`0600` key perms, atomic `ReloadableTls` |
| `cups-dbus` | Pure-Rust D-Bus v1 wire publisher for `org.cups.cupsd.Notifier` (graceful no-op when bus absent) |
| `cups-log` | Thread-safe `TZif` localtime `error_log`/`access_log`/`page_log`, `MaxLogSize` rotation, structured JSON & audit log |
| `backend-common` | Shared backend argv/exit contract, discovery sanitization, URI credential redaction, `SsrfPolicy`, safe `/dev/` open |
| `sys` (`yindle-sys`) | Single audited `unsafe` crate: reentrant `*_r` NSS/shadow, dynamic PAM & `crypt_r`, `SO_PEERCRED`, `sd_notify`, privdrop, Landlock |

### Executables (`bins/` — 15 Binaries)

| Binary | Install Path | Purpose |
|---|---|---|
| `cupsd` | `/usr/sbin/cupsd` | Core IPP scheduler, HTTP/TLS server, observability endpoints, `--check-config`, `doctor` |
| `cupsfilter` | `/usr/bin/cupsfilter` | Standalone `cupsfilter(8)` MIME/PPD filter-chain runner & `--list-filters` inspector |
| `cups-exec` | `/usr/lib/cups/daemon/cups-exec` | Privilege-drop & Linux Landlock sandbox launcher for filters and backends |
| `cups-deviced` | `/usr/lib/cups/daemon/cups-deviced` | Hardened parallel device discovery multiplexer with child reaping |
| `cups-driverd` | `/usr/lib/cups/daemon/cups-driverd` | Path-contained `.ppd`/`.ppd.gz` & `.drv` driver database enumerator and PPD compiler |
| `cups-lpd` | `/usr/lib/cups/daemon/cups-lpd` | Hardened RFC 1179 LPD-to-IPP bridge (streaming `0600` temp spool, real `Get-Jobs`/`Cancel-Job`) |
| `socket` | `/usr/lib/cups/backend/socket` | AppSocket/JetDirect raw TCP/9100 backend (IPv6, `waiteof`, SSRF policy) |
| `ipp` | `/usr/lib/cups/backend/ipp` | `ipp`/`ipps`/`http`/`https` backend (IPv6, streaming, chunked, job polling, CA trust, SSRF policy) |
| `lpd` | `/usr/lib/cups/backend/lpd` | RFC 1179 outbound LPD backend (`cfA`/`dfA`, control sanitization, SSRF policy) |
| `snmp` | `/usr/lib/cups/backend/snmp` | ASN.1 BER SNMP network printer discovery (`snmp.conf`, 9100/631/515 port probing) |
| `dnssd` | `/usr/lib/cups/backend/dnssd` | mDNS `dnssd://` discovery and safe `ipp` handoff |
| `file` | `/usr/lib/cups/backend/file` | Fail-closed `FileDevice`-gated file output backend (`0600`, `O_NOFOLLOW`) |
| `usb` | `/usr/lib/cups/backend/usb` | Linux `usblp` (`/dev/usb/lp*`) character-device backend with IEEE-1284 sanitization |
| `serial` | `/usr/lib/cups/backend/serial` | Serial `/dev/` character-device backend (`O_NOCTTY`, `+`/`&` options, `dtrdsr`) |
| `parallel` | `/usr/lib/cups/backend/parallel` | Parallel `/dev/lp*` & `/dev/parport/*` character-device backend |

---

## Building & Testing

Requires Rust `1.88+`, `cc`, `cmake`, and `make`:

```sh
# Build and run the full workspace test suite
cargo build --workspace --release --locked
cargo test --workspace --locked

# Run the complete CI quality gate (fmt + clippy -D warnings + tests + >=95% per-crate coverage)
make test-gate

# Or run the >=95% per-crate line coverage gate directly
./scripts/coverage-gate.sh --summary

# Run the upstream OpenPrinting ipptool conformance suite (requires ipptool)
make conformance

# Install to standard FHS paths (preserves existing /etc/cups/*.conf)
sudo make install
```

Distro packaging specs live under `packaging/` (`debian`, `rpm`, `alpine`,
`arch`, `aur-bin`, `nix`), man pages under `man/` (`cupsd(8)`, `cupsd.conf(5)`,
`cups-files.conf(5)`, `cups-lpd(8)`, `cupsfilter(8)`), and release artifacts are
reproduced locally via `./scripts/dist.sh`.

---

## Documentation

- [Documentation Hub](docs/index.md)
- [Installation Guide](docs/install.md) — local dev, Docker/Compose, Helm, `install.sh`, distro packages, SBOM/SLSA verification
- [Migration Guide](docs/migration.md) — read-only config audit, conflict-free shadow test on `:8631`, cutover & rollback
- [Enterprise Operations & SRE Runbook](docs/operations.md) — systemd/container/K8s ops, Prometheus/Grafana, `SIGHUP`, TLS/mTLS, AppArmor/SELinux, HA, backups & incident runbooks
- [Compatibility Matrix](docs/compatibility.md) — IPP 1.0–2.2, transports, drivers, backends & platforms
- [Conformance Matrix](docs/conformance.md) — upstream `ipptool` (`test/4.x` + `examples/`) & `test/5.x` results
- [Documented Deviations](docs/deviations.md) — intentional security defaults, runtime dependencies & roadmap
- [Security Architecture](docs/security.md) & [Security Policy](SECURITY.md)
- [Contributing Guide](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), [Changelog](CHANGELOG.md), [Releasing](RELEASING.md)

---

## FAQ

**Can yindle replace `cupsd` on a running Linux system?**
Yes. It reads `/etc/cups/*` in place, keeps your queues and spool, installs the
standard `cups.service` / `cups.socket` / `cups.path` units, and speaks the same
IPP protocol on `/run/cups/cups.sock` and port `631`. The `.deb` declares
`Provides: cups, cups-daemon` and preserves existing configs via
`DEBIAN/conffiles`. Follow [`docs/migration.md`](docs/migration.md) to run a
zero-risk side-by-side shadow test on port `8631` first.

**Do GNOME/KDE print dialogs, `lp`, `lpr`, Firefox, and macOS/iOS clients still work?**
Yes—they speak IPP/AirPrint to port `631` or `/run/cups/cups.sock`, which is
unchanged. The upstream `test/5.x` client suite passes 34/34 against Yindle
using unmodified stock `cups-client` binaries.

**Do I still need `cups-filters`?**
For driverless IPP Everywhere / AirPrint printers (PDF, PWG Raster, URF), no.
For legacy PPD printers requiring PostScript/PDF/raster conversion filters
(`pstops`, `pdftopdf`, `rastertopwg`), yes—keep or install your distribution's
`cups-filters` package (or pass `--build-arg INSTALL_CUPS_FILTERS=true` in
Docker).

**Does Yindle work alongside stock CUPS for testing?**
Yes. Run `./scripts/dev-local.sh --keep`, `docker compose up --build -d` (binds
`127.0.0.1:8631`), or follow the isolated shadow-test instructions in
[`docs/migration.md`](docs/migration.md).

**Is this affiliated with OpenPrinting/CUPS?**
No. Yindle is an independent implementation of the IPP standards and CUPS
file/process contracts.

---

## License

Dual-licensed under **`Apache-2.0 OR MIT`** ([`LICENSE-APACHE`](LICENSE-APACHE),
[`LICENSE-MIT`](LICENSE-MIT)). Upstream OpenPrinting CUPS MIME database files
(`data/mime/mime.types`, `data/mime/mime.convs`) are licensed solely under
**Apache-2.0**—see [`NOTICE`](NOTICE) for complete license scoping and
third-party attributions.
