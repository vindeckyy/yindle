# Presswork Documentation

Presswork is a memory-safe, enterprise-hardened, drop-in replacement for the CUPS 2.x print spooler and IPP scheduler (`cupsd`), written in Rust. It preserves the Common UNIX Printing System's IPP 1.0–2.2 wire protocol, `/etc/cups` configuration files, `/var/spool/cups` spool layout, and filter/backend process contracts so existing clients, desktop print dialogs, scripts, and drivers work unmodified.

## Highlights

- **Memory safety by construction** — `#![forbid(unsafe_code)]` across every crate and binary outside a single audited FFI crate (`crates/sys`), backed by 8 `libFuzzer` targets and a `>= 95%` per-crate line coverage gate.
- **Hardened out of the box** — fail-closed `Satisfy all` authorization, loopback-only default sockets, `cups-exec` privilege drop + Linux Landlock sandboxing, PAM-first auth + mTLS, outbound backend SSRF protection, and `0600` atomic spool files.
- **Drop-in CUPS 2.x compatibility** — 68 IPP operations, driverless IPP Everywhere & AirPrint DNS-SD, `.drv`/PPD legacy driver support, persistent `printers.conf`/`classes.conf`/`subscriptions.conf`, `cups-lpd`, `cupsfilter`, and all 9 standard backends.
- **Enterprise-observable & zero-downtime** — built-in `/healthz`, `/readyz`, `/metrics` (Prometheus), Grafana dashboard & alert rules, Helm chart, structured JSON & audit logging, `SIGHUP` hot-reload, `cupsd --check-config`, and `cupsd doctor`.
- **Verified against upstream** — `ipptool` `test/4.x` + `examples/` conformance matrix passes 34/0/1 and the stock-client `test/5.x` suite passes 34/34.

## Quickstart

```sh
# 1. Local isolated dev & smoke test (zero root, port 8631)
./scripts/dev-local.sh

# 2. Containerized eval via Docker Compose (non-root UID 631, 127.0.0.1:8631)
docker compose up --build -d

# 3. Native Linux install (x86_64 & aarch64, verified SHA256SUMS)
curl -fsSL https://raw.githubusercontent.com/vindeckyy/presswork/main/install.sh | sh
```

## Documentation Guide

- [Installation Guide](install.md) — local dev, Docker/Compose, Kubernetes Helm, `install.sh`, `.deb`, RPM, Arch/AUR, Alpine, Nix, Homebrew, and source builds
- [Migrating from Stock CUPS](migration.md) — read-only config audit, conflict-free side-by-side shadow testing on port `8631`, zero-downtime cutover, and clean rollback
- [Enterprise Operations & SRE Runbook](operations.md) — systemd/container/Helm deployments, Prometheus/Grafana observability, `SIGHUP` reloads, TLS/mTLS rotation, AppArmor/SELinux notes, HA, backups, and incident runbooks
- [Compatibility Matrix](compatibility.md) — IPP 1.0–2.2 operations, transports, drivers, backends, auth, and platform support
- [Conformance Matrix & Methodology](conformance.md) — upstream `ipptool` (`test/4.x` + `examples/`), stock-client (`test/5.x`), and differential test results
- [Documented Deviations](deviations.md) — intentional security-first defaults, runtime differences (`cups-filters`, dynamic PAM/`libcrypt`), and transparent roadmap
- [Security Architecture & Threat Model](security.md) — CVE-2024-47176 class elimination, sandboxing, HTTP/TLS/SSRF hardening, and supply-chain verification
- [0.1.0 Release Announcement](announce-0.1.0.md) — initial public release notes

Source, issues, security advisories, and releases:
[github.com/vindeckyy/presswork](https://github.com/vindeckyy/presswork)
