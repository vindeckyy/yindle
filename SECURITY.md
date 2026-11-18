# Security Policy

Presswork is a network-facing print spooler and IPP scheduler designed as a
memory-safe replacement for CUPS (`cupsd`). We treat security vulnerabilities
as top-priority engineering issues and follow Coordinated Vulnerability
Disclosure (CVD).

---

## Reporting a Vulnerability

**Do NOT open a public GitHub Issue, Pull Request, or Discussion for a suspected
security vulnerability.**

Report vulnerabilities privately through **GitHub Private Vulnerability
Reporting**:

- **Primary channel:** <https://github.com/vindeckyy/presswork/security/advisories/new>

### What to Include

To help us triage and remediate quickly, please include:

1. **Affected version / commit:** output of `cupsd --version` (or `cupsd -v`),
   release tag, or container image digest.
2. **Environment:** OS/distribution, architecture, systemd/container runtime,
   and relevant sanitized `cupsd.conf` / `cups-files.conf` excerpts.
3. **Vulnerability details:** component/crate affected, root cause (if known),
   and impact assessment (e.g., RCE, auth bypass, privilege escalation, SSRF,
   DoS, information disclosure).
4. **Reproduction:** minimal proof-of-concept request, `ipptool` test file,
   malformed input artifact, or step-by-step commands.
5. **Disclosure preference:** whether you wish to be credited in the security
   advisory and release notes.

### Coordinated Vulnerability Disclosure (CVD)

- We request a **90-day coordinated disclosure window** from initial report so
  a fix can be developed, tested, and coordinated with downstream Linux
  distributions before public disclosure.
- For actively exploited zero-day vulnerabilities, we will accelerate triage and
  out-of-band patch releases immediately.
- Confirmed vulnerabilities are published as GitHub Security Advisories with
  CVE identifiers requested through GitHub's CVE Numbering Authority (CNA).

---

## Response SLAs

We target the following response and remediation milestones based on CVSS v3.1
severity:

| Severity | Initial Acknowledgement | Triage & Severity Confirmation | Progress Updates | Patch / Release Target |
|---|---|---|---|---|
| **Critical (9.0–10.0)** | <= 24 hours | <= 48 hours | Every 48 hours | <= 7 days |
| **High (7.0–8.9)** | <= 48 hours | <= 3 business days | Weekly | <= 14–30 days |
| **Medium (4.0–6.9)** | <= 3 business days | <= 5 business days | Bi-weekly | <= 60 days |
| **Low (0.1–3.9)** | <= 5 business days | <= 10 business days | On status change | <= 90 days / next minor release |

---

## Supported Versions

Security fixes and advisories are provided for the following release lines:

| Version | Supported | Notes |
|---|---|---|
| `0.1.x` | Yes | Current minor release line; receives security patches |
| `main` | Best-effort | Active development branch; fixes land here first before backport |
| `< 0.1.0` | No | Pre-release snapshots; upgrade to the latest `0.1.x` release |

Once Presswork reaches `1.0`, the support policy covers the latest minor release
plus one previous minor release (`N` and `N-1`).

---

## Security Architecture Summary

For an extended threat model, see [`docs/security.md`](docs/security.md). Key
architectural security controls:

### 1. Memory Safety & `unsafe` Confinement
- The workspace enforces `#![forbid(unsafe_code)]` across every library crate
  and binary except `crates/sys` (`presswork-sys`), which isolates audited POSIX
  FFI wrappers (reentrant `getpwnam_r`/`getgrnam_r`/`getspnam_r`, `SO_PEERCRED`,
  privilege drop, `rlimit`, `O_NOFOLLOW`, `sd_listen_fds`).
- CI enforces this boundary on every pull request (`forbid-unsafe` job).

### 2. Privilege Separation & Sandboxing
- Filters and backends are executed via direct `execv`-style `Vec<OsString>`
  spawns (never via `/bin/sh`, `system()`, or `popen()`), with strictly
  validated binary paths, allowlisted environment variables (stripping
  credentials and loader/interpreter variables such as `LD_*`, `PATH`, `IFS`),
  and privilege drop (`cups-exec`) to the configured unprivileged `User`/`Group`
  with `umask 077` and resource limits.
- Shipped systemd units enforce least privilege (`ProtectSystem=strict`,
  `ProtectHome=true`, `NoNewPrivileges=true`, restricted
  `CapabilityBoundingSet`, `SystemCallFilter`, memory/task limits) and bind
  `cups.socket` to loopback (`127.0.0.1:631` / `[::1]:631` +
  `/run/cups/cups.sock`) by default.

### 3. Transport Security (TLS / mTLS)
- TLS is provided by `rustls` (`crates/cups-tls`), supporting `SSLListen`,
  `SSLPort`, and RFC 2817 HTTP Upgrade with configurable `SSLOptions`
  (`MinTLS`/`MaxTLS`), optional mutual TLS (mTLS) client certificate
  verification, and strict `0700`/`0600` certificate/key permissions.
- Outbound `ipps://` backends verify server certificates against system trust
  roots and explicitly configured CA bundles.

### 4. Authentication & Authorization
- Local Unix domain socket clients are authenticated via kernel-verified
  `SO_PEERCRED` credentials; HTTP Basic authentication validates against
  PAM / system account databases.
- `<Location>` and `<Policy>`/`<Limit>` rules default to fail-closed
  (`Satisfy All`), enforce `@SYSTEM` and `@OWNER` principals, and validate
  `Host` headers against `ServerName`/`ServerAlias` to mitigate DNS rebinding.
- Sensitive spool files (`c*`, `d*`) and `printers.conf` are written atomically
  with restricted permissions (`0600` / `ConfigFilePerm`, `O_NOFOLLOW`).

### 5. Cryptographic Modules & FIPS 140-3 Note (`aws-lc-sys` / `ring`)
- Presswork's TLS stack (`rustls` 0.23) uses **`aws-lc-rs` / `aws-lc-sys`** as
  its default cryptographic provider, which compiles native C and assembly
  cryptographic primitives derived from AWS-LC. Self-signed certificate
  generation (`rcgen`) additionally uses **`ring`** (native C/assembly).
- **FIPS 140-3 notice:** Standard prebuilt Presswork releases and container
  images compile `aws-lc-sys` in its default (non-FIPS) configuration and are
  **not** FIPS 140-3 certified out of the box. Deployments subject to FIPS 140-3
  mandates must either:
  1. Rebuild Presswork from source enabling the `aws-lc-rs` FIPS module in a
     conforming build environment (with CMake/Clang/Go per AWS-LC-RS FIPS
     guidance), or
  2. Terminate external TLS at a FIPS 140-3 validated reverse proxy/load
     balancer and bind Presswork exclusively to loopback / Unix sockets.

---

## Supply Chain, SBOM & Provenance Verification

Every tagged Presswork release publishes:

- **`SHA256SUMS`** — SHA-256 digests for all tarballs, `.deb` packages, and SBOMs.
- **CycloneDX SBOM (`presswork-<version>.cdx.json`)** — machine-readable
  dependency and license inventory covering the full workspace lockfile.
- **GitHub Artifact Build Provenance & SBOM Attestations** — signed SLSA build
  provenance (`actions/attest-build-provenance`) and SBOM attestations
  (`actions/attest-sbom`) for release assets and multi-arch GHCR container
  images (`ghcr.io/vindeckyy/presswork`).

### Verifying Release Artifacts

1. Verify file checksums:
   ```sh
   sha256sum -c SHA256SUMS --ignore-missing
   ```
2. Verify SLSA build provenance for a tarball or `.deb` package using the
   GitHub CLI (`gh` >= 2.49):
   ```sh
   gh attestation verify presswork-0.1.0-x86_64-unknown-linux-gnu.tar.gz \
     --repo vindeckyy/presswork
   ```
3. Verify container image provenance and SBOM attestations:
   ```sh
   gh attestation verify oci://ghcr.io/vindeckyy/presswork:0.1.0 \
     --repo vindeckyy/presswork
   ```

### Continuous Security Controls
- **Dependency auditing:** `cargo audit` (RustSec) and `cargo deny check`
  (advisories, yanked/unmaintained crates, license allowlist, source registry
  pinning) block CI on every pull request.
- **Automated updates:** Dependabot monitors root Cargo, `fuzz/` Cargo,
  `Dockerfile`, and SHA-pinned GitHub Actions weekly.
- **Fuzzing & coverage:** `cargo-fuzz` smoke runs exercise parsers on every PR,
  and CI enforces a `>= 95%` per-crate line coverage gate (`cargo-llvm-cov`).
- **OpenSSF Scorecard:** Weekly and push-triggered supply-chain checks publish
  SARIF results to GitHub Code Scanning.
