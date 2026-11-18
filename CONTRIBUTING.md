# Contributing to Presswork

Thank you for your interest in contributing to Presswork! Presswork is an
independent, memory-safe Rust implementation of the CUPS 2.x print spooler and
IPP scheduler (`cupsd`).

> **Security vulnerabilities:** Do **not** open a public issue or pull request
> for security bugs. Follow the private disclosure process in
> [`SECURITY.md`](SECURITY.md).

---

## Code of Conduct

Participation in this project is governed by the
[Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you
agree to uphold these standards.

---

## Development Prerequisites

- **Rust toolchain:** Rust `1.88+` (MSRV) with `rustfmt` and `clippy`
  components (`rustup component add rustfmt clippy llvm-tools-preview`).
- **Build tools:** a C compiler toolchain (`cc`, `cmake`) for `aws-lc-sys` /
  `ring` native crypto primitives, plus `make` and `python3`.
- **Recommended Cargo tools:**
  - `cargo-llvm-cov` — per-crate line coverage enforcement (`>= 95%` gate)
  - `cargo-deny` — advisory, license, ban, and source verification
  - `cargo-audit` — RustSec vulnerability scanning
  - `cargo-fuzz` + nightly toolchain — fuzzing parsers under `fuzz/`
- **Optional (for upstream IPP conformance tests):** `cups-ipp-utils`
  (`ipptool`) on Debian/Ubuntu or equivalent package providing `ipptool`.

---

## Repository Layout

- `crates/` — workspace library crates (`ipp-codec`, `httpd`, `cups-config`,
  `mime-db`, `authz`, `authn`, `job`, `printer`, `pipeline`, `ops`, `events`,
  `dnssd`, `cups-tls`, `cups-dbus`, `cups-log`, `backend-common`, `sys`).
- `bins/` — daemon, helper, and backend executables (`cupsd`, `cups-lpd`,
  `cups-deviced`, `cups-driverd`, `cupsfilter`, `cups-exec`, and
  `bins/backends/*`).
- `data/` & `etc/` — default configs (`cupsd.conf.default`,
  `cups-files.conf.default`), MIME rules, systemd units, `tmpfiles.d`,
  `sysusers.d`, and `logrotate.d` templates.
- `packaging/` — distro packaging specs (Debian, RPM, Arch, AUR, Alpine, Nix).
- `fuzz/` — `cargo-fuzz` targets for wire/config/file parsers.
- `scripts/` — local dev, conformance, coverage-gate, and release artifact
  scripts.

---

## Local Development Workflow

### 1. Format, Lint, Build, and Test

Run the same checks CI executes before opening a pull request:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

### 2. Per-Crate Test Coverage Gate (`>= 95%` Lines)

Presswork enforces **at least 95% line coverage on every workspace crate
individually** (not just a workspace average):

```sh
./scripts/coverage-gate.sh
# Or check a single crate while iterating:
cargo llvm-cov --locked --package ipp-codec --fail-under-lines 95
```

When adding or refactoring binaries under `bins/`, structure business logic into
testable modules/functions (using loopback sockets, temporary directories, or
in-memory I/O) so tests verify real behavior without requiring root privileges
or physical printers. Do not bypass coverage gates with assertionless tests or
blanket `#[coverage(off)]` attributes.

### 3. Config Validation & Supply-Chain Checks

```sh
# Validate shipped configuration files
cargo run --locked -p cupsd -- -t -c etc/cupsd.conf.example
cargo run --locked -p cupsd -- -t -c data/cupsd.conf.default -s data/cups-files.conf.default

# Dependency & license hygiene
cargo deny check
cargo audit
```

### 4. Running a Local Unprivileged Dev Server

You can run Presswork locally without `root` privileges and without conflicting
with a host CUPS installation by using an isolated scratch root on a high port
(e.g., `127.0.0.1:8631`):

```sh
# Automated isolated quickstart & smoke test (if present):
./scripts/dev-local.sh

# Or run the upstream ipptool conformance suite against a scratch root:
./scripts/conformance.sh
```

---

## Coding Standards

1. **Strict `unsafe` confinement:** Every crate and binary outside `crates/sys`
   must retain `#![forbid(unsafe_code)]`. Any `unsafe` block added to
   `crates/sys` requires an explicit `// SAFETY:` justification, minimal scope,
   and thread-safe/reentrant POSIX APIs (`*_r` variants, `O_NOFOLLOW`,
   `FD_CLOEXEC`).
2. **No panics on untrusted input:** Do not use `.unwrap()`, `.expect()`, or
   unchecked slice indexing in daemon, network, parser, config, or backend code
   paths. Return typed `Result` errors and handle invalid/malicious input
   gracefully.
3. **Clippy pedantic clean:** Keep `cargo clippy --workspace --all-targets -- -D warnings`
   clean across both MSRV (`1.88.0`) and current `stable`.
4. **CUPS compatibility fidelity:** When modifying IPP wire behavior, config
   parsing, spool formats, or filter/backend contracts, cite the matching
   upstream CUPS behavior (man page, IPP RFC, or upstream source reference). Any
   intentional divergence must be documented in `docs/deviations.md`.
5. **Security-first defaults:** All network parsers must enforce bounded reads
   and timeouts; access controls must fail closed (`Satisfy All`); secrets and
   credentials must never be logged or exposed in `Debug` output.

---

## Pull Request Process & Checklist

1. Fork the repository and create a topic branch from `main`.
2. Keep commits focused and use clear commit prefixes (`feat:`, `fix:`, `sec:`,
   `ci:`, `docs:`, `test:`, `refactor:`).
3. **Sign off every commit** under the Developer Certificate of Origin (DCO 1.1)
   using `git commit -s` (`Signed-off-by: Your Name <email>`).
4. Fill out [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md)
   completely and confirm all checks pass:
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo test --workspace --locked`
   - `>= 95%` per-crate line coverage (`./scripts/coverage-gate.sh`)
   - `cargo deny check` and `cargo audit`
   - `scripts/conformance.sh` (upstream `ipptool` matrix) when touching protocol,
     scheduler, config, or ops code
   - No `unsafe` introduced outside `crates/sys`

---

## Developer Certificate of Origin (DCO) & Licensing

By contributing to Presswork, you certify that your contribution complies with
the [Developer Certificate of Origin v1.1](https://developercertificate.org/)
(indicated via `Signed-off-by:` in each commit message).

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Presswork by you, as defined in the Apache-2.0 license, shall
be dual-licensed under **`Apache-2.0 OR MIT`** (see [`LICENSE-APACHE`](LICENSE-APACHE),
[`LICENSE-MIT`](LICENSE-MIT), and [`NOTICE`](NOTICE)), without any additional
terms or conditions.
