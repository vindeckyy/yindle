# Releasing Yindle

Releases are tag-driven and gated by automated security, test, per-crate
coverage, `.deb` integrity, SBOM, and SLSA provenance pipelines. Cutting a
release once the version bump commit lands on `main` is two commands:

```sh
git tag -a vX.Y.Z -m "yindle X.Y.Z"
git push origin vX.Y.Z
```

---

## 1. Complete Version-Bump Checklist (Before Tagging)

Every release tag `vX.Y.Z` **must** match `Cargo.toml` and `CITATION.cff` (the
`verify` job in `.github/workflows/release.yml` fails closed on any mismatch).
Update **all** of the following files in one clean release-prep commit:

1. **Workspace version**:
   - `Cargo.toml` — `[workspace.package] version = "X.Y.Z"`
2. **Internal crates.io dependency version pins** (required for `cargo publish` in dependency order):
   - `crates/cups-log/Cargo.toml` — `ipp-codec = { path = "../ipp-codec", version = "X.Y.Z" }`
   - `crates/cups-config/Cargo.toml` — `ipp-codec` and `yindle-sys` `version = "X.Y.Z"`
   - Refresh `Cargo.lock` via `cargo check --workspace` so `--locked` passes cleanly.
3. **Citation & release notes**:
   - `CITATION.cff` — `version: X.Y.Z` and `date-released: "YYYY-MM-DD"`
   - `CHANGELOG.md` — move `[Unreleased]` entries under `## [X.Y.Z] - YYYY-MM-DD` (exact header format parsed by `release.yml`)
4. **Distribution packaging manifests**:
   - `packaging/debian/changelog` — add new `yindle (X.Y.Z-1) unstable` entry
   - `packaging/rpm/yindle.spec` — bump `Version: X.Y.Z` and add `%changelog` entry
   - `packaging/alpine/APKBUILD` — bump `pkgver=X.Y.Z` (update `sha512sums` via `abuild checksum` once the tag tarball exists)
   - `packaging/arch/PKGBUILD` & `packaging/aur-bin/PKGBUILD` — bump `pkgver=X.Y.Z` (update `sha256sums` from release `SHA256SUMS` / `updpkgsums`)
   - `packaging/nix/package.nix` — bump `version = "X.Y.Z"` and update `src.hash` (`nix-prefetch-github`) + `cargoHash`
5. **Container & Kubernetes manifests**:
   - `deploy/helm/yindle/Chart.yaml` — bump `version: X.Y.Z` and `appVersion: "X.Y.Z"`
   - `Dockerfile` — bump default `ARG VERSION=X.Y.Z`
   - `docker-compose.yml` — bump default `ghcr.io/vindeckyy/yindle:X.Y.Z` tag
6. **Documentation examples**:
   - Update version examples in `README.md`, `docs/install.md`, and `docs/migration.md` if referencing a concrete tarball/`.deb`/image tag.

---

## 2. Local Pre-Tag Verification Gates

Run the exact gates enforced in CI and `.github/workflows/release.yml`:

```sh
# 1. Format, pedantic clippy (-D warnings), workspace tests, and >=95% per-crate coverage gate
make test-gate
# Equivalent individual commands:
#   cargo fmt --all -- --check
#   cargo clippy --workspace --all-targets -- -D warnings
#   cargo test --workspace --locked
#   THRESHOLD=95 ./scripts/coverage-gate.sh --summary

# 2. Supply-chain and license hygiene
cargo audit
cargo deny check

# 3. Config & migration self-checks
cargo run --locked -p cupsd -- -t -c etc/cupsd.conf.example
cargo run --locked -p cupsd -- -t -c data/cupsd.conf.default -s data/cups-files.conf.default
cargo run --locked -p cupsd -- --check-config -c data/cupsd.conf.default -s data/cups-files.conf.default

# 4. Upstream ipptool conformance suite (must remain 34/0/1)
./scripts/conformance.sh

# 5. Isolated live smoke test
./scripts/dev-local.sh

# 6. Optional local dry-run of release artifacts (tarball + .deb + SHA256SUMS)
./scripts/dist.sh X.Y.Z
```

---

## 3. Automated Release Pipeline

Pushing a `vX.Y.Z` tag triggers two workflows automatically:

### `.github/workflows/release.yml` (Multi-Arch Binaries, `.deb`, SBOM, SLSA & Crates)

1. **`verify` job**:
   - Validates `vX.Y.Z` semver format and checks exact equality with `Cargo.toml` and `CITATION.cff`.
   - Verifies all governance files (`LICENSE-APACHE`, `LICENSE-MIT`, `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`) are non-empty.
   - Runs `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --locked`, **`./scripts/coverage-gate.sh` (`>= 95%` per-crate line coverage)**, `cargo audit`, and `cargo deny check`.
2. **`build-matrix` job** (4 Linux targets):
   - `x86_64-unknown-linux-gnu` — runs `./scripts/dist.sh` to build the tarball and `.deb`, then runs a strict `.deb` integrity gate (`dpkg-deb -c` verifying zero `/` pollution, `/usr/sbin/cupsd` present, no `0775` umask leaks, valid `DEBIAN/conffiles`, executable syntax-checked `postinst` with no unreachable lines after `exit 0`, no placeholder maintainer addresses).
   - `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` — cross-compiled via `cargo-zigbuild`, staged with `make install-files CHOWN=0`, packaged with deterministic `--owner=0 --group=0` tarballs.
3. **`sbom` job**:
   - Generates a validated CycloneDX JSON SBOM (`yindle-X.Y.Z.cdx.json`) across the workspace lockfile using `anchore/sbom-action`.
4. **`publish-release` job**:
   - Generates a unified `SHA256SUMS` covering all `*.tar.gz`, `*.deb`, and `*.cdx.json` artifacts.
   - Signs **SLSA build provenance** (`actions/attest-build-provenance`) for all tarballs, `.deb` packages, and SBOMs, plus **CycloneDX SBOM attestations** (`actions/attest-sbom`) bound to each package.
   - Extracts the matching `## [X.Y.Z]` section from `CHANGELOG.md` and creates/updates the GitHub Release.
5. **`publish-crates` job (chained `.github/workflows/publish.yml` via `workflow_call`)**:
   - Invoked directly via `workflow_call` after `publish-release` succeeds (avoiding GitHub's `GITHUB_TOKEN` event suppression on `release: [published]`).
   - Publishes the 6 library crates to crates.io in dependency order:
     `ipp-codec` -> `yindle-sys` -> `backend-common` -> `cups-tls` -> `cups-log` -> `cups-config`,
     retaining idempotent skip-if-already-uploaded handling and index-propagation retries, using `CARGO_REGISTRY_TOKEN` via environment variable.
   - Can also be run manually via `workflow_dispatch` with `dry_run: true` to test `cargo package` without uploading.

### `.github/workflows/docker.yml` (Multi-Arch GHCR Container Images)

1. Runs a live container build and HTTP listener smoke test (`cupsd -v`, `cupsd -t`, and live connection check).
2. Builds and pushes multi-arch images (`linux/amd64`, `linux/arm64`) to `ghcr.io/vindeckyy/yindle` with OCI SBOMs, `provenance: mode=max`, and GitHub Artifact Build Provenance attestations (`actions/attest-build-provenance`).

---

## 4. Required Repository Secrets

- **`CARGO_REGISTRY_TOKEN`** — crates.io API token with publish permission, passed into `.github/workflows/publish.yml`.
- `GITHUB_TOKEN` — provided automatically by GitHub Actions with least-privilege job-scoped permissions (`contents: write`, `packages: write`, `id-token: write`, `attestations: write`).

---

## 5. Downstream Distribution Channels

- **GitHub Releases**: 4 Linux tarballs (`glibc` + `musl`, `x86_64` + `aarch64`), Debian `.deb`, CycloneDX SBOM, `SHA256SUMS`, and SLSA attestations.
- **crates.io**: 6 reusable library crates published via chained `publish.yml`.
- **GHCR (`ghcr.io/vindeckyy/yindle`)**: multi-arch `linux/amd64` + `linux/arm64` images.
- **Homebrew**: `vindeckyy/homebrew-tap`, `Formula/yindle.rb` — bump `url` and `sha256` to the new release tarball.
- **AUR**: `packaging/aur-bin/` (`yindle-bin`) and `packaging/arch/` (`yindle`) — update `pkgver` and `sha256sums`, run `updpkgsums` and `makepkg --printsrcinfo`.
- **nixpkgs**: `packaging/nix/package.nix` — update `version`, `src.hash`, and `cargoHash`.
- **Debian / RPM / Alpine**: native source specs under `packaging/{debian,rpm,alpine}/`.
- **Helm**: chart under `deploy/helm/yindle/`.

### Curated-List Submissions (Eligibility-Gated)

- **awesome-rust**: requires >50 stars or >2,000 crates.io downloads — submit `vindeckyy/yindle` under "System tools" once eligible.
- **awesome-selfhosted**: requires the first tagged release (`v0.1.0`, `2026-11-12`) to be 4+ months old (eligible **~2027-03-12**) and a human submitter — entries are YAML files in the `awesome-selfhosted-data` repository.
