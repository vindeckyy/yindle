# Installing Yindle

Yindle installs the standard CUPS FHS layout (`/usr/sbin/cupsd`, `/usr/bin/cupsfilter`, `/usr/lib/cups/{daemon,backend,filter}`, `/usr/share/cups/mime`, `/etc/cups`, `/var/{spool,log,cache}/cups`, `/run/cups`) and standard systemd units (`cups.service`, `cups.socket`, `cups.path`, `cups-lpd.socket`, `cups-lpd@.service`).

> **Companion packages**: Yindle replaces the scheduler, helper daemons, and backends. Keep your distribution's **`cups-client`** (for `lp`, `lpr`, `lpstat`, `lpadmin`, `cancel`) and, if printing to non-driverless / legacy PPD printers, **`cups-filters`** (for `pstops`, `pdftopdf`, `rastertopwg`, etc.).

---

## 1. Local Evaluation (Zero Root, Zero Host Conflict)

Clone the repository and run the automated isolated smoke test on `127.0.0.1:8631`:

```sh
./scripts/dev-local.sh          # builds, starts on :8631, prints a test job, cleans up
./scripts/dev-local.sh --keep   # keeps isolated daemon running until Ctrl-C
```

---

## 2. Docker & Docker Compose (Zero Host Install)

Multi-arch container images (`linux/amd64`, `linux/arm64`) are published to GHCR with OCI SBOM and SLSA provenance attestations and run as non-root `lp` (`631:631`) with `ca-certificates` and a built-in `/healthz` `HEALTHCHECK`.

### Docker Compose (Recommended — Hardened & Loopback-Only on `:8631`)

```sh
docker compose up --build -d

# Optional: bundle OpenPrinting cups-filters for legacy PPD conversion
INSTALL_CUPS_FILTERS=true docker compose up --build -d
```

The shipped `docker-compose.yml` binds `127.0.0.1:8631:631`, uses `read_only: true`, `no-new-privileges:true`, `cap_drop: [ALL]` + `NET_BIND_SERVICE`, `net.ipv4.ip_unprivileged_port_start: 631`, and persistent volumes for `/etc/cups`, `/var/spool/cups`, `/var/log/cups`, and `/var/cache/cups`.

### Standalone `docker run`

```sh
docker run -d --name yindle \
  -p 127.0.0.1:8631:631 \
  --read-only \
  --security-opt no-new-privileges:true \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --sysctl net.ipv4.ip_unprivileged_port_start=631 \
  --tmpfs /run/cups:uid=631,gid=631,mode=0755 \
  --tmpfs /tmp:uid=631,gid=631,mode=1777 \
  -v cups-etc:/etc/cups \
  -v cups-spool:/var/spool/cups \
  -v cups-log:/var/log/cups \
  -v cups-cache:/var/cache/cups \
  ghcr.io/vindeckyy/yindle:0.1.1
```

Verify the container without touching host CUPS:

```sh
curl -fsS http://127.0.0.1:8631/healthz
curl -fsS http://127.0.0.1:8631/readyz
lpstat -h 127.0.0.1:8631 -t
```

---

## 3. Kubernetes (Helm Chart)

Deploy Yindle as a hardened non-root StatefulSet with PVCs, `/healthz` + `/readyz` probes, `NetworkPolicy`, and optional Prometheus `ServiceMonitor`:

```sh
helm upgrade --install yindle ./deploy/helm/yindle \
  --namespace printing --create-namespace \
  --set serviceMonitor.enabled=true
```

See [docs/operations.md#kubernetes--helm-deployhelmyindle](operations.md#kubernetes--helm-deployhelmyindle) for full values, Prometheus alert rules (`deploy/monitoring/prometheus-alerts.yaml`), and Grafana dashboard import (`deploy/monitoring/grafana-dashboard.json`).

---

## 4. Native Linux Installer (`install.sh`, `x86_64` & `aarch64`)

```sh
curl -fsSL https://raw.githubusercontent.com/vindeckyy/yindle/main/install.sh | sh
```

What `install.sh` does:
- Detects `x86_64` or `aarch64` Linux and downloads the matching release tarball.
- **Fails closed on integrity verification**: downloads `SHA256SUMS` and verifies the tarball digest before extracting (refuses to proceed if checksums cannot be verified unless `--insecure-skip-verify` is explicitly passed).
- **Preserves existing operator configs**: never overwrites existing `/etc/cups/cupsd.conf`, `/etc/cups/cups-files.conf`, `/etc/pam.d/cups`, or `/etc/logrotate.d/yindle` (writes new defaults to `*.new` / `*.default`).
- Creates `lp` and `lpadmin` accounts without adding `lp` to `lpadmin`, installs `/usr/lib/tmpfiles.d/yindle.conf` and `/usr/lib/sysusers.d/yindle.conf`, enables `cups.socket` + `cups.path` (loopback-only by default), and runs `cupsd -t`.

Supported installer flags:

| Flag | Behavior |
|---|---|
| `--no-start` | Install binaries, configs, and units without starting services |
| `--version VER` | Install a specific release version (default: latest) |
| `--from DIR` | Install from an already-unpacked release directory |
| `--force` | Proceed even if another `/usr/sbin/cupsd` is already present |
| `--insecure-skip-verify` | Skip `SHA256SUMS` verification (not recommended) |
| `--uninstall` | Remove installed Yindle binaries and units (preserves `/etc/cups/*.conf` and `/var/spool/cups`) |

---

## 5. Distribution Packages

### Debian / Ubuntu (`.deb`)

Download `yindle_<version>-1_amd64.deb` from the [GitHub Releases](https://github.com/vindeckyy/yindle/releases) page:

```sh
sudo apt-get install -y ./yindle_0.1.1-1_amd64.deb
```

The `.deb` declares `Provides: cups, cups-daemon`, `Conflicts: cups, cups-daemon`, `Replaces: cups-daemon`, `Recommends: cups-client, cups-filters`, registers `DEBIAN/conffiles`, sets proper directory/config permissions, and enables `cups.socket` + `cups.path`. You can also build a native Debian package from source via `dpkg-buildpackage -us -uc` using `packaging/debian/`.

### Release Tarballs (`glibc` & `musl`, `x86_64` & `aarch64`)

Each release publishes four Linux tarballs:
- `yindle-<version>-x86_64-unknown-linux-gnu.tar.gz`
- `yindle-<version>-aarch64-unknown-linux-gnu.tar.gz`
- `yindle-<version>-x86_64-unknown-linux-musl.tar.gz`
- `yindle-<version>-aarch64-unknown-linux-musl.tar.gz`

Extract and install with the bundled installer:

```sh
tar -xzf yindle-0.1.1-x86_64-unknown-linux-gnu.tar.gz
cd yindle-0.1.1
./install.sh --from .
```

### Fedora / RHEL / Rocky / AlmaLinux (RPM)

Build an RPM from `packaging/rpm/yindle.spec` (supports unprivileged `rpmbuild`/`mock` builds with `CHOWN=0`, `%config(noreplace)`, `tmpfiles.d`, and `sysusers.d`).

### Arch Linux / AUR

- Source package: `packaging/arch/PKGBUILD` (`depends=('glibc' 'gcc-libs' 'libxcrypt')`; uses dynamic `libcrypt.so.2` resolution—no `libxcrypt-compat` needed).
- Prebuilt binary package: `packaging/aur-bin/PKGBUILD` (`yindle-bin`).

### Alpine Linux (OpenRC)

`packaging/alpine/APKBUILD` builds Yindle without systemd units (`INSTALL_SYSTEMD=0`) and installs an executable `/etc/init.d/yindle` OpenRC script.

### Nix / NixOS

`packaging/nix/package.nix` provides a `rustPlatform.buildRustPackage` derivation that stages the FHS layout cleanly without colliding with GNU `file`. When building a release tag locally, update `src.hash` (via `nix-prefetch-github`) and `cargoHash` as noted in the derivation header.

### Homebrew on Linux

```sh
brew install vindeckyy/tap/yindle && brew services start yindle
```

Runs in user space on port `8631` under the Homebrew prefix so it coexists cleanly with a system CUPS daemon.

---

## 6. Building & Installing from Source

Requires Rust `1.88+` (MSRV), `cc`, `cmake` (for `aws-lc-sys` / `ring`), and `make`:

```sh
cargo build --workspace --release --locked
cargo test --workspace --locked
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now cups.socket cups.path
```

Packagers staging into a build root without root privileges can separate build and install:

```sh
cargo build --workspace --release --locked
make install-files DESTDIR=/path/to/stage PROFILE=release CHOWN=0
```

Useful `Makefile` targets: `make build`, `make install`, `make install-files`, `make install-strip`, `make uninstall`, `make check-fmt`, `make clippy`, `make test`, `make coverage`, `make test-gate`, `make conformance`.

---

## 7. Verifying Release Checksums, SBOM & SLSA Provenance

Every tagged GitHub release ships `SHA256SUMS`, a CycloneDX SBOM (`yindle-<version>.cdx.json`), and signed GitHub Artifact Build Provenance + SBOM attestations:

```sh
# 1. Verify SHA-256 digest
sha256sum -c SHA256SUMS --ignore-missing

# 2. Verify SLSA build provenance for a release tarball or .deb (requires gh >= 2.49)
gh attestation verify yindle-0.1.1-x86_64-unknown-linux-gnu.tar.gz \
  --repo vindeckyy/yindle

# 3. Verify container image provenance and SBOM attestations
gh attestation verify oci://ghcr.io/vindeckyy/yindle:0.1.1 \
  --repo vindeckyy/yindle
```

See [SECURITY.md](../SECURITY.md#supply-chain-sbom--provenance-verification) for full verification details.

---

## 8. Post-Install Verification

For a native systemd install:

```sh
cupsd -V
sudo cupsd --check-config
sudo cupsd doctor
sudo usermod -aG lpadmin "$USER"   # grant admin access (re-login to apply)
systemctl status cups.socket cups.service
curl -fsS http://127.0.0.1:631/healthz
lpstat -t
```

Add and test a driverless IPP Everywhere printer:

```sh
lpadmin -p office -E -v ipp://<printer-ip>/ipp/print -m everywhere
lp -d office /etc/hostname
```

Next steps:
- Replacing an existing CUPS daemon: [docs/migration.md](migration.md)
- Production monitoring, TLS/mTLS, AppArmor/SELinux, and runbooks: [docs/operations.md](operations.md)
- Upstream conformance evidence: [docs/conformance.md](conformance.md)
