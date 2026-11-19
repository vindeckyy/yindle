# Migrating from OpenPrinting CUPS to Yindle

Yindle is designed to read your existing `/etc/cups` configuration and `/var/spool/cups` layout in place—and to let you validate every queue, policy, and filter chain **side-by-side on port `8631`** without touching or disrupting the live stock `cupsd` until you are ready to cut over.

---

## 0. Companion Packages to Keep

Yindle replaces the `cupsd` scheduler, helper daemons (`cups-deviced`, `cups-driverd`, `cups-exec`, `cups-lpd`), `cupsfilter`, and the 9 standard backends (`socket`, `file`, `ipp`, `lpd`, `snmp`, `usb`, `dnssd`, `serial`, `parallel`). Keep (or install) these two companion packages from your Linux distribution:

| Package (Debian/Ubuntu) | Equivalent (Fedora/RHEL / Arch) | Purpose |
|---|---|---|
| `cups-client` | `cups-client` / `cups` client tools | Provides `lp`, `lpr`, `lpq`, `lprm`, `lpstat`, `lpadmin`, `lpinfo`, `lpoptions`, `cancel`, `cupsenable`, `cupsaccept` |
| `cups-filters` | `cups-filters` | Provides external conversion filters (`pstops`, `pdftopdf`, `pdftoraster`, `rastertopwg`) needed for non-driverless / legacy PPD printers |
| `cups-ipp-utils` *(optional)* | `cups-ipptool` *(optional)* | Provides `ipptool` for automated IPP conformance testing |

> **Driverless-only environments**: If every printer speaks IPP Everywhere / AirPrint (PDF, PWG Raster, or URF), `cups-filters` is optional. For mixed or legacy PostScript/PPD fleets, install `cups-filters`.

---

## 1. Obtain Yindle Without Replacing Stock CUPS Yet

Build from source or unpack a release tarball into a staging directory so `/usr/sbin/cupsd` remains untouched during shadow validation:

```sh
# Option A: Build from a local checkout
cargo build --workspace --release --locked
PW_BIN="$PWD/target/release"

# Option B: Unpack a release tarball (x86_64 or aarch64)
# tar -xzf yindle-0.1.1-x86_64-unknown-linux-gnu.tar.gz
# PW_BIN="$PWD/yindle-0.1.1/usr/sbin"
```

Verify the Yindle binary version:

```sh
"$PW_BIN/cupsd" -V
```

---

## 2. Audit Your Live `/etc/cups` Configuration First (Read-Only)

Before starting a shadow daemon or cutting over, run Yindle's built-in migration linter and diagnostics against your live CUPS configs (strictly read-only):

```sh
# Classify every directive (Supported / Deprecated / Moved / Unknown) and audit security settings
sudo "$PW_BIN/cupsd" --check-config \
  -c /etc/cups/cupsd.conf \
  -s /etc/cups/cups-files.conf

# Machine-readable JSON output for fleet readiness audits
sudo "$PW_BIN/cupsd" --check-config \
  -c /etc/cups/cupsd.conf \
  -s /etc/cups/cups-files.conf --json

# Check host directories, MIME DB, binaries, TLS certs, PAM/NSS, and AppArmor conflicts
sudo "$PW_BIN/cupsd" doctor \
  -c /etc/cups/cupsd.conf \
  -s /etc/cups/cups-files.conf
```

Pay close attention to:
- **`LOCATION_SATISFY_ANY` / `POLICY_SATISFY_ANY`**: Yindle defaults to fail-closed `Satisfy all` (see [docs/deviations.md](deviations.md)). Review any legacy `<Location>` or `<Policy>` block that mixes `Allow`/`Deny` with `Require`.
- **`Moved` directives**: older `cupsd.conf` files occasionally contain directives that belong in `cups-files.conf`.
- **AppArmor notice**: on Debian/Ubuntu, stock `/etc/apparmor.d/usr.sbin.cupsd` attaches to `/usr/sbin/cupsd` and must be handled at cutover (see [Step 5](#5-check-apparmor--selinux-before-cutover)).

---

## 3. Run a Conflict-Free Side-by-Side Shadow Test (Port `8631`)

This sets up a completely isolated runtime root under `/tmp/pw-shadow` with its own listeners (`127.0.0.1:8631` and `/tmp/pw-shadow/run/cups.sock`), spool, cache, and logs. It **never** binds port `631` and **never** writes to `/etc/cups` or `/var/spool/cups`.

```sh
SHADOW=/tmp/pw-shadow
rm -rf "$SHADOW"
mkdir -p "$SHADOW"/{etc/ppd,etc/ssl,spool/tmp,cache/rss,run/certs,logs,tmp,data/mime,doc-root,bin/{daemon,backend,filter,notifier}}

# 1. Copy Yindle helper daemons and backends into the shadow ServerBin
for d in cups-deviced cups-driverd cups-exec cups-lpd; do
  [ -x "$PW_BIN/$d" ] && cp "$PW_BIN/$d" "$SHADOW/bin/daemon/$d"
done
for b in socket file ipp lpd snmp usb dnssd serial parallel; do
  [ -x "$PW_BIN/$b" ] && cp "$PW_BIN/$b" "$SHADOW/bin/backend/$b"
done
# Symlink host cups-filters (if installed) so shadow filter chains match production
if [ -d /usr/lib/cups/filter ]; then
  ln -s /usr/lib/cups/filter/* "$SHADOW/bin/filter/" 2>/dev/null || true
fi

# 2. Copy stock configs, PPDs, and MIME database (note: stock MIME files live in /usr/share/cups/mime/)
sudo cp /etc/cups/cupsd.conf "$SHADOW/etc/cupsd.conf.orig"
[ -f /etc/cups/printers.conf ] && sudo cp /etc/cups/printers.conf "$SHADOW/etc/printers.conf"
[ -f /etc/cups/classes.conf ]  && sudo cp /etc/cups/classes.conf  "$SHADOW/etc/classes.conf"
[ -d /etc/cups/ppd ]           && sudo cp -a /etc/cups/ppd/.     "$SHADOW/etc/ppd/"
sudo chown -R "$(id -un):$(id -gn)" "$SHADOW"

if [ -d /usr/share/cups/mime ]; then
  cp /usr/share/cups/mime/*.types /usr/share/cups/mime/*.convs "$SHADOW/data/mime/" 2>/dev/null || true
else
  cp data/mime/mime.types data/mime/mime.convs "$SHADOW/data/mime/"
fi
# Also carry over any local MIME overrides from /etc/cups
cp /etc/cups/local.types /etc/cups/local.convs "$SHADOW/etc/" 2>/dev/null || true

# 3. Strip ALL existing Listen/Port/SSLListen/SSLPort directives so port 631 is NEVER touched,
#    then bind isolated shadow listeners on 127.0.0.1:8631 and $SHADOW/run/cups.sock.
grep -viE '^[[:space:]]*(Listen|Port|SSLListen|SSLPort)[[:space:]]' \
  "$SHADOW/etc/cupsd.conf.orig" > "$SHADOW/etc/cupsd.conf"
cat >> "$SHADOW/etc/cupsd.conf" <<EOF

# Shadow test listeners (isolated from host CUPS on :631)
Listen 127.0.0.1:8631
Listen $SHADOW/run/cups.sock
EOF

# 4. Write an isolated cups-files.conf pointing exclusively inside $SHADOW
cat > "$SHADOW/etc/cups-files.conf" <<EOF
User $(id -un)
Group $(id -gn)
SystemGroup $(id -gn)
ServerRoot $SHADOW/etc
RequestRoot $SHADOW/spool
CacheDir $SHADOW/cache
StateDir $SHADOW/run
TempDir $SHADOW/tmp
ServerBin $SHADOW/bin
DataDir $SHADOW/data
DocumentRoot $SHADOW/doc-root
ErrorLog $SHADOW/logs/error_log
AccessLog $SHADOW/logs/access_log
PageLog $SHADOW/logs/page_log
Sandboxing relaxed
FileDevice No
EOF

# 5. Validate the shadow configuration and launch Yindle in the foreground
"$PW_BIN/cupsd" --check-config \
  -c "$SHADOW/etc/cupsd.conf" \
  -s "$SHADOW/etc/cups-files.conf"

"$PW_BIN/cupsd" \
  -c "$SHADOW/etc/cupsd.conf" \
  -s "$SHADOW/etc/cups-files.conf" \
  -f
```

---

## 4. Verify the Shadow Instance Without Hitting Host CUPS

Open a second terminal and target **explicitly** `127.0.0.1:8631` (or `$SHADOW/run/cups.sock`). Always pass `-h 127.0.0.1:8631` or embed `:8631` in the `ipp://` URI so tools never fall back to the host's `/run/cups/cups.sock` or port `631`:

```sh
# 1. Health, readiness, and Prometheus metrics endpoints
curl -fsS http://127.0.0.1:8631/healthz
curl -fsS http://127.0.0.1:8631/readyz
curl -fsS http://127.0.0.1:8631/metrics | head -n 30

# 2. Query queues and scheduler status via stock CUPS client tools
lpstat -h 127.0.0.1:8631 -t
lpq -h 127.0.0.1:8631 -a

# 3. Verify IPP attributes with ipptool (note: ipptool ignores CUPS_SERVER, so embed :8631 in the URI!)
ipptool -t \
  ipp://localhost:8631/printers/<queue> \
  /usr/share/cups/ipptool/get-printer-attributes.test

# 4. Submit a real test job through the shadow filter/backend pipeline
lp -h 127.0.0.1:8631 -d <queue> /path/to/test.pdf
lpstat -h 127.0.0.1:8631 -W all -o

# 5. Test admin operations over the shadow Unix domain socket (SO_PEERCRED auth)
lpstat -h /tmp/pw-shadow/run/cups.sock -t

# 6. Test filter-chain resolution offline with cupsfilter
"$PW_BIN/cupsfilter" --list-filters \
  -c "$SHADOW/etc/cupsd.conf" \
  -p "$SHADOW/etc/ppd/<queue>.ppd" \
  -m application/pdf /path/to/test.pdf
```

When finished testing, press `Ctrl-C` in the shadow terminal (Yindle drains gracefully on `SIGINT`) and delete `/tmp/pw-shadow`.

---

## 5. Check AppArmor / SELinux Before Cutover

- **Ubuntu / Debian**: check `sudo aa-status | grep -i cups`. If `/etc/apparmor.d/usr.sbin.cupsd` is loaded from stock `cups-daemon`, disable or adapt it so it does not block Yindle's `/usr/sbin/cupsd`. Full commands are in [docs/operations.md#4-apparmor--selinux-migration-notes](operations.md#4-apparmor--selinux-migration-notes).
- **Fedora / RHEL / Rocky**: after installing Yindle, run `sudo restorecon -Rv /usr/sbin/cupsd /usr/lib/cups /etc/cups /var/spool/cups /var/log/cups /var/cache/cups /run/cups`.

---

## 6. Zero-Downtime Cutover

### Back Up `/etc/cups` First

```sh
sudo tar --numeric-owner -czf "/root/cups-etc-backup-$(date +%F).tar.gz" /etc/cups
```

### Cutover Option A — Debian / Ubuntu `.deb` Package (Recommended)

The Yindle `.deb` package declares `Provides: cups, cups-daemon`, `Conflicts: cups, cups-daemon`, `Replaces: cups-daemon`, `Recommends: cups-client, cups-filters`, and lists `/etc/cups/cupsd.conf`, `/etc/cups/cups-files.conf`, `/etc/pam.d/cups`, and `/etc/logrotate.d/yindle` in `DEBIAN/conffiles` so your existing configuration is preserved cleanly across replacement and upgrades:

```sh
# Stop stock scheduler cleanly
sudo systemctl stop cups.path cups.socket cups.service

# Install Yindle .deb (replaces cups-daemon while keeping cups-client & cups-filters)
sudo apt-get install -y ./yindle_0.1.1-1_amd64.deb

# Validate config & host health, then activate standard CUPS systemd units
sudo cupsd --check-config
sudo cupsd doctor
sudo systemctl daemon-reload
sudo systemctl enable --now cups.socket cups.path
sudo systemctl status cups.socket cups.service
```

### Cutover Option B — `install.sh` (Tarball / Source)

`install.sh` verifies `SHA256SUMS` (failing closed on mismatch), **preserves existing `/etc/cups/cupsd.conf`, `/etc/cups/cups-files.conf`, `/etc/pam.d/cups`, and `/etc/logrotate.d/yindle`** (saving new defaults alongside them as `*.new` and `*.default`), installs `tmpfiles.d`/`sysusers.d`, and activates `cups.socket` + `cups.path`:

```sh
# 1. Remove stock cups-daemon (keep cups-client and cups-filters!)
sudo systemctl stop cups.path cups.socket cups.service
sudo apt-get remove cups-daemon    # Debian/Ubuntu (leaves /etc/cups intact)

# 2. Run the Yindle installer (downloads verified tarball or use --from <dir>)
curl -fsSL https://raw.githubusercontent.com/vindeckyy/yindle/main/install.sh | sh

# 3. Verify units and queues
sudo cupsd --check-config
sudo cupsd doctor
sudo systemctl enable --now cups.socket cups.path
sudo systemctl status cups.socket cups.service
lpstat -t
```

> **Note on unit names**: Yindle intentionally installs the standard **`cups.service`**, **`cups.socket`**, **`cups.path`**, **`cups-lpd.socket`**, and **`cups-lpd@.service`** units so existing monitoring, scripts, and downstream services work without renaming.
>
> **Note on remote LAN clients**: Yindle's `cups.socket` binds **loopback only** (`127.0.0.1:631`, `[::1]:631`, `/run/cups/cups.sock`) by default. If your previous CUPS server served LAN clients, add a drop-in via `sudo systemctl edit cups.socket` as shown in [docs/operations.md#exposing-ipp-to-a-lan-opt-in](operations.md#exposing-ipp-to-a-lan-opt-in).
>
> **Note on admin access**: Yindle does not add `lp` to `lpadmin`. Ensure human print administrators are members of `lpadmin` (`sudo usermod -aG lpadmin "$USER"`).

---

## 7. Clean Rollback

Because Yindle preserves `/etc/cups` and `/var/spool/cups` in place, rolling back to OpenPrinting CUPS takes less than a minute:

### If Installed via `.deb`

```sh
sudo systemctl stop cups.path cups.socket cups.service
sudo apt-get install -y cups cups-daemon
sudo systemctl daemon-reload
sudo systemctl enable --now cups.socket cups.path
lpstat -t
```

### If Installed via `install.sh` or `make install`

```sh
# Uninstall Yindle binaries/units (preserves /etc/cups/*.conf and /var/spool/cups)
curl -fsSL https://raw.githubusercontent.com/vindeckyy/yindle/main/install.sh | sh -s -- --uninstall
# Or from a source checkout:
# sudo make uninstall

# Reinstall distro CUPS daemon
sudo apt-get install -y cups-daemon    # or: sudo dnf install -y cups
sudo systemctl daemon-reload
sudo systemctl enable --now cups.socket cups.path
lpstat -t
```

---

## Further Reading

- [Documented Deviations](deviations.md) — intentional security defaults and current roadmap
- [Enterprise Operations & SRE Runbook](operations.md) — monitoring, TLS/mTLS, `SIGHUP` reloads, AppArmor/SELinux, HA, and incident runbooks
- [Conformance Matrix](conformance.md) — upstream `ipptool` `test/4.x` and `test/5.x` verification results
