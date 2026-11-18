# Enterprise Operations & SRE Runbook

This manual covers production deployment, observability, zero-downtime lifecycle operations, MAC (AppArmor/SELinux) coexistence, high availability, backups, and incident troubleshooting for Presswork (`cupsd`).

**Contents**:
[1. Production Deployment Patterns](#1-production-deployment-patterns) ·
[2. Observability, Logging & Auditing](#2-observability-logging--auditing) ·
[3. Zero-Downtime Operations & Diagnostics](#3-zero-downtime-operations--diagnostics) ·
[4. AppArmor & SELinux Migration Notes](#4-apparmor--selinux-migration-notes) ·
[5. High Availability & Backup / Restore](#5-high-availability--backup--restore) ·
[6. Incident Troubleshooting Runbooks](#6-incident-troubleshooting-runbooks)

---

## 1. Production Deployment Patterns

### systemd (Bare Metal / VM)

Presswork ships hardened systemd units in `data/systemd/`, along with `data/tmpfiles.d/presswork.conf`, `data/sysusers.d/presswork.conf`, and `data/logrotate.d/presswork`:

- **Activation model**: `cups.socket` (loopback `127.0.0.1:631`, `[::1]:631`, and `/run/cups/cups.sock`) + `cups.path` (watches `/var/spool/cups/d*` for queued jobs) start `cups.service` (`ExecStart=/usr/sbin/cupsd -l`, `Restart=on-failure`, `ExecReload=/bin/kill -HUP $MAINPID`).
- **Tmpfs boot safety**: `cups.service` sets `RuntimeDirectory=cups` (`0755`) and `presswork.conf` in `/usr/lib/tmpfiles.d/` creates `/run/cups`, `/run/cups/certs`, `/var/spool/cups`, `/var/log/cups`, `/var/cache/cups`, and enforces `0700 root:root` on `/etc/cups/ssl` (preventing `226/NAMESPACE` boot failures on tmpfs `/run`).
- **System accounts**: `/usr/lib/sysusers.d/presswork.conf` creates `lp` (user + group) and `lpadmin` (admin group). **`lp` is intentionally NOT added to `lpadmin`** so sandboxed filters/backends cannot gain `@SYSTEM` admin privileges.
- **Unit sandboxing**: `ProtectSystem=strict` (writable only on `/var/spool/cups`, `/var/cache/cups`, `/var/log/cups`, `/etc/cups`), `ProtectHome=true`, `PrivateTmp=true`, `NoNewPrivileges=true`, `RestrictNamespaces=true`, minimal `CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH CAP_SETUID CAP_SETGID CAP_CHOWN CAP_FOWNER`, `SystemCallFilter=@system-service`, `UMask=0027`, `MemoryMax=512M`, `TasksMax=256`.
- **Log rotation**: `/etc/logrotate.d/presswork` rotates `access_log`, `error_log`, and `page_log` weekly (`0640 lp lp`, 12 rotations, compressed) and issues `systemctl reload-or-try-restart cups.service` (`SIGHUP`) to reopen log file descriptors cleanly.

#### Exposing IPP to a LAN (Opt-In)

By default, `cups.socket` binds **loopback only**. To serve remote print clients on a trusted subnet, create a systemd drop-in (`sudo systemctl edit cups.socket`) that clears `ListenStream=` and binds your explicit interface or port alongside TLS:

```ini
[Socket]
ListenStream=
ListenStream=/run/cups/cups.sock
ListenStream=127.0.0.1:631
ListenStream=10.20.0.10:631
```

Then configure TLS and explicit `<Location>` rules in `/etc/cups/cupsd.conf`:

```apache
ServerName print.corp.example
ServerAlias print.corp.example print
SSLOptions MinTLS1.2 DenyCBC

<Location />
  Order allow,deny
  Allow from 127.0.0.1
  Allow from ::1
  Allow from 10.20.0.0/16
</Location>

<Location /admin>
  Encryption Required
  AuthType Default
  Require user @SYSTEM
  Satisfy all
  Order allow,deny
  Allow from 10.20.0.0/16
</Location>
```

Apply without dropping connections:

```sh
sudo cupsd --check-config
sudo systemctl daemon-reload
sudo systemctl restart cups.socket
sudo systemctl reload cups.service
```

#### Legacy LPD (`cups-lpd.socket`)

`cups-lpd.socket` is disabled by default and binds loopback (`127.0.0.1:515`, `[::1]:515`, `MaxConnections=64`, `MaxConnectionsPerSource=16`). `cups-lpd@.service` runs unprivileged as `User=lp` / `Group=lp` with empty `CapabilityBoundingSet=`, `MemoryMax=64M`, `TasksMax=16`, and `UMask=0077`. Enable only if RFC 1179 clients require it (`sudo systemctl enable --now cups-lpd.socket`), and restrict source subnets via firewall rules if bound to a LAN address.

---

### Docker & Docker Compose

The shipped `Dockerfile` and `docker-compose.yml` follow least-privilege container hardening:

- **Non-root UID/GID `631:631` (`lp`)** deterministic across builder and runtime stages.
- **Read-only root filesystem** (`read_only: true`), `no-new-privileges:true`, `cap_drop: [ALL]`, `cap_add: [NET_BIND_SERVICE]`, and `net.ipv4.ip_unprivileged_port_start: 631` so UID 631 binds container port `631` cleanly.
- **Host loopback publish**: `127.0.0.1:8631:631` (never collides with host CUPS on `:631` or exposes the port to the LAN).
- **Persistent volumes**: `cups-etc` (`/etc/cups`), `cups-spool` (`/var/spool/cups`), `cups-log` (`/var/log/cups`), `cups-cache` (`/var/cache/cups`), plus tmpfs `/run/cups` and `/tmp`.
- **Optional `cups-filters`**: pass `--build-arg INSTALL_CUPS_FILTERS=true` (or `INSTALL_CUPS_FILTERS=true docker compose up --build -d`) when printing to legacy PPD / non-driverless printers that need PostScript/PDF/raster conversion.
- **Built-in `HEALTHCHECK`**: probes `GET /healthz` over `/dev/tcp/127.0.0.1/631` with zero extra runtime packages.

```sh
# Start with built-in compose hardening (localhost:8631)
docker compose up --build -d

# Verify health, readiness, and queues
curl -fsS http://127.0.0.1:8631/healthz
curl -fsS http://127.0.0.1:8631/readyz
lpstat -h 127.0.0.1:8631 -t
```

For production builds, pin base image digests via `--build-arg RUST_IMAGE=...` and `--build-arg RUNTIME_IMAGE=...`.

---

### Kubernetes & Helm (`deploy/helm/presswork/`)

Presswork ships a Helm v2 chart at [`deploy/helm/presswork/`](../deploy/helm/presswork/Chart.yaml) modeled as a **StatefulSet** with persistent volumes, least-privilege security contexts, probes, `NetworkPolicy`, and Prometheus Operator `ServiceMonitor` support.

```sh
# Install or upgrade into a dedicated namespace
helm upgrade --install presswork ./deploy/helm/presswork \
  --namespace printing --create-namespace \
  --set serviceMonitor.enabled=true \
  --set 'networkPolicy.egress.printerCidrs={10.20.0.0/16}'

# Verify rollout and test via port-forward
kubectl -n printing rollout status statefulset/presswork
kubectl -n printing port-forward svc/presswork 8631:631 &
curl -fsS http://127.0.0.1:8631/healthz
curl -fsS http://127.0.0.1:8631/metrics
```

Key chart defaults in [`deploy/helm/presswork/values.yaml`](../deploy/helm/presswork/values.yaml):

| Setting | Default | Notes |
|---|---|---|
| `replicaCount` | `1` | Stateful spooler per queue group; see [HA Architecture](#high-availability-architecture) for scaling patterns. |
| `podSecurityContext` | `runAsNonRoot: true`, UID/GID/fsGroup `631`, `seccompProfile: RuntimeDefault`, `net.ipv4.ip_unprivileged_port_start=631` | Matches container `lp` UID 631 without root. |
| `securityContext` | `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, drop `ALL` + add `NET_BIND_SERVICE` | Zero writable root filesystem layers. |
| `probes` | Liveness `/healthz`, Readiness `/readyz`, Startup `/healthz` | Automatically fences draining pods from Service endpoints on `SIGTERM`. |
| `persistence` | `spool: 10Gi` (RWO), `config: 1Gi` (RWO), `logs: disabled` | Preserves `printers.conf`, PPDs, TLS keys, and active spool across pod restarts. |
| `networkPolicy.enabled` | `true` | Restricts ingress to TCP/631 and egress to DNS + printer ports (IPP 631, LPD 515, JetDirect 9100; SNMP 161 opt-in). |
| `serviceMonitor.enabled` | `false` | Set `true` when Prometheus Operator CRDs are installed (scrapes `/metrics` every `30s`). |
| `podDisruptionBudget.enabled` | `false` | Enable when `replicaCount > 1` or when intentionally blocking voluntary node drains. |

---

## 2. Observability, Logging & Auditing

### HTTP Health & Metrics Endpoints

`cupsd` exposes three operational HTTP endpoints (subject to configured `<Location>` rules):

| Endpoint | Success Response | Purpose |
|---|---|---|
| `GET /healthz` | `200 OK` JSON (`{"status":"ok","version":"...","uptime_seconds":...}`) | Liveness probe confirming the scheduler event loop and HTTP server are responsive. |
| `GET /readyz` | `200 OK` JSON (or `503 Service Unavailable` when draining/unhealthy) | Readiness probe verifying spool/scheduler readiness and cleanly signaling shutdown drain to load balancers and Kubernetes. |
| `GET /metrics` | `200 OK` (`text/plain; version=0.0.4; charset=utf-8`) | Prometheus scrape endpoint exporting scheduler, queue, job, IPP, auth, client, and filter-limit metrics. |

### Prometheus Metrics Reference

The metric names and labels exported by `GET /metrics` match [`deploy/monitoring/prometheus-alerts.yaml`](../deploy/monitoring/prometheus-alerts.yaml) and [`deploy/monitoring/grafana-dashboard.json`](../deploy/monitoring/grafana-dashboard.json):

| Metric | Type | Labels | Description |
|---|---|---|---|
| `presswork_jobs_active` | Gauge | `printer` | Currently processing jobs per printer queue. |
| `presswork_jobs_pending` | Gauge | `printer` | Pending/queued jobs per printer queue. |
| `presswork_jobs_total` | Counter | `state` | Cumulative jobs transitioned to terminal states (`completed`, `aborted`, `canceled`, `canceled-at-device`). |
| `presswork_job_duration_seconds` | Histogram | — | End-to-end job processing duration (`_bucket`, `_sum`, `_count`) for p50/p95/p99 latency SLOs. |
| `presswork_ipp_requests_total` | Counter | `operation`, `status` | IPP requests dispatched by operation name and IPP status code (e.g. `successful-ok`). |
| `presswork_auth_failures_total` | Counter | `reason` | Authentication/authorization rejections by failure reason. |
| `presswork_active_clients` | Gauge | — | Current active HTTP/IPP client connections. |
| `presswork_filter_cost_current` | Gauge | — | Current active filter pipeline cost units in flight. |
| `presswork_filter_limit` | Gauge | — | Configured `FilterLimit` budget (`0` = unlimited). |

### Prometheus Alerts & Grafana Dashboard

1. **Prometheus Operator alerts**: apply [`deploy/monitoring/prometheus-alerts.yaml`](../deploy/monitoring/prometheus-alerts.yaml) (`kubectl apply -f deploy/monitoring/prometheus-alerts.yaml`). It defines 6 production alerts (`CupsdDown`, `PrintQueueBacklog`, `HighJobFailureRate`, `FilterLimitSaturated`, `HighAuthFailures`, `SpoolDiskUsage`), each linked directly to its runbook section below.
2. **Grafana dashboard**: import [`deploy/monitoring/grafana-dashboard.json`](../deploy/monitoring/grafana-dashboard.json) (UID `presswork-overview`, Grafana 10+, 11 panels covering scheduler status, active jobs, queue depth, p50/p95/p99 job duration, active clients, IPP request/error rates, auth failures, `FilterLimit` saturation, and spool volume utilization).

### Structured JSON Logging, Audit Log & Page Accounting

- **Structured JSON mode**: launch `cupsd --log-format json` or set `PRESSWORK_LOG_FORMAT=json` in the environment (for example via `systemctl edit cups.service` or Helm `extraEnv`) to emit newline-delimited JSON records to `error_log`, `access_log`, `page_log`, and audit streams for direct ingestion into Loki, Elasticsearch, Splunk, or CloudWatch.
- **Classic CUPS text mode (default)**: preserves exact upstream `error_log`, `access_log` (recording the authenticated username, IPP operation, and status), and `page_log` formats with thread-safe pure-Rust `TZif` localtime formatting and CRLF log-forging sanitization.
- **Enterprise audit events**: security-sensitive actions—authentication failures, printer/class creation/modification/deletion, policy/config reloads, and job cancellations—are emitted as structured audit events (`who`, `action`, `target`, `source_host`, `outcome`).
- **Page accounting (`page_log`)**: updated live from filter/backend `PAGE:` status lines on stderr using `PageLogFormat` (default `%p %u %j %T %P %C %{job-billing} %{job-originating-host-name} %{job-name} %{media} %{sides}`).
- **Log rotation**: set `MaxLogSize 0` in `cupsd.conf` when delegating rotation to `logrotate` (`/etc/logrotate.d/presswork`), or set a byte cap (e.g. `MaxLogSize 10m`) to use Presswork's built-in atomic `.O` rotation.

---

## 3. Zero-Downtime Operations & Diagnostics

### Zero-Downtime Reload (`SIGHUP`)

Sending `SIGHUP` (or running `sudo systemctl reload cups.service`) performs an atomic reload without terminating the daemon:

1. Emits `sd_notify("RELOADING=1")` to systemd.
2. Re-parses `cupsd.conf` and `cups-files.conf` and reloads the MIME database (`DataDir/mime` + `ServerRoot`).
3. Reloads TLS certificates and private keys from `ServerKeychain` (`/etc/cups/ssl`) atomically via `ReloadableTls`—if the new cert/key pair is malformed or mismatched, Presswork logs an error and **retains the previous valid TLS config** instead of crashing or dropping TLS.
4. Reopens `error_log`, `access_log`, and `page_log` descriptors (`logrotate` integration).
5. Refreshes DNS-SD service advertisements.
6. Emits `sd_notify("READY=1")`.

### TLS & Mutual TLS (mTLS) Setup and Certificate Rotation

Certificates live in `ServerKeychain` (default `/etc/cups/ssl`, mode `0700 root:root`):

- Server certificate chain (PEM): `/etc/cups/ssl/server.crt` (`0644 root:root` or `0640 root:lp`)
- Server private key (PEM, PKCS#8 / RSA / ECDSA): `/etc/cups/ssl/server.key` (`0600`, `O_NOFOLLOW` enforced)

To enable direct TLS (`SSLListen`/`SSLPort`) or RFC 2817 HTTP Upgrade (`Encryption Required`) in `/etc/cups/cupsd.conf`:

```apache
SSLListen 10.20.0.10:631
SSLOptions MinTLS1.2 DenyCBC
# Or enforce TLS 1.3 only:
# SSLOptions MinTLS1.3
```

To disable automatic self-signed certificate generation when deploying CA-managed certificates, set in `/etc/cups/cups-files.conf`:

```apache
CreateSelfSignedCerts No
ServerKeychain /etc/cups/ssl
```

**Zero-downtime certificate rotation procedure**:

```sh
# 1. Stage new cert and key with strict permissions in the same directory
sudo install -m 0644 -o root -g root new-server.crt /etc/cups/ssl/server.crt.new
sudo install -m 0600 -o root -g root new-server.key /etc/cups/ssl/server.key.new

# 2. Verify cert and private key match before swapping
diff -u \
  <(sudo openssl x509 -in /etc/cups/ssl/server.crt.new -pubkey -noout) \
  <(sudo openssl pkey -in /etc/cups/ssl/server.key.new -pubout)

# 3. Atomically replace and trigger SIGHUP reload
sudo mv /etc/cups/ssl/server.crt.new /etc/cups/ssl/server.crt
sudo mv /etc/cups/ssl/server.key.new /etc/cups/ssl/server.key
sudo systemctl reload cups.service

# 4. Verify live served certificate
openssl s_client -connect 127.0.0.1:631 -servername "$(hostname -f)" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -dates
```

**Mutual TLS (mTLS) client authentication**: `crates/cups-tls` supports optional and required client certificate verification against a trusted PEM CA bundle (`ClientAuth::OptionalCaFile` / `ClientAuth::RequiredCaFile`) using `rustls::server::WebPkiClientVerifier`. When operating behind an enterprise PKI, distribute your internal client CA bundle to `/etc/cups/ssl/` (`0644 root:root`) and rotate both server certs and client CA bundles atomically followed by `SIGHUP`.

### Graceful Shutdown & Draining (`SIGTERM` / `SIGINT`)

On `SIGTERM` or `SIGINT`:

1. Emits `sd_notify("STOPPING=1")` and flips `GET /readyz` to `503 Service Unavailable`.
2. Stops accepting new connections and deregisters DNS-SD advertisements.
3. Drains in-flight HTTP/IPP requests up to the configured drain timeout.
4. Sends `SIGTERM` -> `SIGKILL` (after `JobKillDelay`) to active job process groups cleanly.
5. Persists `printers.conf`, `classes.conf`, `subscriptions.conf`, and `job.cache` atomically before exiting.

### Pre-Flight Config Audit & Host Diagnostics

Run these two built-in commands before every config change, migration, or upgrade:

```sh
# 1. Static migration & security linter (add --json for CI/automation)
sudo cupsd --check-config
sudo cupsd --check-config -c /etc/cups/cupsd.conf -s /etc/cups/cups-files.conf --json

# 2. Live environment & readiness diagnostics (add --json for fleet checks)
sudo cupsd doctor
sudo cupsd doctor -c /etc/cups/cupsd.conf -s /etc/cups/cups-files.conf --json
```

`cupsd --check-config` classifies every directive as `Supported`, `Deprecated`, `Moved` (e.g., `cups-files.conf` directives misplaced in `cupsd.conf`), or `Unknown`, and flags security risks including:

- `FILE_DEVICE_ENABLED`, `EMPTY_SYSTEM_GROUP`, `ROOT_WORKER_USER`, `SANDBOXING_OFF`
- `WILDCARD_LISTEN`, `REMOTE_WEB_INTERFACE`, `ADMIN_PLAINTEXT_REMOTE`
- `LOCATION_SATISFY_ANY`, `POLICY_SATISFY_ANY`, `MISSING_ADMIN_LOCATION_AUTH`
- `DEFAULT_AUTH_NONE`, `WILDCARD_SERVER_ALIAS`, `WEAK_TLS_OPTIONS`, `UNLIMITED_CLIENTS`, `UNLIMITED_REQUEST_SIZE`

`cupsd doctor` verifies config syntax, directory ownership/permissions (`ServerRoot`, `RequestRoot`, `CacheDir`, `TempDir`, `LogDir`, `RunDir`), loaded MIME rule counts, binary presence/permissions (`cups-exec`, `cups-deviced`, `cups-driverd`, backends, filters), TLS cert/key validity, PAM/NSS availability, and host conflicts such as a leftover Ubuntu/Debian AppArmor profile.

---

## 4. AppArmor & SELinux Migration Notes

### Ubuntu / Debian AppArmor (`/etc/apparmor.d/usr.sbin.cupsd`)

Stock Debian and Ubuntu `cups-daemon` packages install an AppArmor profile at `/etc/apparmor.d/usr.sbin.cupsd` attached to path `/usr/sbin/cupsd`. Because Presswork installs to `/usr/sbin/cupsd` for drop-in compatibility, **a leftover stock CUPS AppArmor profile can silently confine Presswork** and block `dlopen` of `libpam.so.0` / `libcrypt.so.2`, `/proc/self/status` reads, or Landlock syscalls in `cups-exec`.

1. **Check whether a stock profile is loaded**:
   ```sh
   sudo aa-status | grep -i cups || true
   sudo dmesg -T | grep -iE 'apparmor.*DENIED.*cupsd' | tail -n 20
   ```
2. **Option A — Disable the stock CUPS AppArmor profile** (recommended when relying on Presswork's built-in systemd hardening + `cups-exec` Landlock sandboxing):
   ```sh
   sudo apt-get install -y apparmor-utils   # if aa-disable is not installed
   sudo aa-disable /etc/apparmor.d/usr.sbin.cupsd
   sudo systemctl restart cups.service
   ```
   Alternatively, symlink into `/etc/apparmor.d/disable/` and reload:
   ```sh
   sudo ln -sf /etc/apparmor.d/usr.sbin.cupsd /etc/apparmor.d/disable/
   sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.cupsd
   sudo systemctl restart cups.service
   ```
3. **Option B — Keep AppArmor enforced with local overrides**:
   Switch to complain mode first (`sudo aa-complain /etc/apparmor.d/usr.sbin.cupsd`), exercise printing and `cupsd doctor`, inspect `/var/log/syslog` or `journalctl -k`, add required local rules in `/etc/apparmor.d/local/usr.sbin.cupsd` (for example `/proc/@{pid}/status r,`, `/usr/lib/cups/daemon/cups-exec ix,`, `/etc/ssl/certs/** r,`), reload with `sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.cupsd`, and re-enforce with `sudo aa-enforce /etc/apparmor.d/usr.sbin.cupsd`.

### RHEL / Fedora / Rocky / AlmaLinux SELinux

On SELinux enforcing systems, ensure Presswork binaries and state directories carry the standard `cupsd_exec_t` / `cupsd_etc_t` / `cupsd_var_run_t` / `print_spool_t` contexts:

```sh
# Restore default CUPS file contexts after installing Presswork
sudo restorecon -Rv \
  /usr/sbin/cupsd \
  /usr/bin/cupsfilter \
  /usr/lib/cups \
  /etc/cups \
  /var/spool/cups \
  /var/log/cups \
  /var/cache/cups \
  /run/cups

# Check for any SELinux AVC denials
sudo ausearch -m avc -ts recent -c cupsd
```

- If running on a non-standard port (e.g. `8631`), label the port: `sudo semanage port -a -t ipp_port_t -p tcp 8631`.
- If custom enterprise filters or Landlock calls trigger an AVC denial, inspect with `audit2why` and generate a tightly scoped local policy module via `audit2allow -M presswork-local`.

---

## 5. High Availability & Backup / Restore

### High Availability Architecture

Like upstream CUPS, `cupsd` maintains local stateful files (`/var/spool/cups`, `printers.conf`, `job.cache`, monotonically increasing job IDs). Running two active `cupsd` instances concurrently against the same shared `/var/spool/cups` filesystem is **not supported** and will corrupt job IDs and spool files.

Use one of two proven production HA patterns:

1. **Active-Passive Failover (Single Queue Namespace)**
   - **Kubernetes**: deploy the Helm StatefulSet with `replicaCount: 1` and a `ReadWriteOnce` PVC backed by replicated storage (e.g., Ceph/Rook, EBS, Persistent Disk, Longhorn). Kubernetes reschedules the pod onto a healthy node automatically; `Jobs::load_all_with_policy` recovers any job interrupted mid-flight without wedging queues.
   - **Bare Metal / VM**: pair two nodes with Pacemaker/Corosync or Keepalived VIP + replicated block storage (DRBD or SAN LUN with STONITH fencing) mounting `/etc/cups` and `/var/spool/cups` exclusively on the active node.
2. **Horizontal Queue Sharding (Active-Active by Site/Floor)**
   - Partition printers by office, floor, or workload class across independent Presswork StatefulSets/VMs (e.g., `print-nyc`, `print-lon`, `print-warehouse`), each with its own PVC/spool and DNS name. Clients target their regional endpoint directly or through an IPP-aware L7 proxy.

### Backup & Restore

#### What to Back Up

| Path | Contents | Sensitivity |
|---|---|---|
| `/etc/cups/` | `cupsd.conf`, `cups-files.conf`, `printers.conf`, `classes.conf`, `subscriptions.conf`, `local.types`, `local.convs`, `ppd/`, `ssl/` | **High** — contains `ssl/server.key` (`0600`) and may contain backend credentials in `printers.conf` (`0640`). Encrypt backups at rest. |
| `/var/spool/cups/` | Active job control (`c*`) and document (`d*`) files | **High** — contains printed document payloads (`0600`). Back up only if preserving in-flight/history spool is required. |
| `/var/log/cups/page_log` | Print accounting records | Medium — archive per organizational retention policy. |

#### Backup Command

```sh
# Quiesce or snapshot config (zero-downtime config backup)
sudo tar --numeric-owner --xattrs -czf "presswork-etc-$(date +%F).tar.gz" \
  /etc/cups

# Full backup including active spool (stop scheduler briefly for consistency)
sudo systemctl stop cups.path cups.socket cups.service
sudo tar --numeric-owner --xattrs -czf "presswork-full-$(date +%F).tar.gz" \
  /etc/cups /var/spool/cups
sudo systemctl start cups.socket cups.path
```

#### Restore Procedure

```sh
sudo systemctl stop cups.path cups.socket cups.service
sudo tar --numeric-owner --xattrs -xzf presswork-etc-YYYY-MM-DD.tar.gz -C /
sudo chmod 0700 /etc/cups/ssl
sudo chmod 0600 /etc/cups/ssl/server.key 2>/dev/null || true
sudo chown -R lp:lp /var/spool/cups /var/log/cups /var/cache/cups
sudo cupsd --check-config
sudo cupsd doctor
sudo systemctl start cups.socket cups.path
```

---

## 6. Incident Troubleshooting Runbooks

The first six sections correspond 1-to-1 with the `runbook_url` anchors in [`deploy/monitoring/prometheus-alerts.yaml`](../deploy/monitoring/prometheus-alerts.yaml).

### Cupsd Down

**Alert**: `CupsdDown` (`up{job=~".*presswork.*"} == 0` for 2m)

1. **Check service/pod status**:
   - systemd: `sudo systemctl status cups.socket cups.service` and `sudo journalctl -u cups.service -n 100 --no-pager`
   - Kubernetes: `kubectl -n printing describe pod presswork-0` and `kubectl -n printing logs presswork-0 --previous`
2. **Validate configuration & host health**:
   ```sh
   sudo cupsd --check-config
   sudo cupsd doctor
   ```
3. **Check common root causes**:
   - Port `631` conflict with a leftover process: `sudo ss -tlnp 'sport = :631'`
   - Missing `/run/cups` on tmpfs boot: `sudo systemd-tmpfiles --create presswork.conf`
   - Invalid TLS cert/key on an explicit `SSLListen`/`SSLPort` (Presswork fails closed rather than silently falling back to plaintext): inspect `/var/log/cups/error_log` and verify `/etc/cups/ssl/server.{crt,key}` permissions (`0700` dir, `0600` key).
   - Stock Ubuntu/Debian AppArmor denial: see [AppArmor & SELinux Migration Notes](#4-apparmor--selinux-migration-notes).
4. **Recover**: fix the reported error, verify with `cupsd -t`, and run `sudo systemctl restart cups.socket cups.service`.

### Print Queue Backlog

**Alert**: `PrintQueueBacklog` (`presswork_jobs_pending > 50` for 10m)

1. **Inspect queue state and reasons**:
   ```sh
   lpstat -t
   lpstat -o -l
   ```
2. **Check if the printer is paused or rejecting jobs**:
   - Look for `disabled` (`printer-state=stopped`) or `not accepting requests`.
   - Resume after resolving physical device issues (paper jam, toner, offline):
     ```sh
     sudo cupsenable <printer>
     sudo cupsaccept <printer>
     ```
3. **Check backend connectivity & retries**:
   - Inspect `/var/log/cups/error_log` for `CUPS_BACKEND_RETRY`, connection timeouts, or `ErrorPolicy stop-printer` transitions.
   - Test reachability to the printer IP/port (TCP 631 for IPP, 9100 for socket, 515 for LPD).
4. **Check `FilterLimit` throttling**: if `presswork_filter_cost_current` is near `presswork_filter_limit`, see [Filter Limit Saturated](#filter-limit-saturated).

### High Job Failure Rate

**Alert**: `HighJobFailureRate` (>10% aborted/canceled-at-device over 15m)

1. **Inspect recent errors in `error_log`**:
   ```sh
   sudo grep -E '^[ECW] ' /var/log/cups/error_log | tail -n 50
   ```
2. **Differentiate filter vs. backend failures**:
   - **Filter failures**: test the filter chain offline with `cupsfilter --list-filters -p /etc/cups/ppd/<queue>.ppd -m application/pdf /path/to/sample.pdf`. Confirm `cups-filters` is installed if converting non-raw formats (PostScript/PDF/raster).
   - **Backend exit codes**: check `error_log` for `CUPS_BACKEND_AUTH_REQUIRED` (code 2), `CUPS_BACKEND_HOLD` (3), `CUPS_BACKEND_STOP` (4), `CUPS_BACKEND_CANCEL` (5), `CUPS_BACKEND_RETRY` (6/7), or TLS/SSRF errors.
   - **PPD/MIME mismatch**: verify `DataDir /usr/share/cups` contains `mime/mime.types` and `mime/mime.convs` (`sudo cupsd doctor`).

### Filter Limit Saturated

**Alert**: `FilterLimitSaturated` (`presswork_filter_cost_current / presswork_filter_limit > 0.90` for 5m)

1. **Identify long-running filter processes**:
   ```sh
   ps -ef | grep -E '/usr/lib/cups/(filter|daemon/cups-exec)'
   ```
2. **Check for stuck or expensive rasterization jobs**:
   - Inspect `lpstat -W not-completed -o` and `/var/log/cups/error_log` for unusually large PDFs/images.
   - Verify `MaxJobTime` (default `10800s` / 3h) and `JobKillDelay` (default `300s`) are tuned appropriately for your workload.
3. **Tune capacity**: if host CPU and RAM have headroom (and systemd `MemoryMax`/`TasksMax` or Kubernetes `resources.limits` allow), raise `FilterLimit` in `/etc/cups/cupsd.conf` (each standard filter typically costs 50–100 units) and run `sudo systemctl reload cups.service`.

### High Auth Failures

**Alert**: `HighAuthFailures` (`rate(presswork_auth_failures_total[5m]) > 5` for 5m)

1. **Inspect audit & access logs** to distinguish an attack from a misconfigured client or directory outage:
   ```sh
   sudo grep -E ' (401|403) ' /var/log/cups/access_log | tail -n 50
   ```
2. **Check PAM / LDAP / SSSD health**:
   - Verify `/etc/pam.d/cups` exists and `libpam.so.0` is loadable (`sudo cupsd doctor`).
   - Test directory lookup (`getent passwd <user>` and `id <user>`); check `sssd`/`nslcd` status.
3. **Check `lpadmin` / `SystemGroup` membership**:
   - Admin operations require membership in a group listed in `SystemGroup` (`/etc/cups/cups-files.conf`, default `lpadmin`). Add administrators with `sudo usermod -aG lpadmin <user>`.
4. **Mitigate abuse**: if failures originate from an unauthorized subnet or host, tighten `<Location>` `Allow`/`Deny` rules in `/etc/cups/cupsd.conf` and reload via `SIGHUP`, or block at the network firewall / Kubernetes `NetworkPolicy`.

### Spool Disk Usage

**Alert**: `SpoolDiskUsage` (`/var/spool/cups` or spool PVC > 85% for 10m)

1. **Check disk usage breakdown**:
   ```sh
   sudo du -sh /var/spool/cups /var/spool/cups/tmp /var/log/cups /var/cache/cups
   ```
2. **Check `PreserveJobFiles` and `PreserveJobHistory`**:
   - Default `PreserveJobFiles` is `86400` (1 day). Setting `PreserveJobFiles No` (or a shorter interval like `1h`) and `AutoPurgeJobs Yes` in `/etc/cups/cupsd.conf` prevents completed job documents (`d*`) from filling disk.
3. **Free space safely**:
   - Cancel abandoned held jobs (`cancel -a <queue>`), or expand the Kubernetes spool PVC (`persistence.spool.size`) if peak print volume genuinely exceeds capacity.
   - Never delete active `c*`/`d*` files while `cupsd` is actively printing them; use IPP `Cancel-Job`/`Purge-Jobs` or stop `cupsd` first.

---

### Additional Diagnostic Runbooks

#### Auth `401` / `403` / `426` Errors After Migrating from Stock CUPS

- **`401 Unauthorized` / `403 Forbidden` on admin or job ops**: Presswork defaults to `Satisfy all` (requiring **both** host ACL match AND valid credentials/group membership). If a legacy `<Location>` or `<Policy>` block expects anonymous local access without `Require`, remove the `Require` line; if it requires admin access, ensure the user is in `SystemGroup` (`lpadmin`) or connects locally over `/run/cups/cups.sock` (`SO_PEERCRED`). Note that Presswork never falls back to `SO_PEERCRED` if a client sends an invalid `Authorization` header.
- **`426 Upgrade Required`**: the matching `<Location>` sets `Encryption Required` and the client connected over plaintext HTTP. Reconnect over `ipps://` / `https://` or allow RFC 2817 Upgrade.
- **`400 Bad Request` on valid IPP clients using a CNAME/VIP**: add the VIP or DNS alias to `ServerAlias` in `/etc/cups/cupsd.conf` (avoid `ServerAlias *` as it weakens DNS rebinding protection) and reload via `SIGHUP`.

#### Filter Pipeline & Landlock Sandbox Denials

- If a third-party proprietary filter fails with `EACCES` or `EPERM` under `Sandboxing strict`:
  1. Check `/var/log/cups/error_log` at `LogLevel debug` to identify the exact path the filter tried to access.
  2. Switch `Sandboxing relaxed` in `/etc/cups/cups-files.conf` (still enforces privilege drop to `lp`, `umask 077`, `rlimits`, `PR_SET_NO_NEW_PRIVS`, and relaxed Landlock) and reload.
  3. Confirm the filter executable is owned by `root` and not group/world-writable (`chmod 0755`, `chown root:root`); `cups-exec` and `crates/pipeline` refuse to execute group/world-writable or symlink-escaping filters.

#### Backend SSRF Blocks (`ssrf: ... is blocked`)

Presswork's network backends (`ipp`, `lpd`, `socket`, `snmp`, `dnssd`) enforce `SsrfPolicy` to prevent Server-Side Request Forgery against cloud metadata services (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`), link-local addresses (`fe80::/10`), multicast/broadcast, and loopback (`127.0.0.0/8`, `::1`).

- **Legitimate local print gateway / SSH tunnel / test server on `127.0.0.1` or `::1`**: explicitly opt in by passing `CUPS_ALLOW_LOOPBACK_BACKENDS=yes` via `SetEnv CUPS_ALLOW_LOOPBACK_BACKENDS yes` in `/etc/cups/cups-files.conf` (or in the systemd unit / container environment).
- **Cloud metadata / link-local targets**: always blocked by design and cannot be bypassed via IPv4-mapped IPv6 or DNS rebinding.
