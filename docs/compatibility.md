# Compatibility Matrix

This page summarizes Yindle's compatibility with the OpenPrinting CUPS 2.x surface. For per-test upstream `ipptool` results see [docs/conformance.md](conformance.md), and for intentional security defaults and roadmap items see [docs/deviations.md](deviations.md).

---

## Wire & Transport Protocols

| Surface | Status | Details |
|---|---|---|
| **IPP 1.0 – 2.2 wire codec** (`crates/ipp-codec`) | **Implemented** | Byte-compatible with `libcups` IPP encoding (delimiter tags, out-of-band values, collections, `dateTime`, `rangeOfInteger`, `resolution`, bounded `DecodeLimits`) |
| **IPP Everywhere (PWG 5100.14)** | **Implemented** | Full required attribute synthesis, PPD-aware capability derivation, `everywhere` model, `ipp-everywhere` suite passes |
| **HTTP/1.1** (`crates/httpd`) | **Implemented** | Keep-alive, chunked transfer encoding, `Expect: 100-continue`, strict anti-smuggling checks, `Host` header validation (`ServerName`/`ServerAlias`), Slowloris timeouts, disk-spooled large request bodies |
| **TLS & mTLS** (`crates/cups-tls`) | **Implemented** | `SSLListen`/`SSLPort`, RFC 2817 `OPTIONS *` -> `Upgrade: TLS/1.2`, `SSLOptions` (`MinTLS1.2`/`MinTLS1.3`/`MaxTLS*`/`DenyCBC`), optional/required mTLS client CA verification, atomic `SIGHUP` certificate hot-reload |
| **Unix domain socket** | **Implemented** | `Listen /run/cups/cups.sock` (`0666`), kernel-verified `SO_PEERCRED` peer authentication (`PeerCred On\|Off\|RootOnly`) |
| **RFC 1179 LPD** (`bins/cups-lpd`) | **Implemented** | Hardened `cups-lpd` bridge (`0x01` print waiting, `0x02` receive job in both control/data orders with `0600` streaming temp spool, `0x03`/`0x04` real IPP `Get-Jobs` queue status, `0x05` real IPP `Cancel-Job`) |
| **DNS-SD / AirPrint** (`crates/dnssd`) | **Implemented** | Official `printer-type` bitmasks, AirPrint `URF=` TXT record and `_universal` subtype, real `pdl=` forwarding, `BrowseWebIF`/`BrowseIPPSOnly`/`BrowseDNSSDSubTypes`, concurrent `browse_ipp` and UTF-8 percent-decoding `resolve_uri` |
| **D-Bus Notifications** (`crates/cups-dbus`) | **Implemented** | Pure-Rust D-Bus v1 wire publisher emitting `org.cups.cupsd.Notifier` server/printer/job signals over `/run/dbus/system_bus_socket` with graceful no-op when bus is absent |

---

## IPP Operations (68 Dispatched Operations)

All 68 dispatched IPP operations in `crates/ops` pass through fail-closed `<Policy>` authorization (`printer-op-policy` -> `DefaultPolicy` -> `default`), support multi-object fresh-group responses, enforce `JobPrivate*`/`SubscriptionPrivate*` redaction, and support non-blocking async execution (`dispatch_async`):

- **Printer & discovery reads**: `Get-Printer-Attributes`, `Get-Printer-Supported-Values`, `CUPS-Get-Printers`, `CUPS-Get-Classes`, `CUPS-Get-Default`, `CUPS-Get-Devices` (parallel `cups-deviced`), `CUPS-Get-PPDs` (all 9 filter parameters), `CUPS-Get-PPD` (path-contained `cups-driverd`), `Identify-Printer`.
- **Job & document lifecycle**: `Print-Job` (incl. bounded pure-Rust RFC 1952 `compression=gzip`), `Print-URI` (non-`file://`), `Validate-Job` (real format/quota/policy validation), `Create-Job`, `Send-Document`, `Send-URI`, `Close-Job`, `Get-Jobs` (all 11 `which-jobs` keywords, live `queued-job-count`), `Get-Job-Attributes`, `Set-Job-Attributes`, `Cancel-Job`, `Cancel-My-Jobs`, `Cancel-Current-Job`, `Cancel-Jobs`, `Purge-Jobs`, `Hold-Job`, `Release-Job`, `Restart-Job`, `Reprocess-Job`, `Resubmit-Job`, `Suspend-Current-Job`, `Resume-Job`, `Promote-Job`, `Schedule-Job-After`, `Cancel-Document`, `Set-Document-Attributes`, `Get-Documents`, `Get-Document-Attributes`, `CUPS-Move-Job` (single job and move-all), `CUPS-Get-Document`, `CUPS-Authenticate-Job`.
- **Printer & class administration**: `CUPS-Add-Modify-Printer`, `CUPS-Delete-Printer`, `CUPS-Add-Modify-Class`, `CUPS-Delete-Class`, `CUPS-Set-Default`, `CUPS-Create-Local-Printer`, `Set-Printer-Attributes`, `Pause-Printer`, `Resume-Printer`, `Pause-Printer-After-Current-Job`, `Hold-New-Jobs`, `Release-Held-New-Jobs`, `Enable-Printer`, `Disable-Printer`, `Deactivate-Printer`, `Activate-Printer`, `Restart-Printer`, `Shutdown-Printer`, `Startup-Printer`, `CUPS-Accept-Jobs`, `CUPS-Reject-Jobs`.
- **Subscriptions & notifications (RFC 3995)**: `Create-Printer-Subscription`, `Create-Job-Subscription`, `Get-Subscription-Attributes`, `Get-Subscriptions`, `Renew-Subscription`, `Cancel-Subscription`, `Get-Notifications` (non-destructive ring buffer, `notify-sequence-numbers`, sync & async `notify-wait=true`).

---

## Drivers, Filters, and Backends

| Component | Status | Details |
|---|---|---|
| **Driverless IPP / IPP Everywhere** | **First-class** | Synthesized `everywhere` PPD, native PDF / PWG Raster / URF support |
| **`.drv` driver database & `.ppd`/`.ppd.gz`** | **Implemented** | `cups-driverd` compiles `.drv` (with `#include` containment) and extracts `.ppd`/`.ppd.gz` metadata with symlink-loop and path-traversal protection |
| **Multi-stage filter pipeline** (`crates/pipeline`) | **Implemented** | Standard CUPS argv/env/fd contract (`argv[0..6]`, `argv[6]` file passed only to stage 1, stderr `STATE:`/`INFO:`/`PAGE:`/`ATTR:`/`PPD:` parser, back-channel fd 3, side-channel fd 4, `FilterLimit`, `JobKillDelay` PGID kill) |
| **Privilege-drop sandbox launcher** (`bins/cups-exec`) | **Implemented** | Named and file sandbox profiles, executable metadata validation, `set_nice`, `umask 077`, `setrlimit`, `initgroups`/`setgid`/`setuid`, `PR_SET_NO_NEW_PRIVS`, Linux Landlock enforcement |
| **Standalone filter tool** (`bins/cupsfilter`) | **Implemented** | Full `cupsfilter(8)` CLI (`-c/-d/-D/-e/-i/-j/-m/-n/-o/-p/-P/-t/-u/-U/--list-filters/-h/-V`), stdin streaming spool, PPD `*cupsFilter`/`*cupsFilter2` resolution |
| **Standard backends (all 9)** | **Implemented** | `socket` (IPv6 + `waiteof`), `ipp`/`ipps`/`http`/`https` (IPv6, chunked, streaming, job polling, TLS CA bundles), `lpd` (RFC 1179 `cfA`/`dfA`), `snmp` (ASN.1 BER + `snmp.conf` + port probing), `dnssd`, `file` (fail-closed `FileDevice`), `usb` (`usblp` `/dev/usb/lp*`), `serial` (`+`/`&` options + `dtrdsr`), `parallel` (`/dev/lp*` & `/dev/parport/*`) |
| **External `cups-filters` & 3rd-party backends** | **Compatible** | Unmodified CUPS filters (`pstops`, `pdftopdf`, `rastertopwg`, etc.) and third-party backends run under the standard CUPS process contract |

---

## Configuration, Persistence & Auth

- **Configuration files**: `cupsd.conf`, `cups-files.conf`, `mime.types`, `mime.convs`, `local.types`, `local.convs` (loaded from `DataDir/mime` + `ServerRoot`), `<Location>`, `<Policy>`, `<Limit>`, `<LimitExcept>` parsed with upstream 2.x syntax. Audit any existing config with `cupsd --check-config`.
- **State persistence**: `printers.conf`, `classes.conf` (`<Class>`/`<DefaultClass>`/`Printer <member>`), `subscriptions.conf`, `job.cache`, and `/var/spool/cups/{c*,d*}` (supporting job IDs > 99,999 and startup crash recovery for orphaned `Processing` jobs).
- **Authentication**: PAM-first HTTP Basic (`dlopen("libpam.so.0")` for service `cups`), constant-time reentrant `crypt_r` shadow fallback (only when PAM is unavailable), kernel-verified `SO_PEERCRED` on Unix domain sockets, optional/required mTLS client certificates, and extensible `authn::TokenVerifier` trait for `Bearer` tokens. Native Kerberos/GSSAPI and OIDC provider adapters are on the roadmap (see [docs/deviations.md](deviations.md#3-transparent-roadmap-not-yet-implemented)).
- **Authorization**: fail-closed `Satisfy all` default, real `@LOCAL` and `@IF(name)` network interface matching, IPv4 + IPv6 + IPv4-mapped IPv6 CIDR matching, `@OWNER`, `@SYSTEM`, `Require user`/`group`/`valid-user`.

---

## Platforms & Service Integration

| Platform | Status | Notes |
|---|---|---|
| **Linux (`x86_64`, `aarch64`, `glibc` & `musl`)** | **Primary target** | Dynamic PAM + `libcrypt` portability, `SO_PEERCRED`, systemd socket/path activation + `sd_notify` (`READY=1`, `RELOADING=1`, `STOPPING=1`, `WATCHDOG=1`), Linux Landlock sandboxing, `usblp`, D-Bus wire notifier, OpenRC support on Alpine |
| **macOS** | **Tier-2 roadmap** | `launchd`, `local-cert` auth, and IOKit USB planned |
| **Windows** | **Out of scope** | Upstream CUPS does not target Windows |
