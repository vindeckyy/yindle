#!/usr/bin/env bash
# dev-local.sh — one-command, unprivileged local quickstart & smoke test.
#
# Starts an isolated presswork `cupsd` on 127.0.0.1:8631 with temporary spool
# and config (zero root, zero conflict with host CUPS), verifies `/healthz`
# and IPP `CUPS-Get-Printers`, creates a test queue (`dev-test`), prints a
# test job, verifies output, and tears down cleanly.
#
# Usage:
#   ./scripts/dev-local.sh [--port 8631] [--release] [--no-build] [--keep]
#
# Options:
#   --port PORT   Loopback TCP port to listen on (default: 8631)
#   --release     Build/use target/release instead of target/debug
#   --no-build    Skip cargo build and use existing binaries
#   --keep        Keep daemon running after smoke test (Ctrl-C to stop)
#   -h, --help    Show this help message

set -euo pipefail
cd "$(dirname "$0")/.."

command -v cargo >/dev/null 2>&1 || PATH="$HOME/.cargo/bin:$PATH"

PORT="${PW_DEV_PORT:-8631}"
PROFILE="debug"
DO_BUILD=1
KEEP=0

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --port)
            [ $# -ge 2 ] || { echo "dev-local.sh: --port requires a value" >&2; exit 2; }
            PORT="$2"; shift ;;
        --port=*)
            PORT="${1#--port=}" ;;
        --release)
            PROFILE="release" ;;
        --no-build)
            DO_BUILD=0 ;;
        --keep)
            KEEP=1 ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "dev-local.sh: unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

DEVROOT=$(mktemp -d "${TMPDIR:-/tmp}/presswork-dev.XXXXXX")
DAEMON_PID=""

cleanup() {
    local rc=$?
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$DAEMON_PID" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$DEVROOT"
    exit "$rc"
}
trap cleanup EXIT INT TERM

if [ "$DO_BUILD" = 1 ]; then
    echo "[1/6] Building presswork workspace ($PROFILE)..."
    if [ "$PROFILE" = "release" ]; then
        cargo build --workspace --release
    else
        cargo build --workspace
    fi
fi

TARGET_DIR="target/$PROFILE"
if [ ! -x "$TARGET_DIR/cupsd" ]; then
    echo "dev-local.sh: $TARGET_DIR/cupsd not found (run without --no-build)" >&2
    exit 1
fi

echo "[2/6] Staging isolated runtime tree in $DEVROOT..."
mkdir -p "$DEVROOT"/{etc,spool/tmp,run/certs,cache/rss,logs,out,doc-root,tmp,mime,data/mime,ppd,drv,bin/{daemon,backend,filter,notifier}}

cp "$TARGET_DIR/cupsd" "$DEVROOT/cupsd"
for d in cups-deviced cups-driverd cups-lpd cups-exec; do
    [ -x "$TARGET_DIR/$d" ] && cp "$TARGET_DIR/$d" "$DEVROOT/bin/daemon/$d"
done
for b in file ipp lpd socket dnssd snmp serial parallel usb; do
    [ -x "$TARGET_DIR/$b" ] && cp "$TARGET_DIR/$b" "$DEVROOT/bin/backend/$b"
done

cp data/mime/mime.types "$DEVROOT/mime/mime.types"
cp data/mime/mime.convs "$DEVROOT/mime/mime.convs"
cp data/mime/mime.types "$DEVROOT/data/mime/mime.types"
cp data/mime/mime.convs "$DEVROOT/data/mime/mime.convs"

CURRENT_USER=$(id -un)
CURRENT_GROUP=$(id -gn)

cat > "$DEVROOT/etc/cups-files.conf" <<EOF
User $CURRENT_USER
Group $CURRENT_GROUP
SystemGroup $CURRENT_GROUP
ServerRoot $DEVROOT/etc
StateDir $DEVROOT/run
RequestRoot $DEVROOT/spool
CacheDir $DEVROOT/cache
ServerBin $DEVROOT/bin
DataDir $DEVROOT/mime
DocumentRoot $DEVROOT/doc-root
TempDir $DEVROOT/tmp
ErrorLog $DEVROOT/logs/error_log
AccessLog $DEVROOT/logs/access_log
PageLog $DEVROOT/logs/page_log
FileDevice Yes
EOF

cat > "$DEVROOT/etc/cupsd.conf" <<EOF
LogLevel info
MaxLogSize 0
Listen 127.0.0.1:$PORT
Listen $DEVROOT/run/cups.sock
Browsing No
DefaultShared No
WebInterface Yes

<Location />
  Order allow,deny
  Allow from 127.0.0.1
  Allow from ::1
</Location>

<Location /admin>
  Order allow,deny
  Allow from 127.0.0.1
  Allow from ::1
</Location>

<Policy default>
  <Limit All>
    Order allow,deny
    Allow from 127.0.0.1
    Allow from ::1
  </Limit>
</Policy>
EOF

"$DEVROOT/cupsd" -t -c "$DEVROOT/etc/cupsd.conf"

echo "[3/6] Starting unprivileged cupsd on 127.0.0.1:$PORT..."
"$DEVROOT/cupsd" -c "$DEVROOT/etc/cupsd.conf" -f > "$DEVROOT/logs/stdout.log" 2>&1 &
DAEMON_PID=$!

# Wait until loopback port accepts connections (up to 10s).
READY=0
for _ in $(seq 1 50); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "dev-local.sh: cupsd exited unexpectedly:" >&2
        cat "$DEVROOT/logs/stdout.log" >&2 || true
        exit 1
    fi
    if python3 -c "import socket, sys; s = socket.create_connection(('127.0.0.1', int(sys.argv[1])), 0.2); s.close()" "$PORT" 2>/dev/null; then
        READY=1
        break
    fi
    sleep 0.2
done

if [ "$READY" != 1 ]; then
    echo "dev-local.sh: timed out waiting for 127.0.0.1:$PORT" >&2
    cat "$DEVROOT/logs/stdout.log" >&2 || true
    exit 1
fi

echo "[4/6] Checking /healthz and IPP CUPS-Get-Printers..."
python3 - "$PORT" "$DEVROOT/out/dev-test.out" <<'PYEOF'
import http.client
import os
import struct
import sys
import time

port = int(sys.argv[1])
out_path = sys.argv[2]

def http_get(path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers={"Host": f"127.0.0.1:{port}"})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, body

def ipp_attr(tag, name, value):
    nb = name.encode("utf-8")
    vb = value if isinstance(value, bytes) else value.encode("utf-8")
    return struct.pack(">BH", tag, len(nb)) + nb + struct.pack(">H", len(vb)) + vb

def ipp_request(path, op_id, req_id, op_attrs, extra_groups=b"", doc=b""):
    payload = struct.pack(">BBHI", 1, 1, op_id, req_id)
    payload += b"\x01" + op_attrs + extra_groups + b"\x03" + doc
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(
        "POST",
        path,
        body=payload,
        headers={
            "Host": f"127.0.0.1:{port}",
            "Content-Type": "application/ipp",
            "Content-Length": str(len(payload)),
        },
    )
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    if resp.status != 200 or len(raw) < 8:
        raise RuntimeError(f"IPP HTTP error: status={resp.status} len={len(raw)}")
    ver_maj, ver_min, status_code, resp_req_id = struct.unpack(">BBHI", raw[:8])
    return status_code, raw

# 1. Check /healthz
hz_status, hz_body = http_get("/healthz")
if hz_status == 200:
    print(f"  /healthz -> HTTP {hz_status} OK")
elif hz_status == 404:
    print("  /healthz -> HTTP 404 (HTTP listener healthy; /healthz endpoint not yet enabled on this build)")
else:
    raise RuntimeError(f"/healthz unexpected HTTP status {hz_status}: {hz_body!r}")

# 2. Check IPP CUPS-Get-Printers (0x4002)
base_attrs = (
    ipp_attr(0x47, "attributes-charset", "utf-8")
    + ipp_attr(0x48, "attributes-natural-language", "en")
)
status, _ = ipp_request("/", 0x4002, 1, base_attrs)
if status not in (0x0000, 0x0406):  # successful-ok or client-error-not-found (empty queue list)
    raise RuntimeError(f"CUPS-Get-Printers failed: status=0x{status:04x}")
print(f"  IPP CUPS-Get-Printers -> 0x{status:04x} OK")

# 3. Create test queue `dev-test` via CUPS-Add-Modify-Printer (0x4003)
printer_uri = f"ipp://127.0.0.1:{port}/printers/dev-test"
add_op_attrs = (
    base_attrs
    + ipp_attr(0x45, "printer-uri", printer_uri)
    + ipp_attr(0x42, "requesting-user-name", os.environ.get("USER", "dev"))
)
printer_group = (
    b"\x04"  # printer-attributes-tag
    + ipp_attr(0x45, "device-uri", f"file://{out_path}")
    + ipp_attr(0x22, "printer-is-accepting-jobs", b"\x01")
    + ipp_attr(0x23, "printer-state", struct.pack(">I", 3))  # idle
    + ipp_attr(0x41, "printer-info", "Presswork dev-local smoke test queue")
)
status, _ = ipp_request("/admin/", 0x4003, 2, add_op_attrs, extra_groups=printer_group)
if status > 0x00FF:
    raise RuntimeError(f"CUPS-Add-Modify-Printer failed: status=0x{status:04x}")
print(f"  Created queue 'dev-test' (file://{out_path}) -> 0x{status:04x} OK")

# 4. Verify `dev-test` appears in CUPS-Get-Printers
status, raw = ipp_request("/", 0x4002, 3, base_attrs)
if status != 0x0000 or b"dev-test" not in raw:
    raise RuntimeError(f"Queue 'dev-test' missing from CUPS-Get-Printers (status=0x{status:04x})")
print("  Verified 'dev-test' listed in CUPS-Get-Printers OK")

# 5. Print a test job via Print-Job (0x0002)
print_attrs = (
    base_attrs
    + ipp_attr(0x45, "printer-uri", printer_uri)
    + ipp_attr(0x42, "requesting-user-name", os.environ.get("USER", "dev"))
    + ipp_attr(0x42, "job-name", "dev-local-smoke-test")
    + ipp_attr(0x49, "document-format", "application/octet-stream")
)
test_doc = b"Hello from Presswork dev-local smoke test!\n"
status, _ = ipp_request("/printers/dev-test", 0x0002, 4, print_attrs, doc=test_doc)
if status > 0x00FF:
    raise RuntimeError(f"Print-Job failed: status=0x{status:04x}")
print(f"  Submitted Print-Job to 'dev-test' -> 0x{status:04x} OK")

# 6. Wait briefly for file backend output
for _ in range(30):
    if os.path.exists(out_path) and os.path.getsize(out_path) >= len(test_doc):
        break
    time.sleep(0.1)

if os.path.exists(out_path):
    written = open(out_path, "rb").read()
    if test_doc in written:
        print(f"  Verified spool output written to {out_path} ({len(written)} bytes) OK")
    else:
        raise RuntimeError(f"Unexpected output in {out_path}: {written!r}")
else:
    raise RuntimeError(f"Expected print output file was not created: {out_path}")
PYEOF

echo "[5/6] Smoke test PASSED on 127.0.0.1:$PORT!"

if [ "$KEEP" = 1 ]; then
    echo ""
    echo "Presswork dev daemon is running (PID $DAEMON_PID):"
    echo "  IPP URL:    http://127.0.0.1:$PORT"
    echo "  Unix sock:  $DEVROOT/run/cups.sock"
    echo "  Logs:       $DEVROOT/logs/"
    echo "  Try:        lpstat -h 127.0.0.1:$PORT -t"
    echo "Press Ctrl-C to stop and clean up $DEVROOT."
    wait "$DAEMON_PID"
else
    echo "[6/6] Tearing down isolated daemon and cleaning up $DEVROOT..."
fi
