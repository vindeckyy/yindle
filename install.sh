#!/bin/sh
# presswork one-command installer.
#
#   curl -fsSL https://raw.githubusercontent.com/vindeckyy/presswork/main/install.sh | sh
#
# Options:
#   --no-start              Install files and units without starting services
#   --version VER           Install a specific release version (default: latest)
#   --from DIR              Install from an already-unpacked release tree
#   --force                 Proceed even if another cupsd is installed
#   --insecure-skip-verify  Skip SHA256SUMS verification (NOT recommended)
#   --uninstall             Remove installed presswork binaries and units
#                           (preserves /etc/cups/*.conf and /var/spool/cups)
#   -h, --help              Show this help message
#
# Run standalone it downloads the matching release tarball, verifies its
# SHA256SUMS entry (failing closed on mismatch or missing checksums), lands
# the upstream FHS layout without overwriting existing /etc/cups configs,
# creates the lp/lpadmin accounts cleanly, installs tmpfiles.d/sysusers.d,
# and enables socket activation (cups.socket + cups.path).
set -eu

REPO=vindeckyy/presswork

die() { echo "install.sh: $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: install.sh [OPTIONS]

Options:
  --no-start              Install files and units without starting services
  --version VER           Install a specific release version (default: latest)
  --from DIR              Install from an already-unpacked release tree
  --force                 Proceed even if another cupsd is installed
  --insecure-skip-verify  Skip SHA256SUMS verification (NOT recommended)
  --uninstall             Remove installed presswork binaries and units
  -h, --help              Show this help message
EOF
}

START=1
VERSION=""
SRC=""
FORCE=0
INSECURE_SKIP_VERIFY=0
UNINSTALL=0

while [ $# -gt 0 ]; do
    case "$1" in
        --no-start)
            START=0 ;;
        --force)
            FORCE=1 ;;
        --insecure-skip-verify)
            INSECURE_SKIP_VERIFY=1 ;;
        --uninstall)
            UNINSTALL=1 ;;
        --version)
            [ $# -ge 2 ] || die "--version requires a value"
            [ -n "$2" ] || die "--version value cannot be empty"
            VERSION=$2
            shift ;;
        --version=*)
            VERSION=${1#--version=}
            [ -n "$VERSION" ] || die "--version value cannot be empty" ;;
        --from)
            [ $# -ge 2 ] || die "--from requires a directory path"
            [ -n "$2" ] || die "--from value cannot be empty"
            SRC=$2
            shift ;;
        --from=*)
            SRC=${1#--from=}
            [ -n "$SRC" ] || die "--from value cannot be empty" ;;
        -h|--help)
            usage
            exit 0 ;;
        *)
            die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

fetch() {  # url dest
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        die "need curl or wget"
    fi
}

verify_sha256() {  # checksums_file target_filename dir
    cs_file=$1
    target_name=$2
    work_dir=$3

    line=$(awk -v f="$target_name" '$2 == f || $2 == "*" f { print; exit }' "$cs_file")
    [ -n "$line" ] || die "no SHA256SUMS entry found for $target_name"

    if command -v sha256sum >/dev/null 2>&1; then
        ( cd "$work_dir" && printf '%s\n' "$line" | sha256sum -c - ) \
            || die "SHA256 checksum verification failed for $target_name"
    elif command -v shasum >/dev/null 2>&1; then
        ( cd "$work_dir" && printf '%s\n' "$line" | shasum -a 256 -c - ) \
            || die "SHA256 checksum verification failed for $target_name"
    else
        die "sha256sum or shasum is required to verify download integrity (pass --insecure-skip-verify to override)"
    fi
}

install_config_preserve() {  # src_file dest_file mode group
    src_f=$1
    dst_f=$2
    mode=$3
    grp=$4
    [ -f "$src_f" ] || return 0
    if [ -e "$dst_f" ]; then
        $SUDO install -m "$mode" -o root -g "$grp" "$src_f" "${dst_f}.new"
        echo "install.sh: preserved existing $dst_f (new default saved to ${dst_f}.new)"
    else
        $SUDO install -m "$mode" -o root -g "$grp" "$src_f" "$dst_f"
    fi
}

SUDO=""
if [ "$(id -u)" != 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "run as root or install sudo"
    SUDO=sudo
fi

# ---- uninstall --------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        $SUDO systemctl stop cups.path cups.socket cups.service cups-lpd.socket 2>/dev/null || true
        $SUDO systemctl disable cups.socket cups.path cups-lpd.socket 2>/dev/null || true
    fi
    $SUDO rm -f /usr/sbin/cupsd /usr/bin/cupsfilter
    for d in cups-deviced cups-driverd cups-exec cups-lpd; do
        $SUDO rm -f "/usr/lib/cups/daemon/$d"
    done
    for b in socket file ipp lpd snmp usb dnssd serial parallel; do
        $SUDO rm -f "/usr/lib/cups/backend/$b"
    done
    for u in cups.service cups.socket cups.path cups-lpd@.service cups-lpd.socket; do
        $SUDO rm -f "/usr/lib/systemd/system/$u"
    done
    $SUDO rm -f /usr/lib/tmpfiles.d/presswork.conf \
        /usr/lib/sysusers.d/presswork.conf \
        /usr/share/cups/mime/mime.types \
        /usr/share/cups/mime/mime.convs \
        /etc/cups/cupsd.conf.default \
        /etc/cups/cups-files.conf.default
    $SUDO rm -rf /usr/share/doc/presswork
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        $SUDO systemctl daemon-reload || true
    fi
    echo "presswork uninstalled."
    echo "  Preserved user configuration and state:"
    echo "    /etc/cups/ (cupsd.conf, cups-files.conf, printers.conf, ssl/)"
    echo "    /var/spool/cups/, /var/log/cups/, /var/cache/cups/"
    exit 0
fi

# Refuse to silently overwrite a distro-managed cupsd.
if [ "$FORCE" = 0 ] && [ -x /usr/sbin/cupsd ] && [ ! -f /usr/share/doc/presswork/README.md ]; then
    cat >&2 <<'EOF'
install.sh: an existing /usr/sbin/cupsd was found.
  On Debian/Ubuntu remove it first (apt remove cups-daemon; keep
  cups-client for the lp* tools) or install the .deb instead.
  Re-run with --force to overwrite anyway.
EOF
    exit 1
fi

# ---- obtain the release tree ------------------------------------------------
TMP=""
trap '[ -n "$TMP" ] && rm -rf "$TMP"' EXIT

if [ -z "$SRC" ]; then
    if [ -d usr ] && [ -x usr/sbin/cupsd ]; then
        SRC=.
    else
        arch=$(uname -m)
        case "$arch" in
            x86_64|aarch64)
                TARGET="$arch-unknown-linux-gnu" ;;
            *)
                die "no prebuilt package for architecture '$arch'; build from source (see README)" ;;
        esac

        TMP=$(mktemp -d)
        if [ -z "$VERSION" ]; then
            fetch "https://api.github.com/repos/$REPO/releases/latest" "$TMP/latest.json"
            VERSION=$(sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' "$TMP/latest.json" | head -n 1)
            [ -n "$VERSION" ] || die "could not determine latest release"
        fi
        VERSION=${VERSION#v}

        PKG="presswork-$VERSION-$TARGET"
        BASE="https://github.com/$REPO/releases/download/v$VERSION"
        echo "install.sh: fetching $PKG"
        fetch "$BASE/$PKG.tar.gz" "$TMP/$PKG.tar.gz"

        if [ "$INSECURE_SKIP_VERIFY" = 1 ]; then
            echo "install.sh: WARNING: skipping SHA256SUMS verification (--insecure-skip-verify)" >&2
        else
            fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" \
                || die "failed to download SHA256SUMS; refusing unverified install (pass --insecure-skip-verify to override)"
            verify_sha256 "$TMP/SHA256SUMS" "$PKG.tar.gz" "$TMP"
        fi

        tar -C "$TMP" -xzf "$TMP/$PKG.tar.gz"
        SRC="$TMP/presswork-$VERSION"
    fi
fi

[ -x "$SRC/usr/sbin/cupsd" ] || die "$SRC does not look like a presswork release tree"

# ---- accounts ---------------------------------------------------------------
# Create lp user/group and lpadmin group. Do NOT add lp to lpadmin: filters
# and backends run as lp and must never hold @SYSTEM admin privileges.
getent group lp >/dev/null 2>&1 || $SUDO groupadd -r lp
id lp >/dev/null 2>&1 || $SUDO useradd -r -g lp -d /var/spool/cups -s /usr/sbin/nologin lp
getent group lpadmin >/dev/null 2>&1 || $SUDO groupadd -r lpadmin

# ---- file tree --------------------------------------------------------------
$SUDO cp -a "$SRC/usr/." /usr/

# Ensure /etc/cups layout without clobbering existing operator configs.
$SUDO install -d -m 0755 -o root -g lp /etc/cups
$SUDO install -d -m 0755 -o root -g root /etc/cups/ppd /etc/cups/interfaces
$SUDO install -d -m 0700 -o root -g root /etc/cups/ssl

if [ -f "$SRC/etc/cups/cupsd.conf.default" ]; then
    $SUDO install -m 0640 -o root -g lp "$SRC/etc/cups/cupsd.conf.default" /etc/cups/cupsd.conf.default
fi
if [ -f "$SRC/etc/cups/cups-files.conf.default" ]; then
    $SUDO install -m 0640 -o root -g lp "$SRC/etc/cups/cups-files.conf.default" /etc/cups/cups-files.conf.default
fi

# Prefer .default templates if cupsd.conf/cups-files.conf are absent in $SRC.
CUPSD_SRC="$SRC/etc/cups/cupsd.conf"
[ -f "$CUPSD_SRC" ] || CUPSD_SRC="$SRC/etc/cups/cupsd.conf.default"
FILES_SRC="$SRC/etc/cups/cups-files.conf"
[ -f "$FILES_SRC" ] || FILES_SRC="$SRC/etc/cups/cups-files.conf.default"

install_config_preserve "$CUPSD_SRC" /etc/cups/cupsd.conf 0640 lp
install_config_preserve "$FILES_SRC" /etc/cups/cups-files.conf 0640 lp

$SUDO install -d -m 0755 /etc/pam.d /etc/logrotate.d
install_config_preserve "$SRC/etc/pam.d/cups" /etc/pam.d/cups 0644 root
install_config_preserve "$SRC/etc/logrotate.d/presswork" /etc/logrotate.d/presswork 0644 root

# Runtime, spool, log, and cache directories.
$SUDO install -d -m 0710 -o lp -g lp /var/spool/cups /var/spool/cups/tmp
$SUDO install -d -m 0755 -o lp -g lp /var/log/cups
$SUDO install -d -m 0770 -o lp -g lp /var/cache/cups /var/cache/cups/rss
$SUDO install -d -m 0755 -o lp -g lp /run/cups /run/cups/certs

# Install tmpfiles.d/sysusers.d if shipped outside /usr (fallback for custom trees).
if [ -f "$SRC/data/tmpfiles.d/presswork.conf" ] && [ ! -f /usr/lib/tmpfiles.d/presswork.conf ]; then
    $SUDO install -d -m 0755 /usr/lib/tmpfiles.d
    $SUDO install -m 0644 "$SRC/data/tmpfiles.d/presswork.conf" /usr/lib/tmpfiles.d/presswork.conf
fi
if [ -f "$SRC/data/sysusers.d/presswork.conf" ] && [ ! -f /usr/lib/sysusers.d/presswork.conf ]; then
    $SUDO install -d -m 0755 /usr/lib/sysusers.d
    $SUDO install -m 0644 "$SRC/data/sysusers.d/presswork.conf" /usr/lib/sysusers.d/presswork.conf
fi

if command -v systemd-tmpfiles >/dev/null 2>&1 && [ -f /usr/lib/tmpfiles.d/presswork.conf ]; then
    $SUDO systemd-tmpfiles --create presswork.conf 2>/dev/null || true
fi

# ---- activation -------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    $SUDO systemctl daemon-reload || true
    $SUDO systemctl enable cups.socket cups.path 2>/dev/null || true
    if [ "$START" = 1 ]; then
        $SUDO systemctl restart cups.socket cups.path 2>/dev/null || true
        $SUDO systemctl start cups.service 2>/dev/null || true
    fi
fi

# ---- post-install verification ----------------------------------------------
echo "presswork ${VERSION:-release} installed."
if [ -x /usr/sbin/cupsd ]; then
    if $SUDO /usr/sbin/cupsd -t >/dev/null 2>&1; then
        echo "  config check: OK (/usr/sbin/cupsd -t)"
    else
        echo "  config check: WARNING — review /etc/cups/cupsd.conf with '/usr/sbin/cupsd -t'" >&2
    fi
fi
echo ""
echo "Next steps & verification:"
echo "  1. Validate config:    sudo cupsd -t  (or 'cupsd --check-config' / 'cupsd doctor' when available)"
echo "  2. Grant admin access: sudo usermod -aG lpadmin \"\$USER\"  (then re-login)"
echo "  3. Service status:     systemctl status cups.socket cups.service"
echo "  4. Add a print queue:  lpadmin -p <name> -E -v <uri> -m everywhere"
echo "  5. Verify queues:      lpstat -t"
echo "  6. Uninstall later:    install.sh --uninstall"
