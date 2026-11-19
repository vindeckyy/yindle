#!/bin/sh
# dist.sh — build release artifacts into ./dist:
#   yindle-$VER-$TARGET.tar.gz          FHS tree + install.sh
#   yindle_${VER}-1_${DEB_ARCH}.deb     Debian package (dpkg-deb)
#   SHA256SUMS
# Run from the repo root. Used by release.yml; safe to run locally without root.
set -eu

# Enforce deterministic 0755/0644 permissions regardless of caller umask.
umask 022

command -v cargo >/dev/null 2>&1 || PATH="$HOME/.cargo/bin:$PATH"

VER=${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)}
TARGET=$(rustc -vV | sed -n 's/^host: //p')
PKG="yindle-$VER-$TARGET"

if command -v dpkg >/dev/null 2>&1; then
    DEB_ARCH=$(dpkg --print-architecture)
else
    case "$(uname -m)" in
        x86_64)  DEB_ARCH=amd64 ;;
        aarch64) DEB_ARCH=arm64 ;;
        armv7l)  DEB_ARCH=armhf ;;
        riscv64) DEB_ARCH=riscv64 ;;
        *)       DEB_ARCH=$(uname -m) ;;
    esac
fi

DEB_FILE="yindle_${VER}-1_${DEB_ARCH}.deb"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

TAR_STAGE="$WORK/yindle-$VER"
DEB_STAGE="$WORK/deb-stage"

rm -rf dist
mkdir -p dist "$TAR_STAGE" "$DEB_STAGE"

cargo build --workspace --release --locked

# ---- tarball staging (isolated temp dir) -----------------------------------
make install-files DESTDIR="$TAR_STAGE" PROFILE=release CHOWN=0 >/dev/null
install -m 0755 install.sh "$TAR_STAGE/install.sh"
install -m 0644 README.md "$TAR_STAGE/README.md"
[ -f NOTICE ] && install -m 0644 NOTICE "$TAR_STAGE/NOTICE"
[ -f LICENSE-APACHE ] && install -m 0644 LICENSE-APACHE "$TAR_STAGE/LICENSE-APACHE"
[ -f LICENSE-MIT ] && install -m 0644 LICENSE-MIT "$TAR_STAGE/LICENSE-MIT"

# Normalize directory permissions in tarball tree.
find "$TAR_STAGE" -type d -exec chmod 0755 {} +
chmod 0700 "$TAR_STAGE/etc/cups/ssl"
chmod 0710 "$TAR_STAGE/var/spool/cups" "$TAR_STAGE/var/spool/cups/tmp"
chmod 0770 "$TAR_STAGE/var/cache/cups" "$TAR_STAGE/var/cache/cups/rss"
chmod 0700 "$TAR_STAGE/usr/lib/cups/backend/usb" "$TAR_STAGE/usr/lib/cups/backend/parallel"

tar -C "$WORK" --owner=0 --group=0 --numeric-owner \
    -czf "dist/$PKG.tar.gz" "yindle-$VER"

# ---- Debian .deb staging (separate clean temp dir — zero / pollution) ------
make install-files DESTDIR="$DEB_STAGE" PROFILE=release CHOWN=0 >/dev/null

# Normalize all directory permissions (eliminates 0775 umask leaks on /, /etc,
# /usr, /var, /run) while preserving restrictive directory/binary modes.
chmod 0755 "$DEB_STAGE"
find "$DEB_STAGE" -type d -exec chmod 0755 {} +
chmod 0700 "$DEB_STAGE/etc/cups/ssl"
chmod 0710 "$DEB_STAGE/var/spool/cups" "$DEB_STAGE/var/spool/cups/tmp"
chmod 0770 "$DEB_STAGE/var/cache/cups" "$DEB_STAGE/var/cache/cups/rss"
chmod 0700 "$DEB_STAGE/usr/lib/cups/backend/usb" "$DEB_STAGE/usr/lib/cups/backend/parallel"
chmod 0640 "$DEB_STAGE/etc/cups/cupsd.conf" "$DEB_STAGE/etc/cups/cups-files.conf" \
    "$DEB_STAGE/etc/cups/cupsd.conf.default" "$DEB_STAGE/etc/cups/cups-files.conf.default"

# Determine runtime shared-library Depends cleanly.
DEB_DEPENDS="adduser, libc6, libgcc-s1"
if command -v ldd >/dev/null 2>&1 && ldd "$DEB_STAGE/usr/sbin/cupsd" 2>/dev/null | grep -q 'libcrypt\.so'; then
    DEB_DEPENDS="$DEB_DEPENDS, libcrypt1"
fi

DEB="$DEB_STAGE/DEBIAN"
mkdir -p "$DEB"
chmod 0755 "$DEB"

cat > "$DEB/control" <<EOF
Package: yindle
Version: $VER-1
Section: net
Priority: optional
Architecture: $DEB_ARCH
Maintainer: vindeckyy <35399491+vindeckyy@users.noreply.github.com>
Homepage: https://github.com/vindeckyy/yindle
Depends: $DEB_DEPENDS
Recommends: cups-client, cups-filters
Provides: cups, cups-daemon
Conflicts: cups, cups-daemon
Replaces: cups-daemon
Description: memory-safe CUPS-compatible print spooler and IPP scheduler
 A Rust reimplementation of the CUPS 2.x scheduler: cupsd, helper
 daemons, and the standard backends, speaking the same IPP on the same
 sockets and reading /etc/cups in place.
EOF
chmod 0644 "$DEB/control"

# Generate DEBIAN/conffiles so upgrades preserve operator-modified configs.
: > "$DEB/conffiles"
for cf in /etc/cups/cupsd.conf /etc/cups/cups-files.conf /etc/pam.d/cups /etc/logrotate.d/yindle; do
    if [ -f "$DEB_STAGE$cf" ]; then
        printf '%s\n' "$cf" >> "$DEB/conffiles"
    fi
done
chmod 0644 "$DEB/conffiles"

# Build postinst from packaging/debian/yindle.postinst with systemd
# activation BEFORE exit 0 (never appended after exit 0).
sed '/^#DEBHELPER#$/d' packaging/debian/yindle.postinst > "$DEB/postinst"
chmod 0755 "$DEB/postinst"

cat > "$DEB/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "deconfigure" ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl stop cups.path cups.socket cups.service cups-lpd.socket 2>/dev/null || true
        systemctl disable cups.socket cups.path cups-lpd.socket 2>/dev/null || true
    fi
fi
exit 0
EOF
chmod 0755 "$DEB/prerm"

cat > "$DEB/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload 2>/dev/null || true
fi
exit 0
EOF
chmod 0755 "$DEB/postrm"

dpkg-deb --root-owner-group --build "$DEB_STAGE" "dist/$DEB_FILE" >/dev/null

# ---- checksums -------------------------------------------------------------
(cd dist && sha256sum "$PKG.tar.gz" "$DEB_FILE" > SHA256SUMS)

ls -l dist/
