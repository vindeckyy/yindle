# nixpkgs derivation for presswork.
#
# Release maintenance (pkgs/by-name/pr/presswork/package.nix):
#   1. Replace `src.hash` with the SRI hash for tag `v${version}`:
#        nix-prefetch-github vindeckyy presswork --rev v0.1.0
#   2. Replace `cargoHash` with the SRI hash printed by the first Nix build
#      after updating `src.hash`.
#   3. Keep `meta.homepage` and `meta.changelog` pointing at the upstream repo.
{ lib
, rustPlatform
, fetchFromGitHub
, libxcrypt
}:

rustPlatform.buildRustPackage rec {
  pname = "presswork";
  version = "0.1.0";

  src = fetchFromGitHub {
    owner = "vindeckyy";
    repo = "presswork";
    rev = "v${version}";
    # Placeholder: update from `nix-prefetch-github vindeckyy presswork --rev v0.1.0` on release.
    hash = lib.fakeHash;
  };

  # Placeholder: update with the real Cargo vendor hash printed by Nix on release.
  cargoHash = lib.fakeHash;

  # libxcrypt provides libcrypt.so.2 for dynamic shadow auth resolution.
  buildInputs = [ libxcrypt ];

  # The ipptool conformance suite needs a live daemon; run workspace unit/integration tests.
  checkFlags = [ "--workspace" ];

  # Relocate binaries already built by buildRustPackage into the FHS layout.
  # Never invoke `cargo build` or `chown` inside the Nix build sandbox, and
  # move the `file` backend out of $out/bin so it does not collide with GNU file.
  postInstall = ''
    install -d -m 0755 \
      "$out/sbin" \
      "$out/lib/cups/daemon" \
      "$out/lib/cups/backend" \
      "$out/lib/cups/filter" \
      "$out/lib/cups/notifier" \
      "$out/lib/cups/driver" \
      "$out/lib/cups/cgi-bin" \
      "$out/share/cups/mime" \
      "$out/share/cups/banners" \
      "$out/share/cups/drv" \
      "$out/share/cups/ppd" \
      "$out/share/cups/data" \
      "$out/share/cups/templates" \
      "$out/share/cups/doc-root" \
      "$out/share/doc/presswork" \
      "$out/etc/cups" \
      "$out/etc/pam.d" \
      "$out/etc/logrotate.d" \
      "$out/lib/systemd/system" \
      "$out/lib/tmpfiles.d" \
      "$out/lib/sysusers.d"

    mv "$out/bin/cupsd" "$out/sbin/cupsd"
    for d in cups-deviced cups-driverd cups-exec cups-lpd; do
      mv "$out/bin/$d" "$out/lib/cups/daemon/$d"
    done
    for b in socket file ipp lpd snmp usb dnssd serial parallel; do
      mv "$out/bin/$b" "$out/lib/cups/backend/$b"
    done
    chmod 0700 "$out/lib/cups/backend/usb" "$out/lib/cups/backend/parallel"

    # MIME database and default configuration templates.
    install -m 0644 data/mime/mime.types data/mime/mime.convs "$out/share/cups/mime/"
    install -m 0640 data/cupsd.conf.default "$out/etc/cups/cupsd.conf.default"
    install -m 0640 data/cups-files.conf.default "$out/etc/cups/cups-files.conf.default"
    install -m 0644 packaging/pam/cups "$out/etc/pam.d/cups"
    install -m 0644 data/logrotate.d/presswork "$out/etc/logrotate.d/presswork"

    # systemd units (rewrite store paths), tmpfiles.d, and sysusers.d.
    for u in cups.service cups.socket cups.path cups-lpd@.service cups-lpd.socket; do
      substitute "data/systemd/$u" "$out/lib/systemd/system/$u" \
        --replace-quiet "/usr/sbin/cupsd" "$out/sbin/cupsd" \
        --replace-quiet "/usr/lib/cups/daemon/cups-lpd" "$out/lib/cups/daemon/cups-lpd"
    done
    install -m 0644 data/tmpfiles.d/presswork.conf "$out/lib/tmpfiles.d/presswork.conf"
    install -m 0644 data/sysusers.d/presswork.conf "$out/lib/sysusers.d/presswork.conf"

    for doc in README.md SECURITY.md CHANGELOG.md LICENSE-APACHE LICENSE-MIT; do
      [ -f "$doc" ] && install -m 0644 "$doc" "$out/share/doc/presswork/"
    done
  '';

  meta = with lib; {
    description = "Memory-safe CUPS 2.x-compatible print spooler and IPP scheduler in Rust";
    longDescription = ''
      presswork is a drop-in replacement for the CUPS scheduler (cupsd):
      the same IPP wire protocol, config files, spool layout, and
      filter/backend contracts, implemented in Rust with unsafe code
      confined to a single audited FFI crate.
    '';
    homepage = "https://github.com/vindeckyy/presswork";
    changelog = "https://github.com/vindeckyy/presswork/blob/main/CHANGELOG.md";
    license = with licenses; [ asl20 mit ];
    platforms = platforms.linux;
    mainProgram = "cupsd";
    maintainers = [ ];
  };
}
