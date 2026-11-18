# AUR submission: presswork-bin

This directory is a ready-to-push AUR package repo. `presswork-bin`
installs the CI-built release tarball; `presswork` (source build) uses
`packaging/arch/PKGBUILD` instead.

## Runtime dependencies

- `glibc`, `gcc-libs`, `libxcrypt` (Presswork resolves `libcrypt.so.2`
  dynamically via `dlopen` with `libcrypt.so.1` fallback, so Arch's
  native `libxcrypt` works directly without `libxcrypt-compat`).
- Optional: `cups-filters` (for PDF/PostScript/raster filters on legacy
  printers) and `cups-client` (`lp`, `lpstat`, `lpadmin`).

## Submitting (needs an AUR account + SSH key)

```sh
# 1. clone the empty AUR repo for the package name
git clone ssh://aur@aur.archlinux.org/presswork-bin.git aur-presswork-bin
cd aur-presswork-bin

# 2. copy these files in, refresh checksums from the release SHA256SUMS,
#    then generate .SRCINFO
cp /path/to/presswork/packaging/aur-bin/* .
updpkgsums
makepkg --printsrcinfo > .SRCINFO
makepkg -si         # sanity check: installs presswork locally

# 3. push
git add -A && git commit -m "presswork-bin 0.1.0-1" && git push
```

## Per-release maintenance

Bump `pkgver`, refresh the release-tarball SHA-256 hash from the GitHub
release's `SHA256SUMS` asset, run `updpkgsums`, regenerate `.SRCINFO`,
and push.

The aux files mirror `packaging/arch/presswork.{sysusers,tmpfiles}` and
`data/{sysusers.d,tmpfiles.d}/presswork.conf`; keep them in sync if the
runtime user or directories ever change.
