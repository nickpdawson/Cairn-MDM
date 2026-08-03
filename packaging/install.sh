#!/bin/sh
# Cairn installer: detect OS/arch, download the matching release tarball from
# GitHub, VERIFY its checksum against the published checksums.txt, and install
# the binary. Refuses to proceed on a checksum mismatch.
#
#   curl -fsSL https://raw.githubusercontent.com/dzsec/Cairn-MDM/main/packaging/install.sh | sh
#   # or pin a version:
#   ... | sh -s -- v0.2.0
#
# Env overrides: CAIRN_VERSION, CAIRN_INSTALL_DIR (default /usr/local/bin),
# CAIRN_REPO (default dzsec/Cairn-MDM).
set -eu

REPO="${CAIRN_REPO:-dzsec/Cairn-MDM}"
INSTALL_DIR="${CAIRN_INSTALL_DIR:-/usr/local/bin}"
VERSION="${1:-${CAIRN_VERSION:-latest}}"

err() { echo "install: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Pick a downloader.
if have curl; then DL="curl -fsSL"; DLO="curl -fsSL -o";
elif have wget; then DL="wget -qO-"; DLO="wget -qO";
else err "need curl or wget"; fi

# Pick a sha256 tool.
if have sha256sum; then SHA="sha256sum";
elif have shasum; then SHA="shasum -a 256";
else err "need sha256sum or shasum"; fi

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in linux|darwin|freebsd) ;; *) err "unsupported OS: $os" ;; esac
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) err "unsupported arch: $arch" ;;
esac

if [ "$VERSION" = "latest" ]; then
  VERSION="$($DL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)"
  [ -n "$VERSION" ] || err "could not resolve the latest version"
fi
ver_nov="${VERSION#v}"

base="https://github.com/${REPO}/releases/download/${VERSION}"
tarball="cairn_${ver_nov}_${os}_${arch}.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "Downloading ${tarball} (${VERSION})..."
$DLO "$tmp/$tarball" "$base/$tarball" || err "download failed: $base/$tarball"
$DLO "$tmp/checksums.txt" "$base/checksums.txt" || err "download failed: checksums.txt"

echo "Verifying checksum..."
want="$(grep " ${tarball}\$" "$tmp/checksums.txt" | awk '{print $1}')"
[ -n "$want" ] || err "no checksum listed for ${tarball}"
got="$(cd "$tmp" && $SHA "$tarball" | awk '{print $1}')"
[ "$want" = "$got" ] || err "CHECKSUM MISMATCH — refusing to install (want $want, got $got)"

tar -xzf "$tmp/$tarball" -C "$tmp"
if [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "$tmp/cairn" "$INSTALL_DIR/cairn"
else
  echo "Installing to $INSTALL_DIR (needs sudo)..."
  sudo install -m 0755 "$tmp/cairn" "$INSTALL_DIR/cairn"
fi

echo "Installed: $("$INSTALL_DIR/cairn" version)"
echo "Next: run 'cairn init' to set up config, CA, and the admin account."
