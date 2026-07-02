#!/bin/sh
set -eu

REPO="boukaba/dns-guard"
VERSION="${VERSION:-v1.0.0}"
DEST="${DEST:-/usr/local/bin}"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

info()  { printf "${GREEN}%s${NC}\n" "$*"; }
error() { printf "${RED}%s${NC}\n" "$*" >&2; exit 1; }

detect_target() {
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)

    case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) error "unsupported architecture: $arch" ;;
    esac

    case "$os" in
        darwin)  echo "apple-darwin" ;;
        linux)   echo "unknown-linux-gnu" ;;
        mingw*|msys*|cygwin*) echo "pc-windows-gnu" ;;
        *) error "unsupported OS: $os" ;;
    esac
}

target=$(detect_target)
case "$target" in
    apple-darwin)
        archive="dns-guard-${VERSION}-apple-darwin.tar.gz"
        binary="dns-guard"
        extract="tar xzf"
        ;;
    unknown-linux-gnu)
        archive="dns-guard-${VERSION}-x86_64-${target}.tar.gz"
        binary="dns-guard"
        extract="tar xzf"
        ;;
    pc-windows-gnu)
        archive="dns-guard-${VERSION}-x86_64-${target}.zip"
        binary="dns-guard.exe"
        extract="unzip -o"
        ;;
esac

url="https://github.com/${REPO}/releases/download/${VERSION}/${archive}"

info "dns-guard ${VERSION} — ${target}"
info "downloading ${url}"

tmpdir=$(mktemp -d)
cd "$tmpdir"

if command -v curl >/dev/null 2>&1; then
    curl -fsSLO "$url" || error "download failed"
elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" || error "download failed"
else
    error "need curl or wget"
fi

eval "$extract" "$archive" || error "extraction failed"
rm -f "$archive"

chmod +x "$binary"

mkdir -p "$DEST"
mv "$binary" "${DEST}/${binary}" && info "installed to ${DEST}/${binary}" || error "install failed"

rm -rf "$tmpdir"

info "run: sudo dns-guard --mode doh"
