#!/bin/bash
set -euo pipefail

# recon0 installer
# Usage: curl -sSL https://raw.githubusercontent.com/badchars/recon0/main/install.sh | bash

REPO="badchars/recon0"
INSTALL_DIR="/usr/local/bin"
BINARY="recon0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[-]${NC} $1"; exit 1; }

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
    linux)  OS="linux" ;;
    darwin) OS="darwin" ;;
    *)      fail "Unsupported OS: $OS" ;;
esac

# Detect ARCH
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)   ARCH="amd64" ;;
    aarch64|arm64)   ARCH="arm64" ;;
    *)               fail "Unsupported architecture: $ARCH" ;;
esac

info "Detected platform: ${OS}/${ARCH}"

# Fetch latest release tag
info "Checking latest release..."
RELEASE_JSON=$(curl -sS "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null) || fail "Cannot reach GitHub API"

TAG=$(echo "$RELEASE_JSON" | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)
[ -z "$TAG" ] && fail "No releases found for ${REPO}"

ok "Latest version: ${TAG}"

# Check if already installed and same version
if command -v "$BINARY" &>/dev/null; then
    CURRENT=$($BINARY version 2>/dev/null | awk '{print $2}')
    if [ "$CURRENT" = "$TAG" ] || [ "$CURRENT" = "${TAG#v}" ]; then
        ok "Already up to date (${TAG})"
        exit 0
    fi
    warn "Current version: ${CURRENT} → upgrading to ${TAG}"
fi

# Build asset name
ASSET_NAME="recon0-${OS}-${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET_NAME}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${TAG}/checksums.txt"

# Download
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading ${ASSET_NAME}..."
curl -sSL -o "${TMPDIR}/${ASSET_NAME}" "$DOWNLOAD_URL" || fail "Download failed: ${DOWNLOAD_URL}"

# Verify checksum
info "Verifying checksum..."
curl -sSL -o "${TMPDIR}/checksums.txt" "$CHECKSUM_URL" 2>/dev/null
if [ -f "${TMPDIR}/checksums.txt" ]; then
    EXPECTED=$(grep "$ASSET_NAME" "${TMPDIR}/checksums.txt" | awk '{print $1}')
    if [ -n "$EXPECTED" ]; then
        if command -v sha256sum &>/dev/null; then
            ACTUAL=$(sha256sum "${TMPDIR}/${ASSET_NAME}" | awk '{print $1}')
        elif command -v shasum &>/dev/null; then
            ACTUAL=$(shasum -a 256 "${TMPDIR}/${ASSET_NAME}" | awk '{print $1}')
        else
            warn "No sha256sum/shasum found, skipping checksum verification"
            ACTUAL="$EXPECTED"
        fi

        if [ "$ACTUAL" != "$EXPECTED" ]; then
            fail "Checksum mismatch!\n  expected: ${EXPECTED}\n  got:      ${ACTUAL}"
        fi
        ok "Checksum OK"
    else
        warn "Asset not found in checksums.txt, skipping verification"
    fi
else
    warn "Could not download checksums.txt, skipping verification"
fi

# Extract
info "Extracting..."
tar xzf "${TMPDIR}/${ASSET_NAME}" -C "${TMPDIR}"

# Find the binary in extracted files
EXTRACTED=$(find "${TMPDIR}" -name "$BINARY" -type f | head -1)
[ -z "$EXTRACTED" ] && fail "Binary not found in archive"
chmod +x "$EXTRACTED"

# Install
if [ -w "$INSTALL_DIR" ]; then
    mv "$EXTRACTED" "${INSTALL_DIR}/${BINARY}"
else
    info "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "$EXTRACTED" "${INSTALL_DIR}/${BINARY}"
fi

# Verify
INSTALLED_VERSION=$("${INSTALL_DIR}/${BINARY}" version 2>/dev/null | awk '{print $2}')

echo ""
ok "recon0 ${INSTALLED_VERSION} installed to ${INSTALL_DIR}/${BINARY}"
echo ""
echo -e "  Run ${CYAN}recon0 run <domain>${NC} to start scanning"
echo -e "  Run ${CYAN}recon0 providers${NC} to check tool availability"
echo ""
