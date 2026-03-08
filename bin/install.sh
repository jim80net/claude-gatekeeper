#!/bin/sh
# Downloads the prebuilt claude-gatekeeper binary for the current platform.
# Usage: ./bin/install.sh [version]
#   version defaults to "latest"
set -e

REPO="jim80net/claude-gatekeeper"
VERSION="${1:-latest}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"

detect_platform() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "$OS" in
    Linux*)  PLATFORM_OS="linux" ;;
    Darwin*) PLATFORM_OS="darwin" ;;
    MINGW*|MSYS*|CYGWIN*) PLATFORM_OS="windows" ;;
    *)
      echo "Unsupported OS: $OS" >&2
      exit 1
      ;;
  esac

  case "$ARCH" in
    x86_64|amd64) PLATFORM_ARCH="amd64" ;;
    aarch64|arm64) PLATFORM_ARCH="arm64" ;;
    *)
      echo "Unsupported architecture: $ARCH" >&2
      exit 1
      ;;
  esac
}

detect_platform

if [ "$PLATFORM_OS" = "windows" ]; then
  ASSET="claude-gatekeeper_${PLATFORM_OS}_${PLATFORM_ARCH}.zip"
else
  ASSET="claude-gatekeeper_${PLATFORM_OS}_${PLATFORM_ARCH}.tar.gz"
fi

if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"
else
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
fi

echo "Downloading ${ASSET}..." >&2
TMPFILE="$(mktemp)"
trap 'rm -f "$TMPFILE"' EXIT

if command -v curl >/dev/null 2>&1; then
  curl -fSL -o "$TMPFILE" "$URL"
elif command -v wget >/dev/null 2>&1; then
  wget -q -O "$TMPFILE" "$URL"
else
  echo "Neither curl nor wget found. Install one and retry." >&2
  exit 1
fi

echo "Extracting to ${DIR}..." >&2
case "$ASSET" in
  *.tar.gz) tar -xzf "$TMPFILE" -C "$DIR" ;;
  *.zip)    unzip -o "$TMPFILE" -d "$DIR" ;;
esac

chmod +x "$DIR/bin/claude-gatekeeper" 2>/dev/null || true

echo "Installed claude-gatekeeper (${PLATFORM_OS}/${PLATFORM_ARCH}) to ${DIR}" >&2
