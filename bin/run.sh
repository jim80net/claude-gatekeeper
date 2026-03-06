#!/usr/bin/env bash
set -euo pipefail

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)        ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac

# 1. Pre-built platform binary (from CI or goreleaser).
BINARY="$PLUGIN_ROOT/dist/claude-gatekeeper-${OS}-${ARCH}"
if [ -x "$BINARY" ]; then
  exec "$BINARY" "$@"
fi

# 2. Local build (from make build).
BINARY="$PLUGIN_ROOT/bin/claude-gatekeeper"
if [ -x "$BINARY" ]; then
  exec "$BINARY" "$@"
fi

# 3. Fallback: build from source (requires Go).
if command -v go &>/dev/null; then
  echo "Building claude-gatekeeper..." >&2
  (cd "$PLUGIN_ROOT" && go build -ldflags "-s -w" -o bin/claude-gatekeeper ./cmd/claude-gatekeeper) >&2
  exec "$PLUGIN_ROOT/bin/claude-gatekeeper" "$@"
fi

echo "Error: no claude-gatekeeper binary found and Go is not installed." >&2
echo "Install Go 1.22+ or use a pre-built release." >&2
exit 0  # abstain rather than error
