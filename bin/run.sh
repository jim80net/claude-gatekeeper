#!/usr/bin/env bash
set -euo pipefail

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# 1. Pre-built binary (from make build or install.sh download).
BINARY="$PLUGIN_ROOT/bin/claude-gatekeeper"
if [ -x "$BINARY" ]; then
  exec "$BINARY" "$@"
fi

# 2. Auto-download from GitHub Releases.
if [ -x "$PLUGIN_ROOT/bin/install.sh" ]; then
  echo "Downloading claude-gatekeeper binary..." >&2
  if "$PLUGIN_ROOT/bin/install.sh" 2>&1 >&2; then
    if [ -x "$BINARY" ]; then
      exec "$BINARY" "$@"
    fi
  fi
  echo "Download failed, trying go build..." >&2
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
