#!/usr/bin/env bash
set -euo pipefail

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="$PLUGIN_ROOT/bin/claude-gatekeeper"

if [ ! -x "$BINARY" ]; then
  echo "Building claude-gatekeeper..." >&2
  (cd "$PLUGIN_ROOT" && go build -ldflags "-s -w" -o bin/claude-gatekeeper ./cmd/claude-gatekeeper) >&2
fi

exec "$BINARY" "$@"
