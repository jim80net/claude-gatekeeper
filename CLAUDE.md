# claude-gatekeeper

PreToolUse permission hook for Claude Code. Written in Go for fast startup.

## Architecture

- `cmd/claude-gatekeeper/main.go` — CLI entry point, dispatches to hook mode or migrate subcommand
- `internal/protocol/` — Reads hook JSON from stdin, writes decision JSON to stdout
- `internal/config/` — Loads TOML rules from `~/.claude/gatekeeper.toml` + `.claude/gatekeeper.toml`
- `internal/engine/` — Compiles PCRE2 regexes (via regexp2), evaluates rules, deny-always-wins
- `internal/migrate/` — Converts `settings.json` glob permissions to TOML regex rules
- `internal/setup/` — Registers/unregisters the hook in `~/.claude/settings.json` (with backup)
- `hooks/hooks.json` — Claude Code plugin hook definition (uses `${CLAUDE_PLUGIN_ROOT}`)
- `.claude-plugin/plugin.json` — Plugin manifest (hooks auto-loaded from `hooks/hooks.json`)

## Plugin structure

This project is a Claude Code plugin. Key files:
- `.claude-plugin/plugin.json` — manifest (no `hooks` field; `hooks/hooks.json` is auto-loaded)
- `hooks/hooks.json` — hook command using `${CLAUDE_PLUGIN_ROOT}/bin/run.sh`
- `bin/run.sh` — wrapper script that selects the right platform binary (Linux/macOS/WSL)
- `bin/run.ps1` — PowerShell wrapper for native Windows
- `dist/` — pre-built binaries for linux/darwin/windows amd64/arm64 (committed by CI)
- `bin/claude-gatekeeper` — local dev binary (from `make build`)

Test as a plugin: `claude --plugin-dir .`

## Key design decisions

- **PCRE2 regex** via `github.com/dlclark/regexp2` (pure Go, no cgo)
- **TOML config** with single-quoted strings for zero-escape regex
- **No baked-in rules** — all rules come from config files; `gatekeeper.toml` auto-copied to `~/.claude/` on first run
- **Deny always wins** across all config layers
- **Abstain on any error** or no config (exit 0, empty stdout)
- **stdout is the protocol** — all debug/error output goes to stderr
- **Preconditions** allow shell checks (e.g., `git branch --show-current`) for context-dependent rules

## Build and test

```bash
make build        # → bin/claude-gatekeeper
make test         # Race-enabled tests
make plugin-test  # Show command to test as a plugin
make install      # Build + install to ~/.claude/hooks/ (standalone mode)
```

## Config files

- `gatekeeper.toml` — Shipped default rules (auto-copied to `~/.claude/gatekeeper.toml` on first run)
- `~/.claude/gatekeeper.toml` — User global config (deny destructive ops, allow safe tools)
- `.claude/gatekeeper.toml` — Per-project overrides
