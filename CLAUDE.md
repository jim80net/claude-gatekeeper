# claude-gatekeeper

PreToolUse permission hook for Claude Code. Written in Go for fast startup.

## Architecture

- `cmd/claude-gatekeeper/main.go` — CLI entry point, dispatches to hook mode or migrate subcommand
- `internal/protocol/` — Reads hook JSON from stdin, writes decision JSON to stdout
- `internal/config/` — Loads TOML rules from embedded defaults + `~/.claude/.gatekeeper.toml` + `.claude/gatekeeper.toml`
- `internal/engine/` — Compiles PCRE2 regexes (via regexp2), evaluates rules, deny-always-wins
- `internal/migrate/` — Converts `settings.json` glob permissions to TOML regex rules
- `internal/setup/` — Registers/unregisters the hook in `~/.claude/settings.json` (with backup)
- `hooks/hooks.json` — Claude Code plugin hook definition

## Key design decisions

- **PCRE2 regex** via `github.com/dlclark/regexp2` (pure Go, no cgo)
- **TOML config** with single-quoted strings for zero-escape regex
- **Deny always wins** across all config layers
- **Abstain on any error** (exit 0, empty stdout)
- **stdout is the protocol** — all debug/error output goes to stderr
- **Preconditions** allow shell checks (e.g., `git branch --show-current`) for context-dependent rules

## Build and test

```bash
make build   # → bin/claude-gatekeeper
make test    # Race-enabled tests
make install # Build + install to ~/.claude/hooks/
```

## Config files

- `internal/config/defaults.toml` — Embedded default rules (deny destructive ops, allow safe tools)
- `~/.claude/.gatekeeper.toml` — User global overrides
- `.claude/gatekeeper.toml` — Per-project overrides
