# Contributing to claude-gatekeeper

## Development setup

```bash
git clone https://github.com/jim80net/claude-gatekeeper.git
cd claude-gatekeeper
make test
```

Requires Go 1.22+.

## Project structure

```
cmd/claude-gatekeeper/   CLI entry point
internal/config/         TOML config loading and layering
internal/engine/         Rule evaluation engine
internal/protocol/       Claude Code hook JSON wire format
internal/migrate/        settings.json to TOML migration
hooks/                   Claude Code plugin hook definition
```

## Adding a new default rule

1. Add the rule to `internal/config/defaults.toml`
2. Add a test case to `TestDefaultRules` in `internal/engine/engine_test.go`
3. Run `make test`

## Testing

```bash
make test      # Unit tests with race detector
make lint      # Static analysis (requires golangci-lint)
```

### Manual end-to-end test

```bash
make build
echo '{"tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"/tmp"}' | ./bin/claude-gatekeeper --debug
```

## Release process

Tags trigger goreleaser via GitHub Actions (when configured). To test locally:

```bash
goreleaser release --snapshot --clean
```
