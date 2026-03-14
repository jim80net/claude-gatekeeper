# Contributing to claude-gatekeeper

## Development setup

```bash
git clone https://github.com/jim80net/claude-gatekeeper.git
cd claude-gatekeeper
make test
```

Requires Go 1.22+. By submitting a pull request, you agree that your contributions are licensed under the [MIT License](LICENSE).

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

1. Add the rule to `gatekeeper.toml` (repo root)
2. Add a test case to `TestDefaultRules` in `internal/engine/engine_test.go`
3. Run `make test`

## Pre-commit hooks

Install [pre-commit](https://pre-commit.com/) then enable hooks:

```bash
pre-commit install
```

This runs format, vet, lint, build, and test checks before each commit.

## Testing

```bash
make test      # Unit tests with race detector
make lint      # Static analysis (requires golangci-lint)
make fmt       # Check gofmt formatting
make vet       # Run go vet
make check     # Run all checks (fmt + vet + lint + test)
```

CI runs the same checks on every PR via `.github/workflows/ci.yml`.

### Manual end-to-end test

```bash
make build
echo '{"tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"/tmp"}' | ./bin/claude-gatekeeper --debug
```

## Commit conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/) with [release-please](https://github.com/googleapis/release-please) for automated versioning.

| Prefix | Version bump | Example |
|--------|-------------|---------|
| `fix:` | Patch (1.0.x) | `fix: handle empty tool input` |
| `feat:` | Minor (1.x.0) | `feat: add precondition timeout config` |
| `feat!:` or `BREAKING CHANGE:` | Major (x.0.0) | `feat!: rename config file` |
| `chore:`, `docs:`, `ci:`, `test:` | No release | `docs: update README` |

## Release process

Releases are automated via GitHub Actions:

1. Push conventional commits to `main`
2. release-please creates/updates a **Release PR** with changelog and version bump
3. Merge the Release PR → release-please tags and creates a GitHub Release
4. goreleaser builds platform archives and attaches them to the release
5. build.yml rebuilds `dist/` binaries in the repo for marketplace installs

To test goreleaser locally:

```bash
goreleaser release --snapshot --clean
```
