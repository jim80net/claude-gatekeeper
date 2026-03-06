# claude-gatekeeper

A fast PreToolUse permission hook for [Claude Code](https://claude.com/claude-code) that replaces glob-based `permissions` arrays in `settings.json` with PCRE2-compatible regex rules.

## Why

Claude Code's built-in permission globs (`Bash(git add:*)`) can't match env-prefixed commands like `FOO=bar git commit`, pipe chains, or complex argument patterns. Regex can.

**claude-gatekeeper** evaluates every tool call against a layered set of regex rules and returns `allow`, `deny`, or abstains (passes to the user). **Deny always wins.** When a tool call is denied, Claude sees the reason and can adjust its approach.

## Install

### As a Claude Code plugin

```bash
git clone https://github.com/jim80net/claude-gatekeeper.git
cd claude-gatekeeper
make build
claude --plugin-dir .
```

On first tool call, the gatekeeper automatically copies `gatekeeper.toml` to `~/.claude/gatekeeper.toml` if it doesn't exist yet.

### From a GitHub release

Download a pre-built archive from [Releases](https://github.com/jim80net/claude-gatekeeper/releases), extract it, and point Claude Code at the extracted directory:

```bash
claude --plugin-dir /path/to/claude-gatekeeper
```

## How it works

1. Claude Code invokes the gatekeeper before each tool call, sending JSON on stdin.
2. On first run, the shipped `gatekeeper.toml` is auto-copied to `~/.claude/gatekeeper.toml` if it doesn't exist.
3. Rules are loaded from:
   - **Global config** — `~/.claude/gatekeeper.toml` (auto-installed on first run)
   - **Project config** — `.claude/gatekeeper.toml`
3. Each rule has a `tool` regex (matched against the tool name) and an `input` regex (matched against the command/file path/URL).
4. **Deny always wins**: if any deny rule matches, the call is blocked and Claude is told why.
5. If any allow rule matches (and no deny), the call is auto-approved.
6. If nothing matches (or no config exists), the gatekeeper abstains and Claude Code prompts you.

## Default rules

The shipped `gatekeeper.toml` (auto-installed to `~/.claude/gatekeeper.toml` on first run) **denies**:

| Category | Examples |
|----------|----------|
| Destructive git | `git reset --hard`, `git clean -f`, `git push --force`, `git commit --amend`, `git branch -D` |
| Push to main/master | Explicit (`git push origin main`) and implicit (on main branch, run `git push`) |
| Recursive delete | `rm -r`, `rm -rf` |
| sed/awk | Forces the Edit tool instead |
| Destructive SQL | `DROP`, `TRUNCATE`, `DELETE FROM` |
| npm | Use pnpm instead (commented out by default — uncomment to enable) |
| Credential files | `.env`, `.envrc`, `*key.json`, `id_rsa`, `.pem`, `credentials` |

And **allows**:

| Category | Examples |
|----------|----------|
| Version control | `git`, `gh` |
| Containers | `docker`, `docker-compose` |
| Python | `python`, `uv`, `pip`, `pytest` |
| Go | `go build`, `go test`, `golangci-lint` |
| JavaScript/TypeScript | `node`, `npx`, `pnpm`, `eslint`, `vitest` |
| Build systems | `make`, `cargo`, `gradle`, `mvn` |
| Infrastructure | `terraform`, `kubectl`, `helm`, `aws`, `gcloud` |
| Shell utilities | `ls`, `find`, `mkdir`, `curl`, `diff`, `wc`, `jq`, `openssl`, `timeout` |
| Non-Bash tools | `Read`, `Edit`, `Write`, `Glob`, `Grep`, `Agent`, `WebFetch` |

## Configuration

### Rule format

```toml
[[rules]]
tool     = 'Bash'                        # PCRE2 regex matching tool_name
input    = 'git\s+reset\s+--hard'        # PCRE2 regex matching the primary input
decision = "deny"                        # "allow" or "deny"
reason   = "Destructive: git reset"      # Shown to Claude on deny
```

### Preconditions (shell checks)

For rules that need runtime context (e.g., checking the current git branch):

```toml
[[rules]]
tool              = 'Bash'
input             = '\bgit\s+push\b(?!.*\b(main|master)\b)'
precondition      = 'git branch --show-current'
precondition_match = '^(main|master)$'
decision          = "deny"
reason            = "Implicit push to main/master"
```

The `precondition` command runs only when `tool` and `input` both match. It has a 5-second timeout.

### Env-prefix aware variants

Commands like `FOO=bar git commit` bypass anchored patterns. The defaults include commented-out variants:

```toml
# Default (anchored):
input = '(?:^|[|;&]\s*)git\s'

# Env-prefix aware (uncomment to enable):
# input = '(?:^|(\w+=\S+\s+)*)git\s'
```

### Config layering

| File | Scope |
|------|-------|
| `~/.claude/gatekeeper.toml` | All projects (global — auto-installed on first run) |
| `.claude/gatekeeper.toml` | Per-project (appended to global) |

Deny always wins across all layers. If no config files exist, the gatekeeper abstains on everything.

### Security: config trust boundaries

- **Global config** (`~/.claude/gatekeeper.toml`) — trusted, controlled by you.
- **Project config** (`.claude/gatekeeper.toml`) — comes from the repository. A malicious repo could add allow rules or precondition commands that execute shell commands. Review project configs before trusting them. Precondition commands run with a 5-second timeout.

## Migrating from settings.json

If you have existing `permissions.allow` / `permissions.deny` globs in your settings:

```bash
claude-gatekeeper migrate
```

This reads `~/.claude/settings.json` and `settings.local.json`, converts permission globs to regex rules, and writes `~/.claude/gatekeeper.toml`. A backup is created if the output file already exists.

Options:
```bash
claude-gatekeeper migrate --settings /path/to/settings.json --output /path/to/output.toml
```

Review the generated TOML — some globs may need manual refinement.

## Debugging

Run with `--debug` to see rule evaluation on stderr:

```bash
# Test manually:
echo '{"tool_name":"Bash","tool_input":{"command":"git push --force"},"cwd":"/tmp"}' | claude-gatekeeper --debug

# Enable in the plugin by editing hooks/hooks.json:
"command": "${CLAUDE_PLUGIN_ROOT}/bin/claude-gatekeeper --debug"
```

Debug output goes to stderr (visible in Claude Code verbose mode via `Ctrl+R`).

## Development

```bash
make build        # Build to ./bin/claude-gatekeeper
make test         # Run all tests with race detector
make lint         # Run golangci-lint
make plugin-test  # Show command to test as a plugin
make clean        # Remove build artifacts
```

## License

MIT
