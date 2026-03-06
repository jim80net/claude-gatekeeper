# claude-gatekeeper

A fast PreToolUse permission hook for [Claude Code](https://claude.com/claude-code) that replaces glob-based `permissions` arrays in `settings.json` with PCRE2-compatible regex rules.

## Why

Claude Code's built-in permission globs (`Bash(git add:*)`) can't match env-prefixed commands like `FOO=bar git commit`, pipe chains, or complex argument patterns. Regex can.

**claude-gatekeeper** evaluates every tool call against a layered set of regex rules and returns `allow`, `deny`, or abstains (passes to the user). **Deny always wins.**

## Install

### From source

```bash
go install github.com/jim80net/claude-gatekeeper/cmd/claude-gatekeeper@latest
```

### Build locally

```bash
git clone https://github.com/jim80net/claude-gatekeeper.git
cd claude-gatekeeper
make install
```

### GitHub Releases

Download a pre-built binary from [Releases](https://github.com/jim80net/claude-gatekeeper/releases), place it on your `$PATH`, then run:

```bash
claude-gatekeeper setup
```

## Configure Claude Code

`make install` (and `claude-gatekeeper setup`) automatically registers the PreToolUse hook in `~/.claude/settings.json`. A backup is created before any changes.

To configure manually instead, add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "claude-gatekeeper",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

Then remove any `permissions.allow` / `permissions.deny` arrays — gatekeeper handles those now.

## How it works

1. Claude Code invokes `claude-gatekeeper` before each tool call, sending JSON on stdin.
2. The gatekeeper loads rules from:
   - **Embedded defaults** — safe out-of-the-box rules (see below)
   - **Global config** — `~/.claude/.gatekeeper.toml`
   - **Project config** — `.claude/gatekeeper.toml`
3. Each rule has a `tool` regex (matched against the tool name) and an `input` regex (matched against the command/file path/URL).
4. **Deny always wins**: if any deny rule matches, the call is blocked.
5. If any allow rule matches (and no deny), the call is auto-approved.
6. If nothing matches, the gatekeeper abstains and Claude Code prompts the user.

## Default rules

Out of the box, gatekeeper **denies**:

| Category | Examples |
|----------|----------|
| Destructive git | `git reset --hard`, `git clean -f`, `git push --force`, `git commit --amend`, `git branch -D` |
| Push to main/master | Explicit (`git push origin main`) and implicit (on main branch, run `git push`) |
| Recursive delete | `rm -r`, `rm -rf` |
| sed/awk | Forces the Edit tool instead |
| Destructive SQL | `DROP`, `TRUNCATE`, `DELETE FROM` |
| npm | Use pnpm instead |
| Credential files | `.env`, `.envrc`, `*key.json`, `id_rsa`, `.pem`, `credentials` |

And **allows**:

git, gh, docker, python toolchain (uv/pip/pytest), safe shell utilities (ls/find/mkdir/curl/diff/wc/...), Go toolchain, pnpm, build systems (make/cargo/gradle/...), openssl, JS/TS tools (node/npx/eslint/vitest/...), infrastructure tools (terraform/kubectl/helm/aws/...), all non-Bash tools (Read/Edit/Write/Glob/Grep/Agent/WebFetch).

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

### Disabling defaults

```toml
# In ~/.claude/.gatekeeper.toml or .claude/gatekeeper.toml
include_defaults = false

[[rules]]
# Your custom rules only
```

### Config layering

| File | Scope |
|------|-------|
| Embedded `defaults.toml` | Always loaded (unless `include_defaults = false`) |
| `~/.claude/.gatekeeper.toml` | All projects (global) |
| `.claude/gatekeeper.toml` | Per-project (appended to global) |

Deny always wins across all layers.

### Security: config trust boundaries

- **Global config** (`~/.claude/.gatekeeper.toml`) — trusted, controlled by the user.
- **Project config** (`.claude/gatekeeper.toml`) — comes from the repository. A malicious repo could add allow rules or precondition commands that execute shell commands. Review project configs before trusting them. Precondition commands run with a 5-second timeout.

## Migrating from settings.json

```bash
claude-gatekeeper migrate
```

This reads your `~/.claude/settings.json` and `settings.local.json`, converts permission globs to regex rules, and writes `~/.claude/.gatekeeper.toml`.

Options:
```bash
claude-gatekeeper migrate --settings /path/to/settings.json --output /path/to/output.toml
```

The migration creates a backup if the output file already exists. Review the generated TOML and refine with:

```bash
claude -p "Convert these Claude Code permission globs to PCRE2 regex: Bash(git add:*) Bash(curl:*)"
```

## Debugging

Run with `--debug` to see rule evaluation on stderr:

```bash
# Test manually:
echo '{"tool_name":"Bash","tool_input":{"command":"git push --force"},"cwd":"/tmp"}' | claude-gatekeeper --debug

# In settings.json, change the command to:
"command": "claude-gatekeeper --debug"
```

Debug output goes to stderr (visible in Claude Code verbose mode via `Ctrl+R`).

## Development

```bash
make build     # Build to ./bin/claude-gatekeeper
make test      # Run all tests with race detector
make lint      # Run golangci-lint
make clean     # Remove build artifacts
```

## License

MIT
