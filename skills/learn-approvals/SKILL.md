---
description: Use when the user wants to promote manually-approved Bash commands into permanent gatekeeper allow rules, or when reviewing session history to reduce permission prompts
---

# Learn Approvals

Mine session history for Bash commands that were manually approved and promote them into `gatekeeper.toml` allow rules.

## When to Use

- User says "I keep approving X" or "stop asking about X"
- User asks to review approvals or reduce permission prompts
- After a work session with many manual approvals

## Workflow

### 1. Inventory current rules

Read `~/.claude/gatekeeper.toml` and build a list of every command pattern already covered by allow rules.

### 2. Scan session history

Find recent session JSONL files (newest 5-6 by mtime). Search for Bash tool calls and extract the leading command from each. Common locations:

- Claude Code: `~/.claude/projects/*/sessions/`
- OpenClaw: `~/.openclaw/agents/*/sessions/*.jsonl`

### 3. Diff against existing rules

For each command found, test whether it matches an existing allow rule. Commands that don't match are candidates — the user had to manually approve them.

Deduplicate by command name, not by full invocation. Report `ssh` once, not 115 individual `ssh spark ...` calls.

### 4. Also check `settings.local.json`

`~/.claude/settings.local.json` accumulates per-session approvals in `permissions.allow`. Entries like `Bash(ssh:*)` indicate commands the user has approved before but that aren't in the gatekeeper yet.

### 5. Present candidates for confirmation

Show the user a table of candidate commands before writing rules:

| Command | Source | Occurrences |
|---------|--------|-------------|
| `ssh` | sessions + settings.local.json | 115 |
| `scp` | sessions | 6 |

### 6. Write gatekeeper rules

Add new `[[rules]]` blocks to `~/.claude/gatekeeper.toml`. Follow the existing style:

```toml
# =============================================================================
# ALLOW — Description of group
# =============================================================================

[[rules]]
tool   = 'Bash'
input  = '(?:^|[|;&]\s*)(?:cmd1|cmd2)(?:\s|$)'
decision = "allow"
reason = "Short description"
```

Group related commands into a single rule where sensible (e.g., `ssh|scp` together).

### 7. Clean up settings.local.json

Remove entries from `settings.local.json` `permissions.allow` that are now redundant with gatekeeper rules. Keep entries that:

- Reference absolute paths to specific binaries
- Use tool types other than Bash that aren't in the gatekeeper
- Contain env-var prefixed commands not covered by gatekeeper patterns

**Watch for secrets.** If an entry embeds API keys or credentials inline (e.g., `Bash(API_KEY=sk-... some-tool:*)`), remove it and advise the user to set the variable in their shell environment instead.

## Rule Syntax Reference

| Field | Purpose |
|-------|---------|
| `tool` | Tool name regex: `'Bash'`, `'Read'`, `'Read\|Write'` |
| `input` | PCRE2 regex matched against tool input |
| `decision` | `"allow"` or `"deny"` (deny always wins) |
| `reason` | Human-readable explanation |
| `precondition` | Optional shell command for context-dependent rules |
| `precondition_match` | Regex matched against precondition stdout |

Use TOML single-quoted strings (`'...'`) to avoid double-escaping regex.

## Common Mistakes

- **Overly broad rules.** `'.*'` as a Bash allow defeats the gatekeeper. Match specific commands.
- **Forgetting anchors.** Use `(?:\s|$)` after command names so `kill` doesn't match `pkill`.
- **Not grouping.** Five separate rules for `ssh`, `scp`, `sftp`, `rsync`, `sshfs` should be one rule.
- **Leaving secrets in settings.local.json.** Always flag embedded credentials for removal.
