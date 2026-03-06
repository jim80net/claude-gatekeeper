---
description: Show gatekeeper rules summary and configuration help
disable-model-invocation: true
---

# claude-gatekeeper

PCRE2 regex-based permission gatekeeper for Claude Code tool calls. Deny always wins.

## Default deny rules

| Category | Pattern | Reason |
|----------|---------|--------|
| Destructive git | `git reset --hard`, `git clean -f`, `git push --force`, `git commit --amend`, `git branch -D` | Prevents irreversible git operations |
| Push to main/master | `git push origin main` or implicit push while on main/master | Protects default branches |
| Recursive delete | `rm -r`, `rm -rf` | Prevents accidental data loss |
| sed/awk | `sed`, `awk` | Forces the Edit tool for traceability |
| Destructive SQL | `DROP`, `TRUNCATE`, `DELETE FROM` | Prevents data loss |
| Credential files | `.env`, `.envrc`, `*key.json`, `id_rsa`, `.pem`, `credentials` | Blocks secret file access |

## Default allow rules

Git, GitHub CLI, Docker, Python toolchain, Go toolchain, pnpm, build systems, JavaScript/TypeScript tools, shell utilities, infrastructure tools, OpenSSL, timeout wrapper, Read, Edit, Write, Glob, Grep, Agent, WebFetch, WebSearch.

## Configuration

Edit `~/.claude/gatekeeper.toml` for global rules. Add `.claude/gatekeeper.toml` in any project for per-project overrides. Deny always wins across all layers.

Uncomment the npm deny rule in `~/.claude/gatekeeper.toml` if you want to enforce pnpm.

## Debugging

Add `--debug` to the hook command in `hooks/hooks.json` to see rule evaluation on stderr (visible via `Ctrl+R` in Claude Code).
