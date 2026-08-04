# Compatibility after rename (`claude-gatekeeper` → `gatekeeper-claude`)

**Date:** 2026-07-10  
**Operator authorized** rename into the Gatekeeper product family naming system.  
**Fleet program:** multi-repo public product (core + adapters), not monorepo-only.

## What changed

| Surface | Before | After (now) | Notes |
|---------|--------|-------------|--------|
| GitHub repo | `jim80net/claude-gatekeeper` | **`jim80net/gatekeeper-claude`** | Old URL **HTTP 301** → new name (GitHub rename) |
| Releases URL | `…/claude-gatekeeper/releases` | `…/gatekeeper-claude/releases` | Assets move with the repo; old path redirects |
| Release asset names | `claude-gatekeeper_${os}_${arch}.tar.gz` | **unchanged** | installers + hooks depend on these names |
| Binary on disk | `claude-gatekeeper` | **unchanged** | Fleet: `~/go/bin/claude-gatekeeper`, plugin `bin/run.sh` |
| Go module path | `github.com/jim80net/claude-gatekeeper` | **unchanged (for now)** | Renamed only when extract ships `gatekeeper-core` |
| Claude plugin **id** | `claude-gatekeeper@jim80net-plugins` | **unchanged** | Keeps `/plugin install` and caches working |
| Plugin marketplace source URL | `…/claude-gatekeeper.git` | should be `…/gatekeeper-claude.git` | Update marketplace entry (redirect works interim) |
| Product brand | agent-gatekeeper | **unchanged** | Public docs may say Gatekeeper family |
| Config path | `~/.claude/gatekeeper.toml` | **unchanged** | Policy language is harness-neutral |

## What must keep working (dogfood)

1. **Hooks** invoke `$HOME/go/bin/claude-gatekeeper --harness {grok,codex}` (or plugin `bin/run.sh` for Claude).
2. **`make download` / `bin/install.sh`** fetch from GitHub Releases under the **new** repo name (this tree) with **legacy asset** filenames.
3. **Existing clones** with `origin = …/claude-gatekeeper.git` continue via redirect; prefer `git remote set-url origin https://github.com/jim80net/gatekeeper-claude.git`.
4. **Authority domain** (flotilla#551): seats owning this product should list `jim80net/gatekeeper-claude` in `.gatekeeper/domain` (not the old name).

## Product family (target)

```
gatekeeper-core      shared engine + policy schema
gatekeeper-claude    this monorepo (Claude adapter + current all-in-one binary)
gatekeeper-grok      thin Grok packaging (extract)
gatekeeper-codex     thin Codex packaging (extract)
```

Private coordination: `jim80net/gatekeeper-flotilla`.  
Extract plan: `gatekeeper-flotilla` → `docs/EXTRACT-PLAN.md` (flotilla XO).

## Deliberately deferred

- Renaming the **binary** to `gatekeeper` / `gatekeeper-claude` (breaks every live hook path).
- Renaming the **Go module** (wide import churn; do with core extract).
- Renaming the Claude **plugin id** (breaks installed plugin keys).
- OpenCode adapter.

## Verify after this PR

```bash
# release download (new name)
curl -fsSIL "https://github.com/jim80net/gatekeeper-claude/releases/latest/download/claude-gatekeeper_linux_amd64.tar.gz" | head -5

# redirect still works
curl -fsSIL "https://github.com/jim80net/claude-gatekeeper/releases/latest/download/claude-gatekeeper_linux_amd64.tar.gz" | head -5

# fleet binary still gates
echo '{"tool_name":"Bash","tool_input":{"command":"gh pr merge 1 --repo jim80net/flotilla"},"cwd":"/path/to/your-repo"}' \
  | claude-gatekeeper --harness claude
```
