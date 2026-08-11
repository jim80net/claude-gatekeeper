# agent-gatekeeper (`gatekeeper-claude`)

A fast PreToolUse permission hook for coding agents — [Claude Code](https://claude.com/claude-code), [OpenAI Codex CLI](https://github.com/openai/codex), and [xAI grok](https://x.ai) — that replaces glob-based permission arrays with PCRE2-compatible regex rules. One policy, enforced across every harness.

> **Naming (2026-07-10):** the public GitHub repo is
> [`jim80net/gatekeeper-claude`](https://github.com/jim80net/gatekeeper-claude)
> (renamed from `claude-gatekeeper`; old URLs **301** to the new name).
> The **binary**, Claude Code **plugin id**, and Go **module path** still use
> `claude-gatekeeper` so fleet dogfood and existing installs keep working.
> Full matrix: [COMPAT.md](./COMPAT.md). Product family (core + adapters):
> [gatekeeper-flotilla](https://github.com/jim80net/gatekeeper-flotilla) charter.

## Why

Agent permission globs (`Bash(git add:*)`) can't match env-prefixed commands like `FOO=bar git commit`, pipe chains, `HEAD:main` refspecs, or complex argument patterns. Regex can.

**agent-gatekeeper** evaluates every tool call against a layered set of regex rules and returns `allow`, `deny`, or **abstain** (no opinion — the harness's native permission system decides). **Deny always wins.** When a tool call is denied, the agent sees the reason and can adjust.

## Harnesses

One binary serves three harnesses, selected by `--harness` (or the `GATEKEEPER_HARNESS` env var; defaults to `claude`). Tool names are normalised to a canonical taxonomy inside each adapter, so the **same `gatekeeper.toml` rules apply verbatim** to all three.

| Harness | Wire | Status |
|---------|------|--------|
| `claude` | `hookSpecificOutput.permissionDecision` (exit 0) | **Stable.** Byte-for-byte compatible with prior releases. |
| `codex` | Claude-compatible `hookSpecificOutput` **envelope**, narrower value set | **Live-verified (2026-07-03, codex-cli 0.142.5); ALLOW-value fix 2026-07-08.** `permissionDecision:"deny"` blocks even under `approval_policy=never` (full auto); silent abstain falls through to the native policy; codex reads both `~/.codex/hooks.json` (global) and project `.codex/hooks.json`. |
| `grok` | grok-native `{"decision":"deny","reason":...}` (exit 2 deny / exit 0 allow); abstain = fail-open (exit 1) | **Live-verified (2026-07-03, grok 0.2.82).** A global `~/.grok/hooks/` PreToolUse hook deny (`{"decision":"deny"}` + exit 2) **blocks** the tool call even under `--permission-mode bypassPermissions` (full auto); an abstaining call (exit 1, no output) falls through and runs. |

**codex** is verified as a real gate: on a fully-autonomous codex agent (`approval_policy=never`), a hook `deny` — and therefore `on_error = "deny"` — actually blocks the command. The default `abstain` falls through to the native policy exactly as documented. **Only `deny` is ever emitted explicitly.** `permissionDecision:"allow"` and `permissionDecision:"ask"` are both **rejected by codex's own PreToolUse handler** ("PreToolUse hook returned unsupported permissionDecision:allow"/"...ask" — extracted verbatim from the codex-cli 0.143.0 binary, despite both being schema-legal members of the shared wire enum) — an ALLOW verdict is therefore encoded identically to abstain (nothing written), never as an explicit `"allow"`.

**grok is verified as a real gate too (2026-07-03 live probe, grok 0.2.82).** In an isolated sandbox under `--permission-mode bypassPermissions` (grok's full-auto), a global `~/.grok/hooks/` PreToolUse hook that emits the gatekeeper's grok-native `{"decision":"deny"}` + exit 2 **blocked** a canary command (the file was never created), while an abstaining call (exit 1) let a control command run. So the gatekeeper's grok adapter is a real in-harness hard control on auto-approve grok agents — grok evaluates PreToolUse hooks *before* the permission system, "regardless of permission mode." Re-confirmed under the exact deploy config `permission_mode = "always-approve"` (which grok resolves to the same `bypassPermissions` mode it reports in the hook payload): deny blocked, abstain ran.

Grok 0.2.101's shipped hook guide and locally captured shipped tool schemas also pin these native input shapes: `run_terminal_command.command`, `read_file.target_file`, `search_replace.file_path`, `write.file_path`, `list_dir.target_directory`, `grep.pattern`, and `web_fetch.url`. Golden hook fixtures live in `internal/adapter/grok/testdata`. `web_search` is a verified native tool name, but its primary input field remains **unverified** without a live hook capture; the adapter deliberately does not guess one, so input-targeted WebSearch rules are not supported yet.

> **Grok hook wire — verified schema (corrects earlier inference).** grok's PreToolUse hook stdin is **camelCase**: `toolName` (the shell tool is `"Shell"`), `toolInput` (`{command,description}`), `hookEventName` (value `"pre_tool_use"`), `cwd`/`workspaceRoot`, `permissionMode`. Register as a **global** `~/.grok/hooks/*.json` in the Claude-shaped `{ "hooks": { "PreToolUse": [ … ] } }` format. (Grok's separate *settings-layer* `--deny` list is a different mechanism and is **not** enforced under `--always-approve` — the hook is; don't rely on settings-deny for auto-approve agents.)

Register the hook per harness:

```bash
claude-gatekeeper setup --harness claude              # writes ~/.claude/settings.json (default)
claude-gatekeeper setup --harness grok                # writes ~/.grok/hooks/gatekeeper.json
claude-gatekeeper setup --harness codex               # writes ~/.codex/hooks.json (global; preferred)
claude-gatekeeper setup --harness codex --project-dir .  # writes ./.codex/hooks.json (project-scoped)
```

Codex silently skips user-installed hooks until their exact normalized identity
has persisted trust. To prevent an apparently successful but inert install,
Codex setup writes the hook and then verifies its matching `trusted_hash` in
`~/.codex/config.toml`. A trusted hook exits successfully. A new hook or a hook
whose command/config changed exits nonzero with remediation: run `/hooks` in
Codex, review and approve the installed hook, then rerun setup. Vetted non-interactive
automation may instead launch Codex with `--dangerously-bypass-hook-trust`.

### Fleet hook inventory

Use the read-only doctor command before changing an installed binary or hook:

```bash
claude-gatekeeper doctor
claude-gatekeeper doctor --json
claude-gatekeeper doctor --expected-binary ~/go/bin/claude-gatekeeper
claude-gatekeeper doctor --expected-version 1.3.1
claude-gatekeeper doctor --min-surfaces 3
claude-gatekeeper doctor --json --check-latest --min-surfaces 3
CLAUDE_CONFIG_DIR=/path/to/claude-config claude-gatekeeper doctor --json
claude-gatekeeper doctor --claude-config-dir /path/to/claude-config --json
claude-gatekeeper doctor --require-harness codex
```

By default Doctor requires Claude registration at the effective Claude root. The
root is selected in this order: `--claude-config-dir`, `CLAUDE_CONFIG_DIR`, then
`~/.claude`. Once selected, Doctor reads Claude settings and the plugin registry
only from that root; it never merges or falls back to the default root. Missing,
unreadable, or malformed selected-root inputs fail closed. Use
`--require-harness codex`, `--require-harness grok`, or `--require-harness any`
for a deliberately different diagnostic requirement.

It also inventories host-global references in `~/.grok/hooks/gatekeeper.json`
and `~/.codex/hooks.json`. Those observations are scope-labelled and cannot
satisfy a targeted Claude requirement. For each surface it reports the
configured or wrapper-resolved binary,
the result of `claude-gatekeeper --version`, the selected harness, and drift from
the running command's expected binary/version and the surface's required harness.
For the global Codex surface, it also recomputes the current trust hash and
reports missing or stale persisted trust as drift, because Codex otherwise skips
that installed hook silently.
Plugin `bin/run.sh` entries resolve to the plugin's adjacent
`bin/claude-gatekeeper`; the doctor never executes the download/build wrapper.

Doctor reports static registration separately from live firing. Static success
proves configuration/registration only; firing remains `not_tested` unless a
separate known-positive control is executed outside Doctor.

Exit status is 0 when all required surfaces match, 1 when drift or required
registration absence is found, and
2 when inventory or output fails. JSON output is intended for fleet automation
and contains the selected Claude root and source, requirement, Claude
registration/firing state, `expected_binary`, `expected_version`, `min_surfaces`,
`warnings`, scope-labelled `files`, and scope-labelled `surfaces`. With
`--check-latest`, it also
contains a `version_invariant` built from executable-reported surface versions
and the latest published release. `fail` and `unknown` both exit nonzero; the
published source or an executable probe can never fail into `OK`. See
[`docs/doctor-detector.md`](docs/doctor-detector.md) for the independent
user-timer template and its deployment boundary.
The `inventory` subcommand is an exact alias for `doctor`.

The automated inventory is intentionally user-global. Project-scoped
`.codex/hooks.json` files written by `setup --harness codex --project-dir ...`
and project `.claude/settings.json` files are not searched because there is no
bounded, authoritative list of fleet project roots. Until project-scoped
discovery ships, those files remain a manual checklist item (for example, search
known workspaces for both paths). Set `--min-surfaces` to the fleet's expected global count so missing or
unparseable discovery cannot produce a successful migration gate.

Grok requires the project folder to be `/hooks-trust`ed; Codex requires persisted hook trust (or `--dangerously-bypass-hook-trust` for vetted automation). Codex reads both the global `~/.codex/hooks.json` and a project `.codex/hooks.json`.

## Install

### From a marketplace

```shell
/plugin marketplace add jim80net/claude-plugins
/plugin install claude-gatekeeper@jim80net-plugins
```

Pre-built binaries for Linux, macOS, and Windows (amd64/arm64) are auto-downloaded from GitHub Releases on first run. Default rules are auto-copied to `~/.claude/gatekeeper.toml` on first run.

If the plugin wrapper cannot find, download, or build the gatekeeper binary, it
blocks the tool call by default (exit 2) and prints remediation. An explicit
`on_error = "abstain"` in the normal layered config preserves fail-open behavior.
For first-install environments that intentionally prefer availability before
enforcement, `GATEKEEPER_BOOTSTRAP_ABSTAIN=1` is an escape hatch; it emits a
warning that no gatekeeper policy is active.

**Windows (PowerShell)**: If you're on native Windows without Git Bash, edit `hooks/hooks.json` and change the command to:
```
powershell -NoProfile -ExecutionPolicy Bypass -File ${CLAUDE_PLUGIN_ROOT}/bin/run.ps1
```

### Local development

```bash
git clone https://github.com/jim80net/gatekeeper-claude.git
cd gatekeeper-claude
make build
claude --plugin-dir .
```

(`git clone …/claude-gatekeeper.git` still works via GitHub redirect.)

### From a GitHub release

Download a pre-built archive from [Releases](https://github.com/jim80net/gatekeeper-claude/releases), extract it, and point Claude Code at the extracted directory:

```bash
claude --plugin-dir /path/to/gatekeeper-claude
```

Release **asset** filenames remain `claude-gatekeeper_${os}_${arch}.tar.gz` (binary name lag).

## How it works

1. The harness invokes the gatekeeper before each tool call, sending JSON on stdin.
2. The `--harness` adapter parses that harness-native JSON into a canonical tool call (normalising the tool name, e.g. grok's `run_terminal_command` → `Bash`).
3. On first run, the shipped `gatekeeper.toml` is auto-copied to `~/.claude/gatekeeper.toml` if no global config exists.
4. Rules are loaded and layered (see [Config layering](#config-layering)).
5. Each rule has a `tool` regex (matched against the canonical tool name) and an `input` regex (matched against the command/file path/URL).
6. **Deny always wins**: if any deny rule matches, the call is blocked and the agent is told why.
7. If any allow rule matches (and no deny), the call is auto-approved.
8. If nothing matches, the gatekeeper **abstains** — it writes no verdict and the harness's native permission system decides. A missing or empty config also abstains unless the independent fail-closed posture below is active.
9. On any gatekeeper *error*, the [`on_error`](#error-behaviour-on_error) posture decides (default: abstain).

## Default rules

For copy-pasteable policies with the real failure stories and regression probes
behind them, see the [rule cookbook](docs/rule-cookbook.md).

The shipped `gatekeeper.toml` (auto-installed to `~/.claude/gatekeeper.toml` on first run) **denies**:

| Category | Examples |
|----------|----------|
| Destructive git | `git reset --hard`, `git clean -f`, `git push --force`, `git commit --amend`, `git branch -D` |
| Push to main/master | A boundary regex covering `origin main`, `-u origin main`, `HEAD:main`, `main:main`, `:main` (delete), `+main`, `refs/heads/main`, `git -C <path> push origin main`, and implicit (on main branch, bare `git push`) — while allowing branches merely named `main-feature`/`mainline` |
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

The `precondition` command runs only when `tool` and `input` both match. It has a 5-second timeout. The shell inherits the process environment plus **`GATEKEEPER_INPUT`**, set to the (heredoc-stripped) tool input under evaluation. That lets preconditions inspect the command itself — for example, parse `gh pr merge --repo OWNER/REPO` and compare it to the worktree's authority domain (`git remote get-url origin`, or an optional `.gatekeeper/domain` file). See `scripts/merge-domain-check.sh` for a fail-closed reference implementation used by multi-agent fleets (lead seat + domain-scoped merge).

### Env-prefix aware variants

Commands like `FOO=bar git commit` bypass anchored patterns. The defaults include commented-out variants:

```toml
# Default (anchored):
input = '(?:^|[|;&]\s*)git\s'

# Env-prefix aware (uncomment to enable):
# input = '(?:^|(\w+=\S+\s+)*)git\s'
```

### Config layering

Paths are harness-neutral, with a back-compatible `~/.claude` fallback. For each layer the first path that exists is used:

| Layer | Path (first that exists) | Scope |
|-------|--------------------------|-------|
| Global | `${XDG_CONFIG_HOME:-~/.config}/gatekeeper/gatekeeper.toml`, then `~/.claude/gatekeeper.toml` | All projects. `~/.claude` is also the first-run write target, so existing installs are undisturbed. |
| Project | `<cwd>/.gatekeeper/gatekeeper.toml`, then `<cwd>/.claude/gatekeeper.toml` | Per-project (rules appended to global; scalar knobs like `on_error` overridden). |

Deny always wins across all layers. If no config files exist, the gatekeeper abstains on everything.

### Error behaviour (`on_error`)

A top-level knob controls what the gatekeeper emits when it *itself* fails — unparseable stdin, a bad rule regex, an evaluate error, or a recovered panic. A readable global knob can also protect a malformed project overlay. A clean "no rule matched" is **not** an error and always abstains. Because this knob lives in the policy file, it cannot protect against its own file being missing or malformed; unreadable policy cannot communicate its own posture.

```toml
on_error = "abstain"   # default — emit NO verdict; the harness's native permission system decides.
# on_error = "deny"    # opt-in hard posture — on any error, emit an explicit deny.
```

For a fail-closed posture that survives missing or malformed global/project policy, set the independent environment override on the hook command:

```bash
GATEKEEPER_ON_ERROR=deny claude-gatekeeper --harness claude
```

The override is read before hook input or configuration. `deny` makes unparseable input, missing/malformed policy, engine errors, and zero loaded rules emit the harness-native deny. `abstain` explicitly selects advisory behavior. If the variable is absent, existing TOML/default behavior is unchanged. Any other non-empty value warns and fails closed; a typo cannot silently widen authority.

An empty XDG policy is selected ahead of the legacy `~/.claude/gatekeeper.toml` for compatibility, but now always emits a stderr warning, including the shadowed legacy path when present. Under `GATEKEEPER_ON_ERROR=deny`, its zero-rule result denies rather than silently abstaining.

The default is `abstain`: the gatekeeper never decides *for* the permission system on its error path (it forces neither allow nor deny). Each harness encodes abstain natively — Claude/Codex write nothing and exit 0 (their native flow runs); grok has no first-class defer, so its adapter routes abstain through grok's documented fail-open path (no verdict, non-deny exit) so no allow is ever asserted.

> On an auto-approve agent (grok `--always-approve`, codex `approval_policy=never`) the *native* decision is auto-run, so under the default `abstain` a gatekeeper error is a no-op there. If you need a hard floor that also covers policy loss/corruption, set `GATEKEEPER_ON_ERROR=deny` on the hook command and keep a server-side control (e.g. GitHub branch protection) — the hook alone cannot defend against not being invoked.

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

## Test policy changes before deploying them

`claude-gatekeeper test` runs declarative cases through the same canonical rule
engine as live hooks. By default it loads the normal global plus project config
layers for the current directory. Use `--config` to test one candidate policy
file in isolation; the command exits 0 when all cases pass, 1 for expectation
failures, and 2 for invalid input or evaluation errors, making it suitable for
CI.

```bash
claude-gatekeeper test examples/force-push-policy-tests.toml
claude-gatekeeper test --config ./gatekeeper.toml examples/force-push-policy-tests.toml
```

Cases may be TOML or JSON. `command` is a readable alias for `input` when the
tool is `Bash`; other tools use `input`. `expected_reason` is optional and, when
set, must exactly match the final rule reason.

```toml
[[cases]]
name = "force push is denied"
tool = "Bash"
command = "git push origin feature --force"
expected = "deny" # allow | deny | abstain
expected_reason = "Destructive: git force push"
```

The shipped [force-push matrix](examples/force-push-policy-tests.toml) captures
the wrapper, argument-position, newline, subshell, and false-positive probes
used to review the default policy.

### Inspect Authorization Domains contracts (shadow only)

`auth-domains shadow` compiles a synthetic D1 block/exception generation and
simulates one request against an explicit coverage manifest:

```text
claude-gatekeeper auth-domains shadow \
  --policy examples/auth-domains/policy.json \
  --request examples/auth-domains/request-protected.json \
  --coverage examples/auth-domains/coverage.json
```

This is I1a inspection, **not enforcement**. It is not called by the Claude,
Codex, or Grok hook path; it does not emit a harness permission decision; it
does not read, locate, mount, or provision credentials; and every report states
`enforcement: false`. Ordinary objects remain open by default. The only initial
protected action is `read` on one logical exact-object identifier.

The table and `--json` output enumerate contract-only final-PEP, audit, replay,
policy-store, and lifecycle gaps. Exit `0` means valid inputs produced a shadow
report (including a simulated denial), `1` means the contract or coverage is
non-conformant, and `2` means invocation, decoding, or I/O failed. See
[`examples/auth-domains/`](examples/auth-domains/) and the bounded
[`OpenSpec change`](openspec/changes/authorization-domains-d1-shadow/).

The JSON report also exposes the deliberately lossy neutral-replay mapping.
`permit_exception` is not collapsed into ordinary allow: it is shown as
`allow` / `exact_exception` with `representable_in_pinned_v1: false`. The report
lists neutral-v1 omissions (request, generation, classifier, time,
canonicalization, and exception/constraint/lease evidence). The D1
`credential://` logical object and the independent checker's inert `fixture://`
object are distinct non-path identities. Neutral coverage requires a traced
ordinary-work record even though that seam is non-critical.

The neutral/lifecycle alignment is pinned to landed Core main
`cb557239a90a82c34686d6ca55046a7b2c9f3129`, checker
`8e376c79d64bc720b280ab839058cc71ca774990`, and all 38 probe IDs in lifecycle
digest `4a5d12ff…`. Unknown, missing, duplicate, or untraced probes fail.
Unknown/drift evidence must suppress the claim, fail or quarantine its receipt,
provide a reason, mark claims invalid, and list incomplete IDs. The shadow does
not reimplement that oracle or convert its evidence into enforcement.

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
make build        # Build from source to ./bin/claude-gatekeeper
make download     # Download pre-built binary from GitHub Releases
make test         # Run all tests with race detector
make lint         # Run golangci-lint
make plugin-test  # Show command to test as a plugin
make clean        # Remove build artifacts
```

## License

MIT
