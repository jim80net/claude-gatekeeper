# Rule cookbook: policies that survived contact with real agents

Agent commands are rarely the tidy one-liners used in permission examples. A
flag moves after a ref, a command gets wrapped in `timeout`, or a pull-request
body quotes the dangerous command it is trying to fix. A policy that ignores
those forms can either miss the dangerous action or block harmless work.

This cookbook explains the rules that Gatekeeper ships after encountering those
failures. Every recipe is ready to paste into `gatekeeper.toml`, and every case
study explains why the extra regex exists.

## Before copying a rule

Gatekeeper normalizes Claude, Codex, and Grok tool calls into the same tool
names. A rule has four essential fields:

```toml
[[rules]]
tool     = 'Bash'                 # regex matched against the canonical tool name
input    = 'git\s+reset\s+--hard' # PCRE2-compatible regex matched against the command
decision = 'deny'
reason   = 'Destructive: git reset --hard'
```

Use TOML literal strings (`'...'`) so backslashes reach the regex unchanged.
Put global rules in `${XDG_CONFIG_HOME:-~/.config}/gatekeeper/gatekeeper.toml`
or the compatible `~/.claude/gatekeeper.toml`. Project rules may live in
`.gatekeeper/gatekeeper.toml`. Rules from both layers are evaluated together,
and **any matching deny wins**, regardless of file order.

These hooks are defense in depth. Keep branch protection, database permissions,
and other server-side controls in place. On an adapter error, the default
`on_error = 'abstain'` returns the decision to the host agent.

## Recipe 1: deny force pushes, wherever the flag lands

Copy this rule:

```toml
[[rules]]
tool     = 'Bash'
input    = '(?:^|[\s|;&(/`])git\s+push\b[^|;&\n]*\s(?:-[a-zA-Z]*f[a-zA-Z]*|--force(?:-with-lease)?(?:=\S+)?)(?=\s|$)'
decision = 'deny'
reason   = 'Destructive: git force push'
```

### Why the obvious rule failed

The original rule looked reasonable:

```toml
# Do not use: it assumes the force flag immediately follows `push`.
input = 'git\s+push\s+(-[a-zA-Z]*f|--force|--force-with-lease)'
```

It blocked `git push --force origin feature`, but Git also accepts the flag
after the remote and ref. `git push origin feature --force` passed through.
Bundled short flags such as `-uf` were another hole.

The first repair searched the whole `push` argument span for a force token. It
then introduced a different regression by anchoring `git` only at the start or
after shell separators. Real agents commonly emitted
`timeout 600 git push --force ...`, `GIT_TRACE=1 git push --force ...`, or
`sudo git push --force ...`; all three stopped matching.

The final rule uses a **token-boundary class** before `git`:

- `^` covers a plain command.
- whitespace covers wrappers and environment assignments.
- `|;&` covers shell chains.
- `(` and backtick cover common command-substitution forms.
- `/` covers `/usr/bin/git` without accepting a word that merely ends in
  `git`.

After `git push`, `[^|;&\n]*` searches only the current command segment. The
force token must end at whitespace or end-of-input, so prose like
`git commit -m 'use --force later'` does not match.

Do not simplify this to `.*--force`: that crosses shell boundaries and turns
unrelated text later in the input into a denial.

## Recipe 2: protect `main` and `master`, including bare pushes

An explicit protected ref can appear as `main`, `HEAD:main`, `:main`,
`+main`, or `refs/heads/main`. Copy the explicit rule:

```toml
[[rules]]
tool     = 'Bash'
input    = 'git\s+(?:-C\s+\S+\s+)*push\b[^|;&]*(?:[\s:+](main|master)(?=\s|$|:)|\brefs/heads/(main|master)(?=\s|$|:))'
decision = 'deny'
reason   = 'Push to protected branch (main/master)'
```

The end boundary matters. A broad search for `main` also blocks branches such
as `main-feature`, `mainline`, or `feature/main`. The scoped
`refs/heads/` alternative catches the fully qualified protected ref without
treating every slash as authority syntax.

A bare `git push` names no remote or branch. Use a narrowly scoped precondition
rule to check the worktree only for that argument-free form:

```toml
[[rules]]
tool               = 'Bash'
input              = '(?:^|[\s|;&(/`])git\s+(?:-C\s+\S+\s+)*push[ \t]*(?=$|[|;&\n])'
precondition       = 'git branch --show-current'
precondition_match = '^(main|master)$'
decision           = 'deny'
reason             = 'Implicit push to protected branch (currently on main/master)'
```

The precondition runs only after the tool and input regexes match. It has a
five-second timeout and runs in the tool call's working directory. The end
boundary deliberately prevents this rule from classifying an explicit safe
target such as `git push origin feature` as a bare push. If your workflow uses
remote-only forms such as `git push origin`, add separately tested coverage for
the exact remotes and option forms you permit rather than broadening this rule
across arbitrary arguments.

## Recipe 3: allow build cleanup without creating a second target hole

It is useful to allow `rm -rf dist`, but the exemption must not also allow
`rm -rf dist /etc`. This deny rule exempts a known build directory only when the
directory is the complete target before end-of-input or a shell separator:

```toml
[[rules]]
tool     = 'Bash'
input    = '\brm\s+(-[a-zA-Z]*r|--recursive)\S*\s+(?!(\./?)?(dist|build|out|\.next|node_modules|__pycache__|\.cache|\.turbo|target|\.parcel-cache)($|&&|\||;))'
decision = 'deny'
reason   = 'Destructive: recursive delete (rm -r)'
```

The failure story was one character class: an earlier exemption accepted
whitespace after `dist`. That whitespace could introduce a second, arbitrary
target. Removing whitespace from the allowed terminators closed the bypass.

## Recipe 4: match actions, not examples inside heredocs

Agents frequently build commit messages and PR bodies with heredocs:

```bash
gh pr create --body "$(cat <<'EOF'
This change prevents rm -rf / from being executed.
EOF
)"
```

Matching the complete raw string made the text `rm -rf /` look like an actual
command and denied harmless documentation. Gatekeeper now strips heredoc
**bodies** before every Bash rule is evaluated while retaining the command line
that opened the heredoc and commands after its delimiter. It recognizes
`<<EOF`, `<<'EOF'`, `<<"EOF"`, and `<<-EOF` forms.

There is one security exception: when the heredoc is executable input to a
shell or interpreter such as `bash <<EOF`, `sh <<EOF`, or `python <<EOF`, the
body is retained so dangerous commands inside it remain matchable.

There is no special TOML switch to enable this; write the action rule normally:

```toml
[[rules]]
tool     = 'Bash'
input    = '\brm\s+(-[a-zA-Z]*r|--recursive)'
decision = 'deny'
reason   = 'Destructive: recursive delete'
```

The heredoc incident established a general rule-writing principle: match the
executable context as narrowly as possible, and let the engine separate command
syntax from payload text. Do not add broad `(?s).*` patterns merely to catch
multiline input.

## Recipe 5: account for environment and wrapper prefixes

An anchor such as `^git\s` does not match either of these:

```bash
GIT_TRACE=1 git push origin feature
timeout 600 git push origin feature
```

For a command that may appear in a chain and may have environment assignments,
use this copy-pasteable shape:

```toml
[[rules]]
tool     = 'Bash'
input    = '(?:^|[|;&]\s*)(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*git\s+reset\s+--hard\b'
decision = 'deny'
reason   = 'Destructive: git reset --hard'
```

This form handles one or more conventional shell assignments at the start of a
segment. It intentionally does not claim to parse every shell wrapper. For a
high-risk command with known wrapper forms, use a tested token-boundary strategy
like the force-push rule and add each wrapper to the probe matrix.

Avoid `\w+=...` when you mean a shell variable name: `\w` admits a leading
digit, while `[A-Za-z_][A-Za-z0-9_]*` describes the conventional identifier.

## Recipe 6: merge authority needs both role and repository domain

In a multi-agent fleet, a `.gatekeeper/lead` marker can designate a coordinator
allowed to complete merges. Checking only that marker produced an authority
escape: a lead in repository A could run `gh pr merge --repo OWNER/REPO-B` from
repository A.

Gatekeeper ships `scripts/merge-domain-check.sh` to combine two facts:

1. Is this worktree a lead seat?
2. Is the explicit merge target inside this seat's repository domain?

Create `.gatekeeper/domain` with one allowed `owner/repository` per line:

```text
example/acme-api
example/acme-worker
```

Without that file, the script falls back to the `origin` remote. Then add:

```toml
[[rules]]
tool               = 'Bash'
input              = 'gh\s+pr\s+merge\b'
precondition       = '/absolute/path/to/scripts/merge-domain-check.sh'
precondition_match = '^Merge denied:'
decision           = 'deny'
reason             = '{{precondition_output}}'
```

The engine exports the heredoc-stripped command as `GATEKEEPER_INPUT` to the
precondition. The helper returns a factual denial for a non-lead seat, a foreign
repository, an unparseable explicit target, or a missing domain. With
`{{precondition_output}}`, that matched diagnostic becomes the deny reason. A
domain mismatch names the resolved domains, requested target, and marker paths
consulted; it does not recommend changing those markers. The helper returns
`OK` only for a lead whose target is implicit in the current repository or
explicitly belongs to the configured domain.

The helper deliberately prints a denial diagnostic and exits successfully on denial.
A nonzero precondition exit means “precondition failed” and skips the rule; using
exit status as the denial signal would fail open.

This recipe covers `gh pr merge`. The helper can also classify recognized
REST-style merge calls when paired with corresponding input rules. Keep
server-side repository permissions and protected-branch rules as the final
authority boundary.

## Testing a copied rule

Use `--debug` to see which rule matched. This Claude-shaped example is useful
for local testing; select another adapter with `--harness` when needed:

```bash
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin feature --force"},"cwd":"/tmp"}' \
  | claude-gatekeeper --debug
```

For changes to shipped rules, test the installed `gatekeeper.toml`, not a regex
copied into a unit test. The force-push regression test does exactly that:

```bash
go test ./cmd/claude-gatekeeper -run TestShippedForcePushRule -count=1
```

## Appendix: the force-push probe matrix

This is the matrix exercised by `TestShippedForcePushRule`. “Deny” cases prove
coverage; “allow” cases keep the rule from expanding into a prose detector.

| Expected | Case | Command |
|----------|------|---------|
| Deny | flag after refs | `git push origin feature --force` |
| Deny | flag before refs | `git push --force origin feature` |
| Deny | bundled short flag | `git push origin feature -uf` |
| Deny | force with lease | `git push origin feature --force-with-lease` |
| Deny | timeout prefix | `timeout 600 git push --force origin feature` |
| Deny | environment prefix | `GIT_TRACE=1 git push --force origin feature` |
| Deny | sudo prefix | `sudo git push --force origin feature` |
| Deny | absolute binary path | `/usr/bin/git push --force origin feature` |
| Deny | parenthesized subshell | `(git push --force origin feature)` |
| Deny | backtick substitution | `` `git push --force origin feature` `` |
| Deny | newline-separated command | `echo hi` then `git push --force origin feature` on the next line |
| Allow | ordinary push | `git push origin feature` |
| Allow | later unrelated force text | `git push origin feature` then `echo use --force flag later` |
| Allow | force text in commit message | `git commit -m 'use --force later'` |
| Allow | quoted force-push example | `git commit -m "git push --force is dangerous"` |

When a production command finds a new edge, add the failing form and a nearby
safe control to this matrix before changing the regex. That is how a clever
pattern becomes a maintained policy.
