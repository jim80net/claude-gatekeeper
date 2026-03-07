package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jim80net/claude-gatekeeper/internal/config"
	"github.com/jim80net/claude-gatekeeper/internal/engine"
	"github.com/jim80net/claude-gatekeeper/internal/protocol"
)

func bashInput(cmd string) *protocol.HookInput {
	return &protocol.HookInput{
		ToolName:  "Bash",
		ToolInput: json.RawMessage(fmt.Sprintf(`{"command":%q}`, cmd)),
		CWD:       "/tmp",
	}
}

func readInput(path string) *protocol.HookInput {
	return &protocol.HookInput{
		ToolName:  "Read",
		ToolInput: json.RawMessage(fmt.Sprintf(`{"file_path":%q}`, path)),
		CWD:       "/tmp",
	}
}

func toolInput(tool string) *protocol.HookInput {
	return &protocol.HookInput{
		ToolName:  tool,
		ToolInput: json.RawMessage(`{}`),
		CWD:       "/tmp",
	}
}

func newEngine(t *testing.T, rules []config.Rule) *engine.Engine {
	t.Helper()
	cfg := &config.Config{Rules: rules}
	eng, err := engine.New(cfg, false)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return eng
}

func newEngineWithPrecondition(t *testing.T, rules []config.Rule, cmdOutput string) *engine.Engine {
	t.Helper()
	eng := newEngine(t, rules)
	eng.SetExecCommand(func(ctx context.Context, cwd, command string) (string, error) {
		return cmdOutput, nil
	})
	return eng
}

func TestDenyAlwaysWins(t *testing.T) {
	eng := newEngine(t, []config.Rule{
		{Tool: "Bash", Input: "^git\\s", Decision: "allow", Reason: "allow git"},
		{Tool: "Bash", Input: "git\\s+reset\\s+--hard", Decision: "deny", Reason: "deny reset"},
	})

	out, err := eng.Evaluate(bashInput("git reset --hard"))
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.HookSpecificOutput.PermissionDecision != protocol.Deny {
		t.Error("expected deny for git reset --hard")
	}
}

func TestAllowWhenMatched(t *testing.T) {
	eng := newEngine(t, []config.Rule{
		{Tool: "Bash", Input: "^git\\s", Decision: "allow", Reason: "allow git"},
	})

	out, err := eng.Evaluate(bashInput("git status"))
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.HookSpecificOutput.PermissionDecision != protocol.Allow {
		t.Error("expected allow for git status")
	}
}

func TestAbstainWhenNoMatch(t *testing.T) {
	eng := newEngine(t, []config.Rule{
		{Tool: "Bash", Input: "^git\\s", Decision: "allow", Reason: "allow git"},
	})

	out, err := eng.Evaluate(bashInput("some-unknown-command"))
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected abstain (nil) for unmatched command")
	}
}

func TestPreconditionMatches(t *testing.T) {
	eng := newEngineWithPrecondition(t, []config.Rule{
		{
			Tool:              "Bash",
			Input:             "\\bgit\\s+push\\b",
			Precondition:      "git branch --show-current",
			PreconditionMatch: "^(main|master)$",
			Decision:          "deny",
			Reason:            "push on main",
		},
	}, "main\n")

	out, err := eng.Evaluate(bashInput("git push"))
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.HookSpecificOutput.PermissionDecision != protocol.Deny {
		t.Error("expected deny when on main branch")
	}
}

func TestPreconditionDoesNotMatch(t *testing.T) {
	eng := newEngineWithPrecondition(t, []config.Rule{
		{
			Tool:              "Bash",
			Input:             "\\bgit\\s+push\\b",
			Precondition:      "git branch --show-current",
			PreconditionMatch: "^(main|master)$",
			Decision:          "deny",
			Reason:            "push on main",
		},
	}, "feature-branch\n")

	out, err := eng.Evaluate(bashInput("git push"))
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected abstain when on feature branch")
	}
}

func TestPreconditionWithCDPrefix(t *testing.T) {
	// When the command is "cd /other/repo && git push", the precondition
	// should run with "cd /other/repo && git branch --show-current",
	// NOT just "git branch --show-current" in the session CWD.
	rules := []config.Rule{
		{
			Tool:              "Bash",
			Input:             "\\bgit\\s+push\\b(?!.*\\b(main|master)\\b)",
			Precondition:      "git branch --show-current",
			PreconditionMatch: "^(main|master)$",
			Decision:          "deny",
			Reason:            "push on main",
		},
	}

	t.Run("cd to repo on feature branch allows push", func(t *testing.T) {
		eng := newEngine(t, rules)
		eng.SetExecCommand(func(ctx context.Context, cwd, command string) (string, error) {
			// Verify the cd prefix was prepended to the precondition.
			if command != "cd /other/repo && git branch --show-current" {
				t.Errorf("expected cd-prefixed precondition, got: %s", command)
			}
			return "feature-branch\n", nil
		})

		out, err := eng.Evaluate(bashInput("cd /other/repo && git push -u origin feature-branch"))
		if err != nil {
			t.Fatal(err)
		}
		if out != nil {
			t.Error("expected abstain (no deny) when cd'd repo is on feature branch")
		}
	})

	t.Run("cd to repo on main still denies push", func(t *testing.T) {
		eng := newEngine(t, rules)
		eng.SetExecCommand(func(ctx context.Context, cwd, command string) (string, error) {
			if command != "cd /other/repo && git branch --show-current" {
				t.Errorf("expected cd-prefixed precondition, got: %s", command)
			}
			return "main\n", nil
		})

		out, err := eng.Evaluate(bashInput("cd /other/repo && git push"))
		if err != nil {
			t.Fatal(err)
		}
		if out == nil || out.HookSpecificOutput.PermissionDecision != protocol.Deny {
			t.Error("expected deny when cd'd repo is on main")
		}
	})

	t.Run("no cd prefix keeps original behavior", func(t *testing.T) {
		eng := newEngine(t, rules)
		eng.SetExecCommand(func(ctx context.Context, cwd, command string) (string, error) {
			if command != "git branch --show-current" {
				t.Errorf("expected bare precondition, got: %s", command)
			}
			return "main\n", nil
		})

		out, err := eng.Evaluate(bashInput("git push"))
		if err != nil {
			t.Fatal(err)
		}
		if out == nil || out.HookSpecificOutput.PermissionDecision != protocol.Deny {
			t.Error("expected deny when CWD is on main")
		}
	})
}

func TestExtractCDPrefix(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{"cd /tmp/foo && git push", "cd /tmp/foo &&"},
		{"cd /tmp/foo && git push -u origin main", "cd /tmp/foo &&"},
		{"cd ~/projects/bar && git status", "cd ~/projects/bar &&"},
		{"git push", ""},
		{"echo cd /tmp && git push", ""},
		{"cd /tmp/foo", ""},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := engine.ExtractCDPrefix(tt.command)
			if got != tt.want {
				t.Errorf("extractCDPrefix(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}

func TestStripHeredocs(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "no heredoc",
			command: "git status",
			want:    "git status",
		},
		{
			name:    "unquoted heredoc",
			command: "git commit -m \"$(cat <<EOF\nThis mentions rm -rf dist\nEOF\n)\"",
			want:    "git commit -m \"$(cat <<EOF\n)\"",
		},
		{
			name:    "single-quoted heredoc",
			command: "git commit -m \"$(cat <<'EOF'\nrm -rf /tmp/stuff\ngit reset --hard\nEOF\n)\"",
			want:    "git commit -m \"$(cat <<'EOF'\n)\"",
		},
		{
			name:    "double-quoted heredoc",
			command: "gh pr create --body \"$(cat <<\"EOF\"\nDROP TABLE users\nEOF\n)\"",
			want:    "gh pr create --body \"$(cat <<\"EOF\"\n)\"",
		},
		{
			name:    "heredoc with dash",
			command: "cat <<-MARKER\n\tindented content with rm -rf\nMARKER",
			want:    "cat <<-MARKER",
		},
		{
			name:    "multiline command without heredoc",
			command: "echo hello &&\ngit push",
			want:    "echo hello &&\ngit push",
		},
		{
			name:    "command after heredoc preserved",
			command: "cat <<EOF\nheredoc body\nEOF\necho after",
			want:    "cat <<EOF\necho after",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.StripHeredocs(tt.command)
			if got != tt.want {
				t.Errorf("StripHeredocs:\n  input: %q\n  got:   %q\n  want:  %q", tt.command, got, tt.want)
			}
		})
	}
}

func TestHeredocContentDoesNotTriggerDeny(t *testing.T) {
	eng := newEngine(t, []config.Rule{
		{Tool: "Bash", Input: `\brm\s+(-[a-zA-Z]*r|--recursive)`, Decision: "deny", Reason: "recursive delete"},
		{Tool: "Bash", Input: `git\s+reset\s+--hard`, Decision: "deny", Reason: "hard reset"},
		{Tool: "Bash", Input: `(?i)\b(DROP|TRUNCATE)\b`, Decision: "deny", Reason: "destructive SQL"},
		{Tool: "Bash", Input: `(?:^|[|;&]\s*)git\s`, Decision: "allow", Reason: "git"},
		{Tool: "Bash", Input: `(?:^|[|;&]\s*)gh\s`, Decision: "allow", Reason: "gh"},
	})

	tests := []struct {
		name string
		cmd  string
		want *protocol.Decision
	}{
		{
			name: "commit message mentioning rm -rf",
			cmd:  "git commit -m \"$(cat <<'EOF'\nfeat: allow rm -rf on build dirs\nEOF\n)\"",
			want: ptr(protocol.Allow),
		},
		{
			name: "PR body mentioning DROP TABLE",
			cmd:  "gh pr create --body \"$(cat <<'EOF'\nThis fixes the DROP TABLE issue\nEOF\n)\"",
			want: ptr(protocol.Allow),
		},
		{
			name: "commit message mentioning git reset --hard",
			cmd:  "git commit -m \"$(cat <<'EOF'\nRevert git reset --hard behavior\nEOF\n)\"",
			want: ptr(protocol.Allow),
		},
		{
			name: "actual rm -rf still denied",
			cmd:  "rm -rf /tmp/stuff",
			want: ptr(protocol.Deny),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := eng.Evaluate(bashInput(tt.cmd))
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == nil {
				if out != nil {
					t.Errorf("expected abstain, got %s", out.HookSpecificOutput.PermissionDecision)
				}
				return
			}
			if out == nil {
				t.Fatalf("expected %s, got abstain", *tt.want)
			}
			if out.HookSpecificOutput.PermissionDecision != *tt.want {
				t.Errorf("got %s (%s), want %s",
					out.HookSpecificOutput.PermissionDecision,
					out.HookSpecificOutput.PermissionDecisionReason,
					*tt.want)
			}
		})
	}
}

func TestToolMatching(t *testing.T) {
	eng := newEngine(t, []config.Rule{
		{Tool: "Read|Glob|Grep", Input: ".*", Decision: "allow", Reason: "browsing"},
	})

	for _, tool := range []string{"Read", "Glob", "Grep"} {
		out, err := eng.Evaluate(toolInput(tool))
		if err != nil {
			t.Fatal(err)
		}
		if out == nil || out.HookSpecificOutput.PermissionDecision != protocol.Allow {
			t.Errorf("expected allow for tool %s", tool)
		}
	}

	// Bash should not match.
	out, err := eng.Evaluate(bashInput("ls"))
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("expected abstain for Bash (not in Read|Glob|Grep)")
	}
}

func TestCredentialFileDeny(t *testing.T) {
	eng := newEngine(t, []config.Rule{
		{Tool: "Read", Input: `(^|/)\.env(\..*)?$|\.envrc$|key\.json$|id_rsa|id_ed25519|\.pem$|credentials$|\.secret`, Decision: "deny", Reason: "creds"},
		{Tool: "Read|Glob|Grep", Input: ".*", Decision: "allow", Reason: "browsing"},
	})

	denyPaths := []string{
		"/home/user/.env",
		"/project/.env.local",
		"/home/user/.envrc",
		"/secrets/service-key.json",
		"/home/user/.ssh/id_rsa",
		"/home/user/.ssh/id_ed25519",
		"/etc/ssl/cert.pem",
		"/app/credentials",
		"/app/.secret",
	}

	for _, p := range denyPaths {
		out, err := eng.Evaluate(readInput(p))
		if err != nil {
			t.Fatal(err)
		}
		if out == nil || out.HookSpecificOutput.PermissionDecision != protocol.Deny {
			t.Errorf("expected deny for Read %s, got %v", p, out)
		}
	}

	// Safe file should be allowed.
	out, err := eng.Evaluate(readInput("/project/src/main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.HookSpecificOutput.PermissionDecision != protocol.Allow {
		t.Error("expected allow for main.go")
	}
}

func TestInvalidRuleRegex(t *testing.T) {
	_, err := engine.New(&config.Config{Rules: []config.Rule{
		{Tool: "[invalid", Input: ".*", Decision: "allow", Reason: "bad"},
	}}, false)
	if err == nil {
		t.Error("expected error for invalid tool regex")
	}

	_, err = engine.New(&config.Config{Rules: []config.Rule{
		{Tool: "Bash", Input: "[invalid", Decision: "allow", Reason: "bad"},
	}}, false)
	if err == nil {
		t.Error("expected error for invalid input regex")
	}
}

func TestInvalidDecision(t *testing.T) {
	_, err := engine.New(&config.Config{Rules: []config.Rule{
		{Tool: "Bash", Input: ".*", Decision: "maybe", Reason: "bad"},
	}}, false)
	if err == nil {
		t.Error("expected error for invalid decision")
	}
}

// TestDefaultRules validates the shipped default rules against realistic commands.
func TestDefaultRules(t *testing.T) {
	cfg, err := config.LoadFile("../../gatekeeper.toml")
	if err != nil {
		t.Fatalf("LoadFile(gatekeeper.toml): %v", err)
	}

	eng, err := engine.New(cfg, false)
	if err != nil {
		t.Fatalf("engine.New with defaults: %v", err)
	}

	// Override precondition exec so tests don't shell out.
	eng.SetExecCommand(func(ctx context.Context, cwd, command string) (string, error) {
		// Default: not on main.
		return "feature-branch\n", nil
	})

	tests := []struct {
		name string
		input *protocol.HookInput
		want  *protocol.Decision // nil = abstain
	}{
		// Deny cases
		{"deny git reset --hard", bashInput("git reset --hard HEAD~1"), ptr(protocol.Deny)},
		{"deny git clean -fd", bashInput("git clean -fd"), ptr(protocol.Deny)},
		{"deny git push --force", bashInput("git push --force origin feature"), ptr(protocol.Deny)},
		{"deny git push -f", bashInput("git push -f origin feature"), ptr(protocol.Deny)},
		{"deny git commit --amend", bashInput("git commit --amend -m 'fix'"), ptr(protocol.Deny)},
		{"deny git push origin main", bashInput("git push origin main"), ptr(protocol.Deny)},
		{"deny git push origin master", bashInput("git push origin master"), ptr(protocol.Deny)},
		{"deny git branch -D", bashInput("git branch -D feature-branch"), ptr(protocol.Deny)},
		{"deny rm -rf", bashInput("rm -rf /tmp/stuff"), ptr(protocol.Deny)},
		{"deny rm -r", bashInput("rm -r dir/"), ptr(protocol.Deny)},
		{"deny rm --recursive", bashInput("rm --recursive dir/"), ptr(protocol.Deny)},
		{"deny sed", bashInput("sed -i 's/foo/bar/' file.txt"), ptr(protocol.Deny)},
		{"deny awk", bashInput("awk '{print $1}' file.txt"), ptr(protocol.Deny)},
		{"deny DROP TABLE", bashInput("psql -c 'DROP TABLE users'"), ptr(protocol.Deny)},
		{"deny TRUNCATE", bashInput("mysql -e 'TRUNCATE TABLE logs'"), ptr(protocol.Deny)},
		{"deny DELETE FROM", bashInput("sqlite3 db.sqlite 'DELETE FROM users'"), ptr(protocol.Deny)},
		{"deny cat .env", bashInput("cat .env"), ptr(protocol.Deny)},
		{"deny read .env", readInput("/project/.env"), ptr(protocol.Deny)},
		{"deny read id_rsa", readInput("/home/user/.ssh/id_rsa"), ptr(protocol.Deny)},
		{"deny read key.json", readInput("/tmp/service-key.json"), ptr(protocol.Deny)},

		// Allow cases
		{"allow git status", bashInput("git status"), ptr(protocol.Allow)},
		{"allow git add", bashInput("git add -A"), ptr(protocol.Allow)},
		{"allow git commit", bashInput("git commit -m 'test'"), ptr(protocol.Allow)},
		{"allow git log", bashInput("git log --oneline"), ptr(protocol.Allow)},
		{"allow git push feature", bashInput("git push origin feature-branch"), ptr(protocol.Allow)},
		{"allow gh pr list", bashInput("gh pr list"), ptr(protocol.Allow)},
		{"allow docker build", bashInput("docker build -t app ."), ptr(protocol.Allow)},
		{"allow go test", bashInput("go test ./..."), ptr(protocol.Allow)},
		{"allow go build", bashInput("go build ./cmd/..."), ptr(protocol.Allow)},
		{"allow make", bashInput("make build"), ptr(protocol.Allow)},
		{"allow pnpm install", bashInput("pnpm install"), ptr(protocol.Allow)},
		{"allow ls", bashInput("ls -la"), ptr(protocol.Allow)},
		{"allow find", bashInput("find . -name '*.go'"), ptr(protocol.Allow)},
		{"allow curl", bashInput("curl https://example.com"), ptr(protocol.Allow)},
		{"allow openssl", bashInput("openssl rand -hex 32"), ptr(protocol.Allow)},
		{"allow timeout", bashInput("timeout 120 go test ./..."), ptr(protocol.Allow)},
		{"allow python", bashInput("python3 -m pytest"), ptr(protocol.Allow)},
		{"allow pytest", bashInput("pytest -xvs tests/"), ptr(protocol.Allow)},
		{"allow uv", bashInput("uv pip install requests"), ptr(protocol.Allow)},
		{"allow cargo", bashInput("cargo build --release"), ptr(protocol.Allow)},
		{"allow terraform", bashInput("terraform plan"), ptr(protocol.Allow)},
		{"allow jq", bashInput("jq '.name' package.json"), ptr(protocol.Allow)},
		{"allow node", bashInput("node server.js"), ptr(protocol.Allow)},

		// Allow non-Bash tools
		{"allow Read", readInput("/project/src/main.go"), ptr(protocol.Allow)},
		{"allow Glob", toolInput("Glob"), ptr(protocol.Allow)},
		{"allow Grep", toolInput("Grep"), ptr(protocol.Allow)},
		{"allow Edit", toolInput("Edit"), ptr(protocol.Allow)},
		{"allow Write", toolInput("Write"), ptr(protocol.Allow)},
		{"allow Agent", toolInput("Agent"), ptr(protocol.Allow)},

		// Abstain cases (unrecognised commands)
		{"abstain unknown", bashInput("some-exotic-tool --flag"), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := eng.Evaluate(tt.input)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if tt.want == nil {
				if out != nil {
					t.Errorf("expected abstain, got %s: %s",
						out.HookSpecificOutput.PermissionDecision,
						out.HookSpecificOutput.PermissionDecisionReason)
				}
				return
			}
			if out == nil {
				t.Fatalf("expected %s, got abstain", *tt.want)
			}
			if out.HookSpecificOutput.PermissionDecision != *tt.want {
				t.Errorf("got %s (%s), want %s",
					out.HookSpecificOutput.PermissionDecision,
					out.HookSpecificOutput.PermissionDecisionReason,
					*tt.want)
			}
		})
	}
}

func ptr(d protocol.Decision) *protocol.Decision { return &d }
