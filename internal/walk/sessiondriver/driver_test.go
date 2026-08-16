package sessiondriver

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type setupExitError int

func (e setupExitError) Error() string { return "setup failed" }
func (e setupExitError) ExitCode() int { return int(e) }

func TestNativeArgsAreHarnessSpecificLongLivedInterfaces(t *testing.T) {
	checks := map[string][]string{
		"claude": {"--input-format", "stream-json", "--include-hook-events"},
		"codex":  {"--dangerously-bypass-hook-trust", "app-server", "--stdio"},
		"grok":   {"--no-auto-update", "--no-leader", "--always-approve", "agent", "stdio"},
	}
	for harness, wants := range checks {
		joined := strings.Join(nativeArgs(harness), " ")
		for _, want := range wants {
			if !strings.Contains(joined, want) {
				t.Errorf("%s args %q omit %q", harness, joined, want)
			}
		}
	}
}

func TestGrokRPCAndAuthenticationAreExplicit(t *testing.T) {
	client := nativeClient{harness: "grok"}
	message := client.rpcMessage(7, "session/prompt", map[string]any{"sessionId": "s"})
	if message["jsonrpc"] != "2.0" || eventID(message) != 7 {
		t.Fatalf("Grok RPC envelope=%#v", message)
	}
	result := map[string]any{"authMethods": []any{map[string]any{"id": "cached_token"}, map[string]any{"id": "xai.api_key"}}}
	if !authMethodOffered(result, "xai.api_key") || authMethodOffered(result, "missing") {
		t.Fatalf("auth method discrimination failed: %#v", result)
	}
}

func TestProvisionWritesOnlyDisposableHarnessSurfaceAndPolicy(t *testing.T) {
	for _, harness := range []string{"claude", "codex", "grok"} {
		t.Run(harness, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "gatekeeper-walk-session-test")
			t.Setenv("HOME", filepath.Join(root, "home"))
			t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(root, "claude"))
			t.Setenv("CODEX_HOME", filepath.Join(root, "codex"))
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "xdg", "config"))
			t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "xdg", "cache"))
			t.Setenv("XDG_DATA_HOME", filepath.Join(root, "xdg", "data"))
			t.Setenv("GATEKEEPER_WALK_SCOPE", "disposable")
			if err := requireDisposableEnvironment(); err != nil {
				t.Fatal(err)
			}
			opts := options{harness: harness, gatekeeper: "/opt/candidate/claude-gatekeeper"}
			if harness == "codex" || harness == "grok" {
				opts.setup = func(opts options) error {
					var hookPath string
					if opts.harness == "codex" {
						hookPath = filepath.Join(os.Getenv("CODEX_HOME"), "hooks.json")
					} else {
						hookPath = filepath.Join(os.Getenv("HOME"), ".grok", "hooks", "gatekeeper.json")
					}
					return writeJSON(hookPath, claudeHook(opts.gatekeeper+" --harness "+opts.harness))
				}
			}
			if err := provision(opts); err != nil {
				t.Fatal(err)
			}
			policy, err := os.ReadFile(filepath.Join(root, "xdg", "config", "gatekeeper", "gatekeeper.toml"))
			if err != nil || !strings.Contains(string(policy), denyReason) || !strings.Contains(string(policy), denyCommand) {
				t.Fatalf("policy=%q err=%v", policy, err)
			}
			var hookPath string
			switch harness {
			case "claude":
				hookPath = filepath.Join(root, "claude", "settings.json")
			case "codex":
				hookPath = filepath.Join(root, "codex", "hooks.json")
			case "grok":
				hookPath = filepath.Join(root, "home", ".grok", "hooks", "gatekeeper.json")
			}
			hook, err := os.ReadFile(hookPath)
			if err != nil || !strings.Contains(string(hook), "/opt/candidate/claude-gatekeeper") {
				t.Fatalf("hook=%q err=%v", hook, err)
			}
		})
	}
}

func TestSecondHarnessNewcomerRejectsClaudeSurfaceWrite(t *testing.T) {
	for _, harness := range []string{"codex", "grok"} {
		t.Run(harness, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "gatekeeper-walk-session-test")
			setDisposableEnvironment(t, root)
			opts := options{harness: harness, gatekeeper: "/opt/candidate/claude-gatekeeper"}
			opts.setup = func(opts options) error {
				if err := os.WriteFile(filepath.Join(os.Getenv("CLAUDE_CONFIG_DIR"), "settings.json"), []byte("{}"), 0600); err != nil {
					return err
				}
				var hookPath string
				if opts.harness == "codex" {
					hookPath = filepath.Join(os.Getenv("CODEX_HOME"), "hooks.json")
				} else {
					hookPath = filepath.Join(os.Getenv("HOME"), ".grok", "hooks", "gatekeeper.json")
				}
				return writeJSON(hookPath, claudeHook(opts.gatekeeper+" --harness "+opts.harness))
			}
			if err := provision(opts); err == nil || !strings.Contains(err.Error(), "wrote the Claude selected root") {
				t.Fatalf("provision error=%v, want Claude-root refusal", err)
			}
		})
	}
}

func TestCodexNewcomerRejectsLegacyHomeRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "gatekeeper-walk-session-test")
	setDisposableEnvironment(t, root)
	opts := options{harness: "codex", gatekeeper: "/opt/candidate/claude-gatekeeper"}
	opts.setup = func(opts options) error {
		selected := filepath.Join(os.Getenv("CODEX_HOME"), "hooks.json")
		if err := writeJSON(selected, claudeHook(opts.gatekeeper+" --harness codex")); err != nil {
			return err
		}
		return os.MkdirAll(filepath.Join(os.Getenv("HOME"), ".codex"), 0700)
	}
	if err := provision(opts); err == nil || !strings.Contains(err.Error(), "ignored CODEX_HOME") {
		t.Fatalf("provision error=%v, want CODEX_HOME refusal", err)
	}
}

func TestCandidateSetupAcceptsOnlyExactCodexNewcomerFailure(t *testing.T) {
	exact := []byte("Error: hook installed but Codex will silently skip it: untrusted; approve it")
	if err := candidateSetupResult("codex", exact, setupExitError(1)); err != nil {
		t.Fatalf("exact fail-closed newcomer result: %v", err)
	}
	for name, tc := range map[string]struct {
		harness string
		output  []byte
		err     error
	}{
		"wrong harness": {harness: "grok", output: exact, err: setupExitError(1)},
		"wrong status":  {harness: "codex", output: exact, err: setupExitError(2)},
		"wrong reason":  {harness: "codex", output: []byte("untrusted"), err: setupExitError(1)},
		"no exit code":  {harness: "codex", output: exact, err: errors.New("launch failed")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := candidateSetupResult(tc.harness, tc.output, tc.err); err == nil {
				t.Fatal("ambiguous newcomer setup result was accepted")
			}
		})
	}
}

func setDisposableEnvironment(t *testing.T, root string) {
	t.Helper()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(root, "claude"))
	t.Setenv("CODEX_HOME", filepath.Join(root, "codex"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "xdg", "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "xdg", "cache"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "xdg", "data"))
	t.Setenv("GATEKEEPER_WALK_SCOPE", "disposable")
	for _, path := range []string{os.Getenv("HOME"), os.Getenv("CLAUDE_CONFIG_DIR"), os.Getenv("CODEX_HOME"), os.Getenv("XDG_CONFIG_HOME"), os.Getenv("XDG_CACHE_HOME"), os.Getenv("XDG_DATA_HOME")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDisposableEnvironmentRejectsOperatorRoots(t *testing.T) {
	t.Setenv("GATEKEEPER_WALK_SCOPE", "disposable")
	t.Setenv("HOME", "/home/operator")
	if err := requireDisposableEnvironment(); err == nil {
		t.Fatal("live-looking HOME was accepted")
	}
}

func TestDisposableEnvironmentRejectsMixedRoots(t *testing.T) {
	root := filepath.Join(t.TempDir(), "gatekeeper-walk-session-test")
	t.Setenv("GATEKEEPER_WALK_SCOPE", "disposable")
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(root, "claude"))
	t.Setenv("CODEX_HOME", filepath.Join(root, "codex"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "xdg", "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "xdg", "cache"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(t.TempDir(), "gatekeeper-walk-session-other", "xdg", "data"))
	if err := requireDisposableEnvironment(); err == nil {
		t.Fatal("mixed disposable roots were accepted")
	}
}

func TestExecutionEvidenceDoesNotAcceptEchoedPrompt(t *testing.T) {
	for _, harness := range []string{"claude", "codex", "grok"} {
		echo := []map[string]any{{"type": "user", "text": prompt(benignCommand)}}
		if hasExecutionOutput(harness, echo, "GATEKEEPER_WALK_BENIGN") {
			t.Fatalf("%s accepted echoed prompt as execution", harness)
		}
	}
	claudeEvent := map[string]any{
		"type": "user",
		"message": map[string]any{
			"content": []any{map[string]any{"type": "tool_result", "content": "GATEKEEPER_WALK_BENIGN"}},
		},
	}
	if !hasExecutionOutput("claude", []map[string]any{claudeEvent}, "GATEKEEPER_WALK_BENIGN") {
		t.Fatal("Claude tool result was not recognized")
	}
	codexEvent := map[string]any{
		"method": "item/commandExecution/outputDelta",
		"params": map[string]any{"delta": "GATEKEEPER_WALK_BENIGN"},
	}
	if !hasExecutionOutput("codex", []map[string]any{codexEvent}, "GATEKEEPER_WALK_BENIGN") {
		t.Fatal("Codex command output was not recognized")
	}
	grokEvent := map[string]any{
		"method": "session/update",
		"params": map[string]any{
			"update": map[string]any{"sessionUpdate": "tool_call_update", "toolCallId": "1", "content": "GATEKEEPER_WALK_BENIGN"},
		},
	}
	if !hasExecutionOutput("grok", []map[string]any{grokEvent}, "GATEKEEPER_WALK_BENIGN") {
		t.Fatal("Grok tool update was not recognized")
	}
}
