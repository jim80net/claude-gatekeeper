package sessiondriver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
			if err := provision(options{harness: harness, gatekeeper: "/opt/candidate/claude-gatekeeper"}); err != nil {
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
