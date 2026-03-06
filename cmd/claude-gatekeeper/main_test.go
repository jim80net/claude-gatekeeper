package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jim80net/claude-gatekeeper/internal/protocol"
)

// setupTestHome creates a temp HOME with the shipped gatekeeper.toml config.
func setupTestHome(t *testing.T) {
	t.Helper()
	homeDir := t.TempDir()
	claudeDir := filepath.Join(homeDir, ".claude")
	os.MkdirAll(claudeDir, 0755)

	data, err := os.ReadFile("../../gatekeeper.toml")
	if err != nil {
		t.Fatalf("reading gatekeeper.toml: %v", err)
	}
	os.WriteFile(filepath.Join(claudeDir, "gatekeeper.toml"), data, 0644)

	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", homeDir)
}

func hookJSON(toolName, command string) string {
	input := map[string]interface{}{
		"tool_name":  toolName,
		"tool_input": map[string]string{"command": command},
		"cwd":        "/tmp",
	}
	b, _ := json.Marshal(input)
	return string(b)
}

func TestRunHookAllow(t *testing.T) {
	setupTestHome(t)
	stdin := strings.NewReader(hookJSON("Bash", "git status"))
	var stdout bytes.Buffer

	code := run(stdin, &stdout, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if stdout.Len() == 0 {
		t.Fatal("expected output, got nothing (abstain)")
	}

	var out protocol.HookOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != protocol.Allow {
		t.Errorf("decision = %s, want allow", out.HookSpecificOutput.PermissionDecision)
	}
}

func TestRunHookDeny(t *testing.T) {
	setupTestHome(t)
	stdin := strings.NewReader(hookJSON("Bash", "git reset --hard HEAD~1"))
	var stdout bytes.Buffer

	code := run(stdin, &stdout, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var out protocol.HookOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != protocol.Deny {
		t.Errorf("decision = %s, want deny", out.HookSpecificOutput.PermissionDecision)
	}
}

func TestRunHookAbstain(t *testing.T) {
	setupTestHome(t)
	stdin := strings.NewReader(hookJSON("Bash", "some-exotic-tool --flag"))
	var stdout bytes.Buffer

	code := run(stdin, &stdout, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if stdout.Len() != 0 {
		t.Errorf("expected empty stdout (abstain), got %q", stdout.String())
	}
}

func TestRunInvalidJSON(t *testing.T) {
	stdin := strings.NewReader("{not json}")
	var stdout bytes.Buffer

	code := run(stdin, &stdout, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (abstain on error)", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("expected empty stdout on parse error, got %q", stdout.String())
	}
}

func TestRunVersion(t *testing.T) {
	var stdout bytes.Buffer
	code := run(strings.NewReader(""), &stdout, []string{"--version"})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestRunNonBashTool(t *testing.T) {
	setupTestHome(t)
	input := map[string]interface{}{
		"tool_name":  "Read",
		"tool_input": map[string]string{"file_path": "/tmp/main.go"},
		"cwd":        "/tmp",
	}
	b, _ := json.Marshal(input)

	var stdout bytes.Buffer
	code := run(bytes.NewReader(b), &stdout, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var out protocol.HookOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != protocol.Allow {
		t.Errorf("decision = %s, want allow", out.HookSpecificOutput.PermissionDecision)
	}
}

func TestRunNoConfigAbstains(t *testing.T) {
	// With no config files, the gatekeeper should abstain on everything.
	homeDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", homeDir)
	defer os.Setenv("HOME", origHome)

	stdin := strings.NewReader(hookJSON("Bash", "git status"))
	var stdout bytes.Buffer

	code := run(stdin, &stdout, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if stdout.Len() != 0 {
		t.Errorf("expected abstain with no config, got %q", stdout.String())
	}
}
