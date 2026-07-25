package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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

func TestRunDoctorJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := filepath.Join(home, "bin", "claude-gatekeeper")
	if err := os.MkdirAll(filepath.Dir(bin), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'claude-gatekeeper test-version' >&2\n"), 0755); err != nil {
		t.Fatal(err)
	}
	config := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"` + bin + ` --harness grok"}]}]}}`
	hookPath := filepath.Join(home, ".grok", "hooks", "gatekeeper.json")
	if err := os.MkdirAll(filepath.Dir(hookPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	code := run(strings.NewReader(""), &stdout, []string{"doctor", "--json", "--expected-binary", bin, "--expected-version", "test-version"})
	if code != 0 {
		t.Fatalf("exit code = %d, output = %s", code, stdout.String())
	}
	var report struct {
		OK       bool `json:"ok"`
		Surfaces []struct {
			Harness string `json:"harness"`
		} `json:"surfaces"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.OK || len(report.Surfaces) != 1 || report.Surfaces[0].Harness != "grok" {
		t.Fatalf("report = %#v", report)
	}
}

func TestRunDoctorFailureExitCodes(t *testing.T) {
	t.Run("minimum surfaces", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		var stdout bytes.Buffer
		if code := run(strings.NewReader(""), &stdout, []string{"doctor", "--json"}); code != 1 {
			t.Fatalf("exit code = %d, want 1; output = %s", code, stdout.String())
		}
	})
	t.Run("version drift", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		bin := filepath.Join(home, "bin", "claude-gatekeeper")
		if err := os.MkdirAll(filepath.Dir(bin), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'claude-gatekeeper observed'\n"), 0755); err != nil {
			t.Fatal(err)
		}
		hookPath := filepath.Join(home, ".claude", "settings.json")
		if err := os.MkdirAll(filepath.Dir(hookPath), 0755); err != nil {
			t.Fatal(err)
		}
		config := `{"hooks":{"PreToolUse":[{"hooks":[{"command":"` + bin + `"}]}]}}`
		if err := os.WriteFile(hookPath, []byte(config), 0644); err != nil {
			t.Fatal(err)
		}
		code := run(strings.NewReader(""), &bytes.Buffer{}, []string{"doctor", "--expected-binary", bin, "--expected-version", "wanted"})
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
	})
	t.Run("usage error", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		if code := run(strings.NewReader(""), &bytes.Buffer{}, []string{"doctor", "--min-surfaces", "-1"}); code != 2 {
			t.Fatalf("exit code = %d, want 2", code)
		}
	})
	t.Run("help", func(t *testing.T) {
		if code := run(strings.NewReader(""), &bytes.Buffer{}, []string{"doctor", "--help"}); code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
	})
	t.Run("table output error", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		if code := run(strings.NewReader(""), errorWriter{err: errors.New("write failed")}, []string{"doctor"}); code != 2 {
			t.Fatalf("exit code = %d, want 2", code)
		}
	})
	t.Run("all hook file errors", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		for path, content := range map[string]string{
			filepath.Join(home, ".grok", "hooks", "gatekeeper.json"): "{",
			filepath.Join(home, ".codex", "hooks.json"):              "not json",
		} {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
		}

		var stdout bytes.Buffer
		if code := run(strings.NewReader(""), &stdout, []string{"doctor", "--json", "--min-surfaces", "0"}); code != 2 {
			t.Fatalf("exit code = %d, want 2; output = %s", code, stdout.String())
		}
		for _, path := range []string{".grok/hooks/gatekeeper.json", ".codex/hooks.json"} {
			if !strings.Contains(stdout.String(), path) {
				t.Errorf("output missing %q: %s", path, stdout.String())
			}
		}
	})
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

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

func TestRunPolicyTestExitCodes(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "gatekeeper.toml")
	if err := os.WriteFile(configPath, []byte("[[rules]]\ntool='Bash'\ninput='^blocked$'\ndecision='deny'\nreason='nope'\n"), 0644); err != nil {
		t.Fatal(err)
	}
	writeCases := func(name, expected string) string {
		path := filepath.Join(dir, name)
		content := "[[cases]]\nname='case'\ntool='Bash'\ncommand='blocked'\nexpected='" + expected + "'\n"
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"pass", []string{"test", "--config", configPath, writeCases("pass.toml", "deny")}, 0},
		{"assertion failure", []string{"test", "--config", configPath, writeCases("fail.toml", "allow")}, 1},
		{"usage error", []string{"test"}, 2},
		{"parse error", []string{"test", filepath.Join(dir, "missing.toml")}, 2},
		{"help", []string{"test", "--help"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(strings.NewReader(""), io.Discard, tc.args); got != tc.want {
				t.Fatalf("run() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRunReleaseVerifyUsage(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{"missing tag", []string{"verify-release"}, 2},
		{"help", []string{"verify-release", "--help"}, 0},
		{
			"invalid minimum",
			[]string{
				"verify-release",
				"v1.2.3",
				"--host-binary", "/tmp/host",
				"--plugin-binary", "/tmp/plugin",
				"--min-surfaces", "-1",
			},
			2,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := run(strings.NewReader(""), io.Discard, test.args); got != test.want {
				t.Fatalf("run() = %d, want %d", got, test.want)
			}
		})
	}
}
