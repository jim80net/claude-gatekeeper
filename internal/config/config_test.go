package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jim80net/claude-gatekeeper/internal/config"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := config.LoadDefaults()
	if err != nil {
		t.Fatalf("LoadDefaults: %v", err)
	}
	if len(cfg.Rules) == 0 {
		t.Fatal("expected non-zero default rules")
	}

	// Verify key deny rules exist.
	denies := map[string]bool{}
	for _, r := range cfg.Rules {
		if r.Decision == "deny" {
			denies[r.Reason] = true
		}
	}
	for _, want := range []string{
		"Destructive: git reset --hard",
		"Destructive: git force push",
		"Destructive: recursive delete (rm -r)",
		"Use the Edit tool instead of sed/awk",
		"Destructive SQL operation",
		"Use pnpm instead of npm",
		"Credential/secret file access denied",
	} {
		if !denies[want] {
			t.Errorf("missing deny rule: %q", want)
		}
	}

	// Verify key allow rules exist.
	allows := map[string]bool{}
	for _, r := range cfg.Rules {
		if r.Decision == "allow" {
			allows[r.Reason] = true
		}
	}
	for _, want := range []string{
		"Git operations (non-destructive)",
		"GitHub CLI",
		"Docker",
		"Python toolchain",
		"Go toolchain",
		"pnpm package manager",
		"File browsing",
		"File editing",
	} {
		if !allows[want] {
			t.Errorf("missing allow rule: %q", want)
		}
	}
}

func TestLoadLayered(t *testing.T) {
	// Create a temp dir acting as $HOME/.claude/
	homeDir := t.TempDir()
	globalDir := filepath.Join(homeDir, ".claude")
	os.MkdirAll(globalDir, 0755)

	globalConfig := `
[[rules]]
tool  = 'Bash'
input = '^custom-tool\s'
decision = "allow"
reason = "Custom global rule"
`
	os.WriteFile(filepath.Join(globalDir, ".gatekeeper.toml"), []byte(globalConfig), 0644)

	// Create a project dir with its own config.
	projectDir := t.TempDir()
	projectClaudeDir := filepath.Join(projectDir, ".claude")
	os.MkdirAll(projectClaudeDir, 0755)

	projectConfig := `
[[rules]]
tool  = 'Bash'
input = '^project-tool\s'
decision = "deny"
reason = "Project deny rule"
`
	os.WriteFile(filepath.Join(projectClaudeDir, "gatekeeper.toml"), []byte(projectConfig), 0644)

	// Override HOME for this test.
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", homeDir)
	defer os.Setenv("HOME", origHome)

	cfg, err := config.Load(projectDir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Should have defaults + global + project rules.
	foundGlobal := false
	foundProject := false
	for _, r := range cfg.Rules {
		if r.Reason == "Custom global rule" {
			foundGlobal = true
		}
		if r.Reason == "Project deny rule" {
			foundProject = true
		}
	}
	if !foundGlobal {
		t.Error("global rule not found in merged config")
	}
	if !foundProject {
		t.Error("project rule not found in merged config")
	}
}

func TestLoadIncludeDefaultsFalse(t *testing.T) {
	homeDir := t.TempDir()
	globalDir := filepath.Join(homeDir, ".claude")
	os.MkdirAll(globalDir, 0755)

	globalConfig := `
include_defaults = false

[[rules]]
tool  = 'Bash'
input = '^only-this\s'
decision = "allow"
reason = "Only rule"
`
	os.WriteFile(filepath.Join(globalDir, ".gatekeeper.toml"), []byte(globalConfig), 0644)

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", homeDir)
	defer os.Setenv("HOME", origHome)

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].Reason != "Only rule" {
		t.Errorf("unexpected rule: %q", cfg.Rules[0].Reason)
	}
}
