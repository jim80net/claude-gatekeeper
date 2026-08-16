package setup_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jim80net/claude-gatekeeper/internal/codextrust"
	"github.com/jim80net/claude-gatekeeper/internal/setup"
)

func TestInstallGrok(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	if err := setup.InstallGrok("/usr/local/bin/gatekeeper"); err != nil {
		t.Fatalf("InstallGrok: %v", err)
	}

	hookPath := filepath.Join(homeDir, ".grok", "hooks", "gatekeeper.json")
	data, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("reading grok hook: %v", err)
	}
	// grok's global hook is the Claude-shaped hooks.json (live-verified).
	var cfg struct {
		Hooks struct {
			PreToolUse []struct {
				Matcher string `json:"matcher"`
				Hooks   []struct {
					Type    string `json:"type"`
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cfg.Hooks.PreToolUse) != 1 || len(cfg.Hooks.PreToolUse[0].Hooks) != 1 {
		t.Fatalf("unexpected grok hook structure: %s", data)
	}
	h := cfg.Hooks.PreToolUse[0].Hooks[0]
	if h.Type != "command" {
		t.Errorf("type = %q, want command", h.Type)
	}
	if h.Command != "/usr/local/bin/gatekeeper --harness grok" {
		t.Errorf("command = %q", h.Command)
	}
}

func TestInstallCodexProject(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	projectDir := t.TempDir()

	requireCodexTrustFailure(t, setup.InstallCodex("/usr/local/bin/gatekeeper", projectDir), "untrusted")

	assertCodexHook(t, filepath.Join(projectDir, ".codex", "hooks.json"))
}

// TestInstallCodexGlobal covers the preferred global registration
// (~/.codex/hooks.json) selected by an empty projectDir (Q3: codex reads it).
func TestInstallCodexGlobal(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	requireCodexTrustFailure(t, setup.InstallCodex("/usr/local/bin/gatekeeper", ""), "untrusted")

	assertCodexHook(t, filepath.Join(homeDir, ".codex", "hooks.json"))
}

func TestInstallCodexGlobalHonorsSelectedCodexHome(t *testing.T) {
	homeDir := t.TempDir()
	codexHome := filepath.Join(t.TempDir(), "selected-codex")
	t.Setenv("HOME", homeDir)
	t.Setenv("CODEX_HOME", codexHome)

	requireCodexTrustFailure(t, setup.InstallCodex("/usr/local/bin/gatekeeper", ""), "untrusted")

	assertCodexHook(t, filepath.Join(codexHome, "hooks.json"))
	if _, err := os.Stat(filepath.Join(homeDir, ".codex")); !os.IsNotExist(err) {
		t.Fatalf("legacy Claude-named assumption created HOME/.codex: %v", err)
	}
}

func TestInstallCodexTrustUsesSelectedCodexHome(t *testing.T) {
	home := t.TempDir()
	codexHome := filepath.Join(t.TempDir(), "selected-codex")
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", codexHome)
	const binary = "/usr/local/bin/gatekeeper"
	command := binary + " --harness codex"
	hookPath := filepath.Join(codexHome, "hooks.json")

	requireCodexTrustFailure(t, setup.InstallCodex(binary, ""), "untrusted")
	trust, err := codextrust.InspectRoot(codexHome, hookPath, command)
	if err != nil {
		t.Fatal(err)
	}
	config := `[hooks.state."` + trust.Key + `"]
trusted_hash = "` + trust.CurrentHash + `"
`
	if err := os.WriteFile(filepath.Join(codexHome, "config.toml"), []byte(config), 0644); err != nil {
		t.Fatal(err)
	}
	if err := setup.InstallCodex(binary, ""); err != nil {
		t.Fatalf("trusted selected CODEX_HOME install: %v", err)
	}
}

// TestInstallCodexPreservesExisting confirms an existing non-gatekeeper hook in
// .codex/hooks.json survives a gatekeeper install (merge, not clobber).
func TestInstallCodexPreservesExisting(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	projectDir := t.TempDir()
	codexDir := filepath.Join(projectDir, ".codex")
	os.MkdirAll(codexDir, 0755)
	existing := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/other-tool --run"}]}]}}`
	os.WriteFile(filepath.Join(codexDir, "hooks.json"), []byte(existing), 0644)

	requireCodexTrustFailure(t, setup.InstallCodex("/usr/local/bin/claude-gatekeeper", projectDir), "untrusted")

	data, _ := os.ReadFile(filepath.Join(codexDir, "hooks.json"))
	s := string(data)
	if !strings.Contains(s, "/opt/other-tool --run") {
		t.Error("existing non-gatekeeper hook was clobbered")
	}
	if !strings.Contains(s, "claude-gatekeeper --harness codex") {
		t.Error("gatekeeper hook was not added")
	}
}

func TestInstallCodexTrustedAndHashDrift(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	const binary = "/usr/local/bin/gatekeeper"
	command := binary + " --harness codex"
	hookPath := filepath.Join(home, ".codex", "hooks.json")

	requireCodexTrustFailure(t, setup.InstallCodex(binary, ""), "untrusted")
	trust, err := codextrust.Inspect(home, hookPath, command)
	if err != nil {
		t.Fatal(err)
	}
	config := `[hooks.state."` + trust.Key + `"]
trusted_hash = "` + trust.CurrentHash + `"
`
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(config), 0644); err != nil {
		t.Fatal(err)
	}
	if err := setup.InstallCodex(binary, ""); err != nil {
		t.Fatalf("trusted InstallCodex: %v", err)
	}

	config = `[hooks.state."` + trust.Key + `"]
trusted_hash = "sha256:stale"
`
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(config), 0644); err != nil {
		t.Fatal(err)
	}
	requireCodexTrustFailure(t, setup.InstallCodex(binary, ""), "modified")
}

func requireCodexTrustFailure(t *testing.T, err error, state string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), state) || !strings.Contains(err.Error(), "silently skip") {
		t.Fatalf("InstallCodex error = %v, want fail-closed %s trust error", err, state)
	}
}

func assertCodexHook(t *testing.T, hookPath string) {
	t.Helper()
	data, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("reading codex hook: %v", err)
	}
	var cfg struct {
		Hooks struct {
			PreToolUse []struct {
				Hooks []struct {
					Type    string `json:"type"`
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cfg.Hooks.PreToolUse) != 1 || len(cfg.Hooks.PreToolUse[0].Hooks) != 1 {
		t.Fatalf("unexpected codex hook structure: %s", data)
	}
	h := cfg.Hooks.PreToolUse[0].Hooks[0]
	if h.Type != "command" {
		t.Errorf("type = %q, want command", h.Type)
	}
	if h.Command != "/usr/local/bin/gatekeeper --harness codex" {
		t.Errorf("command = %q", h.Command)
	}
}

// TestInstallGrokIsIdempotentlyBackedUp confirms a second install backs up the
// prior hook rather than clobbering silently.
func TestInstallGrokBackup(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	if err := setup.InstallGrok("/bin/one"); err != nil {
		t.Fatal(err)
	}
	if err := setup.InstallGrok("/bin/two"); err != nil {
		t.Fatal(err)
	}
	// A backup of the first install should exist alongside the hook.
	entries, err := os.ReadDir(filepath.Join(homeDir, ".grok", "hooks"))
	if err != nil {
		t.Fatalf("reading grok hooks dir: %v", err)
	}
	backups := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" && len(e.Name()) > len("gatekeeper.json") {
			backups++
		}
	}
	if backups == 0 {
		t.Error("expected a backup of the prior grok hook")
	}
}
