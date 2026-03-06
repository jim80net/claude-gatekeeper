package setup_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jim80net/claude-gatekeeper/internal/setup"
)

func setupHome(t *testing.T, settingsJSON string) (string, string) {
	t.Helper()
	homeDir := t.TempDir()
	claudeDir := filepath.Join(homeDir, ".claude")
	os.MkdirAll(claudeDir, 0755)
	settingsPath := filepath.Join(claudeDir, "settings.json")
	if settingsJSON != "" {
		os.WriteFile(settingsPath, []byte(settingsJSON), 0644)
	}
	t.Setenv("HOME", homeDir)
	return homeDir, settingsPath
}

func readJSON(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parsing %s: %v\n%s", path, err, data)
	}
	return m
}

func TestInstallFresh(t *testing.T) {
	_, settingsPath := setupHome(t, `{"model":"opus"}`)

	if err := setup.Install("/usr/local/bin/claude-gatekeeper"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	m := readJSON(t, settingsPath)
	hooks, ok := m["hooks"].(map[string]interface{})
	if !ok {
		t.Fatal("missing hooks key")
	}
	ptu, ok := hooks["PreToolUse"].([]interface{})
	if !ok || len(ptu) == 0 {
		t.Fatal("missing PreToolUse array")
	}

	// Verify the command was set.
	entry := ptu[0].(map[string]interface{})
	innerHooks := entry["hooks"].([]interface{})
	hookDef := innerHooks[0].(map[string]interface{})
	if hookDef["command"] != "/usr/local/bin/claude-gatekeeper" {
		t.Errorf("command = %v, want /usr/local/bin/claude-gatekeeper", hookDef["command"])
	}

	// Verify existing settings preserved.
	if m["model"] != "opus" {
		t.Errorf("model = %v, want opus", m["model"])
	}
}

func TestInstallNoExistingFile(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	if err := setup.Install("/usr/local/bin/claude-gatekeeper"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	settingsPath := filepath.Join(homeDir, ".claude", "settings.json")
	m := readJSON(t, settingsPath)
	if _, ok := m["hooks"]; !ok {
		t.Fatal("missing hooks key in newly created settings")
	}
}

func TestInstallIdempotent(t *testing.T) {
	_, settingsPath := setupHome(t, `{"model":"opus"}`)

	setup.Install("/usr/local/bin/claude-gatekeeper")
	setup.Install("/usr/local/bin/claude-gatekeeper") // second call

	m := readJSON(t, settingsPath)
	hooks := m["hooks"].(map[string]interface{})
	ptu := hooks["PreToolUse"].([]interface{})
	if len(ptu) != 1 {
		t.Errorf("expected 1 PreToolUse entry, got %d (duplicate added)", len(ptu))
	}
}

func TestInstallPreservesExistingHooks(t *testing.T) {
	existing := `{
		"hooks": {
			"PreToolUse": [
				{
					"matcher": "Bash",
					"hooks": [{"type":"command","command":"other-hook"}]
				}
			]
		}
	}`
	_, settingsPath := setupHome(t, existing)

	if err := setup.Install("/usr/local/bin/claude-gatekeeper"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	m := readJSON(t, settingsPath)
	hooks := m["hooks"].(map[string]interface{})
	ptu := hooks["PreToolUse"].([]interface{})
	if len(ptu) != 2 {
		t.Errorf("expected 2 PreToolUse entries (existing + gatekeeper), got %d", len(ptu))
	}
}

func TestInstallCreatesBackup(t *testing.T) {
	_, settingsPath := setupHome(t, `{"model":"opus"}`)

	setup.Install("/usr/local/bin/claude-gatekeeper")

	matches, _ := filepath.Glob(settingsPath + ".backup.*")
	if len(matches) == 0 {
		t.Error("expected backup file to be created")
	}
}

func TestUninstall(t *testing.T) {
	existing := `{
		"model": "opus",
		"hooks": {
			"PreToolUse": [
				{
					"matcher": "",
					"hooks": [{"type":"command","command":"/home/user/.claude/hooks/claude-gatekeeper","timeout":10}]
				}
			]
		}
	}`
	_, settingsPath := setupHome(t, existing)

	if err := setup.Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	m := readJSON(t, settingsPath)

	// hooks key should be removed entirely since it's now empty.
	if _, ok := m["hooks"]; ok {
		t.Error("hooks key should be removed after uninstall")
	}

	// Other settings preserved.
	if m["model"] != "opus" {
		t.Errorf("model = %v, want opus", m["model"])
	}
}

func TestUninstallPreservesOtherHooks(t *testing.T) {
	existing := `{
		"hooks": {
			"PreToolUse": [
				{
					"matcher": "Bash",
					"hooks": [{"type":"command","command":"other-hook"}]
				},
				{
					"matcher": "",
					"hooks": [{"type":"command","command":"claude-gatekeeper","timeout":10}]
				}
			]
		}
	}`
	_, settingsPath := setupHome(t, existing)

	if err := setup.Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	m := readJSON(t, settingsPath)
	hooks := m["hooks"].(map[string]interface{})
	ptu := hooks["PreToolUse"].([]interface{})
	if len(ptu) != 1 {
		t.Errorf("expected 1 remaining PreToolUse entry, got %d", len(ptu))
	}
}

func TestUninstallNoSettings(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	// Should not error.
	if err := setup.Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
}

func TestInstallIdempotentWithPath(t *testing.T) {
	// Test that idempotent check works with full paths and flags.
	existing := `{
		"hooks": {
			"PreToolUse": [
				{
					"matcher": "",
					"hooks": [{"type":"command","command":"/home/user/.claude/hooks/claude-gatekeeper --debug","timeout":10}]
				}
			]
		}
	}`
	_, settingsPath := setupHome(t, existing)

	// Should detect the existing hook even with a different path/flags.
	setup.Install("/other/path/claude-gatekeeper")

	m := readJSON(t, settingsPath)
	hooks := m["hooks"].(map[string]interface{})
	ptu := hooks["PreToolUse"].([]interface{})
	if len(ptu) != 1 {
		t.Errorf("expected 1 PreToolUse entry (idempotent), got %d", len(ptu))
	}
}

func TestUninstallWithPathAndFlags(t *testing.T) {
	existing := `{
		"model": "opus",
		"hooks": {
			"PreToolUse": [
				{
					"matcher": "",
					"hooks": [{"type":"command","command":"/home/user/.claude/hooks/claude-gatekeeper --debug","timeout":10}]
				}
			]
		}
	}`
	_, settingsPath := setupHome(t, existing)

	if err := setup.Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	m := readJSON(t, settingsPath)
	if _, ok := m["hooks"]; ok {
		t.Error("hooks key should be removed after uninstall")
	}
}

func TestUninstallNoHook(t *testing.T) {
	_, _ = setupHome(t, `{"model":"opus"}`)

	// Should not error.
	if err := setup.Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
}
