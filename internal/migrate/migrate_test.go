package migrate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jim80net/claude-gatekeeper/internal/migrate"
)

func TestMigrateFromSettings(t *testing.T) {
	homeDir := t.TempDir()
	claudeDir := filepath.Join(homeDir, ".claude")
	os.MkdirAll(claudeDir, 0755)

	settings := `{
		"permissions": {
			"allow": [
				"Bash(git add:*)",
				"Bash(curl:*)",
				"Bash(find:*)"
			],
			"deny": [
				"Bash(rm -rf:*)"
			]
		}
	}`
	settingsPath := filepath.Join(claudeDir, "settings.json")
	os.WriteFile(settingsPath, []byte(settings), 0644)

	outputPath := filepath.Join(homeDir, "output.toml")

	err := migrate.Run(settingsPath, outputPath)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	content := string(data)

	// Check that rules were generated.
	if !strings.Contains(content, "tool") {
		t.Error("output missing 'tool' field")
	}
	if !strings.Contains(content, "git add") {
		t.Error("output missing git add rule")
	}
	if !strings.Contains(content, "rm -rf") {
		t.Error("output missing rm -rf rule")
	}
	if !strings.Contains(content, `decision = "deny"`) {
		t.Error("output missing deny decision")
	}
	if !strings.Contains(content, `decision = "allow"`) {
		t.Error("output missing allow decision")
	}
}

func TestMigrateCreatesBackup(t *testing.T) {
	homeDir := t.TempDir()
	claudeDir := filepath.Join(homeDir, ".claude")
	os.MkdirAll(claudeDir, 0755)

	settings := `{"permissions":{"allow":["Bash(ls:*)"],"deny":[]}}`
	settingsPath := filepath.Join(claudeDir, "settings.json")
	os.WriteFile(settingsPath, []byte(settings), 0644)

	outputPath := filepath.Join(homeDir, "output.toml")
	os.WriteFile(outputPath, []byte("existing content"), 0644)

	err := migrate.Run(settingsPath, outputPath)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Verify backup was created.
	matches, _ := filepath.Glob(outputPath + ".backup.*")
	if len(matches) == 0 {
		t.Error("expected backup file to be created")
	}
}

func TestMigrateNoPermissions(t *testing.T) {
	homeDir := t.TempDir()
	claudeDir := filepath.Join(homeDir, ".claude")
	os.MkdirAll(claudeDir, 0755)

	settings := `{"model": "opus"}`
	settingsPath := filepath.Join(claudeDir, "settings.json")
	os.WriteFile(settingsPath, []byte(settings), 0644)

	outputPath := filepath.Join(homeDir, "output.toml")

	// Should not error, just report no rules.
	err := migrate.Run(settingsPath, outputPath)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestMigrateWithLocalSettings(t *testing.T) {
	homeDir := t.TempDir()
	claudeDir := filepath.Join(homeDir, ".claude")
	os.MkdirAll(claudeDir, 0755)

	mainSettings := `{"permissions":{"allow":["Bash(git:*)"],"deny":[]}}`
	localSettings := `{"permissions":{"allow":["Bash(docker:*)"],"deny":[]}}`

	os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(mainSettings), 0644)
	os.WriteFile(filepath.Join(claudeDir, "settings.local.json"), []byte(localSettings), 0644)

	outputPath := filepath.Join(homeDir, "output.toml")

	err := migrate.Run(filepath.Join(claudeDir, "settings.json"), outputPath)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	data, _ := os.ReadFile(outputPath)
	content := string(data)

	if !strings.Contains(content, "git") {
		t.Error("missing rule from main settings")
	}
	if !strings.Contains(content, "docker") {
		t.Error("missing rule from local settings")
	}
}
