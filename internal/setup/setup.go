// Package setup manages the hook registration in ~/.claude/settings.json.
package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const hookCommand = "claude-gatekeeper"

// Install adds the PreToolUse hook to settings.json.
// binaryPath is the absolute path to the installed binary.
func Install(binaryPath string) error {
	settingsPath, err := settingsFilePath()
	if err != nil {
		return err
	}

	settings, err := readSettingsMap(settingsPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", settingsPath, err)
	}
	if settings == nil {
		settings = map[string]interface{}{}
	}

	if hasGatekeeperHook(settings) {
		fmt.Fprintf(os.Stderr, "Hook already configured in %s\n", settingsPath)
		return nil
	}

	if err := backup(settingsPath); err != nil {
		return err
	}

	hookEntry := map[string]interface{}{
		"type":          "command",
		"command":       binaryPath,
		"timeout":       10,
		"statusMessage": "Checking permissions...",
	}

	matcherEntry := map[string]interface{}{
		"matcher": "",
		"hooks":   []interface{}{hookEntry},
	}

	hooks := getMap(settings, "hooks")
	preToolUse := getSlice(hooks, "PreToolUse")
	preToolUse = append(preToolUse, matcherEntry)
	hooks["PreToolUse"] = preToolUse
	settings["hooks"] = hooks

	if err := writeSettings(settingsPath, settings); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Hook installed in %s\n", settingsPath)
	return nil
}

// Uninstall removes the gatekeeper hook from settings.json.
func Uninstall() error {
	settingsPath, err := settingsFilePath()
	if err != nil {
		return err
	}

	settings, err := readSettingsMap(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "No settings file found at %s\n", settingsPath)
			return nil
		}
		return fmt.Errorf("reading %s: %w", settingsPath, err)
	}

	if !hasGatekeeperHook(settings) {
		fmt.Fprintf(os.Stderr, "No gatekeeper hook found in %s\n", settingsPath)
		return nil
	}

	if err := backup(settingsPath); err != nil {
		return err
	}

	removeGatekeeperHook(settings)

	if err := writeSettings(settingsPath, settings); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Hook removed from %s\n", settingsPath)
	return nil
}

func settingsFilePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(homeDir, ".claude", "settings.json"), nil
}

func readSettingsMap(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}
	return m, nil
}

func writeSettings(path string, settings map[string]interface{}) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling JSON: %w", err)
	}
	data = append(data, '\n')
	// Atomic write: write to temp file then rename to avoid corruption on crash.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func backup(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	backupPath := path + ".backup." + time.Now().Format("20060102-150405")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading for backup: %w", err)
	}
	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return fmt.Errorf("writing backup: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Backup: %s\n", backupPath)
	return nil
}

// hasGatekeeperHook checks if a gatekeeper hook is already configured.
// Uses non-mutating peekMap/peekSlice to avoid polluting settings on read.
func hasGatekeeperHook(settings map[string]interface{}) bool {
	hooks := peekMap(settings, "hooks")
	preToolUse := peekSlice(hooks, "PreToolUse")
	for _, entry := range preToolUse {
		if m, ok := entry.(map[string]interface{}); ok {
			for _, h := range peekSlice(m, "hooks") {
				if hm, ok := h.(map[string]interface{}); ok {
					if cmd, _ := hm["command"].(string); isGatekeeperCommand(cmd) {
						return true
					}
				}
			}
		}
	}
	return false
}

// removeGatekeeperHook removes gatekeeper entries from hooks.PreToolUse.
func removeGatekeeperHook(settings map[string]interface{}) {
	hooks := getMap(settings, "hooks")
	preToolUse := getSlice(hooks, "PreToolUse")

	var filtered []interface{}
	for _, entry := range preToolUse {
		m, ok := entry.(map[string]interface{})
		if !ok {
			filtered = append(filtered, entry)
			continue
		}
		innerHooks := getSlice(m, "hooks")
		var kept []interface{}
		for _, h := range innerHooks {
			hm, ok := h.(map[string]interface{})
			if !ok {
				kept = append(kept, h)
				continue
			}
			cmd, _ := hm["command"].(string)
			if !isGatekeeperCommand(cmd) {
				kept = append(kept, h)
			}
		}
		if len(kept) > 0 {
			m["hooks"] = kept
			filtered = append(filtered, m)
		}
		// If no hooks left in this matcher block, drop the whole block.
	}

	if len(filtered) > 0 {
		hooks["PreToolUse"] = filtered
	} else {
		delete(hooks, "PreToolUse")
	}

	if len(hooks) > 0 {
		settings["hooks"] = hooks
	} else {
		delete(settings, "hooks")
	}
}

func isGatekeeperCommand(cmd string) bool {
	if cmd == "" {
		return false
	}
	// The command field may include flags: "/path/to/claude-gatekeeper --debug"
	fields := strings.Fields(cmd)
	return filepath.Base(fields[0]) == hookCommand
}

// getMap returns settings[key] as a map, creating it if absent.
func getMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	v := map[string]interface{}{}
	m[key] = v
	return v
}

// getSlice returns m[key] as a slice, returning nil if absent.
func getSlice(m map[string]interface{}, key string) []interface{} {
	if v, ok := m[key].([]interface{}); ok {
		return v
	}
	return nil
}

// peekMap returns settings[key] as a map without mutating the parent.
func peekMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

// peekSlice returns m[key] as a slice without mutating the parent.
func peekSlice(m map[string]interface{}, key string) []interface{} {
	return getSlice(m, key) // getSlice is already non-mutating
}
