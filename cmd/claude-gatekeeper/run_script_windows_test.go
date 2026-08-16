//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPowerShellRunScriptBootstrapFailurePostures(t *testing.T) {
	tests := []struct {
		name        string
		global      string
		project     string
		escape      bool
		wantExit    int
		wantPosture string
	}{
		{name: "missing config defaults deny", wantExit: 2, wantPosture: "default deny"},
		{name: "configured deny", global: `on_error = "deny"`, wantExit: 2, wantPosture: `on_error = "deny"`},
		{name: "configured abstain", global: `on_error = "abstain"`, wantExit: 0, wantPosture: `on_error = "abstain"`},
		{name: "project overrides global", global: `on_error = "deny"`, project: `on_error = "abstain"`, wantExit: 0, wantPosture: `on_error = "abstain"`},
		{name: "explicit bootstrap escape hatch", global: `on_error = "deny"`, escape: true, wantExit: 0, wantPosture: "GATEKEEPER_BOOTSTRAP_ABSTAIN=1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			project := filepath.Join(root, "project")
			home := filepath.Join(root, "home")
			pluginBin := filepath.Join(root, "plugin", "bin")
			for _, dir := range []string{pluginBin, project, filepath.Join(home, ".claude")} {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			source, err := os.ReadFile("../../bin/run.ps1")
			if err != nil {
				t.Fatal(err)
			}
			// Keep this runtime control local and deterministic: only the copied
			// fixture URL changes, so recovery reaches the posture branch quickly.
			fixture := strings.Replace(string(source),
				`$Url = "https://github.com/$Repo/releases/latest/download/$Asset"`,
				`$Url = "http://127.0.0.1:1/unavailable.zip"`, 1)
			runScript := filepath.Join(pluginBin, "run.ps1")
			if err := os.WriteFile(runScript, []byte(fixture), 0644); err != nil {
				t.Fatal(err)
			}
			if tc.global != "" {
				if err := os.WriteFile(filepath.Join(home, ".claude", "gatekeeper.toml"), []byte(tc.global+"\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.project != "" {
				if err := os.MkdirAll(filepath.Join(project, ".gatekeeper"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(project, ".gatekeeper", "gatekeeper.toml"), []byte(tc.project+"\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}

			cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", runScript)
			cmd.Dir = project
			cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"), "PATH="+filepath.Join(root, "empty-path"))
			if tc.escape {
				cmd.Env = append(cmd.Env, "GATEKEEPER_BOOTSTRAP_ABSTAIN=1")
			}
			output, runErr := cmd.CombinedOutput()
			gotExit := 0
			if exitErr, ok := runErr.(*exec.ExitError); ok {
				gotExit = exitErr.ExitCode()
			} else if runErr != nil {
				t.Fatalf("run PowerShell wrapper: %v", runErr)
			}
			if gotExit != tc.wantExit {
				t.Errorf("exit = %d, want %d; output:\n%s", gotExit, tc.wantExit, output)
			}
			if !strings.Contains(string(output), tc.wantPosture) {
				t.Errorf("output missing %q:\n%s", tc.wantPosture, output)
			}
		})
	}
}
