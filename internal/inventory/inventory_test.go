package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectEnumeratesLiveSurfacesAndReportsDrift(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "go", "bin", "claude-gatekeeper")
	writeFile(t, bin, "binary", 0755)
	writeHook(t, filepath.Join(home, ".grok", "hooks", "gatekeeper.json"), bin+" --harness grok")
	writeHook(t, filepath.Join(home, ".codex", "hooks.json"), bin+" --harness claude")
	writeHook(t, filepath.Join(home, ".claude", "settings.json"), bin)

	plugin := filepath.Join(home, ".claude", "plugins", "cache", "market", "claude-gatekeeper", "1.2.3")
	writeFile(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), `{"version":2,"plugins":{"claude-gatekeeper@market":[{"installPath":"`+plugin+`","version":"1.2.3"}]}}`, 0644)
	writeFile(t, filepath.Join(plugin, "hooks", "hooks.json"), `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"${CLAUDE_PLUGIN_ROOT}/bin/run.sh"}]}]}}`, 0644)
	writeFile(t, filepath.Join(plugin, "bin", "run.sh"), "#!/bin/sh\n", 0755)
	writeFile(t, filepath.Join(plugin, "bin", "claude-gatekeeper"), "binary", 0755)

	report, err := Collect(Options{
		Home:            home,
		ExpectedBinary:  bin,
		ExpectedVersion: "1.2.3",
		VersionProbe: func(path string) (string, error) {
			return "1.2.3", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Surfaces) != 4 {
		t.Fatalf("got %d surfaces: %#v", len(report.Surfaces), report.Surfaces)
	}
	var codex, pluginSurface Surface
	for _, surface := range report.Surfaces {
		switch surface.Kind {
		case "codex-global":
			codex = surface
		case "claude-plugin":
			pluginSurface = surface
		}
	}
	if codex.Harness != "claude" || !contains(codex.Drift, "harness: expected codex, got claude") {
		t.Fatalf("codex drift = %#v", codex)
	}
	if pluginSurface.BinaryPath != filepath.Join(plugin, "bin", "claude-gatekeeper") {
		t.Fatalf("plugin binary = %q", pluginSurface.BinaryPath)
	}
	if len(pluginSurface.Drift) != 0 {
		t.Fatalf("plugin drift = %#v", pluginSurface.Drift)
	}
	if report.OK {
		t.Fatal("report should not be OK when a surface has drift")
	}
}

func TestCollectExcludesStalePluginCacheVersions(t *testing.T) {
	home := t.TempDir()
	live := filepath.Join(home, ".claude", "plugins", "cache", "market", "claude-gatekeeper", "2.0.0")
	stale := filepath.Join(home, ".claude", "plugins", "cache", "market", "claude-gatekeeper", "1.0.0")
	writeFile(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), `{"version":2,"plugins":{"claude-gatekeeper@market":[{"installPath":"`+live+`"}]}}`, 0644)
	for _, root := range []string{live, stale} {
		writeFile(t, filepath.Join(root, "hooks", "hooks.json"), `{"hooks":{"PreToolUse":[{"hooks":[{"command":"${CLAUDE_PLUGIN_ROOT}/bin/run.sh"}]}]}}`, 0644)
		writeFile(t, filepath.Join(root, "bin", "claude-gatekeeper"), "binary", 0755)
	}
	report, err := Collect(Options{Home: home, ExpectedVersion: "2.0.0", VersionProbe: func(string) (string, error) { return "2.0.0", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Surfaces) != 1 || !strings.Contains(report.Surfaces[0].ConfigPath, "2.0.0") {
		t.Fatalf("surfaces = %#v", report.Surfaces)
	}
}

func TestCollectFlagsInstalledButUntrustedCodexHook(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "claude-gatekeeper")
	writeFile(t, bin, "binary", 0755)
	writeHook(t, filepath.Join(home, ".codex", "hooks.json"), bin+" --harness codex")
	report, err := Collect(Options{Home: home, ExpectedBinary: bin, VersionProbe: func(string) (string, error) { return "v", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if report.OK || len(report.Surfaces) != 1 || !contains(report.Surfaces[0].Drift, "trust: hook is installed but untrusted; Codex will silently skip it") {
		t.Fatalf("report = %#v", report)
	}
}

func TestCollectExcludesForeignPluginRunWrapper(t *testing.T) {
	home := t.TempDir()
	foreign := filepath.Join(home, ".claude", "plugins", "cache", "market", "foreign", "1.0.0")
	writeFile(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), `{"version":2,"plugins":{"foreign@market":[{"installPath":"`+foreign+`"}]}}`, 0644)
	writeFile(t, filepath.Join(foreign, "hooks", "hooks.json"), `{"hooks":{"PreToolUse":[{"hooks":[{"command":"${CLAUDE_PLUGIN_ROOT}/bin/run.sh"}]}]}}`, 0644)
	report, err := Collect(Options{Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Surfaces) != 0 || len(report.Files) != 0 {
		t.Fatalf("foreign plugin leaked into report: %#v", report)
	}
}

func TestCollectRecognizesEnvPrefixAndQuotedBinaryPath(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "path with spaces", "claude-gatekeeper")
	writeFile(t, bin, "binary", 0755)
	writeHook(t, filepath.Join(home, ".grok", "hooks", "gatekeeper.json"), `GATEKEEPER_HARNESS=grok "`+bin+`"`)
	report, err := Collect(Options{Home: home, ExpectedBinary: bin, ExpectedVersion: "v", MinSurfaces: 1, VersionProbe: func(string) (string, error) { return "v", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK || len(report.Surfaces) != 1 || report.Surfaces[0].Harness != "grok" || report.Surfaces[0].BinaryPath != bin {
		t.Fatalf("report = %#v", report)
	}
	if report.Files[0].CommandsSeen != 1 || report.Files[0].Recognized != 1 {
		t.Fatalf("file summary = %#v", report.Files[0])
	}
}

func TestCollectParsesHarnessFlagFormsFailClosed(t *testing.T) {
	tests := []struct {
		name             string
		flag             string
		wantRecognized   int
		wantUnrecognized int
	}{
		{name: "single dash", flag: "-harness grok", wantRecognized: 1},
		{name: "single dash equals", flag: "-harness=grok", wantRecognized: 1},
		{name: "double dash separated", flag: "--harness grok", wantRecognized: 1},
		{name: "double dash equals", flag: "--harness=grok", wantRecognized: 1},
		{name: "malformed single dash", flag: "-harness:grok", wantUnrecognized: 1},
		{name: "missing harness value", flag: "--harness", wantUnrecognized: 1},
		{name: "flag shaped harness value", flag: "--harness --json", wantUnrecognized: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			bin := filepath.Join(home, "claude-gatekeeper")
			writeFile(t, bin, "binary", 0755)
			writeHook(t, filepath.Join(home, ".grok", "hooks", "gatekeeper.json"), bin+" "+tc.flag)

			report, err := Collect(Options{Home: home, ExpectedBinary: bin, MinSurfaces: tc.wantRecognized, VersionProbe: func(string) (string, error) { return "v", nil }})
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Files) != 1 || report.Files[0].Recognized != tc.wantRecognized || len(report.Files[0].Unrecognized) != tc.wantUnrecognized {
				t.Fatalf("report = %#v", report)
			}
			if tc.wantRecognized == 1 && (!report.OK || len(report.Surfaces) != 1 || report.Surfaces[0].Harness != "grok") {
				t.Fatalf("recognized report = %#v", report)
			}
			if tc.wantUnrecognized == 1 && (report.OK || len(report.Files[0].Warnings) == 0) {
				t.Fatalf("malformed harness flag was not visibly rejected: %#v", report)
			}
		})
	}
}

func TestCollectResolvesBareGatekeeperCommandThroughPATH(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "bin", "claude-gatekeeper")
	writeFile(t, bin, "binary", 0755)
	writeHook(t, filepath.Join(home, ".grok", "hooks", "gatekeeper.json"), "claude-gatekeeper --harness grok")

	var probed string
	report, err := Collect(Options{
		Home:            home,
		ExpectedBinary:  bin,
		ExpectedVersion: "v",
		MinSurfaces:     1,
		LookPath: func(command string) (string, error) {
			if command != "claude-gatekeeper" {
				t.Fatalf("look path command = %q", command)
			}
			return bin, nil
		},
		VersionProbe: func(path string) (string, error) {
			probed = path
			return "v", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK || len(report.Surfaces) != 1 {
		t.Fatalf("report = %#v", report)
	}
	if got := report.Surfaces[0].BinaryPath; got != bin {
		t.Fatalf("binary path = %q, want %q", got, bin)
	}
	if probed != bin {
		t.Fatalf("version probe path = %q, want %q", probed, bin)
	}
}

func TestCollectFailsClosedOnUnexpectedShapeAndUnrecognizedGatekeeper(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".grok", "hooks", "gatekeeper.json"), `{"hooks":{"PreToolUse":{"command":"/opt/claude-gatekeeper"}}}`, 0644)
	writeHook(t, filepath.Join(home, ".codex", "hooks.json"), `'unterminated-claude-gatekeeper`)
	report, err := Collect(Options{Home: home, MinSurfaces: 1})
	if err != nil {
		t.Fatal(err)
	}
	if report.OK || len(report.Files) != 2 {
		t.Fatalf("report = %#v", report)
	}
	var shapeFile FileSummary
	for _, file := range report.Files {
		if strings.Contains(file.Path, ".grok") {
			shapeFile = file
		}
	}
	if shapeFile.CommandsSeen != 1 || shapeFile.Recognized != 1 {
		t.Fatalf("unexpected-shape coverage = %#v", shapeFile)
	}
	if len(report.Files[0].Warnings) == 0 && len(report.Files[1].Warnings) == 0 {
		t.Fatal("expected per-file warnings")
	}
}

func TestCollectTreatsSymlinkedExpectedBinaryAsSamePath(t *testing.T) {
	home := t.TempDir()
	realBin := filepath.Join(home, "real", "claude-gatekeeper")
	linkBin := filepath.Join(home, "bin", "claude-gatekeeper")
	writeFile(t, realBin, "binary", 0755)
	if err := os.MkdirAll(filepath.Dir(linkBin), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realBin, linkBin); err != nil {
		t.Fatal(err)
	}
	writeHook(t, filepath.Join(home, ".claude", "settings.json"), linkBin)
	report, err := Collect(Options{Home: home, ExpectedBinary: realBin, VersionProbe: func(string) (string, error) { return "v", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Surfaces) != 1 || len(report.Surfaces[0].Drift) != 0 {
		t.Fatalf("surface = %#v", report.Surfaces)
	}
}

func TestProbeVersionTimesOutAndIncludesOutput(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "claude-gatekeeper")
	writeFile(t, bin, "#!/bin/sh\necho wedged >&2\nwhile :; do :; done\n", 0755)
	_, err := probeVersionWithTimeout(bin, 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") || !strings.Contains(err.Error(), "wedged") {
		t.Fatalf("error = %v", err)
	}
}

func TestProbeVersionBoundsGrandchildHoldingPipe(t *testing.T) {
	t.Run("clean child output remains successful", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), "claude-gatekeeper")
		writeFile(t, bin, "#!/bin/sh\necho 'claude-gatekeeper healthy'\nsleep 5 &\n", 0755)
		started := time.Now()
		version, err := probeVersionWithTimeout(bin, 500*time.Millisecond)
		if err != nil || version != "healthy" {
			t.Fatalf("version = %q, error = %v", version, err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("probe held by inherited pipe for %s", elapsed)
		}
	})

	t.Run("killed child and inherited pipe are bounded", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), "claude-gatekeeper")
		writeFile(t, bin, "#!/bin/sh\necho wedged >&2\nsleep 5\n", 0755)
		started := time.Now()
		_, err := probeVersionWithTimeout(bin, 20*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "timed out") || !strings.Contains(err.Error(), "wedged") {
			t.Fatalf("error = %v", err)
		}
		if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
			t.Fatalf("probe held by inherited pipe for %s", elapsed)
		}
	})
}

func TestCollectIgnoresNonGatekeeperHooksAndMissingSurfaces(t *testing.T) {
	home := t.TempDir()
	writeHook(t, filepath.Join(home, ".claude", "settings.json"), "/opt/other-hook")
	report, err := Collect(Options{Home: home, ExpectedBinary: "/bin/claude-gatekeeper", ExpectedVersion: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Surfaces) != 0 || !report.OK {
		t.Fatalf("report = %#v", report)
	}
}

func TestCollectReportsAllUnreadableOrInvalidHookFiles(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".grok", "hooks", "gatekeeper.json"), "{", 0644)
	writeFile(t, filepath.Join(home, ".codex", "hooks.json"), "not json", 0644)
	bin := filepath.Join(home, "bin", "claude-gatekeeper")
	writeFile(t, bin, "binary", 0755)
	writeHook(t, filepath.Join(home, ".claude", "settings.json"), bin)

	report, err := Collect(Options{
		Home:           home,
		ExpectedBinary: bin,
		VersionProbe:   func(string) (string, error) { return "dev", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.OK || !report.HasFileErrors() {
		t.Fatalf("report status = OK:%v, HasFileErrors:%v", report.OK, report.HasFileErrors())
	}
	if len(report.Files) != 3 || len(report.Surfaces) != 1 {
		t.Fatalf("files = %#v, surfaces = %#v", report.Files, report.Surfaces)
	}

	errorsByPath := map[string]string{}
	for _, file := range report.Files {
		if file.Error != "" {
			errorsByPath[file.Path] = file.Error
		}
	}
	for _, path := range []string{
		filepath.Join(home, ".grok", "hooks", "gatekeeper.json"),
		filepath.Join(home, ".codex", "hooks.json"),
	} {
		if errorsByPath[path] == "" {
			t.Errorf("missing file error for %s: %#v", path, report.Files)
		}
	}
}

func TestWriteJSONAndTable(t *testing.T) {
	report := Report{OK: true, ExpectedVersion: "1.0.0", Surfaces: []Surface{{
		Kind: "grok-global", ConfigPath: "/home/me/.grok/hooks/gatekeeper.json",
		BinaryPath: "/home/me/bin/claude-gatekeeper", Version: "1.0.0", Harness: "grok",
	}}}
	var jsonOut strings.Builder
	if err := WriteJSON(&jsonOut, report); err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal([]byte(jsonOut.String()), &decoded); err != nil || !decoded.OK {
		t.Fatalf("json = %q, err = %v", jsonOut.String(), err)
	}
	var table strings.Builder
	if err := WriteTable(&table, report); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SURFACE", "grok-global", "1.0.0", "OK"} {
		if !strings.Contains(table.String(), want) {
			t.Errorf("table missing %q:\n%s", want, table.String())
		}
	}
}

func TestPublishedVersionInvariantNegativeControls(t *testing.T) {
	t.Run("stale binary names both versions", func(t *testing.T) {
		home := t.TempDir()
		bin := filepath.Join(home, "bin", "claude-gatekeeper")
		writeFile(t, bin, "#!/bin/sh\necho 'claude-gatekeeper 1.5.1'\n", 0755)
		writeHook(t, filepath.Join(home, ".claude", "settings.json"), bin)
		report, err := Collect(Options{Home: home, ExpectedBinary: bin, MinSurfaces: 1, PublishedVersionProbe: func() (string, error) { return "v1.6.0", nil }})
		if err != nil {
			t.Fatal(err)
		}
		if report.OK || report.VersionInvariant.Status != "fail" || !strings.Contains(report.VersionInvariant.Reason, "1.5.1") || !strings.Contains(report.VersionInvariant.Reason, "1.6.0") {
			t.Fatalf("invariant = %#v", report.VersionInvariant)
		}
	})

	t.Run("unreachable published source is unknown", func(t *testing.T) {
		home := t.TempDir()
		bin := filepath.Join(home, "bin", "claude-gatekeeper")
		writeFile(t, bin, "#!/bin/sh\necho 'claude-gatekeeper 1.6.0'\n", 0755)
		writeHook(t, filepath.Join(home, ".claude", "settings.json"), bin)
		report, err := Collect(Options{Home: home, MinSurfaces: 1, PublishedVersionProbe: func() (string, error) { return "", errors.New("offline") }})
		if err != nil {
			t.Fatal(err)
		}
		if report.OK || report.VersionInvariant.Status != "unknown" || !strings.Contains(report.VersionInvariant.Reason, "offline") {
			t.Fatalf("invariant = %#v", report.VersionInvariant)
		}
	})

	t.Run("non executable binary is unknown without derived version", func(t *testing.T) {
		home := t.TempDir()
		bin := filepath.Join(home, "cache", "1.3.1", "bin", "claude-gatekeeper")
		writeFile(t, bin, "not executable", 0644)
		writeHook(t, filepath.Join(home, ".claude", "settings.json"), bin)
		report, err := Collect(Options{Home: home, MinSurfaces: 1, PublishedVersionProbe: func() (string, error) { return "v1.6.0", nil }})
		if err != nil {
			t.Fatal(err)
		}
		observation := report.VersionInvariant.Observations[0]
		if report.OK || report.VersionInvariant.Status != "unknown" || observation.ObservedVersion != "" || observation.PathVersion != "" {
			t.Fatalf("invariant = %#v", report.VersionInvariant)
		}
		var output strings.Builder
		if err := WriteJSON(&output, report); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), `"observed_version": "1.3.1"`) || strings.Contains(output.String(), `"path_version"`) {
			t.Fatalf("output derived a version from the path: %s", output.String())
		}
	})

	t.Run("plugin directory mismatch is not current", func(t *testing.T) {
		home := t.TempDir()
		plugin := filepath.Join(home, ".claude", "plugins", "cache", "market", "claude-gatekeeper", "1.3.1")
		writeFile(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), `{"plugins":{"claude-gatekeeper@market":[{"installPath":"`+plugin+`"}]}}`, 0644)
		writeFile(t, filepath.Join(plugin, "hooks", "hooks.json"), `{"hooks":{"PreToolUse":[{"hooks":[{"command":"${CLAUDE_PLUGIN_ROOT}/bin/run.sh"}]}]}}`, 0644)
		writeFile(t, filepath.Join(plugin, "bin", "claude-gatekeeper"), "#!/bin/sh\necho 'claude-gatekeeper 1.5.1'\n", 0755)
		report, err := Collect(Options{Home: home, MinSurfaces: 1, PublishedVersionProbe: func() (string, error) { return "v1.6.0", nil }})
		if err != nil {
			t.Fatal(err)
		}
		observation := report.VersionInvariant.Observations[0]
		if report.OK || report.VersionInvariant.Status != "fail" || observation.PathVersion != "1.3.1" || observation.ObservedVersion != "1.5.1" || !strings.Contains(observation.Reason, "published latest 1.6.0") || !strings.Contains(observation.Reason, "plugin path version 1.3.1") {
			t.Fatalf("invariant = %#v", report.VersionInvariant)
		}
	})
}

func TestFetchPublishedLatest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("missing user agent")
		}
		_, _ = w.Write([]byte(`{"tag_name":"v1.6.0"}`))
	}))
	defer server.Close()
	version, err := FetchPublishedLatest(context.Background(), server.Client(), server.URL)
	if err != nil || version != "v1.6.0" {
		t.Fatalf("version=%q err=%v", version, err)
	}
}

func TestWriteTableIncludesFileErrors(t *testing.T) {
	report := Report{Files: []FileSummary{{Path: "/tmp/hooks.json", Error: "invalid JSON"}}}
	var table strings.Builder
	if err := WriteTable(&table, report); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/tmp/hooks.json", "error: invalid JSON"} {
		if !strings.Contains(table.String(), want) {
			t.Errorf("table missing %q:\n%s", want, table.String())
		}
	}
}

func TestEmptyJSONUsesArraysAndTableHasNoSurfaceHeader(t *testing.T) {
	home := t.TempDir()
	writeHook(t, filepath.Join(home, ".claude", "settings.json"), "/opt/other-hook")
	report, err := Collect(Options{Home: home, MinSurfaces: 1})
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := WriteJSON(&out, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `"surfaces": null`) || !strings.Contains(out.String(), `"surfaces": []`) || strings.Contains(out.String(), `"warnings": null`) {
		t.Fatalf("json = %s", out.String())
	}
	out.Reset()
	if err := WriteTable(&out, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "SURFACE") || !strings.Contains(out.String(), "WARNING") {
		t.Fatalf("table = %q", out.String())
	}
}

func TestWriteTablePropagatesWriterErrors(t *testing.T) {
	want := errors.New("write failed")
	for _, tc := range []struct {
		name   string
		report Report
	}{
		{"surface table flush", Report{Surfaces: []Surface{{Kind: "claude-settings"}}}},
		{"file table separator", Report{Files: []FileSummary{{Path: "/tmp/hooks.json"}}}},
		{"warning", Report{Warnings: []string{"drift"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := WriteTable(errorWriter{err: want}, tc.report)
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
		})
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestCollectSurfaceOrderIsStableByCommand(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "claude-gatekeeper")
	writeFile(t, bin, "binary", 0755)
	config := map[string]any{"hooks": map[string]any{"PreToolUse": []any{
		map[string]any{"hooks": []any{map[string]any{"command": bin + " --debug"}}},
		map[string]any{"hooks": []any{map[string]any{"command": bin}}},
	}}}
	data, _ := json.Marshal(config)
	writeFile(t, filepath.Join(home, ".claude", "settings.json"), string(data), 0644)
	report, err := Collect(Options{Home: home, ExpectedBinary: bin, VersionProbe: func(string) (string, error) { return "v", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Surfaces) != 2 || report.Surfaces[0].Command != bin || report.Surfaces[1].Command != bin+" --debug" {
		t.Fatalf("commands = %#v", report.Surfaces)
	}
}

func TestCollectEffectiveClaudeRootContract(t *testing.T) {
	probe := func(string) (string, error) { return "v", nil }
	makeEmptyRoot := func(t *testing.T, root string) {
		t.Helper()
		writeFile(t, filepath.Join(root, "settings.json"), `{"hooks":{}}`, 0644)
		writeFile(t, filepath.Join(root, "plugins", "installed_plugins.json"), `{"plugins":{}}`, 0644)
	}
	makeDirectRoot := func(t *testing.T, root, bin string) {
		t.Helper()
		writeFile(t, bin, "binary", 0755)
		writeHook(t, filepath.Join(root, "settings.json"), bin)
		writeFile(t, filepath.Join(root, "plugins", "installed_plugins.json"), `{"plugins":{}}`, 0644)
	}
	makePluginRoot := func(t *testing.T, root string) string {
		t.Helper()
		plugin := filepath.Join(root, "plugins", "cache", "market", "claude-gatekeeper", "v")
		writeFile(t, filepath.Join(root, "settings.json"), `{"hooks":{}}`, 0644)
		writeFile(t, filepath.Join(root, "plugins", "installed_plugins.json"), `{"plugins":{"claude-gatekeeper@market":[{"installPath":"`+plugin+`"}]}}`, 0644)
		writeFile(t, filepath.Join(plugin, "hooks", "hooks.json"), `{"hooks":{"PreToolUse":[{"hooks":[{"command":"${CLAUDE_PLUGIN_ROOT}/bin/run.sh"}]}]}}`, 0644)
		writeFile(t, filepath.Join(plugin, "bin", "claude-gatekeeper"), "binary", 0755)
		return plugin
	}

	t.Run("default root plugin", func(t *testing.T) {
		home := t.TempDir()
		root := filepath.Join(home, ".claude")
		plugin := makePluginRoot(t, root)
		report, err := Collect(Options{Home: home, RequiredHarness: "claude", ExpectedVersion: "v", MinSurfaces: 1, VersionProbe: probe})
		if err != nil || !report.OK || report.ClaudeRoot != root || report.ClaudeRootSource != "default" || report.ClaudeRegistration.Status != "registered" || len(report.ClaudeRegistration.Sources) != 1 || !strings.HasPrefix(report.ClaudeRegistration.Sources[0].Path, plugin) {
			t.Fatalf("report=%#v err=%v", report, err)
		}
	})

	t.Run("alternate root excludes default proof and globals cannot rescue", func(t *testing.T) {
		home := t.TempDir()
		makePluginRoot(t, filepath.Join(home, ".claude"))
		t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, "environment-root"))
		bin := filepath.Join(home, "claude-gatekeeper")
		writeFile(t, bin, "binary", 0755)
		writeHook(t, filepath.Join(home, ".codex", "hooks.json"), bin+" --harness codex")
		writeHook(t, filepath.Join(home, ".grok", "hooks", "gatekeeper.json"), bin+" --harness grok")
		alternate := filepath.Join(home, "alternate")
		makeEmptyRoot(t, alternate)
		report, err := Collect(Options{Home: home, ClaudeRoot: alternate, ClaudeRootSource: "cli", RequiredHarness: "claude", ExpectedVersion: "v", MinSurfaces: 1, VersionProbe: probe})
		if err != nil || report.OK || report.ClaudeRoot != alternate || report.ClaudeRootSource != "cli" || report.ClaudeRegistration.Status != "absent" || len(report.Surfaces) != 2 {
			t.Fatalf("report=%#v err=%v", report, err)
		}
		for _, surface := range report.Surfaces {
			if surface.Scope != "host-global" || strings.HasPrefix(surface.ConfigPath, filepath.Join(home, ".claude")) {
				t.Fatalf("default Claude proof leaked: %#v", surface)
			}
		}
	})

	t.Run("alternate registry cannot credit plugin outside selected root", func(t *testing.T) {
		home := t.TempDir()
		defaultRoot := filepath.Join(home, ".claude")
		defaultPlugin := makePluginRoot(t, defaultRoot)
		alternate := filepath.Join(home, "alternate")
		writeFile(t, filepath.Join(alternate, "settings.json"), `{"hooks":{}}`, 0644)
		writeFile(t, filepath.Join(alternate, "plugins", "installed_plugins.json"), `{"plugins":{"claude-gatekeeper@market":[{"installPath":"`+defaultPlugin+`"}]}}`, 0644)
		report, err := Collect(Options{Home: home, ClaudeRoot: alternate, RequiredHarness: "claude", ExpectedVersion: "v", MinSurfaces: 1, VersionProbe: probe})
		if err != nil || report.OK || report.ClaudeRegistration.Status != "error" || len(report.ClaudeRegistration.Sources) != 0 || !report.HasFileErrors() {
			t.Fatalf("report=%#v err=%v", report, err)
		}
		if len(report.ClaudeRegistration.Errors) != 1 || !strings.Contains(report.ClaudeRegistration.Errors[0], "outside selected Claude root") {
			t.Fatalf("registration errors=%#v", report.ClaudeRegistration.Errors)
		}
		for _, surface := range report.Surfaces {
			if surface.Scope == "effective-claude-root" {
				t.Fatalf("outside plugin became effective evidence: %#v", surface)
			}
		}
	})

	t.Run("alternate registry cannot escape selected root through symlink", func(t *testing.T) {
		home := t.TempDir()
		defaultPlugin := makePluginRoot(t, filepath.Join(home, ".claude"))
		alternate := filepath.Join(home, "alternate")
		linkedPlugin := filepath.Join(alternate, "plugins", "cache", "linked-gatekeeper")
		if err := os.MkdirAll(filepath.Dir(linkedPlugin), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(defaultPlugin, linkedPlugin); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(alternate, "settings.json"), `{"hooks":{}}`, 0644)
		writeFile(t, filepath.Join(alternate, "plugins", "installed_plugins.json"), `{"plugins":{"claude-gatekeeper@market":[{"installPath":"`+linkedPlugin+`"}]}}`, 0644)
		report, err := Collect(Options{Home: home, ClaudeRoot: alternate, RequiredHarness: "claude", MinSurfaces: 1})
		if err != nil || report.OK || report.ClaudeRegistration.Status != "error" || len(report.ClaudeRegistration.Sources) != 0 || !report.HasFileErrors() || !strings.Contains(strings.Join(report.ClaudeRegistration.Errors, " "), "outside selected Claude root") {
			t.Fatalf("report=%#v err=%v", report, err)
		}
	})

	t.Run("alternate registry cannot credit lexical prefix sibling", func(t *testing.T) {
		home := t.TempDir()
		alternate := filepath.Join(home, "alternate")
		siblingPlugin := makePluginRoot(t, filepath.Join(home, "alternate-sibling"))
		writeFile(t, filepath.Join(alternate, "settings.json"), `{"hooks":{}}`, 0644)
		writeFile(t, filepath.Join(alternate, "plugins", "installed_plugins.json"), `{"plugins":{"claude-gatekeeper@market":[{"installPath":"`+siblingPlugin+`"}]}}`, 0644)
		report, err := Collect(Options{Home: home, ClaudeRoot: alternate, RequiredHarness: "claude", MinSurfaces: 1})
		if err != nil || report.OK || report.ClaudeRegistration.Status != "error" || len(report.ClaudeRegistration.Sources) != 0 || !report.HasFileErrors() || !strings.Contains(strings.Join(report.ClaudeRegistration.Errors, " "), "outside selected Claude root") {
			t.Fatalf("report=%#v err=%v", report, err)
		}
	})

	t.Run("alternate registry fails closed on unresolvable install ancestry", func(t *testing.T) {
		home := t.TempDir()
		alternate := filepath.Join(home, "alternate")
		missingPlugin := filepath.Join(alternate, "plugins", "cache", "missing-gatekeeper")
		writeFile(t, filepath.Join(alternate, "settings.json"), `{"hooks":{}}`, 0644)
		writeFile(t, filepath.Join(alternate, "plugins", "installed_plugins.json"), `{"plugins":{"claude-gatekeeper@market":[{"installPath":"`+missingPlugin+`"}]}}`, 0644)
		report, err := Collect(Options{Home: home, ClaudeRoot: alternate, RequiredHarness: "claude", MinSurfaces: 1})
		if err != nil || report.OK || report.ClaudeRegistration.Status != "error" || len(report.ClaudeRegistration.Sources) != 0 || !report.HasFileErrors() || !strings.Contains(strings.Join(report.ClaudeRegistration.Errors, " "), "resolve install path symlinks") {
			t.Fatalf("report=%#v err=%v", report, err)
		}
	})

	t.Run("environment root plugin", func(t *testing.T) {
		home := t.TempDir()
		alternate := filepath.Join(home, "alternate")
		makePluginRoot(t, alternate)
		t.Setenv("CLAUDE_CONFIG_DIR", alternate)
		report, err := Collect(Options{Home: home, RequiredHarness: "claude", ExpectedVersion: "v", MinSurfaces: 1, VersionProbe: probe})
		if err != nil || !report.OK || report.ClaudeRoot != alternate || report.ClaudeRootSource != "environment" || report.ClaudeRegistration.Status != "registered" {
			t.Fatalf("report=%#v err=%v", report, err)
		}
	})

	t.Run("direct hook registration and output bounds", func(t *testing.T) {
		home := t.TempDir()
		root := filepath.Join(home, "alternate")
		bin := filepath.Join(home, "claude-gatekeeper")
		makeDirectRoot(t, root, bin)
		report, err := Collect(Options{Home: home, ClaudeRoot: root, RequiredHarness: "claude", ExpectedBinary: bin, ExpectedVersion: "v", MinSurfaces: 1, VersionProbe: probe})
		if err != nil || !report.OK || report.ClaudeRegistration.Status != "registered" || report.ClaudeRegistration.Sources[0].Kind != "claude-settings" || report.ClaudeRegistration.FiringStatus != "not_tested" {
			t.Fatalf("report=%#v err=%v", report, err)
		}
		var table strings.Builder
		if err := WriteTable(&table, report); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{root, "CLAUDE REGISTRATION: REGISTERED", "FIRING: NOT_TESTED", "effective-claude-root", "claude-settings"} {
			if !strings.Contains(table.String(), want) {
				t.Errorf("table missing %q: %s", want, table.String())
			}
		}
	})

	t.Run("missing and malformed roots fail closed structurally", func(t *testing.T) {
		home := t.TempDir()
		for name, prepare := range map[string]func(string){
			"missing root": func(string) {},
			"missing registry": func(root string) {
				writeFile(t, filepath.Join(root, "settings.json"), `{"hooks":{}}`, 0644)
			},
			"malformed settings": func(root string) {
				writeFile(t, filepath.Join(root, "settings.json"), "{", 0644)
				writeFile(t, filepath.Join(root, "plugins", "installed_plugins.json"), `{"plugins":{}}`, 0644)
			},
			"malformed registry": func(root string) {
				writeFile(t, filepath.Join(root, "settings.json"), `{"hooks":{}}`, 0644)
				writeFile(t, filepath.Join(root, "plugins", "installed_plugins.json"), "{", 0644)
			},
			"unreadable settings": func(root string) {
				makeEmptyRoot(t, root)
				if err := os.Remove(filepath.Join(root, "settings.json")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(root, "settings.json"), 0755); err != nil {
					t.Fatal(err)
				}
			},
			"unreadable registry": func(root string) {
				writeFile(t, filepath.Join(root, "settings.json"), `{"hooks":{}}`, 0644)
				if err := os.MkdirAll(filepath.Join(root, "plugins", "installed_plugins.json"), 0755); err != nil {
					t.Fatal(err)
				}
			},
		} {
			t.Run(name, func(t *testing.T) {
				root := filepath.Join(home, name)
				prepare(root)
				report, err := Collect(Options{Home: home, ClaudeRoot: root, RequiredHarness: "claude", MinSurfaces: 1, VersionProbe: probe})
				if err != nil || report.OK || report.ClaudeRegistration.Status != "error" || !report.HasFileErrors() || len(report.ClaudeRegistration.Errors) == 0 {
					t.Fatalf("report=%#v err=%v", report, err)
				}
			})
		}
	})

	t.Run("explicit non Claude target remains compatible", func(t *testing.T) {
		home := t.TempDir()
		bin := filepath.Join(home, "claude-gatekeeper")
		writeFile(t, bin, "binary", 0755)
		writeHook(t, filepath.Join(home, ".grok", "hooks", "gatekeeper.json"), bin+" --harness grok")
		report, err := Collect(Options{Home: home, RequiredHarness: "grok", ExpectedBinary: bin, ExpectedVersion: "v", MinSurfaces: 1, VersionProbe: probe})
		if err != nil || !report.OK || report.RequiredHarness != "grok" {
			t.Fatalf("report=%#v err=%v", report, err)
		}
	})
}

func writeHook(t *testing.T, path, command string) {
	t.Helper()
	data, _ := json.Marshal(map[string]any{"hooks": map[string]any{"PreToolUse": []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": command}}}}}})
	writeFile(t, path, string(data), 0644)
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
