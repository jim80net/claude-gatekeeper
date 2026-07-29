// Package inventory inspects live gatekeeper hook registrations without modifying them.
package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jim80net/claude-gatekeeper/internal/codextrust"
)

const binaryName = "claude-gatekeeper"

// Options controls hook discovery and drift expectations.
type Options struct {
	Home            string
	ExpectedBinary  string
	ExpectedVersion string
	MinSurfaces     int
	VersionProbe    func(string) (string, error)
	LookPath        func(string) (string, error)
}

// Report is the machine-readable result of a hook inventory.
type Report struct {
	OK              bool          `json:"ok"`
	ExpectedBinary  string        `json:"expected_binary"`
	ExpectedVersion string        `json:"expected_version"`
	MinSurfaces     int           `json:"min_surfaces"`
	Warnings        []string      `json:"warnings"`
	Files           []FileSummary `json:"files"`
	Surfaces        []Surface     `json:"surfaces"`
}

// FileSummary reports discovery coverage for one existing hook file.
type FileSummary struct {
	Path         string   `json:"path"`
	CommandsSeen int      `json:"commands_seen"`
	Recognized   int      `json:"commands_recognized"`
	Unrecognized []string `json:"unrecognized_commands"`
	Warnings     []string `json:"warnings"`
	Error        string   `json:"error,omitempty"`
}

// Surface describes one recognized live gatekeeper command and its drift.
type Surface struct {
	Kind            string   `json:"surface"`
	ConfigPath      string   `json:"config_path"`
	Command         string   `json:"command"`
	BinaryPath      string   `json:"binary_path"`
	Version         string   `json:"version,omitempty"`
	Harness         string   `json:"harness"`
	ExpectedBinary  string   `json:"expected_binary"`
	ExpectedHarness string   `json:"expected_harness"`
	Drift           []string `json:"drift"`
}

type candidate struct {
	kind, path, expectedHarness, pluginRoot string
}

// Collect inventories known live user-level hook surfaces and evaluates drift.
func Collect(opts Options) (Report, error) {
	if opts.Home == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Report{}, fmt.Errorf("determine home: %w", err)
		}
		opts.Home = home
	}
	if opts.VersionProbe == nil {
		opts.VersionProbe = probeVersion
	}
	if opts.LookPath == nil {
		opts.LookPath = exec.LookPath
	}
	report := Report{
		OK: true, ExpectedBinary: cleanPath(opts.ExpectedBinary), ExpectedVersion: opts.ExpectedVersion,
		MinSurfaces: opts.MinSurfaces, Warnings: []string{}, Files: []FileSummary{}, Surfaces: []Surface{},
	}
	candidates := []candidate{
		{"grok-global", filepath.Join(opts.Home, ".grok", "hooks", "gatekeeper.json"), "grok", ""},
		{"codex-global", filepath.Join(opts.Home, ".codex", "hooks.json"), "codex", ""},
	}
	settingsPaths, err := filepath.Glob(filepath.Join(opts.Home, ".claude", "settings*.json"))
	if err != nil {
		return Report{}, fmt.Errorf("find Claude settings: %w", err)
	}
	for _, path := range settingsPaths {
		candidates = append(candidates, candidate{"claude-settings", path, "claude", ""})
	}
	pluginRoots, err := installedPluginRoots(opts.Home)
	if err != nil {
		return Report{}, err
	}
	for _, root := range pluginRoots {
		candidates = append(candidates, candidate{"claude-plugin", filepath.Join(root, "hooks", "hooks.json"), "claude", root})
	}

	seen := map[string]bool{}
	for _, c := range candidates {
		commands, shapeWarnings, err := commandsFromFile(c.path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			report.OK = false
			report.Files = append(report.Files, FileSummary{
				Path:         c.path,
				Unrecognized: []string{},
				Warnings:     []string{},
				Error:        err.Error(),
			})
			continue
		}
		summary := FileSummary{Path: c.path, Unrecognized: []string{}, Warnings: append([]string{}, shapeWarnings...)}
		summary.CommandsSeen = len(commands)
		if len(shapeWarnings) > 0 {
			report.OK = false
		}
		for _, command := range commands {
			parsed, parseErr := parseCommand(command)
			if parseErr != nil || (!referencesGatekeeper(parsed) && !(c.pluginRoot != "" && isPluginWrapper(parsed, c.pluginRoot))) {
				summary.Unrecognized = append(summary.Unrecognized, command)
				if looksLikeGatekeeper(command) {
					report.OK = false
					warning := fmt.Sprintf("%s: unrecognized gatekeeper command %q", c.path, command)
					summary.Warnings = append(summary.Warnings, warning)
				}
				continue
			}
			summary.Recognized++
			key := c.path + "\x00" + command
			if seen[key] {
				continue
			}
			seen[key] = true
			s := inspect(c, command, parsed, opts)
			if len(s.Drift) > 0 {
				report.OK = false
			}
			report.Surfaces = append(report.Surfaces, s)
		}
		report.Files = append(report.Files, summary)
	}
	if len(report.Surfaces) < opts.MinSurfaces {
		report.OK = false
		report.Warnings = append(report.Warnings, fmt.Sprintf("only %d gatekeeper surfaces found; minimum is %d", len(report.Surfaces), opts.MinSurfaces))
	}
	sort.SliceStable(report.Surfaces, func(i, j int) bool {
		left, right := report.Surfaces[i], report.Surfaces[j]
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.ConfigPath != right.ConfigPath {
			return left.ConfigPath < right.ConfigPath
		}
		return left.Command < right.Command
	})
	sort.Slice(report.Files, func(i, j int) bool { return report.Files[i].Path < report.Files[j].Path })
	return report, nil
}

// HasFileErrors reports whether any discovered hook file could not be read or parsed.
func (r Report) HasFileErrors() bool {
	for _, file := range r.Files {
		if file.Error != "" {
			return true
		}
	}
	return false
}

// installedPluginRoots reads Claude Code's live-install registry. Cached older
// versions and plugins other than claude-gatekeeper are deliberately excluded.
func installedPluginRoots(home string) ([]string, error) {
	path := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var registry struct {
		Plugins map[string][]struct {
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var roots []string
	for name, installs := range registry.Plugins {
		if !strings.HasPrefix(name, binaryName+"@") {
			continue
		}
		for _, install := range installs {
			if install.InstallPath != "" {
				roots = append(roots, cleanPath(install.InstallPath))
			}
		}
	}
	return roots, nil
}

type parsedCommand struct {
	Binary string
	Args   []string
	Env    map[string]string
}

func parseCommand(command string) (parsedCommand, error) {
	words, err := shellWords(command)
	if err != nil {
		return parsedCommand{}, err
	}
	env := map[string]string{}
	for len(words) > 0 && isEnvAssignment(words[0]) {
		name, value, _ := strings.Cut(words[0], "=")
		env[name] = value
		words = words[1:]
	}
	if len(words) == 0 {
		return parsedCommand{}, errors.New("command contains no executable")
	}
	return parsedCommand{Binary: words[0], Args: words[1:], Env: env}, nil
}

func shellWords(input string) ([]string, error) {
	var words []string
	var word strings.Builder
	var quote rune
	escaped := false
	inWord := false
	flush := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
	}
	for _, r := range input {
		if escaped {
			word.WriteRune(r)
			inWord = true
			escaped = false
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			inWord = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
			inWord = true
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
			inWord = true
		case ' ', '\t', '\r', '\n':
			flush()
		default:
			word.WriteRune(r)
			inWord = true
		}
	}
	if escaped || quote != 0 {
		return nil, errors.New("unterminated quote or escape")
	}
	flush()
	return words, nil
}

func isEnvAssignment(word string) bool {
	name, _, ok := strings.Cut(word, "=")
	if !ok || name == "" {
		return false
	}
	for i, r := range name {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func inspect(c candidate, command string, parsed parsedCommand, opts Options) Surface {
	binary := expandHome(parsed.Binary, opts.Home)
	if c.pluginRoot != "" {
		binary = filepath.Join(c.pluginRoot, "bin", binaryName)
	} else if isBareCommand(binary) {
		if resolved, err := opts.LookPath(binary); err == nil {
			binary = resolved
		}
	}
	harness := "claude"
	if value := parsed.Env["GATEKEEPER_HARNESS"]; value != "" {
		harness = value
	}
	for i := 0; i < len(parsed.Args); i++ {
		if parsed.Args[i] == "--harness" && i+1 < len(parsed.Args) {
			harness = parsed.Args[i+1]
		}
		if strings.HasPrefix(parsed.Args[i], "--harness=") {
			harness = strings.TrimPrefix(parsed.Args[i], "--harness=")
		}
	}
	expectedBinary := cleanPath(opts.ExpectedBinary)
	if c.pluginRoot != "" {
		expectedBinary = filepath.Join(c.pluginRoot, "bin", binaryName)
	}
	s := Surface{Kind: c.kind, ConfigPath: c.path, Command: command, BinaryPath: cleanPath(binary), Harness: harness, ExpectedBinary: expectedBinary, ExpectedHarness: c.expectedHarness, Drift: []string{}}
	if s.Harness != c.expectedHarness {
		s.Drift = append(s.Drift, fmt.Sprintf("harness: expected %s, got %s", c.expectedHarness, s.Harness))
	}
	if expectedBinary != "" && !sameBinaryPath(s.BinaryPath, expectedBinary) {
		s.Drift = append(s.Drift, fmt.Sprintf("binary: expected %s, got %s", expectedBinary, s.BinaryPath))
	}
	if c.kind == "codex-global" {
		trust, err := codextrust.Inspect(opts.Home, c.path, command)
		if err != nil {
			s.Drift = append(s.Drift, "trust: "+err.Error())
		} else if !trust.Trusted() {
			if trust.TrustedHash == "" {
				s.Drift = append(s.Drift, "trust: hook is installed but untrusted; Codex will silently skip it")
			} else {
				s.Drift = append(s.Drift, "trust: hook hash changed since approval; Codex will silently skip it")
			}
		}
	}
	if _, err := os.Stat(s.BinaryPath); err != nil {
		s.Drift = append(s.Drift, "binary: "+err.Error())
		return s
	}
	ver, err := opts.VersionProbe(s.BinaryPath)
	if err != nil {
		s.Drift = append(s.Drift, "version: "+err.Error())
		return s
	}
	s.Version = ver
	if opts.ExpectedVersion != "" && ver != opts.ExpectedVersion {
		s.Drift = append(s.Drift, fmt.Sprintf("version: expected %s, got %s", opts.ExpectedVersion, ver))
	}
	return s
}

func commandsFromFile(path string) ([]string, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, nil, err
	}
	hooksValue, hooksExists := root["hooks"]
	if !hooksExists {
		return nil, nil, nil
	}
	hooks, ok := hooksValue.(map[string]any)
	if !ok {
		return nil, []string{"unexpected hooks shape: expected object"}, nil
	}
	preValue, preExists := hooks["PreToolUse"]
	if !preExists {
		return nil, nil, nil
	}
	entries, ok := preValue.([]any)
	if !ok {
		return findCommands(preValue), []string{"unexpected hooks.PreToolUse shape: expected array"}, nil
	}
	commands := findCommands(preValue)
	var warnings []string
	for i, entry := range entries {
		m, ok := entry.(map[string]any)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("unexpected hooks.PreToolUse[%d] shape: expected object", i))
			continue
		}
		innerValue, exists := m["hooks"]
		if !exists {
			warnings = append(warnings, fmt.Sprintf("unexpected hooks.PreToolUse[%d] shape: missing hooks", i))
			continue
		}
		inner, ok := innerValue.([]any)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("unexpected hooks.PreToolUse[%d].hooks shape: expected array", i))
			continue
		}
		for j, hook := range inner {
			hm, ok := hook.(map[string]any)
			if !ok {
				warnings = append(warnings, fmt.Sprintf("unexpected hooks.PreToolUse[%d].hooks[%d] shape: expected object", i, j))
				continue
			}
			command, exists := hm["command"]
			if !exists {
				continue
			}
			_, ok = command.(string)
			if !ok {
				warnings = append(warnings, fmt.Sprintf("unexpected hooks.PreToolUse[%d].hooks[%d].command shape: expected string", i, j))
				continue
			}
		}
	}
	return commands, warnings, nil
}

func findCommands(value any) []string {
	var commands []string
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if key == "command" {
					if command, ok := child.(string); ok {
						commands = append(commands, command)
					}
					continue
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	sort.Strings(commands)
	return commands
}

func referencesGatekeeper(command parsedCommand) bool {
	return strings.TrimSuffix(filepath.Base(command.Binary), ".exe") == binaryName
}

func isPluginWrapper(command parsedCommand, root string) bool {
	want := filepath.Join(root, "bin", "run.sh")
	got := strings.ReplaceAll(command.Binary, "${CLAUDE_PLUGIN_ROOT}", root)
	return cleanPath(got) == want
}

func looksLikeGatekeeper(command string) bool { return strings.Contains(command, "gatekeeper") }

func probeVersion(path string) (string, error) { return probeVersionWithTimeout(path, 5*time.Second) }

func probeVersionWithTimeout(path string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	// Worst-case wall time is about 2x timeout: the context kills the direct
	// child, then WaitDelay bounds pipe drain from any surviving descendants.
	cmd.WaitDelay = timeout
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if errors.Is(err, exec.ErrWaitDelay) && text != "" {
		return strings.TrimSpace(strings.TrimPrefix(text, binaryName)), nil
	}
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("probe timed out after %s; output: %s", timeout, emptyDash(text))
	}
	if err != nil {
		return "", fmt.Errorf("probe failed: %w; output: %s", err, emptyDash(text))
	}
	return strings.TrimSpace(strings.TrimPrefix(text, binaryName)), nil
}

// WriteJSON writes a stable, indented JSON representation of report.
func WriteJSON(w io.Writer, report Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// WriteTable writes the human-readable surface and per-file coverage tables.
func WriteTable(w io.Writer, report Report) error {
	if len(report.Surfaces) > 0 {
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		if _, err := fmt.Fprintln(tw, "SURFACE\tCONFIG\tHARNESS\tVERSION\tBINARY\tDRIFT"); err != nil {
			return err
		}
		for _, s := range report.Surfaces {
			drift := "OK"
			if len(s.Drift) > 0 {
				drift = strings.Join(s.Drift, "; ")
			}
			if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", s.Kind, s.ConfigPath, s.Harness, emptyDash(s.Version), s.BinaryPath, drift); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(report.Files) > 0 {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		if _, err := fmt.Fprintln(tw, "HOOK FILE\tCOMMANDS\tRECOGNIZED\tWARNINGS"); err != nil {
			return err
		}
		for _, file := range report.Files {
			warnings := append([]string{}, file.Warnings...)
			if file.Error != "" {
				warnings = append(warnings, "error: "+file.Error)
			}
			if len(file.Unrecognized) > 0 {
				warnings = append(warnings, "unrecognized: "+strings.Join(file.Unrecognized, " | "))
			}
			if _, err := fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n", file.Path, file.CommandsSeen, file.Recognized, emptyDash(strings.Join(warnings, "; "))); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	for _, warning := range report.Warnings {
		if _, err := fmt.Fprintf(w, "WARNING: %s\n", warning); err != nil {
			return err
		}
	}
	return nil
}

func sameBinaryPath(left, right string) bool { return canonicalPath(left) == canonicalPath(right) }

func canonicalPath(path string) string {
	path = cleanPath(path)
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

func expandHome(path, home string) string {
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	return path
}

func isBareCommand(path string) bool {
	return path != "" && filepath.Base(path) == path
}

func cleanPath(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
