// Package inventory inspects live gatekeeper hook registrations without modifying them.
package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	Home                  string
	ClaudeRoot            string
	ClaudeRootSource      string
	RequiredHarness       string
	ExpectedBinary        string
	ExpectedVersion       string
	MinSurfaces           int
	VersionProbe          func(string) (string, error)
	LookPath              func(string) (string, error)
	PublishedVersionProbe func() (string, error)
}

// Report is the machine-readable result of a hook inventory.
type Report struct {
	OK                 bool              `json:"ok"`
	ClaudeRoot         string            `json:"claude_root"`
	ClaudeRootSource   string            `json:"claude_root_source"`
	RequiredHarness    string            `json:"required_harness"`
	ClaudeRegistration Registration      `json:"claude_registration"`
	ExpectedBinary     string            `json:"expected_binary"`
	ExpectedVersion    string            `json:"expected_version"`
	MinSurfaces        int               `json:"min_surfaces"`
	Warnings           []string          `json:"warnings"`
	Files              []FileSummary     `json:"files"`
	Surfaces           []Surface         `json:"surfaces"`
	VersionInvariant   *VersionInvariant `json:"version_invariant,omitempty"`
}

// Registration separates static registration evidence from a live firing
// control. Doctor never claims interception from configuration inspection.
type Registration struct {
	Status       string               `json:"status"`
	Sources      []RegistrationSource `json:"sources"`
	FiringStatus string               `json:"firing_status"`
	FiringReason string               `json:"firing_reason"`
	Errors       []string             `json:"errors"`
}

type RegistrationSource struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

// VersionInvariant compares versions reported by enforcing binaries with the
// latest published release. Status is current, fail, or unknown.
type VersionInvariant struct {
	Status          string               `json:"status"`
	PublishedLatest string               `json:"published_latest,omitempty"`
	Reason          string               `json:"reason,omitempty"`
	Observations    []VersionObservation `json:"observations"`
}

// VersionObservation records one enforcing surface's executable-derived version.
type VersionObservation struct {
	Surface         string `json:"surface"`
	BinaryPath      string `json:"binary_path"`
	ObservedVersion string `json:"observed_version,omitempty"`
	ExpectedVersion string `json:"expected_version,omitempty"`
	PathVersion     string `json:"path_version,omitempty"`
	Status          string `json:"status"`
	Reason          string `json:"reason,omitempty"`
}

// FileSummary reports discovery coverage for one existing hook file.
type FileSummary struct {
	Path         string   `json:"path"`
	Scope        string   `json:"scope"`
	ConfigRoot   string   `json:"config_root"`
	Harness      string   `json:"harness"`
	CommandsSeen int      `json:"commands_seen"`
	Recognized   int      `json:"commands_recognized"`
	Unrecognized []string `json:"unrecognized_commands"`
	Warnings     []string `json:"warnings"`
	Error        string   `json:"error,omitempty"`
}

// Surface describes one recognized live gatekeeper command and its drift.
type Surface struct {
	Kind            string   `json:"surface"`
	Scope           string   `json:"scope"`
	ConfigRoot      string   `json:"config_root"`
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
	kind, path, expectedHarness, pluginRoot, scope, configRoot string
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
	claudeRoot, claudeRootSource := resolveClaudeRoot(opts)
	requiredHarness := opts.RequiredHarness
	if requiredHarness == "" {
		requiredHarness = "any"
	}
	if !validRequiredHarness(requiredHarness) {
		return Report{}, fmt.Errorf("invalid required harness %q", requiredHarness)
	}
	report := Report{
		OK: true, ClaudeRoot: claudeRoot, ClaudeRootSource: claudeRootSource, RequiredHarness: requiredHarness,
		ClaudeRegistration: Registration{Status: "absent", Sources: []RegistrationSource{}, FiringStatus: "not_tested", FiringReason: "static Doctor inventory does not execute a known-positive firing control", Errors: []string{}},
		ExpectedBinary:     cleanPath(opts.ExpectedBinary), ExpectedVersion: opts.ExpectedVersion,
		MinSurfaces: opts.MinSurfaces, Warnings: []string{}, Files: []FileSummary{}, Surfaces: []Surface{},
	}
	candidates := []candidate{
		{"grok-global", filepath.Join(opts.Home, ".grok", "hooks", "gatekeeper.json"), "grok", "", "host-global", opts.Home},
		{"codex-global", filepath.Join(opts.Home, ".codex", "hooks.json"), "codex", "", "host-global", opts.Home},
	}
	strictClaude := requiredHarness == "claude"
	if info, statErr := os.Stat(claudeRoot); statErr != nil || !info.IsDir() {
		message := fmt.Sprintf("selected Claude root unavailable: %v", statErr)
		if statErr == nil {
			message = "selected Claude root is not a directory"
		}
		report.ClaudeRegistration.Status = "error"
		report.ClaudeRegistration.Errors = append(report.ClaudeRegistration.Errors, message)
		if strictClaude {
			report.Files = append(report.Files, FileSummary{Path: claudeRoot, Scope: "effective-claude-root", ConfigRoot: claudeRoot, Harness: "claude", Unrecognized: []string{}, Warnings: []string{}, Error: message})
			report.OK = false
		}
	}
	settingsPaths, err := filepath.Glob(filepath.Join(claudeRoot, "settings*.json"))
	if err != nil {
		return Report{}, fmt.Errorf("find Claude settings: %w", err)
	}
	if len(settingsPaths) == 0 && strictClaude && report.ClaudeRegistration.Status != "error" {
		message := "no settings*.json found under selected Claude root"
		report.ClaudeRegistration.Status = "error"
		report.ClaudeRegistration.Errors = append(report.ClaudeRegistration.Errors, message)
		report.Files = append(report.Files, FileSummary{Path: filepath.Join(claudeRoot, "settings*.json"), Scope: "effective-claude-root", ConfigRoot: claudeRoot, Harness: "claude", Unrecognized: []string{}, Warnings: []string{}, Error: message})
		report.OK = false
	}
	for _, path := range settingsPaths {
		candidates = append(candidates, candidate{"claude-settings", path, "claude", "", "effective-claude-root", claudeRoot})
	}
	pluginRoots, registryPath, registryExists, err := installedPluginRoots(claudeRoot)
	if err != nil {
		report.ClaudeRegistration.Status = "error"
		report.ClaudeRegistration.Errors = append(report.ClaudeRegistration.Errors, err.Error())
		if strictClaude {
			report.Files = append(report.Files, FileSummary{Path: registryPath, Scope: "effective-claude-root", ConfigRoot: claudeRoot, Harness: "claude", Unrecognized: []string{}, Warnings: []string{}, Error: err.Error()})
			report.OK = false
		} else if requiredHarness == "any" {
			return Report{}, err
		}
	} else if !registryExists && strictClaude {
		message := fmt.Sprintf("selected-root plugin registry is missing: %s", registryPath)
		report.ClaudeRegistration.Status = "error"
		report.ClaudeRegistration.Errors = append(report.ClaudeRegistration.Errors, message)
		report.Files = append(report.Files, FileSummary{Path: registryPath, Scope: "effective-claude-root", ConfigRoot: claudeRoot, Harness: "claude", Unrecognized: []string{}, Warnings: []string{}, Error: message})
		report.OK = false
	} else if !registryExists {
		message := fmt.Sprintf("selected-root plugin registry is missing: %s", registryPath)
		report.ClaudeRegistration.Status = "error"
		report.ClaudeRegistration.Errors = append(report.ClaudeRegistration.Errors, message)
	}
	for _, root := range pluginRoots {
		candidates = append(candidates, candidate{"claude-plugin", filepath.Join(root, "hooks", "hooks.json"), "claude", root, "effective-claude-root", claudeRoot})
	}

	seen := map[string]bool{}
	for _, c := range candidates {
		commands, shapeWarnings, err := commandsFromFile(c.path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			if candidateRequired(c, requiredHarness) {
				report.OK = false
			}
			if c.expectedHarness == "claude" {
				report.ClaudeRegistration.Status = "error"
				report.ClaudeRegistration.Errors = append(report.ClaudeRegistration.Errors, fmt.Sprintf("%s: %v", c.path, err))
			}
			report.Files = append(report.Files, FileSummary{
				Path:         c.path,
				Scope:        c.scope,
				ConfigRoot:   c.configRoot,
				Harness:      c.expectedHarness,
				Unrecognized: []string{},
				Warnings:     []string{},
				Error:        err.Error(),
			})
			continue
		}
		summary := FileSummary{Path: c.path, Scope: c.scope, ConfigRoot: c.configRoot, Harness: c.expectedHarness, Unrecognized: []string{}, Warnings: append([]string{}, shapeWarnings...)}
		summary.CommandsSeen = len(commands)
		if len(shapeWarnings) > 0 {
			if candidateRequired(c, requiredHarness) {
				report.OK = false
			}
		}
		for _, command := range commands {
			parsed, parseErr := parseCommand(command)
			harness, harnessErr := parseHarness(parsed)
			if parseErr != nil || harnessErr != nil || (!referencesGatekeeper(parsed) && !(c.pluginRoot != "" && isPluginWrapper(parsed, c.pluginRoot))) {
				summary.Unrecognized = append(summary.Unrecognized, command)
				if looksLikeGatekeeper(command) {
					if candidateRequired(c, requiredHarness) {
						report.OK = false
					}
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
			s := inspect(c, command, parsed, harness, opts)
			if len(s.Drift) > 0 && candidateRequired(c, requiredHarness) {
				report.OK = false
			}
			report.Surfaces = append(report.Surfaces, s)
		}
		report.Files = append(report.Files, summary)
	}
	for _, surface := range report.Surfaces {
		if surface.Scope == "effective-claude-root" && surface.Harness == "claude" {
			report.ClaudeRegistration.Sources = append(report.ClaudeRegistration.Sources, RegistrationSource{Kind: surface.Kind, Path: surface.ConfigPath})
		}
	}
	if report.ClaudeRegistration.Status != "error" {
		if len(report.ClaudeRegistration.Sources) > 0 {
			report.ClaudeRegistration.Status = "registered"
		} else {
			report.ClaudeRegistration.Status = "absent"
		}
	}
	matchingSurfaces := requiredSurfaceCount(report.Surfaces, requiredHarness)
	if matchingSurfaces < opts.MinSurfaces {
		report.OK = false
		report.Warnings = append(report.Warnings, fmt.Sprintf("only %d %s gatekeeper surfaces found; minimum is %d", matchingSurfaces, requiredHarness, opts.MinSurfaces))
	}
	if requiredHarness == "claude" && report.ClaudeRegistration.Status != "registered" {
		report.OK = false
		report.Warnings = append(report.Warnings, fmt.Sprintf("effective Claude registration is %s at %s", report.ClaudeRegistration.Status, claudeRoot))
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
	if opts.PublishedVersionProbe != nil {
		report.VersionInvariant = evaluateVersionInvariant(requiredSurfaces(report.Surfaces, requiredHarness), opts.PublishedVersionProbe)
		if report.VersionInvariant.Status != "current" {
			report.OK = false
		}
	}
	return report, nil
}

func evaluateVersionInvariant(surfaces []Surface, publishedProbe func() (string, error)) *VersionInvariant {
	result := &VersionInvariant{Status: "unknown", Observations: []VersionObservation{}}
	published, err := publishedProbe()
	if err != nil {
		result.Reason = "published latest unavailable: " + err.Error()
		return result
	}
	result.PublishedLatest = normalizeVersion(published)
	if result.PublishedLatest == "" {
		result.Reason = "published latest returned an empty version"
		return result
	}
	if len(surfaces) == 0 {
		result.Reason = "no enforcing surfaces discovered"
		return result
	}
	result.Status = "current"
	for _, surface := range surfaces {
		observation := VersionObservation{Surface: surface.Kind, BinaryPath: surface.BinaryPath, ExpectedVersion: result.PublishedLatest, Status: "current"}
		if surface.Version == "" {
			observation.Status = "unknown"
			observation.Reason = "binary version unavailable; execution probe did not succeed"
			if result.Status != "fail" {
				result.Status = "unknown"
				result.Reason = observation.Reason
			}
		} else {
			observation.ObservedVersion = normalizeVersion(surface.Version)
			if observation.ObservedVersion != result.PublishedLatest {
				observation.Status = "stale"
				observation.Reason = fmt.Sprintf("enforcing version %s != published latest %s", observation.ObservedVersion, result.PublishedLatest)
				result.Status = "fail"
				result.Reason = observation.Reason
			}
			if surface.Kind == "claude-plugin" {
				observation.PathVersion = pluginPathVersion(surface.BinaryPath)
				if observation.PathVersion != "" && normalizeVersion(observation.PathVersion) != observation.ObservedVersion {
					observation.Status = "stale"
					pathReason := fmt.Sprintf("plugin path version %s != binary-reported version %s", observation.PathVersion, observation.ObservedVersion)
					if observation.Reason == "" {
						observation.Reason = pathReason
					} else {
						observation.Reason += "; " + pathReason
					}
					result.Status = "fail"
					result.Reason = pathReason
				}
			}
		}
		result.Observations = append(result.Observations, observation)
	}
	return result
}

func normalizeVersion(version string) string {
	return strings.TrimPrefix(strings.TrimSpace(version), "v")
}

func pluginPathVersion(binary string) string {
	if filepath.Base(filepath.Dir(binary)) != "bin" {
		return ""
	}
	version := filepath.Base(filepath.Dir(filepath.Dir(binary)))
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return ""
	}
	for _, part := range parts {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return ""
		}
	}
	return version
}

// FetchPublishedLatest returns the tag of the latest non-draft GitHub release.
func FetchPublishedLatest(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "claude-gatekeeper-doctor")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("release endpoint returned %s", resp.Status)
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	if release.TagName == "" {
		return "", errors.New("release response has no tag_name")
	}
	return release.TagName, nil
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
func installedPluginRoots(claudeRoot string) ([]string, string, bool, error) {
	path := filepath.Join(claudeRoot, "plugins", "installed_plugins.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, path, false, nil
	}
	if err != nil {
		return nil, path, true, fmt.Errorf("read %s: %w", path, err)
	}
	var registry struct {
		Plugins map[string][]struct {
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, path, true, fmt.Errorf("parse %s: %w", path, err)
	}
	var roots []string
	for name, installs := range registry.Plugins {
		if !strings.HasPrefix(name, binaryName+"@") {
			continue
		}
		for _, install := range installs {
			if install.InstallPath != "" {
				root := cleanPath(install.InstallPath)
				if err := requirePathWithinRoot(claudeRoot, root); err != nil {
					return nil, path, true, fmt.Errorf("validate Gatekeeper installPath %q from %s: %w", install.InstallPath, path, err)
				}
				roots = append(roots, root)
			}
		}
	}
	return roots, path, true, nil
}

func requirePathWithinRoot(root, path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("path is not absolute")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve selected root: %w", err)
	}
	pathAbs := filepath.Clean(path)
	if err := requireComponentContainment(rootAbs, pathAbs); err != nil {
		return fmt.Errorf("lexical containment: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return fmt.Errorf("resolve selected root symlinks: %w", err)
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve install path symlinks: %w", err)
	}
	if err := requireComponentContainment(resolvedRoot, resolvedPath); err != nil {
		return fmt.Errorf("resolved containment: %w", err)
	}
	return nil
}

func requireComponentContainment(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return fmt.Errorf("compare path with selected root: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %s is outside selected Claude root %s", path, root)
	}
	return nil
}

func resolveClaudeRoot(opts Options) (string, string) {
	if opts.ClaudeRoot != "" {
		source := opts.ClaudeRootSource
		if source == "" {
			source = "explicit"
		}
		return cleanPath(opts.ClaudeRoot), source
	}
	if root := os.Getenv("CLAUDE_CONFIG_DIR"); root != "" {
		return cleanPath(root), "environment"
	}
	return filepath.Join(opts.Home, ".claude"), "default"
}

func validRequiredHarness(value string) bool {
	return value == "any" || value == "claude" || value == "codex" || value == "grok"
}

func candidateRequired(c candidate, required string) bool {
	return required == "any" || c.expectedHarness == required
}

func requiredSurfaces(surfaces []Surface, required string) []Surface {
	if required == "any" {
		return surfaces
	}
	filtered := make([]Surface, 0, len(surfaces))
	for _, surface := range surfaces {
		if surface.Harness == required {
			filtered = append(filtered, surface)
		}
	}
	return filtered
}

func requiredSurfaceCount(surfaces []Surface, required string) int {
	return len(requiredSurfaces(surfaces, required))
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

func parseHarness(parsed parsedCommand) (string, error) {
	harness := "claude"
	if value := parsed.Env["GATEKEEPER_HARNESS"]; value != "" {
		harness = value
	}
	for i := 0; i < len(parsed.Args); i++ {
		arg := parsed.Args[i]
		switch {
		case arg == "--harness" || arg == "-harness":
			if i+1 >= len(parsed.Args) || strings.HasPrefix(parsed.Args[i+1], "-") {
				return "", fmt.Errorf("%s requires a value", arg)
			}
			harness = parsed.Args[i+1]
			i++ // Consume the flag's value; do not parse it again as an argument.
		case strings.HasPrefix(arg, "--harness=") || strings.HasPrefix(arg, "-harness="):
			_, value, _ := strings.Cut(arg, "=")
			if value == "" {
				return "", fmt.Errorf("%s requires a value", arg)
			}
			harness = value
		case strings.HasPrefix(arg, "--harness") || strings.HasPrefix(arg, "-harness"):
			return "", fmt.Errorf("unrecognized harness flag %q", arg)
		}
	}
	return harness, nil
}

func inspect(c candidate, command string, parsed parsedCommand, harness string, opts Options) Surface {
	binary := expandHome(parsed.Binary, opts.Home)
	if c.pluginRoot != "" {
		binary = filepath.Join(c.pluginRoot, "bin", binaryName)
	} else if isBareCommand(binary) {
		if resolved, err := opts.LookPath(binary); err == nil {
			binary = resolved
		}
	}
	expectedBinary := cleanPath(opts.ExpectedBinary)
	if c.pluginRoot != "" {
		expectedBinary = filepath.Join(c.pluginRoot, "bin", binaryName)
	}
	s := Surface{Kind: c.kind, Scope: c.scope, ConfigRoot: c.configRoot, ConfigPath: c.path, Command: command, BinaryPath: cleanPath(binary), Harness: harness, ExpectedBinary: expectedBinary, ExpectedHarness: c.expectedHarness, Drift: []string{}}
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
	if _, err := fmt.Fprintf(w, "CLAUDE ROOT: %s (source: %s)\n", emptyDash(report.ClaudeRoot), emptyDash(report.ClaudeRootSource)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "REQUIREMENT: %s\n", strings.ToUpper(emptyDash(report.RequiredHarness))); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "CLAUDE REGISTRATION: %s; FIRING: %s", strings.ToUpper(emptyDash(report.ClaudeRegistration.Status)), strings.ToUpper(emptyDash(report.ClaudeRegistration.FiringStatus))); err != nil {
		return err
	}
	if report.ClaudeRegistration.FiringReason != "" {
		if _, err := fmt.Fprintf(w, " — %s", report.ClaudeRegistration.FiringReason); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	for _, source := range report.ClaudeRegistration.Sources {
		if _, err := fmt.Fprintf(w, "CLAUDE REGISTRATION SOURCE: %s %s\n", source.Kind, source.Path); err != nil {
			return err
		}
	}
	for _, diagnosticErr := range report.ClaudeRegistration.Errors {
		if _, err := fmt.Fprintf(w, "CLAUDE REGISTRATION ERROR: %s\n", diagnosticErr); err != nil {
			return err
		}
	}
	if len(report.Surfaces) > 0 {
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		if _, err := fmt.Fprintln(tw, "SURFACE\tSCOPE\tROOT\tCONFIG\tHARNESS\tVERSION\tBINARY\tDRIFT"); err != nil {
			return err
		}
		for _, s := range report.Surfaces {
			drift := "OK"
			if len(s.Drift) > 0 {
				drift = strings.Join(s.Drift, "; ")
			}
			if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s.Kind, s.Scope, s.ConfigRoot, s.ConfigPath, s.Harness, emptyDash(s.Version), s.BinaryPath, drift); err != nil {
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
		if _, err := fmt.Fprintln(tw, "HOOK FILE\tSCOPE\tROOT\tHARNESS\tCOMMANDS\tRECOGNIZED\tWARNINGS"); err != nil {
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
			if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n", file.Path, file.Scope, file.ConfigRoot, file.Harness, file.CommandsSeen, file.Recognized, emptyDash(strings.Join(warnings, "; "))); err != nil {
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
	if report.VersionInvariant != nil {
		if _, err := fmt.Fprintf(w, "VERSION INVARIANT: %s", strings.ToUpper(report.VersionInvariant.Status)); err != nil {
			return err
		}
		if report.VersionInvariant.Reason != "" {
			if _, err := fmt.Fprintf(w, " — %s", report.VersionInvariant.Reason); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
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
