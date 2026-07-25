// Package releaseverify verifies a published gatekeeper release without
// installing, replacing, or otherwise mutating any live binary.
package releaseverify

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	defaultAPIBase = "https://api.github.com"
	defaultRepo    = "jim80net/gatekeeper-claude"
	canaryCommand  = "release-verifier-canary"
	canaryReason   = "release verifier canary"
)

// Options configures one read-only release verification.
type Options struct {
	Tag          string
	Repo         string
	HostBinary   string
	PluginBinary string
	MinSurfaces  int
	APIBase      string
	HTTPClient   *http.Client
	GOOS         string
	GOARCH       string
}

// Check is one independently reportable verification.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Result is the machine-readable verification report.
type Result struct {
	OK       bool    `json:"ok"`
	ExitCode int     `json:"exit_code"`
	Tag      string  `json:"tag"`
	Repo     string  `json:"repo"`
	Checks   []Check `json:"checks"`
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Draft   bool          `json:"draft"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// Verify performs all release checks and returns a report. A failed check is
// represented by Result.OK=false; errors are reserved for failures that prevent
// a meaningful report (invalid arguments, transport errors, or corrupt JSON).
func Verify(ctx context.Context, opts Options) (Result, error) {
	opts = withDefaults(opts)
	if err := validateOptions(opts); err != nil {
		return Result{}, err
	}

	result := Result{Tag: opts.Tag, Repo: opts.Repo}
	add := func(name string, ok bool, detail string) {
		result.Checks = append(result.Checks, Check{Name: name, OK: ok, Detail: detail})
	}

	release, err := fetchRelease(ctx, opts)
	if err != nil {
		return Result{}, err
	}
	if release.TagName != opts.Tag {
		add("release", false, fmt.Sprintf("requested %s, API returned %s", opts.Tag, release.TagName))
		return finish(result), nil
	}
	if release.Draft {
		add("release", false, "release is still a draft")
		return finish(result), nil
	}
	add("release", true, "exact tag is published")

	assets := make(map[string]string, len(release.Assets))
	for _, asset := range release.Assets {
		assets[asset.Name] = asset.URL
	}
	missing := missingAssets(assets)
	if len(missing) > 0 {
		add("assets", false, "missing: "+strings.Join(missing, ", "))
		return finish(result), nil
	}
	add("assets", true, "six platform archives and checksums.txt present")

	tmp, err := os.MkdirTemp("", "gatekeeper-release-verify-*")
	if err != nil {
		return Result{}, fmt.Errorf("create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmp)

	archiveName := assetName(opts.GOOS, opts.GOARCH)
	archivePath := filepath.Join(tmp, archiveName)
	checksumPath := filepath.Join(tmp, "checksums.txt")
	if err := download(ctx, opts.HTTPClient, assets[archiveName], archivePath); err != nil {
		return Result{}, fmt.Errorf("download %s: %w", archiveName, err)
	}
	if err := download(ctx, opts.HTTPClient, assets["checksums.txt"], checksumPath); err != nil {
		return Result{}, fmt.Errorf("download checksums.txt: %w", err)
	}

	wantSum, err := checksumFor(checksumPath, archiveName)
	if err != nil {
		add("checksum", false, err.Error())
		return finish(result), nil
	}
	gotSum, err := fileSHA256(archivePath)
	if err != nil {
		return Result{}, err
	}
	if !strings.EqualFold(wantSum, gotSum) {
		add("checksum", false, fmt.Sprintf("%s: expected %s, got %s", archiveName, wantSum, gotSum))
		return finish(result), nil
	}
	add("checksum", true, archiveName+" matches checksums.txt")

	extractDir := filepath.Join(tmp, "archive")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return Result{}, fmt.Errorf("create extraction directory: %w", err)
	}
	if err := extractArchive(archivePath, extractDir, opts.GOOS); err != nil {
		add("archive", false, err.Error())
		return finish(result), nil
	}
	downloadedBinary, err := findBinary(extractDir, opts.GOOS)
	if err != nil {
		add("archive", false, err.Error())
		return finish(result), nil
	}
	if err := os.Chmod(downloadedBinary, 0755); err != nil {
		return Result{}, fmt.Errorf("make downloaded binary executable: %w", err)
	}
	add("archive", true, "current-platform binary extracted")

	expectedVersion := strings.TrimPrefix(opts.Tag, "v")
	for _, target := range []struct {
		name string
		path string
	}{
		{"downloaded version", downloadedBinary},
		{"host version", opts.HostBinary},
		{"plugin version", opts.PluginBinary},
	} {
		observed, err := probeVersion(ctx, target.path)
		if err != nil {
			add(target.name, false, err.Error())
			continue
		}
		if observed != expectedVersion {
			add(target.name, false, fmt.Sprintf("expected %s, got %s", expectedVersion, observed))
			continue
		}
		add(target.name, true, observed)
	}

	doctorExit, doctorDetail := runDoctor(ctx, opts.PluginBinary, opts.HostBinary, expectedVersion, opts.MinSurfaces)
	add("doctor", doctorExit == 0, doctorDetail)
	if doctorExit > result.ExitCode {
		result.ExitCode = doctorExit
	}

	for _, harness := range []string{"claude", "codex", "grok"} {
		ok, detail := runCanary(ctx, downloadedBinary, harness)
		add(harness+" canary", ok, detail)
	}

	return finish(result), nil
}

func withDefaults(opts Options) Options {
	if opts.Repo == "" {
		opts.Repo = defaultRepo
	}
	if opts.APIBase == "" {
		opts.APIBase = defaultAPIBase
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if opts.GOOS == "" {
		opts.GOOS = runtime.GOOS
	}
	if opts.GOARCH == "" {
		opts.GOARCH = runtime.GOARCH
	}
	return opts
}

func validateOptions(opts Options) error {
	if opts.Tag == "" {
		return errors.New("tag is required")
	}
	if opts.HostBinary == "" {
		return errors.New("--host-binary is required")
	}
	if opts.PluginBinary == "" {
		return errors.New("--plugin-binary is required")
	}
	if opts.MinSurfaces < 0 {
		return errors.New("--min-surfaces must be non-negative")
	}
	if opts.GOOS != "linux" && opts.GOOS != "darwin" && opts.GOOS != "windows" {
		return fmt.Errorf("unsupported operating system %q", opts.GOOS)
	}
	if opts.GOARCH != "amd64" && opts.GOARCH != "arm64" {
		return fmt.Errorf("unsupported architecture %q", opts.GOARCH)
	}
	return nil
}

func fetchRelease(ctx context.Context, opts Options) (githubRelease, error) {
	url := strings.TrimRight(opts.APIBase, "/") + "/repos/" + opts.Repo + "/releases/tags/" + opts.Tag
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return githubRelease{}, fmt.Errorf("build release request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token := firstNonEmpty(os.Getenv("GH_TOKEN"), os.Getenv("GITHUB_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return githubRelease{}, fmt.Errorf("fetch release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return githubRelease{}, fmt.Errorf("fetch release: GitHub returned %s", resp.Status)
	}
	var release githubRelease
	dec := json.NewDecoder(io.LimitReader(resp.Body, 4<<20))
	if err := dec.Decode(&release); err != nil {
		return githubRelease{}, fmt.Errorf("decode release: %w", err)
	}
	return release, nil
}

func expectedAssets() []string {
	return []string{
		"checksums.txt",
		"claude-gatekeeper_darwin_amd64.tar.gz",
		"claude-gatekeeper_darwin_arm64.tar.gz",
		"claude-gatekeeper_linux_amd64.tar.gz",
		"claude-gatekeeper_linux_arm64.tar.gz",
		"claude-gatekeeper_windows_amd64.zip",
		"claude-gatekeeper_windows_arm64.zip",
	}
}

func missingAssets(assets map[string]string) []string {
	var missing []string
	for _, name := range expectedAssets() {
		if assets[name] == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

func assetName(goos, goarch string) string {
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return "claude-gatekeeper_" + goos + "_" + goarch + ext
}

func download(ctx context.Context, client *http.Client, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("server returned %s", resp.Status)
	}
	file, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, io.LimitReader(resp.Body, 256<<20))
	closeErr := file.Close()
	return errors.Join(copyErr, closeErr)
}

func checksumFor(path, name string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.TrimPrefix(fields[len(fields)-1], "*") == name {
			if len(fields[0]) != sha256.Size*2 {
				return "", fmt.Errorf("invalid checksum for %s", name)
			}
			if _, err := hex.DecodeString(fields[0]); err != nil {
				return "", fmt.Errorf("invalid checksum for %s", name)
			}
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("checksums.txt has no entry for %s", name)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func extractArchive(path, dest, goos string) error {
	if goos == "windows" {
		return extractZip(path, dest)
	}
	return extractTarGzip(path, dest)
}

func extractTarGzip(path, dest string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("open gzip archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar archive: %w", err)
		}
		target, err := safeArchivePath(dest, header.Name)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode)&0777)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, io.LimitReader(tr, 256<<20))
			closeErr := out.Close()
			if err := errors.Join(copyErr, closeErr); err != nil {
				return err
			}
		}
	}
}

func extractZip(path, dest string) error {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("open zip archive: %w", err)
	}
	defer reader.Close()
	for _, entry := range reader.File {
		target, err := safeArchivePath(dest, entry.Name)
		if err != nil {
			return err
		}
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		in, err := entry.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, entry.Mode()&0777)
		if err != nil {
			in.Close()
			return err
		}
		_, copyErr := io.Copy(out, io.LimitReader(in, 256<<20))
		err = errors.Join(copyErr, in.Close(), out.Close())
		if err != nil {
			return err
		}
	}
	return nil
}

func safeArchivePath(root, name string) (string, error) {
	clean := filepath.Clean(name)
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	target := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return target, nil
}

func findBinary(root, goos string) (string, error) {
	name := "claude-gatekeeper"
	if goos == "windows" {
		name += ".exe"
	}
	var matches []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && entry.Name() == name {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(matches)
	if len(matches) != 1 {
		return "", fmt.Errorf("archive contains %d %s binaries, expected one", len(matches), name)
	}
	return matches[0], nil
}

func probeVersion(ctx context.Context, binary string) (string, error) {
	stdout, stderr, exit, err := runCommand(ctx, nil, binary, "--version")
	if err != nil {
		return "", fmt.Errorf("%s --version: %w", binary, err)
	}
	if exit != 0 {
		return "", fmt.Errorf("%s --version exited %d", binary, exit)
	}
	fields := strings.Fields(strings.TrimSpace(stdout + "\n" + stderr))
	if len(fields) < 2 || fields[0] != "claude-gatekeeper" {
		return "", fmt.Errorf("%s returned an unrecognized version stamp", binary)
	}
	return strings.TrimPrefix(fields[1], "v"), nil
}

func runDoctor(ctx context.Context, pluginBinary, hostBinary, version string, minSurfaces int) (int, string) {
	stdout, stderr, exit, err := runCommand(ctx, nil, pluginBinary,
		"doctor", "--json",
		"--expected-binary", hostBinary,
		"--expected-version", version,
		"--min-surfaces", fmt.Sprint(minSurfaces),
	)
	if err != nil {
		return 2, err.Error()
	}
	if exit != 0 {
		return exit, fmt.Sprintf("exit %d: %s", exit, compact(stdout+"\n"+stderr))
	}
	var report struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		return 2, "invalid Doctor JSON: " + err.Error()
	}
	if !report.OK {
		return 1, "Doctor returned ok=false with exit 0"
	}
	return 0, "Doctor JSON ok"
}

func runCanary(ctx context.Context, binary, harness string) (bool, string) {
	home, err := os.MkdirTemp("", "gatekeeper-release-canary-*")
	if err != nil {
		return false, err.Error()
	}
	defer os.RemoveAll(home)
	configDir := filepath.Join(home, "config", "gatekeeper")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return false, err.Error()
	}
	policy := "[[rules]]\ntool = '^Bash$'\ninput = '^" + canaryCommand + "$'\ndecision = 'deny'\nreason = '" + canaryReason + "'\n"
	if err := os.WriteFile(filepath.Join(configDir, "gatekeeper.toml"), []byte(policy), 0600); err != nil {
		return false, err.Error()
	}

	payload := map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]string{"command": canaryCommand},
		"cwd":             home,
	}
	if harness == "grok" {
		payload = map[string]any{
			"hookEventName": "pre_tool_use",
			"toolName":      "Shell",
			"toolInput":     map[string]string{"command": canaryCommand},
			"cwd":           home,
		}
	}
	input, err := json.Marshal(payload)
	if err != nil {
		return false, err.Error()
	}
	env := overrideEnv(os.Environ(), map[string]string{
		"HOME":                home,
		"XDG_CONFIG_HOME":     filepath.Join(home, "config"),
		"GATEKEEPER_ON_ERROR": "deny",
	})
	stdout, stderr, exit, err := runCommandEnv(ctx, env, bytes.NewReader(input), binary, "--harness", harness)
	if err != nil {
		return false, err.Error()
	}
	var wire map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &wire); err != nil {
		return false, "invalid deny JSON: " + err.Error() + ": " + compact(stderr)
	}
	switch harness {
	case "claude", "codex":
		if exit != 0 {
			return false, fmt.Sprintf("deny exited %d, expected 0", exit)
		}
		hook, _ := wire["hookSpecificOutput"].(map[string]any)
		if hook["permissionDecision"] != "deny" || hook["permissionDecisionReason"] != canaryReason {
			return false, "deny wire did not match expected hookSpecificOutput"
		}
	case "grok":
		if exit != 2 {
			return false, fmt.Sprintf("deny exited %d, expected 2", exit)
		}
		if wire["decision"] != "deny" || wire["reason"] != canaryReason {
			return false, "deny wire did not match expected grok decision"
		}
	default:
		return false, "unknown harness " + harness
	}
	return true, "native deny wire passed"
}

func runCommand(ctx context.Context, stdin io.Reader, binary string, args ...string) (string, string, int, error) {
	return runCommandEnv(ctx, os.Environ(), stdin, binary, args...)
}

func runCommandEnv(ctx context.Context, env []string, stdin io.Reader, binary string, args ...string) (string, string, int, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = stdin
	cmd.Env = env
	var stdout strings.Builder
	var stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return stdout.String(), stderr.String(), 2, ctx.Err()
	}
	if err == nil {
		return stdout.String(), stderr.String(), 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return stdout.String(), stderr.String(), exitErr.ExitCode(), nil
	}
	return stdout.String(), stderr.String(), 2, err
}

func finish(result Result) Result {
	result.OK = len(result.Checks) > 0
	for _, check := range result.Checks {
		if !check.OK {
			result.OK = false
			break
		}
	}
	if !result.OK && result.ExitCode == 0 {
		result.ExitCode = 1
	}
	if result.OK {
		result.ExitCode = 0
	}
	return result
}

func compact(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func overrideEnv(base []string, overrides map[string]string) []string {
	env := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		name, _, found := strings.Cut(entry, "=")
		if found {
			if _, overridden := overrides[name]; overridden {
				continue
			}
		}
		env = append(env, entry)
	}
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		env = append(env, name+"="+overrides[name])
	}
	return env
}

// WriteJSON writes the stable machine-readable report.
func WriteJSON(w io.Writer, result Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// WriteTable writes a concise human report.
func WriteTable(w io.Writer, result Result) error {
	status := "PASS"
	if !result.OK {
		status = "FAIL"
	}
	if _, err := fmt.Fprintf(w, "Release %s (%s) — %s\n", result.Tag, result.Repo, status); err != nil {
		return err
	}
	for _, check := range result.Checks {
		mark := "ok"
		if !check.OK {
			mark = "FAIL"
		}
		if _, err := fmt.Fprintf(w, "  %-4s %-20s %s\n", mark, check.Name, check.Detail); err != nil {
			return err
		}
	}
	return nil
}
