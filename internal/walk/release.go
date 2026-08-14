package walk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const firingNotTested = "not_tested"

type ReleaseMatrixOptions struct {
	Candidate       string
	CandidateSHA256 string
	ExpectedVersion string
}

type ReleaseMatrixResult struct {
	OK                bool            `json:"ok"`
	Candidate         string          `json:"candidate"`
	CandidateSHA256   string          `json:"candidate_sha256"`
	CandidateVersion  string          `json:"candidate_version"`
	FiringStatusBound string          `json:"firing_status_bound"`
	Roots             []RootMatrixArm `json:"roots"`
}

type RootMatrixArm struct {
	Name               string `json:"name"`
	Root               string `json:"root"`
	ExpectedStatus     string `json:"expected_status"`
	ExpectedExit       int    `json:"expected_exit"`
	ObservedStatus     string `json:"observed_status"`
	ObservedExit       int    `json:"observed_exit"`
	ObservedRoot       string `json:"observed_root"`
	ObservedRootSource string `json:"observed_root_source"`
	FiringStatus       string `json:"firing_status"`
	OK                 bool   `json:"ok"`
	Detail             string `json:"detail,omitempty"`
}

type doctorMatrixReport struct {
	OK                 bool   `json:"ok"`
	ClaudeRoot         string `json:"claude_root"`
	ClaudeRootSource   string `json:"claude_root_source"`
	RequiredHarness    string `json:"required_harness"`
	ClaudeRegistration struct {
		Status       string `json:"status"`
		FiringStatus string `json:"firing_status"`
	} `json:"claude_registration"`
}

func RunReleaseMatrix(ctx context.Context, opts ReleaseMatrixOptions) (ReleaseMatrixResult, error) {
	candidate, err := filepath.Abs(opts.Candidate)
	if err != nil {
		return ReleaseMatrixResult{}, fmt.Errorf("resolve candidate: %w", err)
	}
	if opts.CandidateSHA256 == "" {
		return ReleaseMatrixResult{}, errors.New("candidate SHA-256 is required")
	}
	if opts.ExpectedVersion == "" {
		return ReleaseMatrixResult{}, errors.New("expected version is required")
	}
	info, err := os.Stat(candidate)
	if err != nil {
		return ReleaseMatrixResult{}, fmt.Errorf("stat candidate: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return ReleaseMatrixResult{}, errors.New("candidate must be a regular executable file")
	}
	if filepath.Base(candidate) != "claude-gatekeeper" {
		return ReleaseMatrixResult{}, errors.New("candidate filename must be claude-gatekeeper")
	}
	observedSHA, err := fileSHA256(candidate)
	if err != nil {
		return ReleaseMatrixResult{}, err
	}
	if !strings.EqualFold(observedSHA, opts.CandidateSHA256) {
		return ReleaseMatrixResult{}, fmt.Errorf("candidate SHA-256 mismatch: expected %s, got %s", opts.CandidateSHA256, observedSHA)
	}
	version, err := candidateVersion(ctx, candidate)
	if err != nil {
		return ReleaseMatrixResult{}, err
	}
	if version != strings.TrimPrefix(opts.ExpectedVersion, "v") {
		return ReleaseMatrixResult{}, fmt.Errorf("candidate version mismatch: expected %s, got %s", strings.TrimPrefix(opts.ExpectedVersion, "v"), version)
	}

	fixture, err := os.MkdirTemp("", "gatekeeper-release-matrix-*")
	if err != nil {
		return ReleaseMatrixResult{}, fmt.Errorf("create matrix fixture: %w", err)
	}
	defer os.RemoveAll(fixture)
	home := filepath.Join(fixture, "home")
	if err := os.MkdirAll(home, 0700); err != nil {
		return ReleaseMatrixResult{}, err
	}

	arms := []struct {
		name, root, rootSource, expectedStatus string
		expectedExit                           int
		provisioned                            bool
	}{
		{name: "default", root: filepath.Join(home, ".claude"), rootSource: "default", expectedStatus: "registered", expectedExit: 0, provisioned: true},
		{name: "leadership", root: filepath.Join(fixture, "accounts", "leadership", "claude-config"), rootSource: "environment", expectedStatus: "absent", expectedExit: 1},
		{name: "overflow", root: filepath.Join(fixture, "accounts", "overflow", "claude-config"), rootSource: "environment", expectedStatus: "absent", expectedExit: 1},
	}
	result := ReleaseMatrixResult{
		OK:                true,
		Candidate:         candidate,
		CandidateSHA256:   observedSHA,
		CandidateVersion:  version,
		FiringStatusBound: firingNotTested,
		Roots:             make([]RootMatrixArm, 0, len(arms)),
	}
	for _, spec := range arms {
		if err := plantClaudeRoot(spec.root, candidate, spec.provisioned); err != nil {
			return ReleaseMatrixResult{}, fmt.Errorf("plant %s root: %w", spec.name, err)
		}
		arm := runRootArm(ctx, candidate, home, spec.root, spec.rootSource, version, spec.name, spec.expectedStatus, spec.expectedExit)
		if !arm.OK {
			result.OK = false
		}
		result.Roots = append(result.Roots, arm)
	}
	return result, nil
}

func plantClaudeRoot(root, candidate string, provisioned bool) error {
	if err := os.MkdirAll(filepath.Join(root, "plugins"), 0700); err != nil {
		return err
	}
	settings := map[string]any{"hooks": map[string]any{}}
	if provisioned {
		settings = map[string]any{"hooks": map[string]any{"PreToolUse": []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": candidate + " --harness claude"}}}}}}
	}
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "settings.json"), data, 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "plugins", "installed_plugins.json"), []byte(`{"plugins":{}}`), 0600)
}

func runRootArm(ctx context.Context, candidate, home, root, rootSource, version, name, expectedStatus string, expectedExit int) RootMatrixArm {
	arm := RootMatrixArm{Name: name, Root: root, ExpectedStatus: expectedStatus, ExpectedExit: expectedExit}
	cmd := exec.CommandContext(ctx, candidate,
		"doctor", "--json",
		"--require-harness", "claude",
		"--expected-binary", candidate,
		"--expected-version", version,
		"--min-surfaces", "1",
	)
	claudeRootEnv := root
	if rootSource == "default" {
		claudeRootEnv = ""
	}
	cmd.Env = overrideEnv(os.Environ(), map[string]string{"HOME": home, "CLAUDE_CONFIG_DIR": claudeRootEnv})
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	arm.ObservedExit = commandExit(err)
	if ctx.Err() != nil {
		arm.ObservedExit = 2
		arm.Detail = ctx.Err().Error()
		return arm
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			arm.ObservedExit = 2
			arm.Detail = err.Error()
			return arm
		}
	}
	var report doctorMatrixReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		arm.Detail = "invalid Doctor JSON: " + err.Error() + ": " + strings.TrimSpace(stderr.String())
		return arm
	}
	arm.ObservedStatus = report.ClaudeRegistration.Status
	arm.ObservedRoot = report.ClaudeRoot
	arm.ObservedRootSource = report.ClaudeRootSource
	arm.FiringStatus = report.ClaudeRegistration.FiringStatus
	arm.OK = arm.ObservedExit == expectedExit &&
		arm.ObservedStatus == expectedStatus &&
		arm.ObservedRoot == root &&
		arm.ObservedRootSource == rootSource &&
		arm.FiringStatus == firingNotTested &&
		report.RequiredHarness == "claude" &&
		report.OK == (expectedExit == 0)
	if !arm.OK {
		arm.Detail = strings.TrimSpace(stderr.String())
	}
	return arm
}

func candidateVersion(ctx context.Context, candidate string) (string, error) {
	cmd := exec.CommandContext(ctx, candidate, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("candidate version probe: %w", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 || fields[0] != "claude-gatekeeper" {
		return "", errors.New("candidate returned an unrecognized version stamp")
	}
	return strings.TrimPrefix(fields[1], "v"), nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func commandExit(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 2
}

func overrideEnv(base []string, values map[string]string) []string {
	result := make([]string, 0, len(base)+len(values))
	for _, item := range base {
		key := strings.SplitN(item, "=", 2)[0]
		if _, replaced := values[key]; !replaced {
			result = append(result, item)
		}
	}
	for key, value := range values {
		result = append(result, key+"="+value)
	}
	return result
}
