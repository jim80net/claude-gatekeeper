package walk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const SessionDriverSchema = "gatekeeper.session-driver/v1"

type SessionDriverOptions struct {
	Harness            string
	Driver             string
	ExpectedExecutable string
	Args               []string
	TempParent         string
	Now                time.Time
	Inspect            func(int) (ProcessIdentity, error)
}

type SessionDriverRequest struct {
	Schema string `json:"schema"`
	Arm    string `json:"arm"`
}

type SessionDriverResponse struct {
	Schema    string `json:"schema"`
	Arm       string `json:"arm"`
	NativePID int    `json:"native_pid"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
}

type DisposableSessionResult struct {
	Schema      string            `json:"schema"`
	Status      string            `json:"status"`
	Harness     string            `json:"harness"`
	Lifecycle   string            `json:"lifecycle"`
	Attestation FiringAttestation `json:"attestation"`
}

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

// RunDisposableSession drives an external harness adapter through a bounded
// JSONL protocol. The adapter must start the real native harness in the supplied
// disposable environment and report that process's PID on every response.
func RunDisposableSession(ctx context.Context, opts SessionDriverOptions) (DisposableSessionResult, error) {
	if opts.Harness != "claude" && opts.Harness != "codex" && opts.Harness != "grok" {
		return DisposableSessionResult{}, fmt.Errorf("unsupported harness %q", opts.Harness)
	}
	if strings.TrimSpace(opts.Driver) == "" || !filepath.IsAbs(opts.Driver) {
		return DisposableSessionResult{}, errors.New("absolute session driver path is required")
	}
	driver := filepath.Clean(opts.Driver)
	info, err := os.Stat(driver)
	if err != nil {
		return DisposableSessionResult{}, fmt.Errorf("stat session driver: %w", err)
	}
	if !info.Mode().IsRegular() {
		return DisposableSessionResult{}, errors.New("session driver must be a regular file")
	}
	if strings.TrimSpace(opts.ExpectedExecutable) == "" || !filepath.IsAbs(opts.ExpectedExecutable) {
		return DisposableSessionResult{}, errors.New("absolute expected native executable path is required")
	}
	expectedExecutable, err := filepath.EvalSymlinks(opts.ExpectedExecutable)
	if err != nil {
		return DisposableSessionResult{}, fmt.Errorf("resolve expected native executable: %w", err)
	}

	root, err := os.MkdirTemp(opts.TempParent, "gatekeeper-walk-session-*")
	if err != nil {
		return DisposableSessionResult{}, fmt.Errorf("create disposable session root: %w", err)
	}
	defer os.RemoveAll(root)
	envPaths := map[string]string{
		"HOME":                  filepath.Join(root, "home"),
		"CLAUDE_CONFIG_DIR":     filepath.Join(root, "claude"),
		"CODEX_HOME":            filepath.Join(root, "codex"),
		"XDG_CONFIG_HOME":       filepath.Join(root, "xdg", "config"),
		"XDG_CACHE_HOME":        filepath.Join(root, "xdg", "cache"),
		"XDG_DATA_HOME":         filepath.Join(root, "xdg", "data"),
		"GATEKEEPER_WALK_SCOPE": "disposable",
	}
	for key, path := range envPaths {
		if key == "GATEKEEPER_WALK_SCOPE" {
			continue
		}
		if err := os.MkdirAll(path, 0o700); err != nil {
			return DisposableSessionResult{}, fmt.Errorf("create %s: %w", key, err)
		}
	}

	cmd := exec.CommandContext(ctx, driver, opts.Args...)
	cmd.Env = overrideEnv(os.Environ(), envPaths)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return DisposableSessionResult{}, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return DisposableSessionResult{}, err
	}
	var stderr synchronizedBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return DisposableSessionResult{}, fmt.Errorf("start session driver: %w", err)
	}
	waited := false
	defer func() {
		_ = stdin.Close()
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	decoder := json.NewDecoder(stdout)
	encoder := json.NewEncoder(stdin)
	ready, err := readSessionResponse(decoder, "ready")
	if err != nil {
		return DisposableSessionResult{}, driverStepError(ctx, "ready", err, stderr.String())
	}
	if ready.Status != "ready" || ready.NativePID <= 0 {
		return DisposableSessionResult{}, fmt.Errorf("session driver ready response is incomplete")
	}
	inspect := opts.Inspect
	if inspect == nil {
		inspect = inspectLinuxProcess
	}
	identity, err := inspect(ready.NativePID)
	if err != nil {
		return DisposableSessionResult{}, fmt.Errorf("inspect ready native process: %w", err)
	}
	if identity.Executable != expectedExecutable {
		return DisposableSessionResult{}, fmt.Errorf("native executable = %q, want %q", identity.Executable, expectedExecutable)
	}

	benign, err := runSessionArm(encoder, decoder, "benign", ready.NativePID)
	if err != nil {
		return DisposableSessionResult{}, driverStepError(ctx, "benign", err, stderr.String())
	}
	if benign.Status != "reached" {
		return DisposableSessionResult{}, fmt.Errorf("benign arm status = %q, want reached", benign.Status)
	}
	if err := requireSameProcess(identity, inspect); err != nil {
		return DisposableSessionResult{}, fmt.Errorf("benign arm process identity: %w", err)
	}

	deny, err := runSessionArm(encoder, decoder, "deny", ready.NativePID)
	if err != nil {
		return DisposableSessionResult{}, driverStepError(ctx, "deny", err, stderr.String())
	}
	if deny.Status != "pretool_denied" || strings.TrimSpace(deny.Reason) == "" {
		return DisposableSessionResult{}, errors.New("deny arm must be pretool_denied with a reason")
	}
	if err := requireSameProcess(identity, inspect); err != nil {
		return DisposableSessionResult{}, fmt.Errorf("deny arm process identity: %w", err)
	}

	attestation, err := RecordFiring(FiringOptions{
		Harness: opts.Harness, PID: ready.NativePID, Scope: "disposable",
		Benign: "reached", Deny: "pretool_denied", DenyReason: deny.Reason,
		Now: opts.Now, Inspect: inspect,
	})
	if err != nil {
		return DisposableSessionResult{}, err
	}
	if err := encoder.Encode(SessionDriverRequest{Schema: SessionDriverSchema, Arm: "close"}); err != nil {
		return DisposableSessionResult{}, driverProtocolError("close", err, stderr.String())
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		waited = true
		return DisposableSessionResult{}, driverProtocolError("close", err, stderr.String())
	}
	waited = true
	return DisposableSessionResult{
		Schema: SessionDriverSchema, Status: "pass", Harness: opts.Harness,
		Lifecycle: "closed_after_observation", Attestation: attestation,
	}, nil
}

func runSessionArm(encoder *json.Encoder, decoder *json.Decoder, arm string, pid int) (SessionDriverResponse, error) {
	if err := encoder.Encode(SessionDriverRequest{Schema: SessionDriverSchema, Arm: arm}); err != nil {
		return SessionDriverResponse{}, err
	}
	response, err := readSessionResponse(decoder, arm)
	if err != nil {
		return SessionDriverResponse{}, err
	}
	if response.NativePID != pid {
		return SessionDriverResponse{}, fmt.Errorf("native PID changed from %d to %d", pid, response.NativePID)
	}
	return response, nil
}

func readSessionResponse(decoder *json.Decoder, arm string) (SessionDriverResponse, error) {
	var response SessionDriverResponse
	if err := decoder.Decode(&response); err != nil {
		return response, err
	}
	if response.Schema != SessionDriverSchema || response.Arm != arm {
		return response, fmt.Errorf("response schema/arm = %q/%q, want %q/%q", response.Schema, response.Arm, SessionDriverSchema, arm)
	}
	return response, nil
}

func requireSameProcess(expected ProcessIdentity, inspect func(int) (ProcessIdentity, error)) error {
	current, err := inspect(expected.PID)
	if err != nil {
		return err
	}
	if current != expected {
		return fmt.Errorf("native process was replaced: expected %#v, got %#v", expected, current)
	}
	return nil
}

func driverProtocolError(arm string, err error, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return fmt.Errorf("session driver %s: %w", arm, err)
	}
	return fmt.Errorf("session driver %s: %w (stderr: %s)", arm, err, stderr)
}

func driverStepError(ctx context.Context, arm string, err error, stderr string) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("session driver %s: %w", arm, ctxErr)
	}
	return driverProtocolError(arm, err, stderr)
}
