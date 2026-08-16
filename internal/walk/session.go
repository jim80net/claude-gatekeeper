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
	Scenario           string
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
	Schema      string             `json:"schema"`
	Status      string             `json:"status"`
	Harness     string             `json:"harness"`
	Lifecycle   string             `json:"lifecycle"`
	Transition  *SessionTransition `json:"transition,omitempty"`
	Attestation *FiringAttestation `json:"attestation,omitempty"`
}

type SessionTransition struct {
	Kind         string `json:"kind"`
	BeforePID    int    `json:"before_pid"`
	AfterPID     int    `json:"after_pid,omitempty"`
	BeforeReason string `json:"before_reason,omitempty"`
	AfterReason  string `json:"after_reason,omitempty"`
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
	scenario := opts.Scenario
	if scenario == "" {
		scenario = "steady"
	}
	if scenario != "steady" && scenario != "interrupted" && scenario != "restart" && scenario != "config-change" {
		return DisposableSessionResult{}, fmt.Errorf("unsupported session scenario %q", scenario)
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
		inspect = inspectProcess
	}
	identity, err := inspect(ready.NativePID)
	if err != nil {
		return DisposableSessionResult{}, fmt.Errorf("inspect ready native process: %w", err)
	}
	if !sameExecutable(identity.Executable, expectedExecutable) {
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
	if scenario == "interrupted" {
		interrupted, err := runSessionArm(encoder, decoder, "interrupt", ready.NativePID)
		if err != nil {
			return DisposableSessionResult{}, driverStepError(ctx, "interrupt", err, stderr.String())
		}
		if interrupted.Status != "interrupted" {
			return DisposableSessionResult{}, fmt.Errorf("interrupt status = %q, want interrupted", interrupted.Status)
		}
		_ = stdin.Close()
		if err := cmd.Wait(); err != nil {
			waited = true
			return DisposableSessionResult{}, driverProtocolError("interrupt", err, stderr.String())
		}
		waited = true
		if current, err := inspect(identity.PID); err == nil && sameProcessIdentity(current, identity) {
			return DisposableSessionResult{}, errors.New("interrupted native process remains live")
		}
		return DisposableSessionResult{
			Schema: SessionDriverSchema, Status: "no_data", Harness: opts.Harness,
			Lifecycle:  "interrupted_after_benign",
			Transition: &SessionTransition{Kind: "interrupt", BeforePID: identity.PID},
		}, nil
	}

	var transition *SessionTransition
	if scenario == "restart" {
		restarted, err := runSessionArmAnyPID(encoder, decoder, "restart")
		if err != nil {
			return DisposableSessionResult{}, driverStepError(ctx, "restart", err, stderr.String())
		}
		if restarted.Status != "restarted" || restarted.NativePID <= 0 || restarted.NativePID == identity.PID {
			return DisposableSessionResult{}, errors.New("restart response must name a distinct ready PID")
		}
		newIdentity, err := inspect(restarted.NativePID)
		if err != nil {
			return DisposableSessionResult{}, fmt.Errorf("inspect restarted native process: %w", err)
		}
		if !sameExecutable(newIdentity.Executable, expectedExecutable) {
			return DisposableSessionResult{}, fmt.Errorf("restarted native executable = %q, want %q", newIdentity.Executable, expectedExecutable)
		}
		if current, err := inspect(identity.PID); err == nil && sameProcessIdentity(current, identity) {
			return DisposableSessionResult{}, errors.New("restart left the prior native process live")
		}
		transition = &SessionTransition{Kind: "restart", BeforePID: identity.PID, AfterPID: newIdentity.PID}
		identity = newIdentity
		ready.NativePID = newIdentity.PID
		benign, err = runSessionArm(encoder, decoder, "benign", ready.NativePID)
		if err != nil {
			return DisposableSessionResult{}, driverStepError(ctx, "post-restart benign", err, stderr.String())
		}
		if benign.Status != "reached" {
			return DisposableSessionResult{}, fmt.Errorf("post-restart benign status = %q, want reached", benign.Status)
		}
		if err := requireSameProcess(identity, inspect); err != nil {
			return DisposableSessionResult{}, fmt.Errorf("post-restart benign process identity: %w", err)
		}
	}

	if scenario == "config-change" {
		initialDeny, err := runSessionArm(encoder, decoder, "deny", ready.NativePID)
		if err != nil {
			return DisposableSessionResult{}, driverStepError(ctx, "pre-change deny", err, stderr.String())
		}
		if initialDeny.Status != "pretool_denied" || strings.TrimSpace(initialDeny.Reason) == "" {
			return DisposableSessionResult{}, errors.New("pre-change deny must carry its reason")
		}
		changed, err := runSessionArm(encoder, decoder, "config_change", ready.NativePID)
		if err != nil {
			return DisposableSessionResult{}, driverStepError(ctx, "config change", err, stderr.String())
		}
		if changed.Status != "updated" || strings.TrimSpace(changed.Reason) == "" || changed.Reason == initialDeny.Reason {
			return DisposableSessionResult{}, errors.New("config change must name a distinct expected deny reason")
		}
		transition = &SessionTransition{
			Kind: "config_change", BeforePID: identity.PID, AfterPID: identity.PID,
			BeforeReason: initialDeny.Reason, AfterReason: changed.Reason,
		}
		benign, err = runSessionArm(encoder, decoder, "benign", ready.NativePID)
		if err != nil {
			return DisposableSessionResult{}, driverStepError(ctx, "post-change benign", err, stderr.String())
		}
		if benign.Status != "reached" {
			return DisposableSessionResult{}, fmt.Errorf("post-change benign status = %q, want reached", benign.Status)
		}
		if err := requireSameProcess(identity, inspect); err != nil {
			return DisposableSessionResult{}, fmt.Errorf("post-change benign process identity: %w", err)
		}
	}

	deny, err := runSessionArm(encoder, decoder, "deny", ready.NativePID)
	if err != nil {
		return DisposableSessionResult{}, driverStepError(ctx, "deny", err, stderr.String())
	}
	if deny.Status != "pretool_denied" || strings.TrimSpace(deny.Reason) == "" {
		return DisposableSessionResult{}, errors.New("deny arm must be pretool_denied with a reason")
	}
	if transition != nil && transition.Kind == "config_change" && deny.Reason != transition.AfterReason {
		return DisposableSessionResult{}, fmt.Errorf("post-change deny reason = %q, want %q", deny.Reason, transition.AfterReason)
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
		Lifecycle: lifecycleForScenario(scenario), Transition: transition, Attestation: &attestation,
	}, nil
}

func lifecycleForScenario(scenario string) string {
	switch scenario {
	case "restart":
		return "restarted_then_closed"
	case "config-change":
		return "config_changed_then_closed"
	default:
		return "closed_after_observation"
	}
}

func runSessionArm(encoder *json.Encoder, decoder *json.Decoder, arm string, pid int) (SessionDriverResponse, error) {
	response, err := runSessionArmAnyPID(encoder, decoder, arm)
	if err != nil {
		return response, err
	}
	if response.NativePID != pid {
		return SessionDriverResponse{}, fmt.Errorf("native PID changed from %d to %d", pid, response.NativePID)
	}
	return response, nil
}

func runSessionArmAnyPID(encoder *json.Encoder, decoder *json.Decoder, arm string) (SessionDriverResponse, error) {
	if err := encoder.Encode(SessionDriverRequest{Schema: SessionDriverSchema, Arm: arm}); err != nil {
		return SessionDriverResponse{}, err
	}
	response, err := readSessionResponse(decoder, arm)
	if err != nil {
		return SessionDriverResponse{}, err
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
	if !sameProcessIdentity(current, expected) {
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
