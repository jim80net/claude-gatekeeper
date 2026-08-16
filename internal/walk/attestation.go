package walk

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const firingSchema = "gatekeeper.firing-attestation/v1"

type FiringOptions struct {
	Harness    string
	PID        int
	Scope      string
	Benign     string
	Deny       string
	DenyReason string
	Now        time.Time
	Inspect    func(int) (ProcessIdentity, error)
}

type ProcessIdentity struct {
	PID        int    `json:"pid"`
	Executable string `json:"executable"`
	StartTicks string `json:"start_ticks"`
}

type FiringAttestation struct {
	Schema     string          `json:"schema"`
	Status     string          `json:"status"`
	Harness    string          `json:"harness"`
	Scope      string          `json:"session_scope"`
	ObservedAt time.Time       `json:"observed_at"`
	Process    ProcessIdentity `json:"process"`
	Benign     FiringArm       `json:"benign"`
	Deny       FiringArm       `json:"deny"`
}

type FiringArm struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type AttestationVerification struct {
	Status  string          `json:"status"`
	Reason  string          `json:"reason"`
	Process ProcessIdentity `json:"process"`
}

func RecordFiring(opts FiringOptions) (FiringAttestation, error) {
	if opts.Harness != "claude" && opts.Harness != "codex" && opts.Harness != "grok" {
		return FiringAttestation{}, fmt.Errorf("unsupported harness %q", opts.Harness)
	}
	if opts.Scope != "disposable" {
		return FiringAttestation{}, errors.New("session scope must be disposable")
	}
	if opts.PID <= 0 {
		return FiringAttestation{}, errors.New("live session PID is required")
	}
	if opts.Benign != "reached" {
		return FiringAttestation{}, errors.New("benign arm must be reached")
	}
	if opts.Deny != "pretool_denied" || strings.TrimSpace(opts.DenyReason) == "" {
		return FiringAttestation{}, errors.New("deny arm must be pretool_denied with a reason")
	}
	inspect := opts.Inspect
	if inspect == nil {
		inspect = inspectProcess
	}
	process, err := inspect(opts.PID)
	if err != nil {
		return FiringAttestation{}, fmt.Errorf("inspect live session: %w", err)
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return FiringAttestation{
		Schema:     firingSchema,
		Status:     "pass",
		Harness:    opts.Harness,
		Scope:      opts.Scope,
		ObservedAt: now,
		Process:    process,
		Benign:     FiringArm{Status: opts.Benign},
		Deny:       FiringArm{Status: opts.Deny, Reason: opts.DenyReason},
	}, nil
}

func VerifyFiring(attestation FiringAttestation, inspect func(int) (ProcessIdentity, error)) AttestationVerification {
	if attestation.Schema != firingSchema || attestation.Status != "pass" || attestation.Scope != "disposable" ||
		attestation.Benign.Status != "reached" || attestation.Deny.Status != "pretool_denied" || attestation.Deny.Reason == "" {
		return AttestationVerification{Status: "invalid", Reason: "attestation contract is incomplete"}
	}
	if inspect == nil {
		inspect = inspectProcess
	}
	current, err := inspect(attestation.Process.PID)
	if err != nil {
		return AttestationVerification{Status: "no_data", Reason: "recorded process is no longer live: " + err.Error()}
	}
	if !sameProcessIdentity(current, attestation.Process) {
		return AttestationVerification{Status: "no_data", Reason: "recorded process was replaced", Process: current}
	}
	return AttestationVerification{Status: "pass", Reason: "recorded process identity still matches", Process: current}
}

func WriteJSONFile(path string, value any) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".gatekeeper-walk-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return err
	}
	encoder := json.NewEncoder(temp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func ReadAttestation(path string) (FiringAttestation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FiringAttestation{}, err
	}
	var attestation FiringAttestation
	if err := json.Unmarshal(data, &attestation); err != nil {
		return FiringAttestation{}, err
	}
	return attestation, nil
}
