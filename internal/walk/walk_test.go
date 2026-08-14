package walk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestReleaseMatrixUsesExactCandidateAndOppositeRootControls(t *testing.T) {
	candidate := buildCandidate(t, "matrix-test")
	sha, err := fileSHA256(candidate)
	if err != nil {
		t.Fatal(err)
	}
	result, err := RunReleaseMatrix(context.Background(), ReleaseMatrixOptions{Candidate: candidate, CandidateSHA256: sha, ExpectedVersion: "matrix-test"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.CandidateSHA256 != sha || result.FiringStatusBound != firingNotTested || len(result.Roots) != 3 {
		t.Fatalf("result=%#v", result)
	}
	want := map[string]struct {
		status string
		exit   int
		source string
	}{"default": {"registered", 0, "default"}, "leadership": {"absent", 1, "environment"}, "overflow": {"absent", 1, "environment"}}
	for _, arm := range result.Roots {
		expected := want[arm.Name]
		if !arm.OK || arm.ObservedStatus != expected.status || arm.ObservedExit != expected.exit || arm.ObservedRoot != arm.Root || arm.ObservedRootSource != expected.source || arm.FiringStatus != firingNotTested {
			t.Errorf("arm=%#v", arm)
		}
	}
}

func TestReleaseMatrixRejectsWrongCandidateIdentity(t *testing.T) {
	candidate := buildCandidate(t, "matrix-test")
	_, err := RunReleaseMatrix(context.Background(), ReleaseMatrixOptions{Candidate: candidate, CandidateSHA256: string(make([]byte, sha256.Size*2)), ExpectedVersion: "matrix-test"})
	if err == nil {
		t.Fatal("wrong candidate SHA-256 was accepted")
	}
}

func TestFiringAttestationIsPIDBoundAndReplacementInvalidates(t *testing.T) {
	now := time.Date(2026, 8, 14, 3, 0, 0, 0, time.UTC)
	identity := ProcessIdentity{PID: 42, Executable: "/opt/harness", StartTicks: "100"}
	attestation, err := RecordFiring(FiringOptions{
		Harness: "claude", PID: 42, Scope: "disposable", Benign: "reached", Deny: "pretool_denied", DenyReason: "known Gatekeeper rule", Now: now,
		Inspect: func(int) (ProcessIdentity, error) { return identity, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if result := VerifyFiring(attestation, func(int) (ProcessIdentity, error) { return identity, nil }); result.Status != "pass" {
		t.Fatalf("matching process result=%#v", result)
	}
	replacement := identity
	replacement.StartTicks = "101"
	if result := VerifyFiring(attestation, func(int) (ProcessIdentity, error) { return replacement, nil }); result.Status != "no_data" {
		t.Fatalf("replacement result=%#v", result)
	}
	if result := VerifyFiring(attestation, func(int) (ProcessIdentity, error) { return ProcessIdentity{}, os.ErrNotExist }); result.Status != "no_data" {
		t.Fatalf("dead process result=%#v", result)
	}
}

func TestFiringAttestationRejectsStaticOrIncompleteEvidence(t *testing.T) {
	for name, opts := range map[string]FiringOptions{
		"no pid":         {Harness: "claude", Scope: "disposable", Benign: "reached", Deny: "pretool_denied", DenyReason: "reason"},
		"not disposable": {Harness: "claude", PID: 42, Scope: "static", Benign: "reached", Deny: "pretool_denied", DenyReason: "reason"},
		"no benign":      {Harness: "claude", PID: 42, Scope: "disposable", Deny: "pretool_denied", DenyReason: "reason"},
		"no deny reason": {Harness: "claude", PID: 42, Scope: "disposable", Benign: "reached", Deny: "pretool_denied"},
	} {
		t.Run(name, func(t *testing.T) {
			opts.Inspect = func(int) (ProcessIdentity, error) { return ProcessIdentity{PID: 42}, nil }
			if _, err := RecordFiring(opts); err == nil {
				t.Fatal("incomplete evidence was accepted")
			}
		})
	}
}

func buildCandidate(t *testing.T, version string) string {
	t.Helper()
	candidate := filepath.Join(t.TempDir(), "claude-gatekeeper")
	cmd := exec.Command("go", "build", "-ldflags", "-X main.version="+version, "-o", candidate, "../../cmd/claude-gatekeeper")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build candidate: %v\n%s", err, output)
	}
	return candidate
}

func TestWriteAndReadAttestation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attestation.json")
	value := FiringAttestation{Schema: firingSchema, Status: "pass", Harness: "claude", Scope: "disposable"}
	if err := WriteJSONFile(path, value); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) == "" {
		t.Fatal("empty digest")
	}
	read, err := ReadAttestation(path)
	if err != nil || read.Schema != firingSchema {
		t.Fatalf("read=%#v err=%v", read, err)
	}
}
