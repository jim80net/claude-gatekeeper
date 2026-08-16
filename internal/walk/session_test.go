package walk

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func buildSessionDriverFixture(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Linux PID identity fixture; Windows harness driver remains open")
	}
	path := filepath.Join(t.TempDir(), "session-driver")
	cmd := exec.Command("go", "build", "-o", path, "./testdata/sessiondriver")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build session driver fixture: %v\n%s", err, output)
	}
	return path
}

func TestRunDisposableSessionRecordsPairAndPIDIdentity(t *testing.T) {
	driver := buildSessionDriverFixture(t)
	tempParent := t.TempDir()
	now := time.Date(2026, 8, 15, 3, 8, 0, 0, time.UTC)
	result, err := RunDisposableSession(context.Background(), SessionDriverOptions{
		Harness: "claude", Driver: driver, ExpectedExecutable: driver, TempParent: tempParent, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Schema != SessionDriverSchema || result.Status != "pass" || result.Lifecycle != "closed_after_observation" {
		t.Fatalf("result = %#v", result)
	}
	attestation := result.Attestation
	if attestation == nil {
		t.Fatal("steady result omitted attestation")
	}
	if attestation.Process.PID <= 0 || attestation.Process.Executable != driver || attestation.Process.StartTicks == "" ||
		attestation.ObservedAt != now || attestation.Benign.Status != "reached" ||
		attestation.Deny.Status != "pretool_denied" || attestation.Deny.Reason != "fixture known-deny rule" {
		t.Fatalf("attestation = %#v", attestation)
	}
	if verification := VerifyFiring(*attestation, nil); verification.Status != "no_data" {
		t.Fatalf("closed disposable process must expire to no_data: %#v", verification)
	}
	entries, err := os.ReadDir(tempParent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("disposable roots remain: entries=%v err=%v", entries, err)
	}
}

func TestRunDisposableSessionRecordsControlledInterruptionAsNoData(t *testing.T) {
	driver := buildSessionDriverFixture(t)
	result, err := RunDisposableSession(context.Background(), SessionDriverOptions{
		Harness: "claude", Driver: driver, ExpectedExecutable: driver,
		Scenario: "interrupted", TempParent: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "no_data" || result.Lifecycle != "interrupted_after_benign" ||
		result.Attestation != nil || result.Transition == nil || result.Transition.Kind != "interrupt" {
		t.Fatalf("interrupted result = %#v", result)
	}
}

func TestRunDisposableSessionReattestsAfterRestart(t *testing.T) {
	driver := buildSessionDriverFixture(t)
	oldPID := 0
	oldReads := 0
	result, err := RunDisposableSession(context.Background(), SessionDriverOptions{
		Harness: "codex", Driver: driver, ExpectedExecutable: driver,
		Scenario: "restart", TempParent: t.TempDir(),
		Inspect: func(pid int) (ProcessIdentity, error) {
			if oldPID == 0 {
				oldPID = pid
			}
			if pid == oldPID {
				oldReads++
				if oldReads >= 3 {
					return ProcessIdentity{}, os.ErrNotExist
				}
				return ProcessIdentity{PID: pid, Executable: driver, StartTicks: "before"}, nil
			}
			return ProcessIdentity{PID: pid, Executable: driver, StartTicks: "after"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "pass" || result.Lifecycle != "restarted_then_closed" || result.Attestation == nil ||
		result.Transition == nil || result.Transition.Kind != "restart" ||
		result.Transition.BeforePID == result.Transition.AfterPID || result.Attestation.Process.PID != result.Transition.AfterPID {
		t.Fatalf("restart result = %#v", result)
	}
}

func TestRunDisposableSessionProvesConfigChangeOnSameProcess(t *testing.T) {
	driver := buildSessionDriverFixture(t)
	result, err := RunDisposableSession(context.Background(), SessionDriverOptions{
		Harness: "grok", Driver: driver, ExpectedExecutable: driver,
		Scenario: "config-change", TempParent: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "pass" || result.Lifecycle != "config_changed_then_closed" || result.Attestation == nil ||
		result.Transition == nil || result.Transition.Kind != "config_change" ||
		result.Transition.BeforePID != result.Transition.AfterPID ||
		result.Transition.BeforeReason == result.Transition.AfterReason ||
		result.Attestation.Deny.Reason != result.Transition.AfterReason {
		t.Fatalf("config-change result = %#v", result)
	}
}

func TestRunDisposableSessionRejectsUnprovenLifecycleTransitions(t *testing.T) {
	driver := buildSessionDriverFixture(t)
	for _, tc := range []struct {
		name     string
		scenario string
		mode     string
		want     string
	}{
		{name: "restart reused PID", scenario: "restart", mode: "restart_same_pid", want: "distinct ready PID"},
		{name: "config reason unchanged", scenario: "config-change", mode: "config_same_reason", want: "distinct expected deny reason"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RunDisposableSession(context.Background(), SessionDriverOptions{
				Harness: "claude", Driver: driver, ExpectedExecutable: driver,
				Scenario: tc.scenario, Args: []string{"--mode", tc.mode}, TempParent: t.TempDir(),
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunDisposableSessionRejectsProtocolFailures(t *testing.T) {
	driver := buildSessionDriverFixture(t)
	for _, test := range []struct {
		mode string
		want string
	}{
		{mode: "benign_failed", want: "benign arm status"},
		{mode: "deny_reason_missing", want: "deny arm must be pretool_denied with a reason"},
		{mode: "pid_changed", want: "native PID changed"},
	} {
		t.Run(test.mode, func(t *testing.T) {
			_, err := RunDisposableSession(context.Background(), SessionDriverOptions{
				Harness: "codex", Driver: driver, ExpectedExecutable: driver, Args: []string{"--mode", test.mode}, TempParent: t.TempDir(),
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRunDisposableSessionRejectsProcessReplacementBetweenArms(t *testing.T) {
	driver := buildSessionDriverFixture(t)
	inspections := 0
	_, err := RunDisposableSession(context.Background(), SessionDriverOptions{
		Harness: "grok", Driver: driver, ExpectedExecutable: driver, TempParent: t.TempDir(),
		Inspect: func(pid int) (ProcessIdentity, error) {
			inspections++
			start := "100"
			if inspections >= 3 {
				start = "101"
			}
			return ProcessIdentity{PID: pid, Executable: driver, StartTicks: start}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "native process was replaced") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunDisposableSessionRejectsWrongNativeExecutable(t *testing.T) {
	driver := buildSessionDriverFixture(t)
	wrongExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	_, err = RunDisposableSession(context.Background(), SessionDriverOptions{
		Harness: "claude", Driver: driver, ExpectedExecutable: wrongExecutable, TempParent: t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "native executable") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunDisposableSessionTimeoutIsExplicit(t *testing.T) {
	driver := buildSessionDriverFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := RunDisposableSession(ctx, SessionDriverOptions{
		Harness: "claude", Driver: driver, ExpectedExecutable: driver,
		Args: []string{"--mode", "hang_on_benign"}, TempParent: t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("error = %v", err)
	}
}
