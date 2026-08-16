//go:build windows

package walk

import (
	"os"
	"testing"
)

func TestInspectWindowsProcessBindsExecutableAndCreationTime(t *testing.T) {
	first, err := inspectProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	second, err := inspectProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if first.PID != os.Getpid() || first.Executable == "" || first.StartTicks == "0" || first.StartTicks == "" {
		t.Fatalf("incomplete Windows identity: %#v", first)
	}
	if !sameProcessIdentity(first, second) {
		t.Fatalf("stable Windows process did not retain identity: first=%#v second=%#v", first, second)
	}
}

func TestWindowsExecutableComparisonIgnoresCase(t *testing.T) {
	if !sameExecutable(`C:\\Program Files\\Harness.EXE`, `c:\\program files\\harness.exe`) {
		t.Fatal("Windows executable comparison must be case-insensitive")
	}
}
