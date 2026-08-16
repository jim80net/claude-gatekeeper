package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestHelpIsDiscoverable(t *testing.T) {
	command := exec.Command("go", "run", ".", "--help")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("help failed: %v\n%s", err, output)
	}
	for _, want := range []string{"-harness", "-native-executable", "-gatekeeper-executable"} {
		if !strings.Contains(string(output), want) {
			t.Errorf("help omitted %q:\n%s", want, output)
		}
	}
}
