package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jim80net/claude-gatekeeper/internal/protocol"
)

// TestIntegrationBinary builds the binary and runs end-to-end tests against it.
func TestIntegrationBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	binary := buildBinary(t)

	tests := []struct {
		name  string
		input string
		want  *protocol.Decision // nil = abstain
	}{
		{
			name:  "deny rm -rf",
			input: `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/stuff"},"cwd":"/tmp"}`,
			want:  ptrI(protocol.Deny),
		},
		{
			name:  "deny sed",
			input: `{"tool_name":"Bash","tool_input":{"command":"sed -i 's/a/b/' file"},"cwd":"/tmp"}`,
			want:  ptrI(protocol.Deny),
		},
		{
			name:  "deny npm",
			input: `{"tool_name":"Bash","tool_input":{"command":"npm install express"},"cwd":"/tmp"}`,
			want:  ptrI(protocol.Deny),
		},
		{
			name:  "deny read .env",
			input: `{"tool_name":"Read","tool_input":{"file_path":"/project/.env"},"cwd":"/tmp"}`,
			want:  ptrI(protocol.Deny),
		},
		{
			name:  "allow git status",
			input: `{"tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"/tmp"}`,
			want:  ptrI(protocol.Allow),
		},
		{
			name:  "allow pnpm",
			input: `{"tool_name":"Bash","tool_input":{"command":"pnpm install"},"cwd":"/tmp"}`,
			want:  ptrI(protocol.Allow),
		},
		{
			name:  "allow Read normal file",
			input: `{"tool_name":"Read","tool_input":{"file_path":"/tmp/main.go"},"cwd":"/tmp"}`,
			want:  ptrI(protocol.Allow),
		},
		{
			name:  "allow Edit",
			input: `{"tool_name":"Edit","tool_input":{"file_path":"/tmp/main.go","old_string":"a","new_string":"b"},"cwd":"/tmp"}`,
			want:  ptrI(protocol.Allow),
		},
		{
			name:  "abstain unknown",
			input: `{"tool_name":"Bash","tool_input":{"command":"exotic-thing"},"cwd":"/tmp"}`,
			want:  nil,
		},
		{
			name:  "abstain malformed json",
			input: `{not json}`,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binary)
			cmd.Stdin = strings.NewReader(tt.input)
			cmd.Env = append(os.Environ(), "HOME=/tmp/nonexistent-home")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("binary exited with error: %v", err)
			}

			if tt.want == nil {
				if len(strings.TrimSpace(string(out))) > 0 {
					t.Errorf("expected empty stdout (abstain), got: %s", out)
				}
				return
			}

			var result protocol.HookOutput
			if err := json.Unmarshal(out, &result); err != nil {
				t.Fatalf("unmarshal output: %v\nraw: %s", err, out)
			}
			if result.HookSpecificOutput.PermissionDecision != *tt.want {
				t.Errorf("got %s (%s), want %s",
					result.HookSpecificOutput.PermissionDecision,
					result.HookSpecificOutput.PermissionDecisionReason,
					*tt.want)
			}
		})
	}
}

func ptrI(d protocol.Decision) *protocol.Decision { return &d }

func buildBinary(t *testing.T) string {
	t.Helper()
	binary := t.TempDir() + "/claude-gatekeeper"
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return binary
}
