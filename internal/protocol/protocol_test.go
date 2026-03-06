package protocol_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jim80net/claude-gatekeeper/internal/protocol"
)

func TestReadInput(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
		check   func(*testing.T, *protocol.HookInput)
	}{
		{
			name: "bash command",
			json: `{"tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"/tmp","session_id":"s1"}`,
			check: func(t *testing.T, h *protocol.HookInput) {
				if h.ToolName != "Bash" {
					t.Errorf("ToolName = %q, want Bash", h.ToolName)
				}
				if h.CWD != "/tmp" {
					t.Errorf("CWD = %q, want /tmp", h.CWD)
				}
			},
		},
		{
			name: "edit command",
			json: `{"tool_name":"Edit","tool_input":{"file_path":"/tmp/foo.go","old_string":"a","new_string":"b"}}`,
			check: func(t *testing.T, h *protocol.HookInput) {
				if h.ToolName != "Edit" {
					t.Errorf("ToolName = %q, want Edit", h.ToolName)
				}
			},
		},
		{
			name:    "invalid json",
			json:    `{not json}`,
			wantErr: true,
		},
		{
			name:    "empty input",
			json:    ``,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := protocol.ReadInput(strings.NewReader(tt.json))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, input)
			}
		})
	}
}

func TestWriteOutput(t *testing.T) {
	out := &protocol.HookOutput{
		HookSpecificOutput: &protocol.HookSpecificOutput{
			HookEventName:           "PreToolUse",
			PermissionDecision:      protocol.Deny,
			PermissionDecisionReason: "test reason",
		},
	}

	var buf bytes.Buffer
	if err := protocol.WriteOutput(&buf, out); err != nil {
		t.Fatalf("WriteOutput: %v", err)
	}

	var parsed protocol.HookOutput
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if parsed.HookSpecificOutput.PermissionDecision != protocol.Deny {
		t.Errorf("decision = %q, want deny", parsed.HookSpecificOutput.PermissionDecision)
	}
	if parsed.HookSpecificOutput.PermissionDecisionReason != "test reason" {
		t.Errorf("reason = %q, want %q", parsed.HookSpecificOutput.PermissionDecisionReason, "test reason")
	}
}

func TestExtractInputString(t *testing.T) {
	tests := []struct {
		tool  string
		input string
		want  string
	}{
		{"Bash", `{"command":"git status"}`, "git status"},
		{"Read", `{"file_path":"/tmp/foo"}`, "/tmp/foo"},
		{"Write", `{"file_path":"/tmp/bar","content":"hello"}`, "/tmp/bar"},
		{"Edit", `{"file_path":"/tmp/baz","old_string":"a","new_string":"b"}`, "/tmp/baz"},
		{"Glob", `{"pattern":"**/*.go"}`, "**/*.go"},
		{"Grep", `{"pattern":"TODO","path":"/src"}`, "TODO"},
		{"WebFetch", `{"url":"https://example.com"}`, "https://example.com"},
		{"WebSearch", `{"query":"golang regex"}`, "golang regex"},
		{"Agent", `{"subagent_type":"Explore"}`, "Explore"},
		{"mcp__github__search", `{"query":"test"}`, "mcp__github__search"},
		{"Unknown", `{"anything":"value"}`, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			got := protocol.ExtractInputString(tt.tool, json.RawMessage(tt.input))
			if got != tt.want {
				t.Errorf("ExtractInputString(%s) = %q, want %q", tt.tool, got, tt.want)
			}
		})
	}
}
