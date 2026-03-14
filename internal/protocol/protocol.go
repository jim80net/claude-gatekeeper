// Package protocol handles the Claude Code hook JSON wire format.
package protocol

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// DebugEnabled controls whether Debugf writes to stderr.
var DebugEnabled bool

// HookInput represents the JSON sent to the hook on stdin.
type HookInput struct {
	SessionID      string          `json:"session_id"`
	CWD            string          `json:"cwd"`
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolUseID      string          `json:"tool_use_id"`
	PermissionMode string          `json:"permission_mode"`
}

// Decision is the permission decision type.
type Decision string

const (
	Allow Decision = "allow"
	Deny  Decision = "deny"
)

// HookOutput is the top-level response written to stdout.
type HookOutput struct {
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

// HookSpecificOutput carries the PreToolUse permission decision.
type HookSpecificOutput struct {
	HookEventName            string   `json:"hookEventName"`
	PermissionDecision       Decision `json:"permissionDecision"`
	PermissionDecisionReason string   `json:"permissionDecisionReason,omitempty"`
}

// ReadInput parses hook input from r.
func ReadInput(r io.Reader) (*HookInput, error) {
	var input HookInput
	if err := json.NewDecoder(r).Decode(&input); err != nil {
		return nil, fmt.Errorf("parsing hook input: %w", err)
	}
	return &input, nil
}

// WriteOutput serialises hook output to w.
func WriteOutput(w io.Writer, output *HookOutput) error {
	return json.NewEncoder(w).Encode(output)
}

// ExtractInputString returns the primary matchable string from tool_input.
func ExtractInputString(toolName string, raw json.RawMessage) string {
	switch toolName {
	case "Bash":
		var v struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(raw, &v) == nil {
			return v.Command
		}
	case "Read", "Write", "Edit":
		var v struct {
			FilePath string `json:"file_path"`
		}
		if json.Unmarshal(raw, &v) == nil {
			return v.FilePath
		}
	case "Glob":
		var v struct {
			Pattern string `json:"pattern"`
		}
		if json.Unmarshal(raw, &v) == nil {
			return v.Pattern
		}
	case "Grep":
		var v struct {
			Pattern string `json:"pattern"`
		}
		if json.Unmarshal(raw, &v) == nil {
			return v.Pattern
		}
	case "WebFetch":
		var v struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(raw, &v) == nil {
			return v.URL
		}
	case "WebSearch":
		var v struct {
			Query string `json:"query"`
		}
		if json.Unmarshal(raw, &v) == nil {
			return v.Query
		}
	case "Agent":
		var v struct {
			SubagentType string `json:"subagent_type"`
		}
		if json.Unmarshal(raw, &v) == nil {
			return v.SubagentType
		}
	default:
		// MCP and unknown tools: match against tool_name itself
		return toolName
	}
	return string(raw)
}

// Debugf writes debug output to stderr when DebugEnabled is true.
func Debugf(format string, args ...interface{}) {
	if DebugEnabled {
		fmt.Fprintf(os.Stderr, "[gatekeeper] "+format+"\n", args...)
	}
}
