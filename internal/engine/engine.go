// Package engine evaluates gatekeeper rules against hook inputs.
package engine

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/jim80net/claude-gatekeeper/internal/config"
	"github.com/jim80net/claude-gatekeeper/internal/protocol"
)

// CompiledRule is a rule with pre-compiled regex patterns.
type CompiledRule struct {
	ToolRegex         *regexp2.Regexp
	InputRegex        *regexp2.Regexp
	PreconditionCmd   string
	PreconditionRegex *regexp2.Regexp
	Decision          protocol.Decision
	Reason            string
}

// Engine evaluates rules and returns permission decisions.
type Engine struct {
	rules []CompiledRule
	debug bool
	// execCommand is overridable for testing preconditions.
	execCommand func(ctx context.Context, cwd, command string) (string, error)
}

// SetExecCommand overrides the shell executor (used in tests).
func (e *Engine) SetExecCommand(fn func(ctx context.Context, cwd, command string) (string, error)) {
	e.execCommand = fn
}

// New compiles all rules and returns an Engine.
func New(cfg *config.Config, debug bool) (*Engine, error) {
	rules := make([]CompiledRule, 0, len(cfg.Rules))
	for i, r := range cfg.Rules {
		toolRe, err := regexp2.Compile(r.Tool, regexp2.None)
		if err != nil {
			return nil, fmt.Errorf("rule %d: invalid tool regex %q: %w", i, r.Tool, err)
		}
		inputRe, err := regexp2.Compile(r.Input, regexp2.None)
		if err != nil {
			return nil, fmt.Errorf("rule %d: invalid input regex %q: %w", i, r.Input, err)
		}

		var precondRe *regexp2.Regexp
		if r.PreconditionMatch != "" {
			precondRe, err = regexp2.Compile(r.PreconditionMatch, regexp2.None)
			if err != nil {
				return nil, fmt.Errorf("rule %d: invalid precondition_match regex %q: %w", i, r.PreconditionMatch, err)
			}
		}

		decision := protocol.Decision(r.Decision)
		if decision != protocol.Allow && decision != protocol.Deny {
			return nil, fmt.Errorf("rule %d: invalid decision %q (must be \"allow\" or \"deny\")", i, r.Decision)
		}

		rules = append(rules, CompiledRule{
			ToolRegex:         toolRe,
			InputRegex:        inputRe,
			PreconditionCmd:   r.Precondition,
			PreconditionRegex: precondRe,
			Decision:          decision,
			Reason:            r.Reason,
		})
	}
	return &Engine{rules: rules, debug: debug, execCommand: defaultExecCommand}, nil
}

// Evaluate checks all rules and returns a decision.
// Returns nil when no rules match (abstain).
func (e *Engine) Evaluate(input *protocol.HookInput) (*protocol.HookOutput, error) {
	inputStr := protocol.ExtractInputString(input.ToolName, input.ToolInput)

	if e.debug {
		protocol.Debugf("evaluate: tool=%s input=%q", input.ToolName, inputStr)
	}

	// For Bash commands with a leading "cd <path> &&", extract the prefix
	// so preconditions run in the correct directory.
	var cdPrefix string
	if input.ToolName == "Bash" {
		cdPrefix = ExtractCDPrefix(inputStr)
		if e.debug && cdPrefix != "" {
			protocol.Debugf("  extracted cd prefix: %s", cdPrefix)
		}
	}

	// For Bash commands, strip heredoc bodies so deny rules don't match
	// against data content (e.g., commit messages mentioning "rm -rf").
	matchStr := inputStr
	if input.ToolName == "Bash" {
		matchStr = StripHeredocs(inputStr)
		if e.debug && matchStr != inputStr {
			protocol.Debugf("  stripped heredocs: %q", matchStr)
		}
	}

	var denyReasons []string
	anyAllow := false

	for _, rule := range e.rules {
		toolMatch, err := rule.ToolRegex.MatchString(input.ToolName)
		if err != nil || !toolMatch {
			continue
		}

		inputMatch, err := rule.InputRegex.MatchString(matchStr)
		if err != nil || !inputMatch {
			continue
		}

		// Check precondition if present.
		if rule.PreconditionCmd != "" {
			if !e.checkPrecondition(rule.PreconditionCmd, rule.PreconditionRegex, input.CWD, cdPrefix) {
				if e.debug {
					protocol.Debugf("  precondition failed: %s", rule.Reason)
				}
				continue
			}
		}

		if e.debug {
			protocol.Debugf("  matched: decision=%s reason=%q", rule.Decision, rule.Reason)
		}

		switch rule.Decision {
		case protocol.Deny:
			denyReasons = append(denyReasons, rule.Reason)
		case protocol.Allow:
			anyAllow = true
		}
	}

	// Deny always wins.
	if len(denyReasons) > 0 {
		return makeOutput(protocol.Deny, strings.Join(denyReasons, "; ")), nil
	}

	if anyAllow {
		return makeOutput(protocol.Allow, "Approved by gatekeeper"), nil
	}

	// No match → abstain.
	if e.debug {
		protocol.Debugf("  no rules matched, abstaining")
	}
	return nil, nil
}

func (e *Engine) checkPrecondition(cmd string, matchRe *regexp2.Regexp, cwd string, cdPrefix string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// If the Bash command had a leading "cd <path> &&", prepend it to the
	// precondition so it runs in the same directory the command targets.
	effectiveCmd := cmd
	if cdPrefix != "" {
		effectiveCmd = cdPrefix + " " + cmd
	}

	output, err := e.execCommand(ctx, cwd, effectiveCmd)
	if err != nil {
		if e.debug {
			protocol.Debugf("  precondition cmd error: %v", err)
		}
		return false
	}

	matched, err := matchRe.MatchString(strings.TrimSpace(output))
	if err != nil {
		return false
	}
	return matched
}

func defaultExecCommand(ctx context.Context, cwd, command string) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Dir = cwd
	out, err := cmd.Output()
	return string(out), err
}

// ExtractCDPrefix returns any leading "cd <path> &&" from a Bash command,
// including the "&&". Returns "" if no cd prefix is found.
// This allows preconditions to run in the same directory the command targets.
func ExtractCDPrefix(command string) string {
	idx := strings.Index(command, "&&")
	if idx < 0 {
		return ""
	}
	prefix := strings.TrimSpace(command[:idx])
	if strings.HasPrefix(prefix, "cd ") {
		return strings.TrimSpace(command[:idx+2])
	}
	return ""
}

// heredocStartRe matches heredoc markers: <<EOF, <<'EOF', <<"EOF", <<-EOF, etc.
var heredocStartRe = regexp.MustCompile(`<<-?\s*(?:'(\w+)'|"(\w+)"|(\w+))`)

// shellHeredocRe matches a shell interpreter receiving a heredoc as stdin.
// This detects patterns like: bash <<'EOF', sh <<EOF, python <<'EOF', etc.
// These heredocs contain executable code and must NOT be stripped.
var shellHeredocRe = regexp.MustCompile(`(?:^|[;&|]\s*)(?:bash|sh|dash|zsh|ksh|fish|python[23]?|ruby|perl|node|php)\s+<<`)

// StripHeredocs removes heredoc bodies from a Bash command string.
// This prevents deny rules from matching against data content such as
// commit messages or PR descriptions that happen to contain denied patterns.
// However, heredocs fed as stdin to shell interpreters (bash, sh, python, etc.)
// are preserved because they contain executable code that deny rules must check.
func StripHeredocs(command string) string {
	lines := strings.Split(command, "\n")
	var result []string
	var delim string
	keepBody := false

	for _, line := range lines {
		if delim != "" {
			if keepBody {
				result = append(result, line)
			}
			// Inside a heredoc body — skip/keep lines until closing delimiter.
			if strings.TrimSpace(line) == delim {
				delim = ""
				keepBody = false
			}
			continue
		}

		// Check if this line introduces a heredoc.
		if m := heredocStartRe.FindStringSubmatch(line); m != nil {
			// Capture group 1, 2, or 3 holds the delimiter word.
			for _, g := range m[1:] {
				if g != "" {
					delim = g
					break
				}
			}
			// If a shell interpreter is receiving this heredoc, keep the body.
			if delim != "" && shellHeredocRe.MatchString(line) {
				keepBody = true
			}
		}

		result = append(result, line)
	}

	return strings.Join(result, "\n")
}

func makeOutput(decision protocol.Decision, reason string) *protocol.HookOutput {
	return &protocol.HookOutput{
		HookSpecificOutput: &protocol.HookSpecificOutput{
			HookEventName:           "PreToolUse",
			PermissionDecision:      decision,
			PermissionDecisionReason: reason,
		},
	}
}
