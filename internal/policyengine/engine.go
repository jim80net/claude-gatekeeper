// Package policyengine decorates gatekeeper-core's evaluator with product-level
// rule output features.
package policyengine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jim80net/gatekeeper-core/canonical"
	"github.com/jim80net/gatekeeper-core/config"
	coreengine "github.com/jim80net/gatekeeper-core/engine"
)

// PreconditionReason asks Gatekeeper to use the matched precondition's stdout
// as the deny reason. This is intended for read-only preconditions whose output
// contains the resolved facts that caused the denial.
const PreconditionReason = "{{precondition_output}}"

type dynamicReason struct {
	sentinel string
	command  string
}

// Engine preserves gatekeeper-core matching and deny-wins behavior while
// expanding explicitly requested dynamic precondition reasons.
type Engine struct {
	core    *coreengine.Engine
	reasons []dynamicReason
	outputs map[string]string
}

// New compiles cfg without mutating it.
func New(cfg *config.Config, debug bool) (*Engine, error) {
	copyCfg := &config.Config{OnError: cfg.OnError, Rules: append([]config.Rule(nil), cfg.Rules...)}
	e := &Engine{outputs: make(map[string]string)}
	for i := range copyCfg.Rules {
		rule := &copyCfg.Rules[i]
		if rule.Reason != PreconditionReason {
			continue
		}
		if rule.Precondition == "" {
			return nil, fmt.Errorf("rule %d: %s requires a precondition", i, PreconditionReason)
		}
		if rule.PreconditionMatch == "" {
			return nil, fmt.Errorf("rule %d: %s requires precondition_match", i, PreconditionReason)
		}
		sentinel := fmt.Sprintf("__gatekeeper_precondition_reason_%d__", i)
		e.reasons = append(e.reasons, dynamicReason{sentinel: sentinel, command: rule.Precondition})
		rule.Reason = sentinel
	}

	compiled, err := coreengine.New(copyCfg, debug)
	if err != nil {
		return nil, err
	}
	e.core = compiled
	e.core.SetExecCommand(e.execCommand)
	return e, nil
}

// Evaluate delegates the decision to gatekeeper-core, then substitutes only
// sentinels belonging to rules that core proved matched.
func (e *Engine) Evaluate(tc *canonical.ToolCall) (canonical.Verdict, error) {
	e.outputs = make(map[string]string)
	verdict, err := e.core.Evaluate(tc)
	if err != nil || verdict.Decision != canonical.Deny {
		return verdict, err
	}
	for _, dynamic := range e.reasons {
		if !strings.Contains(verdict.Reason, dynamic.sentinel) {
			continue
		}
		reason := strings.TrimSpace(e.outputs[dynamic.command])
		if reason == "" {
			reason = "Denied by gatekeeper: matched precondition returned no diagnostic"
		}
		verdict.Reason = strings.ReplaceAll(verdict.Reason, dynamic.sentinel, reason)
	}
	return verdict, nil
}

func (e *Engine) execCommand(ctx context.Context, cwd, command, toolInput string) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), coreengine.EnvGatekeeperInput+"="+toolInput)
	out, err := cmd.Output()
	if err == nil {
		e.outputs[command] = string(out)
		for _, dynamic := range e.reasons {
			if command == dynamic.command || strings.HasSuffix(command, " "+dynamic.command) {
				e.outputs[dynamic.command] = string(out)
			}
		}
	}
	return string(out), err
}
