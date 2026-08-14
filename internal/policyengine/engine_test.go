package policyengine_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jim80net/claude-gatekeeper/internal/policyengine"
	"github.com/jim80net/gatekeeper-core/canonical"
	"github.com/jim80net/gatekeeper-core/config"
)

func mergeScript(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "scripts", "merge-domain-check.sh"))
}

func evaluateMerge(t *testing.T, cwd, command string) canonical.Verdict {
	t.Helper()
	cfg := &config.Config{Rules: []config.Rule{{
		Tool: "Bash", Input: `gh\s+pr\s+merge\b`, Decision: "deny",
		Precondition: mergeScript(t), PreconditionMatch: `^Merge denied:`, Reason: policyengine.PreconditionReason,
	}}}
	eng, err := policyengine.New(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := eng.Evaluate(&canonical.ToolCall{Tool: canonical.ToolBash, InputString: command, CWD: cwd})
	if err != nil {
		t.Fatal(err)
	}
	return verdict
}

func writeMarker(t *testing.T, root, name, body string) string {
	t.Helper()
	dir := filepath.Join(root, ".gatekeeper")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMergeDomainReasonNamesFailedArm(t *testing.T) {
	root := t.TempDir()
	verdict := evaluateMerge(t, root, "gh pr merge 68 --repo jim80net/gatekeeper-core")
	if verdict.Decision != canonical.Deny {
		t.Fatalf("decision = %s, want deny", verdict.Decision)
	}
	wantPath := filepath.Join(root, ".gatekeeper", "lead")
	if !strings.Contains(verdict.Reason, "arm=not_lead") || !strings.Contains(verdict.Reason, "lead_marker="+wantPath+" (consulted,absent)") {
		t.Fatalf("reason does not state resolved non-lead facts: %q", verdict.Reason)
	}
	if strings.Contains(verdict.Reason, "domain_mismatch") {
		t.Fatalf("reason names an arm that did not fail: %q", verdict.Reason)
	}
}

func TestMergeDomainMismatchReasonStatesResolvedFacts(t *testing.T) {
	root := t.TempDir()
	leadPath := writeMarker(t, root, "lead", "")
	domainPath := writeMarker(t, root, "domain", "jim80net/gatekeeper-claude\nGeneral-ML/a1-fleet-ops\n")
	verdict := evaluateMerge(t, root, "gh pr merge 68 --repo jim80net/gatekeeper-core")

	wants := []string{
		"arm=domain_mismatch",
		"resolved_domains=jim80net/gatekeeper-claude,general-ml/a1-fleet-ops",
		"requested_target=jim80net/gatekeeper-core",
		"lead_marker=" + leadPath + " (consulted,present)",
		"domain_marker=" + domainPath + " (consulted,present)",
		"domain_source=" + domainPath,
	}
	for _, want := range wants {
		if !strings.Contains(verdict.Reason, want) {
			t.Errorf("reason %q does not contain %q", verdict.Reason, want)
		}
	}
	if verdict.Decision != canonical.Deny {
		t.Errorf("decision = %s, want deny", verdict.Decision)
	}
	if strings.Contains(strings.ToLower(verdict.Reason), "edit") {
		t.Errorf("reason must be non-instructional: %q", verdict.Reason)
	}
}

func TestMergeDomainMatchingTargetDoesNotDeny(t *testing.T) {
	root := t.TempDir()
	writeMarker(t, root, "lead", "")
	writeMarker(t, root, "domain", "jim80net/gatekeeper-claude\n")
	verdict := evaluateMerge(t, root, "gh pr merge 68 --repo JIM80NET/GATEKEEPER-CLAUDE")
	if verdict.Decision != canonical.Abstain {
		t.Fatalf("decision = %s (%q), want abstain", verdict.Decision, verdict.Reason)
	}
}

func TestMergeDomainUnresolvedFactsStayFailClosed(t *testing.T) {
	t.Run("target", func(t *testing.T) {
		root := t.TempDir()
		writeMarker(t, root, "lead", "")
		writeMarker(t, root, "domain", "jim80net/gatekeeper-claude\n")
		verdict := evaluateMerge(t, root, "gh pr merge 68 --repo ???")
		if verdict.Decision != canonical.Deny || !strings.Contains(verdict.Reason, "arm=target_unresolved") || !strings.Contains(verdict.Reason, "requested_target=unresolved") {
			t.Fatalf("verdict = %s (%q), want target_unresolved deny", verdict.Decision, verdict.Reason)
		}
	})

	t.Run("domain", func(t *testing.T) {
		root := t.TempDir()
		writeMarker(t, root, "lead", "")
		verdict := evaluateMerge(t, root, "gh pr merge 68 --repo jim80net/gatekeeper-core")
		if verdict.Decision != canonical.Deny || !strings.Contains(verdict.Reason, "arm=domain_unresolved") || !strings.Contains(verdict.Reason, "domain_marker="+filepath.Join(root, ".gatekeeper", "domain")+" (consulted,absent)") {
			t.Fatalf("verdict = %s (%q), want domain_unresolved deny", verdict.Decision, verdict.Reason)
		}
	})
}

func TestMergeDomainReasonUsesEffectiveCDWorktree(t *testing.T) {
	root := t.TempDir()
	targetRoot := filepath.Join(root, "target")
	writeMarker(t, targetRoot, "lead", "")
	domainPath := writeMarker(t, targetRoot, "domain", "jim80net/gatekeeper-claude\n")
	verdict := evaluateMerge(t, root, "cd target && gh pr merge 68 --repo jim80net/gatekeeper-core")
	if verdict.Decision != canonical.Deny || !strings.Contains(verdict.Reason, "arm=domain_mismatch") || !strings.Contains(verdict.Reason, "domain_marker="+domainPath+" (consulted,present)") {
		t.Fatalf("verdict = %s (%q), want effective-worktree mismatch deny", verdict.Decision, verdict.Reason)
	}
}

func TestDynamicReasonRequiresPrecondition(t *testing.T) {
	_, err := policyengine.New(&config.Config{Rules: []config.Rule{{
		Tool: "Bash", Input: ".*", Decision: "deny", Reason: policyengine.PreconditionReason,
	}}}, false)
	if err == nil || !strings.Contains(err.Error(), "requires a precondition") {
		t.Fatalf("error = %v, want missing-precondition error", err)
	}
}

func TestDynamicReasonRequiresPreconditionMatch(t *testing.T) {
	_, err := policyengine.New(&config.Config{Rules: []config.Rule{{
		Tool: "Bash", Input: ".*", Decision: "deny", Reason: policyengine.PreconditionReason, Precondition: "printf deny",
	}}}, false)
	if err == nil || !strings.Contains(err.Error(), "requires precondition_match") {
		t.Fatalf("error = %v, want missing-precondition-match error", err)
	}
}
