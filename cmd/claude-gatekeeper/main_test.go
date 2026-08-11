package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jim80net/claude-gatekeeper/internal/authdomains"
	"github.com/jim80net/claude-gatekeeper/internal/protocol"
)

// setupTestHome creates a temp HOME with the shipped gatekeeper.toml config.
func setupTestHome(t *testing.T) {
	t.Helper()
	homeDir := t.TempDir()
	claudeDir := filepath.Join(homeDir, ".claude")
	os.MkdirAll(claudeDir, 0755)

	data, err := os.ReadFile("../../gatekeeper.toml")
	if err != nil {
		t.Fatalf("reading gatekeeper.toml: %v", err)
	}
	os.WriteFile(filepath.Join(claudeDir, "gatekeeper.toml"), data, 0644)

	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", homeDir)
}

func TestRunAuthDomainsShadowIsExplicitlyNonEnforcing(t *testing.T) {
	now := time.Now().UTC()
	policy, request, coverage := authdomainsFixture(now)
	dir := t.TempDir()
	write := func(name string, value any) string {
		t.Helper()
		path := filepath.Join(dir, name)
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	var stdout bytes.Buffer
	code := run(strings.NewReader(""), &stdout, []string{"auth-domains", "shadow", "--json", "--policy", write("policy.json", policy), "--request", write("request.json", request), "--coverage", write("coverage.json", coverage)})
	if code != 0 {
		t.Fatalf("code=%d output=%s", code, stdout.String())
	}
	var report authdomains.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Mode != "shadow" || report.Enforcement || report.Decision.Decision != authdomains.DenyBlocked {
		t.Fatalf("report=%#v", report)
	}
}

func TestRunAuthDomainsShadowExitCodes(t *testing.T) {
	var stdout bytes.Buffer
	if got := run(strings.NewReader(""), &stdout, []string{"auth-domains", "shadow"}); got != 2 {
		t.Fatalf("usage code=%d", got)
	}
	now := time.Now().UTC()
	policy, request, coverage := authdomainsFixture(now)
	coverage.Seams = coverage.Seams[1:]
	dir := t.TempDir()
	paths := make([]string, 3)
	for i, value := range []any{policy, request, coverage} {
		paths[i] = filepath.Join(dir, string(rune('a'+i))+".json")
		data, _ := json.Marshal(value)
		if err := os.WriteFile(paths[i], data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	stdout.Reset()
	if got := run(strings.NewReader(""), &stdout, []string{"auth-domains", "shadow", "--json", "--policy", paths[0], "--request", paths[1], "--coverage", paths[2]}); got != 1 {
		t.Fatalf("nonconformant code=%d output=%s", got, stdout.String())
	}
}

func TestAuthDomainsShadowDoesNotChangeHarnessAbstainWires(t *testing.T) {
	setupTestHome(t)
	grokFixture, err := os.ReadFile("../../internal/adapter/grok/testdata/pre_tool_use_run_terminal_command.json")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		args     []string
		input    string
		wantCode int
		wantWire string
	}{
		{name: "claude", args: []string{"--harness", "claude"}, input: hookJSON("Bash", "git status"), wantCode: 0, wantWire: `"permissionDecision":"allow"`},
		{name: "codex", args: []string{"--harness", "codex"}, input: hookJSON("Bash", "git status"), wantCode: 0, wantWire: ""},
		{name: "grok", args: []string{"--harness", "grok"}, input: string(grokFixture), wantCode: 0, wantWire: `"decision":"allow"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout bytes.Buffer
			if got := run(strings.NewReader(tt.input), &stdout, tt.args); got != tt.wantCode {
				t.Fatalf("code=%d want=%d output=%q", got, tt.wantCode, stdout.String())
			}
			if !strings.Contains(stdout.String(), tt.wantWire) || (tt.wantWire == "" && stdout.Len() != 0) {
				t.Fatalf("wire=%q want marker=%q", stdout.String(), tt.wantWire)
			}
		})
	}
}

func authdomainsFixture(now time.Time) (authdomains.PolicyGeneration, authdomains.Request, authdomains.CoverageManifest) {
	ctx := authdomains.DomainContext{SchemaVersion: authdomains.SchemaV1, ContextID: "ctx", DomainID: "domain", PrincipalID: "principal", WorkerID: "worker", SessionID: "session", RuntimeIdentity: authdomains.RuntimeIdentity{Kind: "linux_user", Subject: "uid:1001"}, IsolationClaim: "unproved", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), MintAuthority: "authorization-server"}
	policy := authdomains.PolicyGeneration{SchemaVersion: authdomains.SchemaV1, Generation: 1, RegistryVersion: authdomains.RegistryV1, CreatedAt: now, Blocks: []authdomains.ProtectedBlock{{ID: "block", ObjectSelector: authdomains.ObjectSelector{Kind: "exact", ObjectID: authdomains.PAObjectID}, Actions: []string{"read"}, Reason: "fixture", Owner: "test", AuditPolicy: "durable_before_effect", CreatedAt: now}}}
	request := authdomains.Request{SchemaVersion: authdomains.SchemaV1, RequestID: "req", DomainContext: &ctx, Action: "read", Object: authdomains.RequestObject{ObjectID: authdomains.PAObjectID, CanonicalizationVersion: "1"}, PolicyGeneration: 1, ClassifierVersion: "shadow-v1", RequestedAt: now}
	seams := []authdomains.CoverageSeam{}
	for _, id := range []string{"policy-store-publish", "policy-evaluator", "durable-audit-admission", "decision-replay-claim", "pa-credential-final-pep", "worker-lifecycle-archive"} {
		seams = append(seams, authdomains.CoverageSeam{ID: id, Kind: "contract", Critical: true, Owner: "test", State: "contract_only", TraceAction: id + "-trace", NegativeFixture: id + "-negative", KnownGap: "not implemented"})
	}
	neutral := authdomains.NeutralReplay{Schema: "gatekeeper.auth-domains.replay/v1", SchemaFile: "neutral-replay.schema.json", LifecycleContractSHA256: "4a5d12ff96b136db5bd7e78c9467a222c242be99c060d5a17fe267725bc9caff", LifecycleProbeRegistry: "lifecycle-probes.json", IndependentCheckerHead: "8e376c79d64bc720b280ab839058cc71ca774990", Coverage: []authdomains.NeutralCoverageSeam{{Name: "ordinary-work", RequiredTraced: true, MapsTo: []string{"policy-evaluator"}}, {Name: "protected-read-pep", Critical: true, RequiredTraced: true, MapsTo: []string{"policy-evaluator", "decision-replay-claim", "pa-credential-final-pep"}}, {Name: "protected-read-audit", Critical: true, RequiredTraced: true, MapsTo: []string{"durable-audit-admission"}}}}
	return policy, request, authdomains.CoverageManifest{SchemaVersion: authdomains.SchemaV1, ObjectID: authdomains.PAObjectID, EnforcementClaim: false, NeutralReplay: neutral, Seams: seams}
}

func hookJSON(toolName, command string) string {
	input := map[string]interface{}{
		"tool_name":  toolName,
		"tool_input": map[string]string{"command": command},
		"cwd":        "/tmp",
	}
	b, _ := json.Marshal(input)
	return string(b)
}

func TestRunHookAllow(t *testing.T) {
	setupTestHome(t)
	stdin := strings.NewReader(hookJSON("Bash", "git status"))
	var stdout bytes.Buffer

	code := run(stdin, &stdout, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if stdout.Len() == 0 {
		t.Fatal("expected output, got nothing (abstain)")
	}

	var out protocol.HookOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != protocol.Allow {
		t.Errorf("decision = %s, want allow", out.HookSpecificOutput.PermissionDecision)
	}
}

func TestRunHookDeny(t *testing.T) {
	setupTestHome(t)
	stdin := strings.NewReader(hookJSON("Bash", "git reset --hard HEAD~1"))
	var stdout bytes.Buffer

	code := run(stdin, &stdout, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var out protocol.HookOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != protocol.Deny {
		t.Errorf("decision = %s, want deny", out.HookSpecificOutput.PermissionDecision)
	}
}

func TestRunHookAbstain(t *testing.T) {
	setupTestHome(t)
	stdin := strings.NewReader(hookJSON("Bash", "some-exotic-tool --flag"))
	var stdout bytes.Buffer

	code := run(stdin, &stdout, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if stdout.Len() != 0 {
		t.Errorf("expected empty stdout (abstain), got %q", stdout.String())
	}
}

func TestRunInvalidJSON(t *testing.T) {
	stdin := strings.NewReader("{not json}")
	var stdout bytes.Buffer

	code := run(stdin, &stdout, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (abstain on error)", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("expected empty stdout on parse error, got %q", stdout.String())
	}
}

func TestRunVersion(t *testing.T) {
	var stdout bytes.Buffer
	code := run(strings.NewReader(""), &stdout, []string{"--version"})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestRunDoctorJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := filepath.Join(home, "bin", "claude-gatekeeper")
	if err := os.MkdirAll(filepath.Dir(bin), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'claude-gatekeeper test-version' >&2\n"), 0755); err != nil {
		t.Fatal(err)
	}
	config := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"` + bin + ` --harness grok"}]}]}}`
	hookPath := filepath.Join(home, ".grok", "hooks", "gatekeeper.json")
	if err := os.MkdirAll(filepath.Dir(hookPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	code := run(strings.NewReader(""), &stdout, []string{"doctor", "--json", "--require-harness", "grok", "--expected-binary", bin, "--expected-version", "test-version"})
	if code != 0 {
		t.Fatalf("exit code = %d, output = %s", code, stdout.String())
	}
	var report struct {
		OK       bool `json:"ok"`
		Surfaces []struct {
			Harness string `json:"harness"`
		} `json:"surfaces"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.OK || len(report.Surfaces) != 1 || report.Surfaces[0].Harness != "grok" {
		t.Fatalf("report = %#v", report)
	}
}

func TestRunDoctorAlternateClaudeRootCannotUseDefaultPluginOrGlobals(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	alternate := filepath.Join(home, "alternate")
	t.Setenv("CLAUDE_CONFIG_DIR", alternate)
	for path, content := range map[string]string{
		filepath.Join(alternate, "settings.json"):                           `{"hooks":{}}`,
		filepath.Join(alternate, "plugins", "installed_plugins.json"):       `{"plugins":{}}`,
		filepath.Join(home, ".claude", "settings.json"):                     `{"hooks":{}}`,
		filepath.Join(home, ".claude", "plugins", "installed_plugins.json"): `{"plugins":{"claude-gatekeeper@market":[{"installPath":"` + filepath.Join(home, ".claude", "plugins", "cache", "claude-gatekeeper") + `"}]}}`,
		filepath.Join(home, ".codex", "hooks.json"):                         `{"hooks":{"PreToolUse":[{"hooks":[{"command":"claude-gatekeeper --harness codex"}]}]}}`,
		filepath.Join(home, ".grok", "hooks", "gatekeeper.json"):            `{"hooks":{"PreToolUse":[{"hooks":[{"command":"claude-gatekeeper --harness grok"}]}]}}`,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	pluginHook := filepath.Join(home, ".claude", "plugins", "cache", "claude-gatekeeper", "hooks", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(pluginHook), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pluginHook, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":"${CLAUDE_PLUGIN_ROOT}/bin/run.sh"}]}]}}`), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	code := run(strings.NewReader(""), &stdout, []string{"doctor", "--json"})
	if code != 1 {
		t.Fatalf("exit code=%d, want 1: %s", code, stdout.String())
	}
	for _, want := range []string{`"claude_root": "` + alternate + `"`, `"claude_root_source": "environment"`, `"status": "absent"`, `"firing_status": "not_tested"`, `"scope": "host-global"`} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("output missing %s: %s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), filepath.Join(home, ".claude", "plugins", "cache")) {
		t.Fatalf("default plugin was used as selected-root evidence: %s", stdout.String())
	}

	outsidePlugin := filepath.Join(home, ".claude", "plugins", "cache", "claude-gatekeeper")
	registry := filepath.Join(alternate, "plugins", "installed_plugins.json")
	if err := os.WriteFile(registry, []byte(`{"plugins":{"claude-gatekeeper@market":[{"installPath":"`+outsidePlugin+`"}]}}`), 0644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	code = run(strings.NewReader(""), &stdout, []string{"doctor", "--json"})
	if code != 2 || !strings.Contains(stdout.String(), "outside selected Claude root") || !strings.Contains(stdout.String(), `"status": "error"`) || !strings.Contains(stdout.String(), `"sources": []`) {
		t.Fatalf("cross-root registry control code=%d: %s", code, stdout.String())
	}
}

func TestRunDoctorFailureExitCodes(t *testing.T) {
	t.Run("minimum surfaces", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		var stdout bytes.Buffer
		if code := run(strings.NewReader(""), &stdout, []string{"doctor", "--json", "--require-harness", "any"}); code != 1 {
			t.Fatalf("exit code = %d, want 1; output = %s", code, stdout.String())
		}
	})
	t.Run("version drift", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		bin := filepath.Join(home, "bin", "claude-gatekeeper")
		if err := os.MkdirAll(filepath.Dir(bin), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'claude-gatekeeper observed'\n"), 0755); err != nil {
			t.Fatal(err)
		}
		hookPath := filepath.Join(home, ".claude", "settings.json")
		if err := os.MkdirAll(filepath.Dir(hookPath), 0755); err != nil {
			t.Fatal(err)
		}
		config := `{"hooks":{"PreToolUse":[{"hooks":[{"command":"` + bin + `"}]}]}}`
		if err := os.WriteFile(hookPath, []byte(config), 0644); err != nil {
			t.Fatal(err)
		}
		registry := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")
		if err := os.MkdirAll(filepath.Dir(registry), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(registry, []byte(`{"plugins":{}}`), 0644); err != nil {
			t.Fatal(err)
		}
		code := run(strings.NewReader(""), &bytes.Buffer{}, []string{"doctor", "--expected-binary", bin, "--expected-version", "wanted"})
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
	})
	t.Run("usage error", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		if code := run(strings.NewReader(""), &bytes.Buffer{}, []string{"doctor", "--min-surfaces", "-1"}); code != 2 {
			t.Fatalf("exit code = %d, want 2", code)
		}
	})
	t.Run("help", func(t *testing.T) {
		if code := run(strings.NewReader(""), &bytes.Buffer{}, []string{"doctor", "--help"}); code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
	})
	t.Run("table output error", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		if code := run(strings.NewReader(""), errorWriter{err: errors.New("write failed")}, []string{"doctor"}); code != 2 {
			t.Fatalf("exit code = %d, want 2", code)
		}
	})
	t.Run("all hook file errors", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		for path, content := range map[string]string{
			filepath.Join(home, ".grok", "hooks", "gatekeeper.json"): "{",
			filepath.Join(home, ".codex", "hooks.json"):              "not json",
		} {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
		}

		var stdout bytes.Buffer
		if code := run(strings.NewReader(""), &stdout, []string{"doctor", "--json", "--min-surfaces", "0"}); code != 2 {
			t.Fatalf("exit code = %d, want 2; output = %s", code, stdout.String())
		}
		for _, path := range []string{".grok/hooks/gatekeeper.json", ".codex/hooks.json"} {
			if !strings.Contains(stdout.String(), path) {
				t.Errorf("output missing %q: %s", path, stdout.String())
			}
		}
	})
}

func TestRunDoctorJSONChecksPublishedLatest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := filepath.Join(home, "bin", "claude-gatekeeper")
	if err := os.MkdirAll(filepath.Dir(bin), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'claude-gatekeeper 1.5.1'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":"`+bin+`"}]}]}}`), 0644); err != nil {
		t.Fatal(err)
	}
	registry := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")
	if err := os.MkdirAll(filepath.Dir(registry), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registry, []byte(`{"plugins":{}}`), 0644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"tag_name":"v1.6.0"}`)
	}))
	defer server.Close()
	var stdout bytes.Buffer
	code := run(strings.NewReader(""), &stdout, []string{"doctor", "--json", "--check-latest", "--latest-release-url", server.URL, "--expected-binary", bin, "--min-surfaces", "1"})
	if code != 1 || !strings.Contains(stdout.String(), `"status": "fail"`) || !strings.Contains(stdout.String(), `"published_latest": "1.6.0"`) || !strings.Contains(stdout.String(), `"observed_version": "1.5.1"`) {
		t.Fatalf("code=%d output=%s", code, stdout.String())
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestRunNonBashTool(t *testing.T) {
	setupTestHome(t)
	input := map[string]interface{}{
		"tool_name":  "Read",
		"tool_input": map[string]string{"file_path": "/tmp/main.go"},
		"cwd":        "/tmp",
	}
	b, _ := json.Marshal(input)

	var stdout bytes.Buffer
	code := run(bytes.NewReader(b), &stdout, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var out protocol.HookOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != protocol.Allow {
		t.Errorf("decision = %s, want allow", out.HookSpecificOutput.PermissionDecision)
	}
}

func TestRunNoConfigAbstains(t *testing.T) {
	// With no config files, the gatekeeper should abstain on everything.
	homeDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", homeDir)
	defer os.Setenv("HOME", origHome)

	stdin := strings.NewReader(hookJSON("Bash", "git status"))
	var stdout bytes.Buffer

	code := run(stdin, &stdout, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if stdout.Len() != 0 {
		t.Errorf("expected abstain with no config, got %q", stdout.String())
	}
}

func TestRunPolicyTestExitCodes(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "gatekeeper.toml")
	if err := os.WriteFile(configPath, []byte("[[rules]]\ntool='Bash'\ninput='^blocked$'\ndecision='deny'\nreason='nope'\n"), 0644); err != nil {
		t.Fatal(err)
	}
	writeCases := func(name, expected string) string {
		path := filepath.Join(dir, name)
		content := "[[cases]]\nname='case'\ntool='Bash'\ncommand='blocked'\nexpected='" + expected + "'\n"
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"pass", []string{"test", "--config", configPath, writeCases("pass.toml", "deny")}, 0},
		{"assertion failure", []string{"test", "--config", configPath, writeCases("fail.toml", "allow")}, 1},
		{"usage error", []string{"test"}, 2},
		{"parse error", []string{"test", filepath.Join(dir, "missing.toml")}, 2},
		{"help", []string{"test", "--help"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(strings.NewReader(""), io.Discard, tc.args); got != tc.want {
				t.Fatalf("run() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRunReleaseVerifyUsage(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{"missing tag", []string{"verify-release"}, 2},
		{"help", []string{"verify-release", "--help"}, 0},
		{
			"invalid minimum",
			[]string{
				"verify-release",
				"v1.2.3",
				"--host-binary", "/tmp/host",
				"--plugin-binary", "/tmp/plugin",
				"--min-surfaces", "-1",
			},
			2,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := run(strings.NewReader(""), io.Discard, test.args); got != test.want {
				t.Fatalf("run() = %d, want %d", got, test.want)
			}
		})
	}
}
