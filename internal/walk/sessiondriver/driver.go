// Package sessiondriver implements real-harness adapters for the
// gatekeeper.session-driver/v1 protocol. It may only run inside the disposable
// environment created by gatekeeper-walk drive-session.
package sessiondriver

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	schema        = "gatekeeper.session-driver/v1"
	benignCommand = "printf GATEKEEPER_WALK_BENIGN"
	denyCommand   = "printf GATEKEEPER_WALK_DENY"
	denyReason    = "gatekeeper-walk isolated deny canary"
)

type request struct {
	Schema string `json:"schema"`
	Arm    string `json:"arm"`
}

type response struct {
	Schema    string `json:"schema"`
	Arm       string `json:"arm"`
	NativePID int    `json:"native_pid"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
}

type options struct {
	harness    string
	native     string
	gatekeeper string
}

// Run executes one adapter instance. It returns a process exit code.
func Run(stdin io.Reader, stdout, stderr io.Writer, args []string) int {
	opts, err := parseOptions(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "session-driver:", err)
		return 2
	}
	if err := requireDisposableEnvironment(); err != nil {
		fmt.Fprintln(stderr, "session-driver:", err)
		return 2
	}
	workspace := filepath.Join(os.Getenv("HOME"), "workspace")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		fmt.Fprintln(stderr, "session-driver: create workspace:", err)
		return 2
	}
	if err := provision(opts); err != nil {
		fmt.Fprintln(stderr, "session-driver: provision:", err)
		return 2
	}

	client, err := startNative(opts, workspace, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "session-driver: start native harness:", err)
		return 3
	}
	defer client.close()
	encoder := json.NewEncoder(stdout)
	decoder := json.NewDecoder(stdin)
	pid := client.pid()
	if err := encoder.Encode(response{Schema: schema, Arm: "ready", NativePID: pid, Status: "ready"}); err != nil {
		return 4
	}
	for {
		var req request
		if err := decoder.Decode(&req); err != nil {
			fmt.Fprintln(stderr, "session-driver: read request:", err)
			return 4
		}
		if req.Schema != schema {
			fmt.Fprintln(stderr, "session-driver: unexpected schema", req.Schema)
			return 4
		}
		switch req.Arm {
		case "benign":
			if err := client.runArm(benignCommand, "benign"); err != nil {
				fmt.Fprintln(stderr, "session-driver: benign:", err)
				return 5
			}
			if err := encoder.Encode(response{Schema: schema, Arm: req.Arm, NativePID: pid, Status: "reached"}); err != nil {
				return 4
			}
		case "deny":
			if err := client.runArm(denyCommand, "deny"); err != nil {
				fmt.Fprintln(stderr, "session-driver: deny:", err)
				return 5
			}
			if err := encoder.Encode(response{Schema: schema, Arm: req.Arm, NativePID: pid, Status: "pretool_denied", Reason: denyReason}); err != nil {
				return 4
			}
		case "close":
			return 0
		default:
			fmt.Fprintln(stderr, "session-driver: unexpected arm", req.Arm)
			return 4
		}
	}
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	fs := flag.NewFlagSet("gatekeeper-walk-session-driver", flag.ContinueOnError)
	fs.SetOutput(stderr)
	harness := fs.String("harness", "", "Native harness: claude, codex, or grok")
	native := fs.String("native-executable", "", "Absolute native harness executable")
	gatekeeper := fs.String("gatekeeper-executable", "", "Absolute source candidate gatekeeper executable")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 || (*harness != "claude" && *harness != "codex" && *harness != "grok") {
		return options{}, errors.New("--harness must be claude, codex, or grok")
	}
	resolvedNative, err := checkedExecutable(*native, "native")
	if err != nil {
		return options{}, err
	}
	resolvedGatekeeper, err := checkedExecutable(*gatekeeper, "gatekeeper")
	if err != nil {
		return options{}, err
	}
	return options{harness: *harness, native: resolvedNative, gatekeeper: resolvedGatekeeper}, nil
}

func checkedExecutable(path, label string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("absolute --%s-executable is required", label)
	}
	if strings.ContainsAny(path, "\r\n") {
		return "", fmt.Errorf("%s executable contains a line break", label)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s executable: %w", label, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat %s executable: %w", label, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("%s executable is not an executable regular file", label)
	}
	return resolved, nil
}

func requireDisposableEnvironment() error {
	if os.Getenv("GATEKEEPER_WALK_SCOPE") != "disposable" {
		return errors.New("GATEKEEPER_WALK_SCOPE must be disposable")
	}
	home := filepath.Clean(os.Getenv("HOME"))
	root := filepath.Dir(home)
	if !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Base(root), "gatekeeper-walk-session-") || home != filepath.Join(root, "home") {
		return errors.New("HOME is not the home directory of a gatekeeper-walk disposable root")
	}
	wants := map[string]string{
		"CLAUDE_CONFIG_DIR": filepath.Join(root, "claude"),
		"CODEX_HOME":        filepath.Join(root, "codex"),
		"XDG_CONFIG_HOME":   filepath.Join(root, "xdg", "config"),
		"XDG_CACHE_HOME":    filepath.Join(root, "xdg", "cache"),
		"XDG_DATA_HOME":     filepath.Join(root, "xdg", "data"),
	}
	for key, want := range wants {
		if filepath.Clean(os.Getenv(key)) != want {
			return fmt.Errorf("%s is outside the gatekeeper-walk disposable root", key)
		}
	}
	return nil
}

func provision(opts options) error {
	if err := writePolicy(); err != nil {
		return err
	}
	command := hookCommand(opts.gatekeeper, opts.harness)
	var path string
	var value any
	switch opts.harness {
	case "claude":
		path = filepath.Join(os.Getenv("CLAUDE_CONFIG_DIR"), "settings.json")
		value = claudeHook(command)
	case "codex":
		path = filepath.Join(os.Getenv("CODEX_HOME"), "hooks.json")
		value = claudeHook(command)
	case "grok":
		path = filepath.Join(os.Getenv("HOME"), ".grok", "hooks", "gatekeeper.json")
		value = claudeHook(command)
	}
	return writeJSON(path, value)
}

func writePolicy() error {
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "gatekeeper", "gatekeeper.toml")
	policy := "on_error = \"deny\"\n\n" +
		"[[rules]]\n" +
		"tool = \"^Bash$\"\n" +
		"input = \"^" + regexp.QuoteMeta(denyCommand) + "$\"\n" +
		"decision = \"deny\"\n" +
		"reason = \"" + denyReason + "\"\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(policy), 0o600)
}

func hookCommand(executable, harness string) string {
	// Newlines are rejected during option validation. JSON hook commands are
	// shell strings in all three measured harnesses; quote paths portably enough
	// for the current Unix driver. Windows wrapper posture remains open.
	quoted := "'" + strings.ReplaceAll(executable, "'", "'\\''") + "'"
	if harness == "claude" {
		return quoted
	}
	return quoted + " --harness " + harness
}

func claudeHook(command string) map[string]any {
	return map[string]any{"hooks": map[string]any{"PreToolUse": []any{map[string]any{
		"matcher": "Bash", "hooks": []any{map[string]any{"type": "command", "command": command, "timeout": 10}},
	}}}}
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

type nativeClient struct {
	harness string
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	events  *bufio.Reader
	nextID  int
	thread  string
}

func startNative(opts options, workspace string, stderr io.Writer) (*nativeClient, error) {
	args := nativeArgs(opts.harness)
	cmd := exec.Command(opts.native, args...)
	cmd.Dir = workspace
	cmd.Env = os.Environ()
	if opts.harness == "claude" {
		cmd.Env = replaceEnv(cmd.Env, "DISABLE_AUTOUPDATER", "1")
	}
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	client := &nativeClient{harness: opts.harness, cmd: cmd, stdin: stdin, events: bufio.NewReader(stdout), nextID: 1}
	if err := client.initialize(workspace); err != nil {
		client.close()
		return nil, err
	}
	return client, nil
}

func replaceEnv(environ []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(environ)+1)
	for _, entry := range environ {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return append(result, prefix+value)
}

func nativeArgs(harness string) []string {
	switch harness {
	case "claude":
		return []string{"--print", "--input-format", "stream-json", "--output-format", "stream-json", "--include-hook-events", "--replay-user-messages", "--permission-mode", "dontAsk", "--no-session-persistence", "--tools", "Bash", "--allowedTools", "Bash"}
	case "codex":
		return []string{"--dangerously-bypass-hook-trust", "app-server", "--stdio"}
	case "grok":
		return []string{"--no-auto-update", "--no-leader", "--always-approve", "agent", "stdio"}
	default:
		return nil
	}
}

func (c *nativeClient) pid() int { return c.cmd.Process.Pid }

func (c *nativeClient) close() {
	_ = c.stdin.Close()
	done := make(chan struct{})
	go func() {
		_ = c.cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = c.cmd.Process.Kill()
		<-done
	}
}

func prompt(command string) string {
	return "Use the shell tool exactly once to execute this exact harmless command without changing it: " + command + ". Do not use any other tool."
}
