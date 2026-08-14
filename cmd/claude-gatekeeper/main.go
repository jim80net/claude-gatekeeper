// claude-gatekeeper is a PreToolUse permission hook for coding agents
// (Claude Code, OpenAI Codex, xAI grok). The product is "agent-gatekeeper";
// the binary/repo name is retained for install compatibility.
//
// Default mode (no subcommand): reads the harness's hook JSON from stdin,
// evaluates the shared TOML rules, and writes a permission decision on the
// harness-native wire. The target harness is chosen by --harness
// (claude|codex|grok), the GATEKEEPER_HARNESS env var, or defaults to claude.
//
// On a gatekeeper error the independent GATEKEEPER_ON_ERROR override, when
// present, decides the verdict before hook input or policy is read. Otherwise
// the legacy TOML on_error policy applies when readable. A clean "no rule
// matched" always abstains; zero rules deny only under the independent hard
// posture.
//
// Subcommands:
//
//	migrate   Convert settings.json permissions to gatekeeper TOML.
//	setup     Register the hook for a harness (--harness claude|codex|grok).
//	uninstall Remove the Claude hook registration.
//	doctor    Inventory live gatekeeper hook surfaces and report drift.
//	test      Run declarative policy cases against live or explicit config.
//	auth-domains shadow  Inspect D1 contracts without enforcing them.
//	release-verify Verify a published release and live binary stamps.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jim80net/claude-gatekeeper/internal/adapter"
	"github.com/jim80net/claude-gatekeeper/internal/authdomains"
	"github.com/jim80net/claude-gatekeeper/internal/inventory"
	"github.com/jim80net/claude-gatekeeper/internal/migrate"
	"github.com/jim80net/claude-gatekeeper/internal/policyengine"
	"github.com/jim80net/claude-gatekeeper/internal/policytest"
	"github.com/jim80net/claude-gatekeeper/internal/posture"
	"github.com/jim80net/claude-gatekeeper/internal/releaseverify"
	"github.com/jim80net/claude-gatekeeper/internal/setup"
	"github.com/jim80net/gatekeeper-core/canonical"
	"github.com/jim80net/gatekeeper-core/config"
)

var version = "dev"

func main() {
	os.Exit(run(os.Stdin, os.Stdout, os.Args[1:]))
}

func run(stdin io.Reader, stdout io.Writer, args []string) int {
	// Check for subcommands before flag parsing.
	if len(args) > 0 {
		switch args[0] {
		case "-h", "--help":
			writeTopLevelHelp(stdout)
			return 0
		case "migrate":
			return runMigrate(args[1:])
		case "setup":
			return runSetup(args[1:])
		case "uninstall":
			return runUninstall()
		case "doctor", "inventory":
			return runDoctor(stdout, args[1:])
		case "test":
			return runPolicyTest(stdout, args[1:])
		case "auth-domains":
			return runAuthDomains(stdout, args[1:])
		case "release-verify", "verify-release":
			return runReleaseVerify(stdout, args[1:])
		case "version":
			fmt.Fprintf(os.Stderr, "claude-gatekeeper %s\n", version)
			return 0
		}
	}

	// Hook mode flags.
	fs := flag.NewFlagSet("claude-gatekeeper", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	debug := fs.Bool("debug", false, "Enable debug output to stderr")
	showVersion := fs.Bool("version", false, "Show version")
	harness := fs.String("harness", "", "Target harness: claude|codex|grok (default claude)")
	if err := fs.Parse(args); err != nil {
		return 0 // abstain on flag errors
	}

	if *showVersion {
		fmt.Fprintf(os.Stderr, "claude-gatekeeper %s\n", version)
		return 0
	}

	canonical.DebugEnabled = *debug

	// Select the harness adapter: flag > env > default (claude).
	harnessName := *harness
	if harnessName == "" {
		harnessName = os.Getenv("GATEKEEPER_HARNESS")
	}
	ad, err := adapter.For(harnessName)
	if err != nil {
		// Unknown harness: abstain rather than assert a verdict on the wrong wire.
		canonical.Debugf("adapter selection: %v", err)
		return 0
	}

	// Auto-install default config on first run (best-effort, back-compat).
	installDefaultConfig()

	return runHook(stdin, stdout, ad, *debug)
}

func writeTopLevelHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage: claude-gatekeeper [hook flags]
       claude-gatekeeper <command> [options]

With no command, reads one hook event from stdin and writes a harness decision.

Commands:
  doctor          Inspect selected-root registration and hook drift
  setup           Register the hook for Claude, Codex, or Grok
  test            Run declarative policy cases
  release-verify  Verify release assets and live binary stamps
  migrate         Convert Claude permissions to gatekeeper TOML
  uninstall       Remove Claude hook registration
  auth-domains    Inspect authorization-domain contracts in shadow mode
  version         Print the version

Hook flags:
  --harness name  Target claude, codex, or grok (default: claude)
  --debug         Enable diagnostic output on stderr
  --version       Print the version`)
}

func runAuthDomains(stdout io.Writer, args []string) int {
	if len(args) == 0 || args[0] != "shadow" {
		fmt.Fprintln(os.Stderr, "usage: claude-gatekeeper auth-domains shadow --policy generation.json --request request.json --coverage coverage.json [--json]")
		return 2
	}
	fs := flag.NewFlagSet("auth-domains shadow", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	policyPath := fs.String("policy", "", "D1 policy generation JSON")
	requestPath := fs.String("request", "", "D1 request JSON")
	coveragePath := fs.String("coverage", "", "D1 coverage manifest JSON")
	jsonOutput := fs.Bool("json", false, "Emit machine-readable JSON")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *policyPath == "" || *requestPath == "" || *coveragePath == "" {
		fmt.Fprintln(os.Stderr, "auth-domains shadow: --policy, --request, and --coverage are required")
		return 2
	}
	policy, err := authdomains.LoadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "auth-domains shadow: policy: %v\n", err)
		return 2
	}
	request, err := authdomains.LoadRequest(*requestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "auth-domains shadow: request: %v\n", err)
		return 2
	}
	coverage, err := authdomains.LoadCoverage(*coveragePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "auth-domains shadow: coverage: %v\n", err)
		return 2
	}
	report := authdomains.Shadow(policy, request, coverage, time.Now().UTC())
	if *jsonOutput {
		err = authdomains.WriteJSON(stdout, report)
	} else {
		err = authdomains.WriteTable(stdout, report)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "auth-domains shadow: report: %v\n", err)
		return 2
	}
	if !report.Conformant {
		return 1
	}
	return 0
}

func runReleaseVerify(stdout io.Writer, args []string) int {
	fs := flag.NewFlagSet("release-verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			fs.SetOutput(stdout)
			break
		}
	}
	repo := fs.String("repo", "jim80net/gatekeeper-claude", "GitHub owner/repository")
	hostBinary := fs.String("host-binary", "", "Explicit live host binary path")
	pluginBinary := fs.String("plugin-binary", "", "Explicit active plugin binary path")
	minSurfaces := fs.Int("min-surfaces", 3, "Minimum live hook surfaces Doctor must find")
	jsonOutput := fs.Bool("json", false, "Emit machine-readable JSON")
	tag := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		tag = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if tag == "" {
		if fs.NArg() == 1 {
			tag = fs.Arg(0)
		} else {
			fmt.Fprintln(os.Stderr, "usage: claude-gatekeeper release-verify [options] vX.Y.Z")
			return 2
		}
	} else if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: claude-gatekeeper release-verify [options] vX.Y.Z")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := releaseverify.Verify(ctx, releaseverify.Options{
		Tag:          tag,
		Repo:         *repo,
		HostBinary:   *hostBinary,
		PluginBinary: *pluginBinary,
		MinSurfaces:  *minSurfaces,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-release: %v\n", err)
		return 2
	}
	if *jsonOutput {
		err = releaseverify.WriteJSON(stdout, result)
	} else {
		err = releaseverify.WriteTable(stdout, result)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-release: %v\n", err)
		return 2
	}
	if !result.OK {
		return result.ExitCode
	}
	return 0
}

func runPolicyTest(stdout io.Writer, args []string) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "Evaluate only this gatekeeper TOML (default: layered live config)")
	cwd := fs.String("cwd", "", "Default working directory for project config and preconditions")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: claude-gatekeeper test [--config gatekeeper.toml] [--cwd dir] cases.toml|cases.json")
		return 2
	}
	cases, err := policytest.LoadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "test: %v\n", err)
		return 2
	}
	results, err := policytest.Run(cases, *configPath, *cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "test: %v\n", err)
		return 2
	}
	if err := policytest.WriteTable(stdout, results); err != nil {
		fmt.Fprintf(os.Stderr, "test: %v\n", err)
		return 2
	}
	if !policytest.Passed(results) {
		return 1
	}
	return 0
}

func runDoctor(stdout io.Writer, args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOutput := fs.Bool("json", false, "Emit machine-readable JSON")
	claudeConfigDir := fs.String("claude-config-dir", "", "Effective Claude config root (default: CLAUDE_CONFIG_DIR, then ~/.claude)")
	requireHarness := fs.String("require-harness", "claude", "Registration required for success: claude, codex, grok, or any")
	expectedBinary := fs.String("expected-binary", "", "Expected binary path (default: this executable)")
	expectedVersion := fs.String("expected-version", version, "Expected version stamp")
	minSurfaces := fs.Int("min-surfaces", 1, "Minimum recognized surfaces required for success")
	checkLatest := fs.Bool("check-latest", false, "Compare enforcing binary versions with the latest published release")
	latestURL := fs.String("latest-release-url", "https://api.github.com/repos/jim80net/gatekeeper-claude/releases/latest", "Latest published release API URL")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *minSurfaces < 0 {
		fmt.Fprintln(os.Stderr, "doctor: --min-surfaces must be non-negative")
		return 2
	}
	if *expectedBinary == "" {
		if exe, err := os.Executable(); err == nil {
			*expectedBinary = exe
		}
	}
	options := inventory.Options{ClaudeRoot: *claudeConfigDir, RequiredHarness: *requireHarness, ExpectedBinary: *expectedBinary, ExpectedVersion: *expectedVersion, MinSurfaces: *minSurfaces}
	if *claudeConfigDir != "" {
		options.ClaudeRootSource = "cli"
	}
	if *checkLatest {
		options.PublishedVersionProbe = func() (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return inventory.FetchPublishedLatest(ctx, &http.Client{Timeout: 10 * time.Second}, *latestURL)
		}
	}
	report, err := inventory.Collect(options)
	if err != nil {
		fmt.Fprintf(os.Stderr, "doctor: %v\n", err)
		return 2
	}
	if *jsonOutput {
		if err := inventory.WriteJSON(stdout, report); err != nil {
			fmt.Fprintf(os.Stderr, "doctor: %v\n", err)
			return 2
		}
	} else {
		if err := inventory.WriteTable(stdout, report); err != nil {
			fmt.Fprintf(os.Stderr, "doctor: %v\n", err)
			return 2
		}
	}
	if report.HasFileErrors() {
		return 2
	}
	if !report.OK {
		return 1
	}
	return 0
}

// runHook parses the hook input, evaluates the rules, and encodes the verdict
// on the adapter's wire. Every error path applies the on_error posture; a
// recovered panic does too.
func runHook(stdin io.Reader, stdout io.Writer, ad adapter.Adapter, debug bool) (code int) {
	// Resolve the independent posture before any input/config operation. The
	// deferred recover uses the override or readable TOML posture known at the
	// point of failure.
	override := posture.Resolve()
	onError := canonical.Abstain
	if override.Active {
		onError = override.Decision
	}
	if override.Warning != "" {
		fmt.Fprintf(os.Stderr, "gatekeeper: warning: %s\n", override.Warning)
	}
	for _, warning := range posture.ConfigWarnings() {
		fmt.Fprintf(os.Stderr, "gatekeeper: warning: %s\n", warning)
	}
	defer func() {
		if r := recover(); r != nil {
			canonical.Debugf("panic recovered: %v", r)
			code = emit(stdout, ad, errVerdict(onError, fmt.Sprintf("panic: %v", r)))
		}
	}()

	// Parse hook input from stdin.
	tc, err := ad.ParseInput(stdin)
	if err != nil {
		canonical.Debugf("error reading input: %v", err)
		// No cwd is available on a parse failure; use the global-only posture.
		if !override.Active {
			onError = config.GlobalOnError()
		}
		return emit(stdout, ad, errVerdict(onError, "unparseable hook input"))
	}

	// Only handle PreToolUse events; other events abstain (clean, not an error).
	if tc.EventName != "" && tc.EventName != "PreToolUse" {
		canonical.Debugf("ignoring event: %s", tc.EventName)
		return emit(stdout, ad, canonical.Verdict{Decision: canonical.Abstain})
	}

	// Load config (global + project overlay from the tool call's cwd).
	cfg, err := config.Load(tc.CWD)
	if err != nil {
		canonical.Debugf("error loading config: %v", err)
		// The full load could not be trusted; fall back to the global-only
		// posture (which is Abstain if the global config is itself the problem).
		if !override.Active {
			onError = config.GlobalOnError()
		}
		return emit(stdout, ad, errVerdict(onError, "config load error"))
	}
	if !override.Active {
		onError = cfg.OnErrorDecision()
	}
	if len(cfg.Rules) == 0 && override.Active && override.Decision == canonical.Deny {
		return emit(stdout, ad, errVerdict(onError, "no policy rules loaded while fail-closed posture is active"))
	}

	// Compile the engine.
	eng, err := policyengine.New(cfg, debug)
	if err != nil {
		canonical.Debugf("error creating engine: %v", err)
		return emit(stdout, ad, errVerdict(onError, "engine compile error"))
	}

	// Evaluate.
	v, err := eng.Evaluate(tc)
	if err != nil {
		canonical.Debugf("error evaluating: %v", err)
		return emit(stdout, ad, errVerdict(onError, "evaluate error"))
	}

	return emit(stdout, ad, v)
}

// emit encodes the verdict on the adapter's wire and returns the exit code.
func emit(w io.Writer, ad adapter.Adapter, v canonical.Verdict) int {
	code, err := ad.Encode(w, v)
	if err != nil {
		canonical.Debugf("error encoding output: %v", err)
	}
	return code
}

// errVerdict builds the verdict to emit on a gatekeeper error, per the on_error
// posture. Abstain carries no reason (nothing is written for it anyway).
func errVerdict(d canonical.Decision, ctx string) canonical.Verdict {
	if d == canonical.Abstain {
		return canonical.Verdict{Decision: canonical.Abstain}
	}
	return canonical.Verdict{Decision: d, Reason: "gatekeeper error: " + ctx}
}

// installDefaultConfig writes the default gatekeeper.toml to the back-compat
// global path on first run, best-effort.
func installDefaultConfig() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return
	}
	templatePath := filepath.Join(filepath.Dir(resolved), "..", "gatekeeper.toml")
	if err := config.EnsureGlobalConfig(templatePath); err != nil {
		canonical.Debugf("auto-config: %v", err)
	}
}

func runSetup(args []string) int {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	binaryPath := fs.String("binary", "", "Absolute path to the installed binary (auto-detected if omitted)")
	harness := fs.String("harness", "claude", "Target harness: claude|codex|grok")
	projectDir := fs.String("project-dir", "", "Codex hook location: empty = global ~/.codex/hooks.json (default); a path = that project's .codex/hooks.json")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	bin := *binaryPath
	if bin == "" {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot determine binary path: %v\n", err)
			return 1
		}
		bin = exe
	}

	var err error
	switch *harness {
	case "claude":
		err = setup.Install(bin)
	case "grok":
		err = setup.InstallGrok(bin)
	case "codex":
		err = setup.InstallCodex(bin, *projectDir)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown harness %q (want claude|codex|grok)\n", *harness)
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func runUninstall() int {
	if err := setup.Uninstall(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func runMigrate(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	settingsPath := fs.String("settings", "", "Path to settings.json (auto-detected if omitted)")
	outputPath := fs.String("output", "", "Output path for gatekeeper.toml (default: ~/.claude/gatekeeper.toml)")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	if err := migrate.Run(*settingsPath, *outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}
