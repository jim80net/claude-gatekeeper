// claude-gatekeeper is a PreToolUse permission hook for Claude Code.
//
// Default mode (no args): reads hook JSON from stdin, evaluates rules,
// writes a permission decision to stdout.
//
// Subcommands:
//
//	migrate   Convert settings.json permissions to gatekeeper TOML.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jim80net/claude-gatekeeper/internal/config"
	"github.com/jim80net/claude-gatekeeper/internal/engine"
	"github.com/jim80net/claude-gatekeeper/internal/migrate"
	"github.com/jim80net/claude-gatekeeper/internal/protocol"
	"github.com/jim80net/claude-gatekeeper/internal/setup"
)

var version = "dev"

func main() {
	os.Exit(run(os.Stdin, os.Stdout, os.Args[1:]))
}

func run(stdin io.Reader, stdout io.Writer, args []string) int {
	// Check for subcommands before flag parsing.
	if len(args) > 0 {
		switch args[0] {
		case "migrate":
			return runMigrate(args[1:])
		case "setup":
			return runSetup(args[1:])
		case "uninstall":
			return runUninstall()
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
	if err := fs.Parse(args); err != nil {
		return 0 // abstain on flag errors
	}

	if *showVersion {
		fmt.Fprintf(os.Stderr, "claude-gatekeeper %s\n", version)
		return 0
	}

	protocol.DebugEnabled = *debug

	// Auto-install default config on first run.
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			templatePath := filepath.Join(filepath.Dir(resolved), "..", "gatekeeper.toml")
			if err := config.EnsureGlobalConfig(templatePath); err != nil {
				protocol.Debugf("auto-config: %v", err)
			}
		}
	}

	// Read hook input from stdin.
	input, err := protocol.ReadInput(stdin)
	if err != nil {
		protocol.Debugf("error reading input: %v", err)
		return 0 // abstain
	}

	// Only handle PreToolUse events.
	if input.HookEventName != "" && input.HookEventName != "PreToolUse" {
		protocol.Debugf("ignoring event: %s", input.HookEventName)
		return 0
	}

	// Load config.
	cfg, err := config.Load(input.CWD)
	if err != nil {
		protocol.Debugf("error loading config: %v", err)
		return 0 // abstain
	}

	// Create engine and evaluate.
	eng, err := engine.New(cfg, *debug)
	if err != nil {
		protocol.Debugf("error creating engine: %v", err)
		return 0 // abstain
	}

	output, err := eng.Evaluate(input)
	if err != nil {
		protocol.Debugf("error evaluating: %v", err)
		return 0 // abstain
	}

	// nil output = abstain (write nothing).
	if output != nil {
		if err := protocol.WriteOutput(stdout, output); err != nil {
			protocol.Debugf("error writing output: %v", err)
		}
	}
	return 0
}

func runSetup(args []string) int {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	binaryPath := fs.String("binary", "", "Absolute path to the installed binary (auto-detected if omitted)")
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

	if err := setup.Install(bin); err != nil {
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
