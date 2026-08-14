// gatekeeper-walk runs source-only acceptance checks. It never installs hooks,
// edits live settings, or treats static registration as firing proof.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jim80net/claude-gatekeeper/internal/walk"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "release-matrix":
		return runReleaseMatrix(args[1:])
	case "attest-firing":
		return runAttestFiring(args[1:])
	case "verify-firing":
		return runVerifyFiring(args[1:])
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: gatekeeper-walk <command> [options]

Commands:
  release-matrix  Test one exact candidate against planted three-root fixtures
  attest-firing   Record a disposable live session's benign and deny arms
  verify-firing   Recheck the recorded PID identity; replacement becomes no_data`)
}

func runReleaseMatrix(args []string) int {
	fs := flag.NewFlagSet("release-matrix", flag.ContinueOnError)
	candidate := fs.String("candidate", "", "Exact candidate binary")
	sha := fs.String("candidate-sha256", "", "Required SHA-256 of the candidate")
	version := fs.String("expected-version", "", "Required candidate version")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := walk.RunReleaseMatrix(ctx, walk.ReleaseMatrixOptions{Candidate: *candidate, CandidateSHA256: *sha, ExpectedVersion: *version})
	if err != nil {
		fmt.Fprintln(os.Stderr, "release-matrix:", err)
		return 2
	}
	if err := writeJSON(result); err != nil {
		fmt.Fprintln(os.Stderr, "release-matrix:", err)
		return 2
	}
	if !result.OK {
		return 1
	}
	return 0
}

func runAttestFiring(args []string) int {
	fs := flag.NewFlagSet("attest-firing", flag.ContinueOnError)
	harness := fs.String("harness", "", "claude, codex, or grok")
	pid := fs.Int("pid", 0, "Exact live harness process PID")
	scope := fs.String("session-scope", "", "Must be disposable")
	benign := fs.String("benign", "", "Must be reached")
	deny := fs.String("deny", "", "Must be pretool_denied")
	reason := fs.String("deny-reason", "", "Observed Gatekeeper deny reason")
	output := fs.String("output", "", "Attestation JSON path")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *output == "" {
		return 2
	}
	attestation, err := walk.RecordFiring(walk.FiringOptions{Harness: *harness, PID: *pid, Scope: *scope, Benign: *benign, Deny: *deny, DenyReason: *reason})
	if err != nil {
		fmt.Fprintln(os.Stderr, "attest-firing:", err)
		return 2
	}
	if err := walk.WriteJSONFile(*output, attestation); err != nil {
		fmt.Fprintln(os.Stderr, "attest-firing:", err)
		return 2
	}
	if err := writeJSON(attestation); err != nil {
		return 2
	}
	return 0
}

func runVerifyFiring(args []string) int {
	fs := flag.NewFlagSet("verify-firing", flag.ContinueOnError)
	path := fs.String("attestation", "", "Firing attestation JSON")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *path == "" {
		return 2
	}
	attestation, err := walk.ReadAttestation(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-firing:", err)
		return 2
	}
	result := walk.VerifyFiring(attestation, nil)
	if err := writeJSON(result); err != nil {
		return 2
	}
	if result.Status == "pass" {
		return 0
	}
	if result.Status == "no_data" {
		return 1
	}
	return 2
}

func writeJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
