// Package policytest loads declarative policy cases and evaluates them through
// the same gatekeeper-core engine used by live hooks.
package policytest

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/BurntSushi/toml"
	"github.com/jim80net/claude-gatekeeper/internal/policyengine"
	"github.com/jim80net/gatekeeper-core/canonical"
	"github.com/jim80net/gatekeeper-core/config"
)

// File is the top-level TOML or JSON policy-test document.
type File struct {
	Cases []Case `toml:"cases" json:"cases"`
}

// Case describes one canonical tool call and its expected policy outcome.
type Case struct {
	Name           string `toml:"name" json:"name"`
	Tool           string `toml:"tool" json:"tool"`
	Input          string `toml:"input" json:"input"`
	Command        string `toml:"command" json:"command"`
	CWD            string `toml:"cwd" json:"cwd"`
	Expected       string `toml:"expected" json:"expected"`
	ExpectedReason string `toml:"expected_reason" json:"expected_reason"`
}

// Result records the observed verdict and whether it met a case's expectations.
type Result struct {
	Name           string
	Expected       string
	Actual         string
	Reason         string
	Passed         bool
	FailureMessage string
}

// LoadFile parses a .toml or .json test document and validates its cases.
func LoadFile(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	var f File
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&f)
		if err == nil {
			var trailing any
			if trailingErr := decoder.Decode(&trailing); trailingErr != io.EOF {
				if trailingErr == nil {
					err = fmt.Errorf("multiple JSON values")
				} else {
					err = trailingErr
				}
			}
		}
	case ".toml":
		var metadata toml.MetaData
		metadata, err = toml.Decode(string(data), &f)
		if err == nil {
			if unknown := metadata.Undecoded(); len(unknown) > 0 {
				err = fmt.Errorf("unknown field %q", unknown[0].String())
			}
		}
	default:
		return File{}, fmt.Errorf("unsupported test file %q (want .toml or .json)", path)
	}
	if err != nil {
		return File{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(f.Cases) == 0 {
		return File{}, fmt.Errorf("%s contains no cases", path)
	}
	for i := range f.Cases {
		if err := validateCase(&f.Cases[i], i); err != nil {
			return File{}, err
		}
	}
	return f, nil
}

func validateCase(c *Case, i int) error {
	if c.Name == "" {
		c.Name = fmt.Sprintf("case %d", i+1)
	}
	if c.Tool == "" {
		return fmt.Errorf("%s: tool is required", c.Name)
	}
	if c.Input != "" && c.Command != "" {
		return fmt.Errorf("%s: set input or command, not both", c.Name)
	}
	if c.Command != "" {
		if c.Tool != canonical.ToolBash {
			return fmt.Errorf("%s: command is only valid with tool %q", c.Name, canonical.ToolBash)
		}
		c.Input = c.Command
	}
	switch c.Expected {
	case "allow", "deny", "abstain":
	default:
		return fmt.Errorf("%s: expected must be allow, deny, or abstain", c.Name)
	}
	return nil
}

// Run evaluates all cases against configPath, or the layered live config when
// configPath is empty. defaultCWD selects project config and precondition cwd.
func Run(f File, configPath, defaultCWD string) ([]Result, error) {
	if defaultCWD == "" {
		var err error
		defaultCWD, err = os.Getwd()
		if err != nil {
			return nil, err
		}
	}
	var fixed *config.Config
	var err error
	if configPath != "" {
		fixed, err = config.LoadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("load config: %w", err)
		}
	}
	results := make([]Result, 0, len(f.Cases))
	for _, c := range f.Cases {
		cwd := c.CWD
		if cwd == "" {
			cwd = defaultCWD
		}
		cfg := fixed
		if cfg == nil {
			cfg, err = config.Load(cwd)
			if err != nil {
				return nil, fmt.Errorf("%s: load config: %w", c.Name, err)
			}
		}
		eng, err := policyengine.New(cfg, false)
		if err != nil {
			return nil, fmt.Errorf("%s: compile config: %w", c.Name, err)
		}
		verdict, err := eng.Evaluate(&canonical.ToolCall{Tool: c.Tool, InputString: c.Input, CWD: cwd, EventName: "PreToolUse"})
		if err != nil {
			return nil, fmt.Errorf("%s: evaluate: %w", c.Name, err)
		}
		actual := verdict.Decision.String()
		r := Result{Name: c.Name, Expected: c.Expected, Actual: actual, Reason: verdict.Reason, Passed: actual == c.Expected}
		if !r.Passed {
			r.FailureMessage = fmt.Sprintf("expected %s, got %s", c.Expected, actual)
		} else if c.ExpectedReason != "" && verdict.Reason != c.ExpectedReason {
			r.Passed = false
			r.FailureMessage = fmt.Sprintf("expected reason %q, got %q", c.ExpectedReason, verdict.Reason)
		}
		results = append(results, r)
	}
	return results, nil
}

// WriteTable prints a human-readable test report.
func WriteTable(w io.Writer, results []Result) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "STATUS\tCASE\tEXPECTED\tACTUAL\tREASON"); err != nil {
		return err
	}
	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", status, r.Name, r.Expected, r.Actual, r.Reason); err != nil {
			return err
		}
		if r.FailureMessage != "" {
			if _, err := fmt.Fprintf(tw, "\t%s\t\t\t\n", r.FailureMessage); err != nil {
				return err
			}
		}
	}
	return tw.Flush()
}

// Passed reports whether every result passed.
func Passed(results []Result) bool {
	for _, r := range results {
		if !r.Passed {
			return false
		}
	}
	return true
}
