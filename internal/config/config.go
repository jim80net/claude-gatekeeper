// Package config loads and layers gatekeeper TOML configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/jim80net/claude-gatekeeper/internal/protocol"
)

// Config is the top-level configuration.
type Config struct {
	Rules []Rule `toml:"rules"`
}

// Rule is a single permission rule.
type Rule struct {
	Tool              string `toml:"tool"`
	Input             string `toml:"input"`
	Decision          string `toml:"decision"`
	Reason            string `toml:"reason"`
	Precondition      string `toml:"precondition,omitempty"`
	PreconditionMatch string `toml:"precondition_match,omitempty"`
}

// GlobalConfigPath returns the path to ~/.claude/gatekeeper.toml.
func GlobalConfigPath() string {
	homeDir, _ := os.UserHomeDir()
	if homeDir == "" {
		return ""
	}
	return filepath.Join(homeDir, ".claude", "gatekeeper.toml")
}

// EnsureGlobalConfig copies templatePath to ~/.claude/gatekeeper.toml if the
// global config does not already exist. This provides seamless defaults on
// first run when installed as a plugin.
func EnsureGlobalConfig(templatePath string) error {
	dest := GlobalConfigPath()
	if dest == "" {
		return fmt.Errorf("cannot determine home directory")
	}

	if _, err := os.Stat(dest); err == nil {
		return nil // already exists
	}

	data, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("reading template: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	if err := os.WriteFile(dest, data, 0644); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	protocol.Debugf("installed default config: %s", dest)
	return nil
}

// Load builds the final config by layering global and project files.
// projectDir is typically the cwd from the hook input.
func Load(projectDir string) (*Config, error) {
	var rules []Rule

	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		globalPath := filepath.Join(homeDir, ".claude", "gatekeeper.toml")
		g, err := LoadFile(globalPath)
		if err == nil {
			rules = append(rules, g.Rules...)
			protocol.Debugf("loaded global config: %s (%d rules)", globalPath, len(g.Rules))
		}
	}

	if projectDir != "" {
		projectPath := filepath.Join(projectDir, ".claude", "gatekeeper.toml")
		p, err := LoadFile(projectPath)
		if err == nil {
			rules = append(rules, p.Rules...)
			protocol.Debugf("loaded project config: %s (%d rules)", projectPath, len(p.Rules))
		}
	}

	protocol.Debugf("total rules: %d", len(rules))
	return &Config{Rules: rules}, nil
}

// LoadFile parses a TOML config from the given path.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &cfg, nil
}
