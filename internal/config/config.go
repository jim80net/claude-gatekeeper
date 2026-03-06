// Package config loads and layers gatekeeper TOML configuration.
package config

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/jim80net/claude-gatekeeper/internal/protocol"
)

//go:embed defaults.toml
var defaultsFS embed.FS

// Config is the top-level configuration.
type Config struct {
	IncludeDefaults *bool  `toml:"include_defaults"`
	Rules           []Rule `toml:"rules"`
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

// Load builds the final config by layering defaults, global, and project files.
// projectDir is typically the cwd from the hook input.
func Load(projectDir string) (*Config, error) {
	var global, project *Config

	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		globalPath := filepath.Join(homeDir, ".claude", ".gatekeeper.toml")
		g, err := loadFile(globalPath)
		if err == nil {
			global = g
			protocol.Debugf("loaded global config: %s (%d rules)", globalPath, len(g.Rules))
		}
	}

	if projectDir != "" {
		projectPath := filepath.Join(projectDir, ".claude", "gatekeeper.toml")
		p, err := loadFile(projectPath)
		if err == nil {
			project = p
			protocol.Debugf("loaded project config: %s (%d rules)", projectPath, len(p.Rules))
		}
	}

	includeDefaults := true
	if global != nil && global.IncludeDefaults != nil && !*global.IncludeDefaults {
		includeDefaults = false
	}
	if project != nil && project.IncludeDefaults != nil && !*project.IncludeDefaults {
		includeDefaults = false
	}

	var rules []Rule
	if includeDefaults {
		defaults, err := LoadDefaults()
		if err != nil {
			return nil, fmt.Errorf("loading defaults: %w", err)
		}
		rules = append(rules, defaults.Rules...)
		protocol.Debugf("loaded %d default rules", len(defaults.Rules))
	}
	if global != nil {
		rules = append(rules, global.Rules...)
	}
	if project != nil {
		rules = append(rules, project.Rules...)
	}

	protocol.Debugf("total rules: %d", len(rules))
	return &Config{Rules: rules}, nil
}

// LoadDefaults parses the embedded default rules.
func LoadDefaults() (*Config, error) {
	data, err := defaultsFS.ReadFile("defaults.toml")
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing defaults.toml: %w", err)
	}
	return &cfg, nil
}

func loadFile(path string) (*Config, error) {
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
