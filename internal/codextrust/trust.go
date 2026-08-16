// Package codextrust verifies Codex CLI's persisted hook trust state.
package codextrust

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/BurntSushi/toml"
)

// Status describes whether a hook's current normalized identity is trusted.
type Status struct {
	Key         string
	CurrentHash string
	TrustedHash string
}

// Trusted reports whether the persisted hash matches the current hook identity.
func (s Status) Trusted() bool { return s.TrustedHash == s.CurrentHash }

type hooksFile struct {
	Hooks map[string][]matcherGroup `json:"hooks"`
}

type matcherGroup struct {
	Matcher *string       `json:"matcher,omitempty"`
	Hooks   []commandHook `json:"hooks"`
}

type commandHook struct {
	Type           string  `json:"type"`
	Command        string  `json:"command"`
	CommandWindows *string `json:"commandWindows,omitempty"`
	Timeout        *uint64 `json:"timeout,omitempty"`
	Async          bool    `json:"async"`
	StatusMessage  *string `json:"statusMessage,omitempty"`
}

type configFile struct {
	Hooks struct {
		State map[string]struct {
			TrustedHash string `toml:"trusted_hash"`
		} `toml:"state"`
	} `toml:"hooks"`
}

// Inspect finds command in hookPath and compares its normalized identity with
// the trust state persisted in <home>/.codex/config.toml.
func Inspect(home, hookPath, command string) (Status, error) {
	return InspectRoot(filepath.Join(home, ".codex"), hookPath, command)
}

// InspectRoot finds command in hookPath and compares its normalized identity
// with the trust state persisted in <codexRoot>/config.toml. Callers that honor
// CODEX_HOME must use this form rather than reconstructing ~/.codex.
func InspectRoot(codexRoot, hookPath, command string) (Status, error) {
	data, err := os.ReadFile(hookPath)
	if err != nil {
		return Status{}, fmt.Errorf("read Codex hooks %s: %w", hookPath, err)
	}
	var file hooksFile
	if err := json.Unmarshal(data, &file); err != nil {
		return Status{}, fmt.Errorf("parse Codex hooks %s: %w", hookPath, err)
	}
	groups := file.Hooks["PreToolUse"]
	for groupIndex, group := range groups {
		for handlerIndex, handler := range group.Hooks {
			if handler.Type != "command" || handler.Command != command {
				continue
			}
			if handler.Async {
				return Status{}, fmt.Errorf("Codex skips async PreToolUse hook %q before trust evaluation: async hooks are not supported", command)
			}
			if err := validateMatcher(group.Matcher); err != nil {
				return Status{}, fmt.Errorf("Codex skips PreToolUse hook %q before trust evaluation: %w", command, err)
			}
			absoluteHookPath, err := filepath.Abs(hookPath)
			if err != nil {
				return Status{}, fmt.Errorf("resolve Codex hook path %s: %w", hookPath, err)
			}
			key := fmt.Sprintf("%s:pre_tool_use:%d:%d", absoluteHookPath, groupIndex, handlerIndex)
			currentHash, err := hashPreToolUse(group.Matcher, handler)
			if err != nil {
				return Status{}, err
			}
			cfgData, err := os.ReadFile(filepath.Join(codexRoot, "config.toml"))
			if err != nil && !os.IsNotExist(err) {
				return Status{}, fmt.Errorf("read Codex config: %w", err)
			}
			var cfg configFile
			if len(cfgData) > 0 {
				if _, err := toml.Decode(string(cfgData), &cfg); err != nil {
					return Status{}, fmt.Errorf("parse Codex config: %w", err)
				}
			}
			return Status{Key: key, CurrentHash: currentHash, TrustedHash: cfg.Hooks.State[key].TrustedHash}, nil
		}
	}
	return Status{}, fmt.Errorf("Codex hook command %q not found in %s", command, hookPath)
}

func hashPreToolUse(matcher *string, handler commandHook) (string, error) {
	timeout := uint64(600)
	if handler.Timeout != nil {
		timeout = *handler.Timeout
	}
	if timeout < 1 {
		timeout = 1
	}
	normalized := map[string]interface{}{
		"event_name": "pre_tool_use",
		"hooks": []interface{}{map[string]interface{}{
			"type": handler.Type, "command": handler.Command,
			"timeout": timeout, "async": handler.Async,
		}},
	}
	if matcher != nil {
		normalized["matcher"] = *matcher
	}
	hook := normalized["hooks"].([]interface{})[0].(map[string]interface{})
	if handler.StatusMessage != nil {
		hook["statusMessage"] = *handler.StatusMessage
	}
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return "", fmt.Errorf("marshal normalized Codex hook: %w", err)
	}
	serialized := bytes.TrimSuffix(canonical.Bytes(), []byte{'\n'})
	sum := sha256.Sum256(serialized)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func validateMatcher(matcher *string) error {
	if matcher == nil || *matcher == "" || *matcher == "*" {
		return nil
	}
	exact := true
	for _, r := range *matcher {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '|') {
			exact = false
			break
		}
	}
	if exact {
		return nil
	}
	if _, err := regexp.Compile(*matcher); err != nil {
		return fmt.Errorf("invalid matcher %q: %w", *matcher, err)
	}
	return nil
}
