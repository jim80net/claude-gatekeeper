package main

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/jim80net/gatekeeper-core/canonical"
	"github.com/jim80net/gatekeeper-core/config"
)

// onErrorAfterLoadFailure is the adapter mapping to core 6086c496.
// That SHA's LoadFile validates rules, so config.GlobalOnError() abstains when
// the global TOML is parseable, sets on_error=deny, and contains an uncompilable
// rule. Recover the knob from a TOML-only decode of the same first-present
// global file. Do not re-admit the invalid rules.
func onErrorAfterLoadFailure() canonical.Decision {
	if d := config.GlobalOnError(); d == canonical.Deny {
		return d
	}
	return onErrorFromReadableGlobalTOML()
}

func onErrorFromReadableGlobalTOML() canonical.Decision {
	path := firstPresentGlobalConfig()
	if path == "" {
		return canonical.Abstain
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return canonical.Abstain
	}
	var knob struct {
		OnError string `toml:"on_error"`
	}
	if _, err := toml.Decode(string(data), &knob); err != nil {
		return canonical.Abstain
	}
	if knob.OnError == config.OnErrorDeny {
		return canonical.Deny
	}
	return canonical.Abstain
}

func firstPresentGlobalConfig() string {
	for _, p := range globalConfigCandidates() {
		if p == "" {
			continue
		}
		_, err := os.Stat(p)
		if err == nil || !os.IsNotExist(err) {
			return p
		}
	}
	return ""
}

func globalConfigCandidates() []string {
	var out []string
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		out = append(out, filepath.Join(x, "gatekeeper", "gatekeeper.toml"))
	} else if home, err := os.UserHomeDir(); err == nil && home != "" {
		out = append(out, filepath.Join(home, ".config", "gatekeeper", "gatekeeper.toml"))
	}
	out = append(out, config.GlobalConfigPath())
	return out
}
