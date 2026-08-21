package main

import (
	"testing"

	"github.com/jim80net/gatekeeper-core/canonical"
	"github.com/jim80net/gatekeeper-core/config"
)

func TestOnErrorAfterLoadFailureHonorsDenyOnInvalidRule(t *testing.T) {
	const badRegex = "on_error = \"deny\"\n[[rules]]\ntool='Bash'\ninput='[unclosed'\ndecision=\"allow\"\nreason=\"x\"\n"
	writeHomeConfig(t, badRegex)
	if d := config.GlobalOnError(); d != canonical.Abstain {
		t.Fatalf("GlobalOnError()=%v, want abstain (6086c496 LoadFile validates rules)", d)
	}
	if d := onErrorAfterLoadFailure(); d != canonical.Deny {
		t.Fatalf("onErrorAfterLoadFailure()=%v, want deny", d)
	}
}

func TestOnErrorAfterLoadFailureKeepsAbstainDefault(t *testing.T) {
	const badRegex = "on_error = \"abstain\"\n[[rules]]\ntool='Bash'\ninput='[unclosed'\ndecision=\"allow\"\nreason=\"x\"\n"
	writeHomeConfig(t, badRegex)
	if d := onErrorAfterLoadFailure(); d != canonical.Abstain {
		t.Fatalf("onErrorAfterLoadFailure()=%v, want abstain", d)
	}
}
