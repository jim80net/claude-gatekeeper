// gatekeeper-walk-session-driver adapts Claude, Codex, and Grok machine
// protocols to gatekeeper.session-driver/v1. It refuses non-disposable roots.
package main

import (
	"os"

	"github.com/jim80net/claude-gatekeeper/internal/walk/sessiondriver"
)

func main() {
	os.Exit(sessiondriver.Run(os.Stdin, os.Stdout, os.Stderr, os.Args[1:]))
}
