package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const schema = "gatekeeper.session-driver/v1"

type request struct {
	Schema string `json:"schema"`
	Arm    string `json:"arm"`
}

type response struct {
	Schema    string `json:"schema"`
	Arm       string `json:"arm"`
	NativePID int    `json:"native_pid"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
}

func main() {
	mode := flag.String("mode", "pass", "fixture failure mode")
	flag.Parse()
	if os.Getenv("GATEKEEPER_WALK_SCOPE") != "disposable" ||
		!strings.Contains(os.Getenv("HOME"), "gatekeeper-walk-session-") ||
		!strings.Contains(os.Getenv("CLAUDE_CONFIG_DIR"), "gatekeeper-walk-session-") ||
		!strings.Contains(os.Getenv("CODEX_HOME"), "gatekeeper-walk-session-") {
		fmt.Fprintln(os.Stderr, "disposable environment missing")
		os.Exit(3)
	}
	encoder := json.NewEncoder(os.Stdout)
	decoder := json.NewDecoder(os.Stdin)
	pid := os.Getpid()
	currentPID := pid
	denyReason := "fixture known-deny rule"
	_ = encoder.Encode(response{Schema: schema, Arm: "ready", NativePID: pid, Status: "ready"})
	for {
		var req request
		if err := decoder.Decode(&req); err != nil {
			os.Exit(4)
		}
		if req.Schema != schema {
			os.Exit(5)
		}
		switch req.Arm {
		case "benign":
			if *mode == "hang_on_benign" {
				time.Sleep(time.Hour)
			}
			status := "reached"
			if *mode == "benign_failed" {
				status = "blocked"
			}
			_ = encoder.Encode(response{Schema: schema, Arm: req.Arm, NativePID: pid, Status: status})
		case "deny":
			responsePID := pid
			if *mode == "pid_changed" {
				responsePID++
			}
			reason := denyReason
			if *mode == "deny_reason_missing" {
				reason = ""
			}
			_ = encoder.Encode(response{Schema: schema, Arm: req.Arm, NativePID: responsePID, Status: "pretool_denied", Reason: reason})
		case "restart":
			if *mode != "restart_same_pid" {
				currentPID++
			}
			pid = currentPID
			_ = encoder.Encode(response{Schema: schema, Arm: req.Arm, NativePID: pid, Status: "restarted"})
		case "config_change":
			if *mode != "config_same_reason" {
				denyReason = "fixture known-deny rule after config change"
			}
			_ = encoder.Encode(response{Schema: schema, Arm: req.Arm, NativePID: pid, Status: "updated", Reason: denyReason})
		case "interrupt":
			_ = encoder.Encode(response{Schema: schema, Arm: req.Arm, NativePID: pid, Status: "interrupted"})
			return
		case "close":
			return
		default:
			os.Exit(6)
		}
	}
}
