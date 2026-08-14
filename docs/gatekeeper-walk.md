# Source-only release and firing walk

`gatekeeper-walk` is repository tooling. It does not install Gatekeeper, edit
live settings, launch a real harness, or convert static registration into
firing proof.

## Release matrix

Build the exact candidate with its release version stamp, hash it, then run:

```text
gatekeeper-walk release-matrix \
  --candidate /absolute/path/to/claude-gatekeeper \
  --candidate-sha256 <sha256> \
  --expected-version <version>
```

The command creates three temporary Claude roots and removes them afterward:

- default: provisioned direct registration under the fixture `HOME/.claude`;
- leadership: deliberately unprovisioned, selected through
  `CLAUDE_CONFIG_DIR`;
- overflow: deliberately unprovisioned, selected through
  `CLAUDE_CONFIG_DIR`.

Acceptance is default `registered`/exit 0, both account roots `absent`/exit 1,
the exact resolved root and source on every arm, and
`firing_status=not_tested` everywhere. The supplied digest must match before
any arm runs.

## Process-bound firing record

Run the benign and known-deny calls in a genuinely disposable harness session.
Then record only that session's observed results and native PID:

```text
gatekeeper-walk attest-firing \
  --harness <claude|codex|grok> \
  --pid <live-native-harness-pid> \
  --session-scope disposable \
  --benign reached \
  --deny pretool_denied \
  --deny-reason <observed-reason> \
  --output /path/to/attestation.json
```

Recheck before citing the record:

```text
gatekeeper-walk verify-firing --attestation /path/to/attestation.json
```

The record includes `/proc/<pid>/exe` and process start ticks. A dead or
replaced process returns `no_data`, never a stale pass. This executable
mechanizes evidence identity and expiry; it does not yet drive Claude, Codex,
Grok, or Windows sessions itself. Issue #70 remains open for those real-harness
drivers and failure-seam automation.
