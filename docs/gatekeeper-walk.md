# Source-only release and firing walk

`gatekeeper-walk` is repository tooling. It does not install Gatekeeper, edit
live settings, or convert static registration into firing proof. Its session
driver creates disposable configuration roots and delegates real-harness launch
and observation to an explicit adapter executable.

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

## Disposable session-driver protocol

Source-only adapters can drive a real harness without borrowing live settings:

```text
gatekeeper-walk drive-session \
  --harness <claude|codex|grok> \
  --driver /absolute/path/to/harness-driver \
  --expected-native-executable /absolute/path/to/native-harness \
  --output /path/to/session-result.json \
  -- <driver arguments>
```

Gatekeeper Walk launches the driver directly, without a shell, under fresh
`HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, and XDG roots. It never supplies the
live values. The driver speaks newline-delimited JSON using schema
`gatekeeper.session-driver/v1`:

1. emit `{"schema":"gatekeeper.session-driver/v1","arm":"ready","native_pid":PID,"status":"ready"}` after the real native harness is live;
2. accept requests for `benign` and `deny`, returning the same native PID with
   `reached` and `pretool_denied` respectively (the deny requires its observed
   reason);
3. accept `close` and terminate the disposable session.

The coordinator independently reads the reported PID identity before and after
each arm and requires `/proc/<pid>/exe` to equal the declared native harness
executable. A changed PID, executable, or process start time refuses the result.
The saved record names `lifecycle=closed_after_observation`: because the driver
closes the disposable session, later `verify-firing` correctly returns
`no_data`; the record is exact historical walk evidence, not standing proof for
a replacement process.

The repository fixture exercises the protocol and failure seams with a real
subprocess. Harness-specific Claude, Codex, and Grok adapters, second-harness
first-install flows, interrupted-session scenarios, and Windows process/wrapper
coverage remain the exact open Issue #70 source slices. The protocol and fixture
do not claim those sessions ran.
