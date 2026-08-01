# Tasks — Authorization Domains D1 + I1a shadow

## D1 chapters

- [x] Absorb the approved design and core D1 contract artifacts.
- [x] Absorb the Codex implementation-independent replay constraints.
- [x] Pin the Grok lifecycle/isolation artifact by SHA-256.
- [x] Write proposal, design, and normative requirements.

## I1a implementation

- [x] Add strict D1 JSON types and candidate compilation tests.
- [x] Add deterministic shadow evaluation tests for open ordinary work, exact
  protected reads, exceptions, mismatches, expiry, stale generation, and
  unknown protected actions.
- [x] Add honest coverage validation and lifecycle/isolation receipt tests.
- [x] Add the explicit `auth-domains shadow` report command.
- [x] Add cross-harness non-interference regression tests.
- [x] Document the command and its non-enforcing boundary.

## Gates

- [x] `openspec validate authorization-domains-d1-shadow --strict`
- [x] `gofmt`, `go vet ./...`, and `go test -race -count=1 ./...`
- [x] Build the unified binary and exercise the shadow fixtures.
- [ ] Open a bounded draft PR with a conventional `feat:` title.
- [ ] Surface the draft PR URL and exact head to gatekeeper-xo; do not merge.

## Explicit stop line

- No credential placement, lookup, or reprovisioning.
- No PA activation or production final-PEP enablement.
- No deploy, install, restart, off-host action, spend, or self-merge.
