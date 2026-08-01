# Design — bounded contracts, inspection-only shadow

## 1. Authority model

Authorization Domains is a blocklist around named critical resources, not a
fleet-wide allowlist. A block can remove authority for an exact object/action;
it never grants authority over ordinary work. An exact exception can restore
that one operation for one authenticated principal, worker, session, and
server-resolved domain.

The initial registry is exactly `read`. Unknown actions remain open on ordinary
objects and deny once the exact object is protected.

## 2. Contract boundary

The D1 documents use schema version `authorization-domains/v1`. JSON decoding
rejects unknown fields. A generation is immutable, digest-addressed, and
published conceptually by expected-generation compare-and-swap with last-good
retention. The I1a command validates and simulates that transition but does not
persist or publish a generation.

The first object is the logical identifier
`credential://pa/google-service-account-keyfile/v1`. It is deliberately not a
path. No physical locator appears in policy, decisions, reports, tests, or logs.

## 3. Context and identity

Protected simulation requires a complete `DomainContext` minted by the
configured server authority. Its principal, worker, session, resolved domain,
runtime identity, issue time, and expiry are evaluated. A caller's claimed
domain remains separate evidence and cannot replace any resolved field.

Ordinary simulation does not require a domain context. This preserves the
open-by-default posture and avoids turning the new context into a universal
gate.

## 4. Shadow command

```text
claude-gatekeeper auth-domains shadow \
  --policy generation.json \
  --request request.json \
  --coverage coverage-manifest.json \
  [--json]
```

The command is a read-only offline analyzer:

1. Strictly decode and compile inputs.
2. Validate registry, exact selectors, identities, generation, and timestamps.
3. Simulate `permit_unblocked`, `permit_exception`, or `deny_blocked`.
4. Inspect the coverage manifest and list contract-only, missing, unknown, or
   untraced critical seams.
5. Emit `mode: shadow`, `enforcement: false`, the simulated decision, claimed
   and resolved context evidence, and warnings.

Exit 0 means the inputs were valid and a report was produced, including a
simulated denial. Exit 1 means the candidate or coverage is not conformant.
Exit 2 means invocation, decoding, or I/O failed. No exit code or report is a
harness permission decision.

## 5. Honest coverage

The coverage manifest is data, not proof. Each critical seam has an owner,
trace action, negative fixture, state, and known gap. Only
`implemented_and_probed` could support a future protection claim; this change
accepts and reports `contract_only` and always keeps `enforcement: false`.
Unknown, missing, or untraced critical seams make the shadow report
non-conformant.

## 6. Lifecycle and isolation

Lifecycle receipts model `provision -> operate -> preserve -> archive`, bounded
queues/concurrency/timeouts, descendant cleanup, and cleared/reconstructed child
environments. These mechanics are not isolation. Only recorded cross-worker
probes may derive `dedicated_uid`, `rootless_container`, or
`dedicated_uid+rootless_container`; otherwise the claim is `none`. Shared UID,
process groups alone, privileged containers, host PID/user-namespace
violations, broad host mounts, engine-control sockets, host root, unmanifested
aliases/descriptors/endpoints, drift, or indeterminate mandatory probes
invalidate the relevant claim. Host root is explicitly outside the threat model
and every receipt must say so.

The model uses `ABSENT -> PROVISIONING -> READY -> OPERATING -> QUIESCING ->
PRESERVED -> ARCHIVING -> ARCHIVED`, with `QUARANTINED` for partial,
contradictory, escaped, or indeterminate states. Recovery re-observes reality
from the last durable receipt and never automatically returns quarantine to
operation. Archive completeness separately proves revoke, empty supervisor
scope, mount/endpoint/session absence, artifact custody, useful-artifact
readability, protected-material exclusion, and honest residuals.

I1a only validates the model and receipts. It does not create a user, container,
process, mount, credential binding, or archive.

## 7. Independence and hook non-interference

The independent replay oracle belongs outside the production evaluator and
canonicalizer dependency graph. This implementation emits replay-compatible
evidence but does not import or copy the independent checker into the runtime
package.

`runHook` does not import or call Authorization Domains. The shadow command is
reachable only through its explicit subcommand, reads explicit fixture paths,
and writes only its report stream. Cross-harness tests compare existing Claude,
Codex, and Grok outputs with the feature present.

## 8. Deferred work

I1b credential binding, durable audit storage, replay claims, final-PEP
materialization, lifecycle provisioning, PA activation, and production
enforcement remain separate gated work. New actions beyond `read` also require
design review.
