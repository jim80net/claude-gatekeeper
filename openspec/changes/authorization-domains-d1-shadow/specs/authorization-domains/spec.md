# Authorization Domains requirements

## ADDED Requirements

### Requirement: Ordinary work remains open

The shadow evaluator SHALL return `permit_unblocked` when no protected block
matches the canonical object and action. It SHALL NOT require DomainContext for
ordinary unblocked work.

#### Scenario: Unknown ordinary action

- **WHEN** a request names an action outside registry version 1 on an object
  with no matching protected block
- **THEN** the simulated decision is `permit_unblocked`

### Requirement: Named exact blocks deny narrowly

A `ProtectedBlock` SHALL use an exact object selector and a non-empty subset of
the registry. A matching block SHALL simulate `deny_blocked` unless one exact,
live exception covers every matching block.

#### Scenario: Protected read without exception

- **WHEN** `read` targets the exact synthetic PA credential object and no
  matching exception exists
- **THEN** the simulated decision is `deny_blocked`

#### Scenario: Unknown action at protected object

- **WHEN** a request reaches the exact protected object with an action absent
  from registry version 1
- **THEN** the simulated decision is `deny_blocked`

### Requirement: Exceptions bind authenticated context

An exception SHALL bind the server-resolved domain, authenticated principal,
worker and session, exact object and action, expiry, and materialization lease.
Claimed context SHALL remain evidence only.

#### Scenario: Claimed domain disagrees with resolved domain

- **WHEN** the caller claims the exception domain but the server-resolved
  DomainContext names another domain
- **THEN** the simulated decision is `deny_blocked`

### Requirement: Candidate generations compile safely

Candidate compilation SHALL reject unknown fields or actions, duplicate or
dangling IDs, wider exceptions, ambiguity, invalid time bounds, stale expected
generation, and idempotency-key reuse with another digest. Rejection SHALL
retain the conceptual last-good generation.

#### Scenario: Compare-and-swap mismatch

- **WHEN** expected generation differs from the last-good generation
- **THEN** compilation is non-conformant and reports last-good unchanged

### Requirement: Shadow reports cannot enforce

Every report SHALL identify `mode` as `shadow` and `enforcement` as false. The
shadow evaluator SHALL NOT be invoked by any harness hook path or translate its
decision into a harness verdict.

#### Scenario: Simulated denial

- **WHEN** the shadow evaluator simulates `deny_blocked`
- **THEN** it reports the result without denying or authoritatively allowing a
  harness tool call

### Requirement: Coverage claims are honest

The shadow report SHALL enumerate every supplied seam with state and known gap.
Unknown, missing, or untraced critical seams SHALL make conformance false. A
manifest containing any seam not `implemented_and_probed` SHALL NOT support an
enforcement claim.

#### Scenario: Contract-only final PEP

- **WHEN** the final PEP seam is `contract_only`
- **THEN** the report names the gap and keeps `enforcement` false

### Requirement: Lifecycle mechanics do not overclaim isolation

Lifecycle validation SHALL distinguish bounded process/environment mechanics
from isolation. It SHALL reject a proved-isolation claim for shared UID,
process-group-only, privileged-container, broad-mount, Docker-socket, or
host-root conditions.

#### Scenario: Process group without OS boundary

- **WHEN** a lifecycle receipt records descendant cleanup but no dedicated UID
  or constrained container probe
- **THEN** isolation remains `unproved`

#### Scenario: Indeterminate mandatory probe

- **WHEN** a mandatory UID, namespace, mount, endpoint, or descendant probe is
  skipped, times out, or cannot produce a determinate result
- **THEN** the derived isolation claim is `none` and the receipt fails

### Requirement: Archive receipts prove revoke and custody separately

An archive receipt SHALL NOT be complete until the successor generation is
observed, the exception and session are invalidated, the supervised scope is
empty, protected mounts/endpoints are absent, useful artifacts remain readable,
protected material is excluded, and residual exposure is reported.

#### Scenario: Useful artifacts but missing revoke

- **WHEN** the preserved artifacts are readable but the exception is not
  removed
- **THEN** archive completeness is false

### Requirement: Independent replay remains independent

Replay evidence SHALL preserve claimed and resolved DomainContext separately.
The independent checker SHALL import no production evaluator or canonicalizer,
and SHALL reject missing or unknown critical trace actions.

#### Scenario: Untraced critical seam

- **WHEN** a critical coverage seam has no recognized replay action
- **THEN** independent conformance fails

### Requirement: Neutral replay losses are explicit

The shadow report SHALL map all three D1 decisions. It SHALL mark
`permit_exception` as unavailable in pinned neutral v1 rather than collapsing
it into `permit_unblocked`, and SHALL list omitted request, generation,
classifier, time, canonicalization, exception, constraint, and lease evidence.

#### Scenario: Exact exception permit

- **WHEN** D1 simulates `permit_exception`
- **THEN** the neutral mapping reports `allow` / `exact_exception` and
  `representable_in_pinned_v1: false`

### Requirement: Logical and fixture objects remain distinct

The D1 logical PA object and the independent checker's inert fixture URI SHALL
use distinct schemes and SHALL NOT alias each other or a physical path.

#### Scenario: Independent replay fixture

- **WHEN** replay evidence uses the inert `fixture://` object
- **THEN** it cannot select the D1 `credential://` logical object

### Requirement: Ordinary replay is required even when non-critical

Neutral coverage SHALL require a traced `ordinary-work` seam even though it is
classified non-critical, so the open-by-default invariant has positive replay
evidence.

#### Scenario: Missing ordinary trace

- **WHEN** protected critical seams are traced but `ordinary-work` is absent
- **THEN** shadow coverage is non-conformant
