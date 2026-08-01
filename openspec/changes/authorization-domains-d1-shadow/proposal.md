# Proposal — Authorization Domains D1 contracts and I1a shadow

## Why

Gatekeeper rules can deny known tool forms, but they cannot establish that an
exact protected resource is inaccessible through every final backend path. The
approved Authorization Domains design adds a narrow vocabulary for describing
that future boundary without converting ordinary fleet work to default deny.

The first delivery must make the contracts executable and observable before it
receives any authority. It therefore needs a shadow surface that can compile a
synthetic block/exception generation, simulate a request, and disclose coverage
gaps without changing a hook verdict or touching credential material.

## What changes

1. Add the D1 schemas and examples for `ProtectedBlock`, `BlockException`, the
   read-only action registry, immutable generation/CAS, server-minted
   `DomainContext`, request/decision, final-PEP coverage, audit/revoke, and
   lifecycle/archive receipts.
2. Add `claude-gatekeeper auth-domains shadow`, an explicit offline command that
   evaluates JSON fixtures and prints an inspection report.
3. Report every coverage seam honestly. Contract-only or untraced critical
   seams prevent any enforcement claim.
4. Preserve claimed and server-resolved context separately in inputs and
   output; only the resolved context participates in protected simulation.
5. Keep the ordinary hook path byte-for-byte independent of the shadow package.

## Scope boundary

This change is D1 plus I1a only. It does not place or inspect credentials,
provision or re-provision workers, activate PA, enable a production final PEP,
enforce a shadow decision, deploy, install, restart, act off-host, or spend.
The logical PA object identifier is synthetic and has no filesystem binding.

## Success criteria

- Ordinary objects remain `permit_unblocked`, including actions outside the
  initial protected vocabulary.
- The exact synthetic object is blocked for `read` without an exact exception.
- An exact, live exception may simulate `permit_exception`; context, identity,
  session, generation, expiry, and scope mismatches simulate denial.
- Unknown actions at the protected object deny; the registry contains only
  `read`.
- Reports say `enforcement: false`, disclose every known seam and gap, and
  cannot be confused with a harness verdict.
- Cross-harness regression tests prove the existing hook behavior is unchanged.

## Inputs absorbed

- Authorization Domains r2 design paper and the 2026-08-01 design-GO record.
- gatekeeper-core D1 contract, action registry, fixtures, conformance tests, and
  coverage manifest at exact PR #5 gated head
  `124b0daba1af03f1b913a6610b75262499ea1af2`, landed on main as
  `2575fdba43a5e29ec2d0b538942bab07c0cee325`.
- gatekeeper-core neutral-replay/lifecycle alignment at exact PR #6 gated head
  `39ffaffad5dc6be6addb7f9ccbe6c650c2cfbcec`, landed on main as
  `cb557239a90a82c34686d6ca55046a7b2c9f3129`.
- gatekeeper-codex independent replay/lifecycle checker at
  `8e376c79d64bc720b280ab839058cc71ca774990`: no production
  evaluator/canonicalizer imports, claimed/resolved context separation, and
  unknown or untraced critical seams as coverage failures.
- gatekeeper-grok lifecycle/isolation chapter
  `authorization-domains-d1-lifecycle-isolation-contract-20260801.md`, SHA-256
  `4a5d12ff96b136db5bd7e78c9467a222c242be99c060d5a17fe267725bc9caff`:
  derived claims, receipt schemas, invalidators, and the 38-probe matrix.
