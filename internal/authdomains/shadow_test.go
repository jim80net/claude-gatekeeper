package authdomains

import (
	"strings"
	"testing"
	"time"
)

func fixture(now time.Time) (PolicyGeneration, Request, CoverageManifest) {
	ctx := DomainContext{
		SchemaVersion: SchemaV1, ContextID: "ctx-1", DomainID: "domain-1",
		PrincipalID: "principal-1", WorkerID: "worker-1", SessionID: "session-1",
		RuntimeIdentity: RuntimeIdentity{Kind: "linux_user", Subject: "uid:1001"},
		IsolationClaim:  "unproved", IssuedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour), MintAuthority: "authorization-server",
		ClaimedDomainID: "caller-claim",
	}
	policy := PolicyGeneration{
		SchemaVersion: SchemaV1, Generation: 7, RegistryVersion: RegistryV1,
		CreatedAt: now.Add(-time.Hour),
		Blocks: []ProtectedBlock{{
			ID: "block-pa-read", ObjectSelector: ObjectSelector{Kind: "exact", ObjectID: PAObjectID},
			Actions: []string{"read"}, Reason: "synthetic proof", Owner: "test",
			AuditPolicy: "durable_before_effect", CreatedAt: now.Add(-time.Hour),
		}},
	}
	request := Request{
		SchemaVersion: SchemaV1, RequestID: "request-1", DomainContext: &ctx,
		Action: "read", Object: RequestObject{ObjectID: PAObjectID, CanonicalizationVersion: "1"},
		PolicyGeneration: 7, ClassifierVersion: "shadow-v1", RequestedAt: now,
	}
	coverage := CoverageManifest{SchemaVersion: SchemaV1, ObjectID: PAObjectID, EnforcementClaim: false, NeutralReplay: neutralReplayFixture(), Seams: []CoverageSeam{
		{ID: "policy-store-publish", Kind: "policy_store", Critical: true, Owner: "management", State: "contract_only", TraceAction: "policy_generation_published", NegativeFixture: "cas", KnownGap: "not implemented"},
		{ID: "policy-evaluator", Kind: "evaluator", Critical: true, Owner: "core", State: "contract_only", TraceAction: "decision_evaluated", NegativeFixture: "blocked", KnownGap: "shadow only"},
		{ID: "durable-audit-admission", Kind: "audit", Critical: true, Owner: "audit", State: "contract_only", TraceAction: "decision_durably_admitted", NegativeFixture: "audit", KnownGap: "not implemented"},
		{ID: "decision-replay-claim", Kind: "replay", Critical: true, Owner: "pep", State: "contract_only", TraceAction: "materialization_claimed", NegativeFixture: "replay", KnownGap: "not implemented"},
		{ID: "pa-credential-final-pep", Kind: "final_pep", Critical: true, Owner: "backend", State: "contract_only", TraceAction: "protected_effect_attempted", NegativeFixture: "bypass", KnownGap: "not implemented"},
		{ID: "worker-lifecycle-archive", Kind: "lifecycle", Critical: true, Owner: "lifecycle", State: "contract_only", TraceAction: "archive_receipt_sealed", NegativeFixture: "archive", KnownGap: "not implemented"},
	}}
	return policy, request, coverage
}

func neutralReplayFixture() NeutralReplay {
	return NeutralReplay{Schema: "gatekeeper.auth-domains.replay/v1", SchemaFile: "neutral-replay.schema.json", LifecycleContractSHA256: "4a5d12ff96b136db5bd7e78c9467a222c242be99c060d5a17fe267725bc9caff", LifecycleProbeRegistry: "lifecycle-probes.json", IndependentCheckerHead: "8e376c79d64bc720b280ab839058cc71ca774990", Coverage: []NeutralCoverageSeam{
		{Name: "ordinary-work", Critical: false, RequiredTraced: true, MapsTo: []string{"policy-evaluator"}},
		{Name: "protected-read-pep", Critical: true, RequiredTraced: true, MapsTo: []string{"policy-evaluator", "decision-replay-claim", "pa-credential-final-pep"}},
		{Name: "protected-read-audit", Critical: true, RequiredTraced: true, MapsTo: []string{"durable-audit-admission"}},
	}}
}

func TestEvaluateOpenOrdinaryWork(t *testing.T) {
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	policy, request, coverage := fixture(now)
	request.DomainContext = nil
	request.Action = "draft"
	request.Object.ObjectID = "work://ordinary/document"
	report := Shadow(policy, request, coverage, now)
	if report.Decision.Decision != PermitUnblocked || !report.Conformant || report.Enforcement {
		t.Fatalf("report = %#v", report)
	}
}

func TestEvaluateProtectedReadAndExactException(t *testing.T) {
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	policy, request, coverage := fixture(now)
	report := Shadow(policy, request, coverage, now)
	if report.Decision.Decision != DenyBlocked {
		t.Fatalf("decision = %q", report.Decision.Decision)
	}

	ctx := request.DomainContext
	policy.Exceptions = []BlockException{{
		ID: "exception-pa", BlockID: "block-pa-read", PrincipalID: ctx.PrincipalID,
		WorkerID: ctx.WorkerID, Actions: []string{"read"},
		ObjectSelector: ObjectSelector{Kind: "exact", ObjectID: PAObjectID},
		DomainID:       ctx.DomainID, SessionID: ctx.SessionID, IssuedBy: "operator",
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		Lease: Lease{NotAfter: now.Add(time.Hour), MaxMaterializations: 1},
	}}
	report = Shadow(policy, request, coverage, now)
	if report.Decision.Decision != PermitException || report.Decision.ExceptionID != "exception-pa" {
		t.Fatalf("decision = %#v", report.Decision)
	}
	if report.NeutralMapping.D1Decision != PermitException || report.NeutralMapping.Outcome != "allow" || report.NeutralMapping.Representable {
		t.Fatalf("neutral mapping = %#v", report.NeutralMapping)
	}
	if !contains(report.NeutralMapping.Omitted, "exception_id") {
		t.Fatalf("neutral omissions = %v", report.NeutralMapping.Omitted)
	}

	request.DomainContext.DomainID = "domain-other"
	report = Shadow(policy, request, coverage, now)
	if report.Decision.Decision != DenyBlocked {
		t.Fatalf("mismatched resolved domain decision = %q", report.Decision.Decision)
	}
}

func TestNeutralObjectIdentitiesCannotBeConfused(t *testing.T) {
	if PAObjectID == NeutralFixtureObjectID || !strings.HasPrefix(PAObjectID, "credential://") || !strings.HasPrefix(NeutralFixtureObjectID, "fixture://") {
		t.Fatalf("logical=%q fixture=%q", PAObjectID, NeutralFixtureObjectID)
	}
}

func TestNeutralMappingDisclosesFullContractOmissions(t *testing.T) {
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	policy, request, coverage := fixture(now)
	mapping := Shadow(policy, request, coverage, now).NeutralMapping
	for _, field := range []string{"request_id", "policy_generation", "classifier_version", "requested_at", "decided_at", "full_canonicalization_evidence"} {
		if !contains(mapping.Omitted, field) {
			t.Errorf("missing omission %q: %v", field, mapping.Omitted)
		}
	}
}

func TestUnknownProtectedActionAndStaleGenerationDeny(t *testing.T) {
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	policy, request, coverage := fixture(now)
	request.Action = "send"
	if got := Shadow(policy, request, coverage, now).Decision.Decision; got != DenyBlocked {
		t.Fatalf("unknown protected action = %q", got)
	}
	request.Action = "read"
	request.PolicyGeneration = 6
	if got := Shadow(policy, request, coverage, now).Decision.Decision; got != DenyBlocked {
		t.Fatalf("stale generation = %q", got)
	}
}

func TestCompileRejectsWiderAndUnknownActions(t *testing.T) {
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	policy, _, _ := fixture(now)
	policy.Blocks[0].Actions = []string{"send"}
	err := Compile(policy, now)
	if err == nil || !strings.Contains(err.Error(), "unknown action") {
		t.Fatalf("Compile error = %v", err)
	}
	policy, _, _ = fixture(now)
	policy.Exceptions = []BlockException{{ID: "wide", BlockID: "block-pa-read", Actions: []string{"read"}, ObjectSelector: ObjectSelector{Kind: "exact", ObjectID: "credential://other"}}}
	err = Compile(policy, now)
	if err == nil || !strings.Contains(err.Error(), "widens") {
		t.Fatalf("Compile error = %v", err)
	}
}

func TestCompileRejectsEqualSpecificityOverlap(t *testing.T) {
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	policy, _, _ := fixture(now)
	second := policy.Blocks[0]
	second.ID = "second"
	policy.Blocks = append(policy.Blocks, second)
	if err := Compile(policy, now); err == nil || !strings.Contains(err.Error(), "equal-specificity overlap") {
		t.Fatalf("Compile error = %v", err)
	}
}

func TestCoverageFailsUnknownMissingAndUntracedCriticalSeams(t *testing.T) {
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	policy, request, coverage := fixture(now)
	coverage.Seams = coverage.Seams[1:]
	coverage.Seams = append(coverage.Seams, CoverageSeam{ID: "side-door", Critical: true, State: "contract_only"})
	report := Shadow(policy, request, coverage, now)
	if report.Conformant || len(report.Errors) == 0 {
		t.Fatalf("report = %#v", report)
	}
}

func TestCoverageRequiresTracedOrdinaryWorkEvenThoughNonCritical(t *testing.T) {
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	policy, request, coverage := fixture(now)
	coverage.NeutralReplay.Coverage = coverage.NeutralReplay.Coverage[1:]
	report := Shadow(policy, request, coverage, now)
	if report.Conformant || !strings.Contains(strings.Join(report.Errors, " "), `neutral seam "ordinary-work" is missing`) {
		t.Fatalf("report = %#v", report)
	}
}

func TestCoverageRejectsSupersededIndependentCheckerPin(t *testing.T) {
	now := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	policy, request, coverage := fixture(now)
	coverage.NeutralReplay.IndependentCheckerHead = "1cc451f1ff89aaf8a495b7495a5634ad2609690e"
	report := Shadow(policy, request, coverage, now)
	if report.Conformant || !strings.Contains(strings.Join(report.Errors, " "), "neutral replay pins") {
		t.Fatalf("report = %#v", report)
	}
}

func TestDeriveIsolationNeverConfusesMechanicsWithBoundary(t *testing.T) {
	if got := DeriveIsolation(IsolationEvidence{ProcessTreeBounded: true, EnvironmentReconstructed: true}); got.Claim != "none" {
		t.Fatalf("mechanics claim = %q", got.Claim)
	}
	if got := DeriveIsolation(IsolationEvidence{DedicatedUIDProbePassed: true, HostUID: 1001, PeerUID: 1001}); got.Claim != "none" {
		t.Fatalf("shared uid claim = %q", got.Claim)
	}
	if got := DeriveIsolation(IsolationEvidence{ContainerProbePassed: true, Rootless: true, UserNamespace: true, Privileged: true}); got.Claim != "none" {
		t.Fatalf("privileged claim = %q", got.Claim)
	}
	if got := DeriveIsolation(IsolationEvidence{DedicatedUIDProbePassed: true, HostUID: 1001, PeerUID: 1002, ThreatModelExcludesHostRoot: true}); got.Claim != "dedicated_uid" {
		t.Fatalf("dedicated uid claim = %q, reasons=%v", got.Claim, got.Reasons)
	}
}

func TestArchiveReceiptRequiresEveryProof(t *testing.T) {
	receipt := ArchiveEvidence{SuccessorGenerationObserved: true, SessionInvalidated: true, ScopeEmpty: true, ProtectedMaterialAbsent: true, ArtifactsReadable: true, CustodyRecorded: true, ResidualsReported: true}
	if ArchiveComplete(receipt) {
		t.Fatal("archive complete without exception removal")
	}
	receipt.ExceptionRemoved = true
	receipt.MountsAndEndpointsAbsent = true
	if !ArchiveComplete(receipt) {
		fatal := receipt
		t.Fatalf("archive incomplete: %#v", fatal)
	}
}
