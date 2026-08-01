package authdomains

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

var requiredSeams = map[string]struct{}{
	"policy-store-publish": {}, "policy-evaluator": {},
	"durable-audit-admission": {}, "decision-replay-claim": {},
	"pa-credential-final-pep": {}, "worker-lifecycle-archive": {},
}

// Compile validates a D1 policy generation without publishing or persisting it.
func Compile(policy PolicyGeneration, now time.Time) error {
	var errs []string
	if policy.SchemaVersion != SchemaV1 {
		errs = append(errs, "unsupported schema_version")
	}
	if policy.RegistryVersion != RegistryV1 {
		errs = append(errs, "unsupported registry_version")
	}
	if policy.Generation == 0 {
		errs = append(errs, "generation must be positive")
	}
	ids := map[string]bool{}
	blocks := map[string]ProtectedBlock{}
	for _, block := range policy.Blocks {
		if block.ID == "" || ids[block.ID] {
			errs = append(errs, "duplicate or empty block id")
		}
		ids[block.ID] = true
		blocks[block.ID] = block
		if block.ObjectSelector.Kind != "exact" || block.ObjectSelector.ObjectID == "" {
			errs = append(errs, fmt.Sprintf("block %q selector must be exact", block.ID))
		}
		if len(block.Actions) == 0 {
			errs = append(errs, fmt.Sprintf("block %q actions are empty", block.ID))
		}
		for _, action := range block.Actions {
			if action != "read" {
				errs = append(errs, fmt.Sprintf("block %q has unknown action %q", block.ID, action))
			}
		}
		if block.Reason == "" || block.Owner == "" || block.AuditPolicy != "durable_before_effect" {
			errs = append(errs, fmt.Sprintf("block %q metadata is incomplete", block.ID))
		}
		if block.ExpiresAt != nil && !block.ExpiresAt.After(now) {
			errs = append(errs, fmt.Sprintf("block %q is expired", block.ID))
		}
	}
	overlaps := map[string]string{}
	for _, block := range policy.Blocks {
		for _, action := range block.Actions {
			key := block.ObjectSelector.ObjectID + "\x00" + action
			if prior, exists := overlaps[key]; exists {
				errs = append(errs, fmt.Sprintf("blocks %q and %q have equal-specificity overlap", prior, block.ID))
			} else {
				overlaps[key] = block.ID
			}
		}
	}
	for _, exception := range policy.Exceptions {
		if exception.ID == "" || ids[exception.ID] {
			errs = append(errs, "duplicate or empty exception id")
		}
		ids[exception.ID] = true
		block, ok := blocks[exception.BlockID]
		if !ok {
			errs = append(errs, fmt.Sprintf("exception %q is dangling", exception.ID))
			continue
		}
		if exception.ObjectSelector != block.ObjectSelector {
			errs = append(errs, fmt.Sprintf("exception %q widens object scope", exception.ID))
		}
		if !subset(exception.Actions, block.Actions) || len(exception.Actions) == 0 {
			errs = append(errs, fmt.Sprintf("exception %q widens action scope", exception.ID))
		}
		if exception.PrincipalID == "" || exception.WorkerID == "" || exception.SessionID == "" || exception.DomainID == "" || exception.IssuedBy == "" {
			errs = append(errs, fmt.Sprintf("exception %q identity binding is incomplete", exception.ID))
		}
		if !exception.ExpiresAt.After(exception.IssuedAt) || !exception.Lease.NotAfter.After(exception.IssuedAt) || exception.Lease.MaxMaterializations != 1 {
			errs = append(errs, fmt.Sprintf("exception %q lease is invalid", exception.ID))
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("candidate rejected: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Shadow compiles and simulates a request. It never enforces the result.
func Shadow(policy PolicyGeneration, request Request, coverage CoverageManifest, now time.Time) Report {
	report := Report{SchemaVersion: SchemaV1, Mode: "shadow", Enforcement: false, Coverage: append([]CoverageSeam{}, coverage.Seams...), Warnings: []string{}, Errors: []string{}}
	if request.DomainContext != nil {
		report.ClaimedDomain = request.DomainContext.ClaimedDomainID
		copy := *request.DomainContext
		copy.ClaimedDomainID = ""
		report.ResolvedContext = &copy
	}
	if err := Compile(policy, now); err != nil {
		report.Errors = append(report.Errors, err.Error())
	}
	report.Errors = append(report.Errors, validateCoverage(coverage)...)
	report.Decision = evaluate(policy, request, now)
	for _, seam := range coverage.Seams {
		if seam.State != "implemented_and_probed" {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s: %s", seam.ID, seam.KnownGap))
		}
	}
	sort.Strings(report.Errors)
	sort.Strings(report.Warnings)
	report.Conformant = len(report.Errors) == 0
	return report
}

func evaluate(policy PolicyGeneration, request Request, now time.Time) Decision {
	d := Decision{SchemaVersion: SchemaV1, RequestID: request.RequestID, PolicyGeneration: policy.Generation, BlockIDs: []string{}}
	objectProtected := false
	var matching []ProtectedBlock
	for _, block := range policy.Blocks {
		if block.ObjectSelector.ObjectID != request.Object.ObjectID {
			continue
		}
		objectProtected = true
		if contains(block.Actions, request.Action) {
			matching = append(matching, block)
			d.BlockIDs = append(d.BlockIDs, block.ID)
		}
	}
	if !objectProtected {
		d.Decision, d.ReasonCode = PermitUnblocked, "unprotected"
		return d
	}
	if request.Action != "read" || len(matching) == 0 {
		d.Decision, d.ReasonCode = DenyBlocked, "unknown_protected_action"
		return d
	}
	if request.PolicyGeneration != policy.Generation {
		d.Decision, d.ReasonCode = DenyBlocked, "stale_generation"
		return d
	}
	ctx := request.DomainContext
	if !validContext(ctx, now) {
		d.Decision, d.ReasonCode = DenyBlocked, "invalid_domain_context"
		return d
	}
	d.ResolvedContextID = ctx.ContextID
	for _, exception := range policy.Exceptions {
		if !contains(d.BlockIDs, exception.BlockID) || !contains(exception.Actions, request.Action) {
			continue
		}
		if exception.ObjectSelector.ObjectID == request.Object.ObjectID && exception.DomainID == ctx.DomainID && exception.PrincipalID == ctx.PrincipalID && exception.WorkerID == ctx.WorkerID && exception.SessionID == ctx.SessionID && exception.ExpiresAt.After(now) && exception.Lease.NotAfter.After(now) {
			d.Decision, d.ReasonCode, d.ExceptionID = PermitException, "exact_exception", exception.ID
			return d
		}
	}
	d.Decision, d.ReasonCode = DenyBlocked, "protected_block"
	return d
}

func validContext(ctx *DomainContext, now time.Time) bool {
	if ctx == nil || ctx.SchemaVersion != SchemaV1 || ctx.ContextID == "" || ctx.DomainID == "" || ctx.PrincipalID == "" || ctx.WorkerID == "" || ctx.SessionID == "" || ctx.MintAuthority != "authorization-server" {
		return false
	}
	if ctx.RuntimeIdentity.Kind != "linux_user" && ctx.RuntimeIdentity.Kind != "container" {
		return false
	}
	return !ctx.IssuedAt.After(now) && ctx.ExpiresAt.After(now)
}

func validateCoverage(manifest CoverageManifest) []string {
	var errs []string
	if manifest.SchemaVersion != SchemaV1 {
		errs = append(errs, "coverage: unsupported schema_version")
	}
	if manifest.ObjectID != PAObjectID {
		errs = append(errs, "coverage: unexpected object_id")
	}
	if manifest.EnforcementClaim {
		errs = append(errs, "coverage: D1/I1a cannot claim enforcement")
	}
	seen := map[string]bool{}
	for _, seam := range manifest.Seams {
		if seen[seam.ID] {
			errs = append(errs, fmt.Sprintf("coverage: duplicate seam %q", seam.ID))
		}
		seen[seam.ID] = true
		if _, ok := requiredSeams[seam.ID]; !ok && seam.Critical {
			errs = append(errs, fmt.Sprintf("coverage: unknown critical seam %q", seam.ID))
		}
		if seam.Critical && (seam.TraceAction == "" || seam.NegativeFixture == "" || seam.Owner == "") {
			errs = append(errs, fmt.Sprintf("coverage: critical seam %q is untraced", seam.ID))
		}
	}
	for seam := range requiredSeams {
		if !seen[seam] {
			errs = append(errs, fmt.Sprintf("coverage: critical seam %q is missing", seam))
		}
	}
	neutral := manifest.NeutralReplay
	if neutral.Schema != "gatekeeper.auth-domains.replay/v1" || neutral.SchemaFile == "" || neutral.LifecycleContractSHA256 != "4a5d12ff96b136db5bd7e78c9467a222c242be99c060d5a17fe267725bc9caff" || neutral.LifecycleProbeRegistry == "" || neutral.IndependentCheckerHead == "" {
		errs = append(errs, "coverage: neutral replay pins are incomplete or invalid")
	}
	wantNeutral := map[string]bool{"ordinary-work": false, "protected-read-pep": true, "protected-read-audit": true}
	seenNeutral := map[string]bool{}
	for _, seam := range neutral.Coverage {
		critical, ok := wantNeutral[seam.Name]
		if !ok || critical != seam.Critical || !seam.RequiredTraced || len(seam.MapsTo) == 0 {
			errs = append(errs, fmt.Sprintf("coverage: invalid neutral seam %q", seam.Name))
		}
		if seenNeutral[seam.Name] {
			errs = append(errs, fmt.Sprintf("coverage: duplicate neutral seam %q", seam.Name))
		}
		seenNeutral[seam.Name] = true
		for _, mapped := range seam.MapsTo {
			if !seen[mapped] {
				errs = append(errs, fmt.Sprintf("coverage: neutral seam %q maps to unknown seam %q", seam.Name, mapped))
			}
		}
	}
	for name := range wantNeutral {
		if !seenNeutral[name] {
			errs = append(errs, fmt.Sprintf("coverage: neutral seam %q is missing", name))
		}
	}
	return errs
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func subset(values, allowed []string) bool {
	for _, value := range values {
		if !contains(allowed, value) {
			return false
		}
	}
	return true
}
