// Package authdomains implements the inspection-only Authorization Domains I1a
// shadow. It has no hook integration and no runtime enforcement authority.
package authdomains

import "time"

const (
	SchemaV1   = "authorization-domains/v1"
	RegistryV1 = "1"
	PAObjectID = "credential://pa/google-service-account-keyfile/v1"
)

type DecisionKind string

const (
	PermitUnblocked DecisionKind = "permit_unblocked"
	PermitException DecisionKind = "permit_exception"
	DenyBlocked     DecisionKind = "deny_blocked"
)

type ObjectSelector struct {
	Kind     string `json:"kind"`
	ObjectID string `json:"object_id"`
}

type ProtectedBlock struct {
	ID             string         `json:"id"`
	ObjectSelector ObjectSelector `json:"object_selector"`
	Actions        []string       `json:"actions"`
	Reason         string         `json:"reason"`
	Owner          string         `json:"owner"`
	AuditPolicy    string         `json:"audit_policy"`
	CreatedAt      time.Time      `json:"created_at"`
	ExpiresAt      *time.Time     `json:"expires_at,omitempty"`
}

type Lease struct {
	NotAfter            time.Time `json:"not_after"`
	MaxMaterializations int       `json:"max_materializations"`
}

type BlockException struct {
	ID             string         `json:"id"`
	BlockID        string         `json:"block_id"`
	PrincipalID    string         `json:"principal_id"`
	WorkerID       string         `json:"worker_id"`
	Actions        []string       `json:"actions"`
	ObjectSelector ObjectSelector `json:"object_selector"`
	DomainID       string         `json:"domain_id"`
	SessionID      string         `json:"session_id"`
	IssuedBy       string         `json:"issued_by"`
	IssuedAt       time.Time      `json:"issued_at"`
	ExpiresAt      time.Time      `json:"expires_at"`
	Lease          Lease          `json:"lease"`
}

type PolicyGeneration struct {
	SchemaVersion   string           `json:"schema_version"`
	Generation      uint64           `json:"generation"`
	ParentDigest    string           `json:"parent_digest,omitempty"`
	Digest          string           `json:"digest,omitempty"`
	RegistryVersion string           `json:"registry_version"`
	Blocks          []ProtectedBlock `json:"blocks"`
	Exceptions      []BlockException `json:"exceptions"`
	CreatedAt       time.Time        `json:"created_at"`
}

type RuntimeIdentity struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
}

type DomainContext struct {
	SchemaVersion   string          `json:"schema_version"`
	ContextID       string          `json:"context_id"`
	DomainID        string          `json:"domain_id"`
	PrincipalID     string          `json:"principal_id"`
	WorkerID        string          `json:"worker_id"`
	SessionID       string          `json:"session_id"`
	RuntimeIdentity RuntimeIdentity `json:"runtime_identity"`
	IsolationClaim  string          `json:"isolation_claim"`
	IssuedAt        time.Time       `json:"issued_at"`
	ExpiresAt       time.Time       `json:"expires_at"`
	MintAuthority   string          `json:"mint_authority"`
	ClaimedDomainID string          `json:"claimed_domain_id,omitempty"`
}

type RequestObject struct {
	ObjectID                string `json:"object_id"`
	CanonicalizationVersion string `json:"canonicalization_version"`
}

type Request struct {
	SchemaVersion     string         `json:"schema_version"`
	RequestID         string         `json:"request_id"`
	DomainContext     *DomainContext `json:"domain_context,omitempty"`
	Action            string         `json:"action"`
	Object            RequestObject  `json:"object"`
	PolicyGeneration  uint64         `json:"policy_generation"`
	ClassifierVersion string         `json:"classifier_version"`
	RequestedAt       time.Time      `json:"requested_at"`
}

type Decision struct {
	SchemaVersion     string       `json:"schema_version"`
	RequestID         string       `json:"request_id"`
	Decision          DecisionKind `json:"decision"`
	ReasonCode        string       `json:"reason_code"`
	PolicyGeneration  uint64       `json:"policy_generation"`
	BlockIDs          []string     `json:"block_ids"`
	ExceptionID       string       `json:"exception_id,omitempty"`
	ResolvedContextID string       `json:"resolved_context_id,omitempty"`
}

type CoverageManifest struct {
	SchemaVersion    string         `json:"schema_version"`
	ObjectID         string         `json:"object_id"`
	EnforcementClaim bool           `json:"enforcement_claim"`
	NeutralReplay    NeutralReplay  `json:"neutral_replay"`
	Seams            []CoverageSeam `json:"seams"`
}

type NeutralReplay struct {
	Schema                  string                `json:"schema"`
	SchemaFile              string                `json:"schema_file"`
	LifecycleContractSHA256 string                `json:"lifecycle_contract_sha256"`
	LifecycleProbeRegistry  string                `json:"lifecycle_probe_registry"`
	IndependentCheckerHead  string                `json:"independent_checker_head"`
	Coverage                []NeutralCoverageSeam `json:"coverage"`
}

type NeutralCoverageSeam struct {
	Name           string   `json:"name"`
	Critical       bool     `json:"critical"`
	RequiredTraced bool     `json:"required_traced"`
	MapsTo         []string `json:"maps_to"`
}

type CoverageSeam struct {
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	Critical        bool   `json:"critical"`
	Owner           string `json:"owner"`
	State           string `json:"state"`
	TraceAction     string `json:"trace_action"`
	NegativeFixture string `json:"negative_fixture"`
	KnownGap        string `json:"known_gap"`
}

type Report struct {
	SchemaVersion   string         `json:"schema_version"`
	Mode            string         `json:"mode"`
	Enforcement     bool           `json:"enforcement"`
	Conformant      bool           `json:"conformant"`
	Decision        Decision       `json:"simulated_decision"`
	ClaimedDomain   string         `json:"claimed_domain,omitempty"`
	ResolvedContext *DomainContext `json:"resolved_context,omitempty"`
	Coverage        []CoverageSeam `json:"coverage"`
	Warnings        []string       `json:"warnings"`
	Errors          []string       `json:"errors"`
}
