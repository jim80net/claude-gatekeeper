package authdomains

type IsolationEvidence struct {
	ProcessTreeBounded          bool `json:"process_tree_bounded"`
	EnvironmentReconstructed    bool `json:"environment_reconstructed"`
	DedicatedUIDProbePassed     bool `json:"dedicated_uid_probe_passed"`
	ContainerProbePassed        bool `json:"container_probe_passed"`
	HostUID                     int  `json:"host_uid"`
	PeerUID                     int  `json:"peer_uid"`
	Rootless                    bool `json:"rootless"`
	UserNamespace               bool `json:"user_namespace"`
	Privileged                  bool `json:"privileged"`
	BroadMount                  bool `json:"broad_mount"`
	EngineControl               bool `json:"engine_control"`
	RuntimeDrift                bool `json:"runtime_drift"`
	IndeterminateProbe          bool `json:"indeterminate_probe"`
	ThreatModelExcludesHostRoot bool `json:"threat_model_excludes_host_root"`
}

type IsolationResult struct {
	Claim   string   `json:"claim"`
	Reasons []string `json:"reasons"`
}

func DeriveIsolation(e IsolationEvidence) IsolationResult {
	r := IsolationResult{Claim: "none", Reasons: []string{}}
	if e.IndeterminateProbe {
		r.Reasons = append(r.Reasons, "indeterminate_probe")
	}
	if e.RuntimeDrift {
		r.Reasons = append(r.Reasons, "runtime_drift")
	}
	if e.HostUID == 0 {
		r.Reasons = append(r.Reasons, "host_root_identity")
	}
	if e.DedicatedUIDProbePassed && e.HostUID == e.PeerUID {
		r.Reasons = append(r.Reasons, "same_uid")
	}
	if e.ContainerProbePassed && (!e.Rootless || !e.UserNamespace) {
		r.Reasons = append(r.Reasons, "not_rootless")
	}
	if e.Privileged {
		r.Reasons = append(r.Reasons, "container_privilege")
	}
	if e.BroadMount {
		r.Reasons = append(r.Reasons, "broad_mount")
	}
	if e.EngineControl {
		r.Reasons = append(r.Reasons, "engine_control")
	}
	if !e.ThreatModelExcludesHostRoot {
		r.Reasons = append(r.Reasons, "threat_model_must_exclude_host_root")
	}
	if len(r.Reasons) > 0 {
		return r
	}
	uid := e.DedicatedUIDProbePassed && e.HostUID > 0 && e.HostUID != e.PeerUID
	container := e.ContainerProbePassed && e.Rootless && e.UserNamespace
	switch {
	case uid && container:
		r.Claim = "dedicated_uid+rootless_container"
	case uid:
		r.Claim = "dedicated_uid"
	case container:
		r.Claim = "rootless_container"
	}
	return r
}

type ArchiveEvidence struct {
	SuccessorGenerationObserved bool `json:"successor_generation_observed"`
	ExceptionRemoved            bool `json:"exception_removed"`
	SessionInvalidated          bool `json:"session_invalidated"`
	ScopeEmpty                  bool `json:"scope_empty"`
	MountsAndEndpointsAbsent    bool `json:"mounts_and_endpoints_absent"`
	ProtectedMaterialAbsent     bool `json:"protected_material_absent"`
	ArtifactsReadable           bool `json:"artifacts_readable"`
	CustodyRecorded             bool `json:"custody_recorded"`
	ResidualsReported           bool `json:"residuals_reported"`
}

func ArchiveComplete(e ArchiveEvidence) bool {
	return e.SuccessorGenerationObserved && e.ExceptionRemoved && e.SessionInvalidated && e.ScopeEmpty && e.MountsAndEndpointsAbsent && e.ProtectedMaterialAbsent && e.ArtifactsReadable && e.CustodyRecorded && e.ResidualsReported
}
