package model

// Diagnostic adapters and images are pinned declarations, never proof facts.
// Nil preserves the existing lifecycle wire and keeps independent proof absent.
// Private file/TLS/key/startup-secret references remain process configuration.
type CapacityNativeWorkerReadinessBinding struct {
	Mode                   string                                   `json:"mode"`
	Name                   string                                   `json:"name"`
	Namespace              string                                   `json:"namespace"`
	NamespaceUID           string                                   `json:"namespace_uid"`
	ResourceWriter         CapacityNativeWorkerProbeResourceBinding `json:"resource_writer"`
	ResourceReader         CapacityNativeWorkerProbeResourceBinding `json:"resource_reader"`
	ProbeImage             string                                   `json:"probe_image"`
	ProbeSourceCommit      string                                   `json:"probe_source_commit"`
	CoreWorkerImage        string                                   `json:"core_worker_image"`
	CoreWorkerSourceCommit string                                   `json:"core_worker_source_commit"`
	StartupTemplateSHA256  string                                   `json:"startup_template_sha256"`
}

// Writer uses one separate protected principal for its fixed ensure/destroy
// pair. Reader uses only its fixed observe role and has no callback material.
type CapacityNativeWorkerProbeResourceBinding struct {
	Adapter      CapacityMarketAdapterBinding `json:"adapter"`
	Name         string                       `json:"name"`
	SourceCommit string                       `json:"source_commit"`
	ScopeSHA256  string                       `json:"scope_sha256"`
	PrincipalID  string                       `json:"principal_id,omitempty"`
}
