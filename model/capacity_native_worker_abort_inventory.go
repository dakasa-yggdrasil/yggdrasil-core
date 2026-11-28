package model

import "time"

type CapacityNativeWorkerAbortInventoryRequest struct {
	BindingName         string `json:"binding_name"`
	ProviderID          string `json:"provider_id"`
	CreationProofSHA256 string `json:"creation_proof_sha256"`
	NodeName            string `json:"node_name"`
}

// Requested identity is only a selector. Core must join it to its own sealed
// Attempt and original bootstrap; this observation never grants mutation.
type CapacityNativeWorkerAbortInventoryObservation struct {
	Schema                  string                                    `json:"schema"`
	SourceCommit            string                                    `json:"source_commit"`
	BindingScopeSHA256      string                                    `json:"binding_scope_sha256"`
	Adapter                 CapacityMarketAdapterBinding              `json:"adapter"`
	BindingName             string                                    `json:"binding_name"`
	Requested               CapacityNativeWorkerAbortInventoryRequest `json:"requested"`
	ObservedAt              time.Time                                 `json:"observed_at"`
	Phase                   CapacityNativeWorkerPhaseReadObservation  `json:"phase"`
	BeforePhaseEvidence     string                                    `json:"before_phase_evidence_sha256"`
	Complete                bool                                      `json:"complete"`
	PodsComplete            bool                                      `json:"pods_complete"`
	PodsAllNamespaces       bool                                      `json:"pods_all_namespaces"`
	PodCollectionVersion    string                                    `json:"pod_collection_resource_version"`
	TargetActivePods        int                                       `json:"target_active_pods"`
	TargetPodEvidenceSHA256 string                                    `json:"target_pod_evidence_sha256"`
	EvidenceSHA256          string                                    `json:"evidence_sha256"`
	MutationAuthorized      bool                                      `json:"mutation_authorized"`
}
