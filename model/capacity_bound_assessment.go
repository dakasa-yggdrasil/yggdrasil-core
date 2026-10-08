package model

import "time"

// Adapter revision identity is operator owned. Numeric versions and aliases
// never replace the immutable manifest UUID plus checksum on either side.
type CapacityObservationAdapterBinding struct {
	IntegrationInstanceID string `json:"integration_instance_id"`
	InstanceChecksum      string `json:"instance_checksum"`
	IntegrationTypeID     string `json:"integration_type_id"`
	TypeChecksum          string `json:"type_checksum"`
}

type CapacityHPAMinimumBinding struct {
	Mode            string                            `json:"mode"`
	Unit            string                            `json:"unit"`
	Adapter         CapacityObservationAdapterBinding `json:"adapter"`
	Namespace       string                            `json:"namespace"`
	HPAName         string                            `json:"hpa_name"`
	HPAUID          string                            `json:"hpa_uid"`
	WorkloadName    string                            `json:"workload_name"`
	WorkloadUID     string                            `json:"workload_uid"`
	Owner           string                            `json:"owner"`
	Profile         string                            `json:"profile"`
	ProtectedFloor  int                               `json:"protected_floor"`
	MaximumReplicas int                               `json:"maximum_replicas"`
}

type CapacityMetricSignalBinding struct {
	Name          string                            `json:"name"`
	Adapter       CapacityObservationAdapterBinding `json:"adapter"`
	BindingName   string                            `json:"binding_name"`
	BindingSHA256 string                            `json:"binding_sha256"`
}

type CapacityBoundAssessmentBinding struct {
	Snapshot CapacityHPAMinimumBinding     `json:"snapshot"`
	Signals  []CapacityMetricSignalBinding `json:"signals"`
}

// Fields match the reviewed native HPA diagnostic protocol. HPA status and
// conditions are not transformed into business-ready or warm-capacity facts.
type CapacityHPAEnvelopeCondition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason,omitempty"`
	Message            string `json:"message,omitempty"`
	LastTransitionTime string `json:"last_transition_time,omitempty"`
}

type CapacityHPAEnvelopeObservation struct {
	Namespace               string                         `json:"namespace"`
	HPAName                 string                         `json:"hpa_name"`
	HPAUID                  string                         `json:"hpa_uid"`
	ResourceVersion         string                         `json:"resource_version"`
	APIGeneration           int64                          `json:"api_generation"`
	WorkloadName            string                         `json:"workload_name"`
	WorkloadUID             string                         `json:"workload_uid"`
	WorkloadResourceVersion string                         `json:"workload_resource_version"`
	Owner                   string                         `json:"owner,omitempty"`
	EnvelopeGeneration      int64                          `json:"envelope_generation"`
	IdempotencyKey          string                         `json:"idempotency_key,omitempty"`
	MinReplicas             int                            `json:"min_replicas"`
	MaxReplicas             int                            `json:"max_replicas"`
	ProtectedFloor          int                            `json:"protected_floor"`
	TrackedProtectedFloor   int                            `json:"tracked_protected_floor"`
	MaximumReplicas         int                            `json:"maximum_replicas"`
	CurrentReplicas         int                            `json:"current_replicas"`
	DesiredReplicas         int                            `json:"desired_replicas"`
	ObservedGeneration      *int64                         `json:"observed_generation,omitempty"`
	MatchedOwner            bool                           `json:"matched_owner"`
	BoundsWithinScope       bool                           `json:"bounds_within_scope"`
	TrackingMatchesScope    bool                           `json:"tracking_matches_scope"`
	BoundsMatchTracking     bool                           `json:"bounds_match_tracking"`
	ControllerOwned         bool                           `json:"controller_owned"`
	Conditions              []CapacityHPAEnvelopeCondition `json:"conditions"`
	ObservedAt              string                         `json:"observed_at"`
	DiagnosticOnly          bool                           `json:"diagnostic_only"`
	AtomicSnapshot          bool                           `json:"atomic_snapshot"`
	WarmCapacityVerified    bool                           `json:"warm_capacity_verified"`
	WorkloadDrainVerified   bool                           `json:"workload_drain_verified"`
}

type CapacityHPAEnvelopeResponse struct {
	Operation   string                         `json:"operation"`
	Status      string                         `json:"status"`
	Observation CapacityHPAEnvelopeObservation `json:"observation"`
	Metadata    map[string]any                 `json:"metadata"`
}

type CapacityMetricRangeObservation struct {
	CapacityEvidence
	Operation     string    `json:"operation"`
	Binding       string    `json:"binding"`
	BindingSHA256 string    `json:"binding_sha256"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
	OK            bool      `json:"ok"`
	Reason        string    `json:"reason"`
}

type CapacityBoundAssessmentReceipt struct {
	Mode                string             `json:"mode"`
	Unit                string             `json:"unit"`
	Assessment          CapacityAssessment `json:"assessment"`
	UsefulCapacityKnown bool               `json:"useful_capacity_known"`
	AtomicSnapshot      bool               `json:"atomic_snapshot"`
	ExecutionEnabled    bool               `json:"execution_enabled"`
	Intent              *CapacityIntent    `json:"intent,omitempty"`
}
