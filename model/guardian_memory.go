package model

// GuardianMemory statuses describe the lifecycle and observed outcome of one
// Heimdall action attempt.
const (
	GuardianMemoryStatusPendingApproval  = "pending_approval"
	GuardianMemoryStatusRejected         = "rejected"
	GuardianMemoryStatusExecuting        = "executing"
	GuardianMemoryStatusExecuted         = "executed"
	GuardianMemoryStatusExecutionFailed  = "execution_failed"
	GuardianMemoryStatusObservedRecovered = "observed_recovered"
	GuardianMemoryStatusObservedUnchanged = "observed_unchanged"
	GuardianMemoryStatusObservedRegressed = "observed_regressed"
)

// GuardianMemoryExecutionSpec captures the execution details of one action
// attempt.
type GuardianMemoryExecutionSpec struct {
	AttemptedAt string `json:"attempted_at,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
	Error       string `json:"error,omitempty"`
}

// GuardianMemoryObservationSpec captures the later observed outcome after one
// action has been executed.
type GuardianMemoryObservationSpec struct {
	ObservedAt             string `json:"observed_at,omitempty"`
	LastObservedAt         string `json:"last_observed_at,omitempty"`
	Summary                string `json:"summary,omitempty"`
	ComponentHealth        string `json:"component_health,omitempty"`
	IncidentCount          int    `json:"incident_count,omitempty"`
	ObservationCount       int    `json:"observation_count,omitempty"`
	TimeToRecoverySeconds  int    `json:"time_to_recovery_seconds,omitempty"`
	StableWindowSeconds    int    `json:"stable_window_seconds,omitempty"`
}

// GuardianMemoryManifestSpec stores one operational memory entry emitted by
// Heimdall so later sweeps can reason about what was attempted and what
// actually happened afterward.
type GuardianMemoryManifestSpec struct {
	GuardianRef        ManifestSelector              `json:"guardian_ref"`
	Status             string                        `json:"status,omitempty"`
	Source             string                        `json:"source,omitempty"`
	ComponentKind      string                        `json:"component_kind,omitempty"`
	ComponentNamespace string                        `json:"component_namespace,omitempty"`
	ComponentName      string                        `json:"component_name,omitempty"`
	Action             map[string]any                `json:"action"`
	Incident           map[string]any                `json:"incident,omitempty"`
	Evidence           map[string]any                `json:"evidence,omitempty"`
	Execution          GuardianMemoryExecutionSpec   `json:"execution,omitempty"`
	Observation        GuardianMemoryObservationSpec `json:"observation,omitempty"`
	Metadata           map[string]any                `json:"metadata,omitempty"`
}
