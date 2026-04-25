package model

// EphemeralEnvironmentManifestSpec declares a time-bounded environment that
// Yggdrasil materialises on creation and reaps after TTL expiry.
//
// The shape is purpose-built (not a wrapper around workflow): a Yggdrasil
// adopter declares the environment they want, and core orchestrates the
// create/destroy workflows around it.
type EphemeralEnvironmentManifestSpec struct {
	// CreateWorkflow runs at apply time to spin the environment up.
	CreateWorkflow EphemeralEnvironmentWorkflowSpec `json:"create_workflow"`

	// DestroyWorkflow runs at TTL expiry (or on manual destroy) to tear it down.
	// If absent, AutoDestroy must be false; the operator destroys manually.
	DestroyWorkflow *EphemeralEnvironmentWorkflowSpec `json:"destroy_workflow,omitempty"`

	// TTLSeconds is the lifetime budget. After ExpiresAt, the reaper dispatches
	// DestroyWorkflow when AutoDestroy is true.
	TTLSeconds int64 `json:"ttl_seconds"`

	// AutoDestroy gates the TTL reaper. When false, expiry only marks the
	// environment as `expired` — operator must dispatch destroy explicitly.
	AutoDestroy bool `json:"auto_destroy"`

	// CostProjection is informational; rendered by the API for visibility.
	// Currency is at adopter discretion (default USD if omitted).
	CostProjection *EphemeralEnvironmentCostProjection `json:"cost_projection,omitempty"`

	// Metadata is a free-form bag for adopter-side annotations (PR number,
	// branch name, owning team) that the create_workflow can template against.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// EphemeralEnvironmentWorkflowSpec references a workflow manifest plus inputs.
type EphemeralEnvironmentWorkflowSpec struct {
	WorkflowRef ManifestRef    `json:"workflow_ref"`
	Inputs      map[string]any `json:"inputs,omitempty"`
}

// EphemeralEnvironmentCostProjection is an estimate, not a billing record.
type EphemeralEnvironmentCostProjection struct {
	CPUHours        float64 `json:"cpu_hours,omitempty"`
	MemoryGBHours   float64 `json:"memory_gb_hours,omitempty"`
	StorageGBHours  float64 `json:"storage_gb_hours,omitempty"`
	EstimatedCost   float64 `json:"estimated_cost,omitempty"`
	Currency        string  `json:"currency,omitempty"`
}
