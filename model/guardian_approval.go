package model

// GuardianApproval statuses describe whether a Heimdall action still needs a
// human decision or already passed through one.
const (
	GuardianApprovalStatusPending  = "pending"
	GuardianApprovalStatusApproved = "approved"
	GuardianApprovalStatusRejected = "rejected"
	GuardianApprovalStatusExecuted = "executed"
)

// GuardianApprovalManifestSpec stores one pending or completed approval request
// emitted by Heimdall when autonomy mode requires a human decision.
type GuardianApprovalManifestSpec struct {
	GuardianRef ManifestSelector `json:"guardian_ref"`
	Status      string           `json:"status,omitempty"`
	Source      string           `json:"source,omitempty"`
	Summary     string           `json:"summary,omitempty"`
	Action      map[string]any   `json:"action"`
	Incident    map[string]any   `json:"incident,omitempty"`
	Metadata    map[string]any   `json:"metadata,omitempty"`
}
