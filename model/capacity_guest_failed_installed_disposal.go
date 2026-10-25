package model

// This marker is a reference to an immutable backend admission, never a caller
// assertion of useful capacity, quiescence or absence of business effects.
type CapacityFailedInstalledDisposal struct {
	ID                string `json:"id"`
	AdmissionSHA256   string `json:"admission_sha256"`
	PreregistrationID string `json:"preregistration_id"`
	Stage             string `json:"stage"`
	RunID             string `json:"run_id,omitempty"`
	Fence             int64  `json:"fence,omitempty"`
}
