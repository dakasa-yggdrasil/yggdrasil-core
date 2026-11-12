package model

// CapacityInstalledReadinessHandoff gives one new scheduler owner a finite,
// readiness-only epoch after the original three attempts actually failed.
// HandoffSHA256 authenticates the immutable archive; it never resets its cap.
type CapacityInstalledReadinessHandoff struct {
	Schema                string `json:"schema"`
	HandoffID             string `json:"handoff_id"`
	HandoffSHA256         string `json:"handoff_sha256"`
	OriginalDispositionID string `json:"original_disposition_id"`
	ExhaustedGeneration   int64  `json:"exhausted_generation"`
	ExhaustedFence        int64  `json:"exhausted_fence"`
	ClaimGeneration       int64  `json:"claim_generation"`
	ClaimFence            int64  `json:"claim_fence"`
	RunID                 string `json:"run_id"`
	ExecutorID            string `json:"executor_id"`
	CoreSource            string `json:"core_source"`
}
