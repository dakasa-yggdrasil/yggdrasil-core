package model

// CapacityFailedExpansionTerminalReconcile binds a new Source-owned readonly
// reconciliation to an immutable terminal cleanup. It never grants a provider
// operation or reclassifies the original failed create as successful.
type CapacityFailedExpansionTerminalReconcile struct {
	Schema              string `json:"schema"`
	CleanupID           string `json:"cleanup_id"`
	TerminalEventSHA256 string `json:"terminal_event_sha256"`
	TerminalGeneration  int64  `json:"terminal_generation"`
	TerminalFence       int64  `json:"terminal_fence"`
	ClaimGeneration     int64  `json:"claim_generation"`
	ClaimFence          int64  `json:"claim_fence"`
	PreviousRunID       string `json:"previous_run_id,omitempty"`
	PreviousRunSHA256   string `json:"previous_run_sha256,omitempty"`
	PreviousFence       int64  `json:"previous_fence"`
	RunID               string `json:"run_id"`
	ExecutorID          string `json:"executor_id"`
}
