package model

import "time"

// CapacityDispatchPreActionPlanDisposition retains a recorded UNKNOWN plan
// failure. Only a distinct scheduler dispatch may plan again; this receipt is
// never the old return's acknowledgment or provider execution authority.
type CapacityDispatchPreActionPlanDisposition struct {
	Schema                 string    `json:"schema"`
	ID                     string    `json:"id"`
	JobID                  string    `json:"job_id"`
	RunID                  string    `json:"run_id"`
	SuccessorJobID         string    `json:"successor_job_id"`
	SuccessorRunID         string    `json:"successor_run_id"`
	RootAnchorID           string    `json:"root_anchor_id"`
	PolicyID               string    `json:"policy_id"`
	PolicyChecksum         string    `json:"policy_checksum"`
	Generation             int64     `json:"generation"`
	FencingToken           int64     `json:"fencing_token"`
	OriginalDispatchSHA256 string    `json:"original_dispatch_sha256"`
	OriginalRunSHA256      string    `json:"original_run_sha256"`
	OriginalIntentSHA256   string    `json:"original_intent_sha256"`
	MembersSHA256          string    `json:"members_sha256"`
	EvidenceSHA256         string    `json:"evidence_sha256"`
	OriginalDeadline       time.Time `json:"original_deadline"`
	OriginalReturnedAt     time.Time `json:"original_returned_at"`
	RecordedAt             time.Time `json:"recorded_at"`
}
