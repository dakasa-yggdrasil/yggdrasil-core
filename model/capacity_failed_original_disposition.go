package model

import "time"

const FailedOriginalDispositionSchema = "failed_original_guest_terminal_disposition_v1"

// This separate administrative failure ledger preserves the accepted create,
// its witness and the unknown original dispatch acknowledgment. It establishes
// current terminal native absence, never historical never-started or success.
type CapacityFailedOriginalDisposition struct {
	Schema                              string                                       `json:"schema"`
	ID                                  string                                       `json:"id"`
	GrantID                             string                                       `json:"grant_id"`
	PreregistrationID                   string                                       `json:"preregistration_id"`
	JobID                               string                                       `json:"job_id"`
	RunID                               string                                       `json:"run_id"`
	Issuer                              string                                       `json:"issuer"`
	OriginalGrantSHA256                 string                                       `json:"original_grant_sha256"`
	OriginalPreregistrationSHA256       string                                       `json:"original_preregistration_sha256"`
	OriginalWitnessSHA256               string                                       `json:"original_witness_sha256"`
	OriginalDispatchSHA256              string                                       `json:"original_dispatch_sha256"`
	OriginalRunSHA256                   string                                       `json:"original_run_sha256"`
	OriginalBindingSHA256               string                                       `json:"original_binding_sha256"`
	OriginalSettlementSHA256            string                                       `json:"original_settlement_sha256"`
	OriginalPolicySHA256                string                                       `json:"original_policy_sha256"`
	OriginalWorkflowSHA256              string                                       `json:"original_workflow_sha256"`
	OriginalGeneration                  int64                                        `json:"original_generation"`
	OriginalFencingToken                int64                                        `json:"original_fencing_token"`
	ClosedGeneration                    int64                                        `json:"closed_generation"`
	ClosedFencingToken                  int64                                        `json:"closed_fencing_token"`
	OriginalDeadline                    time.Time                                    `json:"original_deadline"`
	RecordedAt                          time.Time                                    `json:"recorded_at"`
	HistoricalCoreSourceCommit          string                                       `json:"historical_core_source_commit"`
	Observation                         CapacityOriginalCreateDispositionObservation `json:"observation"`
	ObservationSHA256                   string                                       `json:"observation_sha256"`
	OriginalAcceptedUnchanged           bool                                         `json:"original_accepted_unchanged"`
	OriginalWitnessPreserved            bool                                         `json:"original_witness_preserved"`
	OriginalUnknownACKPreserved         bool                                         `json:"original_unknown_ACK_preserved"`
	HistoricalWriterStartState          string                                       `json:"historical_writer_start_state"`
	ServingOrBusinessOrSavingsAuthority bool                                         `json:"serving_or_business_or_savings_authority"`
}
