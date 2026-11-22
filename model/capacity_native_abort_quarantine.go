package model

import "time"

// A separate human administrative receipt. It is never a native return, a lane
// witness, an authority permit, or a change to the original uncertain command.
type CapacityNativeAbortQuarantineBinding struct {
	Schema                     string                     `json:"schema"`
	Confirmation               string                     `json:"confirmation"`
	Native                     CapacityNativeAbortBinding `json:"native"`
	ParentCommandID            string                     `json:"parent_command_id"`
	CommandID                  string                     `json:"command_id"`
	ExpectedIntentFencingToken int64                      `json:"expected_intent_fencing_token"`
}

type CapacityNativeAbortQuarantine struct {
	Schema              string                                         `json:"schema"`
	Binding             CapacityNativeAbortQuarantineBinding           `json:"binding"`
	WorkflowID          string                                         `json:"workflow_id"`
	ExecutorID          string                                         `json:"executor_id"`
	OperatorID          string                                         `json:"operator_id"`
	Observation         AdapterCapacityPodUnregisteredTerminalResponse `json:"observation"`
	History             CapacityNativeAbortZeroHistory                 `json:"history"`
	ParentRecordSHA256  string                                         `json:"parent_record_sha256"`
	CommandRecordSHA256 string                                         `json:"command_record_sha256"`
	ResultSeedSHA256    string                                         `json:"result_seed_sha256"`
	LeaseExpiredAt      time.Time                                      `json:"lease_expired_at"`
	QuarantinedAt       time.Time                                      `json:"quarantined_at"`
}

type CapacityNativeUnsettledCounts struct {
	RawUnsettled    int64 `json:"raw_unsettled_commands"`
	ActiveUnsettled int64 `json:"active_unsettled_commands"`
	Quarantined     int64 `json:"quarantined_commands"`
}
