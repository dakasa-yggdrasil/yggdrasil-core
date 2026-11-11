package model

import "time"

// CapacityInstalledProvisionTimeoutDisposition preserves an unknown original
// dispatch. It authorizes only a distinct installed-readiness observation; it
// is neither an acknowledgment of the old run nor another provider execution.
type CapacityInstalledProvisionTimeoutDisposition struct {
	Schema                       string                                    `json:"schema"`
	ID                           string                                    `json:"id"`
	JobID                        string                                    `json:"job_id"`
	RunID                        string                                    `json:"run_id"`
	PolicyID                     string                                    `json:"policy_id"`
	PolicyChecksum               string                                    `json:"policy_checksum"`
	Generation                   int64                                     `json:"generation"`
	FencingToken                 int64                                     `json:"fencing_token"`
	LeaseOwner                   string                                    `json:"lease_owner"`
	ExecutorID                   string                                    `json:"executor_id"`
	PreregistrationID            string                                    `json:"preregistration_id"`
	CreateGrantID                string                                    `json:"create_grant_id"`
	OriginalDispatchSHA256       string                                    `json:"original_dispatch_sha256"`
	OriginalRunSHA256            string                                    `json:"original_run_sha256"`
	OriginalIntentSHA256         string                                    `json:"original_intent_sha256"`
	MembersSHA256                string                                    `json:"members_sha256"`
	OriginalDeadline             time.Time                                 `json:"original_deadline"`
	OriginalIntentLeaseExpiresAt time.Time                                 `json:"original_intent_lease_expires_at"`
	OriginalReturnedAt           time.Time                                 `json:"original_returned_at"`
	RecordedAt                   time.Time                                 `json:"recorded_at"`
	Members                      []CapacityInstalledProvisionTimeoutMember `json:"members"`
}

type CapacityInstalledProvisionTimeoutMember struct {
	Slot                  int                      `json:"slot"`
	PreregistrationID     string                   `json:"preregistration_id"`
	CreateGrantID         string                   `json:"create_grant_id"`
	Tuple                 CapacityGuestNativeTuple `json:"tuple"`
	RequestSHA256         string                   `json:"request_sha256"`
	PreregistrationSHA256 string                   `json:"preregistration_sha256"`
	WitnessSHA256         string                   `json:"witness_sha256"`
	EnrollmentSHA256      string                   `json:"enrollment_sha256"`
	InstallationSHA256    string                   `json:"installation_sha256"`
	ReceiptSHA256         string                   `json:"receipt_sha256"`
}
