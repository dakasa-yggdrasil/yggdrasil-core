package model

import "time"

// Separate source-owned read-only runtime snapshot ABI. It observes a fresh
// original enrollment under a scoped Core challenge; it never creates a
// retirement journal, provisioning result, writer completion or write grant.

type CapacityGuestRuntimeSnapshotChallenge struct {
	Schema                      string                   `json:"schema"`
	Purpose                     string                   `json:"purpose"`
	ChallengeID                 string                   `json:"challenge_id"`
	BindingName                 string                   `json:"binding_name"`
	Slot                        int                      `json:"slot"`
	PreregistrationID           string                   `json:"preregistration_id"`
	PreregistrationNonceSHA256  string                   `json:"preregistration_nonce_sha256"`
	OriginalRegistrationSHA256  string                   `json:"original_registration_sha256"`
	OriginalCreateWitnessSHA256 string                   `json:"original_create_witness_sha256"`
	EnrollmentSHA256            string                   `json:"enrollment_sha256"`
	ProfileManifestSHA256       string                   `json:"profile_manifest_sha256"`
	Tuple                       CapacityGuestNativeTuple `json:"tuple"`
	RequestID                   string                   `json:"request_id"`
	AttemptID                   string                   `json:"attempt_id"`
	IntentSHA256                string                   `json:"intent_sha256"`
	Phase                       string                   `json:"phase"`
	PolicyID                    string                   `json:"policy_id"`
	PolicyChecksum              string                   `json:"policy_checksum"`
	WorkflowID                  string                   `json:"workflow_id"`
	WorkflowChecksum            string                   `json:"workflow_checksum"`
	Generation                  uint64                   `json:"generation"`
	Fence                       uint64                   `json:"fence"`
	LeaseOwner                  string                   `json:"lease_owner"`
	CoreSourceCommit            string                   `json:"core_source_commit"`
	IssuedAt                    time.Time                `json:"issued_at"`
	OriginalDeadline            time.Time                `json:"original_deadline"`
	Signature                   string                   `json:"signature"`
}

type CapacityGuestRuntimeSnapshotRequest struct {
	Challenge CapacityGuestRuntimeSnapshotChallenge `json:"challenge"`
}

type CapacityGuestRuntimeSnapshot struct {
	Schema                      string                                 `json:"schema"`
	Purpose                     string                                 `json:"purpose"`
	ChallengeID                 string                                 `json:"challenge_id"`
	ChallengeSHA256             string                                 `json:"challenge_sha256"`
	PreregistrationID           string                                 `json:"preregistration_id"`
	OriginalRegistrationSHA256  string                                 `json:"original_registration_sha256"`
	OriginalCreateWitnessSHA256 string                                 `json:"original_create_witness_sha256"`
	ProfileManifestSHA256       string                                 `json:"profile_manifest_sha256"`
	EnrollmentSHA256            string                                 `json:"enrollment_sha256"`
	Tuple                       CapacityGuestNativeTuple               `json:"tuple"`
	Actor                       CapacityGuestRetirementLifetime        `json:"actor"`
	Runtime                     CapacityGuestRetirementLifetime        `json:"runtime"`
	Writers                     []CapacityGuestRetirementWriter        `json:"writers"`
	WriterRosterSHA256          string                                 `json:"writer_roster_sha256"`
	ProtectedCensus             CapacityGuestRetirementProtectedCensus `json:"protected_census"`
	OriginalReadStartedAt       time.Time                              `json:"original_read_started_at"`
	OriginalReadReturnedAt      time.Time                              `json:"original_read_returned_at"`
	OriginalReadsReturned       bool                                   `json:"original_reads_returned"`
	OriginalClosesReturned      bool                                   `json:"original_closes_returned"`
	OriginalContextFailed       bool                                   `json:"original_context_failed"`
	HoldReasons                 []string                               `json:"hold_reasons"`
	Reader                      CapacityGuestRetirementLifetime        `json:"reader"`
	ObservedAt                  time.Time                              `json:"observed_at"`
	Signature                   string                                 `json:"signature"`
}
