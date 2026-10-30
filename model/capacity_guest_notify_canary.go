package model

import "time"

// One source-owned challenge, with separate read and publish purposes. No URL,
// command, SQL, provider action or completion assertion is caller-selected.
type CapacityGuestNotifyCanaryChallenge struct {
	Schema                      string                         `json:"schema"`
	Purpose                     string                         `json:"purpose"`
	ChallengeID                 string                         `json:"challenge_id"`
	NonceSHA256                 string                         `json:"nonce_sha256"`
	UsageClass                  string                         `json:"usage_class"`
	RecordChallengeID           string                         `json:"record_challenge_id"`
	BindingName                 string                         `json:"binding_name"`
	Slot                        int                            `json:"slot"`
	PreregistrationID           string                         `json:"preregistration_id"`
	PreregistrationNonceSHA256  string                         `json:"preregistration_nonce_sha256"`
	OriginalRegistrationSHA256  string                         `json:"original_registration_sha256"`
	OriginalCreateWitnessSHA256 string                         `json:"original_create_witness_sha256"`
	EnrollmentSHA256            string                         `json:"enrollment_sha256"`
	ProfileManifestSHA256       string                         `json:"profile_manifest_sha256"`
	Tuple                       CapacityGuestNativeTuple       `json:"tuple"`
	PolicyID                    string                         `json:"policy_id"`
	PolicyChecksum              string                         `json:"policy_checksum"`
	WorkflowID                  string                         `json:"workflow_id"`
	WorkflowChecksum            string                         `json:"workflow_checksum"`
	Generation                  uint64                         `json:"generation"`
	Fence                       uint64                         `json:"fence"`
	LeaseOwner                  string                         `json:"lease_owner"`
	CoreSourceCommit            string                         `json:"core_source_commit"`
	IssuedAt                    time.Time                      `json:"issued_at"`
	OriginalDeadline            time.Time                      `json:"original_deadline"`
	GuestNonce                  CapacityGuestNotifyCanaryNonce `json:"guest_nonce"`
	Signature                   string                         `json:"signature"`
}

type CapacityGuestNotifyCanaryRequest struct {
	Challenge CapacityGuestNotifyCanaryChallenge `json:"challenge"`
}

// NotifyOriginalReturn contains the exact bounded newline-terminated return
// frame from the SAME original application control pipe. The persistent pipe
// is not closed by a read. Native SQL Rows.Close and the enclosing Guest HTTP
// EOF/Close are independently owned; this DTO never fabricates a pipe Close.
type CapacityGuestNotifyCanaryRead struct {
	Schema                         string                                 `json:"schema"`
	Purpose                        string                                 `json:"purpose"`
	ChallengeID                    string                                 `json:"challenge_id"`
	ChallengeSHA256                string                                 `json:"challenge_sha256"`
	PreregistrationID              string                                 `json:"preregistration_id"`
	EnrollmentSHA256               string                                 `json:"enrollment_sha256"`
	Tuple                          CapacityGuestNativeTuple               `json:"tuple"`
	Actor                          CapacityGuestRetirementLifetime        `json:"actor"`
	Runtime                        CapacityGuestRetirementLifetime        `json:"runtime"`
	Writers                        []CapacityGuestRetirementWriter        `json:"writers"`
	WriterRosterSHA256             string                                 `json:"writer_roster_sha256"`
	CensusBefore                   CapacityGuestRetirementProtectedCensus `json:"census_before"`
	CensusAfter                    CapacityGuestRetirementProtectedCensus `json:"census_after"`
	NotifyOriginalReturn           []byte                                 `json:"notify_original_return_base64"`
	NotifyOriginalReturnSHA256     string                                 `json:"notify_original_return_sha256"`
	OriginalReadStartedAt          time.Time                              `json:"original_read_started_at"`
	OriginalRequestWriteReturnedAt time.Time                              `json:"original_request_write_returned_at"`
	OriginalFrameReadReturnedAt    time.Time                              `json:"original_frame_read_returned_at"`
	OriginalContextFailed          bool                                   `json:"original_context_failed"`
	HoldReasons                    []string                               `json:"hold_reasons"`
	Reader                         CapacityGuestRetirementLifetime        `json:"reader"`
	ObservedAt                     time.Time                              `json:"observed_at"`
	Signature                      string                                 `json:"signature"`
}

// Fixed source profile, not live business evidence. Synthetic recipients stay
// in the separately mounted Notify configuration; only their approved set hash
// appears here. Each actual message ID is derived from the signed challenge.
type CapacityGuestNotifyCanaryBinding struct {
	Mode                              string   `json:"mode"`
	Name                              string   `json:"name"`
	WriterID                          string   `json:"writer_id"`
	NotifySourceCommit                string   `json:"notify_source_commit"`
	QuerySHA256                       string   `json:"query_sha256"`
	RecipientSHA256                   string   `json:"recipient_sha256"`
	RecipientCount                    int      `json:"recipient_count"`
	Database                          string   `json:"database"`
	DatabaseOID                       string   `json:"database_oid"`
	SystemID                          string   `json:"system_identifier"`
	TableOIDs                         []string `json:"table_oids"`
	MinimumPublicationIntervalSeconds int      `json:"minimum_publication_interval_seconds"`
	MaximumPublicationsPerHour        int      `json:"maximum_publications_per_hour"`
	TopologySHA256                    string   `json:"topology_sha256"`
}

// Declarative queue identities belong to the immutable protected source profile.
// They convey no assertion that a physical broker applied these definitions.
type CapacityGuestNotifyCanaryTopology struct {
	Schema            string                           `json:"schema"`
	Namespace         string                           `json:"namespace"`
	Binding           string                           `json:"binding"`
	DefinitionsSHA256 string                           `json:"definitions_sha256"`
	Queues            []CapacityGuestNotifyCanaryQueue `json:"queues"`
}

type CapacityGuestNotifyCanaryQueue struct {
	Provider string `json:"provider"`
	Slot     int    `json:"slot"`
	Name     string `json:"name"`
}

type CapacityGuestNotifyBusinessObservation struct {
	RecordChallengeID          string                        `json:"record_challenge_id"`
	RecordSHA256               string                        `json:"record_sha256"`
	BodySHA256                 string                        `json:"body_sha256"`
	NativeSnapshotSHA256       string                        `json:"native_snapshot_sha256"`
	NotificationSHA256         string                        `json:"notification_sha256"`
	CreationFreshnessClass     string                        `json:"creation_freshness_class"`
	CreationUpperBoundSeconds  int                           `json:"creation_upper_bound_seconds"`
	NativeCommitTimestampKnown bool                          `json:"native_commit_timestamp_known"`
	OriginalXID                string                        `json:"original_xid"`
	OriginalCommit             *time.Time                    `json:"original_commit"`
	NativeObserved             time.Time                     `json:"native_observed"`
	EnrollmentSHA256           string                        `json:"enrollment_sha256"`
	Writer                     CapacityGuestRetirementWriter `json:"writer"`
	RecipientSHA256            string                        `json:"recipient_sha256"`
	RecipientCount             int                           `json:"recipient_count"`
	OriginalReadReturnedAt     time.Time                     `json:"original_read_returned_at"`
}

// Opaque local Guest CLOCK_MONOTONIC custody. Core authenticates this signed
// original budget without comparing different machines' wall clocks.
type CapacityGuestNotifyCanaryNonce struct {
	Schema             string                          `json:"schema"`
	ChallengeID        string                          `json:"challenge_id"`
	Phase              string                          `json:"phase"`
	PreflightSHA256    string                          `json:"preflight_sha256"`
	EnrollmentSHA256   string                          `json:"enrollment_sha256"`
	Actor              CapacityGuestRetirementLifetime `json:"actor"`
	Runtime            CapacityGuestRetirementLifetime `json:"runtime"`
	Writer             CapacityGuestRetirementWriter   `json:"writer"`
	NonceSHA256        string                          `json:"nonce_sha256"`
	IssuedMonotonicNS  int64                           `json:"issued_monotonic_ns"`
	ExpiresMonotonicNS int64                           `json:"expires_monotonic_ns"`
	Signature          string                          `json:"signature"`
}
