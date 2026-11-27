package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Native lifecycle is a separate opt-in authority, never a legacy Guest slot
// or a write credential added to the read-only market collector.
type CapacityNativeWorkerLifecycleBinding struct {
	Mode              string                                     `json:"mode"`
	SourceCommit      string                                     `json:"source_commit"`
	MaxReadAgeSeconds int                                        `json:"max_read_age_seconds"`
	Profiles          []CapacityNativeWorkerExecutionProfile     `json:"profiles"`
	RegistryWriter    *CapacityNativeWorkerRegistryWriterBinding `json:"registry_writer,omitempty"`
}

type CapacityNativeWorkerExecutionProfile struct {
	Profile               string                       `json:"profile"`
	Adapter               CapacityMarketAdapterBinding `json:"adapter"`
	BindingName           string                       `json:"binding_name"`
	ScopeSHA256           string                       `json:"scope_sha256"`
	EnsureCapability      string                       `json:"ensure_capability"`
	ObserveCapability     string                       `json:"observe_capability"`
	DestroyCapability     string                       `json:"destroy_capability"`
	LaunchTemplateSHA256  string                       `json:"launch_template_sha256"`
	BootstrapSourceCommit string                       `json:"bootstrap_source_commit"`
	IPAMScope             string                       `json:"ipam_scope"`
	OverlayCIDR           string                       `json:"overlay_cidr"`
	ExcludedIPv4          []string                     `json:"excluded_ipv4"`
}

// Attempt IDs and addresses are allocated by Core. There is no predeclared
// array of slots and no elapsed-time release of a possible provider send.
type CapacityNativeWorkerAttempt struct {
	ID                          uuid.UUID                            `json:"id"`
	PolicyID                    uuid.UUID                            `json:"policy_id"`
	PolicyChecksum              string                               `json:"policy_checksum"`
	Namespace                   string                               `json:"namespace"`
	Environment                 string                               `json:"environment"`
	Domain                      string                               `json:"domain"`
	Dimension                   string                               `json:"dimension"`
	Generation                  int64                                `json:"generation"`
	FencingToken                int64                                `json:"fencing_token"`
	PoolUID                     string                               `json:"pool_uid"`
	PoolEpoch                   int64                                `json:"pool_epoch"`
	Registry                    CapacityNativePoolRegistryRef        `json:"registry"`
	Profile                     string                               `json:"profile"`
	Provider                    string                               `json:"provider"`
	Region                      string                               `json:"region"`
	ProviderIDPrefix            string                               `json:"provider_id_prefix"`
	SourceCommit                string                               `json:"source_commit"`
	Execution                   CapacityNativeWorkerExecutionProfile `json:"execution"`
	NetworkBindingSHA256        string                               `json:"network_binding_sha256"`
	PhysicalSpecSHA256          string                               `json:"physical_spec_sha256"`
	QualificationEvidenceSHA256 string                               `json:"qualification_evidence_sha256"`
	QualificationValidUntil     time.Time                            `json:"qualification_valid_until"`
	OverlayIPv4                 string                               `json:"overlay_ipv4"`
	LaunchSHA256                string                               `json:"launch_sha256"`
	IntentSHA256                string                               `json:"intent_sha256"`
	State                       string                               `json:"state"`
	Revision                    int64                                `json:"revision"`
	Reservation                 CapacityMarketReservation            `json:"reservation"`
	GroupFixedCostMicros        int64                                `json:"group_fixed_cost_micros"`
	Physical                    *CapacityNativeWorkerPhysical        `json:"physical,omitempty"`
	BirthSHA256                 string                               `json:"birth_sha256,omitempty"`
	NodeUID                     string                               `json:"node_uid,omitempty"`
	CreatedAt                   time.Time                            `json:"created_at"`
	UpdatedAt                   time.Time                            `json:"updated_at"`
}

// Full semantic identity extracted from the original acceptance and compared
// with an independently current bound SDK read. No provider SDK import here.
type CapacityNativeWorkerPhysical struct {
	ResourceID            string    `json:"resource_id"`
	ProviderID            string    `json:"provider_id"`
	AccountID             string    `json:"account_id"`
	InstanceType          string    `json:"instance_type"`
	NetworkID             string    `json:"network_id"`
	CreatedAt             time.Time `json:"created_at"`
	ImageID               string    `json:"image_id"`
	Region                string    `json:"region"`
	Zone                  string    `json:"zone"`
	NativeIPv4            string    `json:"native_ipv4"`
	MACAddress            string    `json:"mac_address"`
	PhysicalSpecSHA256    string    `json:"physical_spec_sha256"`
	PhysicalBindingSHA256 string    `json:"physical_binding_sha256"`
	LaunchSHA256          string    `json:"launch_sha256"`
}

// Birth is neutral registry provenance, not a forged legacy mutation proof.
type CapacityNativeWorkerBirth struct {
	Schema                   string                       `json:"schema"`
	AttemptID                uuid.UUID                    `json:"attempt_id"`
	PolicyID                 uuid.UUID                    `json:"policy_id"`
	Generation               int64                        `json:"generation"`
	FencingToken             int64                        `json:"fencing_token"`
	PoolUID                  string                       `json:"pool_uid"`
	PoolEpoch                int64                        `json:"pool_epoch"`
	ExecutionAdapter         CapacityMarketAdapterBinding `json:"execution_adapter"`
	ExecutionScopeSHA256     string                       `json:"execution_scope_sha256"`
	LaunchSHA256             string                       `json:"launch_sha256"`
	OriginalAcceptanceSHA256 string                       `json:"original_acceptance_sha256"`
	IndependentReadSHA256    string                       `json:"independent_read_sha256"`
	OriginalRequestID        string                       `json:"original_request_id"`
	IndependentRequestID     string                       `json:"independent_request_id"`
	Physical                 CapacityNativeWorkerPhysical `json:"physical"`
}

// These request operands carry no provider acceptance, prices or observation.
type CapacityNativeWorkerAuthority struct {
	Generation   int64 `json:"generation"`
	FencingToken int64 `json:"fencing_token"`
}

// Permit is returned once, only after send_started commits. It is a private
// runtime operand, never proof that a provider accepted or a Node is useful.
type CapacityNativeWorkerPermit struct {
	AttemptID        uuid.UUID
	LaunchSHA256     string
	OverlayIPv4      string
	Adapter          CapacityMarketAdapterBinding
	BindingName      string
	Capability       string
	PublicLaunchJSON json.RawMessage `json:"-"`
}

// OriginalReturn is private custody. It must never be embedded in public
// responses; even malformed/partial/error returns precede any SDK qualification.
type CapacityNativeWorkerOriginalReturn struct {
	Wire            []byte `json:"-"`
	ErrorClass      string `json:"-"`
	CaptureComplete bool   `json:"-"`
}

type CapacityNativeWorkerLaunch struct {
	AttemptID      uuid.UUID
	PoolUID        string
	PoolEpoch      int64
	Generation     int64
	FencingToken   int64
	OverlayIPv4    string
	TemplateSHA256 string
	PublicJSON     json.RawMessage
}

// Observation can only originate from a protected installed runtime callback,
// never a workflow/RPC DTO. Concrete SDK/network/registry collectors are separate.
type CapacityNativeWorkerObservation struct {
	State                         string
	ExecutionScopeSHA256          string
	ObservedAt                    time.Time
	OriginalReturnSHA256          string `json:"-"`
	OriginalAcceptance            CapacityNativeWorkerPhysical
	IndependentCurrent            CapacityNativeWorkerPhysical
	OriginalRequestID             string
	IndependentRequestID          string
	NodeUID                       string
	NodeProviderID                string
	RegistryUID                   string
	RegistryBeforeResourceVersion string
	RegistryAfterResourceVersion  string
	NetworkEvidenceSHA256         string
	NetworkBindingSHA256          string
	WarmupEvidenceSHA256          string
	QualificationEvidenceSHA256   string
	AdmissionReceiptSHA256        string
	DrainEvidenceSHA256           string
	ProviderAbsenceEvidenceSHA256 string
	NetworkAbsenceEvidenceSHA256  string
	AbsentProviderID              string
	AbsentResourceCreatedAt       time.Time
	AbsentOverlayIPv4             string
}
