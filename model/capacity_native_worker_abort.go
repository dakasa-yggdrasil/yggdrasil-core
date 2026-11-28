package model

import (
	"time"

	"github.com/google/uuid"
)

const CapacityNativeWorkerAbortSchema = "native_worker_pre_admission_abort_v1"

// This source-owned opt-in grants no provider or Kubernetes permission itself.
// Runtime composition and the separate active recovery workflow are mandatory.
type CapacityNativeWorkerAbortBinding struct {
	Mode             string           `json:"mode"`
	Workflow         ManifestSelector `json:"workflow"`
	MaxPermitSeconds int              `json:"max_permit_seconds"`
}

// Private one-send command. Read never returns a settlement bearer or a right
// to mutate; only the successful original Redeem can do so.
type CapacityNativeWorkerAbortPermit struct {
	Schema               string                        `json:"schema"`
	PermitID             uuid.UUID                     `json:"permit_id"`
	AttemptID            uuid.UUID                     `json:"attempt_id"`
	State                string                        `json:"state"`
	BindingName          string                        `json:"binding_name"`
	SDKSourceCommit      string                        `json:"sdk_source_commit"`
	ExecutionScopeSHA256 string                        `json:"execution_scope_sha256"`
	Capability           string                        `json:"capability"`
	PoolUID              string                        `json:"pool_uid"`
	PoolEpoch            int64                         `json:"pool_epoch"`
	Registry             CapacityNativePoolRegistryRef `json:"registry"`
	Physical             CapacityNativeWorkerPhysical  `json:"physical"`
	ExpiresAt            time.Time                     `json:"expires_at"`
	Redeemable           bool                          `json:"redeemable"`
	MutationPermitted    bool                          `json:"mutation_permitted"`
	SettlementToken      string                        `json:"settlement_token,omitempty"`
}

type CapacityNativeWorkerAbortReceive struct {
	PermitID        uuid.UUID `json:"permit_id"`
	BindingName     string    `json:"binding_name"`
	SettlementToken string    `json:"settlement_token"`
	OriginalReturn  []byte    `json:"original_return"`
	CaptureComplete bool      `json:"capture_complete"`
	ErrorClass      string    `json:"error_class"`
}

// Protected runtime facts, never accepted from a workflow or mutation actor.
// Unknown Node inventory is explicit and cannot authorize a destructive send.
type CapacityNativeWorkerAbortObservation struct {
	// This optional safe provider snapshot is privately retained in the abort
	// event before a send. It never extends the public AbortPermit wire.
	ResourceFootprint       *CapacityNativeWorkerResourceFootprint `json:"resource_footprint,omitempty"`
	ObservedAt              time.Time
	RealmUID                string
	PoolUID                 string
	Owner                   string
	Epoch                   int64
	Registry                CapacityNativePoolRegistryRef
	RegistryResourceVersion string
	ExecutionScopeSHA256    string
	Physical                CapacityNativeWorkerPhysical
	ProviderOutcome         string // present, not_found, terminal_nonbillable, unknown
	ProviderEvidenceSHA256  string
	NodeState               string // none_confirmed, quarantined, unknown, ambiguous, admitted
	NodeUID                 string
	NodeProviderID          string
	NodeResourceVersion     string
	NodesComplete           bool
	PodsComplete            bool
	QuarantinePresent       bool
	Unschedulable           bool
	ApplicationPods         int
	NodeEvidenceSHA256      string
	RegistryEntryAbsent     bool
	RegistryEvidenceSHA256  string
	NetworkPeerAbsent       bool
	IPAMEntryAbsent         bool
	NetworkEvidenceSHA256   string
	AncillaryChargesClosed  bool
	ChargeEvidenceSHA256    string
}
