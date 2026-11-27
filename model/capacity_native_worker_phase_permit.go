package model

import (
	"time"

	"github.com/google/uuid"
)

const CapacityNativeWorkerPhasePermitSchema = "native_worker_kube_phase_permit_v1"

// Registry writer credentials and authority are independent from the read-only
// pool/market collectors. A single permit authorizes exactly one native CAS.
type CapacityNativeWorkerRegistryWriterBinding struct {
	Adapter          CapacityMarketAdapterBinding `json:"adapter"`
	BindingName      string                       `json:"binding_name"`
	PrincipalID      string                       `json:"principal_id"`
	SourceCommit     string                       `json:"source_commit"`
	ScopeSHA256      string                       `json:"scope_sha256"` // SHA256 of the exact complete reviewed writer inventory bytes.
	Capability       string                       `json:"capability"`
	MaxPermitSeconds int                          `json:"max_permit_seconds"`
}

type CapacityNativeWorkerPhaseNode struct {
	Name                      string `json:"name"`
	UID                       string `json:"uid"`
	ResourceVersion           string `json:"resource_version"`
	ProviderID                string `json:"provider_id"`
	Profile                   string `json:"profile"`
	PhysicalSpecSHA256        string `json:"physical_spec_sha256"`
	RegistrationBindingSHA256 string `json:"registration_binding_sha256"`
	CapacityPolicyID          string `json:"capacity_policy_id"`
	IntentGeneration          int64  `json:"intent_generation"`
	FencingToken              int64  `json:"fencing_token"`
	CreationProofSHA256       string `json:"creation_proof_sha256"`
}

type CapacityNativeWorkerPhaseAdmission struct {
	ReceiptSHA256               string `json:"receipt_sha256,omitempty"`
	NetworkBindingSHA256        string `json:"network_binding_sha256,omitempty"`
	WarmupEvidenceSHA256        string `json:"warmup_evidence_sha256,omitempty"`
	PhysicalQualificationSHA256 string `json:"physical_qualification_sha256,omitempty"`
}

// Read always returns MutationPermitted=false and no settlement token. Only
// the original successful Redeem returns a private one-send mutation permit.
type CapacityNativeWorkerPhasePermit struct {
	Schema                          string                             `json:"schema"`
	PermitID                        uuid.UUID                          `json:"permit_id"`
	AttemptID                       uuid.UUID                          `json:"attempt_id"`
	BindingName                     string                             `json:"binding_name"`
	WriterScopeSHA256               string                             `json:"writer_scope_sha256"`
	Operation                       string                             `json:"operation"`
	Action                          string                             `json:"action"`
	PolicyID                        uuid.UUID                          `json:"policy_id"`
	IntentGeneration                int64                              `json:"intent_generation"`
	FencingToken                    int64                              `json:"fencing_token"`
	PoolUID                         string                             `json:"pool_uid"`
	Owner                           string                             `json:"owner"`
	Epoch                           int64                              `json:"epoch"`
	RealmNamespace                  string                             `json:"realm_namespace"`
	RealmUID                        string                             `json:"realm_uid"`
	Registry                        CapacityNativePoolRegistryRef      `json:"registry"`
	ExpectedRegistryResourceVersion string                             `json:"expected_registry_resource_version"`
	ExpectedRegistrySHA256          string                             `json:"expected_registry_sha256"`
	Node                            CapacityNativeWorkerPhaseNode      `json:"node"`
	Admission                       CapacityNativeWorkerPhaseAdmission `json:"admission"`
	ExpiresAt                       time.Time                          `json:"expires_at"`
	MutationPermitted               bool                               `json:"mutation_permitted"`
	Redeemable                      bool                               `json:"redeemable"`
	PhaseState                      string                             `json:"phase_state"`
	SettlementToken                 string                             `json:"settlement_token,omitempty"`
}

// Caller identity is assembled by authenticated server composition. It is not
// decoded from the capability input, which contains only binding and permit ID.
type CapacityNativeWorkerPhaseCaller struct {
	Adapter      CapacityMarketAdapterBinding
	PrincipalID  string
	BindingName  string
	SourceCommit string
}

// Receive is authenticated original-return custody, not admission authority.
// OriginalReturn and its hash never enter public read/workflow metadata.
type CapacityNativeWorkerPhaseReceive struct {
	PermitID           uuid.UUID `json:"permit_id"`
	BindingName        string    `json:"binding_name"`
	SettlementToken    string    `json:"settlement_token"`
	HTTPStatus         int       `json:"http_status"`
	TransportCompleted bool      `json:"transport_completed"`
	OriginalReturn     []byte    `json:"original_return"`
	CompletedAt        time.Time `json:"completed_at"`
}

// Prepared/observed facts come only from installed read-only runtime callbacks.
// Neither a workflow request nor the mutating adapter supplies these booleans.
type CapacityNativeWorkerPhasePreparation struct {
	Context           CapacityNativeWorkerPhasePermit
	ObservedAt        time.Time
	NodeReady         bool
	NetworkVerified   bool
	WarmupVerified    bool
	PhysicalQualified bool
}

type CapacityNativeWorkerPhaseObservation struct {
	RealmUID                string
	PoolUID                 string
	Owner                   string
	Epoch                   int64
	ObservedAt              time.Time
	Applied                 bool
	NodeUID                 string
	RegistryUID             string
	RegistryResourceVersion string
	RegistrySHA256          string
	ProviderID              string
	AdmissionReceiptSHA256  string
	QuarantineAbsent        bool
	Ready                   bool
}
