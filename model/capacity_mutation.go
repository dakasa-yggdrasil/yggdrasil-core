package model

import (
	"encoding/json"
	"time"
)

// CapacityMutationBinding is operator-owned. A dry-run plan never authorizes
// itself: its normalized non-secret spec must match a preapproved slot digest.
type CapacityMutationBinding struct {
	Name                    string                        `json:"name"`
	IntegrationInstanceID   string                        `json:"integration_instance_id"`
	IntegrationChecksum     string                        `json:"integration_checksum"`
	IntegrationTypeID       string                        `json:"integration_type_id"`
	IntegrationTypeChecksum string                        `json:"integration_type_checksum"`
	AdapterPrincipalID      string                        `json:"adapter_principal_id"`
	ScopeChecksum           string                        `json:"scope_checksum"`
	ProfileName             string                        `json:"profile_name"`
	EnsureCapability        string                        `json:"ensure_capability"`
	DestroyCapability       string                        `json:"destroy_capability"`
	ProtectedSlots          int                           `json:"protected_slots"`
	MaxSlots                int                           `json:"max_slots"`
	Slots                   []CapacityMutationSlotBinding `json:"slots"`
	DefinitiveRejections    []CapacityMutationRejection   `json:"definitive_rejections,omitempty"`
}

type CapacityMutationRejection struct {
	StatusCode       int    `json:"status_code"`
	ErrorCode        string `json:"error_code"`
	DocumentationRef string `json:"documentation_ref"`
}

type CapacityMutationSlotBinding struct {
	Slot              int    `json:"slot"`
	DesiredSpecSHA256 string `json:"desired_spec_sha256"`
}

type CapacityMutationIssue struct {
	BindingName string          `json:"binding_name"`
	DesiredSpec json.RawMessage `json:"desired_spec"`
}

// CapacityMutationSpecV1 is the closed non-secret slot projection shared with
// provider adapters. Physical SDK fields are pinned by profile/admission hashes.
// Unknown fields never enter an authoritative desired-spec digest.
type CapacityMutationSpecV1 struct {
	SchemaVersion             string `json:"schema_version"`
	Capability                string `json:"capability"`
	IntegrationInstanceID     string `json:"integration_instance_id"`
	ScopeChecksum             string `json:"scope_checksum"`
	ProfileChecksum           string `json:"profile_checksum"`
	AdmissionChecksum         string `json:"admission_checksum"`
	ProfileName               string `json:"profile_name"`
	Slot                      int    `json:"slot"`
	NativeName                string `json:"native_name"`
	BootstrapSHA256           string `json:"bootstrap_sha256"`
	ExpectedResourceID        string `json:"expected_resource_id,omitempty"`
	ExpectedResourceCreatedAt string `json:"expected_resource_created_at,omitempty"`
}

// These DTOs agree with the adapter's private callback contract. They contain
// no settlement bearer. Only a hash enters durable redemption state.
type CapacityMutationRedeemRequest struct {
	GrantID                   string `json:"grant_id"`
	AttemptID                 string `json:"attempt_id"`
	SettlementTokenSHA256     string `json:"settlement_token_sha256"`
	Capability                string `json:"capability"`
	IntegrationInstanceID     string `json:"integration_instance_id"`
	ScopeChecksum             string `json:"scope_checksum"`
	ProfileName               string `json:"profile_name"`
	Slot                      int    `json:"slot"`
	RequestSHA256             string `json:"request_sha256"`
	ExpectedResourceID        string `json:"expected_resource_id,omitempty"`
	ExpectedResourceCreatedAt string `json:"expected_resource_created_at,omitempty"`
}

type CapacityMutationRedeemResponse struct {
	Mode          string `json:"mode"`
	GrantID       string `json:"grant_id"`
	AttemptID     string `json:"attempt_id"`
	RequestSHA256 string `json:"request_sha256"`
	ExpiresAt     string `json:"expires_at"`
}

type CapacityMutationSettleRequest struct {
	GrantID                    string                              `json:"grant_id"`
	AttemptID                  string                              `json:"attempt_id"`
	RequestSHA256              string                              `json:"request_sha256"`
	Outcome                    string                              `json:"outcome"`
	TransportCompleted         bool                                `json:"transport_completed"`
	ResourceID                 string                              `json:"resource_id,omitempty"`
	ResourceCreatedAt          string                              `json:"resource_created_at,omitempty"`
	ActionID                   string                              `json:"action_id,omitempty"`
	NextActionIDs              []string                            `json:"next_action_ids,omitempty"`
	ObservedAt                 string                              `json:"observed_at"`
	ProviderErrorCode          string                              `json:"provider_error_code,omitempty"`
	ProviderStatusCode         int                                 `json:"provider_status_code,omitempty"`
	AuxiliaryResources         []CapacityMutationAuxiliaryResource `json:"auxiliary_resources,omitempty"`
	AuxiliaryInventoryComplete bool                                `json:"auxiliary_inventory_complete,omitempty"`
}

type CapacityMutationAuxiliaryResource struct {
	Kind            string `json:"kind"`
	ID              string `json:"id"`
	RequiresAbsence bool   `json:"requires_absence,omitempty"`
}

type CapacityMutationGrant struct {
	GrantID                   string    `json:"grant_id"`
	BindingName               string    `json:"binding_name"`
	IntegrationInstanceID     string    `json:"integration_instance_id"`
	ScopeChecksum             string    `json:"scope_checksum"`
	ProfileName               string    `json:"profile_name"`
	Slot                      int       `json:"slot"`
	Capability                string    `json:"capability"`
	RequestSHA256             string    `json:"request_sha256"`
	ExpectedResourceID        string    `json:"expected_resource_id,omitempty"`
	ExpectedResourceCreatedAt string    `json:"expected_resource_created_at,omitempty"`
	ExpiresAt                 time.Time `json:"expires_at"`
	State                     string    `json:"state"`
}

type CapacityMutationReceipt struct {
	Grant                      CapacityMutationGrant               `json:"grant"`
	AttemptID                  string                              `json:"attempt_id,omitempty"`
	Outcome                    string                              `json:"outcome,omitempty"`
	TransportCompleted         bool                                `json:"transport_completed"`
	ResourceID                 string                              `json:"resource_id,omitempty"`
	ResourceCreatedAt          string                              `json:"resource_created_at,omitempty"`
	ActionID                   string                              `json:"action_id,omitempty"`
	NextActionIDs              []string                            `json:"next_action_ids,omitempty"`
	AuxiliaryResources         []CapacityMutationAuxiliaryResource `json:"auxiliary_resources,omitempty"`
	AuxiliaryInventoryComplete bool                                `json:"auxiliary_inventory_complete,omitempty"`
}

// A native action receipt is assembled by the fixed protected workflow using
// fresh adapter reads. Transport completion, provider action completion, and
// product readiness are distinct facts; this proof addresses only the first two.
type CapacityMutationProof struct {
	GrantID                 string                              `json:"grant_id"`
	BindingName             string                              `json:"binding_name"`
	Slot                    int                                 `json:"slot"`
	ResourceID              string                              `json:"resource_id"`
	ResourceCreatedAt       string                              `json:"resource_created_at"`
	RequestSHA256           string                              `json:"request_sha256"`
	ObservedAt              time.Time                           `json:"observed_at"`
	ReceiptRef              string                              `json:"receipt_ref"`
	OwnerVerified           bool                                `json:"owner_verified"`
	SpecVerified            bool                                `json:"spec_verified"`
	ResourceAbsent          bool                                `json:"resource_absent"`
	ActionIDs               []string                            `json:"action_ids"`
	ActionsTerminal         bool                                `json:"actions_terminal"`
	ActionsSuccessful       bool                                `json:"actions_successful"`
	ObservedCreationGrantID string                              `json:"observed_creation_grant_id,omitempty"`
	AuxiliaryAbsent         []CapacityMutationAuxiliaryResource `json:"auxiliary_absent,omitempty"`
}
