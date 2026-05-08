package model

import (
	"time"

	"github.com/google/uuid"
)

// Canonical pending_action values for collaborator_provider_state.
const (
	PendingActionProvision   = "provision"
	PendingActionUpdate      = "update"
	PendingActionDeprovision = "deprovision"
)

// CollaboratorProviderState is the per-(collaborator, provider) record
// of desired vs observed state used by Crossplane-style reconcile loops.
type CollaboratorProviderState struct {
	CollaboratorID      uuid.UUID      `json:"collaborator_id"`
	Provider            string         `json:"provider"`
	ExternalID          string         `json:"external_id,omitempty"`
	DesiredState        map[string]any `json:"desired_state"`
	ObservedState       map[string]any `json:"observed_state,omitempty"`
	LastReconciledAt    *time.Time     `json:"last_reconciled_at,omitempty"`
	LastDriftDetectedAt *time.Time     `json:"last_drift_detected_at,omitempty"`
	PendingAction       string         `json:"pending_action,omitempty"`
	ErrorCount          int            `json:"error_count"`
	LastError           string         `json:"last_error,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
}

// UpsertProviderStateRequest is the input to
// repository.UpsertCollaboratorProviderState. ObservedState pointer
// distinguishes "do not touch observed" (nil) from "set observed to
// empty" (&{}); DesiredState always replaces.
type UpsertProviderStateRequest struct {
	CollaboratorID uuid.UUID       `json:"collaborator_id"`
	Provider       string          `json:"provider"`
	ExternalID     string          `json:"external_id,omitempty"`
	DesiredState   map[string]any  `json:"desired_state"`
	ObservedState  *map[string]any `json:"observed_state,omitempty"`
	PendingAction  string          `json:"pending_action,omitempty"`
}
