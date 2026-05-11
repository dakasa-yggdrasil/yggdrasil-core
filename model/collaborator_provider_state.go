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

// ReconcileProviderStateRequest is the input to the
// collaborator.reconcile_provider_state AMQP capability. It carries a
// batch of identities discovered in one external provider; the handler
// matches each identity to a collaborator by primary_email and upserts
// the corresponding collaborator_provider_state row.
type ReconcileProviderStateRequest struct {
	Provider string                       `json:"provider"`          // e.g. "github"
	Users    []ReconcileProviderStateUser `json:"users"`             // identities discovered in the provider
}

// ReconcileProviderStateUser is one identity entry in a
// ReconcileProviderStateRequest.
type ReconcileProviderStateUser struct {
	ExternalID    string         `json:"external_id"`               // id in the provider
	Email         string         `json:"email"`                     // primary email of the user at the provider
	DisplayName   string         `json:"display_name,omitempty"`
	ObservedState map[string]any `json:"observed_state,omitempty"`  // raw attributes from the provider
}

// ReconcileProviderStateResponse is the result returned by the
// collaborator.reconcile_provider_state capability.
type ReconcileProviderStateResponse struct {
	Provider        string   `json:"provider"`
	Matched         int      `json:"matched"`                    // rows upserted
	UnmatchedEmails []string `json:"unmatched_emails,omitempty"` // no collaborator found for these emails
}
