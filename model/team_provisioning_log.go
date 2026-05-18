package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// TeamProvisioningLog records that a Yggdrasil team has been mirrored
// into an external system (Slack channel, GitHub team, GW group, ...).
// The reconcile cron uses this table to skip pairs that already have a
// mirror; /teams/{id}/provisioning-status reads it to surface state to
// operators.
type TeamProvisioningLog struct {
	ID                    uuid.UUID       `json:"id"`
	TeamID                uuid.UUID       `json:"team_id"`
	IntegrationInstanceID uuid.UUID       `json:"integration_instance_id"`
	ExternalID            string          `json:"external_id"`
	ExternalMetadata      json.RawMessage `json:"external_metadata"`
	LastSuccessAt         time.Time       `json:"last_success_at"`
	LastEventType         string          `json:"last_event_type"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
}

// UpsertTeamProvisioningLogRequest is the input to
// repository.UpsertTeamProvisioningLog. Called by the reactor dispatcher
// when an adapter returns an `_yggdrasil.team_provisioned` envelope.
type UpsertTeamProvisioningLogRequest struct {
	TeamID                uuid.UUID
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	ExternalMetadata      map[string]any
	LastEventType         string
}
