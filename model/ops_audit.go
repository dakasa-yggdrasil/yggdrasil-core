package model

import (
	"time"

	"github.com/google/uuid"
)

// OpsAuditEvent is the rich shape used by /api/v1/ops/* handlers. It maps
// to the same audit_events table extended in migration 00031 — the legacy
// AuditEvent shape continues to work for non-ops callers.
type OpsAuditEvent struct {
	ID                  uuid.UUID      `json:"id"`
	Actor               string         `json:"actor"`
	ActorCollaboratorID *uuid.UUID     `json:"actor_collaborator_id,omitempty"`
	ActorSessionID      string         `json:"actor_session_id,omitempty"`
	Action              string         `json:"action"`
	TargetKind          string         `json:"target_kind,omitempty"`
	TargetID            string         `json:"target_id,omitempty"`
	ResultStatus        string         `json:"result_status,omitempty"`
	CorrelationID       string         `json:"correlation_id,omitempty"`
	RequestBody         map[string]any `json:"request_body,omitempty"`
	Result              map[string]any `json:"result,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
}

// ListOpsAuditEventsFilter restricts a query.
type ListOpsAuditEventsFilter struct {
	Actor               string
	ActorCollaboratorID *uuid.UUID
	ActionPrefix        string
	TargetKind          string
	TargetID            string
	ResultStatus        string
	CorrelationID       string
	Since               time.Time
	Until               time.Time
	Limit               int
	Offset              int
	OrderDesc           bool
}
