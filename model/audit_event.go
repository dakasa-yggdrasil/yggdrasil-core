package model

import (
	"time"

	"github.com/google/uuid"
)

// AuditEvent records one state-mutating action against the public API.
// Surfaces (console UI, compliance reports) query the audit_events table
// via GET /api/v1/audit. Adopters can also stream events to an external
// SIEM by tailing the table or subscribing to Postgres logical replication.
type AuditEvent struct {
	ID           uuid.UUID      `json:"id"`
	Actor        string         `json:"actor"`         // "user:<id>", "service:<name>", "anonymous"
	Action       string         `json:"action"`        // "manifest.create", "workflow.run", "secret.rotate", etc.
	ResourceKind string         `json:"resource_kind"` // "manifest", "workflow_run", "secret"
	ResourceID   string         `json:"resource_id"`   // UUID or namespace/name
	Outcome      string         `json:"outcome"`       // "success", "denied", "error"
	TenantSlug   string         `json:"tenant_slug,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	TraceID      string         `json:"trace_id,omitempty"`
	SpanID       string         `json:"span_id,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}

// ListAuditEventsFilter restricts a query.
type ListAuditEventsFilter struct {
	Actor        string
	Action       string
	ResourceKind string
	ResourceID   string
	TenantSlug   string
	Since        time.Time
	Until        time.Time
	Limit        int
}
