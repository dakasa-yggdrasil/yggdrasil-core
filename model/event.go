package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Event is a persisted state change event in the yggdrasil-core event stream.
// Events are emitted transactionally with state mutations and consumed by
// subscribers via cursor-based pull.
type Event struct {
	EventID       uuid.UUID       `json:"event_id"`
	Sequence      int64           `json:"sequence"`
	Type          string          `json:"type"`
	SchemaVersion string          `json:"schema_version"`
	AggregateType string          `json:"aggregate_type"`
	AggregateID   string          `json:"aggregate_id"`
	Actor         *EventActor     `json:"actor,omitempty"`
	EmittedAt     time.Time       `json:"emitted_at"`
	Payload       json.RawMessage `json:"payload"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
}

// EventActor identifies who/what caused an event to be emitted.
type EventActor struct {
	Type    string                 `json:"type"`
	ID      string                 `json:"id"`
	Context map[string]interface{} `json:"context,omitempty"`
}

// EmitEventRequest is the input to repository.EmitEvent.
// Called from within a mutation transaction to guarantee atomicity.
//
// IdempotencyKey is optional. When set, repository.EmitEvent dedups against
// (Type, IdempotencyKey) on event_log so the same logical mutation can be
// re-posted without producing a duplicate row. Used by adapter pods
// emitting <provider>.<resource>.<verb_past> mutation events per
// INTEGRATION_CONTRACT §6.5. Maximum length 256 chars (mirrors the column).
type EmitEventRequest struct {
	Type           string
	SchemaVersion  string
	AggregateType  string
	AggregateID    string
	Actor          *EventActor
	Payload        map[string]interface{}
	Metadata       map[string]interface{}
	IdempotencyKey string
}

// EmitEventOutcome is the rich return type for repository.EmitEventWithOutcome.
// It exposes the inserted event ID, the number of integration_event_reactions
// rows materialised in the same Tx (the fan-out an HTTP caller wants to
// surface to the client), and whether the row was deduped against an
// existing idempotency_key.
type EmitEventOutcome struct {
	EventID               uuid.UUID `json:"event_id"`
	MaterializedReactions int64     `json:"materialized_reactions"`
	Deduped               bool      `json:"deduped"`
}

// PullEventsRequest is the input to the event_stream.pull RPC.
type PullEventsRequest struct {
	Cursor  string            `json:"cursor,omitempty"`
	Limit   int               `json:"limit,omitempty"`
	Filters PullEventsFilters `json:"filters,omitempty"`
}

// PullEventsFilters scopes the pulled events. All filters are AND-combined.
type PullEventsFilters struct {
	Types                   []string   `json:"types,omitempty"`
	AggregateType           string     `json:"aggregate_type,omitempty"`
	AggregateID             string     `json:"aggregate_id,omitempty"`
	SupportedSchemaVersions []string   `json:"supported_schema_versions,omitempty"`
	EmittedAfter            *time.Time `json:"emitted_after,omitempty"`
}

// PullEventsResponse is the output of event_stream.pull.
type PullEventsResponse struct {
	Events     []Event `json:"events"`
	NextCursor string  `json:"next_cursor"`
	HasMore    bool    `json:"has_more"`
}

// EventRetentionPolicy describes how long events of a given type pattern are retained.
type EventRetentionPolicy struct {
	TypePattern string    `json:"type_pattern"`
	TTLDays     int       `json:"ttl_days"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Default pagination constants for event pulls.
const (
	DefaultPullLimit = 100
	MaxPullLimit     = 1000
)
