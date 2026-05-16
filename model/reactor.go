// model/reactor.go
package model

import (
	"time"

	"github.com/google/uuid"
)

// ReactionStatus is the lifecycle of a single integration_event_reactions row.
type ReactionStatus string

const (
	ReactionStatusPending      ReactionStatus = "pending"
	ReactionStatusInProgress   ReactionStatus = "in_progress"
	ReactionStatusSucceeded    ReactionStatus = "succeeded"
	ReactionStatusFailed       ReactionStatus = "failed"
	ReactionStatusDeadLettered ReactionStatus = "dead_lettered"
)

// Reactor is the declaration block on an integration_type manifest.
// One Reactor declares: "when event_type fires in core, call my capability".
type Reactor struct {
	EventType   string `json:"event_type"`
	Capability  string `json:"capability"`
	Description string `json:"description,omitempty"`
}

// IntegrationEventReaction represents a single row in
// public.integration_event_reactions.
type IntegrationEventReaction struct {
	ID                        uuid.UUID      `json:"id"`
	EventID                   uuid.UUID      `json:"event_id"`
	EventType                 string         `json:"event_type"`
	IntegrationInstanceID     uuid.UUID      `json:"integration_instance_id"`
	IntegrationTypeManifestID uuid.UUID      `json:"integration_type_manifest_id"`
	Capability                string         `json:"capability"`
	Status                    ReactionStatus `json:"status"`
	Attempt                   int            `json:"attempt"`
	NextAttemptAt             *time.Time     `json:"next_attempt_at,omitempty"`
	StartedAt                 *time.Time     `json:"started_at,omitempty"`
	FinishedAt                *time.Time     `json:"finished_at,omitempty"`
	LastError                 string         `json:"last_error,omitempty"`
	Metadata                  map[string]any `json:"metadata,omitempty"`
	CreatedAt                 time.Time      `json:"created_at"`
	UpdatedAt                 time.Time      `json:"updated_at"`
}

// ReactorContext is the `_context` block injected into every reactor payload.
// Integrations receive it alongside the event payload and use it for
// idempotency (event_id + attempt) and audit (actor + emitted_at).
type ReactorContext struct {
	EventID       string      `json:"event_id"`
	EventType     string      `json:"event_type"`
	SchemaVersion string      `json:"schema_version"`
	EmittedAt     time.Time   `json:"emitted_at"`
	Actor         *EventActor `json:"actor,omitempty"`
	Attempt       int         `json:"attempt"`
}
