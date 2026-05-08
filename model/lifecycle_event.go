package model

import (
	"time"

	"github.com/google/uuid"
)

// Canonical lifecycle event types (spec §5.3).
const (
	LifecycleEventHired              = "hired"
	LifecycleEventOffboarded         = "offboarded"
	LifecycleEventReOnboarded        = "re-onboarded"
	LifecycleEventRoleChanged        = "role-changed"
	LifecycleEventTeamJoined         = "team-joined"
	LifecycleEventTeamLeft           = "team-left"
	LifecycleEventAttributeSet       = "attribute-set"
	LifecycleEventManagerChanged     = "manager-changed"
	LifecycleEventAbsenceStarted     = "absence-started"
	LifecycleEventAbsenceEnded       = "absence-ended"
	LifecycleEventSuspended          = "suspended"
	LifecycleEventUnsuspended        = "unsuspended"
	LifecycleEventMFAEnrolled        = "mfa-enrolled"
	LifecycleEventReconciled         = "reconciled"
	LifecycleEventOnboardingAborted  = "onboarding_aborted"
	LifecycleEventOnboardingComplete = "onboarding_complete"
)

// Canonical actor types.
const (
	ActorTypeHuman    = "human"
	ActorTypeWorkflow = "workflow"
	ActorTypeCLI      = "cli"
	ActorTypeAPI      = "api"
	ActorTypeSystem   = "system"
)

// LifecycleEvent is one append-only entry in the collaborator audit log.
type LifecycleEvent struct {
	ID             uuid.UUID      `json:"id"`
	CollaboratorID uuid.UUID      `json:"collaborator_id"`
	EventType      string         `json:"event_type"`
	Payload        map[string]any `json:"payload"`
	ActorType      string         `json:"actor_type"`
	ActorID        string         `json:"actor_id"`
	OccurredAt     time.Time      `json:"occurred_at"`
	EffectiveAt    time.Time      `json:"effective_at"`
}

// AppendLifecycleEventRequest is the input to repository.AppendLifecycleEvent.
// EffectiveAt may be zero — repository defaults to NOW().
type AppendLifecycleEventRequest struct {
	CollaboratorID uuid.UUID      `json:"collaborator_id"`
	EventType      string         `json:"event_type"`
	Payload        map[string]any `json:"payload,omitempty"`
	ActorType      string         `json:"actor_type"`
	ActorID        string         `json:"actor_id,omitempty"`
	EffectiveAt    *time.Time     `json:"effective_at,omitempty"`
}

// ListLifecycleEventsRequest filters the audit log query.
type ListLifecycleEventsRequest struct {
	CollaboratorID uuid.UUID `json:"collaborator_id"`
	EventType      string    `json:"event_type,omitempty"`
	Limit          int       `json:"limit,omitempty"`
}
