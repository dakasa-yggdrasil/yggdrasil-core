package externalidentity

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

type LinkedInputs struct {
	IdentityID            uuid.UUID
	CollaboratorID        uuid.UUID
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	ReLinked              bool
	LinkedAt              time.Time
	ExternalMetadata      map[string]any
}

func BuildLinkedPayload(in LinkedInputs) map[string]any {
	p := map[string]any{
		"identity_id":             in.IdentityID.String(),
		"collaborator_id":         in.CollaboratorID.String(),
		"integration_instance_id": in.IntegrationInstanceID.String(),
		"external_id":             in.ExternalID,
		"re_linked":               in.ReLinked,
		"linked_at":               in.LinkedAt.UTC().Format(time.RFC3339),
	}
	if in.ExternalMetadata != nil {
		p["external_metadata"] = in.ExternalMetadata
	}
	return p
}

type UnlinkedInputs struct {
	IdentityID            uuid.UUID
	CollaboratorID        uuid.UUID
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	UnlinkedAt            time.Time
}

func BuildUnlinkedPayload(in UnlinkedInputs) map[string]any {
	return map[string]any{
		"identity_id":             in.IdentityID.String(),
		"collaborator_id":         in.CollaboratorID.String(),
		"integration_instance_id": in.IntegrationInstanceID.String(),
		"external_id":             in.ExternalID,
		"unlinked_at":             in.UnlinkedAt.UTC().Format(time.RFC3339),
	}
}

type DriftInputs struct {
	IdentityID            uuid.UUID
	CollaboratorID        uuid.UUID
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	DetectedAt            time.Time
}

func BuildDriftPayload(in DriftInputs) map[string]any {
	return map[string]any{
		"identity_id":             in.IdentityID.String(),
		"collaborator_id":         in.CollaboratorID.String(),
		"integration_instance_id": in.IntegrationInstanceID.String(),
		"external_id":             in.ExternalID,
		"detected_at":             in.DetectedAt.UTC().Format(time.RFC3339),
	}
}

type UnknownExternalInputs struct {
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	ExternalMetadata      map[string]any
	DetectedAt            time.Time
}

func BuildUnknownExternalPayload(in UnknownExternalInputs) map[string]any {
	p := map[string]any{
		"integration_instance_id": in.IntegrationInstanceID.String(),
		"external_id":             in.ExternalID,
		"detected_at":             in.DetectedAt.UTC().Format(time.RFC3339),
	}
	if in.ExternalMetadata != nil {
		p["external_metadata"] = in.ExternalMetadata
	}
	return p
}

type PurgedInputs struct {
	IdentityID            uuid.UUID
	CollaboratorID        uuid.UUID
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	PurgedAt              time.Time
}

func BuildPurgedPayload(in PurgedInputs) map[string]any {
	return map[string]any{
		"identity_id":             in.IdentityID.String(),
		"collaborator_id":         in.CollaboratorID.String(),
		"integration_instance_id": in.IntegrationInstanceID.String(),
		"external_id":             in.ExternalID,
		"purged_at":               in.PurgedAt.UTC().Format(time.RFC3339),
	}
}

type ConflictInputs struct {
	IntegrationInstanceID  uuid.UUID
	ExternalID             string
	IncomingCollaboratorID uuid.UUID
	ExistingCollaboratorID uuid.UUID
	DetectedAt             time.Time
}

func BuildConflictPayload(in ConflictInputs) map[string]any {
	return map[string]any{
		"integration_instance_id":  in.IntegrationInstanceID.String(),
		"external_id":              in.ExternalID,
		"incoming_collaborator_id": in.IncomingCollaboratorID.String(),
		"existing_collaborator_id": in.ExistingCollaboratorID.String(),
		"detected_at":              in.DetectedAt.UTC().Format(time.RFC3339),
	}
}

// EmitEvent persists one canon event row by opening a short tx.
// Aggregate type is derived from event type prefix (everything before the
// first dot). Payload validation happens inside repository.EmitEvent.
func EmitEvent(ctx context.Context, db *sql.DB, eventType string, aggregateID uuid.UUID, payload map[string]any) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	aggType := eventType
	if i := strings.IndexByte(eventType, '.'); i > 0 {
		aggType = eventType[:i]
	}
	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          eventType,
		AggregateType: aggType,
		AggregateID:   aggregateID.String(),
		Payload:       payload,
	}); err != nil {
		return err
	}
	return tx.Commit()
}
