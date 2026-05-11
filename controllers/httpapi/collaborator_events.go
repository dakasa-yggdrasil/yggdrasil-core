package httpapi

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// emitCollaboratorCreated inserts a collaborator.created event into event_log
// inside its own short-lived transaction. Called after CreateCollaborator
// commits so the collaborator row is guaranteed to exist. If the emit fails,
// the error is returned to the caller (which treats it as non-fatal and logs
// a warning); the collaborator is NOT rolled back.
func emitCollaboratorCreated(ctx context.Context, db *sql.DB, collab model.Collaborator, actorID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for collaborator.created emit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]interface{}{
		"collaborator_id": collab.ID.String(),
		"slug":            collab.Slug,
		"display_name":    collab.DisplayName,
	}
	if collab.PrimaryEmail != "" {
		payload["primary_email"] = collab.PrimaryEmail
	}
	if collab.Status != "" {
		payload["status"] = collab.Status
	}

	var actor *model.EventActor
	if actorID != "" {
		actor = &model.EventActor{Type: "api", ID: actorID}
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          "collaborator.created",
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collab.ID.String(),
		Actor:         actor,
		Payload:       payload,
	}); err != nil {
		return fmt.Errorf("emit collaborator.created: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit collaborator.created emit: %w", err)
	}

	return nil
}

// emitCollaboratorOffboarded inserts a collaborator.offboarded event into
// event_log inside its own short-lived transaction. Called after the
// offboard status update commits. Failure is non-fatal to the caller.
func emitCollaboratorOffboarded(ctx context.Context, db *sql.DB, collab model.Collaborator, reason, endDate string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for collaborator.offboarded emit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]interface{}{
		"collaborator_id": collab.ID.String(),
		"reason":          reason,
	}
	if collab.PrimaryEmail != "" {
		payload["primary_email"] = collab.PrimaryEmail
	}
	if endDate != "" {
		payload["end_date"] = endDate
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          "collaborator.offboarded",
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collab.ID.String(),
		Payload:       payload,
	}); err != nil {
		return fmt.Errorf("emit collaborator.offboarded: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit collaborator.offboarded emit: %w", err)
	}

	return nil
}
