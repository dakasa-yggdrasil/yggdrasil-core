package httpapi

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// emitTeamCreated inserts a team.created event into event_log inside its own
// short-lived transaction. Called after CreateTeam commits. Failure is
// non-fatal: the team row is already persisted; the daily reconciliation is
// the safety net for any missed emissions.
func emitTeamCreated(ctx context.Context, db *sql.DB, team model.Team) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for team.created emit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]interface{}{
		"id":   team.ID.String(),
		"slug": team.Slug,
		"name": team.Name,
		"type": team.Type,
	}
	if team.ParentTeamID != nil {
		payload["parent_team_id"] = team.ParentTeamID.String()
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamCreated,
		SchemaVersion: "v1",
		AggregateType: "team",
		AggregateID:   team.ID.String(),
		Payload:       payload,
	}); err != nil {
		return fmt.Errorf("emit team.created: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit team.created emit: %w", err)
	}

	return nil
}

// emitTeamUpdated inserts a team.updated event into event_log inside its own
// short-lived transaction. changedFields contains the set of fields that were
// present in the PATCH request (key → new value after update). Failure is
// non-fatal to the caller.
func emitTeamUpdated(ctx context.Context, db *sql.DB, team model.Team, changedFields map[string]any) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for team.updated emit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]interface{}{
		"id":             team.ID.String(),
		"slug":           team.Slug,
		"changed_fields": changedFields,
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamUpdated,
		SchemaVersion: "v1",
		AggregateType: "team",
		AggregateID:   team.ID.String(),
		Payload:       payload,
	}); err != nil {
		return fmt.Errorf("emit team.updated: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit team.updated emit: %w", err)
	}

	return nil
}

// emitTeamDeleted inserts a team.deleted event into event_log inside its own
// short-lived transaction. The team row is already removed when this is called.
// Failure is non-fatal to the caller.
func emitTeamDeleted(ctx context.Context, db *sql.DB, team model.Team) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for team.deleted emit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]interface{}{
		"id":   team.ID.String(),
		"slug": team.Slug,
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamDeleted,
		SchemaVersion: "v1",
		AggregateType: "team",
		AggregateID:   team.ID.String(),
		Payload:       payload,
	}); err != nil {
		return fmt.Errorf("emit team.deleted: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit team.deleted emit: %w", err)
	}

	return nil
}

// emitTeamMembershipAdded inserts a team_membership.added event into event_log
// inside its own short-lived transaction. Failure is non-fatal to the caller.
func emitTeamMembershipAdded(ctx context.Context, db *sql.DB, membership model.TeamMembership, source string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for team_membership.added emit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]interface{}{
		"collaborator_id": membership.CollaboratorID.String(),
		"team_id":         membership.TeamID.String(),
		"role":            membership.Role,
		"source":          source,
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamMembershipAdded,
		SchemaVersion: "v1",
		AggregateType: "team_membership",
		AggregateID:   membership.ID.String(),
		Payload:       payload,
	}); err != nil {
		return fmt.Errorf("emit team_membership.added: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit team_membership.added emit: %w", err)
	}

	return nil
}

// emitTeamMembershipRemoved inserts a team_membership.removed event into
// event_log inside its own short-lived transaction. Failure is non-fatal to
// the caller.
func emitTeamMembershipRemoved(ctx context.Context, db *sql.DB, membership model.TeamMembership) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for team_membership.removed emit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]interface{}{
		"collaborator_id": membership.CollaboratorID.String(),
		"team_id":         membership.TeamID.String(),
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamMembershipRemoved,
		SchemaVersion: "v1",
		AggregateType: "team_membership",
		AggregateID:   membership.ID.String(),
		Payload:       payload,
	}); err != nil {
		return fmt.Errorf("emit team_membership.removed: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit team_membership.removed emit: %w", err)
	}

	return nil
}
