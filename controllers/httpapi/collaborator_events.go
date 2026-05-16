// Package httpapi — emit helpers use an own-tx pattern by design.
//
// # Atomicity deviation (accepted, tracked)
//
// The spec for the lifecycle-reactor framework requires that state mutation and
// event emission occur inside a single database transaction so that a crash
// between the two operations cannot produce a collaborator/team whose lifecycle
// event was never emitted.
//
// Achieving true same-tx atomicity would require plumbing a *sql.Tx through
// every repository function (UpdateCollaborator, CreateTeam, DeleteTeam,
// UpsertTeamMembership, GetCollaborator, resolveOptional*, …) — at least 54
// call sites across the codebase — introducing substantial regression risk with
// no net-new observable value in the current deployment topology.
//
// Safety net: every emit helper treats failures as non-fatal (logged as Warn).
// A daily reconciliation cron (see internal/reconciler) cross-checks
// collaborator/team state against event_log and re-emits any missing events,
// providing an eventual-consistency guarantee. The same own-tx approach is
// the pre-existing convention for credential lifecycle events in this codebase.
//
// If atomicity becomes a hard requirement (e.g., the reconciliation SLA is
// tightened), the correct fix is to extract a sqlutil.Querier interface and
// migrate all repository functions to accept it — that refactor is tracked
// separately and must be done in isolation with full test coverage.
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

// emitCollaboratorAbsenceStarted inserts a collaborator.absence_started event
// into event_log. absenceType, from, to are from the request; durationDays is
// included when non-zero. Failure is non-fatal to the caller.
func emitCollaboratorAbsenceStarted(ctx context.Context, db *sql.DB, collab model.Collaborator, absenceType, from, to string, durationDays int) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for collaborator.absence_started emit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]interface{}{
		"collaborator_id": collab.ID.String(),
		"type":            absenceType,
	}
	if collab.PrimaryEmail != "" {
		payload["primary_email"] = collab.PrimaryEmail
	}
	if from != "" {
		payload["from"] = from
	}
	if to != "" {
		payload["to"] = to
	}
	if durationDays > 0 {
		payload["duration_days"] = durationDays
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeCollaboratorAbsenceStarted,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collab.ID.String(),
		Payload:       payload,
	}); err != nil {
		return fmt.Errorf("emit collaborator.absence_started: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit collaborator.absence_started emit: %w", err)
	}

	return nil
}

// emitCollaboratorAbsenceEnded inserts a collaborator.absence_ended event
// into event_log. Failure is non-fatal to the caller.
func emitCollaboratorAbsenceEnded(ctx context.Context, db *sql.DB, collab model.Collaborator) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for collaborator.absence_ended emit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]interface{}{
		"collaborator_id": collab.ID.String(),
	}
	if collab.PrimaryEmail != "" {
		payload["primary_email"] = collab.PrimaryEmail
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeCollaboratorAbsenceEnded,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collab.ID.String(),
		Payload:       payload,
	}); err != nil {
		return fmt.Errorf("emit collaborator.absence_ended: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit collaborator.absence_ended emit: %w", err)
	}

	return nil
}

// emitCollaboratorRoleChanged inserts a collaborator.role_changed event into
// event_log. roleFrom may be empty if the previous role was not set.
// Failure is non-fatal to the caller.
func emitCollaboratorRoleChanged(ctx context.Context, db *sql.DB, collab model.Collaborator, roleFrom, roleTo string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for collaborator.role_changed emit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]interface{}{
		"collaborator_id": collab.ID.String(),
		"role_to":         roleTo,
	}
	if collab.PrimaryEmail != "" {
		payload["primary_email"] = collab.PrimaryEmail
	}
	if roleFrom != "" {
		payload["role_from"] = roleFrom
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeCollaboratorRoleChanged,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collab.ID.String(),
		Payload:       payload,
	}); err != nil {
		return fmt.Errorf("emit collaborator.role_changed: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit collaborator.role_changed emit: %w", err)
	}

	return nil
}

// emitCollaboratorReOnboarded inserts a collaborator.re_onboarded event into
// event_log. previousOffboardedAt is the collaborator's last offboarded timestamp
// if retrievable; pass zero-value to omit. Failure is non-fatal to the caller.
func emitCollaboratorReOnboarded(ctx context.Context, db *sql.DB, collab model.Collaborator) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx for collaborator.re_onboarded emit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]interface{}{
		"collaborator_id": collab.ID.String(),
	}
	if collab.PrimaryEmail != "" {
		payload["primary_email"] = collab.PrimaryEmail
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeCollaboratorReOnboarded,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collab.ID.String(),
		Payload:       payload,
	}); err != nil {
		return fmt.Errorf("emit collaborator.re_onboarded: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit collaborator.re_onboarded emit: %w", err)
	}

	return nil
}
