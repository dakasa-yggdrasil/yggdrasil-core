// Package externalidentity manages the collaborator_external_identities
// table — a generic mapping of (collaborator, integration_instance) to a
// provider-side stable identifier plus mutable metadata.
//
// See docs/superpowers/specs/2026-05-16-collaborator-external-identities-design.md.
package externalidentity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Identity is one row of collaborator_external_identities.
type Identity struct {
	ID                    uuid.UUID
	CollaboratorID        uuid.UUID
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	ExternalMetadata      map[string]any
	LinkedAt              time.Time
	LastSeenAt            time.Time
	UnlinkedAt            *time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// UpsertInput is the per-write payload for the idempotent UPSERT.
type UpsertInput struct {
	CollaboratorID        uuid.UUID
	IntegrationInstanceID uuid.UUID
	ExternalID            string
	ExternalMetadata      map[string]any
}

// UpsertOutcome reports what happened. Returned by Upsert so callers can
// emit the appropriate event (linked vs re_linked vs refreshed) or handle
// conflicts.
type UpsertOutcome string

const (
	OutcomeInserted  UpsertOutcome = "inserted"
	OutcomeReLinked  UpsertOutcome = "re_linked"
	OutcomeRefreshed UpsertOutcome = "refreshed"
	OutcomeConflict  UpsertOutcome = "conflict"
)

// ConflictError is returned when Upsert sees an active row with the same
// (instance, external_id) bound to a DIFFERENT collaborator. Neither row
// is mutated; caller decides whether to alert operators or override.
type ConflictError struct {
	IntegrationInstanceID  uuid.UUID
	ExternalID             string
	IncomingCollaboratorID uuid.UUID
	ExistingCollaboratorID uuid.UUID
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("collaborator_external_identity: %s in instance %s is already active on collaborator %s (attempted: %s)",
		e.ExternalID, e.IntegrationInstanceID, e.ExistingCollaboratorID, e.IncomingCollaboratorID)
}

// ListFilters drives List and the dispatcher's pre-populate lookup.
type ListFilters struct {
	CollaboratorID        *uuid.UUID
	IntegrationInstanceID *uuid.UUID
	TypeName              string
	ActiveOnly            bool
	Limit                 int
	Offset                int
}

// Upsert is the idempotent write entry point (spec §5.1).
func Upsert(ctx context.Context, db *sql.DB, in UpsertInput) (uuid.UUID, UpsertOutcome, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	metaJSON, err := json.Marshal(in.ExternalMetadata)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("marshal metadata: %w", err)
	}

	var existingID uuid.UUID
	var existingCollab uuid.UUID
	row := tx.QueryRowContext(ctx, `
		SELECT id, collaborator_id FROM collaborator_external_identities
		WHERE integration_instance_id = $1 AND external_id = $2 AND unlinked_at IS NULL
	`, in.IntegrationInstanceID, in.ExternalID)
	err = row.Scan(&existingID, &existingCollab)
	if err == nil {
		if existingCollab != in.CollaboratorID {
			return uuid.Nil, OutcomeConflict, &ConflictError{
				IntegrationInstanceID:  in.IntegrationInstanceID,
				ExternalID:             in.ExternalID,
				IncomingCollaboratorID: in.CollaboratorID,
				ExistingCollaboratorID: existingCollab,
			}
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE collaborator_external_identities
			SET external_metadata = $1, last_seen_at = NOW(), updated_at = NOW()
			WHERE id = $2
		`, metaJSON, existingID); err != nil {
			return uuid.Nil, "", fmt.Errorf("refresh metadata: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return uuid.Nil, "", fmt.Errorf("commit: %w", err)
		}
		return existingID, OutcomeRefreshed, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, "", fmt.Errorf("lookup active: %w", err)
	}

	row = tx.QueryRowContext(ctx, `
		SELECT id FROM collaborator_external_identities
		WHERE collaborator_id = $1 AND integration_instance_id = $2 AND external_id = $3
		  AND unlinked_at IS NOT NULL
		ORDER BY linked_at DESC LIMIT 1
	`, in.CollaboratorID, in.IntegrationInstanceID, in.ExternalID)
	if err := row.Scan(&existingID); err == nil {
		if _, err := tx.ExecContext(ctx, `
			UPDATE collaborator_external_identities
			SET unlinked_at = NULL, external_metadata = $1, last_seen_at = NOW(), updated_at = NOW()
			WHERE id = $2
		`, metaJSON, existingID); err != nil {
			return uuid.Nil, "", fmt.Errorf("re-link: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return uuid.Nil, "", fmt.Errorf("commit: %w", err)
		}
		return existingID, OutcomeReLinked, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, "", fmt.Errorf("lookup unlinked: %w", err)
	}

	newID := uuid.New()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO collaborator_external_identities
		  (id, collaborator_id, integration_instance_id, external_id, external_metadata)
		VALUES ($1, $2, $3, $4, $5)
	`, newID, in.CollaboratorID, in.IntegrationInstanceID, in.ExternalID, metaJSON); err != nil {
		return uuid.Nil, "", fmt.Errorf("insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return uuid.Nil, "", fmt.Errorf("commit: %w", err)
	}
	return newID, OutcomeInserted, nil
}

// GetByID returns the identity matching id, or sql.ErrNoRows.
func GetByID(ctx context.Context, db *sql.DB, id uuid.UUID) (Identity, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, collaborator_id, integration_instance_id, external_id,
		       external_metadata, linked_at, last_seen_at, unlinked_at,
		       created_at, updated_at
		FROM collaborator_external_identities
		WHERE id = $1
	`, id)
	return scanIdentity(row)
}

// ActiveFor returns the active (unlinked_at IS NULL) identity for the
// (collaborator, integration_instance) pair, or nil when none. Used by
// the reactor dispatcher to pre-populate _context.external_identity.
func ActiveFor(ctx context.Context, db *sql.DB, collaboratorID, integrationInstanceID uuid.UUID) (*Identity, error) {
	rows, err := List(ctx, db, ListFilters{
		CollaboratorID:        &collaboratorID,
		IntegrationInstanceID: &integrationInstanceID,
		ActiveOnly:            true,
		Limit:                 1,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// SoftDelete sets unlinked_at=NOW. Idempotent on a row already soft-deleted.
func SoftDelete(ctx context.Context, db *sql.DB, id uuid.UUID) (Identity, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Identity{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	row := tx.QueryRowContext(ctx, `
		SELECT id, collaborator_id, integration_instance_id, external_id,
		       external_metadata, linked_at, last_seen_at, unlinked_at,
		       created_at, updated_at
		FROM collaborator_external_identities
		WHERE id = $1 FOR UPDATE
	`, id)
	identity, err := scanIdentity(row)
	if err != nil {
		return Identity{}, err
	}
	if identity.UnlinkedAt != nil {
		return identity, tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE collaborator_external_identities
		SET unlinked_at = NOW(), updated_at = NOW()
		WHERE id = $1
	`, id); err != nil {
		return Identity{}, err
	}
	if err := tx.Commit(); err != nil {
		return Identity{}, err
	}
	now := time.Now().UTC()
	identity.UnlinkedAt = &now
	return identity, nil
}

// HardDelete removes the row.
func HardDelete(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM collaborator_external_identities WHERE id = $1`, id)
	return err
}

// HardCleanup deletes rows whose unlinked_at < before. Returns identifying
// info of deleted rows so the caller can emit purged events.
func HardCleanup(ctx context.Context, db *sql.DB, before time.Time) ([]Identity, error) {
	rows, err := db.QueryContext(ctx, `
		DELETE FROM collaborator_external_identities
		WHERE unlinked_at IS NOT NULL AND unlinked_at < $1
		RETURNING id, collaborator_id, integration_instance_id, external_id,
		          external_metadata, linked_at, last_seen_at, unlinked_at,
		          created_at, updated_at
	`, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Identity
	for rows.Next() {
		i, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// List returns identities matching the filters.
func List(ctx context.Context, db *sql.DB, f ListFilters) ([]Identity, error) {
	q := `SELECT id, collaborator_id, integration_instance_id, external_id,
	             external_metadata, linked_at, last_seen_at, unlinked_at,
	             created_at, updated_at
	      FROM collaborator_external_identities WHERE 1=1`
	args := []any{}
	idx := 1
	if f.CollaboratorID != nil {
		q += fmt.Sprintf(" AND collaborator_id = $%d", idx)
		args = append(args, *f.CollaboratorID)
		idx++
	}
	if f.IntegrationInstanceID != nil {
		q += fmt.Sprintf(" AND integration_instance_id = $%d", idx)
		args = append(args, *f.IntegrationInstanceID)
		idx++
	}
	if f.ActiveOnly {
		q += " AND unlinked_at IS NULL"
	}
	if f.TypeName != "" {
		q += fmt.Sprintf(`
			AND integration_instance_id IN (
				SELECT id FROM manifests
				WHERE kind = 'integration_instance' AND active = true
				  AND spec->'type_ref'->>'name' = $%d
			)`, idx)
		args = append(args, f.TypeName)
		idx++
	}
	q += " ORDER BY linked_at DESC"
	if f.Limit > 0 {
		q += fmt.Sprintf(" LIMIT $%d", idx)
		args = append(args, f.Limit)
		idx++
	}
	if f.Offset > 0 {
		q += fmt.Sprintf(" OFFSET $%d", idx)
		args = append(args, f.Offset)
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Identity
	for rows.Next() {
		i, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func scanIdentity(row interface{ Scan(...any) error }) (Identity, error) {
	var i Identity
	var meta []byte
	var unlinked sql.NullTime
	err := row.Scan(&i.ID, &i.CollaboratorID, &i.IntegrationInstanceID,
		&i.ExternalID, &meta, &i.LinkedAt, &i.LastSeenAt, &unlinked,
		&i.CreatedAt, &i.UpdatedAt)
	if err != nil {
		return Identity{}, err
	}
	if unlinked.Valid {
		i.UnlinkedAt = &unlinked.Time
	}
	if len(meta) > 0 {
		_ = json.Unmarshal(meta, &i.ExternalMetadata)
	}
	if i.ExternalMetadata == nil {
		i.ExternalMetadata = map[string]any{}
	}
	return i, nil
}
