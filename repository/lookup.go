package repository

import (
	"context"
	"database/sql"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// LookupCollaboratorByIdentifier returns the collaborator matching primary_email
// (case-insensitive) or slug. Returns (nil, nil) on no match — intentionally
// anti-enum-friendly so callers cannot distinguish "not found" from other branches.
func LookupCollaboratorByIdentifier(ctx context.Context, db *sql.DB, identifier string) (*model.Collaborator, error) {
	row := db.QueryRowContext(ctx, `
		SELECT
			id,
			slug,
			status,
			display_name,
			primary_email,
			manager_id,
			primary_team_id,
			personal_data,
			employment_data,
			third_party_identities,
			traits,
			metadata,
			version,
			created_at,
			updated_at
		FROM collaborators
		WHERE LOWER(primary_email) = LOWER($1) OR slug = $1
		LIMIT 1
	`, identifier)

	c, err := scanCollaborator(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &c, nil
}
