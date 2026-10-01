package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

// CollaboratorProvisioningIdentity is an internal, deliberately narrow source
// projection. The workflow engine must not receive the collaborator's raw
// personal_data, employment_data, traits, metadata, or provider identities.
type CollaboratorProvisioningIdentity struct {
	ID           uuid.UUID
	Status       string
	DisplayName  string
	PrimaryEmail string
	GivenName    string
	FamilyName   string
}

// ListCollaboratorProvisioningIdentities reads at most limit+1 rows so the
// caller can refuse an oversized snapshot without silently omitting people.
func ListCollaboratorProvisioningIdentities(
	ctx context.Context,
	db *sql.DB,
	limit int,
) ([]CollaboratorProvisioningIdentity, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, status, display_name, primary_email,
			COALESCE(
				NULLIF(personal_data->'profile'->>'given_name', ''),
				NULLIF(personal_data->'profile'->>'first_name', ''),
				NULLIF(personal_data->>'given_name', ''),
				personal_data->>'first_name', ''
			),
			COALESCE(
				NULLIF(personal_data->'profile'->>'family_name', ''),
				NULLIF(personal_data->'profile'->>'last_name', ''),
				NULLIF(personal_data->>'family_name', ''),
				personal_data->>'last_name', ''
			)
		FROM public.collaborators
		ORDER BY id
		LIMIT $1
	`, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	identities := make([]CollaboratorProvisioningIdentity, 0)
	for rows.Next() {
		var identity CollaboratorProvisioningIdentity
		if err := rows.Scan(
			&identity.ID,
			&identity.Status,
			&identity.DisplayName,
			&identity.PrimaryEmail,
			&identity.GivenName,
			&identity.FamilyName,
		); err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return identities, nil
}
