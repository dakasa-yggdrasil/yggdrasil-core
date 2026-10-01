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
	PrimaryEmail string
}

// ListCollaboratorProvisioningIdentities reads at most limit+1 rows so the
// caller can refuse an oversized snapshot without silently omitting people.
func ListCollaboratorProvisioningIdentities(
	ctx context.Context,
	db *sql.DB,
	workflowID uuid.UUID,
	limit int,
) ([]CollaboratorProvisioningIdentity, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// The row lock makes this read linearize with manifest replacement:
	// activation/deactivation updates the same row and must wait until the
	// projection has been read. Under READ COMMITTED, a concurrent update
	// that wins first makes this exact-ID query return no row.
	var activeID uuid.UUID
	if err := tx.QueryRowContext(ctx, `
		SELECT id FROM public.manifests
		WHERE id = $1 AND kind = 'workflow' AND namespace = 'dakasa'
			AND name = 'reconcile-identity-providers' AND active = TRUE
		FOR SHARE
	`, workflowID).Scan(&activeID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT id, status, primary_email
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
			&identity.PrimaryEmail,
		); err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return identities, nil
}
