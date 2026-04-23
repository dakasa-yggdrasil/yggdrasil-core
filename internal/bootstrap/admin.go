package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// ensureFirstAdmin creates the configured admin collaborator + password
// credential, but only when the collaborators table is empty. The
// "database is empty" gate is what makes the startup hook safe — a
// pre-existing deployment that restarts with env vars still present does
// not duplicate admins or reset the password.
//
// Returns (created, collaborator, err):
//
//   - created=false with no error when the collaborator table already
//     has rows (no-op, idempotent).
//   - created=true with the fresh collaborator record when we did create.
//   - err=ErrNoAdminPassword when the password is missing (caller misuse).
func ensureFirstAdmin(ctx context.Context, db *sql.DB, cfg Config) (bool, model.Collaborator, error) {
	if strings.TrimSpace(cfg.AdminPassword) == "" {
		return false, model.Collaborator{}, ErrNoAdminPassword
	}

	empty, err := IsEmpty(ctx, db)
	if err != nil {
		return false, model.Collaborator{}, err
	}
	if !empty {
		return false, model.Collaborator{}, nil
	}

	displayName := strings.TrimSpace(cfg.AdminDisplayName)
	if displayName == "" {
		displayName = "Admin"
	}

	collab, err := repository.CreateCollaborator(ctx, db, model.CreateCollaboratorRequest{
		Slug:         strings.ToLower(strings.TrimSpace(cfg.AdminUsername)),
		Status:       "active",
		DisplayName:  displayName,
		PrimaryEmail: strings.TrimSpace(cfg.AdminEmail),
		Metadata: map[string]any{
			"source": "bootstrap.first_run",
		},
	})
	if err != nil {
		return false, model.Collaborator{}, fmt.Errorf("create admin collaborator: %w", err)
	}

	if _, _, err := repository.UpsertPasswordCredential(ctx, db, model.UpsertPasswordCredentialRequest{
		CollaboratorID: collab.ID.String(),
		Password:       cfg.AdminPassword,
		Status:         "active",
		Metadata: map[string]any{
			"source": "bootstrap.first_run",
		},
	}); err != nil {
		return false, model.Collaborator{}, fmt.Errorf("set admin password: %w", err)
	}

	return true, collab, nil
}
