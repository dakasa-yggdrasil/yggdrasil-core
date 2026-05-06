package oidc

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// loadCollaboratorForUserinfo fetches the minimal collaborator profile we
// surface in /userinfo responses. Returned email/displayName are empty
// strings when the collaborator can't be located — callers decide whether
// to error or fall back to a token-only response.
func loadCollaboratorForUserinfo(ctx context.Context, db *sql.DB, userID string) (id uuid.UUID, email, displayName string, err error) {
	parsed, err := uuid.Parse(userID)
	if err != nil {
		return uuid.Nil, "", "", fmt.Errorf("invalid user id: %w", err)
	}
	c, err := repository.GetCollaborator(ctx, db, parsed.String())
	if err != nil {
		return uuid.Nil, "", "", err
	}
	return c.ID, c.PrimaryEmail, c.DisplayName, nil
}

// buildTeamsClaim returns the slugs of the (active) teams the collaborator
// belongs to. Used to populate the "teams" custom claim when the "roles"
// scope is granted. Returns an empty slice (never nil) when the user has
// no memberships — that's a meaningful signal for downstream consumers.
func buildTeamsClaim(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT t.slug
		FROM team_memberships tm
		JOIN teams t ON t.id = tm.team_id
		WHERE tm.collaborator_id = $1 AND tm.active = TRUE
		ORDER BY t.slug
	`, collaboratorID)
	if err != nil {
		return nil, fmt.Errorf("query team memberships: %w", err)
	}
	defer rows.Close()
	slugs := make([]string, 0)
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan team slug: %w", err)
		}
		slugs = append(slugs, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows.Err: %w", err)
	}
	return slugs, nil
}

// scopesContains reports whether scope appears in scopes.
func scopesContains(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
