package oidc

import (
	"context"
	"database/sql"
	"encoding/json"
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

// buildRoleClaim returns the collaborator's primary role (column on the
// collaborators row, populated by migration 00022). Empty string when the
// collaborator has no role assigned.
func buildRoleClaim(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) (string, error) {
	var role string
	if err := db.QueryRowContext(ctx, `
		SELECT COALESCE(role, '')
		FROM public.collaborators
		WHERE id = $1
	`, collaboratorID).Scan(&role); err != nil {
		return "", fmt.Errorf("query role: %w", err)
	}
	return role, nil
}

// buildPermissionsClaim resolves the effective permission set for a
// collaborator by joining their primary role + every team membership against
// role_permission_bindings. Returns sorted-distinct slugs.
func buildPermissionsClaim(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		WITH subjects AS (
			SELECT 'role:' || NULLIF(c.role, '') AS subject
			FROM public.collaborators c
			WHERE c.id = $1 AND COALESCE(c.role, '') <> ''
			UNION
			SELECT 'team:' || t.slug AS subject
			FROM public.team_memberships tm
			JOIN public.teams t ON t.id = tm.team_id
			WHERE tm.collaborator_id = $1 AND tm.active = TRUE
		)
		SELECT DISTINCT pc.slug
		FROM public.role_permission_bindings rpb
		JOIN public.permissions_catalog pc ON pc.id = rpb.permission_id
		JOIN subjects s ON s.subject = rpb.subject
		WHERE rpb.revoked_at IS NULL
		ORDER BY pc.slug
	`, collaboratorID)
	if err != nil {
		// Permission catalog tables may not exist in older deployments; treat
		// as empty rather than failing the whole token mint.
		return []string{}, nil
	}
	defer rows.Close()
	out := make([]string, 0)
	for rows.Next() {
		var slug string
		if err := rows.Scan(&slug); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		out = append(out, slug)
	}
	return out, rows.Err()
}

// buildPictureClaim resolves the collaborator's avatar URL for the standard
// OIDC "picture" claim, best-effort. Precedence (first non-empty wins):
//  1. personal_data ->> 'avatar_url'
//  2. personal_data -> 'profile' ->> 'avatar_url'
//  3. the first linked third-party identity's avatar_url (relational
//     collaborator_third_party_identities table, oldest link first; falls
//     back to the third_party_identities JSONB column on the collaborators
//     row when it carries an array shape).
//
// Returns "" (never an error that fails the mint) when no avatar is found or
// the lookup hits a missing-column/missing-table older deployment.
func buildPictureClaim(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) (string, error) {
	var picture string
	err := db.QueryRowContext(ctx, `
		SELECT COALESCE(
			NULLIF(c.personal_data ->> 'avatar_url', ''),
			NULLIF(c.personal_data -> 'profile' ->> 'avatar_url', ''),
			NULLIF((
				SELECT tpi.avatar_url
				FROM public.collaborator_third_party_identities tpi
				WHERE tpi.collaborator_id = c.id
				  AND COALESCE(tpi.avatar_url, '') <> ''
				ORDER BY tpi.created_at ASC
				LIMIT 1
			), ''),
			NULLIF(CASE
				WHEN jsonb_typeof(c.third_party_identities) = 'array'
				THEN c.third_party_identities -> 0 ->> 'avatar_url'
				ELSE NULL
			END, ''),
			''
		)
		FROM public.collaborators c
		WHERE c.id = $1
	`, collaboratorID).Scan(&picture)
	if err != nil {
		// Missing column / table on an older deployment, or no row: degrade
		// to no picture rather than failing the whole token mint.
		return "", nil
	}
	return picture, nil
}

// buildAttributesClaim returns the collaborator's traits JSONB as a typed map.
func buildAttributesClaim(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) (map[string]any, error) {
	var raw []byte
	if err := db.QueryRowContext(ctx, `
		SELECT COALESCE(traits, '{}'::jsonb)::text
		FROM public.collaborators
		WHERE id = $1
	`, collaboratorID).Scan(&raw); err != nil {
		return nil, fmt.Errorf("query traits: %w", err)
	}
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}, nil
	}
	return out, nil
}
