package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ListActiveCollaboratorsByPrimaryEmail returns active collaborators whose
// primary_email equals the given address, compared case-insensitively through
// the same LOWER(primary_email) expression the collaborators_primary_email_uidx
// unique index is built on. It is an exact match: no pattern, prefix, or
// display-name search. Callers pass a small limit; because the index is unique
// among non-empty addresses, more than one returned row is an invariant
// violation the caller must treat as ambiguous rather than pick from.
func ListActiveCollaboratorsByPrimaryEmail(ctx context.Context, db *sql.DB, email string, limit int) ([]model.Collaborator, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, fmt.Errorf("collaborator primary email is required")
	}
	if limit <= 0 {
		limit = 1
	}

	rows, err := db.QueryContext(ctx, `
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
		FROM public.collaborators
		WHERE LOWER(primary_email) = LOWER($1)
			AND status = 'active'
		ORDER BY created_at ASC, id ASC
		LIMIT $2
	`, email, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	collaborators := []model.Collaborator{}
	for rows.Next() {
		collaborator, err := scanCollaborator(rows)
		if err != nil {
			return nil, err
		}
		collaborators = append(collaborators, collaborator)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return collaborators, nil
}

// ListAuthorizationTeamMemberships returns the collaborator's team
// memberships that confer authority right now, under exactly the predicate
// the RBAC subject projection applies (authorizationMembershipPredicate):
// membership active, team active, NOW() inside the starts_at/ends_at window.
// It is the membership source of the directory machine oracle, so a machine
// caller never reads actions from an expired, not-yet-started, or
// deactivated-team membership that Yggdrasil's own authorization would refuse.
func ListAuthorizationTeamMemberships(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) ([]model.TeamMembership, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			tm.id,
			tm.team_id,
			t.slug,
			tm.collaborator_id,
			c.slug,
			tm.role,
			tm.active,
			tm.source,
			tm.starts_at,
			tm.ends_at,
			tm.metadata,
			tm.created_at,
			tm.updated_at
		FROM public.team_memberships tm
		JOIN public.teams t ON t.id = tm.team_id
		JOIN public.collaborators c ON c.id = tm.collaborator_id
		WHERE
			tm.collaborator_id = $1
			AND `+authorizationMembershipPredicate+`
		ORDER BY t.slug, c.slug
	`, collaboratorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	memberships := []model.TeamMembership{}
	for rows.Next() {
		membership, err := scanTeamMembership(rows)
		if err != nil {
			return nil, err
		}
		memberships = append(memberships, membership)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return memberships, nil
}
