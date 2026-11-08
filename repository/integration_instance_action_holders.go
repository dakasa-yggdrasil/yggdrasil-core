package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
)

// integrationInstanceWildcardAction is the team_grants action_name that means
// "every permission action of that instance" (ADR-0086).
const integrationInstanceWildcardAction = "*"

// ErrInvalidActionHolderQuery is returned when an action holder read is asked
// for a blank action or for the wildcard itself. The HTTP layer validates its
// query before it reaches this package, so this is a programming guard.
var ErrInvalidActionHolderQuery = errors.New("action holder query needs one concrete action")

// integrationInstanceActionHolderCandidatesQuery is the one set-based read
// behind GET /api/v1/tartaro/action-holders (ADR-0107). In a single statement,
// so every part of the answer comes from the same snapshot, it returns:
//
//   - whether any team_grants row on the instance is the "*" wildcard, on
//     every row (the anchor row carries it even when nobody is a candidate);
//   - every collaborator whose status is exactly "active" and who either has
//     at least one membership satisfying authorizationMembershipPredicate in
//     a team holding a grant on the instance whose action_name is the
//     requested action or "*", or carries a traits.yggdrasil_admin key.
//
// For each candidate it reports the exact-grant and wildcard-grant flags
// separately and the raw traits.yggdrasil_admin value. Whether a wildcard
// grant confers the action (the instance permission catalog) and whether the
// admin trait is god mode (the Tartaro god-mode rule) are decided by the
// caller, with the same rules the effective-actions read uses, so this
// statement never decides either on its own. Only direct memberships count,
// exactly like the effective-actions grant walk: ancestor teams confer
// nothing. The membership predicate is authorizationMembershipPredicate
// verbatim, so this roster and the effective-actions read cannot drift.
const integrationInstanceActionHolderCandidatesQuery = `
	WITH instance_grants AS (
		SELECT g.team_id, g.action_name
		FROM public.team_grants g
		WHERE g.integration_instance_namespace = $1
			AND g.integration_instance_name = $2
			AND (g.action_name = $3 OR g.action_name = '*')
	),
	granted AS (
		SELECT
			tm.collaborator_id,
			bool_or(ig.action_name = $3) AS exact_grant,
			bool_or(ig.action_name = '*') AS wildcard_grant
		FROM public.team_memberships tm
		JOIN public.teams t ON t.id = tm.team_id
		JOIN instance_grants ig ON ig.team_id = tm.team_id
		WHERE
			` + authorizationMembershipPredicate + `
		GROUP BY tm.collaborator_id
	),
	candidates AS (
		SELECT
			c.id,
			c.status,
			c.traits -> 'yggdrasil_admin' AS admin_trait,
			COALESCE(granted.exact_grant, FALSE) AS exact_grant,
			COALESCE(granted.wildcard_grant, FALSE) AS wildcard_grant
		FROM public.collaborators c
		LEFT JOIN granted ON granted.collaborator_id = c.id
		WHERE c.status = 'active'
			AND (granted.collaborator_id IS NOT NULL OR c.traits -> 'yggdrasil_admin' IS NOT NULL)
	)
	SELECT
		EXISTS (SELECT 1 FROM instance_grants WHERE action_name = '*') AS instance_has_wildcard_grant,
		candidates.id::text,
		candidates.status,
		candidates.admin_trait,
		candidates.exact_grant,
		candidates.wildcard_grant
	FROM (SELECT 1) AS anchor
	LEFT JOIN candidates ON TRUE
	ORDER BY candidates.id
`

// IntegrationInstanceActionHolderCandidate is one active collaborator who may
// hold an action on an integration instance, before the caller applies the
// catalog and god-mode rules.
type IntegrationInstanceActionHolderCandidate struct {
	CollaboratorID uuid.UUID
	Status         string
	// AdminTrait is the raw JSON value of traits.yggdrasil_admin, nil when
	// the collaborator has no such key.
	AdminTrait json.RawMessage
	// ExactGrant is true when an authorizing membership's team holds a grant
	// on the instance whose action_name equals the requested action.
	ExactGrant bool
	// WildcardGrant is true when an authorizing membership's team holds a "*"
	// grant on the instance. It confers the action only when the instance's
	// permission catalog lists that action.
	WildcardGrant bool
}

// IntegrationInstanceActionHolderCandidates is the snapshot answer of
// ListIntegrationInstanceActionHolderCandidates.
type IntegrationInstanceActionHolderCandidates struct {
	// InstanceHasWildcardGrant is true when any team_grants row on the
	// instance has action_name "*", whoever holds it.
	InstanceHasWildcardGrant bool
	// Candidates are sorted by collaborator id and unique.
	Candidates []IntegrationInstanceActionHolderCandidate
}

// ListIntegrationInstanceActionHolderCandidates reads, in one statement, the
// active collaborators who may hold action on the literal namespace/name
// integration instance (see integrationInstanceActionHolderCandidatesQuery).
// action must be a concrete action name, never blank or "*".
func ListIntegrationInstanceActionHolderCandidates(ctx context.Context, db *sql.DB, namespace, name, action string) (IntegrationInstanceActionHolderCandidates, error) {
	if strings.TrimSpace(action) == "" || action == integrationInstanceWildcardAction {
		return IntegrationInstanceActionHolderCandidates{}, ErrInvalidActionHolderQuery
	}
	rows, err := db.QueryContext(ctx, integrationInstanceActionHolderCandidatesQuery, namespace, name, action)
	if err != nil {
		return IntegrationInstanceActionHolderCandidates{}, err
	}
	defer rows.Close()

	out := IntegrationInstanceActionHolderCandidates{Candidates: []IntegrationInstanceActionHolderCandidate{}}
	seen := map[uuid.UUID]struct{}{}
	for rows.Next() {
		var (
			hasWildcard   bool
			id            sql.NullString
			status        sql.NullString
			adminTrait    []byte
			exactGrant    sql.NullBool
			wildcardGrant sql.NullBool
		)
		if err := rows.Scan(&hasWildcard, &id, &status, &adminTrait, &exactGrant, &wildcardGrant); err != nil {
			return IntegrationInstanceActionHolderCandidates{}, err
		}
		out.InstanceHasWildcardGrant = out.InstanceHasWildcardGrant || hasWildcard
		if !id.Valid {
			// The anchor row of an empty candidate set.
			continue
		}
		collaboratorID, err := uuid.Parse(id.String)
		if err != nil {
			return IntegrationInstanceActionHolderCandidates{}, err
		}
		if _, dup := seen[collaboratorID]; dup {
			continue
		}
		seen[collaboratorID] = struct{}{}
		candidate := IntegrationInstanceActionHolderCandidate{
			CollaboratorID: collaboratorID,
			Status:         status.String,
			ExactGrant:     exactGrant.Valid && exactGrant.Bool,
			WildcardGrant:  wildcardGrant.Valid && wildcardGrant.Bool,
		}
		if adminTrait != nil {
			candidate.AdminTrait = append(json.RawMessage(nil), adminTrait...)
		}
		out.Candidates = append(out.Candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return IntegrationInstanceActionHolderCandidates{}, err
	}
	return out, nil
}
