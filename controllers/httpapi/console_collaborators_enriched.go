package httpapi

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Phase 6 aggregator — audit 2026-05-27 §2.3.
//
// CollaboratorListPage previously fetched THREE datasets:
//
//   1. fetchCollaborators()    — the collaborator rows
//   2. fetchTeams()            — to resolve team names from membership rows
//   3. fetchTeamMemberships()  — to know which collaborator belongs where
//
// The FE then merged client-side via toCollaborator → primaryTeamName().
// This denormalizes the data server-side: each collaborator carries
// team_names[], primary_role, last_login_at, mfa_enrolled directly.
//
// Permission gate: yggdrasil:view_people (existing handler-level gate
// continues to apply via requireOpsPermissionFunc).
//
// Triggered by ?enriched=true on /api/v1/console/collaborators. The
// surface refactor passes this flag; legacy callers (CLI, ops tools)
// keep the old shape and the FE refactor goes opt-in.

// CollaboratorEnriched is the denormalized shape returned when
// ?enriched=true is set. Mirrors model.Collaborator with four extra
// computed fields. Fields are JSON-shaped to match the TS surface
// (snake_case throughout).
type CollaboratorEnriched struct {
	model.Collaborator
	TeamNames   []string   `json:"team_names"`
	PrimaryRole string     `json:"primary_role"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	MFAEnrolled bool       `json:"mfa_enrolled"`
}

// collaboratorEnrichedResponse keeps the envelope key `collaborators`
// identical to the legacy response shape so the FE only has to swap
// the row type.
type collaboratorEnrichedResponse struct {
	Collaborators []CollaboratorEnriched     `json:"collaborators"`
	Pagination    *model.PaginationResponse  `json:"pagination,omitempty"`
}

// enrichCollaborators decorates a slice of collaborators with team
// names + auth identity facts in TWO batch queries — one for
// team_memberships joined to teams (so we get the names without a
// separate teams listing), one for auth_identities. Both are scoped
// to the collaborator IDs present in the input slice. Total round-trips
// to the DB: 2 (vs the 3 the FE was doing for unscoped datasets).
//
// Canonical primary_role resolution mirrors §1.2 of the 2026-05-27
// audit: traits.tartaro_roles[0] → traits.roles[0] → traits.role →
// employment_data.role → metadata.roles[0] → metadata.role → "".
// This collapses the FE's 6-fallback path into one server-computed
// field so each surface page doesn't reinvent it.
func enrichCollaborators(ctx context.Context, db *sql.DB, collabs []model.Collaborator) ([]CollaboratorEnriched, error) {
	out := make([]CollaboratorEnriched, 0, len(collabs))
	for _, c := range collabs {
		out = append(out, CollaboratorEnriched{
			Collaborator: c,
			TeamNames:    []string{},
			PrimaryRole:  resolveCanonicalRole(c),
			MFAEnrolled:  false,
		})
	}
	if len(collabs) == 0 || db == nil {
		return out, nil
	}

	ids := make([]uuid.UUID, 0, len(collabs))
	for _, c := range collabs {
		ids = append(ids, c.ID)
	}

	// 1. Team names per collaborator. ONE SELECT, GROUP BY collab.
	if names, err := fetchTeamNamesByCollaborator(ctx, db, ids); err == nil {
		for i := range out {
			if v, ok := names[out[i].ID.String()]; ok {
				out[i].TeamNames = v
			}
		}
	}

	// 2. Auth identity facts (last_login_at + mfa_enrolled flag). ONE
	// SELECT keyed by collaborator_id, NULL when no identity exists.
	if facts, err := fetchAuthIdentityFacts(ctx, db, ids); err == nil {
		for i := range out {
			if fact, ok := facts[out[i].ID.String()]; ok {
				out[i].LastLoginAt = fact.LastLoginAt
				out[i].MFAEnrolled = fact.MFAEnrolled
			}
		}
	}

	return out, nil
}

// authIdentityFact is the slim auth-identity projection.
type authIdentityFact struct {
	LastLoginAt *time.Time
	MFAEnrolled bool
}

func fetchTeamNamesByCollaborator(ctx context.Context, db *sql.DB, ids []uuid.UUID) (map[string][]string, error) {
	if len(ids) == 0 {
		return map[string][]string{}, nil
	}
	args := make([]any, 0, len(ids))
	placeholders := make([]string, 0, len(ids))
	for i, id := range ids {
		args = append(args, id)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
	}
	q := fmt.Sprintf(`
		SELECT tm.collaborator_id::text, t.name
		FROM public.team_memberships tm
		JOIN public.teams t ON t.id = tm.team_id
		WHERE tm.active = true AND tm.collaborator_id IN (%s)
		ORDER BY tm.collaborator_id, t.name`, strings.Join(placeholders, ","))

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var collabID, name string
		if err := rows.Scan(&collabID, &name); err != nil {
			continue
		}
		out[collabID] = append(out[collabID], name)
	}
	return out, rows.Err()
}

func fetchAuthIdentityFacts(ctx context.Context, db *sql.DB, ids []uuid.UUID) (map[string]authIdentityFact, error) {
	if len(ids) == 0 {
		return map[string]authIdentityFact{}, nil
	}
	args := make([]any, 0, len(ids))
	placeholders := make([]string, 0, len(ids))
	for i, id := range ids {
		args = append(args, id)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
	}
	q := fmt.Sprintf(`
		SELECT collaborator_id::text, last_login_at, mfa_enrolled_at
		FROM public.auth_identities
		WHERE collaborator_id IN (%s)`, strings.Join(placeholders, ","))

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]authIdentityFact{}
	for rows.Next() {
		var collabID string
		var lastLogin sql.NullTime
		var mfaEnrolled sql.NullTime
		if err := rows.Scan(&collabID, &lastLogin, &mfaEnrolled); err != nil {
			continue
		}
		fact := authIdentityFact{}
		if lastLogin.Valid {
			t := lastLogin.Time
			fact.LastLoginAt = &t
		}
		if mfaEnrolled.Valid {
			fact.MFAEnrolled = true
		}
		out[collabID] = fact
	}
	return out, rows.Err()
}

// resolveCanonicalRole collapses the 6 historical role-bearing paths
// into one canonical string. See §1.2 of the 2026-05-27 audit for the
// fallback chain rationale (the FE used to do this client-side; we move
// it server-side so every consumer reads one field).
func resolveCanonicalRole(c model.Collaborator) string {
	// 1. traits.tartaro_roles[0]
	if v := firstNonEmptyArrayString(c.Traits, "tartaro_roles"); v != "" {
		return v
	}
	// 2. traits.roles[0]
	if v := firstNonEmptyArrayString(c.Traits, "roles"); v != "" {
		return v
	}
	// 3. traits.role
	if v := nonEmptyStringField(c.Traits, "role"); v != "" {
		return v
	}
	// 4. employment_data.role
	if v := nonEmptyStringField(c.EmploymentData, "role"); v != "" {
		return v
	}
	// 5. metadata.roles[0]
	if v := firstNonEmptyArrayString(c.Metadata, "roles"); v != "" {
		return v
	}
	// 6. metadata.role
	if v := nonEmptyStringField(c.Metadata, "role"); v != "" {
		return v
	}
	return ""
}

// nonEmptyStringField returns the trimmed string at m[key], or "" when
// missing/empty/non-string.
func nonEmptyStringField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	raw, ok := m[key]
	if !ok {
		return ""
	}
	str, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(str)
}

// firstNonEmptyArrayString returns the trimmed first element of m[key]
// when that key holds a non-empty array whose first element is a string.
func firstNonEmptyArrayString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	raw, ok := m[key]
	if !ok {
		return ""
	}
	arr, ok := raw.([]any)
	if !ok || len(arr) == 0 {
		return ""
	}
	str, ok := arr[0].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(str)
}
