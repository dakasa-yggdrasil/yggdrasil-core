package httpapi

import (
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Phase 6 aggregator — audit 2026-05-27 §2.2.
//
// TeamEditPage previously fired THREE dataset-wide queries on every mount:
//
//   1. fetchTeams()           — full list, just to find ONE team + parent options
//   2. fetchCollaborators()   — full list, for owner candidates + DangerZone
//   3. fetchTeamMemberships() — full list, then filtered client-side to the team
//
// For a 1000-person org with 200 teams and 5000 memberships, the FE
// transferred ~6200 records to edit one team. This aggregate returns
// the same data already scoped to "what this page actually needs".
//
// Permission gate: yggdrasil:view_teams.

type consoleTeamEditContext struct {
	Team             model.Team             `json:"team"`
	ParentOptions    []consoleTeamSlimRef   `json:"parent_options"`
	OwnerCandidates  []consoleTeamCollab    `json:"owner_candidates"`
	ActiveMemberships []model.TeamMembership `json:"active_memberships"`
	// AllMembershipsForCollaborators carries the OTHER memberships for
	// each collaborator currently in THIS team — required by the
	// DangerZone preview to compute "solo vs multi-team" splits without
	// requesting a second dataset.
	OtherMembershipsByCollaborator map[string][]consoleOtherMembership `json:"other_memberships_by_collaborator"`
}

// consoleTeamSlimRef is the parent-options projection — name + slug +
// type are all the dropdown needs.  Drops audit/metadata noise.
type consoleTeamSlimRef struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

// consoleTeamCollab is the slim owner-candidate shape.
type consoleTeamCollab struct {
	ID           string `json:"id"`
	Slug         string `json:"slug"`
	DisplayName  string `json:"display_name"`
	PrimaryEmail string `json:"primary_email,omitempty"`
	Status       string `json:"status,omitempty"`
	// MemberOfThisTeam flags collaborators that already belong to the
	// team being edited.  Lets the surface render the membership toggle
	// without a separate merge step.
	MemberOfThisTeam bool `json:"member_of_this_team"`
}

// consoleOtherMembership is the slim other-team projection — id + name +
// type are enough for DangerZone's "still in X, Y, Z" preview.
type consoleOtherMembership struct {
	TeamID   string `json:"team_id"`
	TeamSlug string `json:"team_slug"`
	TeamName string `json:"team_name"`
	TeamType string `json:"team_type,omitempty"`
}

// handleConsoleTeamEditContext serves /api/v1/console/teams/{id}/edit-context.
//
// Implementation:
//   1. Resolve the team by id-or-slug.
//   2. Load ALL teams (still a dataset op, but bounded by org size — at
//      DaKasa scale ~200 rows) so parent_options + DangerZone destination
//      options can be computed.  This is the SINGLE remaining "list" call;
//      we can't avoid showing the operator a tree-aware picker.
//   3. Load collaborators (limited to 500 — the §2.2 cap).
//   4. Load memberships SCOPED to this team only.
//   5. For each membership, fetch the OTHER memberships of that
//      collaborator (bounded by the count of members in THIS team — usually
//      under 50).
//
// Total queries: 4 (vs the 3 the FE previously made — but each is
// O(team size) instead of O(org size)).
//
// Pagination: the collaborator list caps at 500.  Larger orgs should hit
// the surface-side "type to search" pattern Phase 6B will deliver.
func (s *Server) handleConsoleTeamEditContext(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "team id is required")
		return
	}

	team, err := repository.GetTeam(ctx, s.db, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	allTeams, err := repository.ListTeams(ctx, s.db, model.ListTeamsRequest{})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Compute parent options: every team that is NOT a descendant of
	// `team`. This is what the FE previously did with collectDescendants
	// — we move it server-side so the surface drops the helper.
	descendants := collectTeamDescendants(team.ID.String(), allTeams)
	parentOptions := make([]consoleTeamSlimRef, 0, len(allTeams))
	for _, t := range allTeams {
		if descendants[t.ID.String()] {
			continue
		}
		parentOptions = append(parentOptions, consoleTeamSlimRef{
			ID: t.ID.String(), Slug: t.Slug, Name: t.Name, Type: t.Type,
		})
	}

	// Owner candidates — cap at 500.  Beyond that the surface should
	// offer search-as-you-type, which Phase 6B will deliver.  We use the
	// unpaginated list (cap is per-call here, not per-page) and slice
	// because there's no equivalent of "give me at most N + abort" yet.
	const ownerCandidateCap = 500
	collabs, err := repository.ListCollaborators(ctx, s.db, model.ListCollaboratorsRequest{})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if len(collabs) > ownerCandidateCap {
		collabs = collabs[:ownerCandidateCap]
	}

	// Active memberships SCOPED to this team. The previous FE call
	// fetched ALL memberships and filtered client-side.
	memberships, err := repository.ListTeamMemberships(ctx, s.db, model.ListTeamMembershipsRequest{
		TeamID:     team.ID.String(),
		ActiveOnly: true,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	memberIDs := make(map[string]bool, len(memberships))
	for _, m := range memberships {
		memberIDs[m.CollaboratorID.String()] = true
	}

	// Owner candidates with member flag — saves the FE from doing
	// memberships.filter+map.
	candidates := make([]consoleTeamCollab, 0, len(collabs))
	for _, c := range collabs {
		candidates = append(candidates, consoleTeamCollab{
			ID:               c.ID.String(),
			Slug:             c.Slug,
			DisplayName:      c.DisplayName,
			PrimaryEmail:     c.PrimaryEmail,
			Status:           c.Status,
			MemberOfThisTeam: memberIDs[c.ID.String()],
		})
	}

	// Build the per-collaborator "other memberships" map (DangerZone
	// preview).  We only run this query when there are members — saves
	// a db trip on empty teams.
	otherByCollab := map[string][]consoleOtherMembership{}
	if len(memberships) > 0 {
		teamByID := make(map[string]model.Team, len(allTeams))
		for _, t := range allTeams {
			teamByID[t.ID.String()] = t
		}
		for _, m := range memberships {
			others, err := repository.ListTeamMemberships(ctx, s.db, model.ListTeamMembershipsRequest{
				CollaboratorID: m.CollaboratorID.String(),
				ActiveOnly:     true,
			})
			if err != nil {
				continue
			}
			rows := []consoleOtherMembership{}
			for _, o := range others {
				if o.TeamID == team.ID {
					continue
				}
				ref, ok := teamByID[o.TeamID.String()]
				if !ok {
					continue
				}
				rows = append(rows, consoleOtherMembership{
					TeamID:   ref.ID.String(),
					TeamSlug: ref.Slug,
					TeamName: ref.Name,
					TeamType: ref.Type,
				})
			}
			if len(rows) > 0 {
				otherByCollab[m.CollaboratorID.String()] = rows
			}
		}
	}

	resp := consoleTeamEditContext{
		Team:                           team,
		ParentOptions:                  parentOptions,
		OwnerCandidates:                candidates,
		ActiveMemberships:              memberships,
		OtherMembershipsByCollaborator: otherByCollab,
	}
	if resp.ActiveMemberships == nil {
		resp.ActiveMemberships = []model.TeamMembership{}
	}
	writeJSON(w, http.StatusOK, resp)
}

// collectTeamDescendants returns the set of team IDs that are descendants
// (or self) of `rootID`. Mirrors the FE's collectDescendants helper.
func collectTeamDescendants(rootID string, all []model.Team) map[string]bool {
	out := map[string]bool{rootID: true}
	added := true
	for added {
		added = false
		for _, t := range all {
			if t.ParentTeamID == nil {
				continue
			}
			parentID := t.ParentTeamID.String()
			if out[parentID] && !out[t.ID.String()] {
				out[t.ID.String()] = true
				added = true
			}
		}
	}
	return out
}
