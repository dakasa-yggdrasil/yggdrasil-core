package httpapi

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

const (
	tartaroInstanceNamespace = "dakasa"
	tartaroInstanceName      = "integration-tartaro-dakasa"
)

type effectivePerTeam struct {
	TeamID   string   `json:"team_id"`
	TeamSlug string   `json:"team_slug,omitempty"`
	Actions  []string `json:"actions"`
}

// handleEffectiveTartaroActions returns the trait set vs the ground-
// truth computation. drift=true signals the reactor lagged or failed.
func (s *Server) handleEffectiveTartaroActions(w http.ResponseWriter, r *http.Request) {
	collabIDStr := r.PathValue("id")
	collabID, err := uuid.Parse(collabIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid collaborator id"})
		return
	}

	collab, err := repository.GetCollaborator(r.Context(), s.db, collabIDStr)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	memberships, err := repository.ListTeamMemberships(r.Context(), s.db, model.ListTeamMembershipsRequest{
		CollaboratorID: collabID.String(),
		ActiveOnly:     true,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	perTeam := make([]effectivePerTeam, 0, len(memberships))
	union := map[string]struct{}{}
	for _, m := range memberships {
		grants, err := repository.ListTeamGrants(r.Context(), s.db, model.ListTeamGrantsRequest{TeamID: m.TeamID.String()})
		if err != nil {
			writeMappedError(w, err)
			return
		}
		var actions []string
		for _, g := range grants {
			if g.IntegrationInstanceNamespace != tartaroInstanceNamespace || g.IntegrationInstanceName != tartaroInstanceName {
				continue
			}
			if g.ActionName == "*" {
				continue
			}
			union[g.ActionName] = struct{}{}
			actions = append(actions, g.ActionName)
		}
		sort.Strings(actions)
		if len(actions) > 0 {
			perTeam = append(perTeam, effectivePerTeam{
				TeamID:   m.TeamID.String(),
				TeamSlug: m.TeamSlug,
				Actions:  actions,
			})
		}
	}

	computed := make([]string, 0, len(union))
	for a := range union {
		computed = append(computed, a)
	}
	sort.Strings(computed)

	traitActions := parseTraitActions(collab.Traits)
	drift := !equalSortedStrings(traitActions, computed)

	writeJSON(w, http.StatusOK, map[string]any{
		"collaborator_id":          collabID,
		"trait_tartaro_actions":    traitActions,
		"effective_via_teams":      perTeam,
		"computed_tartaro_actions": computed,
		"drift":                    drift,
	})
}

// handleSyncTartaroActions emits a synthetic team_membership.added event
// so the tartaro reactor reprocesses this user. Returns 202 Accepted.
func (s *Server) handleSyncTartaroActions(w http.ResponseWriter, r *http.Request) {
	collabIDStr := r.PathValue("id")
	collabID, err := uuid.Parse(collabIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid collaborator id"})
		return
	}

	if _, err := repository.GetCollaborator(r.Context(), s.db, collabIDStr); err != nil {
		writeMappedError(w, err)
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamMembershipAdded,
		SchemaVersion: "v1",
		AggregateType: "team_membership",
		AggregateID:   collabID.String(),
		Payload: map[string]any{
			"collaborator_id": collabID.String(),
			"synthetic":       true,
			"trigger":         "sync-tartaro-actions",
		},
		Actor: &model.EventActor{Type: model.ActorTypeAPI, ID: actorIDFromRequest(r)},
	}); err != nil {
		writeMappedError(w, fmt.Errorf("emit synthetic event: %w", err))
		return
	}
	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit: %w", err))
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"collaborator_id": collabID,
		"events_emitted":  1,
		"event_type":      "team_membership.added",
		"note":            "synthetic — reactor recomputes user trait",
	})
}

func parseTraitActions(traits map[string]any) []string {
	if traits == nil {
		return []string{}
	}
	raw, _ := traits["tartaro_actions"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func equalSortedStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
