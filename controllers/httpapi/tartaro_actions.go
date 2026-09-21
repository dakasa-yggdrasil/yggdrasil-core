package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// tartaroInstance{Namespace,Name} identify the Tartaro integration instance
// whose team_grants materialize the tartaro_actions trait. A grant whose
// instance does not match is ignored (see ListTeamGrants filtering below), so
// a wrong name silently zeroes EVERY collaborator's effective tartaro actions,
// which reads as a blanket 403 on Tartaro. The live instance is
// tartaro-dakasa-validation (the only registered Tartaro integration_instance);
// the previous hardcoded "integration-tartaro-dakasa" never existed, so no
// team grant ever matched. Defaults to the live instance and is env-overridable
// so another cluster can point at its own instance without a rebuild.
var (
	tartaroInstanceNamespace = tartaroInstanceEnvOr("YGGDRASIL_TARTARO_INSTANCE_NAMESPACE", "dakasa")
	tartaroInstanceName      = tartaroInstanceEnvOr("YGGDRASIL_TARTARO_INSTANCE_NAME", "tartaro-dakasa-validation")
)

func tartaroInstanceEnvOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

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

	collab, err := getCollaboratorCached(r.Context(), s.db, collabIDStr)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	effective, err := s.computeEffectiveTartaroActions(r.Context(), collabID)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	traitActions := parseTraitActions(collab.Traits)
	drift := !equalSortedStrings(traitActions, effective.Computed)

	writeJSON(w, http.StatusOK, map[string]any{
		"collaborator_id":          collabID,
		"trait_tartaro_actions":    traitActions,
		"effective_via_teams":      effective.PerTeam,
		"computed_tartaro_actions": effective.Computed,
		"drift":                    drift,
	})
}

// effectiveTartaroActionsResult is the ground-truth computation of one
// collaborator's Tartaro actions on the configured instance: the per-team
// breakdown and the sorted union.
type effectiveTartaroActionsResult struct {
	PerTeam  []effectivePerTeam
	Computed []string
}

// computeEffectiveTartaroActions walks the collaborator's active team
// memberships and their grants on the configured Tartaro instance. Grants on
// any other instance and wildcard grants are ignored, exactly as the console
// route has always done. The membership set is the one the tartaro reactor
// materializes into the trait (tm.active only), so the console drift view
// compares like with like.
func (s *Server) computeEffectiveTartaroActions(ctx context.Context, collabID uuid.UUID) (effectiveTartaroActionsResult, error) {
	memberships, err := repository.ListTeamMemberships(ctx, s.db, model.ListTeamMembershipsRequest{
		CollaboratorID: collabID.String(),
		ActiveOnly:     true,
	})
	if err != nil {
		return effectiveTartaroActionsResult{}, err
	}
	return s.tartaroActionsFromMemberships(ctx, memberships)
}

// computeAuthorizedTartaroActions is the directory machine oracle's variant.
// A machine consumer treats the result as proof that a human may act, so it
// walks only memberships that Yggdrasil's own RBAC projection would honor at
// this moment (repository.ListAuthorizationTeamMemberships: membership
// active, team active, inside the starts_at/ends_at window) and then applies
// the same grant walk as the console computation. An expired, not-yet-started,
// or deactivated-team membership therefore contributes no action here even
// while the materialized trait or the console drift view still lists it.
func (s *Server) computeAuthorizedTartaroActions(ctx context.Context, collabID uuid.UUID) (effectiveTartaroActionsResult, error) {
	memberships, err := repository.ListAuthorizationTeamMemberships(ctx, s.db, collabID)
	if err != nil {
		return effectiveTartaroActionsResult{}, err
	}
	return s.tartaroActionsFromMemberships(ctx, memberships)
}

// tartaroActionsFromMemberships is the grant walk shared by both
// computations: per membership, the grants of that team on the configured
// Tartaro instance, wildcards skipped, plus the sorted union.
func (s *Server) tartaroActionsFromMemberships(ctx context.Context, memberships []model.TeamMembership) (effectiveTartaroActionsResult, error) {
	perTeam := make([]effectivePerTeam, 0, len(memberships))
	union := map[string]struct{}{}
	for _, m := range memberships {
		grants, err := repository.ListTeamGrants(ctx, s.db, model.ListTeamGrantsRequest{TeamID: m.TeamID.String()})
		if err != nil {
			return effectiveTartaroActionsResult{}, err
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

	return effectiveTartaroActionsResult{PerTeam: perTeam, Computed: computed}, nil
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

	if _, err := getCollaboratorCached(r.Context(), s.db, collabIDStr); err != nil {
		writeMappedError(w, err)
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	// Payload must satisfy team_membership.added v1 schema:
	// required (collaborator_id, team_id), additionalProperties:false.
	// This is a synthetic event — no real team_id — so we use the
	// zero UUID and encode the trigger in `source` (free-string field).
	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamMembershipAdded,
		SchemaVersion: "v1",
		AggregateType: "team_membership",
		AggregateID:   collabID.String(),
		Payload: map[string]any{
			"collaborator_id": collabID.String(),
			"team_id":         "00000000-0000-0000-0000-000000000000",
			"role":            "synthetic",
			"source":          "sync-tartaro-actions",
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
