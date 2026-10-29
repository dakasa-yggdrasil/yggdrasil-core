package httpapi

import (
	"context"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// tartaroInstance{Namespace,Name} identify the Tartaro integration instance
// whose team_grants confer Tartaro actions. A grant whose instance does not
// match is ignored (see ListTeamGrants filtering below), so
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

// handleEffectiveTartaroActions answers the live computation of the
// collaborator's Tartaro actions: the per-team breakdown and the sorted
// union. The materialized traits.tartaro_actions trait is retired, so nothing
// here reads it or compares the computation with it.
func (s *Server) handleEffectiveTartaroActions(w http.ResponseWriter, r *http.Request) {
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

	effective, err := s.computeEffectiveTartaroActions(r.Context(), collabID)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"collaborator_id":          collabID,
		"effective_via_teams":      effective.PerTeam,
		"computed_tartaro_actions": effective.Computed,
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
// route has always done.
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
// while the console computation still lists it.
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
