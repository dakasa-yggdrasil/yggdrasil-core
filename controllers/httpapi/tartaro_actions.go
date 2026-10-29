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
	"go.uber.org/zap"
)

// tartaroInstance{Namespace,Name} identify the Tartaro integration instance
// whose team_grants confer Tartaro actions. A grant whose instance does not
// match is ignored (see the grant walk below), so a wrong name silently zeroes
// EVERY collaborator's effective tartaro actions, which reads as a blanket 403
// on Tartaro. The live instance is tartaro-dakasa-validation (the only
// registered Tartaro integration_instance); the previous hardcoded
// "integration-tartaro-dakasa" never existed, so no team grant ever matched.
// Defaults to the live instance and is env-overridable so another cluster can
// point at its own instance without a rebuild.
var (
	tartaroInstanceNamespace = tartaroInstanceEnvOr("YGGDRASIL_TARTARO_INSTANCE_NAMESPACE", "dakasa")
	tartaroInstanceName      = tartaroInstanceEnvOr("YGGDRASIL_TARTARO_INSTANCE_NAME", "tartaro-dakasa-validation")
)

// tartaroWildcardAction is the grant action_name that means "every
// permission action of that instance" (ADR-0086). It is expanded from the
// instance's catalog and never appears literally in an answer.
const tartaroWildcardAction = "*"

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

// consoleEffectiveTartaroActionsResponse is the console (caller JWT) answer
// of the live Tartaro authorization read (ADR-0086): the per-team breakdown,
// the sorted union and the god-mode verdict. The materialized trait and its
// drift flag are retired (ADR-0085), so nothing here is read from or compared
// with traits.tartaro_actions.
type consoleEffectiveTartaroActionsResponse struct {
	CollaboratorID         string             `json:"collaborator_id"`
	EffectiveViaTeams      []effectivePerTeam `json:"effective_via_teams"`
	ComputedTartaroActions []string           `json:"computed_tartaro_actions"`
	GodMode                bool               `json:"god_mode"`
}

// handleEffectiveTartaroActions serves the console variant of the live
// Tartaro authorization read. It applies the same membership predicate as the
// directory machine variant (computeAuthorizedTartaroActions), so the two
// variants answer the same action set for the same collaborator.
func (s *Server) handleEffectiveTartaroActions(w http.ResponseWriter, r *http.Request) {
	collabIDStr := r.PathValue("id")
	if _, err := uuid.Parse(collabIDStr); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid collaborator id"})
		return
	}

	collab, err := getCollaboratorCached(r.Context(), s.db, collabIDStr)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	effective, err := s.computeAuthorizedTartaroActions(r.Context(), collab.ID)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, consoleEffectiveTartaroActionsResponse{
		CollaboratorID:         collab.ID.String(),
		EffectiveViaTeams:      effective.PerTeam,
		ComputedTartaroActions: effective.Computed,
		GodMode:                tartaroGodMode(collab),
	})
}

// tartaroGodMode is the god-mode verdict both effective-actions variants
// answer (ADR-0086): the collaborator status is exactly "active" AND
// traits.yggdrasil_admin is the boolean true or exactly the string "true" or
// "1". That is the reading of dakasa-commons security.YggdrasilIsGodMode plus
// the active-status requirement. It is never derived from a team grant, so a
// "*" grant on a yggdrasil-self instance does not make a Tartaro god. Core's
// own console god mode (repository.ResolveYggdrasilPermissions) is a separate,
// unchanged rule.
func tartaroGodMode(collaborator model.Collaborator) bool {
	if collaborator.Status != "active" {
		return false
	}
	switch value := collaborator.Traits["yggdrasil_admin"].(type) {
	case bool:
		return value
	case string:
		return value == "true" || value == "1"
	default:
		return false
	}
}

// effectiveTartaroActionsResult is the ground-truth computation of one
// collaborator's Tartaro actions on the configured instance: the per-team
// breakdown and the sorted union.
type effectiveTartaroActionsResult struct {
	PerTeam  []effectivePerTeam
	Computed []string
}

// computeAuthorizedTartaroActions is the single Tartaro action computation
// behind both the console route and the directory machine route. A consumer
// treats the result as proof that a human may act, so it walks only
// memberships that Yggdrasil's own RBAC projection would honor at this moment
// (repository.ListAuthorizationTeamMemberships: membership active, team
// active, inside the starts_at/ends_at window). An expired, not-yet-started,
// or deactivated-team membership therefore contributes no action.
func (s *Server) computeAuthorizedTartaroActions(ctx context.Context, collabID uuid.UUID) (effectiveTartaroActionsResult, error) {
	memberships, err := repository.ListAuthorizationTeamMemberships(ctx, s.db, collabID)
	if err != nil {
		return effectiveTartaroActionsResult{}, err
	}
	return s.tartaroActionsFromMemberships(ctx, memberships)
}

// tartaroActionsFromMemberships is the grant walk: one read of the grants of
// every membership team (repository.ListTeamGrantsByTeamIDs, no per-team
// round trip), only grants on the configured Tartaro instance, a "*" grant on
// that instance expanded to the instance's permission catalog, then per-team
// sorted sets and the sorted union. Grants on any other instance, a "*" one
// included, are ignored.
func (s *Server) tartaroActionsFromMemberships(ctx context.Context, memberships []model.TeamMembership) (effectiveTartaroActionsResult, error) {
	perTeam := make([]effectivePerTeam, 0, len(memberships))
	if len(memberships) == 0 {
		return effectiveTartaroActionsResult{PerTeam: perTeam, Computed: []string{}}, nil
	}

	teamIDs := make([]uuid.UUID, 0, len(memberships))
	for _, m := range memberships {
		teamIDs = append(teamIDs, m.TeamID)
	}
	grants, err := repository.ListTeamGrantsByTeamIDs(ctx, s.db, teamIDs)
	if err != nil {
		return effectiveTartaroActionsResult{}, err
	}

	grantsByTeam := map[uuid.UUID][]string{}
	hasWildcard := false
	for _, g := range grants {
		if g.IntegrationInstanceNamespace != tartaroInstanceNamespace || g.IntegrationInstanceName != tartaroInstanceName {
			continue
		}
		teamID, parseErr := uuid.Parse(g.TeamID)
		if parseErr != nil {
			continue
		}
		if g.ActionName == tartaroWildcardAction {
			hasWildcard = true
		}
		grantsByTeam[teamID] = append(grantsByTeam[teamID], g.ActionName)
	}

	// The catalog is read at most once per computation, and only when a
	// wildcard grant on the configured instance is present.
	var wildcardActions []string
	if hasWildcard {
		wildcardActions = s.tartaroWildcardActions(ctx)
	}

	union := map[string]struct{}{}
	for _, m := range memberships {
		teamActions := map[string]struct{}{}
		for _, action := range grantsByTeam[m.TeamID] {
			if action == tartaroWildcardAction {
				for _, expanded := range wildcardActions {
					teamActions[expanded] = struct{}{}
				}
				continue
			}
			teamActions[action] = struct{}{}
		}
		if len(teamActions) == 0 {
			continue
		}
		actions := sortedActionSet(teamActions)
		for _, action := range actions {
			union[action] = struct{}{}
		}
		perTeam = append(perTeam, effectivePerTeam{
			TeamID:   m.TeamID.String(),
			TeamSlug: m.TeamSlug,
			Actions:  actions,
		})
	}

	return effectiveTartaroActionsResult{PerTeam: perTeam, Computed: sortedActionSet(union)}, nil
}

// tartaroWildcardActions resolves what a "*" grant on the configured Tartaro
// instance means: every action with category "permission" in the
// action_catalog of that instance's active integration_type. It fails closed:
// when the catalog cannot be resolved (instance or type not resolvable,
// database or decoding failure) the wildcard contributes nothing and the
// failure is logged; the computation itself never errors because of it.
func (s *Server) tartaroWildcardActions(ctx context.Context) []string {
	actions, err := repository.ListIntegrationInstancePermissionActions(ctx, s.db, tartaroInstanceNamespace, tartaroInstanceName)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("tartaro wildcard grant contributes no action: the instance permission catalog is not resolvable",
				zap.String("integration_instance_namespace", tartaroInstanceNamespace),
				zap.String("integration_instance_name", tartaroInstanceName),
				zap.Error(err))
		}
		return nil
	}
	return actions
}

func sortedActionSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for action := range set {
		out = append(out, action)
	}
	sort.Strings(out)
	return out
}
