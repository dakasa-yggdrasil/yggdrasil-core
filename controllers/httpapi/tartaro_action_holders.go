package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

// tartaroActionHoldersPath is the roster of the collaborators who hold one
// Tartaro grant right now (ADR-0107). Tartaro's collective-ban quorum counts
// its eligible voters here, so the roster must be exactly the set that the
// live effective-actions read authorizes.
const tartaroActionHoldersPath = "/api/v1/tartaro/action-holders"

// tartaroActionHoldersMaxActionLength bounds the one query value.
const tartaroActionHoldersMaxActionLength = 128

// Sources of one holder, in the sorted order they are reported.
const (
	tartaroActionHolderSourceGodMode   = "god_mode"
	tartaroActionHolderSourceTeamGrant = "team_grant"
)

// tartaroActionHoldersResponse is the wire contract of
// GET /api/v1/tartaro/action-holders. Every field is always present:
// holders is never null, total always equals len(holders), holders are
// sorted by collaborator_id ascending and unique, and every sources list is
// a non-empty sorted subset of ["god_mode", "team_grant"]. The field names
// are pinned by TestTartaroActionHoldersWireFieldNamesAreTheContract.
type tartaroActionHoldersResponse struct {
	Action              string                       `json:"action"`
	IntegrationInstance tartaroIntegrationInstanceID `json:"integration_instance"`
	Total               int                          `json:"total"`
	Holders             []tartaroActionHolder        `json:"holders"`
}

type tartaroIntegrationInstanceID struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type tartaroActionHolder struct {
	CollaboratorID string   `json:"collaborator_id"`
	Sources        []string `json:"sources"`
}

// parseTartaroActionHoldersQuery accepts exactly one query parameter,
// action, present exactly once, non-empty after trimming, equal to its
// trimmed form, not the "*" wildcard and at most 128 bytes long. A query
// string that does not parse, or any other parameter, is refused.
func parseTartaroActionHoldersQuery(rawQuery string) (string, error) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", fmt.Errorf("malformed query string")
	}
	for key := range values {
		if key != "action" {
			return "", fmt.Errorf("unsupported query parameter %q: only action is accepted", key)
		}
	}
	actions := values["action"]
	if len(actions) != 1 {
		return "", fmt.Errorf("action is required exactly once")
	}
	action := actions[0]
	trimmed := strings.TrimSpace(action)
	switch {
	case trimmed == "":
		return "", fmt.Errorf("action is required")
	case action != trimmed:
		return "", fmt.Errorf("action must not carry surrounding whitespace")
	case action == tartaroWildcardAction:
		return "", fmt.Errorf("action must be a concrete action, not the wildcard")
	case len(action) > tartaroActionHoldersMaxActionLength:
		return "", fmt.Errorf("action is longer than %d bytes", tartaroActionHoldersMaxActionLength)
	}
	return action, nil
}

// handleTartaroActionHolders answers which collaborators hold one Tartaro
// grant right now on the configured Tartaro instance (ADR-0107). A holder is
// exactly a collaborator the live effective-actions read
// (computeAuthorizedTartaroActions plus tartaroGodMode, ADR-0086) would
// authorize for that action:
//
//   - status exactly "active", and
//   - a membership satisfying authorizationMembershipPredicate in a team
//     with a grant on the instance whose action_name is the action, or is
//     "*" while the instance permission catalog lists the action
//     ("team_grant"), or
//   - Tartaro god mode by the tartaroGodMode rule ("god_mode").
//
// It fails toward "cannot count", never toward "count lower": when any "*"
// grant exists on the instance and its catalog cannot be resolved, the answer
// is 503 instead of a roster that silently drops the wildcard holders.
//
// Auth is the console gate, exactly like GET /api/v1/collaborators: any
// authenticated human caller (session or forwarded OIDC JWT), no ops
// permission. The answer carries collaborator ids only.
func (s *Server) handleTartaroActionHolders(w http.ResponseWriter, r *http.Request) {
	claims, _ := claimsFromContext(r.Context())
	if callerID, _ := claims["collaborator_id"].(string); strings.TrimSpace(callerID) == "" {
		// Defense in depth: the console gate only lets an authenticated human
		// reach this handler, and both of its human paths attach claims.
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}

	action, err := parseTartaroActionHoldersQuery(r.URL.RawQuery)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	snapshot, err := repository.ListIntegrationInstanceActionHolderCandidates(r.Context(), s.db, tartaroInstanceNamespace, tartaroInstanceName, action)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// A "*" grant confers the action only when the instance catalog lists
	// it. The catalog is read once, and only when a wildcard grant exists on
	// the instance. Unlike the effective-actions read, where an unresolvable
	// catalog only narrows one collaborator's own answer, a roster that
	// dropped the wildcard holders would undercount the eligible voters, so
	// here an unresolvable catalog refuses to count.
	wildcardConfersAction := false
	if snapshot.InstanceHasWildcardGrant {
		catalog, catalogErr := repository.ListIntegrationInstancePermissionActions(r.Context(), s.db, tartaroInstanceNamespace, tartaroInstanceName)
		if catalogErr != nil {
			if s.logger != nil {
				s.logger.Warn("tartaro action holders unavailable: a wildcard grant exists and the instance permission catalog is not resolvable",
					zap.String("integration_instance_namespace", tartaroInstanceNamespace),
					zap.String("integration_instance_name", tartaroInstanceName),
					zap.Error(catalogErr))
			}
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": "tartaro action holders unavailable: a wildcard grant exists and the instance permission catalog is not resolvable",
			})
			return
		}
		for _, listed := range catalog {
			if listed == action {
				wildcardConfersAction = true
				break
			}
		}
	}

	holders := make([]tartaroActionHolder, 0, len(snapshot.Candidates))
	seen := make(map[string]struct{}, len(snapshot.Candidates))
	for _, candidate := range snapshot.Candidates {
		collaborator := model.Collaborator{ID: candidate.CollaboratorID, Status: candidate.Status}
		if !tartaroCollaboratorActive(collaborator) {
			continue
		}
		if candidate.AdminTrait != nil {
			var adminTrait any
			if err := json.Unmarshal(candidate.AdminTrait, &adminTrait); err != nil {
				writeMappedError(w, fmt.Errorf("decode yggdrasil_admin trait: %w", err))
				return
			}
			collaborator.Traits = map[string]any{"yggdrasil_admin": adminTrait}
		}

		sources := make([]string, 0, 2)
		if tartaroGodMode(collaborator) {
			sources = append(sources, tartaroActionHolderSourceGodMode)
		}
		if candidate.ExactGrant || (candidate.WildcardGrant && wildcardConfersAction) {
			sources = append(sources, tartaroActionHolderSourceTeamGrant)
		}
		if len(sources) == 0 {
			continue
		}
		id := candidate.CollaboratorID.String()
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		sort.Strings(sources)
		holders = append(holders, tartaroActionHolder{CollaboratorID: id, Sources: sources})
	}
	sort.Slice(holders, func(i, j int) bool { return holders[i].CollaboratorID < holders[j].CollaboratorID })

	writeJSON(w, http.StatusOK, tartaroActionHoldersResponse{
		Action: action,
		IntegrationInstance: tartaroIntegrationInstanceID{
			Namespace: tartaroInstanceNamespace,
			Name:      tartaroInstanceName,
		},
		Total:   len(holders),
		Holders: holders,
	})
}
