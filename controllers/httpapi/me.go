package httpapi

import (
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

// GET /api/v1/me returns the collaborator tied to the caller's session.
// Surfaces use this to bootstrap "current user" context without round-
// tripping through /collaborators/<id> after first parsing a JWT or
// cookie. 401 if no valid session is attached to the request.
//
// The response also carries the viewer's effective `permissions` — the
// flat, sorted, de-duplicated union of yggdrasil:* actions resolved via
// repository.ResolveYggdrasilPermissions, the SAME list the ops RBAC
// gates check (see collaboratorHasOpsPermission) and that
// /api/v1/auth/session returns. Surfaces use it for capability-aware
// rendering (hide controls the viewer can't action) without a second
// round-trip.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	_, collaborator, ok := s.resolveCurrentCollaborator(w, r)
	if !ok {
		return
	}

	memberships, err := repository.ListTeamMemberships(r.Context(), s.db, model.ListTeamMembershipsRequest{
		CollaboratorID: collaborator.ID.String(),
		ActiveOnly:     true,
	})
	if err != nil {
		// Memberships are an enrichment — if the query fails we still
		// return the collaborator so callers degrade gracefully.
		memberships = nil
	}

	// Effective permissions resolution is fail-closed: on error we return
	// an empty list so the surface HIDES gated controls rather than
	// optimistically showing actions the viewer may not own. Same posture
	// as /api/v1/auth/session.
	permissions, err := repository.ResolveYggdrasilPermissions(r.Context(), s.db, collaborator.ID, collaborator.Traits)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("me: resolve permissions failed",
				zap.String("collaborator_id", collaborator.ID.String()),
				zap.Error(err))
		}
		permissions = nil
	}

	writeJSON(w, http.StatusOK, buildMeResponse(collaborator, memberships, permissions))
}

// buildMeResponse assembles the /me JSON payload. `permissions` is always
// serialized as a JSON array (never null) so the surface can iterate
// without a null guard and so "no grants" reliably hides every gated
// control.
func buildMeResponse(collaborator model.Collaborator, memberships []model.TeamMembership, permissions []string) map[string]any {
	if permissions == nil {
		permissions = []string{}
	}
	return map[string]any{
		"collaborator": collaborator,
		"memberships":  memberships,
		"permissions":  permissions,
	}
}
