package httpapi

import (
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// GET /api/v1/me returns the collaborator tied to the caller's session.
// Surfaces use this to bootstrap "current user" context without round-
// tripping through /collaborators/<id> after first parsing a JWT or
// cookie. 401 if no valid session is attached to the request.
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

	writeJSON(w, http.StatusOK, map[string]any{
		"collaborator": collaborator,
		"memberships":  memberships,
	})
}
