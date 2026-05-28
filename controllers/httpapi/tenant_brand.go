package httpapi

import (
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func (s *Server) handleTenantBrandGet(w http.ResponseWriter, r *http.Request) {
	brand, err := repository.GetTenantBrand(r.Context(), s.db)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"brand": brand})
}

// handleTenantBrandPatch is gated by requireOpsPermissionFunc(permManageOrganization)
// at the mux. Wildcard `yggdrasil:*` god-mode grants pass via the same path as
// every other `requireOpsPermissionFunc` route — see collaboratorHasOpsPermission.
func (s *Server) handleTenantBrandPatch(w http.ResponseWriter, r *http.Request) {
	token, ok := extractAuthToken(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	_, collaborator, err := repository.ResolveAuthSession(r.Context(), s.db, token)
	if err != nil {
		if isAuthUnauthorizedError(err) {
			clearAuthCookie(w)
			writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		writeMappedError(w, err)
		return
	}

	var req model.UpdateTenantBrandRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	brand, err := repository.UpdateTenantBrand(r.Context(), s.db, req, collaborator.ID)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"brand": brand})
}
