package httpapi

import (
	"net/http"

	"github.com/google/uuid"

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
//
// Auth: the RBAC middleware bypasses for "no claims" (workflow-run-token
// callers). When a console session is present, `updated_by` is the
// session's collaborator ID. When the workflow-run-token authorized the
// request (machine automation, bootstrap, ops scripts), the row's
// updated_by stays NULL — already supported by the column nullability.
func (s *Server) handleTenantBrandPatch(w http.ResponseWriter, r *http.Request) {
	var updatedBy *uuid.UUID
	if token, ok := extractAuthToken(r); ok {
		if _, collaborator, err := repository.ResolveAuthSession(r.Context(), s.db, token); err == nil {
			id := collaborator.ID
			updatedBy = &id
		} else if !isAuthUnauthorizedError(err) {
			writeMappedError(w, err)
			return
		}
		// Token present but doesn't resolve to a session → workflow-run-token
		// or admin-token caller. The RBAC middleware already authorized this
		// path (no claims attached). Fall through with updatedBy=nil.
	}

	var req model.UpdateTenantBrandRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	brand, err := repository.UpdateTenantBrand(r.Context(), s.db, req, updatedBy)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"brand": brand})
}
