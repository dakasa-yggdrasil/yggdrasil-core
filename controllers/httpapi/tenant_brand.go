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
// Authorization layering (defense-in-depth, 2026-05-28 security review):
//
//   - /api/v1/tenant/* is INTENTIONALLY public on the prefix middleware
//     because the GET feeds LoginPage and other unauthenticated surfaces.
//     The PATCH therefore self-gates in this handler.
//   - Accept a valid console session whose collaborator resolves cleanly.
//   - "No token at all" is rejected with 401. Never accept the absence
//     of a credential as a valid state — RBAC's "bypass when no claims"
//     short-circuit is for paths that the upstream middleware already
//     authenticated, which is NOT the case for /api/v1/tenant/*.
//
// updated_by is always the session collaborator ID. Workflow credentials are
// dispatch-only and never authorize tenant or other administrative writes.
func (s *Server) handleTenantBrandPatch(w http.ResponseWriter, r *http.Request) {
	var updatedBy *uuid.UUID
	sessionResolved := false
	tokenPresented := false

	if token, ok := extractAuthToken(r); ok {
		tokenPresented = true
		_, collaborator, err := repository.ResolveAuthSession(r.Context(), s.db, token)
		switch {
		case err == nil:
			id := collaborator.ID
			updatedBy = &id
			sessionResolved = true
		case isAuthUnauthorizedError(err):
			// Token presented but is not a session token. Static workflow,
			// deploy, event, and auth-admin credentials do not authorize this route.
		default:
			writeMappedError(w, err)
			return
		}
	}

	if !sessionResolved {
		// If we saw a Cookie-bound token earlier that did not validate, clear it
		// so the next request lands cleanly on the login flow instead of replaying
		// the stale value.
		if tokenPresented {
			clearAuthCookie(w)
		}
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
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
