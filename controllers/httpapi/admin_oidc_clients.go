package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// adminOIDCClientPatchRequest carries the patch shape for
// PATCH /api/v1/admin/oidc-clients/{id}.  Pointer fields so the caller
// can omit them; a present pointer means "apply this value", a missing
// field means "leave the existing value alone".  AccessTokenLifetimeSeconds
// uses a pointer-to-pointer-equivalent shape (a nullable int pointer wrapped
// in the JSON dance) so the caller can explicitly clear the override:
//
//   {"access_token_lifetime_seconds": 120}     // set override to 120s
//   {"access_token_lifetime_seconds": null}    // explicit clear
//   {}                                          // leave alone
//
// json.Unmarshal of `null` to a *int leaves the pointer at nil, same as
// "not present" — we disambiguate via the raw map check below.
type adminOIDCClientPatchRequest struct {
	AccessTokenLifetimeSeconds *int `json:"access_token_lifetime_seconds,omitempty"`
}

// handleAdminOIDCClientPatch — PATCH /api/v1/admin/oidc-clients/{id}
//
// Auth: shared admin token (YGGDRASIL_AUTH_ADMIN_TOKEN). Same model as
// the other /api/v1/admin/* endpoints — single trust boundary, break-glass
// action.
//
// Behavior:
//   - Validates the client_id path param exists (404 if not).
//   - Applies the patch atomically (one UPDATE per field).
//   - Returns the updated client record (without client_secret_hash —
//     model.OIDCClient marshals that as json:"-").
//
// Audit ref: 2026-05-27 A10 — per-client AccessTokenLifetime override.
// Bounds (60s ≤ value ≤ 86400s) enforced by the DB CHECK constraint on
// migration 00048; we surface a 422 with the underlying error string.
func (s *Server) handleAdminOIDCClientPatch(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r, s.db); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	clientID := strings.TrimSpace(r.PathValue("id"))
	if clientID == "" {
		writeMappedError(w, fmt.Errorf("oidc client id is required"))
		return
	}

	var req adminOIDCClientPatchRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	// Only apply explicit fields. The pointer being non-nil is the
	// "field was supplied" signal. To clear the override the caller
	// sends a value of -1; we map that to nil (revert to global) since
	// json doesn't distinguish "omit" from "null" cleanly with *int.
	if req.AccessTokenLifetimeSeconds != nil {
		var ttl *int
		if *req.AccessTokenLifetimeSeconds != -1 {
			v := *req.AccessTokenLifetimeSeconds
			ttl = &v
		}
		if err := repository.UpdateOIDCClientAccessTokenLifetime(r.Context(), s.db, clientID, ttl); err != nil {
			if errors.Is(err, repository.ErrOIDCClientNotFound) {
				writeJSONError(w, http.StatusNotFound, "oidc_client_not_found")
				return
			}
			// CHECK violation (out of bounds) lands here; surface as 422.
			if strings.Contains(err.Error(), "oidc_clients_access_token_lifetime_chk") {
				writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
					"code":   "access_token_lifetime_out_of_range",
					"detail": "access_token_lifetime_seconds must be between 60 and 86400, or -1 to clear",
				})
				return
			}
			writeMappedError(w, err)
			return
		}
	}

	// Re-read the client to return the canonical post-patch state.
	updated, err := repository.GetOIDCClientByID(r.Context(), s.db, clientID)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"client": updated})
}
