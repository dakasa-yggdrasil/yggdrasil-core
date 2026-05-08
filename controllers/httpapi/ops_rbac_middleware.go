package httpapi

import (
	"context"
	"net/http"
)

// ctxKeyOpsPermission is the context key carrying the permission that
// gated the current request. Audit middleware reads it.
type ctxKeyOpsPermission struct{}

// requireOpsPermission returns a middleware that gates a handler behind
// one ops permission. It joins collaborators.role against
// role_permission_bindings.role to test whether the authenticated
// collaborator carries the permission.
//
// On miss: 403 with JSON {"error":"permission_denied","required":"<perm>"}
// and a denied audit row.
// On no-session: 401.
func (s *Server) requireOpsPermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			collabID := opsCollaboratorID(r)
			if collabID == "" {
				writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
				return
			}
			ok, err := s.collaboratorHasOpsPermission(r.Context(), collabID, perm)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "rbac_check_failed")
				return
			}
			if !ok {
				s.recordOpsAuditDenied(r, collabID, perm)
				writeJSONErrorPayload(w, http.StatusForbidden, map[string]any{
					"error":    "permission_denied",
					"required": perm,
				})
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyOpsPermission{}, perm)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// opsCollaboratorID extracts the collaborator id from the verified JWT
// claims attached by middleware_auth.bearerOrSession. Returns "" when
// no claims are present (e.g. unauthenticated).
func opsCollaboratorID(r *http.Request) string {
	claims, ok := claimsFromContext(r.Context())
	if !ok {
		return ""
	}
	for _, key := range []string{"collaborator_id", "sub"} {
		if v, ok := claims[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// collaboratorHasOpsPermission joins collaborators.role against
// role_permission_bindings.role. The current schema stores a single
// role per collaborator (00002_core_identities.collaborators.role).
func (s *Server) collaboratorHasOpsPermission(ctx context.Context, collabID, perm string) (bool, error) {
	const q = `
		SELECT EXISTS (
		  SELECT 1
		  FROM public.role_permission_bindings rpb
		  JOIN public.collaborators c ON c.role = rpb.role
		  WHERE c.id = $1 AND rpb.permission_name = $2
		)
	`
	var ok bool
	if err := s.db.QueryRowContext(ctx, q, collabID, perm).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}

// recordOpsAuditDenied writes a denied row in audit_events. Best-effort.
func (s *Server) recordOpsAuditDenied(r *http.Request, collabID, perm string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), opsAuditTimeout)
		defer cancel()
		_ = s.recordOpsAuditEntry(ctx, opsAuditEntry{
			CollaboratorID: collabID,
			Action:         "ops.permission.denied",
			TargetKind:     "permission",
			TargetID:       perm,
			ResultStatus:   "denied",
		})
	}()
}

// writeJSONErrorPayload mirrors writeJSONError but with an arbitrary body.
func writeJSONErrorPayload(w http.ResponseWriter, status int, payload map[string]any) {
	writeJSON(w, status, payload)
}
