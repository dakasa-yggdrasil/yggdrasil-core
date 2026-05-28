package httpapi

import (
	"context"
	"net/http"
	"os"
	"strings"

	safego "github.com/dakasa-yggdrasil/yggdrasil-core/internal/goroutine"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// (was //nolint:unused — middleware was dead code until 2026-05-28 Phase 5 wiring.)


// Phase 5 RBAC wiring — audit 2026-05-27 §3.1.
//
// requireOpsPermission gates a route behind ONE yggdrasil:* permission.
// Until this cycle the middleware existed as dead code; surface-console's
// usePermission() was the ONLY enforcement layer and trivially bypassable
// via curl. INTEGRATION_CONTRACT §12 is now enforced server-side.
//
// Two-phase enforcement mirrors the A7 CSRF rollout pattern:
//
//   - YGGDRASIL_CONSOLE_RBAC_ENFORCE=warn (default): a missing permission
//     LOGS, increments the `yggdrasil_console_rbac_denied_total{mode=warn}`
//     counter, sets the `X-RBAC-Warn: <permission>` response header, and
//     ALLOWS the request to continue to the handler. Lets ops compare
//     surface-console's usePermission() catalog against backend enforcement
//     for 24-48h before flipping to hard-fail.
//
//   - YGGDRASIL_CONSOLE_RBAC_ENFORCE=enforce: the request is rejected with
//     HTTP 403 + Problem+JSON `code: permission.denied`. Audit log records
//     the denial.
//
// God-mode (`yggdrasil:*`) short-circuits the check.

// ctxKeyOpsPermission is the context key carrying the permission that
// gated the current request. Audit middleware reads it.
type ctxKeyOpsPermission struct{}

// rbacWarnHeader is the response header set in warn-mode when a request
// would have been rejected in enforce-mode. Lets ops grep for "who would
// have been denied" without poring through structured logs.
const rbacWarnHeader = "X-RBAC-Warn"

// rbacEnforceMode resolves the enforcement mode (warn or enforce).
// Default warn so a partial rollout (backend ships first, surface-console
// later) doesn't 403-storm legitimate traffic — matches the A7 CSRF
// pattern. Unknown values fall back to warn.
func rbacEnforceMode() string {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE")))
	switch value {
	case "enforce":
		return "enforce"
	case "warn", "":
		return "warn"
	default:
		return "warn"
	}
}

// requireOpsPermission returns a middleware that gates a handler behind
// one ops permission.
//
// Resolution: ResolveYggdrasilPermissions (team_grants on yggdrasil-self
// integration instances + traits.yggdrasil_admin god-mode). This matches
// what /api/v1/auth/session returns to the SPA, so the BE check is
// guaranteed-consistent with what the FE knows about.
//
// Bypass cases:
//   - no claims attached → workflow-run-token caller (machine automation
//     authorized upstream by requireAuthenticatedConsoleAPIs). Allow.
//   - god-mode (`yggdrasil:*`) → allow without DB roundtrip per permission.
//
// Failure mode:
//   - warn mode: log + counter + X-RBAC-Warn header + pass through.
//   - enforce mode: 403 Problem+JSON + audit row + stop.
//
// DB error: 500 even in warn mode (fail-closed on infrastructure errors).
func (s *Server) requireOpsPermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := claimsFromContext(r.Context())
			if !ok {
				// No claims attached → workflow-run-token / automation caller
				// already authorized by requireAuthenticatedConsoleAPIs. The
				// RBAC check applies only to human-actor sessions.
				next.ServeHTTP(w, r)
				return
			}

			collabID, _ := claims["collaborator_id"].(string)
			if collabID == "" {
				// Defensive: claims present but no collaborator id. Treat as
				// unauth — the auth middleware shouldn't normally let this
				// happen but a token-only path could.
				next.ServeHTTP(w, r)
				return
			}

			has, err := s.collaboratorHasOpsPermission(r.Context(), collabID, perm)
			if err != nil {
				// Infrastructure error: fail-closed (500) in BOTH modes.
				// Operators want to see this regardless of rollout phase.
				if s.logger != nil {
					s.logger.Error("rbac: permission check failed",
						zap.String("permission", perm),
						zap.String("path", r.URL.Path),
						zap.String("collaborator_id", collabID),
						zap.Error(err),
					)
				}
				writeJSONError(w, http.StatusInternalServerError, "rbac_check_failed")
				return
			}
			if has {
				ctx := context.WithValue(r.Context(), ctxKeyOpsPermission{}, perm)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Permission missing. Log + metric. Behaviour diverges by mode.
			mode := rbacEnforceMode()
			if s.logger != nil {
				s.logger.Warn("rbac: permission denied",
					zap.String("mode", mode),
					zap.String("permission", perm),
					zap.String("method", r.Method),
					zap.String("path", r.URL.Path),
					zap.String("collaborator_id", collabID),
				)
			}
			metrics.IncRBACDenied(perm, mode)

			if mode == "enforce" {
				s.recordOpsAuditDenied(r, collabID, perm)
				writeProblemJSON(w, http.StatusForbidden, "permission.denied",
					"You do not have the required permission "+perm+" to perform this action.")
				return
			}

			// Warn mode: surface the would-have-failed signal but proceed.
			// X-RBAC-Warn lets ops grep logs without parsing zap fields.
			w.Header().Set(rbacWarnHeader, perm)
			ctx := context.WithValue(r.Context(), ctxKeyOpsPermission{}, perm)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// requireOpsPermissionFunc is a HandlerFunc-shaped convenience wrapper used
// when the rest of the codebase registers routes via mux.HandleFunc(...)
// with a HandlerFunc (vs Handle with an http.Handler). Avoids the
// boilerplate of `mux.HandleFunc(p, s.requireOpsPermission(perm)(http.HandlerFunc(h)).ServeHTTP)`
// at each call site.
func (s *Server) requireOpsPermissionFunc(perm string, next http.HandlerFunc) http.HandlerFunc {
	wrapped := s.requireOpsPermission(perm)(next)
	return wrapped.ServeHTTP
}

// collaboratorHasOpsPermission returns true when the collaborator owns
// `perm` via team_grants on yggdrasil-self integration instances (or
// via the traits.yggdrasil_admin god-mode flag). Wraps
// repository.ResolveYggdrasilPermissions so the result is identical
// to what /api/v1/auth/session returns to the SPA.
//
// Wildcard handling: ResolveYggdrasilPermissions collapses a "*" grant to
// the single sentinel `YggdrasilGodModeAction` ("yggdrasil:*"). The check
// here treats that as "matches any yggdrasil:*" — same semantics as
// surface-console's usePermission() so BE/FE stay in sync.
func (s *Server) collaboratorHasOpsPermission(ctx context.Context, collabIDStr, perm string) (bool, error) {
	collabUUID, err := uuid.Parse(collabIDStr)
	if err != nil {
		return false, err
	}

	// Load the collaborator traits so god-mode via traits.yggdrasil_admin
	// is honoured. Best-effort: missing collaborator → empty traits, fall
	// through to team_grants resolution.
	var traits map[string]any
	if c, cErr := repository.GetCollaborator(ctx, s.db, collabIDStr); cErr == nil {
		traits = c.Traits
	}

	owned, err := repository.ResolveYggdrasilPermissions(ctx, s.db, collabUUID, traits)
	if err != nil {
		return false, err
	}
	for _, p := range owned {
		if p == perm {
			return true, nil
		}
		// God-mode: a wildcard grant matches any yggdrasil:* permission.
		if p == repository.YggdrasilGodModeAction && strings.HasPrefix(perm, "yggdrasil:") {
			return true, nil
		}
	}
	return false, nil
}

// recordOpsAuditDenied writes a denied row in audit_events. Best-effort.
func (s *Server) recordOpsAuditDenied(r *http.Request, collabID, perm string) {
	safego.SafeGo("ops_rbac_audit_denied", func() {
		ctx, cancel := context.WithTimeout(context.Background(), opsAuditTimeout)
		defer cancel()
		_ = s.recordOpsAuditEntry(ctx, opsAuditEntry{
			CollaboratorID: collabID,
			Action:         "ops.permission.denied",
			TargetKind:     "permission",
			TargetID:       perm,
			ResultStatus:   "denied",
		})
	})
}

