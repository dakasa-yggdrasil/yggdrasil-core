package httpapi

import (
	"database/sql"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

var errAuthAdminUnauthorized = errors.New("auth admin unauthorized")

// authorizeAuthAdminRequest accepts admin requests via either:
//   - a valid console session (cookie or Bearer/X-Session-Token) — when the
//     middleware has already attached claims, OR when the path is outside
//     the middleware allowlist and we resolve them ourselves below; or
//   - one of the env-shared static tokens (YGGDRASIL_AUTH_ADMIN_TOKEN /
//     YGGDRASIL_WORKFLOW_RUN_TOKEN) sent as a header — used by external
//     workflows and bootstrap scripts that don't carry a session.
//
// Admin-only endpoints (POST /api/v1/auth/passwords, setup-tokens) sit
// outside the `requiresAuthenticatedConsoleAPI` middleware allowlist so
// admin-token-only callers can still reach them. The session path below
// is what the console UI uses — and prior to this fallback resolution
// every console call returned 401.
//
// db may be nil (in older test paths); when nil, the session-fallback is
// skipped and authorization only succeeds via env-token header.
func authorizeAuthAdminRequest(r *http.Request, db *sql.DB) error {
	if _, ok := claimsFromContext(r.Context()); ok {
		return nil
	}

	if db != nil {
		if token, has := extractAuthToken(r); has {
			if _, _, err := repository.ResolveAuthSession(r.Context(), db, token); err == nil {
				return nil
			}
		}
	}

	expected := strings.TrimSpace(os.Getenv("YGGDRASIL_AUTH_ADMIN_TOKEN"))
	if expected == "" {
		expected = strings.TrimSpace(os.Getenv("YGGDRASIL_WORKFLOW_RUN_TOKEN"))
	}
	if expected == "" {
		return errAuthAdminUnauthorized
	}

	candidates := []string{
		strings.TrimSpace(r.Header.Get("X-Yggdrasil-Auth-Admin-Token")),
		strings.TrimSpace(r.Header.Get("X-Yggdrasil-Workflow-Token")),
		bearerToken(r.Header.Get("Authorization")),
	}
	for _, candidate := range candidates {
		if candidate != "" && candidate == expected {
			return nil
		}
	}
	return errAuthAdminUnauthorized
}
