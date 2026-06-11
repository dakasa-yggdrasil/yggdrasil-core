package httpapi

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
)

// requireDeployToken wraps a handler to require a valid deploy credential.
// Accepted credentials, in order:
//   - a valid console session (claims attached upstream by
//     requireAuthenticatedConsoleAPIs + RBAC-checked on the /console routes), or
//   - the deploy token from YGGDRASIL_DEPLOY_TOKEN, or — as a fallback so these
//     routes are never silently unauthenticated just because the dedicated token
//     wasn't provisioned — the shared YGGDRASIL_WORKFLOW_RUN_TOKEN.
// Client sends the token as Authorization: Bearer <token> or X-Deploy-Token: <token>.
// Only when NEITHER token is configured AND there is no session do we allow-all
// (true local dev). In any provisioned environment the deploy surface is closed.
func requireDeployToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A valid console session is sufficient (the /console deploy routes are
		// already RBAC-gated upstream); don't also demand the static token.
		if _, ok := claimsFromContext(r.Context()); ok {
			next(w, r)
			return
		}

		expected := os.Getenv("YGGDRASIL_DEPLOY_TOKEN")
		if expected == "" {
			expected = os.Getenv("YGGDRASIL_WORKFLOW_RUN_TOKEN")
		}
		if expected == "" {
			// Neither token configured AND no session — local dev allow-all.
			next(w, r)
			return
		}

		token := extractDeployToken(r)
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			writeJSON(w, http.StatusUnauthorized, errorResponse{
				Error: "unauthorized: valid deploy token or console session required",
			})
			return
		}

		next(w, r)
	}
}

func extractDeployToken(r *http.Request) string {
	// Try Authorization: Bearer <token>
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(auth[7:])
	}

	// Try X-Deploy-Token header
	if token := r.Header.Get("X-Deploy-Token"); token != "" {
		return strings.TrimSpace(token)
	}

	return ""
}
