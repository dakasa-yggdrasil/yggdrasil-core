package httpapi

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
)

// requireDeployToken wraps a handler to require a valid deploy token.
// Token is read from YGGDRASIL_DEPLOY_TOKEN env var.
// Client sends it as Authorization: Bearer <token> or X-Deploy-Token: <token>.
func requireDeployToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expected := os.Getenv("YGGDRASIL_DEPLOY_TOKEN")
		if expected == "" {
			// No token configured — allow all (dev mode)
			next(w, r)
			return
		}

		token := extractDeployToken(r)
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			writeJSON(w, http.StatusUnauthorized, errorResponse{
				Error: "unauthorized: valid deploy token required",
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
