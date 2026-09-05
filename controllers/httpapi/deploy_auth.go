package httpapi

import (
	"net/http"
	"os"
	"strings"
)

// requireDeployToken wraps a handler to require a valid deploy credential.
// Accepted credentials, in order:
//   - a valid console session (claims attached upstream by
//     requireAuthenticatedConsoleAPIs + RBAC-checked on the /console routes), or
//   - the dedicated deploy token from YGGDRASIL_DEPLOY_TOKEN.
//
// Client sends the token as Authorization: Bearer <token> or X-Deploy-Token: <token>.
// Workflow credentials are never accepted. Only a credential-free request with
// no deploy token configured outside production gets the local-dev allow-all.
func requireDeployToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authorizeDeployRequest(r) == nil {
			next(w, r)
			return
		}
		writeJSON(w, http.StatusUnauthorized, errorResponse{
			Error: "unauthorized: valid deploy token or console session required",
		})
	}
}

func authorizeDeployRequest(r *http.Request) error {
	if !deployCredentialPath(r.Method, r.URL.Path) {
		return errWorkflowRunUnauthorized
	}
	// A valid console session is sufficient only on /console deploy routes,
	// because those handlers are already RBAC-gated upstream. The direct API
	// routes have no equivalent permission wrapper and therefore require the
	// dedicated deploy credential even when claims are present.
	if claims, ok := claimsFromContext(r.Context()); ok && strings.HasPrefix(r.URL.Path, "/api/v1/console/") {
		if collaboratorID, _ := claims["collaborator_id"].(string); strings.TrimSpace(collaboratorID) != "" {
			return nil
		}
	}

	expected := strings.TrimSpace(os.Getenv("YGGDRASIL_DEPLOY_TOKEN"))
	token := extractDeployToken(r)
	if expected == "" {
		if token == "" && !requestPresentsStaticCredential(r) && devEnvAllowsFallback() {
			return nil
		}
		return errWorkflowRunUnauthorized
	}
	if !constantTimeTokenEqual(token, expected) {
		return errWorkflowRunUnauthorized
	}
	return nil
}

func deployCredentialPath(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	switch path {
	case "/api/v1/products/deploy-all",
		"/api/v1/bootstrap",
		"/api/v1/integrations/install",
		"/api/v1/console/products/deploy-all",
		"/api/v1/console/bootstrap",
		"/api/v1/console/integrations/install":
		return true
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 7 && parts[0] == "api" && parts[1] == "v1" &&
		parts[2] == "console" && parts[3] == "products" && parts[6] == "deploy" {
		return parts[4] != "" && parts[5] != ""
	}
	if len(parts) == 6 && parts[0] == "api" && parts[1] == "v1" &&
		parts[2] == "products" && parts[5] == "deploy" {
		return parts[3] != "" && parts[4] != ""
	}
	return false
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
