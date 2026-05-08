package httpapi

import (
	"errors"
	"net/http"
	"os"
	"strings"
)

var errAuthAdminUnauthorized = errors.New("auth admin unauthorized")

func authorizeAuthAdminRequest(r *http.Request) error {
	if requiresAuthenticatedConsoleAPI(r.URL.Path) {
		if _, ok := claimsFromContext(r.Context()); ok {
			return nil
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
