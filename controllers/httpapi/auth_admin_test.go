package httpapi

import (
	"errors"
	"net/http/httptest"
	"testing"
)

func TestAuthorizeAuthAdminRequestFailsClosedWhenUnconfigured(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	req := httptest.NewRequest("POST", "/api/v1/auth/passwords", nil)
	if err := authorizeAuthAdminRequest(req); !errors.Is(err, errAuthAdminUnauthorized) {
		t.Fatalf("expected errAuthAdminUnauthorized, got %v", err)
	}
}

func TestAuthorizeAuthAdminRequestAcceptsAdminHeader(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "auth-secret")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	req := httptest.NewRequest("POST", "/api/v1/auth/passwords", nil)
	req.Header.Set("X-Yggdrasil-Auth-Admin-Token", "auth-secret")
	if err := authorizeAuthAdminRequest(req); err != nil {
		t.Fatalf("expected admin token to authorize request, got %v", err)
	}
}

func TestAuthorizeAuthAdminRequestFallsBackToWorkflowToken(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "workflow-secret")

	req := httptest.NewRequest("POST", "/api/v1/auth/mfa/enroll/request", nil)
	req.Header.Set("Authorization", "Bearer workflow-secret")
	if err := authorizeAuthAdminRequest(req); err != nil {
		t.Fatalf("expected workflow bearer token to authorize request, got %v", err)
	}
}

func TestAuthorizeAuthAdminRequestAcceptsAuthenticatedConsoleContext(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	req := httptest.NewRequest("POST", "/api/v1/console/auth/providers", nil)
	req = req.WithContext(contextWithClaims(req.Context(), map[string]any{"sub": "collab-1"}))
	if err := authorizeAuthAdminRequest(req); err != nil {
		t.Fatalf("expected console-authenticated request to authorize, got %v", err)
	}
}
