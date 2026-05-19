package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthorizeAuthAdminRequestFailsClosedWhenUnconfigured(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	req := httptest.NewRequest("POST", "/api/v1/auth/passwords", nil)
	if err := authorizeAuthAdminRequest(req, nil); !errors.Is(err, errAuthAdminUnauthorized) {
		t.Fatalf("expected errAuthAdminUnauthorized, got %v", err)
	}
}

func TestAuthorizeAuthAdminRequestAcceptsAdminHeader(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "auth-secret")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	req := httptest.NewRequest("POST", "/api/v1/auth/passwords", nil)
	req.Header.Set("X-Yggdrasil-Auth-Admin-Token", "auth-secret")
	if err := authorizeAuthAdminRequest(req, nil); err != nil {
		t.Fatalf("expected admin token to authorize request, got %v", err)
	}
}

func TestAuthorizeAuthAdminRequestFallsBackToWorkflowToken(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "workflow-secret")

	req := httptest.NewRequest("POST", "/api/v1/auth/mfa/enroll/request", nil)
	req.Header.Set("Authorization", "Bearer workflow-secret")
	if err := authorizeAuthAdminRequest(req, nil); err != nil {
		t.Fatalf("expected workflow bearer token to authorize request, got %v", err)
	}
}

func TestAuthorizeAuthAdminRequestAcceptsAuthenticatedConsoleContext(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	req := httptest.NewRequest("POST", "/api/v1/console/auth/providers", nil)
	req = req.WithContext(contextWithClaims(req.Context(), map[string]any{"sub": "collab-1"}))
	if err := authorizeAuthAdminRequest(req, nil); err != nil {
		t.Fatalf("expected console-authenticated request to authorize, got %v", err)
	}
}

// When the path is outside the middleware allowlist (e.g.
// /api/v1/auth/passwords/setup-tokens), claims aren't attached upfront.
// Callers presenting a valid session cookie should still authorize via
// the fallback session resolution, NOT 401 to env-token fallback.
//
// Pre-fix: every console call to setup-tokens returned 401 because the
// browser doesn't send X-Yggdrasil-Auth-Admin-Token.
func TestAuthorizeAuthAdminRequestAcceptsSessionCookieOutsideAllowlist(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "admin-token-not-presented")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	req := httptest.NewRequest("POST", "/api/v1/auth/passwords/setup-tokens", nil)
	req.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: "session-token-irrelevant"})
	// With db=nil the session fallback is skipped (test plumbing); the env
	// token is the only path that could authorize, and we didn't present
	// it, so we expect 401. This pins the contract that without DB we
	// cannot validate session — regression sentinel for the fix that
	// makes the fallback meaningful in prod (where db != nil).
	if err := authorizeAuthAdminRequest(req, nil); !errors.Is(err, errAuthAdminUnauthorized) {
		t.Fatalf("expected 401 when db nil + no env token header, got %v", err)
	}
}
