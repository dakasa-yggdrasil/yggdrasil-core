package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRequireAuthenticatedConsoleAPIs_GuardsLeakingGETs locks down the
// audit-flagged endpoints (security audit 2026-05-27 A2) that previously
// returned internal infra configuration without authentication —
// credential-ref paths, integration instance topology, secret last-4,
// managed permission catalogs, workflow inventory, etc.
//
// Each route MUST refuse anonymous traffic with 401.
func TestRequireAuthenticatedConsoleAPIs_GuardsLeakingGETs(t *testing.T) {
	s := &Server{}
	handler := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler should not be called without a session")
	}))

	// Endpoints the audit found leaking infra data when called anonymously.
	leakers := []string{
		"/api/v1/secrets",
		"/api/v1/secrets/aws/foo",
		"/api/v1/permissions/catalog",
		"/api/v1/permissions/bindings",
		"/api/v1/workflows",
		"/api/v1/integration-instances",
		"/api/v1/integration-runtime-states",
		"/api/v1/integration-catalog",
		"/api/v1/manifests?kind=workflow",
		"/api/v1/repository-bindings",
		"/api/v1/guardian-policies",
		"/api/v1/guardian-approvals",
		"/api/v1/guardian-memories",
		"/api/v1/remediation-bundles",
		"/api/v1/remediation-contracts",
		"/api/v1/surfaces",
		"/api/v1/products",
		"/api/v1/integration-surfaces",
		"/api/v1/audit",
		"/api/v1/reconciler/status",
		"/api/v1/catalog/discovery",
	}

	for _, path := range leakers {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, r)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("status: got %d, want %d (path=%s)", w.Code, http.StatusUnauthorized, path)
			}
		})
	}
}

// TestRequireAuthenticatedConsoleAPIs_AllowsPublicAuthAndDiscovery
// preserves the explicit public surface — login, OIDC discovery,
// healthz/readyz, MFA enrollment validation — so the auth gate does
// not lock out unauthenticated callers from the routes that are
// supposed to be public.
func TestRequireAuthenticatedConsoleAPIs_AllowsPublicAuthAndDiscovery(t *testing.T) {
	s := &Server{}
	publicPaths := []string{
		"/healthz",
		"/readyz",
		"/metrics",
		"/openapi.json",
		"/.well-known/openid-configuration",
		"/api/v1/auth/login",
		"/api/v1/auth/session",
		"/api/v1/auth/logout",
		"/api/v1/auth/passwords/forgot",
		"/api/v1/auth/passwords/reset",
		"/api/v1/auth/passwords/setup",
		"/api/v1/auth/mfa/enroll/request",
		"/api/v1/auth/mfa/enroll/validate",
		"/api/v1/auth/providers",
		"/api/v1/auth/third-party/login",
		"/api/v1/tenant/brand",
	}

	for _, path := range publicPaths {
		t.Run(path, func(t *testing.T) {
			called := false
			handler := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			}))

			r := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if !called {
				t.Errorf("public path %s should pass through (status=%d)", path, w.Code)
			}
		})
	}
}
