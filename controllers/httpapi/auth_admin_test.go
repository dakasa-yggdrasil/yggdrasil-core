package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
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

func TestStaticAuthAdminCredentialPredicateDoesNotTreatSessionClaimsAsMachineToken(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "auth-secret")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/providers", nil)
	req = req.WithContext(contextWithClaims(req.Context(), map[string]any{
		"collaborator_id": uuid.NewString(),
		"sub":             uuid.NewString(),
	}))
	if requestHasStaticAuthAdminCredential(req) {
		t.Fatal("human session claims were mistaken for the static auth-admin credential")
	}
	req.Header.Set("X-Yggdrasil-Auth-Admin-Token", "auth-secret")
	if !requestHasStaticAuthAdminCredential(req) {
		t.Fatal("dedicated auth-admin header was not recognized")
	}
}

// SECURITY (account-takeover chain, 2026-08-11): the broadly-distributed
// YGGDRASIL_WORKFLOW_RUN_TOKEN must NOT act as auth-admin. Only the dedicated
// YGGDRASIL_AUTH_ADMIN_TOKEN authorizes the static-token path; presenting the
// workflow-run token as a Bearer is rejected.
func TestAuthorizeAuthAdminRequestRejectsWorkflowToken(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "workflow-secret")

	req := httptest.NewRequest("POST", "/api/v1/auth/mfa/enroll/request", nil)
	req.Header.Set("Authorization", "Bearer workflow-secret")
	if err := authorizeAuthAdminRequest(req, nil); !errors.Is(err, errAuthAdminUnauthorized) {
		t.Fatalf("expected workflow-run token to be rejected, got %v", err)
	}
}

func TestAuthorizeAuthAdminRequestRejectsHashedWorkflowMachinePrincipal(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "")
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "workflow-machine-token", "ci-dakasa",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy-validation"}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/enroll/request", nil)
	req.Header.Set("Authorization", "Bearer workflow-machine-token")
	if err := authorizeAuthAdminRequest(req, nil); !errors.Is(err, errAuthAdminUnauthorized) {
		t.Fatalf("expected workflow machine credential to be rejected, got %v", err)
	}
}

// SECURITY (account-takeover chain, 2026-08-11): a bare authenticated console
// context is NOT admin. Presence of claims proves authentication only; the
// resolved collaborator must hold a REAL admin capability. Without a db to
// resolve that capability the request fails closed.
func TestAuthorizeAuthAdminRequestRejectsBareConsoleContext(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	req := httptest.NewRequest("POST", "/api/v1/console/auth/providers", nil)
	req = req.WithContext(contextWithClaims(req.Context(), map[string]any{"sub": "collab-1"}))
	if err := authorizeAuthAdminRequest(req, nil); !errors.Is(err, errAuthAdminUnauthorized) {
		t.Fatalf("expected bare console context to be rejected (no admin capability resolvable), got %v", err)
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

func TestConsoleAuthGateAcceptsDedicatedAuthAdminCredentialOnExactMutations(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "dedicated-auth-admin-token")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv(workflowMachinePrincipalsEnv, "")
	t.Setenv(legacyScopedWorkflowTokensEnv, "")

	routes := []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/api/v1/auth/third-party-identities"},
		{method: http.MethodDelete, path: "/api/v1/auth/third-party-identities/oidc/subject"},
		{method: http.MethodPost, path: "/api/v1/auth/providers"},
		{method: http.MethodDelete, path: "/api/v1/auth/providers/oidc"},
		{method: http.MethodPost, path: "/api/v1/auth/scim/clients"},
		{method: http.MethodPost, path: "/api/v1/auth/saml/service-providers"},
		{method: http.MethodPost, path: "/api/v1/auth/saml/rotate-signing-cert"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			server := &Server{}
			called := false
			handler := server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				// Destination auth handlers perform this same revalidation after
				// the outer route-scoped bypass.
				if err := authorizeAuthAdminRequest(r, server.db); err != nil {
					t.Fatalf("destination revalidation rejected dedicated credential: %v", err)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequest(route.method, route.path, nil)
			req.Header.Set("X-Yggdrasil-Auth-Admin-Token", "dedicated-auth-admin-token")
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, req)

			if !called || recorder.Code != http.StatusNoContent {
				t.Fatalf("dedicated auth-admin credential did not reach handler: called=%v status=%d body=%s", called, recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestConsoleAuthGateRejectsWorkflowCredentialsOnAuthAdminMutations(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "dedicated-auth-admin-token")
	routes := []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/api/v1/auth/third-party-identities"},
		{method: http.MethodDelete, path: "/api/v1/auth/third-party-identities/oidc/subject"},
		{method: http.MethodPost, path: "/api/v1/auth/providers"},
		{method: http.MethodDelete, path: "/api/v1/auth/providers/oidc"},
		{method: http.MethodPost, path: "/api/v1/auth/scim/clients"},
		{method: http.MethodPost, path: "/api/v1/auth/saml/service-providers"},
		{method: http.MethodPost, path: "/api/v1/auth/saml/rotate-signing-cert"},
	}
	credentials := []struct {
		name   string
		token  string
		setEnv func(*testing.T)
	}{
		{
			name:  "hashed machine principal",
			token: "workflow-machine-token",
			setEnv: func(t *testing.T) {
				t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
				t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "workflow-machine-token", "ci-dakasa",
					machineWorkflowRef{Namespace: "dakasa", Name: "deploy-validation"}))
			},
		},
		{
			name:  "legacy migration credential",
			token: "legacy-workflow-token",
			setEnv: func(t *testing.T) {
				t.Setenv(workflowMachinePrincipalsEnv, "")
				setTestLegacyWorkflowCredential(t, "legacy-workflow-token")
			},
		},
	}

	for _, credential := range credentials {
		t.Run(credential.name, func(t *testing.T) {
			credential.setEnv(t)
			for _, route := range routes {
				t.Run(route.method+" "+route.path, func(t *testing.T) {
					called := false
					handler := (&Server{}).requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
						called = true
					}))
					req := httptest.NewRequest(route.method, route.path, nil)
					req.Header.Set("Authorization", "Bearer "+credential.token)
					recorder := httptest.NewRecorder()

					handler.ServeHTTP(recorder, req)

					if called || recorder.Code != http.StatusUnauthorized {
						t.Fatalf("workflow credential crossed auth-admin outer gate: called=%v status=%d body=%s", called, recorder.Code, recorder.Body.String())
					}
				})
			}
		})
	}
}

func TestConsoleAuthGateDoesNotBypassRBACForLowPrivilegeSessionOnAuthMutation(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "dedicated-auth-admin-token")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv(workflowMachinePrincipalsEnv, "")
	t.Setenv(legacyScopedWorkflowTokensEnv, "")
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "enforce")

	server, mock := rbacTestSetup(t)
	collaboratorID := uuid.New()
	// Human claims never enter the static-token bypass. The route's existing
	// permission wrapper evaluates manage_auth_providers, which this
	// low-privilege collaborator does not hold.
	programCollaboratorWithPermissions(mock, collaboratorID, nil)

	called := false
	destination := server.requireOpsPermission(permManageAuthProviders)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	handler := server.requireAuthenticatedConsoleAPIs(destination)
	req := rbacTestRequestWithClaims(http.MethodPost, "/api/v1/auth/providers", collaboratorID)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if called || recorder.Code != http.StatusForbidden {
		t.Fatalf("low-privilege session bypassed auth-provider RBAC: called=%v status=%d body=%s", called, recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthAdministrationMutationMatchesOnlyRegisteredRouteShapes(t *testing.T) {
	for _, test := range []struct {
		method string
		path   string
		want   bool
	}{
		{method: http.MethodDelete, path: "/api/v1/auth/providers/oidc", want: true},
		{method: http.MethodDelete, path: "/api/v1/auth/third-party-identities/oidc/subject", want: true},
		{method: http.MethodGet, path: "/api/v1/auth/providers/oidc"},
		{method: http.MethodDelete, path: "/api/v1/auth/providers/"},
		{method: http.MethodDelete, path: "/api/v1/auth/providers/oidc/extra"},
		{method: http.MethodDelete, path: "/api/v1/auth/third-party-identities/oidc"},
		{method: http.MethodDelete, path: "/api/v1/auth/third-party-identities/oidc/subject/extra"},
		{method: http.MethodPost, path: "/api/v1/manifests"},
	} {
		if got := authAdministrationMutation(test.method, test.path); got != test.want {
			t.Fatalf("%s %s matched=%v, want %v", test.method, test.path, got, test.want)
		}
	}
}
