package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWorkflowCredentialCannotAuthorizeDeployRoute(t *testing.T) {
	t.Setenv("YGGDRASIL_ENV", "dev")
	t.Setenv("YGGDRASIL_DEPLOY_TOKEN", "")
	setTestLegacyWorkflowCredential(t, "legacy-workflow-token")

	called := false
	handler := requireDeployToken(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/products/deploy-all", nil)
	req.Header.Set("X-Yggdrasil-Workflow-Token", "legacy-workflow-token")
	recorder := httptest.NewRecorder()
	handler(recorder, req)

	if called || recorder.Code != http.StatusUnauthorized {
		t.Fatalf("workflow credential escaped deploy boundary: called=%v status=%d", called, recorder.Code)
	}
}

func TestDedicatedDeployCredentialStillAuthorizesDeployRoute(t *testing.T) {
	t.Setenv("YGGDRASIL_DEPLOY_TOKEN", "dedicated-deploy-token")
	called := false
	handler := requireDeployToken(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/products/deploy-all", nil)
	req.Header.Set("Authorization", "Bearer dedicated-deploy-token")
	recorder := httptest.NewRecorder()
	handler(recorder, req)

	if !called || recorder.Code != http.StatusNoContent {
		t.Fatalf("dedicated deploy credential rejected: called=%v status=%d", called, recorder.Code)
	}
}

func TestOrdinarySessionCannotAuthorizeDirectDeployRoute(t *testing.T) {
	t.Setenv("YGGDRASIL_DEPLOY_TOKEN", "dedicated-deploy-token")

	direct := httptest.NewRequest(http.MethodPost, "/api/v1/products/deploy-all", nil)
	direct = direct.WithContext(contextWithClaims(direct.Context(), map[string]any{"collaborator_id": "ordinary-collaborator"}))
	if err := authorizeDeployRequest(direct); err == nil {
		t.Fatal("ordinary session claims authorized a direct deploy route without RBAC")
	}

	console := httptest.NewRequest(http.MethodPost, "/api/v1/console/products/deploy-all", nil)
	console = console.WithContext(contextWithClaims(console.Context(), map[string]any{"collaborator_id": "ordinary-collaborator"}))
	if err := authorizeDeployRequest(console); err != nil {
		t.Fatalf("RBAC-wrapped console deploy route rejected session claims: %v", err)
	}
}

func TestConsoleAuthGateAcceptsDedicatedDeployCredentialOnlyOnDeployPaths(t *testing.T) {
	t.Setenv("YGGDRASIL_DEPLOY_TOKEN", "dedicated-deploy-token")
	srv := &Server{}
	for _, test := range []struct {
		path       string
		wantCalled bool
	}{
		{path: "/api/v1/products/dakasa/app/deploy", wantCalled: true},
		{path: "/api/v1/integrations/install", wantCalled: true},
		{path: "/api/v1/manifests"},
		{path: "/api/v1/ops/workflows"},
	} {
		called := false
		handler := srv.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		}))
		req := httptest.NewRequest(http.MethodPost, test.path, nil)
		req.Header.Set("Authorization", "Bearer dedicated-deploy-token")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if called != test.wantCalled {
			t.Fatalf("path=%s called=%v, want %v status=%d", test.path, called, test.wantCalled, recorder.Code)
		}
	}
}
