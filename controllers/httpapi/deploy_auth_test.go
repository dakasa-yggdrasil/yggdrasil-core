package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"go.uber.org/zap"
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

// deployCredentialTestPaths lists one request per route family that
// authorizeDeployRequest guards: the direct and console integration install,
// bootstrap, deploy-all and per-product deploy routes.
var deployCredentialTestPaths = []string{
	"/api/v1/integrations/install",
	"/api/v1/console/integrations/install",
	"/api/v1/bootstrap",
	"/api/v1/console/bootstrap",
	"/api/v1/products/deploy-all",
	"/api/v1/console/products/deploy-all",
	"/api/v1/products/dakasa/app/deploy",
	"/api/v1/console/products/dakasa/app/deploy",
}

// ADR-0022: with no deploy token configured, a request that presents no
// credential passes only when YGGDRASIL_ENV explicitly names a development
// environment. An unset value is how a production Core may run, so it must
// fail closed like production itself.
func TestAuthorizeDeployRequestAnonymousNeedsExplicitDevelopmentEnvironment(t *testing.T) {
	unset := "<unset>"
	for _, test := range []struct {
		environment string
		wantAllowed bool
	}{
		{environment: unset},
		{environment: ""},
		{environment: "production"},
		{environment: "prod"},
		{environment: "PRODUCTION"},
		{environment: "staging"},
		{environment: "dev", wantAllowed: true},
		{environment: "development", wantAllowed: true},
		{environment: "local", wantAllowed: true},
		{environment: "test", wantAllowed: true},
		{environment: " Development ", wantAllowed: true},
	} {
		for _, path := range deployCredentialTestPaths {
			t.Run(test.environment+" "+path, func(t *testing.T) {
				t.Setenv("YGGDRASIL_DEPLOY_TOKEN", "")
				if test.environment == unset {
					unsetEnvForTest(t, "YGGDRASIL_ENV")
				} else {
					t.Setenv("YGGDRASIL_ENV", test.environment)
				}
				err := authorizeDeployRequest(httptest.NewRequest(http.MethodPost, path, nil))
				if test.wantAllowed && err != nil {
					t.Fatalf("explicit development environment refused an anonymous deploy request: %v", err)
				}
				if !test.wantAllowed && err == nil {
					t.Fatal("anonymous deploy request accepted without an explicit development YGGDRASIL_ENV")
				}
			})
		}
	}
}

// A configured deploy token keeps the anonymous posture closed even in an
// explicit development environment, and a presented credential never falls
// into it.
func TestAuthorizeDeployRequestAnonymousStaysClosedWhenAnythingIsConfiguredOrPresented(t *testing.T) {
	t.Setenv("YGGDRASIL_ENV", "dev")

	t.Setenv("YGGDRASIL_DEPLOY_TOKEN", "dedicated-deploy-token")
	if err := authorizeDeployRequest(httptest.NewRequest(http.MethodPost, "/api/v1/integrations/install", nil)); err == nil {
		t.Fatal("anonymous install accepted while a deploy token is configured")
	}

	t.Setenv("YGGDRASIL_DEPLOY_TOKEN", "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/install", nil)
	req.Header.Set("X-Yggdrasil-Event-Token", "some-event-token")
	if err := authorizeDeployRequest(req); err == nil {
		t.Fatal("a request presenting a foreign credential fell into the anonymous posture")
	}
}

const deployAuthQuickstartYAML = `apiVersion: yggdrasil.io/v1alpha1
kind: integration_quickstart
metadata:
  name: secrets-management
  namespace: global
spec:
  display_name: Secrets Management
  providers:
    - id: aws-secrets-manager
      display_name: AWS
      inputs:
        - id: region
          label: Region
          type: string
          required: true
      steps:
        - id: register
          uses:
            kind: integration
            family: secrets-management
            operation: upsert_secret
          with:
            secret_id: probe
`

// The whole request pipeline (console gate, CSRF, ops permission wrapper and
// handler) for an anonymous integration install. Without an explicit
// development YGGDRASIL_ENV the gate answers 401 before the handler fetches,
// compiles or persists anything, and the database is never touched. The dry
// run keeps the development case free of PostgreSQL and RabbitMQ.
func TestAnonymousIntegrationInstallNeedsExplicitDevelopmentEnvironment(t *testing.T) {
	unset := "<unset>"
	for _, test := range []struct {
		name        string
		environment string
		path        string
		wantStatus  int
	}{
		{name: "unset direct", environment: unset, path: "/api/v1/integrations/install", wantStatus: http.StatusUnauthorized},
		{name: "unset console", environment: unset, path: "/api/v1/console/integrations/install", wantStatus: http.StatusUnauthorized},
		{name: "blank direct", environment: "", path: "/api/v1/integrations/install", wantStatus: http.StatusUnauthorized},
		{name: "staging direct", environment: "staging", path: "/api/v1/integrations/install", wantStatus: http.StatusUnauthorized},
		{name: "dev direct", environment: "dev", path: "/api/v1/integrations/install", wantStatus: http.StatusOK},
		{name: "development console", environment: "development", path: "/api/v1/console/integrations/install", wantStatus: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			clearMachineCredentialEnv(t)
			if test.environment == unset {
				unsetEnvForTest(t, "YGGDRASIL_ENV")
			} else {
				t.Setenv("YGGDRASIL_ENV", test.environment)
			}

			fetches := 0
			previousFetcher := quickstartFetcher
			t.Cleanup(func() { quickstartFetcher = previousFetcher })
			quickstartFetcher = func(_ context.Context, _ repoRefSpec) ([]byte, error) {
				fetches++
				return []byte(deployAuthQuickstartYAML), nil
			}

			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			handler, err := New("yggdrasil-core-test", db, nil, zap.NewNop())
			if err != nil {
				t.Fatalf("boot real server: %v", err)
			}

			body := strings.NewReader(`{"repo_ref":"foo/bar","provider_id":"aws-secrets-manager","inputs":{"region":"us-east-1"},"dry_run":true}`)
			req := httptest.NewRequest(http.MethodPost, test.path, body)
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), test.wantStatus)
			}
			if test.wantStatus == http.StatusOK {
				var resp struct {
					CompiledWorkflow map[string]any `json:"compiled_workflow"`
				}
				if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil || resp.CompiledWorkflow == nil {
					t.Fatalf("development dry run did not compile the workflow: err=%v body=%s", err, recorder.Body.String())
				}
				if fetches != 1 {
					t.Fatalf("development dry run fetched the quickstart %d times, want 1", fetches)
				}
			} else if fetches != 0 {
				t.Fatalf("refused install still reached the handler: %d fetches", fetches)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
