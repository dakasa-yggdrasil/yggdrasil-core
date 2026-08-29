package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func TestAuthorizeWorkflowRunRequestAllowsMissingTokenWhenUnset(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	if err := authorizeWorkflowRunRequest(req); err != nil {
		t.Fatalf("expected request to be allowed without configured token, got %v", err)
	}
}

func TestAuthorizeWorkflowRunRequestAcceptsSharedHeader(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "shared-token")

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	req.Header.Set("X-Yggdrasil-Workflow-Token", "shared-token")
	if err := authorizeWorkflowRunRequest(req); err != nil {
		t.Fatalf("expected request to be authorized by explicit header, got %v", err)
	}
}

func TestAuthorizeWorkflowRunRequestAcceptsBearerToken(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "shared-token")

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	req.Header.Set("Authorization", "Bearer shared-token")
	if err := authorizeWorkflowRunRequest(req); err != nil {
		t.Fatalf("expected request to be authorized by bearer token, got %v", err)
	}
}

func TestAuthorizeWorkflowRunRequestRejectsInvalidToken(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "shared-token")

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	req.Header.Set("X-Yggdrasil-Workflow-Token", "wrong-token")
	if err := authorizeWorkflowRunRequest(req); err == nil {
		t.Fatalf("expected invalid token to be rejected")
	}
}

func TestAuthenticateWorkflowRunRequestResolvesScopedSubject(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON", `[{"token":"cd-secret","subject":{"type":"service","id":"github-actions-cd-bot"}}]`)

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	req.Header.Set("Authorization", "Bearer cd-secret")
	actor, err := authenticateWorkflowRunRequest(req)
	if err != nil {
		t.Fatalf("scoped workflow token: %v", err)
	}
	if actor.Subject.Type != "service" || actor.Subject.ID != "github-actions-cd-bot" {
		t.Fatalf("unexpected scoped actor: %+v", actor)
	}
}

func TestScopedWorkflowTokenCannotAuthorizeManifestWrites(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON", `[{"token":"cd-secret","subject":{"type":"service","id":"github-actions-cd-bot"}}]`)

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/manifests", nil)
	req.Header.Set("Authorization", "Bearer cd-secret")
	if err := authorizeWorkflowRunRequest(req); err == nil {
		t.Fatal("workflow-scoped token must not authorize manifest writes")
	}
}

func TestWorkflowScopedTokenConfigFailsClosed(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "shared-token")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON", `[{"token":"","subject":{"type":"service","id":"broken"}}]`)

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	req.Header.Set("Authorization", "Bearer shared-token")
	if _, err := authenticateWorkflowRunRequest(req); err == nil {
		t.Fatal("invalid scoped-token configuration must fail closed, even for the legacy token")
	}
}

func TestAuthenticatedConsoleGateAcceptsScopedTokenOnlyOnWorkflowRuns(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON", `[{"token":"cd-secret","subject":{"type":"service","id":"github-actions-cd-bot"}}]`)

	srv := &Server{}
	called := false
	handler := srv.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs", nil)
	req.Header.Set("Authorization", "Bearer cd-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if !called || w.Code != http.StatusNoContent {
		t.Fatalf("workflow scoped token did not cross auth gate: called=%v status=%d", called, w.Code)
	}

	called = false
	req = httptest.NewRequest(http.MethodPost, "/api/v1/manifests", nil)
	req.Header.Set("Authorization", "Bearer cd-secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if called || w.Code != http.StatusUnauthorized {
		t.Fatalf("workflow scoped token escaped to manifest route: called=%v status=%d", called, w.Code)
	}
}

func TestAuthorizeWorkflowDispatchEvaluatesCatalogPolicy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		environment string
		wantDenied  bool
	}{
		{name: "validation allowed", environment: "validation"},
		{name: "production denied", environment: "production", wantDenied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })

			workflowSpec := `{"authorization":{"rbac":{"namespace":"dakasa","name":"dakasa-validation-rbac"},"policy":{"namespace":"dakasa","name":"dakasa-validation-policy"}},"defaults":{"environment":"validation"},"steps":[]}`
			rbacSpec := `{"roles":[{"name":"cd-dispatcher","rules":[{"effect":"allow","resources":["workflow:dakasa:dakasa-deploy-component"],"actions":["run"]}]}],"bindings":[{"name":"cd","subjects":[{"type":"service","id":"github-actions-cd-bot"}],"roles":["cd-dispatcher"]}]}`
			policySpec := `{"rules":[{"name":"allow-validation","effect":"allow","resources":["workflow:dakasa:dakasa-deploy-component"],"actions":["run"],"conditions":[{"key":"input.environment","operator":"eq","value":"validation"}]},{"name":"deny-production","effect":"deny","resources":["workflow:dakasa:dakasa-deploy-component"],"actions":["run"],"conditions":[{"key":"subject.id","operator":"eq","value":"github-actions-cd-bot"},{"key":"input.environment","operator":"neq","value":"validation"}]}]}`
			expectWorkflowAuthorizationManifest(mock, "workflow", "dakasa-deploy-component", workflowSpec)
			expectWorkflowAuthorizationManifest(mock, "rbac", "dakasa-validation-rbac", rbacSpec)
			expectWorkflowAuthorizationManifest(mock, "policy", "dakasa-validation-policy", policySpec)
			// Authorization audit is best-effort. A failed audit transaction must
			// not alter the already-computed allow/deny decision.
			mock.ExpectBegin().WillReturnError(errors.New("audit unavailable"))

			srv := &Server{db: db, logger: zap.NewNop()}
			err = srv.authorizeWorkflowDispatch(context.Background(), model.RunWorkflowRequest{
				Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "dakasa-deploy-component"},
				Inputs:   map[string]any{"environment": tc.environment},
			}, workflowRunActor{Subject: model.RBACSubject{Type: "service", ID: "github-actions-cd-bot"}})
			if tc.wantDenied != errors.Is(err, errWorkflowAuthorizationDenied) {
				t.Fatalf("environment=%s denied=%v err=%v", tc.environment, tc.wantDenied, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func expectWorkflowAuthorizationManifest(mock sqlmock.Sqlmock, kind, name, spec string) {
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id", "api_version", "kind", "namespace", "name", "version", "active",
		"description", "labels", "spec", "checksum", "created_at", "updated_at",
	}).AddRow(uuid.New(), "yggdrasil.io/v1alpha1", kind, "dakasa", name, 1, true,
		"", []byte(`{}`), []byte(spec), "sha256:test", now, now)
	mock.ExpectQuery(`FROM public\.manifests`).
		WithArgs(kind, "dakasa", name).
		WillReturnRows(rows)
}
