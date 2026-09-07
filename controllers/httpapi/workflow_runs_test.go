package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

func TestAuthorizeWorkflowRunRequestAllowsMissingTokenWhenUnset(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	if err := authorizeWorkflowRunRequest(req); err != nil {
		t.Fatalf("expected request to be allowed without configured token, got %v", err)
	}
}

func TestAuthenticatedConsoleGateKeepsCredentialFreeWorkflowDevCompatibilityExact(t *testing.T) {
	t.Setenv("YGGDRASIL_ENV", "dev")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv(workflowMachinePrincipalsEnv, "")
	t.Setenv(legacyScopedWorkflowTokensEnv, "")

	srv := &Server{}
	called := false
	handler := srv.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if !called || recorder.Code != http.StatusNoContent {
		t.Fatalf("credential-free dev workflow dispatch rejected: called=%v status=%d", called, recorder.Code)
	}

	called = false
	req = httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if called || recorder.Code != http.StatusUnauthorized {
		t.Fatalf("credential-free dev compatibility escaped workflow routes: called=%v status=%d", called, recorder.Code)
	}
}

func TestAuthorizeWorkflowRunRequestAcceptsSharedHeader(t *testing.T) {
	setTestLegacyWorkflowCredential(t, "shared-token")

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	req.Header.Set("X-Yggdrasil-Workflow-Token", "shared-token")
	if err := authorizeWorkflowRunRequest(req); err != nil {
		t.Fatalf("expected request to be authorized by explicit header, got %v", err)
	}
}

func TestAuthorizeWorkflowRunRequestAcceptsBearerToken(t *testing.T) {
	setTestLegacyWorkflowCredential(t, "shared-token")

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	req.Header.Set("Authorization", "Bearer shared-token")
	if err := authorizeWorkflowRunRequest(req); err != nil {
		t.Fatalf("expected request to be authorized by bearer token, got %v", err)
	}
}

func TestAuthorizeWorkflowRunRequestRejectsInvalidToken(t *testing.T) {
	setTestLegacyWorkflowCredential(t, "shared-token")

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	req.Header.Set("X-Yggdrasil-Workflow-Token", "wrong-token")
	if err := authorizeWorkflowRunRequest(req); err == nil {
		t.Fatalf("expected invalid token to be rejected")
	}
}

func TestAuthenticateWorkflowRunRequestResolvesHashedMachinePrincipal(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "cd-secret", "github-actions-cd-bot",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy-validation"}))

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	req.Header.Set("Authorization", "Bearer cd-secret")
	actor, err := authenticateWorkflowRunRequest(req)
	if err != nil {
		t.Fatalf("hashed workflow principal: %v", err)
	}
	if actor.Subject.Type != "service" || actor.Subject.ID != "github-actions-cd-bot" || actor.MachinePrincipalID != "github-actions-cd-bot" {
		t.Fatalf("unexpected machine actor: %+v", actor)
	}
}

func TestWorkflowMachinePrincipalCannotAuthorizeManifestWrites(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "cd-secret", "github-actions-cd-bot",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy-validation"}))

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/manifests", nil)
	req.Header.Set("Authorization", "Bearer cd-secret")
	if err := authorizeWorkflowRunRequest(req); err == nil {
		t.Fatal("workflow machine credential must not authorize manifest writes")
	}
}

func TestRawScopedWorkflowTokenConfigFailsClosed(t *testing.T) {
	setTestLegacyWorkflowCredential(t, "shared-token")
	t.Setenv(legacyScopedWorkflowTokensEnv, `[{"token":"raw-must-not-be-stored","subject":{"type":"service","id":"broken"}}]`)

	req := httptest.NewRequest("POST", "http://yggdrasil-core:9080/api/v1/workflow-runs", nil)
	req.Header.Set("Authorization", "Bearer shared-token")
	if _, err := authenticateWorkflowRunRequest(req); err == nil {
		t.Fatal("raw scoped-token configuration must fail closed, even for the legacy token")
	}
}

func TestAuthenticatedConsoleGateAcceptsMachinePrincipalOnlyOnCanonicalWorkflowRuns(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "cd-secret", "github-actions-cd-bot",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy-validation"}))

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
		t.Fatalf("workflow machine credential did not cross auth gate: called=%v status=%d", called, w.Code)
	}
	called = false
	req = httptest.NewRequest(http.MethodGet, "/api/v1/workflow-runs/00000000-0000-0000-0000-000000000001", nil)
	req.Header.Set("Authorization", "Bearer cd-secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if !called || w.Code != http.StatusNoContent {
		t.Fatalf("workflow machine credential did not cross canonical poll gate: called=%v status=%d", called, w.Code)
	}

	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/api/v1/manifests"},
		{method: http.MethodPost, path: "/api/v1/auth/providers"},
		{method: http.MethodGet, path: "/api/v1/ops/workflows"},
		{method: http.MethodGet, path: "/api/v1/secrets?include_values=true"},
		{method: http.MethodGet, path: "/api/v1/secrets/dakasa/production?include_values=true"},
		{method: http.MethodGet, path: "/api/v1/console/secrets?include_values=true"},
		{method: http.MethodGet, path: "/api/v1/workflow-runs"},
		{method: http.MethodPost, path: "/api/v1/workflow-runs/00000000-0000-0000-0000-000000000001"},
		{method: http.MethodDelete, path: "/api/v1/workflow-runs/00000000-0000-0000-0000-000000000001"},
		{method: http.MethodGet, path: "/api/v1/workflow-runs/00000000-0000-0000-0000-000000000001/steps"},
		{method: http.MethodPost, path: "/api/v1/console/workflow-runs"},
		{method: http.MethodGet, path: "/api/v1/console/workflow-runs/00000000-0000-0000-0000-000000000001"},
	} {
		called = false
		req = httptest.NewRequest(test.method, test.path, nil)
		req.Header.Set("Authorization", "Bearer cd-secret")
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if called || w.Code != http.StatusUnauthorized {
			t.Fatalf("workflow machine credential escaped to %s %s: called=%v status=%d", test.method, test.path, called, w.Code)
		}
	}
}

func TestLegacyWorkflowCredentialIsExplicitTimeBoundAndPathLimited(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "legacy-test-token")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT", "")

	workflowReq := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs", nil)
	workflowReq.Header.Set("Authorization", "Bearer legacy-test-token")
	if err := authorizeWorkflowRunRequest(workflowReq); err == nil {
		t.Fatal("legacy token without explicit migration settings was accepted")
	}

	setTestLegacyWorkflowCredential(t, "legacy-test-token")
	if err := authorizeWorkflowRunRequest(workflowReq); err != nil {
		t.Fatalf("explicit unexpired legacy migration credential rejected: %v", err)
	}
	for _, path := range []string{
		"/api/v1/events",
		"/api/v1/manifests",
		"/api/v1/ops/workflows",
		"/api/v1/auth/passwords",
		"/api/v1/products/deploy-all",
	} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer legacy-test-token")
		if err := authorizeWorkflowRunRequest(req); err == nil {
			t.Fatalf("legacy workflow credential escaped to %s", path)
		}
	}

	t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT", "2020-01-01T00:00:00Z")
	if err := authorizeWorkflowRunRequest(workflowReq); err == nil {
		t.Fatal("expired legacy workflow credential was accepted")
	}
}

func TestWorkflowMachineDispatchFailsClosedWithoutManifestAuthorization(t *testing.T) {
	for _, test := range []struct {
		name       string
		allowedRef machineWorkflowRef
		wantDenied bool
	}{
		{
			name:       "exact allowlist still requires authorization",
			allowedRef: machineWorkflowRef{Namespace: "dakasa", Name: "deploy-validation"},
			wantDenied: true,
		},
		{
			name:       "different workflow",
			allowedRef: machineWorkflowRef{Namespace: "dakasa", Name: "deploy-something-else"},
			wantDenied: true,
		},
		{
			name:       "different namespace",
			allowedRef: machineWorkflowRef{Namespace: "other", Name: "deploy-validation"},
			wantDenied: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			expectWorkflowAuthorizationManifest(mock, "workflow", "deploy-validation", `{"steps":[]}`)

			principal := &workflowMachinePrincipal{
				PrincipalID: "github-actions-cd-bot",
				AllowedWorkflows: map[machineWorkflowRef]struct{}{
					test.allowedRef: {},
				},
			}
			err = (&Server{db: db}).authorizeWorkflowDispatch(context.Background(), model.RunWorkflowRequest{
				Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "deploy-validation"},
			}, workflowRunActor{
				Subject:            model.RBACSubject{Type: "service", ID: principal.PrincipalID},
				MachinePrincipalID: principal.PrincipalID,
				MachinePrincipal:   principal,
			})
			if errors.Is(err, errWorkflowAuthorizationDenied) != test.wantDenied {
				t.Fatalf("denied=%v, want %v; err=%v", errors.Is(err, errWorkflowAuthorizationDenied), test.wantDenied, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHandleWorkflowRunMachineRejectsHistoricalSelectorsBeforeLookup(t *testing.T) {
	t.Setenv("BROKER_URL", "amqp://unit-test")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED", "")
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT", "")
	t.Setenv(legacyScopedWorkflowTokensEnv, "")
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "machine-token", "ci-dakasa",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy"}))

	server := &Server{rabbitmq: &amqp.Connection{}}
	for _, test := range []struct {
		name string
		body string
	}{
		{
			name: "manifest id",
			body: `{"workflow":{"manifest_id":"11111111-1111-1111-1111-111111111111","namespace":"dakasa","name":"deploy"}}`,
		},
		{
			name: "explicit version",
			body: `{"workflow":{"namespace":"dakasa","name":"deploy","version":1}}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs", strings.NewReader(test.body))
			req.Header.Set("Authorization", "Bearer machine-token")
			recorder := httptest.NewRecorder()

			server.handleWorkflowRun(recorder, req)

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status=%d, want %d; body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "current active workflow") {
				t.Fatalf("response did not identify current-active selector requirement: %s", recorder.Body.String())
			}
		})
	}
}

func TestWorkflowMachineAllowlistDeniesBeforeManifestAuthorization(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	expectWorkflowAuthorizationManifest(mock, "workflow", "deploy-validation", `{"authorization":{"rbac":{"namespace":"dakasa","name":"machine-rbac"}},"steps":[]}`)

	principal := &workflowMachinePrincipal{
		PrincipalID: "github-actions-cd-bot",
		AllowedWorkflows: map[machineWorkflowRef]struct{}{
			{Namespace: "dakasa", Name: "different-workflow"}: {},
		},
	}
	err = (&Server{db: db}).authorizeWorkflowDispatch(context.Background(), model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "deploy-validation"},
	}, workflowRunActor{
		Subject:            model.RBACSubject{Type: "service", ID: principal.PrincipalID},
		MachinePrincipalID: principal.PrincipalID,
		MachinePrincipal:   principal,
	})
	if !errors.Is(err, errWorkflowAuthorizationDenied) {
		t.Fatalf("out-of-allowlist workflow was not denied: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBindWorkflowRunMachineActorOverwritesSpoofAndScopesIdempotency(t *testing.T) {
	request := model.RunWorkflowRequest{Metadata: map[string]any{
		repository.WorkflowRunCreatorMachinePrincipalMetadataKey: "spoofed-principal",
		"idempotency_key": "caller-stable-key",
	}}
	bound, originalKey := bindWorkflowRunMachineActor(request, workflowRunActor{MachinePrincipalID: "authenticated-principal"})
	if got := bound.Metadata[repository.WorkflowRunCreatorMachinePrincipalMetadataKey]; got != "authenticated-principal" {
		t.Fatalf("creator metadata = %#v", got)
	}
	if originalKey != "caller-stable-key" {
		t.Fatalf("original idempotency key = %q", originalKey)
	}
	boundKey, _ := bound.Metadata["idempotency_key"].(string)
	if boundKey == "" || boundKey == originalKey {
		t.Fatalf("persisted idempotency key was not principal-scoped: %q", boundKey)
	}
	other, _ := bindWorkflowRunMachineActor(request, workflowRunActor{MachinePrincipalID: "other-principal"})
	if other.Metadata["idempotency_key"] == boundKey {
		t.Fatal("two principals received the same persisted idempotency key")
	}
	if request.Metadata[repository.WorkflowRunCreatorMachinePrincipalMetadataKey] != "spoofed-principal" {
		t.Fatal("binding mutated caller metadata in place")
	}

	humanBound, _ := bindWorkflowRunMachineActor(request, workflowRunActor{CollaboratorID: uuid.NewString()})
	if _, exists := humanBound.Metadata[repository.WorkflowRunCreatorMachinePrincipalMetadataKey]; exists {
		t.Fatal("client supplied reserved creator metadata survived a non-machine request")
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
			principal := &workflowMachinePrincipal{
				PrincipalID: "github-actions-cd-bot",
				AllowedWorkflows: map[machineWorkflowRef]struct{}{
					{Namespace: "dakasa", Name: "dakasa-deploy-component"}: {},
				},
			}
			err = srv.authorizeWorkflowDispatch(context.Background(), model.RunWorkflowRequest{
				Workflow: model.ManifestSelector{Namespace: "dakasa", Name: "dakasa-deploy-component"},
				Inputs:   map[string]any{"environment": tc.environment},
			}, workflowRunActor{
				Subject:            model.RBACSubject{Type: "service", ID: "github-actions-cd-bot"},
				MachinePrincipalID: "github-actions-cd-bot",
				MachinePrincipal:   principal,
			})
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
