package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/httperr"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/workflowdispatchlock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestWorkflowDispatchLockHasStableHTTPMapping(t *testing.T) {
	if got := httpStatusFromError(workflowdispatchlock.ErrLocked); got != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", got, http.StatusServiceUnavailable)
	}
	if got := codeFromError(workflowdispatchlock.ErrLocked, http.StatusServiceUnavailable); got != httperr.CodeWorkflowDispatchLocked {
		t.Fatalf("code = %q, want %q", got, httperr.CodeWorkflowDispatchLocked)
	}
}

func TestManifestMutationHandlersReturnStableLockResponse(t *testing.T) {
	t.Setenv(workflowdispatchlock.EnvName, `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`)
	server := &Server{}

	for _, test := range []struct {
		name    string
		request *http.Request
		handle  func(http.ResponseWriter, *http.Request)
	}{
		{
			name:    "create",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/manifests?kind=workflow", strings.NewReader(`{}`)),
			handle: func(w http.ResponseWriter, r *http.Request) {
				server.handleManifestCreate(w, r, "workflow")
			},
		},
		{
			name:    "delete",
			request: httptest.NewRequest(http.MethodDelete, "/api/v1/manifests/not-parsed", nil),
			handle:  server.handleManifestDelete,
		},
		{
			name:    "integration instance create",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/integration-instances", strings.NewReader(`{}`)),
			handle:  server.handleIntegrationInstanceCreate,
		},
		{
			name:    "catalog discovery register",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/catalog/discovery/register", strings.NewReader(`{}`)),
			handle:  server.handleCatalogDiscoveryRegister,
		},
		{
			name:    "catalog discovery adapter call",
			request: httptest.NewRequest(http.MethodGet, "/api/v1/console/catalog-discovery", nil),
			handle:  server.handleCatalogDiscovery,
		},
		{
			name:    "guardian memory review",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/guardian-memory/review", strings.NewReader(`{}`)),
			handle:  server.handleGuardianMemoryReview,
		},
		{
			name:    "guardian approval decision",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/guardian-approvals/global/example/decision", strings.NewReader(`{}`)),
			handle:  server.handleGuardianApprovalDecision,
		},
		{
			name:    "managed secret create",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/secrets", strings.NewReader(`{}`)),
			handle:  server.handleManagedSecretCreate,
		},
		{
			name:    "managed secret rotate",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/secrets/dakasa/example/rotate", strings.NewReader(`{}`)),
			handle:  server.handleManagedSecretRotate,
		},
		{
			name:    "managed secret disable",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/secrets/dakasa/example/disable", strings.NewReader(`{}`)),
			handle:  server.handleManagedSecretDisable,
		},
		{
			name:    "managed secret revoke",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/secrets/dakasa/example/revoke", strings.NewReader(`{}`)),
			handle:  server.handleManagedSecretRevoke,
		},
		{
			name:    "materialize one",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/secrets/dakasa/example/materialize", nil),
			handle:  server.handleMaterializeOne,
		},
		{
			name:    "materialize all",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/secrets/materialize-all", nil),
			handle:  server.handleMaterializeAll,
		},
		{
			name:    "AWS provisioner",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/provision/aws", strings.NewReader(`{}`)),
			handle:  server.handleProvisionAWS,
		},
		{
			name:    "surface action",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/ops/surfaces/example/action/apply", strings.NewReader(`{}`)),
			handle:  server.handleOpsSurfaceAction,
		},
		{
			name:    "third-party identity upsert",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/auth/third-party-identities", strings.NewReader(`{}`)),
			handle:  server.handleThirdPartyIdentityUpsert,
		},
		{
			name:    "third-party identity delete",
			request: httptest.NewRequest(http.MethodDelete, "/api/v1/auth/third-party-identities/google/example", nil),
			handle:  server.handleThirdPartyIdentityDelete,
		},
		{
			name:    "third-party provider upsert",
			request: httptest.NewRequest(http.MethodPost, "/api/v1/auth/providers", strings.NewReader(`{}`)),
			handle:  server.handleThirdPartyAuthProviderUpsert,
		},
		{
			name:    "third-party provider delete",
			request: httptest.NewRequest(http.MethodDelete, "/api/v1/auth/providers/google", nil),
			handle:  server.handleThirdPartyAuthProviderDelete,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.request = test.request.WithContext(contextWithClaims(test.request.Context(), map[string]any{
				"collaborator_id": "operator",
			}))
			recorder := httptest.NewRecorder()
			test.handle(recorder, test.request)
			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), httperr.CodeWorkflowDispatchLocked) {
				t.Fatalf("body = %s, want stable lock code", recorder.Body.String())
			}
		})
	}
}

func TestGitHubWebhookChecksLockBeforeAcknowledgingDispatch(t *testing.T) {
	t.Setenv(workflowdispatchlock.EnvName, `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`)
	server, mock, cleanup := newWebhookTestServer(t)
	defer cleanup()

	const spec = `{
		"component_kind":"product","component_name":"x","repository":"acme/widget",
		"deploy":{
			"workflow_kind":"yggdrasil",
			"workflow_ref":{"namespace":"acme","name":"deploy"},
			"branch_filter":["main"]
		}
	}`
	mock.ExpectQuery(regexp.QuoteMeta(findBindingQuery)).
		WithArgs("acme/widget").
		WillReturnRows(bindingRows(spec))

	dispatched := false
	server.dispatchWorkflow = func(context.Context, model.ManifestSelector, map[string]any) error {
		dispatched = true
		return nil
	}
	recorder := performPushRequest(t, server, pushPayload("acme/widget", "refs/heads/main"))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if dispatched {
		t.Fatal("locked webhook started asynchronous dispatch")
	}
}

func TestIntegrationInstallRefusesNonDryRunBeforePersistence(t *testing.T) {
	t.Setenv(workflowdispatchlock.EnvName, `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`)
	t.Setenv("YGGDRASIL_DEPLOY_TOKEN", "deploy-token")
	quickstart := []byte(`apiVersion: yggdrasil.io/v1alpha1
kind: integration_quickstart
metadata:
  name: locked-install
  namespace: global
spec:
  providers:
    - id: test-provider
      steps:
        - id: register
          uses:
            kind: integration
            family: test-family
            operation: ensure_test
`)
	body, err := json.Marshal(model.InstallIntegrationRequest{
		ManifestInline: quickstart,
		ProviderID:     "test-provider",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/install", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer deploy-token")
	recorder := httptest.NewRecorder()
	(&Server{}).handleInstallIntegration(recorder, req)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), httperr.CodeWorkflowDispatchLocked) {
		t.Fatalf("body = %s, want stable lock code", recorder.Body.String())
	}
}
