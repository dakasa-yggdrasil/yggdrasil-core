package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func setEventPublishAuthEnvironment(t *testing.T, eventToken, workflowToken string) {
	t.Helper()
	if eventToken == "" {
		t.Setenv(legacyEventPublishTokenEnv, "")
		t.Setenv(legacyEventPublishEnabledEnv, "")
		t.Setenv(legacyEventPublishExpiryEnv, "")
	} else {
		setTestLegacyEventPublishCredential(t, eventToken)
	}
	t.Setenv(eventPublisherPrincipalsEnv, "")
	t.Setenv(workflowMachinePrincipalsEnv, "")
	t.Setenv(legacyScopedWorkflowTokensEnv, "")
	if workflowToken == "" {
		t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
		t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED", "")
		t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT", "")
	} else {
		setTestLegacyWorkflowCredential(t, workflowToken)
	}
}

func TestAuthorizeEventPublishRequestAcceptsDedicatedToken(t *testing.T) {
	setEventPublishAuthEnvironment(t, "event-only-token", "workflow-token")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer event-only-token")
	if err := authorizeEventPublishRequest(req); err != nil {
		t.Fatalf("dedicated event token rejected: %v", err)
	}
}

func TestLegacyEventPublishCredentialIsExplicitAndTimeBound(t *testing.T) {
	setEventPublishAuthEnvironment(t, "", "")
	t.Setenv(legacyEventPublishTokenEnv, "legacy-event-token")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer legacy-event-token")
	if err := authorizeEventPublishRequest(req); err == nil {
		t.Fatal("legacy event credential without explicit migration settings was accepted")
	}

	setTestLegacyEventPublishCredential(t, "legacy-event-token")
	if err := authorizeEventPublishRequest(req); err != nil {
		t.Fatalf("explicit unexpired legacy event credential rejected: %v", err)
	}
	actor, err := authenticateEventPublishRequest(req)
	if err != nil {
		t.Fatalf("authenticate explicit legacy event credential: %v", err)
	}
	if !actor.LegacyMigration || actor.MachinePrincipal != nil {
		t.Fatalf("legacy event credential actor = %+v, want marked migration actor", actor)
	}

	t.Setenv(legacyEventPublishExpiryEnv, "2020-01-01T00:00:00Z")
	if err := authorizeEventPublishRequest(req); err == nil {
		t.Fatal("expired legacy event credential was accepted")
	}
}

func TestEventPublishRejectsHumanSessionBeforePersistence(t *testing.T) {
	setEventPublishAuthEnvironment(t, "", "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(
		`{"type":"deployment.completed","aggregate_type":"deployment","aggregate_id":"one","payload":{}}`,
	))
	req = req.WithContext(contextWithClaims(req.Context(), map[string]any{
		"collaborator_id": "ordinary-collaborator",
	}))
	recorder := httptest.NewRecorder()
	(&Server{}).handleEventPublish(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
}

func TestLegacyEventBridgeRejectsGenericAndBindsReservedMutationActor(t *testing.T) {
	setEventPublishAuthEnvironment(t, "legacy-event-token", "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(
		`{"type":"deployment.completed","aggregate_type":"deployment","aggregate_id":"one","payload":{}}`,
	))
	req.Header.Set("Authorization", "Bearer legacy-event-token")
	recorder := httptest.NewRecorder()
	(&Server{}).handleEventPublish(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("generic legacy publish status=%d, want %d; body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}

	authReq := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	authReq.Header.Set("Authorization", "Bearer legacy-event-token")
	actor, err := authenticateEventPublishRequest(authReq)
	if err != nil {
		t.Fatal(err)
	}
	mutation := eventPublishRequest{
		EventType:  "aws.bucket.ensured",
		Provider:   "aws",
		InstanceID: "aws-primary",
		Actor:      &model.EventActor{Type: "service", ID: "spoofed"},
		Metadata: map[string]any{
			eventPublisherMachinePrincipalMetadataKey: "spoofed",
		},
	}
	if err := authorizeEventPublishPayload(mutation, actor); err != nil {
		t.Fatalf("legacy mutation payload rejected: %v", err)
	}
	bound := bindEventPublishActor(mutation, actor)
	if bound.Actor == nil || bound.Actor.Type != "service" || bound.Actor.ID != legacyEventPublisherPrincipalID {
		t.Fatalf("legacy event actor was not server-bound: %+v", bound.Actor)
	}
	if got := bound.Metadata[eventPublisherMachinePrincipalMetadataKey]; got != legacyEventPublisherPrincipalID {
		t.Fatalf("legacy publisher metadata was not server-bound: %#v", got)
	}
}

func TestDedicatedEventTokenCannotAuthorizeWorkflowRuns(t *testing.T) {
	setEventPublishAuthEnvironment(t, "event-only-token", "workflow-token")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs", nil)
	req.Header.Set("Authorization", "Bearer event-only-token")
	if err := authorizeWorkflowRunRequest(req); err == nil {
		t.Fatal("event-only token authorized a workflow run")
	}
}

func TestAuthorizeEventPublishRequestFailsClosedWhenDedicatedTokenConfigured(t *testing.T) {
	setEventPublishAuthEnvironment(t, "event-only-token", "")

	for _, token := range []string{"", "wrong-token"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if err := authorizeEventPublishRequest(req); err == nil {
			t.Fatalf("token %q unexpectedly authorized", token)
		}
	}
}

func TestAuthorizeEventPublishRequestRejectsLegacyWorkflowToken(t *testing.T) {
	setEventPublishAuthEnvironment(t, "event-only-token", "workflow-token")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	req.Header.Set("X-Yggdrasil-Workflow-Token", "workflow-token")
	if err := authorizeEventPublishRequest(req); err == nil {
		t.Fatal("legacy workflow token authorized event publishing")
	}
}

func TestHashedEventPublisherPrincipalIsIsolatedFromWorkflowPrincipal(t *testing.T) {
	setEventPublishAuthEnvironment(t, "", "")
	t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, "adapter-event-token", "adapter-aws"))
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "workflow-ci-token", "ci-dakasa",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy-validation"}))

	eventReq := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	eventReq.Header.Set("Authorization", "Bearer adapter-event-token")
	if err := authorizeEventPublishRequest(eventReq); err != nil {
		t.Fatalf("hashed event publisher rejected: %v", err)
	}

	workflowReq := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs", nil)
	workflowReq.Header.Set("Authorization", "Bearer adapter-event-token")
	if err := authorizeWorkflowRunRequest(workflowReq); err == nil {
		t.Fatal("event publisher credential authorized workflow dispatch")
	}

	eventReq = httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	eventReq.Header.Set("Authorization", "Bearer workflow-ci-token")
	if err := authorizeEventPublishRequest(eventReq); err == nil {
		t.Fatal("workflow machine credential authorized event publishing")
	}
}

func TestHashedEventPublisherPrincipalIsExactRouteOnly(t *testing.T) {
	setEventPublishAuthEnvironment(t, "", "")
	t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, "adapter-event-token", "adapter-aws"))
	for _, test := range []struct {
		method string
		path   string
		wantOK bool
	}{
		{method: http.MethodPost, path: "/api/v1/events", wantOK: true},
		{method: http.MethodGet, path: "/api/v1/events"},
		{method: http.MethodPost, path: "/api/v1/events/child"},
		{method: http.MethodPost, path: "/api/v1/manifests"},
	} {
		req := httptest.NewRequest(test.method, test.path, nil)
		req.Header.Set("Authorization", "Bearer adapter-event-token")
		if got := authorizeEventPublishRequest(req) == nil; got != test.wantOK {
			t.Fatalf("%s %s authorized=%v, want %v", test.method, test.path, got, test.wantOK)
		}
	}
}

func TestHashedEventPublisherPrincipalIsBoundToExactMutationScope(t *testing.T) {
	setEventPublishAuthEnvironment(t, "", "")
	configs := []eventPublisherPrincipalConfig{
		{
			PrincipalID: "adapter-aws-primary",
			Status:      "active",
			ExpiresAt:   time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
			RotationID:  "aws-primary-r1",
			TokenSHA256: testTokenSHA256("aws-primary-token"),
			AllowedEvents: []eventPublisherEventRef{
				{Provider: "aws", InstanceID: "aws-primary", EventType: "aws.bucket.ensured"},
			},
		},
		{
			PrincipalID: "adapter-aws-secondary",
			Status:      "active",
			ExpiresAt:   time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
			RotationID:  "aws-secondary-r1",
			TokenSHA256: testTokenSHA256("aws-secondary-token"),
			AllowedEvents: []eventPublisherEventRef{
				{Provider: "aws", InstanceID: "aws-secondary", EventType: "aws.bucket.ensured"},
			},
		},
	}
	raw, err := json.Marshal(configs)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(eventPublisherPrincipalsEnv, string(raw))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer aws-primary-token")
	actor, err := authenticateEventPublishRequest(req)
	if err != nil {
		t.Fatal(err)
	}

	allowed := eventPublishRequest{Provider: "aws", InstanceID: "aws-primary", EventType: "aws.bucket.ensured"}
	if err := authorizeEventPublishPayload(allowed, actor); err != nil {
		t.Fatalf("exact event scope rejected: %v", err)
	}
	for _, denied := range []eventPublishRequest{
		{Type: "deployment.completed"},
		{Provider: "aws", InstanceID: "aws-secondary", EventType: "aws.bucket.ensured"},
		{Provider: "aws", InstanceID: "aws-primary", EventType: "aws.bucket.destroyed"},
		{Provider: "gcp", InstanceID: "aws-primary", EventType: "gcp.bucket.ensured"},
	} {
		if err := authorizeEventPublishPayload(denied, actor); err == nil {
			t.Fatalf("out-of-scope event was accepted: %+v", denied)
		}
	}

	spoofed := allowed
	spoofed.Actor = &model.EventActor{Type: "service", ID: "spoofed"}
	spoofed.Metadata = map[string]any{eventPublisherMachinePrincipalMetadataKey: "spoofed"}
	bound := bindEventPublishActor(spoofed, actor)
	if bound.Actor == nil || bound.Actor.Type != "service" || bound.Actor.ID != "adapter-aws-primary" {
		t.Fatalf("event actor was not server-bound: %+v", bound.Actor)
	}
	if got := bound.Metadata[eventPublisherMachinePrincipalMetadataKey]; got != "adapter-aws-primary" {
		t.Fatalf("publisher metadata was not server-bound: %#v", got)
	}
}

func TestHandleEventPublishRejectsGenericAndForeignScopeBeforePersistence(t *testing.T) {
	setEventPublishAuthEnvironment(t, "", "")
	t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(
		t,
		"adapter-event-token",
		"adapter-aws-primary",
		eventPublisherEventRef{Provider: "aws", InstanceID: "aws-primary", EventType: "aws.bucket.ensured"},
	))

	for _, test := range []struct {
		name string
		body string
	}{
		{
			name: "generic event",
			body: `{"type":"deployment.completed","aggregate_type":"deployment","aggregate_id":"one","payload":{}}`,
		},
		{
			name: "other instance",
			body: `{"event_type":"aws.bucket.ensured","provider":"aws","resource":"bucket","verb":"ensured","resource_id":"bucket-one","instance_id":"aws-secondary","idempotency":"one"}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(test.body))
			req.Header.Set("Authorization", "Bearer adapter-event-token")
			recorder := httptest.NewRecorder()
			(&Server{}).handleEventPublish(recorder, req)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status=%d, want %d; body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
			}
		})
	}
}

func TestAuthorizeEventPublishRequestKeepsNoTokenNonProductionCompatibility(t *testing.T) {
	for _, environment := range []string{"", "dev", "test"} {
		t.Run(environment, func(t *testing.T) {
			t.Setenv("YGGDRASIL_ENV", environment)
			setEventPublishAuthEnvironment(t, "", "")

			req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
			if err := authorizeEventPublishRequest(req); err != nil {
				t.Fatalf("non-production no-token compatibility rejected: %v", err)
			}
		})
	}
}

func TestAuthorizeEventPublishRequestRejectsNoTokenInProduction(t *testing.T) {
	t.Setenv("YGGDRASIL_ENV", "production")
	setEventPublishAuthEnvironment(t, "", "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	if err := authorizeEventPublishRequest(req); err == nil {
		t.Fatal("production event publishing was anonymous")
	}
}

func TestConsoleGateAcceptsHashedEventPrincipalOnlyOnPostEventPublish(t *testing.T) {
	setEventPublishAuthEnvironment(t, "", "workflow-token")
	t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, "event-only-token", "adapter-aws"))

	srv := &Server{}
	tests := []struct {
		name       string
		method     string
		path       string
		wantCalled bool
	}{
		{name: "post exact event path", method: http.MethodPost, path: "/api/v1/events", wantCalled: true},
		{name: "get exact event path", method: http.MethodGet, path: "/api/v1/events", wantCalled: false},
		{name: "post event child path", method: http.MethodPost, path: "/api/v1/events/child", wantCalled: false},
		{name: "post manifest path", method: http.MethodPost, path: "/api/v1/manifests", wantCalled: false},
		{name: "auth administration path", method: http.MethodPost, path: "/api/v1/auth/providers", wantCalled: false},
		{name: "secret values path", method: http.MethodGet, path: "/api/v1/secrets?include_values=true", wantCalled: false},
		{name: "console secret values path", method: http.MethodGet, path: "/api/v1/console/secrets?include_values=true", wantCalled: false},
		{name: "generic ops path", method: http.MethodGet, path: "/api/v1/ops/workflows", wantCalled: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			handler := srv.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))

			req := httptest.NewRequest(test.method, test.path, nil)
			req.Header.Set("Authorization", "Bearer event-only-token")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if called != test.wantCalled {
				t.Fatalf("hashed event-principal gate called=%v, want %v (status=%d)", called, test.wantCalled, w.Code)
			}
			wantStatus := http.StatusUnauthorized
			if test.wantCalled {
				wantStatus = http.StatusNoContent
			}
			if w.Code != wantStatus {
				t.Fatalf("status=%d, want %d", w.Code, wantStatus)
			}
		})
	}
}
