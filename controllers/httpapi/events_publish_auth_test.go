package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func setEventPublishAuthEnvironment(t *testing.T, eventToken, workflowToken string) {
	t.Helper()
	t.Setenv("YGGDRASIL_EVENT_PUBLISH_TOKEN", eventToken)
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", workflowToken)
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON", "")
}

func TestAuthorizeEventPublishRequestAcceptsDedicatedToken(t *testing.T) {
	setEventPublishAuthEnvironment(t, "event-only-token", "workflow-token")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer event-only-token")
	if err := authorizeEventPublishRequest(req); err != nil {
		t.Fatalf("dedicated event token rejected: %v", err)
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

func TestAuthorizeEventPublishRequestKeepsLegacyWorkflowTokenCompatibility(t *testing.T) {
	setEventPublishAuthEnvironment(t, "event-only-token", "workflow-token")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	req.Header.Set("X-Yggdrasil-Workflow-Token", "workflow-token")
	if err := authorizeEventPublishRequest(req); err != nil {
		t.Fatalf("legacy workflow token rejected: %v", err)
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

func TestConsoleGateAcceptsDedicatedTokenOnlyOnPostEventPublish(t *testing.T) {
	setEventPublishAuthEnvironment(t, "event-only-token", "workflow-token")

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
				t.Fatalf("dedicated event-token gate called=%v, want %v (status=%d)", called, test.wantCalled, w.Code)
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
