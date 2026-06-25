package httpapi

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestHandleWorkflowRun_503WhenBrokerDown(t *testing.T) {
	t.Setenv("BROKER_URL", "amqp://unreachable:5672")
	s := &Server{rabbitmq: nil}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs",
		strings.NewReader(`{"workflow":"x","namespace":"dakasa"}`))
	rec := httptest.NewRecorder()
	s.handleWorkflowRun(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "workflow_dispatch_unavailable") {
		t.Fatalf("want workflow_dispatch_unavailable, got %s", rec.Body.String())
	}
}

// TestGithubWebhook_503WhenBrokerDown verifies that a push event that would
// otherwise dispatch a yggdrasil workflow returns 503 when the broker is down.
// The guard sits immediately before safego.SafeGo("webhook_dispatch", …), so
// the test must drive the handler all the way through binding lookup,
// deploy-spec resolution, branch-filter match, and kind=yggdrasil before the
// guard is hit. We reuse the same sqlmock setup as TestPushEventDispatchesYggdrasilWorkflow.
func TestGithubWebhook_503WhenBrokerDown(t *testing.T) {
	// GITHUB_WEBHOOK_SECRET left unset → signature check is skipped.
	t.Setenv("GITHUB_WEBHOOK_SECRET", "")
	t.Setenv("BROKER_URL", "amqp://unreachable:5672")

	server, mock, cleanup := newWebhookTestServer(t)
	defer cleanup()
	// Override rabbitmq to nil so isBrokerAvailable() returns false.
	server.rabbitmq = nil

	spec := `{
		"component_kind":"product","component_name":"x","repository":"acme/widget",
		"deploy":{
			"workflow_kind":"yggdrasil",
			"workflow_ref":{"namespace":"acme","name":"deploy-via-kustomize-source"},
			"default_inputs":{
				"git_url":"{{ push.repository.clone_url }}",
				"revision":"{{ push.head_commit.id }}",
				"namespace":"acme"
			},
			"branch_filter":["main"]
		}
	}`
	mock.ExpectQuery(regexp.QuoteMeta(findBindingQuery)).
		WithArgs("acme/widget").
		WillReturnRows(bindingRows(spec))

	body := pushPayload("acme/widget", "refs/heads/main")
	rec := performPushRequest(t, server, body)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "workflow_dispatch_unavailable") {
		t.Fatalf("want workflow_dispatch_unavailable in body, got %s", rec.Body.String())
	}
}

func TestIsBrokerAvailable(t *testing.T) {
	t.Run("broker_url_unset_is_not_available", func(t *testing.T) {
		t.Setenv("BROKER_URL", "")
		s := &Server{rabbitmq: nil}
		if s.isBrokerAvailable() {
			t.Fatal("expected unavailable when BROKER_URL unset")
		}
	})
	t.Run("broker_url_set_but_conn_nil_is_not_available", func(t *testing.T) {
		t.Setenv("BROKER_URL", "amqp://unreachable:5672")
		s := &Server{rabbitmq: nil}
		if s.isBrokerAvailable() {
			t.Fatal("expected unavailable when conn is nil")
		}
	})
}
