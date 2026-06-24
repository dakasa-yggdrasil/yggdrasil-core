package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// minimalPushPayload is a syntactically valid GitHub push event body that
// contains all fields handlePushEvent unmarshals — enough for the handler to
// reach the broker guard before touching the database.
const minimalPushPayload = `{
	"ref": "refs/heads/main",
	"repository": {"full_name": "dakasa-co/test-repo", "clone_url": "https://github.com/dakasa-co/test-repo.git"},
	"pusher": {"name": "ci"},
	"head_commit": {"id": "abc123", "message": "chore: test", "modified": []}
}`

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

func TestGithubWebhook_503WhenBrokerDown(t *testing.T) {
	// GITHUB_WEBHOOK_SECRET left unset → signature check is skipped (see
	// handleGitHubWebhook: the block only runs when secret != "").
	t.Setenv("GITHUB_WEBHOOK_SECRET", "")
	t.Setenv("BROKER_URL", "amqp://unreachable:5672")

	s := &Server{rabbitmq: nil}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/github/webhook",
		strings.NewReader(minimalPushPayload))
	req.Header.Set("X-GitHub-Event", "push")
	rec := httptest.NewRecorder()
	s.handleGitHubWebhook(rec, req)

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
