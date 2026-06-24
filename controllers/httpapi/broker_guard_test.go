package httpapi

import (
	"net/http"
	"net/http/httptest"
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
