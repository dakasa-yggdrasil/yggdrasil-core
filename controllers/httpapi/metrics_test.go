package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestHandleMetricsReturnsPrometheusFormat(t *testing.T) {
	server := &Server{logger: zap.NewNop()}
	r := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	server.handleMetrics(w, r)

	if w.Code != 200 {
		t.Fatalf("status: got %d want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type: got %q", ct)
	}
	body := w.Body.String()
	for _, expected := range []string{
		"yggdrasil_workflow_runs_total",
		"yggdrasil_webhook_events_total",
		"yggdrasil_manifest_applies_total",
		"yggdrasil_secret_lookups_total",
		"yggdrasil_uptime_seconds",
		"yggdrasil_goroutines",
		"yggdrasil_memory_bytes",
		"# TYPE",
		"# HELP",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected metric/comment %q not in body:\n%s", expected, body)
		}
	}
}

func TestIncWorkflowRunUpdatesCounters(t *testing.T) {
	before := metricWorkflowRunsSucceededTotal.Load()
	IncWorkflowRun("succeeded")
	if got := metricWorkflowRunsSucceededTotal.Load(); got != before+1 {
		t.Fatalf("expected %d, got %d", before+1, got)
	}
}

func TestIncWebhookEventCountsByOutcome(t *testing.T) {
	beforeAcc := metricWebhookEventsAcceptedTotal.Load()
	beforeSkip := metricWebhookEventsSkippedTotal.Load()
	IncWebhookEvent("accepted")
	IncWebhookEvent("skipped")
	IncWebhookEvent("skipped")
	if got := metricWebhookEventsAcceptedTotal.Load(); got != beforeAcc+1 {
		t.Fatalf("accepted: got %d, want %d", got, beforeAcc+1)
	}
	if got := metricWebhookEventsSkippedTotal.Load(); got != beforeSkip+2 {
		t.Fatalf("skipped: got %d, want %d", got, beforeSkip+2)
	}
}
