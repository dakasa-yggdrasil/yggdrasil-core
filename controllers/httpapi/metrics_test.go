package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
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
		"yggdrasil_reactor_evaluations_total",
		"yggdrasil_reactor_dispatches_total",
		"yggdrasil_heimdall_flagged_count",
		// Capability-naming validator family (Phase 1 + Phase 2 obs).
		"yggdrasil_capability_warnings",
		"yggdrasil_capability_warnings_total",
		"yggdrasil_capability_rejections_total",
		// Phase-3 auth observability family (audit ref G3).
		"yggdrasil_auth_login_total",
		"yggdrasil_auth_mfa_verify_total",
		"yggdrasil_auth_sessions_created_total",
		"yggdrasil_auth_sessions_revoked_total",
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

// TestHandleMetrics_ReactorCountersRender exercises the new reactor counter
// families: after recording one matched, one error, and two succeeded
// dispatches we expect the rendered /metrics body to expose those exact
// values with the correct outcome labels.
func TestHandleMetrics_ReactorCountersRender(t *testing.T) {
	metrics.ResetForTest()
	metrics.AddReactorEvaluations(metrics.ReactorEvalMatched, 1)
	metrics.IncReactorEvaluation(metrics.ReactorEvalError)
	metrics.IncReactorDispatch(metrics.ReactorDispatchSucceeded)
	metrics.IncReactorDispatch(metrics.ReactorDispatchSucceeded)

	server := &Server{logger: zap.NewNop()}
	w := httptest.NewRecorder()
	server.handleMetrics(w, httptest.NewRequest("GET", "/metrics", nil))

	body := w.Body.String()
	for _, expected := range []string{
		`yggdrasil_reactor_evaluations_total{outcome="matched"} 1`,
		`yggdrasil_reactor_evaluations_total{outcome="error"} 1`,
		`yggdrasil_reactor_dispatches_total{outcome="succeeded"} 2`,
		`yggdrasil_reactor_dispatches_total{outcome="failed"} 0`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected %q in body:\n%s", expected, body)
		}
	}
}

// TestHandleMetrics_HeimdallGaugeRender confirms that once a pulse value is
// recorded the /metrics surface exposes a labelled gauge sample with the
// pulse name as the `pulse` label.
func TestHandleMetrics_HeimdallGaugeRender(t *testing.T) {
	metrics.ResetForTest()
	metrics.SetHeimdallFlaggedCount("heimdall-ci-pulse", 7)

	server := &Server{logger: zap.NewNop()}
	w := httptest.NewRecorder()
	server.handleMetrics(w, httptest.NewRequest("GET", "/metrics", nil))

	body := w.Body.String()
	if !strings.Contains(body, `yggdrasil_heimdall_flagged_count{pulse="heimdall-ci-pulse"} 7`) {
		t.Fatalf("missing heimdall gauge sample in body:\n%s", body)
	}
}
