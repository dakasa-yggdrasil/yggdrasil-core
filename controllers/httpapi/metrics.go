package httpapi

import (
	"fmt"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
)

// Process metrics counters. Concurrent-safe via atomic ops; exposed via
// /metrics in Prometheus text exposition format. v2.4.0 tracks the public
// surface (workflow_runs, webhook events, manifest applies, secret lookups).
// External deps avoided on purpose; switching to prometheus/client_golang is
// a v3 cleanup once the metric set stabilises.
var (
	metricWorkflowRunsSucceededTotal atomic.Uint64
	metricWorkflowRunsFailedTotal    atomic.Uint64
	metricWorkflowRunsRunningTotal   atomic.Uint64

	metricWebhookEventsAcceptedTotal atomic.Uint64
	metricWebhookEventsSkippedTotal  atomic.Uint64
	metricWebhookEventsFailedTotal   atomic.Uint64

	metricManifestAppliedTotal atomic.Uint64
	metricSecretLookupsTotal   atomic.Uint64

	processStartTime = time.Now().UTC()
)

// IncWorkflowRun bumps the counter that matches the run's terminal status.
func IncWorkflowRun(status string) {
	switch status {
	case "succeeded":
		metricWorkflowRunsSucceededTotal.Add(1)
	case "failed":
		metricWorkflowRunsFailedTotal.Add(1)
	case "running":
		metricWorkflowRunsRunningTotal.Add(1)
	}
}

// IncWebhookEvent bumps the webhook outcome counter.
func IncWebhookEvent(outcome string) {
	switch outcome {
	case "accepted":
		metricWebhookEventsAcceptedTotal.Add(1)
	case "skipped":
		metricWebhookEventsSkippedTotal.Add(1)
	case "failed":
		metricWebhookEventsFailedTotal.Add(1)
	}
}

// IncManifestApplied bumps the manifest-write counter (one per successful POST).
func IncManifestApplied() { metricManifestAppliedTotal.Add(1) }

// IncSecretLookup bumps the secret-store lookup counter.
func IncSecretLookup() { metricSecretLookupsTotal.Add(1) }

// handleMetrics serves Prometheus exposition format at /metrics (no auth).
// Adopters scrape on a 15-30s interval. The metric names match the
// production conventions documented in docs/operations/observability.md.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	uptime := time.Since(processStartTime).Seconds()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	fmt.Fprintf(w, "# HELP yggdrasil_workflow_runs_total Total workflow runs by terminal status\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_workflow_runs_total counter\n")
	fmt.Fprintf(w, "yggdrasil_workflow_runs_total{status=\"succeeded\"} %d\n", metricWorkflowRunsSucceededTotal.Load())
	fmt.Fprintf(w, "yggdrasil_workflow_runs_total{status=\"failed\"} %d\n", metricWorkflowRunsFailedTotal.Load())
	fmt.Fprintf(w, "yggdrasil_workflow_runs_total{status=\"running\"} %d\n", metricWorkflowRunsRunningTotal.Load())

	fmt.Fprintf(w, "# HELP yggdrasil_webhook_events_total Total GitHub webhook events by outcome\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_webhook_events_total counter\n")
	fmt.Fprintf(w, "yggdrasil_webhook_events_total{outcome=\"accepted\"} %d\n", metricWebhookEventsAcceptedTotal.Load())
	fmt.Fprintf(w, "yggdrasil_webhook_events_total{outcome=\"skipped\"} %d\n", metricWebhookEventsSkippedTotal.Load())
	fmt.Fprintf(w, "yggdrasil_webhook_events_total{outcome=\"failed\"} %d\n", metricWebhookEventsFailedTotal.Load())

	fmt.Fprintf(w, "# HELP yggdrasil_manifest_applies_total Total POST /api/v1/manifests successes\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_manifest_applies_total counter\n")
	fmt.Fprintf(w, "yggdrasil_manifest_applies_total %d\n", metricManifestAppliedTotal.Load())

	fmt.Fprintf(w, "# HELP yggdrasil_secret_lookups_total Total managed-secret lookups\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_secret_lookups_total counter\n")
	fmt.Fprintf(w, "yggdrasil_secret_lookups_total %d\n", metricSecretLookupsTotal.Load())

	fmt.Fprintf(w, "# HELP yggdrasil_uptime_seconds Process uptime in seconds since start\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_uptime_seconds gauge\n")
	fmt.Fprintf(w, "yggdrasil_uptime_seconds %.0f\n", uptime)

	fmt.Fprintf(w, "# HELP yggdrasil_goroutines Currently scheduled goroutines\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_goroutines gauge\n")
	fmt.Fprintf(w, "yggdrasil_goroutines %d\n", runtime.NumGoroutine())

	fmt.Fprintf(w, "# HELP yggdrasil_memory_bytes Resident heap memory (HeapAlloc)\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_memory_bytes gauge\n")
	fmt.Fprintf(w, "yggdrasil_memory_bytes %d\n", memStats.HeapAlloc)

	// Reactor evaluation counter: bumped once per (event, integration_instance)
	// pair MaterializeReactions persists into integration_event_reactions.
	// outcome=matched means the canon event had at least one reactor declared
	// against it; outcome=skipped means the event was non-canon (no-op); the
	// matched count is incremented N times when N reactions are materialised
	// for a single event so the rate correlates to actual dispatch fan-out.
	evalSnap := metrics.ReactorEvaluationsSnapshot()
	fmt.Fprintf(w, "# HELP yggdrasil_reactor_evaluations_total Total reactor evaluations by outcome\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_reactor_evaluations_total counter\n")
	fmt.Fprintf(w, "yggdrasil_reactor_evaluations_total{outcome=\"matched\"} %d\n", evalSnap[metrics.ReactorEvalMatched])
	fmt.Fprintf(w, "yggdrasil_reactor_evaluations_total{outcome=\"skipped\"} %d\n", evalSnap[metrics.ReactorEvalSkipped])
	fmt.Fprintf(w, "yggdrasil_reactor_evaluations_total{outcome=\"error\"} %d\n", evalSnap[metrics.ReactorEvalError])

	// Reactor dispatch counter: bumped exactly once per reaction row that
	// reaches a terminal status (succeeded / failed / dead_lettered).
	// Transient failures inside the retry loop are NOT counted here — only
	// the final outcome — so the rate matches the heimdall-style "5220
	// succeeded, 0 failed" view that operators use to gauge reactor health.
	dispatchSnap := metrics.ReactorDispatchesSnapshot()
	fmt.Fprintf(w, "# HELP yggdrasil_reactor_dispatches_total Total reactor dispatches by terminal outcome\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_reactor_dispatches_total counter\n")
	fmt.Fprintf(w, "yggdrasil_reactor_dispatches_total{outcome=\"succeeded\"} %d\n", dispatchSnap[metrics.ReactorDispatchSucceeded])
	fmt.Fprintf(w, "yggdrasil_reactor_dispatches_total{outcome=\"failed\"} %d\n", dispatchSnap[metrics.ReactorDispatchFailed])
	fmt.Fprintf(w, "yggdrasil_reactor_dispatches_total{outcome=\"dead_lettered\"} %d\n", dispatchSnap[metrics.ReactorDispatchDeadLettered])

	// Heimdall flagged_count gauge: snapshot of the last value emitted by a
	// heimdall-* workflow's `batch-ci-status` (or equivalent) step output.
	// Keyed by workflow name so multiple pulses (CI / CD / etc.) coexist.
	// The gauge is only populated once a pulse has completed at least once
	// since process start — pre-pulse the family is absent (no zero rows).
	fmt.Fprintf(w, "# HELP yggdrasil_heimdall_flagged_count Latest flagged_count from a heimdall-* pulse workflow\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_heimdall_flagged_count gauge\n")
	for _, sample := range metrics.HeimdallFlaggedCountSnapshot() {
		fmt.Fprintf(w, "yggdrasil_heimdall_flagged_count{pulse=\"%s\"} %v\n", sample.PulseName, sample.Value)
	}
}
