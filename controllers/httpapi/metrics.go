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

	metricManifestAppliedTotal     atomic.Uint64
	metricManifestDeletedHardTotal atomic.Uint64
	metricManifestDeletedSoftTotal atomic.Uint64
	metricManifestPurgedTotal      atomic.Uint64
	metricSecretLookupsTotal       atomic.Uint64

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

// IncManifestDeleted bumps the manifest-delete counter, split by mode
// ("hard" removes rows from the manifests table; "soft" flips
// active=FALSE). Unknown modes are no-ops so future call sites that pass
// a misspelled label don't silently lose audit signal in the wrong
// bucket — operators see a flat line and notice.
func IncManifestDeleted(mode string) {
	switch mode {
	case "hard":
		metricManifestDeletedHardTotal.Add(1)
	case "soft":
		metricManifestDeletedSoftTotal.Add(1)
	}
}

// IncManifestPurged bumps the periodic-purge counter; one per row the
// background runner removed in its last sweep. Reported as a counter so
// rate() over a window gives operators "purge throughput per minute".
func IncManifestPurged(n int64) {
	if n <= 0 {
		return
	}
	metricManifestPurgedTotal.Add(uint64(n))
}

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

	fmt.Fprintf(w, "# HELP yggdrasil_manifest_deletes_total Total DELETE /api/v1/manifests/{id} successes by mode\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_manifest_deletes_total counter\n")
	fmt.Fprintf(w, "yggdrasil_manifest_deletes_total{mode=\"hard\"} %d\n", metricManifestDeletedHardTotal.Load())
	fmt.Fprintf(w, "yggdrasil_manifest_deletes_total{mode=\"soft\"} %d\n", metricManifestDeletedSoftTotal.Load())

	fmt.Fprintf(w, "# HELP yggdrasil_manifest_purges_total Total manifest rows removed by the periodic purge runner (active=FALSE older than retention)\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_manifest_purges_total counter\n")
	fmt.Fprintf(w, "yggdrasil_manifest_purges_total %d\n", metricManifestPurgedTotal.Load())

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

	// Reactor dispatch counter: bumped once per dispatch attempt the
	// Runner finishes.  Outcomes:
	//   - succeeded     : adapter RPC returned OK; row marked succeeded (terminal).
	//   - failed        : adapter RPC errored AND attempt is still retriable;
	//                     row marked failed with next_attempt_at scheduled.  A
	//                     single reaction id may bump this counter multiple
	//                     times across retries (one per failed attempt).
	//   - dead_lettered : adapter RPC errored AND backoff exhausted; row
	//                     marked dead_lettered (terminal).
	// Operators reading "5220 succeeded, 0 failed in 24h" should look at
	// `succeeded` for the success rate and `dead_lettered` for true
	// terminal failures.  Treat `failed` as a retry-pressure signal.
	dispatchSnap := metrics.ReactorDispatchesSnapshot()
	fmt.Fprintf(w, "# HELP yggdrasil_reactor_dispatches_total Total reactor dispatch attempts by outcome\n")
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

	// Capability-naming validator metrics (Phase 1 warn-only + Phase 2
	// hard-fail observation surface).  See INTEGRATION_CONTRACT §5 and
	// the rollout runbook at
	// ~/.claude/projects/-Users-dakasa-projects/memory/reference_phase2_validator_flip_runbook.md.
	//   - per-type gauge surfaces *which* integration_types still emit
	//     non-conformant names, so the operator can see the catalog-wide
	//     residual before flipping YGGDRASIL_VALIDATOR_PHASE=hard-fail.
	//   - unlabeled counter feeds the spike-detection alert (rate over
	//     a 5m window catches a regression — e.g. a stale CI re-publishing
	//     an old action_catalog).
	//   - rejections counter stays at zero in warn-only mode; bumps once
	//     per HTTP 422 returned in hard-fail mode.
	fmt.Fprintf(w, "# HELP yggdrasil_capability_warnings Latest capability-naming warning count per integration_type\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_capability_warnings gauge\n")
	for _, sample := range metrics.CapabilityWarningsSnapshot() {
		fmt.Fprintf(w, "yggdrasil_capability_warnings{integration_type=\"%s\"} %v\n", sample.IntegrationType, sample.Value)
	}

	fmt.Fprintf(w, "# HELP yggdrasil_capability_warnings_total Total capability-naming warnings emitted process-wide\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_capability_warnings_total counter\n")
	fmt.Fprintf(w, "yggdrasil_capability_warnings_total %d\n", metrics.CapabilityWarningsTotalSnapshot())

	fmt.Fprintf(w, "# HELP yggdrasil_capability_rejections_total Total manifest registrations rejected by the hard-fail capability-naming validator (Phase 2)\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_capability_rejections_total counter\n")
	fmt.Fprintf(w, "yggdrasil_capability_rejections_total %d\n", metrics.CapabilityRejectionsTotalSnapshot())

	// Auth login attempts, faceted by terminal outcome. Each call to
	// POST /api/v1/auth/login terminates in exactly one bucket so sum()
	// equals the total attempt count.  Phase-3 audit G3 was "no auth
	// metrics" — operators chart `rate(...[5m])` to alert on failure
	// spikes, rate-limit bursts, and lockout floods.
	loginSnap := metrics.AuthLoginSnapshot()
	fmt.Fprintf(w, "# HELP yggdrasil_auth_login_total Total /api/v1/auth/login attempts by terminal outcome\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_auth_login_total counter\n")
	fmt.Fprintf(w, "yggdrasil_auth_login_total{outcome=\"succeeded\"} %d\n", loginSnap[metrics.AuthLoginSucceeded])
	fmt.Fprintf(w, "yggdrasil_auth_login_total{outcome=\"failed\"} %d\n", loginSnap[metrics.AuthLoginFailed])
	fmt.Fprintf(w, "yggdrasil_auth_login_total{outcome=\"rate_limited\"} %d\n", loginSnap[metrics.AuthLoginRateLimited])
	fmt.Fprintf(w, "yggdrasil_auth_login_total{outcome=\"account_locked\"} %d\n", loginSnap[metrics.AuthLoginAccountLocked])
	fmt.Fprintf(w, "yggdrasil_auth_login_total{outcome=\"mfa_required\"} %d\n", loginSnap[metrics.AuthLoginMFARequired])

	// MFA verify counter, faceted by (outcome, factor). Failures are
	// the leading indicator of an MFA bypass attempt — operators alert
	// when failure rate per factor crosses a baseline.
	mfaSnap := metrics.AuthMFAVerifySnapshot()
	fmt.Fprintf(w, "# HELP yggdrasil_auth_mfa_verify_total Total MFA verify attempts by outcome and factor\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_auth_mfa_verify_total counter\n")
	for _, factor := range []string{metrics.AuthMFAFactorTOTP, metrics.AuthMFAFactorRecoveryCode, metrics.AuthMFAFactorWebAuthn} {
		for _, outcome := range []string{metrics.AuthMFAVerifySucceeded, metrics.AuthMFAVerifyFailed} {
			fmt.Fprintf(w, "yggdrasil_auth_mfa_verify_total{outcome=\"%s\",factor=\"%s\"} %d\n",
				outcome, factor, mfaSnap[outcome+"|"+factor])
		}
	}

	// Session lifecycle counters. created bumps once per auth_sessions
	// INSERT (login + SSO + admin); revoked bumps once per row
	// transitioned to status=revoked.  rate(revoked) >> rate(created)
	// after an outage means stuck sessions; the opposite means an
	// orphaned-session pile-up.
	fmt.Fprintf(w, "# HELP yggdrasil_auth_sessions_created_total Total auth sessions issued (login + SSO + admin)\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_auth_sessions_created_total counter\n")
	fmt.Fprintf(w, "yggdrasil_auth_sessions_created_total %d\n", metrics.AuthSessionsCreatedTotalSnapshot())

	fmt.Fprintf(w, "# HELP yggdrasil_auth_sessions_revoked_total Total auth sessions revoked (logout + admin + password rotation + offboard)\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_auth_sessions_revoked_total counter\n")
	fmt.Fprintf(w, "yggdrasil_auth_sessions_revoked_total %d\n", metrics.AuthSessionsRevokedTotalSnapshot())

	// CSRF rejection counter, faceted by (outcome, mode). The mode label
	// lets dashboards separate "would-have-failed in warn-mode" (training
	// signal for the FE rollout) from "actually 403'd in enforce-mode"
	// (real attack or surface drift). Stays at zero on a happy cluster.
	csrfSnap := metrics.CSRFRejectedSnapshot()
	fmt.Fprintf(w, "# HELP yggdrasil_csrf_rejected_total Total CSRF token validations that failed (audit 2026-05-27 A7)\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_csrf_rejected_total counter\n")
	for _, outcome := range []string{metrics.CSRFRejectedMissingToken, metrics.CSRFRejectedTokenMismatch, metrics.CSRFRejectedInvalidSession} {
		for _, mode := range []string{metrics.CSRFModeWarn, metrics.CSRFModeEnforce} {
			fmt.Fprintf(w, "yggdrasil_csrf_rejected_total{outcome=\"%s\",mode=\"%s\"} %d\n",
				outcome, mode, csrfSnap[outcome+"|"+mode])
		}
	}

	// RBAC denial counter, faceted by (permission, mode). Like CSRF, the
	// mode label separates "warn (would-have-rejected)" from "enforce
	// (actually rejected)". The permission label is dynamic — only the
	// permissions surface-console actually asks for show up; pre-populating
	// the full action_catalog would clutter the surface and force a metric
	// update every time a permission gets added in the integration-yggdrasil-self
	// adapter. Audit ref: §3.1 + INTEGRATION_CONTRACT §12.
	rbacSnap := metrics.RBACDeniedSnapshot()
	fmt.Fprintf(w, "# HELP yggdrasil_console_rbac_denied_total Total /api/v1/console/* RBAC denials by permission and mode (audit 2026-05-27 §3.1, contract §12)\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_console_rbac_denied_total counter\n")
	for key, count := range rbacSnap {
		// key shape: "permission|mode"
		idx := -1
		for i := len(key) - 1; i >= 0; i-- {
			if key[i] == '|' {
				idx = i
				break
			}
		}
		if idx < 0 {
			continue
		}
		permission := key[:idx]
		mode := key[idx+1:]
		fmt.Fprintf(w, "yggdrasil_console_rbac_denied_total{permission=\"%s\",mode=\"%s\"} %d\n",
			permission, mode, count)
	}

	// Reconcile failure counter, faceted by kind (closed set). Bumped
	// each time a background loop hits a non-retryable error. The
	// motivating noise was the permission-catalog duplicate-key warning
	// firing every 30s in production logs without a single visible
	// metric — operators chart
	// `rate(yggdrasil_reconcile_failures_total{kind="permission_catalog"}[5m])`
	// to confirm the rate is shrinking (or alert when it grows).
	//
	// Audit ref: 2026-05-27 G4 / F2.
	reconcileSnap := metrics.ReconcileFailuresSnapshot()
	fmt.Fprintf(w, "# HELP yggdrasil_reconcile_failures_total Total background reconcile failures by kind (audit 2026-05-27 G4)\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_reconcile_failures_total counter\n")
	for _, kind := range []string{
		metrics.ReconcileKindPermissionCatalog,
		metrics.ReconcileKindSecretMaterialize,
		metrics.ReconcileKindManifestApply,
	} {
		fmt.Fprintf(w, "yggdrasil_reconcile_failures_total{kind=\"%s\"} %d\n",
			kind, reconcileSnap[kind])
	}

	// Goroutine panic counter, faceted by SafeGo call-site name. Bumped
	// each time internal/goroutine.SafeGo recovers a panic. Stays at
	// zero on a happy cluster; any non-zero value means a fire-and-forget
	// path is silently failing and operators must investigate.
	//
	// Audit ref: 2026-05-28 F7 (background goroutine bounds).
	panicSnap := metrics.GoroutinePanicsSnapshot()
	fmt.Fprintf(w, "# HELP yggdrasil_goroutine_panics_total Total panics recovered by internal/goroutine.SafeGo, faceted by call-site name (audit 2026-05-28 F7)\n")
	fmt.Fprintf(w, "# TYPE yggdrasil_goroutine_panics_total counter\n")
	for name, count := range panicSnap {
		fmt.Fprintf(w, "yggdrasil_goroutine_panics_total{name=\"%s\"} %d\n", name, count)
	}
}
