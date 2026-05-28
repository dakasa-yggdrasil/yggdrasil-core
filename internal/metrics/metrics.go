// Package metrics holds the atomic counter/gauge state for yggdrasil_*
// process metrics that are scraped by Prometheus via /metrics.
//
// The state lives here (not under controllers/httpapi) so non-httpapi
// packages — repository.MaterializeReactions, internal/reactors.Runner,
// controllers/message.EmitWorkflowRunCompletedEvent — can record signals
// without taking a dependency on the HTTP layer (which would introduce
// import cycles).
//
// controllers/httpapi.handleMetrics is the sole reader; it composes the
// Prometheus text exposition format using the snapshot helpers below.
//
// Style note: we deliberately stay on sync/atomic + a small string→gauge
// map instead of pulling in prometheus/client_golang.  That is the same
// trade-off the original metrics.go made and we are not breaking it for a
// 3-metric expansion.
package metrics

import (
	"sort"
	"sync"
	"sync/atomic"
)

// Reactor evaluation outcomes. The set is closed; callers passing any
// other value are silently dropped to keep label cardinality bounded.
const (
	ReactorEvalMatched = "matched"
	ReactorEvalSkipped = "skipped"
	ReactorEvalError   = "error"
)

// Auth login outcomes. Closed set so the Prometheus label cardinality
// is bounded at 5; unknown values dropped to avoid label-explosion.
//
// Audit ref: G3 (no Prometheus metrics on auth flows). Operators need
// these to alert on:
//   - succeeded rate dropping (outage or surge in lockouts)
//   - failed rate spiking (brute-force in progress)
//   - rate_limited bursts (DDoS or misconfigured client)
//   - mfa_required as a denominator for "% of users with MFA on"
const (
	AuthLoginSucceeded     = "succeeded"
	AuthLoginFailed        = "failed"
	AuthLoginRateLimited   = "rate_limited"
	AuthLoginAccountLocked = "account_locked"
	AuthLoginMFARequired   = "mfa_required"
)

// MFA verify outcomes. Closed set.
const (
	AuthMFAVerifySucceeded = "succeeded"
	AuthMFAVerifyFailed    = "failed"
)

// MFA factor labels for the verify counter. Closed set.
const (
	AuthMFAFactorTOTP         = "totp"
	AuthMFAFactorRecoveryCode = "recovery_code"
	AuthMFAFactorWebAuthn     = "webauthn"
)

// Reactor dispatch outcomes. Same closed-set discipline as evaluations.
const (
	ReactorDispatchSucceeded   = "succeeded"
	ReactorDispatchFailed      = "failed"
	ReactorDispatchDeadLettered = "dead_lettered"
)

var (
	reactorEvalMatched atomic.Uint64
	reactorEvalSkipped atomic.Uint64
	reactorEvalError   atomic.Uint64

	reactorDispatchSucceeded    atomic.Uint64
	reactorDispatchFailed       atomic.Uint64
	reactorDispatchDeadLettered atomic.Uint64

	heimdallFlaggedMu sync.RWMutex
	heimdallFlagged   = map[string]float64{}

	// capabilityWarningsMu guards capabilityWarnings.  The gauge is set
	// at most once per integration_type registration, so contention is
	// negligible — but the validator phase flip will start rejecting
	// manifests instead of just persisting warnings, and the operator
	// needs a stable scrape during the cut-over so we use the same
	// mutex+map pattern as heimdallFlagged.
	capabilityWarningsMu sync.RWMutex
	capabilityWarnings   = map[string]float64{}

	// capabilityWarningsTotal is the rolling counter of warning rows
	// the validator has emitted process-wide.  Distinct from the
	// per-integration_type gauge above: the counter answers "how many
	// non-conformant capability names have we seen ever?" so a 5m
	// rate() against this counter gives operators the spike-detection
	// metric the Phase-2 alert in monitoring/prometheus/alerts.yaml
	// fires on.  Per-integration_type cardinality stays bounded; the
	// counter is unlabeled to keep cardinality at 1.
	capabilityWarningsTotal atomic.Uint64

	// capabilityRejectionsTotal counts manifest registrations the
	// Phase-2 hard-fail validator rejected (HTTP 422).  Stays at zero
	// while the validator is in warn-only mode — the operator uses
	// this to confirm hard-fail is actually live after flipping
	// YGGDRASIL_VALIDATOR_PHASE.
	capabilityRejectionsTotal atomic.Uint64

	// Auth login outcome counters. Each /api/v1/auth/login attempt
	// terminates in exactly one of these buckets so sum() over the
	// family equals the total attempt count.
	authLoginSucceeded     atomic.Uint64
	authLoginFailed        atomic.Uint64
	authLoginRateLimited   atomic.Uint64
	authLoginAccountLocked atomic.Uint64
	authLoginMFARequired   atomic.Uint64

	// Auth MFA verify outcome counters, labeled by factor.
	authMFAVerifySucceededTOTP         atomic.Uint64
	authMFAVerifySucceededRecoveryCode atomic.Uint64
	authMFAVerifySucceededWebAuthn     atomic.Uint64
	authMFAVerifyFailedTOTP            atomic.Uint64
	authMFAVerifyFailedRecoveryCode    atomic.Uint64
	authMFAVerifyFailedWebAuthn        atomic.Uint64

	// Auth session create / revoke counters. Created counts the moment
	// `auth_sessions` row is inserted (across login + SSO + admin
	// flows); revoked counts each row transitioned to status=revoked
	// (logout, admin revoke, password rotation, offboard).
	authSessionsCreatedTotal atomic.Uint64
	authSessionsRevokedTotal atomic.Uint64

	// CSRF rejection counters. Two outcome buckets (missing_token,
	// token_mismatch) × two mode buckets (warn, enforce). Operators
	// chart `rate(yggdrasil_csrf_rejected_total{mode="warn"}[5m])` to
	// pace the FE rollout (warn-mode bumps converge to zero as
	// surface-console adopts the header) and to confirm the flip to
	// enforce mode doesn't 403-storm legitimate traffic.
	//
	// Audit ref: A7 (no CSRF token for state-changing endpoints).
	csrfRejectedMu    sync.RWMutex
	csrfRejectedCount = map[string]uint64{}

	// RBAC denial counters. Keyed by (permission, mode). The permission
	// label is bounded by the yggdrasil-self action_catalog (~17 strings
	// today), the mode label is closed-set {warn, enforce}. Operators
	// chart `rate(yggdrasil_console_rbac_denied_total{mode="warn"}[5m])`
	// during the observation window — when the curve flattens (no new
	// surprise denials from legit users) it's safe to flip
	// YGGDRASIL_CONSOLE_RBAC_ENFORCE=enforce.
	//
	// Audit ref: §3.1 (requireOpsPermission defined but never wired).
	// Contract ref: §12 (backend is authorization authority).
	rbacDeniedMu    sync.RWMutex
	rbacDeniedCount = map[string]uint64{}

	// Reconcile failure counter — bumped each time a background
	// reconciler (permission catalog sync from surface_manifests, secrets
	// materialization, etc.) hits a non-retryable error.  The current
	// failure mode that motivated this metric is the noisy
	// `permission reconcile failed: insert perm github.teams.write: pq:
	// duplicate key value violates unique constraint
	// "permissions_catalog_name_unique"` log line that fires every 30s
	// on a happy cluster (G4 audit) — operators couldn't tell from logs
	// alone whether the count was growing, shrinking, or static. With
	// this counter `rate(yggdrasil_reconcile_failures_total{kind="X"}[5m])`
	// answers the question directly.
	//
	// Label cardinality: `kind` is a closed set (permission_catalog,
	// secret_materialize, manifest_apply, …) drawn from the constants
	// below so unknown values are dropped.
	//
	// Audit ref: 2026-05-27 G4 / F2 (permission reconcile loop noise).
	reconcileFailuresMu    sync.RWMutex
	reconcileFailuresCount = map[string]uint64{}

	// Goroutine panic counter — bumped every time a fire-and-forget
	// goroutine wrapped by internal/goroutine.SafeGo recovers from a
	// panic. Label `name` identifies the call-site (audit_emit,
	// backchannel_dispatch, …) so operators can pinpoint which
	// background path is dying without scraping container logs.
	//
	// Without this metric a panicking goroutine kills the whole process
	// (Go default) — yet the operator only sees an OOMKilled-like
	// CrashLoopBackOff with no signal as to root cause. The wrapper +
	// metric pair gives both safety and observability.
	//
	// Cardinality is bounded by the (small, slow-moving) set of
	// SafeGo call-sites in the codebase. Unknown / empty names are
	// dropped so a typo doesn't explode the label space.
	//
	// Audit ref: 2026-05-28 F7 (background goroutine bounds).
	goroutinePanicsMu    sync.RWMutex
	goroutinePanicsCount = map[string]uint64{}
)

// Reconcile failure `kind` labels — closed set, additions require
// updating ResetForTest below so unit tests don't leak.
const (
	ReconcileKindPermissionCatalog = "permission_catalog"
	ReconcileKindSecretMaterialize = "secret_materialize"
	ReconcileKindManifestApply     = "manifest_apply"
)

// IncReactorEvaluation bumps the evaluation counter for the given outcome.
// Outcome must be one of the ReactorEval* constants; unknown values are
// dropped so cardinality stays bounded.
func IncReactorEvaluation(outcome string) {
	switch outcome {
	case ReactorEvalMatched:
		reactorEvalMatched.Add(1)
	case ReactorEvalSkipped:
		reactorEvalSkipped.Add(1)
	case ReactorEvalError:
		reactorEvalError.Add(1)
	}
}

// AddReactorEvaluations bumps the evaluation counter by n (used by the
// transactional MaterializeReactions path which materialises N reactions
// in one INSERT and wants to report N matches atomically).
func AddReactorEvaluations(outcome string, n uint64) {
	if n == 0 {
		return
	}
	switch outcome {
	case ReactorEvalMatched:
		reactorEvalMatched.Add(n)
	case ReactorEvalSkipped:
		reactorEvalSkipped.Add(n)
	case ReactorEvalError:
		reactorEvalError.Add(n)
	}
}

// IncReactorDispatch bumps the dispatch counter for the given outcome.
func IncReactorDispatch(outcome string) {
	switch outcome {
	case ReactorDispatchSucceeded:
		reactorDispatchSucceeded.Add(1)
	case ReactorDispatchFailed:
		reactorDispatchFailed.Add(1)
	case ReactorDispatchDeadLettered:
		reactorDispatchDeadLettered.Add(1)
	}
}

// SetHeimdallFlaggedCount records the latest flagged_count from a Heimdall
// pulse workflow.  The gauge is keyed by pulse name so multiple pulses
// (e.g., heimdall-ci-pulse, heimdall-cd-pulse) can coexist.  Negative
// values are clamped to 0 to keep the gauge well-defined.
func SetHeimdallFlaggedCount(pulseName string, value float64) {
	if pulseName == "" {
		return
	}
	if value < 0 {
		value = 0
	}
	heimdallFlaggedMu.Lock()
	defer heimdallFlaggedMu.Unlock()
	heimdallFlagged[pulseName] = value
}

// ReactorEvaluationsSnapshot returns the current counter values keyed by
// outcome label.  Used by /metrics to render the counter family.
func ReactorEvaluationsSnapshot() map[string]uint64 {
	return map[string]uint64{
		ReactorEvalMatched: reactorEvalMatched.Load(),
		ReactorEvalSkipped: reactorEvalSkipped.Load(),
		ReactorEvalError:   reactorEvalError.Load(),
	}
}

// ReactorDispatchesSnapshot returns the current counter values keyed by
// outcome label.
func ReactorDispatchesSnapshot() map[string]uint64 {
	return map[string]uint64{
		ReactorDispatchSucceeded:    reactorDispatchSucceeded.Load(),
		ReactorDispatchFailed:       reactorDispatchFailed.Load(),
		ReactorDispatchDeadLettered: reactorDispatchDeadLettered.Load(),
	}
}

// HeimdallFlaggedCountSnapshot returns the latest flagged_count per pulse
// name, in deterministic (sorted) key order so the /metrics output is
// stable across scrapes.
func HeimdallFlaggedCountSnapshot() []HeimdallFlaggedSample {
	heimdallFlaggedMu.RLock()
	defer heimdallFlaggedMu.RUnlock()
	keys := make([]string, 0, len(heimdallFlagged))
	for k := range heimdallFlagged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]HeimdallFlaggedSample, 0, len(keys))
	for _, k := range keys {
		out = append(out, HeimdallFlaggedSample{PulseName: k, Value: heimdallFlagged[k]})
	}
	return out
}

// HeimdallFlaggedSample is one (pulse_name, value) pair emitted by the
// /metrics endpoint.
type HeimdallFlaggedSample struct {
	PulseName string
	Value     float64
}

// SetCapabilityWarnings records the warning count emitted by the
// capability-naming validator for a given integration_type during its
// most recent POST /api/v1/manifests?kind=integration_type.  The gauge
// is keyed by integration_type so the operator can see which adapters
// are still producing warnings during the Phase-2 observation window.
// Empty integration_type strings are dropped; negative counts are
// clamped to 0.  Per-type cardinality is bounded by the number of
// integration_type manifests in the catalog (~30 at writing).
func SetCapabilityWarnings(integrationType string, value float64) {
	if integrationType == "" {
		return
	}
	if value < 0 {
		value = 0
	}
	capabilityWarningsMu.Lock()
	defer capabilityWarningsMu.Unlock()
	capabilityWarnings[integrationType] = value
}

// AddCapabilityWarningsTotal bumps the unlabeled process-wide counter by
// n.  n is the number of warnings emitted in a single validator run, so
// the counter reflects the cumulative warning volume — not the number
// of failed registrations.  Used by the Phase-2 spike-detection alert.
func AddCapabilityWarningsTotal(n uint64) {
	if n == 0 {
		return
	}
	capabilityWarningsTotal.Add(n)
}

// IncCapabilityRejections bumps the manifest-rejection counter — one
// per POST /api/v1/manifests rejected with HTTP 422 by the Phase-2
// hard-fail validator.  Stays at zero while
// YGGDRASIL_VALIDATOR_PHASE != "hard-fail".
func IncCapabilityRejections() {
	capabilityRejectionsTotal.Add(1)
}

// CapabilityWarningsSnapshot returns the latest warning gauge per
// integration_type, sorted alphabetically so /metrics output is
// stable across scrapes.
func CapabilityWarningsSnapshot() []CapabilityWarningsSample {
	capabilityWarningsMu.RLock()
	defer capabilityWarningsMu.RUnlock()
	keys := make([]string, 0, len(capabilityWarnings))
	for k := range capabilityWarnings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]CapabilityWarningsSample, 0, len(keys))
	for _, k := range keys {
		out = append(out, CapabilityWarningsSample{IntegrationType: k, Value: capabilityWarnings[k]})
	}
	return out
}

// CapabilityWarningsTotalSnapshot returns the process-wide counter value.
func CapabilityWarningsTotalSnapshot() uint64 {
	return capabilityWarningsTotal.Load()
}

// CapabilityRejectionsTotalSnapshot returns the count of manifest
// registrations the hard-fail validator has rejected.
func CapabilityRejectionsTotalSnapshot() uint64 {
	return capabilityRejectionsTotal.Load()
}

// CapabilityWarningsSample is one (integration_type, count) pair
// emitted by the /metrics endpoint.
type CapabilityWarningsSample struct {
	IntegrationType string
	Value           float64
}

// IncAuthLogin bumps the auth login counter for the given outcome.
// Outcome must be one of AuthLogin* constants; unknown values are
// dropped to keep label cardinality bounded.
//
// Operators chart `rate(yggdrasil_auth_login_total[5m])` faceted by
// outcome to detect:
//   - failed rate spikes (brute-force)
//   - rate_limited bursts (DDoS / misconfigured client)
//   - account_locked rate (threshold over noise floor → real attack)
//   - succeeded falling to zero (outage / hash corruption regression)
func IncAuthLogin(outcome string) {
	switch outcome {
	case AuthLoginSucceeded:
		authLoginSucceeded.Add(1)
	case AuthLoginFailed:
		authLoginFailed.Add(1)
	case AuthLoginRateLimited:
		authLoginRateLimited.Add(1)
	case AuthLoginAccountLocked:
		authLoginAccountLocked.Add(1)
	case AuthLoginMFARequired:
		authLoginMFARequired.Add(1)
	}
}

// IncAuthMFAVerify bumps the MFA verify counter for (outcome, factor).
// Both labels are closed-set; unknown combinations are no-ops.
func IncAuthMFAVerify(outcome, factor string) {
	switch {
	case outcome == AuthMFAVerifySucceeded && factor == AuthMFAFactorTOTP:
		authMFAVerifySucceededTOTP.Add(1)
	case outcome == AuthMFAVerifySucceeded && factor == AuthMFAFactorRecoveryCode:
		authMFAVerifySucceededRecoveryCode.Add(1)
	case outcome == AuthMFAVerifySucceeded && factor == AuthMFAFactorWebAuthn:
		authMFAVerifySucceededWebAuthn.Add(1)
	case outcome == AuthMFAVerifyFailed && factor == AuthMFAFactorTOTP:
		authMFAVerifyFailedTOTP.Add(1)
	case outcome == AuthMFAVerifyFailed && factor == AuthMFAFactorRecoveryCode:
		authMFAVerifyFailedRecoveryCode.Add(1)
	case outcome == AuthMFAVerifyFailed && factor == AuthMFAFactorWebAuthn:
		authMFAVerifyFailedWebAuthn.Add(1)
	}
}

// IncAuthSessionCreated bumps the lifetime counter of session-create
// events.  Used to compute "session create rate" and serves as the
// numerator of the daily active sessions if combined with retention.
func IncAuthSessionCreated() { authSessionsCreatedTotal.Add(1) }

// IncAuthSessionRevoked bumps the lifetime counter of session-revoke
// events (logout + admin + password rotation + offboard).
func IncAuthSessionRevoked() { authSessionsRevokedTotal.Add(1) }

// AuthLoginSnapshot returns the counter values keyed by outcome label.
func AuthLoginSnapshot() map[string]uint64 {
	return map[string]uint64{
		AuthLoginSucceeded:     authLoginSucceeded.Load(),
		AuthLoginFailed:        authLoginFailed.Load(),
		AuthLoginRateLimited:   authLoginRateLimited.Load(),
		AuthLoginAccountLocked: authLoginAccountLocked.Load(),
		AuthLoginMFARequired:   authLoginMFARequired.Load(),
	}
}

// AuthMFAVerifySnapshot returns the verify-counter values keyed by
// "outcome|factor" for deterministic /metrics rendering.
func AuthMFAVerifySnapshot() map[string]uint64 {
	return map[string]uint64{
		AuthMFAVerifySucceeded + "|" + AuthMFAFactorTOTP:         authMFAVerifySucceededTOTP.Load(),
		AuthMFAVerifySucceeded + "|" + AuthMFAFactorRecoveryCode: authMFAVerifySucceededRecoveryCode.Load(),
		AuthMFAVerifySucceeded + "|" + AuthMFAFactorWebAuthn:     authMFAVerifySucceededWebAuthn.Load(),
		AuthMFAVerifyFailed + "|" + AuthMFAFactorTOTP:            authMFAVerifyFailedTOTP.Load(),
		AuthMFAVerifyFailed + "|" + AuthMFAFactorRecoveryCode:    authMFAVerifyFailedRecoveryCode.Load(),
		AuthMFAVerifyFailed + "|" + AuthMFAFactorWebAuthn:        authMFAVerifyFailedWebAuthn.Load(),
	}
}

// AuthSessionsCreatedTotalSnapshot returns the cumulative session-created counter.
func AuthSessionsCreatedTotalSnapshot() uint64 { return authSessionsCreatedTotal.Load() }

// AuthSessionsRevokedTotalSnapshot returns the cumulative session-revoked counter.
func AuthSessionsRevokedTotalSnapshot() uint64 { return authSessionsRevokedTotal.Load() }

// CSRF rejection outcomes. Closed set so the Prometheus label cardinality
// stays bounded at 4 (2 outcomes × 2 modes).
const (
	CSRFRejectedMissingToken  = "missing_token"
	CSRFRejectedTokenMismatch = "token_mismatch"
	CSRFModeWarn              = "warn"
	CSRFModeEnforce           = "enforce"
)

// IncCSRFRejected bumps the CSRF rejection counter for (outcome, mode).
// Both labels are closed-set; unknown combinations are no-ops to keep
// cardinality bounded.
//
// outcome ∈ {missing_token, token_mismatch}
// mode    ∈ {warn, enforce}
func IncCSRFRejected(outcome, mode string) {
	if outcome != CSRFRejectedMissingToken && outcome != CSRFRejectedTokenMismatch {
		return
	}
	if mode != CSRFModeWarn && mode != CSRFModeEnforce {
		return
	}
	key := outcome + "|" + mode
	csrfRejectedMu.Lock()
	defer csrfRejectedMu.Unlock()
	csrfRejectedCount[key]++
}

// RBAC enforce modes — closed set.
const (
	RBACModeWarn    = "warn"
	RBACModeEnforce = "enforce"
)

// IncRBACDenied bumps the RBAC denial counter for (permission, mode).
// The mode label is closed-set; the permission label is bounded by the
// yggdrasil-self action_catalog (a finite, slow-moving list).
//
// permission: any yggdrasil:* string from the action_catalog
// mode      ∈ {warn, enforce}
func IncRBACDenied(permission, mode string) {
	if permission == "" {
		return
	}
	if mode != RBACModeWarn && mode != RBACModeEnforce {
		return
	}
	key := permission + "|" + mode
	rbacDeniedMu.Lock()
	defer rbacDeniedMu.Unlock()
	rbacDeniedCount[key]++
}

// RBACDeniedSnapshot returns the counter values keyed by "permission|mode".
// Deterministic ordering not required here (the /metrics renderer sorts).
// Unlike the closed-set CSRF family, the permission label set is dynamic
// (driven by what surface-console asks for), so we don't pre-populate
// zero rows — operators see permissions only after the first denial.
func RBACDeniedSnapshot() map[string]uint64 {
	rbacDeniedMu.RLock()
	defer rbacDeniedMu.RUnlock()
	out := make(map[string]uint64, len(rbacDeniedCount))
	for k, v := range rbacDeniedCount {
		out[k] = v
	}
	return out
}

// IncReconcileFailure bumps the failure counter for the given reconcile
// kind.  Unknown kinds are dropped to keep label cardinality bounded.
// Callers SHOULD also log the underlying error (we don't capture detail
// here — that's what structured logs are for); this metric only answers
// "is the loop failing more / less / at all?".
//
// Audit ref: 2026-05-27 G4 / F2.
func IncReconcileFailure(kind string) {
	switch kind {
	case ReconcileKindPermissionCatalog,
		ReconcileKindSecretMaterialize,
		ReconcileKindManifestApply:
		// recognized
	default:
		return
	}
	reconcileFailuresMu.Lock()
	defer reconcileFailuresMu.Unlock()
	reconcileFailuresCount[kind]++
}

// IncGoroutinePanic bumps the panic counter for the given SafeGo call-site
// name. Empty names are dropped to keep the label space sane.  The closed
// set is intentionally NOT enforced here — SafeGo call-sites are added
// incrementally as the codebase evolves and forcing a constant table here
// would create churn for every new background goroutine.
//
// Audit ref: 2026-05-28 F7.
func IncGoroutinePanic(name string) {
	if name == "" {
		return
	}
	goroutinePanicsMu.Lock()
	defer goroutinePanicsMu.Unlock()
	goroutinePanicsCount[name]++
}

// GoroutinePanicsSnapshot returns the panic counter values keyed by call-site
// name. Unlike the closed-set families, ordering is up to the /metrics
// renderer (which sorts).
func GoroutinePanicsSnapshot() map[string]uint64 {
	goroutinePanicsMu.RLock()
	defer goroutinePanicsMu.RUnlock()
	out := make(map[string]uint64, len(goroutinePanicsCount))
	for k, v := range goroutinePanicsCount {
		out[k] = v
	}
	return out
}

// ReconcileFailuresSnapshot returns the counter values keyed by kind.
// Every closed-set kind is present (zero-padded) so /metrics emits a
// stable family — operators build dashboards without "no datapoints"
// gaps before the first failure happens.
func ReconcileFailuresSnapshot() map[string]uint64 {
	reconcileFailuresMu.RLock()
	defer reconcileFailuresMu.RUnlock()
	out := make(map[string]uint64, 3)
	for _, k := range []string{
		ReconcileKindPermissionCatalog,
		ReconcileKindSecretMaterialize,
		ReconcileKindManifestApply,
	} {
		out[k] = reconcileFailuresCount[k]
	}
	return out
}

// CSRFRejectedSnapshot returns the counter values keyed by "outcome|mode".
// Deterministic ordering not required here (the /metrics renderer sorts).
func CSRFRejectedSnapshot() map[string]uint64 {
	csrfRejectedMu.RLock()
	defer csrfRejectedMu.RUnlock()
	out := make(map[string]uint64, len(csrfRejectedCount))
	for k, v := range csrfRejectedCount {
		out[k] = v
	}
	// Ensure every closed-set key is present, so /metrics emits a stable
	// 4-line family even before any rejections happen — operators can
	// build dashboards without "no datapoints" gaps.
	for _, outcome := range []string{CSRFRejectedMissingToken, CSRFRejectedTokenMismatch} {
		for _, mode := range []string{CSRFModeWarn, CSRFModeEnforce} {
			k := outcome + "|" + mode
			if _, ok := out[k]; !ok {
				out[k] = 0
			}
		}
	}
	return out
}

// ResetForTest clears all counters/gauges.  Test-only — not exposed in
// the production /metrics surface.
func ResetForTest() {
	reactorEvalMatched.Store(0)
	reactorEvalSkipped.Store(0)
	reactorEvalError.Store(0)
	reactorDispatchSucceeded.Store(0)
	reactorDispatchFailed.Store(0)
	reactorDispatchDeadLettered.Store(0)
	heimdallFlaggedMu.Lock()
	heimdallFlagged = map[string]float64{}
	heimdallFlaggedMu.Unlock()
	capabilityWarningsMu.Lock()
	capabilityWarnings = map[string]float64{}
	capabilityWarningsMu.Unlock()
	capabilityWarningsTotal.Store(0)
	capabilityRejectionsTotal.Store(0)
	authLoginSucceeded.Store(0)
	authLoginFailed.Store(0)
	authLoginRateLimited.Store(0)
	authLoginAccountLocked.Store(0)
	authLoginMFARequired.Store(0)
	authMFAVerifySucceededTOTP.Store(0)
	authMFAVerifySucceededRecoveryCode.Store(0)
	authMFAVerifySucceededWebAuthn.Store(0)
	authMFAVerifyFailedTOTP.Store(0)
	authMFAVerifyFailedRecoveryCode.Store(0)
	authMFAVerifyFailedWebAuthn.Store(0)
	authSessionsCreatedTotal.Store(0)
	authSessionsRevokedTotal.Store(0)
	csrfRejectedMu.Lock()
	csrfRejectedCount = map[string]uint64{}
	csrfRejectedMu.Unlock()
	rbacDeniedMu.Lock()
	rbacDeniedCount = map[string]uint64{}
	rbacDeniedMu.Unlock()
	reconcileFailuresMu.Lock()
	reconcileFailuresCount = map[string]uint64{}
	reconcileFailuresMu.Unlock()
	goroutinePanicsMu.Lock()
	goroutinePanicsCount = map[string]uint64{}
	goroutinePanicsMu.Unlock()
}
