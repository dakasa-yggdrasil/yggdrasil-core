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
}
