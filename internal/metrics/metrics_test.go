package metrics

import (
	"testing"
)

func TestIncReactorEvaluationCountsByOutcome(t *testing.T) {
	ResetForTest()
	IncReactorEvaluation(ReactorEvalMatched)
	IncReactorEvaluation(ReactorEvalMatched)
	IncReactorEvaluation(ReactorEvalSkipped)
	IncReactorEvaluation(ReactorEvalError)
	IncReactorEvaluation("nonsense") // dropped

	snap := ReactorEvaluationsSnapshot()
	if got := snap[ReactorEvalMatched]; got != 2 {
		t.Fatalf("matched: got %d, want 2", got)
	}
	if got := snap[ReactorEvalSkipped]; got != 1 {
		t.Fatalf("skipped: got %d, want 1", got)
	}
	if got := snap[ReactorEvalError]; got != 1 {
		t.Fatalf("error: got %d, want 1", got)
	}
}

func TestAddReactorEvaluationsBatch(t *testing.T) {
	ResetForTest()
	AddReactorEvaluations(ReactorEvalMatched, 5)
	AddReactorEvaluations(ReactorEvalMatched, 0) // no-op
	AddReactorEvaluations("nonsense", 7)         // dropped

	if got := ReactorEvaluationsSnapshot()[ReactorEvalMatched]; got != 5 {
		t.Fatalf("matched: got %d, want 5", got)
	}
}

func TestIncReactorDispatchCountsByOutcome(t *testing.T) {
	ResetForTest()
	IncReactorDispatch(ReactorDispatchSucceeded)
	IncReactorDispatch(ReactorDispatchSucceeded)
	IncReactorDispatch(ReactorDispatchSucceeded)
	IncReactorDispatch(ReactorDispatchFailed)
	IncReactorDispatch(ReactorDispatchDeadLettered)
	IncReactorDispatch("nonsense") // dropped

	snap := ReactorDispatchesSnapshot()
	if got := snap[ReactorDispatchSucceeded]; got != 3 {
		t.Fatalf("succeeded: got %d, want 3", got)
	}
	if got := snap[ReactorDispatchFailed]; got != 1 {
		t.Fatalf("failed: got %d, want 1", got)
	}
	if got := snap[ReactorDispatchDeadLettered]; got != 1 {
		t.Fatalf("dead_lettered: got %d, want 1", got)
	}
}

func TestSetHeimdallFlaggedCountKeyedByPulse(t *testing.T) {
	ResetForTest()
	SetHeimdallFlaggedCount("heimdall-ci-pulse", 12)
	SetHeimdallFlaggedCount("heimdall-cd-pulse", 0)
	SetHeimdallFlaggedCount("heimdall-ci-pulse", 7) // last-write-wins

	samples := HeimdallFlaggedCountSnapshot()
	if len(samples) != 2 {
		t.Fatalf("expected 2 pulses, got %d", len(samples))
	}
	// Sorted alphabetically by pulse name.
	if samples[0].PulseName != "heimdall-cd-pulse" || samples[0].Value != 0 {
		t.Fatalf("first sample: got %+v", samples[0])
	}
	if samples[1].PulseName != "heimdall-ci-pulse" || samples[1].Value != 7 {
		t.Fatalf("second sample: got %+v (want value 7 last-write-wins)", samples[1])
	}
}

func TestSetHeimdallFlaggedCountRejectsEmptyPulseAndClampsNegative(t *testing.T) {
	ResetForTest()
	SetHeimdallFlaggedCount("", 99) // dropped
	SetHeimdallFlaggedCount("heimdall-ci-pulse", -3)

	samples := HeimdallFlaggedCountSnapshot()
	if len(samples) != 1 {
		t.Fatalf("expected 1 sample after empty-key drop, got %d", len(samples))
	}
	if samples[0].Value != 0 {
		t.Fatalf("expected negative value clamped to 0, got %v", samples[0].Value)
	}
}
