package message

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// TestMaybeUpdateHeimdallFlaggedCount_HappyPath: a heimdall-ci-pulse response
// whose last step output carries flagged_count must publish it to the
// internal metrics gauge keyed by the workflow name.
func TestMaybeUpdateHeimdallFlaggedCount_HappyPath(t *testing.T) {
	metrics.ResetForTest()

	resp := model.RunWorkflowResponse{
		Workflow: model.ManifestReference{Name: "heimdall-ci-pulse", Namespace: "global"},
		Steps: []model.WorkflowRunStepResult{
			{
				ID:       "compose-message",
				Metadata: map[string]any{"output": map[string]any{"text": "12 repos red"}},
			},
			{
				ID: "batch-ci-status",
				Metadata: map[string]any{
					"output": map[string]any{
						"flagged_count": float64(12),
						"repo_count":    float64(42),
					},
				},
			},
		},
	}

	maybeUpdateHeimdallFlaggedCount(resp)

	samples := metrics.HeimdallFlaggedCountSnapshot()
	if len(samples) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(samples))
	}
	if samples[0].PulseName != "heimdall-ci-pulse" {
		t.Fatalf("pulse name: got %q, want heimdall-ci-pulse", samples[0].PulseName)
	}
	if samples[0].Value != 12 {
		t.Fatalf("value: got %v, want 12", samples[0].Value)
	}
}

// Non-heimdall workflows must NOT publish a gauge, even when their steps
// happen to expose flagged_count.  The prefix gate is the only signal we
// trust because the gauge family is scoped to heimdall-* operators.
func TestMaybeUpdateHeimdallFlaggedCount_NonHeimdallSkipped(t *testing.T) {
	metrics.ResetForTest()

	resp := model.RunWorkflowResponse{
		Workflow: model.ManifestReference{Name: "ci-build-pulse", Namespace: "global"},
		Steps: []model.WorkflowRunStepResult{
			{
				ID:       "step-a",
				Metadata: map[string]any{"output": map[string]any{"flagged_count": float64(99)}},
			},
		},
	}

	maybeUpdateHeimdallFlaggedCount(resp)

	if got := len(metrics.HeimdallFlaggedCountSnapshot()); got != 0 {
		t.Fatalf("expected 0 samples for non-heimdall workflow, got %d", got)
	}
}

// JSON-decoded responses (passing through the persisted workflow_runs.result
// path) wrap numbers as json.Number when the decoder uses UseNumber.  The
// extractor must tolerate that representation.
func TestMaybeUpdateHeimdallFlaggedCount_JSONNumber(t *testing.T) {
	metrics.ResetForTest()

	resp := model.RunWorkflowResponse{
		Workflow: model.ManifestReference{Name: "heimdall-ci-pulse"},
		Steps: []model.WorkflowRunStepResult{
			{
				ID:       "batch-ci-status",
				Metadata: map[string]any{"output": map[string]any{"flagged_count": json.Number("7")}},
			},
		},
	}

	maybeUpdateHeimdallFlaggedCount(resp)

	samples := metrics.HeimdallFlaggedCountSnapshot()
	if len(samples) != 1 || samples[0].Value != 7 {
		t.Fatalf("expected value 7, got %+v", samples)
	}
}

// When multiple steps expose flagged_count we pick the LAST one — that
// matches the operator intuition that the pulse settled on the final
// computation.  We also confirm steps with no output are skipped without
// blowing up.
func TestMaybeUpdateHeimdallFlaggedCount_LastWins(t *testing.T) {
	metrics.ResetForTest()

	resp := model.RunWorkflowResponse{
		Workflow: model.ManifestReference{Name: "heimdall-cd-pulse"},
		Steps: []model.WorkflowRunStepResult{
			{ID: "noop", Metadata: nil},
			{ID: "first-count", Metadata: map[string]any{"output": map[string]any{"flagged_count": float64(3)}}},
			{ID: "skip-output", Metadata: map[string]any{"output": "not-a-map"}},
			{ID: "final-count", Metadata: map[string]any{"output": map[string]any{"flagged_count": float64(8)}}},
		},
	}

	maybeUpdateHeimdallFlaggedCount(resp)

	samples := metrics.HeimdallFlaggedCountSnapshot()
	if len(samples) != 1 || samples[0].Value != 8 {
		t.Fatalf("expected last-wins value 8, got %+v", samples)
	}
}

// A pulse that does not surface flagged_count anywhere must leave the
// gauge unchanged from its previous state — important so a degraded pulse
// does not zero out the dashboard.
func TestMaybeUpdateHeimdallFlaggedCount_NoOutputLeavesPriorValue(t *testing.T) {
	metrics.ResetForTest()
	metrics.SetHeimdallFlaggedCount("heimdall-ci-pulse", 17)

	resp := model.RunWorkflowResponse{
		Workflow: model.ManifestReference{Name: "heimdall-ci-pulse"},
		Steps: []model.WorkflowRunStepResult{
			{ID: "compose", Metadata: map[string]any{"output": map[string]any{"text": "all green"}}},
		},
	}

	maybeUpdateHeimdallFlaggedCount(resp)

	samples := metrics.HeimdallFlaggedCountSnapshot()
	if len(samples) != 1 || samples[0].Value != 17 {
		t.Fatalf("expected gauge to remain at 17 (prior value), got %+v", samples)
	}
}
