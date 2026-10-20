//go:build linux && nativequalification

package main

import (
	"fmt"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestOriginalPublicClosedRefusalPredicates(t *testing.T) {
	accepted := []string{
		"original-canonical-floor-next-output",
		"original-canonical-floor-next-permission",
		"original-canonical-floor-permission-gate",
		"original-source-historical-confirm",
		"original-source-historical-output",
		"original-source-live-partial",
		"original-source-live-partial-output",
		"original-source-terminal",
		"original-source-terminal-output",
		"pg17-original-confirm-assertions",
		"pg17-original-create-assertions",
		"pg17-original-historical-assertions",
		"pg17-original-terminal-assertions",
		"pg17-original-workflow-confirm",
	}
	for _, predicate := range accepted {
		t.Run(predicate, func(t *testing.T) {
			var got originalPublicReturn
			got.projectOriginalWorkflowReturn(model.WorkflowRunRecord{Status: "failed", Result: &model.RunWorkflowResponse{Steps: []model.WorkflowRunStepResult{{ID: "original-native-qemu-create", Status: "failed", Error: "protected original Guest source step unavailable", Metadata: map[string]any{"original_guest_refusal_predicate": predicate}}}}})
			if got.WorkflowPredicate != predicate {
				t.Fatal("Source-owned closed predicate discarded")
			}
		})
	}
	for _, predicate := range []string{"pg17-original-create-assertions-extra", "pg17-original-create-assertions\nsecret", "https://example.invalid/secret", "original-source-unknown", "original-guest-step-001"} {
		t.Run("refuse_"+predicate, func(t *testing.T) {
			var got originalPublicReturn
			got.projectOriginalWorkflowReturn(model.WorkflowRunRecord{Status: "failed", Result: &model.RunWorkflowResponse{Steps: []model.WorkflowRunStepResult{{ID: "original-native-qemu-create", Status: "failed", Metadata: map[string]any{"original_guest_refusal_predicate": predicate}}}}})
			if got.WorkflowPredicate != "" {
				t.Fatal("unclosed predicate disclosed")
			}
		})
	}
}

func TestOriginalWorkflowQualificationPredicatesRemainClosed(t *testing.T) {
	for code := 60; code <= 89; code++ {
		predicate := fmt.Sprintf("original-guest-step-%02d", code)
		var got originalPublicReturn
		got.projectOriginalWorkflowReturn(model.WorkflowRunRecord{Status: "failed", Result: &model.RunWorkflowResponse{Steps: []model.WorkflowRunStepResult{{ID: "original_echo_qualified", Status: "failed", Error: "SECRET", Metadata: map[string]any{"original_guest_refusal_predicate": predicate}}}}})
		if got.WorkflowPredicate != predicate || got.WorkflowFailedStep != "original_echo_qualified" {
			t.Fatalf("closed qualification predicate lost: %s", predicate)
		}
	}
}
