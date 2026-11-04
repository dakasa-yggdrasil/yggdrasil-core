//go:build linux && nativequalification

package main

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"strings"
	"testing"
)

func TestOriginalPublicKnownHyphenatedStepProjection(t *testing.T) {
	privateError := "protected original Guest source step unavailable credential=secret https://user:password@example.invalid"
	run := model.WorkflowRunRecord{Status: "failed", Error: "step original-native-qemu-create failed", Result: &model.RunWorkflowResponse{Status: "failed", Steps: []model.WorkflowRunStepResult{{ID: "original-native-qemu-create", Status: "failed", Error: privateError, Metadata: map[string]any{"original_guest_refusal_predicate": "original-guest-step-07"}}}}}
	var got originalPublicReturn
	got.projectOriginalWorkflowReturn(run)
	if got.WorkflowFailedStep != "original-native-qemu-create" || got.WorkflowPredicate != "original-guest-step-07" || got.WorkflowErrorClass != "original_guest_source_hold" || got.WorkflowErrorBytes != len(privateError) || got.WorkflowErrorSHA256 != capacity.BusinessCreationSHA256([]byte(privateError)) {
		t.Fatal("actual typed failed step was discarded or misprojected")
	}
	body, err := json.Marshal(got)
	if err != nil || strings.Contains(string(body), "credential") || strings.Contains(string(body), "password") || strings.Contains(string(body), "example.invalid") || strings.Contains(string(body), privateError) {
		t.Fatal("private error plaintext leaked")
	}
}

func TestOriginalPublicStepProjectionRefusesUnclosedIDs(t *testing.T) {
	for _, id := range []string{"foreign-hyphen", "original-native-qemu-create-extra", "https://example.invalid/secret", strings.Repeat("a", 97)} {
		run := model.WorkflowRunRecord{Status: "failed", Result: &model.RunWorkflowResponse{Steps: []model.WorkflowRunStepResult{{ID: id, Status: "failed", Error: "secret", Metadata: map[string]any{"original_guest_refusal_predicate": "original-guest-step-07"}}}}}
		var got originalPublicReturn
		got.projectOriginalWorkflowReturn(run)
		if got.WorkflowFailedStep != "" || got.WorkflowPredicate != "" || got.WorkflowErrorBytes != 0 || got.WorkflowErrorSHA256 != "" {
			t.Fatal("unclosed ID disclosed step diagnostics")
		}
	}
	var got originalPublicReturn
	got.projectOriginalWorkflowReturn(model.WorkflowRunRecord{Status: "failed", Result: &model.RunWorkflowResponse{Steps: []model.WorkflowRunStepResult{{ID: "old_underscore", Status: "failed", Error: "secret", Metadata: map[string]any{"original_guest_refusal_predicate": "https://example.invalid/secret"}}}}})
	if got.WorkflowFailedStep != "old_underscore" || got.WorkflowPredicate != "" || got.WorkflowErrorClass != "other" {
		t.Fatal("legacy ID, unknown category or predicate privacy changed")
	}
}
