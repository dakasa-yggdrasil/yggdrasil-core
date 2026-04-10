package httpapi

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestGuardianMemoryMatchesPlaybookReview(t *testing.T) {
	t.Parallel()

	spec := model.GuardianMemoryManifestSpec{
		Action: map[string]any{
			"type": "dispatch_workflow",
			"workflow": map[string]any{
				"workflow": "deploy.yml",
			},
			"target": map[string]any{
				"learned_playbook_pattern": "workflow_dispatch:deploy.yml",
			},
		},
		Incident: map[string]any{
			"category": "capacity",
		},
		Metadata: map[string]any{
			"provider_group": "gcp",
		},
	}

	if !guardianMemoryMatchesPlaybookReview(spec, guardianMemoryReviewRequest{
		ActionType:       "dispatch_workflow",
		PatternKind:      "workflow_dispatch",
		PatternValue:     "deploy.yml",
		IncidentCategory: "capacity",
		ProviderGroup:    "gcp",
	}) {
		t.Fatal("expected guardian memory to match requested playbook review")
	}

	if guardianMemoryMatchesPlaybookReview(spec, guardianMemoryReviewRequest{
		ActionType:       "dispatch_workflow",
		PatternKind:      "workflow_dispatch",
		PatternValue:     "incident-escalation.yml",
		IncidentCategory: "capacity",
		ProviderGroup:    "gcp",
	}) {
		t.Fatal("expected guardian memory pattern mismatch to be rejected")
	}
}

func TestApplyGuardianMemoryReview(t *testing.T) {
	t.Parallel()

	metadata := map[string]any{
		"provider_group": "kubernetes",
	}

	promoted := applyGuardianMemoryReview(metadata, "promoted", "human-reviewed")
	if got := promoted["learned_playbook_review_status"]; got != "promoted" {
		t.Fatalf("review status = %#v, want promoted", got)
	}
	if got := promoted["learned_playbook_review_note"]; got != "human-reviewed" {
		t.Fatalf("review note = %#v, want human-reviewed", got)
	}
	if promoted["learned_playbook_reviewed_at"] == nil {
		t.Fatal("expected reviewed_at to be populated")
	}
	structured, ok := promoted["learned_playbook_review"].(map[string]any)
	if !ok {
		t.Fatalf("expected structured review record, got %#v", promoted["learned_playbook_review"])
	}
	if got := structured["status"]; got != "promoted" {
		t.Fatalf("structured review status = %#v, want promoted", got)
	}
	if got := structured["comment"]; got != "human-reviewed" {
		t.Fatalf("structured review comment = %#v, want human-reviewed", got)
	}

	cleared := applyGuardianMemoryReview(promoted, "clear", "")
	if _, ok := cleared["learned_playbook_review_status"]; ok {
		t.Fatal("expected review status to be cleared")
	}
	if _, ok := cleared["learned_playbook_review_note"]; ok {
		t.Fatal("expected review note to be cleared")
	}
	if _, ok := cleared["learned_playbook_reviewed_at"]; ok {
		t.Fatal("expected reviewed_at to be cleared")
	}
	if _, ok := cleared["learned_playbook_review"]; ok {
		t.Fatal("expected structured review record to be cleared")
	}
}
