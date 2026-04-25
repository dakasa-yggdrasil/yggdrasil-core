package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func ephemeralFixture() model.EphemeralEnvironmentManifestSpec {
	return model.EphemeralEnvironmentManifestSpec{
		CreateWorkflow: model.EphemeralEnvironmentWorkflowSpec{
			WorkflowRef: model.ManifestRef{Namespace: "global", Name: "spin-up-stack"},
			Inputs:      map[string]any{"branch": "pr-1234"},
		},
		DestroyWorkflow: &model.EphemeralEnvironmentWorkflowSpec{
			WorkflowRef: model.ManifestRef{Namespace: "global", Name: "tear-down-stack"},
		},
		TTLSeconds:  28800,
		AutoDestroy: true,
	}
}

func TestValidateEphemeralEnvironmentSpec(t *testing.T) {
	if err := ValidateEphemeralEnvironmentSpec(ephemeralFixture()); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateEphemeralEnvironmentSpecRequiresCreateWorkflowName(t *testing.T) {
	spec := ephemeralFixture()
	spec.CreateWorkflow.WorkflowRef.Name = "  "
	if err := ValidateEphemeralEnvironmentSpec(spec); err == nil {
		t.Fatal("expected error for blank create_workflow.workflow_ref.name")
	}
}

func TestValidateEphemeralEnvironmentSpecRejectsAutoDestroyWithoutDestroyWorkflow(t *testing.T) {
	spec := ephemeralFixture()
	spec.DestroyWorkflow = nil
	if err := ValidateEphemeralEnvironmentSpec(spec); err == nil {
		t.Fatal("expected error: auto_destroy requires destroy_workflow")
	}
}

func TestValidateEphemeralEnvironmentSpecRejectsSubMinuteTTL(t *testing.T) {
	spec := ephemeralFixture()
	spec.TTLSeconds = 30
	if err := ValidateEphemeralEnvironmentSpec(spec); err == nil {
		t.Fatal("expected error for sub-minute TTL")
	}
}

func TestValidateEphemeralEnvironmentSpecAcceptsZeroTTL(t *testing.T) {
	spec := ephemeralFixture()
	spec.TTLSeconds = 0
	spec.AutoDestroy = false
	spec.DestroyWorkflow = nil
	if err := ValidateEphemeralEnvironmentSpec(spec); err != nil {
		t.Fatalf("expected zero TTL to be valid, got %v", err)
	}
}

func TestValidateEphemeralEnvironmentSpecRejectsNegativeCost(t *testing.T) {
	spec := ephemeralFixture()
	spec.CostProjection = &model.EphemeralEnvironmentCostProjection{EstimatedCost: -1}
	if err := ValidateEphemeralEnvironmentSpec(spec); err == nil {
		t.Fatal("expected error for negative cost")
	}
}

func TestNormalizeEphemeralEnvironmentSpecDefaults(t *testing.T) {
	spec := ephemeralFixture()
	spec.CreateWorkflow.WorkflowRef.Namespace = ""
	spec.CostProjection = &model.EphemeralEnvironmentCostProjection{EstimatedCost: 0.42}
	out := NormalizeEphemeralEnvironmentSpec(spec)
	if out.CreateWorkflow.WorkflowRef.Namespace != "global" {
		t.Fatalf("expected namespace 'global', got %q", out.CreateWorkflow.WorkflowRef.Namespace)
	}
	if out.CostProjection.Currency != "USD" {
		t.Fatalf("expected currency 'USD', got %q", out.CostProjection.Currency)
	}
}

func TestEphemeralEnvironmentDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(ephemeralFixture())
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "ephemeral_environment",
		Metadata:   model.ManifestMetadataInput{Name: "pr-1234", Namespace: "default"},
		Spec:       raw,
	}
	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(ephemeral_environment): %v", err)
	}
}
