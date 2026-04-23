package manifest

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestCompileQuickstartToWorkflowHappyPath(t *testing.T) {
	spec := integrationQuickstartFixture()
	wf, provider, err := CompileQuickstartToWorkflow(spec, "aws-secrets-manager", map[string]any{
		"region": "us-east-1",
		"tier":   "standard",
	})
	if err != nil {
		t.Fatalf("CompileQuickstartToWorkflow error: %v", err)
	}
	if provider.ID != "aws-secrets-manager" {
		t.Fatalf("expected provider id aws-secrets-manager, got %q", provider.ID)
	}
	if wf.Trigger.Mode != "manual" {
		t.Fatalf("expected trigger mode manual, got %q", wf.Trigger.Mode)
	}
	if len(wf.Steps) != 2 {
		t.Fatalf("expected 2 steps (1 declared + 1 smoke_test), got %d", len(wf.Steps))
	}
	if wf.Steps[0].ID != "register-instance" {
		t.Fatalf("expected first step register-instance, got %q", wf.Steps[0].ID)
	}
	if wf.Steps[1].ID != "smoke-test" {
		t.Fatalf("expected last step smoke-test, got %q", wf.Steps[1].ID)
	}
	if len(wf.Steps[1].DependsOn) != 1 || wf.Steps[1].DependsOn[0] != "register-instance" {
		t.Fatalf("expected smoke-test depends_on=[register-instance], got %v", wf.Steps[1].DependsOn)
	}
	if wf.Defaults["region"] != "us-east-1" {
		t.Fatalf("expected defaults.region=us-east-1, got %v", wf.Defaults["region"])
	}
	if _, ok := wf.InputSchema.Properties["region"]; !ok {
		t.Fatal("expected input_schema.properties.region to be populated")
	}
	if got := wf.Steps[0].Use.Family; got != "secrets-management" {
		t.Fatalf("expected step Use.Family=secrets-management, got %q", got)
	}
}

func TestCompileQuickstartLinearDependsOn(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Steps = []model.QuickstartStep{
		{ID: "step-a", Uses: map[string]any{"kind": "integration", "family": "f", "operation": "op"}},
		{ID: "step-b", Uses: map[string]any{"kind": "integration", "family": "f", "operation": "op"}},
		{ID: "step-c", Uses: map[string]any{"kind": "integration", "family": "f", "operation": "op"}},
	}
	spec.Providers[0].SmokeTest = nil

	wf, _, err := CompileQuickstartToWorkflow(spec, "aws-secrets-manager", map[string]any{
		"region": "us-east-1",
		"tier":   "standard",
	})
	if err != nil {
		t.Fatalf("CompileQuickstartToWorkflow error: %v", err)
	}
	if len(wf.Steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(wf.Steps))
	}
	if len(wf.Steps[0].DependsOn) != 0 {
		t.Fatalf("expected first step to have no depends_on, got %v", wf.Steps[0].DependsOn)
	}
	if len(wf.Steps[1].DependsOn) != 1 || wf.Steps[1].DependsOn[0] != "step-a" {
		t.Fatalf("expected step-b depends_on=[step-a], got %v", wf.Steps[1].DependsOn)
	}
	if len(wf.Steps[2].DependsOn) != 1 || wf.Steps[2].DependsOn[0] != "step-b" {
		t.Fatalf("expected step-c depends_on=[step-b], got %v", wf.Steps[2].DependsOn)
	}
}

func TestCompileQuickstartRequiresProviderIDWhenMultipleProviders(t *testing.T) {
	spec := integrationQuickstartFixture()
	second := spec.Providers[0]
	second.ID = "gcp-secret-manager"
	spec.Providers = append(spec.Providers, second)

	if _, _, err := CompileQuickstartToWorkflow(spec, "", nil); err == nil {
		t.Fatal("expected missing provider_id with multiple providers to fail")
	}
}

func TestCompileQuickstartUnknownProviderID(t *testing.T) {
	spec := integrationQuickstartFixture()
	if _, _, err := CompileQuickstartToWorkflow(spec, "does-not-exist", nil); err == nil {
		t.Fatal("expected unknown provider_id to fail")
	}
}

func TestCompileQuickstartRejectsMissingRequiredInput(t *testing.T) {
	spec := integrationQuickstartFixture()
	if _, _, err := CompileQuickstartToWorkflow(spec, "aws-secrets-manager", map[string]any{
		"tier": "standard",
	}); err == nil {
		t.Fatal("expected missing required input to fail")
	}
}

func TestCompileQuickstartRejectsBadRegex(t *testing.T) {
	spec := integrationQuickstartFixture()
	if _, _, err := CompileQuickstartToWorkflow(spec, "aws-secrets-manager", map[string]any{
		"region": "BAD",
		"tier":   "standard",
	}); err == nil {
		t.Fatal("expected input that fails regex to be rejected")
	}
}

func TestCompileQuickstartRejectsUnknownInput(t *testing.T) {
	spec := integrationQuickstartFixture()
	if _, _, err := CompileQuickstartToWorkflow(spec, "aws-secrets-manager", map[string]any{
		"region":   "us-east-1",
		"tier":     "standard",
		"unknown":  "x",
	}); err == nil {
		t.Fatal("expected unknown input to be rejected")
	}
}

func TestCompileQuickstartRejectsBadSelectChoice(t *testing.T) {
	spec := integrationQuickstartFixture()
	if _, _, err := CompileQuickstartToWorkflow(spec, "aws-secrets-manager", map[string]any{
		"region": "us-east-1",
		"tier":   "ultimate",
	}); err == nil {
		t.Fatal("expected select value outside choices to be rejected")
	}
}

func TestCompileQuickstartCoercesIntegerFromFloat(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Inputs = []model.QuickstartInput{
		{ID: "size", Label: "Size", Type: "integer", Required: true},
	}
	wf, _, err := CompileQuickstartToWorkflow(spec, "aws-secrets-manager", map[string]any{
		"size": float64(20),
	})
	if err != nil {
		t.Fatalf("expected JSON-decoded float to coerce to int: %v", err)
	}
	if wf.Defaults["size"].(int) != 20 {
		t.Fatalf("expected size=20, got %v", wf.Defaults["size"])
	}
}

func TestCompileQuickstartRejectsFractionalIntegerInput(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Inputs = []model.QuickstartInput{
		{ID: "size", Label: "Size", Type: "integer", Required: true},
	}
	if _, _, err := CompileQuickstartToWorkflow(spec, "aws-secrets-manager", map[string]any{
		"size": 1.5,
	}); err == nil {
		t.Fatal("expected fractional integer input to be rejected")
	}
}

func TestCompileQuickstartUsesDefaultWhenInputOmitted(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Inputs = []model.QuickstartInput{
		{ID: "region", Label: "Region", Type: "string", Default: "eu-west-1"},
	}
	wf, _, err := CompileQuickstartToWorkflow(spec, "aws-secrets-manager", nil)
	if err != nil {
		t.Fatalf("CompileQuickstartToWorkflow error: %v", err)
	}
	if wf.Defaults["region"] != "eu-west-1" {
		t.Fatalf("expected default eu-west-1, got %v", wf.Defaults["region"])
	}
}
