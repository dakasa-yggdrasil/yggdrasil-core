package manifest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidateWorkflowSpec(t *testing.T) {
	spec := workflowSpecFixture()

	if err := ValidateWorkflowSpec(spec); err != nil {
		t.Fatalf("ValidateWorkflowSpec error: %v", err)
	}
}

func TestValidateWorkflowSpecRejectsUnknownDependency(t *testing.T) {
	spec := workflowSpecFixture()
	spec.Steps[1].DependsOn = []string{"missing"}

	if err := ValidateWorkflowSpec(spec); err == nil {
		t.Fatal("expected unknown dependency to fail validation")
	}
}

func TestValidateWorkflowSpecRejectsMissingIntegrationRef(t *testing.T) {
	spec := workflowSpecFixture()
	spec.Steps[0].Use.InstanceRef = nil

	if err := ValidateWorkflowSpec(spec); err == nil {
		t.Fatal("expected missing integration instance ref to fail validation")
	}
}

func TestValidateWorkflowSpecAcceptsYggdrasilApplyManifest(t *testing.T) {
	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		Steps: []model.WorkflowStepSpec{
			{
				ID: "register-instance",
				Use: model.WorkflowStepUseSpec{
					Kind:      "yggdrasil",
					Operation: "apply_manifest",
				},
				With: map[string]any{
					"manifest": map[string]any{
						"apiVersion": "yggdrasil.io/v1alpha1",
						"kind":       "integration_instance",
						"metadata":   map[string]any{"name": "ygg-probe", "namespace": "global"},
						"spec":       map[string]any{"type_ref": map[string]any{"name": "probe", "namespace": "dakasa"}},
					},
				},
			},
		},
	}

	if err := ValidateWorkflowSpec(spec); err != nil {
		t.Fatalf("ValidateWorkflowSpec(yggdrasil apply_manifest) error: %v", err)
	}
}

func TestValidateWorkflowSpecRejectsYggdrasilWithUnknownOperation(t *testing.T) {
	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		Steps: []model.WorkflowStepSpec{
			{
				ID: "mystery",
				Use: model.WorkflowStepUseSpec{
					Kind:      "yggdrasil",
					Operation: "delete_manifest",
				},
				With: map[string]any{"manifest": map[string]any{}},
			},
		},
	}

	if err := ValidateWorkflowSpec(spec); err == nil {
		t.Fatal("expected yggdrasil step with unsupported operation to fail validation")
	}
}

func TestValidateWorkflowSpecRejectsYggdrasilWithIntegrationFields(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*model.WorkflowStepSpec)
	}{
		{
			name: "family set",
			mut:  func(s *model.WorkflowStepSpec) { s.Use.Family = "kubernetes" },
		},
		{
			name: "instance_ref set",
			mut: func(s *model.WorkflowStepSpec) {
				s.Use.InstanceRef = &model.ManifestSelector{Name: "whatever", Namespace: "global"}
			},
		},
		{
			name: "provider_ref set",
			mut: func(s *model.WorkflowStepSpec) {
				s.Use.ProviderRef = &model.ManifestSelector{Name: "whatever", Namespace: "global"}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := model.WorkflowManifestSpec{
				Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
				Steps: []model.WorkflowStepSpec{
					{
						ID: "apply",
						Use: model.WorkflowStepUseSpec{
							Kind:      "yggdrasil",
							Operation: "apply_manifest",
						},
						With: map[string]any{"manifest": map[string]any{}},
					},
				},
			}
			tc.mut(&spec.Steps[0])

			if err := ValidateWorkflowSpec(spec); err == nil {
				t.Fatalf("expected yggdrasil step with %s to fail validation", tc.name)
			}
		})
	}
}

func TestValidateWorkflowSpecRejectsYggdrasilWithoutManifest(t *testing.T) {
	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		Steps: []model.WorkflowStepSpec{
			{
				ID: "apply",
				Use: model.WorkflowStepUseSpec{
					Kind:      "yggdrasil",
					Operation: "apply_manifest",
				},
			},
		},
	}

	if err := ValidateWorkflowSpec(spec); err == nil {
		t.Fatal("expected yggdrasil apply_manifest step without with.manifest to fail validation")
	}
}

func TestWorkflowDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(workflowSpecFixture())
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "workflow",
		Metadata: model.ManifestMetadataInput{
			Name:      "service-deploy",
			Namespace: "global",
		},
		Spec: raw,
	}

	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(workflow) error: %v", err)
	}
}

func TestRenderWorkflowInput(t *testing.T) {
	ctx := WorkflowExecutionContext{
		Inputs: map[string]any{
			"repository": "dakasa-co/platform-service",
			"ref":        "main",
			"inputs": map[string]any{
				"image": "sha256:123",
			},
		},
		Metadata: map[string]any{
			"source": "platform-surface",
		},
		Auth: model.WorkflowDispatchAuth{
			Token: "caller-token",
		},
		Workflow: model.ManifestReference{
			Name:      "service-deploy",
			Namespace: "global",
			Version:   2,
		},
		Steps: map[string]model.WorkflowRunStepResult{
			"dispatch": {
				ID:       "dispatch",
				Status:   "succeeded",
				Attempts: 1,
				Metadata: map[string]any{
					"run_id": "1234",
				},
				StartedAt:  time.Now(),
				FinishedAt: time.Now(),
			},
		},
	}

	rendered, err := RenderWorkflowInput(map[string]any{
		"repository": "{{ inputs.repository }}",
		"source":     "{{ metadata.source }}",
		"token":      "{{ auth.token }}",
		"message":    "deploy {{ workflow.name }} on {{ inputs.ref }}",
		"run_id":     "{{ steps.dispatch.metadata.run_id }}",
		"nested": map[string]any{
			"image": "{{ inputs.inputs.image }}",
		},
	}, ctx)
	if err != nil {
		t.Fatalf("RenderWorkflowInput error: %v", err)
	}

	scope := rendered.(map[string]any)
	if scope["repository"] != "dakasa-co/platform-service" {
		t.Fatalf("repository = %#v", scope["repository"])
	}
	if scope["source"] != "platform-surface" {
		t.Fatalf("source = %#v", scope["source"])
	}
	if scope["token"] != "caller-token" {
		t.Fatalf("token = %#v", scope["token"])
	}
	if scope["message"] != "deploy service-deploy on main" {
		t.Fatalf("message = %#v", scope["message"])
	}
	if scope["run_id"] != "1234" {
		t.Fatalf("run_id = %#v", scope["run_id"])
	}
}

func TestMergeWorkflowInputs(t *testing.T) {
	spec := workflowSpecFixture()
	spec.Defaults = map[string]any{
		"repository": "dakasa-co/default",
		"ref":        "main",
		"inputs": map[string]any{
			"environment": "prod",
			"region":      "us-central1",
		},
	}

	merged := MergeWorkflowInputs(spec, map[string]any{
		"ref": "release-2026-03-27",
		"inputs": map[string]any{
			"region": "southamerica-east1",
		},
	})

	if merged["repository"] != "dakasa-co/default" {
		t.Fatalf("repository = %#v", merged["repository"])
	}
	if merged["ref"] != "release-2026-03-27" {
		t.Fatalf("ref = %#v", merged["ref"])
	}

	nested, ok := merged["inputs"].(map[string]any)
	if !ok {
		t.Fatalf("inputs = %#v", merged["inputs"])
	}
	if nested["environment"] != "prod" {
		t.Fatalf("environment = %#v", nested["environment"])
	}
	if nested["region"] != "southamerica-east1" {
		t.Fatalf("region = %#v", nested["region"])
	}
}

func TestValidateWorkflowInputsEnforcesMinLength(t *testing.T) {
	minOne := 1
	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		InputSchema: model.WorkflowInputSchemaSpec{
			Required: []string{"image_repo"},
			Properties: map[string]model.IntegrationSchemaProperty{
				"image_repo": {Type: "string", MinLength: &minOne},
			},
		},
		Steps: []model.WorkflowStepSpec{
			{
				ID: "noop",
				Use: model.WorkflowStepUseSpec{
					Kind:        "integration",
					InstanceRef: &model.ManifestSelector{Name: "x", Namespace: "global"},
					Capability:  "describe",
				},
			},
		},
	}

	cases := []struct {
		name       string
		inputs     map[string]any
		wantErr    bool
		wantSubstr string
	}{
		{
			name:       "empty string rejected",
			inputs:     map[string]any{"image_repo": ""},
			wantErr:    true,
			wantSubstr: "minLength",
		},
		{
			name:       "whitespace string rejected",
			inputs:     map[string]any{"image_repo": "   "},
			wantErr:    true,
			wantSubstr: "minLength",
		},
		{
			name:    "valid string accepted",
			inputs:  map[string]any{"image_repo": "153828470928.dkr.ecr.us-east-1.amazonaws.com/dakasa/enterprise-fe"},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateWorkflowInputs(spec, tc.inputs)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.wantSubstr != "" && !strings.Contains(err.Error(), tc.wantSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateWorkflowInputsMinLengthSkippedWhenFieldAbsent(t *testing.T) {
	// Field declared with minLength but NOT required and NOT provided should
	// not trip — the presence gate is `required`, minLength is a value-shape
	// gate that runs only after a value materializes.
	minOne := 1
	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		InputSchema: model.WorkflowInputSchemaSpec{
			Properties: map[string]model.IntegrationSchemaProperty{
				"optional_repo": {Type: "string", MinLength: &minOne},
			},
		},
		Steps: []model.WorkflowStepSpec{
			{
				ID: "noop",
				Use: model.WorkflowStepUseSpec{
					Kind:        "integration",
					InstanceRef: &model.ManifestSelector{Name: "x", Namespace: "global"},
					Capability:  "describe",
				},
			},
		},
	}

	if err := ValidateWorkflowInputs(spec, map[string]any{}); err != nil {
		t.Fatalf("unexpected error when optional field absent: %v", err)
	}
}

func TestValidateWorkflowInputsMinLengthIgnoredForNonStringTypes(t *testing.T) {
	// minLength is a string-only constraint; declaring it on object/array/
	// integer types should be a no-op rather than a crash.
	minOne := 1
	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		InputSchema: model.WorkflowInputSchemaSpec{
			Properties: map[string]model.IntegrationSchemaProperty{
				"obj_field": {Type: "object", MinLength: &minOne},
				"arr_field": {Type: "array", MinLength: &minOne},
				"int_field": {Type: "integer", MinLength: &minOne},
			},
		},
		Steps: []model.WorkflowStepSpec{
			{
				ID: "noop",
				Use: model.WorkflowStepUseSpec{
					Kind:        "integration",
					InstanceRef: &model.ManifestSelector{Name: "x", Namespace: "global"},
					Capability:  "describe",
				},
			},
		},
	}

	inputs := map[string]any{
		"obj_field": map[string]any{},
		"arr_field": []any{},
		"int_field": 0,
	}
	if err := ValidateWorkflowInputs(spec, inputs); err != nil {
		t.Fatalf("unexpected error for non-string types with minLength: %v", err)
	}
}

func workflowSpecFixture() model.WorkflowManifestSpec {
	return model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{
			Mode: "manual",
		},
		InputSchema: model.WorkflowInputSchemaSpec{
			Required: []string{"repository", "workflow"},
			Properties: map[string]model.IntegrationSchemaProperty{
				"repository": {Type: "string"},
				"workflow":   {Type: "string"},
				"ref":        {Type: "string"},
			},
		},
		Defaults: map[string]any{
			"inputs": map[string]any{
				"environment": "prod",
			},
		},
		Steps: []model.WorkflowStepSpec{
			{
				ID: "dispatch",
				Use: model.WorkflowStepUseSpec{
					Kind: "integration",
					InstanceRef: &model.ManifestSelector{
						Name:      "github-caller",
						Namespace: "global",
					},
					Capability: "dispatch_workflow",
				},
				With: map[string]any{
					"repository": "{{ inputs.repository }}",
					"workflow":   "{{ inputs.workflow }}",
					"ref":        "{{ inputs.ref }}",
					"inputs": map[string]any{
						"environment": "prod",
					},
				},
			},
			{
				ID: "notify",
				Use: model.WorkflowStepUseSpec{
					Kind: "integration",
					InstanceRef: &model.ManifestSelector{
						Name:      "github-caller",
						Namespace: "global",
					},
					Capability: "dispatch_workflow",
				},
				DependsOn: []string{"dispatch"},
				With: map[string]any{
					"repository": "{{ inputs.repository }}",
					"workflow":   "notify.yml",
				},
			},
		},
	}
}
