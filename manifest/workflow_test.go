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

func TestValidateWorkflowSpecAcceptsInputFreeOIDCClientReconcile(t *testing.T) {
	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		Steps: []model.WorkflowStepSpec{{
			ID: "reconcile-oidc-clients",
			Use: model.WorkflowStepUseSpec{
				Kind:      "yggdrasil",
				Operation: "oidc_client.verify_bootstrap_file",
			},
		}},
	}

	if err := ValidateWorkflowSpec(spec); err != nil {
		t.Fatalf("ValidateWorkflowSpec(input-free OIDC client reconcile) error: %v", err)
	}
	spec.Steps[0].With = map[string]any{"client_secret_hash": "forbidden"}
	if err := ValidateWorkflowSpec(spec); err == nil {
		t.Fatal("expected OIDC client reconcile workflow input to be rejected")
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

// TestRenderWorkflowInputPassesThroughDownstreamTemplates locks the carve-out
// that lets a declarative_apply ship ConfigMap blobs (Grafana dashboards,
// Prometheus rules) whose `data` legitimately contains `{{ }}` tokens meant for
// the blob's OWN renderer, not for Yggdrasil. Before this gate the prod
// monitoring deploy aborted at render with `workflow template "{{ }}" could not
// be resolved` the moment a `{{service}}` legend or a `{{ }}` comment reached
// renderWorkflowString.
func TestRenderWorkflowInputPassesThroughDownstreamTemplates(t *testing.T) {
	ctx := WorkflowExecutionContext{
		Inputs: map[string]any{"image_tag": "sha-abc123"},
	}

	rendered, err := RenderWorkflowInput(map[string]any{
		// Yggdrasil template: MUST still resolve.
		"image":  "{{ inputs.image_tag }}",
		"deploy": "rolling out {{ inputs.image_tag }} now",
		// Grafana dashboard legends (no dot): MUST pass through verbatim.
		"legend":   "{{service}}",
		"legendSp": "{{ status }}",
		"compound": "{{service}} success",
		// Prometheus / Alertmanager rule annotations: MUST pass through.
		"promValue": "{{ $value }}s behind",
		"promLabel": "on {{ $labels.db }}",
		// Grafana contact point / Alertmanager Go template (dot): pass through.
		"alertKey": "{{ .GroupKey }}",
		// Empty token (a comment artifact like `interpolates {{ }} tokens`).
		"emptyTok": "engine interpolates {{ }} tokens",
	}, ctx)
	if err != nil {
		t.Fatalf("RenderWorkflowInput error: %v", err)
	}

	scope := rendered.(map[string]any)
	for _, tc := range []struct{ key, want string }{
		{"image", "sha-abc123"},
		{"deploy", "rolling out sha-abc123 now"},
		{"legend", "{{ service }}"},
		{"legendSp", "{{ status }}"},
		{"compound", "{{ service }} success"},
		{"promValue", "{{ $value }}s behind"},
		{"promLabel", "on {{ $labels.db }}"},
		{"alertKey", "{{ .GroupKey }}"},
		{"emptyTok", "engine interpolates {{  }} tokens"},
	} {
		if got := scope[tc.key]; got != tc.want {
			t.Fatalf("%s = %#v, want %q", tc.key, got, tc.want)
		}
	}
}

// TestRenderWorkflowInputStillErrorsOnBadYggdrasilPath keeps the typo safety net:
// a token whose leading segment IS a Yggdrasil root but whose deeper path does
// not resolve must still fail loudly (not silently pass through).
func TestRenderWorkflowInputStillErrorsOnBadYggdrasilPath(t *testing.T) {
	ctx := WorkflowExecutionContext{Inputs: map[string]any{"image_tag": "sha-abc123"}}
	if _, err := RenderWorkflowInput("{{ inputs.does_not_exist }}", ctx); err == nil {
		t.Fatal("expected error for an unresolved inputs.* path")
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

func TestParseWorkflowSpecPreservesWorkflowMaxLengthAliases(t *testing.T) {
	tests := []struct {
		name string
		raw  json.RawMessage
	}{
		{
			name: "canonical JSON Schema maxLength",
			raw:  json.RawMessage(`{"input_schema":{"properties":{"image_digest":{"type":"string","maxLength":71}}}}`),
		},
		{
			name: "legacy integration max_length",
			raw:  json.RawMessage(`{"input_schema":{"properties":{"image_digest":{"type":"string","max_length":71}}}}`),
		},
		{
			name: "matching aliases",
			raw:  json.RawMessage(`{"input_schema":{"properties":{"image_digest":{"type":"string","maxLength":71,"max_length":71}}}}`),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ParseWorkflowSpec(tc.raw)
			if err != nil {
				t.Fatalf("ParseWorkflowSpec() error = %v", err)
			}
			got := spec.InputSchema.Properties["image_digest"].MaxLength
			if got == nil || *got != 71 {
				t.Fatalf("MaxLength = %v, want 71", got)
			}
		})
	}
}

func TestParseWorkflowSpecRejectsConflictingMaxLengthAliases(t *testing.T) {
	_, err := ParseWorkflowSpec(json.RawMessage(`{
		"input_schema": {
			"properties": {
				"image_digest": {"type":"string", "maxLength":71, "max_length":72}
			}
		}
	}`))
	if err == nil || !strings.Contains(err.Error(), "conflicting maxLength and max_length") {
		t.Fatalf("ParseWorkflowSpec() error = %v, want conflicting alias rejection", err)
	}
}

func TestValidateWorkflowInputsEnforcesPatternAndMaxLength(t *testing.T) {
	maxDigestLength := 71
	spec := model.WorkflowManifestSpec{
		InputSchema: model.WorkflowInputSchemaSpec{
			Properties: map[string]model.IntegrationSchemaProperty{
				"image_digest": {
					Type:      "string",
					Pattern:   `^sha256:[0-9a-f]{64}$`,
					MaxLength: &maxDigestLength,
				},
			},
		},
	}

	tests := []struct {
		name       string
		value      string
		wantErr    bool
		wantSubstr string
	}{
		{
			name:  "exact lowercase digest accepted",
			value: "sha256:" + strings.Repeat("a", 64),
		},
		{
			name:       "wrong algorithm rejected by pattern",
			value:      "sha255:" + strings.Repeat("a", 64),
			wantErr:    true,
			wantSubstr: "must match pattern",
		},
		{
			name:       "uppercase digest rejected by pattern",
			value:      "sha256:" + strings.Repeat("A", 64),
			wantErr:    true,
			wantSubstr: "must match pattern",
		},
		{
			name:       "non hexadecimal digest rejected by pattern",
			value:      "sha256:" + strings.Repeat("g", 64),
			wantErr:    true,
			wantSubstr: "must match pattern",
		},
		{
			name:       "short digest rejected by pattern",
			value:      "sha256:" + strings.Repeat("a", 63),
			wantErr:    true,
			wantSubstr: "must match pattern",
		},
		{
			name:       "overlong digest rejected before dispatch",
			value:      "sha256:" + strings.Repeat("a", 65),
			wantErr:    true,
			wantSubstr: "maxLength 71",
		},
		{
			name:       "full image URI rejected before dispatch",
			value:      "registry.example/dakasa/service@sha256:" + strings.Repeat("a", 64),
			wantErr:    true,
			wantSubstr: "maxLength 71",
		},
		{
			name:       "image tag rejected by pattern",
			value:      "sha-main",
			wantErr:    true,
			wantSubstr: "must match pattern",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateWorkflowInputs(spec, map[string]any{"image_digest": tc.value})
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
					t.Fatalf("ValidateWorkflowInputs() error = %v, want %q", err, tc.wantSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateWorkflowInputs() unexpected error = %v", err)
			}
		})
	}
}

func TestValidateWorkflowInputsMaxLengthCountsUnicodeCodePoints(t *testing.T) {
	maxTwo := 2
	spec := model.WorkflowManifestSpec{
		InputSchema: model.WorkflowInputSchemaSpec{
			Properties: map[string]model.IntegrationSchemaProperty{
				"label": {Type: "string", MaxLength: &maxTwo},
			},
		},
	}
	if err := ValidateWorkflowInputs(spec, map[string]any{"label": "éé"}); err != nil {
		t.Fatalf("two Unicode code points should fit maxLength=2: %v", err)
	}
	if err := ValidateWorkflowInputs(spec, map[string]any{"label": "ééé"}); err == nil || !strings.Contains(err.Error(), "maxLength 2") {
		t.Fatalf("three Unicode code points should exceed maxLength=2, got %v", err)
	}
}

func TestValidateWorkflowInputsEnforcesStringConstraintsOnDefaults(t *testing.T) {
	maxThree := 3
	for _, tc := range []struct {
		name       string
		value      string
		wantSubstr string
	}{
		{name: "maximum length", value: "toolong", wantSubstr: "maxLength 3"},
		{name: "pattern", value: "ABC", wantSubstr: "must match pattern"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := model.WorkflowManifestSpec{
				Defaults: map[string]any{"label": tc.value},
				InputSchema: model.WorkflowInputSchemaSpec{
					Properties: map[string]model.IntegrationSchemaProperty{
						"label": {Type: "string", Pattern: `^[a-z]+$`, MaxLength: &maxThree},
					},
				},
			}

			err := ValidateWorkflowInputs(spec, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("ValidateWorkflowInputs() error = %v, want merged default error %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestValidateWorkflowSpecRejectsInvalidStringConstraints(t *testing.T) {
	tests := []struct {
		name       string
		property   model.IntegrationSchemaProperty
		wantSubstr string
	}{
		{
			name:       "invalid pattern",
			property:   model.IntegrationSchemaProperty{Type: "string", Pattern: "["},
			wantSubstr: "invalid pattern",
		},
		{
			name: "negative maxLength",
			property: func() model.IntegrationSchemaProperty {
				value := -1
				return model.IntegrationSchemaProperty{Type: "string", MaxLength: &value}
			}(),
			wantSubstr: "maxLength cannot be negative",
		},
		{
			name: "minLength above maxLength",
			property: func() model.IntegrationSchemaProperty {
				minValue, maxValue := 3, 2
				return model.IntegrationSchemaProperty{Type: "string", MinLength: &minValue, MaxLength: &maxValue}
			}(),
			wantSubstr: "minLength cannot exceed maxLength",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := workflowSpecFixture()
			spec.InputSchema.Properties["ref"] = tc.property
			err := ValidateWorkflowSpec(spec)
			if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("ValidateWorkflowSpec() error = %v, want %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestValidateWorkflowInputsStringConstraintsIgnoredForNonStringTypes(t *testing.T) {
	// String-only constraints on object/array/integer types retain the existing
	// no-op behavior rather than changing integration schema compatibility.
	minOne := 1
	maxOne := 1
	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		InputSchema: model.WorkflowInputSchemaSpec{
			Properties: map[string]model.IntegrationSchemaProperty{
				"obj_field": {Type: "object", MinLength: &minOne, MaxLength: &maxOne, Pattern: "["},
				"arr_field": {Type: "array", MinLength: &minOne, MaxLength: &maxOne, Pattern: "["},
				"int_field": {Type: "integer", MinLength: &minOne, MaxLength: &maxOne, Pattern: "["},
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

func TestParseWorkflowSpecPreservesAdditionalPropertiesFalse(t *testing.T) {
	spec, err := ParseWorkflowSpec(json.RawMessage(`{
		"input_schema": {
			"additionalProperties": false,
			"properties": {"declared": {"type": "string"}}
		}
	}`))
	if err != nil {
		t.Fatalf("ParseWorkflowSpec error: %v", err)
	}
	if spec.InputSchema.AdditionalProperties == nil {
		t.Fatal("additionalProperties=false was discarded")
	}
	if *spec.InputSchema.AdditionalProperties {
		t.Fatal("additionalProperties = true, want false")
	}
}

func TestValidateWorkflowInputsRejectsUndeclaredWhenSchemaIsClosed(t *testing.T) {
	additionalProperties := false
	spec := model.WorkflowManifestSpec{
		InputSchema: model.WorkflowInputSchemaSpec{
			AdditionalProperties: &additionalProperties,
			Properties: map[string]model.IntegrationSchemaProperty{
				"declared": {Type: "string"},
			},
		},
	}

	err := ValidateWorkflowInputs(spec, map[string]any{
		"declared": "ok",
		"zeta":     "must-not-persist",
		"alpha":    "must-not-persist",
	})
	if err == nil {
		t.Fatal("expected undeclared inputs to fail")
	}
	if !strings.Contains(err.Error(), `["alpha" "zeta"]`) {
		t.Fatalf("error = %q, want stable sorted undeclared field names", err)
	}
}

func TestValidateWorkflowInputsKeepsLegacyOpenSchemaCompatibility(t *testing.T) {
	for _, additionalProperties := range []*bool{nil, func() *bool { value := true; return &value }()} {
		spec := model.WorkflowManifestSpec{
			InputSchema: model.WorkflowInputSchemaSpec{
				AdditionalProperties: additionalProperties,
				Properties: map[string]model.IntegrationSchemaProperty{
					"declared": {Type: "string"},
				},
			},
		}
		if err := ValidateWorkflowInputs(spec, map[string]any{"undeclared": "legacy-compatible"}); err != nil {
			t.Fatalf("additionalProperties=%v unexpectedly rejected open-schema input: %v", additionalProperties, err)
		}
	}
}

// TestValidateWorkflowSpecAcceptsDispatchMode_Sync_Async pins the contract
// of the new spec.dispatch_mode field added for the async-by-default
// workflow migration (spec 2026-05-25-yggdrasil-async-dispatch-spec). The
// validator must accept the canonical values, the empty default (legacy
// workflows without the field), and reject typos / mixed-case nonsense.
func TestValidateWorkflowSpecAcceptsDispatchMode_Sync_Async(t *testing.T) {
	cases := []struct {
		name string
		mode string
	}{
		{name: "empty (default)", mode: ""},
		{name: "sync", mode: "sync"},
		{name: "async", mode: "async"},
		{name: "mixed case async", mode: "ASYNC"},
		{name: "padded sync", mode: "  sync  "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := workflowSpecFixture()
			spec.DispatchMode = c.mode
			if err := ValidateWorkflowSpec(spec); err != nil {
				t.Fatalf("ValidateWorkflowSpec(dispatch_mode=%q) error: %v", c.mode, err)
			}
		})
	}
}

func TestValidateWorkflowSpecRejectsUnknownDispatchMode(t *testing.T) {
	spec := workflowSpecFixture()
	spec.DispatchMode = "fire-and-forget"
	if err := ValidateWorkflowSpec(spec); err == nil {
		t.Fatal("expected unknown dispatch_mode to fail validation")
	}
}

func TestValidateWorkflowSpecAuthorizationSelectors(t *testing.T) {
	spec := workflowSpecFixture()
	spec.Authorization = &model.WorkflowAuthorizationSpec{
		RBAC:   model.ManifestSelector{Namespace: "dakasa", Name: "dakasa-validation-rbac"},
		Policy: &model.ManifestSelector{Namespace: "dakasa", Name: "dakasa-validation-policy"},
	}
	if err := ValidateWorkflowSpec(spec); err != nil {
		t.Fatalf("valid workflow authorization: %v", err)
	}

	spec.Authorization.RBAC = model.ManifestSelector{}
	if err := ValidateWorkflowSpec(spec); err == nil {
		t.Fatal("authorization block without RBAC selector must fail")
	}
}

// TestNormalizeWorkflowDispatchMode_DefaultsToSync guards the helper used
// by the HTTP dispatcher to decide between the sync (201) and async (202)
// paths. Empty and whitespace must canonicalize to "sync" so legacy
// workflows (no dispatch_mode field on disk) keep their pre-migration
// behaviour.
func TestNormalizeWorkflowDispatchMode_DefaultsToSync(t *testing.T) {
	cases := []struct {
		name string
		mode string
		want string
	}{
		{name: "empty", mode: "", want: "sync"},
		{name: "whitespace", mode: "   ", want: "sync"},
		{name: "async", mode: "async", want: "async"},
		{name: "ASYNC", mode: "ASYNC", want: "async"},
		{name: "sync", mode: "sync", want: "sync"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := workflowSpecFixture()
			spec.DispatchMode = c.mode
			if got := NormalizeWorkflowDispatchMode(spec); got != c.want {
				t.Fatalf("NormalizeWorkflowDispatchMode(%q) = %q, want %q", c.mode, got, c.want)
			}
		})
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
