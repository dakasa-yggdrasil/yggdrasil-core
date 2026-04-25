package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func workflowTemplateFixture() model.WorkflowTemplateManifestSpec {
	body := json.RawMessage(`{
		"trigger": {"mode": "manual"},
		"input_schema": {"required": ["service"]},
		"steps": [{
			"id": "smoke",
			"use": {"kind": "integration", "instance_ref": {"namespace": "{{ params.namespace }}", "name": "{{ params.k8s_instance }}"}, "capability": "observe_objects"},
			"with": {"objects": [{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "{{ inputs.service }}"}}]}
		}]
	}`)
	return model.WorkflowTemplateManifestSpec{
		DisplayName: "Smoke test a deployed service",
		Description: "Verifies a service Pod exists in the cluster",
		Category:    "operations",
		Tags:        []string{"smoke", "kubernetes"},
		Authors:     []string{"team:platform"},
		Params: map[string]model.WorkflowTemplateParam{
			"namespace":    {Type: "string", Required: true, Description: "Yggdrasil namespace of the kubernetes integration_instance"},
			"k8s_instance": {Type: "string", Required: true},
		},
		Body:    body,
		Version: "v1.0.0",
	}
}

func TestValidateWorkflowTemplateSpec(t *testing.T) {
	if err := ValidateWorkflowTemplateSpec(workflowTemplateFixture()); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateWorkflowTemplateSpecRequiresDisplayName(t *testing.T) {
	spec := workflowTemplateFixture()
	spec.DisplayName = ""
	if err := ValidateWorkflowTemplateSpec(spec); err == nil {
		t.Fatal("expected error for missing display_name")
	}
}

func TestValidateWorkflowTemplateSpecRequiresBody(t *testing.T) {
	spec := workflowTemplateFixture()
	spec.Body = nil
	if err := ValidateWorkflowTemplateSpec(spec); err == nil {
		t.Fatal("expected error for missing body")
	}
}

func TestValidateWorkflowTemplateSpecRejectsUnknownParamType(t *testing.T) {
	spec := workflowTemplateFixture()
	spec.Params["bad"] = model.WorkflowTemplateParam{Type: "garbage"}
	if err := ValidateWorkflowTemplateSpec(spec); err == nil {
		t.Fatal("expected error for unknown param type")
	}
}

func TestValidateWorkflowTemplateSpecRejectsRequiredWithDefault(t *testing.T) {
	spec := workflowTemplateFixture()
	spec.Params["with_default"] = model.WorkflowTemplateParam{Type: "string", Required: true, Default: "x"}
	if err := ValidateWorkflowTemplateSpec(spec); err == nil {
		t.Fatal("expected error: required AND default is contradictory")
	}
}

func TestNormalizeWorkflowTemplateSpec(t *testing.T) {
	spec := model.WorkflowTemplateManifestSpec{DisplayName: " A ", Tags: []string{" t1 "}, Body: json.RawMessage(`{}`)}
	out := NormalizeWorkflowTemplateSpec(spec)
	if out.DisplayName != "A" {
		t.Fatalf("display_name normalisation: got %q", out.DisplayName)
	}
	if out.Tags[0] != "t1" {
		t.Fatalf("tag normalisation: got %q", out.Tags[0])
	}
	if out.Version != "v0.1.0" {
		t.Fatalf("version default: got %q", out.Version)
	}
}

func TestWorkflowTemplateDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(workflowTemplateFixture())
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "workflow_template",
		Metadata:   model.ManifestMetadataInput{Name: "smoke-pod", Namespace: "global"},
		Spec:       raw,
	}
	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(workflow_template): %v", err)
	}
}
