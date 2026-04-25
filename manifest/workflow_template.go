package manifest

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// supportedTemplateParamTypes mirrors the workflow input_schema types we
// already support. Keep in sync with workflow validation.
var supportedTemplateParamTypes = map[string]struct{}{
	"string":  {},
	"integer": {},
	"number":  {},
	"boolean": {},
	"array":   {},
	"object":  {},
}

// ParseWorkflowTemplateSpec parses the raw spec payload.
func ParseWorkflowTemplateSpec(raw json.RawMessage) (model.WorkflowTemplateManifestSpec, error) {
	var spec model.WorkflowTemplateManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.WorkflowTemplateManifestSpec{}, fmt.Errorf("parse workflow_template spec: %w", err)
	}
	return spec, nil
}

// ValidateWorkflowTemplateSpec validates one workflow_template manifest.
func ValidateWorkflowTemplateSpec(spec model.WorkflowTemplateManifestSpec) error {
	if strings.TrimSpace(spec.DisplayName) == "" {
		return fmt.Errorf("workflow_template display_name is required")
	}
	if len(spec.Body) == 0 || string(spec.Body) == "null" {
		return fmt.Errorf("workflow_template body is required (workflow shape with {{ params.* }} placeholders)")
	}
	for name, p := range spec.Params {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("workflow_template params has an empty key")
		}
		if _, ok := supportedTemplateParamTypes[p.Type]; !ok {
			return fmt.Errorf("workflow_template params.%s.type %q is unsupported (expected one of: string, integer, number, boolean, array, object)", name, p.Type)
		}
		if p.Required && p.Default != nil {
			return fmt.Errorf("workflow_template params.%s cannot be required AND have a default", name)
		}
	}
	return nil
}

// NormalizeWorkflowTemplateSpec applies compatibility defaults.
func NormalizeWorkflowTemplateSpec(spec model.WorkflowTemplateManifestSpec) model.WorkflowTemplateManifestSpec {
	spec.DisplayName = strings.TrimSpace(spec.DisplayName)
	spec.Description = strings.TrimSpace(spec.Description)
	spec.Category = strings.TrimSpace(spec.Category)
	for i, t := range spec.Tags {
		spec.Tags[i] = strings.TrimSpace(t)
	}
	for i, a := range spec.Authors {
		spec.Authors[i] = strings.TrimSpace(a)
	}
	if spec.Version == "" {
		spec.Version = "v0.1.0"
	}
	return spec
}
