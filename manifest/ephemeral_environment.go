package manifest

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ParseEphemeralEnvironmentSpec parses the raw spec payload.
func ParseEphemeralEnvironmentSpec(raw json.RawMessage) (model.EphemeralEnvironmentManifestSpec, error) {
	var spec model.EphemeralEnvironmentManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.EphemeralEnvironmentManifestSpec{}, fmt.Errorf("parse ephemeral_environment spec: %w", err)
	}
	return spec, nil
}

// ValidateEphemeralEnvironmentSpec validates one ephemeral_environment manifest.
func ValidateEphemeralEnvironmentSpec(spec model.EphemeralEnvironmentManifestSpec) error {
	if err := validateEphemeralWorkflow("create_workflow", spec.CreateWorkflow); err != nil {
		return err
	}
	if spec.DestroyWorkflow != nil {
		if err := validateEphemeralWorkflow("destroy_workflow", *spec.DestroyWorkflow); err != nil {
			return err
		}
	}
	if spec.AutoDestroy && spec.DestroyWorkflow == nil {
		return fmt.Errorf("ephemeral_environment auto_destroy requires destroy_workflow")
	}
	if spec.TTLSeconds < 0 {
		return fmt.Errorf("ephemeral_environment ttl_seconds must be >= 0 (use 0 for no TTL)")
	}
	if spec.TTLSeconds > 0 && spec.TTLSeconds < 60 {
		return fmt.Errorf("ephemeral_environment ttl_seconds must be 0 or >= 60 (sub-minute TTLs cause reap thrash)")
	}
	if cp := spec.CostProjection; cp != nil {
		if cp.CPUHours < 0 || cp.MemoryGBHours < 0 || cp.StorageGBHours < 0 || cp.EstimatedCost < 0 {
			return fmt.Errorf("ephemeral_environment cost_projection values must be non-negative")
		}
	}
	return validateLooseObject("ephemeral_environment metadata", spec.Metadata)
}

func validateEphemeralWorkflow(field string, spec model.EphemeralEnvironmentWorkflowSpec) error {
	if strings.TrimSpace(spec.WorkflowRef.Name) == "" {
		return fmt.Errorf("ephemeral_environment %s.workflow_ref.name is required", field)
	}
	return nil
}

// NormalizeEphemeralEnvironmentSpec applies compatibility defaults.
func NormalizeEphemeralEnvironmentSpec(spec model.EphemeralEnvironmentManifestSpec) model.EphemeralEnvironmentManifestSpec {
	spec.CreateWorkflow.WorkflowRef.Namespace = strings.ToLower(strings.TrimSpace(spec.CreateWorkflow.WorkflowRef.Namespace))
	if spec.CreateWorkflow.WorkflowRef.Namespace == "" {
		spec.CreateWorkflow.WorkflowRef.Namespace = "global"
	}
	spec.CreateWorkflow.WorkflowRef.Name = strings.TrimSpace(spec.CreateWorkflow.WorkflowRef.Name)
	if spec.DestroyWorkflow != nil {
		spec.DestroyWorkflow.WorkflowRef.Namespace = strings.ToLower(strings.TrimSpace(spec.DestroyWorkflow.WorkflowRef.Namespace))
		if spec.DestroyWorkflow.WorkflowRef.Namespace == "" {
			spec.DestroyWorkflow.WorkflowRef.Namespace = "global"
		}
		spec.DestroyWorkflow.WorkflowRef.Name = strings.TrimSpace(spec.DestroyWorkflow.WorkflowRef.Name)
	}
	if spec.CostProjection != nil && spec.CostProjection.Currency == "" {
		spec.CostProjection.Currency = "USD"
	}
	if spec.Metadata == nil {
		spec.Metadata = map[string]any{}
	}
	return spec
}
