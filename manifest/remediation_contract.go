package manifest

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var supportedRemediationActionModes = []string{
	model.RemediationContractActionModeWorkflowDispatch,
	model.RemediationContractActionModeIntegrationExecute,
}

// ParseRemediationContractSpec parses the raw spec payload into the typed manifest.
func ParseRemediationContractSpec(raw json.RawMessage) (model.RemediationContractManifestSpec, error) {
	var spec model.RemediationContractManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.RemediationContractManifestSpec{}, fmt.Errorf("parse remediation_contract spec: %w", err)
	}
	return spec, nil
}

// ValidateRemediationContractSpec validates one remediation contract manifest.
func ValidateRemediationContractSpec(spec model.RemediationContractManifestSpec) error {
	spec = NormalizeRemediationContractSpec(spec)

	if !slices.Contains(supportedRepositoryBindingComponentKinds, spec.ComponentKind) {
		return fmt.Errorf("remediation_contract component_kind %q is unsupported", spec.ComponentKind)
	}
	if spec.ComponentName == "" {
		return fmt.Errorf("remediation_contract component_name is required")
	}
	if len(spec.Actions) == 0 {
		return fmt.Errorf("remediation_contract actions must contain at least one action")
	}
	if err := validateLooseObject("remediation_contract metadata", spec.Metadata); err != nil {
		return err
	}

	for _, action := range spec.Actions {
		if action.Name == "" {
			return fmt.Errorf("remediation_contract action name is required")
		}
		if !slices.Contains(supportedRemediationActionModes, action.Mode) {
			return fmt.Errorf("remediation_contract action %q mode %q is unsupported", action.Name, action.Mode)
		}
		switch action.Mode {
		case model.RemediationContractActionModeWorkflowDispatch:
			if action.WorkflowDispatch == nil {
				return fmt.Errorf("remediation_contract action %q workflow_dispatch is required", action.Name)
			}
			if repository := strings.TrimSpace(action.WorkflowDispatch.Repository); repository != "" && !repositorySlugPattern.MatchString(repository) {
				return fmt.Errorf("remediation_contract action %q repository must use owner/name format", action.Name)
			}
			if ref := strings.TrimSpace(action.WorkflowDispatch.Ref); strings.Contains(ref, " ") {
				return fmt.Errorf("remediation_contract action %q ref cannot contain spaces", action.Name)
			}
			workflow := strings.TrimSpace(action.WorkflowDispatch.Workflow)
			if workflow != "" && !strings.HasSuffix(workflow, ".yml") && !strings.HasSuffix(workflow, ".yaml") {
				return fmt.Errorf("remediation_contract action %q workflow must be a workflow filename", action.Name)
			}
			if err := validateLooseObject("remediation_contract workflow_dispatch inputs", action.WorkflowDispatch.Inputs); err != nil {
				return err
			}
		case model.RemediationContractActionModeIntegrationExecute:
			if action.IntegrationExecute == nil {
				return fmt.Errorf("remediation_contract action %q integration_execute is required", action.Name)
			}
			if !guardianPolicySelectorProvided(action.IntegrationExecute.Integration) {
				return fmt.Errorf("remediation_contract action %q integration_execute integration is required", action.Name)
			}
			if strings.TrimSpace(action.IntegrationExecute.Operation) == "" {
				return fmt.Errorf("remediation_contract action %q integration_execute operation is required", action.Name)
			}
			if err := validateLooseObject("remediation_contract integration_execute input", action.IntegrationExecute.Input); err != nil {
				return err
			}
		}
	}

	return nil
}

// NormalizeRemediationContractSpec applies compatibility defaults to remediation contracts.
func NormalizeRemediationContractSpec(spec model.RemediationContractManifestSpec) model.RemediationContractManifestSpec {
	spec.ComponentKind = strings.ToLower(strings.TrimSpace(spec.ComponentKind))
	spec.ComponentName = normalizeIntegrationName(spec.ComponentName)
	spec.ComponentNamespace = strings.ToLower(strings.TrimSpace(spec.ComponentNamespace))
	if spec.ComponentNamespace == "" {
		spec.ComponentNamespace = "global"
	}
	if spec.Metadata == nil {
		spec.Metadata = map[string]any{}
	}

	actions := make([]model.RemediationContractActionSpec, 0, len(spec.Actions))
	for _, action := range spec.Actions {
		action.Name = strings.ToLower(strings.TrimSpace(action.Name))
		action.Mode = strings.ToLower(strings.TrimSpace(action.Mode))
		if action.Mode == "" {
			action.Mode = model.RemediationContractActionModeWorkflowDispatch
		}
		if action.WorkflowDispatch != nil {
			action.WorkflowDispatch.Repository = strings.TrimSpace(action.WorkflowDispatch.Repository)
			action.WorkflowDispatch.Workflow = strings.TrimSpace(action.WorkflowDispatch.Workflow)
			if action.WorkflowDispatch.Workflow == "" {
				action.WorkflowDispatch.Workflow = "deploy.yml"
			}
			action.WorkflowDispatch.Ref = strings.TrimSpace(action.WorkflowDispatch.Ref)
			if action.WorkflowDispatch.Ref == "" {
				action.WorkflowDispatch.Ref = "main"
			}
			if action.WorkflowDispatch.Inputs == nil {
				action.WorkflowDispatch.Inputs = map[string]any{}
			}
		}
		if action.IntegrationExecute != nil {
			if strings.TrimSpace(action.IntegrationExecute.Integration.Namespace) == "" {
				action.IntegrationExecute.Integration.Namespace = "global"
			}
			action.IntegrationExecute.Operation = strings.TrimSpace(action.IntegrationExecute.Operation)
			action.IntegrationExecute.Capability = strings.TrimSpace(action.IntegrationExecute.Capability)
			if action.IntegrationExecute.Capability == "" {
				action.IntegrationExecute.Capability = action.IntegrationExecute.Operation
			}
			if action.IntegrationExecute.Input == nil {
				action.IntegrationExecute.Input = map[string]any{}
			}
		}
		actions = append(actions, action)
	}
	spec.Actions = actions

	return spec
}
