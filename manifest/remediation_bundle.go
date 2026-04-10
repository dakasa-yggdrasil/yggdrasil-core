package manifest

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var supportedRemediationBundleKinds = []string{
	model.RemediationBundleKindWorkflowPatch,
	model.RemediationBundleKindIntegrationComposition,
	model.RemediationBundleKindEphemeralExecutor,
}

var supportedRemediationBundleStatuses = []string{
	model.RemediationBundleStatusProposed,
	model.RemediationBundleStatusPendingApproval,
	model.RemediationBundleStatusApproved,
	model.RemediationBundleStatusRejected,
	model.RemediationBundleStatusExecuting,
	model.RemediationBundleStatusExecuted,
	model.RemediationBundleStatusExecutionFailed,
	model.RemediationBundleStatusExpired,
}

// ParseRemediationBundleSpec parses the raw spec payload into the typed manifest.
func ParseRemediationBundleSpec(raw json.RawMessage) (model.RemediationBundleManifestSpec, error) {
	var spec model.RemediationBundleManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.RemediationBundleManifestSpec{}, fmt.Errorf("parse remediation_bundle spec: %w", err)
	}
	return spec, nil
}

// ValidateRemediationBundleSpec validates one generated remediation bundle.
func ValidateRemediationBundleSpec(spec model.RemediationBundleManifestSpec) error {
	spec = NormalizeRemediationBundleSpec(spec)

	if !guardianPolicySelectorProvided(spec.GuardianRef) {
		return fmt.Errorf("remediation_bundle guardian_ref is required")
	}
	if !slices.Contains(supportedRemediationBundleStatuses, spec.Status) {
		return fmt.Errorf("remediation_bundle status %q is unsupported", spec.Status)
	}
	if !slices.Contains(supportedRemediationBundleKinds, spec.BundleKind) {
		return fmt.Errorf("remediation_bundle bundle_kind %q is unsupported", spec.BundleKind)
	}
	if strings.TrimSpace(spec.ComponentName) == "" {
		return fmt.Errorf("remediation_bundle component_name is required")
	}
	if strings.TrimSpace(spec.ExpiresAt) == "" {
		return fmt.Errorf("remediation_bundle expires_at is required")
	}
	expiresAt, err := time.Parse(time.RFC3339, spec.ExpiresAt)
	if err != nil {
		return fmt.Errorf("remediation_bundle expires_at must use RFC3339: %w", err)
	}
	if expiresAt.IsZero() {
		return fmt.Errorf("remediation_bundle expires_at must be set")
	}
	if len(spec.Steps) == 0 {
		return fmt.Errorf("remediation_bundle steps must contain at least one step")
	}
	if err := validateLooseObject("remediation_bundle trigger_action", spec.TriggerAction); err != nil {
		return err
	}
	if err := validateLooseObject("remediation_bundle incident", spec.Incident); err != nil {
		return err
	}
	if err := validateLooseObject("remediation_bundle metadata", spec.Metadata); err != nil {
		return err
	}
	for _, reason := range []*model.RemediationBundleReasonSpec{
		spec.CreationReason,
		spec.ApprovalDecision,
		spec.PromotionReview,
	} {
		if err := validateRemediationBundleReason(reason); err != nil {
			return err
		}
	}
	for _, value := range []string{
		spec.Execution.AttemptedAt,
		spec.Execution.CompletedAt,
	} {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			return fmt.Errorf("remediation_bundle execution timestamps must use RFC3339: %w", err)
		}
	}
	for _, step := range spec.Steps {
		if strings.TrimSpace(step.Name) == "" {
			return fmt.Errorf("remediation_bundle step name is required")
		}
		if !slices.Contains(supportedRemediationActionModes, step.Mode) {
			return fmt.Errorf("remediation_bundle step %q mode %q is unsupported", step.Name, step.Mode)
		}
		if rank := supportedGuardianSeverityRank(step.BlastRadius); step.BlastRadius != "" && rank == 0 {
			return fmt.Errorf("remediation_bundle step %q blast_radius %q is unsupported", step.Name, step.BlastRadius)
		}
		switch step.Mode {
		case model.RemediationContractActionModeWorkflowDispatch:
			if step.WorkflowDispatch == nil {
				return fmt.Errorf("remediation_bundle step %q workflow_dispatch is required", step.Name)
			}
			if repository := strings.TrimSpace(step.WorkflowDispatch.Repository); repository != "" && !repositorySlugPattern.MatchString(repository) {
				return fmt.Errorf("remediation_bundle step %q repository must use owner/name format", step.Name)
			}
			if ref := strings.TrimSpace(step.WorkflowDispatch.Ref); strings.Contains(ref, " ") {
				return fmt.Errorf("remediation_bundle step %q ref cannot contain spaces", step.Name)
			}
			workflow := strings.TrimSpace(step.WorkflowDispatch.Workflow)
			if workflow != "" && !strings.HasSuffix(workflow, ".yml") && !strings.HasSuffix(workflow, ".yaml") {
				return fmt.Errorf("remediation_bundle step %q workflow must be a workflow filename", step.Name)
			}
			if err := validateLooseObject("remediation_bundle workflow_dispatch inputs", step.WorkflowDispatch.Inputs); err != nil {
				return err
			}
		case model.RemediationContractActionModeIntegrationExecute:
			if step.IntegrationExecute == nil {
				return fmt.Errorf("remediation_bundle step %q integration_execute is required", step.Name)
			}
			if !guardianPolicySelectorProvided(step.IntegrationExecute.Integration) {
				return fmt.Errorf("remediation_bundle step %q integration selector is required", step.Name)
			}
			if strings.TrimSpace(step.IntegrationExecute.Operation) == "" {
				return fmt.Errorf("remediation_bundle step %q integration_execute operation is required", step.Name)
			}
			if err := validateLooseObject("remediation_bundle integration_execute input", step.IntegrationExecute.Input); err != nil {
				return err
			}
		}
		if err := validateLooseObject("remediation_bundle step metadata", step.Metadata); err != nil {
			return err
		}
	}

	return nil
}

// NormalizeRemediationBundleSpec applies compatibility defaults to generated remediation bundles.
func NormalizeRemediationBundleSpec(spec model.RemediationBundleManifestSpec) model.RemediationBundleManifestSpec {
	spec.Status = strings.ToLower(strings.TrimSpace(spec.Status))
	if spec.Status == "" {
		spec.Status = model.RemediationBundleStatusProposed
	}
	spec.Source = strings.ToLower(strings.TrimSpace(spec.Source))
	if spec.Source == "" {
		spec.Source = "llm_generated"
	}
	spec.BundleKind = strings.ToLower(strings.TrimSpace(spec.BundleKind))
	spec.Summary = strings.TrimSpace(spec.Summary)
	spec.ComponentKind = strings.ToLower(strings.TrimSpace(spec.ComponentKind))
	if spec.ComponentKind == "" {
		spec.ComponentKind = guardianMemoryFirstNonEmpty(guardianMemoryActionString(spec.TriggerAction, "component_kind"), guardianMemoryActionString(spec.TriggerAction, "kind"), "component")
	}
	spec.ComponentNamespace = strings.ToLower(strings.TrimSpace(spec.ComponentNamespace))
	if spec.ComponentNamespace == "" {
		spec.ComponentNamespace = guardianMemoryFirstNonEmpty(guardianMemoryActionString(spec.TriggerAction, "component_namespace"), guardianMemoryActionString(spec.TriggerAction, "namespace"), "global")
	}
	spec.ComponentName = normalizeIntegrationName(spec.ComponentName)
	if spec.ComponentName == "" {
		spec.ComponentName = guardianMemoryFirstNonEmpty(guardianMemoryActionString(spec.TriggerAction, "component_name"), guardianMemoryActionString(spec.TriggerAction, "name"), "unknown")
	}
	spec.ExpiresAt = strings.TrimSpace(spec.ExpiresAt)
	if spec.TriggerAction == nil {
		spec.TriggerAction = map[string]any{}
	}
	if spec.Incident == nil {
		spec.Incident = map[string]any{}
	}
	spec.CreationReason = normalizeRemediationBundleReason(spec.CreationReason)
	spec.ApprovalDecision = normalizeRemediationBundleReason(spec.ApprovalDecision)
	spec.PromotionReview = normalizeRemediationBundleReason(spec.PromotionReview)
	if spec.Metadata == nil {
		spec.Metadata = map[string]any{}
	}
	spec.Execution.AttemptedAt = strings.TrimSpace(spec.Execution.AttemptedAt)
	spec.Execution.CompletedAt = strings.TrimSpace(spec.Execution.CompletedAt)
	spec.Execution.Error = strings.TrimSpace(spec.Execution.Error)

	steps := make([]model.RemediationBundleStepSpec, 0, len(spec.Steps))
	for _, step := range spec.Steps {
		step.Name = strings.ToLower(strings.TrimSpace(step.Name))
		step.Mode = strings.ToLower(strings.TrimSpace(step.Mode))
		step.Description = strings.TrimSpace(step.Description)
		step.BlastRadius = strings.ToLower(strings.TrimSpace(step.BlastRadius))
		if step.Metadata == nil {
			step.Metadata = map[string]any{}
		}
		if step.WorkflowDispatch != nil {
			step.WorkflowDispatch.Repository = strings.TrimSpace(step.WorkflowDispatch.Repository)
			step.WorkflowDispatch.Workflow = strings.TrimSpace(step.WorkflowDispatch.Workflow)
			if step.WorkflowDispatch.Workflow == "" {
				step.WorkflowDispatch.Workflow = "deploy.yml"
			}
			step.WorkflowDispatch.Ref = strings.TrimSpace(step.WorkflowDispatch.Ref)
			if step.WorkflowDispatch.Ref == "" {
				step.WorkflowDispatch.Ref = "main"
			}
			if step.WorkflowDispatch.Inputs == nil {
				step.WorkflowDispatch.Inputs = map[string]any{}
			}
		}
		if step.IntegrationExecute != nil {
			if strings.TrimSpace(step.IntegrationExecute.Integration.Namespace) == "" {
				step.IntegrationExecute.Integration.Namespace = "global"
			}
			step.IntegrationExecute.Operation = strings.TrimSpace(step.IntegrationExecute.Operation)
			step.IntegrationExecute.Capability = strings.TrimSpace(step.IntegrationExecute.Capability)
			if step.IntegrationExecute.Capability == "" {
				step.IntegrationExecute.Capability = step.IntegrationExecute.Operation
			}
			if step.IntegrationExecute.Input == nil {
				step.IntegrationExecute.Input = map[string]any{}
			}
		}
		steps = append(steps, step)
	}
	spec.Steps = steps

	return spec
}

func validateRemediationBundleReason(reason *model.RemediationBundleReasonSpec) error {
	if reason == nil {
		return nil
	}
	if err := validateLooseObject("remediation_bundle reason metadata", reason.Metadata); err != nil {
		return err
	}
	if strings.TrimSpace(reason.RecordedAt) != "" {
		if _, err := time.Parse(time.RFC3339, reason.RecordedAt); err != nil {
			return fmt.Errorf("remediation_bundle reason recorded_at must use RFC3339: %w", err)
		}
	}
	return nil
}

func normalizeRemediationBundleReason(reason *model.RemediationBundleReasonSpec) *model.RemediationBundleReasonSpec {
	if reason == nil {
		return nil
	}
	normalized := *reason
	normalized.Kind = strings.ToLower(strings.TrimSpace(normalized.Kind))
	normalized.Status = strings.ToLower(strings.TrimSpace(normalized.Status))
	normalized.Summary = strings.TrimSpace(normalized.Summary)
	normalized.Comment = strings.TrimSpace(normalized.Comment)
	normalized.Source = strings.ToLower(strings.TrimSpace(normalized.Source))
	normalized.Actor = strings.TrimSpace(normalized.Actor)
	normalized.RecordedAt = strings.TrimSpace(normalized.RecordedAt)
	if normalized.Metadata == nil {
		normalized.Metadata = map[string]any{}
	}
	return &normalized
}
