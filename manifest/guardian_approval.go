package manifest

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var supportedGuardianApprovalStatuses = []string{
	model.GuardianApprovalStatusPending,
	model.GuardianApprovalStatusApproved,
	model.GuardianApprovalStatusRejected,
	model.GuardianApprovalStatusExecuted,
}

// ParseGuardianApprovalSpec parses the raw spec payload into the typed manifest.
func ParseGuardianApprovalSpec(raw json.RawMessage) (model.GuardianApprovalManifestSpec, error) {
	var spec model.GuardianApprovalManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.GuardianApprovalManifestSpec{}, fmt.Errorf("parse guardian_approval spec: %w", err)
	}
	return spec, nil
}

// ValidateGuardianApprovalSpec validates one guardian approval manifest.
func ValidateGuardianApprovalSpec(spec model.GuardianApprovalManifestSpec) error {
	spec = NormalizeGuardianApprovalSpec(spec)

	if !guardianPolicySelectorProvided(spec.GuardianRef) {
		return fmt.Errorf("guardian_approval guardian_ref is required")
	}
	if !slices.Contains(supportedGuardianApprovalStatuses, spec.Status) {
		return fmt.Errorf("guardian_approval status %q is unsupported", spec.Status)
	}
	if len(spec.Action) == 0 {
		return fmt.Errorf("guardian_approval action is required")
	}
	if err := validateLooseObject("guardian_approval action", spec.Action); err != nil {
		return err
	}
	if err := validateLooseObject("guardian_approval incident", spec.Incident); err != nil {
		return err
	}
	if err := validateLooseObject("guardian_approval metadata", spec.Metadata); err != nil {
		return err
	}

	return nil
}

// NormalizeGuardianApprovalSpec applies compatibility defaults to approval
// manifests emitted by Heimdall.
func NormalizeGuardianApprovalSpec(spec model.GuardianApprovalManifestSpec) model.GuardianApprovalManifestSpec {
	spec.Status = strings.ToLower(strings.TrimSpace(spec.Status))
	if spec.Status == "" {
		spec.Status = model.GuardianApprovalStatusPending
	}
	spec.Source = strings.ToLower(strings.TrimSpace(spec.Source))
	if spec.Source == "" {
		spec.Source = "critical_auto_remediation"
	}
	spec.Summary = strings.TrimSpace(spec.Summary)
	if spec.Action == nil {
		spec.Action = map[string]any{}
	}
	if spec.Incident == nil {
		spec.Incident = map[string]any{}
	}
	if spec.Metadata == nil {
		spec.Metadata = map[string]any{}
	}
	return spec
}
