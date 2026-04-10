package manifest

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var supportedGuardianMemoryStatuses = []string{
	model.GuardianMemoryStatusPendingApproval,
	model.GuardianMemoryStatusRejected,
	model.GuardianMemoryStatusExecuting,
	model.GuardianMemoryStatusExecuted,
	model.GuardianMemoryStatusExecutionFailed,
	model.GuardianMemoryStatusObservedRecovered,
	model.GuardianMemoryStatusObservedUnchanged,
	model.GuardianMemoryStatusObservedRegressed,
}

// ParseGuardianMemorySpec parses the raw spec payload into the typed manifest.
func ParseGuardianMemorySpec(raw json.RawMessage) (model.GuardianMemoryManifestSpec, error) {
	var spec model.GuardianMemoryManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.GuardianMemoryManifestSpec{}, fmt.Errorf("parse guardian_memory spec: %w", err)
	}
	return spec, nil
}

// ValidateGuardianMemorySpec validates one guardian memory manifest.
func ValidateGuardianMemorySpec(spec model.GuardianMemoryManifestSpec) error {
	spec = NormalizeGuardianMemorySpec(spec)

	if !guardianPolicySelectorProvided(spec.GuardianRef) {
		return fmt.Errorf("guardian_memory guardian_ref is required")
	}
	if !slices.Contains(supportedGuardianMemoryStatuses, spec.Status) {
		return fmt.Errorf("guardian_memory status %q is unsupported", spec.Status)
	}
	if strings.TrimSpace(spec.ComponentName) == "" {
		return fmt.Errorf("guardian_memory component_name is required")
	}
	if len(spec.Action) == 0 {
		return fmt.Errorf("guardian_memory action is required")
	}
	if err := validateLooseObject("guardian_memory action", spec.Action); err != nil {
		return err
	}
	if err := validateLooseObject("guardian_memory incident", spec.Incident); err != nil {
		return err
	}
	if err := validateLooseObject("guardian_memory evidence", spec.Evidence); err != nil {
		return err
	}
	if err := validateLooseObject("guardian_memory metadata", spec.Metadata); err != nil {
		return err
	}
	for _, value := range []string{
		spec.Execution.AttemptedAt,
		spec.Execution.CompletedAt,
		spec.Observation.ObservedAt,
		spec.Observation.LastObservedAt,
	} {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			return fmt.Errorf("guardian_memory timestamps must use RFC3339: %w", err)
		}
	}
	if spec.Observation.IncidentCount < 0 {
		return fmt.Errorf("guardian_memory observation incident_count cannot be negative")
	}
	if spec.Observation.ObservationCount < 0 {
		return fmt.Errorf("guardian_memory observation observation_count cannot be negative")
	}
	if spec.Observation.TimeToRecoverySeconds < 0 {
		return fmt.Errorf("guardian_memory observation time_to_recovery_seconds cannot be negative")
	}
	if spec.Observation.StableWindowSeconds < 0 {
		return fmt.Errorf("guardian_memory observation stable_window_seconds cannot be negative")
	}
	return nil
}

// NormalizeGuardianMemorySpec applies compatibility defaults to guardian memory
// manifests emitted by Heimdall.
func NormalizeGuardianMemorySpec(spec model.GuardianMemoryManifestSpec) model.GuardianMemoryManifestSpec {
	spec.Status = strings.ToLower(strings.TrimSpace(spec.Status))
	if spec.Status == "" {
		spec.Status = model.GuardianMemoryStatusExecuting
	}
	spec.Source = strings.ToLower(strings.TrimSpace(spec.Source))
	if spec.Source == "" {
		spec.Source = "critical_auto_remediation"
	}
	spec.ComponentKind = strings.ToLower(strings.TrimSpace(spec.ComponentKind))
	if spec.ComponentKind == "" {
		spec.ComponentKind = guardianMemoryFirstNonEmpty(guardianMemoryActionString(spec.Action, "component_kind"), guardianMemoryActionString(spec.Action, "kind"), "component")
	}
	spec.ComponentNamespace = strings.TrimSpace(spec.ComponentNamespace)
	if spec.ComponentNamespace == "" {
		spec.ComponentNamespace = guardianMemoryFirstNonEmpty(guardianMemoryActionString(spec.Action, "component_namespace"), guardianMemoryActionString(spec.Action, "namespace"), "global")
	}
	spec.ComponentName = strings.TrimSpace(spec.ComponentName)
	if spec.ComponentName == "" {
		spec.ComponentName = guardianMemoryFirstNonEmpty(guardianMemoryActionString(spec.Action, "component_name"), guardianMemoryActionString(spec.Action, "name"), "unknown")
	}
	if spec.Action == nil {
		spec.Action = map[string]any{}
	}
	if spec.Incident == nil {
		spec.Incident = map[string]any{}
	}
	if spec.Evidence == nil {
		spec.Evidence = map[string]any{}
	}
	if spec.Metadata == nil {
		spec.Metadata = map[string]any{}
	}
	spec.Execution.AttemptedAt = strings.TrimSpace(spec.Execution.AttemptedAt)
	spec.Execution.CompletedAt = strings.TrimSpace(spec.Execution.CompletedAt)
	spec.Execution.Error = strings.TrimSpace(spec.Execution.Error)
	spec.Observation.ObservedAt = strings.TrimSpace(spec.Observation.ObservedAt)
	spec.Observation.LastObservedAt = strings.TrimSpace(spec.Observation.LastObservedAt)
	spec.Observation.Summary = strings.TrimSpace(spec.Observation.Summary)
	spec.Observation.ComponentHealth = strings.ToLower(strings.TrimSpace(spec.Observation.ComponentHealth))
	if spec.Observation.ObservationCount == 0 && spec.Observation.ObservedAt != "" {
		spec.Observation.ObservationCount = 1
	}
	return spec
}

func guardianMemoryActionString(action map[string]any, key string) string {
	if action == nil {
		return ""
	}
	value, ok := action[key]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func guardianMemoryFirstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
