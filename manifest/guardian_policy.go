package manifest

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var supportedGuardianSeverityThresholds = []string{"low", "medium", "high", "critical"}
var supportedGuardianAutonomyModes = []string{"policy_bound", "approval_required", "bypass_hotfix"}
var supportedGuardianWeekdays = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

// ParseGuardianPolicySpec parses the raw spec payload into the typed manifest.
func ParseGuardianPolicySpec(raw json.RawMessage) (model.GuardianPolicyManifestSpec, error) {
	var spec model.GuardianPolicyManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.GuardianPolicyManifestSpec{}, fmt.Errorf("parse guardian_policy spec: %w", err)
	}
	return spec, nil
}

// ValidateGuardianPolicySpec validates one guardian policy manifest.
func ValidateGuardianPolicySpec(spec model.GuardianPolicyManifestSpec) error {
	if !guardianPolicySelectorProvided(spec.GuardianRef) {
		return fmt.Errorf("guardian_policy guardian_ref is required")
	}

	spec = NormalizeGuardianPolicySpec(spec)
	if !slices.Contains(supportedGuardianSeverityThresholds, spec.AutoHeal.SeverityThreshold) {
		return fmt.Errorf("guardian_policy auto_heal severity_threshold %q is unsupported", spec.AutoHeal.SeverityThreshold)
	}
	if !slices.Contains(supportedGuardianAutonomyModes, spec.Autonomy.Mode) {
		return fmt.Errorf("guardian_policy autonomy mode %q is unsupported", spec.Autonomy.Mode)
	}
	if spec.MaintenanceMode.Enabled && len(spec.MaintenanceMode.Environments) == 0 {
		return fmt.Errorf("guardian_policy maintenance_mode environments must not be empty when enabled")
	}
	if !slices.Contains(supportedGuardianSeverityThresholds, spec.Autonomy.HotfixSeverityThreshold) {
		return fmt.Errorf("guardian_policy autonomy hotfix_severity_threshold %q is unsupported", spec.Autonomy.HotfixSeverityThreshold)
	}
	if !slices.Contains(supportedGuardianSeverityThresholds, spec.Autonomy.MaxAutoExecuteBlastRadius) {
		return fmt.Errorf("guardian_policy autonomy max_auto_execute_blast_radius %q is unsupported", spec.Autonomy.MaxAutoExecuteBlastRadius)
	}
	if !slices.Contains(supportedGuardianSeverityThresholds, spec.Autonomy.MaxBypassHotfixBlastRadius) {
		return fmt.Errorf("guardian_policy autonomy max_bypass_hotfix_blast_radius %q is unsupported", spec.Autonomy.MaxBypassHotfixBlastRadius)
	}
	if supportedGuardianSeverityRank(spec.Autonomy.MaxAutoExecuteBlastRadius) > supportedGuardianSeverityRank(spec.Autonomy.MaxBypassHotfixBlastRadius) {
		return fmt.Errorf("guardian_policy autonomy max_auto_execute_blast_radius must be <= max_bypass_hotfix_blast_radius")
	}
	if spec.Autonomy.AutoExecuteMinConfidence < 0 || spec.Autonomy.AutoExecuteMinConfidence > 1 {
		return fmt.Errorf("guardian_policy autonomy auto_execute_min_confidence must be between 0 and 1")
	}
	if spec.Autonomy.ManualReviewBelowConfidence < 0 || spec.Autonomy.ManualReviewBelowConfidence > 1 {
		return fmt.Errorf("guardian_policy autonomy manual_review_below_confidence must be between 0 and 1")
	}
	if spec.Autonomy.ManualReviewBelowConfidence > spec.Autonomy.AutoExecuteMinConfidence {
		return fmt.Errorf("guardian_policy autonomy manual_review_below_confidence must be <= auto_execute_min_confidence")
	}
	if spec.GeneratedBundles.MaxTTLSeconds < 0 {
		return fmt.Errorf("guardian_policy generated_bundles max_ttl_seconds must be >= 0")
	}
	if spec.GeneratedBundles.Enabled &&
		!spec.GeneratedBundles.AllowWorkflowPatch &&
		!spec.GeneratedBundles.AllowIntegrationComposition &&
		!spec.GeneratedBundles.AllowEphemeralExecutor {
		return fmt.Errorf("guardian_policy generated_bundles must allow at least one bundle kind when enabled")
	}
	if supportedGuardianSeverityRank(spec.Autonomy.ProtectedEnvironments.MaxAutoExecuteBlastRadius) == 0 {
		return fmt.Errorf("guardian_policy autonomy protected_environments.max_auto_execute_blast_radius %q is unsupported", spec.Autonomy.ProtectedEnvironments.MaxAutoExecuteBlastRadius)
	}
	if supportedGuardianSeverityRank(spec.Autonomy.ProtectedEnvironments.MaxBypassHotfixBlastRadius) == 0 {
		return fmt.Errorf("guardian_policy autonomy protected_environments.max_bypass_hotfix_blast_radius %q is unsupported", spec.Autonomy.ProtectedEnvironments.MaxBypassHotfixBlastRadius)
	}
	if supportedGuardianSeverityRank(spec.Autonomy.ProtectedEnvironments.MaxAutoExecuteBlastRadius) > supportedGuardianSeverityRank(spec.Autonomy.ProtectedEnvironments.MaxBypassHotfixBlastRadius) {
		return fmt.Errorf("guardian_policy autonomy protected_environments.max_auto_execute_blast_radius must be <= protected_environments.max_bypass_hotfix_blast_radius")
	}
	if spec.Autonomy.BusinessHours.Enabled {
		if _, err := time.LoadLocation(spec.Autonomy.BusinessHours.Timezone); err != nil {
			return fmt.Errorf("guardian_policy autonomy business_hours timezone %q is invalid", spec.Autonomy.BusinessHours.Timezone)
		}
		for _, weekday := range spec.Autonomy.BusinessHours.Weekdays {
			if !slices.Contains(supportedGuardianWeekdays, weekday) {
				return fmt.Errorf("guardian_policy autonomy business_hours weekday %q is unsupported", weekday)
			}
		}
		if spec.Autonomy.BusinessHours.StartHour < 0 || spec.Autonomy.BusinessHours.StartHour > 23 {
			return fmt.Errorf("guardian_policy autonomy business_hours start_hour must be between 0 and 23")
		}
		if spec.Autonomy.BusinessHours.EndHour < 0 || spec.Autonomy.BusinessHours.EndHour > 23 {
			return fmt.Errorf("guardian_policy autonomy business_hours end_hour must be between 0 and 23")
		}
	}
	for _, window := range spec.Autonomy.FreezeWindows {
		if strings.TrimSpace(window.Name) == "" {
			return fmt.Errorf("guardian_policy autonomy freeze_windows entries require a name")
		}
		start, err := time.Parse(time.RFC3339, window.StartsAt)
		if err != nil {
			return fmt.Errorf("guardian_policy autonomy freeze_windows %q has invalid starts_at", window.Name)
		}
		end, err := time.Parse(time.RFC3339, window.EndsAt)
		if err != nil {
			return fmt.Errorf("guardian_policy autonomy freeze_windows %q has invalid ends_at", window.Name)
		}
		if !end.After(start) {
			return fmt.Errorf("guardian_policy autonomy freeze_windows %q requires ends_at after starts_at", window.Name)
		}
	}
	if spec.Escalation.Enabled {
		if !slices.Contains(supportedGuardianSeverityThresholds, spec.Escalation.SeverityThreshold) {
			return fmt.Errorf("guardian_policy escalation severity_threshold %q is unsupported", spec.Escalation.SeverityThreshold)
		}
		if !slices.Contains(supportedGuardianSeverityThresholds, spec.Escalation.PostmortemSeverityThreshold) {
			return fmt.Errorf("guardian_policy escalation postmortem_severity_threshold %q is unsupported", spec.Escalation.PostmortemSeverityThreshold)
		}
		if spec.Escalation.MaxAutoHealAttempts < 1 {
			return fmt.Errorf("guardian_policy escalation max_auto_heal_attempts must be >= 1")
		}
		if !spec.Escalation.CreateApproval && !spec.Escalation.DispatchWorkflow {
			return fmt.Errorf("guardian_policy escalation must enable create_approval or dispatch_workflow")
		}
		if spec.Escalation.DispatchWorkflow &&
			strings.TrimSpace(spec.Escalation.IssueWorkflow) == "" &&
			strings.TrimSpace(spec.Escalation.PostmortemWorkflow) == "" {
			return fmt.Errorf("guardian_policy escalation dispatch_workflow requires issue_workflow or postmortem_workflow")
		}
	}
	if spec.AutoHeal.MaxActionsPerSweep < 0 {
		return fmt.Errorf("guardian_policy auto_heal max_actions_per_sweep must be >= 0")
	}
	if spec.AutoHeal.CooldownSeconds < 0 {
		return fmt.Errorf("guardian_policy auto_heal cooldown_seconds must be >= 0")
	}
	if spec.CostOptimization.MinEstimatedMonthlySavingsUSD < 0 {
		return fmt.Errorf("guardian_policy cost_optimization min_estimated_monthly_savings_usd must be >= 0")
	}
	return nil
}

// NormalizeGuardianPolicySpec applies compatibility defaults to guardian policy specs.
func NormalizeGuardianPolicySpec(spec model.GuardianPolicyManifestSpec) model.GuardianPolicyManifestSpec {
	spec.Scope = strings.TrimSpace(spec.Scope)
	if spec.Scope == "" {
		spec.Scope = "global"
	}

	spec.AutoHeal.SeverityThreshold = strings.ToLower(strings.TrimSpace(spec.AutoHeal.SeverityThreshold))
	if spec.AutoHeal.SeverityThreshold == "" {
		spec.AutoHeal.SeverityThreshold = "critical"
	}
	if spec.AutoHeal.MaxActionsPerSweep <= 0 {
		spec.AutoHeal.MaxActionsPerSweep = 1
	}
	if spec.AutoHeal.CooldownSeconds < 0 {
		spec.AutoHeal.CooldownSeconds = 0
	}
	if spec.AutoHeal.CooldownSeconds == 0 {
		spec.AutoHeal.CooldownSeconds = 300
	}

	spec.Autonomy.Mode = strings.ToLower(strings.TrimSpace(spec.Autonomy.Mode))
	if spec.Autonomy.Mode == "" {
		spec.Autonomy.Mode = "policy_bound"
	}
	spec.Autonomy.HotfixSeverityThreshold = strings.ToLower(strings.TrimSpace(spec.Autonomy.HotfixSeverityThreshold))
	if spec.Autonomy.HotfixSeverityThreshold == "" {
		spec.Autonomy.HotfixSeverityThreshold = "critical"
	}
	spec.Autonomy.MaxAutoExecuteBlastRadius = strings.ToLower(strings.TrimSpace(spec.Autonomy.MaxAutoExecuteBlastRadius))
	if spec.Autonomy.MaxAutoExecuteBlastRadius == "" {
		spec.Autonomy.MaxAutoExecuteBlastRadius = "medium"
	}
	spec.Autonomy.MaxBypassHotfixBlastRadius = strings.ToLower(strings.TrimSpace(spec.Autonomy.MaxBypassHotfixBlastRadius))
	if spec.Autonomy.MaxBypassHotfixBlastRadius == "" {
		spec.Autonomy.MaxBypassHotfixBlastRadius = "high"
	}
	if spec.Autonomy.AutoExecuteMinConfidence <= 0 {
		spec.Autonomy.AutoExecuteMinConfidence = 0.7
	}
	if spec.Autonomy.ManualReviewBelowConfidence < 0 {
		spec.Autonomy.ManualReviewBelowConfidence = 0
	}
	if spec.Autonomy.ManualReviewBelowConfidence == 0 {
		spec.Autonomy.ManualReviewBelowConfidence = 0.25
	}
	if spec.Autonomy.ManualReviewBelowConfidence > spec.Autonomy.AutoExecuteMinConfidence {
		spec.Autonomy.ManualReviewBelowConfidence = spec.Autonomy.AutoExecuteMinConfidence
	}
	if spec.GeneratedBundles.MaxTTLSeconds < 0 {
		spec.GeneratedBundles.MaxTTLSeconds = 0
	}
	if spec.GeneratedBundles.MaxTTLSeconds == 0 {
		spec.GeneratedBundles.MaxTTLSeconds = 7200
	}
	if spec.GeneratedBundles.Enabled &&
		!spec.GeneratedBundles.AllowWorkflowPatch &&
		!spec.GeneratedBundles.AllowIntegrationComposition &&
		!spec.GeneratedBundles.AllowEphemeralExecutor {
		spec.GeneratedBundles.AllowIntegrationComposition = true
	}
	spec.Autonomy.ProtectedEnvironments.Environments = normalizeGuardianEnvironmentList(spec.Autonomy.ProtectedEnvironments.Environments)
	if len(spec.Autonomy.ProtectedEnvironments.Environments) == 0 {
		spec.Autonomy.ProtectedEnvironments.Environments = []string{"prod", "production"}
	}
	spec.Autonomy.ProtectedEnvironments.MaxAutoExecuteBlastRadius = strings.ToLower(strings.TrimSpace(spec.Autonomy.ProtectedEnvironments.MaxAutoExecuteBlastRadius))
	if spec.Autonomy.ProtectedEnvironments.MaxAutoExecuteBlastRadius == "" {
		spec.Autonomy.ProtectedEnvironments.MaxAutoExecuteBlastRadius = "low"
	}
	spec.Autonomy.ProtectedEnvironments.MaxBypassHotfixBlastRadius = strings.ToLower(strings.TrimSpace(spec.Autonomy.ProtectedEnvironments.MaxBypassHotfixBlastRadius))
	if spec.Autonomy.ProtectedEnvironments.MaxBypassHotfixBlastRadius == "" {
		spec.Autonomy.ProtectedEnvironments.MaxBypassHotfixBlastRadius = "medium"
	}

	spec.Autonomy.BusinessHours.Timezone = strings.TrimSpace(spec.Autonomy.BusinessHours.Timezone)
	if spec.Autonomy.BusinessHours.Timezone == "" {
		spec.Autonomy.BusinessHours.Timezone = "UTC"
	}
	spec.Autonomy.BusinessHours.Weekdays = normalizeGuardianWeekdays(spec.Autonomy.BusinessHours.Weekdays)
	if len(spec.Autonomy.BusinessHours.Weekdays) == 0 {
		spec.Autonomy.BusinessHours.Weekdays = []string{"mon", "tue", "wed", "thu", "fri"}
	}
	if spec.Autonomy.BusinessHours.StartHour < 0 || spec.Autonomy.BusinessHours.StartHour > 23 {
		spec.Autonomy.BusinessHours.StartHour = 9
	}
	if spec.Autonomy.BusinessHours.EndHour < 0 || spec.Autonomy.BusinessHours.EndHour > 23 {
		spec.Autonomy.BusinessHours.EndHour = 18
	}
	spec.Autonomy.BusinessHours.Environments = normalizeGuardianEnvironmentList(spec.Autonomy.BusinessHours.Environments)

	normalizedFreeze := make([]model.GuardianFreezeWindowPolicySpec, 0, len(spec.Autonomy.FreezeWindows))
	for _, window := range spec.Autonomy.FreezeWindows {
		window.Name = strings.TrimSpace(window.Name)
		window.StartsAt = strings.TrimSpace(window.StartsAt)
		window.EndsAt = strings.TrimSpace(window.EndsAt)
		window.Environments = normalizeGuardianEnvironmentList(window.Environments)
		if window.Name == "" || window.StartsAt == "" || window.EndsAt == "" {
			continue
		}
		normalizedFreeze = append(normalizedFreeze, window)
	}
	spec.Autonomy.FreezeWindows = normalizedFreeze

	spec.MaintenanceMode.Environments = normalizeGuardianEnvironmentList(spec.MaintenanceMode.Environments)
	spec.MaintenanceMode.Reason = strings.TrimSpace(spec.MaintenanceMode.Reason)

	if spec.CostOptimization.MinEstimatedMonthlySavingsUSD < 0 {
		spec.CostOptimization.MinEstimatedMonthlySavingsUSD = 0
	}

	spec.Escalation.SeverityThreshold = strings.ToLower(strings.TrimSpace(spec.Escalation.SeverityThreshold))
	if spec.Escalation.SeverityThreshold == "" {
		spec.Escalation.SeverityThreshold = "critical"
	}
	spec.Escalation.PostmortemSeverityThreshold = strings.ToLower(strings.TrimSpace(spec.Escalation.PostmortemSeverityThreshold))
	if spec.Escalation.PostmortemSeverityThreshold == "" {
		spec.Escalation.PostmortemSeverityThreshold = "critical"
	}
	if spec.Escalation.MaxAutoHealAttempts <= 0 {
		spec.Escalation.MaxAutoHealAttempts = 2
	}
	spec.Escalation.IssueWorkflow = strings.TrimSpace(spec.Escalation.IssueWorkflow)
	spec.Escalation.PostmortemWorkflow = strings.TrimSpace(spec.Escalation.PostmortemWorkflow)
	spec.Escalation.Ref = strings.TrimSpace(spec.Escalation.Ref)
	if spec.Escalation.Ref == "" {
		spec.Escalation.Ref = "main"
	}
	spec.Escalation.Environments = normalizeGuardianEnvironmentList(spec.Escalation.Environments)
	if spec.Escalation.Enabled && !spec.Escalation.CreateApproval && !spec.Escalation.DispatchWorkflow {
		spec.Escalation.CreateApproval = true
	}
	return spec
}

func guardianPolicySelectorProvided(selector model.ManifestSelector) bool {
	return strings.TrimSpace(selector.ManifestID) != "" ||
		strings.TrimSpace(selector.Namespace) != "" ||
		strings.TrimSpace(selector.Name) != "" ||
		selector.Version != nil
}

func supportedGuardianSeverityRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

func normalizeGuardianEnvironmentList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		item := strings.ToLower(strings.TrimSpace(value))
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		normalized = append(normalized, item)
	}
	return normalized
}

func normalizeGuardianWeekdays(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		item := strings.ToLower(strings.TrimSpace(value))
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		normalized = append(normalized, item)
	}
	return normalized
}
