package model

// GuardianPolicyManifestSpec defines the autonomy and blast-radius limits for one guardian integration.
type GuardianPolicyManifestSpec struct {
	GuardianRef          ManifestSelector                       `json:"guardian_ref"`
	Scope                string                                 `json:"scope,omitempty"`
	AutoHeal             GuardianAutoHealPolicySpec             `json:"auto_heal,omitempty"`
	Autonomy             GuardianAutonomyPolicySpec             `json:"autonomy,omitempty"`
	GeneratedBundles     GuardianGeneratedBundlePolicySpec      `json:"generated_bundles,omitempty"`
	ProfilePromotions    GuardianProfilePromotionPolicySpec     `json:"profile_promotions,omitempty"`
	MaintenanceMode      GuardianMaintenanceModePolicySpec      `json:"maintenance_mode,omitempty"`
	Escalation           GuardianEscalationPolicySpec           `json:"escalation,omitempty"`
	RepositoryAutomation GuardianRepositoryAutomationPolicySpec `json:"repository_automation,omitempty"`
	CostOptimization     GuardianCostOptimizationPolicySpec     `json:"cost_optimization,omitempty"`
}

// GuardianAutoHealPolicySpec constrains automatic runtime remediation.
type GuardianAutoHealPolicySpec struct {
	Enabled               bool   `json:"enabled,omitempty"`
	SeverityThreshold     string `json:"severity_threshold,omitempty"`
	MaxActionsPerSweep    int    `json:"max_actions_per_sweep,omitempty"`
	CooldownSeconds       int    `json:"cooldown_seconds,omitempty"`
	AllowDispatchWorkflow bool   `json:"allow_dispatch_workflow,omitempty"`
	AllowRotateSecret     bool   `json:"allow_rotate_secret,omitempty"`
	AllowRightsize        bool   `json:"allow_rightsize,omitempty"`
}

// GuardianRepositoryAutomationPolicySpec constrains repository-facing changes.
type GuardianRepositoryAutomationPolicySpec struct {
	AllowPullRequestAutomation bool `json:"allow_pull_request_automation,omitempty"`
	AllowDirectPush            bool `json:"allow_direct_push,omitempty"`
}

// GuardianCostOptimizationPolicySpec constrains proactive cost actions.
type GuardianCostOptimizationPolicySpec struct {
	Enabled                       bool    `json:"enabled,omitempty"`
	MinEstimatedMonthlySavingsUSD float64 `json:"min_estimated_monthly_savings_usd,omitempty"`
	AllowRightsize                bool    `json:"allow_rightsize,omitempty"`
}

// GuardianAutonomyPolicySpec controls when Heimdall may act directly, when it
// must request approval, and when it may engage the LLM fallback path.
type GuardianAutonomyPolicySpec struct {
	Mode                        string                                 `json:"mode,omitempty"`
	AllowLLMFallback            bool                                   `json:"allow_llm_fallback,omitempty"`
	HotfixSeverityThreshold     string                                 `json:"hotfix_severity_threshold,omitempty"`
	AutoExecuteMinConfidence    float64                                `json:"auto_execute_min_confidence,omitempty"`
	ManualReviewBelowConfidence float64                                `json:"manual_review_below_confidence,omitempty"`
	MaxAutoExecuteBlastRadius   string                                 `json:"max_auto_execute_blast_radius,omitempty"`
	MaxBypassHotfixBlastRadius  string                                 `json:"max_bypass_hotfix_blast_radius,omitempty"`
	ProtectedEnvironments       GuardianProtectedEnvironmentPolicySpec `json:"protected_environments,omitempty"`
	BusinessHours               GuardianBusinessHoursPolicySpec        `json:"business_hours,omitempty"`
	FreezeWindows               []GuardianFreezeWindowPolicySpec       `json:"freeze_windows,omitempty"`
}

// GuardianGeneratedBundlePolicySpec constrains when Heimdall may generate a
// temporary remediation bundle from the LLM fallback path.
type GuardianGeneratedBundlePolicySpec struct {
	Enabled                     bool `json:"enabled,omitempty"`
	RequireApproval             bool `json:"require_approval,omitempty"`
	MaxTTLSeconds               int  `json:"max_ttl_seconds,omitempty"`
	AllowWorkflowPatch          bool `json:"allow_workflow_patch,omitempty"`
	AllowIntegrationComposition bool `json:"allow_integration_composition,omitempty"`
	AllowEphemeralExecutor      bool `json:"allow_ephemeral_executor,omitempty"`
}

// GuardianProfilePromotionPolicySpec governs whether Heimdall may persist
// learned capacity hotfix profiles directly or must request a human review
// first.
type GuardianProfilePromotionPolicySpec struct {
	Enabled         bool `json:"enabled,omitempty"`
	RequireApproval bool `json:"require_approval,omitempty"`
}

// GuardianMaintenanceModePolicySpec blocks or limits autonomous changes during
// planned maintenance periods outside the scheduled freeze-window model.
type GuardianMaintenanceModePolicySpec struct {
	Enabled           bool     `json:"enabled,omitempty"`
	Environments      []string `json:"environments,omitempty"`
	Reason            string   `json:"reason,omitempty"`
	AllowHotfixBypass bool     `json:"allow_hotfix_bypass,omitempty"`
}

// GuardianEscalationPolicySpec defines when Heimdall should stop trying the
// same remediation path and escalate to humans or repository automation.
type GuardianEscalationPolicySpec struct {
	Enabled                     bool     `json:"enabled,omitempty"`
	SeverityThreshold           string   `json:"severity_threshold,omitempty"`
	MaxAutoHealAttempts         int      `json:"max_auto_heal_attempts,omitempty"`
	CreateApproval              bool     `json:"create_approval,omitempty"`
	DispatchWorkflow            bool     `json:"dispatch_workflow,omitempty"`
	IssueWorkflow               string   `json:"issue_workflow,omitempty"`
	PostmortemWorkflow          string   `json:"postmortem_workflow,omitempty"`
	Ref                         string   `json:"ref,omitempty"`
	PostmortemSeverityThreshold string   `json:"postmortem_severity_threshold,omitempty"`
	Environments                []string `json:"environments,omitempty"`
}

// GuardianProtectedEnvironmentPolicySpec tightens autonomy for sensitive environments.
type GuardianProtectedEnvironmentPolicySpec struct {
	Environments               []string `json:"environments,omitempty"`
	MaxAutoExecuteBlastRadius  string   `json:"max_auto_execute_blast_radius,omitempty"`
	MaxBypassHotfixBlastRadius string   `json:"max_bypass_hotfix_blast_radius,omitempty"`
}

// GuardianBusinessHoursPolicySpec limits autonomous actions to a business-hours envelope.
type GuardianBusinessHoursPolicySpec struct {
	Enabled           bool     `json:"enabled,omitempty"`
	Timezone          string   `json:"timezone,omitempty"`
	Weekdays          []string `json:"weekdays,omitempty"`
	StartHour         int      `json:"start_hour,omitempty"`
	EndHour           int      `json:"end_hour,omitempty"`
	Environments      []string `json:"environments,omitempty"`
	AllowHotfixBypass bool     `json:"allow_hotfix_bypass,omitempty"`
}

// GuardianFreezeWindowPolicySpec blocks autonomous changes during planned freeze periods.
type GuardianFreezeWindowPolicySpec struct {
	Name              string   `json:"name,omitempty"`
	StartsAt          string   `json:"starts_at,omitempty"`
	EndsAt            string   `json:"ends_at,omitempty"`
	Environments      []string `json:"environments,omitempty"`
	AllowHotfixBypass bool     `json:"allow_hotfix_bypass,omitempty"`
}
