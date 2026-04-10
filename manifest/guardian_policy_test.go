package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidateGuardianPolicySpec(t *testing.T) {
	spec := guardianPolicyFixture()

	if err := ValidateGuardianPolicySpec(spec); err != nil {
		t.Fatalf("ValidateGuardianPolicySpec error: %v", err)
	}
}

func TestValidateGuardianPolicySpecRejectsMissingGuardianRef(t *testing.T) {
	spec := guardianPolicyFixture()
	spec.GuardianRef = model.ManifestSelector{}

	if err := ValidateGuardianPolicySpec(spec); err == nil {
		t.Fatal("expected missing guardian_ref to fail validation")
	}
}

func TestGuardianPolicyDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(guardianPolicyFixture())
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "guardian_policy",
		Metadata: model.ManifestMetadataInput{
			Name:      "heimdall-default",
			Namespace: "global",
		},
		Spec: raw,
	}

	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(guardian_policy) error: %v", err)
	}
}

func guardianPolicyFixture() model.GuardianPolicyManifestSpec {
	return model.GuardianPolicyManifestSpec{
		GuardianRef: model.ManifestSelector{
			Namespace: "global",
			Name:      "heimdall-guardian",
		},
		Scope: "global",
		AutoHeal: model.GuardianAutoHealPolicySpec{
			Enabled:               true,
			SeverityThreshold:     "critical",
			MaxActionsPerSweep:    2,
			CooldownSeconds:       300,
			AllowDispatchWorkflow: true,
		},
		CostOptimization: model.GuardianCostOptimizationPolicySpec{
			Enabled:                       true,
			MinEstimatedMonthlySavingsUSD: 50,
		},
		Autonomy: model.GuardianAutonomyPolicySpec{
			Mode:                        "policy_bound",
			AllowLLMFallback:            true,
			HotfixSeverityThreshold:     "critical",
			AutoExecuteMinConfidence:    0.7,
			ManualReviewBelowConfidence: 0.25,
			MaxAutoExecuteBlastRadius:   "medium",
			MaxBypassHotfixBlastRadius:  "high",
			ProtectedEnvironments: model.GuardianProtectedEnvironmentPolicySpec{
				Environments:               []string{"production"},
				MaxAutoExecuteBlastRadius:  "low",
				MaxBypassHotfixBlastRadius: "medium",
			},
			BusinessHours: model.GuardianBusinessHoursPolicySpec{
				Enabled:           true,
				Timezone:          "UTC",
				Weekdays:          []string{"mon", "tue", "wed", "thu", "fri"},
				StartHour:         9,
				EndHour:           18,
				Environments:      []string{"production"},
				AllowHotfixBypass: true,
			},
			FreezeWindows: []model.GuardianFreezeWindowPolicySpec{
				{
					Name:         "release-freeze",
					StartsAt:     "2026-12-20T00:00:00Z",
					EndsAt:       "2026-12-27T00:00:00Z",
					Environments: []string{"production"},
				},
			},
		},
		ProfilePromotions: model.GuardianProfilePromotionPolicySpec{
			Enabled:         true,
			RequireApproval: true,
		},
		MaintenanceMode: model.GuardianMaintenanceModePolicySpec{
			Enabled:      true,
			Environments: []string{"production"},
			Reason:       "Planned maintenance.",
		},
		Escalation: model.GuardianEscalationPolicySpec{
			Enabled:                     true,
			SeverityThreshold:           "critical",
			MaxAutoHealAttempts:         2,
			CreateApproval:              true,
			DispatchWorkflow:            true,
			IssueWorkflow:               "incident-escalation.yml",
			PostmortemWorkflow:          "postmortem.yml",
			Ref:                         "main",
			PostmortemSeverityThreshold: "critical",
			Environments:                []string{"production"},
		},
	}
}

func TestValidateGuardianPolicySpecRejectsInvalidConfidenceThresholds(t *testing.T) {
	spec := guardianPolicyFixture()
	spec.Autonomy.AutoExecuteMinConfidence = 1.2

	if err := ValidateGuardianPolicySpec(spec); err == nil {
		t.Fatal("expected invalid auto_execute_min_confidence to fail validation")
	}
}

func TestValidateGuardianPolicySpecRejectsInvalidBlastRadiusOrder(t *testing.T) {
	spec := guardianPolicyFixture()
	spec.Autonomy.MaxAutoExecuteBlastRadius = "critical"
	spec.Autonomy.MaxBypassHotfixBlastRadius = "medium"

	if err := ValidateGuardianPolicySpec(spec); err == nil {
		t.Fatal("expected invalid blast radius ordering to fail validation")
	}
}

func TestValidateGuardianPolicySpecRejectsInvalidFreezeWindow(t *testing.T) {
	spec := guardianPolicyFixture()
	spec.Autonomy.FreezeWindows[0].EndsAt = "2026-12-19T00:00:00Z"

	if err := ValidateGuardianPolicySpec(spec); err == nil {
		t.Fatal("expected invalid freeze window ordering to fail validation")
	}
}

func TestValidateGuardianPolicySpecRejectsEmptyMaintenanceEnvironments(t *testing.T) {
	spec := guardianPolicyFixture()
	spec.MaintenanceMode.Environments = nil

	if err := ValidateGuardianPolicySpec(spec); err == nil {
		t.Fatal("expected maintenance_mode without environments to fail validation")
	}
}

func TestValidateGuardianPolicySpecRejectsEscalationDispatchWithoutWorkflow(t *testing.T) {
	spec := guardianPolicyFixture()
	spec.Escalation.DispatchWorkflow = true
	spec.Escalation.IssueWorkflow = ""
	spec.Escalation.PostmortemWorkflow = ""

	if err := ValidateGuardianPolicySpec(spec); err == nil {
		t.Fatal("expected escalation dispatch without workflow to fail validation")
	}
}
