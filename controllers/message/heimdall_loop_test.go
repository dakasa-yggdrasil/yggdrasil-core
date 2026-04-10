package message

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestHeimdallIntegrationIncidentsAddsOOMCapacityIncident(t *testing.T) {
	health := model.IntegrationInstanceHealth{
		IntegrationInstance: model.ManifestReference{
			Namespace: "global",
			Name:      "heimdall-guardian",
		},
		IntegrationType: model.ManifestReference{
			Namespace: "global",
			Name:      "heimdall",
		},
		RuntimeState: &model.IntegrationRuntimeState{
			Status:  model.IntegrationRuntimeStatusUnreachable,
			Message: "container exited with OOMKilled",
			Details: map[string]any{
				"oom_killed": true,
			},
		},
	}

	incidents := heimdallIntegrationIncidents(health, map[string]any{
		"repository": "dakasa-yggdrasil/integration-heimdall",
	})
	if len(incidents) != 2 {
		t.Fatalf("incidents = %d, want 2", len(incidents))
	}

	foundCapacity := false
	for _, incident := range incidents {
		if strings.EqualFold(anyString(incident["category"]), "capacity") {
			foundCapacity = true
			break
		}
	}
	if !foundCapacity {
		t.Fatal("expected capacity incident for oom-killed runtime")
	}
}

func TestHeimdallApplyIntegrationGuardianSignalsMapsSchedulingFailures(t *testing.T) {
	item := heimdallApplyIntegrationGuardianSignals(
		map[string]any{},
		&model.IntegrationRuntimeState{
			Message: "0/3 nodes are available: 3 Insufficient cpu. FailedScheduling",
			Details: map[string]any{
				"failed_scheduling": true,
				"insufficient_cpu":  true,
			},
		},
		model.IntegrationGuardianSupportSpec{
			Mode: "light",
			Signals: model.IntegrationGuardianSignalSupportSpec{
				SchedulingFailure: []string{"failed_scheduling"},
				InsufficientCPU:   []string{"insufficient_cpu"},
			},
		},
	)

	if got, ok := item["scheduling_failure"].(bool); !ok || !got {
		t.Fatalf("scheduling_failure = %#v, want true", item["scheduling_failure"])
	}
	if got, ok := item["insufficient_cpu"].(bool); !ok || !got {
		t.Fatalf("insufficient_cpu = %#v, want true", item["insufficient_cpu"])
	}
}

func TestHeimdallIntegrationIncidentsAddsSchedulingFailureIncidentForInsufficientCPU(t *testing.T) {
	health := model.IntegrationInstanceHealth{
		IntegrationInstance: model.ManifestReference{
			Namespace: "global",
			Name:      "integration-kubernetes-prod",
		},
		IntegrationType: model.ManifestReference{
			Namespace: "global",
			Name:      "kubernetes",
		},
		RuntimeState: &model.IntegrationRuntimeState{
			Status:  "degraded",
			Message: "0/3 nodes are available: 3 Insufficient cpu. FailedScheduling",
			Details: map[string]any{
				"failed_scheduling": true,
				"insufficient_cpu":  true,
			},
		},
	}

	incidents := heimdallIntegrationIncidents(health, map[string]any{
		"repository":            "dakasa-yggdrasil/integration-kubernetes",
		"guardian_support_mode": "light",
		"scheduling_failure":    true,
		"insufficient_cpu":      true,
	})

	foundSchedulingFailure := false
	for _, incident := range incidents {
		if strings.EqualFold(anyString(incident["category"]), "capacity_scheduling_failure") {
			foundSchedulingFailure = true
			if got := anyString(incident["repository"]); got != "dakasa-yggdrasil/integration-kubernetes" {
				t.Fatalf("repository = %q, want dakasa-yggdrasil/integration-kubernetes", got)
			}
		}
	}
	if !foundSchedulingFailure {
		t.Fatalf("expected capacity_scheduling_failure incident, got %#v", incidents)
	}
}

func TestHeimdallIntegrationIncidentsEnrichEvidenceWithProviderContext(t *testing.T) {
	health := model.IntegrationInstanceHealth{
		IntegrationInstance: model.ManifestReference{
			Namespace: "global",
			Name:      "integration-github-prod",
		},
		IntegrationType: model.ManifestReference{
			Namespace: "global",
			Name:      "github",
		},
		RuntimeState: &model.IntegrationRuntimeState{
			Status:  model.IntegrationRuntimeStatusUnreachable,
			Message: "adapter timed out",
			Details: map[string]any{
				"restart_count": 4,
			},
		},
	}

	incidents := heimdallIntegrationIncidents(health, map[string]any{
		"repository":            "dakasa-yggdrasil/integration-github",
		"guardian_support_mode": "lightweight",
	})
	if len(incidents) == 0 {
		t.Fatal("incidents = 0, want at least one")
	}

	evidence, ok := incidents[0]["evidence"].(map[string]any)
	if !ok {
		t.Fatalf("incident evidence type = %T, want map[string]any", incidents[0]["evidence"])
	}
	if got := anyString(evidence["type_name"]); got != "github" {
		t.Fatalf("type_name = %q, want github", got)
	}
	if got := anyString(evidence["type_namespace"]); got != "global" {
		t.Fatalf("type_namespace = %q, want global", got)
	}
	if got := anyString(evidence["repository"]); got != "dakasa-yggdrasil/integration-github" {
		t.Fatalf("repository = %q, want dakasa-yggdrasil/integration-github", got)
	}
}

func TestResolveHeimdallContractAction(t *testing.T) {
	contracts := map[string]heimdallRemediationContract{
		heimdallComponentKey("surface", "global", "yggdrasil-console"): {
			Spec: model.RemediationContractManifestSpec{
				ComponentKind:      "surface",
				ComponentNamespace: "global",
				ComponentName:      "yggdrasil-console",
				Actions: []model.RemediationContractActionSpec{
					{
						Name:        "rightsize_component",
						Mode:        model.RemediationContractActionModeWorkflowDispatch,
						AutoExecute: true,
						WorkflowDispatch: &model.RemediationWorkflowDispatchSpec{
							Workflow: "deploy.yml",
							Ref:      "main",
						},
					},
				},
			},
		},
	}

	contract, action, err := resolveHeimdallContractAction(map[string]any{
		"type":                "rightsize_component",
		"component_kind":      "surface",
		"component_namespace": "global",
		"component_name":      "yggdrasil-console",
	}, contracts)
	if err != nil {
		t.Fatalf("resolveHeimdallContractAction error: %v", err)
	}
	if contract.Spec.ComponentName != "yggdrasil-console" {
		t.Fatalf("contract component_name = %q, want yggdrasil-console", contract.Spec.ComponentName)
	}
	if action.Name != "rightsize_component" {
		t.Fatalf("action name = %q, want rightsize_component", action.Name)
	}
}

func TestHeimdallRemediationContractActionNamesReturnsSortedUniqueNames(t *testing.T) {
	contracts := map[string]heimdallRemediationContract{
		heimdallComponentKey("integration", "global", "kubernetes-platform-prod"): {
			Spec: model.RemediationContractManifestSpec{
				ComponentKind:      "integration",
				ComponentNamespace: "global",
				ComponentName:      "kubernetes-platform-prod",
				Actions: []model.RemediationContractActionSpec{
					{Name: "capacity_scheduling_hotfix"},
					{Name: "rightsize_component"},
					{Name: "capacity_scheduling_hotfix"},
				},
			},
		},
	}

	got := heimdallRemediationContractActionNames(contracts, "integration", "global", "kubernetes-platform-prod")
	want := []string{"capacity_scheduling_hotfix", "rightsize_component"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("action names = %#v, want %#v", got, want)
	}
}

func TestHeimdallBuildWorkflowInputsIncludesRemediationFields(t *testing.T) {
	inputs := heimdallBuildWorkflowInputs(
		map[string]any{
			"type":                "rightsize_component",
			"component_kind":      "integration",
			"component_namespace": "global",
			"component_name":      "heimdall-guardian",
			"reason":              "oom recovery",
			"workflow": map[string]any{
				"inputs": map[string]any{
					"incident_title": "Integration was OOMKilled",
				},
			},
		},
		model.RepositoryBindingManifestSpec{
			ComponentKind:      "integration",
			ComponentNamespace: "global",
			ComponentName:      "heimdall-guardian",
			Metadata: map[string]any{
				"environment": "production",
			},
		},
		"critical_auto_remediation",
		map[string]any{
			"remediation_contract": "heimdall.rightsize.v1",
		},
	)

	if got := anyString(inputs["component_namespace"]); got != "global" {
		t.Fatalf("component_namespace = %q, want global", got)
	}
	if got := anyString(inputs["incident_title"]); got != "Integration was OOMKilled" {
		t.Fatalf("incident_title = %q, want propagated incident title", got)
	}
	if got := anyString(inputs["remediation_contract"]); got != "heimdall.rightsize.v1" {
		t.Fatalf("remediation_contract = %q, want heimdall.rightsize.v1", got)
	}
	if got := anyString(inputs["event_name"]); got != "critical_auto_remediation" {
		t.Fatalf("event_name = %q, want critical_auto_remediation", got)
	}
}

func TestHeimdallCapacityHotfixProfileFromActionNormalizesShape(t *testing.T) {
	profile, err := heimdallCapacityHotfixProfileFromAction(map[string]any{
		"profile": map[string]any{
			"name":                       "payments-api-prod",
			"environments":               []any{"prod"},
			"namespaces":                 []any{"payments"},
			"workloadNames":              []any{"payments-api"},
			"workload_name_prefixes":     []any{"payments-"},
			"defaultRequestMillicores":   900.0,
			"default_limit_millicores":   1200.0,
			"maxRequestDeltaMillicores":  "250",
			"max_limit_delta_millicores": "300",
		},
	})
	if err != nil {
		t.Fatalf("heimdallCapacityHotfixProfileFromAction error: %v", err)
	}

	if got := anyString(profile["name"]); got != "payments-api-prod" {
		t.Fatalf("name = %q, want payments-api-prod", got)
	}
	if got := reflect.ValueOf(profile["workload_names"]).Interface(); !reflect.DeepEqual(got, []string{"payments-api"}) {
		t.Fatalf("workload_names = %#v, want []string{\"payments-api\"}", got)
	}
	if got := profile["default_request_millicores"]; got != 900 {
		t.Fatalf("default_request_millicores = %#v, want 900", got)
	}
	if got := profile["max_limit_delta_millicores"]; got != 300 {
		t.Fatalf("max_limit_delta_millicores = %#v, want 300", got)
	}
}

func TestHeimdallMergeCapacityHotfixProfilesReplacesAndSorts(t *testing.T) {
	merged := heimdallMergeCapacityHotfixProfiles(
		[]map[string]any{
			{
				"name":                       "zeta",
				"default_request_millicores": 500,
			},
			{
				"name":                       "alpha",
				"default_request_millicores": 250,
			},
		},
		map[string]any{
			"name":                       "alpha",
			"default_request_millicores": 900,
		},
	)

	if len(merged) != 2 {
		t.Fatalf("merged len = %d, want 2", len(merged))
	}
	if got := anyString(merged[0]["name"]); got != "alpha" {
		t.Fatalf("merged[0].name = %q, want alpha", got)
	}
	if got := merged[0]["default_request_millicores"]; got != 900 {
		t.Fatalf("merged[0].default_request_millicores = %#v, want 900", got)
	}
	if got := anyString(merged[1]["name"]); got != "zeta" {
		t.Fatalf("merged[1].name = %q, want zeta", got)
	}
}

func TestHeimdallEscalationWorkflowActionUsesIssueWorkflowBelowPostmortemThreshold(t *testing.T) {
	action, ok := heimdallEscalationWorkflowAction(
		context.Background(),
		nil,
		map[string]any{
			"type":              "dispatch_workflow",
			"component_kind":    "product",
			"component_name":    "yggdrasil",
			"incident_severity": "high",
			"incident_title":    "Smoke issue escalation",
			"incident_category": "oom_killed",
		},
		model.GuardianPolicyManifestSpec{
			Escalation: model.GuardianEscalationPolicySpec{
				IssueWorkflow:               "incident-escalation.yml",
				PostmortemWorkflow:          "postmortem.yml",
				PostmortemSeverityThreshold: "critical",
				Ref:                         "main",
			},
		},
	)
	if !ok {
		t.Fatal("expected escalation workflow action to be generated")
	}

	workflow, _ := action["workflow"].(map[string]any)
	if got := anyString(workflow["workflow"]); got != "incident-escalation.yml" {
		t.Fatalf("workflow = %q, want incident-escalation.yml", got)
	}
	inputs, _ := workflow["inputs"].(map[string]any)
	if got := anyString(inputs["escalation_kind"]); got != "issue" {
		t.Fatalf("escalation_kind = %q, want issue", got)
	}
	if got := anyString(inputs["incident_severity"]); got != "high" {
		t.Fatalf("incident_severity = %q, want high", got)
	}
	if got, _ := inputs["postmortem_required"].(bool); got {
		t.Fatalf("postmortem_required = %v, want false", got)
	}
}

func TestHeimdallEscalationWorkflowActionUsesPostmortemWorkflowAtThreshold(t *testing.T) {
	action, ok := heimdallEscalationWorkflowAction(
		context.Background(),
		nil,
		map[string]any{
			"type":              "dispatch_workflow",
			"component_kind":    "product",
			"component_name":    "yggdrasil",
			"incident_severity": "critical",
			"incident_title":    "Smoke postmortem escalation",
			"incident_category": "oom_killed",
		},
		model.GuardianPolicyManifestSpec{
			Escalation: model.GuardianEscalationPolicySpec{
				IssueWorkflow:               "incident-escalation.yml",
				PostmortemWorkflow:          "postmortem.yml",
				PostmortemSeverityThreshold: "critical",
				Ref:                         "main",
			},
		},
	)
	if !ok {
		t.Fatal("expected escalation workflow action to be generated")
	}

	workflow, _ := action["workflow"].(map[string]any)
	if got := anyString(workflow["workflow"]); got != "postmortem.yml" {
		t.Fatalf("workflow = %q, want postmortem.yml", got)
	}
	inputs, _ := workflow["inputs"].(map[string]any)
	if got := anyString(inputs["escalation_kind"]); got != "postmortem" {
		t.Fatalf("escalation_kind = %q, want postmortem", got)
	}
	if got := anyString(inputs["incident_severity"]); got != "critical" {
		t.Fatalf("incident_severity = %q, want critical", got)
	}
	if got, _ := inputs["postmortem_required"].(bool); !got {
		t.Fatalf("postmortem_required = %v, want true", got)
	}
}

func TestHeimdallWorkflowNameAndRefFromActionMap(t *testing.T) {
	action := map[string]any{
		"workflow": map[string]any{
			"workflow": "incident-escalation.yml",
			"ref":      "main",
			"inputs": map[string]any{
				"incident_title": "Smoke issue escalation",
			},
		},
	}

	if got := heimdallWorkflowNameFromAction(action); got != "incident-escalation.yml" {
		t.Fatalf("workflow name = %q, want incident-escalation.yml", got)
	}
	if got := heimdallWorkflowRefFromAction(action); got != "main" {
		t.Fatalf("workflow ref = %q, want main", got)
	}
	inputs := heimdallWorkflowInputsFromAction(action)
	if got := anyString(inputs["incident_title"]); got != "Smoke issue escalation" {
		t.Fatalf("incident_title = %q, want Smoke issue escalation", got)
	}
}

func TestHeimdallEvaluateMemoryObservationTracksRecoveryTimingAndStability(t *testing.T) {
	now := time.Now().UTC()
	spec := model.GuardianMemoryManifestSpec{
		Status:             model.GuardianMemoryStatusObservedRecovered,
		ComponentKind:      "integration",
		ComponentNamespace: "global",
		ComponentName:      "heimdall-guardian",
		Execution: model.GuardianMemoryExecutionSpec{
			AttemptedAt: now.Add(-26 * time.Hour).Format(time.RFC3339),
			CompletedAt: now.Add(-25 * time.Hour).Format(time.RFC3339),
		},
		Observation: model.GuardianMemoryObservationSpec{
			ObservedAt:       now.Add(-24 * time.Hour).Format(time.RFC3339),
			ObservationCount: 1,
		},
	}

	status, observation, ok := heimdallEvaluateMemoryObservation(map[string]any{
		"integrations": []map[string]any{
			{
				"name":           "heimdall-guardian",
				"namespace":      "global",
				"overall_health": "healthy",
			},
		},
		"incidents": []map[string]any{},
	}, spec)
	if !ok {
		t.Fatal("expected observation to be evaluated")
	}
	if status != model.GuardianMemoryStatusObservedRecovered {
		t.Fatalf("status = %q, want observed_recovered", status)
	}
	if observation.TimeToRecoverySeconds <= 0 {
		t.Fatalf("time_to_recovery_seconds = %d, want > 0", observation.TimeToRecoverySeconds)
	}
	if observation.StableWindowSeconds < 24*60*60-60 {
		t.Fatalf("stable_window_seconds = %d, want roughly >= 24h", observation.StableWindowSeconds)
	}
	if observation.ObservationCount < 2 {
		t.Fatalf("observation_count = %d, want incremented count", observation.ObservationCount)
	}
}

func TestHeimdallDecisionFromAssessmentAutoExecutesTrustedPlaybooks(t *testing.T) {
	decision := heimdallDecisionFromAssessment(
		map[string]any{
			"type":              "dispatch_workflow",
			"incident_severity": "critical",
			"blast_radius":      "medium",
		},
		model.GuardianPolicyManifestSpec{
			Autonomy: model.GuardianAutonomyPolicySpec{
				Mode:                        "policy_bound",
				AutoExecuteMinConfidence:    0.7,
				ManualReviewBelowConfidence: 0.25,
				HotfixSeverityThreshold:     "critical",
				MaxAutoExecuteBlastRadius:   "medium",
				MaxBypassHotfixBlastRadius:  "high",
			},
		},
		"critical_auto_remediation",
		heimdallActionConfidenceAssessment{
			Confidence:       0.88,
			ConfidenceBand:   "trusted",
			ProviderGroup:    "kubernetes",
			IncidentCategory: "capacity",
			Attempts:         4,
			RecoveryRate:     0.92,
		},
	)

	if decision.RequireApproval {
		t.Fatal("expected trusted playbook to auto-execute")
	}
	if decision.ConfidenceBand != "trusted" {
		t.Fatalf("confidence band = %q, want trusted", decision.ConfidenceBand)
	}
}

func TestHeimdallDecisionFromAssessmentRequiresManualReviewForLowConfidence(t *testing.T) {
	decision := heimdallDecisionFromAssessment(
		map[string]any{
			"type":              "rightsize_component",
			"incident_severity": "critical",
		},
		model.GuardianPolicyManifestSpec{
			Autonomy: model.GuardianAutonomyPolicySpec{
				Mode:                        "policy_bound",
				AutoExecuteMinConfidence:    0.7,
				ManualReviewBelowConfidence: 0.25,
				HotfixSeverityThreshold:     "critical",
				MaxAutoExecuteBlastRadius:   "medium",
				MaxBypassHotfixBlastRadius:  "high",
			},
		},
		"critical_auto_remediation",
		heimdallActionConfidenceAssessment{
			Confidence:       0.12,
			ProviderGroup:    "kubernetes",
			IncidentCategory: "capacity",
			Attempts:         1,
			RecoveryRate:     0.1,
		},
	)

	if !decision.RequireApproval {
		t.Fatal("expected low-confidence playbook to require approval")
	}
	if !decision.ManualReview {
		t.Fatal("expected low-confidence playbook to require manual review")
	}
	if decision.ConfidenceBand != "manual_review" {
		t.Fatalf("confidence band = %q, want manual_review", decision.ConfidenceBand)
	}
}

func TestHeimdallDecisionFromAssessmentRequiresApprovalForHighBlastRadius(t *testing.T) {
	decision := heimdallDecisionFromAssessment(
		map[string]any{
			"type":         "dispatch_workflow",
			"blast_radius": "high",
		},
		model.GuardianPolicyManifestSpec{
			Autonomy: model.GuardianAutonomyPolicySpec{
				Mode:                        "policy_bound",
				AutoExecuteMinConfidence:    0.7,
				ManualReviewBelowConfidence: 0.25,
				HotfixSeverityThreshold:     "critical",
				MaxAutoExecuteBlastRadius:   "medium",
				MaxBypassHotfixBlastRadius:  "high",
			},
		},
		"critical_auto_remediation",
		heimdallActionConfidenceAssessment{
			Confidence:       0.93,
			ProviderGroup:    "github",
			IncidentCategory: "runtime",
			Attempts:         6,
			RecoveryRate:     0.95,
		},
	)

	if !decision.RequireApproval {
		t.Fatal("expected high blast radius playbook to require approval")
	}
	if decision.ManualReview {
		t.Fatal("expected high blast radius playbook to require approval, not manual review")
	}
	if decision.BlastRadius != "high" {
		t.Fatalf("blast radius = %q, want high", decision.BlastRadius)
	}
}

func TestHeimdallDecisionFromAssessmentRequiresManualReviewForCriticalBlastRadius(t *testing.T) {
	decision := heimdallDecisionFromAssessment(
		map[string]any{
			"type":         "direct_push",
			"blast_radius": "critical",
		},
		model.GuardianPolicyManifestSpec{
			Autonomy: model.GuardianAutonomyPolicySpec{
				Mode:                        "policy_bound",
				AutoExecuteMinConfidence:    0.7,
				ManualReviewBelowConfidence: 0.25,
				HotfixSeverityThreshold:     "critical",
				MaxAutoExecuteBlastRadius:   "medium",
				MaxBypassHotfixBlastRadius:  "high",
			},
		},
		"critical_auto_remediation",
		heimdallActionConfidenceAssessment{
			Confidence:       0.97,
			ProviderGroup:    "github",
			IncidentCategory: "repository",
			Attempts:         3,
			RecoveryRate:     1,
		},
	)

	if !decision.RequireApproval {
		t.Fatal("expected critical blast radius playbook to require approval")
	}
	if !decision.ManualReview {
		t.Fatal("expected critical blast radius playbook to require manual review")
	}
	if decision.ConfidenceBand != "manual_review" {
		t.Fatalf("confidence band = %q, want manual_review", decision.ConfidenceBand)
	}
}

func TestHeimdallDecisionFromAssessmentProtectsProductionEnvironment(t *testing.T) {
	decision := heimdallDecisionFromAssessmentAt(
		map[string]any{
			"type":         "dispatch_workflow",
			"blast_radius": "medium",
			"environment":  "production",
		},
		model.GuardianPolicyManifestSpec{
			Autonomy: model.GuardianAutonomyPolicySpec{
				Mode:                        "policy_bound",
				AutoExecuteMinConfidence:    0.7,
				ManualReviewBelowConfidence: 0.25,
				HotfixSeverityThreshold:     "critical",
				MaxAutoExecuteBlastRadius:   "medium",
				MaxBypassHotfixBlastRadius:  "high",
				ProtectedEnvironments: model.GuardianProtectedEnvironmentPolicySpec{
					Environments:               []string{"production"},
					MaxAutoExecuteBlastRadius:  "low",
					MaxBypassHotfixBlastRadius: "medium",
				},
			},
		},
		"critical_auto_remediation",
		heimdallActionConfidenceAssessment{
			Confidence:       0.95,
			ProviderGroup:    "github",
			IncidentCategory: "runtime",
			Attempts:         5,
			RecoveryRate:     1,
			BlastRadius:      "medium",
			Environment:      "production",
		},
		time.Date(2026, time.April, 6, 14, 0, 0, 0, time.UTC),
	)

	if !decision.RequireApproval {
		t.Fatal("expected production protection to require approval")
	}
	if !decision.ProtectedEnvironment {
		t.Fatal("expected production environment to be marked as protected")
	}
}

func TestHeimdallDecisionFromAssessmentBlocksOutsideBusinessHours(t *testing.T) {
	decision := heimdallDecisionFromAssessmentAt(
		map[string]any{
			"type":         "dispatch_workflow",
			"blast_radius": "low",
			"environment":  "production",
		},
		model.GuardianPolicyManifestSpec{
			Autonomy: model.GuardianAutonomyPolicySpec{
				Mode:                        "policy_bound",
				AutoExecuteMinConfidence:    0.7,
				ManualReviewBelowConfidence: 0.25,
				MaxAutoExecuteBlastRadius:   "medium",
				MaxBypassHotfixBlastRadius:  "high",
				BusinessHours: model.GuardianBusinessHoursPolicySpec{
					Enabled:           true,
					Timezone:          "UTC",
					Weekdays:          []string{"mon", "tue", "wed", "thu", "fri"},
					StartHour:         9,
					EndHour:           18,
					Environments:      []string{"production"},
					AllowHotfixBypass: false,
				},
			},
		},
		"critical_auto_remediation",
		heimdallActionConfidenceAssessment{
			Confidence:  0.95,
			BlastRadius: "low",
			Environment: "production",
		},
		time.Date(2026, time.April, 6, 2, 0, 0, 0, time.UTC),
	)

	if !decision.RequireApproval {
		t.Fatal("expected outside business hours to require approval")
	}
	if !decision.OutsideBusinessHours {
		t.Fatal("expected decision to flag outside business hours")
	}
}

func TestHeimdallDecisionFromAssessmentBlocksDuringFreezeWindow(t *testing.T) {
	decision := heimdallDecisionFromAssessmentAt(
		map[string]any{
			"type":         "dispatch_workflow",
			"blast_radius": "low",
			"environment":  "production",
		},
		model.GuardianPolicyManifestSpec{
			Autonomy: model.GuardianAutonomyPolicySpec{
				Mode:                        "policy_bound",
				AutoExecuteMinConfidence:    0.7,
				ManualReviewBelowConfidence: 0.25,
				MaxAutoExecuteBlastRadius:   "medium",
				MaxBypassHotfixBlastRadius:  "high",
				FreezeWindows: []model.GuardianFreezeWindowPolicySpec{
					{
						Name:         "release-freeze",
						StartsAt:     "2026-04-01T00:00:00Z",
						EndsAt:       "2026-04-10T00:00:00Z",
						Environments: []string{"production"},
					},
				},
			},
		},
		"critical_auto_remediation",
		heimdallActionConfidenceAssessment{
			Confidence:  0.95,
			BlastRadius: "low",
			Environment: "production",
		},
		time.Date(2026, time.April, 6, 14, 0, 0, 0, time.UTC),
	)

	if !decision.RequireApproval {
		t.Fatal("expected freeze window to require approval")
	}
	if !decision.ManualReview {
		t.Fatal("expected freeze window to require manual review")
	}
	if decision.ActiveFreezeWindow != "release-freeze" {
		t.Fatalf("freeze window = %q, want release-freeze", decision.ActiveFreezeWindow)
	}
}

func TestHeimdallDecisionFromAssessmentEscalatesDuringMaintenanceMode(t *testing.T) {
	decision := heimdallDecisionFromAssessmentAt(
		map[string]any{
			"type":              "rightsize_component",
			"incident_severity": "critical",
			"blast_radius":      "medium",
			"environment":       "production",
		},
		model.GuardianPolicyManifestSpec{
			Autonomy: model.GuardianAutonomyPolicySpec{
				Mode:                        "policy_bound",
				AutoExecuteMinConfidence:    0.7,
				ManualReviewBelowConfidence: 0.25,
				MaxAutoExecuteBlastRadius:   "medium",
				MaxBypassHotfixBlastRadius:  "high",
			},
			MaintenanceMode: model.GuardianMaintenanceModePolicySpec{
				Enabled:      true,
				Environments: []string{"production"},
				Reason:       "Maintenance mode is active for a database migration.",
			},
			Escalation: model.GuardianEscalationPolicySpec{
				Enabled:             true,
				SeverityThreshold:   "critical",
				MaxAutoHealAttempts: 2,
				CreateApproval:      true,
			},
		},
		"critical_auto_remediation",
		heimdallActionConfidenceAssessment{
			Confidence:       0.92,
			BlastRadius:      "medium",
			Environment:      "production",
			ProviderGroup:    "kubernetes",
			IncidentCategory: "capacity",
			Attempts:         1,
			RecoveryRate:     1,
		},
		time.Date(2026, time.April, 6, 14, 0, 0, 0, time.UTC),
	)

	if !decision.Escalate {
		t.Fatal("expected maintenance mode to trigger escalation")
	}
	if !decision.MaintenanceActive {
		t.Fatal("expected maintenance mode to be reflected in the decision")
	}
	if decision.ConfidenceBand != "escalation" {
		t.Fatalf("confidence band = %q, want escalation", decision.ConfidenceBand)
	}
}

func TestHeimdallDecisionFromAssessmentEscalatesAfterRepeatedFailures(t *testing.T) {
	decision := heimdallDecisionFromAssessment(
		map[string]any{
			"type":              "dispatch_workflow",
			"incident_severity": "critical",
			"blast_radius":      "medium",
		},
		model.GuardianPolicyManifestSpec{
			Autonomy: model.GuardianAutonomyPolicySpec{
				Mode:                        "policy_bound",
				AutoExecuteMinConfidence:    0.7,
				ManualReviewBelowConfidence: 0.25,
				MaxAutoExecuteBlastRadius:   "medium",
				MaxBypassHotfixBlastRadius:  "high",
			},
			Escalation: model.GuardianEscalationPolicySpec{
				Enabled:             true,
				SeverityThreshold:   "critical",
				MaxAutoHealAttempts: 2,
				CreateApproval:      true,
			},
		},
		"critical_auto_remediation",
		heimdallActionConfidenceAssessment{
			Confidence:       0.88,
			BlastRadius:      "medium",
			ProviderGroup:    "github",
			IncidentCategory: "availability",
			Attempts:         3,
			RecoveryRate:     0.2,
		},
	)

	if !decision.Escalate {
		t.Fatal("expected repeated failed attempts to escalate")
	}
	if decision.EscalationReason == "" {
		t.Fatal("expected escalation reason to be set")
	}
}
