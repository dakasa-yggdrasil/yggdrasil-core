package manifest

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestProvisioningSnapshotManifestRequiresAuthorizedManualChannel(t *testing.T) {
	disabled := false
	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual", Enabled: &disabled},
		Authorization: &model.WorkflowAuthorizationSpec{
			RBAC: model.ManifestSelector{Namespace: "dakasa", Name: "identity-provisioning-manual"},
		},
		Steps: []model.WorkflowStepSpec{{
			ID:  "list-collaborators",
			Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "collaborator.provisioning_snapshot"},
		}},
	}
	if err := ValidateWorkflowSpec(spec); err != nil {
		t.Fatalf("authorized manual snapshot rejected: %v", err)
	}

	withoutAuthorization := spec
	withoutAuthorization.Authorization = nil
	if err := ValidateWorkflowSpec(withoutAuthorization); err == nil {
		t.Fatal("actorless snapshot manifest accepted")
	}
	defaultTrigger := spec
	defaultTrigger.Trigger.Enabled = nil
	if err := ValidateWorkflowSpec(defaultTrigger); err == nil {
		t.Fatal("default-enabled snapshot trigger accepted")
	}

	withSchedule := spec
	withSchedule.Trigger.Mode = "schedule"
	withSchedule.Trigger.Schedule = &model.WorkflowScheduleTriggerSpec{CronExpression: "0 0 * * *"}
	if err := ValidateWorkflowSpec(withSchedule); err == nil {
		t.Fatal("scheduled snapshot manifest accepted")
	}
	withWrite := spec
	withWrite.Steps = append([]model.WorkflowStepSpec(nil), spec.Steps...)
	withWrite.Steps = append(withWrite.Steps, model.WorkflowStepSpec{
		ID: "provider-write",
		Use: model.WorkflowStepUseSpec{
			Kind: "integration", Operation: "ensure_user",
			InstanceRef: &model.ManifestSelector{Namespace: "dakasa", Name: "provider"},
		},
	})
	if err := ValidateWorkflowSpec(withWrite); err == nil {
		t.Fatal("snapshot manifest with an additional provider step was accepted")
	}
	for _, nonliteralID := range []string{" List-Collaborators ", "LIST-COLLABORATORS"} {
		withAlias := spec
		withAlias.Steps = append([]model.WorkflowStepSpec(nil), spec.Steps...)
		withAlias.Steps[0].ID = nonliteralID
		if err := ValidateWorkflowSpec(withAlias); err == nil {
			t.Fatalf("snapshot step alias %q was accepted", nonliteralID)
		}
	}
}
