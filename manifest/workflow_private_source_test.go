package manifest

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestProvisioningPrivateSourceRequiresNamedProducerAndDependency(t *testing.T) {
	valid := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		Steps: []model.WorkflowStepSpec{
			{
				ID:  "list-collaborators",
				Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "collaborator.provisioning_snapshot"},
			},
			{
				ID: "consume", DependsOn: []string{"list-collaborators"},
				ForEach: &model.WorkflowForEachSpec{Items: "private://list-collaborators/collaborators", As: "collaborator"},
				Use: model.WorkflowStepUseSpec{
					Kind: "integration", Operation: "ensure_user",
					InstanceRef: &model.ManifestSelector{Namespace: "dakasa", Name: "provider"},
				},
			},
		},
	}
	if err := ValidateWorkflowSpec(valid); err != nil {
		t.Fatalf("valid private source: %v", err)
	}

	missingDependency := valid
	missingDependency.Steps = append([]model.WorkflowStepSpec(nil), valid.Steps...)
	missingDependency.Steps[1].DependsOn = nil
	if err := ValidateWorkflowSpec(missingDependency); err == nil {
		t.Fatal("private source without direct producer dependency was accepted")
	}

	wrongSource := valid
	wrongSource.Steps = append([]model.WorkflowStepSpec(nil), valid.Steps...)
	wrongSource.Steps[1].ForEach = &model.WorkflowForEachSpec{Items: "private://other/people", As: "collaborator"}
	if err := ValidateWorkflowSpec(wrongSource); err == nil {
		t.Fatal("unknown private source was accepted")
	}

	wrongProducer := valid
	wrongProducer.Steps = append([]model.WorkflowStepSpec(nil), valid.Steps...)
	wrongProducer.Steps[0].Use.Operation = "assert"
	wrongProducer.Steps[0].With = map[string]any{}
	if err := ValidateWorkflowSpec(wrongProducer); err == nil {
		t.Fatal("private source without provisioning producer was accepted")
	}
}
