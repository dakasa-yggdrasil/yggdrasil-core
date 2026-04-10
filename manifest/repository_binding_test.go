package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidateRepositoryBindingSpec(t *testing.T) {
	spec := repositoryBindingFixture()

	if err := ValidateRepositoryBindingSpec(spec); err != nil {
		t.Fatalf("ValidateRepositoryBindingSpec error: %v", err)
	}
}

func TestValidateRepositoryBindingSpecRejectsBadRepository(t *testing.T) {
	spec := repositoryBindingFixture()
	spec.Repository = "dakasa-yggdrasil"

	if err := ValidateRepositoryBindingSpec(spec); err == nil {
		t.Fatal("expected invalid repository to fail validation")
	}
}

func TestRepositoryBindingDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(repositoryBindingFixture())
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "repository_binding",
		Metadata: model.ManifestMetadataInput{
			Name:      "yggdrasil",
			Namespace: "global",
		},
		Spec: raw,
	}

	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(repository_binding) error: %v", err)
	}
}

func repositoryBindingFixture() model.RepositoryBindingManifestSpec {
	return model.RepositoryBindingManifestSpec{
		ComponentKind:      "product",
		ComponentNamespace: "global",
		ComponentName:      "yggdrasil",
		Repository:         "dakasa-yggdrasil/yggdrasil",
		DefaultBranch:      "main",
		DeployWorkflow:     "deploy.yml",
		Automation: model.RepositoryBindingAutomationSpec{
			Observe:               true,
			AllowDispatchWorkflow: true,
		},
	}
}
