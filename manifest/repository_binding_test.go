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

func TestValidateRepositoryBindingSpecAcceptsDeployYggdrasil(t *testing.T) {
	spec := repositoryBindingFixture()
	spec.Deploy = &model.RepositoryBindingDeploySpec{
		WorkflowKind: "yggdrasil",
		WorkflowRef:  &model.ManifestRef{Namespace: "dakasa", Name: "deploy-via-kustomize-source"},
	}
	if err := ValidateRepositoryBindingSpec(spec); err != nil {
		t.Fatalf("expected valid yggdrasil deploy, got %v", err)
	}
}

func TestValidateRepositoryBindingSpecAcceptsGithubActions(t *testing.T) {
	spec := repositoryBindingFixture()
	spec.Deploy = &model.RepositoryBindingDeploySpec{WorkflowKind: "github_actions"}
	if err := ValidateRepositoryBindingSpec(spec); err != nil {
		t.Fatalf("expected valid github_actions deploy (no workflow_ref required), got %v", err)
	}
}

func TestValidateRepositoryBindingSpecRejectsEmptyWorkflowKind(t *testing.T) {
	spec := repositoryBindingFixture()
	spec.Deploy = &model.RepositoryBindingDeploySpec{}
	if err := ValidateRepositoryBindingSpec(spec); err == nil {
		t.Fatal("expected error for empty workflow_kind")
	}
}

func TestValidateRepositoryBindingSpecRejectsUnknownWorkflowKind(t *testing.T) {
	spec := repositoryBindingFixture()
	spec.Deploy = &model.RepositoryBindingDeploySpec{WorkflowKind: "garbage"}
	if err := ValidateRepositoryBindingSpec(spec); err == nil {
		t.Fatal("expected error for unknown workflow_kind")
	}
}

func TestValidateRepositoryBindingSpecRequiresWorkflowRefForYggdrasil(t *testing.T) {
	spec := repositoryBindingFixture()
	spec.Deploy = &model.RepositoryBindingDeploySpec{WorkflowKind: "yggdrasil"}
	if err := ValidateRepositoryBindingSpec(spec); err == nil {
		t.Fatal("expected error for missing workflow_ref")
	}
}

func TestValidateRepositoryBindingSpecRequiresWorkflowRefName(t *testing.T) {
	spec := repositoryBindingFixture()
	spec.Deploy = &model.RepositoryBindingDeploySpec{
		WorkflowKind: "yggdrasil",
		WorkflowRef:  &model.ManifestRef{Namespace: "dakasa", Name: "  "},
	}
	if err := ValidateRepositoryBindingSpec(spec); err == nil {
		t.Fatal("expected error for blank workflow_ref name")
	}
}

func TestValidateRepositoryBindingSpecRejectsBadPathGlob(t *testing.T) {
	spec := repositoryBindingFixture()
	spec.Deploy = &model.RepositoryBindingDeploySpec{
		WorkflowKind: "yggdrasil",
		WorkflowRef:  &model.ManifestRef{Namespace: "dakasa", Name: "wf"},
		PathFilter:   []string{"deploy/[bad"},
	}
	if err := ValidateRepositoryBindingSpec(spec); err == nil {
		t.Fatal("expected error for malformed glob")
	}
}

func TestNormalizeRepositoryBindingSpecDefaultsBranchFilterMain(t *testing.T) {
	spec := repositoryBindingFixture()
	spec.Deploy = &model.RepositoryBindingDeploySpec{
		WorkflowKind: "yggdrasil",
		WorkflowRef:  &model.ManifestRef{Namespace: "dakasa", Name: "wf"},
	}
	out := NormalizeRepositoryBindingSpec(spec)
	if got := out.Deploy.BranchFilter; len(got) != 1 || got[0] != "main" {
		t.Fatalf("expected ['main'], got %v", got)
	}
}

func TestNormalizeRepositoryBindingSpecPreservesExplicitBranches(t *testing.T) {
	spec := repositoryBindingFixture()
	spec.Deploy = &model.RepositoryBindingDeploySpec{
		WorkflowKind: "yggdrasil",
		WorkflowRef:  &model.ManifestRef{Namespace: "dakasa", Name: "wf"},
		BranchFilter: []string{"main", "release"},
	}
	out := NormalizeRepositoryBindingSpec(spec)
	if got := out.Deploy.BranchFilter; len(got) != 2 || got[0] != "main" || got[1] != "release" {
		t.Fatalf("expected explicit branches preserved, got %v", got)
	}
}

func TestNormalizeRepositoryBindingSpecDefaultsWorkflowRefNamespace(t *testing.T) {
	spec := repositoryBindingFixture()
	spec.Deploy = &model.RepositoryBindingDeploySpec{
		WorkflowKind: "yggdrasil",
		WorkflowRef:  &model.ManifestRef{Namespace: "", Name: "wf"},
	}
	out := NormalizeRepositoryBindingSpec(spec)
	if got := out.Deploy.WorkflowRef.Namespace; got != "global" {
		t.Fatalf("expected namespace 'global', got %q", got)
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
