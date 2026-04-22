package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidateProductSpecInlineRawK8s(t *testing.T) {
	spec := productSpecInlineFixture()

	if err := ValidateProductSpec(spec); err != nil {
		t.Fatalf("ValidateProductSpec(inline/raw_k8s) error: %v", err)
	}
}

func TestValidateProductSpecOCIHelm(t *testing.T) {
	spec := productSpecHelmFixture()

	if err := ValidateProductSpec(spec); err != nil {
		t.Fatalf("ValidateProductSpec(oci/helm) error: %v", err)
	}
}

func TestValidateProductSpecGitKustomize(t *testing.T) {
	spec := productSpecKustomizeFixture()

	if err := ValidateProductSpec(spec); err != nil {
		t.Fatalf("ValidateProductSpec(git/kustomize) error: %v", err)
	}
}

func TestValidateProductSpecIntegrationRawK8s(t *testing.T) {
	spec := productSpecIntegrationFixture()

	if err := ValidateProductSpec(spec); err != nil {
		t.Fatalf("ValidateProductSpec(integration/raw_k8s) error: %v", err)
	}
}

func TestValidateProductSpecRejectsInvalidRequirementPolicy(t *testing.T) {
	spec := productSpecIntegrationFixture()
	spec.Components[0].Requires[0].Policy = "eventually"

	if err := ValidateProductSpec(spec); err == nil {
		t.Fatal("expected invalid requirement policy to fail validation")
	}
}

func TestValidateProductSpecRejectsInlineHelm(t *testing.T) {
	spec := productSpecInlineFixture()
	spec.Components[0].Renderer.Kind = "helm"

	if err := ValidateProductSpec(spec); err == nil {
		t.Fatal("expected inline source with helm renderer to fail validation")
	}
}

func TestValidateProductSpecRejectsOCIKustomize(t *testing.T) {
	spec := productSpecHelmFixture()
	spec.Components[0].Renderer.Kind = "kustomize"
	spec.Components[0].Renderer.Path = "deploy/overlays/prod"

	if err := ValidateProductSpec(spec); err == nil {
		t.Fatal("expected oci source with kustomize renderer to fail validation")
	}
}

func TestValidateProductSpecRejectsUnknownComponentDependency(t *testing.T) {
	spec := productSpecHelmFixture()
	spec.Components[0].DependsOn = []string{"missing"}

	if err := ValidateProductSpec(spec); err == nil {
		t.Fatal("expected unknown component dependency to fail validation")
	}
}

func TestValidateProductSpecRejectsIntegrationWithUnsupportedOperation(t *testing.T) {
	spec := productSpecIntegrationFixture()
	spec.Components[0].Source.Operation = "reconcile_installation"

	if err := ValidateProductSpec(spec); err == nil {
		t.Fatal("expected integration source with unsupported operation to fail validation")
	}
}

func TestValidateProductSpecRejectsIntegrationHelm(t *testing.T) {
	spec := productSpecIntegrationFixture()
	spec.Components[0].Renderer.Kind = "helm"
	spec.Components[0].Renderer.Values = map[string]any{
		"namespace": "identities",
	}

	if err := ValidateProductSpec(spec); err == nil {
		t.Fatal("expected integration source with helm renderer to fail validation")
	}
}

func TestValidateProductSpecRejectsGitCapabilityFields(t *testing.T) {
	spec := productSpecKustomizeFixture()
	spec.Components[0].Source.Capability = "generate-product"
	spec.Components[0].Source.Input = map[string]any{
		"blueprint": "service",
	}

	if err := ValidateProductSpec(spec); err == nil {
		t.Fatal("expected git source with capability/input to fail validation")
	}
}

func TestProductDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(productSpecInlineFixture())
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "product",
		Metadata: model.ManifestMetadataInput{
			Name:      "cert-manager",
			Namespace: "global",
		},
		Spec: raw,
	}

	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(product) error: %v", err)
	}
}

func productSpecInlineFixture() model.ProductManifestSpec {
	return model.ProductManifestSpec{
		Category: "certificate",
		Class:    "platform",
		Owners:   []string{"team:platform"},
		Lifecycle: model.ProductLifecycleSpec{
			Tier:  "critical",
			Stage: "production",
		},
		Components: []model.ProductComponentSpec{
			{
				Name: "cert-manager-bundle",
				Source: model.ProductSourceSpec{
					Kind: "inline",
					Objects: []map[string]any{
						{
							"apiVersion": "v1",
							"kind":       "Namespace",
							"metadata": map[string]any{
								"name": "cert-manager",
							},
						},
					},
				},
				Renderer: model.ProductRendererSpec{
					Kind: "raw_k8s",
				},
				Target: model.ProductTargetSpec{
					Kind: "kubernetes",
					IntegrationInstanceRef: model.ManifestSelector{
						Name:      "kubernetes-platform-prod",
						Namespace: "global",
					},
					Namespace: "cert-manager",
				},
				Reconcile: model.ProductReconcileSpec{
					Strategy: "apply",
					Prune:    true,
				},
			},
		},
	}
}

func productSpecHelmFixture() model.ProductManifestSpec {
	return model.ProductManifestSpec{
		Category: "identity",
		Class:    "application",
		Owners:   []string{"team:platform"},
		Lifecycle: model.ProductLifecycleSpec{
			Tier:  "standard",
			Stage: "production",
		},
		Components: []model.ProductComponentSpec{
			{
				Name: "identities-api",
				Source: model.ProductSourceSpec{
					Kind: "oci",
					IntegrationInstanceRef: &model.ManifestSelector{
						Name:      "artifact-registry-prod",
						Namespace: "global",
					},
					Locator: "oci://us-central1-docker.pkg.dev/dakasa/charts/component-api",
					Version: "1.2.3",
				},
				Renderer: model.ProductRendererSpec{
					Kind: "helm",
					Values: map[string]any{
						"image": map[string]any{
							"repository": "us-central1-docker.pkg.dev/dakasa/apps",
							"tag":        "2026.03.25",
						},
						"namespace": "identities",
					},
				},
				Target: model.ProductTargetSpec{
					Kind: "kubernetes",
					IntegrationInstanceRef: model.ManifestSelector{
						Name:      "gke-apps-prod",
						Namespace: "global",
					},
					Namespace: "identities",
				},
				Reconcile: model.ProductReconcileSpec{
					Strategy: "sync",
					Prune:    true,
					Wait:     true,
				},
			},
		},
		Dependencies: []string{"platform-observability"},
	}
}

func productSpecKustomizeFixture() model.ProductManifestSpec {
	return model.ProductManifestSpec{
		Category: "identity",
		Class:    "application",
		Owners:   []string{"team:platform"},
		Lifecycle: model.ProductLifecycleSpec{
			Tier:  "standard",
			Stage: "production",
		},
		Components: []model.ProductComponentSpec{
			{
				Name: "identities-api",
				Source: model.ProductSourceSpec{
					Kind: "git",
					IntegrationInstanceRef: &model.ManifestSelector{
						Name:      "github-dakasa-prod",
						Namespace: "global",
					},
					Locator:  "github.com/dakasa-co/identity-service",
					Revision: "main",
				},
				Renderer: model.ProductRendererSpec{
					Kind: "kustomize",
					Path: "deploy/overlays/prod",
				},
				Target: model.ProductTargetSpec{
					Kind: "kubernetes",
					IntegrationInstanceRef: model.ManifestSelector{
						Name:      "gke-apps-prod",
						Namespace: "global",
					},
					Namespace: "identities",
				},
				Reconcile: model.ProductReconcileSpec{
					Strategy: "sync",
					Prune:    true,
					Wait:     true,
				},
			},
		},
	}
}

func productSpecIntegrationFixture() model.ProductManifestSpec {
	return model.ProductManifestSpec{
		Category: "messaging",
		Class:    "platform",
		Owners:   []string{"team:platform"},
		Lifecycle: model.ProductLifecycleSpec{
			Tier:  "critical",
			Stage: "production",
		},
		Components: []model.ProductComponentSpec{
			{
				Name: "rabbitmq-foundation",
				Source: model.ProductSourceSpec{
					Kind: "integration",
					IntegrationInstanceRef: &model.ManifestSelector{
						Name:      "rabbitmq-kubernetes-platform-prod",
						Namespace: "global",
					},
					Operation: "generate_installation",
					Input: map[string]any{
						"blueprint":   "shared-broker",
						"environment": "prod",
						"namespace":   "rabbitmq-system",
					},
				},
				Renderer: model.ProductRendererSpec{
					Kind: "raw_k8s",
				},
				Target: model.ProductTargetSpec{
					Kind: "kubernetes",
					IntegrationInstanceRef: model.ManifestSelector{
						Name:      "kubernetes-platform-prod",
						Namespace: "global",
					},
					Namespace: "rabbitmq-system",
				},
				Reconcile: model.ProductReconcileSpec{
					Strategy: "apply",
					Prune:    true,
					Wait:     true,
				},
				Requires: []model.ProductRequirementSpec{
					{
						Kind: "integration_instance",
						Selector: model.ManifestSelector{
							Name:      "kubernetes-platform-prod",
							Namespace: "global",
						},
						State:  "active",
						Policy: "must_exist",
						Wait:   true,
					},
					{
						Kind: "product",
						Selector: model.ManifestSelector{
							Name:      "rabbitmq-cluster-operator",
							Namespace: "global",
						},
						State:  "materialized",
						Policy: "install_if_missing",
						Wait:   true,
					},
				},
			},
		},
	}
}
