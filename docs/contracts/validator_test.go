package contracts

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestValidateIntegrationExecuteContract(t *testing.T) {
	req := model.AdapterExecuteIntegrationRequest{
		Operation:  "dispatch_workflow",
		Capability: "dispatch_workflow",
		Input: map[string]any{
			"repository": "dakasa-co/platform-service",
		},
		Auth: map[string]any{
			"token": "secret",
		},
		Integration: sampleExecuteIntegrationContext(),
	}

	if err := Validate(FamilyIntegrationAdapterV1, "adapterExecuteIntegrationRequest", req); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateProductInstallationContracts(t *testing.T) {
	req := model.AdapterGenerateInstallationRequest{
		Operation:  "generate_installation",
		Capability: "generate_installation",
		Context: model.AdapterGenerateInstallationContext{
			Product:   sampleManifestReference("product", "global", "observability-grafana"),
			Component: "grafana",
			Category:  "observability",
			Class:     "platform",
		},
		Integration: model.AdapterGenerateInstallationIntegrationContext{
			Type:         sampleManifestReference("integration_type", "global", "grafana-on-kubernetes"),
			TypeSpec:     sampleIntegrationTypeSpec(),
			Instance:     sampleManifestReference("integration_instance", "global", "grafana-on-kubernetes-platform"),
			InstanceSpec: sampleIntegrationInstanceSpec(),
		},
		Input: map[string]any{
			"blueprint": "single-instance",
		},
	}

	if err := Validate(FamilyProductInstallationAdapterV1, "generateInstallationRequest", req); err != nil {
		t.Fatalf("Validate(generateInstallationRequest) error = %v", err)
	}

	applyReq := model.AdapterDeclarativeApplyRequest{
		Operation: "declarative_apply",
		Context:   req.Context,
		Target: model.AdapterTargetIntegrationContext{
			Type:         sampleManifestReference("integration_type", "global", "kubernetes"),
			TypeSpec:     sampleIntegrationTypeSpec(),
			Instance:     sampleManifestReference("integration_instance", "global", "kubernetes-platform"),
			InstanceSpec: sampleIntegrationInstanceSpec(),
		},
		Objects: []map[string]any{
			{
				"apiVersion": "v1",
				"kind":       "Namespace",
				"metadata": map[string]any{
					"name": "grafana",
				},
			},
		},
		Namespace: "grafana",
	}

	if err := Validate(FamilyProductInstallationAdapterV1, "declarativeApplyRequest", applyReq); err != nil {
		t.Fatalf("Validate(declarativeApplyRequest) error = %v", err)
	}

	deleteReq := model.AdapterDeclarativeDeleteRequest{
		Operation: "declarative_delete",
		Context:   req.Context,
		Target: model.AdapterTargetIntegrationContext{
			Type:         sampleManifestReference("integration_type", "global", "kubernetes"),
			TypeSpec:     sampleIntegrationTypeSpec(),
			Instance:     sampleManifestReference("integration_instance", "global", "kubernetes-platform"),
			InstanceSpec: sampleIntegrationInstanceSpec(),
		},
		Objects: []map[string]any{
			{
				"apiVersion": "v1",
				"kind":       "Namespace",
				"metadata": map[string]any{
					"name": "grafana",
				},
			},
		},
		Namespace: "grafana",
	}

	if err := Validate(FamilyProductInstallationAdapterV1, "declarativeDeleteRequest", deleteReq); err != nil {
		t.Fatalf("Validate(declarativeDeleteRequest) error = %v", err)
	}

	deleteResp := model.AdapterDeclarativeDeleteResponse{
		Operation:   "declarative_delete",
		Uninstalled: true,
	}
	if err := Validate(FamilyProductInstallationAdapterV1, "declarativeDeleteResponse", deleteResp); err != nil {
		t.Fatalf("Validate(declarativeDeleteResponse) error = %v", err)
	}
}

func TestValidateRejectsMissingRequiredField(t *testing.T) {
	invalid := map[string]any{
		"integration": sampleExecuteIntegrationContext(),
	}

	err := Validate(FamilyIntegrationAdapterV1, "adapterExecuteIntegrationRequest", invalid)
	if err == nil {
		t.Fatal("Validate() error = nil, want error")
	}
}

func sampleExecuteIntegrationContext() model.AdapterExecuteIntegrationContext {
	return model.AdapterExecuteIntegrationContext{
		Type:         sampleManifestReference("integration_type", "global", "github"),
		TypeSpec:     sampleIntegrationTypeSpec(),
		Instance:     sampleManifestReference("integration_instance", "global", "github-caller"),
		InstanceSpec: sampleIntegrationInstanceSpec(),
	}
}

func sampleManifestReference(kind string, namespace string, name string) model.ManifestReference {
	return model.ManifestReference{
		ID:        uuid.New(),
		Kind:      kind,
		Namespace: namespace,
		Name:      name,
		Version:   1,
	}
}

func sampleIntegrationTypeSpec() model.IntegrationTypeManifestSpec {
	return model.IntegrationTypeManifestSpec{
		Provider: "github",
		Adapter: model.IntegrationAdapterSpec{
			Transport: "rabbitmq",
			Version:   "1.0.0",
			Queues: model.IntegrationAdapterQueue{
				Describe: "describe",
				Execute:  "execute",
			},
			TimeoutSeconds: 20,
		},
		Capabilities: []string{"describe", "execute"},
		CredentialSchema: model.IntegrationSchemaSpec{
			Mode: "inline",
		},
		InstanceSchema: model.IntegrationSchemaSpec{
			Mode: "inline",
		},
		ResourceTypes: []model.IntegrationResourceType{
			{
				Name:             "repository",
				CanonicalPrefix:  "thirdparty.github.repository",
				IdentityTemplate: "repository.{repository}",
				Discoverable:     false,
				DefaultActions:   []string{"dispatch_workflow"},
			},
		},
		ActionCatalog: []model.IntegrationActionDefinition{
			{
				Name: "dispatch_workflow",
			},
		},
		Discovery: model.IntegrationDiscoverySpec{
			Mode: "push",
		},
		Normalization: model.IntegrationNormalizationSpec{
			ExternalIDPath:         "full_name",
			FallbackResourcePrefix: "thirdparty.github.custom",
		},
		Execution: model.IntegrationExecutionSpec{},
		Extensions: model.IntegrationExtensionsSpec{
			PreserveRawPayload: true,
		},
	}
}

func sampleIntegrationInstanceSpec() model.IntegrationInstanceManifestSpec {
	return model.IntegrationInstanceManifestSpec{
		TypeRef: model.ManifestSelector{
			Namespace: "global",
			Name:      "github",
		},
		Status: "active",
		Config: map[string]any{
			"default_ref": "main",
		},
		Discovery: model.IntegrationInstanceDiscoverySpec{
			Enabled: false,
			Mode:    "manual",
		},
	}
}
