package message

import (
	"fmt"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestCompareIntegrationTypeSpecIgnoresOrderingNoise(t *testing.T) {
	expected := model.IntegrationTypeManifestSpec{
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
		Capabilities: []string{"execute", "describe"},
		CredentialSchema: model.IntegrationSchemaSpec{
			Mode:     "inline",
			Required: []string{"token", "owner"},
			Properties: map[string]model.IntegrationSchemaProperty{
				"owner": {Type: "string"},
				"token": {Type: "string", Secret: true},
			},
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
				DefaultActions:   []string{"read", "dispatch_workflow"},
			},
		},
		ActionCatalog: []model.IntegrationActionDefinition{
			{
				Name:          "dispatch_workflow",
				ResourceTypes: []string{"repository"},
			},
			{
				Name:          "read",
				ResourceTypes: []string{"repository"},
			},
		},
		Discovery: model.IntegrationDiscoverySpec{
			Mode:   "push",
			Cursor: "none",
		},
		Normalization: model.IntegrationNormalizationSpec{
			ExternalIDPath:         "full_name",
			FallbackResourcePrefix: "thirdparty.github.custom",
		},
		Execution: model.IntegrationExecutionSpec{
			IdempotentActions: []string{"read", "dispatch_workflow"},
		},
		Extensions: model.IntegrationExtensionsSpec{
			PreserveRawPayload: true,
		},
	}

	actual := model.IntegrationTypeManifestSpec{
		Provider: " github ",
		Adapter: model.IntegrationAdapterSpec{
			Transport: "RABBITMQ",
			Version:   "1.0.0",
			Queues: model.IntegrationAdapterQueue{
				Describe: "describe",
				Execute:  "execute",
			},
			TimeoutSeconds: 20,
		},
		Capabilities: []string{"describe", "execute"},
		CredentialSchema: model.IntegrationSchemaSpec{
			Mode:     "INLINE",
			Required: []string{"owner", "token"},
			Properties: map[string]model.IntegrationSchemaProperty{
				"token": {Type: "STRING", Secret: true},
				"owner": {Type: "string"},
			},
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
				DefaultActions:   []string{"dispatch_workflow", "read"},
			},
		},
		ActionCatalog: []model.IntegrationActionDefinition{
			{
				Name:          "read",
				ResourceTypes: []string{"repository"},
			},
			{
				Name:          "dispatch_workflow",
				ResourceTypes: []string{"repository"},
			},
		},
		Discovery: model.IntegrationDiscoverySpec{
			Mode:   "push",
			Cursor: "none",
		},
		Normalization: model.IntegrationNormalizationSpec{
			ExternalIDPath:         "full_name",
			FallbackResourcePrefix: "thirdparty.github.custom",
		},
		Execution: model.IntegrationExecutionSpec{
			IdempotentActions: []string{"dispatch_workflow", "read"},
		},
		Extensions: model.IntegrationExtensionsSpec{
			PreserveRawPayload: true,
		},
	}

	if err := compareIntegrationTypeSpec(expected, actual); err != nil {
		t.Fatalf("compareIntegrationTypeSpec() error = %v", err)
	}
}

func TestCompareIntegrationTypeSpecDetectsMismatch(t *testing.T) {
	expected := model.IntegrationTypeManifestSpec{
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
		Capabilities:     []string{"describe", "execute"},
		CredentialSchema: model.IntegrationSchemaSpec{Mode: "inline"},
		InstanceSchema:   model.IntegrationSchemaSpec{Mode: "inline"},
		ResourceTypes: []model.IntegrationResourceType{
			{
				Name:             "repository",
				CanonicalPrefix:  "thirdparty.github.repository",
				IdentityTemplate: "repository.{repository}",
				Discoverable:     false,
				DefaultActions:   []string{"dispatch_workflow"},
			},
		},
		Discovery: model.IntegrationDiscoverySpec{
			Mode: "push",
		},
		Normalization: model.IntegrationNormalizationSpec{
			ExternalIDPath:         "full_name",
			FallbackResourcePrefix: "thirdparty.github.custom",
		},
		Execution:  model.IntegrationExecutionSpec{},
		Extensions: model.IntegrationExtensionsSpec{},
	}

	actual := expected
	actual.Adapter.Version = "2.0.0"

	err := compareIntegrationTypeSpec(expected, actual)
	if err == nil {
		t.Fatal("compareIntegrationTypeSpec() error = nil, want error")
	}
}

func TestCompareIntegrationTypeSpecTreatsEmptySchemaCollectionsAsOmitted(t *testing.T) {
	expected := model.IntegrationTypeManifestSpec{
		CredentialSchema: model.IntegrationSchemaSpec{
			Mode:       "none",
			Required:   []string{},
			Properties: map[string]model.IntegrationSchemaProperty{},
		},
		InstanceSchema: model.IntegrationSchemaSpec{
			Mode:       "none",
			Required:   []string{},
			Properties: map[string]model.IntegrationSchemaProperty{},
		},
	}
	actual := model.IntegrationTypeManifestSpec{
		CredentialSchema: model.IntegrationSchemaSpec{Mode: "none"},
		InstanceSchema:   model.IntegrationSchemaSpec{Mode: "none"},
	}

	if err := compareIntegrationTypeSpec(expected, actual); err != nil {
		t.Fatalf("compareIntegrationTypeSpec() error = %v", err)
	}
}

func TestIntegrationDescribeFailureStatus(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status string
	}{
		{
			name:   "invalid response schema",
			err:    fmt.Errorf("describe integration type global/github through queue \"describe\": validate integration describe response: missing field"),
			status: model.IntegrationRuntimeStatusInvalidResponse,
		},
		{
			name:   "contract mismatch",
			err:    fmt.Errorf("integration type global/github does not match live adapter describe contract: provider mismatch"),
			status: model.IntegrationRuntimeStatusContractMismatch,
		},
		{
			name:   "unreachable transport",
			err:    fmt.Errorf("describe integration type global/github through queue \"describe\": context deadline exceeded"),
			status: model.IntegrationRuntimeStatusUnreachable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := integrationDescribeFailureStatus(tc.err); got != tc.status {
				t.Fatalf("integrationDescribeFailureStatus() = %q, want %q", got, tc.status)
			}
		})
	}
}

// Regression: ensure the live → spec conversion carries adapter-declared
// reactors through to the resulting spec. Without this, even if an adapter
// emits `reactors[]` in its describe response, manifest_sync's merge sees
// an empty live spec.Reactors and never seeds the field.
func TestIntegrationTypeSpecFromDescribeResponse_CarriesReactors(t *testing.T) {
	response := model.AdapterDescribeResponse{
		Provider:     "slack",
		Capabilities: []string{"describe", "execute"},
		ActionCatalog: []model.IntegrationActionDefinition{
			{Name: "on_collaborator_session_terminated", Category: "reactor"},
		},
		Reactors: []model.IntegrationTypeReactor{
			{EventType: "collaborator.session.terminated", Capability: "on_collaborator_session_terminated"},
		},
	}
	spec := integrationTypeSpecFromDescribeResponse(response)
	if len(spec.Reactors) != 1 {
		t.Fatalf("expected 1 reactor in derived spec, got %d", len(spec.Reactors))
	}
	if spec.Reactors[0].EventType != "collaborator.session.terminated" {
		t.Fatalf("expected event_type=collaborator.session.terminated, got %q", spec.Reactors[0].EventType)
	}
	if spec.Reactors[0].Capability != "on_collaborator_session_terminated" {
		t.Fatalf("expected capability=on_collaborator_session_terminated, got %q", spec.Reactors[0].Capability)
	}
}
