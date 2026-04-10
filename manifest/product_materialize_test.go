package manifest

import (
	"context"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type fakeProductGenerator struct {
	output GenerateProductComponentOutput
	err    error
}

func (f fakeProductGenerator) Generate(_ context.Context, input GenerateProductComponentInput) (GenerateProductComponentOutput, error) {
	output := f.output
	if output.Trace.Name == "" {
		output.Trace.Name = input.Component.Name
	}
	return output, f.err
}

func TestMaterializeProductSpecRewritesIntegrationComponent(t *testing.T) {
	spec := productSpecIntegrationFixture()
	product := model.ManifestReference{
		ID:        uuid.New(),
		Kind:      "product",
		Namespace: "global",
		Name:      "rabbitmq-on-kubernetes-platform",
		Version:   1,
	}

	materialized, components, err := MaterializeProductSpec(context.Background(), product, spec, fakeProductGenerator{
		output: GenerateProductComponentOutput{
			Objects: []map[string]any{
				{
					"apiVersion": "v1",
					"kind":       "Namespace",
					"metadata": map[string]any{
						"name": "rabbitmq-system",
					},
				},
			},
			Trace: model.ProductMaterializationComponent{
				Metadata: map[string]any{
					"generator": "rabbitmq",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("MaterializeProductSpec error: %v", err)
	}

	if materialized.Components[0].Source.Kind != "inline" {
		t.Fatalf("expected component source to be rewritten to inline, got %q", materialized.Components[0].Source.Kind)
	}
	if len(materialized.Components[0].Source.Objects) != 1 {
		t.Fatalf("expected generated objects to be materialized, got %#v", materialized.Components[0].Source.Objects)
	}
	if len(components) != 1 {
		t.Fatalf("expected one materialized component trace, got %#v", components)
	}
	if components[0].SourceKind != "integration" || components[0].ResolvedSourceKind != "inline" {
		t.Fatalf("unexpected component trace %#v", components[0])
	}
	if components[0].Operation != "generate_installation" {
		t.Fatalf("unexpected component operation %#v", components[0].Operation)
	}
	if components[0].Capability != "generate_installation" {
		t.Fatalf("unexpected component capability %#v", components[0].Capability)
	}
}

func TestMaterializeProductSpecRejectsEmptyGeneratedObjects(t *testing.T) {
	spec := productSpecIntegrationFixture()
	product := model.ManifestReference{
		ID:        uuid.New(),
		Kind:      "product",
		Namespace: "global",
		Name:      "rabbitmq-on-kubernetes-platform",
		Version:   1,
	}

	_, _, err := MaterializeProductSpec(context.Background(), product, spec, fakeProductGenerator{})
	if err == nil {
		t.Fatal("expected empty generated objects to fail materialization")
	}
}
