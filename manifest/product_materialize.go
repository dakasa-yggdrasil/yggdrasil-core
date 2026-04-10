package manifest

import (
	"context"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ProductComponentGenerator generates one integration-backed component into concrete inline objects.
type ProductComponentGenerator interface {
	Generate(ctx context.Context, input GenerateProductComponentInput) (GenerateProductComponentOutput, error)
}

// GenerateProductComponentInput is the context passed to a product component generator.
type GenerateProductComponentInput struct {
	Product   model.ManifestReference
	Category  string
	Class     string
	Component model.ProductComponentSpec
}

// GenerateProductComponentOutput is the generated output returned by one integration-backed component generator.
type GenerateProductComponentOutput struct {
	Objects []map[string]any
	Trace   model.ProductMaterializationComponent
}

// MaterializeProductSpec rewrites integration-backed product components into inline object bundles.
func MaterializeProductSpec(
	ctx context.Context,
	product model.ManifestReference,
	spec model.ProductManifestSpec,
	generator ProductComponentGenerator,
) (model.ProductManifestSpec, []model.ProductMaterializationComponent, error) {
	if generator == nil {
		return model.ProductManifestSpec{}, nil, fmt.Errorf("product component generator is required")
	}

	materialized := spec
	materialized.Components = make([]model.ProductComponentSpec, 0, len(spec.Components))

	var components []model.ProductMaterializationComponent
	for _, component := range spec.Components {
		sourceKind := strings.ToLower(strings.TrimSpace(component.Source.Kind))
		if sourceKind != "integration" {
			materialized.Components = append(materialized.Components, component)
			continue
		}

		output, err := generator.Generate(ctx, GenerateProductComponentInput{
			Product:   product,
			Category:  spec.Category,
			Class:     spec.Class,
			Component: component,
		})
		if err != nil {
			return model.ProductManifestSpec{}, nil, fmt.Errorf("generate product component %q: %w", component.Name, err)
		}
		if len(output.Objects) == 0 {
			return model.ProductManifestSpec{}, nil, fmt.Errorf("generate product component %q: no objects returned", component.Name)
		}

		rewritten := component
		rewritten.Source = model.ProductSourceSpec{
			Kind:    "inline",
			Objects: output.Objects,
		}

		trace := output.Trace
		trace.Name = component.Name
		if strings.TrimSpace(trace.SourceKind) == "" {
			trace.SourceKind = "integration"
		}
		if strings.TrimSpace(trace.ResolvedSourceKind) == "" {
			trace.ResolvedSourceKind = "inline"
		}
		if strings.TrimSpace(trace.Operation) == "" {
			trace.Operation = NormalizeProductSourceOperation(component.Source)
		}
		if strings.TrimSpace(trace.Capability) == "" {
			trace.Capability = NormalizeProductSourceCapability(component.Source)
		}
		if len(trace.Input) == 0 && len(component.Source.Input) > 0 {
			trace.Input = component.Source.Input
		}

		materialized.Components = append(materialized.Components, rewritten)
		components = append(components, trace)
	}

	if err := ValidateProductSpec(materialized); err != nil {
		return model.ProductManifestSpec{}, nil, fmt.Errorf("validate materialized product spec: %w", err)
	}

	return materialized, components, nil
}
