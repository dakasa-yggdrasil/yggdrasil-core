package manifest

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var (
	supportedProductSourceKinds           = []string{"inline", "git", "oci", "integration"}
	supportedProductRendererKinds         = []string{"raw_k8s", "kustomize", "helm"}
	supportedProductTargetKinds           = []string{"kubernetes"}
	supportedProductStages                = []string{"draft", "development", "staging", "production", "retired"}
	supportedProductStrategies            = []string{"apply", "sync"}
	supportedProductIntegrationOperations = []string{"generate_installation"}
	supportedProductRequirementKinds      = []string{"product", "integration_instance", "resource"}
	supportedProductRequirementStates     = []string{"declared", "active", "materialized"}
	supportedProductRequirementPolicies   = []string{"must_exist", "install_if_missing", "optional"}
)

// ParseProductSpec parses the raw spec payload into the typed product manifest.
func ParseProductSpec(raw json.RawMessage) (model.ProductManifestSpec, error) {
	var spec model.ProductManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.ProductManifestSpec{}, fmt.Errorf("parse product spec: %w", err)
	}
	return spec, nil
}

// ValidateProductSpec validates one product manifest.
func ValidateProductSpec(spec model.ProductManifestSpec) error {
	category := normalizeIntegrationName(spec.Category)
	if category == "" {
		return fmt.Errorf("product category is required")
	}
	if !integrationNamePattern.MatchString(category) {
		return fmt.Errorf("product category %q is invalid", spec.Category)
	}

	class := normalizeIntegrationName(spec.Class)
	if class == "" {
		return fmt.Errorf("product class is required")
	}
	if !integrationNamePattern.MatchString(class) {
		return fmt.Errorf("product class %q is invalid", spec.Class)
	}

	if err := validateNamedStringList("product owners", spec.Owners); err != nil {
		return err
	}
	if err := validateProductLifecycle(spec.Lifecycle); err != nil {
		return err
	}
	if err := validateNamedStringList("product dependencies", spec.Dependencies); err != nil {
		return err
	}
	if len(spec.Components) == 0 {
		return fmt.Errorf("product components require at least one value")
	}

	componentNames := map[string]struct{}{}
	for _, component := range spec.Components {
		name := normalizeIntegrationName(component.Name)
		if name == "" {
			return fmt.Errorf("product component name is required")
		}
		if _, exists := componentNames[name]; exists {
			return fmt.Errorf("product component %q is duplicated", name)
		}
		componentNames[name] = struct{}{}

		if err := validateProductSource(component.Source); err != nil {
			return fmt.Errorf("product component %q source: %w", name, err)
		}
		if err := validateProductRenderer(component.Source, component.Renderer); err != nil {
			return fmt.Errorf("product component %q renderer: %w", name, err)
		}
		if err := validateProductTarget(component.Target); err != nil {
			return fmt.Errorf("product component %q target: %w", name, err)
		}
		if err := validateProductReconcile(component.Reconcile); err != nil {
			return fmt.Errorf("product component %q reconcile: %w", name, err)
		}
		if err := validateProductRequirements(component.Requires); err != nil {
			return fmt.Errorf("product component %q requires: %w", name, err)
		}
		if err := validateNamedStringList("product component depends_on", component.DependsOn); err != nil {
			return fmt.Errorf("product component %q: %w", name, err)
		}
	}

	for _, component := range spec.Components {
		name := normalizeIntegrationName(component.Name)
		for _, dependency := range component.DependsOn {
			dependency = normalizeIntegrationName(dependency)
			if _, exists := componentNames[dependency]; !exists {
				return fmt.Errorf("product component %q depends_on unknown component %q", name, dependency)
			}
			if dependency == name {
				return fmt.Errorf("product component %q cannot depend on itself", name)
			}
		}
	}

	return nil
}

func validateProductRequirements(requirements []model.ProductRequirementSpec) error {
	seen := map[string]struct{}{}
	for _, requirement := range requirements {
		kind := NormalizeProductRequirementKind(requirement.Kind)
		if !slices.Contains(supportedProductRequirementKinds, kind) {
			return fmt.Errorf("requirement kind %q is unsupported", requirement.Kind)
		}

		if err := validateManifestSelector("product requirement selector", requirement.Selector); err != nil {
			return err
		}

		state := NormalizeProductRequirementState(requirement)
		if !slices.Contains(supportedProductRequirementStates, state) {
			return fmt.Errorf("requirement state %q is unsupported", requirement.State)
		}

		policy := NormalizeProductRequirementPolicy(requirement)
		if !slices.Contains(supportedProductRequirementPolicies, policy) {
			return fmt.Errorf("requirement policy %q is unsupported", requirement.Policy)
		}

		key := fmt.Sprintf("%s:%s:%s:%d:%s:%s", kind, requirement.Selector.Namespace, requirement.Selector.Name, selectorVersionValue(requirement.Selector.Version), state, policy)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("requirement %q is duplicated", key)
		}
		seen[key] = struct{}{}
	}

	return nil
}

func validateProductLifecycle(lifecycle model.ProductLifecycleSpec) error {
	if strings.TrimSpace(lifecycle.Tier) != "" {
		tier := normalizeIntegrationName(lifecycle.Tier)
		if !integrationNamePattern.MatchString(tier) {
			return fmt.Errorf("product lifecycle tier %q is invalid", lifecycle.Tier)
		}
	}

	if strings.TrimSpace(lifecycle.Stage) != "" {
		stage := strings.ToLower(strings.TrimSpace(lifecycle.Stage))
		if !slices.Contains(supportedProductStages, stage) {
			return fmt.Errorf("product lifecycle stage %q is unsupported", lifecycle.Stage)
		}
	}

	return nil
}

func validateProductSource(source model.ProductSourceSpec) error {
	kind := strings.ToLower(strings.TrimSpace(source.Kind))
	if !slices.Contains(supportedProductSourceKinds, kind) {
		return fmt.Errorf("source kind %q is unsupported", source.Kind)
	}

	switch kind {
	case "inline":
		if source.IntegrationInstanceRef != nil || strings.TrimSpace(source.Operation) != "" || strings.TrimSpace(source.Capability) != "" || len(source.Input) > 0 || strings.TrimSpace(source.Locator) != "" || strings.TrimSpace(source.Revision) != "" || strings.TrimSpace(source.Version) != "" {
			return fmt.Errorf("inline source cannot define integration refs, operation, capability, input, locator, revision, or version")
		}
		if len(source.Objects) == 0 {
			return fmt.Errorf("inline source requires at least one object")
		}
		for index, object := range source.Objects {
			if len(object) == 0 {
				return fmt.Errorf("inline source object %d cannot be empty", index)
			}
			if strings.TrimSpace(asString(object["apiVersion"])) == "" {
				return fmt.Errorf("inline source object %d requires apiVersion", index)
			}
			if strings.TrimSpace(asString(object["kind"])) == "" {
				return fmt.Errorf("inline source object %d requires kind", index)
			}
		}
	case "git":
		if source.IntegrationInstanceRef == nil {
			return fmt.Errorf("git source requires integration_instance_ref")
		}
		if err := validateManifestSelector("product source integration_instance_ref", *source.IntegrationInstanceRef); err != nil {
			return err
		}
		if strings.TrimSpace(source.Operation) != "" || strings.TrimSpace(source.Capability) != "" || len(source.Input) > 0 {
			return fmt.Errorf("git source cannot define operation, capability, or input")
		}
		if strings.TrimSpace(source.Locator) == "" {
			return fmt.Errorf("git source requires locator")
		}
		if strings.TrimSpace(source.Revision) == "" {
			return fmt.Errorf("git source requires revision")
		}
		if strings.TrimSpace(source.Version) != "" {
			return fmt.Errorf("git source cannot define version")
		}
		if len(source.Objects) > 0 {
			return fmt.Errorf("git source cannot define inline objects")
		}
	case "oci":
		if source.IntegrationInstanceRef == nil {
			return fmt.Errorf("oci source requires integration_instance_ref")
		}
		if err := validateManifestSelector("product source integration_instance_ref", *source.IntegrationInstanceRef); err != nil {
			return err
		}
		if strings.TrimSpace(source.Operation) != "" || strings.TrimSpace(source.Capability) != "" || len(source.Input) > 0 {
			return fmt.Errorf("oci source cannot define operation, capability, or input")
		}
		if strings.TrimSpace(source.Locator) == "" {
			return fmt.Errorf("oci source requires locator")
		}
		if strings.TrimSpace(source.Version) == "" {
			return fmt.Errorf("oci source requires version")
		}
		if strings.TrimSpace(source.Revision) != "" {
			return fmt.Errorf("oci source cannot define revision")
		}
		if len(source.Objects) > 0 {
			return fmt.Errorf("oci source cannot define inline objects")
		}
	case "integration":
		if source.IntegrationInstanceRef == nil {
			return fmt.Errorf("integration source requires integration_instance_ref")
		}
		if err := validateManifestSelector("product source integration_instance_ref", *source.IntegrationInstanceRef); err != nil {
			return err
		}

		operation := NormalizeProductSourceOperation(source)
		if operation == "" {
			return fmt.Errorf("integration source requires operation")
		}
		if !slices.Contains(supportedProductIntegrationOperations, operation) {
			return fmt.Errorf("integration source operation %q is unsupported", source.Operation)
		}

		capability := normalizeIntegrationName(source.Capability)
		if capability != "" && !integrationNamePattern.MatchString(capability) {
			return fmt.Errorf("integration source capability %q is invalid", source.Capability)
		}
		if err := validateLooseObject("product source input", source.Input); err != nil {
			return err
		}
		if strings.TrimSpace(source.Locator) != "" || strings.TrimSpace(source.Revision) != "" || strings.TrimSpace(source.Version) != "" {
			return fmt.Errorf("integration source cannot define locator, revision, or version")
		}
		if len(source.Objects) > 0 {
			return fmt.Errorf("integration source cannot define inline objects")
		}
	}

	return nil
}

// NormalizeProductSourceOperation returns the normalized integration operation, defaulting to installation generation.
func NormalizeProductSourceOperation(source model.ProductSourceSpec) string {
	if strings.ToLower(strings.TrimSpace(source.Kind)) != "integration" {
		return strings.ToLower(strings.TrimSpace(source.Operation))
	}

	operation := strings.ToLower(strings.TrimSpace(source.Operation))
	if operation == "" {
		return "generate_installation"
	}
	return operation
}

// NormalizeProductSourceCapability returns the normalized integration capability, defaulting to the operation when omitted.
func NormalizeProductSourceCapability(source model.ProductSourceSpec) string {
	capability := normalizeIntegrationName(source.Capability)
	if capability != "" {
		return capability
	}
	return NormalizeProductSourceOperation(source)
}

// NormalizeProductRequirementKind returns the normalized requirement kind.
func NormalizeProductRequirementKind(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// NormalizeProductRequirementPolicy returns the normalized requirement policy with a default.
func NormalizeProductRequirementPolicy(requirement model.ProductRequirementSpec) string {
	policy := strings.ToLower(strings.TrimSpace(requirement.Policy))
	if policy == "" {
		return "must_exist"
	}
	return policy
}

// NormalizeProductRequirementState returns the normalized requirement state with policy-aware defaults.
func NormalizeProductRequirementState(requirement model.ProductRequirementSpec) string {
	state := strings.ToLower(strings.TrimSpace(requirement.State))
	if state != "" {
		return state
	}

	kind := NormalizeProductRequirementKind(requirement.Kind)
	policy := NormalizeProductRequirementPolicy(requirement)
	if kind == "product" && policy == "install_if_missing" {
		return "materialized"
	}
	if kind == "integration_instance" {
		return "active"
	}
	return "declared"
}

func selectorVersionValue(version *int) int {
	if version == nil {
		return 0
	}
	return *version
}

func validateProductRenderer(source model.ProductSourceSpec, renderer model.ProductRendererSpec) error {
	kind := strings.ToLower(strings.TrimSpace(renderer.Kind))
	if !slices.Contains(supportedProductRendererKinds, kind) {
		return fmt.Errorf("renderer kind %q is unsupported", renderer.Kind)
	}

	switch kind {
	case "raw_k8s":
		if len(renderer.Values) > 0 {
			return fmt.Errorf("raw_k8s renderer cannot define values")
		}

		sourceKind := strings.ToLower(strings.TrimSpace(source.Kind))
		switch sourceKind {
		case "inline":
			if strings.TrimSpace(renderer.Path) != "" || len(renderer.Include) > 0 {
				return fmt.Errorf("raw_k8s renderer with inline source cannot define path or include")
			}
		case "git":
			if strings.TrimSpace(renderer.Path) == "" && len(renderer.Include) == 0 {
				return fmt.Errorf("raw_k8s renderer with git source requires path or include")
			}
		case "integration":
			if strings.TrimSpace(renderer.Path) != "" || len(renderer.Include) > 0 {
				return fmt.Errorf("raw_k8s renderer with integration source cannot define path or include")
			}
		default:
			return fmt.Errorf("raw_k8s renderer does not support source kind %q", source.Kind)
		}
	case "kustomize":
		if len(renderer.Include) > 0 {
			return fmt.Errorf("kustomize renderer cannot define include")
		}
		if len(renderer.Values) > 0 {
			return fmt.Errorf("kustomize renderer cannot define values")
		}

		sourceKind := strings.ToLower(strings.TrimSpace(source.Kind))
		switch sourceKind {
		case "git":
			if strings.TrimSpace(renderer.Path) == "" {
				return fmt.Errorf("kustomize renderer with git source requires path")
			}
		default:
			return fmt.Errorf("kustomize renderer does not support source kind %q", source.Kind)
		}
	case "helm":
		if len(renderer.Include) > 0 {
			return fmt.Errorf("helm renderer cannot define include")
		}
		if err := validateLooseObject("product renderer values", renderer.Values); err != nil {
			return err
		}

		sourceKind := strings.ToLower(strings.TrimSpace(source.Kind))
		switch sourceKind {
		case "git":
			if strings.TrimSpace(renderer.Path) == "" {
				return fmt.Errorf("helm renderer with git source requires path")
			}
		case "oci":
			if strings.TrimSpace(renderer.Path) != "" {
				return fmt.Errorf("helm renderer with oci source cannot define path")
			}
		default:
			return fmt.Errorf("helm renderer does not support source kind %q", source.Kind)
		}
	}

	return nil
}

func validateProductTarget(target model.ProductTargetSpec) error {
	kind := strings.ToLower(strings.TrimSpace(target.Kind))
	if !slices.Contains(supportedProductTargetKinds, kind) {
		return fmt.Errorf("target kind %q is unsupported", target.Kind)
	}

	if err := validateManifestSelector("product target integration_instance_ref", target.IntegrationInstanceRef); err != nil {
		return err
	}

	return nil
}

func validateProductReconcile(reconcile model.ProductReconcileSpec) error {
	strategy := strings.ToLower(strings.TrimSpace(reconcile.Strategy))
	if strategy == "" {
		return nil
	}
	if !slices.Contains(supportedProductStrategies, strategy) {
		return fmt.Errorf("strategy %q is unsupported", reconcile.Strategy)
	}
	return nil
}

func asString(value any) string {
	text, _ := value.(string)
	return text
}
