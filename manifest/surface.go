package manifest

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var (
	supportedSurfaceCategories          = []string{"api", "auth", "console", "bff", "webhook", "gateway"}
	supportedSurfaceRuntimeKinds        = []string{"http_api", "web_ui", "worker", "hybrid"}
	supportedSurfaceExposures           = []string{"internal", "operator", "collaborator", "public"}
	supportedSurfaceIntegrationBindings = []string{"core_only"}
	supportedSurfaceCoreContracts       = []string{"manifest", "authorization", "auth", "topology", "collaborator", "team", "product", "workflow", "integration_catalog", "integration_execute", "surface"}
	supportedSurfaceCapabilityKinds     = []string{"endpoint", "auth_flow", "ui_area", "webhook", "rpc"}
	supportedSurfaceAudiences           = []string{"internal", "operator", "collaborator", "service", "public"}
	supportedSurfaceHTTPMethods         = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
)

// ParseSurfaceSpec parses the raw spec payload into the typed surface manifest.
func ParseSurfaceSpec(raw json.RawMessage) (model.SurfaceManifestSpec, error) {
	var spec model.SurfaceManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.SurfaceManifestSpec{}, fmt.Errorf("parse surface spec: %w", err)
	}
	return spec, nil
}

// ValidateSurfaceSpec validates one surface manifest.
func ValidateSurfaceSpec(spec model.SurfaceManifestSpec) error {
	category := normalizeIntegrationName(spec.Category)
	if category == "" {
		return fmt.Errorf("surface category is required")
	}
	if !slices.Contains(supportedSurfaceCategories, category) {
		return fmt.Errorf("surface category %q is unsupported", spec.Category)
	}

	if err := validateNamedStringList("surface owners", spec.Owners); err != nil {
		return err
	}
	if err := validateNamedStringList("surface replaces", spec.Replaces); err != nil {
		return err
	}

	binding := NormalizeSurfaceIntegrationBinding(spec)
	if !slices.Contains(supportedSurfaceIntegrationBindings, binding) {
		return fmt.Errorf("surface integration_binding %q is unsupported", spec.IntegrationBinding)
	}

	if err := validateSurfaceRuntime(spec.Runtime); err != nil {
		return err
	}
	if err := validateSurfaceCoreContracts(spec.CoreContracts); err != nil {
		return err
	}
	if err := validateSurfaceCapabilities(spec.Capabilities); err != nil {
		return err
	}

	return nil
}

func validateSurfaceRuntime(runtime model.SurfaceRuntimeSpec) error {
	kind := strings.ToLower(strings.TrimSpace(runtime.Kind))
	if !slices.Contains(supportedSurfaceRuntimeKinds, kind) {
		return fmt.Errorf("surface runtime kind %q is unsupported", runtime.Kind)
	}

	exposure := strings.ToLower(strings.TrimSpace(runtime.Exposure))
	if exposure == "" {
		exposure = "internal"
	}
	if !slices.Contains(supportedSurfaceExposures, exposure) {
		return fmt.Errorf("surface runtime exposure %q is unsupported", runtime.Exposure)
	}

	if runtime.Port < 0 || runtime.Port > 65535 {
		return fmt.Errorf("surface runtime port must be between 0 and 65535")
	}
	if slices.Contains([]string{"http_api", "web_ui", "hybrid"}, kind) && runtime.Port <= 0 {
		return fmt.Errorf("surface runtime kind %q requires a positive port", kind)
	}

	if strings.TrimSpace(runtime.BasePath) != "" && !strings.HasPrefix(strings.TrimSpace(runtime.BasePath), "/") {
		return fmt.Errorf("surface runtime base_path must start with /")
	}
	if strings.TrimSpace(runtime.HealthPath) != "" && !strings.HasPrefix(strings.TrimSpace(runtime.HealthPath), "/") {
		return fmt.Errorf("surface runtime health_path must start with /")
	}

	return nil
}

func validateSurfaceCoreContracts(contracts []string) error {
	seen := map[string]struct{}{}
	for _, contract := range contracts {
		contract = normalizeIntegrationName(contract)
		if contract == "" {
			return fmt.Errorf("surface core_contracts cannot contain empty values")
		}
		if !slices.Contains(supportedSurfaceCoreContracts, contract) {
			return fmt.Errorf("surface core_contract %q is unsupported", contract)
		}
		if _, exists := seen[contract]; exists {
			return fmt.Errorf("surface core_contract %q is duplicated", contract)
		}
		seen[contract] = struct{}{}
	}
	return nil
}

func validateSurfaceCapabilities(capabilities []model.SurfaceCapabilitySpec) error {
	seen := map[string]struct{}{}

	for _, capability := range capabilities {
		name := normalizeIntegrationName(capability.Name)
		if name == "" {
			return fmt.Errorf("surface capability name is required")
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("surface capability %q is duplicated", name)
		}
		seen[name] = struct{}{}

		kind := strings.ToLower(strings.TrimSpace(capability.Kind))
		if !slices.Contains(supportedSurfaceCapabilityKinds, kind) {
			return fmt.Errorf("surface capability %q kind %q is unsupported", name, capability.Kind)
		}

		audience := strings.ToLower(strings.TrimSpace(capability.Audience))
		if audience != "" && !slices.Contains(supportedSurfaceAudiences, audience) {
			return fmt.Errorf("surface capability %q audience %q is unsupported", name, capability.Audience)
		}

		if strings.TrimSpace(capability.Path) != "" && !strings.HasPrefix(strings.TrimSpace(capability.Path), "/") {
			return fmt.Errorf("surface capability %q path must start with /", name)
		}

		methodSeen := map[string]struct{}{}
		for _, method := range capability.Methods {
			method = strings.ToUpper(strings.TrimSpace(method))
			if method == "" {
				return fmt.Errorf("surface capability %q methods cannot contain empty values", name)
			}
			if !slices.Contains(supportedSurfaceHTTPMethods, method) {
				return fmt.Errorf("surface capability %q method %q is unsupported", name, method)
			}
			if _, exists := methodSeen[method]; exists {
				return fmt.Errorf("surface capability %q method %q is duplicated", name, method)
			}
			methodSeen[method] = struct{}{}
		}

		if len(capability.Methods) > 0 && !slices.Contains([]string{"endpoint", "webhook"}, kind) {
			return fmt.Errorf("surface capability %q only endpoint/webhook kinds can define methods", name)
		}
		if slices.Contains([]string{"endpoint", "webhook", "ui_area"}, kind) && strings.TrimSpace(capability.Path) == "" {
			return fmt.Errorf("surface capability %q kind %q requires path", name, kind)
		}
	}

	return nil
}

// NormalizeSurfaceIntegrationBinding resolves the default integration binding for a surface.
func NormalizeSurfaceIntegrationBinding(spec model.SurfaceManifestSpec) string {
	binding := strings.ToLower(strings.TrimSpace(spec.IntegrationBinding))
	if binding == "" {
		return "core_only"
	}
	return binding
}
