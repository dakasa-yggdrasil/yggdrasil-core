package manifest

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var supportedResourceSourceKinds = []string{"core", "integration"}

// ParseResourceSpec parses the raw spec payload into the typed resource manifest.
func ParseResourceSpec(raw json.RawMessage) (model.ResourceManifestSpec, error) {
	var spec model.ResourceManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.ResourceManifestSpec{}, fmt.Errorf("parse resource spec: %w", err)
	}
	return spec, nil
}

// ValidateResourceSpec validates one canonical resource manifest.
func ValidateResourceSpec(spec model.ResourceManifestSpec) error {
	resource := normalizeIntegrationName(spec.Resource)
	if resource == "" {
		return fmt.Errorf("resource resource is required")
	}
	if !integrationNamePattern.MatchString(resource) {
		return fmt.Errorf("resource resource %q is invalid", spec.Resource)
	}

	resourceType := normalizeIntegrationName(spec.Type)
	if resourceType == "" {
		return fmt.Errorf("resource type is required")
	}
	if !integrationNamePattern.MatchString(resourceType) {
		return fmt.Errorf("resource type %q is invalid", spec.Type)
	}

	if len(spec.Actions) == 0 {
		return fmt.Errorf("resource actions require at least one value")
	}
	if err := validateNamedStringList("resource actions", spec.Actions); err != nil {
		return err
	}
	if err := validateNamedStringList("resource owners", spec.Owners); err != nil {
		return err
	}
	if err := validateLooseObject("resource attributes", spec.Attributes); err != nil {
		return err
	}
	if err := validateLooseObject("resource raw", spec.Raw); err != nil {
		return err
	}
	if err := validateResourceSource(spec.Source); err != nil {
		return err
	}

	return nil
}

func validateResourceSource(source model.ResourceSourceSpec) error {
	kind := strings.ToLower(strings.TrimSpace(source.Kind))
	if !slices.Contains(supportedResourceSourceKinds, kind) {
		return fmt.Errorf("resource source kind %q is unsupported", source.Kind)
	}

	switch kind {
	case "core":
		if source.IntegrationTypeRef != nil || source.IntegrationInstanceRef != nil || strings.TrimSpace(source.ExternalID) != "" {
			return fmt.Errorf("resource source kind core cannot define integration refs or external_id")
		}
	case "integration":
		if source.IntegrationInstanceRef == nil {
			return fmt.Errorf("resource source kind integration requires integration_instance_ref")
		}
		if err := validateManifestSelector("resource source integration_instance_ref", *source.IntegrationInstanceRef); err != nil {
			return err
		}
		if source.IntegrationTypeRef != nil {
			if err := validateManifestSelector("resource source integration_type_ref", *source.IntegrationTypeRef); err != nil {
				return err
			}
		}
		if strings.TrimSpace(source.ExternalID) == "" {
			return fmt.Errorf("resource source kind integration requires external_id")
		}
	}

	return nil
}
