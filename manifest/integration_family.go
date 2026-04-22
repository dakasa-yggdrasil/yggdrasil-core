package manifest

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ParseIntegrationFamilySpec parses the raw spec payload into the typed
// integration_family manifest.
func ParseIntegrationFamilySpec(raw json.RawMessage) (model.IntegrationFamilyManifestSpec, error) {
	var spec model.IntegrationFamilyManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.IntegrationFamilyManifestSpec{}, fmt.Errorf("parse integration_family spec: %w", err)
	}
	return spec, nil
}

// ValidateIntegrationFamilySpec validates one integration_family manifest.
func ValidateIntegrationFamilySpec(spec model.IntegrationFamilyManifestSpec) error {
	if err := validateNamedStringList("integration_family owners", spec.Owners); err != nil {
		return err
	}

	if len(spec.Operations) == 0 {
		return fmt.Errorf("integration_family must declare at least one operation")
	}

	seen := make(map[string]struct{}, len(spec.Operations))
	for _, op := range spec.Operations {
		name := strings.ToLower(strings.TrimSpace(op.Name))
		if name == "" {
			return fmt.Errorf("integration_family operation name cannot be empty")
		}
		if !integrationNamePattern.MatchString(name) {
			return fmt.Errorf("integration_family operation name %q is invalid", op.Name)
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("integration_family operation %q is duplicated", name)
		}
		seen[name] = struct{}{}
	}

	return nil
}
