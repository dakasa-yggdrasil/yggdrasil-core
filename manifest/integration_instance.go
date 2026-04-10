package manifest

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var (
	supportedIntegrationInstanceStatuses       = []string{"draft", "active", "disabled"}
	supportedIntegrationInstanceDiscoveryModes = []string{"manual", "scheduled", "webhook", "hybrid"}
)

// ParseIntegrationInstanceSpec parses the raw spec payload into the typed integration instance manifest.
func ParseIntegrationInstanceSpec(raw json.RawMessage) (model.IntegrationInstanceManifestSpec, error) {
	var spec model.IntegrationInstanceManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.IntegrationInstanceManifestSpec{}, fmt.Errorf("parse integration_instance spec: %w", err)
	}
	return spec, nil
}

// ValidateIntegrationInstanceSpec validates one concrete integration instance manifest.
func ValidateIntegrationInstanceSpec(spec model.IntegrationInstanceManifestSpec) error {
	if err := validateManifestSelector("integration_instance type_ref", spec.TypeRef); err != nil {
		return err
	}

	status := strings.ToLower(strings.TrimSpace(spec.Status))
	if status == "" {
		status = "active"
	}
	if !slices.Contains(supportedIntegrationInstanceStatuses, status) {
		return fmt.Errorf("integration_instance status %q is unsupported", spec.Status)
	}

	if err := validateNamedStringList("integration_instance owners", spec.Owners); err != nil {
		return err
	}
	if strings.TrimSpace(spec.CredentialsRef) != "" {
		if !strings.HasPrefix(strings.TrimSpace(spec.CredentialsRef), "secret://") {
			return fmt.Errorf("integration_instance credentials_ref must use secret:// references")
		}
	}
	if err := validateLooseObject("integration_instance credentials", spec.Credentials); err != nil {
		return err
	}
	if err := validateLooseObject("integration_instance config", spec.Config); err != nil {
		return err
	}
	if err := validateIntegrationInstanceDiscovery(spec.Discovery); err != nil {
		return err
	}
	if err := validateIntegrationInstanceExecution(spec.Execution); err != nil {
		return err
	}

	return nil
}

func validateIntegrationInstanceDiscovery(discovery model.IntegrationInstanceDiscoverySpec) error {
	mode := strings.ToLower(strings.TrimSpace(discovery.Mode))
	if mode == "" {
		mode = "manual"
	}
	if !slices.Contains(supportedIntegrationInstanceDiscoveryModes, mode) {
		return fmt.Errorf("integration_instance discovery mode %q is unsupported", discovery.Mode)
	}

	if discovery.SyncIntervalSeconds < 0 {
		return fmt.Errorf("integration_instance discovery sync_interval_seconds cannot be negative")
	}
	if discovery.Enabled && (mode == "scheduled" || mode == "hybrid") && discovery.SyncIntervalSeconds <= 0 {
		return fmt.Errorf("integration_instance discovery mode %q requires sync_interval_seconds when enabled", mode)
	}

	return nil
}

func validateIntegrationInstanceExecution(execution model.IntegrationInstanceExecutionSpec) error {
	if execution.MaxBatchSize < 0 {
		return fmt.Errorf("integration_instance execution max_batch_size cannot be negative")
	}
	return nil
}

func validateManifestSelector(label string, selector model.ManifestSelector) error {
	if strings.TrimSpace(selector.ManifestID) == "" && strings.TrimSpace(selector.Name) == "" {
		return fmt.Errorf("%s requires manifest_id or name", label)
	}
	if selector.Version != nil && *selector.Version <= 0 {
		return fmt.Errorf("%s version must be greater than zero", label)
	}
	return nil
}

func validateNamedStringList(label string, values []string) error {
	seen := map[string]struct{}{}
	for _, value := range values {
		normalized := normalizeIntegrationName(value)
		if normalized == "" {
			return fmt.Errorf("%s cannot contain empty values", label)
		}
		if !integrationNamePattern.MatchString(normalized) {
			return fmt.Errorf("%s value %q is invalid", label, value)
		}
		if _, exists := seen[normalized]; exists {
			return fmt.Errorf("%s value %q is duplicated", label, normalized)
		}
		seen[normalized] = struct{}{}
	}

	return nil
}

func validateLooseObject(label string, input map[string]any) error {
	for key := range input {
		normalized := normalizeIntegrationName(key)
		if normalized == "" {
			return fmt.Errorf("%s cannot contain empty keys", label)
		}
	}
	return nil
}
