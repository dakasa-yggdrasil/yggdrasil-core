package manifest

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ValidateIntegrationInstanceCredentialStorage validates how one integration_instance stores credentials against integration_type policy.
func ValidateIntegrationInstanceCredentialStorage(spec model.IntegrationInstanceManifestSpec, typeSpec model.IntegrationTypeManifestSpec) error {
	policy := NormalizeIntegrationCredentialPolicy(typeSpec.CredentialPolicy, typeSpec.CredentialSchema)
	hasInline := len(spec.Credentials) > 0
	hasRef := strings.TrimSpace(spec.CredentialsRef) != ""

	switch policy.Source {
	case "none":
		if hasInline || hasRef {
			return fmt.Errorf("integration_instance cannot define credentials for this integration_type")
		}
	case "inline":
		if hasRef {
			return fmt.Errorf("integration_instance must not use credentials_ref for this integration_type")
		}
	case "secret_ref":
		if hasInline {
			return fmt.Errorf("integration_instance must store credentials through credentials_ref for this integration_type")
		}
		if !hasRef {
			return fmt.Errorf("integration_instance credentials_ref is required for this integration_type")
		}
	case "inline_or_secret_ref":
		if hasInline && hasRef {
			return fmt.Errorf("integration_instance must use either credentials or credentials_ref, not both")
		}
	}

	return nil
}

// ValidateHydratedIntegrationInstanceInputs validates resolved credentials and config against one integration_type contract.
func ValidateHydratedIntegrationInstanceInputs(spec model.IntegrationInstanceManifestSpec, typeSpec model.IntegrationTypeManifestSpec) error {
	if err := ValidateIntegrationInputValues("integration credentials", typeSpec.CredentialSchema, spec.Credentials); err != nil {
		return err
	}
	if err := ValidateIntegrationInputValues("integration config", typeSpec.InstanceSchema, spec.Config); err != nil {
		return err
	}
	return nil
}

// ValidateIntegrationInputValues validates one loose object against an integration schema.
func ValidateIntegrationInputValues(label string, schema model.IntegrationSchemaSpec, values map[string]any) error {
	mode := strings.ToLower(strings.TrimSpace(schema.Mode))
	if mode == "" {
		mode = "none"
	}
	if len(values) == 0 {
		values = nil
	}

	normalizedValues := make(map[string]any, len(values))
	for key, value := range values {
		normalized := normalizeIntegrationName(key)
		if normalized == "" {
			return fmt.Errorf("%s cannot contain empty keys", label)
		}
		normalizedValues[normalized] = value
	}
	values = normalizedValues

	switch mode {
	case "none":
		if len(values) > 0 {
			return fmt.Errorf("%s are not supported for this integration_type", label)
		}
		return nil
	case "inline", "secret_ref":
	default:
		return fmt.Errorf("%s schema mode %q is unsupported", label, schema.Mode)
	}

	normalizedProperties := make(map[string]model.IntegrationSchemaProperty, len(schema.Properties))
	for key, property := range schema.Properties {
		normalizedProperties[normalizeIntegrationName(key)] = property
	}

	for _, field := range schema.Required {
		normalized := normalizeIntegrationName(field)
		if _, ok := values[normalized]; !ok {
			return fmt.Errorf("%s required field %q is missing", label, normalized)
		}
	}

	for key, value := range values {
		normalized := normalizeIntegrationName(key)
		property, ok := normalizedProperties[normalized]
		if !ok && len(normalizedProperties) > 0 {
			return fmt.Errorf("%s field %q is not declared in the integration_type schema", label, normalized)
		}
		if ok {
			if err := validateIntegrationSchemaValue(fmt.Sprintf("%s %q", label, normalized), property, value); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateIntegrationSchemaValue(label string, property model.IntegrationSchemaProperty, value any) error {
	switch strings.ToLower(strings.TrimSpace(property.Type)) {
	case "", "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s must be a string", label)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s must be a boolean", label)
		}
	case "integer":
		if !isIntegrationInteger(value) {
			return fmt.Errorf("%s must be an integer", label)
		}
	case "number":
		if !isIntegrationNumber(value) {
			return fmt.Errorf("%s must be a number", label)
		}
	case "object":
		switch value.(type) {
		case map[string]any, map[string]string:
		default:
			return fmt.Errorf("%s must be an object", label)
		}
	case "array":
		if _, ok := value.([]any); !ok {
			return fmt.Errorf("%s must be an array", label)
		}
	default:
		return fmt.Errorf("%s has unsupported type %q", label, property.Type)
	}

	if len(property.Enum) > 0 && !integrationEnumContains(property.Enum, value) {
		return fmt.Errorf("%s must be one of the declared enum values", label)
	}
	return nil
}

func integrationEnumContains(options []any, value any) bool {
	for _, option := range options {
		optionJSON, _ := json.Marshal(option)
		valueJSON, _ := json.Marshal(value)
		if string(optionJSON) == string(valueJSON) {
			return true
		}
	}
	return false
}

func isIntegrationInteger(value any) bool {
	switch typed := value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, json.Number:
		return true
	case float32:
		return math.Mod(float64(typed), 1) == 0
	case float64:
		return math.Mod(typed, 1) == 0
	default:
		return false
	}
}

func isIntegrationNumber(value any) bool {
	switch value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return true
	default:
		return false
	}
}

// EffectiveIntegrationCredentialPolicy returns the normalized policy used by the core.
func EffectiveIntegrationCredentialPolicy(typeSpec model.IntegrationTypeManifestSpec) model.IntegrationCredentialPolicySpec {
	policy := NormalizeIntegrationCredentialPolicy(typeSpec.CredentialPolicy, typeSpec.CredentialSchema)
	if policy.Source != "none" && !policy.MaterializeInline {
		if slices.Contains([]string{"secret_ref", "inline_or_secret_ref"}, policy.Source) {
			policy.MaterializeInline = true
		}
	}
	return policy
}
