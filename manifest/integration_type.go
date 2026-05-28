package manifest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var (
	supportedIntegrationCapabilities = []string{
		"describe",
		"discover",
		"read",
		"execute",
		"sync",
		"health",
	}
	supportedIntegrationTransports     = []string{"rabbitmq", "http_json"}
	supportedIntegrationSchemaModes    = []string{"none", "inline", "secret_ref"}
	supportedCredentialPolicySources   = []string{"none", "inline", "secret_ref", "inline_or_secret_ref"}
	supportedGuardianSupportModes      = []string{"none", "light", "full"}
	supportedIntegrationSchemaTypes    = []string{"string", "number", "integer", "boolean", "object", "array"}
	supportedIntegrationDiscoveryModes = []string{"pull", "push", "hybrid"}
	supportedIntegrationCursorModes    = []string{"none", "full", "incremental"}
	// Closed enum codified in INTEGRATION_CONTRACT §17. Drives the
	// purpose-based grouping in /ops/integrations and equivalent
	// surfaces. Empty domain is accepted in Phase A (the consumer
	// falls back to "platform"); Phase B will hard-fail.
	supportedIntegrationDomains = []string{
		"identity",
		"payments",
		"observability",
		"infrastructure",
		"data",
		"platform",
	}
	integrationNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]*$`)
)

// ParseIntegrationTypeSpec parses the raw spec payload into the typed integration type manifest.
func ParseIntegrationTypeSpec(raw json.RawMessage) (model.IntegrationTypeManifestSpec, error) {
	var spec model.IntegrationTypeManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.IntegrationTypeManifestSpec{}, fmt.Errorf("parse integration_type spec: %w", err)
	}
	return spec, nil
}

// ValidateIntegrationTypeSpec validates the adapter contract exposed through an integration_type manifest.
func ValidateIntegrationTypeSpec(spec model.IntegrationTypeManifestSpec) error {
	provider := normalizeIntegrationName(spec.Provider)
	if provider == "" {
		return fmt.Errorf("integration_type provider is required")
	}
	if !integrationNamePattern.MatchString(provider) {
		return fmt.Errorf("integration_type provider %q is invalid", spec.Provider)
	}

	// Domain is optional in Phase A — empty falls back to "platform"
	// on the client. When declared it MUST match the closed enum
	// (INTEGRATION_CONTRACT §17). Phase B will reject empty too.
	if domain := strings.TrimSpace(spec.Domain); domain != "" {
		if !slices.Contains(supportedIntegrationDomains, domain) {
			return fmt.Errorf(
				"integration_type domain %q is invalid; expected one of %v",
				spec.Domain, supportedIntegrationDomains,
			)
		}
	}

	// Dashboard is optional; when present URL must be non-empty (label
	// defaults to "Abrir <provider>" on the client when missing).
	if spec.Dashboard != nil {
		if strings.TrimSpace(spec.Dashboard.URL) == "" {
			return fmt.Errorf("integration_type dashboard.url is required when dashboard is declared")
		}
		if !strings.HasPrefix(spec.Dashboard.URL, "https://") &&
			!strings.HasPrefix(spec.Dashboard.URL, "http://") {
			return fmt.Errorf(
				"integration_type dashboard.url %q must be an http(s) URL",
				spec.Dashboard.URL,
			)
		}
	}

	if spec.FamilyRef != nil {
		if err := validateManifestSelector("integration_type family_ref", *spec.FamilyRef); err != nil {
			return err
		}
		if len(spec.ImplementedOperations) == 0 {
			return fmt.Errorf("integration_type with family_ref must declare implemented_operations")
		}
		if err := validateNamedStringList("integration_type implemented_operations", spec.ImplementedOperations); err != nil {
			return err
		}
	} else if len(spec.ImplementedOperations) > 0 {
		return fmt.Errorf("integration_type implemented_operations requires family_ref to be set")
	}

	if err := validateIntegrationAdapter(spec.Adapter, spec.Capabilities); err != nil {
		return err
	}
	if err := validateIntegrationCapabilities(spec.Capabilities); err != nil {
		return err
	}
	if err := ValidateIntegrationCredentialPolicy(spec.CredentialPolicy, spec.CredentialSchema); err != nil {
		return err
	}
	if err := validateIntegrationGuardianSupport(spec.GuardianSupport); err != nil {
		return err
	}
	if err := validateIntegrationSchema("credential_schema", spec.CredentialSchema); err != nil {
		return err
	}
	if err := validateIntegrationSchema("instance_schema", spec.InstanceSchema); err != nil {
		return err
	}
	if err := validateIntegrationResourceTypes(spec.ResourceTypes); err != nil {
		return err
	}
	if err := validateIntegrationActionCatalog(spec.ActionCatalog, spec.ResourceTypes); err != nil {
		return err
	}
	if err := validateIntegrationDiscovery(spec.Discovery); err != nil {
		return err
	}
	if err := validateIntegrationNormalization(spec.Normalization); err != nil {
		return err
	}
	if err := validateIntegrationExecution(spec.Execution, spec.ActionCatalog, spec.ResourceTypes, spec.Extensions); err != nil {
		return err
	}

	return nil
}

func validateIntegrationGuardianSupport(spec model.IntegrationGuardianSupportSpec) error {
	spec = NormalizeIntegrationGuardianSupport(spec)
	if !slices.Contains(supportedGuardianSupportModes, spec.Mode) {
		return fmt.Errorf("integration_type guardian_support mode %q is unsupported", spec.Mode)
	}

	for label, values := range integrationGuardianSignalGroups(spec.Signals) {
		if err := validateGuardianSignalKeys(label, values); err != nil {
			return err
		}
	}

	return nil
}

// NormalizeIntegrationGuardianSupport applies compatibility defaults to
// guardian support blocks that are owned by the core rather than the adapter.
func NormalizeIntegrationGuardianSupport(spec model.IntegrationGuardianSupportSpec) model.IntegrationGuardianSupportSpec {
	spec.Mode = strings.ToLower(strings.TrimSpace(spec.Mode))
	if spec.Mode == "" {
		if len(integrationGuardianSignalGroups(spec.Signals)) == 0 {
			spec.Mode = "none"
		} else {
			spec.Mode = "light"
		}
	}
	spec.Signals = normalizeIntegrationGuardianSignals(spec.Signals)
	return spec
}

// NormalizeIntegrationCredentialPolicy applies compatibility defaults to an integration credential policy.
func NormalizeIntegrationCredentialPolicy(policy model.IntegrationCredentialPolicySpec, schema model.IntegrationSchemaSpec) model.IntegrationCredentialPolicySpec {
	policy.Source = strings.ToLower(strings.TrimSpace(policy.Source))
	if policy.Source == "" {
		switch strings.ToLower(strings.TrimSpace(schema.Mode)) {
		case "none":
			policy.Source = "none"
		default:
			policy.Source = "inline_or_secret_ref"
		}
	}
	return policy
}

// ValidateIntegrationCredentialPolicy validates one integration_type credential policy.
func ValidateIntegrationCredentialPolicy(policy model.IntegrationCredentialPolicySpec, schema model.IntegrationSchemaSpec) error {
	policy = NormalizeIntegrationCredentialPolicy(policy, schema)
	if !slices.Contains(supportedCredentialPolicySources, policy.Source) {
		return fmt.Errorf("integration_type credential_policy source %q is unsupported", policy.Source)
	}

	schemaMode := strings.ToLower(strings.TrimSpace(schema.Mode))
	if schemaMode == "" {
		schemaMode = "none"
	}
	if policy.Source == "none" && schemaMode != "none" {
		return fmt.Errorf("integration_type credential_policy source %q requires credential_schema mode \"none\"", policy.Source)
	}
	if schemaMode == "none" && policy.Source != "none" {
		return fmt.Errorf("integration_type credential_schema mode %q requires credential_policy source \"none\"", schema.Mode)
	}
	if policy.MaterializeInline && policy.Source == "none" {
		return fmt.Errorf("integration_type credential_policy cannot materialize inline credentials when source is none")
	}
	if policy.MaterializeInline && policy.Source == "inline" {
		return fmt.Errorf("integration_type credential_policy cannot materialize inline credentials when source is inline")
	}

	return nil
}

func normalizeIntegrationGuardianSignals(signals model.IntegrationGuardianSignalSupportSpec) model.IntegrationGuardianSignalSupportSpec {
	signals.OOMKilled = normalizeGuardianSignalKeys(signals.OOMKilled)
	signals.RestartCount = normalizeGuardianSignalKeys(signals.RestartCount)
	signals.ErrorRate = normalizeGuardianSignalKeys(signals.ErrorRate)
	signals.QueueBacklog = normalizeGuardianSignalKeys(signals.QueueBacklog)
	signals.MemoryPressure = normalizeGuardianSignalKeys(signals.MemoryPressure)
	signals.DiskPressure = normalizeGuardianSignalKeys(signals.DiskPressure)
	signals.RateLimited = normalizeGuardianSignalKeys(signals.RateLimited)
	signals.AuthDenied = normalizeGuardianSignalKeys(signals.AuthDenied)
	signals.SyncLagSeconds = normalizeGuardianSignalKeys(signals.SyncLagSeconds)
	signals.MonthlyCostUSD = normalizeGuardianSignalKeys(signals.MonthlyCostUSD)
	signals.Utilization = normalizeGuardianSignalKeys(signals.Utilization)
	signals.IdleHours = normalizeGuardianSignalKeys(signals.IdleHours)
	signals.Overprovisioned = normalizeGuardianSignalKeys(signals.Overprovisioned)
	signals.SchedulingFailure = normalizeGuardianSignalKeys(signals.SchedulingFailure)
	signals.InsufficientCPU = normalizeGuardianSignalKeys(signals.InsufficientCPU)
	return signals
}

func normalizeGuardianSignalKeys(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		key := normalizeIntegrationName(value)
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, key)
	}
	return normalized
}

func validateGuardianSignalKeys(label string, values []string) error {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = normalizeIntegrationName(value)
		if value == "" {
			return fmt.Errorf("integration_type guardian_support %s cannot contain empty values", label)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("integration_type guardian_support %s key %q is duplicated", label, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func integrationGuardianSignalGroups(signals model.IntegrationGuardianSignalSupportSpec) map[string][]string {
	groups := map[string][]string{}
	add := func(label string, values []string) {
		if len(values) > 0 {
			groups[label] = values
		}
	}
	add("oom_killed", signals.OOMKilled)
	add("restart_count", signals.RestartCount)
	add("error_rate", signals.ErrorRate)
	add("queue_backlog", signals.QueueBacklog)
	add("memory_pressure", signals.MemoryPressure)
	add("disk_pressure", signals.DiskPressure)
	add("rate_limited", signals.RateLimited)
	add("auth_denied", signals.AuthDenied)
	add("sync_lag_seconds", signals.SyncLagSeconds)
	add("monthly_cost_usd", signals.MonthlyCostUSD)
	add("utilization", signals.Utilization)
	add("idle_hours", signals.IdleHours)
	add("overprovisioned", signals.Overprovisioned)
	add("scheduling_failure", signals.SchedulingFailure)
	add("insufficient_cpu", signals.InsufficientCPU)
	return groups
}

func validateIntegrationAdapter(adapter model.IntegrationAdapterSpec, capabilities []string) error {
	transport := strings.ToLower(strings.TrimSpace(adapter.Transport))
	if !slices.Contains(supportedIntegrationTransports, transport) {
		return fmt.Errorf("integration_type adapter transport %q is unsupported", adapter.Transport)
	}

	if strings.TrimSpace(adapter.Version) == "" {
		return fmt.Errorf("integration_type adapter version is required")
	}
	if adapter.TimeoutSeconds <= 0 {
		return fmt.Errorf("integration_type adapter timeout_seconds must be greater than zero")
	}

	queues := map[string]string{
		"describe": strings.TrimSpace(adapter.Queues.Describe),
		"discover": strings.TrimSpace(adapter.Queues.Discover),
		"read":     strings.TrimSpace(adapter.Queues.Read),
		"execute":  strings.TrimSpace(adapter.Queues.Execute),
		"sync":     strings.TrimSpace(adapter.Queues.Sync),
		"health":   strings.TrimSpace(adapter.Queues.Health),
	}
	endpoints := map[string]string{
		"describe": strings.TrimSpace(adapter.Endpoints.Describe),
		"discover": strings.TrimSpace(adapter.Endpoints.Discover),
		"read":     strings.TrimSpace(adapter.Endpoints.Read),
		"execute":  strings.TrimSpace(adapter.Endpoints.Execute),
		"sync":     strings.TrimSpace(adapter.Endpoints.Sync),
		"health":   strings.TrimSpace(adapter.Endpoints.Health),
	}

	capabilitySet := toIntegrationNameSet(capabilities)
	for capability := range capabilitySet {
		switch transport {
		case "rabbitmq":
			if queues[capability] == "" {
				return fmt.Errorf("integration_type adapter queue for capability %q is required", capability)
			}
		case "http_json":
			if endpoints[capability] == "" {
				return fmt.Errorf("integration_type adapter endpoint for capability %q is required", capability)
			}
		}
	}

	return nil
}

func validateIntegrationCapabilities(capabilities []string) error {
	if len(capabilities) == 0 {
		return fmt.Errorf("integration_type capabilities require at least one value")
	}

	seen := map[string]struct{}{}
	for _, capability := range capabilities {
		capability = normalizeIntegrationName(capability)
		if capability == "" {
			return fmt.Errorf("integration_type capabilities cannot contain empty values")
		}
		if !slices.Contains(supportedIntegrationCapabilities, capability) {
			return fmt.Errorf("integration_type capability %q is unsupported", capability)
		}
		if _, exists := seen[capability]; exists {
			return fmt.Errorf("integration_type capability %q is duplicated", capability)
		}
		seen[capability] = struct{}{}
	}

	if _, hasDescribe := seen["describe"]; !hasDescribe {
		return fmt.Errorf("integration_type capabilities must include describe")
	}

	return nil
}

func validateIntegrationSchema(label string, schema model.IntegrationSchemaSpec) error {
	mode := strings.ToLower(strings.TrimSpace(schema.Mode))
	if !slices.Contains(supportedIntegrationSchemaModes, mode) {
		return fmt.Errorf("integration_type %s mode %q is unsupported", label, schema.Mode)
	}

	requiredSeen := map[string]struct{}{}
	for _, field := range schema.Required {
		field = normalizeIntegrationName(field)
		if field == "" {
			return fmt.Errorf("integration_type %s required cannot contain empty values", label)
		}
		if _, exists := requiredSeen[field]; exists {
			return fmt.Errorf("integration_type %s required field %q is duplicated", label, field)
		}
		requiredSeen[field] = struct{}{}
	}

	for name, property := range schema.Properties {
		normalizedName := normalizeIntegrationName(name)
		if normalizedName == "" {
			return fmt.Errorf("integration_type %s property name is required", label)
		}
		propertyType := strings.ToLower(strings.TrimSpace(property.Type))
		if !slices.Contains(supportedIntegrationSchemaTypes, propertyType) {
			return fmt.Errorf("integration_type %s property %q has unsupported type %q", label, name, property.Type)
		}
	}

	if len(schema.Properties) > 0 {
		for field := range requiredSeen {
			if _, exists := schema.Properties[field]; !exists {
				return fmt.Errorf("integration_type %s required field %q must exist in properties", label, field)
			}
		}
	}

	return nil
}

func validateIntegrationResourceTypes(resourceTypes []model.IntegrationResourceType) error {
	if len(resourceTypes) == 0 {
		return fmt.Errorf("integration_type resource_types require at least one value")
	}

	seen := map[string]struct{}{}
	for _, resourceType := range resourceTypes {
		name := normalizeIntegrationName(resourceType.Name)
		if name == "" {
			return fmt.Errorf("integration_type resource_type name is required")
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("integration_type resource_type %q is duplicated", name)
		}
		seen[name] = struct{}{}

		if strings.TrimSpace(resourceType.CanonicalPrefix) == "" {
			return fmt.Errorf("integration_type resource_type %q canonical_prefix is required", name)
		}
		if strings.TrimSpace(resourceType.IdentityTemplate) == "" {
			return fmt.Errorf("integration_type resource_type %q identity_template is required", name)
		}
		if len(resourceType.DefaultActions) == 0 {
			return fmt.Errorf("integration_type resource_type %q default_actions require at least one value", name)
		}

		actionSeen := map[string]struct{}{}
		for _, action := range resourceType.DefaultActions {
			action = normalizeIntegrationName(action)
			if action == "" {
				return fmt.Errorf("integration_type resource_type %q default_actions cannot contain empty values", name)
			}
			if _, exists := actionSeen[action]; exists {
				return fmt.Errorf("integration_type resource_type %q default action %q is duplicated", name, action)
			}
			actionSeen[action] = struct{}{}
		}
	}

	return nil
}

func validateIntegrationActionCatalog(actions []model.IntegrationActionDefinition, resourceTypes []model.IntegrationResourceType) error {
	if len(actions) == 0 {
		return nil
	}

	resourceTypeNames := map[string]struct{}{}
	for _, resourceType := range resourceTypes {
		resourceTypeNames[normalizeIntegrationName(resourceType.Name)] = struct{}{}
	}

	seen := map[string]struct{}{}
	for _, action := range actions {
		name := normalizeIntegrationName(action.Name)
		if name == "" {
			return fmt.Errorf("integration_type action_catalog name is required")
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("integration_type action_catalog action %q is duplicated", name)
		}
		seen[name] = struct{}{}

		resourceSet := map[string]struct{}{}
		for _, resourceType := range action.ResourceTypes {
			resourceType = normalizeIntegrationName(resourceType)
			if resourceType == "" {
				return fmt.Errorf("integration_type action_catalog action %q contains an empty resource_types value", name)
			}
			if _, exists := resourceTypeNames[resourceType]; !exists {
				return fmt.Errorf("integration_type action_catalog action %q references unknown resource_type %q", name, resourceType)
			}
			if _, exists := resourceSet[resourceType]; exists {
				return fmt.Errorf("integration_type action_catalog action %q duplicates resource_type %q", name, resourceType)
			}
			resourceSet[resourceType] = struct{}{}
		}
	}

	return nil
}

func validateIntegrationDiscovery(discovery model.IntegrationDiscoverySpec) error {
	mode := strings.ToLower(strings.TrimSpace(discovery.Mode))
	if !slices.Contains(supportedIntegrationDiscoveryModes, mode) {
		return fmt.Errorf("integration_type discovery mode %q is unsupported", discovery.Mode)
	}

	cursor := strings.ToLower(strings.TrimSpace(discovery.Cursor))
	if cursor == "" {
		cursor = "none"
	}
	if !slices.Contains(supportedIntegrationCursorModes, cursor) {
		return fmt.Errorf("integration_type discovery cursor %q is unsupported", discovery.Cursor)
	}
	if (mode == "pull" || mode == "hybrid") && cursor == "none" {
		return fmt.Errorf("integration_type discovery mode %q requires a cursor strategy", mode)
	}

	return nil
}

func validateIntegrationNormalization(normalization model.IntegrationNormalizationSpec) error {
	if strings.TrimSpace(normalization.ExternalIDPath) == "" {
		return fmt.Errorf("integration_type normalization external_id_path is required")
	}
	if strings.TrimSpace(normalization.FallbackResourcePrefix) == "" {
		return fmt.Errorf("integration_type normalization fallback_resource_prefix is required")
	}
	return nil
}

func validateIntegrationExecution(
	execution model.IntegrationExecutionSpec,
	actionCatalog []model.IntegrationActionDefinition,
	resourceTypes []model.IntegrationResourceType,
	extensions model.IntegrationExtensionsSpec,
) error {
	knownActions := map[string]struct{}{}
	for _, action := range actionCatalog {
		knownActions[normalizeIntegrationName(action.Name)] = struct{}{}
	}
	for _, resourceType := range resourceTypes {
		for _, action := range resourceType.DefaultActions {
			knownActions[normalizeIntegrationName(action)] = struct{}{}
		}
	}

	seen := map[string]struct{}{}
	for _, action := range execution.IdempotentActions {
		action = normalizeIntegrationName(action)
		if action == "" {
			return fmt.Errorf("integration_type execution idempotent_actions cannot contain empty values")
		}
		if _, exists := seen[action]; exists {
			return fmt.Errorf("integration_type execution idempotent action %q is duplicated", action)
		}
		seen[action] = struct{}{}

		if _, exists := knownActions[action]; !exists && !extensions.AllowCustomActions {
			return fmt.Errorf("integration_type execution idempotent action %q is unknown", action)
		}
	}

	return nil
}

func normalizeIntegrationName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func toIntegrationNameSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = normalizeIntegrationName(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	return set
}
