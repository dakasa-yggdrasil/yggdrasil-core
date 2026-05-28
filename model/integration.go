package model

// IntegrationTypeManifestSpec describes one adapter contract supported by Yggdrasil.
//
// When FamilyRef is set, this integration_type acts as one provider implementation
// of the named integration_family contract. The provider must declare which subset
// of the family's operations it covers via ImplementedOperations (or via the
// adapter's describe response). Workflows that target the family + operation pair
// will resolve to this provider when it's the active implementation.
//
// When FamilyRef is empty the type is standalone — the legacy single-implementation
// model with no family contract.
type IntegrationTypeManifestSpec struct {
	Provider              string                          `json:"provider"`
	FamilyRef             *ManifestSelector               `json:"family_ref,omitempty"`
	ImplementedOperations []string                        `json:"implemented_operations,omitempty"`
	// Domain is the business-purpose bucket the adapter belongs to.
	// Drives client-side grouping in /ops/integrations and equivalent
	// surfaces. Closed enum (see INTEGRATION_CONTRACT §17): identity,
	// payments, observability, infrastructure, data, platform.
	// Empty = the surface falls back to "platform" until the adapter
	// declares its own. Validator warns when missing (Phase A) and
	// rejects in Phase B; this lets in-flight adapters land their
	// declaration without breaking registration.
	Domain string `json:"domain,omitempty"`
	// Dashboard points operators at the provider's own management UI
	// when the integration is configured outside Yggdrasil
	// (Stripe / EFI / NFE.io and similar). Optional; absent when the
	// adapter ships its own federated surface or runs purely internal.
	Dashboard             *IntegrationDashboardSpec       `json:"dashboard,omitempty"`
	Adapter               IntegrationAdapterSpec          `json:"adapter"`
	Capabilities          []string                        `json:"capabilities"`
	CredentialPolicy      IntegrationCredentialPolicySpec `json:"credential_policy,omitempty"`
	GuardianSupport  IntegrationGuardianSupportSpec  `json:"guardian_support,omitempty"`
	CredentialSchema IntegrationSchemaSpec           `json:"credential_schema"`
	InstanceSchema   IntegrationSchemaSpec           `json:"instance_schema"`
	ResourceTypes    []IntegrationResourceType       `json:"resource_types"`
	ActionCatalog    []IntegrationActionDefinition   `json:"action_catalog,omitempty"`
	Discovery        IntegrationDiscoverySpec        `json:"discovery"`
	Normalization    IntegrationNormalizationSpec    `json:"normalization"`
	Execution        IntegrationExecutionSpec        `json:"execution"`
	Extensions       IntegrationExtensionsSpec       `json:"extensions"`
	Reactors         []IntegrationTypeReactor        `json:"reactors,omitempty"`
}

// IntegrationDashboardSpec links to the provider's own UI for
// integrations whose primary management surface lives outside
// Yggdrasil. Surfaced as an "Abrir <provider>" CTA on the
// /ops/integrations card.
type IntegrationDashboardSpec struct {
	URL   string `json:"url"`
	Label string `json:"label,omitempty"`
}

// IntegrationAdapterSpec declares how the adapter is reached by the core.
type IntegrationAdapterSpec struct {
	Transport      string                  `json:"transport"`
	Version        string                  `json:"version"`
	Queues         IntegrationAdapterQueue `json:"queues"`
	Endpoints      IntegrationAdapterRoute `json:"endpoints,omitempty"`
	TimeoutSeconds int                     `json:"timeout_seconds,omitempty"`
}

// IntegrationAdapterQueue enumerates the queue names one adapter can implement.
type IntegrationAdapterQueue struct {
	Describe string `json:"describe,omitempty"`
	Discover string `json:"discover,omitempty"`
	Read     string `json:"read,omitempty"`
	Execute  string `json:"execute,omitempty"`
	Sync     string `json:"sync,omitempty"`
	Health   string `json:"health,omitempty"`
}

// IntegrationAdapterRoute enumerates the HTTP endpoints one adapter can expose.
type IntegrationAdapterRoute struct {
	Describe string `json:"describe,omitempty"`
	Discover string `json:"discover,omitempty"`
	Read     string `json:"read,omitempty"`
	Execute  string `json:"execute,omitempty"`
	Sync     string `json:"sync,omitempty"`
	Health   string `json:"health,omitempty"`
}

// IntegrationSchemaSpec describes instance or credential inputs expected by the adapter.
type IntegrationSchemaSpec struct {
	Mode       string                               `json:"mode"`
	Required   []string                             `json:"required,omitempty"`
	Properties map[string]IntegrationSchemaProperty `json:"properties,omitempty"`
}

// IntegrationSchemaProperty defines one typed input field used by an integration.
//
// MinLength enforces a minimum character count on string-typed inputs after
// trimming surrounding whitespace. It is ignored for non-string types. The
// presence-only `required` check on its own cannot catch empty-string
// payloads (e.g. `image_repo: ""` expanding into `image_overrides {"":":"}`
// that the kubernetes adapter silently no-ops); pair the two when a workflow
// input must be a non-empty value.
//
// UI metadata (§15 of INTEGRATION_CONTRACT.md) lets surfaces render forms
// generically without per-provider hardcoding:
//
//   - Label, LabelLocale: human-readable field label + per-locale translations.
//     Surfaces fall back to the property key when neither is set.
//   - Placeholder, PlaceholderLocale: HTML form placeholder hint.
//   - DescriptionLocale: per-locale translations of Description.
//   - Group, GroupLocale: declares which form section this field belongs to,
//     so a surface can render fields grouped instead of as a flat list.
//   - Order: presentation order within the group (lowest first). Ties broken
//     alphabetically by property key.
//   - Sensitive: when true, surfaces render as password fields. Independent
//     of Secret (which signals "the value is itself a secret"); a value can
//     be Sensitive without being a Secret (e.g. PIN) and vice versa.
//   - DependsOn: conditional visibility. The field only appears when another
//     field has a specific value (e.g. mtls_enabled=true reveals cert fields).
//   - Format: a JSON Schema "format" hint (e.g. "uri", "email", "uuid",
//     "password"). Surfaces use this to pick the right input widget.
//   - Pattern: regex string. Surfaces use for client-side preview validation;
//     server still re-validates.
//   - MaxLength: maximum character count for string inputs (mirrors MinLength).
//
// All UI metadata fields are optional; existing manifests without them keep
// working unchanged (the new fields are omitempty across JSON and YAML).
type IntegrationSchemaProperty struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Secret      bool   `json:"secret,omitempty"`
	Enum        []any  `json:"enum,omitempty"`
	Default     any    `json:"default,omitempty"`
	MinLength   *int   `json:"minLength,omitempty"`

	// UI metadata (§15) — optional, drives generic form rendering in surfaces.
	Label             string                       `json:"label,omitempty"             yaml:"label,omitempty"`
	LabelLocale       map[string]string            `json:"label_locale,omitempty"      yaml:"label_locale,omitempty"`
	Placeholder       string                       `json:"placeholder,omitempty"       yaml:"placeholder,omitempty"`
	PlaceholderLocale map[string]string            `json:"placeholder_locale,omitempty" yaml:"placeholder_locale,omitempty"`
	DescriptionLocale map[string]string            `json:"description_locale,omitempty" yaml:"description_locale,omitempty"`
	Group             string                       `json:"group,omitempty"             yaml:"group,omitempty"`
	GroupLocale       map[string]string            `json:"group_locale,omitempty"      yaml:"group_locale,omitempty"`
	Order             int                          `json:"order,omitempty"             yaml:"order,omitempty"`
	Sensitive         bool                         `json:"sensitive,omitempty"         yaml:"sensitive,omitempty"`
	DependsOn         *IntegrationSchemaDependency `json:"depends_on,omitempty"        yaml:"depends_on,omitempty"`
	Format            string                       `json:"format,omitempty"            yaml:"format,omitempty"`
	Pattern           string                       `json:"pattern,omitempty"           yaml:"pattern,omitempty"`
	MaxLength         *int                         `json:"max_length,omitempty"        yaml:"max_length,omitempty"`
}

// IntegrationSchemaDependency expresses a conditional-visibility relationship
// between two properties on the same schema. The dependent property is shown
// to the user (and required, if its `required` flag is set) only when the
// referenced Field has the specified Value in the current form state.
//
// Field MUST refer to another property declared in the same schema's
// Properties map. Surfaces consume this to drive show/hide logic without
// per-provider hardcoded branches.
type IntegrationSchemaDependency struct {
	Field string `json:"field" yaml:"field"`
	Value any    `json:"value" yaml:"value"`
}

// IntegrationCredentialPolicySpec defines how one integration_type expects credentials to be supplied and stored.
type IntegrationCredentialPolicySpec struct {
	Source            string `json:"source,omitempty"`
	MaterializeInline bool   `json:"materialize_inline,omitempty"`
}

// IntegrationGuardianSupportSpec describes how an integration can expose
// lightweight operational signals to Heimdall without needing a custom plugin
// path per provider.
type IntegrationGuardianSupportSpec struct {
	Mode    string                               `json:"mode,omitempty"`
	Signals IntegrationGuardianSignalSupportSpec `json:"signals,omitempty"`
}

// IntegrationGuardianSignalSupportSpec maps provider-specific runtime detail
// keys into the canonical signals Heimdall understands in lightweight mode.
type IntegrationGuardianSignalSupportSpec struct {
	OOMKilled         []string `json:"oom_killed,omitempty"`
	RestartCount      []string `json:"restart_count,omitempty"`
	ErrorRate         []string `json:"error_rate,omitempty"`
	QueueBacklog      []string `json:"queue_backlog,omitempty"`
	MemoryPressure    []string `json:"memory_pressure,omitempty"`
	DiskPressure      []string `json:"disk_pressure,omitempty"`
	RateLimited       []string `json:"rate_limited,omitempty"`
	AuthDenied        []string `json:"auth_denied,omitempty"`
	SyncLagSeconds    []string `json:"sync_lag_seconds,omitempty"`
	MonthlyCostUSD    []string `json:"monthly_cost_usd,omitempty"`
	Utilization       []string `json:"utilization,omitempty"`
	IdleHours         []string `json:"idle_hours,omitempty"`
	Overprovisioned   []string `json:"overprovisioned,omitempty"`
	SchedulingFailure []string `json:"scheduling_failure,omitempty"`
	InsufficientCPU   []string `json:"insufficient_cpu,omitempty"`
}

// IntegrationResourceType defines one external resource category exposed by the adapter.
type IntegrationResourceType struct {
	Name             string   `json:"name"`
	CanonicalPrefix  string   `json:"canonical_prefix"`
	IdentityTemplate string   `json:"identity_template"`
	Discoverable     bool     `json:"discoverable"`
	DefaultActions   []string `json:"default_actions"`
}

// IntegrationActionDefinition describes one action supported by one or more resource types.
//
// Category lets UIs (team-grant picker, console catalog) sort actions by
// semantic role:
//   - "reactor"    : framework hook (on_team_*, on_membership_*). Never
//                    user-grantable; hidden from grant pickers.
//   - "capability" : adapter operation dispatched by Yggdrasil via Execute.
//                    Default when unset (back-compat for older adapters).
//   - "permission" : product-level permission, NOT dispatched; granted via
//                    team_grant and authorized by the downstream app.
type IntegrationActionDefinition struct {
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	ResourceTypes []string `json:"resource_types,omitempty"`
	Idempotent    bool     `json:"idempotent,omitempty"`
	Category      string   `json:"category,omitempty"`
}

// IntegrationDiscoverySpec declares how the adapter discovers external resources.
type IntegrationDiscoverySpec struct {
	Mode             string `json:"mode"`
	Cursor           string `json:"cursor,omitempty"`
	SupportsWebhooks bool   `json:"supports_webhooks,omitempty"`
}

// IntegrationNormalizationSpec describes how raw provider payloads become canonical Yggdrasil resources.
type IntegrationNormalizationSpec struct {
	ExternalIDPath         string `json:"external_id_path"`
	NamePath               string `json:"name_path,omitempty"`
	OwnerPath              string `json:"owner_path,omitempty"`
	FallbackResourcePrefix string `json:"fallback_resource_prefix"`
}

// IntegrationExecutionSpec declares execution semantics for adapter actions.
type IntegrationExecutionSpec struct {
	SupportsDryRun    bool     `json:"supports_dry_run,omitempty"`
	IdempotentActions []string `json:"idempotent_actions,omitempty"`
}

// IntegrationExtensionsSpec configures how much uncontrolled provider surface the adapter can expose.
type IntegrationExtensionsSpec struct {
	AllowCustomResourceTypes bool `json:"allow_custom_resource_types,omitempty"`
	AllowCustomActions       bool `json:"allow_custom_actions,omitempty"`
	PreserveRawPayload       bool `json:"preserve_raw_payload,omitempty"`
}

// AdapterDescribeRequest is sent by the core to one adapter queue to introspect its capabilities.
type AdapterDescribeRequest struct {
	Provider        string `json:"provider"`
	ExpectedVersion string `json:"expected_version,omitempty"`
}

// AdapterDescribeResponse is the normalized response returned by one adapter implementation.
//
// `Reactors` is optional — when populated, the adapter declares which canonical
// lifecycle events it subscribes to (event_type → capability mapping). On
// initial manifest registration / first sync, manifest_sync adopts the
// adapter-declared reactors verbatim. Once an operator overrides the reactor
// set via the manifest catalog, the operator's value wins (see
// `internal/manifestsync/merge.go::MergeSpec`).
type AdapterDescribeResponse struct {
	Provider         string                        `json:"provider"`
	Adapter          IntegrationAdapterSpec        `json:"adapter"`
	Capabilities     []string                      `json:"capabilities"`
	CredentialSchema IntegrationSchemaSpec         `json:"credential_schema"`
	InstanceSchema   IntegrationSchemaSpec         `json:"instance_schema"`
	ResourceTypes    []IntegrationResourceType     `json:"resource_types"`
	ActionCatalog    []IntegrationActionDefinition `json:"action_catalog,omitempty"`
	Discovery        IntegrationDiscoverySpec      `json:"discovery"`
	Normalization    IntegrationNormalizationSpec  `json:"normalization"`
	Execution        IntegrationExecutionSpec      `json:"execution"`
	Extensions       IntegrationExtensionsSpec     `json:"extensions"`
	Reactors         []IntegrationTypeReactor      `json:"reactors,omitempty"`
}

// IntegrationTypeReactor describes one event-driven reaction configuration.
// When a canonical lifecycle event occurs, if this integration_type has a
// reactor that matches the event type, the named capability action is invoked.
type IntegrationTypeReactor struct {
	EventType  string `json:"event_type"`
	Capability string `json:"capability"`
}
