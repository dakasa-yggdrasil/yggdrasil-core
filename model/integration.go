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
type IntegrationSchemaProperty struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Secret      bool   `json:"secret,omitempty"`
	Enum        []any  `json:"enum,omitempty"`
	Default     any    `json:"default,omitempty"`
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
type IntegrationActionDefinition struct {
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	ResourceTypes []string `json:"resource_types,omitempty"`
	Idempotent    bool     `json:"idempotent,omitempty"`
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
}

// IntegrationTypeReactor describes one event-driven reaction configuration.
// When a canonical lifecycle event occurs, if this integration_type has a
// reactor that matches the event type, the named capability action is invoked.
type IntegrationTypeReactor struct {
	EventType  string `json:"event_type"`
	Capability string `json:"capability"`
}
