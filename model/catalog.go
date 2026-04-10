package model

import "time"

// IntegrationInstanceManifestSpec defines one concrete installation of an integration_type.
type IntegrationInstanceManifestSpec struct {
	TypeRef        ManifestSelector                 `json:"type_ref"`
	Status         string                           `json:"status,omitempty"`
	Owners         []string                         `json:"owners,omitempty"`
	Credentials    map[string]any                   `json:"credentials,omitempty"`
	CredentialsRef string                           `json:"credentials_ref,omitempty"`
	Config         map[string]any                   `json:"config,omitempty"`
	Discovery      IntegrationInstanceDiscoverySpec `json:"discovery"`
	Execution      IntegrationInstanceExecutionSpec `json:"execution,omitempty"`
}

// IntegrationInstanceDiscoverySpec configures how one integration instance is synchronized.
type IntegrationInstanceDiscoverySpec struct {
	Enabled             bool   `json:"enabled"`
	Mode                string `json:"mode,omitempty"`
	SyncIntervalSeconds int    `json:"sync_interval_seconds,omitempty"`
}

// IntegrationInstanceExecutionSpec overrides runtime execution defaults for one instance.
type IntegrationInstanceExecutionSpec struct {
	DefaultDryRun bool `json:"default_dry_run,omitempty"`
	MaxBatchSize  int  `json:"max_batch_size,omitempty"`
}

// ResourceManifestSpec defines one canonical resource persisted in the core catalog.
type ResourceManifestSpec struct {
	Resource    string             `json:"resource"`
	Type        string             `json:"type"`
	DisplayName string             `json:"display_name,omitempty"`
	Actions     []string           `json:"actions"`
	Owners      []string           `json:"owners,omitempty"`
	Source      ResourceSourceSpec `json:"source"`
	Attributes  map[string]any     `json:"attributes,omitempty"`
	Raw         map[string]any     `json:"raw,omitempty"`
}

// ResourceSourceSpec describes where a canonical resource came from.
type ResourceSourceSpec struct {
	Kind                   string            `json:"kind"`
	IntegrationTypeRef     *ManifestSelector `json:"integration_type_ref,omitempty"`
	IntegrationInstanceRef *ManifestSelector `json:"integration_instance_ref,omitempty"`
	ExternalID             string            `json:"external_id,omitempty"`
	ExternalType           string            `json:"external_type,omitempty"`
	DiscoveredAt           *time.Time        `json:"discovered_at,omitempty"`
}

// AdapterDiscoverRequest asks one adapter instance for normalized discoverable resources.
type AdapterDiscoverRequest struct {
	InstanceRef ManifestSelector `json:"instance_ref"`
	Cursor      string           `json:"cursor,omitempty"`
	Limit       int              `json:"limit,omitempty"`
}

// AdapterDiscoveredResource is one resource item emitted by an adapter discovery run.
type AdapterDiscoveredResource struct {
	ExternalID        string         `json:"external_id"`
	Type              string         `json:"type"`
	Name              string         `json:"name,omitempty"`
	Owner             string         `json:"owner,omitempty"`
	CanonicalResource string         `json:"canonical_resource,omitempty"`
	Actions           []string       `json:"actions,omitempty"`
	Attributes        map[string]any `json:"attributes,omitempty"`
	Raw               map[string]any `json:"raw,omitempty"`
}

// AdapterDiscoverResponse returns one page of discovered resources from an adapter.
type AdapterDiscoverResponse struct {
	NextCursor string                      `json:"next_cursor,omitempty"`
	Resources  []AdapterDiscoveredResource `json:"resources"`
}
