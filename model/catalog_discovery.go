package model

const (
	CatalogDiscoverOperation               = "catalog_discover"
	CatalogDiscoveryKindIntegration        = "integration"
	CatalogDiscoveryKindSurface            = "surface"
	CatalogDiscoveryRegistrationRegistered = "registered"
	CatalogDiscoveryRegistrationMissing    = "unregistered"
)

// DiscoverCatalogRequest asks the core to query one or more discovery-capable integration instances.
type DiscoverCatalogRequest struct {
	Source    ManifestSelector `json:"source,omitempty"`
	Namespace string           `json:"namespace,omitempty"`
	Kinds     []string         `json:"kinds,omitempty"`
	Query     string           `json:"query,omitempty"`
	Limit     int              `json:"limit,omitempty"`
}

// CatalogDiscoverySource summarizes one integration instance used as a discovery backend.
type CatalogDiscoverySource struct {
	IntegrationInstance ManifestReference `json:"integration_instance"`
	IntegrationType     ManifestReference `json:"integration_type"`
	Provider            string            `json:"provider"`
	PluginName          string            `json:"plugin_name"`
	Domain              string            `json:"domain,omitempty"`
	Section             string            `json:"section,omitempty"`
	Entry               string            `json:"entry,omitempty"`
	HealthStatus        string            `json:"health_status,omitempty"`
	DiscoveryStatus     string            `json:"discovery_status,omitempty"`
	Message             string            `json:"message,omitempty"`
}

// CatalogDiscoveryCandidate is the normalized shape expected from one discovery-capable plugin.
type CatalogDiscoveryCandidate struct {
	Kind         string                        `json:"kind"`
	Name         string                        `json:"name"`
	Namespace    string                        `json:"namespace,omitempty"`
	DisplayName  string                        `json:"display_name,omitempty"`
	Description  string                        `json:"description,omitempty"`
	Domain       string                        `json:"domain,omitempty"`
	Section      string                        `json:"section,omitempty"`
	Entry        string                        `json:"entry,omitempty"`
	Repository   string                        `json:"repository,omitempty"`
	Labels       map[string]string             `json:"labels,omitempty"`
	Metadata     map[string]any                `json:"metadata,omitempty"`
	Registration *CatalogDiscoveryRegistration `json:"registration,omitempty"`
}

// CatalogDiscoveryItem is one discovered candidate enriched with core registration state.
type CatalogDiscoveryItem struct {
	Source             CatalogDiscoverySource        `json:"source"`
	Kind               string                        `json:"kind"`
	Name               string                        `json:"name"`
	Namespace          string                        `json:"namespace,omitempty"`
	DisplayName        string                        `json:"display_name,omitempty"`
	Description        string                        `json:"description,omitempty"`
	Domain             string                        `json:"domain,omitempty"`
	Section            string                        `json:"section,omitempty"`
	Entry              string                        `json:"entry,omitempty"`
	Repository         string                        `json:"repository,omitempty"`
	Labels             map[string]string             `json:"labels,omitempty"`
	Metadata           map[string]any                `json:"metadata,omitempty"`
	Registration       *CatalogDiscoveryRegistration `json:"registration,omitempty"`
	RegisteredManifest *ManifestReference            `json:"registered_manifest,omitempty"`
	RegistrationStatus string                        `json:"registration_status"`
}

// DiscoverCatalogResponse returns the normalized discovery results together with source status.
type DiscoverCatalogResponse struct {
	Sources []CatalogDiscoverySource `json:"sources"`
	Items   []CatalogDiscoveryItem   `json:"items"`
}

// CatalogDiscoveryRegistration describes one optional manifest candidate that can be registered in the core.
type CatalogDiscoveryRegistration struct {
	Manifest ManifestDocument `json:"manifest"`
}
