package model

const (
	IntegrationCatalogLabelDomain             = "yggdrasil.io/catalog-domain"
	IntegrationCatalogLabelSection            = "yggdrasil.io/catalog-section"
	IntegrationCatalogLabelEntry              = "yggdrasil.io/catalog-entry"
	IntegrationCatalogSectionInstallations    = "installations"
	IntegrationCatalogSectionOperations       = "operations"
	IntegrationCatalogEntryStatusUnconfigured = "unconfigured"
)

// ListIntegrationCatalogRequest filters the explicit integration catalog view.
type ListIntegrationCatalogRequest struct {
	Namespace string `json:"namespace,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Section   string `json:"section,omitempty"`
	Entry     string `json:"entry,omitempty"`
	CheckKind string `json:"check_kind,omitempty"`
}

// GetIntegrationCatalogEntryRequest fetches one explicit catalog entry.
type GetIntegrationCatalogEntryRequest struct {
	Namespace string `json:"namespace,omitempty"`
	Domain    string `json:"domain"`
	Section   string `json:"section"`
	Entry     string `json:"entry"`
	CheckKind string `json:"check_kind,omitempty"`
}

// IntegrationCatalogDomain groups entries by shared domain.
type IntegrationCatalogDomain struct {
	Domain   string                      `json:"domain"`
	Sections []IntegrationCatalogSection `json:"sections"`
}

// IntegrationCatalogSection groups entries within one domain area.
type IntegrationCatalogSection struct {
	Name    string                    `json:"name"`
	Entries []IntegrationCatalogEntry `json:"entries"`
}

// IntegrationCatalogEntry is one concrete plugin entry exposed by the explicit catalog API.
type IntegrationCatalogEntry struct {
	Domain          string                       `json:"domain"`
	Section         string                       `json:"section"`
	Entry           string                       `json:"entry"`
	PluginName      string                       `json:"plugin_name"`
	Description     string                       `json:"description,omitempty"`
	Provider        string                       `json:"provider"`
	AdapterVersion  string                       `json:"adapter_version,omitempty"`
	Status          string                       `json:"status"`
	Labels          map[string]string            `json:"labels,omitempty"`
	Capabilities    []string                     `json:"capabilities,omitempty"`
	IntegrationType ManifestReference            `json:"integration_type"`
	RuntimeState    *IntegrationRuntimeState     `json:"runtime_state,omitempty"`
	Instances       []IntegrationCatalogInstance `json:"instances,omitempty"`
}

// IntegrationCatalogInstance summarizes one configured integration instance under a catalog entry.
type IntegrationCatalogInstance struct {
	IntegrationInstance ManifestReference        `json:"integration_instance"`
	Description         string                   `json:"description,omitempty"`
	Owners              []string                 `json:"owners,omitempty"`
	DeclaredStatus      string                   `json:"declared_status"`
	Status              string                   `json:"status"`
	RuntimeState        *IntegrationRuntimeState `json:"runtime_state,omitempty"`
}
