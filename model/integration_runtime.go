package model

// ExecuteIntegrationRequest asks the core to execute one integration capability through a configured instance.
type ExecuteIntegrationRequest struct {
	Integration ManifestSelector `json:"integration"`
	Operation   string           `json:"operation,omitempty"`
	Capability  string           `json:"capability,omitempty"`
	Input       map[string]any   `json:"input,omitempty"`
	Auth        map[string]any   `json:"auth,omitempty"`
	Metadata    map[string]any   `json:"metadata,omitempty"`
}

// ExecuteIntegrationResponse returns the normalized outcome of one integration execution.
type ExecuteIntegrationResponse struct {
	Operation           string            `json:"operation"`
	Capability          string            `json:"capability,omitempty"`
	Status              string            `json:"status,omitempty"`
	IntegrationInstance ManifestReference `json:"integration_instance"`
	IntegrationType     ManifestReference `json:"integration_type"`
	Output              any               `json:"output,omitempty"`
	Metadata            map[string]any    `json:"metadata,omitempty"`
}

// AdapterExecuteIntegrationContext gives the adapter the resolved integration manifests it needs.
type AdapterExecuteIntegrationContext struct {
	Type         ManifestReference               `json:"type"`
	TypeSpec     IntegrationTypeManifestSpec     `json:"type_spec"`
	Instance     ManifestReference               `json:"instance"`
	InstanceSpec IntegrationInstanceManifestSpec `json:"instance_spec"`
}

// AdapterExecuteIntegrationRequest is sent to an integration execute queue for one generic capability invocation.
type AdapterExecuteIntegrationRequest struct {
	Operation   string                           `json:"operation"`
	Capability  string                           `json:"capability,omitempty"`
	Input       map[string]any                   `json:"input,omitempty"`
	Auth        map[string]any                   `json:"auth,omitempty"`
	Metadata    map[string]any                   `json:"metadata,omitempty"`
	Integration AdapterExecuteIntegrationContext `json:"integration"`
}

// AdapterExecuteIntegrationResponse is returned by an integration after a generic capability invocation.
type AdapterExecuteIntegrationResponse struct {
	Operation  string         `json:"operation,omitempty"`
	Capability string         `json:"capability,omitempty"`
	Status     string         `json:"status,omitempty"`
	Output     any            `json:"output,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}
