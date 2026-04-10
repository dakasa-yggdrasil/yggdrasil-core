package model

// ReconcileProductInstallationRequest asks the core to build an installation reconciliation plan for one product.
type ReconcileProductInstallationRequest struct {
	Product ManifestSelector `json:"product"`
}

// ProductInstallationReconcileResult is one component-level reconciliation result returned by the core.
type ProductInstallationReconcileResult struct {
	Name                string                     `json:"name"`
	Operation           string                     `json:"operation"`
	Capability          string                     `json:"capability,omitempty"`
	Mode                string                     `json:"mode,omitempty"`
	Objects             []map[string]any           `json:"objects,omitempty"`
	Requirements        []ProductRequirementResult `json:"requirements,omitempty"`
	IntegrationType     *ManifestReference         `json:"integration_type,omitempty"`
	IntegrationInstance *ManifestReference         `json:"integration_instance,omitempty"`
	Metadata            map[string]any             `json:"metadata,omitempty"`
}

// ReconcileProductInstallationResponse returns the reconciliation plan for one product.
type ReconcileProductInstallationResponse struct {
	Product ManifestReference                    `json:"product"`
	Results []ProductInstallationReconcileResult `json:"results,omitempty"`
}

// DiscoverProductInstallationStateRequest asks the core to query installation state for one product.
type DiscoverProductInstallationStateRequest struct {
	Product ManifestSelector `json:"product"`
}

// InstallationResourceState describes one installation resource returned by an integration plugin.
type InstallationResourceState struct {
	Kind      string         `json:"kind"`
	Namespace string         `json:"namespace,omitempty"`
	Name      string         `json:"name"`
	Status    string         `json:"status,omitempty"`
	Observed  bool           `json:"observed,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// ProductInstallationStateResult is one component-level installation state returned by the core.
type ProductInstallationStateResult struct {
	Name                string                      `json:"name"`
	Operation           string                      `json:"operation"`
	Capability          string                      `json:"capability,omitempty"`
	Status              string                      `json:"status,omitempty"`
	Observed            bool                        `json:"observed,omitempty"`
	Resources           []InstallationResourceState `json:"resources,omitempty"`
	IntegrationType     *ManifestReference          `json:"integration_type,omitempty"`
	IntegrationInstance *ManifestReference          `json:"integration_instance,omitempty"`
	Metadata            map[string]any              `json:"metadata,omitempty"`
}

// DiscoverProductInstallationStateResponse returns installation state for one product.
type DiscoverProductInstallationStateResponse struct {
	Product ManifestReference                `json:"product"`
	Results []ProductInstallationStateResult `json:"results,omitempty"`
}

// ProductRequirementResult is the evaluated status of one declared component requirement.
type ProductRequirementResult struct {
	Kind      string             `json:"kind"`
	Selector  ManifestSelector   `json:"selector"`
	State     string             `json:"state,omitempty"`
	Policy    string             `json:"policy,omitempty"`
	Wait      bool               `json:"wait,omitempty"`
	Satisfied bool               `json:"satisfied"`
	Planned   bool               `json:"planned,omitempty"`
	Reference *ManifestReference `json:"reference,omitempty"`
	Message   string             `json:"message,omitempty"`
}

// AdapterReconcileInstallationRequest is sent to an integration execute queue to build a reconciliation plan.
type AdapterReconcileInstallationRequest struct {
	Operation   string                                        `json:"operation"`
	Context     AdapterGenerateInstallationContext            `json:"context"`
	Integration AdapterGenerateInstallationIntegrationContext `json:"integration"`
	Capability  string                                        `json:"capability,omitempty"`
	Input       map[string]any                                `json:"input,omitempty"`
	Target      ProductTargetSpec                             `json:"target"`
	Reconcile   ProductReconcileSpec                          `json:"reconcile,omitempty"`
}

// AdapterReconcileInstallationResponse is returned by an integration after planning reconciliation.
type AdapterReconcileInstallationResponse struct {
	Operation string           `json:"operation,omitempty"`
	Mode      string           `json:"mode,omitempty"`
	Objects   []map[string]any `json:"objects,omitempty"`
	Metadata  map[string]any   `json:"metadata,omitempty"`
}

// AdapterDiscoverInstallationStateRequest is sent to an integration execute queue to query installation state.
type AdapterDiscoverInstallationStateRequest struct {
	Operation   string                                        `json:"operation"`
	Context     AdapterGenerateInstallationContext            `json:"context"`
	Integration AdapterGenerateInstallationIntegrationContext `json:"integration"`
	Capability  string                                        `json:"capability,omitempty"`
	Input       map[string]any                                `json:"input,omitempty"`
	Target      ProductTargetSpec                             `json:"target"`
}

// AdapterDiscoverInstallationStateResponse is returned by an integration after querying installation state.
type AdapterDiscoverInstallationStateResponse struct {
	Operation string                      `json:"operation,omitempty"`
	Status    string                      `json:"status,omitempty"`
	Observed  bool                        `json:"observed,omitempty"`
	Resources []InstallationResourceState `json:"resources,omitempty"`
	Metadata  map[string]any              `json:"metadata,omitempty"`
}
