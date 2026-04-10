package model

// ApplyProductInstallationRequest asks the core to apply one product to its declared target integrations.
type ApplyProductInstallationRequest struct {
	Product ManifestSelector `json:"product"`
}

// ProductInstallationApplyResult describes one component apply result.
type ProductInstallationApplyResult struct {
	Name           string                      `json:"name"`
	Operation      string                      `json:"operation"`
	Mode           string                      `json:"mode,omitempty"`
	Applied        bool                        `json:"applied"`
	Resources      []InstallationResourceState `json:"resources,omitempty"`
	TargetType     *ManifestReference          `json:"target_type,omitempty"`
	TargetInstance *ManifestReference          `json:"target_instance,omitempty"`
	Metadata       map[string]any              `json:"metadata,omitempty"`
}

// ApplyProductInstallationResponse returns the apply results for one product.
type ApplyProductInstallationResponse struct {
	Product ManifestReference                `json:"product"`
	Results []ProductInstallationApplyResult `json:"results,omitempty"`
}

// ObserveProductInstallationRequest asks the core to observe one product on its declared target integrations.
type ObserveProductInstallationRequest struct {
	Product ManifestSelector `json:"product"`
}

// ProductInstallationObservationResult describes one component observation result.
type ProductInstallationObservationResult struct {
	Name           string                      `json:"name"`
	Operation      string                      `json:"operation"`
	Status         string                      `json:"status,omitempty"`
	Observed       bool                        `json:"observed,omitempty"`
	Resources      []InstallationResourceState `json:"resources,omitempty"`
	TargetType     *ManifestReference          `json:"target_type,omitempty"`
	TargetInstance *ManifestReference          `json:"target_instance,omitempty"`
	Metadata       map[string]any              `json:"metadata,omitempty"`
}

// ObserveProductInstallationResponse returns the observation results for one product.
type ObserveProductInstallationResponse struct {
	Product ManifestReference                      `json:"product"`
	Results []ProductInstallationObservationResult `json:"results,omitempty"`
}

// AdapterTargetIntegrationContext gives one target-side adapter the resolved manifests it needs.
type AdapterTargetIntegrationContext struct {
	Type         ManifestReference               `json:"type"`
	TypeSpec     IntegrationTypeManifestSpec     `json:"type_spec"`
	Instance     ManifestReference               `json:"instance"`
	InstanceSpec IntegrationInstanceManifestSpec `json:"instance_spec"`
}

// AdapterDeclarativeApplyRequest asks a target integration to apply one desired object set.
type AdapterDeclarativeApplyRequest struct {
	Operation string                             `json:"operation"`
	Context   AdapterGenerateInstallationContext `json:"context"`
	Target    AdapterTargetIntegrationContext    `json:"target"`
	Objects   []map[string]any                   `json:"objects"`
	Namespace string                             `json:"namespace,omitempty"`
	Reconcile ProductReconcileSpec               `json:"reconcile,omitempty"`
}

// AdapterDeclarativeApplyResponse is returned by a target integration after applying objects.
type AdapterDeclarativeApplyResponse struct {
	Operation string                      `json:"operation,omitempty"`
	Applied   bool                        `json:"applied"`
	Mode      string                      `json:"mode,omitempty"`
	Resources []InstallationResourceState `json:"resources,omitempty"`
	Metadata  map[string]any              `json:"metadata,omitempty"`
}

// AdapterObserveObjectsRequest asks a target integration to observe a desired object set.
type AdapterObserveObjectsRequest struct {
	Operation string                             `json:"operation"`
	Context   AdapterGenerateInstallationContext `json:"context"`
	Target    AdapterTargetIntegrationContext    `json:"target"`
	Objects   []map[string]any                   `json:"objects"`
	Namespace string                             `json:"namespace,omitempty"`
}

// AdapterObserveObjectsResponse is returned by a target integration after observing objects.
type AdapterObserveObjectsResponse struct {
	Operation string                      `json:"operation,omitempty"`
	Status    string                      `json:"status,omitempty"`
	Observed  bool                        `json:"observed,omitempty"`
	Resources []InstallationResourceState `json:"resources,omitempty"`
	Metadata  map[string]any              `json:"metadata,omitempty"`
}
