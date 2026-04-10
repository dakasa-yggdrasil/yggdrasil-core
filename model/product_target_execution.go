package model

// ApplyProductInstallationRequest asks the core to apply one product to its
// declared target integrations. Optional TargetOverrides allow workflow
// callers to redirect specific components to different integration instances
// at apply time without modifying the immutable Product manifest.
type ApplyProductInstallationRequest struct {
	Product         ManifestSelector        `json:"product"`
	TargetOverrides map[string]TargetOverride `json:"target_overrides,omitempty"`
}

// TargetOverride replaces a component's target.integration_instance_ref and
// optionally its namespace at apply time. The map key on the request is the
// integration_instance_ref.name as authored in the Product manifest —
// matching components get the override applied.
type TargetOverride struct {
	// IntegrationInstanceRef is the replacement instance reference. Required.
	IntegrationInstanceRef ManifestSelector `json:"integration_instance_ref"`

	// Namespace overrides the component's target.namespace. Empty string
	// means "keep the original namespace".
	Namespace string `json:"namespace,omitempty"`

	// ImageOverrides remaps container image references at apply time.
	// Keys are the original image reference (e.g.
	// "ghcr.io/dakasa-co/identities"); values are the replacement,
	// typically the same repository with a new tag
	// ("ghcr.io/dakasa-co/identities:sha-abc1234"). Empty map means "no
	// remap". The core forwards the map verbatim to the target adapter
	// via AdapterDeclarativeApplyRequest.ImageOverrides — the adapter is
	// responsible for applying the overrides at render time (e.g.
	// Kustomize images: field) before the actual apply.
	//
	// Consumer-side CD flows use this to avoid committing a new image
	// tag to git on every build.
	ImageOverrides map[string]string `json:"image_overrides,omitempty"`
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

// ObserveProductInstallationRequest asks the core to observe one product on
// its declared target integrations. TargetOverrides (same semantics as
// ApplyProductInstallationRequest) redirect observation to different targets.
type ObserveProductInstallationRequest struct {
	Product         ManifestSelector        `json:"product"`
	TargetOverrides map[string]TargetOverride `json:"target_overrides,omitempty"`
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

// UninstallProductInstallationRequest asks the core to remove one product
// installation from its declared target integrations. TargetOverrides
// (same semantics as ApplyProductInstallationRequest) redirect the
// uninstall to different targets — useful when the original apply was
// itself redirected.
//
// The core regenerates the Kubernetes object set using the same
// reconcile code path as apply, then dispatches a declarative_delete
// adapter RPC. Components whose source.kind is not "integration" are
// skipped (same filter as apply).
type UninstallProductInstallationRequest struct {
	Product         ManifestSelector          `json:"product"`
	TargetOverrides map[string]TargetOverride `json:"target_overrides,omitempty"`
}

// ProductInstallationUninstallResult describes one component uninstall result.
type ProductInstallationUninstallResult struct {
	Name           string                      `json:"name"`
	Operation      string                      `json:"operation"`
	Mode           string                      `json:"mode,omitempty"`
	Uninstalled    bool                        `json:"uninstalled"`
	Resources      []InstallationResourceState `json:"resources,omitempty"`
	TargetType     *ManifestReference          `json:"target_type,omitempty"`
	TargetInstance *ManifestReference          `json:"target_instance,omitempty"`
	Metadata       map[string]any              `json:"metadata,omitempty"`
}

// UninstallProductInstallationResponse returns the uninstall results for one product.
type UninstallProductInstallationResponse struct {
	Product ManifestReference                    `json:"product"`
	Results []ProductInstallationUninstallResult `json:"results,omitempty"`
}

// AdapterDeclarativeDeleteRequest asks a target integration to delete one desired object set.
// Symmetric to AdapterDeclarativeApplyRequest — the core sends the same
// object list that was applied so the adapter can delete the same
// objects.
type AdapterDeclarativeDeleteRequest struct {
	Operation string                             `json:"operation"`
	Context   AdapterGenerateInstallationContext `json:"context"`
	Target    AdapterTargetIntegrationContext    `json:"target"`
	Objects   []map[string]any                   `json:"objects"`
	Namespace string                             `json:"namespace,omitempty"`
}

// AdapterDeclarativeDeleteResponse is returned by a target integration after deleting objects.
type AdapterDeclarativeDeleteResponse struct {
	Operation   string                      `json:"operation,omitempty"`
	Uninstalled bool                        `json:"uninstalled"`
	Mode        string                      `json:"mode,omitempty"`
	Resources   []InstallationResourceState `json:"resources,omitempty"`
	Metadata    map[string]any              `json:"metadata,omitempty"`
}

// AdapterTargetIntegrationContext gives one target-side adapter the resolved manifests it needs.
type AdapterTargetIntegrationContext struct {
	Type         ManifestReference               `json:"type"`
	TypeSpec     IntegrationTypeManifestSpec     `json:"type_spec"`
	Instance     ManifestReference               `json:"instance"`
	InstanceSpec IntegrationInstanceManifestSpec `json:"instance_spec"`
}

// AdapterDeclarativeApplyRequest asks a target integration to apply one desired object set.
//
// ImageOverrides carries any runtime container-image remaps the workflow
// wants the adapter to apply before materializing the objects on the
// cluster. The core does not parse or enforce it — adapters that
// understand image overrides (e.g. integration-kubernetes with
// Kustomize) are responsible for applying them at render time.
type AdapterDeclarativeApplyRequest struct {
	Operation      string                             `json:"operation"`
	Context        AdapterGenerateInstallationContext `json:"context"`
	Target         AdapterTargetIntegrationContext    `json:"target"`
	Objects        []map[string]any                   `json:"objects"`
	Namespace      string                             `json:"namespace,omitempty"`
	ImageOverrides map[string]string                  `json:"image_overrides,omitempty"`
	Reconcile      ProductReconcileSpec               `json:"reconcile,omitempty"`
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
