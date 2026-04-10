package model

// ProductManifestSpec defines one delivery/composition manifest that can replace legacy product bundles.
// The preferred internal path is Git-backed raw Kubernetes or Kustomize, while Helm remains optional compatibility.
type ProductManifestSpec struct {
	Category     string                 `json:"category"`
	Class        string                 `json:"class"`
	Owners       []string               `json:"owners,omitempty"`
	Lifecycle    ProductLifecycleSpec   `json:"lifecycle,omitempty"`
	Components   []ProductComponentSpec `json:"components"`
	Dependencies []string               `json:"dependencies,omitempty"`
}

// ProductLifecycleSpec stores coarse lifecycle metadata for one product.
type ProductLifecycleSpec struct {
	Tier  string `json:"tier,omitempty"`
	Stage string `json:"stage,omitempty"`
}

// ProductComponentSpec defines one deployable part of a product.
type ProductComponentSpec struct {
	Name        string                   `json:"name"`
	Description string                   `json:"description,omitempty"`
	Source      ProductSourceSpec        `json:"source"`
	Renderer    ProductRendererSpec      `json:"renderer"`
	Target      ProductTargetSpec        `json:"target"`
	Reconcile   ProductReconcileSpec     `json:"reconcile,omitempty"`
	Requires    []ProductRequirementSpec `json:"requires,omitempty"`
	DependsOn   []string                 `json:"depends_on,omitempty"`
}

// ProductRequirementSpec declares one external prerequisite for a product component.
type ProductRequirementSpec struct {
	Kind     string           `json:"kind"`
	Selector ManifestSelector `json:"selector"`
	State    string           `json:"state,omitempty"`
	Policy   string           `json:"policy,omitempty"`
	Wait     bool             `json:"wait,omitempty"`
}

// ProductSourceSpec points to the origin of the component payload.
type ProductSourceSpec struct {
	Kind                   string            `json:"kind"`
	IntegrationInstanceRef *ManifestSelector `json:"integration_instance_ref,omitempty"`
	Operation              string            `json:"operation,omitempty"`
	Capability             string            `json:"capability,omitempty"`
	Input                  map[string]any    `json:"input,omitempty"`
	Locator                string            `json:"locator,omitempty"`
	Revision               string            `json:"revision,omitempty"`
	Version                string            `json:"version,omitempty"`
	Objects                []map[string]any  `json:"objects,omitempty"`
}

// ProductRendererSpec defines how the component source is materialized.
// Supported renderers are intentionally biased toward Git-native delivery over centralized chart repositories.
type ProductRendererSpec struct {
	Kind    string         `json:"kind"`
	Path    string         `json:"path,omitempty"`
	Include []string       `json:"include,omitempty"`
	Values  map[string]any `json:"values,omitempty"`
}

// ProductTargetSpec defines where the component is reconciled.
type ProductTargetSpec struct {
	Kind                   string           `json:"kind"`
	IntegrationInstanceRef ManifestSelector `json:"integration_instance_ref"`
	Namespace              string           `json:"namespace,omitempty"`
}

// ProductReconcileSpec defines the desired reconciliation behavior for the component.
type ProductReconcileSpec struct {
	Strategy string `json:"strategy,omitempty"`
	Prune    bool   `json:"prune,omitempty"`
	Wait     bool   `json:"wait,omitempty"`
}
