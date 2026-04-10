package model

// SurfaceManifestSpec defines one replaceable edge runtime that talks to the core.
// Surfaces are intentionally not the heart of the product. They are cataloged so
// organizations can keep the core stable while swapping or splitting APIs, auth,
// consoles, and other edge entrypoints.
type SurfaceManifestSpec struct {
	Category           string                  `json:"category"`
	Owners             []string                `json:"owners,omitempty"`
	Replaces           []string                `json:"replaces,omitempty"`
	IntegrationBinding string                  `json:"integration_binding,omitempty"`
	Runtime            SurfaceRuntimeSpec      `json:"runtime"`
	CoreContracts      []string                `json:"core_contracts,omitempty"`
	Capabilities       []SurfaceCapabilitySpec `json:"capabilities,omitempty"`
}

// SurfaceRuntimeSpec describes the runtime shape of one surface.
type SurfaceRuntimeSpec struct {
	Kind       string `json:"kind"`
	Exposure   string `json:"exposure,omitempty"`
	Port       int    `json:"port,omitempty"`
	BasePath   string `json:"base_path,omitempty"`
	HealthPath string `json:"health_path,omitempty"`
}

// SurfaceCapabilitySpec describes one user-facing or service-facing capability exposed by a surface.
type SurfaceCapabilitySpec struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	Audience string   `json:"audience,omitempty"`
	Path     string   `json:"path,omitempty"`
	Methods  []string `json:"methods,omitempty"`
}
