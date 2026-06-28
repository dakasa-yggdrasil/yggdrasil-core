package integrationsurfaces

import "time"

type Category string

const (
	CategoryIntegration Category = "integration"
	CategoryCore        Category = "core"
	CategoryDomain      Category = "domain"
)

type Manifest struct {
	ID              string       `json:"id"`
	Name            string       `json:"name"`
	IntegrationType *string      `json:"integration_type,omitempty"`
	Category        Category     `json:"category"`
	Spec            ManifestSpec `json:"spec"`
	Active          bool         `json:"active"`
	RegisteredAt    time.Time    `json:"registered_at"`
	UpdatedAt       time.Time    `json:"updated_at"`
}

type ManifestSpec struct {
	Category      Category         `json:"category"`
	Owners        []string         `json:"owners,omitempty"`
	Runtime       Runtime          `json:"runtime"`
	Display       Display          `json:"display"`
	CoreContracts []string         `json:"core_contracts,omitempty"`
	Capabilities  []CapabilitySpec `json:"capabilities,omitempty"`
	// Queries is the OPTIONAL per-query view-access declaration for the surface's
	// on_surface_query reads. It is the manifest source of truth for the opt-in
	// gate enforced by yggdrasil-core's surface-query handler: a query listed here
	// with a non-empty requires_permission is gated; any query NOT listed (or
	// listed with an empty requires_permission) stays UNGATED — backward-compat /
	// zero-lockout, so every surface that worked before and every self-service
	// read (e.g. CLT my-*) keeps working untouched. Surfaces declare perms, they
	// do not invent them (INTEGRATION_CONTRACT §15.3); requires_permission MUST be
	// one of spec.permissions[].id from the same surface manifest.
	Queries []SurfaceQuerySpec `json:"queries,omitempty"`
}

// SurfaceQuerySpec optionally binds one on_surface_query query_name to the
// permission a caller must hold to read it. Omitting the entry (or leaving
// requires_permission empty) means the query is ungated.
type SurfaceQuerySpec struct {
	// Name is the on_surface_query query_name (e.g. "list-employees").
	Name string `json:"name"`
	// RequiresPermission is the permission id the caller must hold to read this
	// query. Empty ⇒ the query is ungated. The gate ALSO honours any permission
	// in this permission's namespace plus admin perms, mirroring the SPA's
	// canViewSurface (surface-toolkit/SurfaceViewGate.tsx).
	RequiresPermission string `json:"requires_permission,omitempty"`
}

type Runtime struct {
	Kind       string `json:"kind"` // "spa" | "http_api"
	Exposure   string `json:"exposure,omitempty"`
	BasePath   string `json:"base_path"`
	HealthPath string `json:"health_path,omitempty"`
	Image      string `json:"image,omitempty"`
}

type Display struct {
	Title      string   `json:"title"`
	Subtitle   string   `json:"subtitle,omitempty"`
	Icon       string   `json:"icon,omitempty"`
	ColorToken string   `json:"color_token,omitempty"`
	AppearsOn  []string `json:"appears_on,omitempty"`
}

type CapabilitySpec struct {
	Name string   `json:"name"`
	Tabs []string `json:"tabs,omitempty"`
}

var validSlots = map[string]struct{}{
	"console-home":       {},
	"ops-integrations":   {},
	"me":                 {},
	"equipe":             {},
	"orgchart":           {},
	"colaborador-detail": {},
}

func IsValidSlot(s string) bool {
	_, ok := validSlots[s]
	return ok
}
