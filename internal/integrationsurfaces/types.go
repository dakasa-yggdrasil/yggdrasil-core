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
