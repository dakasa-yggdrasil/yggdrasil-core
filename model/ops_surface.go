package model

const CurrentOpsSchemaVersion = 1

type SurfaceListEntry struct {
	Surface        string `json:"surface"`
	SurfaceVersion string `json:"surface_version"`
	DisplayName    string `json:"display_name"`
	Icon           string `json:"icon"`
	Health         string `json:"health"`
}

type SurfaceListResponse struct {
	Surfaces []SurfaceListEntry `json:"surfaces"`
}

type SurfacePermission struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type SurfacePage struct {
	ID       string         `json:"id"`
	Path     string         `json:"path"`
	Title    string         `json:"title"`
	Requires []string       `json:"requires,omitempty"`
	View     map[string]any `json:"view"`
}

type SurfaceWidget struct {
	ID       string         `json:"id"`
	Target   string         `json:"target"`
	Section  string         `json:"section,omitempty"`
	Priority int            `json:"priority,omitempty"`
	View     map[string]any `json:"view"`
	Link     string         `json:"link,omitempty"`
}

type SurfaceManifest struct {
	Surface        string              `json:"surface"`
	SurfaceVersion string              `json:"surface_version"`
	SchemaVersion  int                 `json:"schema_version"`
	DisplayName    string              `json:"display_name"`
	Icon           string              `json:"icon"`
	Description    string              `json:"description,omitempty"`
	Permissions    []SurfacePermission `json:"permissions,omitempty"`
	Pages          []SurfacePage       `json:"pages"`
	Widgets        []SurfaceWidget     `json:"widgets,omitempty"`
}
