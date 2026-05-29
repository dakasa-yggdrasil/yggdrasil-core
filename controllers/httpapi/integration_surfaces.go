package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/integrationsurfaces"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// IntegrationSurfacesRepo is the slice of *integrationsurfaces.Repository the handlers need.
type IntegrationSurfacesRepo interface {
	List(ctx context.Context, f integrationsurfaces.ListFilter) ([]integrationsurfaces.Manifest, error)
	GetByName(ctx context.Context, name string) (*integrationsurfaces.Manifest, error)
	Touch(ctx context.Context, name string) error
	Deactivate(ctx context.Context, name string) error
}

// SurfaceQueryDispatcher abstracts the synchronous RPC executor that
// forwards an adapter operation to the named instance. The production
// implementation wraps controllers/message.ExecuteIntegration. See
// addons/integration_surface_sync.go for the production wiring; tests
// use a fake.
type SurfaceQueryDispatcher interface {
	Execute(ctx context.Context, req model.ExecuteIntegrationRequest) (any, error)
}

func (s *Server) handleIntegrationSurfacesList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.integrationSurfacesRepo == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "integration surfaces repository not configured")
			return
		}
		f := integrationsurfaces.ListFilter{
			AppearsOn:       strings.TrimSpace(r.URL.Query().Get("appears_on")),
			IntegrationType: strings.TrimSpace(r.URL.Query().Get("integration_type")),
			Category:        strings.TrimSpace(r.URL.Query().Get("category")),
		}
		items, err := s.integrationSurfacesRepo.List(r.Context(), f)
		if err != nil {
			writeMappedError(w, err)
			return
		}
		// §15 Lego principle: surfaces inherit display.icon from their
		// parent integration_type when they didn't declare their own.
		// The integration_type manifest is the canonical owner of brand
		// UI metadata (spec.icon.url is the data URI). The console must
		// not hardcode slug→asset mappings — it only renders what flows
		// down from the adapter manifest.
		s.enrichSurfacesWithTypeIcons(r.Context(), items)
		writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
			"total": len(items),
		})
	}
}

// surfaceIconIsRenderable returns true when display.icon already holds
// a value the SPA can render verbatim — a data URI, an absolute URL,
// or an absolute path (something the adapter or operator explicitly
// stamped). Bare slugs like "slack" or empty strings count as "the
// adapter just hinted at its integration_type"; those still need
// enrichment from the integration_type manifest.
func surfaceIconIsRenderable(v string) bool {
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "data:") {
		return true
	}
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		return true
	}
	if strings.HasPrefix(v, "/") {
		return true
	}
	return false
}

// enrichSurfacesWithTypeIcons rewrites display.icon to a data URI or
// absolute URL whenever the field was either empty or a bare slug.
// One SQL query + in-memory join, so cost stays bounded by the number
// of distinct integration_types referenced — not by surface count.
//
// The "bare slug" case is the common one in production today:
// adapters declare `display.icon: "slack"` as a hint, expecting the
// SPA to map it to a brand asset. That mapping is anti-Lego console
// hardcoding; the canonical source of brand icons is the
// integration_type manifest's spec.icon.url, so we backfill from
// there. Surfaces that already shipped a real renderable icon (data
// URI / URL / absolute path) win. Surfaces without integration_type
// (core/domain categories) are left untouched.
func (s *Server) enrichSurfacesWithTypeIcons(
	ctx context.Context,
	surfaces []integrationsurfaces.Manifest,
) {
	if s.db == nil || len(surfaces) == 0 {
		return
	}
	// Collect the integration_type names whose icon we need.
	needed := map[string]struct{}{}
	for _, sf := range surfaces {
		if surfaceIconIsRenderable(sf.Spec.Display.Icon) {
			continue
		}
		if sf.IntegrationType == nil || *sf.IntegrationType == "" {
			continue
		}
		needed[*sf.IntegrationType] = struct{}{}
	}
	if len(needed) == 0 {
		return
	}
	mans, err := repository.ListManifests(ctx, s.db, model.ListManifestFilters{Kind: "integration_type"})
	if err != nil {
		// Soft-fail: a partial enrichment is fine. The console renders
		// the letter fallback when icon is empty.
		return
	}
	byName := make(map[string]string, len(mans))
	for _, m := range mans {
		name := m.Metadata.Name
		if name == "" {
			continue
		}
		if _, ok := needed[name]; !ok {
			continue
		}
		// spec.icon.url lives inside the raw JSON spec. Decode just
		// the icon block — full spec parsing would couple this handler
		// to the integration_type schema, which is owned by the §15
		// validator, not by us.
		var spec struct {
			Icon struct {
				URL string `json:"url"`
			} `json:"icon"`
		}
		if err := json.Unmarshal(m.Spec, &spec); err != nil {
			continue
		}
		url := strings.TrimSpace(spec.Icon.URL)
		if url == "" {
			continue
		}
		byName[name] = url
	}
	for i := range surfaces {
		sf := &surfaces[i]
		if surfaceIconIsRenderable(sf.Spec.Display.Icon) {
			continue
		}
		if sf.IntegrationType == nil {
			continue
		}
		if url, ok := byName[*sf.IntegrationType]; ok {
			sf.Spec.Display.Icon = url
		}
	}
}

func (s *Server) handleIntegrationSurfaceGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.integrationSurfacesRepo == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "integration surfaces repository not configured")
			return
		}
		name := strings.TrimSpace(r.PathValue("name"))
		if name == "" {
			writeJSONError(w, http.StatusBadRequest, "missing name")
			return
		}
		m, err := s.integrationSurfacesRepo.GetByName(r.Context(), name)
		if errors.Is(err, integrationsurfaces.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "integration surface not found")
			return
		}
		if err != nil {
			writeMappedError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, m)
	}
}

// handleIntegrationSurfaceDeactivate flips active=false on a federated
// integration surface row. Used to retire surfaces whose backing
// integration_type was archived/deleted (the syncer only Upserts, so
// orphaned active=true rows would otherwise linger forever and surface
// in /ops/integrations + console-home "Surfaces em execução" listings —
// confusing for non-technical operators who see stale entries with no
// way to clean them up).
//
// The repository.Deactivate is a soft-delete (active=false); a future
// resync can revive the row via Upsert if the integration_type is
// re-registered. Gated by permManageIntegrations at the mux.
func (s *Server) handleIntegrationSurfaceDeactivate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.integrationSurfacesRepo == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "integration surfaces repository not configured")
			return
		}
		name := strings.TrimSpace(r.PathValue("name"))
		if name == "" {
			writeJSONError(w, http.StatusBadRequest, "missing name")
			return
		}
		if err := s.integrationSurfacesRepo.Deactivate(r.Context(), name); err != nil {
			if errors.Is(err, integrationsurfaces.ErrNotFound) {
				writeJSONError(w, http.StatusNotFound, "integration surface not found")
				return
			}
			writeMappedError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deactivated": true, "name": name})
	}
}

func (s *Server) handleIntegrationSurfaceSync() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.integrationSurfacesRepo == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "integration surfaces repository not configured")
			return
		}
		name := strings.TrimSpace(r.PathValue("name"))
		if name == "" {
			writeJSONError(w, http.StatusBadRequest, "missing name")
			return
		}
		if err := s.integrationSurfacesRepo.Touch(r.Context(), name); err != nil {
			if errors.Is(err, integrationsurfaces.ErrNotFound) {
				writeJSONError(w, http.StatusNotFound, "integration surface not found")
				return
			}
			writeMappedError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"sync_queued": true, "name": name})
	}
}
