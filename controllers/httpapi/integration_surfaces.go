package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/integrationsurfaces"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// IntegrationSurfacesRepo is the slice of *integrationsurfaces.Repository the handlers need.
type IntegrationSurfacesRepo interface {
	List(ctx context.Context, f integrationsurfaces.ListFilter) ([]integrationsurfaces.Manifest, error)
	GetByName(ctx context.Context, name string) (*integrationsurfaces.Manifest, error)
	Upsert(ctx context.Context, m *integrationsurfaces.Manifest) error
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
		// Surfaces are independent of their adapter (an adapter can have
		// zero, one, or many surfaces, and a surface can exist without
		// any adapter coupling at all). The surface declares its own
		// display.icon in its manifest; nothing here inherits from the
		// linked integration_type. Operators backfill via the manifest
		// PATCH API, not via type-driven enrichment.
		writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
			"total": len(items),
		})
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

// handleIntegrationSurfaceUpdateIcon updates display.icon on one
// surface manifest. Surfaces are independent entities — they don't
// inherit a brand mark from their adapter. This endpoint is the
// supported path for operators to stamp the icon (data URI or
// absolute URL) on a surface row without having to round-trip
// through the adapter's Describe + manifest-sync.
//
// Body: {"icon":"<url>"} where icon is a data URI, an https:// URL,
// or an absolute path. Empty string clears the field; anything else
// is stored verbatim and the SPA renders it as-is.
type surfaceIconUpdateReq struct {
	Icon string `json:"icon"`
}

func (s *Server) handleIntegrationSurfaceUpdateIcon() http.HandlerFunc {
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
		var req surfaceIconUpdateReq
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid body: "+err.Error())
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
		m.Spec.Display.Icon = strings.TrimSpace(req.Icon)
		if err := s.integrationSurfacesRepo.Upsert(r.Context(), m); err != nil {
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
