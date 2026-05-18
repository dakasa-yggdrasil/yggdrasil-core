package httpapi

import (
	"context"
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
	Touch(ctx context.Context, name string) error
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
