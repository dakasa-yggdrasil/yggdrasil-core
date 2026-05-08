package httpapi

import (
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Phase 1: empty surface registry. Phase 3 populates via adapter discovery.

func (s *Server) handleOpsSurfacesList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, model.SurfaceListResponse{
		Surfaces: []model.SurfaceListEntry{},
	})
}

func (s *Server) handleOpsSurfaceManifest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing surface id")
		return
	}
	writeJSONError(w, http.StatusNotFound, "surface not found")
}

func (s *Server) handleOpsSurfaceData(w http.ResponseWriter, r *http.Request) {
	_ = r.PathValue("id")
	_ = r.PathValue("viewId")
	writeJSONError(w, http.StatusNotFound, "surface not found")
}

func (s *Server) handleOpsSurfaceAction(w http.ResponseWriter, r *http.Request) {
	_ = r.PathValue("id")
	_ = r.PathValue("actionId")
	writeJSONError(w, http.StatusNotFound, "surface not found")
}
