package httpapi

import (
	"fmt"
	"net/http"
	"strings"
)

// handleManifestListGeneric exposes the kind-agnostic list endpoint the
// yggdrasil CLI uses for `yggdrasil get <kind>`. Kind comes from the
// ?kind= query parameter; the rest of the filters (namespace, name,
// active_only) are the same ones the kind-specific handlers accept.
//
// This is a small router on top of the same repository.ListManifests
// used by handleWorkflowList, handleProductList, etc. Keeping it
// separate from those lets existing surfaces keep their typed wrappers
// while giving the CLI one URL for every kind.
func (s *Server) handleManifestListGeneric(w http.ResponseWriter, r *http.Request) {
	kind := strings.TrimSpace(queryString(r, "kind"))
	if kind == "" {
		writeMappedError(w, fmt.Errorf("kind query parameter is required"))
		return
	}
	s.handleManifestList(w, r, kind)
}

// handleManifestCreateGeneric is the write side — `yggdrasil apply -f`
// routes here and the kind travels in the ?kind= query parameter so the
// CLI does not need per-kind POST URLs. The payload still obeys the
// same consoleCreateManifestRequest shape the kind-specific endpoints
// accept, and validation runs through the exact same pipeline.
func (s *Server) handleManifestCreateGeneric(w http.ResponseWriter, r *http.Request) {
	kind := strings.TrimSpace(queryString(r, "kind"))
	if kind == "" {
		writeMappedError(w, fmt.Errorf("kind query parameter is required"))
		return
	}
	s.handleManifestCreate(w, r, kind)
}
