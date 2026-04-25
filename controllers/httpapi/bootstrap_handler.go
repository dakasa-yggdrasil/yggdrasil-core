// Package httpapi: legacy bootstrap handler was removed in v2.0.0.
// Initial deployment now goes through the control_plane manifest +
// yggdrasil-deploy-control-plane workflow, then repository_binding
// manifests for application-level CD. See docs/architecture/cd-via-yggdrasil.md.
package httpapi

import (
	"fmt"
	"net/http"
)

const bootstrapDeprecationMessage = "deprecated in yggdrasil v2.0.0; bootstrap via the control_plane manifest + yggdrasil-deploy-control-plane workflow, then apply repository_binding manifests"

// handleBootstrap returns 410 Gone (legacy endpoint).
//
//	POST /api/v1/bootstrap
func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	deployGone(w, fmt.Sprintf("POST %s — %s", r.URL.Path, bootstrapDeprecationMessage))
}
