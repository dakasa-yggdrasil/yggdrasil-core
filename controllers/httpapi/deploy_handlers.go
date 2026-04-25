// Package httpapi: legacy product-deploy handlers were removed in v2.0.0.
// The endpoints retain their routes but now return 410 Gone with a pointer
// to the replacement primitive (kind=repository_binding + workflow dispatch).
package httpapi

import (
	"fmt"
	"net/http"
)

const deployDeprecationMessage = "deprecated in yggdrasil v2.0.0; configure a repository_binding manifest with spec.deploy and let GitHub webhook dispatch a workflow_run"

// handleDeployProduct returns 410 Gone (legacy endpoint).
//
//	POST /api/v1/products/{namespace}/{name}/deploy
func (s *Server) handleDeployProduct(w http.ResponseWriter, r *http.Request) {
	deployGone(w, fmt.Sprintf("POST %s — %s", r.URL.Path, deployDeprecationMessage))
}

// handleDeployAll returns 410 Gone (legacy endpoint).
//
//	POST /api/v1/products/deploy-all
func (s *Server) handleDeployAll(w http.ResponseWriter, r *http.Request) {
	deployGone(w, fmt.Sprintf("POST %s — %s", r.URL.Path, deployDeprecationMessage))
}

func deployGone(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGone)
	fmt.Fprintf(w, `{"error":%q,"deprecation":"yggdrasil v2.0.0"}`, msg)
}
