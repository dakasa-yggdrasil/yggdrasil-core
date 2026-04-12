package httpapi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

// productDeployOrder defines the dependency-safe order for deploying all products.
var productDeployOrder = []string{
	"dakasa-infra",
	"dakasa-shared",
	"dakasa-app",
	"dakasa-enterprise",
	"dakasa-tartaro",
}

// handleDeployProduct deploys all kustomize components of a single product.
//
//	POST /api/v1/products/{namespace}/{name}/deploy
func (s *Server) handleDeployProduct(w http.ResponseWriter, r *http.Request) {
	if s.deployer == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Error: "kustomize deployer is not available (repo volume not mounted or addon not loaded)",
		})
		return
	}

	namespace := r.PathValue("namespace")
	name := r.PathValue("name")
	if strings.TrimSpace(namespace) == "" || strings.TrimSpace(name) == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "namespace and name are required"})
		return
	}

	manifests, err := repository.ListManifests(r.Context(), s.db, model.ListManifestFilters{
		Kind:       "product",
		Namespace:  namespace,
		Name:       name,
		ActiveOnly: true,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if len(manifests) == 0 {
		writeJSON(w, http.StatusNotFound, errorResponse{
			Error: fmt.Sprintf("product %s/%s not found", namespace, name),
		})
		return
	}

	manifest := manifests[0]
	result, err := s.deployer.DeployProduct(r.Context(), manifest)
	if err != nil {
		s.logger.Error("deploy product failed",
			zap.String("namespace", namespace),
			zap.String("name", name),
			zap.Error(err),
		)
		writeMappedError(w, err)
		return
	}

	s.logger.Info("deploy product completed",
		zap.String("product", name),
		zap.Int("deployed", result.Deployed),
		zap.Int("errors", result.Errors),
		zap.String("duration", result.Duration),
	)

	writeJSON(w, http.StatusOK, result)
}

// handleDeployAll deploys all products in dependency order.
//
//	POST /api/v1/products/deploy-all
func (s *Server) handleDeployAll(w http.ResponseWriter, r *http.Request) {
	if s.deployer == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Error: "kustomize deployer is not available (repo volume not mounted or addon not loaded)",
		})
		return
	}

	namespace := queryString(r, "namespace")
	if namespace == "" {
		namespace = "dakasa"
	}

	// Fetch all products and sort them into deploy order.
	allManifests, err := repository.ListManifests(r.Context(), s.db, model.ListManifestFilters{
		Kind:       "product",
		Namespace:  namespace,
		ActiveOnly: true,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Index by name for ordering.
	byName := make(map[string]model.Manifest, len(allManifests))
	for _, m := range allManifests {
		byName[m.Metadata.Name] = m
	}

	// Build ordered list.
	ordered := make([]model.Manifest, 0, len(productDeployOrder))
	for _, name := range productDeployOrder {
		if m, ok := byName[name]; ok {
			ordered = append(ordered, m)
		}
	}

	// Append any products not in the explicit order (e.g., dakasa-platform).
	seen := make(map[string]bool, len(productDeployOrder))
	for _, name := range productDeployOrder {
		seen[name] = true
	}
	for _, m := range allManifests {
		if !seen[m.Metadata.Name] {
			ordered = append(ordered, m)
		}
	}

	results, err := s.deployer.DeployAllProducts(r.Context(), ordered)
	if err != nil {
		s.logger.Error("deploy-all failed", zap.Error(err))
		writeMappedError(w, err)
		return
	}

	totalDeployed := 0
	totalErrors := 0
	for _, r := range results {
		totalDeployed += r.Deployed
		totalErrors += r.Errors
	}

	s.logger.Info("deploy-all completed",
		zap.Int("products", len(results)),
		zap.Int("deployed", totalDeployed),
		zap.Int("errors", totalErrors),
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"products":        results,
		"total_deployed":  totalDeployed,
		"total_errors":    totalErrors,
		"products_count":  len(results),
	})
}
