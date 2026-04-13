package provisioner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"go.uber.org/zap"
)

// DeployResult summarises the outcome of deploying a full product.
type DeployResult struct {
	Product    string                  `json:"product"`
	Namespace  string                  `json:"namespace"`
	Deployed   int                     `json:"deployed"`
	Skipped    int                     `json:"skipped"`
	Errors     int                     `json:"errors"`
	Components []DeployComponentResult `json:"components"`
	Duration   string                  `json:"duration"`
}

// DeployComponentResult captures the outcome of one component deploy.
type DeployComponentResult struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Status  string `json:"status"` // "deployed", "skipped", "error"
	Message string `json:"message,omitempty"`
}

// KustomizeDeployer deploys Kubernetes resources from kustomize overlays
// by shelling out to kubectl.
type KustomizeDeployer struct {
	repoBasePath string
	logger       *zap.Logger
}

// NewKustomizeDeployer creates a deployer that resolves overlays under repoBasePath.
func NewKustomizeDeployer(repoBasePath string, logger *zap.Logger) *KustomizeDeployer {
	return &KustomizeDeployer{
		repoBasePath: repoBasePath,
		logger:       logger,
	}
}

// locatorMap maps git locators (from product specs) to local directory names
// under the repo base path. The renderer.path is appended to this directory.
//
// For repos that live at the submodule root (e.g., dakasa-orchestrator), the
// locator maps directly. For repos nested inside a parent submodule
// (e.g., dakasa-tartaro-fe hosts 5 services), the locator maps to the parent
// directory and the renderer.path already contains the backend sub-path.
var locatorMap = map[string]string{
	// dakasa-app (6 standalone backend repos inside dakasa-app-fe/backend/)
	"github.com/dakasa-co/dakasa-app-identities-api":      "dakasa-app-fe/backend/dakasa-identities",
	"github.com/dakasa-co/dakasa-app-hall-api":             "dakasa-app-fe/backend/dakasa-hall",
	"github.com/dakasa-co/dakasa-app-room-api":             "dakasa-app-fe/backend/dakasa-room",
	"github.com/dakasa-co/dakasa-app-notify-api":           "dakasa-app-fe/backend/dakasa-notify",
	"github.com/dakasa-co/dakasa-app-media-compressor-api": "dakasa-app-fe/backend/dakasa-media-compressor",
	"github.com/dakasa-co/dakasa-app-rta-api":              "dakasa-app-fe/backend/dakasa-rta",

	// dakasa-enterprise (6 standalone backend repos inside dakasa-enterprise-fe/backend/)
	"github.com/dakasa-co/dakasa-enterprise-identities-api":       "dakasa-enterprise-fe/backend/dakasa-enterprise-api",
	"github.com/dakasa-co/dakasa-enterprise-ads-api":               "dakasa-enterprise-fe/backend/enterprise-ads-api",
	"github.com/dakasa-co/dakasa-enterprise-payments-api":          "dakasa-enterprise-fe/backend/dakasa-enterprise-payments-api",
	"github.com/dakasa-co/dakasa-enterprise-notify-api":            "dakasa-enterprise-fe/backend/dakasa-enterprise-notify",
	"github.com/dakasa-co/dakasa-enterprise-media-compressor-api":  "dakasa-enterprise-fe/backend/dakasa-enterprise-media-compressor",
	"github.com/dakasa-co/dakasa-enterprise-rta-api":               "dakasa-enterprise-fe/backend/dakasa-enterprise-rta",

	// dakasa-shared
	"github.com/dakasa-co/dakasa-orchestrator": "dakasa-orchestrator",

	// dakasa-tartaro (tartaro-api has its own repo; the rest live inside dakasa-tartaro-fe)
	"github.com/dakasa-co/dakasa-tartaro-api": "dakasa-tartaro-fe/backend/dakasa-tartaro-api",
	"github.com/dakasa-co/dakasa-tartaro-fe":  "dakasa-tartaro-fe",

	// dakasa-infra (all components live inside dakasa-system itself)
	"github.com/dakasa-co/dakasa-system": ".",
}

// LocatorToLocalPath resolves a git locator to a local directory path
// relative to the repo base.
func (d *KustomizeDeployer) LocatorToLocalPath(locator string) (string, error) {
	localDir, ok := locatorMap[locator]
	if !ok {
		return "", fmt.Errorf("unknown locator %q: not in locator map", locator)
	}
	return localDir, nil
}

// DeployComponent runs kustomize build + kubectl apply for one product component.
func (d *KustomizeDeployer) DeployComponent(ctx context.Context, comp model.ProductComponentSpec) error {
	localDir, err := d.LocatorToLocalPath(comp.Source.Locator)
	if err != nil {
		return err
	}

	overlayPath := filepath.Join(d.repoBasePath, localDir, comp.Renderer.Path)

	// Check kustomization.yaml exists at the overlay path.
	kustomizationFile := filepath.Join(overlayPath, "kustomization.yaml")
	if _, err := os.Stat(kustomizationFile); err != nil {
		return fmt.Errorf("kustomization.yaml not found at %s: %w", overlayPath, err)
	}

	// Run: kubectl kustomize <path> | kubectl apply -f -
	// The KUBECONFIG env is left empty so kubectl uses in-cluster config automatically.
	shellCmd := fmt.Sprintf("kubectl kustomize %s | kubectl apply --validate=false --force -f -", overlayPath)
	cmd := exec.CommandContext(ctx, "sh", "-c", shellCmd)
	cmd.Env = filterKubeconfig(os.Environ())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply failed for %s: %s: %w", comp.Name, string(output), err)
	}

	d.logger.Info("component deployed",
		zap.String("component", comp.Name),
		zap.String("path", overlayPath),
		zap.String("output", string(output)),
	)
	return nil
}

// DeployProduct deploys all components of a product in order.
func (d *KustomizeDeployer) DeployProduct(ctx context.Context, manifest model.Manifest) (*DeployResult, error) {
	started := time.Now()

	var spec model.ProductManifestSpec
	if err := json.Unmarshal(manifest.Spec, &spec); err != nil {
		return nil, fmt.Errorf("parse product spec: %w", err)
	}

	result := &DeployResult{
		Product:    manifest.Metadata.Name,
		Namespace:  manifest.Metadata.Namespace,
		Components: make([]DeployComponentResult, 0, len(spec.Components)),
	}

	for _, comp := range spec.Components {
		// Only deploy kustomize-rendered components.
		rendererKind := strings.ToLower(strings.TrimSpace(comp.Renderer.Kind))
		if rendererKind != "kustomize" {
			result.Skipped++
			result.Components = append(result.Components, DeployComponentResult{
				Name:    comp.Name,
				Status:  "skipped",
				Message: fmt.Sprintf("renderer kind %q is not kustomize", comp.Renderer.Kind),
			})
			continue
		}

		// Only deploy git-sourced components (skip integration/inline).
		sourceKind := strings.ToLower(strings.TrimSpace(comp.Source.Kind))
		if sourceKind != "git" {
			result.Skipped++
			result.Components = append(result.Components, DeployComponentResult{
				Name:    comp.Name,
				Status:  "skipped",
				Message: fmt.Sprintf("source kind %q is not git", comp.Source.Kind),
			})
			continue
		}

		localDir, _ := d.LocatorToLocalPath(comp.Source.Locator)
		overlayPath := filepath.Join(d.repoBasePath, localDir, comp.Renderer.Path)

		if err := d.DeployComponent(ctx, comp); err != nil {
			result.Errors++
			result.Components = append(result.Components, DeployComponentResult{
				Name:    comp.Name,
				Path:    overlayPath,
				Status:  "error",
				Message: err.Error(),
			})
			d.logger.Error("deploy component failed",
				zap.String("product", manifest.Metadata.Name),
				zap.String("component", comp.Name),
				zap.Error(err),
			)
			continue
		}

		result.Deployed++
		result.Components = append(result.Components, DeployComponentResult{
			Name:   comp.Name,
			Path:   overlayPath,
			Status: "deployed",
		})
	}

	result.Duration = time.Since(started).String()
	return result, nil
}

// DeployAllProducts deploys multiple products in the given order.
func (d *KustomizeDeployer) DeployAllProducts(ctx context.Context, manifests []model.Manifest) ([]*DeployResult, error) {
	results := make([]*DeployResult, 0, len(manifests))
	for _, m := range manifests {
		result, err := d.DeployProduct(ctx, m)
		if err != nil {
			return results, fmt.Errorf("deploy product %s/%s: %w", m.Metadata.Namespace, m.Metadata.Name, err)
		}
		results = append(results, result)
	}
	return results, nil
}

// filterKubeconfig returns a copy of the environment with KUBECONFIG removed,
// so kubectl falls back to in-cluster config.
func filterKubeconfig(environ []string) []string {
	filtered := make([]string, 0, len(environ))
	for _, env := range environ {
		if strings.HasPrefix(env, "KUBECONFIG=") {
			continue
		}
		filtered = append(filtered, env)
	}
	return filtered
}
