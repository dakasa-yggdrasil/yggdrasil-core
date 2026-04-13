package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

// BootstrapResult captures the outcome of a full bootstrap run.
type BootstrapResult struct {
	Status   string                 `json:"status"` // "completed" or "partial"
	Phases   []BootstrapPhaseResult `json:"phases"`
	Duration string                 `json:"duration"`
}

// BootstrapPhaseResult captures the outcome of one bootstrap phase.
type BootstrapPhaseResult struct {
	Phase   string `json:"phase"`
	Status  string `json:"status"` // "ok", "error", "skipped"
	Message string `json:"message,omitempty"`
}

// handleBootstrap runs the complete DaKasa bootstrap sequence:
//  1. Materialize all secrets → K8s Secrets
//  2. Deploy infra (databases, queues, temporal)
//  3. Deploy platform (yggdrasil itself — skipped if already running)
//  4. Deploy application services (app, enterprise, tartaro, shared)
//
// POST /api/v1/bootstrap
func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	result := BootstrapResult{Status: "completed"}

	s.logger.Info("bootstrap started")

	// Phase 1: Materialize secrets
	phase1 := s.bootstrapSecrets(r.Context())
	result.Phases = append(result.Phases, phase1)
	s.logger.Info("bootstrap phase complete", zap.String("phase", phase1.Phase), zap.String("status", phase1.Status))

	// Phase 2: Deploy infra
	phase2 := s.bootstrapDeploy(r.Context(), "dakasa-infra", "infra")
	result.Phases = append(result.Phases, phase2)
	s.logger.Info("bootstrap phase complete", zap.String("phase", phase2.Phase), zap.String("status", phase2.Status))

	// Phase 3: Deploy shared (orchestrator)
	phase3 := s.bootstrapDeploy(r.Context(), "dakasa-shared", "shared")
	result.Phases = append(result.Phases, phase3)
	s.logger.Info("bootstrap phase complete", zap.String("phase", phase3.Phase), zap.String("status", phase3.Status))

	// Phase 4: Deploy app services
	phase4 := s.bootstrapDeploy(r.Context(), "dakasa-app", "app")
	result.Phases = append(result.Phases, phase4)
	s.logger.Info("bootstrap phase complete", zap.String("phase", phase4.Phase), zap.String("status", phase4.Status))

	// Phase 5: Deploy enterprise services
	phase5 := s.bootstrapDeploy(r.Context(), "dakasa-enterprise", "enterprise")
	result.Phases = append(result.Phases, phase5)
	s.logger.Info("bootstrap phase complete", zap.String("phase", phase5.Phase), zap.String("status", phase5.Status))

	// Phase 6: Deploy tartaro services
	phase6 := s.bootstrapDeploy(r.Context(), "dakasa-tartaro", "tartaro")
	result.Phases = append(result.Phases, phase6)
	s.logger.Info("bootstrap phase complete", zap.String("phase", phase6.Phase), zap.String("status", phase6.Status))

	// Phase 7: Deploy platform marker (if exists)
	phase7 := s.bootstrapDeploy(r.Context(), "dakasa-platform", "platform")
	result.Phases = append(result.Phases, phase7)

	// Check if any phase had errors
	for _, p := range result.Phases {
		if p.Status == "error" {
			result.Status = "partial"
			break
		}
	}

	result.Duration = time.Since(started).String()

	s.logger.Info("bootstrap complete",
		zap.String("status", result.Status),
		zap.String("duration", result.Duration),
	)

	writeJSON(w, http.StatusOK, result)
}

// bootstrapSecrets materializes all managed secrets as K8s Secrets.
func (s *Server) bootstrapSecrets(ctx context.Context) BootstrapPhaseResult {
	if s.reconciler == nil {
		return BootstrapPhaseResult{Phase: "secrets", Status: "skipped", Message: "reconciler not available"}
	}

	secrets, err := repository.ListManagedSecrets(ctx, s.db, model.ListManagedSecretsRequest{Status: "active"})
	if err != nil {
		return BootstrapPhaseResult{Phase: "secrets", Status: "error", Message: err.Error()}
	}

	errors := 0
	for _, secret := range secrets {
		if err := s.reconciler.MaterializeSecret(ctx, secret); err != nil {
			errors++
			s.logger.Warn("bootstrap: secret materialize failed",
				zap.String("secret", secret.Namespace+"/"+secret.Name),
				zap.Error(err),
			)
		}
	}

	if errors > 0 {
		return BootstrapPhaseResult{
			Phase:   "secrets",
			Status:  "error",
			Message: fmt.Sprintf("%d/%d secrets materialized, %d errors", len(secrets)-errors, len(secrets), errors),
		}
	}

	return BootstrapPhaseResult{
		Phase:   "secrets",
		Status:  "ok",
		Message: fmt.Sprintf("%d secrets materialized", len(secrets)),
	}
}

// bootstrapDeploy deploys one product by name.
func (s *Server) bootstrapDeploy(ctx context.Context, productName, phaseName string) BootstrapPhaseResult {
	if s.deployer == nil {
		return BootstrapPhaseResult{Phase: phaseName, Status: "skipped", Message: "deployer not available"}
	}

	manifests, err := repository.ListManifests(ctx, s.db, model.ListManifestFilters{
		Kind:       "product",
		Namespace:  "dakasa",
		Name:       productName,
		ActiveOnly: true,
	})
	if err != nil || len(manifests) == 0 {
		return BootstrapPhaseResult{Phase: phaseName, Status: "skipped", Message: fmt.Sprintf("product %s not found", productName)}
	}

	result, err := s.deployer.DeployProduct(ctx, manifests[0])
	if err != nil {
		return BootstrapPhaseResult{Phase: phaseName, Status: "error", Message: err.Error()}
	}

	if result.Errors > 0 {
		return BootstrapPhaseResult{
			Phase:   phaseName,
			Status:  "error",
			Message: fmt.Sprintf("deployed %d, errors %d, skipped %d (%s)", result.Deployed, result.Errors, result.Skipped, result.Duration),
		}
	}

	return BootstrapPhaseResult{
		Phase:   phaseName,
		Status:  "ok",
		Message: fmt.Sprintf("deployed %d components (%s)", result.Deployed, result.Duration),
	}
}
