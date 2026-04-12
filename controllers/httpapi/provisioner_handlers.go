package httpapi

import (
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/provisioner"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

// handleProvisionAWS orchestrates full AWS resource provisioning and secret
// generation for a namespace. After secrets are stored it triggers a
// reconciler materialize-all to push them to Kubernetes.
func (s *Server) handleProvisionAWS(w http.ResponseWriter, r *http.Request) {
	if s.provisioner == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Error: "aws provisioner is not available (missing credentials or addon not loaded)",
		})
		return
	}

	var req provisioner.ProvisionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	result, err := s.provisioner.ProvisionAll(r.Context(), req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Trigger reconciler materialize-all so secrets are pushed to K8s immediately.
	if s.reconciler != nil {
		secrets, listErr := repository.ListManagedSecrets(r.Context(), s.db, model.ListManagedSecretsRequest{
			Status: "active",
		})
		if listErr != nil {
			s.logger.Error("provision: list secrets for materialize-all failed", zap.Error(listErr))
		} else {
			var matErrors int
			for _, secret := range secrets {
				if mErr := s.reconciler.MaterializeSecret(r.Context(), secret); mErr != nil {
					s.logger.Error("provision: materialize secret failed",
						zap.String("namespace", secret.Namespace),
						zap.String("name", secret.Name),
						zap.Error(mErr),
					)
					matErrors++
				}
			}
			s.logger.Info("provision: materialize-all completed",
				zap.Int("total", len(secrets)),
				zap.Int("errors", matErrors),
			)
		}
	}

	writeJSON(w, http.StatusOK, result)
}
