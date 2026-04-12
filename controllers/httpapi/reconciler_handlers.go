package httpapi

import (
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

// handleMaterializeOne materializes a single managed secret into Kubernetes.
func (s *Server) handleMaterializeOne(w http.ResponseWriter, r *http.Request) {
	if s.reconciler == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "reconciler is not available"})
		return
	}

	namespace := r.PathValue("namespace")
	name := r.PathValue("name")

	secret, err := repository.GetManagedSecret(r.Context(), s.db, model.GetManagedSecretRequest{
		Namespace: namespace,
		Name:      name,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	if err := s.reconciler.MaterializeSecret(r.Context(), secret); err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "materialized",
		"namespace": secret.Namespace,
		"name":      secret.Name,
	})
}

// handleMaterializeAll lists all active managed secrets and materializes each.
func (s *Server) handleMaterializeAll(w http.ResponseWriter, r *http.Request) {
	if s.reconciler == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "reconciler is not available"})
		return
	}

	secrets, err := repository.ListManagedSecrets(r.Context(), s.db, model.ListManagedSecretsRequest{
		Status: "active",
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	var created, updated, skipped, errors int
	for _, secret := range secrets {
		if mErr := s.reconciler.MaterializeSecret(r.Context(), secret); mErr != nil {
			s.logger.Error("materialize-all: failed",
				zap.String("namespace", secret.Namespace),
				zap.String("name", secret.Name),
				zap.Error(mErr),
			)
			errors++
		} else {
			updated++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "completed",
		"total":   len(secrets),
		"created": created,
		"updated": updated,
		"skipped": skipped,
		"errors":  errors,
	})
}

// handleReconcilerStatus returns the last reconciliation result.
func (s *Server) handleReconcilerStatus(w http.ResponseWriter, _ *http.Request) {
	if s.reconciler == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "reconciler is not available"})
		return
	}

	writeJSON(w, http.StatusOK, s.reconciler.LastResult())
}

// materializeAfterWrite notifies the reconciler of a secret change so it can
// be materialized reactively. Safe to call when reconciler is nil.
func (s *Server) materializeAfterWrite(secret model.ManagedSecret) {
	if s.reconciler == nil {
		return
	}
	s.reconciler.NotifyChange(secret)
}
