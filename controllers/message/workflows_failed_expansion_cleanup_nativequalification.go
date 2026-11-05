//go:build nativequalification

package message

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func planFailedExpansionCleanup(context.Context, repository.CapacityStore, model.Manifest, model.Manifest, model.WorkflowStepSpec) (any, bool, error) {
	return nil, false, nil
}
func executeFailedExpansionCleanupStep(context.Context, *sql.DB, repository.CapacityStore, model.Manifest, model.CapacityPolicySpec, model.WorkflowStepSpec, guestOriginalStepInput, ed25519.PrivateKey, bool) (any, bool, error) {
	return nil, false, nil
}
func completeFailedExpansionCleanup(context.Context, repository.CapacityStore, model.Manifest, model.Manifest, model.CapacityPolicySpec, model.WorkflowStepSpec, originalGuestReconcileInput) (any, bool, error) {
	return nil, false, nil
}
