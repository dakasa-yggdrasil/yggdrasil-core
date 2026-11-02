//go:build nativequalification

package message

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func executeProductionGuestRetirementFinishedV2(context.Context, *sql.DB, repository.CapacityStore, model.Manifest, model.CapacityPolicySpec, model.WorkflowStepSpec, guestOriginalStepInput, ed25519.PrivateKey) (any, error) {
	return nil, errOriginalGuestStep
}
