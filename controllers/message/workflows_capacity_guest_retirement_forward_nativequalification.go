//go:build nativequalification

package message

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Production forward recovery grants no authority to native qualification.
func liveGuestRetirementForward(context.Context, repository.CapacityStore, model.Manifest, guestOriginalStepInput, string) (any, error) {
	return nil, errOriginalGuestStep
}
func historicalGuestRetirementForward(context.Context, repository.CapacityStore, model.Manifest, guestOriginalStepInput) (any, bool, error) {
	return nil, false, nil
}
func planGuestRetirementForward(context.Context, repository.CapacityStore, model.Manifest, model.Manifest, model.WorkflowStepSpec) (any, bool, error) {
	return nil, false, nil
}
