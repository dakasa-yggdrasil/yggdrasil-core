//go:build !recoveryfixture || nativequalification

package message

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"testing"
)

func nativeWorkflowFixtureDSN(_ *testing.T, dsn string) string { return dsn }
func nativeWorkflowFixtureWorkflow(_ *testing.T, wf model.WorkflowManifestSpec) model.WorkflowManifestSpec {
	return wf
}
func nativeWorkflowFixturePolicy(_ *testing.T, p model.CapacityPolicySpec, b model.CapacityMutationBinding, _ []model.CapacityMutationSlotBinding) (model.CapacityPolicySpec, model.CapacityMutationBinding) {
	return p, b
}
func nativeWorkflowFixtureStore(_ *testing.T, s repository.CapacityStore) repository.CapacityStore {
	return s
}
func nativeWorkflowSyntheticGate(*testing.T) bool { return false }

func nativeWorkflowFixtureSettlement(_ *testing.T, _ model.CapacityMutationBinding, _ model.CapacityMutationGrant, s model.CapacityMutationSettleRequest) model.CapacityMutationSettleRequest {
	return s
}

func nativeWorkflowFixtureContext(_ *testing.T, ctx context.Context) context.Context { return ctx }
