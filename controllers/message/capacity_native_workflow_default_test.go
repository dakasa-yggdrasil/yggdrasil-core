//go:build !recoveryfixture || nativequalification

package message

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"testing"
)

func nativeWorkflowFixtureDSN(_ *testing.T, dsn string) string { return dsn }
func nativeWorkflowFixtureWorkflow(_ *testing.T, wf model.WorkflowManifestSpec) model.WorkflowManifestSpec {
	return wf
}
func nativeWorkflowFixturePolicy(_ *testing.T, p model.CapacityPolicySpec, _ model.CapacityMutationBinding, _ []model.CapacityMutationSlotBinding) model.CapacityPolicySpec {
	return p
}
func nativeWorkflowFixtureStore(_ *testing.T, s repository.CapacityStore) repository.CapacityStore {
	return s
}
func nativeWorkflowSyntheticGate(*testing.T) bool { return false }
